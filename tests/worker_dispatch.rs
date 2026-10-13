//! Real PostgreSQL and dedicated worker logins; Kubernetes is an owned transport
//! probe. This proves dispatch/lease/recovery, never physical sandbox readiness.
#[allow(dead_code)]
mod support;

use std::{convert::Infallible, sync::Arc, time::Duration};

use anyhow::{Context, ensure};
use axum::{body::Body, http::Response};
use kube::Client;
use sandbox_platform::{db::Database, runtime::KubernetesRuntime, worker::Worker};
use serde_json::json;
use sqlx::postgres::PgListener;
use support::{Fixture, api_failure};
use tokio::{sync::Semaphore, time::Instant};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

async fn worker_fixture() -> anyhow::Result<Fixture> {
    // The generic API fixture has an empty policy document. A runtime probe
    // must use the same explicit approved deny-all policy as worker recovery.
    let mut f = Fixture::new(10).await?;
    let policy = Uuid::new_v4();
    let mut tx = f.owner_transaction().await?;
    sqlx::query("INSERT INTO security_policy_versions(id,tenant_id,name,version,status,rules) VALUES($1,$2,'dispatch-deny-all',1,'APPROVED',$3)")
        .bind(policy).bind(f.actor.tenant_id).bind(json!({"profile":"deny-all","dns":true})).execute(&mut *tx).await?;
    tx.commit().await?;
    f.request.security_profile_id = policy;
    Ok(f)
}

async fn worker_database(f: &Fixture, max: u32) -> anyhow::Result<Database> {
    let url = std::env::var("TEST_WORKER_DATABASE_URL")?;
    let checked = url::Url::parse(&url)?;
    let expected = url::Url::parse(&std::env::var("TEST_DATABASE_URL")?)?;
    ensure!(
        checked.username() == "sandbox_worker"
            && checked.path().ends_with("_test")
            && checked.path() == expected.path()
            && checked.host_str() == expected.host_str()
            && checked.port_or_known_default() == expected.port_or_known_default()
    );
    sqlx::raw_sql(include_str!("../scripts/sql/worker-role.sql"))
        .execute(&f.owner)
        .await?;
    let db = Database::connect(&url, max).await?;
    db.verify_runtime_role().await?;
    Ok(db)
}

fn probe_worker(
    db: Database,
    name: &str,
    arrivals: Arc<Semaphore>,
    release: Arc<Semaphore>,
    concurrency: usize,
) -> anyhow::Result<Worker> {
    let service = tower::service_fn(move |request: axum::http::Request<kube::client::Body>| {
        let arrivals = arrivals.clone();
        let release = release.clone();
        async move {
            let (code, body) = if request.uri().path()
                == "/apis/node.k8s.io/v1/runtimeclasses/kata-qemu"
            {
                arrivals.add_permits(1);
                if let Ok(permit) = release.acquire().await {
                    permit.forget();
                }
                (
                    200,
                    json!({"apiVersion":"node.k8s.io/v1","kind":"RuntimeClass","metadata":{"name":"kata-qemu"},"handler":"kata-qemu","scheduling":{"nodeSelector":{"sandbox.platform/worker-pool":"kata"}}}),
                )
            } else {
                // After releasing the probe, persist a normal bounded retry.
                (
                    503,
                    json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"ServiceUnavailable","code":503,"message":"owned test transport has no cluster"}),
                )
            };
            let response = Response::builder()
                .status(code)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap_or_else(|_| Response::new(Body::empty()));
            Ok::<_, Infallible>(response)
        }
    });
    Worker::new(
        db,
        KubernetesRuntime::from_client(Client::new(service, "default")),
        name.into(),
        "integration-evidence-reference".into(),
        concurrency,
        "kube-system".into(),
        [("k8s-app".into(), "kube-dns".into())].into(),
    )
}

async fn arrival(probe: &Semaphore) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), probe.acquire())
        .await
        .context("durable work did not reach owned runtime probe")??
        .forget();
    Ok(())
}

// Defer only this test tenant's retained intents before a later case uses the
// same disposable DB. This does not simulate physical cleanup or free quota.
async fn defer_fixture_intents(f: &Fixture) -> anyhow::Result<()> {
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET next_attempt_at=clock_timestamp()+interval '1 day' WHERE tenant_id=$1 AND status IN ('QUEUED','RUNNING','WAITING')")
        .bind(f.actor.tenant_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

async fn no_hint(listener: &mut PgListener) -> anyhow::Result<()> {
    ensure!(
        tokio::time::timeout(Duration::from_millis(100), listener.try_recv())
            .await
            .is_err(),
        "rollback, future eligibility or lease heartbeat emitted a hint"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable TLS PostgreSQL and explicit TEST_WORKER_DATABASE_URL"]
async fn dispatch_hints_follow_commit_and_never_authorize_or_expose_work() -> anyhow::Result<()> {
    let _serial = support::serial().await;
    let f = worker_fixture().await?;
    let db = worker_database(&f, 4).await?;
    let mut listener = PgListener::connect_with(&db.pool).await?;
    listener.listen("sandbox_worker_dispatch").await?;
    let accepted = f.create("hint-commit").await.map_err(api_failure)?;
    let hint = tokio::time::timeout(Duration::from_secs(5), listener.try_recv())
        .await??
        .context("committed queue hint missing")?;
    ensure!(hint.channel() == "sandbox_worker_dispatch" && hint.payload().is_empty());
    let op = accepted.body.operation.id;
    let mut tx = f.owner_transaction().await?;
    sqlx::query(
        "UPDATE operations SET next_attempt_at=clock_timestamp()+interval '1 hour' WHERE id=$1",
    )
    .bind(op)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    no_hint(&mut listener).await?;
    let mut tx = f.owner_transaction().await?;
    sqlx::query(
        "UPDATE operations SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE id=$1",
    )
    .bind(op)
    .execute(&mut *tx)
    .await?;
    no_hint(&mut listener).await?; // Not delivered while mutation is uncommitted.
    tx.rollback().await?;
    no_hint(&mut listener).await?;
    // Even a forged wakeup cannot bypass eligibility or component routing.
    sqlx::query("SELECT pg_notify('sandbox_worker_dispatch','FORGED-TENANT-AND-TOKEN')")
        .execute(&db.pool)
        .await?;
    let _ = tokio::time::timeout(Duration::from_secs(5), listener.try_recv()).await??;
    let engine =
        sandbox_platform::engine::OperationEngine::new(db.clone(), "hint-no-authority".into())?;
    ensure!(engine.claim().await.map_err(api_failure)?.is_none());
    let mut tx = f.owner_transaction().await?;
    sqlx::query(
        "UPDATE operations SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE id=$1",
    )
    .bind(op)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let hint = tokio::time::timeout(Duration::from_secs(5), listener.try_recv())
        .await??
        .context("due hint missing")?;
    ensure!(hint.payload().is_empty());
    let claim = engine
        .claim()
        .await
        .map_err(api_failure)?
        .context("due claim missing")?;
    ensure!(claim.operation_id == op);
    no_hint(&mut listener).await?;
    ensure!(engine.heartbeat(&claim).await.map_err(api_failure)?);
    no_hint(&mut listener).await?;
    // Second worker cannot obtain an already leased claim after duplicate hints.
    let second =
        sandbox_platform::engine::OperationEngine::new(db.clone(), "hint-other-replica".into())?;
    sqlx::query("SELECT pg_notify('sandbox_worker_dispatch','')")
        .execute(&db.pool)
        .await?;
    ensure!(second.claim().await.map_err(api_failure)?.is_none());
    listener.unlisten_all().await?;
    drop(listener);
    db.pool.close().await;
    defer_fixture_intents(&f).await?;
    f.database.pool.close().await;
    f.owner.close().await;
    println!("WORKER_HINT_COMMIT_ROLLBACK_EMPTY_PAYLOAD_LEASE_AUTHORITY_VERIFIED");
    Ok(())
}

#[tokio::test]
#[ignore = "Requires fresh disposable TLS PostgreSQL; no real Kubernetes isolation"]
async fn worker_fills_capacity_and_recovers_missing_hints_future_work_and_listener_loss()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let f = worker_fixture().await?;
    let db = worker_database(&f, 4).await?;
    let pool = db.pool.clone();
    let arrivals = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    let first = f
        .create("dispatch-before-listen-a")
        .await
        .map_err(api_failure)?;
    let second = f
        .create("dispatch-before-listen-b")
        .await
        .map_err(api_failure)?;
    let third = f
        .create("dispatch-future-no-hint")
        .await
        .map_err(api_failure)?;
    let mut tx = f.owner_transaction().await?;
    sqlx::query(
        "UPDATE operations SET next_attempt_at=clock_timestamp()+interval '1 hour' WHERE id=$1",
    )
    .bind(third.body.operation.id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let worker = probe_worker(
        db,
        "dispatch-capacity",
        arrivals.clone(),
        release.clone(),
        2,
    )?;
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    let started = Instant::now();
    let task = tokio::spawn(async move { worker.run(signal).await });
    arrival(&arrivals).await?;
    let first_probe = started.elapsed();
    arrival(&arrivals).await?;
    let second_probe = started.elapsed();
    let mut tx = f.owner_transaction().await?;
    let leased: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM operations WHERE lease_owner='dispatch-capacity' ORDER BY id",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut expected = vec![first.body.operation.id, second.body.operation.id];
    expected.sort();
    ensure!(
        leased == expected && arrivals.available_permits() == 0,
        "capacity or due-time contract changed"
    );
    // Remove the listener's actual physical backend with its exact login and
    // LISTEN query. It must reconnect and cannot own any authoritative work.
    tx.commit().await?;
    let listener_pid: i32 = sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND usename='sandbox_worker' AND query IN ('LISTEN \"sandbox_worker_dispatch\"','LISTEN \"sandbox_worker_dispatch\";') AND state='idle'").fetch_one(&pool).await?;
    // The fixture's owner is deliberately not allowed pg_terminate_backend of
    // another role; a same-role worker connection may terminate its own peer.
    let stopped: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
        .bind(listener_pid)
        .fetch_one(&pool)
        .await?;
    ensure!(stopped);
    let backends: i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND usename='sandbox_worker' AND backend_type='client backend'")
        .fetch_one(&pool).await?;
    ensure!(
        (1..=4).contains(&backends),
        "listener exceeded configured pool budget"
    );
    // Disable just this owned fixture's hint trigger, then make future work due.
    // Recovery must rely on SQL scans; no production setting is changed.
    let mut tx = f.owner_transaction().await?;
    sqlx::raw_sql("ALTER TABLE operation_dispatch DISABLE TRIGGER worker_dispatch_hint")
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE operations SET next_attempt_at=clock_timestamp()+interval '700 milliseconds' WHERE id=$1").bind(third.body.operation.id).execute(&mut *tx).await?;
    tx.commit().await?;
    release.add_permits(2);
    arrival(&arrivals).await?;
    let mut tx = f.owner_transaction().await?;
    let (attempts, owner): (i32, String) =
        sqlx::query_as("SELECT attempts,lease_owner FROM operations WHERE id=$1")
            .bind(third.body.operation.id)
            .fetch_one(&mut *tx)
            .await?;
    ensure!(attempts == 1 && owner == "dispatch-capacity");
    sqlx::raw_sql("ALTER TABLE operation_dispatch ENABLE TRIGGER worker_dispatch_hint")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let reconnect_deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let reconnected: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND usename='sandbox_worker' AND pid<>$1 AND query IN ('LISTEN \"sandbox_worker_dispatch\"','LISTEN \"sandbox_worker_dispatch\";') AND state='idle')")
            .bind(listener_pid).fetch_one(&pool).await?;
        if reconnected {
            break;
        }
        ensure!(
            Instant::now() < reconnect_deadline,
            "owned listener never resubscribed after physical disconnect"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    shutdown.cancel();
    release.add_permits(32);
    tokio::time::timeout(Duration::from_secs(5), task).await???;
    pool.close().await;
    defer_fixture_intents(&f).await?;
    f.database.pool.close().await;
    f.owner.close().await;
    println!(
        "WORKER_DISPATCH_CAPACITY_STARTUP_LOST_HINT_FUTURE_LISTENER_LOSS_VERIFIED first_us={} second_us={}",
        first_probe.as_micros(),
        second_probe.as_micros()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable TLS PostgreSQL and exact worker login"]
async fn single_connection_worker_recovers_expired_lease_without_listener_or_new_hint()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let f = worker_fixture().await?;
    let db = worker_database(&f, 1).await?;
    let pool = db.pool.clone();
    let accepted = f
        .create("dispatch-expired-lease")
        .await
        .map_err(api_failure)?;
    let old =
        sandbox_platform::engine::OperationEngine::new(db.clone(), "dispatch-crashed".into())?;
    let previous = old
        .claim()
        .await
        .map_err(api_failure)?
        .context("previous claim missing")?;
    ensure!(previous.operation_id == accepted.body.operation.id);
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET lease_until=clock_timestamp()+interval '700 milliseconds' WHERE id=$1")
        .bind(previous.operation_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let arrivals = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    let worker = probe_worker(db, "dispatch-single", arrivals.clone(), release.clone(), 1)?;
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    let task = tokio::spawn(async move { worker.run(signal).await });
    arrival(&arrivals).await?;
    let mut tx = f.owner_transaction().await?;
    let (token, owner, attempts): (i64, String, i32) =
        sqlx::query_as("SELECT lease_token,lease_owner,attempts FROM operations WHERE id=$1")
            .bind(previous.operation_id)
            .fetch_one(&mut *tx)
            .await?;
    ensure!(token == previous.lease_token + 1 && owner == "dispatch-single" && attempts == 2);
    tx.commit().await?;
    ensure!(!old.heartbeat(&previous).await.map_err(api_failure)?);
    let listeners: i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND usename='sandbox_worker' AND query IN ('LISTEN \"sandbox_worker_dispatch\"','LISTEN \"sandbox_worker_dispatch\";')").fetch_one(&pool).await?;
    let backends: i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND usename='sandbox_worker' AND backend_type='client backend'")
        .fetch_one(&pool).await?;
    ensure!(
        backends == 1,
        "poll-only worker exceeded its one-connection budget"
    );
    ensure!(
        listeners == 0,
        "single-connection pool allocated a listener"
    );
    shutdown.cancel();
    release.add_permits(32);
    tokio::time::timeout(Duration::from_secs(5), task).await???;
    pool.close().await;
    defer_fixture_intents(&f).await?;
    f.database.pool.close().await;
    f.owner.close().await;
    println!("WORKER_DISPATCH_SINGLE_POOL_EXPIRED_LEASE_OLD_TOKEN_REJECTED_VERIFIED");
    Ok(())
}
