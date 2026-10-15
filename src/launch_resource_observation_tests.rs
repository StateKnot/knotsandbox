//! Ordinary-role PostgreSQL and authenticated TLS nodeguard, with Kubernetes
//! observations supplied only through the production readback verifier.
use crate::{
    termination_ledger::{LaunchAuthorization, tests::FixtureRuntime},
    test_support_db::{self, api_failure, require_pg_error},
};
use anyhow::{Context, ensure};
use serde_json::{Value, json};
use std::{sync::atomic::Ordering, time::Duration};

#[path = "../tests/worker_support/commit_proxy.rs"]
mod commit_proxy;
#[path = "launch_resource_observation_upgrade_tests.rs"]
mod upgrade;

#[tokio::test]
#[ignore = "Requires owned TLS PostgreSQL and normal migration/runtime roles"]
async fn startup_refuses_observation_write_grants_disabled_guards_and_same_name_function_replacement()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = FixtureRuntime::new(false).await?;
    for (drift, repair) in [
        (
            "GRANT UPDATE(pod_resource_version) ON launch_pod_resource_observations TO sandbox_app",
            "REVOKE UPDATE(pod_resource_version) ON launch_pod_resource_observations FROM sandbox_app",
        ),
        (
            "ALTER TABLE launch_permit_receipts DISABLE TRIGGER launch_registration_resource_complete",
            "ALTER TABLE launch_permit_receipts ENABLE TRIGGER launch_registration_resource_complete",
        ),
    ] {
        sqlx::raw_sql(drift).execute(&f.f.owner).await?;
        let rejected = f.f.database.verify_runtime_role().await.is_err();
        sqlx::raw_sql(repair).execute(&f.f.owner).await?;
        ensure!(
            rejected,
            "ordinary startup accepted a broken observation guard"
        );
        f.f.database.verify_runtime_role().await?;
    }
    sqlx::raw_sql("CREATE OR REPLACE FUNCTION sandbox_lock_registration_boundary(node_id uuid) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN RETURN true; END $$")
        .execute(&f.f.owner).await?;
    let rejected = f.f.database.verify_runtime_role().await.is_err();
    let (_, declaration) = include_str!("../migrations/0046_launch_pod_resource_observations.sql")
        .split_once("CREATE FUNCTION sandbox_lock_registration_boundary(")
        .context("reviewed boundary declaration")?;
    let (body, _) = declaration
        .split_once("\n$observation$;")
        .context("reviewed boundary function end")?;
    sqlx::raw_sql(&format!(
        "CREATE OR REPLACE FUNCTION sandbox_lock_registration_boundary({body}\n$observation$;"
    ))
    .execute(&f.f.owner)
    .await?;
    ensure!(
        rejected,
        "ordinary startup accepted a replaced boundary function"
    );
    f.f.database.verify_runtime_role().await?;
    f.engine.database.verify_runtime_role().await?;
    f.guard.shutdown().await?;
    Ok(())
}

async fn authorize(f: &FixtureRuntime) -> anyhow::Result<LaunchAuthorization> {
    f.engine
        .database
        .prepare_launch_authorization(f.f.actor.tenant_id, f.create_op, &f.node, &f.launch)
        .await
        .map_err(api_failure)
}
async fn saved(f: &FixtureRuntime) -> anyhow::Result<Option<Value>> {
    let mut tx = f.f.owner_transaction().await?;
    let value = sqlx::query_scalar("SELECT to_jsonb(o) FROM launch_pod_resource_observations o WHERE tenant_id=$1 AND instance_id=$2")
        .bind(f.f.actor.tenant_id).bind(f.launch.instance_id).fetch_optional(&mut *tx).await?;
    tx.commit().await?;
    Ok(value)
}
async fn counts(f: &FixtureRuntime) -> anyhow::Result<(i64, i64)> {
    let mut tx = f.f.owner_transaction().await?;
    let value = sqlx::query_as("SELECT (SELECT count(*) FROM launch_permit_receipts r JOIN launch_permits p ON(p.tenant_id,p.id)=(r.tenant_id,r.permit_id) WHERE p.tenant_id=$1 AND p.instance_id=$2),(SELECT count(*) FROM launch_pod_resource_observations WHERE tenant_id=$1 AND instance_id=$2)")
        .bind(f.f.actor.tenant_id).bind(f.launch.instance_id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(value)
}

#[tokio::test]
#[ignore = "Requires disposable TLS PostgreSQL, ordinary termination role and authenticated nodeguard"]
async fn atomic_registration_captures_exact_resources_once_and_rv_replay_preserves_history()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = FixtureRuntime::new(false).await?;
    let authorization = authorize(&f).await?;
    let ack = f.guard.client.register(&authorization.request).await?;
    let overhead = json!({"cpu":"37m","memory":"9007199254740993"});
    let resources = f
        .observe_resources_with(Some(&overhead), "pod-rv-first", "class-rv-first")
        .await?;
    f.engine
        .database
        .record_launch_authorization(&authorization, &ack, &resources)
        .await
        .map_err(api_failure)?;
    let before = saved(&f).await?.context("committed observation")?;
    ensure!(counts(&f).await? == (1, 1));
    ensure!(
        before["tenant_id"] == f.launch.tenant_id.to_string()
            && before["project_id"] == f.launch.project_id.to_string()
            && before["workspace_id"] == f.launch.workspace_id.to_string()
            && before["generation"] == f.launch.generation
            && before["launch_id"] == f.launch.launch_id.to_string()
            && before["cluster_epoch"] == f.node.cluster_epoch.to_string()
            && before["pod_uid"] == f.launch.pod_uid.to_string()
            && before["node_uid"] == f.node.node_uid.to_string()
            && before["node_boot_id"] == f.node.boot_id.to_string()
            && before["base_permit_id"] == authorization.base_permit.request.permit_id.to_string()
            && before["registration_id"] == authorization.request.permit_id.to_string()
            && before["source"] == "KUBERNETES_API_READBACK"
    );
    ensure!(
        before["pod_overhead_cpu_millis"] == 37
            && before["pod_overhead_memory_bytes"] == 9_007_199_254_740_993_i64
            && before["workload_request_cpu_millis"] == 1000
            && before["workload_request_memory_bytes"] == 2_147_483_648_i64
            && before["effective_request_memory_bytes"] == 9_007_201_402_224_641_i64
    );
    let metadata_only = f
        .observe_resources_with(Some(&overhead), "pod-rv-later", "class-rv-later")
        .await?;
    f.engine
        .database
        .record_launch_authorization(&authorization, &ack, &metadata_only)
        .await
        .map_err(api_failure)?;
    ensure!(
        saved(&f).await? == Some(before.clone()),
        "metadata replay must preserve the entire original row"
    );
    let conflict = f
        .observe_resources_with(
            Some(&json!({"cpu":"38m","memory":"9007199254740993"})),
            "pod-rv-third",
            "class-rv-third",
        )
        .await?;
    ensure!(
        f.engine
            .database
            .record_launch_authorization(&authorization, &ack, &conflict)
            .await
            .is_err()
    );
    ensure!(saved(&f).await? == Some(before) && counts(&f).await? == (1, 1));
    f.guard.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable TLS PostgreSQL, ordinary termination role and authenticated nodeguard"]
async fn receipt_without_observation_and_failed_ack_leave_no_half_commit() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = FixtureRuntime::new(false).await?;
    let authorization = authorize(&f).await?;
    let mut tx = f
        .engine
        .database
        .begin(f.f.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    sqlx::query(
        "INSERT INTO launch_permit_receipts(tenant_id,permit_id,journal_revision) VALUES($1,$2,1)",
    )
    .bind(f.f.actor.tenant_id)
    .bind(authorization.request.permit_id)
    .execute(&mut *tx)
    .await?;
    require_pg_error(tx.commit().await, "23514")?;
    ensure!(counts(&f).await? == (0, 0));
    let other = FixtureRuntime::new(false).await?;
    let wrong = authorize(&other).await?;
    let wrong_ack = other.guard.client.register(&wrong.request).await?;
    let resources = f.observe_resources().await?;
    ensure!(
        f.engine
            .database
            .record_launch_authorization(&authorization, &wrong_ack, &resources)
            .await
            .is_err()
    );
    let good_ack = f.guard.client.register(&authorization.request).await?;
    let other_resources = other.observe_resources().await?;
    ensure!(
        f.engine
            .database
            .record_launch_authorization(&authorization, &good_ack, &other_resources)
            .await
            .is_err()
    );
    ensure!(counts(&f).await? == (0, 0) && counts(&other).await? == (0, 0));
    other.guard.shutdown().await?;
    f.guard.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable TLS PostgreSQL and all ordinary component roles"]
async fn observations_are_tenant_read_only_and_baseline_and_scalar_ingress_are_closed()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = FixtureRuntime::new(true).await?;
    let other = FixtureRuntime::new(false).await?;
    let mut tx =
        f.f.database
            .begin(f.f.actor.tenant_id)
            .await
            .map_err(api_failure)?;
    let visible: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM launch_pod_resource_observations WHERE instance_id=$1",
    )
    .bind(f.launch.instance_id)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(visible == 1);
    tx.commit().await?;
    let mut tx = other
        .f
        .database
        .begin(other.f.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    let hidden: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM launch_pod_resource_observations WHERE instance_id=$1",
    )
    .bind(f.launch.instance_id)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(hidden == 0);
    tx.commit().await?;
    for database in [&f.f.database, &f.engine.database] {
        for query in [
            "INSERT INTO launch_pod_resource_observations(id) VALUES(gen_random_uuid())",
            "UPDATE launch_pod_resource_observations SET source=source",
            "DELETE FROM launch_pod_resource_observations",
            "SELECT * FROM launch_registration_legacy_baseline",
            "INSERT INTO launch_registration_legacy_baseline(registration_id) VALUES(gen_random_uuid())",
        ] {
            let mut tx = database
                .begin(f.f.actor.tenant_id)
                .await
                .map_err(api_failure)?;
            require_pg_error(sqlx::query(query).execute(&mut *tx).await, "42501")?;
            tx.rollback().await?;
        }
    }
    let allowed: bool =
        sqlx::query_scalar("SELECT has_function_privilege(current_user,$1,'EXECUTE')")
            .bind(format!(
                "public.{}",
                crate::launch_resource_observation_schema::RECORD_SIGNATURE
            ))
            .fetch_one(&f.f.database.pool)
            .await?;
    ensure!(!allowed, "API role cannot call the trusted scalar ingress");
    let mut tx = f.f.owner_transaction().await?;
    require_pg_error(sqlx::query("UPDATE launch_pod_resource_observations SET pod_resource_version='rewrite' WHERE instance_id=$1")
        .bind(f.launch.instance_id).execute(&mut *tx).await,"23514")?;
    tx.rollback().await?;
    f.f.database.verify_runtime_role().await?;
    f.engine.database.verify_runtime_role().await?;
    other.guard.shutdown().await?;
    f.guard.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable verify-full TLS PostgreSQL and private fixture CA"]
async fn actual_lost_commit_ack_replays_original_registration_and_observation_id()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = FixtureRuntime::new(false).await?;
    let authorization = authorize(&f).await?;
    let ack = f.guard.client.register(&authorization.request).await?;
    let resources = f.observe_resources().await?;
    let (mut proxy, database) = commit_proxy::CommitProxy::connect_termination().await?;
    let result = async {
        proxy.arm.store(true,Ordering::SeqCst);
        let write = database.record_launch_authorization(&authorization,&ack,&resources);
        tokio::pin!(write);
        tokio::select! {
            result = &mut write => anyhow::bail!("registration completed before the owned COMMIT ACK was held: {}",result.is_ok()),
            _ = tokio::time::timeout(Duration::from_secs(10),proxy.arrived.notified()) => {}
        }
        ensure!(proxy.target_backend_pid.load(Ordering::SeqCst)>0,"proxy must identify the actual backend");
        let before = saved(&f).await?.context("independent owner must see the committed observation before losing ACK")?;
        ensure!(counts(&f).await?==(1,1),"registration receipt and observation must commit together");
        proxy.drop_ack();
        ensure!(tokio::time::timeout(Duration::from_secs(5),&mut write).await?.is_err(),"real transport must report the lost COMMIT ACK");
        database.record_launch_authorization(&authorization,&ack,&resources).await.map_err(api_failure)?;
        ensure!(counts(&f).await?==(1,1) && saved(&f).await?==Some(before));
        Ok::<(),anyhow::Error>(())
    }.await;
    let pids = proxy.backend_pids();
    let cleanup = proxy.finish(&database).await;
    let absence = async {
        let pids = pids?;
        ensure!(!pids.is_empty(), "actual TLS backend identities must be recorded");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE pid=ANY($1) AND datname=current_database() AND usename='sandbox_termination'")
                .bind(&pids).fetch_one(&f.engine.database.pool).await?;
            if remaining == 0 { break; }
            ensure!(tokio::time::Instant::now() < deadline, "owned termination proxy backends did not retire after awaited drain");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<(),anyhow::Error>(())
    }.await;
    f.guard.shutdown().await?;
    result?;
    cleanup?;
    absence?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable TLS PostgreSQL and a real expired old host permit"]
async fn expired_old_ack_cannot_register_after_unacknowledged_lease_renewal() -> anyhow::Result<()>
{
    let _serial = test_support_db::serial().await;
    let f = FixtureRuntime::new(false).await?;
    let mut tx = f.f.owner_transaction().await?;
    sqlx::query("UPDATE instances SET compute_lease_expires_at=clock_timestamp()+interval '5 seconds' WHERE tenant_id=$1 AND id=$2")
        .bind(f.f.actor.tenant_id).bind(f.launch.instance_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let original = authorize(&f).await?;
    let ack = f.guard.client.register(&original.request).await?;
    let current =
        f.f.database
            .get_instance(&f.f.actor, f.launch.instance_id)
            .await
            .map_err(api_failure)?;
    f.f.database
        .renew_instance(
            &f.f.actor,
            current.id,
            &crate::model::RenewRequest {
                expires_at: original.request.expires_at + chrono::Duration::seconds(300),
            },
            &uuid::Uuid::new_v4().to_string(),
            current.spec_version,
            86400,
        )
        .await
        .map_err(api_failure)?;
    let extended = authorize(&f).await?;
    ensure!(extended.request.permit_id != original.request.permit_id);
    // This is real expiry, not a forged ACK/capability or a substituted clock.
    let remaining = (original.request.expires_at - chrono::Utc::now())
        .to_std()
        .unwrap_or_default();
    tokio::time::sleep(remaining + Duration::from_millis(30)).await;
    let mut tx = f.f.owner_transaction().await?;
    let expired: bool = sqlx::query_scalar("SELECT clock_timestamp()>$1")
        .bind(original.request.expires_at)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    ensure!(expired);
    let fresh = f.observe_resources().await?;
    let error = f
        .engine
        .database
        .record_launch_authorization(&original, &ack, &fresh)
        .await
        .err()
        .context("expired original registration must fail despite the renewed compute lease")?;
    ensure!(error.code == "LAUNCH_REGISTRATION_EXPIRED");
    ensure!(
        counts(&f).await? == (0, 0),
        "unacknowledged extension cannot revive an expired ACK or commit a resource observation"
    );
    f.guard.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable TLS PostgreSQL and concurrent owner locks"]
async fn revocation_committed_while_registration_waits_for_node_rolls_back_both_facts()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = FixtureRuntime::new(false).await?;
    let authorization = authorize(&f).await?;
    let ack = f.guard.client.register(&authorization.request).await?;
    let resources = f.observe_resources().await?;
    let mut blocker = f.f.owner_transaction().await?;
    sqlx::query("SELECT id FROM runtime_nodes WHERE node_uid=$1 AND boot_id=$2 FOR UPDATE")
        .bind(f.node.node_uid)
        .bind(f.node.boot_id)
        .fetch_one(&mut *blocker)
        .await?;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    let write = f
        .engine
        .database
        .record_launch_authorization(&authorization, &ack, &resources);
    tokio::pin!(write);
    let barrier = async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE $1=ANY(pg_blocking_pids(a.pid)))")
                .bind(blocker_pid).fetch_one(&f.f.owner).await?;
            if waiting {
                break;
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "registration must actually wait for the owned node lock"
            );
            tokio::task::yield_now().await;
        }
        let mut revoke = f.f.owner_transaction().await?;
        sqlx::query("UPDATE grants SET enabled=false,revoked_at=clock_timestamp() WHERE tenant_id=$1 AND principal_id=$2 AND action='instances:create'")
            .bind(f.f.actor.tenant_id).bind(f.f.actor.principal_id).execute(&mut *revoke).await?;
        revoke.commit().await?;
        blocker.commit().await?;
        Ok::<(), anyhow::Error>(())
    };
    let (written, released) = tokio::join!(&mut write, barrier);
    released?;
    ensure!(
        written.is_err() && counts(&f).await? == (0, 0),
        "waited registration must recheck current grants and atomically roll back"
    );
    f.guard.shutdown().await?;
    Ok(())
}
