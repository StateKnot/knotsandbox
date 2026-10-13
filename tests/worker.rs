//! Real PostgreSQL, separate non-owner worker identity, mock Kubernetes transport.
//! These tests verify control-plane recovery, never physical Kata/CNI isolation.
#![allow(dead_code)]
mod support;
mod worker_support;

use anyhow::{Context, ensure};
use sandbox_platform::{domain::InstanceAction, model::StartRequest};
use serde_json::json;
use std::sync::atomic::Ordering;
use support::{Fixture, api_failure};
use uuid::Uuid;
use worker_support::{MockKube, claim, fixture, register_mock_launch, stage, worker};

#[tokio::test]
#[ignore = "Requires PostgreSQL and explicit TEST_WORKER_DATABASE_URL; no cluster isolation claim"]
async fn crash_after_pod_create_recovers_uid_once_and_requires_trusted_launch_registration()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let f = fixture().await?;
    let accepted = f.create("worker-recovery").await.map_err(api_failure)?;
    let i = &accepted.body.resource;
    let op = accepted.body.operation.id;
    let mock = MockKube::new(&f, i, op).await?;
    let first = worker(&f, &mock, "worker-before-crash").await?;
    stage(&f, &first, op).await?;
    stage(&f, &first, op).await?;
    mock.expire_pod_create.store(true, Ordering::SeqCst);
    let old_claim = claim(&f, &first, op).await?;
    let error = first
        .reconcile(&old_claim)
        .await
        .err()
        .context("stale worker should fail")?;
    assert_eq!(error.code, "WORKER_LEASE_LOST");
    let mut tx = f.owner_transaction().await?;
    let pod_records: i64 =
        sqlx::query_scalar("SELECT count(*) FROM external_resources WHERE kind='POD'")
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(pod_records, 0);
    tx.commit().await?;
    let restarted = worker(&f, &mock, "worker-after-crash").await?;
    stage(&f, &restarted, op).await?;
    let unregistered = claim(&f, &restarted, op).await?;
    let denied = restarted
        .reconcile(&unregistered)
        .await
        .err()
        .context("Ready without trusted host registration must fail")?;
    assert_eq!(denied.code, "TRUSTED_LAUNCH_REGISTRATION_REQUIRED");
    restarted
        .engine
        .wait(
            &unregistered,
            "WAITING_REGISTRATION",
            "TEST_REGISTRATION_PENDING",
            1,
        )
        .await
        .map_err(api_failure)?;
    register_mock_launch(&f, op, i.id).await?;
    stage(&f, &restarted, op).await?;
    for kind in ["Pod", "PersistentVolumeClaim", "CiliumNetworkPolicy"] {
        assert_eq!(
            mock.posts(kind)?,
            1,
            "recovery must adopt verified fixed identity"
        );
    }
    assert!(
        !first
            .engine
            .heartbeat(&old_claim)
            .await
            .map_err(api_failure)?
    );
    let mut tx = f.owner_transaction().await?;
    let (state,operation,ready):(String,String,bool)=sqlx::query_as("SELECT i.observed_state,o.status,i.ready_generation=i.runtime_generation AND i.ready_launch_id=i.launch_id AND i.ready_pod_uid=i.pod_uid AND i.ready_cluster_epoch=i.cluster_epoch FROM instances i JOIN operations o ON o.id=$1 WHERE i.id=$2").bind(op).bind(i.id).fetch_one(&mut *tx).await?;
    assert_eq!(
        (state.as_str(), operation.as_str(), ready),
        ("RUNNING", "SUCCEEDED", true)
    );
    let pending: i64 = sqlx::query_scalar("SELECT sum(pending)::bigint FROM quota_accounts")
        .fetch_one(&mut *tx)
        .await?;
    assert_eq!(pending, 0);
    tx.commit().await?;
    let stopped = f
        .database
        .lifecycle_action(
            &f.actor,
            i.id,
            InstanceAction::Stop,
            &StartRequest::default(),
            "worker-stop",
            i.spec_version,
            300,
            86400,
        )
        .await
        .map_err(api_failure)?;
    assert!(
        restarted.engine.claim_termination().await.is_err(),
        "compute worker must not claim trusted termination work"
    );
    let mut tx = f.owner_transaction().await?;
    let (state,status,queue):(String,String,String)=sqlx::query_as("SELECT i.observed_state,o.status,d.queue_role FROM instances i JOIN operations o ON o.id=i.active_operation_id JOIN operation_dispatch d ON d.operation_id=o.id WHERE i.id=$1 AND o.id=$2")
        .bind(i.id).bind(stopped.body.operation.id).fetch_one(&mut *tx).await?;
    assert_ne!(state, "STOPPED");
    assert_ne!(status, "SUCCEEDED");
    assert_eq!(queue, "TERMINATION");
    let allocated:i64=sqlx::query_scalar("SELECT sum(allocated)::bigint FROM quota_accounts WHERE dimension IN ('CPU_MILLIS','MEMORY_MIB')").fetch_one(&mut *tx).await?;
    ensure!(
        allocated > 0,
        "uncertain termination must retain compute quota"
    );
    tx.commit().await?;
    let state = mock
        .state
        .lock()
        .map_err(|_| anyhow::anyhow!("mock lock"))?;
    assert_eq!(state.deletes, 0);
    let pod = state
        .objects
        .values()
        .find(|v| v["kind"] == "Pod")
        .context("pod retained")?;
    assert!(
        pod["metadata"]["finalizers"]
            .as_array()
            .context("finalizers")?
            .contains(&json!("sandbox.platform/termination-protection"))
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires PostgreSQL and TEST_WORKER_DATABASE_URL"]
async fn missing_known_pvc_fails_closed_without_replacement_or_ready() -> anyhow::Result<()> {
    let _serial = support::serial().await;
    let f = fixture().await?;
    let a = f.create("worker-lost-pvc").await.map_err(api_failure)?;
    let mock = MockKube::new(&f, &a.body.resource, a.body.operation.id).await?;
    let w = worker(&f, &mock, "worker-lost-volume").await?;
    stage(&f, &w, a.body.operation.id).await?;
    stage(&f, &w, a.body.operation.id).await?;
    mock.remove("PersistentVolumeClaim")?;
    let c = claim(&f, &w, a.body.operation.id).await?;
    let e = w
        .reconcile(&c)
        .await
        .err()
        .context("missing known volume must fail")?;
    assert_eq!(e.code, "RUNTIME_RESOURCE_DRIFT");
    assert_eq!(mock.posts("PersistentVolumeClaim")?, 1);
    assert_eq!(mock.posts("Pod")?, 0);
    let mut tx = f.owner_transaction().await?;
    let state: String = sqlx::query_scalar("SELECT observed_state FROM instances WHERE id=$1")
        .bind(a.body.resource.id)
        .fetch_one(&mut *tx)
        .await?;
    assert_ne!(state, "RUNNING");
    // Historical deletion evidence must not authorize a new empty PVC for the
    // same workspace. Restrict fixture mutation explicitly as well as by RLS.
    sqlx::query("UPDATE external_resources SET status='DELETED',deleted_at=clock_timestamp() WHERE tenant_id=$1 AND instance_id=$2 AND kind='PVC'")
        .bind(f.actor.tenant_id).bind(a.body.resource.id).execute(&mut *tx).await?;
    tx.commit().await?;
    assert_eq!(
        w.reconcile(&c)
            .await
            .err()
            .context("deleted volume ledger must block")?
            .code,
        "RESOURCE_LEDGER_MISMATCH"
    );
    assert_eq!(mock.posts("PersistentVolumeClaim")?, 1);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires PostgreSQL and TEST_WORKER_DATABASE_URL"]
async fn safe_mode_and_live_revocation_block_remote_create() -> anyhow::Result<()> {
    let _serial = support::serial().await;
    let f = fixture().await?;
    let a = f.create("worker-safe-mode").await.map_err(api_failure)?;
    let mock = MockKube::new(&f, &a.body.resource, a.body.operation.id).await?;
    let w = worker(&f, &mock, "worker-safe-mode").await?;
    let c = claim(&f, &w, a.body.operation.id).await?;
    sqlx::query("UPDATE platform_configuration SET safe_mode=true")
        .execute(&f.owner)
        .await?;
    let result = w.reconcile(&c).await;
    sqlx::query("UPDATE platform_configuration SET safe_mode=false")
        .execute(&f.owner)
        .await?;
    assert_eq!(
        result.err().context("safe mode must block")?.code,
        "SAFE_MODE"
    );
    assert_eq!(mock.posts("CiliumNetworkPolicy")?, 0);
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE grants SET revoked_at=clock_timestamp() WHERE action='instances:create'")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    assert_eq!(
        w.reconcile(&c)
            .await
            .err()
            .context("revocation must block")?
            .code,
        "PERMISSION_DENIED"
    );
    assert_eq!(mock.posts("CiliumNetworkPolicy")?, 0);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL and a same-database non-owner TEST_WORKER_DATABASE_URL"]
async fn supervised_timer_skips_hundred_locked_workspaces_and_accepts_later_expiry()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let f = Fixture::new(110).await?;
    let mut workspaces = Vec::new();
    let mut blocked_instances = Vec::new();
    for n in 0..100 {
        let created = f
            .create(&format!("timer-lock-{n}"))
            .await
            .map_err(api_failure)?;
        workspaces.push(created.body.resource.workspace_id);
        blocked_instances.push(created.body.resource.id);
    }
    let healthy = f
        .create("timer-lock-later-healthy")
        .await
        .map_err(api_failure)?;
    let mock = MockKube::new(&f, &healthy.body.resource, healthy.body.operation.id).await?;
    let w = worker(&f, &mock, "timer-physical-locks").await?;
    let runtime_pool = w.engine.database.pool.clone();
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE instances SET compute_lease_started_at='0001-01-01T00:00:00Z',compute_lease_expires_at='0001-01-01T00:01:00Z' WHERE tenant_id=$1 AND id=ANY($2)")
        .bind(f.actor.tenant_id).bind(&blocked_instances).execute(&mut *tx).await?;
    sqlx::query("UPDATE instances SET compute_lease_started_at='0002-01-01T00:00:00Z',compute_lease_expires_at='0002-01-01T00:01:00Z' WHERE tenant_id=$1 AND id=$2")
        .bind(f.actor.tenant_id).bind(healthy.body.resource.id).execute(&mut *tx).await?;
    tx.commit().await?;
    let mut holder = f.owner_transaction().await?;
    let locked: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM workspaces WHERE tenant_id=$1 AND id=ANY($2) ORDER BY id FOR UPDATE",
    )
    .bind(f.actor.tenant_id)
    .bind(&workspaces)
    .fetch_all(&mut *holder)
    .await?;
    ensure!(
        locked.len() == 100,
        "Trial must own all hundred physical workspace row locks"
    );
    let shutdown = tokio_util::sync::CancellationToken::new();
    let mut task = tokio::spawn(w.run(shutdown.clone()));
    let outcome=async{
        let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(15);
        loop{
            ensure!(!task.is_finished(),"A contested row was classified as permanent controller failure");
            let mut tx=f.owner_transaction().await?;
            let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM operations WHERE tenant_id=$1 AND instance_id=$2 AND kind='STOP'),(SELECT count(*) FROM operations WHERE tenant_id=$1 AND instance_id=ANY($3) AND kind='STOP')")
                .bind(f.actor.tenant_id).bind(healthy.body.resource.id).bind(&blocked_instances).fetch_one(&mut *tx).await?;
            tx.commit().await?;
            ensure!(tokio::time::Instant::now()<deadline && counts.0<=1 && counts.1==0,
                "Later expiry was starved, duplicated or a held workspace lock was bypassed");
            if counts.0==1{break;}
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        // The holder is still live. Success therefore proves timer progress
        // without releasing/resetting the hundred earlier row locks.
        let mut tx=f.owner_transaction().await?;
        let retained:i64=sqlx::query_scalar("SELECT count(*) FROM instances WHERE tenant_id=$1 AND id=ANY($2) AND desired_state='RUNNING' AND stop_accepted_at IS NULL AND compute_lease_expires_at='0001-01-01T00:01:00Z'")
            .bind(f.actor.tenant_id).bind(&blocked_instances).fetch_one(&mut *tx).await?;
        ensure!(retained==100,"Timer retry changed deadlines or mutated a contested instance");
        tx.commit().await?;
        ensure!(mock.posts("Pod")?==0,"Expired work must not create a guest Pod");
        Ok::<(),anyhow::Error>(())
    }.await;
    shutdown.cancel();
    let joined = match tokio::time::timeout(std::time::Duration::from_secs(35), &mut task).await {
        Ok(result) => result
            .context("Actual worker task failed")
            .and_then(|result| result),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(anyhow::anyhow!(
                "Actual worker failed bounded timer shutdown"
            ))
        }
    };
    let released = holder.rollback().await;
    runtime_pool.close().await;
    f.database.pool.close().await;
    f.owner.close().await;
    outcome?;
    released?;
    joined?;
    println!("WORKER_TIMER_HUNDRED_LOCKS_LATER_STOP_WITHOUT_DEADLINE_CHANGE_VERIFIED");
    Ok(())
}
