#[allow(dead_code)]
mod support;

use std::{sync::Arc, time::Duration};

use anyhow::{Context, ensure};
use chrono::Utc;
use futures_util::future::join_all;
use sandbox_platform::{
    db::{Database, insert_operation, reserve_quota},
    domain::InstanceAction,
    engine::{Claim, OperationEngine},
    model::{RenewRequest, StartRequest},
};
use serde_json::{Value, json};
use sqlx::PgPool;
use support::{Fixture, api_failure, require_api_error, require_pg_error};
use tokio::sync::{Barrier, oneshot};
use uuid::Uuid;

async fn expire(fixture: &Fixture, id: Uuid) -> anyhow::Result<()> {
    let mut tx = fixture.owner_transaction().await?;
    // Historical timestamps make this fixture deterministically eligible without
    // sleeping and put it ahead of unrelated test rows in the bounded scanner.
    sqlx::query("UPDATE instances SET compute_lease_started_at='1970-01-01T00:00:00Z',compute_lease_expires_at='1970-01-01T00:01:00Z' WHERE tenant_id=$1 AND id=$2")
        .bind(fixture.actor.tenant_id).bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

async fn quota_snapshot(fixture: &Fixture) -> anyhow::Result<Vec<Value>> {
    let mut tx = fixture.owner_transaction().await?;
    let rows = sqlx::query_scalar(
        "SELECT to_jsonb(q) FROM quota_accounts q WHERE tenant_id=$1 ORDER BY id",
    )
    .bind(fixture.actor.tenant_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(rows)
}

async fn dedicated_runtime() -> anyhow::Result<(Database, i32)> {
    let database = Database::connect(&std::env::var("TEST_DATABASE_URL")?, 1).await?;
    let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&database.pool)
        .await?;
    Ok((database, pid))
}

async fn wait_for_lock(pool: &PgPool, waiting_pid: i32, holder_pid: i32) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            // Include soft blockers ahead of this session in PostgreSQL's lock
            // queue, which may themselves be waiting on the held row.
            let blocked: bool = sqlx::query_scalar("WITH RECURSIVE blockers(pid) AS (SELECT unnest(pg_blocking_pids($1)) UNION SELECT p.pid FROM blockers b CROSS JOIN LATERAL unnest(pg_blocking_pids(b.pid)) AS p(pid)) SELECT EXISTS(SELECT 1 FROM blockers WHERE pid=$2)")
                .bind(waiting_pid)
                .bind(holder_pid)
                .fetch_one(pool)
                .await?;
            if blocked {
                return Ok::<(), anyhow::Error>(());
            }
            // Poll an actual database barrier, never simulate lease expiry by sleeping.
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("Expected the operation to block on the held database row lock")?
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn concurrent_expiry_accepts_one_system_stop_and_fences_create_without_releasing_data()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let fixture = Fixture::new(10).await?;
    let created = fixture.create("expiry-race").await.map_err(api_failure)?;
    let before = &created.body.resource;
    let worker = "timer-old-create-worker";
    let transfer = Uuid::new_v4();
    let transfer_operation = Uuid::new_v4();
    let mut tx = fixture.owner_transaction().await?;
    let now: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    let transfer_deadline = now + chrono::Duration::seconds(60);
    sqlx::query("UPDATE operations SET status='RUNNING',lease_owner=$3,lease_token=7,lease_until=clock_timestamp()+interval '5 minutes' WHERE tenant_id=$1 AND id=$2")
        .bind(fixture.actor.tenant_id).bind(created.body.operation.id).bind(worker).execute(&mut *tx).await?;
    // Seed a complete retained upload contract, not a detached FILE_WRITE ID.
    // This owner-only prerequisite deliberately retains the pending CREATE:
    // normal file acceptance requires a ready instance and cannot seed this
    // reconciliation scenario. No process or VM closure evidence is fabricated.
    for project in [None, Some(before.project_id)] {
        for (dimension, limit) in [
            ("FILE_TRANSFERS", 10_i64),
            ("FILE_TRANSFER_BYTES", 1024_i64),
        ] {
            sqlx::query("INSERT INTO quota_accounts(tenant_id,project_id,dimension,limit_value) VALUES($1,$2,$3,$4)")
                .bind(fixture.actor.tenant_id).bind(project).bind(dimension).bind(limit).execute(&mut *tx).await?;
        }
    }
    insert_operation(
        &mut tx,
        &fixture.actor,
        transfer_operation,
        before.project_id,
        before.id,
        before.workspace_id,
        "FILE_TRANSFER",
        &json!({"transfer_id":transfer,"direction":"UPLOAD","on_timeout":"HARD_STOP_INSTANCE"}),
        transfer_deadline,
    )
    .await
    .map_err(api_failure)?;
    sqlx::query("UPDATE instances SET pod_uid=$4,slot_held=true,activity_kind='FILE_WRITE',activity_id=$3,activity_generation=runtime_generation,idle_since=NULL WHERE tenant_id=$1 AND id=$2")
        .bind(fixture.actor.tenant_id).bind(before.id).bind(transfer).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO file_transfers(id,tenant_id,project_id,instance_id,workspace_id,operation_id,runtime_generation,launch_id,pod_uid,cluster_epoch,content_id,direction,path,status,byte_limit,expected_sha256,replace,slot_held,deadline,content_expires_at) SELECT $3,i.tenant_id,i.project_id,i.id,i.workspace_id,$4,i.runtime_generation,i.launch_id,i.pod_uid,i.cluster_epoch,$5,'UPLOAD','input/data.bin','WAITING_UPLOAD',3,'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',false,true,$6,$7 FROM instances i WHERE i.tenant_id=$1 AND i.id=$2")
        .bind(fixture.actor.tenant_id).bind(before.id).bind(transfer).bind(transfer_operation).bind(Uuid::new_v4()).bind(transfer_deadline).bind(now+chrono::Duration::hours(24)).execute(&mut *tx).await?;
    reserve_quota(
        &mut tx,
        &fixture.actor,
        before.project_id,
        transfer_operation,
        before.id,
        before.workspace_id,
        &[("FILE_TRANSFERS", 1), ("FILE_TRANSFER_BYTES", 3)],
    )
    .await
    .map_err(api_failure)?;
    let transfer_before: Value =
        sqlx::query_scalar("SELECT to_jsonb(f) FROM file_transfers f WHERE tenant_id=$1 AND id=$2")
            .bind(fixture.actor.tenant_id)
            .bind(transfer)
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    let quota_before = quota_snapshot(&fixture).await?;
    expire(&fixture, before.id).await?;
    let expired = fixture
        .database
        .get_instance(&fixture.actor, before.id)
        .await
        .map_err(api_failure)?;
    let scanner = Database {
        pool: fixture.owner.clone(),
    };
    assert!(
        scanner
            .due_instances()
            .await
            .map_err(api_failure)?
            .contains(&(fixture.actor.tenant_id, before.id))
    );
    let barrier = Arc::new(Barrier::new(12));
    let attempts = (0..12).map(|_| {
        let database = fixture.database.clone();
        let barrier = barrier.clone();
        let tenant = fixture.actor.tenant_id;
        let id = before.id;
        async move {
            barrier.wait().await;
            database.accept_due_stop(tenant, id).await
        }
    });
    let mut accepted = Vec::new();
    for result in join_all(attempts).await {
        if let Some(id) = result.map_err(api_failure)? {
            accepted.push(id);
        }
    }
    assert_eq!(accepted.len(), 1);
    let stopped = fixture
        .database
        .get_instance(&fixture.actor, before.id)
        .await
        .map_err(api_failure)?;
    assert_eq!(stopped.desired_state, "STOPPED");
    assert_eq!(stopped.observed_state, "PENDING");
    assert!(
        stopped.slot_held,
        "Safety-stop acceptance is not proof that remote activity terminated"
    );
    assert_eq!(stopped.stop_reason.as_deref(), Some("LEASE_EXPIRED"));
    assert_eq!(stopped.active_operation_id, Some(accepted[0]));
    assert_eq!(stopped.compute_lease_id, before.compute_lease_id);
    assert_eq!(stopped.compute_lease_version, expired.compute_lease_version);
    assert_eq!(
        stopped.compute_lease_started_at,
        expired.compute_lease_started_at
    );
    assert_eq!(
        stopped.compute_lease_expires_at,
        expired.compute_lease_expires_at
    );
    assert_eq!(stopped.spec_version, before.spec_version + 1);
    assert_eq!(quota_snapshot(&fixture).await?, quota_before);
    let mut tx = fixture.owner_transaction().await?;
    let retained_transfer: Value =
        sqlx::query_scalar("SELECT to_jsonb(f) FROM file_transfers f WHERE tenant_id=$1 AND id=$2")
            .bind(fixture.actor.tenant_id)
            .bind(transfer)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(
        retained_transfer, transfer_before,
        "Accepting STOP must preserve the upload slot, process/content state, exact identity and deadlines"
    );
    let file_reservations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM quota_reservations WHERE tenant_id=$1 AND operation_id=$2 AND status='PENDING'",
    )
    .bind(fixture.actor.tenant_id)
    .bind(transfer_operation)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(file_reservations, 4);
    let old: (String,i64,bool,Option<String>,Option<chrono::DateTime<Utc>>) = sqlx::query_as("SELECT status,lease_token,cancel_requested,lease_owner,lease_until FROM operations WHERE tenant_id=$1 AND id=$2")
        .bind(fixture.actor.tenant_id).bind(created.body.operation.id).fetch_one(&mut *tx).await?;
    assert_eq!(old, ("CANCELLED".into(), 8, true, None, None));
    let system: (String,String,Uuid,Uuid) = sqlx::query_as("SELECT o.kind,p.kind,o.actor_principal_id,c.safety_principal_id FROM operations o JOIN principals p ON p.id=o.actor_principal_id CROSS JOIN platform_configuration c WHERE o.tenant_id=$1 AND o.id=$2")
        .bind(fixture.actor.tenant_id).bind(accepted[0]).fetch_one(&mut *tx).await?;
    assert_eq!(system.0, "STOP");
    assert_eq!(system.1, "SYSTEM");
    assert_eq!(system.2, system.3);
    let workspace: (Option<Uuid>,Option<chrono::DateTime<Utc>>,Option<chrono::DateTime<Utc>>) = sqlx::query_as("SELECT active_operation_id,delete_requested_at,deleted_at FROM workspaces WHERE tenant_id=$1 AND id=$2")
        .bind(fixture.actor.tenant_id).bind(before.workspace_id).fetch_one(&mut *tx).await?;
    assert_eq!(workspace, (Some(accepted[0]), None, None));
    let released: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM quota_reservations WHERE tenant_id=$1 AND status='RELEASED'",
    )
    .bind(fixture.actor.tenant_id)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(released, 0);
    tx.commit().await?;
    let engine = OperationEngine::new(fixture.database.clone(), worker.into())?;
    assert!(
        !engine
            .heartbeat(&Claim {
                tenant_id: fixture.actor.tenant_id,
                operation_id: created.body.operation.id,
                lease_token: 7
            })
            .await
            .map_err(api_failure)?
    );
    assert!(
        !scanner
            .due_instances()
            .await
            .map_err(api_failure)?
            .contains(&(fixture.actor.tenant_id, before.id))
    );
    let mut tx = fixture.owner_transaction().await?;
    let kinds: Vec<String> = sqlx::query_scalar(
        "SELECT kind FROM operations WHERE tenant_id=$1 AND instance_id=$2 ORDER BY kind",
    )
    .bind(fixture.actor.tenant_id)
    .bind(before.id)
    .fetch_all(&mut *tx)
    .await?;
    assert_eq!(kinds, ["CREATE", "FILE_TRANSFER", "STOP"]);
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn expiry_preempts_start_after_grant_revocation_and_principal_disable() -> anyhow::Result<()>
{
    let _serial = support::serial().await;
    let fixture = Fixture::new(10).await?;
    let created = fixture.create("expiry-start").await.map_err(api_failure)?;
    let before = &created.body.resource;
    fixture.seed_observed_state(before.id, "STOPPED").await?;
    fixture.release_fixture_compute(before.id).await?;
    let started = fixture
        .database
        .lifecycle_action(
            &fixture.actor,
            before.id,
            InstanceAction::Start,
            &StartRequest::default(),
            "start-before-expiry",
            before.spec_version,
            300,
            86400,
        )
        .await
        .map_err(api_failure)?;
    let quota_before = quota_snapshot(&fixture).await?;
    let mut tx = fixture.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false,revoked_at=clock_timestamp() WHERE tenant_id=$1 AND principal_id=$2")
        .bind(fixture.actor.tenant_id).bind(fixture.actor.principal_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE principals SET enabled=false WHERE id=$1")
        .bind(fixture.actor.principal_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    expire(&fixture, before.id).await?;
    let stop = fixture
        .database
        .accept_due_stop(fixture.actor.tenant_id, before.id)
        .await
        .map_err(api_failure)?
        .context("Expired START must be stopped independently of user authorization")?;
    let mut tx = fixture.owner_transaction().await?;
    let old: (String, i64, bool) = sqlx::query_as(
        "SELECT status,lease_token,cancel_requested FROM operations WHERE tenant_id=$1 AND id=$2",
    )
    .bind(fixture.actor.tenant_id)
    .bind(started.body.operation.id)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(old, ("CANCELLED".into(), 1, true));
    let state: (String,String,Uuid,Uuid) = sqlx::query_as("SELECT i.desired_state,i.stop_reason,i.active_operation_id,o.actor_principal_id FROM instances i JOIN operations o ON o.tenant_id=i.tenant_id AND o.id=i.active_operation_id WHERE i.tenant_id=$1 AND i.id=$2")
        .bind(fixture.actor.tenant_id).bind(before.id).fetch_one(&mut *tx).await?;
    assert_eq!(state.0, "STOPPED");
    assert_eq!(state.1, "LEASE_EXPIRED");
    assert_eq!(state.2, stop);
    assert_ne!(state.3, fixture.actor.principal_id);
    tx.commit().await?;
    assert_eq!(quota_snapshot(&fixture).await?, quota_before);
    assert!(
        fixture
            .database
            .get_instance(&fixture.actor, before.id)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn renewal_commits_while_scanner_waits_and_scanner_rechecks_the_new_lease()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let fixture = Fixture::new(10).await?;
    let created = fixture
        .create("renew-before-expiry")
        .await
        .map_err(api_failure)?;
    let before = created.body.resource;
    let (scanner, pid) = dedicated_runtime().await?;
    let (renew_db, renew_pid) = dedicated_runtime().await?;
    let mut held = fixture.owner_transaction().await?;
    let holder: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *held)
        .await?;
    sqlx::query("SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(fixture.actor.tenant_id)
        .bind(before.workspace_id)
        .fetch_one(&mut *held)
        .await?;
    let (ready_tx, ready_rx) = oneshot::channel();
    let tenant = fixture.actor.tenant_id;
    let id = before.id;
    let actor = fixture.actor.clone();
    let renewal = tokio::spawn(async move {
        let _ = ready_tx.send(());
        renew_db
            .renew_instance(
                &actor,
                id,
                &RenewRequest {
                    expires_at: before.compute_lease_expires_at + chrono::Duration::seconds(300),
                },
                "renew-wins-lock",
                before.spec_version,
                86400,
            )
            .await
    });
    ready_rx.await?;
    wait_for_lock(&fixture.owner, renew_pid, holder).await?;
    let task = tokio::spawn(async move { scanner.accept_due_stop(tenant, id).await });
    wait_for_lock(&fixture.owner, pid, holder).await?;
    held.commit().await?;
    let renewed = renewal.await?.map_err(api_failure)?;
    assert!(task.await?.map_err(api_failure)?.is_none());
    let after = fixture
        .database
        .get_instance(&fixture.actor, id)
        .await
        .map_err(api_failure)?;
    assert_eq!(
        after.compute_lease_expires_at,
        renewed.body.resource.compute_lease_expires_at
    );
    assert_eq!(after.desired_state, "RUNNING");
    assert!(after.stop_accepted_at.is_none());
    assert_eq!(fixture.count("operations").await?, 2);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn renewal_waiting_on_the_instance_lock_cannot_revive_an_expired_lease() -> anyhow::Result<()>
{
    let _serial = support::serial().await;
    let fixture = Fixture::new(10).await?;
    let created = fixture
        .create("expiry-before-renew")
        .await
        .map_err(api_failure)?;
    let before = created.body.resource;
    let (renew_db, renew_pid) = dedicated_runtime().await?;
    let (stop_db, stop_pid) = dedicated_runtime().await?;
    let mut held = fixture.owner_transaction().await?;
    let holder: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *held)
        .await?;
    // The committed row is still valid when renewal begins; it only discovers
    // the expired lease after this transaction releases the shared instance lock.
    sqlx::query("UPDATE instances SET compute_lease_started_at=clock_timestamp()-interval '2 minutes',compute_lease_expires_at=clock_timestamp()-interval '1 minute' WHERE tenant_id=$1 AND id=$2")
        .bind(fixture.actor.tenant_id).bind(before.id).execute(&mut *held).await?;
    let actor = fixture.actor.clone();
    let id = before.id;
    let (ready_tx, ready_rx) = oneshot::channel();
    let renewal = tokio::spawn(async move {
        let _ = ready_tx.send(());
        renew_db
            .renew_instance(
                &actor,
                id,
                &RenewRequest {
                    expires_at: before.compute_lease_expires_at + chrono::Duration::seconds(300),
                },
                "blocked-renew",
                before.spec_version,
                86400,
            )
            .await
    });
    ready_rx.await?;
    wait_for_lock(&fixture.owner, renew_pid, holder).await?;
    let tenant = fixture.actor.tenant_id;
    let expiry = tokio::spawn(async move { stop_db.accept_due_stop(tenant, id).await });
    wait_for_lock(&fixture.owner, stop_pid, holder).await?;
    held.commit().await?;
    let error = require_api_error(renewal.await?)?;
    ensure!(
        [
            "COMPUTE_LEASE_EXPIRED",
            "VERSION_MISMATCH",
            "STOP_ALREADY_ACCEPTED"
        ]
        .contains(&error.code),
        "Unexpected blocked renewal error: {}",
        error.code
    );
    assert!(expiry.await?.map_err(api_failure)?.is_some());
    let after = fixture
        .database
        .get_instance(&fixture.actor, id)
        .await
        .map_err(api_failure)?;
    assert_eq!(after.desired_state, "STOPPED");
    assert_eq!(after.stop_reason.as_deref(), Some("LEASE_EXPIRED"));
    let late = require_api_error(
        fixture
            .database
            .renew_instance(
                &fixture.actor,
                id,
                &RenewRequest {
                    expires_at: Utc::now() + chrono::Duration::minutes(20),
                },
                "renew-after-stop",
                after.spec_version,
                86400,
            )
            .await,
    )?;
    assert_eq!(late.code, "STOP_ALREADY_ACCEPTED");
    assert_eq!(fixture.count("operations").await?, 2);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn idle_stops_only_after_slot_release_and_unknown_execution_keeps_its_slot()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let fixture = Fixture::new(10).await?;
    let created = fixture.create("idle-unknown").await.map_err(api_failure)?;
    let before = &created.body.resource;
    fixture.seed_observed_state(before.id, "RUNNING").await?;
    let execution = Uuid::new_v4();
    let operation = Uuid::new_v4();
    let mut tx = fixture.owner_transaction().await?;
    sqlx::query("INSERT INTO operations(id,tenant_id,project_id,instance_id,workspace_id,kind,request,actor_principal_id,request_id,deadline) VALUES($1,$2,$3,$4,$5,'EXECUTE','{}',$6,$7,clock_timestamp()+interval '5 minutes')")
        .bind(operation).bind(fixture.actor.tenant_id).bind(before.project_id).bind(before.id).bind(before.workspace_id).bind(fixture.actor.principal_id).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO executions(id,tenant_id,project_id,instance_id,operation_id,runtime_generation,launch_id,pod_uid,status,dispatch_attempt_id,dispatch_attempted_at,deadline,timeout_seconds,termination_status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'OUTCOME_UNKNOWN',$9,clock_timestamp()-interval '2 minutes',clock_timestamp()-interval '1 minute',60,'UNKNOWN')")
        .bind(execution).bind(fixture.actor.tenant_id).bind(before.project_id).bind(before.id).bind(operation).bind(before.runtime_generation).bind(Uuid::new_v4()).bind(Uuid::new_v4()).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    sqlx::query("UPDATE instances SET idle_timeout_seconds=1,last_activity_at=clock_timestamp()-interval '1 hour',slot_held=true,activity_kind='EXECUTION',activity_id=$3,activity_generation=runtime_generation,idle_since=NULL WHERE tenant_id=$1 AND id=$2")
        .bind(fixture.actor.tenant_id).bind(before.id).bind(execution).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(
        fixture
            .database
            .accept_due_stop(fixture.actor.tenant_id, before.id)
            .await
            .map_err(api_failure)?
            .is_none()
    );
    let mut tx = fixture.owner_transaction().await?;
    let unchanged: (String, bool, String) = sqlx::query_as(
        "SELECT status,slot_held,termination_status FROM executions WHERE tenant_id=$1 AND id=$2",
    )
    .bind(fixture.actor.tenant_id)
    .bind(execution)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(
        unchanged,
        ("OUTCOME_UNKNOWN".into(), true, "UNKNOWN".into())
    );
    // Only a separately confirmed termination releases the slot and starts idle.
    sqlx::query("UPDATE executions SET termination_status='CONFIRMED',slot_held=false WHERE tenant_id=$1 AND id=$2")
        .bind(fixture.actor.tenant_id).bind(execution).execute(&mut *tx).await?;
    sqlx::query("UPDATE instances SET slot_held=false,activity_kind=NULL,activity_id=NULL,activity_generation=NULL,idle_since=clock_timestamp()-interval '1 minute' WHERE tenant_id=$1 AND id=$2")
        .bind(fixture.actor.tenant_id).bind(before.id).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(
        fixture
            .database
            .accept_due_stop(fixture.actor.tenant_id, before.id)
            .await
            .map_err(api_failure)?
            .is_some()
    );
    let after = fixture
        .database
        .get_instance(&fixture.actor, before.id)
        .await
        .map_err(api_failure)?;
    assert_eq!(after.stop_reason.as_deref(), Some("IDLE"));
    assert!(after.compute_lease_expires_at > Utc::now());
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn future_lease_is_not_accepted_and_timer_migration_preserves_rls_and_worker_only_scan()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let fixture = Fixture::new(10).await?;
    let created = fixture.create("not-due").await.map_err(api_failure)?;
    let before = &created.body.resource;
    assert!(
        fixture
            .database
            .accept_due_stop(fixture.actor.tenant_id, before.id)
            .await
            .map_err(api_failure)?
            .is_none()
    );
    assert_eq!(fixture.count("operations").await?, 1);
    assert_eq!(fixture.count("audit_events").await?, 1);
    let forced: bool = sqlx::query_scalar("SELECT bool_and(relrowsecurity AND relforcerowsecurity) FROM pg_class WHERE relnamespace='public'::regnamespace AND relname=ANY(ARRAY['tenants','instances'])")
        .fetch_one(&fixture.owner).await?;
    assert!(forced);
    let no_context: (i64, i64) =
        sqlx::query_as("SELECT (SELECT count(*) FROM tenants),(SELECT count(*) FROM instances)")
            .fetch_one(&fixture.database.pool)
            .await?;
    assert_eq!(no_context, (0, 0));
    let direct = sqlx::query("SELECT * FROM instance_timers")
        .fetch_all(&fixture.database.pool)
        .await;
    require_pg_error(direct, "42501")?;
    let scan = sqlx::query("SELECT * FROM sandbox_due_instances(100)")
        .fetch_all(&fixture.database.pool)
        .await;
    require_pg_error(scan, "42501")?;
    let registered: chrono::DateTime<Utc> =
        sqlx::query_scalar("SELECT due_at FROM instance_timers WHERE instance_id=$1")
            .bind(before.id)
            .fetch_one(&fixture.owner)
            .await?;
    assert_eq!(registered, before.compute_lease_expires_at);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn incompatible_workspace_owner_rolls_back_the_safety_stop() -> anyhow::Result<()> {
    let _serial = support::serial().await;
    let fixture = Fixture::new(10).await?;
    let created = fixture
        .create("workspace-conflict")
        .await
        .map_err(api_failure)?;
    let before = &created.body.resource;
    let unrelated = Uuid::new_v4();
    let mut tx = fixture.owner_transaction().await?;
    sqlx::query("INSERT INTO operations(id,tenant_id,project_id,workspace_id,kind,request,actor_principal_id,request_id,deadline) VALUES($1,$2,$3,$4,'DELETE_WORKSPACE','{}',$5,$6,clock_timestamp()+interval '5 minutes')")
        .bind(unrelated).bind(fixture.actor.tenant_id).bind(before.project_id).bind(before.workspace_id).bind(fixture.actor.principal_id).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    sqlx::query("UPDATE workspaces SET active_operation_id=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(fixture.actor.tenant_id)
        .bind(before.workspace_id)
        .bind(unrelated)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    expire(&fixture, before.id).await?;
    let result = fixture
        .database
        .accept_due_stop(fixture.actor.tenant_id, before.id)
        .await;
    match result {
        Err(error) => assert_eq!(error.code, "WORKSPACE_RECONCILIATION_REQUIRED"),
        Ok(_) => anyhow::bail!("Incompatible workspace operation was incorrectly superseded"),
    }
    let unchanged = fixture
        .database
        .get_instance(&fixture.actor, before.id)
        .await
        .map_err(api_failure)?;
    assert_eq!(unchanged.desired_state, "RUNNING");
    assert_eq!(
        unchanged.active_operation_id,
        Some(created.body.operation.id)
    );
    assert!(unchanged.stop_accepted_at.is_none());
    let mut tx = fixture.owner_transaction().await?;
    let active_status: String =
        sqlx::query_scalar("SELECT status FROM operations WHERE tenant_id=$1 AND id=$2")
            .bind(fixture.actor.tenant_id)
            .bind(created.body.operation.id)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(active_status, "QUEUED");
    tx.commit().await?;
    assert_eq!(fixture.count("operations").await?, 2);
    assert_eq!(fixture.count("audit_events").await?, 1);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and TEST_WORKER_DATABASE_URL on the same disposable database"]
async fn blocked_first_hundred_cannot_starve_later_expiry_and_replicas_accept_one_stop()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let f = Fixture::new(110).await?;
    let parsed = url::Url::parse(&std::env::var("TEST_WORKER_DATABASE_URL")?)?;
    let expected = url::Url::parse(&std::env::var("TEST_DATABASE_URL")?)?;
    ensure!(
        parsed.path().ends_with("_test")
            && parsed.path() == expected.path()
            && parsed.host_str() == expected.host_str()
            && parsed.port_or_known_default() == expected.port_or_known_default()
            && parsed.username() == "sandbox_worker",
        "Fairness scanner must use the exact worker login on the fixture database"
    );
    sqlx::raw_sql(include_str!("../scripts/sql/worker-role.sql"))
        .execute(&f.owner)
        .await?;
    let scanner = Database::connect(parsed.as_str(), 8).await?;
    scanner.verify_runtime_role().await?;
    let outcome = async {
        let mut blocked = Vec::new();
        for n in 0..100 {
            let created = f.create(&format!("fair-blocked-{n}")).await.map_err(api_failure)?;
            let mut tx = f.owner_transaction().await?;
            let conflicting = Uuid::new_v4();
            sqlx::query("INSERT INTO operations(id,tenant_id,project_id,workspace_id,kind,request,actor_principal_id,request_id,deadline) VALUES($1,$2,$3,$4,'DELETE_WORKSPACE','{}',$5,$6,clock_timestamp()+interval '5 minutes')")
                .bind(conflicting).bind(f.actor.tenant_id).bind(created.body.resource.project_id)
                .bind(created.body.resource.workspace_id).bind(f.actor.principal_id)
                .bind(Uuid::new_v4()).execute(&mut *tx).await?;
            sqlx::query("UPDATE workspaces SET active_operation_id=$3 WHERE tenant_id=$1 AND id=$2")
                .bind(f.actor.tenant_id).bind(created.body.resource.workspace_id).bind(conflicting)
                .execute(&mut *tx).await?;
            sqlx::query("UPDATE instances SET compute_lease_started_at='0001-01-01T00:00:00Z',compute_lease_expires_at='0001-01-01T00:01:00Z' WHERE tenant_id=$1 AND id=$2")
                .bind(f.actor.tenant_id).bind(created.body.resource.id).execute(&mut *tx).await?;
            tx.commit().await?;
            blocked.push(created.body.resource.id);
        }
        let healthy = f.create("fair-later-healthy").await.map_err(api_failure)?;
        let mut tx = f.owner_transaction().await?;
        sqlx::query("UPDATE instances SET compute_lease_started_at='0002-01-01T00:00:00Z',compute_lease_expires_at='0002-01-01T00:01:00Z' WHERE tenant_id=$1 AND id=$2")
            .bind(f.actor.tenant_id).bind(healthy.body.resource.id).execute(&mut *tx).await?;
        let deadlines: Vec<(Uuid, chrono::DateTime<Utc>)> = sqlx::query_as("SELECT instance_id,due_at FROM instance_timers WHERE tenant_id=$1 ORDER BY instance_id")
            .bind(f.actor.tenant_id).fetch_all(&mut *tx).await?;
        tx.commit().await?;
        let first = scanner.due_instances().await.map_err(api_failure)?;
        ensure!(first.len() == 100 && first.iter().all(|(tenant,id)| *tenant==f.actor.tenant_id && blocked.contains(id)),
            "The real first bounded batch must consist of the hundred incompatible instances");
        for (tenant,id) in first {
            let error = scanner.accept_due_stop(tenant,id).await.err()
                .context("Conflicting workspace must retain the existing operation")?;
            ensure!(error.code == "WORKSPACE_RECONCILIATION_REQUIRED", "Expected real workspace contract rejection");
        }
        // No clock advancement, modified deadline, deleted routing row or reset
        // claim is used to make the healthy item visible to the next replica.
        let second = scanner.due_instances().await.map_err(api_failure)?;
        ensure!(second.contains(&(f.actor.tenant_id,healthy.body.resource.id)),
            "A later normal expiry must be selected behind a fully blocked first batch");
        let mut tx = f.owner_transaction().await?;
        let actual: Vec<(Uuid,chrono::DateTime<Utc>)> = sqlx::query_as("SELECT instance_id,due_at FROM instance_timers WHERE tenant_id=$1 ORDER BY instance_id")
            .bind(f.actor.tenant_id).fetch_all(&mut *tx).await?;
        ensure!(actual == deadlines, "Fair retry selection changed a real TTL/idle deadline");
        tx.commit().await?;
        let barrier = Arc::new(Barrier::new(12));
        let attempts=(0..12).map(|_| {
            let db=scanner.clone(); let barrier=barrier.clone(); let id=healthy.body.resource.id;
            let tenant=f.actor.tenant_id;
            async move { barrier.wait().await; db.accept_due_stop(tenant,id).await }
        });
        let mut accepted=Vec::new();
        for attempt in join_all(attempts).await {
            if let Some(id)=attempt.map_err(api_failure)? { accepted.push(id); }
        }
        ensure!(accepted.len()==1,"Concurrent replicas must accept exactly one safety STOP");
        let after=f.database.get_instance(&f.actor,healthy.body.resource.id).await.map_err(api_failure)?;
        ensure!(after.active_operation_id==Some(accepted[0]) && after.stop_reason.as_deref()==Some("LEASE_EXPIRED")
            && after.observed_state=="PENDING", "Expiry acceptance must retain physical termination obligations");
        let mut tx=f.owner_transaction().await?;
        let counts: (i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM operations WHERE tenant_id=$1 AND kind='STOP'),(SELECT count(*) FROM instances WHERE tenant_id=$1 AND desired_state='RUNNING' AND stop_accepted_at IS NULL)")
            .bind(f.actor.tenant_id).fetch_one(&mut *tx).await?;
        ensure!(counts==(1,100),"Fair acceptance duplicated a STOP or superseded a conflicting instance");
        tx.commit().await?;
        Ok::<(),anyhow::Error>(())
    }.await;
    scanner.pool.close().await;
    f.database.pool.close().await;
    f.owner.close().await;
    outcome
}
