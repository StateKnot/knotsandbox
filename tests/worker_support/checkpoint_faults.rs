//! A real PostgreSQL pre-COMMIT checkpoint failure. Holding domain_events blocks
//! the checkpoint read/insert before COMMIT. This is not a lost-ACK experiment.

use std::time::Duration;

use anyhow::{Context, ensure};
use sandbox_platform::worker::Worker;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::MockKube;
use crate::support::Fixture;

/// Uses and closes this fixture's dedicated worker pool. The caller retains the
/// owner/API fixture pools and closes those in its own final cleanup.
pub(crate) async fn verify_precommit_rollback(
    f: &Fixture,
    mock: &MockKube,
    operation: Uuid,
    worker: &Worker,
) -> anyhow::Result<()> {
    let mut holder = f.owner_transaction().await?;
    let prepared = async {
        let original_stage: String = sqlx::query_scalar(
            "SELECT stage FROM operations WHERE tenant_id=$1 AND id=$2 AND status='QUEUED' AND attempts=0 AND lease_token=0",
        )
        .bind(f.actor.tenant_id)
        .bind(operation)
        .fetch_one(&mut *holder)
        .await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *holder)
            .await?;
        sqlx::query("LOCK TABLE public.domain_events IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *holder)
            .await?;
        Ok::<_, anyhow::Error>((original_stage, pid))
    }
    .await;
    let (original_stage, holder_pid) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            holder.rollback().await?;
            return Err(error);
        }
    };
    let shutdown = CancellationToken::new();
    let mut task = tokio::spawn(worker.clone().run(shutdown.clone()));
    let mut joined = false;
    let outcome = async {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            ensure!(!task.is_finished(), "owned worker stopped before checkpoint fault");
            let blocked: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid WHERE a.datname=current_database() AND a.usename='sandbox_worker' AND l.locktype='relation' AND l.relation='public.domain_events'::regclass AND NOT l.granted AND $1=ANY(pg_blocking_pids(a.pid))",
            )
            .bind(holder_pid)
            .fetch_one(&f.owner)
            .await?;
            if mock.posts("CiliumNetworkPolicy")? == 1 && blocked > 0 {
                break;
            }
            ensure!(Instant::now() < deadline, "real checkpoint lock wait was not observed");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Stop new claims while keeping the fault lock live. The already-owned
        // turn and its durable defer both encounter the normal 3s lock timeout.
        // We do not alter worker timeouts, lease clocks or authorization.
        shutdown.cancel();
        match tokio::time::timeout(Duration::from_secs(12), &mut task).await {
            Ok(result) => {
                joined = true;
                result.context("owned pre-COMMIT worker task failed")??;
            }
            Err(error) => return Err(error).context("pre-COMMIT worker turn exceeded bound"),
        }
        ensure!(
            mock.posts("CiliumNetworkPolicy")? == 1
                && mock.posts("PersistentVolumeClaim")? == 0
                && mock.posts("Pod")? == 0,
            "uncommitted checkpoint must not create the next resource"
        );
        let policy_uid = {
            let state = mock
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("owned mock state poisoned"))?;
            let policies: Vec<_> = state
                .objects
                .values()
                .filter(|value| value["kind"] == "CiliumNetworkPolicy")
                .collect();
            ensure!(policies.len() == 1, "remote fixture must retain the created policy");
            policies[0]["metadata"]["uid"]
                .as_str()
                .context("created fixture policy UID")?
                .to_owned()
        };
        // The holder owns the ACCESS EXCLUSIVE lock itself, so this read does
        // not wait on our own lock. Reading through another pool would deadlock.
        let (resources, events, committed_uid): (i64, i64, bool) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM external_resources WHERE tenant_id=$1 AND operation_id=$2),(SELECT count(*) FROM domain_events WHERE tenant_id=$1 AND operation_id=$2 AND event_type='operation.progressed'),EXISTS(SELECT 1 FROM external_resources WHERE tenant_id=$1 AND operation_id=$2 AND provider_id=$3)",
        )
        .bind(f.actor.tenant_id)
        .bind(operation)
        .bind(&policy_uid)
        .fetch_one(&mut *holder)
        .await?;
        ensure!(
            resources == 0 && events == 0 && !committed_uid,
            "resource UID and checkpoint event must roll back together"
        );
        let (status, stage, attempts, token, ready): (String, String, i32, i64, bool) =
            sqlx::query_as(
                "SELECT o.status,o.stage,o.attempts,o.lease_token,(i.ready_generation IS NOT NULL OR i.ready_launch_id IS NOT NULL OR i.ready_pod_uid IS NOT NULL OR i.ready_cluster_epoch IS NOT NULL OR i.ready_observed_at IS NOT NULL) FROM operations o JOIN instances i ON i.tenant_id=o.tenant_id AND i.id=o.instance_id WHERE o.tenant_id=$1 AND o.id=$2",
            )
            .bind(f.actor.tenant_id)
            .bind(operation)
            .fetch_one(&mut *holder)
            .await?;
        // operation.waiting uses the same outbox and can also roll back under
        // this fault. Do not demand a fabricated WAITING receipt after failure.
        ensure!(
            status == "RUNNING" && stage == original_stage && attempts == 1 && token == 1 && !ready,
            "failed checkpoint must retain its original claimed state and no ready proof"
        );
        let (pending, allocated): (i64, i64) = sqlx::query_as(
            "SELECT sum(pending)::bigint,sum(allocated)::bigint FROM quota_accounts WHERE tenant_id=$1",
        )
        .bind(f.actor.tenant_id)
        .fetch_one(&mut *holder)
        .await?;
        ensure!(pending > 0 && allocated == 0, "uncertain create must retain pending quota");
        Ok::<_, anyhow::Error>(())
    }
    .await;

    shutdown.cancel();
    let drained = if joined {
        Ok(())
    } else {
        match tokio::time::timeout(Duration::from_secs(35), &mut task).await {
            Ok(result) => result
                .context("owned fault worker did not join")
                .and_then(|result| result),
            Err(error) => {
                task.abort();
                let _ = task.await;
                Err(error).context("owned fault worker exceeded its graceful drain")
            }
        }
    };
    // Execute every owned cleanup even if the assertions failed. Releasing the
    // fault only after the worker has settled prevents a late successful stage.
    let released = holder.rollback().await;
    let closed =
        tokio::time::timeout(Duration::from_secs(5), worker.engine.database.pool.close()).await;
    outcome?;
    drained?;
    released?;
    closed.context("owned fault worker pool failed to close")?;
    println!("WORKER_PRECOMMIT_CHECKPOINT_ROLLBACK_NO_NEXT_RESOURCE_VERIFIED");
    Ok(())
}
