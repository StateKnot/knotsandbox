//! PRIVATE faults for the new Bound read APIs themselves. The normal Pending
//! parent and early PV intent remain the only storage authority. No future
//! receipt, PV binding, host permit or signed-disk observation is fabricated.
use super::*;
use crate::restore::tests::admission::commit::CommitProxy;
use std::{sync::atomic::Ordering, time::Instant};

#[derive(Clone, Copy, Debug)]
enum Reader {
    Admission,
    Backup,
}
impl Reader {
    fn login(self) -> &'static str {
        match self {
            Self::Admission => "sandbox_admission",
            Self::Backup => "sandbox_backup",
        }
    }
}
#[derive(Clone, Copy, Debug)]
enum FaultMode {
    Delay,
    Lost,
}
struct ReadFailure {
    code: u16,
    message: String,
}
impl From<crate::admission::Denial> for ReadFailure {
    fn from(error: crate::admission::Denial) -> Self {
        Self {
            code: error.code,
            message: error.message.into(),
        }
    }
}
impl From<crate::error::ApiError> for ReadFailure {
    fn from(error: crate::error::ApiError) -> Self {
        Self {
            code: error.status.as_u16(),
            message: error.detail,
        }
    }
}

// This is the actual caller order: the sealed timer is created before the real
// locator GET. First and final API reads receive that same unreset attempt.
async fn read_pair(
    case: &SelectedCase<'_>,
    database: &Database,
    reader: Reader,
    node_hint: &str,
) -> anyhow::Result<Result<(), ReadFailure>> {
    let attempt = RawBoundAttempt::start();
    let hint = Box::pin(locate_selected_parent(case, node_hint)).await?;
    let result = match reader {
        Reader::Admission => {
            let service = RestoreAdmissionService {
                database: database.clone(),
                ..case.service.clone()
            };
            match service
                .prepare_raw_bound_admission(&attempt, case.t, case.r, &hint)
                .await
            {
                Ok(first) => service
                    .recheck_raw_bound_admission(&first)
                    .await
                    .map_err(ReadFailure::from),
                Err(error) => Err(error.into()),
            }
        }
        Reader::Backup => {
            match database
                .prepare_restore_bound_authority(
                    &attempt,
                    &case.source.f.backup,
                    case.claim,
                    case.r,
                    &hint,
                )
                .await
            {
                Ok(first) => database
                    .recheck_restore_bound_authority(&case.source.f.backup, case.claim, &first)
                    .await
                    .map_err(ReadFailure::from),
                Err(error) => Err(error.into()),
            }
        }
    };
    Ok(result)
}

// On an assertion/monitor error, delayed mode releases the barriers and lost
// mode closes the actual forwarding sockets without releasing a held ACK. The
// decision future is polled and awaited in this function, never detached.
struct ReleaseAcks<'a> {
    proxy: &'a CommitProxy,
    mode: FaultMode,
}
impl Drop for ReleaseAcks<'_> {
    fn drop(&mut self) {
        match self.mode {
            FaultMode::Delay => {
                self.proxy.first_ack.notify_one();
                self.proxy.final_ack.notify_one();
            }
            // Never release a held ACK on the lost-response path: racing that
            // notification with stop could forward the frame before FD close.
            FaultMode::Lost => self.proxy.stop.cancel(),
        }
    }
}
async fn renew(case: &SelectedCase<'_>) -> anyhow::Result<()> {
    ensure!(
        case.source
            .f
            .backup
            .heartbeat(case.claim)
            .await
            .map_err(api_failure)?,
        "only the actual current worker renews its normal claim before an independent Bound fault"
    );
    Ok(())
}
async fn shorten_lease(case: &SelectedCase<'_>) -> anyhow::Result<chrono::DateTime<Utc>> {
    let mut tx = case.source.f.base.f.owner_transaction().await?;
    let saved: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT lease_until FROM operations WHERE tenant_id=$1 AND id=$2 AND lease_owner=$3 AND lease_token=$4 AND status='RUNNING' AND lease_until>clock_timestamp() FOR UPDATE")
        .bind(case.t).bind(case.claim.operation_id).bind(case.source.f.backup.worker_id()).bind(case.claim.lease_token).fetch_one(&mut *tx).await?;
    let changed = sqlx::query("UPDATE operations SET lease_until=clock_timestamp()+interval '2 seconds' WHERE tenant_id=$1 AND id=$2 AND lease_owner=$3 AND lease_token=$4 AND status='RUNNING'")
        .bind(case.t).bind(case.claim.operation_id).bind(case.source.f.backup.worker_id()).bind(case.claim.lease_token).execute(&mut *tx).await?;
    ensure!(
        changed.rows_affected() == 1,
        "finite lease installed only for this actual claim"
    );
    tx.commit().await?;
    Ok(saved)
}
async fn restore_lease(
    case: &SelectedCase<'_>,
    saved: chrono::DateTime<Utc>,
) -> anyhow::Result<()> {
    let mut tx = case.source.f.base.f.owner_transaction().await?;
    let changed = sqlx::query("UPDATE operations SET lease_until=$5 WHERE tenant_id=$1 AND id=$2 AND lease_owner=$3 AND lease_token=$4 AND status='RUNNING' AND $5>clock_timestamp()")
        .bind(case.t).bind(case.claim.operation_id).bind(case.source.f.backup.worker_id()).bind(case.claim.lease_token).bind(saved).execute(&mut *tx).await?;
    ensure!(
        changed.rows_affected() == 1,
        "fixture restores its own still-finite original lease without changing owner/token/status"
    );
    tx.commit().await?;
    Ok(())
}
async fn unchanged_without_future(case: &SelectedCase<'_>) -> anyhow::Result<()> {
    absent_companion(case).await?;
    ensure!(
        case.w.reads(case.pvc_path)? == 1 && case.cloud.actions()?.is_empty(),
        "new Bound API fault reaches exactly its actual locator GET, no CSI/Node/cloud observations"
    );
    let pv_path = format!(
        "/api/v1/persistentvolumes/disk-{}",
        case.w.get(case.pvc_path)?["metadata"]["uid"]
            .as_str()
            .context("normal parent UID")?
    );
    ensure!(
        case.w.reads(&pv_path)? == 0,
        "reader fault never adopts a future PV"
    );
    Ok(())
}

async fn committed_backend_idle(
    case: &SelectedCase<'_>,
    reader: Reader,
    pid: i32,
) -> anyhow::Result<()> {
    // A normal owner has no pg_read_all_stats and cannot see another login's
    // state. This independent pool has the same authenticated reader identity;
    // PostgreSQL exposes its own role's backend state without any added grant.
    let observer = match reader {
        Reader::Admission => &case.service.database.pool,
        Reader::Backup => &case.source.f.backup.database.pool,
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let released: bool = tokio::time::timeout_at(deadline,sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND state='idle' AND xact_start IS NULL) AND NOT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND granted AND locktype IN('relation','transactionid'))").bind(pid).fetch_one(observer))
            .await.context("real Bound COMMIT lock/transaction monitor deadline")??;
        ensure!(
            tokio::time::Instant::now() < deadline,
            "real Bound COMMIT observer cannot certify a late response"
        );
        if released {
            return Ok(());
        }
        // CommandComplete may be seen before the idle state is published.
        // Wait only within the original observer window for the actual fact.
        tokio::time::timeout_at(deadline, tokio::time::sleep(Duration::from_millis(25)))
            .await
            .context("actual Bound backend did not reach idle with locks released")?;
    }
}
async fn acknowledgements(
    case: &SelectedCase<'_>,
    node_hint: &str,
    reader: Reader,
    ordinal: usize,
    mode: FaultMode,
) -> anyhow::Result<()> {
    Box::pin(renew(case)).await?;
    case.configure(0, Fault::None)?;
    let (mut proxy, database) = match reader {
        Reader::Admission => CommitProxy::connect_bound_admission(ordinal).await?,
        Reader::Backup => CommitProxy::connect_bound_backup(ordinal).await?,
    };
    let (pid, current, session): (i32, String, String) =
        sqlx::query_as("SELECT pg_backend_pid(),current_user::text,session_user::text")
            .fetch_one(&database.pool)
            .await?;
    let started = Instant::now();
    let mut saved = None;
    let outcome = Box::pin(async {
        ensure!(
            current == reader.login() && session == reader.login(),
            "actual distinct Bound reader login, no owner or SET ROLE authority"
        );
        if matches!(mode, FaultMode::Delay) {
            saved = Some(Box::pin(shorten_lease(case)).await?);
        }
    let (decision, observed) = tokio::join!(
        tokio::time::timeout(
            Duration::from_secs(10),
            Box::pin(read_pair(case, &database, reader, node_hint))
        ),
        Box::pin(async {
            let _release = ReleaseAcks {
                proxy: &proxy,
                mode,
            };
            let barrier = if ordinal == 1 {
                &proxy.first
            } else {
                &proxy.final_commit
            };
            tokio::time::timeout(Duration::from_secs(3), barrier.notified())
                .await
                .context("new Bound API did not reach the targeted actual backend COMMIT")?;
            ensure!(
                proxy.completed.load(Ordering::SeqCst) == ordinal,
                "new Bound first/final backend COMMIT ordinal is exact"
            );
            Box::pin(committed_backend_idle(case, reader, pid)).await?;
            match mode {
                FaultMode::Delay => {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    let mut tx = case.source.f.base.f.owner_transaction().await?;
                    let expired: bool = sqlx::query_scalar("SELECT lease_until<=clock_timestamp() FROM operations WHERE tenant_id=$1 AND id=$2 AND lease_owner=$3 AND lease_token=$4")
                        .bind(case.t).bind(case.claim.operation_id).bind(case.source.f.backup.worker_id()).bind(case.claim.lease_token).fetch_one(&mut *tx).await?;
                    tx.commit().await?;
                    ensure!(
                        expired,
                        "held new Bound ACK crosses the actual finite lease, not a statement or lock timeout"
                    );
                }
                FaultMode::Lost => {
                    let mut tx = case.source.f.base.f.owner_transaction().await?;
                    let current: bool = sqlx::query_scalar("SELECT lease_until>clock_timestamp() FROM operations WHERE tenant_id=$1 AND id=$2 AND lease_owner=$3 AND lease_token=$4")
                        .bind(case.t).bind(case.claim.operation_id).bind(case.source.f.backup.worker_id()).bind(case.claim.lease_token).fetch_one(&mut *tx).await?;
                    tx.commit().await?;
                    ensure!(
                        current,
                        "new Bound lost response occurs while actual claim remains current"
                    );
                    // Cancellation drops the actual forwarding socket halves
                    // after backend CommandComplete, before that ACK is sent.
                    proxy.stop.cancel();
                }
            }
            Ok::<_, anyhow::Error>(())
        })
    );
    observed?;
    let result =
        decision.context("new Bound API watchdog expired; not a verified authority denial")??;
    let failure = result
        .err()
        .context("new Bound response fault must not return an authority token/success")?;
    match mode {
        FaultMode::Delay => ensure!(
            failure.code == 403
                && failure.message
                    == "Raw bound authority expired during read, observation or COMMIT acknowledgement",
            "new Bound delayed ACK exact budget category, not a SQL/lock/dependency failure"
        ),
        FaultMode::Lost => ensure!(
            failure.code == 503 && failure.message == "Restore admission dependency unavailable",
            "new Bound lost backend ACK exact dependency category, no durable token fallback"
        ),
    }
    ensure!(
        started.elapsed() < Duration::from_secs(10)
            && proxy.completed.load(Ordering::SeqCst) == ordinal,
        "new Bound fault stays inside original unreset ten-second attempt and exact first/final COMMIT count"
    );
        Ok::<_, anyhow::Error>(())
    }).await;
    // All business and watcher futures finish before closing the exact pool;
    // owner join and backend PID absence are obtained even after an assertion.
    let cleanup = proxy
        .finish_owner(&database, &case.source.f.base.f.owner, pid)
        .await;
    let restored = if let Some(saved) = saved {
        Box::pin(restore_lease(case, saved)).await
    } else {
        Ok(())
    };
    let unchanged = Box::pin(unchanged_without_future(case)).await;
    outcome?;
    cleanup?;
    restored?;
    unchanged?;
    eprintln!(
        "VERIFIED private raw-bound {reader:?} {mode:?} COMMIT ordinal {ordinal}: actual backend committed/locks released, distinct login and new API exact denial, owned proxy joined/PID absent, unchanged whole facts and zero future identities; not a disk or VM proof"
    );
    Ok(())
}

// Test only mutable source permission; the original Node/enrollment/owner
// topology receipts and every storage intent/binding remain untouched.
async fn lockwait_revocation(
    case: &SelectedCase<'_>,
    node_hint: &str,
    reader: Reader,
    final_read: bool,
) -> anyhow::Result<()> {
    Box::pin(renew(case)).await?;
    case.configure(0, Fault::None)?;
    let attempt = RawBoundAttempt::start();
    let hint = Box::pin(locate_selected_parent(case, node_hint)).await?;
    let database = match reader {
        Reader::Admission => &case.service.database,
        Reader::Backup => &case.source.f.backup.database,
    };
    let first = if final_read {
        Some(match reader {
            Reader::Admission => case
                .service
                .prepare_raw_bound_admission(&attempt, case.t, case.r, &hint)
                .await
                .map_err(|e| anyhow::anyhow!(e.message))?,
            Reader::Backup => database
                .prepare_restore_bound_authority(
                    &attempt,
                    &case.source.f.backup,
                    case.claim,
                    case.r,
                    &hint,
                )
                .await
                .map_err(api_failure)?,
        })
    } else {
        None
    };
    let mut blocker = case.source.f.base.f.owner_transaction().await?;
    sqlx::query("SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(case.t)
        .bind(case.job.record.workspace_id)
        .fetch_one(&mut *blocker)
        .await?;
    let grant: Uuid = sqlx::query_scalar("SELECT g.id FROM grants g JOIN operations o ON o.tenant_id=g.tenant_id AND o.actor_principal_id=g.principal_id WHERE o.tenant_id=$1 AND o.id=$2 AND g.project_id=$3 AND g.action='backups:restore' AND g.enabled AND g.revoked_at IS NULL")
        .bind(case.t).bind(case.claim.operation_id).bind(case.job.record.source_project_id).fetch_one(&mut *blocker).await?;
    let changed =
        sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND id=$2 AND enabled")
            .bind(case.t)
            .bind(grant)
            .execute(&mut *blocker)
            .await?;
    ensure!(
        changed.rows_affected() == 1,
        "only this actual fixture source permission is withdrawn"
    );
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    let started = Instant::now();
    let (decision, committed) = tokio::join!(
        tokio::time::timeout(
            Duration::from_secs(10),
            Box::pin(async {
                match (reader, first.as_ref()) {
                    (Reader::Admission, Some(first)) => case
                        .service
                        .recheck_raw_bound_admission(first)
                        .await
                        .map_err(ReadFailure::from),
                    (Reader::Admission, None) => case
                        .service
                        .prepare_raw_bound_admission(&attempt, case.t, case.r, &hint)
                        .await
                        .map(|_| ())
                        .map_err(ReadFailure::from),
                    (Reader::Backup, Some(first)) => database
                        .recheck_restore_bound_authority(&case.source.f.backup, case.claim, first)
                        .await
                        .map_err(ReadFailure::from),
                    (Reader::Backup, None) => database
                        .prepare_restore_bound_authority(
                            &attempt,
                            &case.source.f.backup,
                            case.claim,
                            case.r,
                            &hint,
                        )
                        .await
                        .map(|_| ())
                        .map_err(ReadFailure::from),
                }
            })
        ),
        Box::pin(async {
            let observed=async {
                let deadline=tokio::time::Instant::now()+Duration::from_secs(2);
                loop {
                    let blocked:bool=tokio::time::timeout_at(deadline,sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND usename=$1 AND $2=ANY(pg_blocking_pids(pid)))").bind(reader.login()).bind(blocker_pid).fetch_one(&case.source.f.base.f.owner)).await.context("new Bound real lock monitor exceeded original two-second window")??;
                    ensure!(tokio::time::Instant::now()<deadline,"new Bound lock monitor cannot certify a late response");
                    if blocked { break; }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    ensure!(tokio::time::Instant::now()<deadline,"new Bound reader did not reach this exact workspace lock before three-second DB lock timeout");
                }
                Ok::<_,anyhow::Error>(())
            }.await;
            if observed.is_ok() {
                blocker.commit().await?;
            } else {
                blocker.rollback().await?;
            }
            observed
        })
    );
    // Fixture maintenance restores only enabled, with monotonic grant versions;
    // never undo a principal/epoch/claim or write a topology/certification row.
    let restored = async {
        let mut tx = case.source.f.base.f.owner_transaction().await?;
        sqlx::query("UPDATE grants SET enabled=true WHERE tenant_id=$1 AND id=$2 AND NOT enabled")
            .bind(case.t)
            .bind(grant)
            .execute(&mut *tx)
            .await?;
        let enabled: bool =
            sqlx::query_scalar("SELECT enabled FROM grants WHERE tenant_id=$1 AND id=$2")
                .bind(case.t)
                .bind(grant)
                .fetch_one(&mut *tx)
                .await?;
        ensure!(
            enabled,
            "fixture source permission restored without changing scope"
        );
        tx.commit().await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let unchanged = Box::pin(unchanged_without_future(case)).await;
    committed?;
    let result =
        decision.context("new Bound post-lock watchdog expired; not a SQL authority denial")?;
    let failure = result
        .err()
        .context("new Bound read must deny committed source revocation after lock wait")?;
    ensure!(
        failure.code == 403 && failure.message == "Current raw bound authority unavailable",
        "new Bound first/final post-lock denial comes from current six-scope statement, not lock timeout or old selected API"
    );
    ensure!(
        started.elapsed() < Duration::from_secs(3),
        "new Bound actual workspace wait releases before unchanged DB three-second lock timeout"
    );
    restored?;
    unchanged?;
    eprintln!(
        "VERIFIED private raw-bound {reader:?} final={final_read}: pg_blocking_pids observes real owner workspace lock, committed source withdrawal then exact new reader403, both futures/transaction finished, unchanged whole facts/zero future identities"
    );
    Ok(())
}

pub(super) async fn run(case: &SelectedCase<'_>, node_hint: &str) -> anyhow::Result<()> {
    for reader in [Reader::Admission, Reader::Backup] {
        for ordinal in [1, 2] {
            for mode in [FaultMode::Delay, FaultMode::Lost] {
                Box::pin(acknowledgements(case, node_hint, reader, ordinal, mode)).await?;
            }
        }
        for final_read in [false, true] {
            Box::pin(lockwait_revocation(case, node_hint, reader, final_read)).await?;
        }
    }
    Box::pin(renew(case)).await?;
    Box::pin(pair(case, node_hint)).await?;
    absent_companion(case).await?;
    eprintln!(
        "VERIFIED private raw-bound new APIs: eight first/final delayed/lost backend COMMIT ACK trials plus four observed real lock-wait source withdrawals; original attempt before locator GET, independent admission/current backup login, no new PV/disk/permit/proof facts; not CSI media or production activation"
    );
    Ok(())
}
