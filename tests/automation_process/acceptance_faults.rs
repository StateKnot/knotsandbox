//! Recoverable acceptance faults at the normal execution transaction seam.
//! Quota timeout and final safe-mode rejection retain the genuine original intent.
use super::*;

#[derive(Clone, Copy)]
enum AcceptanceFault {
    QuotaTimeout,
    FinalSafeMode,
}
impl AcceptanceFault {
    fn stage(self) -> &'static str {
        match self {
            Self::QuotaTimeout => "ACCEPT_QUOTA_TRANSIENT",
            Self::FinalSafeMode => "ACCEPT_FINAL_SAFE_MODE_FENCE",
        }
    }
}

async fn safe_mode(f: &Fixture, enabled: bool) -> anyhow::Result<()> {
    let deadline = Instant::now() + OBSERVE;
    let changed = tokio::time::timeout_at(
        deadline,
        sqlx::query("UPDATE platform_configuration SET safe_mode=$1 WHERE singleton")
            .bind(enabled)
            .execute(&f.owner),
    )
    .await
    .context("Disposable operator safe-mode fixture exceeded original bound")??;
    ensure!(
        Instant::now() < deadline && changed.rows_affected() == 1,
        "Operator safe-mode mutation ACK was late or singleton missing"
    );
    Ok(())
}

async fn queue_after_finish(f: &Fixture, automation: Uuid) -> anyhow::Result<Value> {
    let deadline = Instant::now() + OBSERVE;
    let value = tokio::time::timeout_at(deadline, async {
        let mut tx = f.owner.begin().await?;
        sqlx::query("SET TRANSACTION READ ONLY").execute(&mut *tx).await?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(f.actor.tenant_id.to_string()).execute(&mut *tx).await?;
        let value: Value = sqlx::query_scalar("SELECT jsonb_build_object('queue',to_jsonb(c),'database_now',clock_timestamp()) FROM automation_claims c WHERE c.tenant_id=$1 AND c.automation_id=$2")
            .bind(f.actor.tenant_id).bind(automation).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok::<_, anyhow::Error>(value)
    }).await.context("Independent normal finish queue observation exceeded original bound")??;
    ensure!(
        Instant::now() < deadline,
        "Queue observer COMMIT ACK was late"
    );
    Ok(value)
}

async fn blocked_accept_deadline(monitor: &Database, blocker: i32) -> anyhow::Result<Instant> {
    // Translate the actual blocked SQL statement's server age to a conservative
    // monotonic bound. Safe-mode mutation and lock-release ACK must precede the
    // existing three-second lock timeout, including snapshot/observer latency.
    let observed_at = Instant::now();
    let observation_deadline = observed_at + OBSERVE;
    let rows: Vec<(DateTime<Utc>, DateTime<Utc>)> = tokio::time::timeout_at(observation_deadline,
        sqlx::query_as("SELECT a.query_start,clock_timestamp() FROM pg_stat_activity a WHERE a.datname=current_database() AND a.usename=current_user AND a.backend_type='client backend' AND a.application_name LIKE 'sbx1.automation.%' AND $1=ANY(pg_blocking_pids(a.pid)) AND a.query=$2")
            .bind(blocker)
            .bind("SELECT id,project_id,dimension,limit_value,pending,allocated FROM quota_accounts WHERE tenant_id=$1 AND (project_id=$2 OR project_id IS NULL) ORDER BY id FOR UPDATE")
            .fetch_all(&monitor.pool)).await
        .context("Actual blocked acceptance statement age observation exceeded original bound")??;
    ensure!(
        Instant::now() < observation_deadline && rows.len() == 1,
        "Safe-mode trial must observe exactly one actual owned reserve_quota statement and its timely ACK"
    );
    let age = (rows[0].1 - rows[0].0).to_std()?;
    let remaining = Duration::from_secs(3)
        .checked_sub(age)
        .context("Acceptance statement already consumed its original lock-timeout window")?;
    Ok(observed_at + remaining)
}

async fn trial(
    owner: &Database,
    monitor: &Database,
    f: &Fixture,
    url: &str,
    pod: Uuid,
    mode: AcceptanceFault,
) -> anyhow::Result<()> {
    println!("AUTOMATION_PROCESS_STEP {} START", mode.stage());
    let baseline = sessions(&monitor.pool, None).await?;
    ensure!(
        baseline.len() == 1,
        "Acceptance trial must own the only automation process"
    );
    let mut owned = Owned::empty();
    let mut quota_lock = None;
    let mut safe_changed = false;
    let outcome = async {
        let identity = start_ready(&mut owned, monitor, &baseline, url, pod).await?;
        let automation = create_execute(f).await?;
        let deadline = Instant::now() + Duration::from_secs(15);
        quota_lock = Some(tokio::time::timeout_at(deadline, owner.pool.begin()).await
            .context("Acceptance blocker BEGIN exceeded original observer bound")??);
        let tx = quota_lock.as_mut().context("Owned quota blocker missing")?;
        tokio::time::timeout_at(deadline,
            sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
                .bind(f.actor.tenant_id.to_string()).execute(&mut **tx)).await
                .context("Quota blocker tenant configuration exceeded original bound")??;
        let blocker: i32 = tokio::time::timeout_at(deadline,
            sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut **tx)).await
            .context("Quota blocker physical identity query exceeded original bound")??;
        let accounts: Vec<Uuid> = tokio::time::timeout_at(deadline,
            sqlx::query_scalar("SELECT id FROM quota_accounts WHERE tenant_id=$1 AND dimension='EXECUTIONS' ORDER BY id FOR UPDATE")
                .bind(f.actor.tenant_id).fetch_all(&mut **tx)).await
                .context("Quota blocker row acquisition exceeded original observer bound")??;
        ensure!(accounts.len() == 2, "Only the fixture's exact tenant and project execution accounts may be locked");
        // Prepare does not acquire these accounts; the real accept transaction
        // has inserted operation/execution and is blocked in normal reserve_quota.
        let (before, original_accept_deadline) = loop {
            ensure!(owned.child()?.try_wait()?.is_none(), "Acceptance worker exited before real quota blocking");
            let rows = tokio::time::timeout_at(deadline, sessions(&monitor.pool, Some(blocker))).await
                .context("Real quota-blocked acceptor was not observed")??;
            let actual = child_backends(&rows, &baseline);
            if actual.values().any(|(_, blocked, _)| *blocked) {
                ensure!(process_identity(&actual, pod)? == identity, "Quota-blocked acceptor changed process identity");
                let original_accept_deadline = if matches!(mode, AcceptanceFault::FinalSafeMode) {
                    Some(blocked_accept_deadline(monitor, blocker).await?)
                } else { None };
                let value = tokio::time::timeout_at(deadline, snapshot(f, automation)).await
                    .context("Genuine prepared intent observation exceeded original bound")??;
                ensure!(value["status"] == "DISPATCHING" && value["failure_code"].is_null()
                    && value["operations"] == 0 && value["executions"] == 0 && value["idempotency"] == 0,
                    "Real quota-blocked acceptance must still have only its committed original intent");
                break (value, original_accept_deadline);
            }
            ensure!(Instant::now() < deadline, "Quota blocking observation ACK was late");
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        if matches!(mode, AcceptanceFault::FinalSafeMode) {
            // Set after actual uncommitted operation INSERT, so only the
            // deferred normal final SQL fence should reject the attempted COMMIT.
            safe_changed = true;
            let release_deadline = (Instant::now() + LOCK_WINDOW).min(original_accept_deadline
                .context("Original accept statement deadline is missing")?);
            ensure!(Instant::now() < release_deadline, "Genuine reserve_quota statement's original lock window already elapsed");
            tokio::time::timeout_at(release_deadline, safe_mode(f, true)).await
                .context("Final-fence operator change exceeded original release window")??;
            tokio::time::timeout_at(release_deadline, rollback_lock(&mut quota_lock)).await
                .context("Final-fence quota lock release exceeded original window")??;
            ensure!(Instant::now() < release_deadline, "Final-fence quota ROLLBACK ACK was late");
        }
        let probe = client()?;
        let address = owned.address.context("Acceptance worker health address missing")?;
        let failure_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            ensure!(owned.child()?.try_wait()?.is_none(), "Normal acceptance dependency/fence error incorrectly killed the real process");
            let value = tokio::time::timeout_at(failure_deadline, snapshot(f, automation)).await
                .context("Acceptance refusal state was not observed within original bound")??;
            ensure!(value["immutable"] == before["immutable"] && value["run_count"] == 1
                && value["emitted_runs"] == 1 && value["operations"] == 0 && value["executions"] == 0
                && value["idempotency"] == 0 && value["held_activity"] == 0 && value["execution_reservations"] == 0,
                "Refused accept transaction must rollback every operation/resource/slot/quota mutation without changing immutable intent");
            let recorded = match mode {
                AcceptanceFault::QuotaTimeout => value["status"] == "OUTCOME_UNKNOWN" && value["failure_code"] == "DEPENDENCY_UNAVAILABLE",
                AcceptanceFault::FinalSafeMode => (value["status"] == "OUTCOME_UNKNOWN" && value["failure_code"] == "AUTOMATION_FENCE_CHANGED")
                    || (value["status"] == "DISPATCHING" && value["failure_code"].is_null()),
            };
            let response = probe.get(format!("http://{address}/health/ready")).send().await?;
            if recorded && response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE {
                // A DISPATCHING snapshot alone is insufficient in SafeMode:
                // the real acceptor must also no longer wait for quota and
                // actual finish must release its routing lease normally.
                let queue = queue_after_finish(f, automation).await?;
                if queue["queue"]["lease_owner"].is_null() && queue["queue"]["lease_until"].is_null() { break; }
            }
            ensure!(Instant::now() < failure_deadline, "Acceptance refusal observer ACK was late");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        println!("AUTOMATION_PROCESS_STEP {} UNKNOWN_ROLLBACK_ALIVE_READY_503", mode.stage());
        // Timeout mode deliberately waited for the original runtime 3-second
        // lock timeout; its blocker now releases without changing production settings.
        rollback_lock(&mut quota_lock).await?;
        if safe_changed { safe_mode(f, false).await?; safe_changed = false; }
        let queue = queue_after_finish(f, automation).await?;
        let eligible: DateTime<Utc> = serde_json::from_value(queue["queue"]["eligible_at"].clone())?;
        let resumed_deadline = Instant::now() + TAKEOVER;
        loop {
            ensure!(owned.child()?.try_wait()?.is_none(), "Acceptance worker exited during original-intent reconciliation");
            let value = tokio::time::timeout_at(resumed_deadline, snapshot(f, automation)).await
                .context("Same-process original-intent recovery exceeded overall observer bound")??;
            ensure!(Instant::now() < resumed_deadline && value["immutable"] == before["immutable"]
                && value["run_count"] == 1 && value["emitted_runs"] == 1,
                "Same-process recovery returned a late ACK or replaced its durable original intent");
            let database_now: DateTime<Utc> = serde_json::from_value(value["database_now"].clone())?;
            if value["status"] == "SUBMITTED" {
                ensure!(database_now >= eligible && value["operations"] == 1 && value["executions"] == 1
                    && value["idempotency"] == 1 && value["held_execution"] == 1 && value["held_activity"] == 1
                    && value["execution_reservations"] == 2 && value["lease_token"].as_i64() > before["lease_token"].as_i64(),
                    "Normal queue eligibility must resume the exact original request once and retain live activity");
                break;
            }
            ensure!(value["status"] != "FAILED" && value["failure_code"] != "INTERNAL_ERROR"
                && value["operations"] == 0 && value["executions"] == 0,
                "Normal retryable acceptance refusal became a permanent failure or duplicate acceptance");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        ensure!(process_identity(&child_backends(&sessions(&monitor.pool, None).await?, &baseline), pod)? == identity,
            "Recoverable acceptance replaced or restarted the real process");
        let ready = probe.get(format!("http://{address}/health/ready")).send().await?;
        ensure!(ready.status() == reqwest::StatusCode::NO_CONTENT, "Successful genuine reconciliation did not recover readiness");
        let pid = owned.child()?.id().context("Owned accepting process missing")?;
        kill(Pid::from_raw(i32::try_from(pid)?), Signal::SIGTERM)?;
        returned_exit(&mut owned, true).await?;
        require_absent(&monitor.pool, &baseline).await?;
        let final_value = snapshot(f, automation).await?;
        ensure!(final_value["immutable"] == before["immutable"] && final_value["status"] == "SUBMITTED"
            && final_value["operations"] == 1 && final_value["executions"] == 1 && final_value["held_execution"] == 1
            && final_value["held_activity"] == 1 && final_value["execution_reservations"] == 2,
            "Successful drain released guest activity or changed durable original acceptance");
        println!("AUTOMATION_PROCESS_STEP {} SAME_PROCESS_ORIGINAL_INTENT_EXACTLY_ONCE", mode.stage());
        Ok::<_, anyhow::Error>(())
    }.await;
    let lock_cleanup = rollback_lock(&mut quota_lock).await;
    let mode_cleanup = if safe_changed {
        safe_mode(f, false).await
    } else {
        Ok(())
    };
    let process_cleanup = owned.cleanup(outcome.is_err()).await;
    let absence = require_absent(&monitor.pool, &baseline).await;
    outcome?;
    lock_cleanup?;
    mode_cleanup?;
    absence?;
    let (out, err) = process_cleanup?;
    let stdout = std::str::from_utf8(&out)?;
    let code = match mode {
        AcceptanceFault::QuotaTimeout => "DEPENDENCY_UNAVAILABLE",
        AcceptanceFault::FinalSafeMode => "AUTOMATION_FENCE_CHANGED",
    };
    ensure!(
        stdout.contains(code)
            && stdout.matches("database connection pool drained").count() == 1
            && !stdout.contains(PRIVATE_MARKER)
            && err.is_empty(),
        "Actual recoverable error classification, confidentiality or single awaited drain was lost"
    );
    if matches!(mode, AcceptanceFault::FinalSafeMode) {
        ensure!(
            stdout.contains("P4090"),
            "Final-fence case must retain the actual SQL P4090 provenance"
        );
    }
    println!("AUTOMATION_PROCESS_STEP {} OUTPUT_JOINED", mode.stage());
    Ok(())
}

pub(super) async fn verify(
    owner: &Database,
    monitor: &Database,
    url: &str,
    pod: Uuid,
) -> anyhow::Result<()> {
    for mode in [
        AcceptanceFault::QuotaTimeout,
        AcceptanceFault::FinalSafeMode,
    ] {
        let f = Fixture::new(10).await?;
        let outcome = trial(owner, monitor, &f, url, pod, mode).await;
        f.database.pool.close().await;
        f.owner.close().await;
        outcome?;
    }
    Ok(())
}
