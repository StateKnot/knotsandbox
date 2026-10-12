//! Real automation process fault supervision through normal database seams.
//! The existing ignored process test owns these trials and their awaited cleanup.
//! Run and intent creation use the public application API and natural leases.
use super::*;
#[path = "acceptance_faults.rs"]
mod acceptance;
#[allow(dead_code)]
#[path = "../support/mod.rs"]
mod support;

use sandbox_platform::{
    auth::VerifiedIdentity,
    automation::{AutomationAction, AutomationTrigger, CreateAutomation},
    model::{CreateExecution, ExecutionTimeoutPolicy},
};
use serde_json::Value;
use support::Fixture;

const TAKEOVER: Duration = Duration::from_secs(45);
const PRIVATE_MARKER: &str = "AUTOMATION_PRIVATE_RUNTIME_PERMISSION_MARKER";

#[derive(Clone, Copy)]
enum Fault {
    Claim,
    ExecutionInsert,
}
impl Fault {
    fn revoke(self) -> &'static str {
        match self {
            Self::Claim => {
                "REVOKE EXECUTE ON FUNCTION sandbox_claim_automation(text) FROM sandbox_automation"
            }
            Self::ExecutionInsert => "REVOKE INSERT ON executions FROM sandbox_automation",
        }
    }
    fn restore(self) -> &'static str {
        match self {
            Self::Claim => {
                "GRANT EXECUTE ON FUNCTION sandbox_claim_automation(text) TO sandbox_automation"
            }
            Self::ExecutionInsert => "GRANT INSERT ON executions TO sandbox_automation",
        }
    }
    fn stage(self) -> &'static str {
        match self {
            Self::Claim => "RUNTIME_CLAIM_PERMISSION",
            Self::ExecutionInsert => "RUNTIME_EXECUTION_PERMISSION",
        }
    }
}

struct Owned {
    child: Option<Child>,
    stdout: Option<OutputReader>,
    stderr: Option<OutputReader>,
    address: Option<std::net::SocketAddr>,
}
impl Owned {
    fn empty() -> Self {
        Self {
            child: None,
            stdout: None,
            stderr: None,
            address: None,
        }
    }
    fn child(&mut self) -> anyhow::Result<&mut Child> {
        self.child
            .as_mut()
            .context("Owned fault process is missing")
    }
    async fn cleanup(&mut self, failed: bool) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        // Evaluate and await every cleanup before propagating any one failure.
        let child = cleanup_child(&mut self.child, failed).await;
        let stdout = finish_reader(&mut self.stdout).await;
        let stderr = finish_reader(&mut self.stderr).await;
        child?;
        Ok((stdout?, stderr?))
    }
}

fn client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .no_proxy()
        .pool_max_idle_per_host(0)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(250))
        .build()?)
}

async fn start_ready(
    owned: &mut Owned,
    monitor: &Database,
    baseline: &Backends,
    url: &str,
    pod: Uuid,
) -> anyhow::Result<Uuid> {
    let reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = reservation.local_addr()?;
    drop(reservation);
    owned.address = Some(address);
    let mut command = Command::new(env!("CARGO_BIN_EXE_sandbox-automation"));
    command
        .env_clear()
        .env("RUST_LOG", "sandbox_platform=info,sandbox_automation=info")
        .env("SANDBOX_AUTOMATION_DATABASE_URL", url)
        .env("SANDBOX_PROCESS_POD_UID", pod.to_string())
        .args([
            "--db-max-connections",
            "4",
            "--health-listen",
            &address.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    owned.child = Some(
        command
            .spawn()
            .context("Cannot start actual fault worker")?,
    );
    let child = owned.child()?;
    let out = child.stdout.take().context("Owned fault stdout missing")?;
    let err = child.stderr.take().context("Owned fault stderr missing")?;
    owned.stdout = Some(tokio::spawn(bounded_output(out)));
    owned.stderr = Some(tokio::spawn(bounded_output(err)));
    let probe = client()?;
    let deadline = Instant::now() + READY;
    loop {
        ensure!(
            owned.child()?.try_wait()?.is_none(),
            "Fault worker exited before readiness"
        );
        let ready = probe
            .get(format!("http://{address}/health/ready"))
            .send()
            .await
            .is_ok_and(|r| r.status() == reqwest::StatusCode::NO_CONTENT);
        ensure!(
            Instant::now() < deadline,
            "Fault worker readiness exceeded its original bound"
        );
        if ready {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    process_identity(
        &child_backends(&sessions(&monitor.pool, None).await?, baseline),
        pod,
    )
}

async fn returned_exit(owned: &mut Owned, success: bool) -> anyhow::Result<()> {
    let deadline = Instant::now() + EXIT;
    let status = tokio::time::timeout_at(deadline, owned.child()?.wait())
        .await
        .context("Owned runtime-fault worker did not exit within original bound")??;
    ensure!(
        Instant::now() < deadline && status.success() == success,
        "Owned runtime-fault worker did not preserve its intended exit"
    );
    let address = owned.address.context("Owned health address missing")?;
    let probe = client()?;
    ensure!(
        probe
            .get(format!("http://{address}/health/live"))
            .send()
            .await
            .is_err(),
        "Exited fault worker still serves its health listener"
    );
    let reservation = std::net::TcpListener::bind(address)
        .context("Exited worker did not release its exact health socket")?;
    ensure!(
        reservation.local_addr()? == address,
        "Exact health socket absence check changed address"
    );
    Ok(())
}

async fn permission(pool: &PgPool, sql: &str) -> anyhow::Result<()> {
    let deadline = Instant::now() + OBSERVE;
    tokio::time::timeout_at(deadline, sqlx::query(sql).execute(pool))
        .await
        .context("Disposable fixture privilege mutation exceeded original bound")??;
    ensure!(Instant::now() < deadline, "Privilege mutation ACK was late");
    Ok(())
}

async fn health_denied(owned: &mut Owned) -> anyhow::Result<()> {
    let address = owned
        .address
        .context("Owned fault health address missing")?;
    let response = client()?
        .get(format!("http://{address}/health/ready"))
        .send()
        .await?;
    ensure!(
        response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "Runtime permission revocation must fail readiness while the real claim is blocked"
    );
    ensure!(
        owned.child()?.try_wait()?.is_none(),
        "Blocked real worker must still be alive during readiness refusal"
    );
    Ok(())
}

async fn snapshot(f: &Fixture, automation: Uuid) -> anyhow::Result<Value> {
    let deadline = Instant::now() + OBSERVE;
    let result = tokio::time::timeout_at(deadline, async {
        let mut tx = f.owner.begin().await?;
        sqlx::query("SET TRANSACTION READ ONLY").execute(&mut *tx).await?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(f.actor.tenant_id.to_string()).execute(&mut *tx).await?;
        let value: Value = sqlx::query_scalar("SELECT jsonb_build_object('immutable',to_jsonb(r)-ARRAY['version','status','lease_owner','lease_token','lease_until','operation_id','accepted_at','failure_code','updated_at','completed_at'],'database_now',clock_timestamp(),'status',r.status,'lease_owner',r.lease_owner,'lease_token',r.lease_token,'lease_until',r.lease_until,'operation_id',r.operation_id,'failure_code',r.failure_code,'emitted_runs',a.emitted_runs,'run_count',(SELECT count(*) FROM automation_runs z WHERE z.tenant_id=r.tenant_id AND z.automation_id=r.automation_id),'operations',(SELECT count(*) FROM operations o WHERE o.tenant_id=r.tenant_id AND o.request_id=r.id),'executions',(SELECT count(*) FROM executions e WHERE e.tenant_id=r.tenant_id AND e.id=r.produced_resource_id),'idempotency',(SELECT count(*) FROM idempotency_keys k WHERE k.tenant_id=r.tenant_id AND k.operation_id=r.operation_id),'held_execution',(SELECT count(*) FROM executions e WHERE e.tenant_id=r.tenant_id AND e.id=r.produced_resource_id AND e.operation_id=r.operation_id AND e.slot_held),'held_activity',(SELECT count(*) FROM instances i WHERE i.tenant_id=r.tenant_id AND i.id=r.instance_id AND i.slot_held AND i.activity_kind='EXECUTION' AND i.activity_id=r.produced_resource_id),'execution_reservations',(SELECT count(*) FROM quota_reservations q JOIN quota_accounts account ON account.tenant_id=q.tenant_id AND account.id=q.quota_account_id WHERE q.tenant_id=r.tenant_id AND q.operation_id=r.operation_id AND account.dimension='EXECUTIONS' AND q.amount=1 AND q.status IN('PENDING','ALLOCATED'))) FROM automation_runs r JOIN automations a ON a.tenant_id=r.tenant_id AND a.id=r.automation_id WHERE r.tenant_id=$1 AND r.automation_id=$2")
            .bind(f.actor.tenant_id).bind(automation).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok::<_, anyhow::Error>(value)
    }).await.context("Private immutable run observation exceeded original bound")??;
    ensure!(
        Instant::now() < deadline,
        "Immutable run observation COMMIT ACK was late"
    );
    Ok(result)
}

async fn create_execute(f: &Fixture) -> anyhow::Result<Uuid> {
    let created = f
        .create("runtime-fault-instance")
        .await
        .map_err(|e| anyhow::anyhow!("create fixture instance: {}", e.code))?;
    let instance = created.body.resource;
    f.seed_observed_state(instance.id, "RUNNING").await?;
    let mut tx = f.owner_transaction().await?;
    // Same explicit API-acceptance prerequisites as the original 18-case
    // EXECUTE case; these metadata fixtures do not assert that a VM exists.
    sqlx::query("UPDATE instances SET pod_uid=$3,ready_generation=runtime_generation,ready_launch_id=launch_id,ready_pod_uid=$3,ready_cluster_epoch=cluster_epoch,ready_observed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
        .bind(f.actor.tenant_id).bind(instance.id).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    for project in [None, Some(f.request.project_id)] {
        sqlx::query("INSERT INTO quota_accounts(tenant_id,project_id,dimension,limit_value) VALUES($1,$2,'EXECUTIONS',10)")
            .bind(f.actor.tenant_id).bind(project).execute(&mut *tx).await?;
        for action in [
            "automations:write",
            "executions:create",
            "instances:hard_stop",
        ] {
            sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
                .bind(f.actor.tenant_id).bind(project).bind(f.actor.principal_id).bind(action)
                .execute(&mut *tx).await?;
        }
    }
    tx.commit().await?;
    f.bind_client_id("automation-process-test").await?;
    let identity = VerifiedIdentity {
        scope_profile: Default::default(),
        issuer: "https://issuer.example.test".into(),
        subject: f.actor.principal_id.to_string(),
        client_id: Some("automation-process-test".into()),
        scopes: vec![],
        expires_at: (Utc::now() + chrono::Duration::hours(1)).timestamp(),
    };
    let request = CreateAutomation {
        name: "runtime privilege fault execution".into(),
        action: AutomationAction::Execute {
            request: CreateExecution {
                argv: vec!["/bin/true".into(), PRIVATE_MARKER.into()],
                public_env: BTreeMap::from([(
                    "AUTOMATION_PRIVATE_FIXTURE".into(),
                    PRIVATE_MARKER.into(),
                )]),
                cwd: "/workspace".into(),
                timeout_seconds: 60,
                on_timeout: ExecutionTimeoutPolicy::HardStopInstance,
                output_limit_bytes: 1024,
                client_reference: Some(PRIVATE_MARKER.into()),
            },
        },
        trigger: AutomationTrigger::Once {
            at: Utc::now() + chrono::Duration::seconds(5),
        },
        delegation_expires_at: Utc::now() + chrono::Duration::days(1),
        run_budget: 1,
        minimum_interval_seconds: 60,
        grace_seconds: 300,
    };
    f.database.check_automation_api_schema().await?;
    let receipt = f
        .database
        .create_automation(
            &f.actor,
            &identity,
            instance.id,
            &request,
            "runtime-fault-automation",
            instance.spec_version,
            86400,
        )
        .await
        .map_err(|e| anyhow::anyhow!("formal app create automation: {}", e.code))?;
    Ok(receipt.body.resource.id)
}

async fn fault_trial(
    owner: &Database,
    monitor: &Database,
    f: &Fixture,
    url: &str,
    pod: Uuid,
    fault: Fault,
) -> anyhow::Result<()> {
    println!("AUTOMATION_PROCESS_STEP {} START", fault.stage());
    let baseline = sessions(&monitor.pool, None).await?;
    ensure!(
        baseline.len() == 1,
        "Only the exact independent automation monitor may be present"
    );
    let mut original = Owned::empty();
    let mut replacement = Owned::empty();
    let mut lock = None;
    let mut revoked = false;
    let outcome = async {
        let first_id = start_ready(&mut original, monitor, &baseline, url, pod).await?;
        let automation = if matches!(fault, Fault::ExecutionInsert) { Some(create_execute(f).await?) } else { None };
        let deadline = Instant::now() + LOCK_WINDOW;
        lock = Some(tokio::time::timeout_at(deadline, owner.pool.begin()).await
            .context("Owned queue lock BEGIN exceeded original bound")??);
        let tx = lock.as_mut().context("Owned queue lock missing")?;
        let blocker: i32 = tokio::time::timeout_at(deadline,
            sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut **tx)).await
            .context("Queue blocker identity observation exceeded original bound")??;
        tokio::time::timeout_at(deadline,
            sqlx::query("LOCK TABLE automation_claims IN ACCESS EXCLUSIVE MODE").execute(&mut **tx))
            .await.context("Runtime claim lock acquisition exceeded original bound")??;
        loop {
            ensure!(original.child()?.try_wait()?.is_none(), "Original worker exited before injection");
            let observed = tokio::time::timeout_at(deadline, sessions(&monitor.pool, Some(blocker)))
                .await.context("Real blocked runtime claim was not observed")??;
            ensure!(Instant::now() < deadline, "Blocked runtime observation ACK was late");
            let actual = child_backends(&observed, &baseline);
            if actual.values().any(|(_, blocked, _)| *blocked) {
                ensure!(process_identity(&actual, pod)? == first_id, "Blocked worker identity changed");
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // A second ordinary owner fixture pool performs only reversible
        // permission injection; the blocker owns the other pool's connection.
        revoked = true;
        tokio::time::timeout_at(deadline, permission(&f.owner, fault.revoke())).await
            .context("Runtime privilege injection exceeded original lock window")??;
        tokio::time::timeout_at(deadline, health_denied(&mut original)).await
            .context("Runtime readiness observation exceeded original lock window")??;
        println!("AUTOMATION_PROCESS_STEP {} BLOCKED_READY_503", fault.stage());
        tokio::time::timeout_at(deadline, rollback_lock(&mut lock)).await
            .context("Runtime queue lock release exceeded original window")??;
        ensure!(Instant::now() < deadline, "Runtime queue lock ROLLBACK ACK was late");
        returned_exit(&mut original, false).await?;
        require_absent(&monitor.pool, &baseline).await?;
        println!("AUTOMATION_PROCESS_STEP {} FATAL_BACKENDS_HEALTH_ABSENT", fault.stage());
        if let Some(automation) = automation {
            let before = snapshot(f, automation).await?;
            ensure!(before["status"] == "DISPATCHING" && before["failure_code"].is_null()
                && before["operations"] == 0 && before["executions"] == 0
                && before["idempotency"] == 0 && before["run_count"] == 1 && before["emitted_runs"] == 1
                && before["held_activity"] == 0 && before["execution_reservations"] == 0,
                "Fatal acceptance must preserve one genuine prepared intent without a linked operation");
            let old_until: DateTime<Utc> = serde_json::from_value(before["lease_until"].clone())?;
            let before_clock: DateTime<Utc> = serde_json::from_value(before["database_now"].clone())?;
            ensure!(old_until > before_clock, "Original real 30-second claim expired before restart observation");
            permission(&f.owner, fault.restore()).await?;
            revoked = false;
            let second_id = start_ready(&mut replacement, monitor, &baseline, url, pod).await?;
            ensure!(first_id != second_id, "Natural restart must use a new process UUID under the same Pod UID");
            let deadline = Instant::now() + TAKEOVER;
            loop {
                ensure!(replacement.child()?.try_wait()?.is_none(), "Replacement worker exited before takeover");
                let current = tokio::time::timeout_at(deadline, snapshot(f, automation)).await
                    .context("Takeover snapshot exceeded original overall observation bound")??;
                ensure!(Instant::now() < deadline, "Takeover snapshot returned a late ACK");
                ensure!(current["immutable"] == before["immutable"] && current["run_count"] == 1
                    && current["emitted_runs"] == 1, "Restart changed immutable intent or emitted a duplicate run");
                let database_now: DateTime<Utc> = serde_json::from_value(current["database_now"].clone())?;
                let lease_expired = old_until <= database_now;
                if current["status"] == "SUBMITTED" {
                    ensure!(lease_expired && current["operations"] == 1 && current["executions"] == 1
                        && current["idempotency"] == 1 && current["held_execution"] == 1
                        && current["held_activity"] == 1 && current["execution_reservations"] == 2
                        && current["lease_token"].as_i64() > before["lease_token"].as_i64()
                        && current["lease_owner"] != before["lease_owner"],
                        "Natural lease takeover must submit the exact original resource once and preserve its held slot");
                    break;
                }
                if !lease_expired {
                    ensure!(current["status"] == "DISPATCHING" && current["operations"] == 0
                        && current["executions"] == 0 && current["lease_token"] == before["lease_token"],
                        "Replacement acquired or mutated the intent before natural lease expiry");
                }
                ensure!(Instant::now() < deadline, "Natural lease takeover exceeded its original observer bound");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let pid = replacement.child()?.id().context("Owned replacement process missing")?;
            kill(Pid::from_raw(i32::try_from(pid)?), Signal::SIGTERM)?;
            returned_exit(&mut replacement, true).await?;
            require_absent(&monitor.pool, &baseline).await?;
            let after = snapshot(f, automation).await?;
            ensure!(after["immutable"] == before["immutable"] && after["status"] == "SUBMITTED"
                && after["operations"] == 1 && after["executions"] == 1 && after["idempotency"] == 1
                && after["held_execution"] == 1 && after["held_activity"] == 1
                && after["execution_reservations"] == 2, "Graceful replacement exit altered durable acceptance or released live activity");
            println!("AUTOMATION_PROCESS_STEP {} ORIGINAL_INTENT_NATURAL_LEASE_EXACTLY_ONCE", fault.stage());
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    // Cleanup completes before business or assertion errors propagate. A forced
    // kill on failure is hygiene, never evidence of natural fatal drain.
    let lock_cleanup = rollback_lock(&mut lock).await;
    let restoration = if revoked {
        permission(&f.owner, fault.restore()).await
    } else {
        Ok(())
    };
    let original_cleanup = original.cleanup(outcome.is_err()).await;
    let replacement_cleanup = replacement.cleanup(outcome.is_err()).await;
    let absence = require_absent(&monitor.pool, &baseline).await;
    outcome?;
    lock_cleanup?;
    restoration?;
    absence?;
    let (out, err) = original_cleanup?;
    let stdout = std::str::from_utf8(&out)?;
    let stderr = std::str::from_utf8(&err)?;
    ensure!(
        stdout.matches("database connection pool drained").count() == 1
            && stderr.contains("INTERNAL_ERROR"),
        "Actual fatal outcome or its single awaited database drain was lost"
    );
    ensure!(
        !stdout.contains(PRIVATE_MARKER) && !stderr.contains(PRIVATE_MARKER),
        "Actual fatal process disclosed private command/environment/reference data"
    );
    let (out, err) = replacement_cleanup?;
    if matches!(fault, Fault::ExecutionInsert) {
        ensure!(
            std::str::from_utf8(&out)?
                .matches("database connection pool drained")
                .count()
                == 1
                && err.is_empty(),
            "Replacement did not finish its intended single successful drain"
        );
        ensure!(
            !std::str::from_utf8(&out)?.contains(PRIVATE_MARKER),
            "Replacement process disclosed private command/environment/reference data"
        );
    }
    println!("AUTOMATION_PROCESS_STEP {} OUTPUT_JOINED", fault.stage());
    Ok(())
}

async fn blocked_claim_start(
    monitor: &Database,
    blocker: i32,
) -> anyhow::Result<Option<DateTime<Utc>>> {
    let deadline = Instant::now() + OBSERVE;
    let rows: Vec<DateTime<Utc>> = tokio::time::timeout_at(deadline, async {
        let mut tx = monitor.pool.begin().await?;
        sqlx::query("SET TRANSACTION READ ONLY").execute(&mut *tx).await?;
        let rows = sqlx::query_scalar("SELECT a.query_start FROM pg_stat_activity a WHERE a.datname=current_database() AND a.usename=current_user AND a.backend_type='client backend' AND $1=ANY(pg_blocking_pids(a.pid)) AND a.application_name LIKE 'sbx1.automation.%' AND a.state='active' AND a.query LIKE 'SELECT * FROM sandbox_claim_automation%' ORDER BY a.pid")
            .bind(blocker).fetch_all(&mut *tx).await?;
        tx.commit().await?;
        Ok::<_, anyhow::Error>(rows)
    }).await.context("Real transient blocked-query observation exceeded original bound")??;
    ensure!(
        Instant::now() < deadline && rows.len() <= 1,
        "Transient observation ACK was late or more than one owned claim was blocked"
    );
    Ok(rows.first().copied())
}

async fn transient_trial(
    owner: &Database,
    monitor: &Database,
    f: &Fixture,
    url: &str,
    pod: Uuid,
) -> anyhow::Result<()> {
    println!("AUTOMATION_PROCESS_STEP RUNTIME_TRANSIENT START");
    let baseline = sessions(&monitor.pool, None).await?;
    ensure!(
        baseline.len() == 1,
        "Transient trial requires only its same-LOGIN monitor"
    );
    let mut owned = Owned::empty();
    let mut lock = None;
    let outcome = async {
        let identity = start_ready(&mut owned, monitor, &baseline, url, pod).await?;
        let deadline = Instant::now() + Duration::from_secs(10);
        lock = Some(tokio::time::timeout_at(deadline, owner.pool.begin()).await
            .context("Transient blocker BEGIN exceeded original observer bound")??);
        let tx = lock.as_mut().context("Owned transient lock missing")?;
        let blocker: i32 = tokio::time::timeout_at(deadline,
            sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut **tx)).await
            .context("Transient blocker identity query exceeded original bound")??;
        tokio::time::timeout_at(deadline,
            sqlx::query("LOCK TABLE automation_claims IN ACCESS EXCLUSIVE MODE").execute(&mut **tx))
            .await.context("Transient blocker acquisition exceeded original observer bound")??;
        let first = loop {
            ensure!(owned.child()?.try_wait()?.is_none(), "Transient worker exited before a real blocked claim");
            let start = tokio::time::timeout_at(deadline, blocked_claim_start(monitor, blocker)).await
                .context("First blocked claim was not observed within original bound")??;
            if let Some(start) = start { break start; }
            ensure!(Instant::now() < deadline, "First transient claim ACK was late");
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let probe = client()?;
        let address = owned.address.context("Transient worker health address missing")?;
        let mut degraded_seen = false;
        let second = loop {
            ensure!(owned.child()?.try_wait()?.is_none(), "Retryable lock timeout incorrectly killed the worker");
            let response = tokio::time::timeout_at(deadline,
                probe.get(format!("http://{address}/health/ready")).send()).await
                .context("Transient readiness probe exceeded original observation bound")??;
            if response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE { degraded_seen = true; }
            else { ensure!(response.status() == reqwest::StatusCode::NO_CONTENT, "Transient readiness returned an unexpected status"); }
            let start = tokio::time::timeout_at(deadline, blocked_claim_start(monitor, blocker)).await
                .context("Retried blocked claim was not observed within original bound")??;
            if let Some(start) = start && start != first { break start; }
            ensure!(Instant::now() < deadline, "Transient retry observation ACK was late");
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        ensure!(degraded_seen && second - first >= chrono::Duration::seconds(5),
            "Actual claim retries must retain the normal three-second lock timeout and two-second backoff while readiness is degraded");
        let actual = child_backends(&sessions(&monitor.pool, Some(blocker)).await?, &baseline);
        ensure!(process_identity(&actual, pod)? == identity && actual.values().any(|(_, blocked, _)| *blocked),
            "Transient retry must use the same real process identity and actually block on the original owned lock");
        tokio::time::timeout_at(deadline, rollback_lock(&mut lock)).await
            .context("Transient blocker release exceeded original observer bound")??;
        ensure!(Instant::now() < deadline, "Transient blocker ROLLBACK ACK was late");
        let ready_deadline = Instant::now() + READY;
        loop {
            ensure!(owned.child()?.try_wait()?.is_none(), "Transient worker exited instead of recovering readiness");
            let response = probe.get(format!("http://{address}/health/ready")).send().await?;
            ensure!(Instant::now() < ready_deadline, "Transient recovery readiness ACK was late");
            if response.status() == reqwest::StatusCode::NO_CONTENT { break; }
            ensure!(response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE,
                "Transient recovery returned an unexpected health status");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        ensure!(process_identity(&child_backends(&sessions(&monitor.pool, None).await?, &baseline), pod)? == identity,
            "Readiness recovery restarted or replaced the actual worker");
        let deadline = Instant::now() + OBSERVE;
        let mut tx = tokio::time::timeout_at(deadline, f.owner_transaction()).await
            .context("Transient ledger observer BEGIN exceeded original bound")??;
        let counts: (i64, i64, i64) = tokio::time::timeout_at(deadline,
            sqlx::query_as("SELECT (SELECT count(*) FROM automation_runs WHERE tenant_id=$1),(SELECT count(*) FROM operations WHERE tenant_id=$1),(SELECT count(*) FROM executions WHERE tenant_id=$1)")
                .bind(f.actor.tenant_id).fetch_one(&mut *tx)).await
                .context("Transient ledger observation exceeded original bound")??;
        tokio::time::timeout_at(deadline, tx.commit()).await
            .context("Transient ledger observation COMMIT ACK exceeded original bound")??;
        ensure!(Instant::now() < deadline && counts == (0, 0, 0),
            "Transient idle claim recovery must not fabricate a run, operation or execution");
        let pid = owned.child()?.id().context("Owned transient process ID missing")?;
        kill(Pid::from_raw(i32::try_from(pid)?), Signal::SIGTERM)?;
        returned_exit(&mut owned, true).await?;
        require_absent(&monitor.pool, &baseline).await?;
        println!("AUTOMATION_PROCESS_STEP RUNTIME_TRANSIENT DEGRADED_BACKOFF_SAME_PROCESS_RECOVERED");
        Ok::<_, anyhow::Error>(())
    }.await;
    let lock_cleanup = rollback_lock(&mut lock).await;
    let process_cleanup = owned.cleanup(outcome.is_err()).await;
    let absence = require_absent(&monitor.pool, &baseline).await;
    outcome?;
    lock_cleanup?;
    absence?;
    let (out, err) = process_cleanup?;
    let stdout = std::str::from_utf8(&out)?;
    ensure!(
        stdout.contains("DEPENDENCY_UNAVAILABLE")
            && stdout.matches("database connection pool drained").count() == 1
            && err.is_empty(),
        "Actual transient classification or awaited successful pool drain was lost"
    );
    println!("AUTOMATION_PROCESS_STEP RUNTIME_TRANSIENT OUTPUT_JOINED");
    Ok(())
}

pub(super) async fn verify(
    owner: &Database,
    monitor: &Database,
    url: &str,
    pod: Uuid,
) -> anyhow::Result<()> {
    let _serial = support::serial().await;
    let f = Fixture::new(10).await?;
    let outcome = async {
        // Do not delete routing records or overwrite a live lease to isolate a
        // trial. The runner must give this process suite its fresh database.
        let routing: i64 = sqlx::query_scalar("SELECT count(*) FROM automation_claims").fetch_one(&f.owner).await?;
        ensure!(routing == 0, "Fault process suite requires a fresh independently migrated database, not old business-suite routing rows");
        fault_trial(owner, monitor, &f, url, pod, Fault::Claim).await?;
        transient_trial(owner, monitor, &f, url, pod).await?;
        fault_trial(owner, monitor, &f, url, pod, Fault::ExecutionInsert).await?;
        acceptance::verify(owner, monitor, url, pod).await?;
        Ok::<_, anyhow::Error>(())
    }.await;
    f.database.pool.close().await;
    f.owner.close().await;
    outcome
}
