#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::*;
use crate::{
    auth::VerifiedIdentity,
    history::{CursorSigner, HistoryQuery},
    test_support_db::{
        self, Fixture, VerifiedFixtureConnections, VerifiedRuntimeDatabase, api_failure,
    },
};
use anyhow::{Context, ensure};
use chrono::Duration;
use controller::{AutomationClaim, AutomationController};
use tokio::sync::OnceCell;
struct PreparedFixture {
    fixture: VerifiedFixtureConnections,
    automation: VerifiedRuntimeDatabase,
    termination: VerifiedRuntimeDatabase,
    backup: VerifiedRuntimeDatabase,
    _other_components: Vec<VerifiedRuntimeDatabase>,
}
static SCHEMA: OnceCell<PreparedFixture> = OnceCell::const_new();
pub(super) fn automation_test_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: std::sync::LazyLock<tokio::runtime::Runtime> = std::sync::LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("automation fixture runtime")
    });
    &RUNTIME
}
async fn prepared_fixture() -> anyhow::Result<&'static PreparedFixture> {
    SCHEMA.get_or_try_init(|| async {
        ensure!(std::env::var("AUTOMATION_TEST_FORMAL").as_deref()==Ok("39"),
            "explicit isolated formal automation test entry is required");
        ensure!(url::Url::parse(&std::env::var("TEST_DATABASE_URL")?)?.path()=="/sandbox_automation_pipeline_test",
            "automation acceptance requires its dedicated disposable database");
        // The shared fixture invokes the actual embedded SQLx migrator and
        // validates its checksum ledger before constructing any runtime proof.
        let fixture=Fixture::prepare_verified_connections().await?;
        let owner=fixture.owner();
        let normal_without_restore:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=39 AND success) AND NOT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=38) AND to_regclass('public.restores') IS NULL AND to_regprocedure('public.sandbox_workspace_restore_binding(uuid,uuid)') IS NULL").fetch_one(&owner).await?;
        ensure!(normal_without_restore,"formal automation must start without an unpublished restore component");
        for role_script in ["worker","admission","gateway","termination","fencing","volume-deleter","backup","automation"] {
            let path=format!("scripts/sql/{role_script}-role.sql");
            sqlx::raw_sql(&std::fs::read_to_string(path)?).execute(&owner).await?;
        }
        let termination=fixture.runtime("TEST_TERMINATION_DATABASE_URL","sandbox_termination",5).await?;
        let backup=fixture.runtime("TEST_BACKUP_DATABASE_URL","sandbox_backup",4).await?;
        let automation=fixture.runtime("TEST_AUTOMATION_DATABASE_URL","sandbox_automation",8).await?;
        let mut others=Vec::new();
        for (environment,role) in [
            ("TEST_WORKER_DATABASE_URL","sandbox_worker"),
            ("TEST_ADMISSION_DATABASE_URL","sandbox_admission"),
            ("TEST_GATEWAY_DATABASE_URL","sandbox_gateway"),
            ("TEST_FENCING_DATABASE_URL","sandbox_fencing"),
            ("TEST_VOLUME_DELETER_DATABASE_URL","sandbox_volume_deleter"),
        ] {others.push(fixture.runtime(environment,role,1).await?);}
        fixture.database().check_automation_api_schema().await?;
        let controller=AutomationController::new(automation.database_for("sandbox_automation")?,"startup-verification".into(),3600,86400).map_err(api_failure)?;
        controller.check_schema().await?;
        for component in [&automation,&termination,&backup].into_iter().chain(others.iter()) {
            component.database().verify_runtime_role().await?;
        }
        Ok::<_,anyhow::Error>(PreparedFixture{fixture,automation,termination,backup,_other_components:others})
    }).await
}
pub(super) struct Ready {
    pub(super) f: Fixture,
    pub(super) instance: crate::model::Instance,
    pub(super) worker: AutomationController,
    pub(super) identity: VerifiedIdentity,
}
impl Ready {
    pub(super) async fn new() -> anyhow::Result<Self> {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("sandbox_platform=error")
            .with_test_writer()
            .try_init();
        let connections = prepared_fixture().await?;
        let f = Fixture::new_with_verified_connections(10, &connections.fixture).await?;
        f.bind_client_id("automation-http-test").await?;
        // Each serial case owns its tenants; remove only routing rows from
        // earlier cases in this dedicated disposable database. Historical
        // runs/operations/authority remain intact for inspecting evidence.
        sqlx::query("DELETE FROM automation_claims")
            .execute(&f.owner)
            .await?;
        let created = f.create("automation-instance").await.map_err(api_failure)?;
        let mut tx = f.owner_transaction().await?;
        for action in [
            "automations:write",
            "automations:read",
            "executions:create",
            "backups:create",
            "events:read",
        ] {
            sqlx::query(
                "INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4)",
            )
            .bind(f.actor.tenant_id)
            .bind(f.request.project_id)
            .bind(f.actor.principal_id)
            .bind(action)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        let db = connections.automation.database_for("sandbox_automation")?;
        let worker = AutomationController::new(
            db,
            format!("automation-test-{}", Uuid::new_v4()),
            3600,
            86400,
        )
        .map_err(api_failure)?;
        let identity = VerifiedIdentity {
            scope_profile: Default::default(),
            issuer: "https://issuer.example.test".into(),
            subject: f.actor.principal_id.to_string(),
            client_id: Some("automation-http-test".into()),
            scopes: vec![],
            expires_at: (Utc::now() + Duration::hours(1)).timestamp(),
        };
        Ok(Self {
            f,
            instance: created.body.resource,
            worker,
            identity,
        })
    }
    pub(super) fn request(&self) -> CreateAutomation {
        CreateAutomation {
            name: "bounded renewal".into(),
            action: AutomationAction::Renew { ttl_seconds: 7200 },
            trigger: AutomationTrigger::Once {
                at: Utc::now() + Duration::seconds(2),
            },
            delegation_expires_at: Utc::now() + Duration::days(1),
            run_budget: 1,
            minimum_interval_seconds: 60,
            grace_seconds: 300,
        }
    }
    pub(super) async fn create(
        &self,
        request: &CreateAutomation,
    ) -> anyhow::Result<AutomationReceipt> {
        Ok(self
            .f
            .database
            .create_automation(
                &self.f.actor,
                &self.identity,
                self.instance.id,
                request,
                "automation-create",
                self.instance.spec_version,
                86400,
            )
            .await
            .map_err(api_failure)
            .context("create automation acceptance")?
            .body)
    }
    pub(super) async fn due_claim(&self) -> anyhow::Result<AutomationClaim> {
        due_claim(&self.worker).await
    }
    async fn count_operations(&self, id: Uuid) -> anyhow::Result<i64> {
        let mut tx = self.f.owner_transaction().await?;
        Ok(sqlx::query_scalar("SELECT count(*) FROM operations o JOIN automation_runs r ON r.tenant_id=o.tenant_id AND r.operation_id=o.id WHERE r.tenant_id=$1 AND r.automation_id=$2").bind(self.f.actor.tenant_id).bind(id).fetch_one(&mut *tx).await?)
    }
}
async fn due_claim(worker: &AutomationController) -> anyhow::Result<AutomationClaim> {
    // Wait for the actual DB clock/queue decision. A fixed 150 ms scheduling
    // margin races normal transaction latency on a busy build/test host.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if let Some(claim) = worker.claim().await.map_err(api_failure)? {
            return Ok(claim);
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "expected due automation claim"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
fn signer() -> CursorSigner {
    use base64::Engine;
    CursorSigner::from_json(&serde_json::json!({"active":{"kid":"automation-test","key_base64":base64::engine::general_purpose::STANDARD.encode([37u8;32])},"previous":[]}).to_string()).unwrap()
}

#[test]
#[ignore = "requires dedicated disposable real PostgreSQL automation role"]
fn accepted_execute_uses_fixed_resource_and_ack_replay_cannot_duplicate_or_release_live_activity()
-> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
    let _serial = test_support_db::serial().await;
    let r = Ready::new().await?;
    r.f.seed_observed_state(r.instance.id, "RUNNING").await?;
    let mut tx = r.f.owner_transaction().await?;
    let pod = Uuid::new_v4();
    sqlx::query("UPDATE instances SET pod_uid=$3,ready_generation=runtime_generation,ready_launch_id=launch_id,ready_pod_uid=$3,ready_cluster_epoch=cluster_epoch,ready_observed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
  .bind(r.f.actor.tenant_id).bind(r.instance.id).bind(pod).execute(&mut *tx).await?;
    for project in [None, Some(r.f.request.project_id)] {
        sqlx::query("INSERT INTO quota_accounts(tenant_id,project_id,dimension,limit_value) VALUES($1,$2,'EXECUTIONS',10)").bind(r.f.actor.tenant_id).bind(project).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    let mut request = r.request();
    request.run_budget = 2;
    request.action = AutomationAction::Execute {
        request: crate::model::CreateExecution {
            argv: vec!["/bin/true".into()],
            public_env: Default::default(),
            cwd: "/workspace".into(),
            timeout_seconds: 60,
            on_timeout: crate::model::ExecutionTimeoutPolicy::HardStopInstance,
            output_limit_bytes: 1024,
            client_reference: Some("durable automation fixture".into()),
        },
    };
    let receipt = r.create(&request).await?;
    let claim = r.due_claim().await?;
    let p = r
        .worker
        .prepare(&claim)
        .await
        .map_err(api_failure)?
        .unwrap();
    let (first, second) = tokio::join!(r.worker.accept(&p), r.worker.accept(&p));
    first.map_err(api_failure)?;
    second.map_err(api_failure)?; // same key/If-Match, fixed resource
    r.worker.run_claim(&claim).await.map_err(api_failure)?;
    ensure!(r.count_operations(receipt.resource.id).await? == 1);
    let mut tx = r.f.owner_transaction().await?;
    let (operation,produced,actual,status):(Uuid,Uuid,Uuid,String)=sqlx::query_as("SELECT r.operation_id,r.produced_resource_id,e.id,r.status FROM automation_runs r JOIN executions e ON e.tenant_id=r.tenant_id AND e.operation_id=r.operation_id WHERE r.tenant_id=$1 AND r.automation_id=$2")
  .bind(r.f.actor.tenant_id).bind(receipt.resource.id).fetch_one(&mut *tx).await?;
    ensure!(produced == actual && status == "SUBMITTED");
    sqlx::query("UPDATE operations SET status='FAILED',stage='COMPLETED',completed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
  .bind(r.f.actor.tenant_id).bind(operation).execute(&mut *tx).await?;
    // Owner-only historical timestamps preserve every production constraint.
    sqlx::query("UPDATE idempotency_keys SET created_at=clock_timestamp()-interval '8 days',expires_at=clock_timestamp()-interval '1 second',tombstone_until=clock_timestamp()+interval '90 days' WHERE tenant_id=$1 AND operation_id=$2")
        .bind(r.f.actor.tenant_id).bind(operation).execute(&mut *tx).await?;
    tx.commit().await?;
    let expired = r.worker.accept(&p).await.unwrap_err();
    ensure!(expired.code == "IDEMPOTENCY_EXPIRED");
    r.worker.run_claim(&claim).await.map_err(api_failure)?;
    let mut tx = r.f.owner_transaction().await?;
    let(status,held):(String,bool)=sqlx::query_as("SELECT r.status,e.slot_held FROM automation_runs r JOIN executions e ON e.tenant_id=r.tenant_id AND e.operation_id=r.operation_id WHERE r.tenant_id=$1 AND r.automation_id=$2")
  .bind(r.f.actor.tenant_id).bind(receipt.resource.id).fetch_one(&mut *tx).await?;
    ensure!(
        status == "SUBMITTED" && held,
        "failed management record cannot prove its execution activity closed"
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM automation_runs WHERE tenant_id=$1 AND automation_id=$2",
    )
    .bind(r.f.actor.tenant_id)
    .bind(receipt.resource.id)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(count == 1);
    Ok(())
    })
}

#[test]
#[ignore = "requires dedicated disposable real PostgreSQL automation role"]
fn creator_identity_principal_and_project_revocation_prevent_acceptance_but_preserve_committed_reconciliation()
-> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
    let _serial = test_support_db::serial().await;
    for mode in ["identity", "principal", "project"] {
        let r = Ready::new().await?;
        let receipt = r.create(&r.request()).await?;
        let claim = r.due_claim().await?;
        let p = r
            .worker
            .prepare(&claim)
            .await
            .map_err(api_failure)?
            .unwrap();
        let mut tx = r.f.owner_transaction().await?;
        match mode {
            "identity" => {
                sqlx::query("UPDATE principal_identities SET enabled=false WHERE principal_id=$1")
                    .bind(r.f.actor.principal_id)
                    .execute(&mut *tx)
                    .await?;
            }
            "principal" => {
                sqlx::query("UPDATE tenant_principals SET enabled=false WHERE tenant_id=$1 AND principal_id=$2").bind(r.f.actor.tenant_id).bind(r.f.actor.principal_id).execute(&mut *tx).await?;
            }
            _ => {
                sqlx::query("UPDATE projects SET enabled=false WHERE tenant_id=$1 AND id=$2")
                    .bind(r.f.actor.tenant_id)
                    .bind(r.f.request.project_id)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        tx.commit().await?;
        ensure!(r.worker.accept(&p).await.is_err());
        ensure!(r.count_operations(receipt.resource.id).await? == 0);
    }
    let r = Ready::new().await?;
    let receipt = r.create(&r.request()).await?;
    let claim = r.due_claim().await?;
    let p = r
        .worker
        .prepare(&claim)
        .await
        .map_err(api_failure)?
        .unwrap();
    r.worker.accept(&p).await.map_err(api_failure)?;
    let mut tx = r.f.owner_transaction().await?;
    sqlx::query("UPDATE principal_identities SET enabled=false WHERE principal_id=$1")
        .bind(r.f.actor.principal_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE tenant_principals SET enabled=false WHERE tenant_id=$1 AND principal_id=$2",
    )
    .bind(r.f.actor.tenant_id)
    .bind(r.f.actor.principal_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE projects SET enabled=false WHERE tenant_id=$1 AND id=$2")
        .bind(r.f.actor.tenant_id)
        .bind(r.f.request.project_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    r.worker.run_claim(&claim).await.map_err(api_failure)?;
    let mut tx = r.f.owner_transaction().await?;
    let status: String = sqlx::query_scalar(
        "SELECT status FROM automation_runs WHERE tenant_id=$1 AND automation_id=$2",
    )
    .bind(r.f.actor.tenant_id)
    .bind(receipt.resource.id)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(status == "SUCCEEDED");
    Ok(())
    })
}

#[test]
#[ignore = "requires dedicated disposable real PostgreSQL automation role"]
fn epoch_drift_fences_original_claim_without_constructing_a_new_operation() -> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
    let _serial = test_support_db::serial().await;
    let r = Ready::new().await?;
    let receipt = r.create(&r.request()).await?;
    let claim = r.due_claim().await?;
    let p = r
        .worker
        .prepare(&claim)
        .await
        .map_err(api_failure)?
        .unwrap();
    let old: Uuid =
        sqlx::query_scalar("SELECT cluster_epoch FROM platform_configuration WHERE singleton")
            .fetch_one(&r.f.owner)
            .await?;
    sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton")
        .bind(Uuid::new_v4())
        .execute(&r.f.owner)
        .await?;
    let result = r.worker.accept(&p).await;
    let reconciled = async {
        r.worker.run_claim(&claim).await.map_err(api_failure)?;
        // The old claim may not reconcile across epochs. A freshly claimed
        // coordinator cancels the immutable old run, never changes its request.
        sqlx::query("UPDATE automation_claims SET lease_owner=NULL,lease_until=NULL,eligible_at=clock_timestamp() WHERE automation_id=$1")
            .bind(receipt.resource.id).execute(&r.f.owner).await?;
        let fresh=r.worker.claim().await.map_err(api_failure)?.context("new epoch claim")?;
        r.worker.run_claim(&fresh).await.map_err(api_failure)?;
        Ok::<(),anyhow::Error>(())
    }.await;
    sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton")
        .bind(old)
        .execute(&r.f.owner)
        .await?;
    ensure!(result.is_err());
    reconciled?;
    ensure!(r.count_operations(receipt.resource.id).await? == 0);
    let mut tx = r.f.owner_transaction().await?;
    let (status, reason): (String, String) = sqlx::query_as(
        "SELECT status,failure_code FROM automation_runs WHERE tenant_id=$1 AND automation_id=$2",
    )
    .bind(r.f.actor.tenant_id)
    .bind(receipt.resource.id)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(status == "CANCELLED" && reason == "CONTROL_EPOCH_CHANGED");
    Ok(())
    })
}

#[test]
#[ignore = "requires dedicated disposable real PostgreSQL automation role"]
fn cold_backup_reuses_authenticated_stop_and_cleanup_then_keeps_run_blocked_until_hold_release()
-> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
    let _serial = test_support_db::serial().await;
    let _bootstrap = Ready::new().await?;
    // Existing fixture uses actual authenticated mTLS and real PG, with explicit
    // controlled host/Kube/CSI observations; no real cloud/Kata claim is made.
    let connections = prepared_fixture().await?;
    let cold = crate::backup_ledger::tests::Fixture::new_with_verified_connections(
        true,
        &connections.fixture,
        &connections.termination,
        &connections.backup,
    )
    .await?;
    let f = &cold.base.f;
    f.bind_client_id("automation-http-test").await?;
    let mut tx = f.owner_transaction().await?;
    for action in ["automations:write", "automations:read"] {
        sqlx::query(
            "INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4)",
        )
        .bind(f.actor.tenant_id)
        .bind(cold.base.launch.project_id)
        .bind(f.actor.principal_id)
        .bind(action)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    let identity = VerifiedIdentity {
        scope_profile: Default::default(),
        issuer: "https://issuer.example.test".into(),
        subject: f.actor.principal_id.to_string(),
        client_id: Some("automation-http-test".into()),
        scopes: vec![],
        expires_at: (Utc::now() + Duration::hours(1)).timestamp(),
    };
    let instance = f
        .database
        .get_instance(&f.actor, cold.base.launch.instance_id)
        .await
        .map_err(api_failure)?;
    let request = CreateAutomation {
        name: "authenticated cold backup".into(),
        action: AutomationAction::Backup {
            request: crate::backup_ledger::CreateBackup {
                profile_id: cold.profile,
                retention_days: 31,
            },
        },
        trigger: AutomationTrigger::Once {
            at: Utc::now() + Duration::seconds(2),
        },
        delegation_expires_at: Utc::now() + Duration::days(1),
        run_budget: 1,
        minimum_interval_seconds: 60,
        grace_seconds: 300,
    };
    let receipt = f
        .database
        .create_automation(
            &f.actor,
            &identity,
            instance.id,
            &request,
            "cold-backup-automation",
            instance.spec_version,
            86400,
        )
        .await
        .map_err(api_failure)?;
    let worker = AutomationController::new(
        connections.automation.database_for("sandbox_automation")?,
        "cold-automation-worker".into(),
        3600,
        86400,
    )
    .map_err(api_failure)?;
    let claim = due_claim(&worker).await?;
    let p = worker.prepare(&claim).await.map_err(api_failure)?.unwrap();
    let (first, second) = tokio::join!(worker.accept(&p), worker.accept(&p));
    first.map_err(api_failure)?;
    second.map_err(api_failure)?;
    let mut tx = f.owner_transaction().await?;
    let (count,operation,produced,actual):(i64,Uuid,Uuid,Uuid)=sqlx::query_as("SELECT count(*) OVER(),r.operation_id,r.produced_resource_id,b.id FROM automation_runs r JOIN backups b ON b.tenant_id=r.tenant_id AND b.operation_id=r.operation_id WHERE r.tenant_id=$1 AND r.automation_id=$2")
  .bind(f.actor.tenant_id).bind(receipt.body.resource.id).fetch_one(&mut *tx).await?;
    ensure!(count == 1 && produced == actual);
    sqlx::query("UPDATE operations SET status='FAILED',stage='COMPLETED',completed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(operation).execute(&mut *tx).await?;
    tx.commit().await?;
    worker.run_claim(&claim).await.map_err(api_failure)?;
    let mut tx = f.owner_transaction().await?;
    let(status,held):(String,bool)=sqlx::query_as("SELECT r.status,NOT EXISTS(SELECT 1 FROM workspace_hold_releases h WHERE h.tenant_id=b.tenant_id AND h.hold_id=b.hold_id) FROM automation_runs r JOIN backups b ON b.tenant_id=r.tenant_id AND b.operation_id=r.operation_id WHERE r.tenant_id=$1 AND r.automation_id=$2")
  .bind(f.actor.tenant_id).bind(receipt.body.resource.id).fetch_one(&mut *tx).await?;
    ensure!(status == "SUBMITTED" && held);
    Ok(())
    })
}

#[test]
#[ignore = "requires dedicated disposable real PostgreSQL automation role"]
fn exact_event_rule_deduplicates_automated_feedback_and_enforces_interval_budget_and_signed_history()
-> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
    let _serial = test_support_db::serial().await;
    let r = Ready::new().await?;
    let mut request = r.request();
    request.run_budget = 2;
    request.trigger = AutomationTrigger::Event {
        event_type: "instances:renew.accepted".into(),
        aggregate_id: r.instance.id,
    };
    let receipt = r.create(&request).await?;
    let manual =
        r.f.database
            .renew_instance(
                &r.f.actor,
                r.instance.id,
                &crate::model::RenewRequest {
                    expires_at: Utc::now() + Duration::seconds(3600),
                },
                "manual-event-renew",
                r.instance.spec_version,
                86400,
            )
            .await
            .map_err(api_failure)?;
    sqlx::query(
        "UPDATE automation_claims SET eligible_at=clock_timestamp() WHERE automation_id=$1",
    )
    .bind(receipt.resource.id)
    .execute(&r.f.owner)
    .await?;
    let first = r.worker.claim().await.map_err(api_failure)?.unwrap();
    r.worker.run_claim(&first).await.map_err(api_failure)?;
    ensure!(r.count_operations(receipt.resource.id).await? == 1);
    // Reconcile the already accepted real renewal before reading later events.
    sqlx::query(
        "UPDATE automation_claims SET eligible_at=clock_timestamp() WHERE automation_id=$1",
    )
    .bind(receipt.resource.id)
    .execute(&r.f.owner)
    .await?;
    let close = r.worker.claim().await.map_err(api_failure)?.unwrap();
    r.worker.run_claim(&close).await.map_err(api_failure)?;
    sqlx::query(
        "UPDATE automation_claims SET eligible_at=clock_timestamp() WHERE automation_id=$1",
    )
    .bind(receipt.resource.id)
    .execute(&r.f.owner)
    .await?;
    let feedback = r.worker.claim().await.map_err(api_failure)?.unwrap();
    r.worker.run_claim(&feedback).await.map_err(api_failure)?;
    let a =
        r.f.database
            .get_automation(&r.f.actor, receipt.resource.id)
            .await
            .map_err(api_failure)?;
    ensure!(
        a.emitted_runs == 1,
        "known automated origin cannot retrigger the rule"
    );
    let current =
        r.f.database
            .get_instance(&r.f.actor, r.instance.id)
            .await
            .map_err(api_failure)?;
    r.f.database
        .renew_instance(
            &r.f.actor,
            r.instance.id,
            &crate::model::RenewRequest {
                expires_at: Utc::now() + Duration::seconds(9000),
            },
            "second-user-event",
            current.spec_version,
            86400,
        )
        .await
        .map_err(api_failure)?;
    sqlx::query(
        "UPDATE automation_claims SET eligible_at=clock_timestamp() WHERE automation_id=$1",
    )
    .bind(receipt.resource.id)
    .execute(&r.f.owner)
    .await?;
    let throttled = r.worker.claim().await.map_err(api_failure)?.unwrap();
    r.worker.run_claim(&throttled).await.map_err(api_failure)?;
    let a =
        r.f.database
            .get_automation(&r.f.actor, receipt.resource.id)
            .await
            .map_err(api_failure)?;
    ensure!(a.status == "EXHAUSTED" && a.emitted_runs == 2);
    ensure!(r.count_operations(a.id).await? == 1);
    let mut query = HistoryQuery {
        project_id: r.f.request.project_id,
        instance_id: Some(r.instance.id),
        limit: Some(1),
        cursor: None,
    };
    let page =
        r.f.database
            .list_automation_runs(&r.f.actor, a.id, &query, &signer())
            .await
            .map_err(api_failure)?;
    ensure!(
        page.items[0].status == "SKIPPED"
            && page.items[0].failure_code.as_deref() == Some("EVENT_RATE_LIMITED")
    );
    query.cursor = page.next_cursor;
    ensure!(query.cursor.is_some());
    let next =
        r.f.database
            .list_automation_runs(&r.f.actor, a.id, &query, &signer())
            .await
            .map_err(api_failure)?;
    ensure!(next.items[0].status == "SUCCEEDED");
    let mut tx = r.f.owner_transaction().await?;
    let source:Uuid=sqlx::query_scalar("SELECT e.operation_id FROM automation_runs r JOIN domain_events e ON e.tenant_id=r.tenant_id AND e.id=r.source_event_id WHERE r.tenant_id=$1 AND r.automation_id=$2 AND r.status='SUCCEEDED'").bind(r.f.actor.tenant_id).bind(a.id).fetch_one(&mut *tx).await?;
    ensure!(source == manual.body.operation.id);
    tx.rollback().await?;
    let mut tx = r.f.owner_transaction().await?;
    ensure!(
        sqlx::query("UPDATE automations SET run_budget=run_budget+1 WHERE tenant_id=$1 AND id=$2")
            .bind(r.f.actor.tenant_id)
            .bind(a.id)
            .execute(&mut *tx)
            .await
            .is_err()
    );
    tx.rollback().await?;
    let other =
        Fixture::new_with_verified_connections(10, &prepared_fixture().await?.fixture).await?;
    let mut tx = other
        .database
        .begin(other.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    let visible: i64 =
        sqlx::query_scalar("SELECT count(*) FROM automation_runs WHERE automation_id=$1")
            .bind(a.id)
            .fetch_one(&mut *tx)
            .await?;
    ensure!(visible == 0);
    tx.commit().await?;
    let mut forged = query.clone();
    forged.project_id = other.request.project_id;
    ensure!(
        r.f.database
            .list_automation_runs(&r.f.actor, a.id, &forged, &signer())
            .await
            .is_err()
    );
    Ok(())
    })
}

#[test]
#[ignore = "requires dedicated disposable real PostgreSQL automation role"]
fn durable_once_renewal_links_real_operation_and_recovers_lost_ack_without_reexecution()
-> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
        let _serial = test_support_db::serial().await;
        let r = Ready::new().await?;
        // Normal startup accepts the complete formal schema. The separately
        // bounded actual process suite exercises run/check/bind/SIGTERM; never
        // await an uncancelled successful daemon as a schema assertion.
        r.f.database.check_automation_api_schema().await?;
        r.worker.check_schema().await?;
        let request = r.request();
        let receipt = r.create(&request).await?;
        let same = r.create(&request).await?;
        ensure!(same.resource.id == receipt.resource.id);
        let claim = r.due_claim().await?;
        // The accepted creation receipt remains replayable after its once-at time.
        let after_due = r.create(&request).await?;
        ensure!(after_due.resource.id == receipt.resource.id);
        let p = r
            .worker
            .prepare(&claim)
            .await
            .map_err(api_failure)?
            .context("prepared request")?;
        r.worker.accept(&p).await.map_err(api_failure)?; // caller receipt is deliberately discarded
        ensure!(r.count_operations(receipt.resource.id).await? == 1);
        r.worker.run_claim(&claim).await.map_err(api_failure)?; // durable operation link outranks ACK loss
        ensure!(r.count_operations(receipt.resource.id).await? == 1);
        let current =
            r.f.database
                .get_automation(&r.f.actor, receipt.resource.id)
                .await
                .map_err(api_failure)?;
        ensure!(current.status == "EXHAUSTED");
        let query = HistoryQuery {
            project_id: r.f.request.project_id,
            instance_id: Some(r.instance.id),
            limit: Some(1),
            cursor: None,
        };
        let list =
            r.f.database
                .list_automations(&r.f.actor, &query, &signer())
                .await
                .map_err(api_failure)?;
        ensure!(list.items.len() == 1);
        let runs =
            r.f.database
                .list_automation_runs(&r.f.actor, receipt.resource.id, &query, &signer())
                .await
                .map_err(api_failure)?;
        ensure!(runs.items[0].status == "SUCCEEDED");
        let json = serde_json::to_string(&runs)?;
        for secret in [
            "original_request",
            "operation_request",
            "lease_token",
            "management_key",
            "identity_subject",
        ] {
            ensure!(!json.contains(secret));
        }
        let restricted = prepared_fixture()
            .await?
            .automation
            .database_for("sandbox_automation")?;
        let mut tx = restricted
            .begin(r.f.actor.tenant_id)
            .await
            .map_err(api_failure)?;
        ensure!(
            sqlx::query("SELECT lease_token FROM automation_runs")
                .execute(&mut *tx)
                .await
                .is_err()
        );
        tx.rollback().await?;
        Ok(())
    })
}

#[test]
#[ignore = "requires dedicated disposable real PostgreSQL automation role"]
fn pause_fences_prepared_acceptance_and_does_not_claim_existing_operation_cancelled()
-> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
        let _serial = test_support_db::serial().await;
        let r = Ready::new().await?;
        let mut request = r.request();
        request.run_budget = 2;
        let receipt = r.create(&request).await?;
        let claim = r.due_claim().await?;
        let p = r
            .worker
            .prepare(&claim)
            .await
            .map_err(api_failure)?
            .unwrap();
        let paused =
            r.f.database
                .change_automation(
                    &r.f.actor,
                    &r.identity,
                    receipt.resource.id,
                    &AutomationChange::Pause,
                    "pause",
                    1,
                )
                .await
                .map_err(api_failure)?;
        ensure!(paused.body.resource.status == "PAUSED");
        ensure!(r.worker.accept(&p).await.is_err());
        ensure!(r.count_operations(receipt.resource.id).await? == 0);
        let replay =
            r.f.database
                .change_automation(
                    &r.f.actor,
                    &r.identity,
                    receipt.resource.id,
                    &AutomationChange::Pause,
                    "pause",
                    1,
                )
                .await
                .map_err(api_failure)?;
        ensure!(replay.body.resource.version == 2);
        let revoked =
            r.f.database
                .change_automation(
                    &r.f.actor,
                    &r.identity,
                    receipt.resource.id,
                    &AutomationChange::Revoke,
                    "revoke",
                    2,
                )
                .await
                .map_err(api_failure)?;
        ensure!(revoked.body.resource.status == "REVOKED");
        ensure!(
            r.f.database
                .change_automation(
                    &r.f.actor,
                    &r.identity,
                    receipt.resource.id,
                    &AutomationChange::Resume,
                    "resume",
                    3
                )
                .await
                .is_err()
        );
        let query = HistoryQuery {
            project_id: r.f.request.project_id,
            instance_id: None,
            limit: None,
            cursor: None,
        };
        let runs =
            r.f.database
                .list_automation_runs(&r.f.actor, receipt.resource.id, &query, &signer())
                .await
                .map_err(api_failure)?;
        ensure!(runs.items[0].status == "CANCELLED");
        Ok(())
    })
}

#[test]
#[ignore = "requires dedicated disposable real PostgreSQL automation role"]
fn final_event_head_wait_rechecks_live_grant_and_rolls_back_operation_link() -> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
    let _serial = test_support_db::serial().await;
    let r = Ready::new().await?;
    let receipt = r.create(&r.request()).await?;
    let claim = r.due_claim().await?;
    let p = r
        .worker
        .prepare(&claim)
        .await
        .map_err(api_failure)?
        .unwrap();
    let mut head = r.f.owner_transaction().await?;
    sqlx::query(
        "SELECT project_id FROM event_stream_heads WHERE tenant_id=$1 AND project_id=$2 FOR UPDATE",
    )
    .bind(r.f.actor.tenant_id)
    .bind(r.f.request.project_id)
    .fetch_one(&mut *head)
    .await?;
    let accept = r.worker.accept(&p);
    let revoke = async {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let mut tx = r.f.owner_transaction().await?;
        sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='instances:renew'").bind(r.f.actor.tenant_id).bind(r.f.actor.principal_id).execute(&mut *tx).await?;
        tx.commit().await?;
        head.commit().await?;
        Ok::<(), anyhow::Error>(())
    };
    let (result, revoked) = tokio::join!(accept, revoke);
    revoked?;
    ensure!(result.is_err());
    ensure!(r.count_operations(receipt.resource.id).await? == 0);
    let mut tx = r.f.owner_transaction().await?;
    let linked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM automation_runs WHERE tenant_id=$1 AND automation_id=$2 AND operation_id IS NOT NULL)").bind(r.f.actor.tenant_id).bind(receipt.resource.id).fetch_one(&mut *tx).await?;
    ensure!(!linked);
    Ok(())
    })
}

#[test]
#[ignore = "requires dedicated disposable real PostgreSQL automation role"]
fn parallel_claim_and_lost_lease_cannot_borrow_a_new_workers_fence() -> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
    let _serial = test_support_db::serial().await;
    let r = Ready::new().await?;
    let receipt = r.create(&r.request()).await?;
    let mut due = r.f.owner_transaction().await?;
    sqlx::query("SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM(next_due_at-clock_timestamp())))) FROM automations WHERE tenant_id=$1 AND id=$2 AND next_due_at<clock_timestamp()+interval '10 seconds'")
        .bind(r.f.actor.tenant_id).bind(receipt.resource.id).fetch_one(&mut *due).await?;
    due.commit().await?;
    let claims = futures_util::future::join_all((0..12).map(|_| r.worker.claim())).await;
    let mut winners = Vec::new();
    for c in claims {
        if let Some(c) = c.map_err(api_failure)? {
            winners.push(c);
        }
    }
    ensure!(
        winners.len() == 1,
        "one durable queue row permits exactly one concurrent claim"
    );
    let old = winners.pop().unwrap();
    let prepared = r.worker.prepare(&old).await.map_err(api_failure)?.unwrap();
    // An operator-controlled fixture forces a real DB lease loss. Run identity,
    // original request and key are preserved; neither client time nor sleeps
    // manufacture a new request or a false operation completion.
    sqlx::query("UPDATE automation_claims SET lease_owner=NULL,lease_until=NULL,eligible_at=clock_timestamp() WHERE automation_id=$1").bind(receipt.resource.id).execute(&r.f.owner).await?;
    let current = r.worker.claim().await.map_err(api_failure)?.unwrap();
    ensure!(current.lease_token > old.lease_token);
    let replay = r
        .worker
        .prepare(&current)
        .await
        .map_err(api_failure)?
        .unwrap();
    ensure!(
        r.worker.accept(&prepared).await.is_err(),
        "stale token cannot use the renewed run lease"
    );
    r.worker.accept(&replay).await.map_err(api_failure)?;
    ensure!(r.count_operations(receipt.resource.id).await? == 1);
    let mut tx = r.f.owner_transaction().await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM automation_runs WHERE tenant_id=$1 AND automation_id=$2",
    )
    .bind(r.f.actor.tenant_id)
    .bind(receipt.resource.id)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(count == 1);
    Ok(())
    })
}

#[test]
#[ignore = "requires dedicated disposable real PostgreSQL automation role"]
fn missed_cron_records_one_skipped_span_and_advances_to_future_db_time() -> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
    let _serial = test_support_db::serial().await;
    let r = Ready::new().await?;
    let mut request = r.request();
    request.trigger = AutomationTrigger::CronUtc {
        expression: "0 * * * * * *".into(),
    };
    request.run_budget = 10;
    request.grace_seconds = 1;
    let receipt = r.create(&request).await?;
    let mut tx = r.f.owner_transaction().await?;
    sqlx::query("UPDATE automations SET next_due_at=clock_timestamp()-interval '5 hours' WHERE tenant_id=$1 AND id=$2").bind(r.f.actor.tenant_id).bind(receipt.resource.id).execute(&mut *tx).await?;
    tx.commit().await?;
    let claim = r.worker.claim().await.map_err(api_failure)?.unwrap();
    r.worker.run_claim(&claim).await.map_err(api_failure)?;
    ensure!(r.count_operations(receipt.resource.id).await? == 0);
    let a =
        r.f.database
            .get_automation(&r.f.actor, receipt.resource.id)
            .await
            .map_err(api_failure)?;
    ensure!(a.emitted_runs == 1);
    let mut tx = r.f.owner_transaction().await?;
    let future: bool = sqlx::query_scalar(
        "SELECT next_due_at>clock_timestamp() FROM automations WHERE tenant_id=$1 AND id=$2",
    )
    .bind(r.f.actor.tenant_id)
    .bind(a.id)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(future);
    let (status,span):(String,bool)=sqlx::query_as("SELECT status,skipped_through>=scheduled_for+interval '5 hours' FROM automation_runs WHERE tenant_id=$1 AND automation_id=$2").bind(r.f.actor.tenant_id).bind(a.id).fetch_one(&mut *tx).await?;
    ensure!(status == "SKIPPED" && span);
    Ok(())
    })
}

#[test]
#[ignore = "requires dedicated disposable real PostgreSQL automation role"]
fn final_event_head_wait_cannot_extend_the_original_run_deadline() -> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
        let _serial = test_support_db::serial().await;
        let r = Ready::new().await?;
        let mut request = r.request();
        request.grace_seconds = 1;
        let receipt = r.create(&request).await?;
        let claim = r.due_claim().await?;
        let p = r
            .worker
            .prepare(&claim)
            .await
            .map_err(api_failure)?
            .unwrap();
        let mut head = r.f.owner_transaction().await?;
        sqlx::query(
        "SELECT project_id FROM event_stream_heads WHERE tenant_id=$1 AND project_id=$2 FOR UPDATE",
    )
    .bind(r.f.actor.tenant_id)
    .bind(r.f.request.project_id)
    .fetch_one(&mut *head)
    .await?;
        let result = r.worker.accept(&p);
        let release = async {
            tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
            head.commit().await
        };
        let (result, released) = tokio::join!(result, release);
        released?;
        ensure!(result.is_err());
        ensure!(r.count_operations(receipt.resource.id).await? == 0);
        Ok(())
    })
}

async fn wait_for_database_lock_waiters(owner: &sqlx::PgPool, minimum: i64) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        let count:i64=sqlx::query_scalar("SELECT count(DISTINCT l.pid) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.datname=current_database() AND NOT l.granted AND l.pid<>pg_backend_pid()")
            .fetch_one(owner).await?;
        if count >= minimum {
            return Ok(());
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "expected concurrent database lock waiters"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[test]
#[ignore = "requires dedicated disposable real PostgreSQL automation role"]
fn concurrent_pause_and_delegation_revoke_linearize_with_acceptance_without_cancel_claims()
-> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
    let _serial = test_support_db::serial().await;
    for change in [AutomationChange::Pause, AutomationChange::Revoke] {
        for acceptance_first in [false, true] {
            let r = Ready::new().await?;
            let receipt = r.create(&r.request()).await?;
            let claim = r.due_claim().await?;
            let prepared = r
                .worker
                .prepare(&claim)
                .await
                .map_err(api_failure)?
                .unwrap();
            let mut head = r.f.owner_transaction().await?;
            sqlx::query("SELECT project_id FROM event_stream_heads WHERE tenant_id=$1 AND project_id=$2 FOR UPDATE")
                .bind(r.f.actor.tenant_id).bind(r.f.request.project_id).fetch_one(&mut *head).await?;
            let accept = async {
                if !acceptance_first {
                    wait_for_database_lock_waiters(&r.f.owner, 1).await?;
                }
                Ok::<_, anyhow::Error>(r.worker.accept(&prepared).await)
            };
            let changing = async {
                if acceptance_first {
                    wait_for_database_lock_waiters(&r.f.owner, 1).await?;
                }
                r.f.database
                    .change_automation(
                        &r.f.actor,
                        &r.identity,
                        receipt.resource.id,
                        &change,
                        "concurrent-change",
                        1,
                    )
                    .await
                    .map_err(api_failure)
            };
            let release = async {
                wait_for_database_lock_waiters(&r.f.owner, 2).await?;
                head.commit().await?;
                Ok::<(), anyhow::Error>(())
            };
            let (accepted, changed, released) = tokio::join!(accept, changing, release);
            released?;
            let accepted = accepted?;
            let changed = changed?;
            ensure!(
                changed.body.resource.status
                    == if matches!(change, AutomationChange::Pause) {
                        "PAUSED"
                    } else {
                        "REVOKED"
                    }
            );
            let operations = r.count_operations(receipt.resource.id).await?;
            let mut tx = r.f.owner_transaction().await?;
            let(status,operation):(String,Option<Uuid>)=sqlx::query_as("SELECT status,operation_id FROM automation_runs WHERE tenant_id=$1 AND automation_id=$2")
                .bind(r.f.actor.tenant_id).bind(receipt.resource.id).fetch_one(&mut *tx).await?;
            if acceptance_first {
                accepted.map_err(api_failure)?;
                ensure!(
                    operations == 1 && status == "SUBMITTED" && operation.is_some(),
                    "committed effects cannot be reported cancelled"
                );
            } else {
                ensure!(
                    accepted.is_err()
                        && operations == 0
                        && status == "CANCELLED"
                        && operation.is_none(),
                    "pause/revocation wins before any business operation"
                );
            }
        }
    }
    Ok(())
    })
}

#[test]
#[ignore = "requires dedicated disposable real PostgreSQL automation role"]
fn event_stream_epoch_change_fences_prepared_intent_and_requires_a_new_rule() -> anyhow::Result<()>
{
    automation_test_runtime().block_on(async {
    let _serial = test_support_db::serial().await;
    let r = Ready::new().await?;
    let mut request = r.request();
    request.run_budget = 2;
    request.trigger = AutomationTrigger::Event {
        event_type: "instances:renew.accepted".into(),
        aggregate_id: r.instance.id,
    };
    let receipt = r.create(&request).await?;
    r.f.database
        .renew_instance(
            &r.f.actor,
            r.instance.id,
            &crate::model::RenewRequest {
                expires_at: Utc::now() + Duration::seconds(3600),
            },
            "event-before-reset",
            r.instance.spec_version,
            86400,
        )
        .await
        .map_err(api_failure)?;
    sqlx::query(
        "UPDATE automation_claims SET eligible_at=clock_timestamp() WHERE automation_id=$1",
    )
    .bind(receipt.resource.id)
    .execute(&r.f.owner)
    .await?;
    let claim = r.worker.claim().await.map_err(api_failure)?.unwrap();
    let prepared = r
        .worker
        .prepare(&claim)
        .await
        .map_err(api_failure)?
        .unwrap();
    let mut tx = r.f.owner_transaction().await?;
    sqlx::query("UPDATE event_stream_heads SET epoch=gen_random_uuid() WHERE tenant_id=$1 AND project_id=$2")
        .bind(r.f.actor.tenant_id).bind(r.f.request.project_id).execute(&mut *tx).await?;
    tx.commit().await?;
    ensure!(r.worker.accept(&prepared).await.is_err());
    r.worker.run_claim(&claim).await.map_err(api_failure)?;
    ensure!(r.count_operations(receipt.resource.id).await? == 0);
    let rule =
        r.f.database
            .get_automation(&r.f.actor, receipt.resource.id)
            .await
            .map_err(api_failure)?;
    ensure!(rule.status == "PAUSED");
    let runs =
        r.f.database
            .list_automation_runs(
                &r.f.actor,
                rule.id,
                &HistoryQuery {
                    project_id: rule.project_id,
                    instance_id: None,
                    limit: None,
                    cursor: None,
                },
                &signer(),
            )
            .await
            .map_err(api_failure)?;
    ensure!(
        runs.items[0].status == "CANCELLED"
            && runs.items[0].failure_code.as_deref() == Some("EVENT_STREAM_CHANGED")
    );
    ensure!(
        r.f.database
            .change_automation(
                &r.f.actor,
                &r.identity,
                rule.id,
                &AutomationChange::Resume,
                "resume-after-stream-reset",
                rule.version
            )
            .await
            .is_err()
    );
    Ok(())
    })
}

#[test]
#[ignore = "requires dedicated disposable real PostgreSQL automation role"]
fn epoch_change_before_prepare_invalidates_claim_and_new_claim_preserves_single_intent()
-> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
    let _serial = test_support_db::serial().await;
    let r = Ready::new().await?;
    let receipt = r.create(&r.request()).await?;
    let claim = r.due_claim().await?;
    let original: Uuid =
        sqlx::query_scalar("SELECT cluster_epoch FROM platform_configuration WHERE singleton")
            .fetch_one(&r.f.owner)
            .await?;
    sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton")
        .bind(Uuid::new_v4())
        .execute(&r.f.owner)
        .await?;
    let result = r.worker.prepare(&claim).await;
    // Restore the independent test configuration before any fallible assertion.
    sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton")
        .bind(original)
        .execute(&r.f.owner)
        .await?;
    ensure!(
        result.map_err(api_failure)?.is_none(),
        "an old due claim cannot construct an intent in a new epoch"
    );
    let mut tx = r.f.owner_transaction().await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM automation_runs WHERE tenant_id=$1 AND automation_id=$2",
    )
    .bind(r.f.actor.tenant_id)
    .bind(receipt.resource.id)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(count == 0);
    tx.commit().await?;
    sqlx::query("UPDATE automation_claims SET lease_owner=NULL,lease_until=NULL,eligible_at=clock_timestamp() WHERE automation_id=$1").bind(receipt.resource.id).execute(&r.f.owner).await?;
    let fresh = r.worker.claim().await.map_err(api_failure)?.unwrap();
    r.worker.run_claim(&fresh).await.map_err(api_failure)?;
    ensure!(r.count_operations(receipt.resource.id).await? == 1);
    Ok(())
    })
}

#[path = "automation_http_tests.rs"]
mod http;

#[test]
#[ignore = "requires dedicated disposable real PostgreSQL automation role"]
fn durable_controller_restart_recovers_prepared_run_and_shutdown_does_not_create_second_work()
-> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
    let _serial = test_support_db::serial().await;
    let r = Ready::new().await?;
    let receipt = r.create(&r.request()).await?;
    let old = r.due_claim().await?;
    let original = r.worker.prepare(&old).await.map_err(api_failure)?.unwrap();
    let mut tx = r.f.owner_transaction().await?;
    let intent:(Uuid,Value,String,Uuid,Uuid)=sqlx::query_as("SELECT id,original_request,management_key,produced_resource_id,dispatch_attempt_id FROM automation_runs WHERE tenant_id=$1 AND automation_id=$2")
        .bind(r.f.actor.tenant_id).bind(receipt.resource.id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    // Simulate the coordinator process ending after durable prepare and before
    // management I/O. Force only the disposable queue's lease expiry.
    sqlx::query("UPDATE automation_claims SET lease_owner=NULL,lease_until=NULL,eligible_at=clock_timestamp() WHERE automation_id=$1")
        .bind(receipt.resource.id).execute(&r.f.owner).await?;
    let restarted = AutomationController::new(
        prepared_fixture()
            .await?
            .automation
            .database_for("sandbox_automation")?,
        format!("restart-{}", Uuid::new_v4()),
        3600,
        86400,
    )
    .map_err(api_failure)?;
    let shutdown = tokio_util::sync::CancellationToken::new();
    let loop_stop = shutdown.clone();
    let mut task = tokio::spawn(async move { std::sync::Arc::new(restarted).run(loop_stop).await });
    let outcome = async {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if r.count_operations(receipt.resource.id).await? == 1 {
                break;
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "restarted durable worker must reconcile the existing prepared run"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        // Once the new coordinator committed the atomic operation/run link,
        // the original caller may obtain its exact retained idempotent receipt.
        // This is a read of the accepted result, not a new acceptance.
        r.worker.accept(&original).await.map_err(api_failure)?;
        ensure!(r.count_operations(receipt.resource.id).await? == 1);
        Ok::<(), anyhow::Error>(())
    }
    .await;
    shutdown.cancel();
    match tokio::time::timeout(std::time::Duration::from_secs(5), &mut task).await {
        Ok(result) => result??,
        Err(_) => {
            task.abort();
            let _ = task.await;
            anyhow::bail!("restarted fixture worker exceeded its original shutdown budget");
        }
    }
    outcome?;
    ensure!(r.count_operations(receipt.resource.id).await? == 1);
    let mut tx = r.f.owner_transaction().await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM automation_runs WHERE tenant_id=$1 AND automation_id=$2",
    )
    .bind(r.f.actor.tenant_id)
    .bind(receipt.resource.id)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(count == 1);
    let current:(Uuid,Value,String,Uuid,Uuid)=sqlx::query_as("SELECT id,original_request,management_key,produced_resource_id,dispatch_attempt_id FROM automation_runs WHERE tenant_id=$1 AND automation_id=$2")
        .bind(r.f.actor.tenant_id).bind(receipt.resource.id).fetch_one(&mut *tx).await?;
    ensure!(
        current == intent,
        "restart preserves the original run, body, key, resource and attempt"
    );
    Ok(())
    })
}

#[test]
#[ignore = "requires dedicated disposable real PostgreSQL automation role"]
fn real_lifecycle_stop_preempts_pending_create_once_and_retains_compute_until_physical_closure()
-> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
    let _serial = test_support_db::serial().await;
    let r = Ready::new().await?;
    let mut request = r.request();
    request.action = AutomationAction::Stop;
    let receipt = r.create(&request).await?;
    let claim = r.due_claim().await?;
    let p = r
        .worker
        .prepare(&claim)
        .await
        .map_err(api_failure)?
        .unwrap();
    let (first, second) = tokio::join!(r.worker.accept(&p), r.worker.accept(&p));
    first.map_err(api_failure)?;
    second.map_err(api_failure)?;
    ensure!(r.count_operations(receipt.resource.id).await? == 1);
    let current =
        r.f.database
            .get_instance(&r.f.actor, r.instance.id)
            .await
            .map_err(api_failure)?;
    ensure!(current.desired_state == "STOPPED" && current.stop_accepted_at.is_some());
    let mut tx = r.f.owner_transaction().await?;
    let(status,kind):(String,String)=sqlx::query_as("SELECT o.status,o.kind FROM operations o JOIN automation_runs r ON r.tenant_id=o.tenant_id AND r.operation_id=o.id WHERE r.tenant_id=$1 AND r.automation_id=$2")
        .bind(r.f.actor.tenant_id).bind(receipt.resource.id).fetch_one(&mut *tx).await?;
    ensure!(kind == "STOP" && status == "QUEUED");
    let held:i64=sqlx::query_scalar("SELECT count(*) FROM quota_reservations r JOIN quota_accounts q ON q.tenant_id=r.tenant_id AND q.id=r.quota_account_id WHERE r.tenant_id=$1 AND r.resource_id=$2 AND r.status<>'RELEASED' AND q.dimension IN('CPU_MILLIS','MEMORY_MIB')")
        .bind(r.f.actor.tenant_id).bind(r.instance.id).fetch_one(&mut *tx).await?;
    ensure!(
        held > 0,
        "requesting STOP is not proof that compute physically ended"
    );
    tx.commit().await?;
    r.worker.run_claim(&claim).await.map_err(api_failure)?;
    let run =
        r.f.database
            .list_automation_runs(
                &r.f.actor,
                receipt.resource.id,
                &HistoryQuery {
                    project_id: r.f.request.project_id,
                    instance_id: None,
                    limit: None,
                    cursor: None,
                },
                &signer(),
            )
            .await
            .map_err(api_failure)?;
    ensure!(run.items[0].status == "SUBMITTED");
    Ok(())
    })
}

#[test]
#[ignore = "requires dedicated disposable real PostgreSQL automation role"]
fn safe_mode_denies_due_claim_and_old_prepared_acceptance_without_changing_effect_result()
-> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
        let _serial = test_support_db::serial().await;
        let r = Ready::new().await?;
        let receipt = r.create(&r.request()).await?;
        let claim = r.due_claim().await?;
        let prepared = r
            .worker
            .prepare(&claim)
            .await
            .map_err(api_failure)?
            .unwrap();
        let original: bool =
            sqlx::query_scalar("SELECT safe_mode FROM platform_configuration WHERE singleton")
                .fetch_one(&r.f.owner)
                .await?;
        sqlx::query("UPDATE platform_configuration SET safe_mode=true WHERE singleton")
            .execute(&r.f.owner)
            .await?;
        let result = async {
            ensure!(r.worker.claim().await.map_err(api_failure)?.is_none());
            ensure!(
                r.worker
                    .prepare(&claim)
                    .await
                    .map_err(api_failure)?
                    .is_none()
            );
            ensure!(r.worker.accept(&prepared).await.is_err());
            ensure!(r.count_operations(receipt.resource.id).await? == 0);
            Ok::<(), anyhow::Error>(())
        }
        .await;
        sqlx::query("UPDATE platform_configuration SET safe_mode=$1 WHERE singleton")
            .bind(original)
            .execute(&r.f.owner)
            .await?;
        result?;
        Ok(())
    })
}
