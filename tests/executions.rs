#[allow(dead_code)]
mod support;

use std::{collections::BTreeMap, sync::Arc};

use anyhow::{Context, ensure};
use futures_util::future::join_all;
use sandbox_platform::{
    engine::{Claim, OperationEngine},
    execution::{DispatchIdentity, ExecutionMutationResult},
    model::{CancelExecution, CreateExecution, ExecutionTimeoutPolicy, Instance},
};
use serde_json::{Value, json};
use support::{Fixture, api_failure, require_pg_error};
use tokio::sync::Barrier;
use uuid::Uuid;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use sandbox_platform::{
    api::{AppState, router},
    auth::{AuthConfig, JwtAuthenticator},
};
use tower::ServiceExt;

fn command() -> CreateExecution {
    CreateExecution {
        argv: vec![
            "/usr/bin/python3".into(),
            "-c".into(),
            "print('ordinary-argument-marker')".into(),
        ],
        public_env: BTreeMap::from([("TASK_MODE".into(), "ordinary-environment-marker".into())]),
        cwd: "/workspace".into(),
        timeout_seconds: 60,
        on_timeout: ExecutionTimeoutPolicy::HardStopInstance,
        output_limit_bytes: 1024,
        client_reference: Some("execution-integration".into()),
    }
}

struct Ready {
    fixture: Fixture,
    instance: Instance,
    identity: DispatchIdentity,
}
impl Ready {
    async fn new(execution_limit: i64) -> anyhow::Result<Self> {
        let fixture = Fixture::new(10).await?;
        let created = fixture
            .create("execution-instance")
            .await
            .map_err(api_failure)?;
        fixture
            .seed_observed_state(created.body.resource.id, "RUNNING")
            .await?;
        let mut tx = fixture.owner_transaction().await?;
        for action in ["executions:create", "executions:read", "executions:cancel"] {
            sqlx::query(
                "INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4)",
            )
            .bind(fixture.actor.tenant_id)
            .bind(created.body.resource.project_id)
            .bind(fixture.actor.principal_id)
            .bind(action)
            .execute(&mut *tx)
            .await?;
        }
        for project in [None, Some(created.body.resource.project_id)] {
            sqlx::query("INSERT INTO quota_accounts(tenant_id,project_id,dimension,limit_value) VALUES($1,$2,'EXECUTIONS',$3)")
                .bind(fixture.actor.tenant_id).bind(project).bind(execution_limit).execute(&mut *tx).await?;
        }
        let pod = Uuid::new_v4();
        // These are controlled, owner-seeded admission prerequisites. This test
        // does not claim that a Kubernetes Pod was observed or a VM was run.
        sqlx::query("UPDATE instances SET pod_uid=$3,ready_generation=runtime_generation,ready_launch_id=launch_id,ready_pod_uid=$3,ready_cluster_epoch=cluster_epoch,ready_observed_at=clock_timestamp(),observed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
            .bind(fixture.actor.tenant_id).bind(created.body.resource.id).bind(pod).execute(&mut *tx).await?;
        let (generation,launch,epoch):(i64,Uuid,Uuid)=sqlx::query_as("SELECT runtime_generation,launch_id,cluster_epoch FROM instances WHERE tenant_id=$1 AND id=$2")
            .bind(fixture.actor.tenant_id).bind(created.body.resource.id).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        let instance = fixture
            .database
            .get_instance(&fixture.actor, created.body.resource.id)
            .await
            .map_err(api_failure)?;
        Ok(Self {
            fixture,
            instance,
            identity: DispatchIdentity {
                runtime_generation: generation,
                launch_id: launch,
                pod_uid: pod,
                cluster_epoch: epoch,
            },
        })
    }
    async fn create(
        &self,
        key: &str,
    ) -> Result<ExecutionMutationResult, sandbox_platform::error::ApiError> {
        self.fixture
            .database
            .create_execution(
                &self.fixture.actor,
                self.instance.id,
                &command(),
                key,
                self.instance.spec_version,
            )
            .await
    }
    async fn claim(&self, operation: Uuid) -> anyhow::Result<(OperationEngine, Claim)> {
        let mut tx = self.fixture.owner_transaction().await?;
        sqlx::query("UPDATE operations SET status='RUNNING',lease_owner='execution-integration-worker',lease_token=1,lease_until=clock_timestamp()+interval '5 minutes' WHERE tenant_id=$1 AND id=$2")
            .bind(self.fixture.actor.tenant_id).bind(operation).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok((
            OperationEngine::new(
                self.fixture.database.clone(),
                "execution-integration-worker".into(),
            )?,
            Claim {
                tenant_id: self.fixture.actor.tenant_id,
                operation_id: operation,
                lease_token: 1,
            },
        ))
    }
    async fn quota(&self) -> anyhow::Result<Vec<Value>> {
        let mut tx = self.fixture.owner_transaction().await?;
        let rows = sqlx::query_scalar(
            "SELECT to_jsonb(q) FROM quota_accounts q WHERE tenant_id=$1 ORDER BY id",
        )
        .bind(self.fixture.actor.tenant_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows)
    }
}

#[test]
fn command_validation_reuses_runner_limits_and_rejects_ambiguous_environment() -> anyhow::Result<()>
{
    let valid = command();
    assert!(valid.runner_request(Uuid::new_v4()).is_ok());
    let mut bad = valid.clone();
    bad.argv = Vec::new();
    assert!(bad.runner_request(Uuid::new_v4()).is_err());
    let mut bad = valid.clone();
    bad.argv = vec!["x".into(); 65];
    assert!(bad.runner_request(Uuid::new_v4()).is_err());
    let mut bad = valid.clone();
    bad.cwd = "/workspace/../etc".into();
    assert!(bad.runner_request(Uuid::new_v4()).is_err());
    let mut bad = valid.clone();
    bad.public_env.insert("PATH".into(), "/untrusted".into());
    assert!(bad.runner_request(Uuid::new_v4()).is_err());
    let mut bad = valid.clone();
    bad.public_env.insert("SANDBOX_TOKEN".into(), "x".into());
    assert!(bad.runner_request(Uuid::new_v4()).is_err());
    let mut bad = valid.clone();
    bad.timeout_seconds = 3601;
    assert!(bad.runner_request(Uuid::new_v4()).is_err());
    let mut bad = valid.clone();
    bad.output_limit_bytes = 16 * 1024 * 1024 + 1;
    assert!(bad.runner_request(Uuid::new_v4()).is_err());
    let duplicate = r#"{"argv":["true"],"public_env":{"TASK":"one","TASK":"two"},"cwd":"/workspace","timeout_seconds":1,"on_timeout":"HARD_STOP_INSTANCE","output_limit_bytes":0}"#;
    assert!(serde_json::from_str::<CreateExecution>(duplicate).is_err());
    let mut secret = serde_json::to_value(&valid)?;
    secret["secret_env"] = json!({"PASSWORD":"must-reject"});
    assert!(serde_json::from_value::<CreateExecution>(secret).is_err());
    let mut missing_policy = serde_json::to_value(&valid)?;
    missing_policy
        .as_object_mut()
        .context("Command must be an object")?
        .remove("on_timeout");
    assert!(serde_json::from_value::<CreateExecution>(missing_policy).is_err());
    let mut unsupported_policy = serde_json::to_value(&valid)?;
    unsupported_policy["on_timeout"] = json!("IGNORE");
    assert!(serde_json::from_value::<CreateExecution>(unsupported_policy).is_err());
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn concurrent_same_key_returns_one_receipt_and_public_views_never_echo_command_parameters()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let ready = Ready::new(2).await?;
    let barrier = Arc::new(Barrier::new(8));
    let attempts = (0..8).map(|_| {
        let database = ready.fixture.database.clone();
        let actor = ready.fixture.actor.clone();
        let barrier = barrier.clone();
        let id = ready.instance.id;
        let version = ready.instance.spec_version;
        async move {
            barrier.wait().await;
            database
                .create_execution(&actor, id, &command(), "shared-execution-key", version)
                .await
        }
    });
    let mut receipts = Vec::new();
    for result in join_all(attempts).await {
        receipts.push(result.map_err(api_failure)?.body);
    }
    let first = receipts.first().context("No execution receipts")?;
    for receipt in &receipts {
        assert_eq!(serde_json::to_value(receipt)?, serde_json::to_value(first)?);
    }
    assert_eq!(ready.fixture.count("operations").await?, 2);
    assert_eq!(ready.fixture.count("quota_reservations").await?, 10);
    let fetched = ready
        .fixture
        .database
        .get_execution(&ready.fixture.actor, first.resource.id)
        .await
        .map_err(api_failure)?;
    assert_eq!(fetched.status, "QUEUED");
    assert!(fetched.slot_held);
    assert!(fetched.result_ref.is_none());
    let instance = ready
        .fixture
        .database
        .get_instance(&ready.fixture.actor, ready.instance.id)
        .await
        .map_err(api_failure)?;
    assert!(instance.slot_held);
    assert_eq!(instance.spec_version, ready.instance.spec_version + 1);
    let mut tx = ready.fixture.owner_transaction().await?;
    let observations:Value=sqlx::query_scalar("SELECT jsonb_build_object('audits',(SELECT jsonb_agg(to_jsonb(a)) FROM audit_events a WHERE tenant_id=$1),'events',(SELECT jsonb_agg(to_jsonb(d)) FROM domain_events d WHERE tenant_id=$1))")
        .bind(ready.fixture.actor.tenant_id).fetch_one(&mut *tx).await?;
    let stored: Value =
        sqlx::query_scalar("SELECT request FROM operations WHERE tenant_id=$1 AND id=$2")
            .bind(ready.fixture.actor.tenant_id)
            .bind(first.operation.id)
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    for value in [
        serde_json::to_value(first)?,
        serde_json::to_value(fetched)?,
        observations,
    ] {
        let encoded = value.to_string();
        assert!(!encoded.contains("ordinary-argument-marker"));
        assert!(!encoded.contains("ordinary-environment-marker"));
    }
    assert_eq!(
        stored["runner"]["env"]["TASK_MODE"],
        "ordinary-environment-marker"
    );
    let mut changed = command();
    changed.argv = vec!["true".into()];
    let result = ready
        .fixture
        .database
        .create_execution(
            &ready.fixture.actor,
            ready.instance.id,
            &changed,
            "shared-execution-key",
            ready.instance.spec_version,
        )
        .await;
    assert!(matches!(result,Err(error) if error.code=="IDEMPOTENCY_CONFLICT"));
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn competing_commands_share_one_activity_slot_and_both_quota_scopes_are_enforced()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let ready = Ready::new(1).await?;
    let barrier = Arc::new(Barrier::new(6));
    let attempts = (0..6).map(|index| {
        let database = ready.fixture.database.clone();
        let actor = ready.fixture.actor.clone();
        let barrier = barrier.clone();
        let id = ready.instance.id;
        let version = ready.instance.spec_version;
        async move {
            barrier.wait().await;
            database
                .create_execution(
                    &actor,
                    id,
                    &command(),
                    &format!("competing-{index}"),
                    version,
                )
                .await
        }
    });
    let mut accepted = 0;
    for result in join_all(attempts).await {
        match result {
            Ok(_) => accepted += 1,
            Err(error) => assert_eq!(error.code, "VERSION_MISMATCH"),
        }
    }
    assert_eq!(accepted, 1);
    let busy = ready
        .fixture
        .database
        .create_execution(
            &ready.fixture.actor,
            ready.instance.id,
            &command(),
            "while-slot-held",
            ready.instance.spec_version + 1,
        )
        .await;
    assert!(matches!(busy,Err(error) if error.code=="INSTANCE_BUSY"));
    let limited = Ready::new(0).await?;
    let quota = limited.create("no-budget").await;
    assert!(matches!(quota,Err(error) if error.code=="QUOTA_EXCEEDED"));
    let mut tx = limited.fixture.owner_transaction().await?;
    sqlx::query("UPDATE quota_accounts SET limit_value=1 WHERE tenant_id=$1 AND dimension='EXECUTIONS' AND project_id IS NOT NULL")
        .bind(limited.fixture.actor.tenant_id).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(
        matches!(limited.create("tenant-budget-still-zero").await,Err(error) if error.code=="QUOTA_EXCEEDED")
    );
    assert_eq!(limited.fixture.count("operations").await?, 1);
    let current = limited
        .fixture
        .database
        .get_instance(&limited.fixture.actor, limited.instance.id)
        .await
        .map_err(api_failure)?;
    assert!(!current.slot_held);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn timeout_policy_requires_hard_stop_authority_on_admission_replay_and_dispatch_and_rejects_legacy_requests()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let ready = Ready::new(2).await?;
    let mut tx = ready.fixture.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='instances:hard_stop'")
        .bind(ready.fixture.actor.tenant_id).bind(ready.fixture.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(ready.create("missing-timeout-authority").await.is_err());
    assert_eq!(ready.fixture.count("operations").await?, 1);
    let mut tx = ready.fixture.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=true WHERE tenant_id=$1 AND principal_id=$2 AND action='instances:hard_stop'")
        .bind(ready.fixture.actor.tenant_id).bind(ready.fixture.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let accepted = ready
        .create("timeout-authorized")
        .await
        .map_err(api_failure)?;
    let (engine, claim) = ready.claim(accepted.body.operation.id).await?;
    let mut tx = ready.fixture.owner_transaction().await?;
    let stored: Value =
        sqlx::query_scalar("SELECT request FROM operations WHERE tenant_id=$1 AND id=$2")
            .bind(ready.fixture.actor.tenant_id)
            .bind(accepted.body.operation.id)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(stored["on_timeout"], "HARD_STOP_INSTANCE");
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='instances:hard_stop'")
        .bind(ready.fixture.actor.tenant_id).bind(ready.fixture.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(ready.create("timeout-authorized").await.is_err());
    assert!(
        ready
            .fixture
            .database
            .begin_execution_dispatch(&engine, &claim, accepted.body.resource.id, ready.identity)
            .await
            .is_err()
    );

    let legacy = Ready::new(2).await?;
    let execution = Uuid::new_v4();
    let operation = Uuid::new_v4();
    let runner = command().runner_request(execution).map_err(api_failure)?;
    let mut tx = legacy.fixture.owner_transaction().await?;
    // A historical immutable operation has valid runner input but no explicit
    // timeout policy. New dispatch must not manufacture consent for this record.
    sqlx::query("INSERT INTO operations(id,tenant_id,project_id,instance_id,workspace_id,kind,request,actor_principal_id,request_id,deadline) VALUES($1,$2,$3,$4,$5,'EXECUTE',$6,$7,$8,clock_timestamp()+interval '1 minute')")
        .bind(operation).bind(legacy.fixture.actor.tenant_id).bind(legacy.instance.project_id).bind(legacy.instance.id).bind(legacy.instance.workspace_id).bind(json!({"protocol_version":1,"classification":"NON_SENSITIVE","runner":runner})).bind(legacy.fixture.actor.principal_id).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO executions(id,tenant_id,project_id,instance_id,operation_id,runtime_generation,launch_id,pod_uid,cluster_epoch,deadline,timeout_seconds) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp()+interval '1 minute',60)")
        .bind(execution).bind(legacy.fixture.actor.tenant_id).bind(legacy.instance.project_id).bind(legacy.instance.id).bind(operation).bind(legacy.identity.runtime_generation).bind(legacy.identity.launch_id).bind(legacy.identity.pod_uid).bind(legacy.identity.cluster_epoch).execute(&mut *tx).await?;
    sqlx::query("UPDATE instances SET slot_held=true,activity_kind='EXECUTION',activity_id=$3,activity_generation=runtime_generation,idle_since=NULL WHERE tenant_id=$1 AND id=$2")
        .bind(legacy.fixture.actor.tenant_id).bind(legacy.instance.id).bind(execution).execute(&mut *tx).await?;
    tx.commit().await?;
    let (engine, claim) = legacy.claim(operation).await?;
    assert!(
        matches!(legacy.fixture.database.begin_execution_dispatch(&engine,&claim,execution,legacy.identity).await,Err(error) if error.code=="INVALID_EXECUTION_REQUEST")
    );
    let mut tx = legacy.fixture.owner_transaction().await?;
    let not_sent: bool = sqlx::query_scalar(
        "SELECT dispatch_attempt_id IS NULL FROM executions WHERE tenant_id=$1 AND id=$2",
    )
    .bind(legacy.fixture.actor.tenant_id)
    .bind(execution)
    .fetch_one(&mut *tx)
    .await?;
    assert!(not_sent);
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn running_without_current_ready_evidence_and_expired_or_insufficient_lease_is_rejected()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let ready = Ready::new(2).await?;
    for (name, assignment) in [
        (
            "missing-evidence",
            "ready_generation=NULL,ready_launch_id=NULL,ready_pod_uid=NULL,ready_cluster_epoch=NULL,ready_observed_at=NULL",
        ),
        (
            "wrong-generation",
            "ready_generation=runtime_generation+1,ready_launch_id=launch_id,ready_pod_uid=pod_uid,ready_cluster_epoch=cluster_epoch,ready_observed_at=clock_timestamp()",
        ),
        (
            "wrong-pod",
            "ready_generation=runtime_generation,ready_launch_id=launch_id,ready_pod_uid=gen_random_uuid(),ready_cluster_epoch=cluster_epoch,ready_observed_at=clock_timestamp()",
        ),
        (
            "wrong-epoch",
            "ready_generation=runtime_generation,ready_launch_id=launch_id,ready_pod_uid=pod_uid,ready_cluster_epoch=gen_random_uuid(),ready_observed_at=clock_timestamp()",
        ),
    ] {
        let mut tx = ready.fixture.owner_transaction().await?;
        sqlx::query(&format!(
            "UPDATE instances SET {assignment} WHERE tenant_id=$1 AND id=$2"
        ))
        .bind(ready.fixture.actor.tenant_id)
        .bind(ready.instance.id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        assert!(matches!(ready.create(name).await,Err(error) if error.code=="INSTANCE_NOT_READY"));
    }
    let valid = Ready::new(2).await?;
    let mut too_long = command();
    too_long.timeout_seconds = 3600;
    assert!(
        matches!(valid.fixture.database.create_execution(&valid.fixture.actor,valid.instance.id,&too_long,"too-long",valid.instance.spec_version).await,Err(error) if error.code=="EXECUTION_EXCEEDS_LEASE")
    );
    let mut tx = valid.fixture.owner_transaction().await?;
    sqlx::query("UPDATE instances SET compute_lease_started_at=clock_timestamp()-interval '2 minutes',compute_lease_expires_at=clock_timestamp()-interval '1 minute' WHERE tenant_id=$1 AND id=$2")
        .bind(valid.fixture.actor.tenant_id).bind(valid.instance.id).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(
        matches!(valid.create("expired").await,Err(error) if error.code=="COMPUTE_LEASE_EXPIRED")
    );
    assert_eq!(ready.fixture.count("operations").await?, 1);
    assert_eq!(valid.fixture.count("operations").await?, 1);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn dispatch_persists_one_attempt_before_return_and_unknown_outcomes_never_replay()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let ready = Ready::new(2).await?;
    let accepted = ready.create("dispatch-once").await.map_err(api_failure)?;
    let execution = accepted.body.resource.id;
    let (engine, claim) = ready.claim(accepted.body.operation.id).await?;
    let mut wrong = ready.identity;
    wrong.pod_uid = Uuid::new_v4();
    assert!(
        matches!(ready.fixture.database.begin_execution_dispatch(&engine,&claim,execution,wrong).await,Err(error) if error.code=="EXECUTION_IDENTITY_CHANGED")
    );
    let barrier = Arc::new(Barrier::new(2));
    let attempts = (0..2).map(|_| {
        let database = ready.fixture.database.clone();
        let engine = engine.clone();
        let claim = claim.clone();
        let barrier = barrier.clone();
        let identity = ready.identity;
        async move {
            barrier.wait().await;
            database
                .begin_execution_dispatch(&engine, &claim, execution, identity)
                .await
        }
    });
    let mut attempts_persisted = Vec::new();
    for result in join_all(attempts).await {
        match result {
            Ok(prepared) => {
                assert_eq!(prepared.request.execution_id, execution);
                assert!(prepared.request.timeout_seconds <= 60);
                attempts_persisted.push(prepared.dispatch_attempt_id);
            }
            Err(error) => assert_eq!(error.code, "DISPATCH_ALREADY_ATTEMPTED"),
        }
    }
    assert_eq!(attempts_persisted.len(), 1);
    let current = ready
        .fixture
        .database
        .get_execution(&ready.fixture.actor, execution)
        .await
        .map_err(api_failure)?;
    assert_eq!(current.status, "DISPATCHING");
    assert!(current.dispatch_attempted_at.is_some());
    assert!(current.slot_held);
    let mut tx = ready.fixture.owner_transaction().await?;
    let tamper = sqlx::query(
        "UPDATE executions SET dispatch_attempt_id=gen_random_uuid() WHERE tenant_id=$1 AND id=$2",
    )
    .bind(ready.fixture.actor.tenant_id)
    .bind(execution)
    .execute(&mut *tx)
    .await;
    require_pg_error(tamper, "23514")?;
    tx.rollback().await?;
    ready
        .fixture
        .database
        .mark_execution_outcome_unknown(
            ready.fixture.actor.tenant_id,
            execution,
            attempts_persisted[0],
        )
        .await
        .map_err(api_failure)?;
    let unknown = ready
        .fixture
        .database
        .get_execution(&ready.fixture.actor, execution)
        .await
        .map_err(api_failure)?;
    assert_eq!(unknown.status, "OUTCOME_UNKNOWN");
    assert!(unknown.slot_held);
    assert_eq!(unknown.termination_status, "UNKNOWN");
    assert!(
        ready
            .fixture
            .database
            .begin_execution_dispatch(&engine, &claim, execution, ready.identity)
            .await
            .is_err()
    );
    let replay = ready.create("dispatch-once").await.map_err(api_failure)?;
    assert_eq!(
        serde_json::to_value(replay.body)?,
        serde_json::to_value(accepted.body)?
    );
    let quota_before = ready.quota().await?;
    let cancel = ready
        .fixture
        .database
        .cancel_execution(
            &ready.fixture.actor,
            execution,
            &CancelExecution {
                hard_stop_instance: true,
            },
            "unknown-cancel",
            unknown.version,
        )
        .await
        .map_err(api_failure)?;
    assert_eq!(cancel.body.resource.status, "OUTCOME_UNKNOWN");
    assert_eq!(cancel.body.resource.termination_status, "PENDING");
    assert!(cancel.body.resource.slot_held);
    assert_eq!(ready.quota().await?, quota_before);
    let mut tx = ready.fixture.owner_transaction().await?;
    sqlx::query("UPDATE executions SET termination_status='CONFIRMED',slot_held=false WHERE tenant_id=$1 AND id=$2")
        .bind(ready.fixture.actor.tenant_id).bind(execution).execute(&mut *tx).await?;
    let falsify=sqlx::query("UPDATE executions SET status='CANCELLED',completed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
        .bind(ready.fixture.actor.tenant_id).bind(execution).execute(&mut *tx).await;
    require_pg_error(falsify, "23514")?;
    tx.rollback().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn cancellation_requires_explicit_scope_and_preserves_slot_and_quota_until_vm_evidence()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let ready = Ready::new(2).await?;
    let accepted = ready.create("cancel-queued").await.map_err(api_failure)?;
    let execution = accepted.body.resource.id;
    let quota_before = ready.quota().await?;
    let rejected = ready
        .fixture
        .database
        .cancel_execution(
            &ready.fixture.actor,
            execution,
            &CancelExecution {
                hard_stop_instance: false,
            },
            "must-ack-stop",
            1,
        )
        .await;
    assert!(matches!(rejected,Err(error) if error.code=="INVALID_ARGUMENT"));
    let mut tx = ready.fixture.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='instances:hard_stop'")
        .bind(ready.fixture.actor.tenant_id).bind(ready.fixture.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(
        ready
            .fixture
            .database
            .cancel_execution(
                &ready.fixture.actor,
                execution,
                &CancelExecution {
                    hard_stop_instance: true
                },
                "missing-permission",
                1
            )
            .await
            .is_err()
    );
    let mut tx = ready.fixture.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=true WHERE tenant_id=$1 AND principal_id=$2 AND action='instances:hard_stop'")
        .bind(ready.fixture.actor.tenant_id).bind(ready.fixture.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let cancelled = ready
        .fixture
        .database
        .cancel_execution(
            &ready.fixture.actor,
            execution,
            &CancelExecution {
                hard_stop_instance: true,
            },
            "cancel-key",
            1,
        )
        .await
        .map_err(api_failure)?;
    assert_eq!(cancelled.body.operation.kind, "STOP");
    assert_eq!(cancelled.body.resource.termination_status, "PENDING");
    assert!(cancelled.body.resource.slot_held);
    assert!(cancelled.body.resource.dispatch_attempted_at.is_none());
    assert_eq!(ready.quota().await?, quota_before);
    let replay = ready
        .fixture
        .database
        .cancel_execution(
            &ready.fixture.actor,
            execution,
            &CancelExecution {
                hard_stop_instance: true,
            },
            "cancel-key",
            1,
        )
        .await
        .map_err(api_failure)?;
    assert_eq!(
        serde_json::to_value(replay.body)?,
        serde_json::to_value(&cancelled.body)?
    );
    let instance = ready
        .fixture
        .database
        .get_instance(&ready.fixture.actor, ready.instance.id)
        .await
        .map_err(api_failure)?;
    assert_eq!(instance.desired_state, "STOPPED");
    assert!(instance.slot_held);
    let mut tx = ready.fixture.owner_transaction().await?;
    let original: (String, i64) =
        sqlx::query_as("SELECT status,lease_token FROM operations WHERE tenant_id=$1 AND id=$2")
            .bind(ready.fixture.actor.tenant_id)
            .bind(accepted.body.operation.id)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(original, ("CANCELLED".into(), 1));
    let retained:bool=sqlx::query_scalar("SELECT delete_requested_at IS NULL AND deleted_at IS NULL FROM workspaces WHERE tenant_id=$1 AND id=$2")
        .bind(ready.fixture.actor.tenant_id).bind(ready.instance.workspace_id).fetch_one(&mut *tx).await?;
    assert!(retained);
    tx.commit().await?;
    assert_eq!(ready.fixture.count("operations").await?, 3);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn cancellation_reuses_an_existing_safety_stop_instead_of_creating_a_second_stop()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let ready = Ready::new(2).await?;
    let accepted = ready.create("cancel-reuse").await.map_err(api_failure)?;
    let mut tx = ready.fixture.owner_transaction().await?;
    sqlx::query("UPDATE instances SET compute_lease_started_at=clock_timestamp()-interval '2 minutes',compute_lease_expires_at=clock_timestamp()-interval '1 minute' WHERE tenant_id=$1 AND id=$2")
        .bind(ready.fixture.actor.tenant_id).bind(ready.instance.id).execute(&mut *tx).await?;
    tx.commit().await?;
    let safety_stop = ready
        .fixture
        .database
        .accept_due_stop(ready.fixture.actor.tenant_id, ready.instance.id)
        .await
        .map_err(api_failure)?
        .context("Expected expiry stop")?;
    let cancelled = ready
        .fixture
        .database
        .cancel_execution(
            &ready.fixture.actor,
            accepted.body.resource.id,
            &CancelExecution {
                hard_stop_instance: true,
            },
            "reuse-stop",
            1,
        )
        .await
        .map_err(api_failure)?;
    assert_eq!(cancelled.body.operation.id, safety_stop);
    assert_eq!(ready.fixture.count("operations").await?, 3);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn scoped_result_references_and_current_authorization_are_enforced_on_reads_and_dispatch()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let ready = Ready::new(2).await?;
    let foreign = Ready::new(2).await?;
    let accepted = ready.create("read-result").await.map_err(api_failure)?;
    let execution = accepted.body.resource.id;
    assert!(
        foreign
            .fixture
            .database
            .get_execution(&foreign.fixture.actor, execution)
            .await
            .is_err()
    );
    let object_key = format!(
        "tenants/{}/executions/{execution}/manifest.json",
        ready.fixture.actor.tenant_id
    );
    let mut tx = ready.fixture.owner_transaction().await?;
    sqlx::query("UPDATE executions SET output_manifest=$3,output_status='COMPLETE' WHERE tenant_id=$1 AND id=$2")
        .bind(ready.fixture.actor.tenant_id).bind(execution).bind(json!({"object_key":object_key,"sha256":"a".repeat(64),"size_bytes":42})).execute(&mut *tx).await?;
    tx.commit().await?;
    let result = ready
        .fixture
        .database
        .get_execution(&ready.fixture.actor, execution)
        .await
        .map_err(api_failure)?;
    assert_eq!(
        result
            .result_ref
            .context("Expected validated result reference")?
            .object_key,
        object_key
    );
    let mut tx = ready.fixture.owner_transaction().await?;
    sqlx::query("UPDATE executions SET output_manifest=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(ready.fixture.actor.tenant_id).bind(execution).bind(json!({"object_key":format!("tenants/{}/executions/{execution}/manifest.json",foreign.fixture.actor.tenant_id),"sha256":"a".repeat(64),"size_bytes":42})).execute(&mut *tx).await?;
    tx.commit().await?;
    let withheld = ready
        .fixture
        .database
        .get_execution(&ready.fixture.actor, execution)
        .await
        .map_err(api_failure)?;
    assert!(withheld.result_ref.is_none());
    assert_eq!(withheld.output_status, "LOST");
    let mut tx = ready.fixture.owner_transaction().await?;
    sqlx::query("UPDATE executions SET output_manifest=NULL WHERE tenant_id=$1 AND id=$2")
        .bind(ready.fixture.actor.tenant_id)
        .bind(execution)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE grants SET enabled=false,revoked_at=clock_timestamp() WHERE tenant_id=$1 AND principal_id=$2 AND action IN ('executions:create','executions:read')")
        .bind(ready.fixture.actor.tenant_id).bind(ready.fixture.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(
        ready
            .fixture
            .database
            .get_execution(&ready.fixture.actor, execution)
            .await
            .is_err()
    );
    assert!(
        ready.create("read-result").await.is_err(),
        "Revocation must apply even to idempotent replay"
    );
    let (engine, claim) = ready.claim(accepted.body.operation.id).await?;
    assert!(
        ready
            .fixture
            .database
            .begin_execution_dispatch(&engine, &claim, execution, ready.identity)
            .await
            .is_err()
    );
    let mut tx = ready.fixture.owner_transaction().await?;
    let not_sent: bool = sqlx::query_scalar(
        "SELECT dispatch_attempt_id IS NULL FROM executions WHERE tenant_id=$1 AND id=$2",
    )
    .bind(ready.fixture.actor.tenant_id)
    .bind(execution)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(
        not_sent,
        "A revoked actor must not acquire a dispatch attempt"
    );
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+, both TEST_*DATABASE_URL credentials and a loopback mock JWKS listener"]
async fn signed_s2s_http_create_get_and_cancel_follow_execution_etag_and_receipt_contract()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let ready = Ready::new(2).await?;
    let jwk: Value = serde_json::from_str(include_str!("fixtures/auth/jwk-a.json"))?;
    let kid = jwk["kid"]
        .as_str()
        .context("Fixture JWK has no kid")?
        .to_owned();
    let keys = json!({"keys":[jwk]});
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let routes = Router::new().route(
            "/jwks",
            get(move || {
                let keys = keys.clone();
                async move { axum::Json(keys) }
            }),
        );
        axum::serve(listener, routes).await
    });
    ready
        .fixture
        .bind_client_id("execution-http-client")
        .await?;
    let auth = JwtAuthenticator::new(AuthConfig {
        scope_profile: Default::default(),
        issuer: "https://issuer.example.test".into(),
        audience: "sandbox-api".into(),
        jwks_url: format!("http://{address}/jwks"),
        required_scopes: vec!["sandbox:access".into()],
        jwks_ttl_seconds: 300,
        clock_skew_seconds: 0,
        allow_loopback_http: true,
        max_token_lifetime_seconds: 300,
    })?;
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("at+jwt".into());
    header.kid = Some(kid);
    let now = chrono::Utc::now().timestamp();
    let token = encode(
        &header,
        &json!({"iss":"https://issuer.example.test","sub":ready.fixture.actor.principal_id.to_string(),"aud":"sandbox-api","client_id":"execution-http-client","jti":Uuid::new_v4().to_string(),"iat":now,"exp":now+300,"scope":"sandbox:access"}),
        &EncodingKey::from_rsa_der(include_bytes!("fixtures/auth/rsa-a.der")),
    )?;
    let app = router(Arc::new(AppState {
        output_reader: None,
        metrics: None,
        cursor_signer: sandbox_platform::history::CursorSigner::from_json(include_str!(
            "fixtures/history/cursor-keys.json"
        ))?,
        database: ready.fixture.database.clone(),
        auth,
        default_ttl_seconds: 300,
        max_ttl_seconds: 86400,
    }));
    let request = |method: &str,
                   path: String,
                   body: Value,
                   etag: Option<String>,
                   key: Option<&str>|
     -> anyhow::Result<Request<Body>> {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .header("x-tenant-id", ready.fixture.actor.tenant_id.to_string())
            .header("content-type", "application/json");
        if let Some(etag) = etag {
            builder = builder.header("if-match", etag);
        }
        if let Some(key) = key {
            builder = builder.header("idempotency-key", key);
        }
        Ok(builder.body(Body::from(serde_json::to_vec(&body)?))?)
    };
    let path = format!("/v1/instances/{}/executions", ready.instance.id);
    let missing = app
        .clone()
        .oneshot(request(
            "POST",
            path.clone(),
            serde_json::to_value(command())?,
            None,
            Some("missing-if-match"),
        )?)
        .await?;
    assert_eq!(missing.status(), StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(
        missing.headers()["content-type"],
        "application/problem+json"
    );
    let accepted = app
        .clone()
        .oneshot(request(
            "POST",
            path,
            serde_json::to_value(command())?,
            Some(format!("\"{}\"", ready.instance.spec_version)),
            Some("http-command"),
        )?)
        .await?;
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    assert_eq!(accepted.headers()["etag"], "\"1\"");
    assert_eq!(
        accepted.headers()["x-instance-etag"],
        format!("\"{}\"", ready.instance.spec_version + 1)
    );
    assert_eq!(accepted.headers()["cache-control"], "no-store");
    let location = accepted.headers()["location"].to_str()?.to_owned();
    let receipt: Value = serde_json::from_slice(&accepted.into_body().collect().await?.to_bytes())?;
    let execution = receipt["resource"]["id"]
        .as_str()
        .context("Execution id is missing")?;
    assert_eq!(location, format!("/v1/executions/{execution}"));
    let current = app
        .clone()
        .oneshot(request("GET", location.clone(), Value::Null, None, None)?)
        .await?;
    assert_eq!(current.status(), StatusCode::OK);
    assert_eq!(current.headers()["etag"], "\"1\"");
    let body = current.into_body().collect().await?.to_bytes();
    let public = std::str::from_utf8(&body)?;
    assert!(!public.contains("ordinary-environment-marker"));
    assert!(!public.contains("ordinary-argument-marker"));
    let cancelled = app
        .oneshot(request(
            "POST",
            format!("{location}/cancel"),
            json!({"hard_stop_instance":true}),
            Some("\"1\"".into()),
            Some("http-hard-cancel"),
        )?)
        .await?;
    assert_eq!(cancelled.status(), StatusCode::ACCEPTED);
    assert_eq!(cancelled.headers()["etag"], "\"2\"");
    let body: Value = serde_json::from_slice(&cancelled.into_body().collect().await?.to_bytes())?;
    assert_eq!(body["operation"]["kind"], "STOP");
    assert_eq!(body["resource"]["termination_status"], "PENDING");
    assert_eq!(body["resource"]["slot_held"], true);
    server.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn system_transport_stop_survives_user_revocation_and_is_idempotent_without_releasing_activity()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let ready = Ready::new(2).await?;
    let accepted = ready
        .create("system-transport")
        .await
        .map_err(api_failure)?;
    let id = accepted.body.resource.id;
    let tenant = ready.fixture.actor.tenant_id;
    assert!(
        matches!(ready.fixture.database.stop_execution_for_safety(tenant,id,"TIMEOUT").await,Err(error) if error.code=="EXECUTION_NOT_DUE")
    );
    assert!(
        matches!(ready.fixture.database.stop_execution_for_safety(tenant,id,"TRANSPORT_LOST").await,Err(error) if error.code=="DISPATCH_NOT_ATTEMPTED")
    );
    let (engine, claim) = ready.claim(accepted.body.operation.id).await?;
    ready
        .fixture
        .database
        .begin_execution_dispatch(&engine, &claim, id, ready.identity)
        .await
        .map_err(api_failure)?;
    let quota = ready.quota().await?;
    let mut tx = ready.fixture.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2")
        .bind(tenant)
        .bind(ready.fixture.actor.principal_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE principals SET enabled=false WHERE id=$1")
        .bind(ready.fixture.actor.principal_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let barrier = Arc::new(Barrier::new(4));
    let results = join_all((0..4).map(|_| {
        let db = ready.fixture.database.clone();
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            db.stop_execution_for_safety(tenant, id, "TRANSPORT_LOST")
                .await
        }
    }))
    .await;
    let mut stops = Vec::new();
    for result in results {
        stops.push(
            result
                .map_err(api_failure)?
                .context("Expected safety stop")?,
        );
    }
    assert!(stops.iter().all(|id| *id == stops[0]));
    assert_eq!(ready.quota().await?, quota);
    let mut tx = ready.fixture.owner_transaction().await?;
    let current: Value =
        sqlx::query_scalar("SELECT to_jsonb(e) FROM executions e WHERE tenant_id=$1 AND id=$2")
            .bind(tenant)
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(current["status"], "OUTCOME_UNKNOWN");
    assert_eq!(current["termination_status"], "PENDING");
    assert_eq!(current["slot_held"], true);
    assert_eq!(current["version"], 3);
    let audit_count:i64=sqlx::query_scalar("SELECT count(*) FROM audit_events a JOIN principals p ON p.id=a.actor_principal_id WHERE a.tenant_id=$1 AND a.resource_id=$2 AND a.action='executions:safety_stop' AND p.kind='SYSTEM'")
        .bind(tenant).bind(id).fetch_one(&mut *tx).await?;
    assert_eq!(audit_count, 1);
    let safe_workspace:bool=sqlx::query_scalar("SELECT w.status='IN_USE' AND w.delete_requested_at IS NULL AND w.active_operation_id=$3 FROM workspaces w WHERE tenant_id=$1 AND id=$2")
        .bind(tenant).bind(ready.instance.workspace_id).bind(stops[0]).fetch_one(&mut *tx).await?;
    assert!(safe_workspace);
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn queued_expiry_records_timeout_but_preserves_slot_until_vm_termination()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let ready = Ready::new(2).await?;
    let id = Uuid::new_v4();
    let operation = Uuid::new_v4();
    let runner = command().runner_request(id).map_err(api_failure)?;
    let tenant = ready.fixture.actor.tenant_id;
    let mut tx = ready.fixture.owner_transaction().await?;
    // Seed a historical accepted deadline at INSERT, rather than sleeping or
    // bypassing immutable-deadline triggers after acceptance.
    sqlx::query("INSERT INTO operations(id,tenant_id,project_id,instance_id,workspace_id,kind,request,actor_principal_id,request_id,deadline) VALUES($1,$2,$3,$4,$5,'EXECUTE',$6,$7,$8,clock_timestamp()-interval '1 second')")
        .bind(operation).bind(tenant).bind(ready.instance.project_id).bind(ready.instance.id).bind(ready.instance.workspace_id).bind(json!({"protocol_version":1,"classification":"NON_SENSITIVE","on_timeout":"HARD_STOP_INSTANCE","runner":runner})).bind(ready.fixture.actor.principal_id).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO executions(id,tenant_id,project_id,instance_id,operation_id,runtime_generation,launch_id,pod_uid,cluster_epoch,deadline,timeout_seconds) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp()-interval '1 second',60)")
        .bind(id).bind(tenant).bind(ready.instance.project_id).bind(ready.instance.id).bind(operation).bind(ready.identity.runtime_generation).bind(ready.identity.launch_id).bind(ready.identity.pod_uid).bind(ready.identity.cluster_epoch).execute(&mut *tx).await?;
    sqlx::query("UPDATE instances SET slot_held=true,activity_kind='EXECUTION',activity_id=$3,activity_generation=runtime_generation,idle_since=NULL WHERE tenant_id=$1 AND id=$2")
        .bind(tenant).bind(ready.instance.id).bind(id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO quota_reservations(tenant_id,project_id,quota_account_id,operation_id,resource_id,amount) SELECT $1,$2,id,$3,$4,1 FROM quota_accounts WHERE tenant_id=$1 AND dimension='EXECUTIONS'")
        .bind(tenant).bind(ready.instance.project_id).bind(operation).bind(ready.instance.id).execute(&mut *tx).await?;
    sqlx::query(
        "UPDATE quota_accounts SET pending=pending+1 WHERE tenant_id=$1 AND dimension='EXECUTIONS'",
    )
    .bind(tenant)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let quota = ready.quota().await?;
    let stop = ready
        .fixture
        .database
        .stop_execution_for_safety(tenant, id, "TIMEOUT")
        .await
        .map_err(api_failure)?
        .context("Expected timeout stop")?;
    let current = ready
        .fixture
        .database
        .get_execution(&ready.fixture.actor, id)
        .await
        .map_err(api_failure)?;
    assert_eq!(current.status, "TIMED_OUT");
    assert!(current.completed_at.is_some());
    assert!(current.dispatch_attempted_at.is_none());
    assert!(current.slot_held);
    assert_eq!(current.termination_status, "PENDING");
    assert_eq!(ready.quota().await?, quota);
    let mut tx = ready.fixture.owner_transaction().await?;
    let reason: String =
        sqlx::query_scalar("SELECT stop_reason FROM operations WHERE tenant_id=$1 AND id=$2")
            .bind(tenant)
            .bind(stop)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(reason, "EXECUTION_TIMEOUT");
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn operation_errors_are_sanitized_in_current_reads_and_historical_execution_receipts()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let ready = Ready::new(2).await?;
    let accepted = ready.create("error-receipt").await.map_err(api_failure)?;
    let marker = json!({"code":"PRIVATE-MARKER","message":"PRIVATE-MARKER","retryable":true,"provider":{"secret":"PRIVATE-MARKER"}});
    let mut tx = ready.fixture.owner_transaction().await?;
    sqlx::query("UPDATE operations SET error=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(ready.fixture.actor.tenant_id)
        .bind(accepted.body.operation.id)
        .bind(&marker)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE idempotency_keys SET response_body=jsonb_set(response_body,'{operation,error}',$3) WHERE tenant_id=$1 AND operation_id=$2")
        .bind(ready.fixture.actor.tenant_id).bind(accepted.body.operation.id).bind(&marker).execute(&mut *tx).await?;
    tx.commit().await?;
    let operation = ready
        .fixture
        .database
        .get_operation(&ready.fixture.actor, accepted.body.operation.id)
        .await
        .map_err(api_failure)?;
    let current = serde_json::to_value(operation)?;
    assert_eq!(
        current["error"],
        json!({"code":"OPERATION_FAILED","retryable":false})
    );
    assert!(!current.to_string().contains("PRIVATE-MARKER"));
    let replay = ready.create("error-receipt").await.map_err(api_failure)?;
    let serialized = serde_json::to_value(replay.body)?;
    assert_eq!(
        serialized["operation"]["error"],
        json!({"code":"OPERATION_FAILED","retryable":false})
    );
    assert!(!serialized.to_string().contains("PRIVATE-MARKER"));
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn instance_details_expose_launch_evidence_without_claiming_health_and_redact_execution_by_separate_grant()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let ready = Ready::new(2).await?;
    let initial = serde_json::to_value(
        ready
            .fixture
            .database
            .instance_details(&ready.fixture.actor, ready.instance.id)
            .await
            .map_err(api_failure)?,
    )?;
    assert_eq!(
        initial["launch_readiness"]["status"],
        "VERIFIED_CURRENT_LAUNCH"
    );
    assert_eq!(
        initial["runtime_health"],
        json!({"status":"UNKNOWN","reason":"CONTINUOUS_OBSERVATION_UNAVAILABLE"})
    );
    assert_eq!(initial["active_execution"]["state"], "NONE");
    assert_eq!(
        initial["workspace"]["id"],
        ready.instance.workspace_id.to_string()
    );
    assert_eq!(
        initial["template"]["image_digest"],
        format!("sha256:{}", "a".repeat(64))
    );
    assert!(!initial.to_string().contains("integration-storage"));
    assert!(!initial.to_string().contains("cloud_volume_id"));
    assert!(!initial.to_string().contains("key_ref"));
    let accepted = ready
        .create("details-execution")
        .await
        .map_err(api_failure)?;
    let details = serde_json::to_value(
        ready
            .fixture
            .database
            .instance_details(&ready.fixture.actor, ready.instance.id)
            .await
            .map_err(api_failure)?,
    )?;
    assert_eq!(details["active_execution"]["state"], "AVAILABLE");
    assert_eq!(
        details["active_execution"]["resource"]["id"],
        accepted.body.resource.id.to_string()
    );
    assert!(!details.to_string().contains("ordinary-environment-marker"));
    assert!(!details.to_string().contains("ordinary-argument-marker"));
    assert!(
        !details["active_execution"]
            .to_string()
            .contains("result_ref")
    );
    let mut tx = ready.fixture.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='executions:read'").bind(ready.fixture.actor.tenant_id).bind(ready.fixture.actor.principal_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE instances SET observed_at=clock_timestamp()-interval '1 hour',ready_generation=runtime_generation+1 WHERE tenant_id=$1 AND id=$2").bind(ready.fixture.actor.tenant_id).bind(ready.instance.id).execute(&mut *tx).await?;
    tx.commit().await?;
    let details = serde_json::to_value(
        ready
            .fixture
            .database
            .instance_details(&ready.fixture.actor, ready.instance.id)
            .await
            .map_err(api_failure)?,
    )?;
    assert_eq!(
        details["active_execution"],
        json!({"state":"REDACTED","resource":null})
    );
    assert_eq!(details["launch_readiness"]["status"], "UNVERIFIED");
    assert_eq!(details["launch_readiness"]["matches_current_launch"], false);
    assert_eq!(details["lifecycle_observation"]["freshness"], "HISTORICAL");
    assert_eq!(details["runtime_health"]["status"], "UNKNOWN");
    let other = Ready::new(2).await?;
    assert!(
        matches!(ready.fixture.database.instance_details(&ready.fixture.actor,other.instance.id).await,Err(error) if error.status==StatusCode::NOT_FOUND)
    );
    assert!(
        matches!(ready.fixture.database.instance_details(&ready.fixture.actor,Uuid::new_v4()).await,Err(error) if error.status==StatusCode::NOT_FOUND)
    );
    let mut tx = ready.fixture.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='instances:read'").bind(ready.fixture.actor.tenant_id).bind(ready.fixture.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(
        matches!(ready.fixture.database.instance_details(&ready.fixture.actor,ready.instance.id).await,Err(error) if error.status==StatusCode::NOT_FOUND)
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires PostgreSQL and both TEST_*DATABASE_URL credentials"]
async fn tenant_membership_disable_denies_old_receipts_and_new_dispatch_without_reenabling_on_grant_insert()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let ready = Ready::new(2).await?;
    let accepted = ready
        .create("membership-dispatch")
        .await
        .map_err(api_failure)?;
    let execution = accepted.body.resource.id;
    let (engine, claim) = ready.claim(accepted.body.operation.id).await?;
    let mut tx = ready.fixture.owner_transaction().await?;
    sqlx::query(
        "UPDATE tenant_principals SET enabled=false WHERE tenant_id=$1 AND principal_id=$2",
    )
    .bind(ready.fixture.actor.tenant_id)
    .bind(ready.fixture.actor.principal_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) SELECT $1,project_id,$2,'events:read' FROM instances WHERE tenant_id=$1 AND id=$3 ON CONFLICT DO NOTHING")
        .bind(ready.fixture.actor.tenant_id).bind(ready.fixture.actor.principal_id).bind(ready.instance.id).execute(&mut *tx).await?;
    let enabled: bool = sqlx::query_scalar(
        "SELECT enabled FROM tenant_principals WHERE tenant_id=$1 AND principal_id=$2",
    )
    .bind(ready.fixture.actor.tenant_id)
    .bind(ready.fixture.actor.principal_id)
    .fetch_one(&mut *tx)
    .await?;
    assert!(
        !enabled,
        "Grant insertion cannot reenable a disabled membership"
    );
    tx.commit().await?;
    assert!(ready.create("membership-dispatch").await.is_err());
    assert!(
        ready
            .fixture
            .database
            .get_execution(&ready.fixture.actor, execution)
            .await
            .is_err()
    );
    assert!(
        ready
            .fixture
            .database
            .begin_execution_dispatch(&engine, &claim, execution, ready.identity)
            .await
            .is_err()
    );
    let mut tx = ready.fixture.owner_transaction().await?;
    let not_sent: bool = sqlx::query_scalar(
        "SELECT dispatch_attempt_id IS NULL FROM executions WHERE tenant_id=$1 AND id=$2",
    )
    .bind(ready.fixture.actor.tenant_id)
    .bind(execution)
    .fetch_one(&mut *tx)
    .await?;
    assert!(not_sent);
    tx.commit().await?;
    Ok(())
}
