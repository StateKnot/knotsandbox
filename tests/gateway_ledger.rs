//! SQL evidence/atomicity tests. Object receipts and Ready observations below
//! are test-owner fixtures, not claims that OSS or a real VM was exercised.
#[path = "support/gateway_pipeline.rs"]
mod pipeline;
#[allow(dead_code)]
mod support;
use anyhow::{Context, ensure};
use sandbox_platform::{
    db::Database,
    engine::{Claim, OperationEngine},
    execution::DispatchIdentity,
    gateway_ledger::{NormalProcessCompletion, StoredOutputSegment},
    model::{CreateExecution, ExecutionResultRef, ExecutionTimeoutPolicy},
    runner::RunSummary,
};
use support::{Fixture, api_failure};
use uuid::Uuid;

struct Dispatched {
    f: Fixture,
    engine: OperationEngine,
    claim: Claim,
    execution: Uuid,
    attempt: Uuid,
    instance: Uuid,
}
impl Dispatched {
    async fn new() -> anyhow::Result<Self> {
        Self::setup(true, 1024).await
    }
    async fn setup(dispatch: bool, output_limit: u64) -> anyhow::Result<Self> {
        let mut f = Fixture::new(10).await?;
        let policy = Uuid::new_v4();
        let mut tx = f.owner_transaction().await?;
        sqlx::query("INSERT INTO security_policy_versions(id,tenant_id,name,version,status,rules) VALUES($1,$2,'gateway-deny-policy',1,'APPROVED','{\"profile\":\"deny-all\",\"dns\":true}'::jsonb)")
            .bind(policy).bind(f.actor.tenant_id).execute(&mut *tx).await?;
        tx.commit().await?;
        f.request.security_profile_id = policy;
        let created = f
            .create("gateway-ledger-instance")
            .await
            .map_err(api_failure)?;
        let instance = created.body.resource.id;
        f.seed_observed_state(instance, "RUNNING").await?;
        let mut tx = f.owner_transaction().await?;
        for action in [
            "executions:create",
            "executions:read",
            "executions:cancel",
            "executions:output:read",
            "instances:hard_stop",
        ] {
            sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING").bind(f.actor.tenant_id).bind(f.request.project_id).bind(f.actor.principal_id).bind(action).execute(&mut *tx).await?;
        }
        for project in [None, Some(f.request.project_id)] {
            sqlx::query("INSERT INTO quota_accounts(tenant_id,project_id,dimension,limit_value) VALUES($1,$2,'EXECUTIONS',10)").bind(f.actor.tenant_id).bind(project).execute(&mut *tx).await?;
        }
        let pod = Uuid::new_v4();
        sqlx::query("UPDATE instances SET pod_uid=$3,ready_generation=runtime_generation,ready_launch_id=launch_id,ready_pod_uid=$3,ready_cluster_epoch=cluster_epoch,ready_observed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(instance).bind(pod).execute(&mut *tx).await?;
        let (generation,launch,epoch):(i64,Uuid,Uuid)=sqlx::query_as("SELECT runtime_generation,launch_id,cluster_epoch FROM instances WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(instance).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        f.seed_test_launch_certification(instance, chrono::Utc::now() + chrono::Duration::days(2))
            .await?;
        let request = CreateExecution {
            argv: vec!["/usr/bin/true".into()],
            public_env: Default::default(),
            cwd: "/workspace".into(),
            timeout_seconds: 60,
            on_timeout: ExecutionTimeoutPolicy::HardStopInstance,
            output_limit_bytes: output_limit,
            client_reference: None,
        };
        let accepted = f
            .database
            .create_execution(
                &f.actor,
                instance,
                &request,
                "gateway-exec",
                created.body.resource.spec_version,
            )
            .await
            .map_err(api_failure)?;
        sqlx::raw_sql(include_str!("../scripts/sql/gateway-role.sql"))
            .execute(&f.owner)
            .await?;
        let url = std::env::var("TEST_GATEWAY_DATABASE_URL")
            .context("TEST_GATEWAY_DATABASE_URL required")?;
        let target = url::Url::parse(&url)?;
        let original = url::Url::parse(&std::env::var("TEST_DATABASE_URL")?)?;
        ensure!(
            target.username() == "sandbox_gateway"
                && target.path().ends_with("_test")
                && target.path() == original.path()
                && target.host_str() == original.host_str()
                && target.port_or_known_default() == original.port_or_known_default(),
            "gateway must target same disposable database with dedicated role"
        );
        let db = Database::connect(&url, 4).await?;
        db.verify_runtime_role().await?;
        let engine = OperationEngine::new(db, "gateway-ledger-test".into())?;
        let mut tx = f.owner_transaction().await?;
        sqlx::query("UPDATE operations SET next_attempt_at='1000-01-01 00:00:00+00' WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(accepted.body.operation.id).execute(&mut *tx).await?;
        tx.commit().await?;
        let claim = engine
            .claim_execution()
            .await
            .map_err(api_failure)?
            .context("execution queue claim")?;
        ensure!(
            claim.operation_id == accepted.body.operation.id,
            "test expected its prioritized execution"
        );
        let execution = accepted.body.resource.id;
        let attempt = if dispatch {
            let prepared = engine
                .database
                .begin_execution_dispatch(
                    &engine,
                    &claim,
                    execution,
                    DispatchIdentity {
                        runtime_generation: generation,
                        launch_id: launch,
                        pod_uid: pod,
                        cluster_epoch: epoch,
                    },
                )
                .await
                .map_err(api_failure)?;
            let attempt = prepared.dispatch_attempt_id;
            // Simulate the already-authenticated admission transport invoking the
            // real consume gate. This test does not replace live webhook validation.
            let admitted: bool =
                sqlx::query_scalar("SELECT sandbox_admit_execution_connect($1,$2,$3,$4)")
                    .bind(f.actor.tenant_id)
                    .bind(execution)
                    .bind(attempt)
                    .bind(Uuid::new_v4())
                    .fetch_one(&f.owner)
                    .await?;
            ensure!(admitted, "admission gate rejected controlled fixture");
            attempt
        } else {
            Uuid::nil()
        };
        Ok(Self {
            f,
            engine,
            claim,
            execution,
            attempt,
            instance,
        })
    }
    fn completion(&self) -> NormalProcessCompletion {
        let sha = "a".repeat(64);
        NormalProcessCompletion {
            trusted_process_exit_code: 0,
            guest_report: RunSummary {
                exit_code: Some(0),
                signal: None,
                timed_out: false,
                cancelled: false,
                output_complete: true,
                output_truncated: false,
                bytes_observed: 0,
                bytes_emitted: 0,
                termination_confirmed: true,
            },
            output_status: "COMPLETE".into(),
            manifest: Some(ExecutionResultRef {
                object_key: format!(
                    "tenants/{}/executions/{}/attempts/{}/manifest-{sha}.json",
                    self.f.actor.tenant_id, self.execution, self.attempt
                ),
                sha256: sha,
                size_bytes: 100,
            }),
        }
    }
}

#[tokio::test]
#[ignore = "Requires disposable PostgreSQL and dedicated TEST_GATEWAY_DATABASE_URL"]
async fn trusted_process_completion_releases_only_platform_slot_and_execution_quota()
-> anyhow::Result<()> {
    let _scope = support::serial().await;
    let d = Dispatched::new().await?;
    d.engine
        .database
        .complete_execution_process(&d.engine, &d.claim, d.execution, d.attempt, &d.completion())
        .await
        .map_err(api_failure)?;
    let mut tx = d.f.owner_transaction().await?;
    let (status,slot,termination,kind,source):(String,bool,String,String,String)=sqlx::query_as("SELECT status,slot_held,termination_status,activity_completion_kind,result_source FROM executions WHERE tenant_id=$1 AND id=$2").bind(d.f.actor.tenant_id).bind(d.execution).fetch_one(&mut *tx).await?;
    assert_eq!(
        (
            status.as_str(),
            slot,
            termination.as_str(),
            kind.as_str(),
            source.as_str()
        ),
        (
            "SUCCEEDED",
            false,
            "NOT_REQUESTED",
            "EXEC_PROCESS_EXITED",
            "GUEST_REPORTED"
        )
    );
    let (state, slot): (String, bool) = sqlx::query_as(
        "SELECT observed_state,slot_held FROM instances WHERE tenant_id=$1 AND id=$2",
    )
    .bind(d.f.actor.tenant_id)
    .bind(d.instance)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!((state.as_str(), slot), ("RUNNING", false));
    let reserved:i64=sqlx::query_scalar("SELECT sum(pending+allocated)::bigint FROM quota_accounts WHERE tenant_id=$1 AND dimension='EXECUTIONS'").bind(d.f.actor.tenant_id).fetch_one(&mut *tx).await?;
    assert_eq!(reserved, 0);
    let compute:i64=sqlx::query_scalar("SELECT sum(pending+allocated)::bigint FROM quota_accounts WHERE tenant_id=$1 AND dimension IN ('CPU_MILLIS','MEMORY_MIB')").bind(d.f.actor.tenant_id).fetch_one(&mut *tx).await?;
    ensure!(
        compute > 0,
        "process completion must not release VM compute"
    );
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable PostgreSQL and dedicated TEST_GATEWAY_DATABASE_URL"]
async fn unknown_or_lost_lease_cannot_be_reclassified_by_late_guest_report() -> anyhow::Result<()> {
    let _scope = support::serial().await;
    let d = Dispatched::new().await?;
    let mut bad = d.completion();
    bad.trusted_process_exit_code = 70;
    assert!(
        d.engine
            .database
            .complete_execution_process(&d.engine, &d.claim, d.execution, d.attempt, &bad)
            .await
            .is_err()
    );
    d.engine
        .database
        .mark_execution_outcome_unknown(d.f.actor.tenant_id, d.execution, d.attempt)
        .await
        .map_err(api_failure)?;
    assert!(
        d.engine
            .database
            .complete_execution_process(
                &d.engine,
                &d.claim,
                d.execution,
                d.attempt,
                &d.completion()
            )
            .await
            .is_err()
    );
    let mut tx = d.f.owner_transaction().await?;
    let (status, slot): (String, bool) =
        sqlx::query_as("SELECT status,slot_held FROM executions WHERE tenant_id=$1 AND id=$2")
            .bind(d.f.actor.tenant_id)
            .bind(d.execution)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!((status.as_str(), slot), ("OUTCOME_UNKNOWN", true));
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable PostgreSQL and dedicated TEST_GATEWAY_DATABASE_URL"]
async fn output_receipts_are_immutable_idempotent_and_tenant_scoped() -> anyhow::Result<()> {
    let _scope = support::serial().await;
    let d = Dispatched::new().await?;
    let sha = "b".repeat(64);
    let receipt = StoredOutputSegment {
        execution_id: d.execution,
        dispatch_attempt_id: d.attempt,
        sequence: 0,
        first_frame_sequence: 0,
        last_frame_sequence: 1,
        raw_bytes: 3,
        object_bytes: 128,
        sha256: sha.clone(),
        object_key: format!(
            "tenants/{}/executions/{}/attempts/{}/segments/0-{sha}.ndjson",
            d.f.actor.tenant_id, d.execution, d.attempt
        ),
    };
    for _ in 0..2 {
        d.engine
            .database
            .record_execution_output_segment(&d.engine, &d.claim, &receipt)
            .await
            .map_err(api_failure)?;
    }
    let mut altered = receipt.clone();
    altered.raw_bytes = 4;
    assert_eq!(
        d.engine
            .database
            .record_execution_output_segment(&d.engine, &d.claim, &altered)
            .await
            .err()
            .context("different receipt must fail")?
            .code,
        "OUTPUT_SEGMENT_CONFLICT"
    );
    let mut tx = d.f.owner_transaction().await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM execution_output_segments WHERE tenant_id=$1 AND execution_id=$2",
    )
    .bind(d.f.actor.tenant_id)
    .bind(d.execution)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(count, 1);
    tx.commit().await?;
    let mut tx = d
        .engine
        .database
        .begin(Uuid::new_v4())
        .await
        .map_err(api_failure)?;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM execution_output_segments WHERE execution_id=$1")
            .bind(d.execution)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(count, 0);
    tx.commit().await?;
    // The non-owner API role cannot manufacture the trusted completion columns.
    let mut tx =
        d.f.database
            .begin(d.f.actor.tenant_id)
            .await
            .map_err(api_failure)?;
    let forged=sqlx::query("UPDATE executions SET exec_process_attempt_id=$3,exec_process_exited_at=clock_timestamp(),exec_process_exit_code=0 WHERE tenant_id=$1 AND id=$2").bind(d.f.actor.tenant_id).bind(d.execution).bind(d.attempt).execute(&mut *tx).await;
    support::require_pg_error(forged, "42501")?;
    tx.rollback().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable PostgreSQL and dedicated TEST_GATEWAY_DATABASE_URL"]
async fn gateway_restart_never_reconnects_a_persisted_dispatch_and_keeps_quota()
-> anyhow::Result<()> {
    use axum::{
        body::Body,
        http::{Request, Response},
    };
    use kube::{Client, client::Body as KubeBody};
    use sandbox_platform::{
        gateway::Gateway,
        output_store::{OssOutputConfig, OssOutputStore},
        runtime::KubernetesRuntime,
        runtime_manifest::RuntimeManifestConfig,
    };
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    let _scope = support::serial().await;
    let d = Dispatched::new().await?;
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let service = tower::service_fn(move |_: Request<KubeBody>| {
        count.fetch_add(1, Ordering::SeqCst);
        async {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = axum::http::StatusCode::INTERNAL_SERVER_ERROR;
            Ok::<_, Infallible>(response)
        }
    });
    let output = OssOutputStore::new(OssOutputConfig {
        endpoint: "https://oss-cn-hangzhou-internal.aliyuncs.com".into(),
        bucket: "sandbox-output".into(),
        kms_key_id: "test-key".into(),
        sts_credentials_file: "/nonexistent-test-output-sts.json".into(),
    })?;
    let gateway = Gateway::new(
        d.engine.database.clone(),
        KubernetesRuntime::from_client(Client::new(service, "default")),
        output,
        "gateway-restarted".into(),
        "test-certification".into(),
        1,
        RuntimeManifestConfig {
            runtime_class_name: "kata-qemu".into(),
            dns_namespace: "kube-system".into(),
            dns_labels: [("k8s-app".into(), "kube-dns".into())].into(),
            ephemeral_storage_mib: 1024,
            tmp_size_mib: 256,
        },
    )?;
    let mut tx = d.f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET lease_until='0001-01-01 00:00:00+00',next_attempt_at='0001-01-01 00:00:00+00' WHERE tenant_id=$1 AND id=$2")
        .bind(d.f.actor.tenant_id).bind(d.claim.operation_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let claimed = gateway
        .engine
        .claim_execution()
        .await
        .map_err(api_failure)?
        .context("recoverable dispatch claim")?;
    ensure!(
        claimed.operation_id == d.claim.operation_id && claimed.lease_token > d.claim.lease_token,
        "recovery must advance same operation lease"
    );
    gateway.reconcile(&claimed).await.map_err(api_failure)?;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "persisted dispatch must never issue GET or CONNECT"
    );
    let mut tx = d.f.owner_transaction().await?;
    let (status,termination,slot,stop):(String,String,bool,Option<Uuid>)=sqlx::query_as("SELECT status,termination_status,slot_held,cancel_operation_id FROM executions WHERE tenant_id=$1 AND id=$2")
        .bind(d.f.actor.tenant_id).bind(d.execution).fetch_one(&mut *tx).await?;
    assert_eq!(
        (status.as_str(), termination.as_str(), slot),
        ("OUTCOME_UNKNOWN", "PENDING", true)
    );
    assert!(stop.is_some());
    let reserved:i64=sqlx::query_scalar("SELECT sum(pending+allocated)::bigint FROM quota_accounts WHERE tenant_id=$1 AND dimension='EXECUTIONS'").bind(d.f.actor.tenant_id).fetch_one(&mut *tx).await?;
    assert_eq!(
        reserved, 2,
        "tenant and project execution quotas remain held"
    );
    tx.commit().await?;
    assert!(
        d.engine
            .database
            .complete_execution_process(
                &d.engine,
                &d.claim,
                d.execution,
                d.attempt,
                &d.completion()
            )
            .await
            .is_err()
    );
    Ok(())
}
