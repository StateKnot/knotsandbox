//! Real PG proof/permission races. Kubernetes inventory below is an explicit
//! protocol substitute; these tests make no claim of live Kata certification.
use super::*;
use crate::{
    domain::InstanceAction,
    termination_ledger::tests::FixtureRuntime,
    test_support_db::{self, api_failure, require_pg_error},
};
use anyhow::{Context, ensure};

struct NeverFixture {
    runtime: FixtureRuntime,
    contract: Uuid,
}
impl NeverFixture {
    async fn new() -> anyhow::Result<Self> {
        let mut runtime = FixtureRuntime::new(false).await?;
        let mut policy = runtime.f.owner_transaction().await?;
        let policy_id = Uuid::new_v4();
        sqlx::query("INSERT INTO security_policy_versions(id,tenant_id,name,version,status,rules) VALUES($1,$2,'never-authorized-test',1,'APPROVED',$3)")
            .bind(policy_id).bind(runtime.f.actor.tenant_id).bind(json!({"profile":"deny-all","dns":true})).execute(&mut *policy).await?;
        policy.commit().await?;
        runtime.f.request.security_profile_id = policy_id;
        let contract = Uuid::new_v4();
        let node: Uuid = sqlx::query_scalar(
            "SELECT id FROM runtime_nodes WHERE cluster_epoch=$1 AND node_uid=$2 AND boot_id=$3",
        )
        .bind(runtime.node.cluster_epoch)
        .bind(runtime.node.node_uid)
        .bind(runtime.node.boot_id)
        .fetch_one(&runtime.f.owner)
        .await?;
        sqlx::query("INSERT INTO launch_guard_contracts(id,cluster_epoch,protocol,certification_report_sha256,runtime_node_ids,approval_reference,valid_until) VALUES($1,$2,'NODEGUARD_REQUIRED_V1',$3,$4,'TEST ONLY: synthetic reviewed guard contract',clock_timestamp()+interval '5 minutes')")
            .bind(contract).bind(runtime.node.cluster_epoch).bind("a".repeat(64)).bind(vec![node]).execute(&runtime.f.owner).await?;
        let result = runtime.f.create(&Uuid::new_v4().to_string()).await;
        // Revoke even when acceptance fails. A test must not change the birth
        // protocol of unrelated later test cases through global configuration.
        sqlx::query("INSERT INTO launch_guard_contract_revocations(contract_id,approval_reference) VALUES($1,'TEST ONLY: stop new test births')").bind(contract).execute(&runtime.f.owner).await?;
        let accepted = result.map_err(api_failure)?;
        runtime.create_op = accepted.body.operation.id;
        runtime.launch.instance_id = accepted.body.resource.id;
        runtime.launch.workspace_id = accepted.body.resource.workspace_id;
        let mut tx = runtime.f.owner_transaction().await?;
        let (launch, namespace, name): (Uuid, String, String) = sqlx::query_as(
            "SELECT launch_id,namespace,pod_name FROM instances WHERE tenant_id=$1 AND id=$2",
        )
        .bind(runtime.f.actor.tenant_id)
        .bind(runtime.launch.instance_id)
        .fetch_one(&mut *tx)
        .await?;
        runtime.launch.launch_id = launch;
        runtime.launch.namespace = namespace;
        runtime.launch.pod_name = name;
        runtime.launch.pod_uid = Uuid::new_v4();
        tx.commit().await?;
        Ok(Self { runtime, contract })
    }
    async fn claim(&self) -> anyhow::Result<Claim> {
        self.runtime.accept(InstanceAction::Delete).await
    }
    async fn close(&self, claim: &Claim) -> anyhow::Result<Option<Uuid>> {
        let mut tx = self
            .runtime
            .engine
            .database
            .begin(claim.tenant_id)
            .await
            .map_err(api_failure)?;
        let id: Option<Uuid> =
            sqlx::query_scalar("SELECT sandbox_close_never_authorized($1,$2,$3,$4)")
                .bind(claim.tenant_id)
                .bind(claim.operation_id)
                .bind(self.runtime.engine.worker_id())
                .bind(claim.lease_token)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(id)
    }
    async fn insert_permit(&self, tx: &mut Transaction<'_, Postgres>) -> Result<(), sqlx::Error> {
        let r = &self.runtime;
        // Explicit test fixture: simulate a durable permit whose host ACK was
        // lost, with a live guard version admitting this exact registered node.
        sqlx::query("INSERT INTO launch_guard_contracts(id,cluster_epoch,protocol,certification_report_sha256,runtime_node_ids,approval_reference,valid_until) SELECT $1,cluster_epoch,'NODEGUARD_REQUIRED_V1',certification_report_sha256,runtime_node_ids,'TEST ONLY: delayed permit',valid_until FROM launch_guard_contracts WHERE id=$2")
            .bind(Uuid::new_v4()).bind(self.contract).execute(&mut **tx).await?;
        sqlx::query("UPDATE instances SET pod_uid=$3 WHERE tenant_id=$1 AND id=$2")
            .bind(r.f.actor.tenant_id)
            .bind(r.launch.instance_id)
            .bind(r.launch.pod_uid)
            .execute(&mut **tx)
            .await?;
        sqlx::query("INSERT INTO launch_permits(tenant_id,project_id,instance_id,workspace_id,operation_id,runtime_node_id,cluster_epoch,generation,launch_id,pod_uid,namespace,pod_name,pvc_uid,pv_uid,pv_name,csi_volume_handle,expires_at) SELECT $1,$2,$3,$4,$5,n.id,$6,1,$7,$8,$9,$10,$11,$12,$13,$14,clock_timestamp()+interval '60 seconds' FROM runtime_nodes n WHERE n.cluster_epoch=$6 AND n.node_uid=$15 AND n.boot_id=$16")
            .bind(r.f.actor.tenant_id).bind(r.launch.project_id).bind(r.launch.instance_id).bind(r.launch.workspace_id).bind(r.create_op).bind(r.node.cluster_epoch).bind(r.launch.launch_id).bind(r.launch.pod_uid).bind(&r.launch.namespace).bind(&r.launch.pod_name).bind(r.launch.pvc_uid).bind(r.launch.pv_uid).bind(&r.launch.pv_name).bind(&r.launch.csi_volume_handle).bind(r.node.node_uid).bind(r.node.boot_id).execute(&mut **tx).await?;
        sqlx::query("INSERT INTO launch_guard_contract_revocations(contract_id,approval_reference) SELECT id,'TEST ONLY: finish delayed permit fixture' FROM launch_guard_contracts c WHERE cluster_epoch=$1 AND approval_reference='TEST ONLY: delayed permit' AND NOT EXISTS(SELECT 1 FROM launch_guard_contract_revocations r WHERE r.contract_id=c.id)")
            .bind(r.node.cluster_epoch).execute(&mut **tx).await?;
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires dedicated real PostgreSQL roles"]
async fn closure_survives_controller_crash_and_releases_compute_only() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = NeverFixture::new().await?;
    let r = &f.runtime;
    let claim = f.claim().await?;
    let closed = f
        .close(&claim)
        .await?
        .context("born generation must close without a permit")?;
    ensure!(
        f.close(&claim).await? == Some(closed),
        "closure retry must preserve identity"
    );
    ensure!(
        r.engine
            .database
            .complete_never_authorized_deletion(&r.engine, &claim)
            .await
            .map_err(api_failure)?,
        "closure recovery should finish"
    );
    let mut tx = r.f.owner_transaction().await?;
    let state:(String,String,Uuid,Option<Uuid>)=sqlx::query_as("SELECT i.observed_state,w.status,i.never_authorized_closure_id,i.last_termination_proof_id FROM instances i JOIN workspaces w ON w.tenant_id=i.tenant_id AND w.id=i.workspace_id WHERE i.tenant_id=$1 AND i.id=$2").bind(r.f.actor.tenant_id).bind(r.launch.instance_id).fetch_one(&mut *tx).await?;
    ensure!(
        state == ("DELETED".into(), "PENDING".into(), closed, None),
        "no host or volume proof may be fabricated"
    );
    let held:Vec<(String,i64)>=sqlx::query_as("SELECT q.dimension,count(*) FROM quota_reservations r JOIN quota_accounts q ON q.tenant_id=r.tenant_id AND q.id=r.quota_account_id WHERE r.tenant_id=$1 AND r.resource_id IN($2,$3) AND r.status IN('PENDING','ALLOCATED') GROUP BY q.dimension ORDER BY q.dimension").bind(r.f.actor.tenant_id).bind(r.launch.workspace_id).bind(r.launch.instance_id).fetch_all(&mut *tx).await?;
    ensure!(
        held == vec![("WORKSPACE_GIB".into(), 2)],
        "storage must remain reserved despite absent PVC/Pod"
    );
    let events:i64=sqlx::query_scalar("SELECT count(*) FROM domain_events WHERE tenant_id=$1 AND aggregate_id=$2 AND event_type='instance.deleted'").bind(r.f.actor.tenant_id).bind(r.launch.instance_id).fetch_one(&mut *tx).await?;
    ensure!(events == 1, "completion exactly once");
    tx.commit().await?;
    ensure!(
        r.engine
            .database
            .complete_never_authorized_deletion(&r.engine, &claim)
            .await
            .is_err(),
        "finished lease cannot replay effects"
    );
    let mut tx = r.f.owner_transaction().await?;
    require_pg_error(f.insert_permit(&mut tx).await, "23514")?;
    tx.rollback().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "requires dedicated real PostgreSQL roles"]
async fn committed_permit_without_ack_blocks_nonexecution_proof() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = NeverFixture::new().await?;
    let mut tx = f.runtime.f.owner_transaction().await?;
    f.insert_permit(&mut tx).await?;
    tx.commit().await?;
    let claim = f.claim().await?;
    ensure!(
        f.close(&claim).await?.is_none(),
        "missing ACK does not mean never authorized"
    );
    ensure!(
        !f.runtime
            .engine
            .database
            .complete_never_authorized_deletion(&f.runtime.engine, &claim)
            .await
            .map_err(api_failure)?,
        "must use host closure"
    );
    Ok(())
}
#[tokio::test]
#[ignore = "requires dedicated real PostgreSQL roles"]
async fn old_generations_and_restored_epoch_cannot_infer_nonexecution() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let old = FixtureRuntime::new(false).await?;
    let claim = old.accept(InstanceAction::Delete).await?;
    ensure!(
        !old.engine
            .database
            .complete_never_authorized_deletion(&old.engine, &claim)
            .await
            .map_err(api_failure)?,
        "no retrospective birth receipt"
    );
    let f = NeverFixture::new().await?;
    let claim = f.claim().await?;
    let closure = f.close(&claim).await?.context("closure")?;
    // A transaction-local epoch change exercises the SQL proof gate and rolls
    // back even if the assertion fails; no global restore state is published.
    let mut tx = f.runtime.f.owner_transaction().await?;
    sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton")
        .bind(Uuid::new_v4())
        .execute(&mut *tx)
        .await?;
    let proof: bool = sqlx::query_scalar("SELECT sandbox_never_authorized($1,$2,$3,1,$4,$5,$6)")
        .bind(f.runtime.f.actor.tenant_id)
        .bind(f.runtime.launch.instance_id)
        .bind(f.runtime.launch.workspace_id)
        .bind(f.runtime.launch.launch_id)
        .bind(f.runtime.node.cluster_epoch)
        .bind(closure)
        .fetch_one(&mut *tx)
        .await?;
    ensure!(!proof, "restore epoch must fence prior proof");
    tx.rollback().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "requires dedicated real PostgreSQL roles"]
async fn closure_waiting_for_workspace_rechecks_expired_lease() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = NeverFixture::new().await?;
    let claim = f.claim().await?;
    let mut lock = f.runtime.f.owner_transaction().await?;
    sqlx::query("SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(claim.tenant_id)
        .bind(f.runtime.launch.workspace_id)
        .fetch_one(&mut *lock)
        .await?;
    // Concurrent real SQL waits for the shared workspace row.
    let db = f.runtime.engine.database.clone();
    let worker = f.runtime.engine.worker_id().to_string();
    let next = claim.clone();
    let task = tokio::spawn(async move {
        let mut tx = db.begin(next.tenant_id).await.map_err(api_failure)?;
        let result: Result<Option<Uuid>, sqlx::Error> =
            sqlx::query_scalar("SELECT sandbox_close_never_authorized($1,$2,$3,$4)")
                .bind(next.tenant_id)
                .bind(next.operation_id)
                .bind(worker)
                .bind(next.lease_token)
                .fetch_one(&mut *tx)
                .await;
        tx.rollback().await?;
        Ok::<_, anyhow::Error>(result)
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    sqlx::query("UPDATE operations SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND id=$2").bind(claim.tenant_id).bind(claim.operation_id).execute(&mut *lock).await?;
    lock.commit().await?;
    require_pg_error(task.await??, "P4090")?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires dedicated PostgreSQL plus local Kubernetes protocol substitute"]
async fn late_pod_after_empty_inventory_is_bound_before_finalizer_removal() -> anyhow::Result<()> {
    use crate::{
        admission::{AdmissionConfig, AdmissionRequest, AdmissionService},
        never_authorized_gc::NeverAuthorizedGc,
        runtime_manifest::{RuntimeManifestConfig, build_manifests},
    };
    use axum::{
        body::Body,
        http::{Method, Request, Response},
    };
    use http_body_util::BodyExt;
    use kube::{Client, client::Body as KubeBody};
    use std::sync::{Arc, Mutex};
    let _serial = test_support_db::serial().await;
    let f = NeverFixture::new().await?;
    let r = &f.runtime;
    let claim = f.claim().await?;
    let mut known = r.f.owner_transaction().await?;
    sqlx::query("UPDATE instances SET pod_uid=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(r.f.actor.tenant_id)
        .bind(r.launch.instance_id)
        .bind(r.launch.pod_uid)
        .execute(&mut *known)
        .await?;
    sqlx::query("INSERT INTO external_resources(tenant_id,project_id,operation_id,instance_id,workspace_id,provider,kind,provider_id,generation,owner_id,status) VALUES($1,$2,$3,$4,$5,'kubernetes','POD',$6,1,$4,'ACTIVE')")
        .bind(r.f.actor.tenant_id).bind(r.launch.project_id).bind(r.create_op).bind(r.launch.instance_id).bind(r.launch.workspace_id).bind(r.launch.pod_uid.to_string()).execute(&mut *known).await?;
    known.commit().await?;
    let target = r
        .engine
        .database
        .load_termination_target(claim.tenant_id, claim.operation_id)
        .await
        .map_err(api_failure)?;
    ensure!(
        r.engine
            .database
            .complete_never_authorized_deletion(&r.engine, &claim)
            .await
            .map_err(api_failure)?,
        "compute closure"
    );
    let manifests = RuntimeManifestConfig {
        runtime_class_name: "kata-qemu".into(),
        dns_namespace: "kube-system".into(),
        dns_labels: std::collections::BTreeMap::from([("k8s-app".into(), "kube-dns".into())]),
        ephemeral_storage_mib: 1024,
        tmp_size_mib: 256,
    };
    let current: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let state = current.clone();
    let namespace = json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":r.launch.namespace,"uid":Uuid::new_v4(),"labels":{"sandbox.platform/managed":"true","sandbox.platform/tenant-id":r.f.actor.tenant_id,"sandbox.platform/project-id":r.launch.project_id,"sandbox.platform/cluster-epoch":r.node.cluster_epoch},"annotations":{"sandbox.platform/certification-id":"test-never-authorized"}}});
    let client = Client::new(
        tower::service_fn(move |request: Request<KubeBody>| {
            let state = state.clone();
            let namespace = namespace.clone();
            async move {
                let path = request.uri().path().to_string();
                let method = request.method().clone();
                let body = request
                    .into_body()
                    .collect()
                    .await
                    .map_err(|_| std::io::Error::other("body"))?
                    .to_bytes();
                let mut pod = state
                    .lock()
                    .map_err(|_| std::io::Error::other("fixture lock"))?;
                let mut status = 200;
                let value = if path == "/api/v1/pods" {
                    json!({"apiVersion":"v1","kind":"PodList","metadata":{},"items":pod.iter().cloned().collect::<Vec<_>>()})
                } else if !path.contains("/pods/") {
                    namespace
                } else if let Some(before) = pod.as_ref().cloned() {
                    if method == Method::DELETE {
                        let params: Value = serde_json::from_slice(&body)?;
                        if params["preconditions"]["uid"] != before["metadata"]["uid"]
                            || params["preconditions"]["resourceVersion"]
                                != before["metadata"]["resourceVersion"]
                            || params["gracePeriodSeconds"] != json!(30)
                        {
                            status = 409;
                            before
                        } else {
                            let mut next = before;
                            next["metadata"]["deletionTimestamp"] = json!(Utc::now());
                            next["metadata"]["resourceVersion"] = json!("2");
                            *pod = Some(next.clone());
                            next
                        }
                    } else if method == Method::PATCH {
                        let patch: Value = serde_json::from_slice(&body)?;
                        if patch["metadata"]["uid"] != before["metadata"]["uid"]
                            || patch["metadata"]["resourceVersion"]
                                != before["metadata"]["resourceVersion"]
                            || patch["metadata"]["finalizers"] != json!([])
                        {
                            status = 409;
                            before
                        } else {
                            let mut next = before;
                            next["metadata"]["finalizers"] = json!([]);
                            *pod = None;
                            next
                        }
                    } else {
                        before
                    }
                } else {
                    status = 404;
                    json!({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","message":"missing","code":404})
                };
                Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(Body::from(value.to_string()))
                    .map_err(std::io::Error::other)
            }
        }),
        "default",
    );
    let gc = NeverAuthorizedGc {
        database: r.engine.database.clone(),
        client: client.clone(),
        manifests: manifests.clone(),
    };
    ensure!(
        gc.page(None).await?.is_none(),
        "first inventory intentionally empty"
    );
    let mut pod = build_manifests(&target.context, &manifests)?.pod;
    pod.metadata.uid = Some(r.launch.pod_uid.to_string());
    pod.metadata.resource_version = Some("1".into());
    let good = serde_json::to_value(&pod)?;
    let mut config: Value =
        serde_json::from_str(include_str!("../deploy/admission/config.example.json"))?;
    fn substitute(value: &mut Value) {
        match value {
            Value::Object(map) => {
                for (key, v) in map {
                    if key == "uid" {
                        *v = json!(Uuid::new_v4());
                    } else {
                        substitute(v)
                    }
                }
            }
            Value::Array(values) => {
                for v in values {
                    substitute(v)
                }
            }
            _ => {}
        }
    }
    substitute(&mut config);
    config["certification_id"] = json!("test-never-authorized");
    let config: AdmissionConfig = serde_json::from_value(config)?;
    sqlx::raw_sql(include_str!("../scripts/sql/admission-role.sql"))
        .execute(&r.f.owner)
        .await?;
    let admission = AdmissionService {
        database: Database::connect(&std::env::var("TEST_ADMISSION_DATABASE_URL")?, 2).await?,
        kubernetes: client.clone(),
        config,
    };
    let delete: AdmissionRequest = serde_json::from_value(
        json!({"uid":Uuid::new_v4(),"resource":{"group":"","version":"v1","resource":"pods"},"operation":"DELETE","namespace":r.launch.namespace,"name":r.launch.pod_name,"userInfo":{"username":admission.config.termination.username,"uid":admission.config.termination.uid},"oldObject":good,"options":{"preconditions":{"uid":r.launch.pod_uid,"resourceVersion":"1"},"gracePeriodSeconds":30}}),
    )?;
    ensure!(
        admission.decide(&delete).await.is_err(),
        "known closure without verified Pod receipt cannot remove resource"
    );
    let mut wrong = pod.clone();
    wrong.spec.as_mut().context("spec")?.runtime_class_name = Some("runc".into());
    *current.lock().map_err(|_| anyhow::anyhow!("lock"))? = Some(serde_json::to_value(&wrong)?);
    ensure!(
        gc.collect(&wrong).await.is_err(),
        "wrong runtime cannot be recorded as controlled late Pod"
    );
    *current.lock().map_err(|_| anyhow::anyhow!("lock"))? = Some(good);
    ensure!(
        gc.collect(&pod).await?,
        "late live Pod gets exact UID receipt then DELETE"
    );
    ensure!(
        admission.decide(&delete).await.is_ok(),
        "exact bound deletion is admitted"
    );
    let old = current
        .lock()
        .map_err(|_| anyhow::anyhow!("lock"))?
        .clone()
        .context("deleting Pod")?;
    let mut unprotected = old.clone();
    unprotected["metadata"]["finalizers"] = json!([]);
    let mut patch: AdmissionRequest = serde_json::from_value(
        json!({"uid":Uuid::new_v4(),"resource":{"group":"","version":"v1","resource":"pods"},"operation":"UPDATE","namespace":r.launch.namespace,"name":r.launch.pod_name,"userInfo":{"username":admission.config.termination.username,"uid":admission.config.termination.uid},"oldObject":old,"object":unprotected}),
    )?;
    ensure!(
        admission.decide(&patch).await.is_ok(),
        "only permanent exact proof permits finalizer removal"
    );
    patch.user_info.username = admission.config.worker.username.clone();
    patch.user_info.uid = admission.config.worker.uid.clone();
    ensure!(
        admission.decide(&patch).await.is_err(),
        "ordinary worker cannot remove finalizer"
    );
    let deleting = serde_json::from_value(old)?;
    ensure!(
        gc.collect(&deleting).await?,
        "next reconciliation finalizes exact UID"
    );
    ensure!(
        current
            .lock()
            .map_err(|_| anyhow::anyhow!("lock"))?
            .is_none(),
        "protocol substitute completed deletion"
    );
    // A later different UID does not inherit the old admission receipt. It
    // remains discoverable by the permanent birth record and needs revalidation.
    let mut replacement = pod;
    replacement.metadata.uid = Some(Uuid::new_v4().to_string());
    *current.lock().map_err(|_| anyhow::anyhow!("lock"))? =
        Some(serde_json::to_value(&replacement)?);
    let mut another = delete.clone();
    another.old_object = Some(serde_json::to_value(&replacement)?);
    another.options = Some(
        json!({"preconditions":{"uid":replacement.metadata.uid,"resourceVersion":"1"},"gracePeriodSeconds":30}),
    );
    ensure!(
        admission.decide(&another).await.is_err(),
        "replacement UID cannot reuse prior receipt"
    );
    ensure!(
        gc.collect(&replacement).await?,
        "GC must not forget the birth after an earlier cleanup"
    );
    ensure!(
        admission.decide(&another).await.is_ok(),
        "new independently verified UID supersedes only GC's old instance UID"
    );
    let mut tx = r.f.owner_transaction().await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM never_authorized_pod_observations WHERE tenant_id=$1",
    )
    .bind(r.f.actor.tenant_id)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(count == 2, "both exact UIDs remain append-only");
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL lock and DELETE/permit transactions"]
async fn delete_waits_for_inflight_permit_and_cancels_create_lease_atomically() -> anyhow::Result<()>
{
    let _serial = test_support_db::serial().await;
    let f = NeverFixture::new().await?;
    let r = &f.runtime;
    let mut producer = r.f.owner_transaction().await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *producer)
        .await?;
    sqlx::query("SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(r.f.actor.tenant_id)
        .bind(r.launch.workspace_id)
        .fetch_one(&mut *producer)
        .await?;
    f.insert_permit(&mut producer).await?;
    let database = r.f.database.clone();
    let actor = r.f.actor.clone();
    let id = r.launch.instance_id;
    let pending = tokio::spawn(async move {
        database
            .lifecycle_action(
                &actor,
                id,
                InstanceAction::Delete,
                &crate::model::StartRequest { ttl_seconds: None },
                &Uuid::new_v4().to_string(),
                1,
                300,
                86400,
            )
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
            )
            .bind(pid)
            .fetch_one(&r.f.owner)
            .await?;
            if blocked {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok::<_, sqlx::Error>(())
    })
    .await??;
    producer.commit().await?;
    let accepted = pending.await?.map_err(api_failure)?;
    let mut tx = r.f.owner_transaction().await?;
    let old: (String, String, i64) = sqlx::query_as(
        "SELECT status,stage,lease_token FROM operations WHERE tenant_id=$1 AND id=$2",
    )
    .bind(r.f.actor.tenant_id)
    .bind(r.create_op)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(
        old.0 == "CANCELLED" && old.1 == "SUPERSEDED_BY_DELETE" && old.2 > 0,
        "CREATE lease must be fenced in same transaction"
    );
    sqlx::query("UPDATE operations SET next_attempt_at=(SELECT COALESCE(min(eligible_at),clock_timestamp())-interval '1 day' FROM operation_dispatch WHERE queue_role='TERMINATION') WHERE tenant_id=$1 AND id=$2").bind(r.f.actor.tenant_id).bind(accepted.body.operation.id).execute(&mut *tx).await?;
    tx.commit().await?;
    let claim = r
        .engine
        .claim_termination()
        .await
        .map_err(api_failure)?
        .context("claim")?;
    ensure!(
        claim.operation_id == accepted.body.operation.id,
        "own operation"
    );
    ensure!(
        f.close(&claim).await?.is_none(),
        "committed inflight permit forces host closure even without ACK"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL stream-head locking"]
async fn event_wait_cannot_release_compute_after_closure_claim_expires() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = NeverFixture::new().await?;
    let r = &f.runtime;
    let claim = f.claim().await?;
    let closure = f.close(&claim).await?.context("closure")?;
    let mut tx = r.f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET lease_until=clock_timestamp()+interval '1 second' WHERE tenant_id=$1 AND id=$2").bind(claim.tenant_id).bind(claim.operation_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let mut blocker = r.f.owner_transaction().await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    sqlx::query(
        "SELECT project_id FROM event_stream_heads WHERE tenant_id=$1 AND project_id=$2 FOR UPDATE",
    )
    .bind(r.f.actor.tenant_id)
    .bind(r.launch.project_id)
    .fetch_one(&mut *blocker)
    .await?;
    let engine = r.engine.clone();
    let next = claim.clone();
    let pending = tokio::spawn(async move {
        engine
            .database
            .complete_never_authorized_deletion(&engine, &next)
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
            )
            .bind(pid)
            .fetch_one(&r.f.owner)
            .await?;
            if waiting {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok::<_, sqlx::Error>(())
    })
    .await??;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    blocker.commit().await?;
    ensure!(
        matches!(pending.await?,Err(e) if e.code=="WORKER_LEASE_LOST"),
        "event wait must not bypass lease"
    );
    let mut tx = r.f.owner_transaction().await?;
    let proof: bool = sqlx::query_scalar("SELECT sandbox_never_authorized($1,$2,$3,1,$4,$5,$6)")
        .bind(r.f.actor.tenant_id)
        .bind(r.launch.instance_id)
        .bind(r.launch.workspace_id)
        .bind(r.launch.launch_id)
        .bind(r.node.cluster_epoch)
        .bind(closure)
        .fetch_one(&mut *tx)
        .await?;
    ensure!(proof, "permanent closure survives completion rollback");
    let held:i64=sqlx::query_scalar("SELECT count(*) FROM quota_reservations WHERE tenant_id=$1 AND resource_id=$2 AND status IN('PENDING','ALLOCATED')").bind(r.f.actor.tenant_id).bind(r.launch.instance_id).fetch_one(&mut *tx).await?;
    ensure!(
        held == 6,
        "compute quota remains until fresh lease completion"
    );
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL SYSTEM timer and operation leasing"]
async fn expired_create_system_stop_can_be_explicitly_deleted_without_reviving_old_worker()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = NeverFixture::new().await?;
    let r = &f.runtime;
    let mut tx = r.f.owner_transaction().await?;
    sqlx::query("UPDATE instances SET compute_lease_started_at='1970-01-01Z',compute_lease_expires_at='1970-01-02Z' WHERE tenant_id=$1 AND id=$2").bind(r.f.actor.tenant_id).bind(r.launch.instance_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let stop =
        r.f.database
            .accept_due_stop(r.f.actor.tenant_id, r.launch.instance_id)
            .await
            .map_err(api_failure)?
            .context("system TTL stop")?;
    let mut tx = r.f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET status='RUNNING',lease_owner=$3,lease_until=clock_timestamp()+interval '1 minute',lease_token=7 WHERE tenant_id=$1 AND id=$2").bind(r.f.actor.tenant_id).bind(stop).bind(r.engine.worker_id()).execute(&mut *tx).await?;
    tx.commit().await?;
    let old = Claim {
        tenant_id: r.f.actor.tenant_id,
        operation_id: stop,
        lease_token: 7,
    };
    let claim = f.claim().await?;
    let mut tx = r
        .engine
        .database
        .begin(old.tenant_id)
        .await
        .map_err(api_failure)?;
    ensure!(
        matches!(r.engine.assert_claim(&mut tx,&old).await,Err(error) if error.code=="WORKER_LEASE_LOST"),
        "old STOP worker must lose its lease"
    );
    tx.rollback().await?;
    ensure!(
        r.engine
            .database
            .complete_never_authorized_deletion(&r.engine, &claim)
            .await
            .map_err(api_failure)?,
        "TTL failure can complete explicit compute DELETE"
    );
    let mut tx = r.f.owner_transaction().await?;
    let audit:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM audit_events WHERE tenant_id=$1 AND operation_id=$2 AND action='operations:cancel' AND details->>'superseded_by'=$3)").bind(r.f.actor.tenant_id).bind(stop).bind(claim.operation_id.to_string()).fetch_one(&mut *tx).await?;
    ensure!(audit, "STOP replacement must be audited");
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; temporarily pauses fixture node admission"]
async fn reviewed_contract_activation_is_owner_only_exact_and_versioned() -> anyhow::Result<()> {
    use crate::launch_authority::{GuardContractRequest, apply_guard_contract};
    let _serial = test_support_db::serial().await;
    let r = FixtureRuntime::new(false).await?;
    let node: Uuid = sqlx::query_scalar(
        "SELECT id FROM runtime_nodes WHERE cluster_epoch=$1 AND node_uid=$2 AND boot_id=$3",
    )
    .bind(r.node.cluster_epoch)
    .bind(r.node.node_uid)
    .bind(r.node.boot_id)
    .fetch_one(&r.f.owner)
    .await?;
    let report:String=sqlx::query_scalar("SELECT certification_report_sha256 FROM runtime_node_enrollments WHERE runtime_node_id=$1 ORDER BY certification_reviewed_at DESC,registered_at DESC,id DESC LIMIT 1").bind(node).fetch_one(&r.f.owner).await?;
    let id = Uuid::new_v4();
    let request = GuardContractRequest::parse(&serde_json::to_vec(
        &json!({"action":"activate","contract_id":id,"cluster_epoch":r.node.cluster_epoch,"certification_report_sha256":report,"runtime_node_ids":[node],"approval_reference":"TEST ONLY: owner activation regression"}),
    )?)?;
    ensure!(
        apply_guard_contract(&r.f.database, &request).await.is_err(),
        "API runtime cannot activate guard protocol"
    );
    let owner = Database {
        pool: r.f.owner.clone(),
    };
    ensure!(
        apply_guard_contract(&owner, &request).await.is_err(),
        "owner still needs maintenance safe mode"
    );
    let (prior_safe,others):(bool,Vec<Uuid>)=sqlx::query_as("SELECT c.safe_mode,ARRAY(SELECT id FROM runtime_nodes WHERE cluster_epoch=c.cluster_epoch AND enabled AND id<>$1) FROM platform_configuration c WHERE singleton").bind(node).fetch_one(&r.f.owner).await?;
    let mut tx = r.f.owner.begin().await?;
    sqlx::query("UPDATE platform_configuration SET safe_mode=true WHERE singleton")
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE runtime_nodes SET enabled=false WHERE id=ANY($1)")
        .bind(&others)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let outcome = async {
        let receipt = apply_guard_contract(&owner, &request).await?;
        ensure!(
            receipt.changed && !receipt.revoked,
            "activate exact reviewed set"
        );
        ensure!(
            !apply_guard_contract(&owner, &request).await?.changed,
            "identical installation replay is idempotent"
        );
        let wrong = GuardContractRequest::Activate {
            contract_id: Uuid::new_v4(),
            cluster_epoch: r.node.cluster_epoch,
            certification_report_sha256: report.clone(),
            runtime_node_ids: vec![Uuid::new_v4()],
            approval_reference: "TEST ONLY: wrong set".into(),
        };
        ensure!(
            apply_guard_contract(&owner, &wrong).await.is_err(),
            "cannot certify a caller-invented node set"
        );
        let revoke = GuardContractRequest::Revoke {
            contract_id: id,
            approval_reference: "TEST ONLY: revoke activation regression".into(),
        };
        ensure!(
            apply_guard_contract(&owner, &revoke).await?.changed,
            "revocation persisted"
        );
        ensure!(
            apply_guard_contract(&owner, &request).await.is_err(),
            "revoked immutable identity cannot be silently reactivated"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    // Restore global fixture admission even if one assertion failed. The audit
    // remains append-only and explicitly test-only in this disposable database.
    let cleanup=async {
        sqlx::query("INSERT INTO launch_guard_contract_revocations(contract_id,approval_reference) SELECT id,'TEST ONLY: failed test cleanup' FROM launch_guard_contracts WHERE id=$1 ON CONFLICT(contract_id) DO NOTHING").bind(id).execute(&r.f.owner).await?;
        let mut tx=r.f.owner.begin().await?;sqlx::query("UPDATE runtime_nodes SET enabled=true WHERE id=ANY($1)").bind(&others).execute(&mut *tx).await?;sqlx::query("UPDATE platform_configuration SET safe_mode=$1 WHERE singleton").bind(prior_safe).execute(&mut *tx).await?;tx.commit().await?;Ok::<_,anyhow::Error>(())
    }.await;
    cleanup?;
    outcome
}

#[tokio::test]
#[ignore = "requires real PostgreSQL admission identity and Kubernetes protocol substitute"]
async fn scheduler_binding_requires_enrolled_boot_profile_and_guard_node_set() -> anyhow::Result<()>
{
    use crate::{
        admission::{AdmissionConfig, AdmissionRequest, AdmissionService},
        runtime_manifest::{RuntimeManifestConfig, build_manifests},
    };
    use axum::{
        body::Body,
        http::{Request, Response},
    };
    use kube::{Client, client::Body as KubeBody};
    use std::sync::{Arc, Mutex};
    let _serial = test_support_db::serial().await;
    let f = NeverFixture::new().await?;
    let r = &f.runtime;
    let target = r
        .engine
        .database
        .load_termination_target(r.f.actor.tenant_id, r.create_op)
        .await
        .map_err(api_failure)?;
    let manifests = RuntimeManifestConfig {
        runtime_class_name: "kata-qemu".into(),
        dns_namespace: "kube-system".into(),
        dns_labels: std::collections::BTreeMap::from([("k8s-app".into(), "kube-dns".into())]),
        ephemeral_storage_mib: 1024,
        tmp_size_mib: 256,
    };
    let mut pod = build_manifests(&target.context, &manifests)?.pod;
    pod.metadata.uid = Some(r.launch.pod_uid.to_string());
    pod.metadata.resource_version = Some("1".into());
    let node = json!({"apiVersion":"v1","kind":"Node","metadata":{"name":r.node.node_name,"uid":r.node.node_uid,"labels":{"sandbox.platform/worker-pool":"kata"},"annotations":{"sandbox.platform/runtime-profile-sha256":r.node.profile_sha256}},"spec":{},"status":{"conditions":[{"type":"Ready","status":"True"}],"nodeInfo":{"bootID":r.node.boot_id,"architecture":"amd64","containerRuntimeVersion":"containerd://2.3.5","kernelVersion":"TEST ONLY","kubeProxyVersion":"","kubeletVersion":"v1.36.4","machineID":"test","operatingSystem":"linux","osImage":"TEST ONLY","systemUUID":"test"}}});
    let current = Arc::new(Mutex::new(node.clone()));
    let observed = current.clone();
    let namespace = json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":r.launch.namespace,"uid":Uuid::new_v4(),"labels":{"sandbox.platform/managed":"true","sandbox.platform/tenant-id":r.f.actor.tenant_id,"sandbox.platform/project-id":r.launch.project_id,"sandbox.platform/cluster-epoch":r.node.cluster_epoch},"annotations":{"sandbox.platform/certification-id":"test-never-authorized"}}});
    let pod = serde_json::to_value(pod)?;
    let client = Client::new(
        tower::service_fn(move |request: Request<KubeBody>| {
            let observed = observed.clone();
            let namespace = namespace.clone();
            let pod = pod.clone();
            async move {
                let value = if request.uri().path().contains("/nodes/") {
                    observed
                        .lock()
                        .map_err(|_| std::io::Error::other("fixture lock"))?
                        .clone()
                } else if request.uri().path().contains("/pods/") {
                    pod
                } else {
                    namespace
                };
                Response::builder()
                    .header("content-type", "application/json")
                    .body(Body::from(value.to_string()))
                    .map_err(std::io::Error::other)
            }
        }),
        "default",
    );
    let mut config: Value =
        serde_json::from_str(include_str!("../deploy/admission/config.example.json"))?;
    fn substitute(v: &mut Value) {
        match v {
            Value::Object(m) => {
                for (k, v) in m {
                    if k == "uid" {
                        *v = json!(Uuid::new_v4());
                    } else {
                        substitute(v)
                    }
                }
            }
            Value::Array(a) => {
                for v in a {
                    substitute(v)
                }
            }
            _ => {}
        }
    }
    substitute(&mut config);
    config["certification_id"] = json!("test-never-authorized");
    let config: AdmissionConfig = serde_json::from_value(config)?;
    sqlx::raw_sql(include_str!("../scripts/sql/admission-role.sql"))
        .execute(&r.f.owner)
        .await?;
    let admission = AdmissionService {
        database: Database::connect(&std::env::var("TEST_ADMISSION_DATABASE_URL")?, 2).await?,
        kubernetes: client,
        config,
    };
    let binding: AdmissionRequest = serde_json::from_value(
        json!({"uid":Uuid::new_v4(),"resource":{"group":"","version":"v1","resource":"pods"},"subResource":"binding","operation":"CREATE","namespace":r.launch.namespace,"name":r.launch.pod_name,"userInfo":{"username":"system:kube-scheduler","uid":"","groups":["system:authenticated"]},"object":{"apiVersion":"v1","kind":"Binding","metadata":{"name":r.launch.pod_name,"namespace":r.launch.namespace,"uid":r.launch.pod_uid},"target":{"apiVersion":"v1","kind":"Node","name":r.node.node_name}}}),
    )?;
    ensure!(
        admission.decide(&binding).await.is_err(),
        "revoked contract cannot schedule a born workload"
    );
    // Publish only this explicit synthetic fixture contract; revoke it below
    // even when an assertion fails, without granting real certification.
    let contract = Uuid::new_v4();
    sqlx::query("INSERT INTO launch_guard_contracts(id,cluster_epoch,protocol,certification_report_sha256,runtime_node_ids,approval_reference,valid_until) SELECT $1,cluster_epoch,protocol,certification_report_sha256,runtime_node_ids,'TEST ONLY: binding gate',valid_until FROM launch_guard_contracts WHERE id=$2").bind(contract).bind(f.contract).execute(&r.f.owner).await?;
    let outcome = async {
        ensure!(
            admission.decide(&binding).await.is_ok(),
            "exact enrolled current boot with valid contract may bind"
        );
        for (pointer, value) in [
            ("/metadata/uid", json!(Uuid::new_v4())),
            ("/status/nodeInfo/bootID", json!(Uuid::new_v4())),
            (
                "/metadata/annotations/sandbox.platform~1runtime-profile-sha256",
                json!("ff".repeat(32)),
            ),
        ] {
            let mut wrong = node.clone();
            *wrong.pointer_mut(pointer).context("fixture pointer")? = value;
            *current.lock().map_err(|_| anyhow::anyhow!("lock"))? = wrong;
            ensure!(
                admission.decide(&binding).await.is_err(),
                "labels and Ready cannot substitute exact enrollment"
            );
        }
        *current.lock().map_err(|_| anyhow::anyhow!("lock"))? = node.clone();
        sqlx::query("UPDATE runtime_nodes SET enabled=false WHERE node_uid=$1 AND boot_id=$2")
            .bind(r.node.node_uid)
            .bind(r.node.boot_id)
            .execute(&r.f.owner)
            .await?;
        ensure!(
            admission.decide(&binding).await.is_err(),
            "disabled enrolled nodes cannot receive a new binding"
        );
        sqlx::query("UPDATE runtime_nodes SET enabled=true WHERE node_uid=$1 AND boot_id=$2")
            .bind(r.node.node_uid)
            .bind(r.node.boot_id)
            .execute(&r.f.owner)
            .await?;
        let mut tx = admission
            .database
            .begin(r.f.actor.tenant_id)
            .await
            .map_err(api_failure)?;
        let cross: bool =
            sqlx::query_scalar("SELECT sandbox_guarded_node_binding($1,$2,$3,$4,$5,$6)")
                .bind(Uuid::new_v4())
                .bind(r.launch.instance_id)
                .bind(r.node.node_uid)
                .bind(&r.node.node_name)
                .bind(r.node.boot_id)
                .bind(&r.node.profile_sha256)
                .fetch_one(&mut *tx)
                .await?;
        ensure!(!cross, "narrow function cannot cross selected tenant");
        tx.rollback().await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    sqlx::query("UPDATE runtime_nodes SET enabled=true WHERE node_uid=$1 AND boot_id=$2")
        .bind(r.node.node_uid)
        .bind(r.node.boot_id)
        .execute(&r.f.owner)
        .await?;
    sqlx::query("INSERT INTO launch_guard_contract_revocations(contract_id,approval_reference) VALUES($1,'TEST ONLY: finish binding gate')").bind(contract).execute(&r.f.owner).await?;
    outcome?;
    Ok(())
}
