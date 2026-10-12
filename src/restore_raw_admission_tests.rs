//! Private raw-parent acceptance against actual narrow-role PG and TCP HTTP.
//! The API server is a stateful stand-in; this is not vendor CSI certification.
//! Every POST invokes the actual RestoreAdmissionService before storing a UID.
use super::super::{
    RestoreRecord, admission::RestoreAdmissionService, resources::RestoreStoragePlan,
};
use crate::{
    admission::{AdmissionRequest, ControllerIdentity, ServiceIdentity},
    backup_admission::BackupAdmissionIdentities,
    backup_job::{BackupCloudSettings, BackupJobRuntime},
    backup_manifest::NAMESPACE,
    db::Database,
    engine::{Claim, OperationEngine},
    runtime::KubernetesRuntime,
    termination_ledger::tests::FixtureRuntime,
    test_support_db::api_failure,
};
use anyhow::{Context, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, Response, StatusCode},
};
use chrono::Utc;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;

/// One fixture context keeps the accepted owner/source/claim chain intact.
/// No JobPlan or future Bound receipt is manufactured to enter this path.
pub(super) struct RawParentCase<'a> {
    pub engine: &'a OperationEngine,
    pub claim: Claim,
    pub base: &'a FixtureRuntime,
    pub plan: RestoreStoragePlan,
    pub objects: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug)]
enum Fault {
    SecondUid,
    BoundWithoutParent,
    UnknownPhase,
    MissingPhase,
    SecondPhase,
    Deleting,
    ResponseUid,
    LostCreateAck,
    ConflictAfterStored,
    Readback(u8),
}
#[derive(Default)]
struct State {
    objects: BTreeMap<String, Value>,
    requests: Vec<(Method, String)>,
    service: Option<RestoreAdmissionService>,
    user: Value,
    pvc_path: String,
    reads: usize,
    stored: usize,
    conflicts: usize,
    lost_acks: usize,
    reviews: Vec<(Value, u16)>,
    fault: Option<Fault>,
}
type Shared = Arc<Mutex<State>>;
fn response(status: StatusCode, body: Value) -> Response<Body> {
    let mut answer = Response::new(Body::from(body.to_string()));
    *answer.status_mut() = status;
    answer.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    answer
}
fn error(status: StatusCode, reason: &str) -> Response<Body> {
    response(
        status,
        json!({"apiVersion":"v1","kind":"Status","status":"Failure",
            "reason":reason,"message":reason,"code":status.as_u16()}),
    )
}
fn review(candidate: Value, user: Value) -> anyhow::Result<AdmissionRequest> {
    Ok(serde_json::from_value(json!({
        "uid":Uuid::new_v4(),"resource":{"group":"","version":"v1","resource":"persistentvolumeclaims"},
        "operation":"CREATE","namespace":NAMESPACE,"name":candidate["metadata"]["name"],
        "userInfo":user,"object":candidate
    }))?)
}
fn server_candidate(mut body: Value) -> Value {
    // Pinned v1.36.4 PrepareForCreate clears status before validation; the
    // storage GET is defaulted to Pending. Do not inject a future binding here.
    // Pinned apiserver fills system metadata before validating admission.
    // The sole known protection finalizer is added by builtin mutating admission.
    body["metadata"]["uid"] = json!(Uuid::new_v4());
    body["metadata"]["creationTimestamp"] = json!(Utc::now());
    if body.pointer("/metadata/finalizers").is_none() {
        body["metadata"]["finalizers"] = json!(["kubernetes.io/pvc-protection"]);
    }
    body
}
async fn http(shared: Shared, request: Request<Body>) -> Response<Body> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let bytes = match to_bytes(request.into_body(), 131_072).await {
        Ok(body) => body,
        Err(_) => return error(StatusCode::BAD_REQUEST, "BadRequest"),
    };
    if method == Method::GET {
        let Ok(mut state) = shared.lock() else {
            return error(StatusCode::INTERNAL_SERVER_ERROR, "FixtureState");
        };
        state.requests.push((method, path.clone()));
        if path == state.pvc_path && state.objects.contains_key(&path) {
            state.reads += 1;
            let fault = state.fault;
            let reads = state.reads;
            if let Some(actual) = state.objects.get_mut(&path) {
                match fault {
                    Some(Fault::SecondUid) if reads == 2 => {
                        actual["metadata"]["uid"] = json!(Uuid::new_v4());
                    }
                    Some(Fault::Readback(index)) if index != 7 || reads == 2 => match index {
                        0 => {
                            actual["metadata"]["annotations"]["volume.kubernetes.io/selected-node"] =
                                json!("foreign-node")
                        }
                        1 => {
                            actual["metadata"]["finalizers"] = json!(["external.example/finalizer"])
                        }
                        2 => {
                            actual["metadata"]["labels"]["foreign.example/label"] = json!("foreign")
                        }
                        3 => actual["metadata"]["unreviewed"] = json!(true),
                        4 => actual["spec"]["unreviewed"] = json!({"hostPath":"/dev"}),
                        5 => {
                            if let Some(meta) = actual["metadata"].as_object_mut() {
                                meta.remove("resourceVersion");
                            }
                        }
                        6 => {
                            if let Some(meta) = actual["metadata"].as_object_mut() {
                                meta.remove("creationTimestamp");
                            }
                        }
                        _ => {
                            actual["metadata"]["annotations"]["foreign.example/annotation"] =
                                json!("unreviewed")
                        }
                    },
                    Some(Fault::BoundWithoutParent) => {
                        actual["status"] = json!({
                            "phase":"Bound",
                            "accessModes":actual["spec"]["accessModes"],
                            "capacity":{"storage":actual["spec"]["resources"]["requests"]["storage"]}
                        });
                        actual["spec"]["volumeName"] = json!(format!(
                            "disk-{}",
                            actual["metadata"]["uid"].as_str().unwrap_or_default()
                        ));
                    }
                    Some(Fault::UnknownPhase) => actual["status"]["phase"] = json!("Lost"),
                    Some(Fault::MissingPhase) => actual["status"] = json!({}),
                    Some(Fault::SecondPhase) if reads == 2 => {
                        actual["status"]["phase"] = json!("Bound");
                    }
                    Some(Fault::Deleting) => {
                        actual["metadata"]["deletionTimestamp"] = json!(Utc::now());
                    }
                    _ => {}
                }
            }
        }
        return state.objects.get(&path).cloned().map_or_else(
            || error(StatusCode::NOT_FOUND, "NotFound"),
            |body| response(StatusCode::OK, body),
        );
    }
    if method != Method::POST
        || path != format!("/api/v1/namespaces/{NAMESPACE}/persistentvolumeclaims")
    {
        return error(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed");
    }
    let body: Value = match serde_json::from_slice(&bytes) {
        Ok(body) => body,
        Err(_) => return error(StatusCode::BAD_REQUEST, "BadRequest"),
    };
    let candidate = server_candidate(body);
    let (service, user) = {
        let Ok(mut state) = shared.lock() else {
            return error(StatusCode::INTERNAL_SERVER_ERROR, "FixtureState");
        };
        state.requests.push((method, path.clone()));
        (state.service.clone(), state.user.clone())
    };
    let Some(service) = service else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "FixtureAdmissionMissing");
    };
    let reviewed = match review(candidate.clone(), user) {
        Ok(reviewed) => reviewed,
        Err(_) => return error(StatusCode::BAD_REQUEST, "BadRequest"),
    };
    // No state lock crosses I/O: admission performs its actual GETs through this
    // same server and its real tenant-scoped database role.
    let result =
        tokio::time::timeout(Duration::from_secs(4), Box::pin(service.decide(&reviewed))).await;
    let denial = match result {
        Ok(Ok(())) => None,
        Ok(Err(denial)) => Some(denial.code),
        Err(_) => Some(503),
    };
    let Ok(mut state) = shared.lock() else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "FixtureState");
    };
    state
        .reviews
        .push((candidate.clone(), denial.unwrap_or(200)));
    if let Some(code) = denial {
        return error(
            StatusCode::from_u16(code).unwrap_or(StatusCode::FORBIDDEN),
            "AdmissionDenied",
        );
    }
    let Some(name) = candidate.pointer("/metadata/name").and_then(Value::as_str) else {
        return error(StatusCode::BAD_REQUEST, "BadRequest");
    };
    let item_path = format!("{path}/{name}");
    if state.objects.contains_key(&item_path) {
        state.conflicts += 1;
        return error(StatusCode::CONFLICT, "AlreadyExists");
    }
    let mut stored = candidate;
    stored["metadata"]["resourceVersion"] = json!("1");
    stored["status"] = json!({"phase":"Pending"});
    state.objects.insert(item_path, stored.clone());
    state.stored += 1;
    if matches!(state.fault, Some(Fault::ResponseUid)) {
        stored["metadata"]["uid"] = json!(Uuid::new_v4());
    }
    if matches!(state.fault, Some(Fault::ConflictAfterStored)) {
        state.conflicts += 1;
        return error(StatusCode::CONFLICT, "AlreadyExists");
    }
    if matches!(state.fault, Some(Fault::LostCreateAck)) {
        state.lost_acks += 1;
        return error(StatusCode::SERVICE_UNAVAILABLE, "FixtureLostAckAfterCommit");
    }
    response(StatusCode::CREATED, stored)
}

struct Fixture {
    state: Shared,
    runtime: BackupJobRuntime,
    service: RestoreAdmissionService,
    url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}
impl Fixture {
    async fn new(
        database: Database,
        cloud: &BackupCloudSettings,
        pvc: &Value,
        objects: BTreeMap<String, Value>,
    ) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let runtime = BackupJobRuntime::new(KubernetesRuntime::from_client(
            kube::Client::try_from(kube::Config::new(url.parse()?))?,
        ));
        let service = RestoreAdmissionService {
            raw_scheduling: None,
            database,
            runtime: runtime.clone(),
            identities: BackupAdmissionIdentities {
                controller: ServiceIdentity {
                    username: "system:serviceaccount:sandbox-system:sandbox-backup-controller"
                        .into(),
                    uid: Uuid::new_v4().to_string(),
                },
                job_controller: ControllerIdentity::ControlPlane {
                    username: "system:kube-controller-manager".into(),
                },
            },
            scheduler: ControllerIdentity::ControlPlane {
                username: "system:kube-scheduler".into(),
            },
            control_gc: ControllerIdentity::ControlPlane {
                username: "system:kube-controller-manager".into(),
            },
        };
        let user = json!({"username":service.identities.controller.username,"uid":service.identities.controller.uid});
        let name = pvc
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .context("raw name")?;
        let state = Arc::new(Mutex::new(State {
            objects: support_objects(cloud, objects),
            service: Some(service.clone()),
            user,
            pvc_path: format!("/api/v1/namespaces/{NAMESPACE}/persistentvolumeclaims/{name}"),
            ..State::default()
        }));
        let callback = state.clone();
        let app = Router::new().fallback(move |request| http(callback.clone(), request));
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = stopped.await;
                })
                .await
        });
        Ok(Self {
            state,
            runtime,
            service,
            url,
            shutdown: Some(shutdown),
            task: Some(task),
        })
    }
    fn edit(&self, change: impl FnOnce(&mut State)) -> anyhow::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("raw fixture state poisoned"))?;
        change(&mut state);
        Ok(())
    }
    async fn post(&self, body: &Value) -> anyhow::Result<reqwest::Response> {
        Ok(reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?
            .post(format!(
                "{}/api/v1/namespaces/{NAMESPACE}/persistentvolumeclaims",
                self.url
            ))
            .json(body)
            .send()
            .await?)
    }
    async fn finish(mut self) -> anyhow::Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let outcome = if let Some(mut task) = self.task.take() {
            match tokio::time::timeout(Duration::from_secs(3), &mut task).await {
                Ok(result) => result
                    .map_err(anyhow::Error::from)
                    .and_then(|result| result.map_err(anyhow::Error::from)),
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    Err(anyhow::anyhow!("owned raw TCP fixture failed to drain"))
                }
            }
        } else {
            Ok(())
        };
        // The separate narrow-role pool belongs to this fixture, not its
        // parent. Close it after all HTTP decisions have actually drained.
        self.service.database.pool.close().await;
        outcome
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
fn support_objects(
    cloud: &BackupCloudSettings,
    mut objects: BTreeMap<String, Value>,
) -> BTreeMap<String, Value> {
    // Typed fixed baseline consumed by verify_network's final actual GET.
    // This is a reviewed API stand-in, not proof of a real Kata host.
    let runtime_class = k8s_openapi::api::node::v1::RuntimeClass {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some("kata-backup-qemu".into()),
            uid: Some(Uuid::new_v4().to_string()),
            ..Default::default()
        },
        handler: "kata-qemu".into(),
        ..Default::default()
    };
    objects.insert(
        "/apis/node.k8s.io/v1/runtimeclasses/kata-backup-qemu".into(),
        json!(runtime_class),
    );
    let cnp = json!({"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"sandbox-backup-egress","namespace":NAMESPACE,"uid":Uuid::new_v4()},"spec":cloud.network_spec()});
    let np = json!({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"sandbox-backup-default-deny","namespace":NAMESPACE,"uid":Uuid::new_v4()},"spec":{"podSelector":{"matchExpressions":[{"key":"sandbox.platform/backup-id","operator":"Exists"}]},"policyTypes":["Ingress","Egress"]}});
    let list =
        |items: Vec<Value>| json!({"apiVersion":"v1","kind":"List","metadata":{},"items":items});
    objects.insert(
        format!(
            "/apis/cilium.io/v2/namespaces/{NAMESPACE}/ciliumnetworkpolicies/sandbox-backup-egress"
        ),
        cnp.clone(),
    );
    objects.insert(
        format!("/apis/cilium.io/v2/namespaces/{NAMESPACE}/ciliumnetworkpolicies"),
        list(vec![cnp]),
    );
    objects.insert(format!("/apis/networking.k8s.io/v1/namespaces/{NAMESPACE}/networkpolicies/sandbox-backup-default-deny"), np.clone());
    objects.insert(
        format!("/apis/networking.k8s.io/v1/namespaces/{NAMESPACE}/networkpolicies"),
        list(vec![np]),
    );
    objects.insert("/apis/cilium.io/v2/ciliumclusterwidenetworkpolicies".into(), list(vec![
        json!({"apiVersion":"cilium.io/v2","kind":"CiliumClusterwideNetworkPolicy","metadata":{"name":"sandbox-trusted-bootstrap"},"spec":{"endpointSelector":{"matchExpressions":[{"key":"k8s:io.kubernetes.pod.namespace","operator":"In","values":["kube-system","sandbox-system"]},{"key":"k8s:sandbox.platform/backup-id","operator":"DoesNotExist"}]}}}),
        json!({"apiVersion":"cilium.io/v2","kind":"CiliumClusterwideNetworkPolicy","metadata":{"name":"sandbox-host-bootstrap"},"spec":{"nodeSelector":{}}}),
    ]));
    objects.insert("/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/sandbox-runtime-protection".into(),json!({"apiVersion":"admissionregistration.k8s.io/v1","kind":"ValidatingWebhookConfiguration","metadata":{"name":"sandbox-runtime-protection"},"webhooks":[{"name":"runtime.sandbox.platform","failurePolicy":"Fail","sideEffects":"None","admissionReviewVersions":["v1"],"clientConfig":{"caBundle":"Zml4dHVyZQ==","service":{"name":"sandbox-admission","namespace":NAMESPACE,"path":"/validate","port":443}},"rules":[{"apiGroups":[""],"apiVersions":["v1"],"resources":["secrets"],"operations":["CREATE","UPDATE","DELETE"],"scope":"Namespaced"}]}]}));
    for (_, key, binding) in cloud.secret_bindings.entries() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        objects.insert(format!("/api/v1/namespaces/{NAMESPACE}/secrets/{}", binding.name),json!({"apiVersion":"v1","kind":"Secret","metadata":{"name":binding.name,"namespace":NAMESPACE,"uid":binding.uid},"immutable":true,"type":"Opaque","data":{key:STANDARD.encode(format!("test-only-backup-key-{key}"))}}));
    }
    objects
}
async fn invariants(base: &FixtureRuntime, r: &RestoreRecord) -> anyhow::Result<Value> {
    let mut tx = base.f.owner_transaction().await?;
    let snapshot: Value = sqlx::query_scalar("SELECT jsonb_build_object('source',b.source,'source_vault',to_jsonb(v),'target',jsonb_build_object('instance',i.id,'workspace',w.id,'storage_class',w.storage_class,'size_gib',w.size_gib,'desired',i.desired_state,'observed',i.observed_state,'generation',i.runtime_generation),'hold',to_jsonb(h),'hold_release',(SELECT count(*) FROM workspace_hold_releases hr WHERE hr.tenant_id=r.tenant_id AND hr.hold_id=r.hold_id),'quota',COALESCE((SELECT jsonb_agg(to_jsonb(q) ORDER BY q.id) FROM quota_reservations q WHERE q.tenant_id=r.tenant_id AND q.operation_id=r.operation_id),'[]'::jsonb)) FROM restores r JOIN backups b ON b.tenant_id=r.tenant_id AND b.id=r.backup_id JOIN backup_vault_receipts v ON v.tenant_id=b.tenant_id AND v.backup_id=b.id JOIN instances i ON i.tenant_id=r.tenant_id AND i.id=r.instance_id JOIN workspaces w ON w.tenant_id=r.tenant_id AND w.id=r.workspace_id JOIN workspace_holds h ON h.tenant_id=r.tenant_id AND h.id=r.hold_id WHERE r.tenant_id=$1 AND r.id=$2")
        .bind(r.tenant_id).bind(r.id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(snapshot)
}
async fn artifacts(base: &FixtureRuntime, r: &RestoreRecord) -> anyhow::Result<Value> {
    let mut tx = base.f.owner_transaction().await?;
    let snapshot: Value = sqlx::query_scalar("SELECT jsonb_build_object('status',r.status,'pvc_binding',(SELECT count(*) FROM restore_resource_intents i JOIN restore_resource_bindings b ON b.intent_id=i.id AND b.tenant_id=i.tenant_id WHERE i.tenant_id=r.tenant_id AND i.restore_id=r.id AND i.kind='BLOCK_PVC'),'pv_intent',(SELECT count(*) FROM restore_resource_intents i WHERE i.tenant_id=r.tenant_id AND i.restore_id=r.id AND i.kind='BLOCK_PV'),'pv_binding',(SELECT count(*) FROM restore_resource_intents i JOIN restore_resource_bindings b ON b.intent_id=i.id AND b.tenant_id=i.tenant_id WHERE i.tenant_id=r.tenant_id AND i.restore_id=r.id AND i.kind='BLOCK_PV'),'raw',(SELECT count(*) FROM restore_block_receipts x WHERE x.tenant_id=r.tenant_id AND x.restore_id=r.id),'job_context',(SELECT count(*) FROM restore_job_contexts x WHERE x.tenant_id=r.tenant_id AND x.restore_id=r.id),'permit',(SELECT count(*) FROM restore_launch_permits x WHERE x.tenant_id=r.tenant_id AND x.restore_id=r.id),'proof',(SELECT count(*) FROM restore_termination_proofs x WHERE x.tenant_id=r.tenant_id AND x.restore_id=r.id),'cleanup',(SELECT count(*) FROM restore_cleanup_receipts x WHERE x.tenant_id=r.tenant_id AND x.restore_id=r.id)) FROM restores r WHERE r.tenant_id=$1 AND r.id=$2")
        .bind(r.tenant_id).bind(r.id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(snapshot)
}
fn empty() -> Value {
    json!({"status":"BLOCK_PENDING","pvc_binding":0,"pv_intent":0,"pv_binding":0,"raw":0,"job_context":0,"permit":0,"proof":0,"cleanup":0})
}
fn mutate(body: &mut Value, index: usize) {
    match index {
        0 => body["metadata"]["labels"]["sandbox.platform/restore-id"] = json!(Uuid::new_v4()),
        1 => body["metadata"]["labels"]["sandbox.platform/tenant-id"] = json!(Uuid::new_v4()),
        2 => body["metadata"]["labels"]["sandbox.platform/project-id"] = json!(Uuid::new_v4()),
        3 => body["metadata"]["labels"]["sandbox.platform/backup-id"] = json!(Uuid::new_v4()),
        4 => body["metadata"]["labels"]["sandbox.platform/cluster-epoch"] = json!(Uuid::new_v4()),
        5 => body["metadata"]["name"] = json!("sbx-bvol-other"),
        6 => body["metadata"]["namespace"] = json!("other"),
        7 => body["spec"]["volumeMode"] = json!("Filesystem"),
        8 => body["spec"]["accessModes"] = json!(["ReadWriteMany"]),
        9 => body["spec"]["resources"]["requests"]["storage"] = json!("999Gi"),
        10 => body["spec"]["storageClassName"] = json!("unreviewed-class"),
        11 => {
            body["spec"]["dataSource"] = json!({"apiGroup":"snapshot.storage.k8s.io","kind":"VolumeSnapshot","name":"unreviewed"})
        }
        12 => body["spec"]["volumeName"] = json!("disk-external"),
        13 => {
            body["metadata"]["annotations"] =
                json!({"volume.kubernetes.io/selected-node":"unreviewed"})
        }
        14 => body["spec"]["volumeAttributesClassName"] = json!("unreviewed"),
        15 => {
            body["metadata"]["ownerReferences"] =
                json!([{"apiVersion":"v1","kind":"Pod","name":"foreign","uid":Uuid::new_v4()}])
        }
        16 => body["metadata"]["finalizers"] = json!(["external.example/finalizer"]),
        17 => {
            body["metadata"]["finalizers"] = json!([
                "kubernetes.io/pvc-protection",
                "kubernetes.io/pvc-protection"
            ])
        }
        18 => body["metadata"]["generateName"] = json!("generated-"),
        19 => body["status"] = json!({"phase":"Bound"}),
        20 => body["spec"]["unknownSource"] = json!({"hostPath":"/dev"}),
        _ => body["metadata"]["unreviewed"] = json!(true),
    }
}
pub(super) async fn verify(mut case: RawParentCase<'_>) -> anyhow::Result<()> {
    let mut tx = case.base.f.owner_transaction().await?;
    let record: RestoreRecord =
        sqlx::query_as("SELECT * FROM restores WHERE tenant_id=$1 AND id=$2")
            .bind(case.claim.tenant_id)
            .bind(case.plan.context.restore_id)
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    ensure!(
        artifacts(case.base, &record).await? == empty(),
        "initial Raw parent truly precedes Job context, binding, PV and permit"
    );
    ensure!(
        case.plan.source.cluster_epoch != record.cluster_epoch
            && record.cluster_epoch == case.plan.context.cluster_epoch,
        "actual signed historical source epoch must differ from the current restore/PVC epoch"
    );
    let before = invariants(case.base, &record).await?;
    let expected = case.plan.context.block_pvc()?;
    let database = Database::connect(&std::env::var("TEST_ADMISSION_DATABASE_URL")?, 4).await?;
    let fixture = Fixture::new(
        database,
        &case.plan.cloud,
        &expected,
        std::mem::take(&mut case.objects),
    )
    .await?;
    let outcome = Box::pin(exercise(&mut case, &record, &expected, &before, &fixture)).await;
    let closed = fixture.finish().await;
    outcome?;
    closed?;
    eprintln!(
        "VERIFIED private Raw CREATE actual narrow PG/TCP, no Job context/Bound, permit ledger remains empty (host birth denial is not exercised), historical source epoch differs from current restore, exact actual Pending UID and one immutable disk-fullUID earlyintent; source, target, quota and hold remain intact; this is not CSI/cloud certification"
    );
    Ok(())
}

// This asks the Raw-specific finite reader through the real admission role;
// the already-covered Job horizon is not a substitute for this function.
async fn raw_budget(
    service: &RestoreAdmissionService,
    r: &RestoreRecord,
) -> anyhow::Result<Option<i64>> {
    let mut tx = service
        .database
        .begin(r.tenant_id)
        .await
        .map_err(api_failure)?;
    let answer: Option<Value> =
        sqlx::query_scalar("SELECT sandbox_restore_raw_parent_admission($1,$2)")
            .bind(r.tenant_id)
            .bind(r.id)
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    answer
        .map(|value| {
            ensure!(
                value["pin"]["record"]["id"] == json!(r.id),
                "horizon must belong to this real restore"
            );
            let budget = value["valid_for_us"]
                .as_i64()
                .context("Raw finite budget")?;
            ensure!(
                (1..=10_000_000).contains(&budget),
                "Raw reader budget must remain finite and positive"
            );
            Ok(budget)
        })
        .transpose()
}
async fn raw_horizons(
    service: &RestoreAdmissionService,
    r: &RestoreRecord,
    base: &FixtureRuntime,
) -> anyhow::Result<()> {
    type SavedGrant = (Uuid, Option<Uuid>, String, Option<chrono::DateTime<Utc>>);
    let mut tx = base.f.owner_transaction().await?;
    let actor: Uuid = sqlx::query_scalar(
        "SELECT actor_principal_id FROM operations WHERE tenant_id=$1 AND id=$2",
    )
    .bind(r.tenant_id)
    .bind(r.operation_id)
    .fetch_one(&mut *tx)
    .await?;
    let saved: Vec<SavedGrant> = sqlx::query_as("SELECT id,project_id,action,expires_at FROM grants WHERE tenant_id=$1 AND principal_id=$2 AND enabled AND revoked_at IS NULL AND((project_id IS NULL AND action IN('backups:read','backups:restore','instances:create')) OR(project_id=$3 AND action IN('backups:read','backups:restore')) OR(project_id=$4 AND action='instances:create'))")
        .bind(r.tenant_id).bind(actor).bind(r.source_project_id).bind(r.target_project_id).fetch_all(&mut *tx).await?;
    let wildcard_free: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM grants WHERE tenant_id=$1 AND principal_id=$2 AND action='*' AND(project_id IS NULL OR project_id IN($3,$4)))")
        .bind(r.tenant_id).bind(actor).bind(r.source_project_id).bind(r.target_project_id).fetch_one(&mut *tx).await?;
    let required = [
        (None, "backups:read"),
        (Some(r.source_project_id), "backups:read"),
        (None, "backups:restore"),
        (Some(r.source_project_id), "backups:restore"),
        (None, "instances:create"),
        (Some(r.target_project_id), "instances:create"),
    ];
    ensure!(
        r.source_project_id != r.target_project_id
            && wildcard_free
            && saved.len() == 6
            && required.iter().all(|(project, action)| saved
                .iter()
                .filter(|row| row.1 == *project && row.2 == *action)
                .count()
                == 1),
        "isolated actor must have exactly the six required scopes, with no wildcard alternative"
    );
    let exact_source = saved
        .iter()
        .find(|row| row.1 == Some(r.source_project_id) && row.2 == "backups:restore")
        .context("source restore grant")?
        .0;
    let tenant_read = saved
        .iter()
        .find(|row| row.1.is_none() && row.2 == "backups:read")
        .context("tenant backup read grant")?;
    let source_wildcard = Uuid::new_v4();
    let target_wildcard = Uuid::new_v4();
    tx.commit().await?;
    let result = async {
        // Every scope is AND-required, not tenant OR project. A surviving source
        // read grant cannot replace source restore; target create cannot either.
        for (id, project, action, _) in &saved {
            let mut tx = base.f.owner_transaction().await?;
            sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND id=$2")
                .bind(r.tenant_id).bind(id).execute(&mut *tx).await?;
            tx.commit().await?;
            ensure!(raw_budget(service,r).await?.is_none(), "missing exact required scope {project:?}/{action} must deny Raw authority");
            let mut tx = base.f.owner_transaction().await?;
            sqlx::query("UPDATE grants SET enabled=true WHERE tenant_id=$1 AND id=$2")
                .bind(r.tenant_id).bind(id).execute(&mut *tx).await?;
            tx.commit().await?;
        }
        let mut tx = base.f.owner_transaction().await?;
        sqlx::query("UPDATE grants SET expires_at=clock_timestamp()+interval '2 seconds' WHERE tenant_id=$1 AND id=$2")
            .bind(r.tenant_id).bind(exact_source).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO grants(id,tenant_id,principal_id,project_id,action,expires_at) VALUES($1,$2,$3,$4,'*',clock_timestamp()+interval '10 minutes')")
            .bind(source_wildcard).bind(r.tenant_id).bind(actor).bind(r.source_project_id).execute(&mut *tx).await?;
        tx.commit().await?;
        ensure!(raw_budget(service,r).await?.is_some_and(|v|v>5_000_000), "MAX must use longer valid exact-source wildcard rather than shorter replaceable exact grant");
        let mut tx = base.f.owner_transaction().await?;
        sqlx::query("UPDATE grants SET expires_at=NULL WHERE tenant_id=$1 AND id=$2")
            .bind(r.tenant_id).bind(source_wildcard).execute(&mut *tx).await?;
        tx.commit().await?;
        ensure!(raw_budget(service,r).await?.is_some_and(|v|v>5_000_000), "permanent valid alternative contributes infinity before the finite resource cap");
        // An independently required tenant scope remains a MIN bound even when
        // the exact-source scope is backed by a permanent wildcard.
        let mut tx = base.f.owner_transaction().await?;
        sqlx::query("UPDATE grants SET expires_at=clock_timestamp()+interval '2 seconds' WHERE tenant_id=$1 AND id=$2")
            .bind(r.tenant_id).bind(tenant_read.0).execute(&mut *tx).await?;
        tx.commit().await?;
        ensure!(raw_budget(service,r).await?.is_some_and(|v|v>0 && v<=2_000_000), "MIN across required scopes must retain the tenant read expiry");
        let mut tx = base.f.owner_transaction().await?;
        sqlx::query("UPDATE grants SET expires_at=$3 WHERE tenant_id=$1 AND id=$2")
            .bind(r.tenant_id).bind(tenant_read.0).bind(tenant_read.3).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM grants WHERE tenant_id=$1 AND id=$2")
            .bind(r.tenant_id).bind(source_wildcard).execute(&mut *tx).await?;
        sqlx::query("UPDATE grants SET expires_at=clock_timestamp()+interval '2 seconds' WHERE tenant_id=$1 AND id=$2")
            .bind(r.tenant_id).bind(exact_source).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO grants(id,tenant_id,principal_id,project_id,action) VALUES($1,$2,$3,$4,'*')")
            .bind(target_wildcard).bind(r.tenant_id).bind(actor).bind(r.target_project_id).execute(&mut *tx).await?;
        tx.commit().await?;
        ensure!(raw_budget(service,r).await?.is_some_and(|v|v>0 && v<=2_000_000), "target wildcard cannot lengthen the exact-source restore scope");
        let mut tx = base.f.owner_transaction().await?;
        sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND id=$2")
            .bind(r.tenant_id).bind(exact_source).execute(&mut *tx).await?;
        tx.commit().await?;
        ensure!(raw_budget(service,r).await?.is_none(), "tenant grants and foreign target wildcard cannot replace a missing exact-source scope");
        anyhow::Ok(())
    }.await;
    // Reset only disposable grant setup, preserving every immutable source,
    // binding, claim and proof. Cleanup also runs when an assertion fails.
    let mut tx = base.f.owner_transaction().await?;
    sqlx::query("DELETE FROM grants WHERE tenant_id=$1 AND id IN($2,$3)")
        .bind(r.tenant_id)
        .bind(source_wildcard)
        .bind(target_wildcard)
        .execute(&mut *tx)
        .await?;
    for (id, _, _, expiry) in &saved {
        sqlx::query("UPDATE grants SET enabled=true,expires_at=$3 WHERE tenant_id=$1 AND id=$2")
            .bind(r.tenant_id)
            .bind(id)
            .bind(expiry)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    result?;
    eprintln!(
        "VERIFIED Raw-specific narrow-role finite horizon: six exact scopes AND-required; per-scope MAX finite/permanent alternatives, cross-scope MIN and foreign-scope rejection"
    );
    Ok(())
}

async fn exercise(
    case: &mut RawParentCase<'_>,
    r: &RestoreRecord,
    expected: &Value,
    before: &Value,
    fixture: &Fixture,
) -> anyhow::Result<()> {
    for index in 0..22 {
        let mut changed = expected.clone();
        mutate(&mut changed, index);
        let answer = fixture.post(&changed).await?;
        ensure!(
            answer.status() == StatusCode::FORBIDDEN,
            "actual Raw manifest case {index} must reach policy403"
        );
        ensure!(
            artifacts(case.base, r).await? == empty(),
            "denied CREATE cannot register any UID or future media"
        );
    }
    let normal_user = json!({"username":fixture.service.identities.controller.username,"uid":fixture.service.identities.controller.uid});
    for wrong in [
        json!({"username":fixture.service.identities.controller.username,"uid":Uuid::new_v4()}),
        json!({"username":"system:kube-controller-manager","uid":""}),
        json!({"username":"system:kube-scheduler","uid":""}),
        json!({"username":"system:serviceaccount:sandbox-system:sandbox-csi-controller","uid":Uuid::new_v4()}),
    ] {
        fixture.edit(|state| state.user = wrong)?;
        ensure!(
            fixture.post(expected).await?.status() == StatusCode::FORBIDDEN,
            "only exact reviewed backup controller can request Raw CREATE"
        );
    }
    fixture.edit(|state| state.user = normal_user.clone())?;
    for purpose in [
        (
            &case.plan.context.storage_contract.mapping.normal.name,
            false,
        ),
        (&case.plan.context.storage_contract.mapping.raw.name, false),
        (
            &case.plan.context.storage_contract.mapping.delivery.name,
            false,
        ),
        (
            &case.plan.context.storage_contract.mapping.snapshot.name,
            true,
        ),
    ] {
        let path = if purpose.1 {
            format!(
                "/apis/snapshot.storage.k8s.io/v1/volumesnapshotclasses/{}",
                purpose.0
            )
        } else {
            format!("/apis/storage.k8s.io/v1/storageclasses/{}", purpose.0)
        };
        let original = {
            fixture
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("raw state"))?
                .objects
                .get(&path)
                .cloned()
                .context("certified class")?
        };
        for change in 0..4 {
            let (target_gets, stored) = {
                let state = fixture
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("raw state"))?;
                (
                    state
                        .requests
                        .iter()
                        .filter(|(method, p)| *method == Method::GET && p == &path)
                        .count(),
                    state.stored,
                )
            };
            fixture.edit(|state| {
                if let Some(class) = state.objects.get_mut(&path) {
                    match change {
                        0 => class["metadata"]["uid"] = json!(Uuid::new_v4()),
                        1 => {
                            class["parameters"][if purpose.1 {
                                "snapshotTags/Deployment"
                            } else {
                                "diskTags/Deployment"
                            }] = json!("foreign-deployment")
                        }
                        2 => class["metadata"]["deletionTimestamp"] = json!(Utc::now()),
                        _ if purpose.1 => class["driver"] = json!("foreign.example/driver"),
                        _ => class["parameters"]["kmsKeyId"] = json!("foreign-key"),
                    }
                }
            })?;
            ensure!(
                fixture.post(expected).await?.status() == StatusCode::FORBIDDEN,
                "actual certified class drift must prevent CREATE"
            );
            {
                let state = fixture
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("raw state"))?;
                ensure!(
                    state
                        .requests
                        .iter()
                        .filter(|(method, p)| *method == Method::GET && p == &path)
                        .count()
                        > target_gets
                        && state.stored == stored,
                    "class drift must reach this exact actual GET without storing a CREATE; earlier dependency failure is not coverage"
                );
            }
            fixture.edit(|state| {
                state.objects.insert(path.clone(), original.clone());
            })?;
        }
    }
    ensure!(
        case.engine
            .heartbeat(&case.claim)
            .await
            .map_err(api_failure)?,
        "real live claim precedes Raw-specific horizon checks"
    );
    Box::pin(raw_horizons(&fixture.service, r, case.base)).await?;
    let candidate = server_candidate(expected.clone());
    let good_review = review(candidate, normal_user)?;
    super::admission::commit::raw_ack(&fixture.service, &good_review, r, case.base, false).await?;
    super::admission::commit::raw_ack(&fixture.service, &good_review, r, case.base, true).await?;
    super::admission::commit::raw_final_grant_ack(&fixture.service, &good_review, r, case.base)
        .await?;
    let mut tx = case.base.f.owner_transaction().await?;
    let grants: Vec<Uuid> = sqlx::query_scalar("SELECT g.id FROM grants g JOIN operations o ON o.tenant_id=g.tenant_id AND o.actor_principal_id=g.principal_id WHERE o.tenant_id=$1 AND o.id=$2 AND g.project_id=$3 AND g.action IN('backups:restore','*') AND g.enabled AND g.revoked_at IS NULL")
        .bind(r.tenant_id).bind(r.operation_id).bind(r.source_project_id).fetch_all(&mut *tx).await?;
    ensure!(
        !grants.is_empty(),
        "live source restore grant required for real revocation"
    );
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND id=ANY($2)")
        .bind(r.tenant_id)
        .bind(&grants)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    ensure!(
        fixture.post(expected).await?.status() == StatusCode::FORBIDDEN,
        "live source revocation blocks new Raw CREATE"
    );
    let mut tx = case.base.f.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=true WHERE tenant_id=$1 AND id=ANY($2)")
        .bind(r.tenant_id)
        .bind(&grants)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    {
        let state = fixture
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("raw state"))?;
        ensure!(
            state.stored == 0 && !state.objects.contains_key(&state.pvc_path),
            "all denied POSTs leave the API and durable ledger unbound"
        );
    }
    for fault in [
        Fault::SecondUid,
        Fault::BoundWithoutParent,
        Fault::UnknownPhase,
        Fault::MissingPhase,
        Fault::SecondPhase,
        Fault::Deleting,
        Fault::ResponseUid,
    ]
    .into_iter()
    .chain((0..8).map(Fault::Readback))
    {
        let stored_before = {
            let state = fixture
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("raw state"))?;
            state.stored
        };
        fixture.edit(|state| {
            state.fault = Some(fault);
            state.reads = 0;
            let path = state.pvc_path.clone();
            state.objects.remove(&path);
        })?;
        ensure!(
            Box::pin(fixture.runtime.reconcile_restore_block(
                &case.plan.context,
                &case.plan.cloud,
                None,
                None,
                &case.plan.source
            ))
            .await
            .is_err(),
            "actual Pending GET drift cannot construct typed observation"
        );
        {
            let state = fixture
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("raw state"))?;
            let expected_reads = if matches!(fault, Fault::SecondUid | Fault::SecondPhase) {
                2
            } else {
                1
            };
            let observed_reads = if matches!(fault, Fault::Readback(7)) {
                state.reads == 2
            } else if matches!(fault, Fault::Readback(_)) {
                state.reads >= 1
            } else {
                state.reads == expected_reads
            };
            ensure!(
                state.stored == stored_before + 1
                    && observed_reads
                    && state.reviews.last().is_some_and(|(_, code)| *code == 200),
                "fault {fault:?} must reach an admitted stored CREATE and its actual GET, not fail an earlier dependency"
            );
        }
        if matches!(fault, Fault::BoundWithoutParent) {
            {
                let state = fixture
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("raw state"))?;
                ensure!(
                    !state.requests.iter().any(|(method, path)| {
                        *method == Method::GET && path.starts_with("/api/v1/persistentvolumes/")
                    }),
                    "unrecorded Bound parent must be refused before any PV observation"
                );
                let live = state
                    .objects
                    .get(&state.pvc_path)
                    .context("stored Raw PVC")?;
                let uid = live["metadata"]["uid"].as_str().context("stored Raw UID")?;
                ensure!(
                    live["status"]["phase"] == json!("Bound")
                        && live["spec"]["volumeName"] == json!(format!("disk-{uid}")),
                    "deny must follow an actual Bound GET with the exact generated PV name"
                );
            }
            ensure!(
                &invariants(case.base, r).await? == before,
                "unrecorded Bound denial preserves source, target, quota and hold"
            );
        }
        ensure!(
            artifacts(case.base, r).await? == empty(),
            "failed observation cannot bind partial parent or earlyPV"
        );
    }
    for uid in [
        case.plan.source.source_pvc_uid,
        case.plan.source.clone_pvc_uid,
    ] {
        fixture.edit(|state| {
            let mut foreign = server_candidate(expected.clone());
            foreign["metadata"]["uid"] = json!(uid);
            foreign["metadata"]["resourceVersion"] = json!("1");
            foreign["status"] = json!({"phase":"Pending"});
            state.fault = None;
            state.reads = 0;
            let path = state.pvc_path.clone();
            state.objects.insert(path, foreign);
        })?;
        ensure!(
            Box::pin(fixture.runtime.reconcile_restore_block(
                &case.plan.context,
                &case.plan.cloud,
                None,
                None,
                &case.plan.source
            ))
            .await
            .is_err(),
            "actual same-name raw claim cannot adopt historical source/clone UID"
        );
        ensure!(
            artifacts(case.base, r).await? == empty(),
            "historical UID is never persisted as a new parent"
        );
    }
    let conflicts_before = {
        let state = fixture
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("raw state"))?;
        state.conflicts
    };
    fixture.edit(|state| {
        state.fault = Some(Fault::ConflictAfterStored);
        state.reads = 0;
        let path = state.pvc_path.clone();
        state.objects.remove(&path);
    })?;
    let conflicting = Box::pin(fixture.runtime.reconcile_restore_block(
        &case.plan.context,
        &case.plan.cloud,
        None,
        None,
        &case.plan.source,
    ))
    .await?;
    {
        let state = fixture
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("raw state"))?;
        ensure!(
            state.conflicts == conflicts_before + 1
                && state.reads == 2
                && state
                    .objects
                    .get(&state.pvc_path)
                    .is_some_and(|v| v["metadata"]["uid"] == json!(conflicting.pvc_uid))
                && state.reviews.last().is_some_and(|(_, code)| *code == 200),
            "actual admitted CREATE returning409 must follow two GETs of the stored winner UID"
        );
    }
    ensure!(
        conflicting.bound.is_none() && artifacts(case.base, r).await? == empty(),
        "409 recovery is Pending observation only and does not bind the ledger until normal record"
    );
    // Reset only the disposable API stand-in for the independent lost-ACK
    // scenario. This is not represented as authorized Kubernetes deletion.
    let (creates_before, posts_before, lost_acks_before, conflicts_before) = {
        let state = fixture
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("raw state"))?;
        (
            state.stored,
            state
                .requests
                .iter()
                .filter(|(m, _)| *m == Method::POST)
                .count(),
            state.lost_acks,
            state.conflicts,
        )
    };
    fixture.edit(|state| {
        state.fault = Some(Fault::LostCreateAck);
        state.reads = 0;
        let path = state.pvc_path.clone();
        state.objects.remove(&path);
    })?;
    // The locked kube-client retries this cloneable JSON POST after HTTP 503.
    // Its repeated POST receives 409 for the same stored name; only the two
    // actual GETs establish the returned Pending UID. A 503 is not an overall
    // management-call failure when the standard client resolves the conflict.
    let recovered = Box::pin(fixture.runtime.reconcile_restore_block(
        &case.plan.context,
        &case.plan.cloud,
        None,
        None,
        &case.plan.source,
    ))
    .await?;
    {
        let state = fixture
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("raw state"))?;
        ensure!(
            state.stored == creates_before + 1
                && state.lost_acks == lost_acks_before + 1
                && state.conflicts == conflicts_before + 1
                && state
                    .requests
                    .iter()
                    .filter(|(m, _)| *m == Method::POST)
                    .count()
                    == posts_before + 2
                && state.reads == 2
                && state
                    .objects
                    .get(&state.pvc_path)
                    .is_some_and(|v| v["metadata"]["uid"] == json!(recovered.pvc_uid)),
            "stored503 followed by standard POST retry409 must store once and recover the same UID with two actual GETs"
        );
    }
    ensure!(
        recovered.bound.is_none() && artifacts(case.base, r).await? == empty(),
        "503/409 recovery is Pending observation only and does not bind the ledger until normal record"
    );
    fixture.edit(|state| {
        state.fault = None;
        state.reads = 0;
    })?;
    let (creates, posts) = {
        let state = fixture
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("raw state"))?;
        (
            state.stored,
            state
                .requests
                .iter()
                .filter(|(m, _)| *m == Method::POST)
                .count(),
        )
    };
    // The next management reconciliation reads the already persisted parent;
    // it does not rename the object or create a second restore/PVC.
    let actual = Box::pin(fixture.runtime.reconcile_restore_block(
        &case.plan.context,
        &case.plan.cloud,
        None,
        None,
        &case.plan.source,
    ))
    .await?;
    ensure!(
        actual.bound.is_none() && actual.pvc_uid == recovered.pvc_uid,
        "the next management call preserves the recovered Pending UID"
    );
    {
        let state = fixture
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("raw state"))?;
        ensure!(
            state.stored == creates
                && state
                    .requests
                    .iter()
                    .filter(|(m, _)| *m == Method::POST)
                    .count()
                    == posts
                && state.reads == 2,
            "next management reconciliation observes two actual GETs without another POST"
        );
    }
    ensure!(
        artifacts(case.base, r).await? == empty(),
        "both management calls leave the Pending observation unrecorded"
    );
    let mut tx = case.base.f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND id=$2")
        .bind(r.tenant_id).bind(r.operation_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let new_claim = case
        .engine
        .claim_backup()
        .await
        .map_err(api_failure)?
        .context("same normally admitted restore must be reclaimed after lease loss")?;
    ensure!(
        new_claim.operation_id == r.operation_id && new_claim.lease_token > case.claim.lease_token,
        "normal durable claim replacement must increment fence"
    );
    ensure!(
        case.engine
            .database
            .record_restore_block(case.engine, &case.claim, &actual)
            .await
            .is_err(),
        "old claim cannot record an observed parent after claim replacement"
    );
    ensure!(
        artifacts(case.base, r).await? == empty(),
        "lost old claim leaves no partial binding or earlyintent"
    );
    case.claim = new_claim;
    case.engine
        .database
        .record_restore_block(case.engine, &case.claim, &actual)
        .await
        .map_err(api_failure)?;
    case.engine
        .database
        .record_restore_block(case.engine, &case.claim, &actual)
        .await
        .map_err(api_failure)?;
    let pending = json!({"status":"RESTORE_PENDING","pvc_binding":1,"pv_intent":1,"pv_binding":0,"raw":0,"job_context":0,"permit":0,"proof":0,"cleanup":0});
    ensure!(
        artifacts(case.base, r).await? == pending,
        "same UID replay produces exactly one parent binding/earlyintent with no future authority"
    );
    let mut tx = case.base.f.owner_transaction().await?;
    let intent: (String, String, Option<Value>) = sqlx::query_as("SELECT namespace,name,expected_object FROM restore_resource_intents WHERE tenant_id=$1 AND restore_id=$2 AND kind='BLOCK_PV'")
        .bind(r.tenant_id).bind(r.id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    ensure!(
        intent == (String::new(), format!("disk-{}", actual.pvc_uid), None),
        "earlyintent is identity-only exact canonical full PVC UID"
    );
    let original = {
        fixture
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("raw state"))?
            .objects
            .values()
            .find(|v| v.pointer("/metadata/uid") == Some(&json!(actual.pvc_uid)))
            .cloned()
            .context("persisted exact Raw parent")?
    };
    fixture.edit(|state| {
        let path = state.pvc_path.clone();
        let mut changed = original.clone();
        changed["metadata"]["uid"] = json!(Uuid::new_v4());
        state.objects.insert(path, changed);
        state.reads = 0;
    })?;
    let replacement = Box::pin(fixture.runtime.reconcile_restore_block(
        &case.plan.context,
        &case.plan.cloud,
        None,
        None,
        &case.plan.source,
    ))
    .await?;
    ensure!(
        replacement.pvc_uid != actual.pvc_uid,
        "fixture presents a real same-name replacement to a stale unbound controller plan"
    );
    ensure!(
        case.engine
            .database
            .record_restore_block(case.engine, &case.claim, &replacement)
            .await
            .is_err(),
        "real PG must refuse remapping its immutable bound parent"
    );
    ensure!(
        artifacts(case.base, r).await? == pending,
        "UID remap rejection preserves all durable parent rows"
    );
    fixture.edit(|state| {
        let path = state.pvc_path.clone();
        state.objects.insert(path, original);
        state.reads = 0;
    })?;
    ensure!(
        fixture.post(expected).await?.status() == StatusCode::FORBIDDEN,
        "later RESTORE_PENDING cannot recreate bound Raw parent"
    );
    for operation in ["UPDATE", "DELETE"] {
        let mut unsupported = good_review.clone();
        unsupported.operation = operation.into();
        unsupported.old_object = unsupported.object.clone();
        ensure!(
            fixture
                .service
                .decide(&unsupported)
                .await
                .err()
                .is_some_and(|d| d.code == 403),
            "this slice does not authorize Raw {operation}"
        );
    }
    let mut pv = good_review.clone();
    pv.resource.resource = "persistentvolumes".into();
    pv.namespace.clear();
    ensure!(
        fixture
            .service
            .decide(&pv)
            .await
            .err()
            .is_some_and(|d| d.code == 403),
        "an earlyintent alone cannot authorize CSI PV CREATE"
    );
    let job = case
        .engine
        .database
        .prepare_restore_job(case.engine, &case.claim)
        .await
        .map_err(api_failure)?;
    ensure!(
        job.known_job.is_none() && job.known_pod.is_none(),
        "normal Job preparation does not pretend objects/VM exist"
    );
    let final_rows = artifacts(case.base, r).await?;
    let mut job_expected = pending.clone();
    job_expected["job_context"] = json!(1);
    ensure!(
        final_rows == job_expected,
        "normal prepareJob only adds context, no media receipt or permit"
    );
    ensure!(
        &invariants(case.base, r).await? == before,
        "original source, target identity, quota and unreleased hold are unchanged"
    );
    ensure!(
        before["hold_release"] == json!(0)
            && before["quota"]
                .as_array()
                .is_some_and(|q| !q.is_empty() && q.iter().all(|r| r["status"] != "RELEASED")),
        "proofless path retains every reservation/hold"
    );
    fixture.edit(|state| {
        assert!(state.reviews.iter().any(|(v, code)| *code == 200
            && v.pointer("/metadata/uid").is_some()
            && v.pointer("/metadata/creationTimestamp").is_some()
            && v.pointer("/metadata/finalizers")
                == Some(&json!(["kubernetes.io/pvc-protection"]))));
    })?;
    Ok(())
}
