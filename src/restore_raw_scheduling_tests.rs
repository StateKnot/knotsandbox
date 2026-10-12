//! PRIVATE actual PG + stateful TCP candidate. All cloud/Kubernetes endpoints
//! are public test stand-ins; this does not certify a deployed CSI installation.
use super::super::{admission, grants};
use super::{
    ACCESS, ACCOUNT, CloudFixture, KubeFixture, ROLE_ID, SECRET, Server, TOKEN, canonical_sha,
    enrollment_plan, insert_profile, terraform,
};
use crate::{
    admission::{AdmissionRequest, ControllerIdentity, ServiceIdentity},
    backup_admission::BackupAdmissionIdentities,
    backup_job::{BackupCloudSettings, BackupJobRuntime},
    backup_ledger::pipeline_tests::vault::completed_source,
    backup_manifest::{NAMESPACE, block_pvc_name, config_name},
    cloud_fencing::{
        admission_node_topology::AlibabaCloudAdmissionNodeTopology,
        node_topology::{NodeTopologyCloudBinding, NodeTopologyCloudConfig, verify_test_request},
    },
    db::Database,
    model::Flavor,
    node_enrollment::enroll_with_client_test,
    nodeguard::protocol::{BackupStage, backup_job_name},
    restore::{
        CreateRestore,
        admission::{RawSchedulingRuntime, RestoreAdmissionService},
        ledger::JobPlan,
        node_topology_owner::{NodeTopologyRequest, collect_with_client, record_node_topology},
    },
    runtime::KubernetesRuntime,
    termination_client::test_support::{FixtureGuard, node},
    test_support_db::{self, api_failure},
};
use anyhow::{Context, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Method, Request, Response, StatusCode},
    routing::any,
};
use chrono::{Duration as Days, SecondsFormat, Utc};
use serde_json::{Value, json};
use sqlx::Connection;
use std::{
    collections::BTreeMap,
    io::Write,
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;

#[path = "restore_raw_bound_authority_tests.rs"]
mod bound_authority;
#[path = "restore_raw_scheduling_boundary_tests.rs"]
mod boundary;
#[path = "restore_raw_scheduling_identity_tests.rs"]
mod identity;

const SELECTED: &str = "volume.kubernetes.io/selected-node";
const STABLE: &str = "volume.kubernetes.io/storage-provisioner";
const BETA: &str = "volume.beta.kubernetes.io/storage-provisioner";
const DRIVER: &str = "diskplugin.csi.alibabacloud.com";
const ADMISSION_SUBJECT: &str = "system:serviceaccount:sandbox-system:sandbox-admission";
const ADMISSION_OIDC: &str = "PUBLIC_SELECTED_ADMISSION_OIDC_ONLY";

fn answer(code: StatusCode, value: Value) -> Response<Body> {
    let mut r = Response::new(Body::from(value.to_string()));
    *r.status_mut() = code;
    r.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    r
}
fn failure(code: StatusCode) -> Response<Body> {
    answer(
        code,
        json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"FixtureFailure","code":code.as_u16()}),
    )
}
fn user(service: &RestoreAdmissionService) -> Value {
    json!({"username":service.identities.controller.username,"uid":service.identities.controller.uid})
}
fn control_user() -> Value {
    json!({"username":"system:kube-controller-manager","uid":"","groups":["system:authenticated"]})
}
fn scheduler_user() -> Value {
    json!({"username":"system:kube-scheduler","uid":"","groups":["system:authenticated"]})
}
fn service(database: Database, runtime: BackupJobRuntime) -> RestoreAdmissionService {
    RestoreAdmissionService {
        database,
        runtime,
        scheduler: ControllerIdentity::ControlPlane {
            username: "system:kube-scheduler".into(),
        },
        control_gc: ControllerIdentity::ControlPlane {
            username: "system:kube-controller-manager".into(),
        },
        identities: BackupAdmissionIdentities {
            controller: ServiceIdentity {
                username: "system:serviceaccount:sandbox-system:sandbox-backup-controller".into(),
                uid: Uuid::new_v4().to_string(),
            },
            job_controller: ControllerIdentity::ControlPlane {
                username: "system:kube-controller-manager".into(),
            },
        },
        raw_scheduling: None,
    }
}
fn review(
    object: Value,
    old: Option<Value>,
    resource: &str,
    operation: &str,
    username: Value,
) -> anyhow::Result<AdmissionRequest> {
    Ok(serde_json::from_value(
        json!({"uid":Uuid::new_v4(),"resource":{"group":if resource=="jobs"{"batch"}else{""},"version":"v1","resource":resource},"namespace":NAMESPACE,"name":object["metadata"]["name"],"operation":operation,"object":object,"oldObject":old,"userInfo":username}),
    )?)
}

#[derive(Clone, Copy, Debug)]
enum Fault {
    None,
    PodAssigned,
    PodTerminated,
    SecondPodUid,
    DuplicatePod,
    ContinuedPodList,
    SecondPvcUid,
    ConfigSource,
    JobOwner,
    SecondNodeUid,
    SecondCsiUid,
    ExistingPv,
    FirstPvcBound,
    SecondPvcBound,
    SecondExistingPv,
    SecondChangedPv,
}
// Single read-side barrier only. It carries no admission/database authority.
// The request count is committed before the wait; no std Mutex guard is held.
struct ReadPause {
    path: String,
    hit: usize,
    arrived: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}
struct WorkloadState {
    objects: Arc<Mutex<BTreeMap<String, Value>>>,
    service: Option<RestoreAdmissionService>,
    fault: Fault,
    requests: Vec<(Method, String)>,
    reads: BTreeMap<String, usize>,
    raw_read_responses: Vec<(String, u16, Option<String>, Option<String>)>,
    pv_read_responses: Vec<u16>,
    read_pause: Option<Arc<ReadPause>>,
    decisions: Vec<(String, u16)>,
    decision_messages: Vec<(u16, &'static str)>,
    stored: Vec<String>,
    job_uid: Option<Uuid>,
    callers: BTreeMap<String, Value>,
    revision: u64,
    violations: Vec<&'static str>,
}
type Shared = Arc<Mutex<WorkloadState>>;
async fn workload_http(State(shared): State<Shared>, request: Request<Body>) -> Response<Body> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let purpose = request
        .headers()
        .get("x-public-fixture-caller")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let pairs: Vec<(String, String)> =
        url::form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
            .into_owned()
            .collect();
    let query: BTreeMap<String, String> = pairs.iter().cloned().collect();
    if pairs.len() != query.len() {
        if let Ok(mut s) = shared.lock() {
            s.violations.push("duplicate query key")
        }
        return failure(StatusCode::BAD_REQUEST);
    }
    let (objects, service, fault, reading, job_uid, pause) = {
        let Ok(mut s) = shared.lock() else {
            return failure(StatusCode::INTERNAL_SERVER_ERROR);
        };
        s.requests.push((method.clone(), path.clone()));
        let reading = if method == Method::GET {
            *s.reads.entry(path.clone()).or_default() += 1;
            s.reads.get(&path).copied().unwrap_or_default()
        } else {
            0
        };
        (
            s.objects.clone(),
            s.service.clone(),
            s.fault,
            reading,
            s.job_uid,
            s.read_pause.clone(),
        )
    };
    let expected = match path.as_str() {
        "/apis/cilium.io/v2/namespaces/sandbox-system/ciliumnetworkpolicies"
        | "/apis/networking.k8s.io/v1/namespaces/sandbox-system/networkpolicies" => {
            Some(BTreeMap::from([("limit".into(), "2".into())]))
        }
        "/apis/cilium.io/v2/ciliumclusterwidenetworkpolicies" => {
            Some(BTreeMap::from([("limit".into(), "4".into())]))
        }
        "/api/v1/namespaces/kube-system/pods" => {
            if query.get("labelSelector").map(String::as_str) == Some("app=csi-provisioner") {
                Some(BTreeMap::from([
                    ("labelSelector".into(), "app=csi-provisioner".into()),
                    ("limit".into(), "4".into()),
                ]))
            } else {
                let node_name = objects.lock().ok().and_then(|map| {
                    map.get("selected-plugin-list")
                        .and_then(|list| list.pointer("/items/0/spec/nodeName"))
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                });
                node_name.map(|node| {
                    BTreeMap::from([
                        ("labelSelector".into(), "app=csi-plugin".into()),
                        ("fieldSelector".into(), format!("spec.nodeName={node}")),
                        ("limit".into(), "2".into()),
                    ])
                })
            }
        }
        "/api/v1/namespaces/sandbox-system/pods" => job_uid.map(|id| {
            BTreeMap::from([
                ("limit".into(), "2".into()),
                (
                    "labelSelector".into(),
                    format!("batch.kubernetes.io/controller-uid={id}"),
                ),
            ])
        }),
        _ => None,
    };
    if method == Method::GET && expected.as_ref().map_or(!query.is_empty(), |e| e != &query)
        || method != Method::GET && !query.is_empty()
    {
        if let Ok(mut s) = shared.lock() {
            s.violations.push("unexpected query")
        }
        return failure(StatusCode::BAD_REQUEST);
    }
    if method == Method::GET {
        if let Some(pause) = pause.filter(|p| p.path == path && p.hit == reading) {
            pause.arrived.notify_one();
            pause.resume.notified().await;
        }
        let Ok(map) = objects.lock() else {
            return failure(StatusCode::INTERNAL_SERVER_ERROR);
        };
        let mut body = if path == "/api/v1/namespaces/kube-system/pods" {
            let key =
                if query.get("labelSelector").map(String::as_str) == Some("app=csi-provisioner") {
                    "controller-list"
                } else {
                    "selected-plugin-list"
                };
            let Some(list) = map.get(key) else {
                return failure(StatusCode::NOT_FOUND);
            };
            list.clone()
        } else if path == "/api/v1/namespaces/sandbox-system/pods" {
            let items: Vec<Value> = map
                .iter()
                .filter(|(p, _)| p.starts_with("/api/v1/namespaces/sandbox-system/pods/"))
                .map(|(_, v)| v.clone())
                .collect();
            json!({"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"401"},"items":items})
        } else if path.starts_with("/api/v1/persistentvolumes/disk-")
            && (matches!(fault, Fault::ExistingPv)
                || reading == 2
                    && matches!(fault, Fault::SecondExistingPv | Fault::SecondChangedPv))
        {
            let uid = if matches!(fault, Fault::SecondChangedPv) {
                "22222222-2222-4222-8222-222222222222"
            } else {
                "11111111-1111-4111-8111-111111111111"
            };
            // This is an actual live GET observation only, never a recorded
            // PV binding, raw receipt, launch permit or media absence proof.
            json!({"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":path.rsplit('/').next(),"uid":uid,"resourceVersion":"999"},"spec":{"accessModes":["ReadWriteOnce"],"capacity":{"storage":"4Gi"},"persistentVolumeReclaimPolicy":"Retain","volumeMode":"Block","csi":{"driver":DRIVER,"volumeHandle":if matches!(fault,Fault::SecondChangedPv){"d-public-foreign-observation"}else{"d-public-reset-observation"}}}})
        } else {
            let Some(v) = map.get(&path) else {
                drop(map);
                if path.starts_with("/api/v1/namespaces/sandbox-system/persistentvolumeclaims/")
                    || path.starts_with("/api/v1/persistentvolumes/disk-")
                {
                    let Ok(mut s) = shared.lock() else {
                        return failure(StatusCode::INTERNAL_SERVER_ERROR);
                    };
                    if path.starts_with("/api/v1/persistentvolumes/disk-") {
                        s.pv_read_responses.push(404);
                    } else {
                        s.raw_read_responses.push((path.clone(), 404, None, None));
                    }
                }
                return failure(StatusCode::NOT_FOUND);
            };
            v.clone()
        };
        if path.starts_with("/api/v1/namespaces/sandbox-system/pods/") {
            match fault {
                Fault::PodAssigned => body["spec"]["nodeName"] = json!("already-assigned"),
                Fault::PodTerminated => body["status"]["phase"] = json!("Succeeded"),
                Fault::SecondPodUid if reading == 2 => {
                    body["metadata"]["uid"] = json!(Uuid::new_v4())
                }
                _ => {}
            }
        } else if path == "/api/v1/namespaces/sandbox-system/pods" {
            match fault {
                Fault::DuplicatePod => {
                    let item = body["items"][0].clone();
                    if let Some(v) = body["items"].as_array_mut() {
                        v.push(item);
                    }
                }
                Fault::ContinuedPodList => body["metadata"]["continue"] = json!("more-items"),
                _ => {}
            }
        } else if path.starts_with("/api/v1/namespaces/sandbox-system/persistentvolumeclaims/")
            && ((matches!(fault, Fault::FirstPvcBound) && reading == 1)
                || (matches!(fault, Fault::SecondPvcBound) && reading == 2))
        {
            body["spec"]["volumeName"] = json!(format!(
                "disk-{}",
                body["metadata"]["uid"].as_str().unwrap_or_default()
            ));
            body["status"]["phase"] = json!("Bound");
        } else if path.starts_with("/api/v1/namespaces/sandbox-system/persistentvolumeclaims/")
            && matches!(fault, Fault::SecondPvcUid)
            && reading == 2
        {
            body["metadata"]["uid"] = json!(Uuid::new_v4());
        } else if path.starts_with("/api/v1/namespaces/sandbox-system/configmaps/")
            && matches!(fault, Fault::ConfigSource)
        {
            body["data"]["job.json"] = json!("{\"foreign_source\":true}");
        } else if path.starts_with("/apis/batch/v1/namespaces/sandbox-system/jobs/")
            && matches!(fault, Fault::JobOwner)
        {
            body["spec"]["template"]["metadata"]["labels"]["controller-uid"] =
                json!(Uuid::new_v4());
        } else if reading == 2
            && ((path.starts_with("/api/v1/nodes/") && matches!(fault, Fault::SecondNodeUid))
                || (path.starts_with("/apis/storage.k8s.io/v1/csinodes/")
                    && matches!(fault, Fault::SecondCsiUid)))
        {
            body["metadata"]["uid"] = json!(Uuid::new_v4());
        }
        drop(map);
        if path.starts_with("/api/v1/namespaces/sandbox-system/persistentvolumeclaims/") {
            let Ok(mut s) = shared.lock() else {
                return failure(StatusCode::INTERNAL_SERVER_ERROR);
            };
            s.raw_read_responses.push((
                path.clone(),
                200,
                body.pointer("/metadata/uid")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                body.pointer("/status/phase")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            ));
        }
        if path.starts_with("/api/v1/persistentvolumes/disk-") {
            let Ok(mut s) = shared.lock() else {
                return failure(StatusCode::INTERNAL_SERVER_ERROR);
            };
            s.pv_read_responses.push(200);
        }
        return answer(StatusCode::OK, body);
    }
    let Some(service) = service else {
        return failure(StatusCode::SERVICE_UNAVAILABLE);
    };
    let bytes = match to_bytes(request.into_body(), 131_072).await {
        Ok(v) => v,
        Err(_) => return failure(StatusCode::BAD_REQUEST),
    };
    let body: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return failure(StatusCode::BAD_REQUEST),
    };
    let (resource, operation, old, candidate, caller) = if method == Method::POST
        && path == "/api/v1/namespaces/sandbox-system/persistentvolumeclaims"
    {
        let mut candidate = body;
        candidate["metadata"]["uid"] = json!(Uuid::new_v4());
        candidate["metadata"]["creationTimestamp"] =
            json!(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));
        candidate["metadata"]["finalizers"] = json!(["kubernetes.io/pvc-protection"]);
        candidate["status"] = json!({});
        (
            "persistentvolumeclaims",
            "CREATE",
            None,
            candidate,
            user(&service),
        )
    } else if method == Method::POST && path == "/api/v1/namespaces/sandbox-system/pods" {
        let mut candidate = body;
        candidate["metadata"]["uid"] = json!(Uuid::new_v4());
        candidate["metadata"]["creationTimestamp"] =
            json!(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));
        // The pinned apiserver strategy runs before validating admission. This
        // fixture renders one approved Restore container with unequal CPU and
        // memory requests/limits, so its derived QoS is exactly Burstable.
        if candidate
            .pointer("/spec/containers")
            .and_then(Value::as_array)
            .is_none_or(|v| v.len() != 1)
            || candidate.pointer("/spec/resources").is_some()
            || candidate
                .pointer("/spec/initContainers")
                .is_some_and(|v| v.as_array().is_none_or(|v| !v.is_empty()))
            || candidate
                .pointer("/spec/schedulingGates")
                .is_some_and(|v| v.as_array().is_none_or(|v| !v.is_empty()))
            || candidate.pointer("/spec/containers/0/resources/requests/cpu") != Some(&json!("1"))
            || candidate.pointer("/spec/containers/0/resources/limits/cpu") != Some(&json!("2"))
            || candidate.pointer("/spec/containers/0/resources/requests/memory")
                != Some(&json!("1Gi"))
            || candidate.pointer("/spec/containers/0/resources/limits/memory")
                != Some(&json!("2Gi"))
        {
            if let Ok(mut s) = shared.lock() {
                s.violations.push("controlled Pod QoS fixture contract")
            }
            return failure(StatusCode::BAD_REQUEST);
        }
        candidate["metadata"]["generation"] = json!(1);
        candidate["status"] = json!({"phase":"Pending","qosClass":"Burstable"});
        ("pods", "CREATE", None, candidate, control_user())
    } else if method == Method::PUT
        && path.starts_with("/api/v1/namespaces/sandbox-system/persistentvolumeclaims/")
    {
        let old = {
            let Ok(m) = objects.lock() else {
                return failure(StatusCode::INTERNAL_SERVER_ERROR);
            };
            let Some(v) = m.get(&path) else {
                return failure(StatusCode::NOT_FOUND);
            };
            v.clone()
        };
        let caller = {
            let Ok(s) = shared.lock() else {
                return failure(StatusCode::INTERNAL_SERVER_ERROR);
            };
            let Some(c) = purpose.as_ref().and_then(|p| s.callers.get(p)) else {
                return failure(StatusCode::FORBIDDEN);
            };
            c.clone()
        };
        ("persistentvolumeclaims", "UPDATE", Some(old), body, caller)
    } else if method == Method::PATCH
        && path.starts_with("/apis/batch/v1/namespaces/sandbox-system/jobs/")
    {
        let old = {
            let Ok(m) = objects.lock() else {
                return failure(StatusCode::INTERNAL_SERVER_ERROR);
            };
            let Some(v) = m.get(&path) else {
                return failure(StatusCode::NOT_FOUND);
            };
            v.clone()
        };
        if body
            != json!({"metadata":{"uid":old["metadata"]["uid"],"resourceVersion":old["metadata"]["resourceVersion"]},"spec":{"suspend":false}})
        {
            return failure(StatusCode::BAD_REQUEST);
        }
        let mut candidate = old.clone();
        candidate["spec"]["suspend"] = json!(false);
        candidate["metadata"]["generation"] = json!(2);
        ("jobs", "UPDATE", Some(old), candidate, user(&service))
    } else {
        if let Ok(mut s) = shared.lock() {
            s.violations.push("unknown mutable route")
        }
        return failure(StatusCode::METHOD_NOT_ALLOWED);
    };
    let r = match review(candidate, old, resource, operation, caller) {
        Ok(r) => r,
        Err(_) => return failure(StatusCode::BAD_REQUEST),
    };
    let (code, message) =
        match tokio::time::timeout(Duration::from_secs(4), Box::pin(service.decide(&r))).await {
            Ok(Ok(())) => (200, "ALLOW"),
            Ok(Err(e)) => (e.code, e.message),
            Err(_) => (503, "FixtureAdmissionTimeout"),
        };
    if let Ok(mut s) = shared.lock() {
        s.decisions.push((resource.into(), code));
        s.decision_messages.push((code, message));
    }
    if code != 200 {
        return failure(StatusCode::from_u16(code).unwrap_or(StatusCode::FORBIDDEN));
    }
    let mut stored = r.object.unwrap_or(Value::Null);
    let revision = {
        let Ok(mut state) = shared.lock() else {
            return failure(StatusCode::INTERNAL_SERVER_ERROR);
        };
        state.revision += 1;
        state.revision.to_string()
    };
    stored["metadata"]["resourceVersion"] = json!(revision);
    if resource == "persistentvolumeclaims" {
        stored["status"] = json!({"phase":"Pending"})
    }
    let object_path = if operation == "UPDATE" {
        path
    } else {
        format!(
            "{path}/{}",
            stored["metadata"]["name"].as_str().unwrap_or_default()
        )
    };
    {
        let Ok(mut map) = objects.lock() else {
            return failure(StatusCode::INTERNAL_SERVER_ERROR);
        };
        if operation == "CREATE" && map.contains_key(&object_path) {
            return failure(StatusCode::CONFLICT);
        }
        map.insert(object_path.clone(), stored.clone());
    }
    if let Ok(mut s) = shared.lock() {
        s.stored.push(object_path);
    }
    answer(
        if operation == "CREATE" {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        stored,
    )
}

struct Workload {
    shared: Shared,
    objects: Arc<Mutex<BTreeMap<String, Value>>>,
    runtime: BackupJobRuntime,
    server: Server,
}
impl Workload {
    async fn start(objects: BTreeMap<String, Value>) -> anyhow::Result<Self> {
        let objects = Arc::new(Mutex::new(objects));
        let shared = Arc::new(Mutex::new(WorkloadState {
            objects: objects.clone(),
            service: None,
            fault: Fault::None,
            requests: vec![],
            reads: BTreeMap::new(),
            raw_read_responses: vec![],
            pv_read_responses: vec![],
            read_pause: None,
            decisions: vec![],
            decision_messages: vec![],
            stored: vec![],
            job_uid: None,
            callers: BTreeMap::new(),
            revision: 200,
            violations: vec![],
        }));
        let server = Server::start(
            Router::new()
                .fallback(any(workload_http))
                .with_state(shared.clone()),
        )
        .await?;
        let runtime = BackupJobRuntime::new(KubernetesRuntime::from_client(
            kube::Client::try_from(kube::Config::new(server.url.as_str().parse()?))?,
        ));
        Ok(Self {
            shared,
            objects,
            runtime,
            server,
        })
    }
    fn install(&self, service: RestoreAdmissionService, job: Option<Uuid>) -> anyhow::Result<()> {
        let mut s = self
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("workload state"))?;
        s.service = Some(service);
        s.job_uid = job;
        Ok(())
    }
    fn reset(&self, fault: Fault) -> anyhow::Result<()> {
        let mut s = self
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("workload state"))?;
        s.fault = fault;
        s.reads.clear();
        s.raw_read_responses.clear();
        s.pv_read_responses.clear();
        s.read_pause = None;
        s.decision_messages.clear();
        s.requests.clear();
        Ok(())
    }
    fn get(&self, path: &str) -> anyhow::Result<Value> {
        self.objects
            .lock()
            .map_err(|_| anyhow::anyhow!("workload objects"))?
            .get(path)
            .cloned()
            .context("actual stored object")
    }
    fn reads(&self, path: &str) -> anyhow::Result<usize> {
        Ok(self
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("workload state"))?
            .reads
            .get(path)
            .copied()
            .unwrap_or_default())
    }
    async fn finish(self) -> anyhow::Result<()> {
        self.server.finish().await?;
        ensure!(
            self.shared
                .lock()
                .map_err(|_| anyhow::anyhow!("workload state"))?
                .violations
                .is_empty(),
            "workload protocol mismatch"
        );
        Ok(())
    }
}

fn support(
    cloud: &BackupCloudSettings,
    mut map: BTreeMap<String, Value>,
) -> BTreeMap<String, Value> {
    let cnp = json!({"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"sandbox-backup-egress","namespace":NAMESPACE,"uid":Uuid::new_v4()},"spec":cloud.network_spec()});
    let np = json!({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"sandbox-backup-default-deny","namespace":NAMESPACE,"uid":Uuid::new_v4()},"spec":{"podSelector":{"matchExpressions":[{"key":"sandbox.platform/backup-id","operator":"Exists"}]},"policyTypes":["Ingress","Egress"]}});
    let list = |v: Vec<Value>| json!({"apiVersion":"v1","kind":"List","metadata":{},"items":v});
    map.insert(
        format!(
            "/apis/cilium.io/v2/namespaces/{NAMESPACE}/ciliumnetworkpolicies/sandbox-backup-egress"
        ),
        cnp.clone(),
    );
    map.insert(
        format!("/apis/cilium.io/v2/namespaces/{NAMESPACE}/ciliumnetworkpolicies"),
        list(vec![cnp]),
    );
    map.insert(format!("/apis/networking.k8s.io/v1/namespaces/{NAMESPACE}/networkpolicies/sandbox-backup-default-deny"),np.clone());
    map.insert(
        format!("/apis/networking.k8s.io/v1/namespaces/{NAMESPACE}/networkpolicies"),
        list(vec![np]),
    );
    map.insert("/apis/cilium.io/v2/ciliumclusterwidenetworkpolicies".into(),list(vec![json!({"apiVersion":"cilium.io/v2","kind":"CiliumClusterwideNetworkPolicy","metadata":{"name":"sandbox-trusted-bootstrap"},"spec":{"endpointSelector":{"matchExpressions":[{"key":"k8s:io.kubernetes.pod.namespace","operator":"In","values":["kube-system","sandbox-system"]},{"key":"k8s:sandbox.platform/backup-id","operator":"DoesNotExist"}]}}}),json!({"apiVersion":"cilium.io/v2","kind":"CiliumClusterwideNetworkPolicy","metadata":{"name":"sandbox-host-bootstrap"},"spec":{"nodeSelector":{}}})]));
    map.insert("/apis/node.k8s.io/v1/runtimeclasses/kata-backup-qemu".into(),json!({"apiVersion":"node.k8s.io/v1","kind":"RuntimeClass","metadata":{"name":"kata-backup-qemu"},"handler":"kata-qemu"}));
    map.insert("/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/sandbox-runtime-protection".into(),json!({"apiVersion":"admissionregistration.k8s.io/v1","kind":"ValidatingWebhookConfiguration","metadata":{"name":"sandbox-runtime-protection"},"webhooks":[{"name":"runtime.sandbox.platform","failurePolicy":"Fail","sideEffects":"None","admissionReviewVersions":["v1"],"clientConfig":{"caBundle":"Zml4dHVyZQ==","service":{"name":"sandbox-admission","namespace":NAMESPACE,"path":"/validate","port":443}},"rules":[{"apiGroups":[""],"apiVersions":["v1"],"resources":["secrets"],"operations":["CREATE","UPDATE","DELETE"],"scope":"Namespaced"}]}]}));
    for (_, key, binding) in cloud.secret_bindings.entries() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        map.insert(format!("/api/v1/namespaces/{NAMESPACE}/secrets/{}",binding.name),json!({"apiVersion":"v1","kind":"Secret","metadata":{"name":binding.name,"namespace":NAMESPACE,"uid":binding.uid},"immutable":true,"type":"Opaque","data":{key:STANDARD.encode(format!("test-only-backup-key-{key}"))}}));
    }
    map
}

#[derive(Default)]
struct AdmissionCloudState {
    actions: Vec<String>,
    responses: Vec<(&'static str, u16, &'static str)>,
    session: String,
    mode: u8,
    violations: Vec<&'static str>,
}
#[derive(Clone)]
struct AdmissionCloudRoutes {
    shared: Arc<Mutex<AdmissionCloudState>>,
    binding: NodeTopologyCloudBinding,
}
fn cloud_action_name(action: &str) -> &'static str {
    match action {
        "AssumeRoleWithOIDC" => "AssumeRoleWithOIDC",
        "GetCallerIdentity" => "GetCallerIdentity",
        "DescribeInstances" => "DescribeInstances",
        _ => "UNAPPROVED_ACTION",
    }
}
fn cloud_failure(
    state: &mut AdmissionCloudState,
    action: &str,
    code: StatusCode,
    reason: &'static str,
) -> Response<Body> {
    state
        .responses
        .push((cloud_action_name(action), code.as_u16(), reason));
    failure(code)
}
async fn cloud_http(
    State(routes): State<AdmissionCloudRoutes>,
    r: Request<Body>,
) -> Response<Body> {
    let pairs: Vec<(String, String)> =
        url::form_urlencoded::parse(r.uri().query().unwrap_or_default().as_bytes())
            .into_owned()
            .collect();
    let q: BTreeMap<String, String> = pairs.iter().cloned().collect();
    let action = r
        .headers()
        .get("x-acs-action")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let Ok(mut s) = routes.shared.lock() else {
        return failure(StatusCode::INTERNAL_SERVER_ERROR);
    };
    s.actions.push(action.clone());
    if pairs.len() != q.len() || r.method() != Method::POST || r.uri().path() != "/" {
        s.violations.push("cloud route/query");
        return cloud_failure(&mut s, &action, StatusCode::BAD_REQUEST, "ROUTE_QUERY");
    }
    if action != "AssumeRoleWithOIDC"
        && (!verify_test_request(
            r.headers(),
            r.uri().query().unwrap_or_default(),
            ACCESS,
            SECRET,
        ) || r
            .headers()
            .get("x-acs-security-token")
            .and_then(|v| v.to_str().ok())
            != Some(TOKEN))
    {
        s.violations.push("signed admission request");
        return cloud_failure(&mut s, &action, StatusCode::FORBIDDEN, "SIGNATURE_TOKEN");
    }
    let b = &routes.binding;
    let id = "public-admission-readonly/selected:2026";
    let v = match action.as_str() {
        "AssumeRoleWithOIDC" => {
            let policy = json!({"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:DescribeInstances"],"Resource":[format!("acs:ecs:{}:{}:instance/{}",b.region,b.account_id,b.instance_id)]},{"Effect":"Allow","Action":["sts:GetCallerIdentity"],"Resource":["*"]}]});
            let expected: BTreeMap<String, String> = BTreeMap::from([
                (
                    "RoleArn".into(),
                    format!("acs:ram::{ACCOUNT}:role/admission-readonly"),
                ),
                (
                    "OIDCProviderArn".into(),
                    format!("acs:ram::{ACCOUNT}:oidc-provider/fixture"),
                ),
                ("OIDCToken".into(), ADMISSION_OIDC.into()),
                ("DurationSeconds".into(), "900".into()),
                // The production anonymous STS transport supplies these exact
                // official RPC common parameters before canonical encoding.
                ("Action".into(), "AssumeRoleWithOIDC".into()),
                ("Version".into(), "2015-04-01".into()),
                ("Format".into(), "JSON".into()),
            ]);
            if r.headers().contains_key("authorization")
                || q.len() != expected.len() + 2
                || q.get("Policy")
                    .and_then(|v| serde_json::from_str::<Value>(v).ok())
                    != Some(policy)
                || expected.iter().any(|(k, v)| q.get(k) != Some(v))
                || q.get("RoleSessionName").is_none_or(|s| s.is_empty())
                || r.headers()
                    .get("x-acs-version")
                    .and_then(|v| v.to_str().ok())
                    != Some("2015-04-01")
            {
                s.violations
                    .push("admission exact OIDC role/provider/policy/version");
                return cloud_failure(
                    &mut s,
                    &action,
                    StatusCode::BAD_REQUEST,
                    "EXACT_OIDC_PROTOCOL",
                );
            }
            s.session = q["RoleSessionName"].clone();
            json!({"RequestId":id,"AssumedRoleUser":{"Arn":format!("acs:ram::{ACCOUNT}:role/admission-readonly/{}",s.session),"AssumedRoleId":"PUBLIC_SELECTED:session"},"OIDCTokenInfo":{"Issuer":"https://issuer.fixture.invalid","Subject":if s.mode==1{"system:serviceaccount:sandbox-system:sandbox-node-topology-owner"}else{ADMISSION_SUBJECT},"ClientIds":"sts.aliyuncs.com","VerificationInfo":"Success","ExpirationTime":Utc::now()+Days::seconds(600),"IssuanceTime":Utc::now()-Days::seconds(10)},"Credentials":{"AccessKeyId":ACCESS,"AccessKeySecret":SECRET,"SecurityToken":TOKEN,"Expiration":Utc::now()+Days::seconds(900)}})
        }
        "GetCallerIdentity" => {
            json!({"RequestId":id,"AccountId":if s.mode==2{"9999999999999999"}else{ACCOUNT},"IdentityType":"AssumedRoleUser","Arn":format!("acs:ram::{ACCOUNT}:role/admission-readonly/{}",s.session),"RoleId":ROLE_ID,"PrincipalId":"PUBLIC_SELECTED"})
        }
        "DescribeInstances" => {
            if q != BTreeMap::from([
                ("RegionId".into(), b.region.clone()),
                ("InstanceIds".into(), format!("[\"{}\"]", b.instance_id)),
                ("MaxResults".into(), "10".into()),
            ]) || r
                .headers()
                .get("x-acs-version")
                .and_then(|v| v.to_str().ok())
                != Some("2014-05-26")
            {
                s.violations.push("admission exact-instance Describe");
                return cloud_failure(
                    &mut s,
                    &action,
                    StatusCode::BAD_REQUEST,
                    "EXACT_DESCRIBE_PROTOCOL",
                );
            }
            let mut item = json!({"InstanceId":b.instance_id,"RegionId":b.region,"ZoneId":b.zone_id,"InstanceNetworkType":"vpc","Status":"Running","VpcAttributes":{"VpcId":b.vpc_id,"VSwitchId":b.vswitch_id,"PrivateIpAddress":{"IpAddress":[b.private_ip.to_string()]}},"Tags":{"Tag":[{"TagKey":"Deployment","TagValue":b.deployment},{"TagKey":"Role","TagValue":"kata"}]}});
            match s.mode {
                3 => item["ZoneId"] = json!("cn-hangzhou-b"),
                4 => item["VpcAttributes"]["VSwitchId"] = json!("vsw-foreign"),
                5 => item["Tags"]["Tag"][1]["TagValue"] = json!("control"),
                _ => {}
            }
            json!({"RequestId":id,"TotalCount":1,"NextToken":"","Instances":{"Instance":[item]}})
        }
        _ => {
            s.violations.push("unapproved admission action");
            return cloud_failure(
                &mut s,
                &action,
                StatusCode::METHOD_NOT_ALLOWED,
                "UNAPPROVED_ACTION",
            );
        }
    };
    s.responses.push((cloud_action_name(&action), 200, "OK"));
    answer(StatusCode::OK, v)
}
struct AdmissionCloud {
    shared: Arc<Mutex<AdmissionCloudState>>,
    binding: NodeTopologyCloudBinding,
    server: Server,
    token: tempfile::NamedTempFile,
}
impl AdmissionCloud {
    async fn new(binding: NodeTopologyCloudBinding) -> anyhow::Result<Self> {
        let shared = Arc::new(Mutex::new(AdmissionCloudState::default()));
        let server = Server::start(Router::new().fallback(any(cloud_http)).with_state(
            AdmissionCloudRoutes {
                shared: shared.clone(),
                binding: binding.clone(),
            },
        ))
        .await?;
        let mut token = tempfile::NamedTempFile::new()?;
        token.write_all(ADMISSION_OIDC.as_bytes())?;
        token.flush()?;
        Ok(Self {
            shared,
            binding,
            server,
            token,
        })
    }
    fn client(&self, mode: u8) -> anyhow::Result<AlibabaCloudAdmissionNodeTopology> {
        {
            let mut s = self
                .shared
                .lock()
                .map_err(|_| anyhow::anyhow!("admission cloud state"))?;
            s.mode = mode;
            s.actions.clear();
            s.responses.clear();
        }
        let config = NodeTopologyCloudConfig {
            account_id: ACCOUNT.into(),
            region: self.binding.region.clone(),
            role_arn: format!("acs:ram::{ACCOUNT}:role/admission-readonly"),
            role_id: ROLE_ID.into(),
            oidc_provider_arn: format!("acs:ram::{ACCOUNT}:oidc-provider/fixture"),
            oidc_issuer: "https://issuer.fixture.invalid".into(),
            oidc_audience: "sts.aliyuncs.com".into(),
            oidc_subject: ADMISSION_SUBJECT.into(),
            oidc_token_file: self.token.path().into(),
            requests_per_second: 20,
            max_in_flight: 4,
        };
        AlibabaCloudAdmissionNodeTopology::for_test(
            config,
            self.binding.clone(),
            self.server.url.clone(),
        )
        .map_err(|e| anyhow::anyhow!("admission cloud fixture {e:?}"))
    }
    fn actions(&self) -> anyhow::Result<Vec<String>> {
        Ok(self
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("admission cloud state"))?
            .actions
            .clone())
    }
    async fn finish(self) -> anyhow::Result<()> {
        let joined = self.server.finish().await;
        eprintln!(
            "PRIVATE selected admissionCloud HTTP_JOIN_{}",
            if joined.is_ok() {
                "COMPLETED"
            } else {
                "FAILED"
            }
        );
        joined?;
        let state = self
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("admission cloud state"))?;
        if !state.violations.is_empty() {
            eprintln!(
                "PRIVATE selected admissionCloud protocol categories {:?}",
                state.violations
            );
        }
        ensure!(
            state.violations.is_empty(),
            "admission cloud protocol mismatch"
        );
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires fresh private PG, actual Pending/Job/Pod creation, enrolled topology and independent signed admission STS; not CSI certification"]
async fn raw_selected_node_metadata_requires_current_authority_and_live_unassigned_pod()
-> anyhow::Result<()> {
    Box::pin(run()).await
}
async fn clear(pools: &[&sqlx::PgPool]) -> anyhow::Result<()> {
    for pool in pools {
        let mut connections = vec![];
        for _ in 0..pool.options().get_max_connections() {
            let mut c = pool.acquire().await?;
            c.clear_cached_statements().await?;
            connections.push(c);
        }
    }
    Ok(())
}
async fn run() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let parsed = url::Url::parse(&std::env::var("TEST_DATABASE_URL")?)?;
    ensure!(
        parsed
            .path()
            .strip_prefix("/sandbox_restore_acceptance_")
            .and_then(|v| v.strip_suffix("_test"))
            .is_some_and(|v| !v.is_empty()
                && v.len() <= 20
                && v.bytes().all(|c| c.is_ascii_digit())),
        "dedicated new selected-node acceptance DB"
    );
    let (source, verifier, _source_files) = Box::pin(completed_source())
        .await
        .context("selected normal completed backup source setup")?;
    for grant in [
        include_str!("../scripts/sql/worker-role.sql"),
        include_str!("../scripts/sql/gateway-role.sql"),
        include_str!("../scripts/sql/admission-role.sql"),
        include_str!("../scripts/sql/termination-role.sql"),
        include_str!("../scripts/sql/fencing-role.sql"),
        include_str!("../scripts/sql/volume-deleter-role.sql"),
        include_str!("../scripts/sql/backup-role.sql"),
    ] {
        sqlx::raw_sql(grant).execute(&source.f.base.f.owner).await?;
    }
    let verified = test_support_db::Fixture::prepare_verified_connections().await?;
    let admission_role = verified
        .runtime("TEST_ADMISSION_DATABASE_URL", "sandbox_admission", 4)
        .await?;
    let admission_db = admission_role.database_for("sandbox_admission")?;
    let hot = bound_authority::hot::HotPools::prepare(
        &verified,
        &admission_db,
        &source.f.backup.database,
    )
    .await?;
    let hot_result = Box::pin(async {
    let owner = Database {
        pool: verified.owner(),
    };
    let mut tx = owner.pool.begin().await?;
    for ddl in [
        include_str!("../tests/fixtures/restore/0038_restores.sql"),
        include_str!("../tests/fixtures/restore/0038_restore_control_admission.sql"),
        include_str!("../tests/fixtures/restore/0038_restore_raw_parent_admission.sql"),
        include_str!("../tests/fixtures/restore/0038_restore_node_topology.sql"),
        include_str!("../tests/fixtures/restore/0038_restore_raw_scheduling_admission.sql"),
        include_str!("../tests/fixtures/restore/0038_restore_raw_disk_receipts.sql"),
        include_str!("../tests/fixtures/restore/0038_restore_raw_bound_authority.sql"),
    ] {
        sqlx::raw_sql(ddl).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    sqlx::raw_sql(include_str!("../scripts/sql/restore-role.sql"))
        .execute(&owner.pool)
        .await?;
    verified.clear_statement_caches().await?;
    admission_role.clear_statement_caches().await?;
    hot.clear_after_draft().await?;
    clear(&[
        &source.f.base.f.database.pool,
        &source.f.base.engine.database.pool,
        &source.f.backup.database.pool,
    ])
    .await?;
    for db in [
        &source.f.base.f.database,
        &source.f.backup.database,
        &admission_db,
    ] {
        let error = db
            .verify_runtime_role()
            .await
            .err()
            .context("private selected DDL must reject startup")?;
        ensure!(
            error
                .to_string()
                .contains("successful ordered migration 0038"),
            "normal draft gate, not role failure"
        );
    }
    let mut binding = node();
    binding.cluster_epoch = Uuid::new_v4();
    sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton")
        .bind(binding.cluster_epoch)
        .execute(&owner.pool)
        .await?;
    let cloud_binding = NodeTopologyCloudBinding {
        account_id: ACCOUNT.into(),
        region: "cn-hangzhou".into(),
        instance_id: format!("i-selected{}", Uuid::new_v4().simple()),
        zone_id: "cn-hangzhou-a".into(),
        vpc_id: "vpc-publictopology".into(),
        vswitch_id: "vsw-zonea".into(),
        private_ip: "10.0.0.8".parse()?,
        deployment: "sandbox".into(),
    };
    let tf = terraform(&binding, &cloud_binding);
    let raw = serde_json::to_vec_pretty(&tf)?;
    let canonical = canonical_sha(&raw)?;
    let plan = enrollment_plan(
        &binding,
        &cloud_binding,
        &tf,
        &raw,
        Utc::now() + Days::days(1),
    )?;
    let kube = KubeFixture::new(&binding, &cloud_binding).await?;
    {
        let mut state = kube
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("server Node metadata"))?;
        let created = json!(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));
        state.node["metadata"]["creationTimestamp"] = created.clone();
        state.csi["metadata"]["creationTimestamp"] = created;
    }
    let guard = FixtureGuard::start(binding.clone()).await?;
    let owner_cloud = CloudFixture::new(cloud_binding.clone()).await?;
    let admission_cloud = AdmissionCloud::new(cloud_binding).await?;
    let outcome=Box::pin(async {
        let enrolled=enroll_with_client_test(&owner,kube.runtime.runtime(),&guard.client,&plan).await?;
        ensure!(enrolled.enabled&&enrolled.changed,"normal current-epoch mTLS enrollment");
        kube.eligible()?;
        let profile=insert_profile(&owner,source.f.profile,binding.cluster_epoch,&canonical,Utc::now()+Days::days(2),Utc::now(),Utc::now()+Days::hours(12)).await?;
        let proof=collect_with_client(&owner,&kube.runtime,&guard.client,&owner_cloud.client(0)?,NodeTopologyRequest{runtime_node_id:enrolled.runtime_node_id,enrollment_id:enrolled.enrollment_id,restore_profile_id:profile},&raw).await?;
        record_node_topology(&owner,&proof).await?;
        let target=Uuid::new_v4();let security=Uuid::new_v4();
        let mut tx=source.f.base.f.owner_transaction().await?;
        sqlx::query("INSERT INTO projects(id,tenant_id,name,max_ttl_seconds,runtime_namespace,storage_class) VALUES($1,$2,'Selected target',86400,$3,'integration-storage')").bind(target).bind(source.f.base.f.actor.tenant_id).bind(format!("selected-{}",target.simple())).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO quota_accounts(tenant_id,project_id,dimension,limit_value) SELECT tenant_id,$2,dimension,limit_value FROM quota_accounts WHERE tenant_id=$1 AND project_id=$3").bind(source.f.base.f.actor.tenant_id).bind(target).bind(source.f.base.launch.project_id).execute(&mut *tx).await?;
        for (project,action) in [(None,"backups:restore"),(Some(source.f.base.launch.project_id),"backups:restore"),(None,"instances:create"),(Some(target),"instances:create"),(None,"restores:read"),(Some(target),"restores:read")]{sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING").bind(source.f.base.f.actor.tenant_id).bind(project).bind(source.f.base.f.actor.principal_id).bind(action).execute(&mut *tx).await?;}
        sqlx::query("INSERT INTO security_policy_versions(id,tenant_id,name,version,status,rules) VALUES($1,$2,'selected-runtime',1,'APPROVED',$3)").bind(security).bind(source.f.base.f.actor.tenant_id).bind(json!({"profile":"deny-all","dns":true})).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO launch_guard_contracts(id,cluster_epoch,protocol,certification_report_sha256,runtime_node_ids,approval_reference,valid_until) VALUES($1,$2,'NODEGUARD_REQUIRED_V1',$3,$4,'PUBLIC_SELECTED_TEST_ONLY',clock_timestamp()+interval '1 day')").bind(Uuid::new_v4()).bind(binding.cluster_epoch).bind("a".repeat(64)).bind(vec![enrolled.runtime_node_id]).execute(&mut *tx).await?;
        let version:i64=sqlx::query_scalar("SELECT version FROM backups WHERE tenant_id=$1 AND id=$2").bind(source.f.base.f.actor.tenant_id).bind(source.plan.backup.id).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        let delegated=grants::create(&source.f.base.f.database,&source.f.base.f.owner,&source.f.base.f.actor,source.f.base.launch.project_id,target).await?;
        source.f.base.f.database.update_project_grant(&source.f.base.f.actor,source.f.base.launch.project_id,delegated.source_restore.id,&crate::grants::UpdateGrant{enabled:true,expires_at:Some(Utc::now()+Days::hours(1))},"selected-renew-source-grant",delegated.source_restore.version).await.map_err(api_failure)?;
        let accepted=source.f.base.f.database.create_restore(&delegated.actor,source.plan.backup.id,&CreateRestore{target_project_id:target,name:"selected-workspace".into(),profile_id:profile,template_version_id:source.f.base.f.request.template_version_id,security_profile_id:security,flavor:Flavor::Cpu2Mem4},"selected-restore",version).await.map_err(api_failure)?;
        let claim=source.f.backup.claim_backup().await.map_err(api_failure)?.context("normal only restore claim")?;
        ensure!(claim.operation_id==accepted.body.operation.id,"accepted original management operation");
        let vault=source.f.backup.database.prepare_restore_verification(&source.f.backup,&claim).await.map_err(api_failure)?;
        let verified_vault=verifier.verify(&vault.expectation).await?;
        source.f.backup.database.record_restore_verification(&source.f.backup,&claim,&verified_vault).await.map_err(api_failure)?;
        let raw_plan=source.f.backup.database.prepare_restore_storage(&source.f.backup,&claim).await.map_err(api_failure)?;
        let workload=Workload::start(support(&raw_plan.cloud,classes(&raw_plan.context.storage_contract))).await?;
        let business=Box::pin(accepted_chain(&source,&claim,(&admission_db,&hot),&workload,&raw_plan,&kube,&admission_cloud)).await;
        let drained=workload.finish().await;
        business?;drained?;
        Ok::<_,anyhow::Error>(())
    }).await;

    let admission_closed = admission_cloud.finish().await;
    let owner_closed = owner_cloud.finish().await;
    let kube_closed = kube.finish().await;
    let node_closed = guard.shutdown().await;
    let source_closed = source.f.base.guard.shutdown().await;
    for (name, failed) in [
        ("admissionCloud", admission_closed.is_err()),
        ("ownerCloud", owner_closed.is_err()),
        ("Kube", kube_closed.is_err()),
        ("currentNodeguard", node_closed.is_err()),
        ("sourceNodeguard", source_closed.is_err()),
    ] {
        if failed {
            eprintln!("PRIVATE selected fixture cleanup failed {name}; not certified drained");
        }
    }
    outcome?;
    admission_closed?;
    owner_closed?;
    kube_closed?;
    node_closed?;
    source_closed?;
    Ok::<_,anyhow::Error>(())
    }).await;
    let hot_closed = hot.finish().await;
    if hot_closed.is_err() {
        eprintln!("PRIVATE hot pools physical absence/monitor failed; not certified drained");
    }
    hot_result?;
    hot_closed?;
    Ok(())
}

fn classes(
    contract: &crate::restore::storage_contract::RestoreStorageContract,
) -> BTreeMap<String, Value> {
    use crate::restore::storage_contract::{
        RestoreStoragePurpose, expected_snapshot_class_spec, expected_storage_class_spec,
    };
    let mut map = BTreeMap::new();
    for (purpose, id) in [
        (RestoreStoragePurpose::Normal, &contract.mapping.normal),
        (RestoreStoragePurpose::Raw, &contract.mapping.raw),
        (RestoreStoragePurpose::Delivery, &contract.mapping.delivery),
    ] {
        let mut v = expected_storage_class_spec(&contract.mapping, purpose);
        v["metadata"] = json!({"name":id.name,"uid":id.uid});
        map.insert(
            format!("/apis/storage.k8s.io/v1/storageclasses/{}", id.name),
            v,
        );
    }
    let id = &contract.mapping.snapshot;
    let mut v = expected_snapshot_class_spec(&contract.mapping);
    v["metadata"] = json!({"name":id.name,"uid":id.uid});
    map.insert(
        format!(
            "/apis/snapshot.storage.k8s.io/v1/volumesnapshotclasses/{}",
            id.name
        ),
        v,
    );
    map
}
async fn facts(owner: &sqlx::PgPool, t: Uuid, r: Uuid) -> anyhow::Result<Value> {
    let mut tx = owner.begin().await?;
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(t.to_string())
        .execute(&mut *tx)
        .await?;
    let v=sqlx::query_scalar("SELECT jsonb_build_object('source',to_jsonb(b),'source_vault',to_jsonb(v),'source_instance',(SELECT to_jsonb(i) FROM instances i WHERE i.tenant_id=b.tenant_id AND i.id=b.instance_id),'source_workspace',(SELECT to_jsonb(w) FROM workspaces w WHERE w.tenant_id=b.tenant_id AND w.id=b.workspace_id),'target_instance',(SELECT to_jsonb(i) FROM instances i WHERE i.tenant_id=r.tenant_id AND i.id=r.instance_id),'target_workspace',(SELECT to_jsonb(w) FROM workspaces w WHERE w.tenant_id=r.tenant_id AND w.id=r.workspace_id),'restore',to_jsonb(r),'bindings',COALESCE((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.intent_id) FROM restore_resource_bindings x WHERE x.tenant_id=r.tenant_id AND x.restore_id=r.id),'[]'::jsonb),'intents',COALESCE((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.id) FROM restore_resource_intents x WHERE x.tenant_id=r.tenant_id AND x.restore_id=r.id),'[]'::jsonb),'admission',(SELECT to_jsonb(x) FROM restore_pod_admissions x WHERE x.tenant_id=r.tenant_id AND x.restore_id=r.id),'raw',(SELECT count(*) FROM restore_block_receipts x WHERE x.tenant_id=r.tenant_id AND x.restore_id=r.id),'pv_bindings',(SELECT count(*) FROM restore_resource_bindings x JOIN restore_resource_intents i ON i.tenant_id=x.tenant_id AND i.id=x.intent_id WHERE i.tenant_id=r.tenant_id AND i.restore_id=r.id AND i.kind='BLOCK_PV'),'permit',(SELECT count(*) FROM restore_launch_permits x WHERE x.tenant_id=r.tenant_id AND x.restore_id=r.id),'proof',(SELECT count(*) FROM restore_termination_proofs x WHERE x.tenant_id=r.tenant_id AND x.restore_id=r.id),'cleanup',(SELECT count(*) FROM restore_cleanup_receipts x WHERE x.tenant_id=r.tenant_id AND x.restore_id=r.id),'holds',COALESCE((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.id) FROM workspace_holds x WHERE x.tenant_id=r.tenant_id),'[]'::jsonb),'releases',COALESCE((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.hold_id) FROM workspace_hold_releases x WHERE x.tenant_id=r.tenant_id),'[]'::jsonb),'quota',COALESCE((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.id) FROM quota_accounts x WHERE x.tenant_id=r.tenant_id),'[]'::jsonb),'reservations',COALESCE((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.id) FROM quota_reservations x WHERE x.tenant_id=r.tenant_id),'[]'::jsonb)) FROM restores r JOIN backups b ON b.tenant_id=r.tenant_id AND b.id=r.backup_id JOIN backup_vault_receipts v ON v.tenant_id=b.tenant_id AND v.backup_id=b.id WHERE r.tenant_id=$1 AND r.id=$2")
        .bind(t).bind(r).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(v)
}
fn no_future(v: &Value) -> anyhow::Result<()> {
    for (field, record, id) in [
        ("source_instance", "source", "instance_id"),
        ("source_workspace", "source", "workspace_id"),
        ("target_instance", "restore", "instance_id"),
        ("target_workspace", "restore", "workspace_id"),
    ] {
        ensure!(
            v[field].is_object()
                && v[field]["id"] == v[record][id]
                && v[field]["tenant_id"] == v[record]["tenant_id"],
            "actual whole {field} row exists and is scoped to the recorded identity"
        );
    }
    ensure!(
        v["restore"]["status"] == json!("RESTORE_PENDING")
            && ["raw", "pv_bindings", "permit", "proof", "cleanup"]
                .iter()
                .all(|k| v[*k] == json!(0)),
        "metadata scheduling cannot produce future writer/media/closure authority"
    );
    ensure!(
        v["holds"].as_array().is_some_and(|rows| rows
            .iter()
            .filter(|h| h["id"] == v["restore"]["hold_id"]
                && h["reference_id"] == v["restore"]["id"]
                && h["workspace_id"] == v["restore"]["workspace_id"]
                && h["kind"] == "RESTORE")
            .count()
            == 1)
            && v["releases"]
                .as_array()
                .is_some_and(|rows| rows.iter().all(|r| r["hold_id"] != v["restore"]["hold_id"]))
            && v["reservations"].as_array().is_some_and(|rows| {
                let current: Vec<_> = rows
                    .iter()
                    .filter(|r| r["operation_id"] == v["restore"]["operation_id"])
                    .collect();
                current.len() == 10
                    && current
                        .iter()
                        .all(|r| r["status"] == "PENDING" && r["released_at"].is_null())
            }),
        "current restore holds and quota remain reserved"
    );
    Ok(())
}
async fn accepted_chain(
    source: &crate::backup_ledger::pipeline_tests::Pipeline,
    claim: &crate::engine::Claim,
    connections: (&Database, &bound_authority::hot::HotPools),
    w: &Workload,
    raw: &crate::restore::resources::RestoreStoragePlan,
    kube: &KubeFixture,
    cloud: &AdmissionCloud,
) -> anyhow::Result<()> {
    let (admission_db, hot) = connections;
    let t = claim.tenant_id;
    let r = raw.context.restore_id;
    let pvc_path = format!(
        "/api/v1/namespaces/{NAMESPACE}/persistentvolumeclaims/{}",
        block_pvc_name(r)
    );
    w.install(service(admission_db.clone(), w.runtime.clone()), None)?;
    let observed = Box::pin(w.runtime.reconcile_restore_block(
        &raw.context,
        &raw.cloud,
        None,
        None,
        &raw.source,
    ))
    .await?;
    ensure!(
        observed.bound.is_none() && w.reads(&pvc_path)? == 3,
        "initial missing GET then two actual admitted Pending GETs; total={}",
        w.reads(&pvc_path)?
    );
    {
        let s = w
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("raw creation state"))?;
        let uid = Some(observed.pvc_uid.to_string());
        let pending = Some("Pending".to_owned());
        ensure!(
            s.raw_read_responses
                == vec![
                    (pvc_path.clone(), 404, None, None),
                    (pvc_path.clone(), 200, uid.clone(), pending.clone()),
                    (pvc_path.clone(), 200, uid, pending),
                ],
            "exact initial404 then two Pending successful GETs of observed UID: {:?}",
            s.raw_read_responses
        );
        ensure!(
            s.decisions == vec![("persistentvolumeclaims".into(), 200)]
                && s.stored == vec![pvc_path.clone()],
            "actual rawPOST passes decision before one stored parent"
        );
        ensure!(
            s.requests
                .iter()
                .filter(|(m, _)| *m == Method::POST)
                .count()
                == 1
                && s.requests
                    .iter()
                    .all(|(_, p)| !p.starts_with("/api/v1/persistentvolumes/")),
            "one CREATE, no future PV observation"
        );
    }
    source
        .f
        .backup
        .database
        .record_restore_block(&source.f.backup, claim, &observed)
        .await
        .map_err(api_failure)?;
    let job = source
        .f
        .backup
        .database
        .prepare_restore_job(&source.f.backup, claim)
        .await
        .map_err(api_failure)?;
    let (service, (config_uid, job_uid)) = Box::pin(admission::prepare(
        admission_db.clone(),
        &w.runtime,
        &job,
        &source.f.base,
        &w.objects,
    ))
    .await?;
    source
        .f
        .backup
        .database
        .record_restore_job_objects(&source.f.backup, claim, config_uid, job_uid)
        .await
        .map_err(api_failure)?;
    Box::pin(admission::verify_recorded_objects(
        &source.f.backup,
        claim,
        &source.f.base,
        t,
        r,
        config_uid,
        job_uid,
    ))
    .await?;
    w.install(service.clone(), Some(job_uid))?;
    let no_pod = Box::pin(w.runtime.start_and_observe(&job.context, job_uid, None)).await?;
    ensure!(
        no_pod.pod.is_none(),
        "real normal unsuspend PATCH still creates no Pod by itself"
    );
    let pod_name = format!("{}-sel01", backup_job_name(r, BackupStage::Restore));
    let expected = crate::backup_admission::expected_pod(&job.context, job_uid, &pod_name)
        .map_err(|e| anyhow::anyhow!(e.message))?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let url = format!("{}api/v1/namespaces/{NAMESPACE}/pods", w.server.url);
    ensure!(
        client.post(&url).json(&expected).send().await?.status() == StatusCode::CREATED,
        "actual one-shot PodCREATE must Allow then store"
    );
    ensure!(
        client.post(&url).json(&expected).send().await?.status() == StatusCode::FORBIDDEN,
        "second same-name PodCREATE cannot consume a new one-shot authority"
    );
    let actual = Box::pin(w.runtime.start_and_observe(&job.context, job_uid, None)).await?;
    let pod = actual
        .pod
        .context("actual PodLIST after successful CREATE")?;
    ensure!(
        pod.node_name.is_none() && pod.exit.is_none(),
        "Pending Pod is recorded before any node assignment/exit"
    );
    let pod_path = format!("/api/v1/namespaces/{NAMESPACE}/pods/{pod_name}");
    let stored: Value = client
        .get(format!(
            "{}{pod_path}",
            w.server.url.as_str().trim_end_matches('/')
        ))
        .send()
        .await?
        .json()
        .await?;
    ensure!(
        stored["metadata"]["uid"] == json!(pod.uid)
            && stored["metadata"]["generation"] == json!(1)
            && stored["status"] == json!({"phase":"Pending","qosClass":"Burstable"})
            && stored.pointer("/spec/nodeName").is_none()
            && stored["metadata"]["ownerReferences"][0]["uid"] == json!(job_uid),
        "actual PodGET binds server UID and real Job owner, still unassigned"
    );
    source
        .f
        .backup
        .database
        .record_restore_pod(&source.f.backup, claim, job_uid, &pod)
        .await
        .map_err(api_failure)?;
    let current = source
        .f
        .backup
        .database
        .prepare_restore_job(&source.f.backup, claim)
        .await
        .map_err(api_failure)?;
    ensure!(
        current.known_pod == Some(pod.uid),
        "normal Pod ledger refetch"
    );
    {
        let node_state = kube
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("current node state"))?;
        let mut map = w
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("workload objects"))?;
        map.insert(
            format!(
                "/api/v1/nodes/{}",
                node_state.node["metadata"]["name"]
                    .as_str()
                    .context("enrolled Node name")?
            ),
            node_state.node.clone(),
        );
        map.insert(
            format!(
                "/apis/storage.k8s.io/v1/csinodes/{}",
                node_state.csi["metadata"]["name"]
                    .as_str()
                    .context("CSI name")?
            ),
            node_state.csi.clone(),
        );
    }
    let baseline = facts(&source.f.base.f.owner, t, r).await?;
    no_future(&baseline)?;
    ensure!(
        baseline["restore"]["cluster_epoch"] != baseline["source"]["cluster_epoch"],
        "current restored epoch remains separate from immutable historical source"
    );
    Box::pin(reader_privileges(source, admission_db, t, r)).await?;
    let csi = ServiceIdentity {
        username: "system:serviceaccount:kube-system:sandbox-csi-controller".into(),
        uid: Uuid::new_v4().to_string(),
    };
    {
        let mut s = w
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("caller state"))?;
        s.callers.insert("select".into(), scheduler_user());
        s.callers.insert("provision".into(), control_user());
        s.callers.insert(
            "reset".into(),
            json!({"username":csi.username,"uid":csi.uid}),
        );
        s.callers.insert("wrong-scheduler".into(),json!({"username":"system:kube-scheduler","uid":Uuid::new_v4(),"groups":["system:authenticated"]}));
        s.callers.insert(
            "wrong-csi".into(),
            json!({"username":csi.username,"uid":Uuid::new_v4()}),
        );
        s.callers.insert("backup".into(), user(&service));
    }
    Box::pin(exercise(SelectedCase {
        source,
        claim,
        t,
        r,
        pvc_path: &pvc_path,
        pod_path: &pod_path,
        job: &current,
        service: &service,
        csi: &csi,
        w,
        cloud,
        hot,
        baseline: &baseline,
    }))
    .await?;
    Ok(())
}
struct SelectedCase<'a> {
    source: &'a crate::backup_ledger::pipeline_tests::Pipeline,
    claim: &'a crate::engine::Claim,
    t: Uuid,
    r: Uuid,
    pvc_path: &'a str,
    pod_path: &'a str,
    job: &'a JobPlan,
    service: &'a RestoreAdmissionService,
    csi: &'a ServiceIdentity,
    w: &'a Workload,
    cloud: &'a AdmissionCloud,
    hot: &'a bound_authority::hot::HotPools,
    baseline: &'a Value,
}
async fn reader_privileges(
    source: &crate::backup_ledger::pipeline_tests::Pipeline,
    admission: &Database,
    tenant: Uuid,
    restore_id: Uuid,
) -> anyhow::Result<()> {
    for (role, database) in [
        ("sandbox_app", &source.f.base.f.database),
        ("sandbox_backup", &source.f.backup.database),
    ] {
        for query in [
            "SELECT sandbox_restore_raw_scheduling_admission($1,$2,'unknown-node')",
            "SELECT sandbox_restore_raw_reschedule_admission($1,$2)",
        ] {
            let mut tx = database.begin(tenant).await.map_err(api_failure)?;
            let error = sqlx::query(query)
                .bind(tenant)
                .bind(restore_id)
                .execute(&mut *tx)
                .await
                .err()
                .context("ordinary role must not execute selected readers")?;
            ensure!(
                error.as_database_error().and_then(|e| e.code()).as_deref() == Some("42501"),
                "actual reader EXEC rejects ordinary role {role}"
            );
            tx.rollback().await?;
        }
    }
    for (requested_tenant, requested_restore) in [
        (Uuid::new_v4(), restore_id),
        (tenant, Uuid::new_v4()),
        (tenant, source.plan.backup.id),
    ] {
        for query in [
            "SELECT sandbox_restore_raw_scheduling_admission($1,$2,'unknown-node')",
            "SELECT sandbox_restore_raw_reschedule_admission($1,$2)",
        ] {
            let mut tx = admission.begin(tenant).await.map_err(api_failure)?;
            let result: Option<Value> = sqlx::query_scalar(query)
                .bind(requested_tenant)
                .bind(requested_restore)
                .fetch_one(&mut *tx)
                .await?;
            ensure!(
                result.is_none(),
                "selected reader cannot disclose a foreign or source-backup scope"
            );
            tx.commit().await?;
        }
    }
    let mut tx = admission.begin(tenant).await.map_err(api_failure)?;
    let error = sqlx::query("SELECT * FROM restore_node_topology_receipts")
        .fetch_all(&mut *tx)
        .await
        .err()
        .context("admission role must not get global topology SELECT")?;
    ensure!(
        error.as_database_error().and_then(|e| e.code()).as_deref() == Some("42501"),
        "actual admission role stays EXEC-only without global topology read"
    );
    tx.rollback().await?;
    Ok(())
}
impl SelectedCase<'_> {
    fn configure(&self, mode: u8, fault: Fault) -> anyhow::Result<()> {
        self.w.reset(fault)?;
        let mut service = self.service.clone();
        service.raw_scheduling = Some(
            RawSchedulingRuntime::new(self.csi.clone(), vec![self.cloud.client(mode)?])
                .map_err(|e| anyhow::anyhow!(e.message))?,
        );
        self.w.install(
            service,
            Some(self.job.known_job.context("recorded actual JobUID")?),
        )
    }
    async fn put(&self, caller: &str, body: Value, expected: StatusCode) -> anyhow::Result<()> {
        ensure!(
            self.source
                .f
                .backup
                .heartbeat(self.claim)
                .await
                .map_err(api_failure)?,
            "normal current worker heartbeat before metadata trial"
        );
        let original = self.w.get(self.pvc_path)?;
        let url = format!(
            "{}{}",
            self.w.server.url.as_str().trim_end_matches('/'),
            self.pvc_path
        );
        let response = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?
            .put(url)
            .header("x-public-fixture-caller", caller)
            .json(&body)
            .send()
            .await?;
        if response.status() != expected && self.safe_diagnostics().is_err() {
            eprintln!("PRIVATE selected fixed diagnostic collection failed");
        }
        ensure!(
            response.status() == expected,
            "actual metadata UPDATE caller={caller} expected{} got{}",
            expected,
            response.status()
        );
        if expected == StatusCode::FORBIDDEN {
            ensure!(
                self.w.get(self.pvc_path)? == original,
                "denied UPDATE leaves stored original PVC exactly unchanged"
            );
        }
        ensure!(
            facts(&self.source.f.base.f.owner, self.t, self.r).await? == *self.baseline,
            "metadata annotation/status observations cannot mutate source/DB authority/hold/quota"
        );
        Ok(())
    }
    fn safe_diagnostics(&self) -> anyhow::Result<()> {
        let state = self
            .w
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("workload diagnostic state"))?;
        let count = |path: &str| state.reads.get(path).copied().unwrap_or_default();
        let counts = [
            ("raw_pvc", count(self.pvc_path)),
            (
                "config",
                count(&format!(
                    "/api/v1/namespaces/{NAMESPACE}/configmaps/{}",
                    config_name(self.r)
                )),
            ),
            (
                "job",
                count(&format!(
                    "/apis/batch/v1/namespaces/{NAMESPACE}/jobs/{}",
                    backup_job_name(self.r, BackupStage::Restore)
                )),
            ),
            ("pod", count(self.pod_path)),
            (
                "pod_list",
                count(&format!("/api/v1/namespaces/{NAMESPACE}/pods")),
            ),
            (
                "node",
                state
                    .reads
                    .iter()
                    .filter(|(p, _)| p.starts_with("/api/v1/nodes/"))
                    .map(|(_, n)| *n)
                    .sum(),
            ),
            (
                "csi_node",
                state
                    .reads
                    .iter()
                    .filter(|(p, _)| p.starts_with("/apis/storage.k8s.io/v1/csinodes/"))
                    .map(|(_, n)| *n)
                    .sum(),
            ),
            (
                "generated_pv",
                state
                    .reads
                    .iter()
                    .filter(|(p, _)| p.starts_with("/api/v1/persistentvolumes/disk-"))
                    .map(|(_, n)| *n)
                    .sum(),
            ),
        ];
        eprintln!(
            "PRIVATE selected fixed GET counts {:?}; decision codes/static messages {:?}; protocol categories {:?}",
            counts, state.decision_messages, state.violations
        );
        drop(state);
        let cloud = self
            .cloud
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("cloud diagnostic state"))?;
        eprintln!(
            "PRIVATE selected cloud fixed actions/codes/categories {:?}; protocol categories {:?}",
            cloud.responses, cloud.violations
        );
        Ok(())
    }
    fn changed(&self, change: impl FnOnce(&mut Value)) -> anyhow::Result<Value> {
        let mut body = self.w.get(self.pvc_path)?;
        change(&mut body);
        Ok(body)
    }
    fn complete_rounds(&self, node: bool) -> anyhow::Result<()> {
        let j = self.job.known_job.context("JobUID")?;
        for path in [
            self.pvc_path.to_owned(),
            format!(
                "/api/v1/namespaces/{NAMESPACE}/configmaps/{}",
                config_name(self.r)
            ),
            format!(
                "/apis/batch/v1/namespaces/{NAMESPACE}/jobs/{}",
                backup_job_name(self.r, BackupStage::Restore)
            ),
            self.pod_path.to_owned(),
            format!("/api/v1/namespaces/{NAMESPACE}/pods"),
        ] {
            ensure!(
                self.w.reads(&path)? == 2,
                "two actual workload reads at exact {path} Job{j}"
            );
        }
        let node_name = self
            .w
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("node object"))?
            .values()
            .find(|v| v["kind"] == json!("Node"))
            .and_then(|v| v["metadata"]["name"].as_str())
            .context("Node name")?
            .to_owned();
        ensure!(
            self.w.reads(&format!("/api/v1/nodes/{node_name}"))? == if node { 2 } else { 0 }
                && self
                    .w
                    .reads(&format!("/apis/storage.k8s.io/v1/csinodes/{node_name}"))?
                    == if node { 2 } else { 0 },
            "exact Node and CSI two rounds, RESET none"
        );
        Ok(())
    }
}
fn selected(body: &mut Value, node: &str) {
    let metadata = body["metadata"]
        .as_object_mut()
        .map(|m| m.entry("annotations").or_insert(json!({})));
    if let Some(v) = metadata {
        v[SELECTED] = json!(node);
    }
}
fn provision(body: &mut Value) {
    body["metadata"]["annotations"][STABLE] = json!(DRIVER);
    body["metadata"]["annotations"][BETA] = json!(DRIVER);
}
fn reset(body: &mut Value) {
    if let Some(a) = body["metadata"]["annotations"].as_object_mut() {
        a.remove(SELECTED);
    }
}
async fn exercise(case: SelectedCase<'_>) -> anyhow::Result<()> {
    let node_name = {
        let map = case
            .w
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("Node map"))?;
        map.values()
            .find(|v| v["kind"] == json!("Node"))
            .and_then(|v| v["metadata"]["name"].as_str())
            .context("Node name")?
            .to_owned()
    };
    // No runtime means explicit Deny before any Kubernetes/cloud observation.
    case.w.reset(Fault::None)?;
    case.w.install(case.service.clone(), case.job.known_job)?;
    case.put(
        "select",
        case.changed(|v| selected(v, &node_name))?,
        StatusCode::FORBIDDEN,
    )
    .await?;
    ensure!(
        case.w.reads(case.pvc_path)? == 0,
        "unconfigured metadata path starts no I/O"
    );
    for caller in ["backup", "wrong-scheduler", "wrong-csi"] {
        case.configure(0, Fault::None)?;
        case.put(
            caller,
            case.changed(|v| selected(v, &node_name))?,
            StatusCode::FORBIDDEN,
        )
        .await?;
        ensure!(
            case.w.reads(case.pvc_path)? == 0 && case.cloud.actions()?.is_empty(),
            "wrong exact identity cannot start observation"
        );
    }
    case.configure(0, Fault::None)?;
    case.put(
        "select",
        case.changed(|v| selected(v, &node_name))?,
        StatusCode::OK,
    )
    .await?;
    case.complete_rounds(true)?;
    ensure!(
        case.cloud.actions()?
            == vec![
                "AssumeRoleWithOIDC",
                "GetCallerIdentity",
                "DescribeInstances"
            ],
        "fresh signed dedicated admission subject reads exact one instance"
    );
    for (caller, change) in [
        ("select", 0_u8),
        ("provision", 1),
        ("provision", 0),
        ("reset", 2),
        ("reset", 0),
    ] {
        case.configure(0, Fault::None)?;
        let body = case.changed(|v| match change {
            1 => provision(v),
            2 => reset(v),
            _ => {}
        })?;
        case.put(caller, body, StatusCode::OK).await?;
        case.complete_rounds(caller != "reset")?;
        if caller == "reset" {
            ensure!(
                case.cloud.actions()?.is_empty(),
                "CSI reset uses no owner/admission cloud identity"
            );
            ensure!(
                case.w.reads(&format!(
                    "/api/v1/persistentvolumes/disk-{}",
                    case.w.get(case.pvc_path)?["metadata"]["uid"]
                        .as_str()
                        .context("PVCUID")?
                ))? == 2,
                "two actual404 generated PV reads before hint reset"
            );
        }
    }
    // Provisioner pair is retained by RESET, and exact re-selection is legal.
    case.configure(0, Fault::None)?;
    case.put(
        "select",
        case.changed(|v| selected(v, &node_name))?,
        StatusCode::OK,
    )
    .await?;
    for field in [
        "pair-half",
        "pair-driver",
        "annotation",
        "spec",
        "status",
        "uid",
        "remap",
        "remove",
    ] {
        case.configure(0, Fault::None)?;
        let changed = case.changed(|v| match field {
            "pair-half" => {
                v["metadata"]["annotations"]
                    .as_object_mut()
                    .map(|a| a.remove(BETA));
            }
            "pair-driver" => v["metadata"]["annotations"][STABLE] = json!("foreign.csi"),
            "annotation" => v["metadata"]["annotations"]["foreign/authority"] = json!("true"),
            "spec" => v["spec"]["volumeMode"] = json!("Filesystem"),
            "status" => v["status"]["phase"] = json!("Bound"),
            "uid" => v["metadata"]["uid"] = json!(Uuid::new_v4()),
            "remap" => selected(v, "different-unenrolled-node"),
            _ => reset(v),
        })?;
        case.put("select", changed, StatusCode::FORBIDDEN).await?;
        ensure!(
            case.cloud.actions()?.is_empty(),
            "metadata diff negative {field} cannot reach cloud"
        );
    }
    for fault in [
        Fault::PodAssigned,
        Fault::PodTerminated,
        Fault::SecondPodUid,
        Fault::DuplicatePod,
        Fault::ContinuedPodList,
        Fault::SecondPvcUid,
        Fault::ConfigSource,
        Fault::JobOwner,
        Fault::SecondNodeUid,
        Fault::SecondCsiUid,
    ] {
        case.configure(0, fault)?;
        case.put("select", case.changed(|_| {})?, StatusCode::FORBIDDEN)
            .await?;
        match fault {
            Fault::PodAssigned | Fault::PodTerminated => ensure!(
                case.w.reads(case.pod_path)? == 1 && case.cloud.actions()?.is_empty(),
                "fault reaches real pendingPod firstGET"
            ),
            Fault::DuplicatePod | Fault::ContinuedPodList => ensure!(
                case.w
                    .reads(&format!("/api/v1/namespaces/{NAMESPACE}/pods"))?
                    == 1
                    && case.cloud.actions()?.is_empty(),
                "fault reaches actual selector list"
            ),
            Fault::ConfigSource => ensure!(
                case.w.reads(&format!(
                    "/api/v1/namespaces/{NAMESPACE}/configmaps/{}",
                    config_name(case.r)
                ))? == 1
                    && case.cloud.actions()?.is_empty(),
                "fault reaches observed frozen config"
            ),
            Fault::JobOwner => ensure!(
                case.w.reads(&format!(
                    "/apis/batch/v1/namespaces/{NAMESPACE}/jobs/{}",
                    backup_job_name(case.r, BackupStage::Restore)
                ))? == 1
                    && case.cloud.actions()?.is_empty(),
                "fault reaches observed Job generated fields"
            ),
            Fault::SecondPvcUid => ensure!(
                case.w.reads(case.pvc_path)? == 2
                    && case
                        .cloud
                        .actions()?
                        .iter()
                        .filter(|a| a.as_str() == "DescribeInstances")
                        .count()
                        == 1,
                "secondPVC drift happens after signed cloud"
            ),
            Fault::SecondPodUid => ensure!(
                case.w.reads(case.pod_path)? == 2
                    && case
                        .cloud
                        .actions()?
                        .iter()
                        .filter(|a| a.as_str() == "DescribeInstances")
                        .count()
                        == 1,
                "secondPod drift reaches secondGET after cloud"
            ),
            Fault::SecondNodeUid => ensure!(
                case.w.reads(&format!("/api/v1/nodes/{node_name}"))? == 2
                    && case
                        .w
                        .reads(&format!("/apis/storage.k8s.io/v1/csinodes/{node_name}"))?
                        == 1
                    && case
                        .cloud
                        .actions()?
                        .iter()
                        .filter(|a| a.as_str() == "DescribeInstances")
                        .count()
                        == 1,
                "secondNode drift reaches secondGET after cloud"
            ),
            Fault::SecondCsiUid => ensure!(
                case.w
                    .reads(&format!("/apis/storage.k8s.io/v1/csinodes/{node_name}"))?
                    == 2
                    && case.w.reads(&format!("/api/v1/nodes/{node_name}"))? == 2
                    && case
                        .cloud
                        .actions()?
                        .iter()
                        .filter(|a| a.as_str() == "DescribeInstances")
                        .count()
                        == 1,
                "secondCSI drift reaches secondGET after cloud"
            ),
            _ => anyhow::bail!("unhandled target fault"),
        }
    }
    for mode in 1..=5 {
        case.configure(mode, Fault::None)?;
        case.put("select", case.changed(|_| {})?, StatusCode::FORBIDDEN)
            .await?;
        let expected = match mode {
            1 => vec!["AssumeRoleWithOIDC"],
            2 => vec!["AssumeRoleWithOIDC", "GetCallerIdentity"],
            _ => vec![
                "AssumeRoleWithOIDC",
                "GetCallerIdentity",
                "DescribeInstances",
            ],
        };
        ensure!(
            case.cloud.actions()? == expected,
            "exact cloud target stage mode{mode}"
        );
    }
    case.configure(0, Fault::ExistingPv)?;
    case.put("reset", case.changed(reset)?, StatusCode::FORBIDDEN)
        .await?;
    ensure!(
        case.w.reads(&format!(
            "/api/v1/persistentvolumes/disk-{}",
            case.w.get(case.pvc_path)?["metadata"]["uid"]
                .as_str()
                .context("PVCUID")?
        ))? == 1
            && case.cloud.actions()?.is_empty(),
        "actual existing generatedPV blocks reset without using oldNode/cloud"
    );
    no_future(&facts(&case.source.f.base.f.owner, case.t, case.r).await?)?;
    Box::pin(scope_budgets(&case, &node_name)).await?;
    Box::pin(postwait_revocation(&case)).await?;
    Box::pin(acknowledgements(&case)).await?;
    Box::pin(bound_authority::run(&case, &node_name)).await?;
    // Independent boxed phases avoid another flag/large branch in the common
    // Restore scenario. Claim replacement is the last phase by construction.
    Box::pin(boundary::run(&case, &node_name)).await?;
    eprintln!(
        "VERIFIED private normal rawPending+realJobcreateGET/ledger+unsuspend+actualoneShotPodcreateGET/record, SELECT/PROVISIONER/RESET dedicated readonly subject and precise first/second target denial counts; noPV/permit/proof/cleanup/holdquota release; not cloudCSI or VMbirth certification"
    );
    Ok(())
}

async fn budget(case: &SelectedCase<'_>, node: Option<&str>) -> anyhow::Result<Option<i64>> {
    let mut tx = case
        .service
        .database
        .begin(case.t)
        .await
        .map_err(api_failure)?;
    let value: Option<Value> = if let Some(n) = node {
        sqlx::query_scalar("SELECT sandbox_restore_raw_scheduling_admission($1,$2,$3)")
            .bind(case.t)
            .bind(case.r)
            .bind(n)
            .fetch_one(&mut *tx)
            .await?
    } else {
        sqlx::query_scalar("SELECT sandbox_restore_raw_reschedule_admission($1,$2)")
            .bind(case.t)
            .bind(case.r)
            .fetch_one(&mut *tx)
            .await?
    };
    tx.commit().await?;
    value
        .map(|v| {
            ensure!(
                v.as_object().is_some_and(|m| m.len() == 2
                    && m.contains_key("pin")
                    && m.contains_key("valid_for_us")),
                "real role exact reader envelope"
            );
            ensure!(
                v["pin"].as_object().is_some_and(|m| m.len() == 11),
                "real role full11pin"
            );
            ensure!(
                v["pin"]["resource_identities"]["BLOCK_PV"]["binding"].is_null(),
                "no future PVbinding through selected reader"
            );
            if node.is_none() {
                ensure!(
                    v["pin"]["node_identity"].is_null() && v["pin"]["node_topology"].is_null(),
                    "RESET authority does not adopt a node"
                );
            }
            let us = v["valid_for_us"].as_i64().context("strict reader i64");
            let us = us?;
            ensure!(
                (1..=10_000_000).contains(&us),
                "bounded positive reader horizon"
            );
            Ok(us)
        })
        .transpose()
}
async fn scope_budgets(case: &SelectedCase<'_>, node: &str) -> anyhow::Result<()> {
    type Grant = (Uuid, Option<Uuid>, String, Option<chrono::DateTime<Utc>>);
    ensure!(
        case.source
            .f
            .backup
            .heartbeat(case.claim)
            .await
            .map_err(api_failure)?,
        "fresh normal current claim for scope trial"
    );
    let mut tx = case.source.f.base.f.owner_transaction().await?;
    let actor: Uuid = sqlx::query_scalar(
        "SELECT actor_principal_id FROM operations WHERE tenant_id=$1 AND id=$2",
    )
    .bind(case.t)
    .bind(case.job.record.operation_id)
    .fetch_one(&mut *tx)
    .await?;
    let saved:Vec<Grant>=sqlx::query_as("SELECT id,project_id,action,expires_at FROM grants WHERE tenant_id=$1 AND principal_id=$2 AND enabled AND revoked_at IS NULL AND ((project_id IS NULL AND action IN ('backups:read','backups:restore','instances:create')) OR (project_id=$3 AND action IN ('backups:read','backups:restore')) OR (project_id=$4 AND action='instances:create'))").bind(case.t).bind(actor).bind(case.job.record.source_project_id).bind(case.job.record.target_project_id).fetch_all(&mut *tx).await?;
    let no_wildcard:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM grants WHERE tenant_id=$1 AND principal_id=$2 AND action='*')").bind(case.t).bind(actor).fetch_one(&mut *tx).await?;
    let required = [
        (None, "backups:read"),
        (Some(case.job.record.source_project_id), "backups:read"),
        (None, "backups:restore"),
        (Some(case.job.record.source_project_id), "backups:restore"),
        (None, "instances:create"),
        (Some(case.job.record.target_project_id), "instances:create"),
    ];
    ensure!(
        no_wildcard
            && saved.len() == 6
            && required.iter().all(|(p, a)| saved
                .iter()
                .filter(|g| g.1 == *p && g.2 == *a)
                .count()
                == 1),
        "actual six exact delegated scopes isolated from wildcard alternatives"
    );
    tx.commit().await?;
    let source = saved
        .iter()
        .find(|g| g.1 == Some(case.job.record.source_project_id) && g.2 == "backups:restore")
        .context("source restore scope")?
        .0;
    let tenant_read = saved
        .iter()
        .find(|g| g.1.is_none() && g.2 == "backups:read")
        .context("tenant read scope")?
        .0;
    let source_wildcard = Uuid::new_v4();
    let target_wildcard = Uuid::new_v4();
    let result=Box::pin(async {
        for (id,project,action,_) in &saved {
            let mut tx=case.source.f.base.f.owner_transaction().await?;sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND id=$2").bind(case.t).bind(id).execute(&mut *tx).await?;tx.commit().await?;
            ensure!(budget(case,Some(node)).await?.is_none()&&budget(case,None).await?.is_none(),"SELECT and RESET both require exact scope {project:?}/{action}");
            case.configure(0,Fault::None)?;case.put("select",case.changed(|_|{})?,StatusCode::FORBIDDEN).await?;
            ensure!(case.w.reads(case.pvc_path)?==0&&case.cloud.actions()?.is_empty(),"missing exact required scope refuses before any observation");
            let mut tx=case.source.f.base.f.owner_transaction().await?;sqlx::query("UPDATE grants SET enabled=true WHERE tenant_id=$1 AND id=$2").bind(case.t).bind(id).execute(&mut *tx).await?;tx.commit().await?;
        }
        let mut tx=case.source.f.base.f.owner_transaction().await?;
        sqlx::query("UPDATE grants SET expires_at=clock_timestamp()+interval '2 seconds' WHERE tenant_id=$1 AND id=$2").bind(case.t).bind(source).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO grants(id,tenant_id,principal_id,project_id,action,expires_at) VALUES($1,$2,$3,$4,'*',clock_timestamp()+interval '10 minutes')").bind(source_wildcard).bind(case.t).bind(actor).bind(case.job.record.source_project_id).execute(&mut *tx).await?;tx.commit().await?;
        ensure!(budget(case,Some(node)).await?.is_some_and(|v|v>5_000_000),"MAX uses longer exact-source alternate before MIN resource cap");
        let mut tx=case.source.f.base.f.owner_transaction().await?;sqlx::query("UPDATE grants SET expires_at=NULL WHERE tenant_id=$1 AND id=$2").bind(case.t).bind(source_wildcard).execute(&mut *tx).await?;tx.commit().await?;
        ensure!(budget(case,Some(node)).await?.is_some_and(|v|v>5_000_000),"permanent alternative acts as infinity, not missing scope");
        let mut tx=case.source.f.base.f.owner_transaction().await?;sqlx::query("UPDATE grants SET expires_at=clock_timestamp()+interval '2 seconds' WHERE tenant_id=$1 AND id=$2").bind(case.t).bind(tenant_read).execute(&mut *tx).await?;tx.commit().await?;
        ensure!(budget(case,Some(node)).await?.is_some_and(|v|v>0&&v<=2_000_000),"MIN retains a separately required tenant scope under permanent project alternate");
        let mut tx=case.source.f.base.f.owner_transaction().await?;
        let expiry=saved.iter().find(|g|g.0==tenant_read).context("saved tenant scope")?.3;
        sqlx::query("UPDATE grants SET expires_at=$3 WHERE tenant_id=$1 AND id=$2").bind(case.t).bind(tenant_read).bind(expiry).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM grants WHERE tenant_id=$1 AND id=$2").bind(case.t).bind(source_wildcard).execute(&mut *tx).await?;
        sqlx::query("UPDATE grants SET expires_at=clock_timestamp()+interval '2 seconds' WHERE tenant_id=$1 AND id=$2").bind(case.t).bind(source).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO grants(id,tenant_id,principal_id,project_id,action) VALUES($1,$2,$3,$4,'*')").bind(target_wildcard).bind(case.t).bind(actor).bind(case.job.record.target_project_id).execute(&mut *tx).await?;tx.commit().await?;
        ensure!(budget(case,Some(node)).await?.is_some_and(|v|v>0&&v<=2_000_000),"foreign target wildcard cannot extend source-project restore budget");
        let mut tx=case.source.f.base.f.owner_transaction().await?;sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND id=$2").bind(case.t).bind(source).execute(&mut *tx).await?;tx.commit().await?;
        ensure!(budget(case,Some(node)).await?.is_none(),"tenant grant and foreign-project wildcard cannot replace missing exact-source permission");
        Ok::<_,anyhow::Error>(())
    }).await;
    let mut tx = case.source.f.base.f.owner_transaction().await?;
    sqlx::query("DELETE FROM grants WHERE tenant_id=$1 AND id IN($2,$3)")
        .bind(case.t)
        .bind(source_wildcard)
        .bind(target_wildcard)
        .execute(&mut *tx)
        .await?;
    for (id, _, _, expiry) in saved {
        sqlx::query("UPDATE grants SET enabled=true,expires_at=$3 WHERE tenant_id=$1 AND id=$2")
            .bind(case.t)
            .bind(id)
            .bind(expiry)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    result?;
    ensure!(
        budget(case, Some(node)).await?.is_some() && budget(case, None).await?.is_some(),
        "normal role authority restored for remaining exact acknowledgement trials"
    );
    Ok(())
}
async fn postwait_revocation(case: &SelectedCase<'_>) -> anyhow::Result<()> {
    case.configure(0, Fault::None)?;
    let mut blocker = case.source.f.base.f.owner_transaction().await?;
    sqlx::query("SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(case.t)
        .bind(case.job.record.workspace_id)
        .fetch_one(&mut *blocker)
        .await?;
    let grant: Uuid = sqlx::query_scalar("SELECT g.id FROM grants g JOIN operations o ON o.tenant_id=g.tenant_id AND o.actor_principal_id=g.principal_id WHERE o.tenant_id=$1 AND o.id=$2 AND g.project_id=$3 AND g.action='backups:restore' AND g.enabled AND g.revoked_at IS NULL")
        .bind(case.t)
        .bind(case.job.record.operation_id)
        .bind(case.job.record.source_project_id)
        .fetch_one(&mut *blocker)
        .await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND id=$2")
        .bind(case.t)
        .bind(grant)
        .execute(&mut *blocker)
        .await?;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    let body = case.changed(|_| {})?;
    let (decision, released) = tokio::join!(
        case.put("select", body, StatusCode::FORBIDDEN),
        async {
            let mut blocked = false;
            for _ in 0..30 {
                blocked = sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND usename='sandbox_admission' AND $1=ANY(pg_blocking_pids(pid)))")
                    .bind(blocker_pid)
                    .fetch_one(&case.source.f.base.f.owner)
                    .await?;
                if blocked {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            ensure!(
                blocked,
                "actual selected admission waits on this workspace lock before committed revocation"
            );
            blocker.commit().await?;
            anyhow::Ok(())
        }
    );
    // Restore only this fixture grant even when the assertion fails. Failure
    // paths remain failures; there is no retry that changes the expected result.
    let mut tx = case.source.f.base.f.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=true WHERE tenant_id=$1 AND id=$2")
        .bind(case.t)
        .bind(grant)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    released?;
    decision?;
    ensure!(
        case.w.reads(case.pvc_path)? == 0 && case.cloud.actions()?.is_empty(),
        "post-lock source grant revocation refuses before any live workload or cloud observation"
    );
    eprintln!(
        "VERIFIED private selected source-grant revocation during an observed real workspace lock wait denies before I/O"
    );
    Ok(())
}

async fn acknowledgements(case: &SelectedCase<'_>) -> anyhow::Result<()> {
    for final_ack in [false, true] {
        ensure!(
            case.source
                .f
                .backup
                .heartbeat(case.claim)
                .await
                .map_err(api_failure)?,
            "current worker renews only its actual claim before independent ACK fault"
        );
        case.configure(0, Fault::None)?;
        let live = case
            .w
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("ACK service"))?
            .service
            .clone()
            .context("configured scheduling service")?;
        let old = case.w.get(case.pvc_path)?;
        let request = review(
            old.clone(),
            Some(old),
            "persistentvolumeclaims",
            "UPDATE",
            scheduler_user(),
        )?;
        Box::pin(admission::commit::raw_ack(
            &live,
            &request,
            &case.job.record,
            &case.source.f.base,
            final_ack,
        ))
        .await
        .context(if final_ack {
            "selected original raw final ACK case"
        } else {
            "selected original raw first ACK case"
        })?;
        if !final_ack {
            ensure!(
                case.w.reads(case.pvc_path)? == 0 && case.cloud.actions()?.is_empty(),
                "held first real COMMIT ACK crosses finite lease before any I/O"
            );
        } else {
            case.complete_rounds(true)?;
            ensure!(
                case.cloud
                    .actions()?
                    .iter()
                    .filter(|s| s.as_str() == "DescribeInstances")
                    .count()
                    == 1,
                "final ACK fault reaches real signed cloud and complete second reads"
            );
        }
    }
    ensure!(
        case.source
            .f
            .backup
            .heartbeat(case.claim)
            .await
            .map_err(api_failure)?,
        "normal current claim before final finite grant ACK"
    );
    case.configure(0, Fault::None)?;
    let live = case
        .w
        .shared
        .lock()
        .map_err(|_| anyhow::anyhow!("ACK service"))?
        .service
        .clone()
        .context("configured scheduling service")?;
    let old = case.w.get(case.pvc_path)?;
    let request = review(
        old.clone(),
        Some(old),
        "persistentvolumeclaims",
        "UPDATE",
        scheduler_user(),
    )?;
    Box::pin(admission::commit::raw_final_grant_ack(
        &live,
        &request,
        &case.job.record,
        &case.source.f.base,
    ))
    .await?;
    case.complete_rounds(true)?;
    ensure!(
        facts(&case.source.f.base.f.owner, case.t, case.r).await? == *case.baseline,
        "first/final realACK expiry denial leaves frozen source, record, holds and quota unchanged"
    );
    Ok(())
}
