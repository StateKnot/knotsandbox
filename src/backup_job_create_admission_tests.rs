//! First CAPTURE Job CREATE through normal shared admission and real PG roles.
//! Prior snapshot/clone observations are explicit synthetic CSI prerequisites;
//! this fixture is not a real CSI/cloud or installed apiserver certification.
use super::{JobPlan, SnapshotObservation, tests::Fixture};
use crate::{
    admission::{AdmissionConfig, AdmissionRequest, AdmissionService},
    backup_job::BackupJobRuntime,
    backup_manifest::{NAMESPACE, build_backup_manifests, config_name},
    backup_runtime::{BoundBackupVolume, CloneObservation, SnapshotReady},
    db::Database,
    nodeguard::protocol::{BackupStage, backup_job_name},
    runtime::KubernetesRuntime,
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
use k8s_openapi::api::{batch::v1::Job, core::v1::ConfigMap};
use kube::{
    Api,
    api::{GetParams, PostParams},
    core::Request as KubeRequest,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::oneshot;
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
enum Fault {
    Nil,
    Label,
    Selector,
    Caller,
}
#[derive(Default)]
struct StateData {
    service: Option<Arc<AdmissionService>>,
    user: Value,
    objects: BTreeMap<String, Value>,
    candidates: Vec<(Value, u16, String)>,
    targets: BTreeMap<String, usize>,
    job_posts: usize,
    job_stores: usize,
    config_posts: usize,
    config_stores: usize,
    conflicts: usize,
    fault: Option<Fault>,
    protocol_failures: Vec<&'static str>,
}
type Shared = Arc<Mutex<StateData>>;
fn response(code: StatusCode, value: Value) -> Response<Body> {
    let mut answer = Response::new(Body::from(value.to_string()));
    *answer.status_mut() = code;
    answer.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    answer
}
fn failure(code: StatusCode, reason: &str) -> Response<Body> {
    response(
        code,
        json!({"apiVersion":"v1","kind":"Status","status":"Failure",
        "reason":reason,"message":reason,"code":code.as_u16()}),
    )
}
fn prepared(mut value: Value) -> anyhow::Result<Value> {
    let is_job = value["kind"] == "Job";
    let name = value["metadata"]["name"]
        .as_str()
        .context("object name")?
        .to_owned();
    let meta = value["metadata"].as_object_mut().context("metadata")?;
    for key in [
        "uid",
        "creationTimestamp",
        "deletionTimestamp",
        "deletionGracePeriodSeconds",
        "selfLink",
    ] {
        meta.remove(key);
    }
    let uid = Uuid::new_v4();
    meta.insert("uid".into(), json!(uid));
    meta.insert(
        "creationTimestamp".into(),
        json!(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)),
    );
    if is_job {
        meta.insert("generation".into(), json!(1));
        value["status"] = json!({});
        let spec = value["spec"].as_object_mut().context("Job spec")?;
        spec.entry("manualSelector").or_insert(json!(false));
        if spec["manualSelector"] == json!(false) {
            let labels = spec["template"]["metadata"]["labels"]
                .as_object_mut()
                .context("template labels")?;
            for key in ["job-name", "batch.kubernetes.io/job-name"] {
                labels.entry(key).or_insert(json!(name));
            }
            for key in ["controller-uid", "batch.kubernetes.io/controller-uid"] {
                labels.entry(key).or_insert(json!(uid));
            }
            spec.entry("selector")
                .or_insert(json!({}))
                .as_object_mut()
                .context("selector")?
                .entry("matchLabels")
                .or_insert(json!({}))
                .as_object_mut()
                .context("matchLabels")?
                .entry("batch.kubernetes.io/controller-uid")
                .or_insert(json!(uid));
        }
    }
    Ok(value)
}
fn query_valid(method: &Method, path: &str, query: &str) -> bool {
    let expected = match path {
        "/apis/cilium.io/v2/namespaces/sandbox-system/ciliumnetworkpolicies"
        | "/apis/networking.k8s.io/v1/namespaces/sandbox-system/networkpolicies" => Some("2"),
        "/apis/cilium.io/v2/ciliumclusterwidenetworkpolicies" => Some("4"),
        _ => None,
    };
    let parts = url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
    if *method == Method::GET {
        match expected {
            Some(limit) => parts.len() == 1 && parts[0].0 == "limit" && parts[0].1 == limit,
            None => parts.is_empty(),
        }
    } else {
        parts.is_empty()
    }
}
async fn http(State(shared): State<Shared>, request: Request<Body>) -> Response<Body> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    if !query_valid(&method, &path, request.uri().query().unwrap_or_default()) {
        if let Ok(mut state) = shared.lock() {
            state.protocol_failures.push("unexpected query");
        }
        return failure(StatusCode::BAD_REQUEST, "FixtureQuery");
    }
    if method == Method::GET {
        let Ok(mut state) = shared.lock() else {
            return failure(StatusCode::INTERNAL_SERVER_ERROR, "FixtureState");
        };
        *state.targets.entry(path.clone()).or_default() += 1;
        return state.objects.get(&path).cloned().map_or_else(
            || failure(StatusCode::NOT_FOUND, "NotFound"),
            |v| response(StatusCode::OK, v),
        );
    }
    let is_job = path == format!("/apis/batch/v1/namespaces/{NAMESPACE}/jobs");
    let is_config = path == format!("/api/v1/namespaces/{NAMESPACE}/configmaps");
    if method != Method::POST || !(is_job || is_config) {
        if let Ok(mut state) = shared.lock() {
            state.protocol_failures.push("unexpected mutation");
        }
        return failure(StatusCode::METHOD_NOT_ALLOWED, "FixtureMethod");
    }
    let bytes = match to_bytes(request.into_body(), 131072).await {
        Ok(b) => b,
        Err(_) => return failure(StatusCode::BAD_REQUEST, "FixtureBody"),
    };
    let mut candidate = match serde_json::from_slice::<Value>(&bytes)
        .map_err(anyhow::Error::from)
        .and_then(prepared)
    {
        Ok(v) => v,
        Err(_) => return failure(StatusCode::BAD_REQUEST, "FixturePreparation"),
    };
    let (service, mut user, fault) = {
        let Ok(mut state) = shared.lock() else {
            return failure(StatusCode::INTERNAL_SERVER_ERROR, "FixtureState");
        };
        if is_job {
            state.job_posts += 1;
        } else {
            state.config_posts += 1;
        }
        (
            state.service.clone(),
            state.user.clone(),
            if is_job { state.fault.take() } else { None },
        )
    };
    match fault {
        Some(Fault::Nil) => candidate["metadata"]["uid"] = json!(Uuid::nil()),
        Some(Fault::Label) => {
            candidate["spec"]["template"]["metadata"]["labels"]["controller-uid"] =
                json!(Uuid::new_v4())
        }
        Some(Fault::Selector) => {
            candidate["spec"]["selector"]["matchLabels"]["batch.kubernetes.io/controller-uid"] =
                json!(Uuid::new_v4())
        }
        Some(Fault::Caller) => user["uid"] = json!(Uuid::new_v4()),
        None => {}
    }
    let Some(service) = service else {
        return failure(StatusCode::INTERNAL_SERVER_ERROR, "FixtureService");
    };
    let resource = if is_job { "jobs" } else { "configmaps" };
    let review: AdmissionRequest = match serde_json::from_value(json!({"uid":Uuid::new_v4(),
        "resource":{"group":if is_job {"batch"} else {""},"version":"v1","resource":resource},
        "operation":"CREATE","namespace":NAMESPACE,"name":candidate["metadata"]["name"],
        "object":candidate,"userInfo":user}))
    {
        Ok(r) => r,
        Err(_) => return failure(StatusCode::INTERNAL_SERVER_ERROR, "FixtureReview"),
    };
    let result =
        tokio::time::timeout(Duration::from_secs(4), Box::pin(service.decide(&review))).await;
    let (code, message) = match result {
        Ok(Ok(())) => (200, String::new()),
        Ok(Err(d)) => (d.code, d.message.to_owned()),
        Err(_) => (504, "FixtureDecisionTimeout".into()),
    };
    let candidate = review.object.unwrap_or(Value::Null);
    {
        let Ok(mut state) = shared.lock() else {
            return failure(StatusCode::INTERNAL_SERVER_ERROR, "FixtureState");
        };
        if is_job {
            state
                .candidates
                .push((candidate.clone(), code, message.clone()));
        }
    }
    if code != 200 {
        return failure(
            StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            &message,
        );
    }
    let Some(name) = candidate["metadata"]["name"].as_str() else {
        return failure(StatusCode::INTERNAL_SERVER_ERROR, "FixtureName");
    };
    let item = format!("{path}/{name}");
    let Ok(mut state) = shared.lock() else {
        return failure(StatusCode::INTERNAL_SERVER_ERROR, "FixtureState");
    };
    if state.objects.contains_key(&item) {
        state.conflicts += 1;
        return failure(StatusCode::CONFLICT, "AlreadyExists");
    }
    let mut stored = candidate;
    stored["metadata"]["resourceVersion"] = json!("101");
    state.objects.insert(item, stored.clone());
    if is_job {
        state.job_stores += 1;
    } else {
        state.config_stores += 1;
    }
    response(StatusCode::CREATED, stored)
}
struct Server {
    shared: Shared,
    client: kube::Client,
    runtime: BackupJobRuntime,
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl Server {
    async fn new(
        database: Database,
        config: AdmissionConfig,
        objects: BTreeMap<String, Value>,
    ) -> anyhow::Result<Self> {
        let shared = Arc::new(Mutex::new(StateData {
            objects,
            user: json!({"username":config.backup.as_ref().context("backup identities")?.controller.username,
            "uid":config.backup.as_ref().context("backup identities")?.controller.uid}),
            ..StateData::default()
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let client =
            kube::Client::try_from(kube::Config::new(format!("http://{address}").parse()?))?;
        let runtime = BackupJobRuntime::new(KubernetesRuntime::from_client(client.clone()));
        shared
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture state"))?
            .service = Some(Arc::new(AdmissionService {
            database,
            kubernetes: client.clone(),
            config,
        }));
        let (stop, shutdown) = oneshot::channel();
        let state = shared.clone();
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().fallback(any(http)).with_state(state),
            )
            .with_graceful_shutdown(async move {
                let _ = shutdown.await;
            })
            .await
        });
        Ok(Self {
            shared,
            client,
            runtime,
            stop: Some(stop),
            task: Some(task),
        })
    }
    async fn finish(mut self) -> anyhow::Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let task = self.task.as_mut().context("owned HTTP task")?;
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .context("HTTP server drain deadline")?
            .context("HTTP server task join")?
            .context("HTTP serve failure")?;
        self.task.take();
        Ok(())
    }
    fn fault(&self, fault: Fault) -> anyhow::Result<()> {
        self.shared
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture state"))?
            .fault = Some(fault);
        Ok(())
    }
    async fn actual(&self, url: &str, name: &str) -> anyhow::Result<Value> {
        let request = KubeRequest::new(url).get(name, &GetParams::default())?;
        Ok(self.client.request(request).await?)
    }
}
fn config() -> anyhow::Result<AdmissionConfig> {
    let config: AdmissionConfig = serde_json::from_value(json!({
        "gateway":{"username":"system:serviceaccount:sandbox-system:sandbox-gateway","uid":Uuid::new_v4()},
        "termination":{"username":"system:serviceaccount:sandbox-system:sandbox-termination","uid":Uuid::new_v4()},
        "worker":{"username":"system:serviceaccount:sandbox-system:sandbox-worker","uid":Uuid::new_v4()},
        "namespace_provisioner":{"username":"system:serviceaccount:sandbox-system:namespace-provisioner","uid":Uuid::new_v4()},
        "backup":{"controller":{"username":"system:serviceaccount:sandbox-system:sandbox-backup-controller","uid":Uuid::new_v4()},"job_controller":{"kind":"control_plane","username":"system:kube-controller-manager"}},
        "scheduler":{"kind":"control_plane","username":"system:kube-scheduler"},
        "storage_controllers":[{"kind":"service_account","username":"system:serviceaccount:kube-system:csi-provisioner","uid":Uuid::new_v4()}],
        "policy_status_controllers":[{"kind":"service_account","username":"system:serviceaccount:kube-system:cilium","uid":Uuid::new_v4()}],
        "namespace_status_controllers":[{"kind":"control_plane","username":"system:kube-controller-manager"}],
        "pod_garbage_collectors":[{"kind":"control_plane","username":"system:kube-controller-manager"}],
        "storage_provisioner":"diskplugin.csi.alibabacloud.com","certification_id":"test-only-backup-job-create",
        "dns_namespace":"kube-system","dns_labels":{"k8s-app":"kube-dns"},"ephemeral_storage_mib":1024,"tmp_size_mib":256
    }))?;
    config.validate()?;
    Ok(config)
}
async fn capture_plan(f: &Fixture) -> anyhow::Result<(super::Claim, JobPlan, BoundBackupVolume)> {
    let accepted = f
        .accept("first-capture-job-create")
        .await
        .map_err(api_failure)?;
    let claim = f.claim(accepted.body.operation.id).await?;
    let storage = Box::pin(f.backup.database.prepare_backup_storage(&f.backup, &claim))
        .await
        .map_err(api_failure)?;
    // Synthetic CSI preconditions use normal recording methods. They are not
    // Job bindings and do not attest an actual snapshot or cloud disk exists.
    let snapshot_uid = Uuid::new_v4();
    let snapshot = SnapshotObservation {
        snapshot_uid,
        ready: Some(SnapshotReady {
            snapshot_uid,
            content_uid: Uuid::new_v4(),
            content_name: "snapcontent-job-create-fixture".into(),
            cloud_snapshot: "s-firstcapture".into(),
            created_at: Utc::now() - Days::seconds(1),
            restore_size: storage.source.size_bytes,
        }),
    };
    Box::pin(
        f.backup
            .database
            .record_backup_snapshot(&f.backup, &claim, &snapshot),
    )
    .await
    .map_err(api_failure)?;
    Box::pin(f.backup.database.prepare_backup_storage(&f.backup, &claim))
        .await
        .map_err(api_failure)?;
    let volume = BoundBackupVolume {
        pvc_uid: Uuid::new_v4(),
        pv_uid: Uuid::new_v4(),
        pv_name: format!("pvc-{}", Uuid::new_v4()),
        cloud_disk: "d-capturefixture".into(),
        size_bytes: storage.source.size_bytes,
    };
    Box::pin(f.backup.database.record_backup_clone(
        &f.backup,
        &claim,
        &CloneObservation {
            delegated_content_uid: Uuid::new_v4(),
            delegated_snapshot_uid: Uuid::new_v4(),
            pvc_uid: volume.pvc_uid,
            bound: Some(volume.clone()),
        },
    ))
    .await
    .map_err(api_failure)?;
    let plan = Box::pin(f.backup.database.prepare_backup_job(&f.backup, &claim))
        .await
        .map_err(api_failure)?;
    ensure!(
        plan.context.stage == BackupStage::Capture
            && plan.backup.status == "CAPTURE_PENDING"
            && plan.known_config.is_none()
            && plan.known_job.is_none()
            && plan.known_pod.is_none(),
        "first Capture intent must have no future Job/config/Pod binding"
    );
    Ok((claim, plan, volume))
}
async fn unchanged_facts(database: &Database, plan: &JobPlan) -> anyhow::Result<Value> {
    let mut tx = database
        .begin(plan.backup.tenant_id)
        .await
        .map_err(api_failure)?;
    let facts:Value=sqlx::query_scalar("SELECT jsonb_build_object('backup',to_jsonb(b),'source_instance',(SELECT to_jsonb(i) FROM instances i WHERE i.tenant_id=b.tenant_id AND i.id=b.instance_id),'source_workspace',(SELECT to_jsonb(w) FROM workspaces w WHERE w.tenant_id=b.tenant_id AND w.id=b.workspace_id),'holds',(SELECT jsonb_agg(to_jsonb(h) ORDER BY h.id) FROM workspace_holds h WHERE h.tenant_id=b.tenant_id AND h.id=b.hold_id),'releases',(SELECT count(*) FROM workspace_hold_releases h WHERE h.tenant_id=b.tenant_id AND h.hold_id=b.hold_id),'reservations',(SELECT jsonb_agg(to_jsonb(r) ORDER BY r.quota_account_id) FROM quota_reservations r WHERE r.tenant_id=b.tenant_id AND r.operation_id=b.operation_id),'quotas',(SELECT jsonb_agg(to_jsonb(q) ORDER BY q.id) FROM quota_accounts q WHERE q.tenant_id=b.tenant_id),'pod_admissions',(SELECT count(*) FROM backup_pod_admissions a WHERE a.tenant_id=b.tenant_id AND a.backup_id=b.id),'permits',(SELECT count(*) FROM backup_launch_permits p WHERE p.tenant_id=b.tenant_id AND p.backup_id=b.id),'proofs',(SELECT count(*) FROM backup_termination_proofs p WHERE p.tenant_id=b.tenant_id AND p.backup_id=b.id),'cleanup',(SELECT count(*) FROM backup_cleanup_receipts c WHERE c.tenant_id=b.tenant_id AND c.backup_id=b.id)) FROM backups b WHERE b.tenant_id=$1 AND b.id=$2")
        .bind(plan.backup.tenant_id).bind(plan.backup.id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(facts)
}
async fn job_bindings(database: &Database, plan: &JobPlan) -> anyhow::Result<Vec<(String, Uuid)>> {
    let mut tx = database
        .begin(plan.backup.tenant_id)
        .await
        .map_err(api_failure)?;
    let rows=sqlx::query_as("SELECT i.kind,b.uid FROM backup_resource_intents i JOIN backup_resource_bindings b ON b.tenant_id=i.tenant_id AND b.intent_id=i.id WHERE i.tenant_id=$1 AND i.backup_id=$2 AND i.attempt_id=$3 AND i.kind IN('CONFIG','JOB','POD') ORDER BY i.kind")
        .bind(plan.backup.tenant_id).bind(plan.backup.id).bind(plan.context.attempt_id).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    Ok(rows)
}
async fn run(
    f: &Fixture,
    claim: &super::Claim,
    plan: &JobPlan,
    server: &Server,
) -> anyhow::Result<()> {
    let before = unchanged_facts(&f.backup.database, plan).await?;
    ensure!(
        before["source_instance"].is_object() && before["source_workspace"].is_object(),
        "source preservation must compare actual RLS-visible source rows"
    );
    for field in ["releases", "pod_admissions", "permits", "proofs", "cleanup"] {
        ensure!(
            before[field] == json!(0),
            "first CAPTURE CREATE setup cannot have future authority or completion: {field}"
        );
    }
    ensure!(
        before["holds"].as_array().is_some_and(|h| h.len() == 1)
            && before["reservations"]
                .as_array()
                .is_some_and(|r| !r.is_empty()),
        "normal backup hold and reservations must exist before first CREATE"
    );
    ensure!(
        job_bindings(&f.backup.database, plan).await?.is_empty(),
        "no seeded Job/config/Pod binding"
    );
    let observed = Box::pin(server.runtime.ensure_job(&plan.context, None, None)).await?;
    let again = Box::pin(server.runtime.ensure_job(
        &plan.context,
        Some(observed.0),
        Some(observed.1),
    ))
    .await?;
    ensure!(
        again == observed,
        "actual GET identity must remain stable before normal record"
    );
    let jobs = Api::<Job>::namespaced(server.client.clone(), NAMESPACE);
    let configs = Api::<ConfigMap>::namespaced(server.client.clone(), NAMESPACE);
    let job_name = backup_job_name(plan.context.attempt_id, plan.context.stage);
    let config_name = config_name(plan.context.attempt_id);
    let actual = server.actual(jobs.resource_url(), &job_name).await?;
    let actual_config = server.actual(configs.resource_url(), &config_name).await?;
    ensure!(
        actual["metadata"]["uid"] == json!(observed.1)
            && actual_config["metadata"]["uid"] == json!(observed.0)
            && actual["metadata"]["resourceVersion"] == "101"
            && actual_config["metadata"]["resourceVersion"] == "101"
            && actual["spec"]["suspend"] == json!(true),
        "literal GET fields must equal actual ensure result"
    );
    let manifests = build_backup_manifests(&plan.context)?;
    let body: Job = serde_json::from_value(manifests.job.clone())?;
    let conflict = jobs
        .create(&PostParams::default(), &body)
        .await
        .err()
        .context("same-name conflict")?;
    ensure!(
        matches!(conflict,kube::Error::Api(ref e) if e.code==409),
        "unbound prospective retry reaches AlreadyExists"
    );
    for (fault, expected) in [
        (
            Fault::Nil,
            "Job CREATE requires canonical server candidate UID",
        ),
        (
            Fault::Label,
            "Job CREATE generated controller UID label changed",
        ),
        (Fault::Selector, "Job CREATE generated selector changed"),
        (
            Fault::Caller,
            "Only the exact backup controller may manage Jobs",
        ),
    ] {
        server.fault(fault)?;
        let denied = jobs
            .create(&PostParams::default(), &body)
            .await
            .err()
            .context("fault must deny")?;
        ensure!(
            matches!(denied,kube::Error::Api(ref e) if e.code==403),
            "fault {fault:?} must reach actual policy denial"
        );
        let state = server
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture state"))?;
        ensure!(
            state
                .candidates
                .last()
                .is_some_and(|v| v.1 == 403 && v.2 == expected),
            "fault {fault:?} must hit intended guard"
        );
    }
    ensure!(
        unchanged_facts(&f.backup.database, plan).await? == before
            && job_bindings(&f.backup.database, plan).await?.is_empty(),
        "candidate admission must not write identity or release hold/quota"
    );
    {
        let state = server
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture state"))?;
        ensure!(
            state.job_posts == 6
                && state.job_stores == 1
                && state.config_posts == 1
                && state.config_stores == 1
                && state.conflicts == 1
                && state.candidates.len() == 6
                && state.candidates[0].1 == 200
                && state.candidates[1].1 == 200
                && state.candidates[2..].iter().all(|v| v.1 == 403),
            "all real prepared CREATE attempts must be accounted"
        );
        ensure!(
            state.candidates[0].0["metadata"]["uid"] == json!(observed.1)
                && state.candidates[1].0["metadata"]["uid"] != json!(observed.1)
                && state
                    .candidates
                    .iter()
                    .all(|v| v.0.pointer("/metadata/resourceVersion").is_none()),
            "only stored winner is observed; no CREATE candidate has a storage RV"
        );
        for name in [
            format!("{}/{}", jobs.resource_url(), job_name),
            format!("{}/{}", configs.resource_url(), config_name),
        ] {
            ensure!(
                state.targets.get(&name) == Some(&3),
                "initial404 plus two real GETs expected for {name}"
            );
        }
        let dependencies=[
            format!("/apis/cilium.io/v2/namespaces/{NAMESPACE}/ciliumnetworkpolicies/sandbox-backup-egress"),
            format!("/apis/cilium.io/v2/namespaces/{NAMESPACE}/ciliumnetworkpolicies"),
            format!("/apis/networking.k8s.io/v1/namespaces/{NAMESPACE}/networkpolicies/sandbox-backup-default-deny"),
            format!("/apis/networking.k8s.io/v1/namespaces/{NAMESPACE}/networkpolicies"),
            "/apis/cilium.io/v2/ciliumclusterwidenetworkpolicies".into(),
            "/apis/node.k8s.io/v1/runtimeclasses/kata-backup-qemu".into(),
            "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/sandbox-runtime-protection".into(),
        ];
        for path in dependencies.into_iter().chain(
            plan.cloud
                .secret_bindings
                .entries()
                .into_iter()
                .map(|(_, _, b)| format!("/api/v1/namespaces/{NAMESPACE}/secrets/{}", b.name)),
        ) {
            ensure!(
                state.targets.get(&path) == Some(&7),
                "every seven prepared shared decisions must reach exact dependency {path}"
            );
        }
        ensure!(
            state.protocol_failures.is_empty(),
            "HTTP protocol mismatch cannot count as coverage"
        );
    }
    Box::pin(f.backup.database.record_backup_job_objects(
        &f.backup,
        claim,
        plan.context.attempt_id,
        observed.0,
        observed.1,
    ))
    .await
    .map_err(api_failure)?;
    let refetched = Box::pin(f.backup.database.prepare_backup_job(&f.backup, claim))
        .await
        .map_err(api_failure)?;
    ensure!(
        refetched.known_config == Some(observed.0)
            && refetched.known_job == Some(observed.1)
            && refetched.known_pod.is_none(),
        "normal record/refetch must bind actual GET identities only"
    );
    ensure!(
        job_bindings(&f.backup.database, plan).await?
            == vec![("CONFIG".into(), observed.0), ("JOB".into(), observed.1)],
        "RLS-visible exact attempt bindings must match actual GETs"
    );
    ensure!(
        unchanged_facts(&f.backup.database, plan).await? == before,
        "identity recording must not change source/hold/quota or mint permits"
    );
    let replaced = prepared(manifests.job)?;
    {
        let mut state = server
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture state"))?;
        let mut stored = replaced;
        stored["metadata"]["resourceVersion"] = json!("102");
        state
            .objects
            .insert(format!("{}/{}", jobs.resource_url(), job_name), stored);
    }
    ensure!(
        Box::pin(server.runtime.ensure_job(
            &plan.context,
            refetched.known_config,
            refetched.known_job
        ))
        .await
        .is_err(),
        "coherent observed replacement cannot replace durable Job UID"
    );
    ensure!(
        job_bindings(&f.backup.database, plan).await?
            == vec![("CONFIG".into(), observed.0), ("JOB".into(), observed.1)],
        "replacement GET cannot rewrite ledger"
    );
    Ok(())
}
async fn capture() -> anyhow::Result<()> {
    let verified = test_support_db::Fixture::prepare_verified_connections().await?;
    for sql in [
        include_str!("../scripts/sql/termination-role.sql"),
        include_str!("../scripts/sql/admission-role.sql"),
        include_str!("../scripts/sql/backup-role.sql"),
    ] {
        sqlx::raw_sql(sql).execute(&verified.owner()).await?;
    }
    let termination = verified
        .runtime("TEST_TERMINATION_DATABASE_URL", "sandbox_termination", 4)
        .await?;
    let backup = verified
        .runtime("TEST_BACKUP_DATABASE_URL", "sandbox_backup", 4)
        .await?;
    let admission = verified
        .runtime("TEST_ADMISSION_DATABASE_URL", "sandbox_admission", 4)
        .await?;
    let admission = admission.database_for("sandbox_admission")?;
    let (session, current): (String, String) =
        sqlx::query_as("SELECT session_user::text,current_user::text")
            .fetch_one(&admission.pool)
            .await?;
    ensure!(
        session == "sandbox_admission" && current == "sandbox_admission",
        "exact narrow shared admission login required"
    );
    let f = Box::pin(Fixture::new_with_verified_connections(
        true,
        &verified,
        &termination,
        &backup,
    ))
    .await?;
    let (claim, plan, volume) = Box::pin(capture_plan(&f)).await?;
    let placeholder = json!({"metadata":{"name":"never-created-placeholder"}});
    let (objects, _) =
        super::pipeline_tests::runtime_objects(&plan, &volume, &f.base.node, &placeholder)?;
    let mut objects = objects
        .lock()
        .map_err(|_| anyhow::anyhow!("fixture objects"))?
        .clone();
    objects.remove(&format!(
        "/api/v1/namespaces/{NAMESPACE}/pods/never-created-placeholder"
    ));
    ensure!(
        !objects.keys().any(|p| p
            .starts_with(&format!("/apis/batch/v1/namespaces/{NAMESPACE}/jobs"))
            || p.starts_with(&format!(
                "/api/v1/namespaces/{NAMESPACE}/configmaps/{}",
                config_name(plan.context.attempt_id)
            ))
            || p.starts_with(&format!("/api/v1/namespaces/{NAMESPACE}/pods/"))),
        "no target control or future Pod object may be seeded"
    );
    let server = Box::pin(Server::new(admission, config()?, objects)).await?;
    let outcome = Box::pin(run(&f, &claim, &plan, &server)).await;
    let drained = server.finish().await;
    match (outcome, drained) {
        (Ok(()), Ok(())) => {}
        (Err(business), Err(drain)) => anyhow::bail!(
            "business failure: {business:#}; independent HTTP drain failure: {drain:#}"
        ),
        (Err(e), Ok(())) | (Ok(()), Err(e)) => return Err(e),
    }
    eprintln!(
        "VERIFIED first CAPTURE Job CREATE normal37/actual narrow-role shared AdmissionService+TCP prepared-object Allow then storage, GET identities then normal record/refetch; before normal record, admitted candidates create no ledger Job/config/Pod binding, permit, proof, or hold release. CSI prerequisites are synthetic; SEAL and installed cloud/apiserver remain untested by this case"
    );
    Ok(())
}
#[tokio::test]
#[ignore = "requires fresh normally migrated PostgreSQL and exact component logins"]
async fn capture_first_job_create_shared_admission_then_actual_get_and_normal_record()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    Box::pin(capture()).await
}

#[path = "backup_job_seal_create_admission_tests.rs"]
mod seal_tests;
