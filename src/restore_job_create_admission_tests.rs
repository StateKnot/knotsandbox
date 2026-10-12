//! PRIVATE prepared Job CREATE regression. The TCP apiserver is a stand-in,
//! not an installed Kubernetes certification. No submitted UID is bound here.
use super::{JobPlan, RestoreAdmissionService};
use crate::{
    admission::AdmissionRequest,
    backup_job::BackupJobRuntime,
    backup_manifest::{NAMESPACE, build_backup_manifests},
    runtime::KubernetesRuntime,
};
use anyhow::{Context, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Method, Request, Response, StatusCode},
    routing::any,
};
use chrono::{SecondsFormat, Utc};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::oneshot;
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
enum CandidateFault {
    Nil,
    Label,
    Selector,
}
#[derive(Default)]
struct CreateState {
    service: Option<RestoreAdmissionService>,
    user: Value,
    objects: BTreeMap<String, Value>,
    path: String,
    config_path: String,
    candidates: Vec<(Value, u16)>,
    posts: usize,
    stores: usize,
    reads: usize,
    config_posts: usize,
    config_stores: usize,
    config_reads: usize,
    conflicts: usize,
    dependency_reads: usize,
    job_not_found_reads: usize,
    config_not_found_reads: usize,
    targets: BTreeMap<String, usize>,
    fault: Option<CandidateFault>,
    protocol_failures: Vec<&'static str>,
}
type Shared = Arc<Mutex<CreateState>>;
fn response(status: StatusCode, value: Value) -> Response<Body> {
    let mut answer = Response::new(Body::from(value.to_string()));
    *answer.status_mut() = status;
    answer.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    answer
}
fn failure(status: StatusCode, reason: &str) -> Response<Body> {
    response(
        status,
        json!({"apiVersion":"v1","kind":"Status","status":"Failure",
            "reason":reason,"message":reason,"code":status.as_u16()}),
    )
}

/// Emulates only the relevant pinned v1.36.4 create preparation. UID/time are
/// server generated, status is reset, automatic selector labels are generated
/// before validating admission. No resourceVersion exists until storage.
fn prepare(mut candidate: Value) -> anyhow::Result<Value> {
    let is_job = candidate.get("kind") == Some(&json!("Job"));
    let name = candidate["metadata"]["name"]
        .as_str()
        .context("fixed Job name")?
        .to_owned();
    let metadata = candidate["metadata"]
        .as_object_mut()
        .context("Job metadata")?;
    for field in [
        "creationTimestamp",
        "uid",
        "deletionTimestamp",
        "deletionGracePeriodSeconds",
        "selfLink",
    ] {
        metadata.remove(field);
    }
    let uid = Uuid::new_v4();
    metadata.insert("uid".into(), json!(uid));
    metadata.insert(
        "creationTimestamp".into(),
        json!(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)),
    );
    if !is_job {
        return Ok(candidate);
    }
    metadata.insert("generation".into(), json!(1));
    candidate["status"] = json!({});
    let spec = candidate["spec"].as_object_mut().context("Job spec")?;
    spec.entry("manualSelector").or_insert(json!(false));
    if spec["manualSelector"] == json!(false) {
        let labels = spec["template"]["metadata"]["labels"]
            .as_object_mut()
            .context("Job template labels")?;
        for key in ["job-name", "batch.kubernetes.io/job-name"] {
            labels.entry(key).or_insert(json!(name));
        }
        for key in ["controller-uid", "batch.kubernetes.io/controller-uid"] {
            labels.entry(key).or_insert(json!(uid));
        }
        let selector = spec.entry("selector").or_insert(json!({}));
        let match_labels = selector
            .as_object_mut()
            .context("Job selector")?
            .entry("matchLabels")
            .or_insert(json!({}))
            .as_object_mut()
            .context("Job matchLabels")?;
        match_labels
            .entry("batch.kubernetes.io/controller-uid")
            .or_insert(json!(uid));
    }
    Ok(candidate)
}

async fn http(State(shared): State<Shared>, request: Request<Body>) -> Response<Body> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or_default();
    let expected_limit = match path.as_str() {
        "/apis/cilium.io/v2/namespaces/sandbox-system/ciliumnetworkpolicies"
        | "/apis/networking.k8s.io/v1/namespaces/sandbox-system/networkpolicies" => Some("2"),
        "/apis/cilium.io/v2/ciliumclusterwidenetworkpolicies" => Some("4"),
        _ => None,
    };
    let query_valid = if method == Method::GET {
        match expected_limit {
            Some(limit) => query == format!("&limit={limit}"),
            None => query.is_empty(),
        }
    } else {
        query.is_empty()
    };
    if !query_valid {
        if let Ok(mut state) = shared.lock() {
            state.protocol_failures.push("unexpected request query");
        }
        return failure(StatusCode::BAD_REQUEST, "FixtureProtocol");
    }
    if method == Method::GET {
        let Ok(mut state) = shared.lock() else {
            return failure(StatusCode::INTERNAL_SERVER_ERROR, "FixtureState");
        };
        *state.targets.entry(path.clone()).or_default() += 1;
        if path == state.path {
            state.reads += 1;
            if !state.objects.contains_key(&path) {
                state.job_not_found_reads += 1;
            }
        } else if path == state.config_path {
            state.config_reads += 1;
            if !state.objects.contains_key(&path) {
                state.config_not_found_reads += 1;
            }
        } else {
            state.dependency_reads += 1;
        }
        return state.objects.get(&path).cloned().map_or_else(
            || failure(StatusCode::NOT_FOUND, "NotFound"),
            |value| response(StatusCode::OK, value),
        );
    }
    let is_job = path == format!("/apis/batch/v1/namespaces/{NAMESPACE}/jobs");
    let is_config = path == format!("/api/v1/namespaces/{NAMESPACE}/configmaps");
    if method != Method::POST || !(is_job || is_config) {
        if let Ok(mut state) = shared.lock() {
            state.protocol_failures.push("unexpected mutable request");
        }
        return failure(StatusCode::METHOD_NOT_ALLOWED, "FixtureProtocol");
    }
    let bytes = match to_bytes(request.into_body(), 131_072).await {
        Ok(value) => value,
        Err(_) => return failure(StatusCode::BAD_REQUEST, "FixtureBody"),
    };
    let mut candidate = match serde_json::from_slice::<Value>(&bytes)
        .map_err(anyhow::Error::from)
        .and_then(prepare)
    {
        Ok(value) => value,
        Err(_) => return failure(StatusCode::BAD_REQUEST, "FixturePreparation"),
    };
    let (service, user, fault) = {
        let Ok(mut state) = shared.lock() else {
            return failure(StatusCode::INTERNAL_SERVER_ERROR, "FixtureState");
        };
        if is_job {
            state.posts += 1;
        } else {
            state.config_posts += 1;
        }
        (
            state.service.clone(),
            state.user.clone(),
            if is_job { state.fault } else { None },
        )
    };
    // Defense-in-depth negative bodies are explicitly post-preparation faults;
    // they do not claim that builtin Kubernetes validation would permit them.
    match fault {
        Some(CandidateFault::Nil) => candidate["metadata"]["uid"] = json!(Uuid::nil()),
        Some(CandidateFault::Label) => {
            candidate["spec"]["template"]["metadata"]["labels"]["controller-uid"] =
                json!(Uuid::new_v4());
        }
        Some(CandidateFault::Selector) => {
            candidate["spec"]["selector"]["matchLabels"]["batch.kubernetes.io/controller-uid"] =
                json!(Uuid::new_v4());
        }
        None => {}
    }
    let Some(service) = service else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "FixtureNotConfigured");
    };
    let reviewed: AdmissionRequest = match serde_json::from_value(json!({
        "uid":Uuid::new_v4(),"resource":{"group":if is_job {"batch"} else {""},"version":"v1","resource":if is_job {"jobs"} else {"configmaps"}},
        "namespace":NAMESPACE,"name":candidate["metadata"]["name"],"operation":"CREATE",
        "object":candidate,"userInfo":user
    })) {
        Ok(value) => value,
        Err(_) => return failure(StatusCode::BAD_REQUEST, "FixtureReview"),
    };
    let result =
        tokio::time::timeout(Duration::from_secs(4), Box::pin(service.decide(&reviewed))).await;
    let code = match result {
        Ok(Ok(())) => 200,
        Ok(Err(denial)) => denial.code,
        Err(_) => 503,
    };
    let Ok(mut state) = shared.lock() else {
        return failure(StatusCode::INTERNAL_SERVER_ERROR, "FixtureState");
    };
    let candidate = reviewed.object.unwrap_or(Value::Null);
    if is_job {
        state.candidates.push((candidate.clone(), code));
    }
    if code != 200 {
        return failure(
            StatusCode::from_u16(code).unwrap_or(StatusCode::FORBIDDEN),
            "AdmissionDenied",
        );
    }
    let key = if is_job {
        state.path.clone()
    } else {
        state.config_path.clone()
    };
    if state.objects.contains_key(&key) {
        if is_job {
            state.conflicts += 1;
        }
        return failure(StatusCode::CONFLICT, "AlreadyExists");
    }
    let mut stored = candidate;
    stored["metadata"]["resourceVersion"] = json!("101");
    if is_job {
        state.stores += 1;
    } else {
        state.config_stores += 1;
    }
    state.objects.insert(key, stored.clone());
    response(StatusCode::CREATED, stored)
}

struct Server {
    base: String,
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}
impl Server {
    async fn start(shared: Shared) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().fallback(any(http)).with_state(shared),
            )
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
        });
        Ok(Self {
            base,
            stop: Some(stop),
            task: Some(task),
        })
    }
    async fn finish(mut self) -> anyhow::Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.as_mut() {
            tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .context(
                    "prepared CREATE server drain failed; Drop abort is not a drain certificate",
                )???;
        }
        self.task.take();
        Ok(())
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn facts(owner: &sqlx::PgPool, plan: &JobPlan) -> anyhow::Result<Value> {
    let mut tx = owner.begin().await?;
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(plan.record.tenant_id.to_string())
        .execute(&mut *tx)
        .await?;
    let value = sqlx::query_scalar("SELECT jsonb_build_object('restore',to_jsonb(r),'bindings',COALESCE((SELECT jsonb_agg(to_jsonb(b) ORDER BY b.intent_id) FROM restore_resource_bindings b WHERE b.tenant_id=r.tenant_id AND b.restore_id=r.id),'[]'::jsonb),'job_bindings',(SELECT count(*) FROM restore_resource_bindings b JOIN restore_resource_intents i ON i.tenant_id=b.tenant_id AND i.id=b.intent_id WHERE b.tenant_id=r.tenant_id AND b.restore_id=r.id AND i.kind='JOB'),'config_bindings',(SELECT count(*) FROM restore_resource_bindings b JOIN restore_resource_intents i ON i.tenant_id=b.tenant_id AND i.id=b.intent_id WHERE b.tenant_id=r.tenant_id AND b.restore_id=r.id AND i.kind='CONFIG'),'pod_reviews',(SELECT count(*) FROM restore_pod_admissions p WHERE p.tenant_id=r.tenant_id AND p.restore_id=r.id),'permits',(SELECT count(*) FROM restore_launch_permits p WHERE p.tenant_id=r.tenant_id AND p.restore_id=r.id),'holds',COALESCE((SELECT jsonb_agg(to_jsonb(h) ORDER BY h.id) FROM workspace_holds h WHERE h.tenant_id=r.tenant_id AND h.workspace_id=r.workspace_id),'[]'::jsonb),'hold_releases',COALESCE((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.hold_id) FROM workspace_hold_releases x JOIN workspace_holds h ON h.tenant_id=x.tenant_id AND h.id=x.hold_id WHERE h.tenant_id=r.tenant_id AND h.workspace_id=r.workspace_id),'[]'::jsonb),'quota_accounts',COALESCE((SELECT jsonb_agg(to_jsonb(q) ORDER BY q.id) FROM quota_accounts q WHERE q.tenant_id=r.tenant_id),'[]'::jsonb),'quota_reservations',COALESCE((SELECT jsonb_agg(to_jsonb(q) ORDER BY q.id) FROM quota_reservations q WHERE q.tenant_id=r.tenant_id),'[]'::jsonb)) FROM restores r WHERE r.tenant_id=$1 AND r.id=$2")
        .bind(plan.record.tenant_id).bind(plan.record.id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(value)
}

pub(super) async fn verify(
    service: &RestoreAdmissionService,
    plan: &JobPlan,
    owner: &sqlx::PgPool,
    dependencies: &Arc<Mutex<BTreeMap<String, Value>>>,
) -> anyhow::Result<(Uuid, Uuid)> {
    let before = facts(owner, plan).await?;
    ensure!(
        before["job_bindings"] == json!(0)
            && before["config_bindings"] == json!(0)
            && before["pod_reviews"] == json!(0)
            && before["permits"] == json!(0),
        "normal unbound CREATE checkpoint required"
    );
    let manifests = build_backup_manifests(&plan.context)?;
    let job = manifests.job;
    let config_map = manifests.config_map;
    let path = format!(
        "/apis/batch/v1/namespaces/{NAMESPACE}/jobs/{}",
        job["metadata"]["name"].as_str().context("Job name")?
    );
    let config_path = format!(
        "/api/v1/namespaces/{NAMESPACE}/configmaps/{}",
        config_map["metadata"]["name"]
            .as_str()
            .context("Config name")?
    );
    let mut objects = dependencies
        .lock()
        .map_err(|_| anyhow::anyhow!("dependency fixture lock"))?
        .clone();
    objects.remove(&path);
    objects.remove(&config_path);
    let shared = Arc::new(Mutex::new(CreateState {
        objects,
        path: path.clone(),
        config_path: config_path.clone(),
        user: super::user(service),
        ..Default::default()
    }));
    let server = Server::start(shared.clone()).await?;
    let outcome = Box::pin(async {
        let config = kube::Config::new(server.base.parse()?);
        let mut live = service.clone();
        live.runtime = BackupJobRuntime::new(KubernetesRuntime::from_client(
            kube::Client::try_from(config)?,
        ));
        shared
            .lock()
            .map_err(|_| anyhow::anyhow!("CREATE fixture state"))?
            .service = Some(live);
        let runtime = shared
            .lock()
            .map_err(|_| anyhow::anyhow!("CREATE fixture state"))?
            .service
            .as_ref()
            .context("service installed")?
            .runtime
            .clone();
        // Production ensure_job, default pinned kube PostParams and GetParams.
        // The first two GETs are actual404; both POSTs invoke real admission.
        let created = Box::pin(runtime.ensure_job(&plan.context, None, None)).await?;
        let observed =
            Box::pin(runtime.ensure_job(&plan.context, Some(created.0), Some(created.1))).await?;
        ensure!(
            created == observed,
            "production GET readback must keep stored identities"
        );
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;
        let config_response = client
            .get(format!("{}{}", server.base, config_path))
            .send()
            .await?;
        ensure!(
            config_response.status() == StatusCode::OK,
            "second actual Config GET"
        );
        let actual_config: Value = config_response.json().await?;
        let config_uid = actual_config["metadata"]["uid"]
            .as_str()
            .context("stored Config UID")?
            .to_owned();
        let job_response = client
            .get(format!("{}{}", server.base, path))
            .send()
            .await?;
        ensure!(
            job_response.status() == StatusCode::OK,
            "second actual Job GET"
        );
        let actual: Value = job_response.json().await?;
        let uid = actual["metadata"]["uid"]
            .as_str()
            .context("stored Job UID")?
            .to_owned();
        ensure!(
            observed == (Uuid::parse_str(&config_uid)?, Uuid::parse_str(&uid)?)
                && actual["metadata"]["resourceVersion"] == json!("101")
                && actual_config["metadata"]["resourceVersion"] == json!("101"),
            "actual GET identities returned for normal DB record"
        );
        let collection = format!("{}/apis/batch/v1/namespaces/{NAMESPACE}/jobs", server.base);
        let conflict = client.post(&collection).json(&job).send().await?;
        ensure!(
            conflict.status() == StatusCode::CONFLICT,
            "unrecorded same-name CREATE remains storage conflict"
        );
        for fault in [
            CandidateFault::Nil,
            CandidateFault::Label,
            CandidateFault::Selector,
        ] {
            shared
                .lock()
                .map_err(|_| anyhow::anyhow!("CREATE fixture state"))?
                .fault = Some(fault);
            let denied = client.post(&collection).json(&job).send().await?;
            ensure!(
                denied.status() == StatusCode::FORBIDDEN,
                "prepared fault {fault:?} must reach403"
            );
        }
        {
            let state = shared
                .lock()
                .map_err(|_| anyhow::anyhow!("CREATE fixture state"))?;
            ensure!(
                state.posts == 5
                    && state.stores == 1
                    && state.reads == 3
                    && state.conflicts == 1
                    && state.config_posts == 1
                    && state.config_stores == 1
                    && state.config_reads == 3
                    && state.job_not_found_reads == 1
                    && state.config_not_found_reads == 1
                    && state
                        .targets
                        .get("/apis/node.k8s.io/v1/runtimeclasses/kata-backup-qemu")
                        == Some(&6)
                    && state.protocol_failures.is_empty(),
                "exact prepared TCP request/store/GET targets"
            );
            ensure!(
                state.candidates.len() == 5
                    && state.candidates[0].1 == 200
                    && state.candidates[1].1 == 200
                    && state.candidates[2..].iter().all(|v| v.1 == 403),
                "every negative reaches the actual validator"
            );
            ensure!(
                state.candidates[0].0["metadata"]["uid"] == json!(uid)
                    && state.candidates[1].0["metadata"]["uid"] != json!(uid),
                "second prospective system UID cannot replace first stored UID"
            );
            ensure!(
                state
                    .candidates
                    .iter()
                    .all(|v| v.0.pointer("/metadata/resourceVersion").is_none()),
                "no storage RV in prepared CREATE"
            );
            ensure!(
                state.objects.get(&path) == Some(&actual),
                "denial/conflict leave stored object unchanged"
            );
        }
        ensure!(
            facts(owner, plan).await? == before,
            "CREATE candidate must not bind UID, create Pod/permit or release holds/quota"
        );
        Ok::<_, anyhow::Error>((
            Uuid::parse_str(&config_uid)?,
            Uuid::parse_str(&uid)?,
            actual_config,
            actual,
        ))
    })
    .await;
    let closed = server.finish().await;
    if closed.is_err() {
        eprintln!("prepared CREATE fixture cleanup failed; not certified drained");
    }
    if outcome.is_err() {
        let state = shared
            .lock()
            .map_err(|_| anyhow::anyhow!("CREATE failure state"))?;
        eprintln!(
            "PREPARED_CREATE_FAILURE actualConfigPOST={} actualJobPOST={} configStored={} jobStored={} jobGET={} lastDecision={:?} protocolFailures={:?} targetCounts={:?}",
            state.config_posts,
            state.posts,
            state.config_stores,
            state.stores,
            state.reads,
            state.candidates.last().map(|v| v.1),
            state.protocol_failures,
            state.targets
        );
    }
    let (config_uid, job_uid, actual_config, actual_job) = outcome?;
    closed?;
    // Continue the existing test storage with the objects from actual successful
    // POST+GET. This is not an INSERT of a durable identity; the caller invokes
    // normal record_restore_job_objects afterward with these observed UIDs.
    {
        let mut map = dependencies
            .lock()
            .map_err(|_| anyhow::anyhow!("storage continuation lock"))?;
        map.insert(config_path, actual_config);
        map.insert(path, actual_job);
    }
    eprintln!(
        "VERIFIED faithful prepared Job CREATE through actual narrow-role PG + stateful TCP; two distinct candidate UIDs, one stored object, two successful GETs per object plus initial404, stable UID/RV, no durable Job/Pod/permit or hold/quota change before normal caller record; not deployed apiserver certification"
    );
    Ok((config_uid, job_uid))
}
