//! First SEAL CREATE after normal CAPTURE launch, trusted closure and handoff.
//! Only dependency/guest observations are synthetic. No future durable identity,
//! stage, permit, termination proof or cleanup row is seeded by this test.
use super::*;
use crate::{
    backup_admission::expected_pod, backup_job::ObservedBackupPod, backup_manifest::capture_name,
    engine::Claim, runtime_manifest::TERMINATION_FINALIZER,
    termination_client::TerminationObservation,
};
use k8s_openapi::api::core::v1::Pod;
use std::sync::atomic::Ordering;

struct ReviewFact {
    operation: String,
    resource: String,
    subresource: String,
    name: String,
    object: Value,
    code: u16,
    message: String,
}
struct SealState {
    service: Option<Arc<AdmissionService>>,
    identities: AdmissionConfig,
    objects: BTreeMap<String, Value>,
    reviews: Vec<ReviewFact>,
    targets: BTreeMap<String, usize>,
    stores: BTreeMap<String, usize>,
    conflicts: usize,
    fault: Option<Fault>,
    protocol_failures: Vec<&'static str>,
    removed_pod: Option<Value>,
}
type SealShared = Arc<Mutex<SealState>>;

fn pods_url() -> String {
    format!("/api/v1/namespaces/{NAMESPACE}/pods")
}
fn jobs_url() -> String {
    format!("/apis/batch/v1/namespaces/{NAMESPACE}/jobs")
}
fn configs_url() -> String {
    format!("/api/v1/namespaces/{NAMESPACE}/configmaps")
}
fn selector(query: &str) -> Option<String> {
    let values = url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
    if values.len() != 2
        || values
            .iter()
            .filter(|v| v.0 == "limit" && v.1 == "2")
            .count()
            != 1
        || values.iter().filter(|v| v.0 == "labelSelector").count() != 1
    {
        return None;
    }
    let value = values.iter().find(|v| v.0 == "labelSelector")?.1.as_ref();
    let uid = value.strip_prefix("batch.kubernetes.io/controller-uid=")?;
    let parsed = Uuid::parse_str(uid).ok()?;
    (!parsed.is_nil() && parsed.to_string() == uid).then(|| uid.to_owned())
}
fn controller(config: &AdmissionConfig) -> anyhow::Result<Value> {
    let id = &config
        .backup
        .as_ref()
        .context("backup identities")?
        .controller;
    Ok(json!({"username":id.username,"uid":id.uid}))
}
fn control_plane(username: &str) -> Value {
    json!({"username":username,"uid":"","groups":["system:authenticated"]})
}
fn prepared_seal(value: Value) -> anyhow::Result<Value> {
    let mut candidate = prepared(value)?;
    if candidate["kind"] == "Pod" {
        ensure!(
            candidate["spec"]["containers"][0]["resources"]["requests"]["cpu"] == "1"
                && candidate["spec"]["containers"][0]["resources"]["limits"]["cpu"] == "2"
                && candidate["spec"]["containers"][0]["resources"]["requests"]["memory"] == "1Gi"
                && candidate["spec"]["containers"][0]["resources"]["limits"]["memory"] == "2Gi"
                && candidate.pointer("/spec/resources").is_none()
                && candidate.pointer("/spec/initContainers").is_none()
                && candidate.pointer("/spec/schedulingGates").is_none(),
            "approved runner shape derives Burstable/no scheduling condition"
        );
        // Pinned Kubernetes v1.36.4 PodStrategy::PrepareForCreate, not a
        // submitted guest status. The approved runner has unequal CPU/memory
        // requests and limits and is therefore Burstable, not Guaranteed.
        candidate["metadata"]["generation"] = json!(1);
        candidate["status"] = json!({"phase":"Pending","qosClass":"Burstable"});
    }
    Ok(candidate)
}
fn apply_merge(value: &mut Value, patch: &Value) -> anyhow::Result<()> {
    let target = value.as_object_mut().context("merge object")?;
    for (key, next) in patch.as_object().context("merge patch")? {
        if next.is_object() {
            apply_merge(target.get_mut(key).context("merge target field")?, next)?;
        } else if next.is_null() {
            target.remove(key);
        } else {
            target.insert(key.clone(), next.clone());
        }
    }
    Ok(())
}
async fn decide(
    shared: &SealShared,
    review: AdmissionRequest,
) -> anyhow::Result<Result<(), (u16, String)>> {
    let service = shared
        .lock()
        .map_err(|_| anyhow::anyhow!("seal state"))?
        .service
        .clone()
        .context("shared admission service")?;
    let outcome =
        tokio::time::timeout(Duration::from_secs(4), Box::pin(service.decide(&review))).await;
    let (code, message) = match outcome {
        Ok(Ok(())) => (200, String::new()),
        Ok(Err(denial)) => (denial.code, denial.message.to_owned()),
        Err(_) => (504, "FixtureDecisionTimeout".to_owned()),
    };
    shared
        .lock()
        .map_err(|_| anyhow::anyhow!("seal state"))?
        .reviews
        .push(ReviewFact {
            operation: review.operation,
            resource: review.resource.resource,
            subresource: review.sub_resource,
            name: review.name,
            object: review.object.context("review object")?,
            code,
            message: message.clone(),
        });
    Ok(if code == 200 {
        Ok(())
    } else {
        Err((code, message))
    })
}
async fn seal_http_inner(
    shared: SealShared,
    request: Request<Body>,
) -> anyhow::Result<Response<Body>> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or_default().to_owned();
    if method == Method::GET {
        let pod_selector = if path == pods_url() {
            Some(selector(&query).context("PodList exact limit/selector")?)
        } else {
            None
        };
        let attachment_fields = url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
        let attachment_query = path == "/apis/storage.k8s.io/v1/volumeattachments"
            && attachment_fields.len() == 1
            && attachment_fields[0].0 == "limit"
            && attachment_fields[0].1 == "100";
        ensure!(
            pod_selector.is_some() || attachment_query || query_valid(&method, &path, &query),
            "GET query"
        );
        let mut state = shared.lock().map_err(|_| anyhow::anyhow!("seal state"))?;
        *state.targets.entry(path.clone()).or_default() += 1;
        if let Some(selected) = pod_selector {
            let items: Vec<_> = state
                .objects
                .iter()
                .filter(|(key, value)| {
                    key.starts_with(&format!("{}/", pods_url()))
                        && value["kind"] == "Pod"
                        && value["metadata"]["labels"]["batch.kubernetes.io/controller-uid"]
                            == json!(selected)
                })
                .map(|(_, value)| value.clone())
                .collect();
            return Ok(response(
                StatusCode::OK,
                json!({"apiVersion":"v1","kind":"PodList","metadata":{},"items":items}),
            ));
        }
        return Ok(state.objects.get(&path).cloned().map_or_else(
            || failure(StatusCode::NOT_FOUND, "NotFound"),
            |v| response(StatusCode::OK, v),
        ));
    }
    ensure!(query.is_empty(), "mutation query");
    let bytes = to_bytes(request.into_body(), 131072).await?;
    let body: Value = serde_json::from_slice(&bytes)?;
    let identities = shared
        .lock()
        .map_err(|_| anyhow::anyhow!("seal state"))?
        .identities
        .clone();
    let (resource, subresource, operation, mut candidate, before, options, mut user) =
        if method == Method::POST && [jobs_url(), configs_url(), pods_url()].contains(&path) {
            let resource = if path == jobs_url() {
                "jobs"
            } else if path == configs_url() {
                "configmaps"
            } else {
                "pods"
            };
            let user = if resource == "pods" {
                control_plane("system:kube-controller-manager")
            } else {
                controller(&identities)?
            };
            (
                resource,
                "",
                "CREATE",
                prepared_seal(body)?,
                None,
                None,
                user,
            )
        } else if method == Method::POST
            && path.starts_with(&format!("{}/", pods_url()))
            && path.ends_with("/binding")
        {
            (
                "pods",
                "binding",
                "CREATE",
                body,
                None,
                None,
                control_plane("system:kube-scheduler"),
            )
        } else if (method == Method::PATCH || method == Method::DELETE)
            && (path.starts_with(&format!("{}/", jobs_url()))
                || path.starts_with(&format!("{}/", pods_url())))
        {
            let before = shared
                .lock()
                .map_err(|_| anyhow::anyhow!("seal state"))?
                .objects
                .get(&path)
                .cloned()
                .context("mutation current object")?;
            let resource = if before["kind"] == "Job" {
                "jobs"
            } else {
                "pods"
            };
            if method == Method::PATCH {
                let wanted_uid = before["metadata"]["uid"].clone();
                let wanted_version = before["metadata"]["resourceVersion"].clone();
                ensure!(
                    body["metadata"]["uid"] == wanted_uid
                        && body["metadata"]["resourceVersion"] == wanted_version,
                    "exact mutation preconditions"
                );
                let mut candidate = before.clone();
                apply_merge(&mut candidate, &body)?;
                if resource == "jobs" && candidate["spec"] != before["spec"] {
                    let generation = before["metadata"]["generation"]
                        .as_u64()
                        .context("Job generation")?;
                    candidate["metadata"]["generation"] = json!(
                        generation
                            .checked_add(1)
                            .context("Job generation overflow")?
                    );
                }
                (
                    resource,
                    "",
                    "UPDATE",
                    candidate,
                    Some(before),
                    None,
                    controller(&identities)?,
                )
            } else {
                (
                    resource,
                    "",
                    "DELETE",
                    before,
                    None,
                    Some(body),
                    controller(&identities)?,
                )
            }
        } else {
            anyhow::bail!("unsupported fixture mutation");
        };
    if operation == "CREATE" && resource == "jobs" {
        let fault = shared
            .lock()
            .map_err(|_| anyhow::anyhow!("seal state"))?
            .fault
            .take();
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
    }
    let review: AdmissionRequest = serde_json::from_value(json!({
        "uid":Uuid::new_v4(),"resource":{"group":if resource=="jobs" {"batch"} else {""},"version":"v1","resource":resource},
        "subResource":subresource,"operation":operation,"namespace":NAMESPACE,"name":candidate["metadata"]["name"],
        "object":candidate,"oldObject":before,"options":options,"userInfo":user
    }))?;
    if let Err((code, message)) = decide(&shared, review).await? {
        return Ok(failure(StatusCode::from_u16(code)?, &message));
    }
    if operation == "UPDATE"
        && resource == "pods"
        && candidate["metadata"]["deletionTimestamp"].is_string()
        && candidate["metadata"]["finalizers"]
            .as_array()
            .is_some_and(|f| f.iter().all(|v| v != TERMINATION_FINALIZER))
    {
        // The reviewed KCM consumes a separate exact metadata transition after
        // the accepted proof-authorized protection removal. It cannot synthesize
        // termination authority or make the controller's first patch sufficient.
        candidate["metadata"]["resourceVersion"] = json!("104");
        shared
            .lock()
            .map_err(|_| anyhow::anyhow!("seal state"))?
            .objects
            .insert(path.clone(), candidate.clone());
        let mut tracked = candidate.clone();
        tracked["metadata"]["finalizers"] = json!([]);
        let tracking: AdmissionRequest = serde_json::from_value(json!({"uid":Uuid::new_v4(),
            "resource":{"group":"","version":"v1","resource":"pods"},"operation":"UPDATE",
            "namespace":NAMESPACE,"name":tracked["metadata"]["name"],"object":tracked,"oldObject":candidate,
            "userInfo":control_plane("system:kube-controller-manager")}))?;
        if let Err((code, message)) = decide(&shared, tracking).await? {
            return Ok(failure(StatusCode::from_u16(code)?, &message));
        }
        tracked["metadata"]["resourceVersion"] = json!("105");
        let mut state = shared.lock().map_err(|_| anyhow::anyhow!("seal state"))?;
        state.removed_pod = Some(tracked);
        state.objects.remove(&path);
        return Ok(response(StatusCode::OK, candidate));
    }
    let mut state = shared.lock().map_err(|_| anyhow::anyhow!("seal state"))?;
    if subresource == "binding" {
        let pod_path = path.strip_suffix("/binding").context("binding path")?;
        let assigned = state
            .objects
            .get_mut(pod_path)
            .context("binding current Pod")?;
        ensure!(
            assigned.pointer("/spec/nodeName").is_none(),
            "initial unassigned Pod"
        );
        assigned["spec"]["nodeName"] = candidate["target"]["name"].clone();
        assigned["metadata"]["resourceVersion"] = json!("102");
        return Ok(response(StatusCode::CREATED, candidate));
    }
    if operation == "CREATE" {
        let name = candidate["metadata"]["name"]
            .as_str()
            .context("CREATE name")?;
        let item = format!("{path}/{name}");
        if state.objects.contains_key(&item) {
            state.conflicts += 1;
            return Ok(failure(StatusCode::CONFLICT, "AlreadyExists"));
        }
        ensure!(
            candidate.pointer("/metadata/resourceVersion").is_none(),
            "no storage version before admission"
        );
        candidate["metadata"]["resourceVersion"] = json!("101");
        *state.stores.entry(item.clone()).or_default() += 1;
        state.objects.insert(item, candidate.clone());
        return Ok(response(StatusCode::CREATED, candidate));
    }
    if operation == "DELETE" {
        candidate["metadata"]["deletionTimestamp"] =
            json!(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));
        candidate["metadata"]["deletionGracePeriodSeconds"] = json!(30);
        candidate["metadata"]["resourceVersion"] = json!("103");
        state.objects.insert(path, candidate.clone());
        return Ok(response(StatusCode::OK, candidate));
    }
    candidate["metadata"]["resourceVersion"] = json!("104");
    state.objects.insert(path, candidate.clone());
    Ok(response(StatusCode::OK, candidate))
}
async fn seal_http(State(shared): State<SealShared>, request: Request<Body>) -> Response<Body> {
    match Box::pin(seal_http_inner(shared.clone(), request)).await {
        Ok(response) => response,
        Err(_) => {
            if let Ok(mut state) = shared.lock() {
                state.protocol_failures.push("fixture protocol/state error");
            }
            failure(StatusCode::BAD_REQUEST, "FixtureProtocol")
        }
    }
}
struct SealServer {
    shared: SealShared,
    client: kube::Client,
    runtime: BackupJobRuntime,
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}
impl Drop for SealServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl SealServer {
    async fn new(
        database: Database,
        identities: AdmissionConfig,
        objects: BTreeMap<String, Value>,
    ) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let client =
            kube::Client::try_from(kube::Config::new(format!("http://{address}").parse()?))?;
        let runtime = BackupJobRuntime::new(KubernetesRuntime::from_client(client.clone()));
        let shared = Arc::new(Mutex::new(SealState {
            service: Some(Arc::new(AdmissionService {
                database,
                kubernetes: client.clone(),
                config: identities.clone(),
            })),
            identities,
            objects,
            reviews: vec![],
            targets: BTreeMap::new(),
            stores: BTreeMap::new(),
            conflicts: 0,
            fault: None,
            protocol_failures: vec![],
            removed_pod: None,
        }));
        let (stop, shutdown) = oneshot::channel();
        let state = shared.clone();
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().fallback(any(seal_http)).with_state(state),
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
        tokio::time::timeout(
            Duration::from_secs(3),
            self.task.as_mut().context("owned Seal HTTP task")?,
        )
        .await
        .context("Seal HTTP drain deadline")?
        .context("Seal HTTP join")?
        .context("Seal HTTP serve failure")?;
        self.task.take();
        Ok(())
    }
    async fn actual(&self, url: &str, name: &str) -> anyhow::Result<Value> {
        Ok(self
            .client
            .request(KubeRequest::new(url).get(name, &GetParams::default())?)
            .await?)
    }
    fn fault(&self, fault: Fault) -> anyhow::Result<()> {
        self.shared
            .lock()
            .map_err(|_| anyhow::anyhow!("seal state"))?
            .fault = Some(fault);
        Ok(())
    }
}

async fn first_job(
    f: &Fixture,
    claim: &Claim,
    plan: &JobPlan,
    server: &SealServer,
) -> anyhow::Result<JobPlan> {
    ensure!(
        plan.known_config.is_none() && plan.known_job.is_none() && plan.known_pod.is_none(),
        "first attempt has no future bindings"
    );
    ensure!(
        job_bindings(&f.backup.database, plan).await?.is_empty(),
        "RLS confirms no prebound job"
    );
    let before = unchanged_facts(&f.backup.database, plan).await?;
    let observed = Box::pin(server.runtime.ensure_job(&plan.context, None, None)).await?;
    ensure!(
        Box::pin(
            server
                .runtime
                .ensure_job(&plan.context, Some(observed.0), Some(observed.1))
        )
        .await?
            == observed,
        "observed first UID stable on actual readback"
    );
    let name = backup_job_name(plan.context.attempt_id, plan.context.stage);
    let actual = server.actual(&jobs_url(), &name).await?;
    let actual_config = server
        .actual(&configs_url(), &config_name(plan.context.attempt_id))
        .await?;
    ensure!(
        actual["metadata"]["uid"] == json!(observed.1)
            && actual_config["metadata"]["uid"] == json!(observed.0)
            && actual["spec"]["suspend"] == true,
        "actual suspended first objects"
    );
    ensure!(
        unchanged_facts(&f.backup.database, plan).await? == before
            && job_bindings(&f.backup.database, plan).await?.is_empty(),
        "CREATE and GET do not create durable job identity or closure"
    );
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
        "normal record binds actual GETs only"
    );
    ensure!(
        job_bindings(&f.backup.database, plan).await?
            == vec![("CONFIG".into(), observed.0), ("JOB".into(), observed.1)],
        "exact RLS durable job identities"
    );
    Ok(refetched)
}

async fn capture_launch(
    f: &Fixture,
    claim: &Claim,
    plan: &JobPlan,
    server: &SealServer,
) -> anyhow::Result<(JobPlan, ObservedBackupPod)> {
    let job_uid = plan.known_job.context("actual recorded Capture Job")?;
    ensure!(
        Box::pin(
            server
                .runtime
                .start_and_observe(&plan.context, job_uid, None)
        )
        .await?
        .pod
        .is_none(),
        "actual unsuspend does not invent Pod"
    );
    let pods = Api::<Pod>::namespaced(server.client.clone(), NAMESPACE);
    let name = format!(
        "{}-abcde",
        backup_job_name(plan.context.attempt_id, plan.context.stage)
    );
    let value =
        expected_pod(&plan.context, job_uid, &name).map_err(|d| anyhow::anyhow!(d.message))?;
    let created = pods
        .create(&PostParams::default(), &serde_json::from_value(value)?)
        .await?;
    let created_uid = Uuid::parse_str(
        created
            .metadata
            .uid
            .as_deref()
            .context("stored once Pod UID")?,
    )?;
    let second_name = format!(
        "{}-abcdf",
        backup_job_name(plan.context.attempt_id, plan.context.stage)
    );
    let second: Pod = serde_json::from_value(
        expected_pod(&plan.context, job_uid, &second_name)
            .map_err(|d| anyhow::anyhow!(d.message))?,
    )?;
    let second = pods
        .create(&PostParams::default(), &second)
        .await
        .err()
        .context("second Pod must deny")?;
    ensure!(
        matches!(second,kube::Error::Api(ref e) if e.code==403 && e.message=="Backup Pod attempt has no remaining one-shot admission"),
        "actual second once admission denial"
    );
    let observed = Box::pin(
        server
            .runtime
            .start_and_observe(&plan.context, job_uid, None),
    )
    .await?
    .pod
    .context("actual one-shot Pod readback")?;
    ensure!(
        observed.uid == created_uid && observed.name == name && observed.node_name.is_none(),
        "only actual initial unassigned Pod can be recorded"
    );
    Box::pin(f.backup.database.record_backup_pod(
        &f.backup,
        claim,
        plan.context.attempt_id,
        job_uid,
        &observed,
    ))
    .await
    .map_err(api_failure)?;
    let binding = json!({"apiVersion":"v1","kind":"Binding","metadata":{"name":name,"namespace":NAMESPACE,"uid":created_uid},"target":{"apiVersion":"v1","kind":"Node","name":f.base.node.node_name}});
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("{}/{name}/binding", pods_url()))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&binding)?)?;
    let _: Value = server.client.request(request).await?;
    let bound = Box::pin(server.runtime.start_and_observe(
        &plan.context,
        job_uid,
        Some(created_uid),
    ))
    .await?
    .pod
    .context("actual bound Pod GET/list")?;
    ensure!(
        bound.uid == created_uid
            && bound.node_name.as_deref() == Some(f.base.node.node_name.as_str()),
        "scheduler binding readback keeps exact Pod"
    );
    let refetched = Box::pin(f.backup.database.prepare_backup_job(&f.backup, claim))
        .await
        .map_err(api_failure)?;
    ensure!(
        refetched.known_pod == Some(created_uid),
        "normal refetch retains once Pod UID"
    );
    Ok((refetched, bound))
}

async fn close_capture(
    f: &Fixture,
    claim: &Claim,
    plan: &JobPlan,
    pod: &ObservedBackupPod,
    volume: &BoundBackupVolume,
    server: &SealServer,
) -> anyhow::Result<JobPlan> {
    let registrations = f.base.guard.registrations.load(Ordering::SeqCst);
    let closes = f.base.guard.close_requests.load(Ordering::SeqCst);
    let observed = Box::pin(server.runtime.observe_launch(plan, &pod.name, Some(volume))).await?;
    let permit = Box::pin(
        f.backup
            .database
            .prepare_backup_launch(&f.backup, claim, &observed),
    )
    .await
    .map_err(api_failure)?;
    let registration = f.base.guard.client.register(&permit.request).await?;
    Box::pin(
        f.backup
            .database
            .record_backup_registration(&f.backup, claim, &registration),
    )
    .await
    .map_err(api_failure)?;
    let report = crate::backup_job::BackupJobExit {
        exit_code: 0,
        report: Some(
            json!({"snapshot_id":"c".repeat(64),"disk":{"size_bytes":volume.size_bytes,"sha256":"d".repeat(64)}}),
        ),
        finished_at: Utc::now(),
    };
    Box::pin(
        f.backup
            .database
            .close_backup_attempt(&f.backup, claim, Some(&report)),
    )
    .await
    .map_err(api_failure)?;
    let closing = Box::pin(f.backup.database.prepare_backup_job(&f.backup, claim))
        .await
        .map_err(api_failure)?;
    ensure!(
        closing.backup.status == "CAPTURE_CLOSING",
        "only normal closure begins closing"
    );
    ensure!(
        Box::pin(f.backup.database.prepare_capture_config(&f.backup, claim))
            .await
            .is_err(),
        "guest report and closing intent alone cannot grant handoff"
    );
    let challenge = Box::pin(f.backup.database.prepare_backup_close(&f.backup, claim))
        .await
        .map_err(api_failure)?;
    Box::pin(
        server
            .runtime
            .request_close(&closing, &challenge.permit.request.launch),
    )
    .await?;
    let TerminationObservation::Verified(proof) =
        f.base.guard.client.close(&challenge.request).await?
    else {
        anyhow::bail!("actual mTLS trusted closure required")
    };
    let proof_id = Box::pin(
        f.backup
            .database
            .record_backup_termination(&f.backup, claim, &proof),
    )
    .await
    .map_err(api_failure)?;
    ensure!(
        Box::pin(f.backup.database.prepare_capture_config(&f.backup, claim))
            .await
            .is_err(),
        "trusted proof without actual Pod/attachment cleanup cannot grant handoff"
    );
    let cleanup = Box::pin(server.runtime.finish_cleanup(&closing, &proof))
        .await?
        .context("actual HTTP cleanup must complete")?;
    Box::pin(
        f.backup
            .database
            .record_backup_cleanup(&f.backup, claim, proof_id, &cleanup),
    )
    .await
    .map_err(api_failure)?;
    ensure!(
        f.base.guard.registrations.load(Ordering::SeqCst) == registrations + 1
            && f.base.guard.close_requests.load(Ordering::SeqCst) == closes + 1,
        "new actual mTLS registration and closure, not source STOP proof reuse"
    );
    let seal = Box::pin(f.backup.database.prepare_backup_job(&f.backup, claim))
        .await
        .map_err(api_failure)?;
    ensure!(
        seal.context.stage == BackupStage::Seal
            && seal.backup.status == "SEAL_PENDING"
            && seal.known_config.is_none()
            && seal.known_job.is_none()
            && seal.known_pod.is_none()
            && seal.context.block_pvc.is_none(),
        "normal trusted cleanup alone yields initial volume-free Seal"
    );
    Ok(seal)
}

async fn handoff(
    f: &Fixture,
    claim: &Claim,
    seal: &JobPlan,
    server: &SealServer,
) -> anyhow::Result<()> {
    let report = Box::pin(f.backup.database.prepare_capture_config(&f.backup, claim))
        .await
        .map_err(api_failure)?;
    ensure!(
        report.known_uid.is_none(),
        "first handoff has no seeded config identity"
    );
    let before = unchanged_facts(&f.backup.database, seal).await?;
    let uid = Box::pin(server.runtime.ensure_capture_config(&report.object, None)).await?;
    let actual = server
        .actual(&configs_url(), &capture_name(seal.backup.id))
        .await?;
    ensure!(
        actual["metadata"]["uid"] == json!(uid)
            && actual["immutable"] == true
            && actual["data"] == report.object["data"],
        "handoff actual CREATE/GET matches normal intent"
    );
    let unrecorded = Box::pin(f.backup.database.prepare_capture_config(&f.backup, claim))
        .await
        .map_err(api_failure)?;
    ensure!(
        unrecorded.known_uid.is_none()
            && unchanged_facts(&f.backup.database, seal).await? == before,
        "handoff admission alone cannot bind or change closure"
    );
    Box::pin(
        f.backup
            .database
            .record_capture_config(&f.backup, claim, uid),
    )
    .await
    .map_err(api_failure)?;
    let refetched = Box::pin(f.backup.database.prepare_capture_config(&f.backup, claim))
        .await
        .map_err(api_failure)?;
    ensure!(
        refetched.known_uid == Some(uid) && refetched.object == report.object,
        "normal handoff record keeps actual identity and capture data"
    );
    ensure!(
        Box::pin(
            server
                .runtime
                .ensure_capture_config(&refetched.object, refetched.known_uid)
        )
        .await?
            == uid,
        "handoff retry is actual GET of existing winner"
    );
    Ok(())
}

async fn seal_first_job(
    f: &Fixture,
    claim: &Claim,
    seal: &JobPlan,
    server: &SealServer,
) -> anyhow::Result<()> {
    ensure!(
        job_bindings(&f.backup.database, seal).await?.is_empty(),
        "Seal first CREATE cannot start with bindings"
    );
    let before = unchanged_facts(&f.backup.database, seal).await?;
    let observed = Box::pin(server.runtime.ensure_job(&seal.context, None, None)).await?;
    ensure!(
        Box::pin(
            server
                .runtime
                .ensure_job(&seal.context, Some(observed.0), Some(observed.1))
        )
        .await?
            == observed,
        "Seal actual repeated GET identity"
    );
    let jobs = Api::<Job>::namespaced(server.client.clone(), NAMESPACE);
    let name = backup_job_name(seal.context.attempt_id, BackupStage::Seal);
    let actual = server.actual(jobs.resource_url(), &name).await?;
    let actual_config = server
        .actual(&configs_url(), &config_name(seal.context.attempt_id))
        .await?;
    ensure!(
        actual["metadata"]["uid"] == json!(observed.1)
            && actual_config["metadata"]["uid"] == json!(observed.0)
            && actual["spec"]["suspend"] == true,
        "literal Seal GETs match returned IDs"
    );
    let manifests = build_backup_manifests(&seal.context)?;
    ensure!(
        manifests
            .job
            .pointer("/spec/template/spec/containers/0/volumeDevices")
            .is_none()
            && !manifests.job["spec"]["template"]["spec"]["volumes"]
                .as_array()
                .context("Seal volumes")?
                .iter()
                .any(|v| v.get("persistentVolumeClaim").is_some()),
        "Seal has no tenant block device"
    );
    let body: Job = serde_json::from_value(manifests.job.clone())?;
    let conflict = jobs
        .create(&PostParams::default(), &body)
        .await
        .err()
        .context("Seal same-name conflict")?;
    ensure!(
        matches!(conflict,kube::Error::Api(ref e) if e.code==409),
        "prospective Seal candidate never supersedes stored winner"
    );
    for (fault, message) in [
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
        let denial = jobs
            .create(&PostParams::default(), &body)
            .await
            .err()
            .context("Seal prepared fault must deny")?;
        ensure!(
            matches!(denial,kube::Error::Api(ref e) if e.code==403 && e.message==message),
            "Seal {fault:?} reaches exact prepared guard"
        );
    }
    ensure!(
        job_bindings(&f.backup.database, seal).await?.is_empty()
            && unchanged_facts(&f.backup.database, seal).await? == before,
        "all Seal prepared decisions create no durable identity/authority/accounting change"
    );
    Box::pin(f.backup.database.record_backup_job_objects(
        &f.backup,
        claim,
        seal.context.attempt_id,
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
        "first Seal record/refetch uses actual GET only"
    );
    ensure!(
        job_bindings(&f.backup.database, seal).await?
            == vec![("CONFIG".into(), observed.0), ("JOB".into(), observed.1)],
        "exact Seal attempt RLS binding"
    );
    ensure!(
        unchanged_facts(&f.backup.database, seal).await? == before,
        "binding Seal metadata alone has no extra closure/accounting effects"
    );
    let mut replacement = prepared(manifests.job)?;
    replacement["metadata"]["resourceVersion"] = json!("105");
    server
        .shared
        .lock()
        .map_err(|_| anyhow::anyhow!("seal state"))?
        .objects
        .insert(format!("{}/{name}", jobs_url()), replacement);
    ensure!(
        Box::pin(server.runtime.ensure_job(
            &seal.context,
            refetched.known_config,
            refetched.known_job
        ))
        .await
        .is_err(),
        "coherent replacement GET cannot replace actual Seal ledger UID"
    );
    ensure!(
        job_bindings(&f.backup.database, seal).await?
            == vec![("CONFIG".into(), observed.0), ("JOB".into(), observed.1)],
        "replacement cannot rewrite Seal identity"
    );
    let state = server
        .shared
        .lock()
        .map_err(|_| anyhow::anyhow!("seal state"))?;
    let creates = state
        .reviews
        .iter()
        .filter(|r| r.resource == "jobs" && r.operation == "CREATE" && r.name == name)
        .collect::<Vec<_>>();
    ensure!(
        creates.len() == 6
            && creates[0].code == 200
            && creates[1].code == 200
            && creates[2..].iter().all(|r| r.code == 403),
        "Seal six actual prepared decisions"
    );
    ensure!(
        creates[0].object["metadata"]["uid"] == json!(observed.1)
            && creates[1].object["metadata"]["uid"] != json!(observed.1)
            && creates
                .iter()
                .all(|r| r.object.pointer("/metadata/resourceVersion").is_none()),
        "candidate UID local; actual stored winner only"
    );
    ensure!(
        state.stores.get(&format!("{}/{name}", jobs_url())) == Some(&1) && state.conflicts == 1,
        "one Seal stored winner and one conflict"
    );
    ensure!(
        state.protocol_failures.is_empty(),
        "protocol errors cannot count as coverage"
    );
    Ok(())
}

async fn sequence(
    f: &Fixture,
    claim: &Claim,
    initial: &JobPlan,
    volume: &BoundBackupVolume,
    server: &SealServer,
) -> anyhow::Result<()> {
    let before = unchanged_facts(&f.backup.database, initial).await?;
    ensure!(
        initial.backup.source.is_object()
            && before["backup"]["source"].is_object()
            && before["backup"]["source"] == initial.backup.source,
        "initial RLS backup source must be a real immutable object matching the normal plan"
    );
    for (field, id) in [
        ("source_instance", "instance_id"),
        ("source_workspace", "workspace_id"),
    ] {
        ensure!(
            before[field].is_object()
                && before[field]["id"] == before["backup"][id]
                && before[field]["tenant_id"] == json!(initial.backup.tenant_id),
            "initial RLS {field} is a real whole source row with exact ID/tenant"
        );
    }
    ensure!(
        ["pod_admissions", "permits", "proofs", "cleanup", "releases"]
            .iter()
            .all(|key| before[*key] == json!(0)),
        "no future trusted closure in initial fixture"
    );
    let capture = Box::pin(first_job(f, claim, initial, server)).await?;
    ensure!(
        f.backup.heartbeat(claim).await.map_err(api_failure)?,
        "normal claim heartbeat before Capture launch"
    );
    let (capture, pod) = Box::pin(capture_launch(f, claim, &capture, server)).await?;
    ensure!(
        f.backup.heartbeat(claim).await.map_err(api_failure)?,
        "normal claim heartbeat before trusted closure"
    );
    let seal = Box::pin(close_capture(f, claim, &capture, &pod, volume, server)).await?;
    Box::pin(handoff(f, claim, &seal, server)).await?;
    ensure!(
        f.backup.heartbeat(claim).await.map_err(api_failure)?,
        "normal claim heartbeat before Seal first CREATE"
    );
    Box::pin(seal_first_job(f, claim, &seal, server)).await?;
    let after = unchanged_facts(&f.backup.database, &seal).await?;
    for (field, id) in [
        ("source_instance", "instance_id"),
        ("source_workspace", "workspace_id"),
    ] {
        ensure!(
            after[field].is_object()
                && after[field]["id"] == after["backup"][id]
                && after[field]["tenant_id"] == json!(initial.backup.tenant_id),
            "final RLS {field} remains a real whole source row with exact ID/tenant"
        );
    }
    for key in [
        "source_instance",
        "source_workspace",
        "holds",
        "releases",
        "reservations",
        "quotas",
    ] {
        ensure!(
            before[key] == after[key],
            "normal closure/Seal metadata cannot change source/hold/quota {key}"
        );
    }
    ensure!(
        after["backup"]["source"].is_object()
            && before["backup"]["source"] == after["backup"]["source"]
            && after["backup"]["source"] == initial.backup.source,
        "frozen source identity survives Capture-to-Seal"
    );
    ensure!(
        after["pod_admissions"] == 1
            && after["permits"] == 1
            && after["proofs"] == 1
            && after["cleanup"] == 1,
        "only actual Capture once/launch/closure can exist; Seal has no future proof"
    );
    let state = server
        .shared
        .lock()
        .map_err(|_| anyhow::anyhow!("seal state"))?;
    let checks = [
        ("UPDATE", "jobs", "", ""),
        ("CREATE", "pods", "binding", pod.name.as_str()),
        ("DELETE", "pods", "", pod.name.as_str()),
        ("UPDATE", "pods", "", pod.name.as_str()),
    ];
    for (operation, resource, subresource, name) in checks {
        ensure!(
            state.reviews.iter().any(|r| r.operation == operation
                && r.resource == resource
                && r.subresource == subresource
                && (name.is_empty() || r.name == name)
                && r.code == 200),
            "normal Capture transition requires actual shared decision {operation}/{resource}/{subresource}"
        );
    }
    ensure!(
        state
            .removed_pod
            .as_ref()
            .is_some_and(|v| v["metadata"]["uid"] == json!(pod.uid)
                && v["metadata"]["deletionTimestamp"].is_string()),
        "cleanup removed only exact deleted Capture Pod after proof-authorized patch"
    );
    ensure!(
        state
            .targets
            .get(&format!("{}/{}", pods_url(), pod.name))
            .is_some_and(|n| *n >= 5)
            && state
                .targets
                .get("/apis/storage.k8s.io/v1/volumeattachments")
                == Some(&1),
        "actual Pod and attachment readbacks are observed"
    );
    ensure!(
        state.stores.get(&format!(
            "{}/{}",
            configs_url(),
            capture_name(seal.backup.id)
        )) == Some(&1),
        "one actual handoff config store"
    );
    ensure!(
        state
            .reviews
            .iter()
            .any(|r| r.name == capture_name(seal.backup.id)
                && r.resource == "configmaps"
                && r.operation == "CREATE"
                && r.code == 200),
        "handoff must reach real shared gate"
    );
    ensure!(
        state
            .reviews
            .iter()
            .filter(|r| r.resource == "pods"
                && r.operation == "CREATE"
                && r.code == 403
                && r.message == "Backup Pod attempt has no remaining one-shot admission")
            .count()
            == 1,
        "one actual rejected replacement Pod"
    );
    Ok(())
}

async fn seal() -> anyhow::Result<()> {
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
        .await?
        .database_for("sandbox_admission")?;
    let (session, current): (String, String) =
        sqlx::query_as("SELECT session_user::text,current_user::text")
            .fetch_one(&admission.pool)
            .await?;
    ensure!(
        session == "sandbox_admission" && current == "sandbox_admission",
        "exact shared admission login"
    );
    let f = Box::pin(Fixture::new_with_verified_connections(
        true,
        &verified,
        &termination,
        &backup,
    ))
    .await?;
    let (claim, plan, volume) = Box::pin(capture_plan(&f)).await?;
    let placeholder = json!({"metadata":{"name":"never-created-seal-placeholder"}});
    let (objects, _) =
        super::super::pipeline_tests::runtime_objects(&plan, &volume, &f.base.node, &placeholder)?;
    let mut objects = objects
        .lock()
        .map_err(|_| anyhow::anyhow!("dependency map"))?
        .clone();
    objects.remove(&format!("{}/never-created-seal-placeholder", pods_url()));
    ensure!(
        !objects
            .values()
            .any(|v| v["kind"] == "Pod" || v["kind"] == "Job" || v["kind"] == "ConfigMap"),
        "dependency fixtures contain no future control or Pod object"
    );
    let server = Box::pin(SealServer::new(admission, config()?, objects)).await?;
    let result = Box::pin(sequence(&f, &claim, &plan, &volume, &server)).await;
    let drained = server.finish().await;
    match (result, drained) {
        (Ok(()), Ok(())) => {}
        (Err(business), Err(drain)) => anyhow::bail!(
            "Seal business failure: {business:#}; independent HTTP drain failure: {drain:#}"
        ),
        (Err(e), Ok(())) | (Ok(()), Err(e)) => return Err(e),
    }
    eprintln!(
        "VERIFIED first SEAL Job CREATE after normal actual shared Capture Job/once Pod CREATE+GET/record, scheduler binding, mTLS registration/termination and HTTP cleanup; normal capture handoff CREATE+GET+record, then actual prepared Seal CREATE+GET+record/refetch. Dependency CSI/Node/guest report and controller storage transitions are explicit stand-ins, not cloud/apiserver/Kata/vault certification. No sealed proof/status/permit/job-binding seed; Seal execution itself is not covered"
    );
    Ok(())
}
#[tokio::test]
#[ignore = "requires fresh normally migrated PostgreSQL and exact component logins"]
async fn seal_first_job_create_after_normal_capture_trusted_cleanup_and_handoff()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    Box::pin(seal()).await
}
