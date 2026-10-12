//! Actual loopback HTTP observations. These fixtures do not certify a CSI driver.
#![allow(clippy::unwrap_used)]
use super::*;
use crate::{
    backup_job::{BackupCloudSettings, BackupJobRuntime},
    backup_object::BackupIdentity,
    runtime::KubernetesRuntime,
};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, Response, StatusCode},
};
use k8s_openapi::api::core::v1::PersistentVolumeClaim;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct State {
    objects: BTreeMap<String, Value>,
    requests: Vec<(Method, String)>,
    pending_post: Option<(String, Value)>,
}
fn response(code: StatusCode, value: Value) -> Response<Body> {
    Response::builder()
        .status(code)
        .header("content-type", "application/json")
        .body(Body::from(value.to_string()))
        .unwrap()
}
fn missing() -> Response<Body> {
    response(
        StatusCode::NOT_FOUND,
        json!({"apiVersion":"v1","kind":"Status",
        "status":"Failure","reason":"NotFound","message":"fixture object absent","code":404}),
    )
}
async fn http(state: Arc<Mutex<State>>, request: Request<Body>) -> Response<Body> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let bytes = match to_bytes(request.into_body(), 2 * 1024 * 1024).await {
        Ok(v) => v,
        Err(_) => return response(StatusCode::BAD_REQUEST, json!({"code":400})),
    };
    let mut state = state.lock().unwrap();
    state.requests.push((method.clone(), path.clone()));
    if method == Method::GET {
        return state
            .objects
            .get(&path)
            .cloned()
            .map(|v| response(StatusCode::OK, v))
            .unwrap_or_else(missing);
    }
    if method == Method::POST
        && let Some((allowed, expected)) = &state.pending_post
        && &path == allowed
    {
        let actual: Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return response(StatusCode::BAD_REQUEST, json!({"code":400})),
        };
        if actual != *expected {
            return response(StatusCode::BAD_REQUEST, json!({"code":400}));
        }
        let mut actual = actual;
        actual["metadata"]["uid"] = json!(Uuid::new_v4());
        actual["metadata"]["resourceVersion"] = json!("1");
        actual["metadata"]["creationTimestamp"] = json!(Utc::now());
        actual["metadata"]["finalizers"] = json!(["kubernetes.io/pvc-protection"]);
        actual["status"] = json!({"phase":"Pending"});
        let name = actual["metadata"]["name"].as_str().unwrap();
        state
            .objects
            .insert(format!("{path}/{name}"), actual.clone());
        return response(StatusCode::CREATED, actual);
    }
    response(
        StatusCode::METHOD_NOT_ALLOWED,
        json!({"apiVersion":"v1","kind":"Status",
        "status":"Failure","reason":"MethodNotAllowed","message":"unexpected fixture mutation","code":405}),
    )
}
struct Fixture {
    runtime: BackupJobRuntime,
    state: Arc<Mutex<State>>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}
impl Fixture {
    async fn new(
        objects: BTreeMap<String, Value>,
        pending_post: Option<(String, Value)>,
    ) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let runtime = BackupJobRuntime::new(KubernetesRuntime::from_client(
            kube::Client::try_from(kube::Config::new(base.parse()?))?,
        ));
        let state = Arc::new(Mutex::new(State {
            objects,
            requests: Vec::new(),
            pending_post,
        }));
        let callback = state.clone();
        let app = Router::new().fallback(move |r: Request<Body>| http(callback.clone(), r));
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = stopped.await;
                })
                .await
        });
        Ok(Self {
            runtime,
            state,
            shutdown: Some(shutdown),
            task: Some(task),
        })
    }
    fn no_mutation_after_read(&self, class_path: &str) -> anyhow::Result<()> {
        let state = self.state.lock().unwrap();
        ensure!(
            state
                .requests
                .iter()
                .any(|(m, p)| *m == Method::GET && p == class_path),
            "drift failure must reach the exact actual class GET"
        );
        ensure!(
            state.requests.iter().all(|(m, _)| *m == Method::GET),
            "class drift must prevent every storage mutation"
        );
        Ok(())
    }
    async fn finish(mut self) -> anyhow::Result<()> {
        if let Some(stop) = self.shutdown.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.as_mut() {
            match tokio::time::timeout(std::time::Duration::from_secs(3), task).await {
                Ok(result) => result??,
                Err(_) => anyhow::bail!("actual HTTP fixture did not drain"),
            }
        }
        self.task.take();
        Ok(())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(stop) = self.shutdown.take() {
            let _ = stop.send(());
        }
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
fn class_path(name: &str) -> String {
    format!("/apis/storage.k8s.io/v1/storageclasses/{name}")
}
fn snapshot_path(name: &str) -> String {
    format!("/apis/snapshot.storage.k8s.io/v1/volumesnapshotclasses/{name}")
}
fn mutate(value: &mut Value, edit: usize, snapshot: bool) {
    if edit == 13 {
        value["metadata"]["unknown"] = json!(true);
        return;
    }
    match edit {
        0 => value["metadata"]["uid"] = json!(Uuid::new_v4()),
        1 => value["metadata"]["deletionTimestamp"] = json!("2026-10-08T00:00:00Z"),
        2 => {
            value["parameters"][if snapshot {
                "snapshotTags/Deployment"
            } else {
                "diskTags/Deployment"
            }] = json!("wrong-deployment")
        }
        3 if snapshot => value["driver"] = json!("wrong.csi.example.test"),
        3 => value["provisioner"] = json!("wrong.csi.example.test"),
        4 if snapshot => value["deletionPolicy"] = json!("Delete"),
        4 => value["parameters"]["kmsKeyId"] = json!("unreviewed-key"),
        5 if snapshot => value["parameters"]["unexpected"] = json!("value"),
        5 => {
            value["volumeBindingMode"] = json!(if value["volumeBindingMode"] == "Immediate" {
                "WaitForFirstConsumer"
            } else {
                "Immediate"
            })
        }
        6 => value["allowedTopologies"]
            .as_array_mut()
            .unwrap()
            .push(json!({"matchLabelExpressions":[]})),
        7 => value["parameters"]["zoneId"] = json!("cn-hangzhou-a"),
        8 => value["mountOptions"] = json!(["discard"]),
        9 => {
            value["metadata"]["annotations"] =
                json!({"storageclass.kubernetes.io/is-default-class":"true"})
        }
        10 => {
            value["parameters"]["csi.storage.k8s.io/provisioner-secret-name"] =
                json!("unreviewed-secret")
        }
        11 => {
            value["allowVolumeExpansion"] = json!(!value["allowVolumeExpansion"].as_bool().unwrap())
        }
        12 => {
            value["allowedTopologies"] = json!([{"matchLabelExpressions":[{
                "key":"topology.diskplugin.csi.alibabacloud.com/zone",
                "values":["cn-hangzhou-a"]
            }]}])
        }
        _ => unreachable!(),
    }
}

pub(super) async fn pending_and_drift(
    c: &manifest::RestoreStorageContext,
    cloud: &BackupCloudSettings,
    source: &BackupIdentity,
    mut objects: BTreeMap<String, Value>,
) -> anyhow::Result<()> {
    let expected: PersistentVolumeClaim = serde_json::from_value(c.block_pvc()?)?;
    let expected = serde_json::to_value(expected)?;
    let collection = "/api/v1/namespaces/sandbox-system/persistentvolumeclaims";
    let raw_pvc = format!(
        "{collection}/{}",
        expected["metadata"]["name"].as_str().unwrap()
    );
    objects.remove(&raw_pvc);
    let raw_name = expected["metadata"]["name"].as_str().unwrap();
    objects.retain(|path, object| {
        !(path.starts_with("/api/v1/persistentvolumes/")
            && object.pointer("/spec/claimRef/namespace") == Some(&json!("sandbox-system"))
            && object.pointer("/spec/claimRef/name") == Some(&json!(raw_name)))
    });
    // The positive path actually creates Pending; no PV/Bound receipt is seeded.
    for identity in [
        &c.storage_contract.mapping.normal,
        &c.storage_contract.mapping.raw,
        &c.storage_contract.mapping.delivery,
    ] {
        let path = class_path(&identity.name);
        for edit in 0..14 {
            let mut changed = objects.clone();
            mutate(
                changed.get_mut(&path).context("initial class fixture")?,
                edit,
                false,
            );
            let f = Fixture::new(changed, Some((collection.to_owned(), expected.clone()))).await?;
            ensure!(
                Box::pin(
                    f.runtime
                        .reconcile_restore_block(c, cloud, None, None, source)
                )
                .await
                .is_err(),
                "initial class {} drift {edit} was accepted",
                identity.name
            );
            f.no_mutation_after_read(&path)?;
            f.finish().await?;
        }
    }
    let snapshot = snapshot_path(&c.storage_contract.mapping.snapshot.name);
    for edit in [0, 1, 2, 3, 4, 5, 13] {
        let mut changed = objects.clone();
        mutate(
            changed
                .get_mut(&snapshot)
                .context("snapshot class fixture")?,
            edit,
            true,
        );
        let f = Fixture::new(changed, Some((collection.to_owned(), expected.clone()))).await?;
        ensure!(
            Box::pin(
                f.runtime
                    .reconcile_restore_block(c, cloud, None, None, source)
            )
            .await
            .is_err(),
            "initial snapshot class drift {edit} was accepted"
        );
        f.no_mutation_after_read(&snapshot)?;
        f.finish().await?;
    }
    let f = Fixture::new(objects, Some((collection.to_owned(), expected))).await?;
    let observed = Box::pin(
        f.runtime
            .reconcile_restore_block(c, cloud, None, None, source),
    )
    .await?;
    ensure!(
        observed.bound.is_none() && !observed.pvc_uid.is_nil(),
        "actual new raw PVC must remain Pending"
    );
    {
        let state = f.state.lock().unwrap();
        ensure!(
            state
                .requests
                .iter()
                .filter(|(m, _)| *m == Method::POST)
                .count()
                == 1,
            "exactly one actual raw PVC POST required"
        );
        ensure!(
            state.objects[&raw_pvc]["status"]["phase"] == "Pending"
                && state.objects[&raw_pvc]
                    .pointer("/spec/volumeName")
                    .is_none(),
            "Pending raw PVC must not acquire a fabricated Bound pair"
        );
    }
    f.finish().await?;
    Ok(())
}

pub(super) async fn snapshot_and_delivery_drift(
    p: &snapshot_ledger::RestoreDeliveryPlan,
    objects: BTreeMap<String, Value>,
    certification_id: &str,
) -> anyhow::Result<()> {
    let mapping = &p.snapshot.context.storage_contract.mapping;
    for (path, snapshot, edits) in [
        (
            class_path(&mapping.raw.name),
            false,
            (0..14).collect::<Vec<_>>(),
        ),
        (
            snapshot_path(&mapping.snapshot.name),
            true,
            vec![0, 1, 2, 3, 4, 5, 13],
        ),
    ] {
        for edit in edits {
            let mut changed = objects.clone();
            mutate(
                changed
                    .get_mut(&path)
                    .context("snapshot-stage class fixture")?,
                edit,
                snapshot,
            );
            let f = Fixture::new(changed, None).await?;
            ensure!(
                Box::pin(f.runtime.reconcile_restore_snapshot(&p.snapshot))
                    .await
                    .is_err(),
                "snapshot stage drift {edit} was accepted"
            );
            f.no_mutation_after_read(&path)?;
            f.finish().await?;
        }
    }
    let path = class_path(&mapping.delivery.name);
    for edit in 0..14 {
        let mut changed = objects.clone();
        mutate(
            changed.get_mut(&path).context("delivery class fixture")?,
            edit,
            false,
        );
        let f = Fixture::new(changed, None).await?;
        ensure!(
            Box::pin(f.runtime.reconcile_restore_delivery(p, certification_id))
                .await
                .is_err(),
            "Immediate delivery class drift {edit} was accepted"
        );
        f.no_mutation_after_read(&path)?;
        f.finish().await?;
    }
    Ok(())
}
