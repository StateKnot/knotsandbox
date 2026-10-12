#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use crate::termination_client::{TerminationObservation, test_support};
use axum::{
    body::Body,
    http::{Method, Request, Response},
};
use http_body_util::BodyExt;
use kube::{Client, client::Body as KubeBody};
use serde_json::Value;
use std::{
    convert::Infallible,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

#[derive(Clone)]
struct Cluster {
    pod: Arc<Mutex<Option<Value>>>,
    pvc: Arc<Mutex<Value>>,
    pv: Arc<Mutex<Value>>,
    attached: Arc<Mutex<bool>>,
    race: Arc<Mutex<bool>>,
    patches: Arc<AtomicUsize>,
}
fn cluster(node: &NodeBinding, launch: &LaunchBinding) -> Cluster {
    let labels: std::collections::BTreeMap<_, _> = [
        ("tenant-id", launch.tenant_id.to_string()),
        ("project-id", launch.project_id.to_string()),
        ("instance-id", launch.instance_id.to_string()),
        ("workspace-id", launch.workspace_id.to_string()),
        ("generation", launch.generation.to_string()),
        ("launch-id", launch.launch_id.to_string()),
        ("cluster-epoch", node.cluster_epoch.to_string()),
    ]
    .into_iter()
    .map(|(key, value)| (format!("sandbox.platform/{key}"), value))
    .collect();
    Cluster {
        pod: Arc::new(Mutex::new(Some(
            json!({"apiVersion":"v1","kind":"Pod","metadata":{"uid":launch.pod_uid,"name":launch.pod_name,"namespace":launch.namespace,
            "resourceVersion":"7","deletionTimestamp":Utc::now(),"finalizers":[TERMINATION_FINALIZER],"labels":labels},"spec":{"containers":[],"nodeName":node.node_name,"runtimeClassName":"kata-qemu"}}),
        ))),
        pvc: Arc::new(Mutex::new(
            json!({"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":{"uid":launch.pvc_uid,"name":pvc_name(launch.workspace_id),"namespace":launch.namespace},"spec":{"volumeName":launch.pv_name},"status":{"phase":"Bound"}}),
        )),
        pv: Arc::new(Mutex::new(
            json!({"apiVersion":"v1","kind":"PersistentVolume","metadata":{"uid":launch.pv_uid,"name":launch.pv_name},"spec":{"volumeMode":"Filesystem","accessModes":["ReadWriteOnce"],"persistentVolumeReclaimPolicy":"Retain",
            "csi":{"driver":CSI_DRIVER,"volumeHandle":launch.csi_volume_handle},"claimRef":{"uid":launch.pvc_uid,"name":pvc_name(launch.workspace_id),"namespace":launch.namespace}}}),
        )),
        attached: Arc::new(Mutex::new(false)),
        race: Arc::new(Mutex::new(false)),
        patches: Arc::new(AtomicUsize::new(0)),
    }
}
fn runtime(cluster: Cluster) -> TerminationRuntime {
    let client = Client::new(
        tower::service_fn(move |request: Request<KubeBody>| {
            let c = cluster.clone();
            async move {
                let path = request.uri().path().to_owned();
                let method = request.method().clone();
                let body = request.into_body().collect().await.unwrap().to_bytes();
                let mut status = 200;
                let value = if path.contains("/pods/") {
                    let mut current = c.pod.lock().unwrap();
                    if method == Method::PATCH {
                        c.patches.fetch_add(1, Ordering::SeqCst);
                        let patch: Value = serde_json::from_slice(&body).unwrap();
                        if *c.race.lock().unwrap() {
                            current.as_mut().unwrap()["metadata"]["resourceVersion"] = json!("8");
                        }
                        if current.as_ref().is_some_and(|pod| {
                            patch["metadata"]["uid"] == pod["metadata"]["uid"]
                                && patch["metadata"]["resourceVersion"]
                                    == pod["metadata"]["resourceVersion"]
                                && patch["metadata"]["finalizers"] == json!([])
                        }) {
                            let mut removed = current.take().unwrap();
                            removed["metadata"]["finalizers"] = json!([]);
                            removed
                        } else {
                            status = 409;
                            status_value(status)
                        }
                    } else if let Some(pod) = current.as_ref() {
                        pod.clone()
                    } else {
                        status = 404;
                        status_value(status)
                    }
                } else if path.contains("/persistentvolumeclaims/") {
                    c.pvc.lock().unwrap().clone()
                } else if path.contains("/persistentvolumes/") {
                    c.pv.lock().unwrap().clone()
                } else if path.ends_with("/volumeattachments") {
                    let items = if *c.attached.lock().unwrap() {
                        vec![
                            json!({"metadata":{"name":"old-attachment"},"spec":{"attacher":CSI_DRIVER,"nodeName":"old-node","source":{"persistentVolumeName":c.pv.lock().unwrap()["metadata"]["name"]}},"status":{"attached":true}}),
                        ]
                    } else {
                        vec![]
                    };
                    json!({"apiVersion":"storage.k8s.io/v1","kind":"VolumeAttachmentList","metadata":{"resourceVersion":"10"},"items":items})
                } else {
                    status = 404;
                    status_value(status)
                };
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_vec(&value).unwrap()))
                        .unwrap(),
                )
            }
        }),
        "default",
    );
    TerminationRuntime::new(
        KubernetesRuntime::from_client(client),
        RuntimeManifestConfig {
            runtime_class_name: "kata-qemu".into(),
            dns_namespace: "kube-system".into(),
            dns_labels: [("k8s-app".into(), "kube-dns".into())].into(),
            ephemeral_storage_mib: 1024,
            tmp_size_mib: 256,
        },
        "test-reference".into(),
    )
}
fn status_value(code: u16) -> Value {
    json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":if code==404{"NotFound"}else{"Conflict"},"message":"test state changed","code":code})
}

#[tokio::test]
async fn cleanup_preserves_volume_attachment_gate_and_exact_resource_version() -> anyhow::Result<()>
{
    let node = test_support::node();
    let launch = test_support::launch();
    let guard = test_support::FixtureGuard::start(node.clone()).await?;
    let request = test_support::request(node.clone(), launch.clone());
    let TerminationObservation::Verified(proof) = guard.client.close(&request).await? else {
        panic!("expected real mTLS test evidence")
    };
    let c = cluster(&node, &launch);
    *c.attached.lock().unwrap() = true;
    let runtime = runtime(c.clone());
    assert!(runtime.cleanup(&proof).await?.is_none());
    assert_eq!(c.patches.load(Ordering::SeqCst), 1);
    assert!(c.pod.lock().unwrap().is_none());
    *c.attached.lock().unwrap() = false;
    let cleanup = runtime.cleanup(&proof).await?.unwrap();
    assert_eq!(cleanup.proof_challenge_id(), request.challenge_id);
    assert_eq!(cleanup.launch(), &launch);
    assert_eq!(cleanup.node(), &node);
    assert!(cleanup.pod_resource_version().is_none());
    assert!(cleanup.volume_checked_at() >= cleanup.pod_absent_at());
    guard.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn replaced_pod_changed_volume_or_concurrent_patch_never_complete_cleanup()
-> anyhow::Result<()> {
    let node = test_support::node();
    let launch = test_support::launch();
    let guard = test_support::FixtureGuard::start(node.clone()).await?;
    let request = test_support::request(node.clone(), launch.clone());
    let TerminationObservation::Verified(proof) = guard.client.close(&request).await? else {
        panic!("expected test evidence")
    };
    let c = cluster(&node, &launch);
    c.pod.lock().unwrap().as_mut().unwrap()["metadata"]["uid"] = json!(Uuid::new_v4());
    assert!(runtime(c.clone()).cleanup(&proof).await.is_err());
    assert_eq!(c.patches.load(Ordering::SeqCst), 0);
    let c = cluster(&node, &launch);
    *c.race.lock().unwrap() = true;
    assert!(matches!(
        runtime(c.clone()).cleanup(&proof).await,
        Err(RuntimeError::Kubernetes(Some(409)))
    ));
    assert!(c.pod.lock().unwrap().is_some());
    let c = cluster(&node, &launch);
    c.pv.lock().unwrap()["spec"]["csi"]["volumeHandle"] = json!("d-other-tenant");
    assert!(runtime(c).cleanup(&proof).await.is_err());
    guard.shutdown().await?;
    Ok(())
}
