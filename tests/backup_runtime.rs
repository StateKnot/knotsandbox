//! Real kube Client against a stateful synthetic apiserver. No cloud / CSI VM
//! certification is inferred from these control-plane transport tests.
use axum::{
    body::Body,
    http::{Method, Request, Response},
};
use chrono::{Duration, Utc};
use kube::{Client, client::Body as KubeBody};
use sandbox_platform::{
    backup_manifest::{BackupBlockContext, block_pvc_name, build_backup_block_pvc},
    backup_runtime::*,
    runtime::KubernetesRuntime,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};
use uuid::Uuid;
struct Fixture {
    source: BackupSource,
    class: Value,
    snapshot: Value,
    content: Value,
    pvc: Value,
    pv: Value,
}
impl Fixture {
    fn new() -> anyhow::Result<Self> {
        let source = BackupSource {
            tenant_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            backup_id: Uuid::new_v4(),
            cluster_epoch: Uuid::new_v4(),
            namespace: "sandbox-project".into(),
            pvc_name: String::new(),
            pvc_uid: Uuid::new_v4(),
            pv_name: "source-volume".into(),
            pv_uid: Uuid::new_v4(),
            cloud_disk: "d-source0001".into(),
            storage_class: "workspace-retain".into(),
            snapshot_class: "snapshot-retain".into(),
            size_bytes: 20 * 1024_u64.pow(3),
        };
        let source = BackupSource {
            pvc_name: format!("ws-{}", source.workspace_id),
            ..source
        };
        let mut snapshot = serde_json::to_value(source.snapshot()?)?;
        let suid = Uuid::new_v4();
        let cuid = Uuid::new_v4();
        let now = Utc::now() - Duration::minutes(1);
        snapshot["metadata"]["uid"] = json!(suid);
        snapshot["status"] = json!({"boundVolumeSnapshotContentName":"snapcontent-source","readyToUse":true,"creationTime":now.to_rfc3339_opts(chrono::SecondsFormat::Secs,true),"restoreSize":"20Gi"});
        let content = json!({"apiVersion":"snapshot.storage.k8s.io/v1","kind":"VolumeSnapshotContent","metadata":{"name":"snapcontent-source","uid":cuid},"spec":{"driver":"diskplugin.csi.alibabacloud.com","deletionPolicy":"Retain","volumeSnapshotClassName":source.snapshot_class,"sourceVolumeMode":"Filesystem","source":{"volumeHandle":source.cloud_disk},"volumeSnapshotRef":{"namespace":source.namespace,"name":source.snapshot_name(),"uid":suid}},"status":{"readyToUse":true,"snapshotHandle":"s-snapshot001","creationTime":now.timestamp_nanos_opt(),"restoreSize":source.size_bytes}});
        let pvc = json!({"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":{"namespace":source.namespace,"name":source.pvc_name,"uid":source.pvc_uid},"spec":{"storageClassName":source.storage_class,"volumeMode":"Filesystem","volumeName":source.pv_name,"accessModes":["ReadWriteOnce"]},"status":{"phase":"Bound"}});
        let pv = json!({"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":source.pv_name,"uid":source.pv_uid},"spec":{"storageClassName":source.storage_class,"volumeMode":"Filesystem","persistentVolumeReclaimPolicy":"Retain","accessModes":["ReadWriteOnce"],"capacity":{"storage":"20Gi"},"csi":{"driver":"diskplugin.csi.alibabacloud.com","volumeHandle":source.cloud_disk},"claimRef":{"kind":"PersistentVolumeClaim","uid":source.pvc_uid,"namespace":source.namespace,"name":source.pvc_name}},"status":{"phase":"Bound"}});
        Ok(Self {
            class: json!({"apiVersion":"snapshot.storage.k8s.io/v1","kind":"VolumeSnapshotClass","metadata":{"name":source.snapshot_class},"driver":"diskplugin.csi.alibabacloud.com","deletionPolicy":"Retain","parameters":{"snapshotTags/Deployment":"sandbox"}}),
            source,
            snapshot,
            content,
            pvc,
            pv,
        })
    }
    fn client(&self, include_snapshot: bool) -> (BackupRuntime, Arc<Mutex<Vec<Method>>>) {
        let s = &self.source;
        let mut objects = BTreeMap::from([
            (
                format!(
                    "/api/v1/namespaces/{}/persistentvolumeclaims/{}",
                    s.namespace, s.pvc_name
                ),
                self.pvc.clone(),
            ),
            (
                format!("/api/v1/persistentvolumes/{}", s.pv_name),
                self.pv.clone(),
            ),
            (
                format!(
                    "/apis/snapshot.storage.k8s.io/v1/volumesnapshotclasses/{}",
                    s.snapshot_class
                ),
                self.class.clone(),
            ),
            (
                "/apis/snapshot.storage.k8s.io/v1/volumesnapshotcontents/snapcontent-source".into(),
                self.content.clone(),
            ),
        ]);
        if include_snapshot {
            objects.insert(
                format!(
                    "/apis/snapshot.storage.k8s.io/v1/namespaces/{}/volumesnapshots/{}",
                    s.namespace,
                    s.snapshot_name()
                ),
                self.snapshot.clone(),
            );
        }
        let objects = Arc::new(Mutex::new(objects));
        let methods = Arc::new(Mutex::new(vec![]));
        let observed = methods.clone();
        let svc = tower::service_fn(move |r: Request<KubeBody>| {
            let objects = objects.clone();
            let methods = observed.clone();
            async move {
                let method = r.method().clone();
                let path = r.uri().path().to_owned();
                if let Ok(mut m) = methods.lock() {
                    m.push(method.clone());
                }
                let body = if method == Method::POST {
                    let bytes = axum::body::to_bytes(Body::new(r.into_body()), 131072)
                        .await
                        .unwrap_or_default();
                    serde_json::from_slice::<Value>(&bytes).ok()
                } else {
                    None
                };
                let (status, value) = if let Ok(mut o) = objects.lock() {
                    if let Some(mut b) = body {
                        b["metadata"]["uid"] = json!(Uuid::new_v4());
                        let key = format!(
                            "{path}/{}",
                            b["metadata"]["name"].as_str().unwrap_or_default()
                        );
                        o.insert(key, b.clone());
                        (201, b)
                    } else if let Some(v) = o.get(&path) {
                        (200, v.clone())
                    } else {
                        (
                            404,
                            json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404}),
                        )
                    }
                } else {
                    (
                        500,
                        json!({"kind":"Status","code":500,"reason":"InternalError","status":"Failure"}),
                    )
                };
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(Body::from(value.to_string()))
                        .unwrap_or_else(|_| Response::new(Body::empty())),
                )
            }
        });
        (
            BackupRuntime::new(KubernetesRuntime::from_client(Client::new(svc, "default"))),
            methods,
        )
    }
}
#[test]
fn exact_source_and_snapshot_identity_rejects_drift() -> anyhow::Result<()> {
    let f = Fixture::new()?;
    validate_source(&f.source, &f.pvc, &f.pv)?;
    let ready = validate_snapshot_ready(
        &f.source,
        &f.snapshot,
        &f.content,
        &SnapshotKnown::default(),
    )?
    .ok_or_else(|| anyhow::anyhow!("ready"))?;
    assert_eq!(ready.restore_size, f.source.size_bytes);
    for (path, v) in [
        ("/spec/sourceVolumeMode", json!("Block")),
        ("/spec/deletionPolicy", json!("Delete")),
        ("/spec/source/volumeHandle", json!("d-other")),
        ("/spec/volumeSnapshotRef/uid", json!(Uuid::new_v4())),
        ("/status/restoreSize", json!(1)),
        ("/status/snapshotHandle", json!("d-wrong")),
        (
            "/status/creationTime",
            json!(Utc::now().timestamp_nanos_opt()),
        ),
    ] {
        let mut c = f.content.clone();
        *c.pointer_mut(path)
            .ok_or_else(|| anyhow::anyhow!("{path}"))? = v;
        assert!(
            validate_snapshot_ready(&f.source, &f.snapshot, &c, &SnapshotKnown::default()).is_err(),
            "{path}"
        );
    }
    let mut pv = f.pv.clone();
    pv["spec"]["csi"]["volumeHandle"] = json!("d-foreign");
    assert!(validate_source(&f.source, &f.pvc, &pv).is_err());
    Ok(())
}
#[test]
fn clone_must_be_new_block_disk_not_original_filesystem() -> anyhow::Result<()> {
    let f = Fixture::new()?;
    let b = BackupBlockContext {
        backup_id: f.source.backup_id,
        attempt_id: Uuid::new_v4(),
        storage_class: "backup-retain".into(),
        size_bytes: f.source.size_bytes,
        snapshot_name: Some(f.source.snapshot_name()),
    };
    let uid = Uuid::new_v4();
    let mut pvc = build_backup_block_pvc(&b)?;
    pvc["metadata"]["uid"] = json!(uid);
    pvc["spec"]["volumeName"] = json!("clone-volume");
    pvc["status"] = json!({"phase":"Bound"});
    let mut pv = f.pv.clone();
    pv["metadata"]["name"] = json!("clone-volume");
    pv["metadata"]["uid"] = json!(Uuid::new_v4());
    pv["spec"]["storageClassName"] = json!(b.storage_class);
    pv["spec"]["volumeMode"] = json!("Block");
    pv["spec"]["csi"]["volumeHandle"] = json!("d-clone001");
    pv["spec"]["claimRef"] = json!({"kind":"PersistentVolumeClaim","uid":uid,"name":block_pvc_name(b.attempt_id),"namespace":"sandbox-system"});
    validate_bound_clone(&f.source, &b, &pvc, &pv, None)?;
    for (path, v) in [
        ("/spec/csi/volumeHandle", json!(f.source.cloud_disk)),
        ("/metadata/uid", json!(f.source.pv_uid)),
        ("/spec/volumeMode", json!("Filesystem")),
        ("/spec/persistentVolumeReclaimPolicy", json!("Delete")),
        ("/spec/claimRef/namespace", json!(f.source.namespace)),
    ] {
        let mut x = pv.clone();
        *x.pointer_mut(path).ok_or_else(|| anyhow::anyhow!("path"))? = v;
        assert!(
            validate_bound_clone(&f.source, &b, &pvc, &x, None).is_err(),
            "{path}"
        );
    }
    Ok(())
}
#[tokio::test]
async fn restart_adopts_exact_snapshot_without_second_create_and_uid_loss_fails_closed()
-> anyhow::Result<()> {
    let f = Fixture::new()?;
    let (runtime, methods) = f.client(true);
    let result = runtime
        .reconcile_snapshot(&f.source, &SnapshotKnown::default(), "sandbox")
        .await?;
    let ready = result.ready.ok_or_else(|| anyhow::anyhow!("ready"))?;
    runtime
        .reconcile_snapshot(
            &f.source,
            &SnapshotKnown {
                snapshot_uid: Some(result.snapshot_uid),
                content_uid: Some(ready.content_uid),
            },
            "sandbox",
        )
        .await?;
    assert!(
        methods
            .lock()
            .map_err(|_| anyhow::anyhow!("mutex"))?
            .iter()
            .all(|m| m == Method::GET)
    );
    let (runtime, methods) = f.client(false);
    assert!(
        runtime
            .reconcile_snapshot(
                &f.source,
                &SnapshotKnown {
                    snapshot_uid: Some(result.snapshot_uid),
                    content_uid: None
                },
                "sandbox",
            )
            .await
            .is_err()
    );
    assert!(
        methods
            .lock()
            .map_err(|_| anyhow::anyhow!("mutex"))?
            .iter()
            .all(|m| m == Method::GET)
    );
    Ok(())
}
#[tokio::test]
async fn snapshot_class_tag_drift_prevents_any_create() -> anyhow::Result<()> {
    for (field, value) in [
        ("parameters", json!({})),
        ("parameters", json!({"snapshotTags/Deployment":"foreign"})),
        (
            "parameters",
            json!({"snapshotTags/Deployment":"sandbox","unexpected":"yes"}),
        ),
        ("deletionPolicy", json!("Delete")),
        ("driver", json!("foreign.csi.invalid")),
    ] {
        let mut f = Fixture::new()?;
        f.class[field] = value;
        let (runtime, methods) = f.client(false);
        assert!(
            runtime
                .reconcile_snapshot(&f.source, &SnapshotKnown::default(), "sandbox")
                .await
                .is_err()
        );
        assert!(
            methods
                .lock()
                .map_err(|_| anyhow::anyhow!("mutex"))?
                .iter()
                .all(|m| m == Method::GET)
        );
    }
    Ok(())
}

#[tokio::test]
async fn first_snapshot_create_is_real_and_pending_is_not_backup_success() -> anyhow::Result<()> {
    let f = Fixture::new()?;
    let (runtime, methods) = f.client(false);
    let result = runtime
        .reconcile_snapshot(&f.source, &SnapshotKnown::default(), "sandbox")
        .await?;
    assert!(result.ready.is_none());
    assert!(!result.snapshot_uid.is_nil());
    assert_eq!(
        methods
            .lock()
            .map_err(|_| anyhow::anyhow!("mutex"))?
            .iter()
            .filter(|m| **m == Method::POST)
            .count(),
        1
    );
    Ok(())
}
