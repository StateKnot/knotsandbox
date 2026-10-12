//! Real CSI snapshot/clone I/O with exact immutable identities. ReadyToUse is
//! snapshot evidence only: it is not independent backup or application recovery.
use crate::{
    backup_manifest::{BACKUP_LABEL, BackupBlockContext, NAMESPACE, build_backup_block_pvc},
    runtime::{KubernetesRuntime, RuntimeError},
    runtime_manifest::ManifestError,
};
use chrono::{DateTime, Utc};
use k8s_openapi::api::core::v1::{PersistentVolume, PersistentVolumeClaim};
use kube::{
    Api,
    api::PostParams,
    core::{ApiResource, DynamicObject, GroupVersionKind},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

const DRIVER: &str = "diskplugin.csi.alibabacloud.com";
const PROTECTION: &str = "sandbox.platform/backup-protection";
fn require(ok: bool, why: &'static str) -> Result<(), RuntimeError> {
    if ok {
        Ok(())
    } else {
        Err(ManifestError::SpecificationDrift(why).into())
    }
}
pub(crate) fn validate_snapshot_class(value: &Value, deployment: &str) -> Result<(), RuntimeError> {
    require(
        crate::backup_job::valid_deployment(deployment)
            && value.get("driver") == Some(&json!(DRIVER))
            && value.get("deletionPolicy") == Some(&json!("Retain"))
            && value.get("parameters") == Some(&json!({"snapshotTags/Deployment":deployment}))
            && value
                .pointer("/metadata/deletionTimestamp")
                .is_none_or(Value::is_null),
        "snapshot class driver, retention or deployment tag drift",
    )
}
fn id(value: Option<&str>) -> Result<Uuid, RuntimeError> {
    value
        .and_then(|s| Uuid::parse_str(s).ok())
        .filter(|u| !u.is_nil())
        .ok_or(RuntimeError::MissingIdentity)
}
pub(crate) fn dyn_api(
    runtime: &KubernetesRuntime,
    kind: &str,
    namespace: Option<&str>,
) -> Api<DynamicObject> {
    let ar = ApiResource::from_gvk(&GroupVersionKind::gvk(
        "snapshot.storage.k8s.io",
        "v1",
        kind,
    ));
    match namespace {
        Some(ns) => Api::namespaced_with(runtime.client_clone(), ns, &ar),
        None => Api::all_with(runtime.client_clone(), &ar),
    }
}
fn encode(value: &impl Serialize) -> Result<Value, RuntimeError> {
    serde_json::to_value(value).map_err(|_| RuntimeError::MissingIdentity)
}
fn object(value: Value) -> Result<DynamicObject, RuntimeError> {
    serde_json::from_value(value).map_err(|_| RuntimeError::MissingIdentity)
}
fn decimal_bytes(value: &Value) -> Option<u64> {
    let s = value.as_str()?;
    for (suffix, factor) in [
        ("Ti", 1024_u64.pow(4)),
        ("Gi", 1024_u64.pow(3)),
        ("Mi", 1024_u64.pow(2)),
        ("Ki", 1024),
    ] {
        if let Some(n) = s.strip_suffix(suffix) {
            return n.parse::<u64>().ok()?.checked_mul(factor);
        }
    }
    s.parse().ok()
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSource {
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub workspace_id: Uuid,
    pub backup_id: Uuid,
    pub cluster_epoch: Uuid,
    pub namespace: String,
    pub pvc_name: String,
    pub pvc_uid: Uuid,
    pub pv_name: String,
    pub pv_uid: Uuid,
    pub cloud_disk: String,
    pub storage_class: String,
    pub snapshot_class: String,
    pub size_bytes: u64,
}
impl BackupSource {
    pub fn validate(&self) -> Result<(), RuntimeError> {
        require(
            [
                self.tenant_id,
                self.project_id,
                self.workspace_id,
                self.backup_id,
                self.cluster_epoch,
                self.pvc_uid,
                self.pv_uid,
            ]
            .iter()
            .all(|u| !u.is_nil())
                && self.pvc_name == format!("ws-{}", self.workspace_id)
                && crate::backup_manifest::valid_name(&self.namespace)
                && crate::backup_manifest::valid_name(&self.pv_name)
                && crate::backup_manifest::valid_name(&self.storage_class)
                && crate::backup_manifest::valid_name(&self.snapshot_class)
                && self
                    .cloud_disk
                    .strip_prefix("d-")
                    .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric()))
                && self.size_bytes > 0
                && self.size_bytes.is_multiple_of(512)
                && self.size_bytes <= 16 * 1024_u64.pow(4),
            "invalid backup source",
        )
    }
    pub fn snapshot_name(&self) -> String {
        format!("sbx-bs-{}", self.backup_id)
    }
    pub fn snapshot(&self) -> Result<DynamicObject, RuntimeError> {
        self.validate()?;
        object(
            json!({"apiVersion":"snapshot.storage.k8s.io/v1","kind":"VolumeSnapshot",
        "metadata":{"name":self.snapshot_name(),"namespace":self.namespace,"labels":{BACKUP_LABEL:self.backup_id,"sandbox.platform/tenant-id":self.tenant_id,"sandbox.platform/project-id":self.project_id,"sandbox.platform/cluster-epoch":self.cluster_epoch},"finalizers":[PROTECTION]},
        "spec":{"volumeSnapshotClassName":self.snapshot_class,"source":{"persistentVolumeClaimName":self.pvc_name}}}),
        )
    }
}
#[derive(Clone, Debug, Default)]
pub struct SnapshotKnown {
    pub snapshot_uid: Option<Uuid>,
    pub content_uid: Option<Uuid>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotReady {
    pub snapshot_uid: Uuid,
    pub content_uid: Uuid,
    pub content_name: String,
    pub cloud_snapshot: String,
    pub created_at: DateTime<Utc>,
    pub restore_size: u64,
}
#[derive(Clone, Debug)]
pub struct SnapshotObservation {
    pub snapshot_uid: Uuid,
    pub ready: Option<SnapshotReady>,
}
#[derive(Clone, Debug, Default)]
pub struct CloneKnown {
    pub delegated_content_uid: Option<Uuid>,
    pub delegated_snapshot_uid: Option<Uuid>,
    pub pvc_uid: Option<Uuid>,
    pub pv_uid: Option<Uuid>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BoundBackupVolume {
    pub pvc_uid: Uuid,
    pub pv_uid: Uuid,
    pub pv_name: String,
    pub cloud_disk: String,
    pub size_bytes: u64,
}
#[derive(Clone, Debug)]
pub struct CloneObservation {
    pub delegated_content_uid: Uuid,
    pub delegated_snapshot_uid: Uuid,
    pub pvc_uid: Uuid,
    pub bound: Option<BoundBackupVolume>,
}
#[derive(Clone)]
pub struct BackupRuntime {
    runtime: KubernetesRuntime,
}
impl BackupRuntime {
    pub fn new(runtime: KubernetesRuntime) -> Self {
        Self { runtime }
    }
    pub async fn verify_source(&self, source: &BackupSource) -> Result<(), RuntimeError> {
        source.validate()?;
        let pvcs: Api<PersistentVolumeClaim> =
            Api::namespaced(self.runtime.client_clone(), &source.namespace);
        let pvs: Api<PersistentVolume> = Api::all(self.runtime.client_clone());
        let pvc = encode(&pvcs.get(&source.pvc_name).await?)?;
        let pv = encode(&pvs.get(&source.pv_name).await?)?;
        validate_source(source, &pvc, &pv)
    }
    pub async fn reconcile_snapshot(
        &self,
        source: &BackupSource,
        known: &SnapshotKnown,
        deployment: &str,
    ) -> Result<SnapshotObservation, RuntimeError> {
        self.verify_source(source).await?;
        let class = dyn_api(&self.runtime, "VolumeSnapshotClass", None)
            .get(&source.snapshot_class)
            .await?;
        let class = encode(&class)?;
        validate_snapshot_class(&class, deployment)?;
        let expected = source.snapshot()?;
        let api = dyn_api(&self.runtime, "VolumeSnapshot", Some(&source.namespace));
        let snapshot = ensure(&api, &expected, known.snapshot_uid).await?;
        let snapshot_uid = id(snapshot.metadata.uid.as_deref())?;
        let value = encode(&snapshot)?;
        require(
            value.pointer("/status/error").is_none_or(Value::is_null),
            "CSI snapshot reported an error",
        )?;
        let Some(name) = value
            .pointer("/status/boundVolumeSnapshotContentName")
            .and_then(Value::as_str)
        else {
            return Ok(SnapshotObservation {
                snapshot_uid,
                ready: None,
            });
        };
        let content = dyn_api(&self.runtime, "VolumeSnapshotContent", None)
            .get(name)
            .await?;
        let ready = validate_snapshot_ready(source, &value, &encode(&content)?, known)?;
        Ok(SnapshotObservation {
            snapshot_uid,
            ready,
        })
    }
    pub async fn reconcile_clone(
        &self,
        source: &BackupSource,
        ready: &SnapshotReady,
        block: &BackupBlockContext,
        known: &CloneKnown,
    ) -> Result<CloneObservation, RuntimeError> {
        source.validate()?;
        require(
            block.backup_id == source.backup_id
                && block.size_bytes == source.size_bytes
                && crate::backup_manifest::valid_name(&block.storage_class)
                && block.snapshot_name.as_deref() == Some(source.snapshot_name().as_str()),
            "clone differs from snapshot intent",
        )?;
        // Re-read the source snapshot/content immediately before creating a static
        // cross-namespace reference; no caller-selected cloud snapshot handle.
        let snapshots = dyn_api(&self.runtime, "VolumeSnapshot", Some(&source.namespace));
        let snapshot = snapshots.get(&source.snapshot_name()).await?;
        let content = dyn_api(&self.runtime, "VolumeSnapshotContent", None)
            .get(&ready.content_name)
            .await?;
        let current = validate_snapshot_ready(
            source,
            &encode(&snapshot)?,
            &encode(&content)?,
            &SnapshotKnown {
                snapshot_uid: Some(ready.snapshot_uid),
                content_uid: Some(ready.content_uid),
            },
        )?
        .ok_or(ManifestError::SpecificationDrift(
            "snapshot no longer ready",
        ))?;
        require(
            current.cloud_snapshot == ready.cloud_snapshot
                && current.created_at == ready.created_at
                && current.restore_size == ready.restore_size,
            "snapshot identity changed",
        )?;
        let name = source.snapshot_name();
        let delegated = clone_content(source, ready)?;
        let delegated = ensure(
            &dyn_api(&self.runtime, "VolumeSnapshotContent", None),
            &delegated,
            known.delegated_content_uid,
        )
        .await?;
        let delegated_content_uid = id(delegated.metadata.uid.as_deref())?;
        let expected = clone_snapshot(source)?;
        let snapshot = ensure(
            &dyn_api(&self.runtime, "VolumeSnapshot", Some(NAMESPACE)),
            &expected,
            known.delegated_snapshot_uid,
        )
        .await?;
        let delegated_snapshot_uid = id(snapshot.metadata.uid.as_deref())?;
        let current_content = dyn_api(&self.runtime, "VolumeSnapshotContent", None)
            .get(&name)
            .await?;
        require(
            id(current_content.metadata.uid.as_deref())? == delegated_content_uid,
            "delegated content UID changed",
        )?;
        let delegated_value = encode(&current_content)?;
        if let Some(uid) = delegated_value.pointer("/spec/volumeSnapshotRef/uid") {
            require(
                uid == &json!(delegated_snapshot_uid),
                "delegated snapshot reference changed",
            )?;
        }
        let static_ready = delegated_value.pointer("/spec/volumeSnapshotRef/uid")
            == Some(&json!(delegated_snapshot_uid))
            && delegated_value.pointer("/status/readyToUse") == Some(&json!(true))
            && delegated_value.pointer("/status/snapshotHandle")
                == Some(&json!(ready.cloud_snapshot))
            && encode(&snapshot)?.pointer("/status/readyToUse") == Some(&json!(true));
        require(
            delegated_value
                .pointer("/status/error")
                .is_none_or(Value::is_null),
            "delegated snapshot error",
        )?;
        let pvc_api: Api<PersistentVolumeClaim> =
            Api::namespaced(self.runtime.client_clone(), NAMESPACE);
        let expected = scoped_block_pvc(source, block)?;
        let pvc_name = crate::backup_manifest::block_pvc_name(block.attempt_id);
        let pvc = match pvc_api.get_opt(&pvc_name).await? {
            Some(pvc) => pvc,
            None => {
                require(known.pvc_uid.is_none(), "recorded clone PVC disappeared")?;
                let body: PersistentVolumeClaim = serde_json::from_value(expected.clone())
                    .map_err(|_| RuntimeError::MissingIdentity)?;
                match pvc_api.create(&PostParams::default(), &body).await {
                    Ok(pvc) => pvc,
                    Err(kube::Error::Api(e)) if e.code == 409 => pvc_api.get(&pvc_name).await?,
                    Err(e) => return Err(e.into()),
                }
            }
        };
        let pvc_value = encode(&pvc)?;
        validate_clone_pvc(&pvc_value, &expected, known.pvc_uid)?;
        let pvc_uid = id(pvc.metadata.uid.as_deref())?;
        let bound = if pvc_value.pointer("/status/phase") == Some(&json!("Bound")) {
            require(
                static_ready,
                "clone bound before exact static snapshot readiness",
            )?;
            let name = pvc_value
                .pointer("/spec/volumeName")
                .and_then(Value::as_str)
                .ok_or(RuntimeError::MissingIdentity)?;
            let pvs: Api<PersistentVolume> = Api::all(self.runtime.client_clone());
            Some(validate_bound_clone(
                source,
                block,
                &pvc_value,
                &encode(&pvs.get(name).await?)?,
                known.pv_uid,
            )?)
        } else {
            None
        };
        Ok(CloneObservation {
            delegated_content_uid,
            delegated_snapshot_uid,
            pvc_uid,
            bound,
        })
    }
}

pub(crate) async fn ensure(
    api: &Api<DynamicObject>,
    expected: &DynamicObject,
    known: Option<Uuid>,
) -> Result<DynamicObject, RuntimeError> {
    let name = expected
        .metadata
        .name
        .as_deref()
        .ok_or(RuntimeError::MissingIdentity)?;
    let actual = match api.get_opt(name).await? {
        Some(v) => v,
        None => {
            require(known.is_none(), "recorded snapshot resource disappeared")?;
            match api.create(&PostParams::default(), expected).await {
                Ok(v) => v,
                Err(kube::Error::Api(e)) if e.code == 409 => api.get(name).await?,
                Err(e) => return Err(e.into()),
            }
        }
    };
    let uid = id(actual.metadata.uid.as_deref())?;
    require(known.is_none_or(|u| u == uid), "snapshot UID changed")?;
    require(
        actual.metadata.name == expected.metadata.name
            && actual.metadata.namespace == expected.metadata.namespace
            && actual.metadata.deletion_timestamp.is_none()
            && actual
                .metadata
                .owner_references
                .as_ref()
                .is_none_or(Vec::is_empty),
        "snapshot ownership changed",
    )?;
    let mut spec = actual
        .data
        .get("spec")
        .cloned()
        .ok_or(RuntimeError::MissingIdentity)?;
    // The snapshot-controller fills only this immutable UID after binding the
    // pre-provisioned content to the exact named snapshot. It is checked below.
    if expected
        .data
        .get("spec")
        .and_then(|s| s.get("volumeSnapshotRef"))
        .is_some()
        && let Some(reference) = spec
            .get_mut("volumeSnapshotRef")
            .and_then(Value::as_object_mut)
    {
        reference.remove("uid");
        reference.remove("resourceVersion");
        reference.remove("kind");
        reference.remove("apiVersion");
    }
    require(
        Some(&spec) == expected.data.get("spec"),
        "snapshot specification drift",
    )?;
    require(
        expected.metadata.labels.as_ref().is_none_or(|wanted| {
            wanted
                .iter()
                .all(|(k, v)| actual.metadata.labels.as_ref().and_then(|m| m.get(k)) == Some(v))
        }),
        "snapshot labels changed",
    )?;
    require(
        expected.metadata.annotations.as_ref().is_none_or(|wanted| {
            wanted.iter().all(|(k, v)| {
                actual.metadata.annotations.as_ref().and_then(|m| m.get(k)) == Some(v)
            })
        }),
        "snapshot conversion approval missing",
    )?;
    require(
        actual
            .metadata
            .finalizers
            .as_ref()
            .is_some_and(|f| f.iter().any(|v| v == PROTECTION)),
        "snapshot protection finalizer missing",
    )?;
    Ok(actual)
}
fn live_identity(
    value: &Value,
    uid: Uuid,
    name: &str,
    namespace: Option<&str>,
) -> Result<(), RuntimeError> {
    require(
        value.pointer("/metadata/uid") == Some(&json!(uid))
            && value.pointer("/metadata/name") == Some(&json!(name))
            && namespace.is_none_or(|ns| value.pointer("/metadata/namespace") == Some(&json!(ns)))
            && value
                .pointer("/metadata/deletionTimestamp")
                .is_none_or(Value::is_null),
        "storage identity changed",
    )
}
pub fn validate_source(s: &BackupSource, pvc: &Value, pv: &Value) -> Result<(), RuntimeError> {
    s.validate()?;
    live_identity(pvc, s.pvc_uid, &s.pvc_name, Some(&s.namespace))?;
    live_identity(pv, s.pv_uid, &s.pv_name, None)?;
    require(
        pvc.pointer("/status/phase") == Some(&json!("Bound"))
            && pvc.pointer("/spec/volumeName") == Some(&json!(s.pv_name))
            && pvc.pointer("/spec/storageClassName") == Some(&json!(s.storage_class))
            && pvc
                .pointer("/spec/volumeMode")
                .is_none_or(|v| v == &json!("Filesystem")),
        "source claim not expected filesystem volume",
    )?;
    validate_pv(
        pv,
        s.pvc_uid,
        &s.pvc_name,
        &s.namespace,
        &s.storage_class,
        "Filesystem",
        s.size_bytes,
    )?;
    require(
        pv.pointer("/spec/csi/volumeHandle") == Some(&json!(s.cloud_disk)),
        "source cloud disk changed",
    )
}
pub(crate) fn validate_pv(
    pv: &Value,
    pvc_uid: Uuid,
    pvc_name: &str,
    namespace: &str,
    class: &str,
    mode: &str,
    size: u64,
) -> Result<(), RuntimeError> {
    require(
        pv.pointer("/metadata/deletionTimestamp")
            .is_none_or(Value::is_null)
            && pv.pointer("/spec/csi/driver") == Some(&json!(DRIVER))
            && pv.pointer("/spec/persistentVolumeReclaimPolicy") == Some(&json!("Retain"))
            && pv.pointer("/status/phase") == Some(&json!("Bound"))
            && pv.pointer("/spec/storageClassName") == Some(&json!(class))
            && pv.pointer("/spec/volumeMode") == Some(&json!(mode))
            && pv.pointer("/spec/accessModes") == Some(&json!(["ReadWriteOnce"]))
            && pv.pointer("/spec/claimRef/uid") == Some(&json!(pvc_uid))
            && pv.pointer("/spec/claimRef/name") == Some(&json!(pvc_name))
            && pv.pointer("/spec/claimRef/namespace") == Some(&json!(namespace))
            && pv.pointer("/spec/claimRef/kind") == Some(&json!("PersistentVolumeClaim"))
            && pv.pointer("/spec/capacity/storage").and_then(decimal_bytes) == Some(size),
        "PV claim/driver/mode/retention/capacity changed",
    )
}
pub fn validate_snapshot_ready(
    s: &BackupSource,
    snapshot: &Value,
    content: &Value,
    known: &SnapshotKnown,
) -> Result<Option<SnapshotReady>, RuntimeError> {
    let snapshot_uid = id(snapshot.pointer("/metadata/uid").and_then(Value::as_str))?;
    let content_uid = id(content.pointer("/metadata/uid").and_then(Value::as_str))?;
    live_identity(
        snapshot,
        snapshot_uid,
        &s.snapshot_name(),
        Some(&s.namespace),
    )?;
    require(
        known.snapshot_uid.is_none_or(|u| u == snapshot_uid)
            && known.content_uid.is_none_or(|u| u == content_uid),
        "snapshot/content UID changed",
    )?;
    require(
        snapshot.pointer("/spec/source") == Some(&json!({"persistentVolumeClaimName":s.pvc_name}))
            && snapshot.pointer("/spec/volumeSnapshotClassName") == Some(&json!(s.snapshot_class)),
        "snapshot source changed",
    )?;
    let content_name = content
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .ok_or(RuntimeError::MissingIdentity)?;
    require(
        content
            .pointer("/metadata/deletionTimestamp")
            .is_none_or(Value::is_null)
            && snapshot.pointer("/status/boundVolumeSnapshotContentName")
                == Some(&json!(content_name))
            && content.pointer("/spec/driver") == Some(&json!(DRIVER))
            && content.pointer("/spec/deletionPolicy") == Some(&json!("Retain"))
            && content.pointer("/spec/volumeSnapshotClassName") == Some(&json!(s.snapshot_class))
            && content.pointer("/spec/sourceVolumeMode") == Some(&json!("Filesystem"))
            && content.pointer("/spec/source") == Some(&json!({"volumeHandle":s.cloud_disk}))
            && content.pointer("/spec/volumeSnapshotRef/uid") == Some(&json!(snapshot_uid))
            && content.pointer("/spec/volumeSnapshotRef/name") == Some(&json!(s.snapshot_name()))
            && content.pointer("/spec/volumeSnapshotRef/namespace") == Some(&json!(s.namespace))
            && content.pointer("/status/error").is_none_or(Value::is_null)
            && snapshot.pointer("/status/error").is_none_or(Value::is_null),
        "snapshot/content binding changed",
    )?;
    if snapshot.pointer("/status/readyToUse") != Some(&json!(true))
        || content.pointer("/status/readyToUse") != Some(&json!(true))
    {
        return Ok(None);
    }
    let cloud_snapshot = content
        .pointer("/status/snapshotHandle")
        .and_then(Value::as_str)
        .ok_or(RuntimeError::MissingIdentity)?;
    require(
        cloud_snapshot
            .strip_prefix("s-")
            .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric())),
        "invalid cloud snapshot handle",
    )?;
    let created = snapshot
        .pointer("/status/creationTime")
        .and_then(Value::as_str)
        .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
        .map(|v| v.with_timezone(&Utc))
        .ok_or(RuntimeError::MissingIdentity)?;
    let nanos = content
        .pointer("/status/creationTime")
        .and_then(Value::as_i64)
        .ok_or(RuntimeError::MissingIdentity)?;
    require(
        nanos > 0
            && created.timestamp() == nanos / 1_000_000_000
            && DateTime::<Utc>::from_timestamp_nanos(nanos) <= Utc::now()
            && snapshot
                .pointer("/status/restoreSize")
                .and_then(decimal_bytes)
                == Some(s.size_bytes)
            && content
                .pointer("/status/restoreSize")
                .and_then(Value::as_u64)
                == Some(s.size_bytes),
        "snapshot time or exact size changed",
    )?;
    Ok(Some(SnapshotReady {
        snapshot_uid,
        content_uid,
        content_name: content_name.into(),
        cloud_snapshot: cloud_snapshot.into(),
        created_at: DateTime::<Utc>::from_timestamp_micros(nanos.div_euclid(1000))
            .ok_or(RuntimeError::MissingIdentity)?,
        restore_size: s.size_bytes,
    }))
}
fn validate_clone_pvc(
    pvc: &Value,
    expected: &Value,
    uid: Option<Uuid>,
) -> Result<(), RuntimeError> {
    let actual_uid = id(pvc.pointer("/metadata/uid").and_then(Value::as_str))?;
    require(
        uid.is_none_or(|u| u == actual_uid)
            && pvc
                .pointer("/metadata/deletionTimestamp")
                .is_none_or(Value::is_null)
            && pvc.pointer("/metadata/name") == expected.pointer("/metadata/name")
            && pvc.pointer("/metadata/namespace") == Some(&json!(NAMESPACE)),
        "clone PVC ownership changed",
    )?;
    let mut spec = pvc
        .get("spec")
        .cloned()
        .ok_or(RuntimeError::MissingIdentity)?;
    if let Some(object) = spec.as_object_mut() {
        object.remove("volumeName");
        if let Some(reference) = object.remove("dataSourceRef") {
            require(
                object.get("dataSource") == Some(&reference),
                "clone datasource alias changed",
            )?;
        }
    }
    // Quantity encoders may normalize 21474836480 to 20Gi, with equal bytes.
    let capacity = spec
        .pointer("/resources/requests/storage")
        .and_then(decimal_bytes);
    require(
        capacity
            == expected
                .pointer("/spec/resources/requests/storage")
                .and_then(decimal_bytes),
        "clone size changed",
    )?;
    spec["resources"]["requests"]["storage"] =
        expected["spec"]["resources"]["requests"]["storage"].clone();
    require(
        Some(&spec) == expected.get("spec"),
        "clone block specification changed",
    )
}
pub fn validate_bound_clone(
    s: &BackupSource,
    b: &BackupBlockContext,
    pvc: &Value,
    pv: &Value,
    known: Option<Uuid>,
) -> Result<BoundBackupVolume, RuntimeError> {
    let expected = build_backup_block_pvc(b)?;
    validate_clone_pvc(pvc, &expected, None)?;
    let pvc_uid = id(pvc.pointer("/metadata/uid").and_then(Value::as_str))?;
    let pv_uid = id(pv.pointer("/metadata/uid").and_then(Value::as_str))?;
    let pv_name = pv
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .ok_or(RuntimeError::MissingIdentity)?;
    require(
        pvc_uid != s.pvc_uid
            && pv_uid != s.pv_uid
            && known.is_none_or(|u| u == pv_uid)
            && pvc.pointer("/spec/volumeName") == Some(&json!(pv_name))
            && pvc.pointer("/status/phase") == Some(&json!("Bound")),
        "clone reuses source identity or binding changed",
    )?;
    validate_pv(
        pv,
        pvc_uid,
        &crate::backup_manifest::block_pvc_name(b.attempt_id),
        NAMESPACE,
        &b.storage_class,
        "Block",
        b.size_bytes,
    )?;
    let cloud_disk = pv
        .pointer("/spec/csi/volumeHandle")
        .and_then(Value::as_str)
        .ok_or(RuntimeError::MissingIdentity)?;
    require(
        cloud_disk != s.cloud_disk
            && cloud_disk
                .strip_prefix("d-")
                .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric())),
        "clone reuses original cloud disk",
    )?;
    Ok(BoundBackupVolume {
        pvc_uid,
        pv_uid,
        pv_name: pv_name.into(),
        cloud_disk: cloud_disk.into(),
        size_bytes: b.size_bytes,
    })
}

pub(crate) fn clone_content(
    source: &BackupSource,
    ready: &SnapshotReady,
) -> Result<DynamicObject, RuntimeError> {
    let name = source.snapshot_name();
    let content = object(
        json!({"apiVersion":"snapshot.storage.k8s.io/v1","kind":"VolumeSnapshotContent","metadata":{"name":name,
            "labels":{BACKUP_LABEL:source.backup_id,"sandbox.platform/tenant-id":source.tenant_id,"sandbox.platform/project-id":source.project_id,"sandbox.platform/cluster-epoch":source.cluster_epoch},"annotations":{"snapshot.storage.kubernetes.io/allow-volume-mode-change":"true"},"finalizers":[PROTECTION]},
            "spec":{"deletionPolicy":"Retain","driver":DRIVER,"sourceVolumeMode":"Filesystem","source":{"snapshotHandle":ready.cloud_snapshot},"volumeSnapshotRef":{"name":name,"namespace":NAMESPACE}}}),
    )?;
    Ok(content)
}

pub(crate) fn clone_snapshot(source: &BackupSource) -> Result<DynamicObject, RuntimeError> {
    let name = source.snapshot_name();
    let snapshot = object(
        json!({"apiVersion":"snapshot.storage.k8s.io/v1","kind":"VolumeSnapshot","metadata":{"name":name,"namespace":NAMESPACE,
            "labels":{BACKUP_LABEL:source.backup_id,"sandbox.platform/tenant-id":source.tenant_id,"sandbox.platform/project-id":source.project_id,"sandbox.platform/cluster-epoch":source.cluster_epoch},"finalizers":[PROTECTION]},"spec":{"source":{"volumeSnapshotContentName":name}}}),
    )?;
    Ok(snapshot)
}

pub(crate) fn scoped_block_pvc(
    source: &BackupSource,
    block: &BackupBlockContext,
) -> Result<Value, RuntimeError> {
    let mut v = build_backup_block_pvc(block)?;
    for (key, id) in [
        ("sandbox.platform/tenant-id", source.tenant_id),
        ("sandbox.platform/project-id", source.project_id),
        ("sandbox.platform/cluster-epoch", source.cluster_epoch),
    ] {
        v["metadata"]["labels"][key] = json!(id);
    }
    Ok(v)
}
