//! Controlled storage conversion. A restored raw device is snapshotted only
//! after trusted VM closure; a new Filesystem PVC consumes a retained static
//! snapshot reference. Existing PVC volumeMode is never patched.
use super::storage_contract::RestoreStorageContract;
use crate::{
    backup_manifest::{BACKUP_LABEL, NAMESPACE, block_pvc_name, valid_name},
    runtime_manifest::ManifestError,
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

const DRIVER: &str = "diskplugin.csi.alibabacloud.com";
const PROTECTION: &str = "sandbox.platform/backup-protection";

/// The reviewed provisioner uses `--volume-name-prefix=disk` and the full
/// claim UID. A different installation requires new certification.
pub(crate) fn generated_block_pv_name(pvc_uid: Uuid) -> Result<String, ManifestError> {
    if pvc_uid.is_nil() {
        return Err(ManifestError::InvalidConfiguration(
            "restore raw parent UID",
        ));
    }
    Ok(format!("disk-{pvc_uid}"))
}

#[derive(Clone, Debug)]
pub(crate) struct RestoreStorageContext {
    pub tenant_id: Uuid,
    pub source_backup_id: Uuid,
    pub restore_id: Uuid,
    pub target_project_id: Uuid,
    pub instance_id: Uuid,
    pub workspace_id: Uuid,
    pub cluster_epoch: Uuid,
    pub target_namespace: String,
    pub storage_contract: RestoreStorageContract,
    pub size_bytes: u64,
}
impl RestoreStorageContext {
    fn validate(&self) -> Result<(), ManifestError> {
        if [
            self.tenant_id,
            self.source_backup_id,
            self.restore_id,
            self.target_project_id,
            self.instance_id,
            self.workspace_id,
            self.cluster_epoch,
        ]
        .iter()
        .any(Uuid::is_nil)
            || !valid_name(&self.target_namespace)
            || self.target_namespace == NAMESPACE
            || self.storage_contract.cluster_epoch != self.cluster_epoch
            || !(20 * 1024_u64.pow(3)..=1024 * 1024_u64.pow(3)).contains(&self.size_bytes)
            || !self.size_bytes.is_multiple_of(1024_u64.pow(3))
        {
            return Err(ManifestError::InvalidConfiguration(
                "restore storage identity",
            ));
        }
        self.storage_contract.validate()?;
        Ok(())
    }
    pub fn raw_snapshot_name(&self) -> String {
        format!("sbx-rraw-{}", self.restore_id)
    }
    pub fn delivery_snapshot_name(&self) -> String {
        format!("sbx-rs-{}", self.restore_id)
    }
    fn labels(&self) -> Value {
        json!({BACKUP_LABEL:self.source_backup_id,"sandbox.platform/restore-id":self.restore_id,
            "sandbox.platform/tenant-id":self.tenant_id,"sandbox.platform/project-id":self.target_project_id,
            "sandbox.platform/cluster-epoch":self.cluster_epoch,"app.kubernetes.io/managed-by":"sandbox-backup"})
    }
    pub fn block_pvc(&self) -> Result<Value, ManifestError> {
        self.validate()?;
        let mut body = crate::backup_manifest::build_backup_block_pvc(
            &crate::backup_manifest::BackupBlockContext {
                backup_id: self.source_backup_id,
                attempt_id: self.restore_id,
                storage_class: self.storage_contract.mapping.raw.name.clone(),
                size_bytes: self.size_bytes,
                snapshot_name: None,
            },
        )?;
        body["metadata"]["labels"] = self.labels();
        // Kubernetes canonicalizes whole-Gi quantities; use the same form for
        // immutable PVC comparisons instead of an equivalent decimal byte string.
        body["spec"]["resources"]["requests"]["storage"] = json!(
            crate::runtime_manifest::quantity_mib((self.size_bytes / 1024_u64.pow(2)) as i64)
        );
        Ok(body)
    }
    pub fn raw_snapshot(&self) -> Result<Value, ManifestError> {
        self.validate()?;
        Ok(
            json!({"apiVersion":"snapshot.storage.k8s.io/v1","kind":"VolumeSnapshot",
            "metadata":{"name":self.raw_snapshot_name(),"namespace":NAMESPACE,"labels":self.labels(),"finalizers":[PROTECTION]},
            "spec":{"volumeSnapshotClassName":self.storage_contract.mapping.snapshot.name,"source":{"persistentVolumeClaimName":block_pvc_name(self.restore_id)}}}),
        )
    }
    pub fn delivery_content(&self, cloud_snapshot: &str) -> Result<Value, ManifestError> {
        self.validate()?;
        if !cloud_snapshot
            .strip_prefix("s-")
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric()))
        {
            return Err(ManifestError::InvalidConfiguration(
                "restore cloud snapshot identity",
            ));
        }
        let name = self.delivery_snapshot_name();
        Ok(
            json!({"apiVersion":"snapshot.storage.k8s.io/v1","kind":"VolumeSnapshotContent",
            "metadata":{"name":name,"labels":self.labels(),"annotations":{"snapshot.storage.kubernetes.io/allow-volume-mode-change":"true"},"finalizers":[PROTECTION]},
            "spec":{"driver":DRIVER,"deletionPolicy":"Retain","sourceVolumeMode":"Block","source":{"snapshotHandle":cloud_snapshot},
                "volumeSnapshotRef":{"name":name,"namespace":self.target_namespace}}}),
        )
    }
    pub fn delivery_snapshot(&self) -> Result<Value, ManifestError> {
        self.validate()?;
        let name = self.delivery_snapshot_name();
        Ok(
            json!({"apiVersion":"snapshot.storage.k8s.io/v1","kind":"VolumeSnapshot",
            "metadata":{"name":name,"namespace":self.target_namespace,"labels":self.labels(),"finalizers":[PROTECTION]},
            "spec":{"source":{"volumeSnapshotContentName":name}}}),
        )
    }
    pub fn filesystem_pvc(&self) -> Result<Value, ManifestError> {
        self.validate()?;
        Ok(json!({"apiVersion":"v1","kind":"PersistentVolumeClaim",
            "metadata":{"name":format!("ws-{}",self.workspace_id),"namespace":self.target_namespace,"labels":{
                "sandbox.platform/tenant-id":self.tenant_id,"sandbox.platform/project-id":self.target_project_id,
                "sandbox.platform/instance-id":self.instance_id,"sandbox.platform/workspace-id":self.workspace_id,"app.kubernetes.io/managed-by":"sandbox-platform"}},
            "spec":{"volumeMode":"Filesystem","accessModes":["ReadWriteOnce"],"storageClassName":self.storage_contract.mapping.delivery.name,
                "dataSource":{"apiGroup":"snapshot.storage.k8s.io","kind":"VolumeSnapshot","name":self.delivery_snapshot_name()},
                "resources":{"requests":{"storage":crate::runtime_manifest::quantity_mib((self.size_bytes/1024_u64.pow(2)) as i64)}}}}))
    }
}

fn require(ok: bool, why: &'static str) -> Result<(), ManifestError> {
    if ok {
        Ok(())
    } else {
        Err(ManifestError::SpecificationDrift(why))
    }
}
fn object_uid(v: &Value) -> Result<Uuid, ManifestError> {
    v.pointer("/metadata/uid")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .filter(|u| !u.is_nil())
        .ok_or(ManifestError::OwnershipMismatch("snapshot UID"))
}
fn bytes(v: Option<&Value>) -> Option<u64> {
    let v = v?;
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    let s = v.as_str()?;
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
#[derive(Clone, Debug)]
pub(crate) struct RestoreSnapshotObservation {
    pub snapshot_uid: Uuid,
    pub content_uid: Uuid,
    pub content_name: String,
    pub cloud_snapshot: String,
    pub size_bytes: u64,
}
/// ReadyToUse is storage evidence. This pure validation grants neither a host
/// termination proof nor permission to expose the new workspace.
pub(crate) fn verify_raw_snapshot(
    context: &RestoreStorageContext,
    snapshot: &Value,
    content: &Value,
    raw_disk: &str,
    closed_at: DateTime<Utc>,
    known_snapshot: Option<Uuid>,
    known_content: Option<Uuid>,
) -> Result<Option<RestoreSnapshotObservation>, ManifestError> {
    context.validate()?;
    let snapshot_uid = object_uid(snapshot)?;
    let content_uid = object_uid(content)?;
    let content_name = content
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .filter(|s| valid_name(s))
        .ok_or(ManifestError::OwnershipMismatch("snapshot content name"))?;
    require(
        raw_disk
            .strip_prefix("d-")
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric()))
            && known_snapshot.is_none_or(|u| u == snapshot_uid)
            && known_content.is_none_or(|u| u == content_uid)
            && snapshot.pointer("/metadata/name") == Some(&json!(context.raw_snapshot_name()))
            && snapshot.pointer("/metadata/namespace") == Some(&json!(NAMESPACE))
            && snapshot
                .pointer("/metadata/deletionTimestamp")
                .is_none_or(Value::is_null)
            && content
                .pointer("/metadata/deletionTimestamp")
                .is_none_or(Value::is_null)
            && snapshot
                .pointer("/metadata/ownerReferences")
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))
            && content
                .pointer("/metadata/ownerReferences")
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))
            && snapshot
                .pointer("/metadata/finalizers")
                .and_then(Value::as_array)
                .is_some_and(|f| f.iter().any(|v| v == PROTECTION))
            && context.labels().as_object().is_some_and(|labels| {
                labels.iter().all(|(key, value)| {
                    snapshot
                        .pointer("/metadata/labels")
                        .and_then(|v| v.get(key))
                        == Some(value)
                })
            })
            && snapshot.get("spec") == context.raw_snapshot()?.get("spec")
            && snapshot.pointer("/status/boundVolumeSnapshotContentName")
                == Some(&json!(content_name))
            && content.pointer("/spec/driver") == Some(&json!(DRIVER))
            && content.pointer("/spec/deletionPolicy") == Some(&json!("Retain"))
            && content.pointer("/spec/sourceVolumeMode") == Some(&json!("Block"))
            && content.pointer("/spec/source") == Some(&json!({"volumeHandle":raw_disk}))
            && content.pointer("/spec/volumeSnapshotClassName")
                == Some(&json!(context.storage_contract.mapping.snapshot.name))
            && content.pointer("/spec/volumeSnapshotRef/uid") == Some(&json!(snapshot_uid))
            && content.pointer("/spec/volumeSnapshotRef/name")
                == Some(&json!(context.raw_snapshot_name()))
            && content.pointer("/spec/volumeSnapshotRef/namespace") == Some(&json!(NAMESPACE))
            && snapshot.pointer("/status/error").is_none_or(Value::is_null)
            && content.pointer("/status/error").is_none_or(Value::is_null),
        "restored raw snapshot binding changed",
    )?;
    if snapshot.pointer("/status/readyToUse") != Some(&json!(true))
        || content.pointer("/status/readyToUse") != Some(&json!(true))
    {
        return Ok(None);
    }
    let cloud_snapshot = content
        .pointer("/status/snapshotHandle")
        .and_then(Value::as_str)
        .ok_or(ManifestError::OwnershipMismatch("cloud snapshot handle"))?;
    let created = snapshot
        .pointer("/status/creationTime")
        .and_then(Value::as_str)
        .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
        .map(|t| t.with_timezone(&Utc))
        .ok_or(ManifestError::SpecificationDrift(
            "restored snapshot timestamp",
        ))?;
    let nanos = content
        .pointer("/status/creationTime")
        .and_then(Value::as_i64)
        .filter(|n| *n > 0)
        .ok_or(ManifestError::SpecificationDrift(
            "restored content timestamp",
        ))?;
    require(
        cloud_snapshot.strip_prefix("s-").is_some_and(|s|!s.is_empty()&&s.bytes().all(|b|b.is_ascii_alphanumeric()))
        // The cloud/CSI timestamps may have second precision; the durable
        // snapshot intent separately forbids creation before trusted cleanup.
        && created.timestamp()>=closed_at.timestamp() && created<=Utc::now() && created.timestamp()==nanos/1_000_000_000
        && DateTime::<Utc>::from_timestamp_nanos(nanos).timestamp()>=closed_at.timestamp() && DateTime::<Utc>::from_timestamp_nanos(nanos)<=Utc::now()
        && bytes(snapshot.pointer("/status/restoreSize"))==Some(context.size_bytes) && bytes(content.pointer("/status/restoreSize"))==Some(context.size_bytes),
        "restored snapshot size or cloud handle changed",
    )?;
    Ok(Some(RestoreSnapshotObservation {
        snapshot_uid,
        content_uid,
        content_name: content_name.to_owned(),
        cloud_snapshot: cloud_snapshot.to_owned(),
        size_bytes: context.size_bytes,
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chrono::Duration;
    fn context() -> RestoreStorageContext {
        let fixture: Value = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/restore/storage-canonical.json"
        ))
        .unwrap();
        let storage_contract = RestoreStorageContract::parse(&fixture["contract"]).unwrap();
        RestoreStorageContext {
            tenant_id: Uuid::new_v4(),
            source_backup_id: Uuid::new_v4(),
            restore_id: Uuid::new_v4(),
            target_project_id: Uuid::new_v4(),
            instance_id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            cluster_epoch: storage_contract.cluster_epoch,
            target_namespace: "target-project".into(),
            storage_contract,
            size_bytes: 20 * 1024_u64.pow(3),
        }
    }
    #[test]
    fn maximum_raw_and_filesystem_claims_use_canonical_tib_storage() {
        let mut c = context();
        c.size_bytes = 1024_u64.pow(4);
        for pvc in [c.block_pvc().unwrap(), c.filesystem_pvc().unwrap()] {
            assert_eq!(pvc["spec"]["resources"]["requests"]["storage"], "1Ti");
            assert_eq!(
                bytes(pvc.pointer("/spec/resources/requests/storage")),
                Some(c.size_bytes)
            );
        }
    }
    #[test]
    fn mode_conversion_creates_a_new_filesystem_claim_and_static_retained_reference() {
        let c = context();
        let raw = c.raw_snapshot().unwrap();
        assert_eq!(
            raw.pointer("/spec/source/persistentVolumeClaimName"),
            Some(&json!(block_pvc_name(c.restore_id)))
        );
        let content = c.delivery_content("s-restored123").unwrap();
        assert_eq!(
            content.pointer("/spec/sourceVolumeMode"),
            Some(&json!("Block"))
        );
        assert_eq!(
            content.pointer("/spec/deletionPolicy"),
            Some(&json!("Retain"))
        );
        assert_eq!(
            content.pointer(
                "/metadata/annotations/snapshot.storage.kubernetes.io~1allow-volume-mode-change"
            ),
            Some(&json!("true"))
        );
        assert_eq!(
            content.pointer("/spec/volumeSnapshotRef/namespace"),
            Some(&json!(c.target_namespace))
        );
        let snapshot = c.delivery_snapshot().unwrap();
        let pvc = c.filesystem_pvc().unwrap();
        assert_eq!(pvc.pointer("/spec/volumeMode"), Some(&json!("Filesystem")));
        assert_ne!(
            pvc.pointer("/metadata/name"),
            raw.pointer("/spec/source/persistentVolumeClaimName")
        );
        assert_eq!(
            pvc.pointer("/spec/dataSource/name"),
            snapshot.pointer("/metadata/name")
        );
        assert!(pvc.pointer("/spec/dataSource/namespace").is_none());
        assert!(pvc.pointer("/metadata/ownerReferences").is_none());
        assert!(
            c.delivery_content("https://foreign.invalid/snapshot")
                .is_err()
        );
        let mut system = c;
        system.target_namespace = NAMESPACE.into();
        assert!(system.filesystem_pvc().is_err());
    }
    #[test]
    fn ready_snapshot_cannot_reuse_source_volume_or_precede_closed_restore() {
        let c = context();
        let snapshot_uid = Uuid::new_v4();
        let content_uid = Uuid::new_v4();
        let closed_at = Utc::now() - Duration::seconds(5);
        let created = Utc::now() - Duration::seconds(1);
        let mut snapshot = c.raw_snapshot().unwrap();
        snapshot["metadata"]["uid"] = json!(snapshot_uid);
        snapshot["status"] = json!({"boundVolumeSnapshotContentName":"snapcontent-restored","readyToUse":true,"restoreSize":"20Gi","creationTime":created.to_rfc3339()});
        let content = json!({"apiVersion":"snapshot.storage.k8s.io/v1","kind":"VolumeSnapshotContent","metadata":{"name":"snapcontent-restored","uid":content_uid},
            "spec":{"driver":DRIVER,"deletionPolicy":"Retain","sourceVolumeMode":"Block","source":{"volumeHandle":"d-target123"},"volumeSnapshotClassName":c.storage_contract.mapping.snapshot.name,
                "volumeSnapshotRef":{"name":c.raw_snapshot_name(),"namespace":NAMESPACE,"uid":snapshot_uid}},
            "status":{"readyToUse":true,"snapshotHandle":"s-restored123","restoreSize":c.size_bytes,"creationTime":created.timestamp_nanos_opt().unwrap()}});
        let verify = |s: &Value, v: &Value| {
            verify_raw_snapshot(
                &c,
                s,
                v,
                "d-target123",
                closed_at,
                Some(snapshot_uid),
                Some(content_uid),
            )
        };
        let observed = verify(&snapshot, &content).unwrap().unwrap();
        assert_eq!(observed.cloud_snapshot, "s-restored123");
        assert_eq!(observed.size_bytes, c.size_bytes);
        assert_eq!(observed.snapshot_uid, snapshot_uid);
        assert_eq!(observed.content_uid, content_uid);
        assert_eq!(observed.content_name, "snapcontent-restored");
        for (path, wrong) in [
            ("/spec/source/volumeHandle", json!("d-original123")),
            ("/spec/sourceVolumeMode", json!("Filesystem")),
            ("/spec/deletionPolicy", json!("Delete")),
            ("/spec/volumeSnapshotRef/namespace", json!("foreign")),
            ("/spec/volumeSnapshotRef/uid", json!(Uuid::new_v4())),
            ("/status/restoreSize", json!(512)),
            ("/status/snapshotHandle", json!("s-../../wrong")),
            ("/metadata/uid", json!(Uuid::new_v4())),
        ] {
            let mut altered = content.clone();
            *altered.pointer_mut(path).unwrap() = wrong;
            assert!(
                verify(&snapshot, &altered).is_err(),
                "accepted content edit {path}"
            );
        }
        for (path, wrong) in [
            (
                "/metadata/labels/sandbox.platform~1restore-id",
                json!(Uuid::new_v4()),
            ),
            ("/status/restoreSize", json!("21Gi")),
            (
                "/status/creationTime",
                json!((closed_at - Duration::seconds(5)).to_rfc3339()),
            ),
            (
                "/spec/source/persistentVolumeClaimName",
                json!("old-source-claim"),
            ),
        ] {
            let mut altered = snapshot.clone();
            *altered.pointer_mut(path).unwrap() = wrong;
            assert!(
                verify(&altered, &content).is_err(),
                "accepted snapshot edit {path}"
            );
        }
        let mut pending = content;
        pending["status"]["readyToUse"] = json!(false);
        assert!(verify(&snapshot, &pending).unwrap().is_none());
    }
}
