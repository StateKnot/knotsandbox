//! Real raw-volume observations. Construction is private: a parsed API object
//! or an I/O result alone cannot manufacture a persisted storage receipt.
use super::{
    manifest::{RestoreStorageContext, generated_block_pv_name},
    storage_contract::RestoreStoragePurpose,
};
use crate::{
    backup_job::{BackupCloudSettings, BackupJobRuntime},
    backup_manifest::NAMESPACE,
    backup_runtime::{BoundBackupVolume, validate_pv},
    runtime::RuntimeError,
    runtime_manifest::{ManifestError, validate_existing_pvc},
};
use chrono::DateTime;
use k8s_openapi::api::core::v1::{PersistentVolume, PersistentVolumeClaim};
use kube::{
    Api,
    api::{GetParams, PostParams},
    core::Request,
};
use serde_json::{Value, json};
use uuid::Uuid;

pub(crate) struct RestoreBlockObservation {
    pub tenant_id: Uuid,
    pub restore_id: Uuid,
    pub source_backup_id: Uuid,
    pub pvc_uid: Uuid,
    pub bound: Option<BoundBackupVolume>,
    _private: (),
}
fn require(ok: bool, why: &'static str) -> Result<(), RuntimeError> {
    if ok {
        Ok(())
    } else {
        Err(ManifestError::SpecificationDrift(why).into())
    }
}
fn uid(s: Option<&str>) -> Result<Uuid, RuntimeError> {
    s.and_then(|v| Uuid::parse_str(v).ok())
        .filter(|v| !v.is_nil())
        .ok_or(RuntimeError::MissingIdentity)
}
fn encode(v: &impl serde::Serialize) -> Result<Value, RuntimeError> {
    serde_json::to_value(v).map_err(|_| RuntimeError::MissingIdentity)
}
// An unrecorded raw parent may only be adopted before scheduler/provisioner
// behavior is attached. Preserve the API JSON: typed ObjectMeta silently drops
// unknown metadata and cannot enforce this boundary.
fn validate_initial_pending_raw_pvc(actual: &Value, expected: &Value) -> Result<(), RuntimeError> {
    let mut comparable = actual.clone();
    let metadata = comparable
        .get_mut("metadata")
        .and_then(Value::as_object_mut)
        .ok_or(RuntimeError::MissingIdentity)?;
    require(
        metadata.keys().all(|key| {
            [
                "name",
                "namespace",
                "labels",
                "uid",
                "resourceVersion",
                "creationTimestamp",
                "generation",
                "managedFields",
                "finalizers",
                "annotations",
                "ownerReferences",
            ]
            .contains(&key.as_str())
        }) && metadata
            .get("uid")
            .and_then(Value::as_str)
            .is_some_and(|value| {
                Uuid::parse_str(value).is_ok_and(|uid| !uid.is_nil() && uid.to_string() == value)
            })
            && metadata
                .get("resourceVersion")
                .and_then(Value::as_str)
                .is_some_and(|value| {
                    !value.is_empty()
                        && value.len() <= 128
                        && value.bytes().all(|byte| byte.is_ascii_graphic())
                })
            && metadata
                .get("creationTimestamp")
                .and_then(Value::as_str)
                .is_some_and(|value| {
                    value.len() <= 64 && DateTime::parse_from_rfc3339(value).is_ok()
                })
            && metadata
                .get("generation")
                .is_none_or(|value| value.as_u64().is_some())
            && metadata.get("managedFields").is_none_or(|value| {
                value.as_array().is_some_and(|entries| {
                    entries.len() <= 128 && entries.iter().all(Value::is_object)
                })
            })
            && metadata.get("finalizers").is_none_or(|value| {
                value == &json!([]) || value == &json!(["kubernetes.io/pvc-protection"])
            })
            && metadata
                .get("annotations")
                .is_none_or(|value| value.as_object().is_some_and(serde_json::Map::is_empty))
            && metadata
                .get("ownerReferences")
                .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty)),
        "Initial restore raw claim has unknown, behavioral, owned or malformed metadata",
    )?;
    // Only apiserver bookkeeping is normalized. No specification, label or
    // behavior annotation is removed or converted into storage authority.
    for key in [
        "uid",
        "resourceVersion",
        "creationTimestamp",
        "generation",
        "managedFields",
        "finalizers",
        "annotations",
        "ownerReferences",
    ] {
        metadata.remove(key);
    }
    let object = comparable
        .as_object_mut()
        .ok_or(RuntimeError::MissingIdentity)?;
    require(
        object.remove("status") == Some(json!({"phase":"Pending"})),
        "Initial restore raw claim status differs from unbound Pending",
    )?;
    require(
        comparable == *expected,
        "Initial restore raw claim differs from the complete frozen Block manifest",
    )
}
impl BackupJobRuntime {
    async fn read_restore_raw_pvc(
        &self,
        name: &str,
    ) -> Result<Option<(Value, PersistentVolumeClaim)>, RuntimeError> {
        let client = self.runtime().client_clone();
        let api = Api::<PersistentVolumeClaim>::namespaced(client.clone(), NAMESPACE);
        let request = Request::new(api.resource_url())
            .get(name, &GetParams::default())
            .map_err(kube::Error::BuildRequest)?;
        let value: Value = match client.request(request).await {
            Ok(value) => value,
            Err(kube::Error::Api(error)) if error.code == 404 => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let typed =
            serde_json::from_value(value.clone()).map_err(|_| RuntimeError::MissingIdentity)?;
        Ok(Some((value, typed)))
    }
    pub(crate) async fn reconcile_restore_block(
        &self,
        c: &RestoreStorageContext,
        cloud: &BackupCloudSettings,
        known_pvc: Option<Uuid>,
        known_pv: Option<Uuid>,
        source: &crate::backup_object::BackupIdentity,
    ) -> Result<RestoreBlockObservation, RuntimeError> {
        require(
            source.tenant_id == c.tenant_id
                && source.backup_id == c.source_backup_id
                && source.size_bytes == c.size_bytes,
            "Restore storage source differs from signed backup",
        )?;
        self.verify_network(cloud).await?;
        self.verify_profile_secrets(cloud).await?;
        c.storage_contract.validate_cloud(cloud)?;
        for purpose in [
            RestoreStoragePurpose::Normal,
            RestoreStoragePurpose::Raw,
            RestoreStoragePurpose::Delivery,
        ] {
            self.verify_restore_storage_class(&c.storage_contract, purpose)
                .await?;
        }
        self.verify_restore_snapshot_class(&c.storage_contract)
            .await?;
        let expected_raw = c.block_pvc()?;
        let expected: PersistentVolumeClaim = serde_json::from_value(expected_raw.clone())
            .map_err(|_| RuntimeError::MissingIdentity)?;
        let name = expected
            .metadata
            .name
            .as_deref()
            .ok_or(RuntimeError::MissingIdentity)?;
        let pvcs =
            Api::<PersistentVolumeClaim>::namespaced(self.runtime().client_clone(), NAMESPACE);
        let ((actual_raw, actual), created_uid) = match self.read_restore_raw_pvc(name).await? {
            Some(v) => (v, None),
            None => {
                require(
                    known_pvc.is_none(),
                    "Recorded restore raw claim disappeared",
                )?;
                match pvcs.create(&PostParams::default(), &expected).await {
                    Ok(v) => {
                        let returned_uid = uid(v.metadata.uid.as_deref())?;
                        // A create response is not an independent observation
                        // of the object actually stored by the apiserver.
                        (
                            self.read_restore_raw_pvc(name)
                                .await?
                                .ok_or(RuntimeError::MissingIdentity)?,
                            Some(returned_uid),
                        )
                    }
                    Err(kube::Error::Api(e)) if e.code == 409 => (
                        self.read_restore_raw_pvc(name)
                            .await?
                            .ok_or(RuntimeError::MissingIdentity)?,
                        None,
                    ),
                    Err(e) => return Err(e.into()),
                }
            }
        };
        let pvc_uid = uid(actual.metadata.uid.as_deref())?;
        require(
            created_uid.is_none_or(|value| value == pvc_uid),
            "Restore raw create response and stored claim UID differ",
        )?;
        validate_existing_pvc(
            &actual,
            &expected,
            known_pvc.map(|v| v.to_string()).as_deref(),
        )?;
        require(
            pvc_uid != source.source_pvc_uid && pvc_uid != source.clone_pvc_uid,
            "Restore claim reuses historical source identity",
        )?;
        let bound = if actual.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Bound") {
            require(
                known_pvc.is_some(),
                "Bound restore raw claim requires its recorded immutable parent",
            )?;
            let pv_name = actual
                .spec
                .as_ref()
                .and_then(|s| s.volume_name.as_deref())
                .ok_or(RuntimeError::MissingIdentity)?;
            require(
                pv_name == generated_block_pv_name(pvc_uid)?,
                "Restore raw PV name differs from its immutable claim parent",
            )?;
            let pvs = Api::<PersistentVolume>::all(self.runtime().client_clone());
            let pv = pvs.get(pv_name).await?;
            let pv_uid = uid(pv.metadata.uid.as_deref())?;
            require(
                known_pv.is_none_or(|v| v == pv_uid),
                "Restore raw PV changed identity",
            )?;
            let raw = encode(&pv)?;
            validate_pv(
                &raw,
                pvc_uid,
                name,
                NAMESPACE,
                &c.storage_contract.mapping.raw.name,
                "Block",
                c.size_bytes,
            )?;
            let cloud_disk = raw
                .pointer("/spec/csi/volumeHandle")
                .and_then(Value::as_str)
                .ok_or(RuntimeError::MissingIdentity)?;
            require(
                cloud_disk
                    .strip_prefix("d-")
                    .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric())),
                "Restore raw volume cloud identity is invalid",
            )?;
            let (_, again) = self
                .read_restore_raw_pvc(name)
                .await?
                .ok_or(RuntimeError::MissingIdentity)?;
            validate_existing_pvc(&again, &expected, Some(pvc_uid.to_string().as_str()))?;
            require(
                again.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Bound")
                    && again.spec.as_ref().and_then(|s| s.volume_name.as_deref()) == Some(pv_name),
                "Restore claim changed binding during observation",
            )?;
            let again = pvs.get(pv_name).await?;
            require(
                uid(again.metadata.uid.as_deref())? == pv_uid,
                "Restore PV was replaced during observation",
            )?;
            validate_pv(
                &encode(&again)?,
                pvc_uid,
                name,
                NAMESPACE,
                &c.storage_contract.mapping.raw.name,
                "Block",
                c.size_bytes,
            )?;
            require(
                encode(&again)?.pointer("/spec/csi/volumeHandle")
                    == Some(&Value::String(cloud_disk.into())),
                "Restore PV changed cloud identity during observation",
            )?;
            Some(BoundBackupVolume {
                pvc_uid,
                pv_uid,
                pv_name: pv_name.into(),
                cloud_disk: cloud_disk.into(),
                size_bytes: c.size_bytes,
            })
        } else {
            require(
                actual.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Pending")
                    && known_pv.is_none()
                    && actual
                        .spec
                        .as_ref()
                        .and_then(|s| s.volume_name.as_deref())
                        .is_none(),
                "Restore raw claim is not a stable Pending observation",
            )?;
            if known_pvc.is_none() {
                validate_initial_pending_raw_pvc(&actual_raw, &expected_raw)?;
            }
            let (again_raw, again) = self
                .read_restore_raw_pvc(name)
                .await?
                .ok_or(RuntimeError::MissingIdentity)?;
            validate_existing_pvc(&again, &expected, Some(pvc_uid.to_string().as_str()))?;
            if known_pvc.is_none() {
                validate_initial_pending_raw_pvc(&again_raw, &expected_raw)?;
            }
            require(
                again.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Pending")
                    && again
                        .spec
                        .as_ref()
                        .and_then(|s| s.volume_name.as_deref())
                        .is_none(),
                "Restore raw claim changed while observing Pending; retry actual reads",
            )?;
            None
        };
        Ok(RestoreBlockObservation {
            tenant_id: c.tenant_id,
            restore_id: c.restore_id,
            source_backup_id: c.source_backup_id,
            pvc_uid,
            bound,
            _private: (),
        })
    }
}

#[cfg(test)]
#[path = "restore_storage_readback_tests.rs"]
mod readback_tests;
