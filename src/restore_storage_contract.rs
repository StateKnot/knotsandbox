//! A reviewed, immutable storage mapping. It does not authorize a writer or
//! certify CSI behavior: every writer still needs the independent live fences.
use crate::{
    backup_job::{BackupCloudSettings, BackupJobRuntime},
    backup_manifest::valid_name,
    backup_runtime::dyn_api,
    runtime::RuntimeError,
    runtime_manifest::ManifestError,
};
use kube::{
    Api,
    api::{ApiResource, GetParams},
    core::{DynamicObject, GroupVersionKind, Request},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub(crate) const RESTORE_TOPOLOGY_KEY: &str = "topology.diskplugin.csi.alibabacloud.com/zone";
const DRIVER: &str = "diskplugin.csi.alibabacloud.com";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClassIdentity {
    pub name: String,
    pub uid: Uuid,
    pub spec_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreTopology {
    pub key: String,
    pub zone_ids: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreStorageMapping {
    pub normal: ClassIdentity,
    pub raw: ClassIdentity,
    pub delivery: ClassIdentity,
    pub snapshot: ClassIdentity,
    pub workspace_kms_key_id: String,
    pub account_id: String,
    pub region: String,
    pub deployment: String,
    pub topology: RestoreTopology,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreStorageContract {
    pub protocol: u32,
    pub profile_id: Uuid,
    pub cluster_epoch: Uuid,
    pub backup_certification_sha256: String,
    pub report_sha256: String,
    pub mapping: RestoreStorageMapping,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RestoreStoragePurpose {
    Normal,
    Raw,
    Delivery,
}
fn valid_hash(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_region(v: &str) -> bool {
    v.starts_with("cn-")
        && (4..=32).contains(&v.len())
        && v.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn require(ok: bool, why: &'static str) -> Result<(), ManifestError> {
    if ok {
        Ok(())
    } else {
        Err(ManifestError::SpecificationDrift(why))
    }
}
impl ClassIdentity {
    fn validate(&self) -> Result<(), ManifestError> {
        require(
            valid_name(&self.name) && !self.uid.is_nil() && valid_hash(&self.spec_sha256),
            "restore class identity",
        )
    }
}
impl RestoreStorageMapping {
    pub(crate) fn validate(&self) -> Result<(), ManifestError> {
        let classes = [&self.normal, &self.raw, &self.delivery, &self.snapshot];
        for class in classes {
            class.validate()?;
        }
        for i in 0..3 {
            for j in i + 1..3 {
                require(
                    classes[i].name != classes[j].name,
                    "restore storage purposes share a name",
                )?;
            }
        }
        for i in 0..classes.len() {
            for j in i + 1..classes.len() {
                require(
                    classes[i].uid != classes[j].uid,
                    "restore class UIDs are reused",
                )?;
            }
        }
        require(
            self.account_id.len() == 16
                && self.account_id.bytes().all(|b| b.is_ascii_digit())
                && valid_region(&self.region)
                && crate::backup_job::valid_deployment(&self.deployment)
                && !self.workspace_kms_key_id.is_empty()
                && self.workspace_kms_key_id.len() <= 256
                && self
                    .workspace_kms_key_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/_:-".contains(&b)),
            "restore deployment and compute KMS identity",
        )?;
        require(
            self.topology.key == RESTORE_TOPOLOGY_KEY
                && self.topology.zone_ids.len() == 3
                && self.topology.zone_ids.windows(2).all(|w| w[0] < w[1])
                && self.topology.zone_ids.iter().all(|zone| {
                    zone.strip_prefix(&format!("{}-", self.region))
                        .is_some_and(|suffix| {
                            !suffix.is_empty()
                                && zone.len() <= 64
                                && suffix.bytes().all(|b| {
                                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'
                                })
                        })
                }),
            "restore three fault domains",
        )
    }
    pub(crate) fn class(&self, purpose: RestoreStoragePurpose) -> &ClassIdentity {
        match purpose {
            RestoreStoragePurpose::Normal => &self.normal,
            RestoreStoragePurpose::Raw => &self.raw,
            RestoreStoragePurpose::Delivery => &self.delivery,
        }
    }
}
impl RestoreStorageContract {
    pub(crate) fn parse(value: &Value) -> Result<Self, ManifestError> {
        let encoded = serde_json::to_vec(value).map_err(|_| ManifestError::Encoding)?;
        require(
            encoded.len() <= 16384 && value.get("protocol").is_some_and(|v| v.as_u64() == Some(1)),
            "restore storage contract envelope",
        )?;
        let contract: Self = serde_json::from_value(value.clone())
            .map_err(|_| ManifestError::InvalidConfiguration("restore storage contract shape"))?;
        // Typed UUID deserialization alone accepts noncanonical text. Comparing
        // the decoded domain rejects alternate UUID encodings, without guessing.
        require(
            serde_json::to_value(&contract).map_err(|_| ManifestError::Encoding)? == *value,
            "restore storage contract canonical types",
        )?;
        contract.validate()?;
        Ok(contract)
    }
    pub(crate) fn validate(&self) -> Result<(), ManifestError> {
        require(
            self.protocol == 1
                && !self.profile_id.is_nil()
                && !self.cluster_epoch.is_nil()
                && valid_hash(&self.backup_certification_sha256)
                && valid_hash(&self.report_sha256),
            "restore storage contract certification identity",
        )?;
        self.mapping.validate()
    }
    pub(crate) fn validate_cloud(&self, cloud: &BackupCloudSettings) -> Result<(), ManifestError> {
        self.validate()?;
        require(
            self.mapping.account_id == cloud.account_id
                && self.mapping.region == cloud.region
                && self.mapping.deployment == cloud.deployment,
            "restore storage mapping cloud identity",
        )
    }
}

/// Explicit projection, shared with Python fixtures. Metadata identity is
/// checked separately. Absent and empty optional lists have one representation.
pub(crate) fn expected_storage_class_spec(
    mapping: &RestoreStorageMapping,
    purpose: RestoreStoragePurpose,
) -> Value {
    let normal = purpose == RestoreStoragePurpose::Normal;
    let delivery = purpose == RestoreStoragePurpose::Delivery;
    let mut parameters = json!({"type":"cloud_essd","encrypted":"true",
        "kmsKeyId":mapping.workspace_kms_key_id,"diskTags/Deployment":mapping.deployment});
    if normal || delivery {
        parameters["fsType"] = json!("ext4");
    }
    json!({"apiVersion":"storage.k8s.io/v1","kind":"StorageClass","provisioner":DRIVER,
        "reclaimPolicy":"Retain","volumeBindingMode":if delivery {"Immediate"} else {"WaitForFirstConsumer"},
        "allowVolumeExpansion":normal,"parameters":parameters,"mountOptions":[],
        "allowedTopologies":if normal {json!([])} else {json!([{"matchLabelExpressions":[{
            "key":RESTORE_TOPOLOGY_KEY,"values":mapping.topology.zone_ids}]}])}})
}
pub(crate) fn expected_snapshot_class_spec(mapping: &RestoreStorageMapping) -> Value {
    json!({"apiVersion":"snapshot.storage.k8s.io/v1","kind":"VolumeSnapshotClass",
        "driver":DRIVER,"deletionPolicy":"Retain","parameters":{"snapshotTags/Deployment":mapping.deployment}})
}
fn projection(value: &Value, expected: &Value) -> Result<Value, ManifestError> {
    let actual = value
        .as_object()
        .ok_or(ManifestError::SpecificationDrift("restore class object"))?;
    let expected = expected.as_object().ok_or(ManifestError::Encoding)?;
    require(
        actual
            .keys()
            .all(|key| key == "metadata" || expected.contains_key(key)),
        "restore class unknown behavior field",
    )?;
    let mut projected = serde_json::Map::new();
    for (key, wanted) in expected {
        let observed = actual.get(key);
        if key == "mountOptions" || key == "allowedTopologies" && wanted == &json!([]) {
            require(
                observed.is_none() || observed == Some(wanted),
                "restore class optional list drift",
            )?;
        } else {
            require(
                observed == Some(wanted),
                "restore class purpose policy drift",
            )?;
        }
        projected.insert(key.clone(), wanted.clone());
    }
    Ok(Value::Object(projected))
}
fn spec_hash(value: Value) -> Result<String, ManifestError> {
    let bytes = serde_json::to_vec(&value).map_err(|_| ManifestError::Encoding)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}
pub(crate) fn storage_class_spec_sha256(
    value: &Value,
    mapping: &RestoreStorageMapping,
    purpose: RestoreStoragePurpose,
) -> Result<String, ManifestError> {
    mapping.validate()?;
    spec_hash(projection(
        value,
        &expected_storage_class_spec(mapping, purpose),
    )?)
}
pub(crate) fn snapshot_class_spec_sha256(
    value: &Value,
    mapping: &RestoreStorageMapping,
) -> Result<String, ManifestError> {
    mapping.validate()?;
    spec_hash(projection(value, &expected_snapshot_class_spec(mapping))?)
}
fn metadata(value: &Value, identity: &ClassIdentity) -> Result<(), ManifestError> {
    let meta = value
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or(ManifestError::OwnershipMismatch("restore class metadata"))?;
    require(
        meta.keys().all(|key| {
            [
                "name",
                "uid",
                "resourceVersion",
                "creationTimestamp",
                "generation",
                "managedFields",
                "labels",
                "annotations",
                "deletionTimestamp",
                "ownerReferences",
                "finalizers",
            ]
            .contains(&key.as_str())
        }),
        "restore class metadata field",
    )?;
    require(
        meta.get("name").and_then(Value::as_str) == Some(identity.name.as_str())
            && meta.get("uid").and_then(Value::as_str) == Some(identity.uid.to_string().as_str()),
        "restore class name or UID replacement",
    )?;
    require(
        meta.get("deletionTimestamp").is_none_or(Value::is_null),
        "restore class deleting",
    )?;
    for key in ["ownerReferences", "finalizers"] {
        require(
            meta.get(key)
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
            "restore class has owner or finalizers",
        )?;
    }
    if let Some(labels) = meta.get("labels") {
        require(
            labels.as_object().is_some_and(|m| {
                m.len() <= 128
                    && m.iter().all(|(k, v)| {
                        k.is_ascii()
                            && k.len() <= 253
                            && v.as_str().is_some_and(|s| s.is_ascii() && s.len() <= 256)
                    })
            }),
            "restore class labels",
        )?;
    }
    if let Some(annotations) = meta.get("annotations") {
        require(
            annotations.as_object().is_some_and(|m| {
                m.keys()
                    .all(|key| key == "kubectl.kubernetes.io/last-applied-configuration")
                    && m.values()
                        .all(|v| v.as_str().is_some_and(|s| s.is_ascii() && s.len() <= 65536))
            }),
            "restore class behavior annotations",
        )?;
    }
    Ok(())
}
pub(crate) fn validate_storage_class(
    value: &Value,
    contract: &RestoreStorageContract,
    purpose: RestoreStoragePurpose,
) -> Result<(), ManifestError> {
    contract.validate()?;
    let identity = contract.mapping.class(purpose);
    metadata(value, identity)?;
    require(
        storage_class_spec_sha256(value, &contract.mapping, purpose)? == identity.spec_sha256,
        "restore class approved specification hash",
    )
}
pub(crate) fn validate_snapshot_class(
    value: &Value,
    contract: &RestoreStorageContract,
) -> Result<(), ManifestError> {
    contract.validate()?;
    metadata(value, &contract.mapping.snapshot)?;
    require(
        snapshot_class_spec_sha256(value, &contract.mapping)?
            == contract.mapping.snapshot.spec_sha256,
        "restore snapshot class approved specification hash",
    )
}
impl BackupJobRuntime {
    pub(crate) async fn verify_restore_storage_class(
        &self,
        contract: &RestoreStorageContract,
        purpose: RestoreStoragePurpose,
    ) -> Result<(), RuntimeError> {
        contract.validate()?;
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            "storage.k8s.io",
            "v1",
            "StorageClass",
        ));
        let client = self.runtime().client_clone();
        let api = Api::<DynamicObject>::all_with(client.clone(), &resource);
        // ObjectMeta discards unknown fields during typed deserialization. Keep
        // the original JSON so the metadata allowlist sees the complete object.
        let request = Request::new(api.resource_url())
            .get(&contract.mapping.class(purpose).name, &GetParams::default())
            .map_err(kube::Error::BuildRequest)?;
        let value: Value = client.request(request).await?;
        validate_storage_class(&value, contract, purpose)?;
        Ok(())
    }
    pub(crate) async fn verify_restore_snapshot_class(
        &self,
        contract: &RestoreStorageContract,
    ) -> Result<(), RuntimeError> {
        contract.validate()?;
        let api = dyn_api(self.runtime(), "VolumeSnapshotClass", None);
        let request = Request::new(api.resource_url())
            .get(&contract.mapping.snapshot.name, &GetParams::default())
            .map_err(kube::Error::BuildRequest)?;
        let value: Value = self.runtime().client_clone().request(request).await?;
        validate_snapshot_class(&value, contract)?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "restore_storage_contract_tests.rs"]
mod tests;

#[cfg(test)]
#[test]
fn raw_class_json_rejects_unknown_metadata_for_both_class_kinds() -> Result<(), ManifestError> {
    let fixture: Value = serde_json::from_slice(include_bytes!(
        "../tests/fixtures/restore/storage-canonical.json"
    ))
    .map_err(|_| ManifestError::Encoding)?;
    let contract = RestoreStorageContract::parse(&fixture["contract"])?;
    let mut storage = expected_storage_class_spec(&contract.mapping, RestoreStoragePurpose::Raw);
    storage["metadata"] = json!({"name":contract.mapping.raw.name,"uid":contract.mapping.raw.uid});
    validate_storage_class(&storage, &contract, RestoreStoragePurpose::Raw)?;
    storage["metadata"]["unknown"] = json!({"permission":"unreviewed"});
    assert!(validate_storage_class(&storage, &contract, RestoreStoragePurpose::Raw).is_err());

    let mut snapshot = expected_snapshot_class_spec(&contract.mapping);
    snapshot["metadata"] =
        json!({"name":contract.mapping.snapshot.name,"uid":contract.mapping.snapshot.uid});
    validate_snapshot_class(&snapshot, &contract)?;
    snapshot["metadata"]["unknown"] = json!({"permission":"unreviewed"});
    assert!(validate_snapshot_class(&snapshot, &contract).is_err());
    Ok(())
}
