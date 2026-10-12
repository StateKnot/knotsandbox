//! Exact raw-PV/PVC wire projection. This is not tenant authorization, a fresh
//! cloud proof, a storage receipt, or permission to launch or delete a VM.
//!
//! The only implemented wire template combines driver v1.37.2 with upstream
//! external-provisioner v6.2.1. It is NOT certification of v6.2.1-aliyun. No
//! production route may select this template until its fixed vendor transcript
//! is independently certified. Unknown vendor output is rejected, not stripped.
use super::manifest::{RestoreStorageContext, generated_block_pv_name};
use crate::{
    backup_manifest::{NAMESPACE, block_pvc_name, valid_name},
    cloud_fencing::node_topology::NodeTopologyCloudBinding,
    runtime_manifest::ManifestError,
};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const DRIVER: &str = "diskplugin.csi.alibabacloud.com";
const PV_PROTECTION: &str = "kubernetes.io/pv-protection";
const CSI_FINALIZER: &str = "external-provisioner.volume.kubernetes.io/finalizer";
const SELECTED: &str = "volume.kubernetes.io/selected-node";
const STABLE: &str = "volume.kubernetes.io/storage-provisioner";
const BETA: &str = "volume.beta.kubernetes.io/storage-provisioner";
const BOUND: &str = "pv.kubernetes.io/bound-by-controller";
const COMPLETED: &str = "pv.kubernetes.io/bind-completed";
type Result<T> = std::result::Result<T, ManifestError>;

/// Typed comparison facts only. A caller must derive them from its current
/// locked DB plan and sealed observations. There is deliberately no Deserialize
/// or trusted flag, and this module cannot turn these facts into authority.
pub(crate) struct RawPvNodeFacts {
    pub runtime_node_id: Uuid,
    pub node_uid: Uuid,
    pub boot_id: Uuid,
    pub profile_id: Uuid,
    pub cluster_epoch: Uuid,
    pub topology_receipt_id: Uuid,
    pub node_name: String,
    pub cloud: NodeTopologyCloudBinding,
}
/// Restore-only comparison facts, deliberately separate from deletion-purpose
/// CloudDiskIdentity/observe_disk. No API client, timeout or proof constructor.
pub(crate) struct RawPvDiskFacts {
    pub account_id: String,
    pub region: String,
    pub disk_id: String,
    pub zone_id: String,
    pub deployment: String,
    pub namespace: String,
    pub pvc_name: String,
    pub pv_name: String,
    pub kms_key_id: String,
    pub size_gib: u32,
    pub serial_number: String,
    pub creation_time: DateTime<Utc>,
}
pub(crate) struct RawPvShapeExpected<'a> {
    pub context: &'a RestoreStorageContext,
    pub recorded_parent_uid: Uuid,
    pub selected_node: &'a RawPvNodeFacts,
    pub disk_identity: &'a RawPvDiskFacts,
}
/// Successful projection remains an unverified vendor-template observation.
/// Private fields prevent constructing it from tenant JSON or a DTO literal.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RawPvProjection {
    uid: Uuid,
    parent_uid: Uuid,
    name: String,
    disk_id: String,
    zone_id: String,
    spec_sha256: String,
}
impl RawPvProjection {
    pub(crate) fn uid(&self) -> Uuid {
        self.uid
    }
    pub(crate) fn parent_uid(&self) -> Uuid {
        self.parent_uid
    }
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
    pub(crate) fn disk_id(&self) -> &str {
        &self.disk_id
    }
    pub(crate) fn zone_id(&self) -> &str {
        &self.zone_id
    }
    pub(crate) fn spec_sha256(&self) -> &str {
        &self.spec_sha256
    }
}
fn require(ok: bool, why: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(ManifestError::SpecificationDrift(why))
    }
}
fn exact(value: &Value, keys: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|o| o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k)))
}
fn visible(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|b| b.is_ascii_graphic())
}
fn node_name(value: &str) -> bool {
    value.len() <= 253 && value.split('.').all(valid_name)
}
fn cloud_id(value: &str, prefix: &str) -> bool {
    value.len() <= 128
        && value
            .strip_prefix(prefix)
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric()))
}
fn canonical_uid(value: &Value) -> Option<Uuid> {
    let s = value.as_str()?;
    Uuid::parse_str(s)
        .ok()
        .filter(|u| !u.is_nil() && u.to_string() == s)
}
fn timestamp(value: &Value) -> bool {
    let Some(s) = value.as_str() else {
        return false;
    };
    let b = s.as_bytes();
    if !(20..=30).contains(&b.len())
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[b.len() - 1] != b'Z'
        || ![0..4, 5..7, 8..10, 11..13, 14..16, 17..19]
            .iter()
            .all(|r| b[r.clone()].iter().all(u8::is_ascii_digit))
        || &b[0..4] == b"0000"
        || &b[11..13] > b"23".as_slice()
        || &b[14..16] > b"59".as_slice()
        || &b[17..19] > b"59".as_slice()
    {
        return false;
    }
    if b.len() != 20
        && (b[19] != b'.' || b.len() == 21 || !b[20..b.len() - 1].iter().all(u8::is_ascii_digit))
    {
        return false;
    }
    DateTime::parse_from_rfc3339(s).is_ok()
}
fn capacity(value: &Value) -> Option<u64> {
    let s = value.as_str()?;
    if s.len() > 32 {
        return None;
    }
    let (digits, multiplier) = [
        ("Ti", 1024_u64.pow(4)),
        ("Gi", 1024_u64.pow(3)),
        ("Mi", 1024_u64.pow(2)),
        ("Ki", 1024),
    ]
    .into_iter()
    .find_map(|(suffix, m)| s.strip_suffix(suffix).map(|n| (n, m)))
    .unwrap_or((s, 1));
    if digits.is_empty()
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
    {
        return None;
    }
    digits.parse::<u64>().ok()?.checked_mul(multiplier)
}
fn fields_v1(value: &Value, depth: u8) -> bool {
    depth <= 32
        && value.as_object().is_some_and(|o| {
            o.len() <= 128
                && o.iter().all(|(k, v)| {
                    !k.is_empty()
                        && k.len() <= 1024
                        && (k == "." || ["f:", "k:", "v:", "i:"].iter().any(|p| k.starts_with(p)))
                        && fields_v1(v, depth + 1)
                })
        })
}
fn managed_fields(value: &Value) -> bool {
    value.as_array().is_some_and(|a| {
        a.len() <= 128
            && a.iter().all(|entry| {
                entry.as_object().is_some_and(|e| {
                    e.keys().all(|k| {
                        [
                            "manager",
                            "operation",
                            "apiVersion",
                            "time",
                            "fieldsType",
                            "fieldsV1",
                            "subresource",
                        ]
                        .contains(&k.as_str())
                    }) && e
                        .get("manager")
                        .is_some_and(|v| v.as_str().is_some_and(|s| visible(s, 128)))
                        && e.get("operation")
                            .is_some_and(|v| v == "Update" || v == "Apply")
                        && e.get("apiVersion").is_some_and(|v| v == "v1")
                        && e.get("time").is_none_or(timestamp)
                        && e.get("fieldsType") == Some(&json!("FieldsV1"))
                        && e.get("fieldsV1").is_some_and(fields_v1_root)
                        && e.get("subresource")
                            .is_none_or(|v| v == "" || v == "status")
                })
            })
    })
}
fn fields_v1_root(value: &Value) -> bool {
    fields_v1(value, 0)
}
fn expected_valid(e: &RawPvShapeExpected<'_>) -> Result<String> {
    e.context.block_pvc()?;
    let c = e.context;
    let m = &c.storage_contract.mapping;
    let n = e.selected_node;
    let b = e.disk_identity;
    let name = generated_block_pv_name(e.recorded_parent_uid)?;
    require(
        [
            n.runtime_node_id,
            n.node_uid,
            n.boot_id,
            n.profile_id,
            n.cluster_epoch,
            n.topology_receipt_id,
        ]
        .iter()
        .all(|u| !u.is_nil())
            && n.profile_id == c.storage_contract.profile_id
            && n.cluster_epoch == c.cluster_epoch
            && node_name(&n.node_name)
            && m.topology.zone_ids.contains(&n.cloud.zone_id)
            && n.cloud.account_id == m.account_id
            && n.cloud.region == m.region
            && n.cloud.deployment == m.deployment
            && cloud_id(&n.cloud.instance_id, "i-")
            && cloud_id(&n.cloud.vpc_id, "vpc-")
            && cloud_id(&n.cloud.vswitch_id, "vsw-")
            && n.cloud.private_ip.is_private(),
        "raw PV comparison node facts differ from frozen mapping",
    )?;
    require(
        b.account_id == m.account_id
            && b.region == m.region
            && b.deployment == m.deployment
            && b.zone_id == n.cloud.zone_id
            && b.kms_key_id == m.workspace_kms_key_id
            && b.namespace == NAMESPACE
            && b.pvc_name == block_pvc_name(c.restore_id)
            && b.pv_name == name
            && u64::from(b.size_gib) * 1024_u64.pow(3) == c.size_bytes
            && cloud_id(&b.disk_id, "d-")
            && visible(&e.disk_identity.serial_number, 128)
            && e.disk_identity.creation_time.timestamp() > 0,
        "raw PV comparison disk facts differ from recorded parent and compute KMS",
    )?;
    Ok(name)
}
fn metadata<'a>(
    v: &'a Value,
    name: &str,
    namespace: Option<&str>,
    creating: bool,
) -> Result<&'a Map<String, Value>> {
    let m =
        v.get("metadata")
            .and_then(Value::as_object)
            .ok_or(ManifestError::OwnershipMismatch(
                "raw volume metadata missing",
            ))?;
    require(
        m.keys().all(|k| {
            [
                "name",
                "namespace",
                "uid",
                "resourceVersion",
                "creationTimestamp",
                "generation",
                "managedFields",
                "labels",
                "annotations",
                "finalizers",
                "ownerReferences",
            ]
            .contains(&k.as_str())
        }) && m.get("name") == Some(&json!(name))
            && m.get("uid").and_then(canonical_uid).is_some()
            && m.get("creationTimestamp").is_some_and(timestamp)
            && m.get("generation").is_none_or(|v| v.as_u64() == Some(0))
            && m.get("managedFields").is_none_or(managed_fields)
            && m.get("ownerReferences").is_none_or(|v| v == &json!([])),
        "raw volume metadata unknown, owned, deleting or malformed",
    )?;
    require(
        match namespace {
            Some(ns) => m.get("namespace") == Some(&json!(ns)),
            None => m.get("namespace").is_none_or(|v| v == ""),
        },
        "raw volume namespace",
    )?;
    require(
        if creating {
            m.get("resourceVersion").is_none_or(|v| v == "")
        } else {
            m.get("resourceVersion")
                .and_then(Value::as_str)
                .is_some_and(|s| visible(s, 128))
        },
        "raw volume resourceVersion",
    )?;
    Ok(m)
}
fn pv_finalizers(value: &Value, creating: bool) -> bool {
    value == &json!([CSI_FINALIZER, PV_PROTECTION])
        || value == &json!([PV_PROTECTION, CSI_FINALIZER])
        || (!creating && value == &json!([PV_PROTECTION]))
}
fn driver_attributes(e: &RawPvShapeExpected<'_>, actual: &Value) -> Result<()> {
    let identity = actual
        .get("storage.kubernetes.io/csiProvisionerIdentity")
        .and_then(Value::as_str);
    require(
        identity.is_some_and(|s| visible(s, 256)),
        "raw PV provisioner identity malformed",
    )?;
    let m = &e.context.storage_contract.mapping;
    // Go json.Marshal(NodeSelector) field order is fixed in the pinned source.
    let disk_topology = "{\"nodeSelectorTerms\":[{\"matchExpressions\":[{\"key\":\"node.csi.alibabacloud.com/disktype.cloud_essd\",\"operator\":\"In\",\"values\":[\"available\"]}]}]}";
    let initial = json!({"storage.kubernetes.io/csiProvisionerIdentity":identity,
        "type":"cloud_essd","encrypted":"true","kmsKeyId":m.workspace_kms_key_id,"diskTags/Deployment":m.deployment,
        "csi.alibabacloud.com/label-prefix/topology.diskplugin.csi.alibabacloud.com/region":m.region,
        "csi.alibabacloud.com/label-prefix/topology.diskplugin.csi.alibabacloud.com/zone":e.selected_node.cloud.zone_id,
        "csi.alibabacloud.com/label-prefix/csi.alibabacloud.com/disktype":"cloud_essd.PL1",
        "csi.alibabacloud.com/annotation-prefix/csi.alibabacloud.com/volume-topology":disk_topology});
    // Pinned v1.37.2 initially omits an unspecified performanceLevel, but its
    // idempotent existing-disk path copies the actual PL1 into VolumeContext.
    // These are two complete exact objects. No field is stripped or ignored;
    // performanceLevel remains in the immutable spec digest and UPDATE diff.
    let mut retry = initial.clone();
    retry["performanceLevel"] = json!("PL1");
    require(
        actual == &initial || actual == &retry,
        "raw PV driver context differs from fixed upstream template",
    )
}
fn project_pv(
    v: &Value,
    e: &RawPvShapeExpected<'_>,
    creating: bool,
    known_uid: Option<Uuid>,
) -> Result<RawPvProjection> {
    require(
        serde_json::to_vec(v)
            .map_err(|_| ManifestError::Encoding)?
            .len()
            <= 65536
            && exact(v, &["apiVersion", "kind", "metadata", "spec", "status"])
            && v["apiVersion"] == "v1"
            && v["kind"] == "PersistentVolume",
        "raw PV envelope",
    )?;
    let name = expected_valid(e)?;
    let meta = metadata(v, &name, None, creating)?;
    let uid = canonical_uid(&meta["uid"]).ok_or(ManifestError::OwnershipMismatch("raw PV UID"))?;
    require(
        known_uid.is_none_or(|known| known == uid && !known.is_nil()),
        "recorded raw PV UID replaced",
    )?;
    require(
        meta.get("labels").is_none_or(|v| v == &json!({}))
            && meta.get("annotations")
                == Some(&json!({"pv.kubernetes.io/provisioned-by":DRIVER,
            "volume.kubernetes.io/provisioner-deletion-secret-name":"","volume.kubernetes.io/provisioner-deletion-secret-namespace":""}))
            && meta
                .get("finalizers")
                .is_some_and(|f| pv_finalizers(f, creating)),
        "raw PV upstream metadata/finalizers",
    )?;
    let status = &v["status"];
    require(
        exact(status, &["phase", "lastPhaseTransitionTime"])
            && status.get("lastPhaseTransitionTime").is_some_and(timestamp)
            && (status["phase"] == "Pending" || (!creating && status["phase"] == "Bound")),
        "raw PV server phase/time",
    )?;
    let s = &v["spec"];
    require(
        s.as_object().is_some_and(|o| {
            o.keys().all(|k| {
                [
                    "capacity",
                    "accessModes",
                    "volumeMode",
                    "persistentVolumeReclaimPolicy",
                    "storageClassName",
                    "csi",
                    "claimRef",
                    "nodeAffinity",
                    "mountOptions",
                ]
                .contains(&k.as_str())
            })
        }) && exact(&s["capacity"], &["storage"])
            && capacity(&s["capacity"]["storage"]) == Some(e.context.size_bytes)
            && s["accessModes"] == json!(["ReadWriteOnce"])
            && s["volumeMode"] == "Block"
            && s["persistentVolumeReclaimPolicy"] == "Retain"
            && s["storageClassName"] == e.context.storage_contract.mapping.raw.name
            && s.get("mountOptions").is_none_or(|v| v == &json!([])),
        "raw PV Retain Block specification",
    )?;
    let csi = &s["csi"];
    require(
        csi.as_object().is_some_and(|o| {
            o.keys().all(|k| {
                [
                    "driver",
                    "volumeHandle",
                    "volumeAttributes",
                    "readOnly",
                    "fsType",
                ]
                .contains(&k.as_str())
            })
        }) && csi["driver"] == DRIVER
            && csi["volumeHandle"] == e.disk_identity.disk_id
            && csi.get("readOnly").is_none_or(|v| v == &json!(false))
            && csi.get("fsType").is_none_or(|v| v == ""),
        "raw PV CSI identity or secret/filesystem fields",
    )?;
    driver_attributes(e, &csi["volumeAttributes"])?;
    let r = &s["claimRef"];
    require(
        exact(
            r,
            &[
                "apiVersion",
                "kind",
                "namespace",
                "name",
                "uid",
                "resourceVersion",
            ],
        ) && r["apiVersion"] == "v1"
            && r["kind"] == "PersistentVolumeClaim"
            && r["namespace"] == NAMESPACE
            && r["name"] == block_pvc_name(e.context.restore_id)
            && canonical_uid(&r["uid"]) == Some(e.recorded_parent_uid)
            && r["resourceVersion"]
                .as_str()
                .is_some_and(|s| visible(s, 128)),
        "raw PV recorded claim reference",
    )?;
    require(
        s["nodeAffinity"]
            == json!({"required":{"nodeSelectorTerms":[{"matchExpressions":[{
        "key":e.context.storage_contract.mapping.topology.key,"operator":"In","values":[e.selected_node.cloud.zone_id]}]}]}}),
        "raw PV certified single-AZ affinity",
    )?;
    let mut spec = s.clone();
    spec["capacity"]["storage"] = json!(format!("{}Gi", e.context.size_bytes / 1024_u64.pow(3)));
    let o = spec
        .as_object_mut()
        .ok_or(ManifestError::SpecificationDrift("raw PV spec missing"))?;
    o.remove("mountOptions");
    let csi = spec["csi"]
        .as_object_mut()
        .ok_or(ManifestError::SpecificationDrift("raw PV CSI missing"))?;
    csi.remove("readOnly");
    csi.remove("fsType");
    let digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&spec).map_err(|_| ManifestError::Encoding)?,
    ));
    Ok(RawPvProjection {
        uid,
        parent_uid: e.recorded_parent_uid,
        name,
        disk_id: e.disk_identity.disk_id.clone(),
        zone_id: e.selected_node.cloud.zone_id.clone(),
        spec_sha256: digest,
    })
}
/// Server-prepared upstream-template CREATE only; its UID is not recorded here.
pub(crate) fn project_raw_pv_create_template(
    v: &Value,
    e: &RawPvShapeExpected<'_>,
) -> Result<RawPvProjection> {
    project_pv(v, e, true, None)
}
/// Actual raw GET template projection. `known_uid` must be DB-derived if present.
pub(crate) fn project_raw_pv_live_template(
    v: &Value,
    e: &RawPvShapeExpected<'_>,
    known_uid: Option<Uuid>,
) -> Result<RawPvProjection> {
    project_pv(v, e, false, known_uid)
}
fn protected(v: &Value) -> Value {
    let mut result = v.clone();
    if let Some(m) = result.get_mut("metadata").and_then(Value::as_object_mut) {
        m.remove("managedFields");
    }
    result
}
fn pv_pair(old: &Value, new: &Value, e: &RawPvShapeExpected<'_>) -> Result<()> {
    let before = project_raw_pv_live_template(old, e, None)?;
    project_raw_pv_live_template(new, e, Some(before.uid))?;
    Ok(())
}
/// KCM main object: the approved PV is already fully prebound; no rebinding or
/// bound-by-controller annotation is needed by pinned GetBindVolumeToClaim.
pub(crate) fn validate_raw_pv_prebound_update(
    old: &Value,
    new: &Value,
    e: &RawPvShapeExpected<'_>,
) -> Result<()> {
    pv_pair(old, new, e)?;
    require(
        protected(old) == protected(new),
        "raw PV prebound UPDATE changed protected body",
    )
}
/// KCM /status only. Same-phase retry retains transition time exactly.
pub(crate) fn validate_raw_pv_status_update(
    old: &Value,
    new: &Value,
    e: &RawPvShapeExpected<'_>,
) -> Result<()> {
    pv_pair(old, new, e)?;
    let before = &old["status"];
    let after = &new["status"];
    require(
        (before["phase"] == "Pending" && after["phase"] == "Bound")
            || (before["phase"] == "Bound" && before == after),
        "raw PV invalid phase transition/retry",
    )?;
    let mut b = protected(old);
    let mut n = protected(new);
    b.as_object_mut()
        .ok_or(ManifestError::Encoding)?
        .remove("status");
    n.as_object_mut()
        .ok_or(ManifestError::Encoding)?
        .remove("status");
    require(
        b == n,
        "raw PV status UPDATE changed protected metadata/spec",
    )
}
/// Exact CSI caller on live Retain PV; sole external finalizer removal/retry.
pub(crate) fn validate_raw_pv_retain_finalizer_update(
    old: &Value,
    new: &Value,
    e: &RawPvShapeExpected<'_>,
) -> Result<()> {
    pv_pair(old, new, e)?;
    require(
        new["metadata"]["finalizers"] == json!([PV_PROTECTION]),
        "raw PV protection removal or extra finalizer",
    )?;
    let mut b = protected(old);
    let mut n = protected(new);
    b["metadata"]
        .as_object_mut()
        .ok_or(ManifestError::Encoding)?
        .remove("finalizers");
    n["metadata"]
        .as_object_mut()
        .ok_or(ManifestError::Encoding)?
        .remove("finalizers");
    require(b == n, "raw PV finalizer UPDATE changed protected body")
}
#[derive(PartialEq, Eq)]
enum ClaimState {
    Pending,
    Prebound,
    Bound,
}
fn claim(v: &Value, e: &RawPvShapeExpected<'_>) -> Result<ClaimState> {
    expected_valid(e)?;
    require(
        exact(v, &["apiVersion", "kind", "metadata", "spec", "status"])
            && v["apiVersion"] == "v1"
            && v["kind"] == "PersistentVolumeClaim"
            && serde_json::to_vec(v)
                .map_err(|_| ManifestError::Encoding)?
                .len()
                <= 65536,
        "raw PVC envelope",
    )?;
    let expected = e.context.block_pvc()?;
    let m = metadata(
        v,
        &block_pvc_name(e.context.restore_id),
        Some(NAMESPACE),
        false,
    )?;
    require(
        canonical_uid(&m["uid"]) == Some(e.recorded_parent_uid)
            && m.get("labels") == expected.pointer("/metadata/labels")
            && m.get("finalizers") == Some(&json!(["kubernetes.io/pvc-protection"])),
        "raw PVC recorded parent/protection",
    )?;
    let pv = generated_block_pv_name(e.recorded_parent_uid)?;
    let selected = json!({SELECTED:e.selected_node.node_name,STABLE:DRIVER,BETA:DRIVER});
    let bound_annotations = json!({SELECTED:e.selected_node.node_name,STABLE:DRIVER,BETA:DRIVER,BOUND:"yes",COMPLETED:"yes"});
    let bound = v.pointer("/spec/volumeName") == Some(&json!(pv));
    require(
        if bound {
            m.get("annotations") == Some(&bound_annotations)
        } else {
            v.pointer("/spec/volumeName").is_none_or(|v| v == "")
                && m.get("annotations") == Some(&selected)
        },
        "raw PVC selected/provisioner/binding annotations",
    )?;
    let mut s = v["spec"].clone();
    s.as_object_mut()
        .ok_or(ManifestError::Encoding)?
        .remove("volumeName");
    require(
        capacity(&s["resources"]["requests"]["storage"]) == Some(e.context.size_bytes),
        "raw PVC request capacity",
    )?;
    s["resources"]["requests"]["storage"] =
        expected["spec"]["resources"]["requests"]["storage"].clone();
    require(s == expected["spec"], "raw PVC immutable raw Block intent")?;
    if v["status"] == json!({"phase":"Pending"}) {
        return Ok(if bound {
            ClaimState::Prebound
        } else {
            ClaimState::Pending
        });
    }
    require(
        bound
            && exact(&v["status"], &["phase", "accessModes", "capacity"])
            && v["status"]["phase"] == "Bound"
            && v["status"]["accessModes"] == json!(["ReadWriteOnce"])
            && exact(&v["status"]["capacity"], &["storage"])
            && capacity(&v["status"]["capacity"]["storage"]) == Some(e.context.size_bytes),
        "raw PVC unsupported Bound/resize/VAC status",
    )?;
    Ok(ClaimState::Bound)
}
/// Actual raw GET template validation only. No binding/permission is returned.
pub(crate) fn validate_raw_pvc_live_template(v: &Value, e: &RawPvShapeExpected<'_>) -> Result<()> {
    claim(v, e).map(|_| ())
}
/// KCM main UPDATE: Pending claim receives generated volumeName + both bind
/// annotations; status remains Pending. Already-prebound/bound replay is exact.
pub(crate) fn validate_raw_pvc_binding_update(
    old: &Value,
    new: &Value,
    e: &RawPvShapeExpected<'_>,
) -> Result<()> {
    let before = claim(old, e)?;
    let after = claim(new, e)?;
    require(
        (before == ClaimState::Pending && after == ClaimState::Prebound)
            || (before == after && before != ClaimState::Pending),
        "raw PVC main binding transition",
    )?;
    let mut b = protected(old);
    let mut n = protected(new);
    for v in [&mut b, &mut n] {
        v["spec"]
            .as_object_mut()
            .ok_or(ManifestError::Encoding)?
            .remove("volumeName");
        let a = v["metadata"]["annotations"]
            .as_object_mut()
            .ok_or(ManifestError::Encoding)?;
        a.remove(BOUND);
        a.remove(COMPLETED);
    }
    require(
        b == n,
        "raw PVC binding UPDATE changed protected metadata/status/spec",
    )
}
/// KCM /status UPDATE only after exact main-object prebinding.
pub(crate) fn validate_raw_pvc_status_update(
    old: &Value,
    new: &Value,
    e: &RawPvShapeExpected<'_>,
) -> Result<()> {
    let before = claim(old, e)?;
    let after = claim(new, e)?;
    require(
        [ClaimState::Prebound, ClaimState::Bound].contains(&before) && after == ClaimState::Bound,
        "raw PVC status without exact prebinding",
    )?;
    let mut b = protected(old);
    let mut n = protected(new);
    b.as_object_mut()
        .ok_or(ManifestError::Encoding)?
        .remove("status");
    n.as_object_mut()
        .ok_or(ManifestError::Encoding)?
        .remove("status");
    require(
        b == n,
        "raw PVC status UPDATE changed protected metadata/spec",
    )
}

#[cfg(test)]
#[path = "restore_raw_volume_tests.rs"]
mod tests;
