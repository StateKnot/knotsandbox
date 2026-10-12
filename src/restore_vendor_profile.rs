//! Strict installed report EXPECTATIONS, not certification or a publication
//! capability. Parsing owner claims never creates a Gate, writer or host permit.
use super::{
    admission::{RawBoundDiskScope, RawBoundVendorFacts},
    storage_contract::{ClassIdentity, RestoreStorageMapping},
};
use crate::{backup_object::canonical_decode, nodeguard::protocol::valid_sha256};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use uuid::Uuid;

const REPORT_LIMIT: usize = 131072;
const POLICY: &str = "ALIYUN_RAW_WFFC_BOUND_V1";
const POD_POLICY: &str = "K8S_1_36_4_CSI_POD_V1";
const CASES: [&str; 6] = [
    "initial_pv_create",
    "pl1_idempotent_retry",
    "pv_status_bound",
    "pvc_main_binding",
    "pvc_status_bound",
    "retain_external_finalizer_removal",
];
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum VendorReportError {
    #[error("Restore vendor report unavailable")]
    Unavailable,
    #[error("Restore vendor report file unavailable")]
    Read,
    #[error("Restore vendor report shape rejected")]
    Shape,
    #[error("Restore vendor report differs from current sealed scope")]
    Binding,
    #[error("Restore vendor report or original scope expired")]
    Expired,
}
type Result<T> = std::result::Result<T, VendorReportError>;
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(VendorReportError::Shape)
    }
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Report {
    protocol: u32,
    bindings: Bindings,
    reviewed_at: String,
    expires_at: String,
    raw_bound_vendor: Vendor,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bindings {
    profile_id: Uuid,
    cluster_epoch: Uuid,
    backup_certification_sha256: String,
    storage_mappings: Vec<RestoreStorageMapping>,
    account_id: String,
    region: String,
    deployment: String,
    workspace_kms_key_id: String,
    versions_lock_sha256: String,
    infrastructure_sha256: String,
}
/// Ordinary expected resource identity. These fields cannot mint authority;
/// the later pure/live CSI validator must also verify the actual object.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VendorWorkloadExpectation {
    pub(crate) kind: String,
    pub(crate) namespace: String,
    pub(crate) name: String,
    pub(crate) uid: Uuid,
    pub(crate) service_account_name: String,
    pub(crate) service_account_uid: Uuid,
    pub(crate) spec_sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VendorActiveImageExpectation {
    pub(crate) workload_name: String,
    pub(crate) container_kind: String,
    pub(crate) container_name: String,
    pub(crate) image_ref: String,
    pub(crate) platform_descriptor_sha256: String,
    // This bounded literal is an operator expectation, not verification of a
    // registry descriptor -> runtime imageID relation. Never prefix-match it.
    pub(crate) runtime_image_id: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Images {
    locked: BTreeMap<String, String>,
    active: Vec<VendorActiveImageExpectation>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Protection {
    webhook_uid: Uuid,
    webhook_spec_sha256: String,
    raw_binding_admission_contract_sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Case {
    observed_at: String,
    transcript_sha256: String,
    decoded_case_sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Vendor {
    protocol: u32,
    projector_contract: String,
    terraform_output_sha256: String,
    controller: VendorWorkloadExpectation,
    node_plugin: VendorWorkloadExpectation,
    images: Images,
    pod_projection_contract: String,
    protection: Protection,
    wire_cases_by_zone: BTreeMap<String, BTreeMap<String, Case>>,
    evidence_bundle_sha256: String,
}
/// Private parsed expected data and its exact installed bytes digest. There is
/// no Deserialize/Clone/From<Value>, approved bool or certification constructor.
pub(crate) struct RestoreVendorReport {
    report: Report,
    sha256: String,
    reviewed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}
// Borrowed parsed EXPECTATIONS for the sibling installation-owner writer.
// These fields create no runtime authority and have no caller constructor.
pub(super) struct RestoreReportRegistrationView<'a> {
    pub(super) profile_id: Uuid,
    pub(super) cluster_epoch: Uuid,
    pub(super) backup_certification_sha256: &'a str,
    pub(super) report_sha256: &'a str,
    pub(super) reviewed_at: DateTime<Utc>,
    pub(super) expires_at: DateTime<Utc>,
    pub(super) report: Value,
    pub(super) storage_mappings: Value,
}
fn utc_micros(s: &str) -> Result<DateTime<Utc>> {
    require(s.len() == 27 && s.is_ascii())?;
    let bytes = s.as_bytes();
    require(
        [4, 7].into_iter().all(|p| bytes[p] == b'-')
            && bytes[10] == b'T'
            && bytes[13] == b':'
            && bytes[16] == b':'
            && bytes[19] == b'.'
            && bytes[26] == b'Z'
            && bytes
                .iter()
                .enumerate()
                .all(|(p, b)| [4, 7, 10, 13, 16, 19, 26].contains(&p) || b.is_ascii_digit())
            && &bytes[11..13] <= b"23".as_slice()
            && &bytes[14..16] <= b"59".as_slice()
            && &bytes[17..19] <= b"59".as_slice(),
    )?;
    let value = DateTime::parse_from_rfc3339(s)
        .map_err(|_| VendorReportError::Shape)?
        .with_timezone(&Utc);
    require(value.to_rfc3339_opts(SecondsFormat::Micros, true) == s)?;
    Ok(value)
}
fn mappings(bindings: &Bindings) -> Result<()> {
    let entries = &bindings.storage_mappings;
    require(
        (1..=32).contains(&entries.len())
            && serde_json::to_vec(entries)
                .map_err(|_| VendorReportError::Shape)?
                .len()
                <= 65536,
    )?;
    let first = &entries[0];
    let mut seen: Vec<(&str, &ClassIdentity)> = Vec::new();
    for mapping in entries {
        mapping.validate().map_err(|_| VendorReportError::Shape)?;
        require(
            mapping.account_id == bindings.account_id
                && mapping.region == bindings.region
                && mapping.deployment == bindings.deployment
                && mapping.workspace_kms_key_id == bindings.workspace_kms_key_id
                && mapping.topology == first.topology,
        )?;
        for (purpose, identity) in [
            ("normal", &mapping.normal),
            ("raw", &mapping.raw),
            ("delivery", &mapping.delivery),
            ("snapshot", &mapping.snapshot),
        ] {
            for (prior_purpose, prior) in &seen {
                require(
                    !(purpose == "normal"
                        && *prior_purpose == "normal"
                        && prior.name == identity.name),
                )?;
                let same_resource = prior.uid == identity.uid
                    || (purpose == "snapshot"
                        && *prior_purpose == "snapshot"
                        && prior.name == identity.name)
                    || (purpose != "snapshot"
                        && *prior_purpose != "snapshot"
                        && prior.name == identity.name);
                require(!same_resource || (purpose == *prior_purpose && identity == *prior))?;
            }
            seen.push((purpose, identity));
        }
    }
    Ok(())
}
fn workload(w: &VendorWorkloadExpectation, controller: bool) -> Result<()> {
    let (kind, name, sa) = if controller {
        ("Deployment", "csi-provisioner", "sandbox-csi-controller")
    } else {
        ("DaemonSet", "csi-plugin", "sandbox-csi-node")
    };
    require(
        w.kind == kind
            && w.namespace == "kube-system"
            && w.name == name
            && w.service_account_name == sa
            && !w.uid.is_nil()
            && !w.service_account_uid.is_nil()
            && valid_sha256(&w.spec_sha256),
    )
}
fn images(images: &Images, lock: &Value) -> Result<()> {
    let locked = lock["csi_images"]
        .as_object()
        .ok_or(VendorReportError::Shape)?;
    let expected: BTreeSet<&str> = locked
        .values()
        .map(|v| v.as_str().ok_or(VendorReportError::Shape))
        .collect::<Result<_>>()?;
    require(
        expected.len() == 8
            && images.locked.len() == 8
            && images
                .locked
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == expected
            && images.locked.values().all(|v| valid_sha256(v))
            && (2..=16).contains(&images.active.len()),
    )?;
    let mut previous = None;
    let mut workloads = BTreeSet::new();
    for entry in &images.active {
        let key = (
            &entry.workload_name,
            &entry.container_kind,
            &entry.container_name,
        );
        require(
            previous.is_none_or(|prior| prior < key)
                && ["csi-provisioner", "csi-plugin"].contains(&entry.workload_name.as_str())
                && ["regular", "init"].contains(&entry.container_kind.as_str())
                && crate::backup_manifest::valid_name(&entry.container_name)
                && expected.contains(entry.image_ref.as_str())
                && valid_sha256(&entry.platform_descriptor_sha256)
                && !entry.runtime_image_id.is_empty()
                && entry.runtime_image_id.len() <= 2048
                && entry
                    .runtime_image_id
                    .bytes()
                    .all(|b| (b'!'..=b'~').contains(&b) && !b"*?".contains(&b)),
        )?;
        previous = Some(key);
        if entry.container_kind == "regular" {
            workloads.insert(entry.workload_name.as_str());
        }
    }
    require(workloads == BTreeSet::from(["csi-plugin", "csi-provisioner"]))
}
impl RestoreVendorReport {
    /// A bounded regular public file read. Projected ConfigMap symlinks use the
    /// existing opened-target permission/size checks; credentials are not read.
    pub(crate) fn read(path: &Path) -> Result<Self> {
        let bytes =
            crate::api_tls::read(path, REPORT_LIMIT, false).map_err(|_| VendorReportError::Read)?;
        Self::parse(&bytes)
    }
    pub(crate) fn parse(raw: &[u8]) -> Result<Self> {
        require(!raw.is_empty() && raw.len() <= REPORT_LIMIT)?;
        let value: Value = canonical_decode(raw).map_err(|_| VendorReportError::Shape)?;
        if value.get("raw_bound_vendor").is_none() {
            return Err(VendorReportError::Unavailable);
        }
        let report: Report =
            serde_json::from_value(value.clone()).map_err(|_| VendorReportError::Shape)?;
        require(
            serde_json::to_value(&report).map_err(|_| VendorReportError::Shape)? == value
                && report.protocol == 1
                && report.raw_bound_vendor.protocol == 1
                && !report.bindings.profile_id.is_nil()
                && !report.bindings.cluster_epoch.is_nil()
                && valid_sha256(&report.bindings.backup_certification_sha256)
                && valid_sha256(&report.bindings.infrastructure_sha256),
        )?;
        let lock_bytes = include_bytes!("../deploy/cluster/versions.lock.json");
        let lock: Value =
            serde_json::from_slice(lock_bytes).map_err(|_| VendorReportError::Shape)?;
        require(
            report.bindings.versions_lock_sha256 == hash(lock_bytes)
                && lock["versions"]["kubernetes"] == "1.36.4"
                && lock["versions"]["csi_driver"] == "1.37.2",
        )?;
        mappings(&report.bindings)?;
        let reviewed_at = utc_micros(&report.reviewed_at)?;
        let expires_at = utc_micros(&report.expires_at)?;
        require(expires_at > reviewed_at && expires_at <= reviewed_at + Duration::days(30))?;
        let v = &report.raw_bound_vendor;
        require(
            v.projector_contract == POLICY
                && v.pod_projection_contract == POD_POLICY
                && valid_sha256(&v.terraform_output_sha256)
                && valid_sha256(&v.evidence_bundle_sha256)
                && !v.protection.webhook_uid.is_nil()
                && valid_sha256(&v.protection.webhook_spec_sha256)
                && valid_sha256(&v.protection.raw_binding_admission_contract_sha256),
        )?;
        workload(&v.controller, true)?;
        workload(&v.node_plugin, false)?;
        require(
            BTreeSet::from([
                v.controller.uid,
                v.controller.service_account_uid,
                v.node_plugin.uid,
                v.node_plugin.service_account_uid,
            ])
            .len()
                == 4,
        )?;
        images(&v.images, &lock)?;
        let zones = &report.bindings.storage_mappings[0].topology.zone_ids;
        require(
            v.wire_cases_by_zone.keys().collect::<Vec<_>>() == zones.iter().collect::<Vec<_>>(),
        )?;
        let expected: BTreeSet<&str> = CASES.into_iter().collect();
        for cases in v.wire_cases_by_zone.values() {
            require(cases.keys().map(String::as_str).collect::<BTreeSet<_>>() == expected)?;
            for case in cases.values() {
                let observed_at = utc_micros(&case.observed_at)?;
                require(
                    observed_at <= reviewed_at
                        && observed_at >= reviewed_at - Duration::days(7)
                        && valid_sha256(&case.transcript_sha256)
                        && valid_sha256(&case.decoded_case_sha256),
                )?;
            }
        }
        Ok(Self {
            report,
            sha256: hash(raw),
            reviewed_at,
            expires_at,
        })
    }
    pub(crate) fn report_sha256(&self) -> &str {
        &self.sha256
    }
    pub(super) fn registration_view(&self) -> Result<RestoreReportRegistrationView<'_>> {
        Ok(RestoreReportRegistrationView {
            profile_id: self.report.bindings.profile_id,
            cluster_epoch: self.report.bindings.cluster_epoch,
            backup_certification_sha256: &self.report.bindings.backup_certification_sha256,
            report_sha256: &self.sha256,
            reviewed_at: self.reviewed_at,
            expires_at: self.expires_at,
            report: serde_json::to_value(&self.report).map_err(|_| VendorReportError::Shape)?,
            storage_mappings: serde_json::to_value(&self.report.bindings.storage_mappings)
                .map_err(|_| VendorReportError::Shape)?,
        })
    }
    pub(crate) fn controller(&self) -> &VendorWorkloadExpectation {
        &self.report.raw_bound_vendor.controller
    }
    pub(crate) fn node_plugin(&self) -> &VendorWorkloadExpectation {
        &self.report.raw_bound_vendor.node_plugin
    }
    pub(crate) fn active_images(&self) -> &[VendorActiveImageExpectation] {
        &self.report.raw_bound_vendor.images.active
    }
    /// Comparison only, after the normal owned final14/current check. This
    /// method accepts only the genuine sealed scope, not a naked facts DTO.
    /// Even Ok returns no runtime/vendor proof and confers no publication right.
    pub(crate) fn compare_scope(&self, scope: &RawBoundDiskScope) -> Result<()> {
        scope.current().map_err(|_| VendorReportError::Expired)?;
        let facts: &RawBoundVendorFacts = scope
            .vendor_facts()
            .map_err(|_| VendorReportError::Expired)?;
        let contract = &scope.collection().storage.storage_contract;
        let b = &self.report.bindings;
        let ok = facts.profile_id() == b.profile_id
            && facts.cluster_epoch() == b.cluster_epoch
            && facts.profile_id() == contract.profile_id
            && facts.cluster_epoch() == contract.cluster_epoch
            && facts.report_sha256() == self.sha256
            && contract.report_sha256 == self.sha256
            && contract.backup_certification_sha256 == b.backup_certification_sha256
            && b.storage_mappings.contains(&contract.mapping)
            && facts.terraform_output_sha256()
                == self.report.raw_bound_vendor.terraform_output_sha256
            && facts.infrastructure_sha256() == b.infrastructure_sha256
            && facts.reviewed_at() == self.reviewed_at
            && self.expires_at >= facts.certified_until()
            && !facts.topology_receipt_id().is_nil()
            && !facts.enrollment_id().is_nil();
        contract
            .validate_cloud(&scope.collection().cloud_settings)
            .map_err(|_| VendorReportError::Binding)?;
        if !ok {
            return Err(VendorReportError::Binding);
        }
        if self.expires_at <= Utc::now() {
            return Err(VendorReportError::Expired);
        }
        scope.current().map_err(|_| VendorReportError::Expired)
    }
}
#[cfg(test)]
#[path = "restore_vendor_profile_tests.rs"]
mod tests;
