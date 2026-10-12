//! Private metadata-only WFFC scheduling. No disk/VM birth, closure, quota
//! release or media-absence authority is produced by this decision.
use super::super::{
    manifest::{RestoreStorageContext, generated_block_pv_name},
    policy,
    storage_contract::{RestoreStorageContract, RestoreStoragePurpose},
};
use super::{Decision, RestoreAdmissionService, checked, dependency, observation, selector};
use crate::{
    admission::{AdmissionRequest, ControllerIdentity, Denial, ServiceIdentity},
    backup_admission::{verify_job_object, verify_pod_object},
    backup_job::BackupCloudSettings,
    backup_manifest::{
        BackupManifestContext, NAMESPACE, block_pvc_name, build_backup_manifests, config_name,
        valid_name,
    },
    cloud_fencing::{
        CloudErrorCode, admission_node_topology::AlibabaCloudAdmissionNodeTopology,
        node_topology::NodeTopologyCloudBinding,
    },
    nodeguard::protocol::{BackupStage, NodeBinding, backup_job_name, valid_sha256},
};
use chrono::{DateTime, SecondsFormat, Utc};
use k8s_openapi::api::{
    batch::v1::Job,
    core::v1::{ConfigMap, Node, PersistentVolume, PersistentVolumeClaim, Pod},
    storage::v1::CSINode,
};
use kube::{
    Api,
    api::{GetParams, ListParams},
    core::Request,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    time::{Duration, Instant},
};
use uuid::Uuid;
const SELECTED: &str = "volume.kubernetes.io/selected-node";
const STABLE: &str = "volume.kubernetes.io/storage-provisioner";
const BETA: &str = "volume.beta.kubernetes.io/storage-provisioner";
const DRIVER: &str = "diskplugin.csi.alibabacloud.com";
const TOTAL: Duration = Duration::from_secs(10);
const CSI_KEYS: [&str; 4] = [
    "alibabacloud.com/ecs-instance-id",
    "topology.diskplugin.csi.alibabacloud.com/zone",
    "topology.kubernetes.io/region",
    "topology.kubernetes.io/zone",
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mutation {
    Select,
    Provisioner,
    Reset,
}
#[derive(Clone)]
pub(crate) struct RawSchedulingRuntime {
    csi_controller: ServiceIdentity,
    // Reviewed bound clients persist their request limits/credential caches.
    // There is no runtime fallback to owner identity or unreviewed cloud tuple.
    cloud_clients: BTreeMap<String, AlibabaCloudAdmissionNodeTopology>,
}
impl RawSchedulingRuntime {
    pub(crate) fn new(
        csi: ServiceIdentity,
        clients: Vec<AlibabaCloudAdmissionNodeTopology>,
    ) -> Decision<Self> {
        checked(
            csi.username == "system:serviceaccount:kube-system:sandbox-csi-controller"
                && canonical_uuid(&csi.uid)
                && !clients.is_empty()
                && clients.len() <= 1024,
            "Reviewed exact CSI and independent admission cloud inventory required",
        )?;
        let mut cloud_clients = BTreeMap::new();
        for c in clients {
            let id = c.binding().instance_id.clone();
            checked(
                cloud_clients.insert(id, c).is_none(),
                "Duplicate admission cloud instance binding",
            )?;
        }
        Ok(Self {
            csi_controller: csi,
            cloud_clients,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SchedulingRecord {
    id: Uuid,
    tenant_id: Uuid,
    backup_id: Uuid,
    source_project_id: Uuid,
    target_project_id: Uuid,
    workspace_id: Uuid,
    instance_id: Uuid,
    operation_id: Uuid,
    profile_id: Uuid,
    hold_id: Uuid,
    cluster_epoch: Uuid,
    source_manifest_sha256: String,
    source_identity: Value,
    storage_contract: Value,
    size_gib: i64,
    status: String,
    version: i64,
    deadline: DateTime<Utc>,
    created_at: DateTime<Utc>,
    #[serde(rename = "updated_at")]
    _updated_at: DateTime<Utc>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    id: Uuid,
    tenant_id: Uuid,
    restore_id: Uuid,
    kind: String,
    namespace: String,
    name: String,
    expected_object: Value,
    created_at: DateTime<Utc>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiedVault {
    restore_id: Uuid,
    tenant_id: Uuid,
    backup_id: Uuid,
    manifest_sha256: String,
    signing_key_sha256: String,
    vault_endpoint: String,
    #[serde(rename = "verified_at")]
    _verified_at: DateTime<Utc>,
    #[serde(rename = "recorded_at")]
    _recorded_at: DateTime<Utc>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceVault {
    backup_id: Uuid,
    tenant_id: Uuid,
    manifest_sha256: String,
    manifest: Value,
    #[serde(rename = "verified_at")]
    _verified_at: DateTime<Utc>,
    #[serde(rename = "recorded_at")]
    _recorded_at: DateTime<Utc>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Vault {
    verified: VerifiedVault,
    source: SourceVault,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationIdentity {
    id: Uuid,
    tenant_id: Uuid,
    project_id: Uuid,
    instance_id: Uuid,
    workspace_id: Uuid,
    kind: String,
    actor_principal_id: Uuid,
    request_id: Uuid,
    lease_owner: String,
    lease_token: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthzIdentity {
    tenant_version: i64,
    principal_version: i64,
    source_project_version: i64,
    target_project_version: i64,
    instance_spec_version: i64,
    template_id: Uuid,
    template_version: i64,
    security_id: Uuid,
    security_version: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    intent_id: Uuid,
    tenant_id: Uuid,
    restore_id: Uuid,
    uid: Uuid,
    observed_at: DateTime<Utc>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Resource {
    intent: Intent,
    binding: Option<Binding>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Resources {
    #[serde(rename = "BLOCK_PVC")]
    pvc: Resource,
    #[serde(rename = "BLOCK_PV")]
    pv: Resource,
    #[serde(rename = "CONFIG")]
    config: Resource,
    #[serde(rename = "JOB")]
    job: Resource,
    #[serde(rename = "POD")]
    pod: Resource,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JobContext {
    restore_id: Uuid,
    tenant_id: Uuid,
    context: BackupManifestContext,
    deadline: DateTime<Utc>,
    created_at: DateTime<Utc>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PodAdmission {
    restore_id: Uuid,
    tenant_id: Uuid,
    job_uid: Uuid,
    review_uid: Uuid,
    admitted_at: DateTime<Utc>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeIdentity {
    runtime_node_id: Uuid,
    cluster_epoch: Uuid,
    node_uid: Uuid,
    node_name: String,
    boot_id: Uuid,
    profile_sha256: String,
    cloud_account_id: String,
    region: String,
    cloud_instance_id: String,
    private_ip: String,
}
impl NodeIdentity {
    fn binding(&self) -> NodeBinding {
        NodeBinding {
            cluster_epoch: self.cluster_epoch,
            node_uid: self.node_uid,
            node_name: self.node_name.clone(),
            boot_id: self.boot_id,
            profile_sha256: self.profile_sha256.clone(),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudFact {
    protocol: u32,
    account_id: String,
    region: String,
    instance_id: String,
    zone_id: String,
    vpc_id: String,
    vswitch_id: String,
    private_ip: String,
    deployment: String,
    role: String,
    status: String,
    request_id: String,
    response_sha256: String,
    observed_at: DateTime<Utc>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CsiRegistration {
    csi_node_uid: Uuid,
    node_id: String,
    topology_keys: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Topology {
    id: Uuid,
    runtime_node_id: Uuid,
    enrollment_id: Uuid,
    restore_profile_id: Uuid,
    restore_report_sha256: String,
    terraform_output_sha256: String,
    infrastructure_sha256: String,
    zone_id: String,
    describe_instance: CloudFact,
    csi_registration: CsiRegistration,
    observed_node_resource_version: String,
    observed_csi_node_resource_version: String,
    observed_at: DateTime<Utc>,
    reviewed_at: DateTime<Utc>,
    certified_until: DateTime<Utc>,
    recorded_at: DateTime<Utc>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    record: SchedulingRecord,
    cloud_settings: BackupCloudSettings,
    target_namespace: String,
    vault: Vault,
    operation_identity: OperationIdentity,
    authz_identity: AuthzIdentity,
    job_context: JobContext,
    resource_identities: Resources,
    pod_admission: PodAdmission,
    node_identity: Option<NodeIdentity>,
    node_topology: Option<Topology>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    pin: Pin,
    valid_for_us: i64,
}
struct Loaded {
    pin: Value,
    authority: Pin,
    contract: RestoreStorageContract,
    expected_pvc: Value,
    pvc_uid: Uuid,
    job_uid: Uuid,
    pod_uid: Uuid,
    valid_until: Instant,
}
fn canonical_uuid(s: &str) -> bool {
    Uuid::parse_str(s).is_ok_and(|u| !u.is_nil() && u.to_string() == s)
}
fn exact(v: &Value, keys: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|o| o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k)))
}
fn visible(s: &str, n: usize) -> bool {
    !s.is_empty() && s.len() <= n && s.bytes().all(|b| b.is_ascii_graphic())
}
fn node_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 253 && s.split('.').all(valid_name)
}
fn utc(v: &Value) -> Decision<DateTime<Utc>> {
    let s = v.as_str().ok_or(Denial {
        code: 403,
        message: "UTC topology timestamp required",
    })?;
    let body = s
        .strip_suffix('Z')
        .or_else(|| s.strip_suffix("+00:00"))
        .ok_or(Denial {
            code: 403,
            message: "UTC topology timestamp required",
        })?;
    checked(
        (20..=35).contains(&s.len())
            && body.is_ascii()
            && body.len() >= 19
            && body.as_bytes()[4] == b'-'
            && body.as_bytes()[7] == b'-'
            && body.as_bytes()[10] == b'T'
            && body.as_bytes()[13] == b':'
            && body.as_bytes()[16] == b':'
            && [(11, 23), (14, 59), (17, 59)].iter().all(|(i, m)| {
                body.get(*i..*i + 2).is_some_and(|p| {
                    p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u8>().is_ok_and(|x| x <= *m)
                })
            })
            && body.as_bytes()[..4].iter().all(u8::is_ascii_digit)
            && (body.len() == 19
                || (body.as_bytes()[19] == b'.'
                    && (21..=26).contains(&body.len())
                    && body.as_bytes()[20..].iter().all(u8::is_ascii_digit))),
        "Topology UTC timestamp shape differs",
    )?;
    DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|_| Denial {
            code: 403,
            message: "Topology UTC timestamp invalid",
        })
}
fn check_budget(started: Instant, a: &Loaded, b: Option<&Loaded>) -> Decision<()> {
    checked(
        started.elapsed() < TOTAL
            && Instant::now() < a.valid_until
            && b.is_none_or(|b| Instant::now() < b.valid_until),
        "Raw scheduling authority expired during observation or COMMIT acknowledgement",
    )
}
fn options(r: &AdmissionRequest) -> Decision<()> {
    let Some(v) = &r.options else { return Ok(()) };
    let o = v.as_object().ok_or(Denial {
        code: 403,
        message: "UpdateOptions malformed",
    })?;
    checked(
        o.keys().all(|k| {
            [
                "apiVersion",
                "kind",
                "dryRun",
                "fieldManager",
                "fieldValidation",
            ]
            .contains(&k.as_str())
        }) && o.get("apiVersion").is_none_or(|v| v == "meta.k8s.io/v1")
            && o.get("kind").is_none_or(|v| v == "UpdateOptions")
            && o.get("dryRun")
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))
            && o.get("fieldManager")
                .is_none_or(|v| v.as_str().is_some_and(|s| s.is_ascii() && s.len() <= 128))
            && o.get("fieldValidation").is_none_or(|v| {
                v.as_str()
                    .is_some_and(|s| ["", "Strict", "Warn", "Ignore"].contains(&s))
            }),
        "Unknown or dry-run raw scheduling options",
    )
}
fn annotations(v: &Value) -> Decision<BTreeMap<String, String>> {
    let Some(a) = v.pointer("/metadata/annotations") else {
        return Ok(BTreeMap::new());
    };
    let o = a.as_object().ok_or(Denial {
        code: 403,
        message: "PVC annotations malformed",
    })?;
    checked(
        o.len() <= 3
            && o.keys()
                .all(|k| [SELECTED, STABLE, BETA].contains(&k.as_str())),
        "Unknown raw scheduling annotation",
    )?;
    let mut out = BTreeMap::new();
    for (k, v) in o {
        out.insert(
            k.clone(),
            v.as_str()
                .ok_or(Denial {
                    code: 403,
                    message: "PVC annotation value malformed",
                })?
                .to_owned(),
        );
    }
    checked(
        out.get(SELECTED).is_none_or(|s| node_name(s)),
        "Invalid selected Node name",
    )?;
    checked(
        match (out.get(STABLE), out.get(BETA)) {
            (None, None) => true,
            (Some(a), Some(b)) => a == DRIVER && b == DRIVER,
            _ => false,
        },
        "Provisioner annotations must be the complete reviewed pair",
    )?;
    Ok(out)
}
fn pvc(v: &Value, expected: &Value, uid: Uuid) -> Decision<()> {
    let m = v.get("metadata").and_then(Value::as_object).ok_or(Denial {
        code: 403,
        message: "PVC metadata missing",
    })?;
    checked(
        m.keys().all(|k| {
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
            .contains(&k.as_str())
        }) && m.get("uid") == Some(&json!(uid))
            && m.get("resourceVersion")
                .and_then(Value::as_str)
                .is_some_and(|s| visible(s, 128))
            && m.get("creationTimestamp").is_some_and(|v| utc(v).is_ok())
            && m.get("generation").is_none_or(|v| v.as_u64().is_some())
            && m.get("managedFields").is_none_or(|v| {
                v.as_array()
                    .is_some_and(|a| a.len() <= 128 && a.iter().all(Value::is_object))
            })
            && m.get("finalizers")
                .is_none_or(|v| v == &json!([]) || v == &json!(["kubernetes.io/pvc-protection"]))
            && m.get("ownerReferences")
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
        "PVC has unknown, deleting, owned or malformed metadata",
    )?;
    annotations(v)?;
    let mut baseline = v.clone();
    let m = baseline["metadata"].as_object_mut().ok_or(Denial {
        code: 403,
        message: "PVC metadata missing",
    })?;
    for k in [
        "uid",
        "resourceVersion",
        "creationTimestamp",
        "generation",
        "managedFields",
        "finalizers",
        "annotations",
        "ownerReferences",
    ] {
        m.remove(k);
    }
    let o = baseline.as_object_mut().ok_or(Denial {
        code: 403,
        message: "PVC object malformed",
    })?;
    checked(
        o.remove("status") == Some(json!({"phase":"Pending"})) && baseline == *expected,
        "PVC must remain exact unbound Pending Block intent",
    )
}
fn delta(kind: Mutation, old: &Value, new: &Value, a: &Loaded) -> Decision<Option<String>> {
    body_delta(kind, old, new, &a.expected_pvc, a.pvc_uid)
}
fn body_delta(
    kind: Mutation,
    old: &Value,
    new: &Value,
    expected: &Value,
    uid: Uuid,
) -> Decision<Option<String>> {
    pvc(old, expected, uid)?;
    pvc(new, expected, uid)?;
    let before = annotations(old)?;
    let after = annotations(new)?;
    let mut b = old.clone();
    let mut n = new.clone();
    for v in [&mut b, &mut n] {
        let m = v["metadata"].as_object_mut().ok_or(Denial {
            code: 403,
            message: "PVC metadata missing",
        })?;
        m.remove("managedFields");
        m.remove("annotations");
    }
    checked(
        b == n,
        "Raw scheduling UPDATE changed protected metadata, status or specification",
    )?;
    match kind {
        Mutation::Select => {
            checked(
                before.get(STABLE) == after.get(STABLE) && before.get(BETA) == after.get(BETA),
                "Scheduler cannot write provisioner annotations",
            )?;
            let target = after.get(SELECTED).ok_or(Denial {
                code: 403,
                message: "Scheduler target missing",
            })?;
            checked(
                before.get(SELECTED).is_none_or(|s| s == target),
                "Scheduler cannot replace or remove existing selection",
            )?;
            Ok(Some(target.clone()))
        }
        Mutation::Provisioner => {
            let target = before.get(SELECTED).ok_or(Denial {
                code: 403,
                message: "KCM requires existing selection",
            })?;
            checked(
                after.get(SELECTED) == Some(target)
                    && after.get(STABLE).is_some_and(|s| s == DRIVER)
                    && after.get(BETA).is_some_and(|s| s == DRIVER),
                "KCM may only add or replay the exact provisioner pair",
            )?;
            Ok(Some(target.clone()))
        }
        Mutation::Reset => {
            checked(
                !after.contains_key(SELECTED)
                    && before.get(STABLE) == after.get(STABLE)
                    && before.get(BETA) == after.get(BETA),
                "CSI may only remove selected-node",
            )?;
            Ok(None)
        }
    }
}

fn validate_abi(pin: &Value) -> Decision<()> {
    checked(
        exact(
            pin,
            &[
                "record",
                "cloud_settings",
                "target_namespace",
                "vault",
                "operation_identity",
                "authz_identity",
                "job_context",
                "resource_identities",
                "pod_admission",
                "node_identity",
                "node_topology",
            ],
        ),
        "Raw scheduling pin ABI differs",
    )?;
    checked(
        exact(
            &pin["resource_identities"],
            &["BLOCK_PVC", "BLOCK_PV", "CONFIG", "JOB", "POD"],
        ),
        "Raw resource identity ABI differs",
    )?;
    for key in ["BLOCK_PVC", "BLOCK_PV", "CONFIG", "JOB", "POD"] {
        let r = &pin["resource_identities"][key];
        checked(
            exact(r, &["intent", "binding"])
                && exact(
                    &r["intent"],
                    &[
                        "id",
                        "tenant_id",
                        "restore_id",
                        "kind",
                        "namespace",
                        "name",
                        "expected_object",
                        "created_at",
                    ],
                ),
            "Resource intent ABI differs",
        )?;
        checked(
            if key == "BLOCK_PV" {
                r["binding"].is_null()
            } else {
                exact(
                    &r["binding"],
                    &["intent_id", "tenant_id", "restore_id", "uid", "observed_at"],
                )
            },
            "Resource binding ABI differs",
        )?;
    }
    // Chrono deliberately accepts some leap seconds. Persisted installation
    // timestamps use the same explicit A-v2/B-v3 UTC microsecond wire contract.
    if !pin["node_topology"].is_null() {
        for key in [
            "observed_at",
            "reviewed_at",
            "certified_until",
            "recorded_at",
        ] {
            utc(&pin["node_topology"][key])?;
        }
        utc(&pin["node_topology"]["describe_instance"]["observed_at"])?;
    }
    Ok(())
}
fn fixed_binding(
    r: &Resource,
    tenant: Uuid,
    restore: Uuid,
    kind: &str,
    name: &str,
) -> Decision<Uuid> {
    let i = &r.intent;
    let b = r.binding.as_ref().ok_or(Denial {
        code: 403,
        message: "Fixed resource binding missing",
    })?;
    checked(
        !i.id.is_nil()
            && i.tenant_id == tenant
            && i.restore_id == restore
            && i.kind == kind
            && i.namespace == NAMESPACE
            && i.name == name
            && b.intent_id == i.id
            && b.tenant_id == tenant
            && b.restore_id == restore
            && !b.uid.is_nil()
            && b.observed_at >= i.created_at,
        "Fixed resource binding differs from its intent",
    )?;
    Ok(b.uid)
}
#[derive(Clone, Copy)]
enum AuthorityPurpose {
    Scheduling(Mutation),
    Bound,
}
fn authority(
    envelope: Envelope,
    pin: Value,
    kind: Mutation,
    target: Option<&str>,
    tenant: Uuid,
    restore: Uuid,
    reading: Instant,
) -> Decision<Loaded> {
    authority_for(
        envelope,
        pin,
        AuthorityPurpose::Scheduling(kind),
        target,
        tenant,
        restore,
        reading,
    )
}
fn authority_for(
    envelope: Envelope,
    pin: Value,
    purpose: AuthorityPurpose,
    target: Option<&str>,
    tenant: Uuid,
    restore: Uuid,
    reading: Instant,
) -> Decision<Loaded> {
    let p = envelope.pin;
    let r = &p.record;
    let o = &p.operation_identity;
    let auth = &p.authz_identity;
    checked(
        (1..=10_000_000).contains(&envelope.valid_for_us)
            && r.id == restore
            && r.tenant_id == tenant
            && r.status == "RESTORE_PENDING"
            && r.version > 0
            && [
                r.id,
                r.tenant_id,
                r.backup_id,
                r.source_project_id,
                r.target_project_id,
                r.workspace_id,
                r.instance_id,
                r.operation_id,
                r.profile_id,
                r.hold_id,
                r.cluster_epoch,
            ]
            .iter()
            .all(|u| !u.is_nil())
            && valid_sha256(&r.source_manifest_sha256)
            && valid_name(&p.target_namespace)
            && p.target_namespace != NAMESPACE
            && o.id == r.operation_id
            && o.tenant_id == tenant
            && o.project_id == r.target_project_id
            && o.instance_id == r.instance_id
            && o.workspace_id == r.workspace_id
            && o.kind == "RESTORE"
            && !o.actor_principal_id.is_nil()
            && !o.request_id.is_nil()
            && visible(&o.lease_owner, 128)
            && o.lease_token > 0
            && [
                auth.tenant_version,
                auth.principal_version,
                auth.source_project_version,
                auth.target_project_version,
                auth.instance_spec_version,
                auth.template_version,
                auth.security_version,
            ]
            .iter()
            .all(|v| *v > 0)
            && !auth.template_id.is_nil()
            && !auth.security_id.is_nil()
            && r.created_at <= r.deadline,
        "Current scheduling scope or operation claim identity differs",
    )?;
    let s = policy::Source::from_receipt(
        tenant,
        r.source_project_id,
        r.backup_id,
        r.size_gib,
        p.vault.source.manifest_sha256.clone(),
        p.vault.source.manifest.clone(),
    )
    .map_err(dependency)?;
    policy::compatible(&s, &p.cloud_settings, &p.cloud_settings).map_err(dependency)?;
    checked(
        json!(s.identity) == r.source_identity
            && s.manifest_sha256 == r.source_manifest_sha256
            && p.vault.source.backup_id == r.backup_id
            && p.vault.source.tenant_id == tenant
            && p.vault.verified.restore_id == restore
            && p.vault.verified.tenant_id == tenant
            && p.vault.verified.backup_id == r.backup_id
            && p.vault.verified.manifest_sha256 == s.manifest_sha256
            && p.vault.verified.signing_key_sha256 == s.signing_key_sha256
            && p.vault.verified.vault_endpoint == s.vault_endpoint,
        "Independent restore vault identity changed",
    )?;
    let contract = RestoreStorageContract::parse(&r.storage_contract).map_err(dependency)?;
    contract
        .validate_cloud(&p.cloud_settings)
        .map_err(dependency)?;
    checked(
        contract.profile_id == r.profile_id && contract.cluster_epoch == r.cluster_epoch,
        "Storage contract identity differs",
    )?;
    let storage = RestoreStorageContext {
        tenant_id: tenant,
        source_backup_id: r.backup_id,
        restore_id: restore,
        target_project_id: r.target_project_id,
        instance_id: r.instance_id,
        workspace_id: r.workspace_id,
        cluster_epoch: r.cluster_epoch,
        target_namespace: p.target_namespace.clone(),
        storage_contract: contract.clone(),
        size_bytes: s.identity.size_bytes,
    };
    let expected_pvc = storage.block_pvc().map_err(dependency)?;
    let resources = &p.resource_identities;
    let pvc_uid = fixed_binding(
        &resources.pvc,
        tenant,
        restore,
        "BLOCK_PVC",
        &block_pvc_name(restore),
    )?;
    let job_uid = fixed_binding(
        &resources.job,
        tenant,
        restore,
        "JOB",
        &backup_job_name(restore, BackupStage::Restore),
    )?;
    fixed_binding(
        &resources.config,
        tenant,
        restore,
        "CONFIG",
        &config_name(restore),
    )?;
    let pod_uid = fixed_binding(
        &resources.pod,
        tenant,
        restore,
        "POD",
        &resources.pod.intent.name,
    )?;
    checked(
        resources.pvc.intent.expected_object == expected_pvc
            && (matches!(purpose, AuthorityPurpose::Bound) || resources.pv.binding.is_none())
            && !resources.pv.intent.id.is_nil()
            && resources.pv.intent.tenant_id == tenant
            && resources.pv.intent.restore_id == restore
            && resources.pv.intent.kind == "BLOCK_PV"
            && resources.pv.intent.namespace.is_empty()
            && resources.pv.intent.name == generated_block_pv_name(pvc_uid).map_err(dependency)?
            && resources.pv.intent.expected_object.is_null()
            && resources.pod.intent.expected_object.is_null()
            && pvc_uid != s.identity.source_pvc_uid
            && resources
                .pod
                .intent
                .name
                .strip_prefix(&format!(
                    "{}-",
                    backup_job_name(restore, BackupStage::Restore)
                ))
                .is_some_and(|s| {
                    s.len() == 5
                        && s.bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                }),
        "Raw parent/generated PV/normal Pod identity differs",
    )?;
    let c = &p.job_context;
    let context = &c.context;
    checked(
        c.tenant_id == tenant
            && c.restore_id == restore
            && c.created_at < c.deadline
            && c.deadline <= r.deadline
            && context.tenant_id == tenant
            && context.project_id == r.source_project_id
            && context.backup_id == r.backup_id
            && context.attempt_id == restore
            && context.cluster_epoch == r.cluster_epoch
            && context.stage == BackupStage::Restore
            && context.certification_sha256 == contract.backup_certification_sha256
            && context.block_pvc.as_deref() == Some(block_pvc_name(restore).as_str())
            && context.expected_manifest_sha256.as_deref()
                == Some(r.source_manifest_sha256.as_str())
            && context.password_secret == p.cloud_settings.secret_bindings.password.name
            && context.signing_private_secret
                == p.cloud_settings.secret_bindings.signing_private.name
            && context.signing_public_secret
                == p.cloud_settings.secret_bindings.signing_public.name,
        "Frozen normal restore Job context differs",
    )?;
    let mut config = json!(s.identity);
    let m = config.as_object_mut().ok_or(Denial {
        code: 403,
        message: "Signed source identity malformed",
    })?;
    m.insert("issuer".into(), json!(p.cloud_settings.issuer));
    m.insert(
        "oidc_provider_arn".into(),
        json!(p.cloud_settings.oidc_provider_arn),
    );
    m.insert("roles".into(), json!(p.cloud_settings.roles));
    m.insert(
        "runtime_certification_sha256".into(),
        json!(context.certification_sha256),
    );
    m.insert(
        "deadline".into(),
        json!(c.deadline.to_rfc3339_opts(SecondsFormat::Micros, true)),
    );
    let actual_config: Value = serde_json::from_str(&context.config_json).map_err(dependency)?;
    checked(
        actual_config == config,
        "Restore Job configuration reinterprets frozen historical source",
    )?;
    let manifests = build_backup_manifests(context).map_err(dependency)?;
    checked(
        resources.config.intent.expected_object == manifests.config_map
            && resources.job.intent.expected_object == manifests.job
            && p.pod_admission.tenant_id == tenant
            && p.pod_admission.restore_id == restore
            && p.pod_admission.job_uid == job_uid
            && !p.pod_admission.review_uid.is_nil()
            && pod_uid != p.pod_admission.review_uid
            && p.pod_admission.admitted_at >= c.created_at,
        "Restore Job/config or once Pod admission differs",
    )?;
    match (purpose, &p.node_identity, &p.node_topology) {
        (AuthorityPurpose::Scheduling(Mutation::Reset), None, None) => {}
        (
            AuthorityPurpose::Scheduling(Mutation::Select | Mutation::Provisioner)
            | AuthorityPurpose::Bound,
            Some(n),
            Some(t),
        ) => {
            let cf = &t.describe_instance;
            let ip: Ipv4Addr = n.private_ip.parse().map_err(dependency)?;
            checked(
                n.binding().validate()
                    && target == Some(n.node_name.as_str())
                    && !n.runtime_node_id.is_nil()
                    && n.cluster_epoch == r.cluster_epoch
                    && n.cloud_account_id == contract.mapping.account_id
                    && n.region == contract.mapping.region
                    && ip.is_private()
                    && ip.to_string() == n.private_ip
                    && cf.protocol == 1
                    && cf.account_id == n.cloud_account_id
                    && cf.region == n.region
                    && cf.instance_id == n.cloud_instance_id
                    && cf.zone_id == t.zone_id
                    && cf.private_ip == n.private_ip
                    && cf.deployment == contract.mapping.deployment
                    && cf.role == "kata"
                    && cf.status == "Running"
                    && visible(&cf.request_id, 256)
                    && valid_sha256(&cf.response_sha256)
                    && !t.id.is_nil()
                    && !t.enrollment_id.is_nil()
                    && t.runtime_node_id == n.runtime_node_id
                    && t.restore_profile_id == r.profile_id
                    && t.restore_report_sha256 == contract.report_sha256
                    && valid_sha256(&t.terraform_output_sha256)
                    && valid_sha256(&t.infrastructure_sha256)
                    && contract.mapping.topology.zone_ids.contains(&t.zone_id)
                    && t.certified_until >= c.deadline
                    && t.reviewed_at < t.certified_until
                    && t.recorded_at >= t.observed_at - chrono::Duration::seconds(2)
                    && t.recorded_at <= t.observed_at + chrono::Duration::seconds(10)
                    && cf.observed_at >= t.observed_at - chrono::Duration::seconds(10)
                    && cf.observed_at <= t.observed_at
                    && visible(&t.observed_node_resource_version, 256)
                    && visible(&t.observed_csi_node_resource_version, 256)
                    && !t.csi_registration.csi_node_uid.is_nil()
                    && t.csi_registration.node_id == n.cloud_instance_id
                    && t.csi_registration.topology_keys == CSI_KEYS.map(str::to_owned),
                "Current registered node/topology provenance differs",
            )?;
            // Do not require this immutable installation observation to be younger than
            // ten seconds now. Its current referenced expiry covers the exact Job;
            // fresh Node/CSI/cloud observations are independently performed below.
        }
        _ => {
            return Err(Denial {
                code: 403,
                message: "Scheduling/reset node pin shape differs",
            });
        }
    }
    let valid_until = reading
        .checked_add(Duration::from_micros(
            u64::try_from(envelope.valid_for_us).map_err(dependency)?,
        ))
        .ok_or(Denial {
            code: 403,
            message: "Scheduling horizon overflow",
        })?;
    Ok(Loaded {
        pin,
        authority: p,
        contract,
        expected_pvc,
        pvc_uid,
        job_uid,
        pod_uid,
        valid_until,
    })
}
// Dedicated bound-purpose entry. Existing scheduling ABI/status/no-PV guard is
// unchanged. The new caller must additionally validate all three post-record
// identities; this intermediate value grants no disk, VM or absence authority.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceCloneReceipt {
    attempt_id: Uuid,
    tenant_id: Uuid,
    backup_id: Uuid,
    pvc_uid: Uuid,
    pv_uid: Uuid,
    pv_name: String,
    cloud_disk: String,
    size_bytes: u64,
    recorded_at: DateTime<Utc>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundSourceStorage {
    source: crate::backup_runtime::BackupSource,
    capture_attempt_id: Uuid,
    clone_receipt: SourceCloneReceipt,
}
fn bounded_disk(value: &str) -> bool {
    value.len() <= 128
        && value
            .strip_prefix("d-")
            .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric()))
}
impl BoundSourceStorage {
    fn parse(value: &Value) -> Decision<Self> {
        checked(
            exact(value, &["source", "capture_attempt_id", "clone_receipt"])
                && exact(
                    &value["source"],
                    &[
                        "tenant_id",
                        "project_id",
                        "workspace_id",
                        "backup_id",
                        "cluster_epoch",
                        "namespace",
                        "pvc_name",
                        "pvc_uid",
                        "pv_name",
                        "pv_uid",
                        "cloud_disk",
                        "storage_class",
                        "snapshot_class",
                        "size_bytes",
                    ],
                )
                && exact(
                    &value["clone_receipt"],
                    &[
                        "attempt_id",
                        "tenant_id",
                        "backup_id",
                        "pvc_uid",
                        "pv_uid",
                        "pv_name",
                        "cloud_disk",
                        "size_bytes",
                        "recorded_at",
                    ],
                )
                && value["source"]["size_bytes"]
                    .as_u64()
                    .is_some_and(|n| n > 0)
                && value["clone_receipt"]["size_bytes"]
                    .as_u64()
                    .is_some_and(|n| n > 0),
            "Bound source storage ABI differs",
        )?;
        let source: Self = serde_json::from_value(value.clone()).map_err(|_| Denial {
            code: 403,
            message: "Bound source storage value malformed",
        })?;
        source.source.validate().map_err(|_| Denial {
            code: 403,
            message: "Bound source storage source invalid",
        })?;
        let original = &source.source;
        let clone = &source.clone_receipt;
        let ids = [
            original.pvc_uid,
            original.pv_uid,
            clone.pvc_uid,
            clone.pv_uid,
        ];
        checked(
            value["source"] == json!(original)
                && value["capture_attempt_id"] == json!(source.capture_attempt_id)
                && !source.capture_attempt_id.is_nil()
                && value["clone_receipt"]["attempt_id"] == json!(clone.attempt_id)
                && value["clone_receipt"]["tenant_id"] == json!(clone.tenant_id)
                && value["clone_receipt"]["backup_id"] == json!(clone.backup_id)
                && value["clone_receipt"]["pvc_uid"] == json!(clone.pvc_uid)
                && value["clone_receipt"]["pv_uid"] == json!(clone.pv_uid)
                && !clone.tenant_id.is_nil()
                && !clone.backup_id.is_nil()
                && clone.attempt_id == source.capture_attempt_id
                && clone.tenant_id == original.tenant_id
                && clone.backup_id == original.backup_id
                && ids.iter().all(|id| !id.is_nil())
                && ids
                    .iter()
                    .enumerate()
                    .all(|(i, id)| ids[..i].iter().all(|old| old != id))
                && valid_name(&clone.pv_name)
                && clone.pv_name != original.pv_name
                && bounded_disk(&original.cloud_disk)
                && bounded_disk(&clone.cloud_disk)
                && clone.cloud_disk != original.cloud_disk
                && clone.size_bytes == original.size_bytes
                && utc(&value["clone_receipt"]["recorded_at"])? == clone.recorded_at
                && clone.recorded_at.timestamp() > 0,
            "Bound source and normal capture clone identity differs",
        )?;
        Ok(source)
    }
    fn validate(&self, loaded: &Loaded) -> Decision<()> {
        let a = &loaded.authority;
        let r = &a.record;
        let identity: crate::backup_object::BackupIdentity =
            serde_json::from_value(r.source_identity.clone()).map_err(|_| Denial {
                code: 403,
                message: "Bound verified source identity malformed",
            })?;
        let source = &self.source;
        let clone = &self.clone_receipt;
        let excluded = [source.pvc_uid, source.pv_uid, clone.pvc_uid, clone.pv_uid];
        checked(
            source.tenant_id == r.tenant_id
                && source.project_id == r.source_project_id
                && source.backup_id == r.backup_id
                && source.tenant_id == identity.tenant_id
                && source.project_id == identity.project_id
                && source.backup_id == identity.backup_id
                && source.cluster_epoch == identity.cluster_epoch
                && source.pvc_uid == identity.source_pvc_uid
                && clone.pvc_uid == identity.clone_pvc_uid
                && self.capture_attempt_id != identity.seal_attempt_id
                && source.size_bytes == identity.size_bytes
                && clone.recorded_at <= a.vault.source._recorded_at + chrono::Duration::seconds(2)
                && !excluded.contains(&loaded.pvc_uid)
                && a.resource_identities
                    .pv
                    .binding
                    .as_ref()
                    .is_none_or(|pv| !excluded.contains(&pv.uid)),
            "Bound source storage differs from verified source or raw parent",
        )
    }
}
/// Readonly report comparison facts from the already validated same14 pin.
/// Private fields/constructor; this is not vendor certification or authority.
pub(crate) struct RawBoundVendorFacts {
    profile_id: Uuid,
    cluster_epoch: Uuid,
    report_sha256: String,
    topology_receipt_id: Uuid,
    enrollment_id: Uuid,
    reviewed_at: DateTime<Utc>,
    certified_until: DateTime<Utc>,
    terraform_output_sha256: String,
    infrastructure_sha256: String,
}
impl RawBoundVendorFacts {
    pub(crate) fn profile_id(&self) -> Uuid {
        self.profile_id
    }
    pub(crate) fn cluster_epoch(&self) -> Uuid {
        self.cluster_epoch
    }
    pub(crate) fn report_sha256(&self) -> &str {
        &self.report_sha256
    }
    pub(crate) fn topology_receipt_id(&self) -> Uuid {
        self.topology_receipt_id
    }
    pub(crate) fn enrollment_id(&self) -> Uuid {
        self.enrollment_id
    }
    pub(crate) fn reviewed_at(&self) -> DateTime<Utc> {
        self.reviewed_at
    }
    pub(crate) fn certified_until(&self) -> DateTime<Utc> {
        self.certified_until
    }
    pub(crate) fn terraform_output_sha256(&self) -> &str {
        &self.terraform_output_sha256
    }
    pub(crate) fn infrastructure_sha256(&self) -> &str {
        &self.infrastructure_sha256
    }
}
pub(super) struct RawBoundBase {
    loaded: Loaded,
    source_storage: BoundSourceStorage,
}
impl RawBoundBase {
    pub(super) fn valid_until(&self) -> Instant {
        self.loaded.valid_until
    }
    pub(super) fn narrow_horizon(&mut self, original: Instant) {
        self.loaded.valid_until = self.loaded.valid_until.min(original);
    }
    pub(super) fn disk_facts(&self) -> Decision<super::raw_bound::RawBoundDiskFacts> {
        let a = &self.loaded.authority;
        let r = &a.record;
        let node = a.node_identity.as_ref().ok_or(Denial {
            code: 403,
            message: "Bound selected node identity missing",
        })?;
        let topology = a.node_topology.as_ref().ok_or(Denial {
            code: 403,
            message: "Bound selected topology missing",
        })?;
        let source = &self.source_storage.source;
        let clone = &self.source_storage.clone_receipt;
        Ok(super::raw_bound::RawBoundDiskFacts {
            tenant_id: r.tenant_id,
            restore_id: r.id,
            cluster_epoch: r.cluster_epoch,
            namespace: NAMESPACE.into(),
            pvc_name: block_pvc_name(r.id),
            pvc_uid: self.loaded.pvc_uid,
            pv_name: a.resource_identities.pv.intent.name.clone(),
            parent_intent_created_at: a.resource_identities.pvc.intent.created_at,
            account_id: self.loaded.contract.mapping.account_id.clone(),
            region: self.loaded.contract.mapping.region.clone(),
            deployment: self.loaded.contract.mapping.deployment.clone(),
            workspace_kms_key_id: self.loaded.contract.mapping.workspace_kms_key_id.clone(),
            size_gib: u32::try_from(r.size_gib).map_err(dependency)?,
            zone_id: topology.zone_id.clone(),
            runtime_node_id: node.runtime_node_id,
            node: node.binding(),
            cloud_instance_id: node.cloud_instance_id.clone(),
            source_pvc_uid: source.pvc_uid,
            source_pv_uid: source.pv_uid,
            source_disk_id: source.cloud_disk.clone(),
            clone_pvc_uid: clone.pvc_uid,
            clone_pv_uid: clone.pv_uid,
            clone_disk_id: clone.cloud_disk.clone(),
        })
    }
    pub(super) fn vendor_facts(&self) -> Decision<RawBoundVendorFacts> {
        let topology = self.loaded.authority.node_topology.as_ref().ok_or(Denial {
            code: 403,
            message: "Bound vendor comparison topology missing",
        })?;
        Ok(RawBoundVendorFacts {
            profile_id: self.loaded.contract.profile_id,
            cluster_epoch: self.loaded.contract.cluster_epoch,
            report_sha256: self.loaded.contract.report_sha256.clone(),
            topology_receipt_id: topology.id,
            enrollment_id: topology.enrollment_id,
            reviewed_at: topology.reviewed_at,
            certified_until: topology.certified_until,
            terraform_output_sha256: topology.terraform_output_sha256.clone(),
            infrastructure_sha256: topology.infrastructure_sha256.clone(),
        })
    }
    pub(super) fn collection_facts(&self) -> Decision<super::raw_bound::RawBoundCollectionFacts> {
        let a = &self.loaded.authority;
        let r = &a.record;
        let topology = a.node_topology.as_ref().ok_or(Denial {
            code: 403,
            message: "Bound collection topology missing",
        })?;
        let recorded = match &a.resource_identities.pv.binding {
            None => {
                checked(
                    self.loaded.pin["block_receipt"].is_null()
                        && self.loaded.pin["disk_receipt"].is_null(),
                    "Bound collection target records incomplete",
                )?;
                None
            }
            Some(binding) => {
                let disk = &self.loaded.pin["disk_receipt"];
                let disk_id = disk["cloud_identity"]["binding"]["disk_id"]
                    .as_str()
                    .ok_or(Denial {
                        code: 403,
                        message: "Bound collection recorded disk missing",
                    })?;
                let serial = disk["cloud_identity"]["serial_number"]
                    .as_str()
                    .ok_or(Denial {
                        code: 403,
                        message: "Bound collection recorded serial missing",
                    })?;
                let digest = disk["pv_spec_sha256"].as_str().ok_or(Denial {
                    code: 403,
                    message: "Bound collection recorded digest missing",
                })?;
                checked(
                    visible(serial, 128)
                        && valid_sha256(digest)
                        && disk_id
                            == self.loaded.pin["block_receipt"]["cloud_disk"]
                                .as_str()
                                .unwrap_or(""),
                    "Bound collection immutable target differs",
                )?;
                Some(super::raw_bound::RawBoundRecordedDiskFacts {
                    pv_uid: binding.uid,
                    pv_spec_sha256: digest.into(),
                    disk_id: disk_id.into(),
                    serial_number: serial.into(),
                    creation_time: utc(&disk["cloud_identity"]["creation_time"])?,
                })
            }
        };
        Ok(super::raw_bound::RawBoundCollectionFacts {
            storage: RestoreStorageContext {
                tenant_id: r.tenant_id,
                source_backup_id: r.backup_id,
                restore_id: r.id,
                target_project_id: r.target_project_id,
                instance_id: r.instance_id,
                workspace_id: r.workspace_id,
                cluster_epoch: r.cluster_epoch,
                target_namespace: a.target_namespace.clone(),
                storage_contract: self.loaded.contract.clone(),
                size_bytes: self.source_storage.source.size_bytes,
            },
            cloud: cloud_binding(&self.loaded)?,
            cloud_settings: a.cloud_settings.clone(),
            topology_receipt_id: topology.id,
            csi_node_uid: topology.csi_registration.csi_node_uid,
            recorded,
        })
    }
    pub(super) fn validate_collection_node(&self, node: &Value, csi: &Value) -> Decision<()> {
        let binding = cloud_binding(&self.loaded)?;
        live_node(node, &self.loaded, &binding)?;
        live_csi(csi, &self.loaded, &binding)
    }
    pub(super) fn compare_collection_objects(&self, before: &Value, after: &Value) -> Decision<()> {
        same_protected(before, after)
    }
    pub(super) fn claim_matches(&self, operation: Uuid, owner: &str, token: i64) -> bool {
        let c = &self.loaded.authority.operation_identity;
        c.id == operation && c.lease_owner == owner && c.lease_token == token
    }
    pub(super) fn validate_post_record(&self, block: &Value, disk: &Value) -> Decision<()> {
        let a = &self.loaded.authority;
        let r = &a.record;
        let pv = &a.resource_identities.pv;
        let b = pv.binding.as_ref();
        if b.is_none() && block.is_null() && disk.is_null() {
            return checked(
                r.status == "RESTORE_PENDING",
                "Pre-record bound authority phase differs",
            );
        }
        let Some(b) = b else {
            return checked(false, "Incomplete bound identity/receipts");
        };
        checked(
            !b.uid.is_nil()
                && b.uid != self.loaded.pvc_uid
                && b.intent_id == pv.intent.id
                && b.tenant_id == r.tenant_id
                && b.restore_id == r.id
                && b.observed_at >= pv.intent.created_at
                && block["restore_id"] == json!(r.id)
                && block["tenant_id"] == json!(r.tenant_id)
                && block["pvc_uid"] == json!(self.loaded.pvc_uid)
                && block["pv_uid"] == json!(b.uid)
                && block["pv_name"] == json!(pv.intent.name)
                && block["size_bytes"].as_i64() == r.size_gib.checked_mul(1_073_741_824)
                && block["cloud_disk"].as_str().is_some_and(|disk| {
                    disk != self.source_storage.source.cloud_disk
                        && disk != self.source_storage.clone_receipt.cloud_disk
                })
                && block["cloud_disk"].as_str().is_some_and(|s| {
                    s.len() <= 128
                        && s.strip_prefix("d-").is_some_and(|v| {
                            !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric())
                        })
                })
                && disk["restore_id"] == json!(r.id)
                && disk["tenant_id"] == json!(r.tenant_id)
                && disk["pv_spec_sha256"].as_str().is_some_and(valid_sha256),
            "Recorded raw parent/PV/volume/digest identity differs",
        )?;
        let topology = a.node_topology.as_ref().ok_or(Denial {
            code: 403,
            message: "Bound node topology missing",
        })?;
        let binding = &disk["cloud_identity"]["binding"];
        checked(
            disk["node_topology_receipt_id"] == json!(topology.id)
                && *binding
                    == json!({"account_id":self.loaded.contract.mapping.account_id,
                    "region":self.loaded.contract.mapping.region,"disk_id":block["cloud_disk"],
                    "zone_id":topology.zone_id,"deployment":self.loaded.contract.mapping.deployment,
                    "namespace":NAMESPACE,"pvc_name":block_pvc_name(r.id),"pv_name":pv.intent.name,
                    "kms_key_id":self.loaded.contract.mapping.workspace_kms_key_id,"size_gib":r.size_gib}),
            "Recorded raw disk encryption/topology/parent identity differs",
        )?;
        let observed = utc(&disk["cloud_evidence"]["observed_at"])?;
        let recorded = utc(&disk["recorded_at"])?;
        let raw_recorded = utc(&block["recorded_at"])?;
        checked(
            observed >= utc(&disk["cloud_identity"]["creation_time"])?
                && recorded >= observed - chrono::Duration::seconds(2)
                && recorded <= observed + chrono::Duration::seconds(10)
                && raw_recorded >= observed - chrono::Duration::seconds(2)
                && raw_recorded <= observed + chrono::Duration::seconds(10)
                && raw_recorded
                    >= a.resource_identities
                        .pvc
                        .binding
                        .as_ref()
                        .ok_or(Denial {
                            code: 403,
                            message: "Raw parent binding missing",
                        })?
                        .observed_at
                && raw_recorded >= b.observed_at - chrono::Duration::seconds(2),
            "Recorded raw disk observation/publication relationship differs",
        )
    }
}
pub(super) fn decode_raw_bound_base(
    value: &Value,
    tenant: Uuid,
    restore: Uuid,
    node_hint: &str,
    reading: Instant,
) -> Decision<RawBoundBase> {
    checked(
        exact(value, &["pin", "valid_for_us"]),
        "Bound reader envelope ABI differs",
    )?;
    let mut base_pin = value["pin"].clone();
    let fields = base_pin.as_object_mut().ok_or(Denial {
        code: 403,
        message: "Bound pin malformed",
    })?;
    checked(
        fields.len() == 14
            && fields.remove("block_receipt").is_some()
            && fields.remove("disk_receipt").is_some(),
        "Bound pin ABI differs",
    )?;
    let source_storage =
        BoundSourceStorage::parse(&fields.remove("source_storage").ok_or(Denial {
            code: 403,
            message: "Bound source storage missing",
        })?)?;
    // Reuse the original ABI validator on a validation-only view. Never erase
    // the actual PV binding from the full pin or from the typed bound decoder.
    let mut abi_view = base_pin.clone();
    abi_view["resource_identities"]["BLOCK_PV"]["binding"] = Value::Null;
    validate_abi(&abi_view)?;
    let envelope: Envelope =
        serde_json::from_value(json!({"pin":base_pin,"valid_for_us":value["valid_for_us"]}))
            .map_err(dependency)?;
    let loaded = authority_for(
        envelope,
        value["pin"].clone(),
        AuthorityPurpose::Bound,
        Some(node_hint),
        tenant,
        restore,
        reading,
    )?;
    source_storage.validate(&loaded)?;
    Ok(RawBoundBase {
        loaded,
        source_storage,
    })
}

impl RestoreAdmissionService {
    async fn load_raw_scheduling(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant: Uuid,
        restore: Uuid,
        kind: Mutation,
        target: Option<&str>,
        reading: Instant,
    ) -> Decision<Loaded> {
        let value: Option<Value> = if kind == Mutation::Reset {
            sqlx::query_scalar("SELECT sandbox_restore_raw_reschedule_admission($1,$2)")
                .bind(tenant)
                .bind(restore)
                .fetch_one(&mut **tx)
                .await
                .map_err(dependency)?
        } else {
            sqlx::query_scalar("SELECT sandbox_restore_raw_scheduling_admission($1,$2,$3)")
                .bind(tenant)
                .bind(restore)
                .bind(target)
                .fetch_one(&mut **tx)
                .await
                .map_err(dependency)?
        };
        let value = value.ok_or(Denial {
            code: 403,
            message: "Current raw scheduling authority unavailable",
        })?;
        checked(
            exact(&value, &["pin", "valid_for_us"]),
            "Scheduling reader envelope ABI differs",
        )?;
        let pin = value["pin"].clone();
        validate_abi(&pin)?;
        let envelope: Envelope = serde_json::from_value(value).map_err(dependency)?;
        authority(envelope, pin, kind, target, tenant, restore, reading)
    }
}

// This classifier does not infer purpose from submitted annotations. Separate
// reviewed caller identities select one fixed, metadata-only operation.
fn controller_purpose(identity: &ControllerIdentity, control_name: &str) -> bool {
    match identity {
        ControllerIdentity::ControlPlane { username } => username == control_name,
        ControllerIdentity::ServiceAccount { username, uid } => {
            let parts: Vec<_> = username.split(':').collect();
            parts.len() == 4
                && parts[0] == "system"
                && parts[1] == "serviceaccount"
                && parts[2..].iter().all(|s| valid_name(s))
                && canonical_uuid(uid)
        }
    }
}
fn service_part(identity: &ControllerIdentity) -> Option<(&str, &str)> {
    match identity {
        ControllerIdentity::ServiceAccount { username, uid } => Some((username, uid)),
        _ => None,
    }
}
fn classify(
    service: &RestoreAdmissionService,
    runtime: &RawSchedulingRuntime,
    r: &AdmissionRequest,
) -> Decision<Mutation> {
    checked(
        controller_purpose(&service.scheduler, "system:kube-scheduler")
            && controller_purpose(
                &service.identities.job_controller,
                "system:kube-controller-manager",
            )
            && service.identities.controller.username
                == "system:serviceaccount:sandbox-system:sandbox-backup-controller"
            && canonical_uuid(&service.identities.controller.uid),
        "Distinct reviewed scheduling identities required",
    )?;
    let mut accounts = vec![
        (
            runtime.csi_controller.username.as_str(),
            runtime.csi_controller.uid.as_str(),
        ),
        (
            service.identities.controller.username.as_str(),
            service.identities.controller.uid.as_str(),
        ),
    ];
    accounts.extend(service_part(&service.scheduler));
    accounts.extend(service_part(&service.identities.job_controller));
    checked(
        accounts.iter().enumerate().all(|(i, (name, uid))| {
            accounts
                .iter()
                .skip(i + 1)
                .all(|(n, u)| name != n && uid != u)
        }),
        "Scheduling, KCM, CSI and backup identities must be distinct",
    )?;
    if service.scheduler.matches(&r.user_info) {
        Ok(Mutation::Select)
    } else if service.identities.job_controller.matches(&r.user_info) {
        Ok(Mutation::Provisioner)
    } else if runtime.csi_controller.username == r.user_info.username
        && runtime.csi_controller.uid == r.user_info.uid
    {
        Ok(Mutation::Reset)
    } else {
        Err(Denial {
            code: 403,
            message: "Caller has no raw scheduling purpose",
        })
    }
}
fn target_hint(kind: Mutation, old: &Value, new: &Value) -> Decision<Option<String>> {
    // These untrusted names are solely SQL locators. No submitted node UID,
    // topology or physical identity can become authority through this hint.
    let b = annotations(old)?;
    let n = annotations(new)?;
    match kind {
        Mutation::Select => n.get(SELECTED).cloned().map(Some).ok_or(Denial {
            code: 403,
            message: "Selected Node locator missing",
        }),
        Mutation::Provisioner => b.get(SELECTED).cloned().map(Some).ok_or(Denial {
            code: 403,
            message: "Provisioner Node locator missing",
        }),
        Mutation::Reset => Ok(None),
    }
}
fn metadata(value: &Value, name: &str, namespace: Option<&str>, uid: Uuid) -> Decision<()> {
    let m = value
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or(Denial {
            code: 403,
            message: "Observed resource metadata missing",
        })?;
    checked(
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
                "ownerReferences",
                "finalizers",
                "generateName",
            ]
            .contains(&k.as_str())
        }) && m.get("name") == Some(&json!(name))
            && m.get("uid") == Some(&json!(uid))
            && match namespace {
                Some(ns) => m.get("namespace") == Some(&json!(ns)),
                None => m.get("namespace").is_none_or(|v| v == ""),
            }
            && m.get("resourceVersion")
                .and_then(Value::as_str)
                .is_some_and(|s| visible(s, 256))
            && m.get("creationTimestamp").is_some_and(|v| utc(v).is_ok())
            && m.get("generation").is_none_or(|v| v.as_u64().is_some())
            && m.get("managedFields").is_none_or(|v| {
                v.as_array()
                    .is_some_and(|a| a.len() <= 128 && a.iter().all(Value::is_object))
            }),
        "Observed resource has unknown, deleting or malformed metadata",
    )
}
fn protected(mut value: Value) -> Value {
    // No unknown fields are removed. Callers validate the original raw JSON
    // first; only well-known, non-authorizing API bookkeeping/status is omitted.
    if let Some(m) = value.get_mut("metadata").and_then(Value::as_object_mut) {
        for key in [
            "resourceVersion",
            "creationTimestamp",
            "generation",
            "managedFields",
        ] {
            m.remove(key);
        }
    }
    if let Some(o) = value.as_object_mut() {
        o.remove("status");
    }
    value
}
fn same_protected(a: &Value, b: &Value) -> Decision<()> {
    checked(
        protected(a.clone()) == protected(b.clone()),
        "Observed protected resource changed during scheduling decision",
    )
}
fn pending_pod(value: &Value, a: &Loaded) -> Decision<()> {
    let name = &a.authority.resource_identities.pod.intent.name;
    metadata(value, name, Some(NAMESPACE), a.pod_uid)?;
    checked(
        value.pointer("/spec/nodeName").is_none_or(|v| v == "")
            && value
                .get("status")
                .is_none_or(|v| v.is_object() && v.get("phase").is_none_or(|p| p == "Pending")),
        "Restore Pod is assigned, terminating or beyond Pending",
    )?;
    verify_pod_object(
        value,
        &a.authority.job_context.context,
        a.job_uid,
        a.pod_uid,
    )
}
async fn get(client: &kube::Client, url: &str, name: &str) -> Decision<Option<Value>> {
    let request = Request::new(url)
        .get(name, &GetParams::default())
        .map_err(dependency)?;
    match client.request::<Value>(request).await {
        Ok(value) => Ok(Some(value)),
        Err(kube::Error::Api(error)) if error.code == 404 => Ok(None),
        Err(error) => Err(dependency(error)),
    }
}
fn required(value: Option<Value>) -> Decision<Value> {
    value.ok_or(Denial {
        code: 403,
        message: "Fixed live scheduling resource absent",
    })
}
fn single_pod_page(value: &Value, a: &Loaded) -> Decision<Value> {
    checked(
        exact(value, &["apiVersion", "kind", "metadata", "items"])
            && value["apiVersion"] == "v1"
            && value["kind"] == "PodList",
        "Pod list ABI differs",
    )?;
    let m = value["metadata"].as_object().ok_or(Denial {
        code: 403,
        message: "Pod list metadata missing",
    })?;
    checked(
        m.keys().all(|k| {
            [
                "resourceVersion",
                "continue",
                "remainingItemCount",
                "selfLink",
            ]
            .contains(&k.as_str())
        }) && m
            .get("resourceVersion")
            .and_then(Value::as_str)
            .is_some_and(|s| visible(s, 256))
            && m.get("continue").is_none_or(|v| v == "")
            && m.get("selfLink").is_none_or(|v| v == "")
            && m.get("remainingItemCount")
                .is_none_or(|v| v.as_u64() == Some(0)),
        "Pod list pagination or metadata is incomplete",
    )?;
    let items = value["items"].as_array().ok_or(Denial {
        code: 403,
        message: "Pod list items malformed",
    })?;
    // Never filter deleting, terminal or unexpected items out before counting.
    checked(
        items.len() == 1,
        "Restore Job must have exactly one current Pod",
    )?;
    pending_pod(&items[0], a)?;
    Ok(items[0].clone())
}
struct WorkloadObservation {
    pvc: Value,
    config: Value,
    job: Value,
    pod: Value,
}
impl RestoreAdmissionService {
    async fn workload_observation(&self, a: &Loaded, old: &Value) -> Decision<WorkloadObservation> {
        let client = self.runtime.runtime().client_clone();
        let resources = &a.authority.resource_identities;
        let pvcs = Api::<PersistentVolumeClaim>::namespaced(client.clone(), NAMESPACE);
        let pvc = required(get(&client, pvcs.resource_url(), &resources.pvc.intent.name).await?)?;
        pvc_validate_live(&pvc, old, a)?;
        let configs = Api::<ConfigMap>::namespaced(client.clone(), NAMESPACE);
        let config = required(
            get(
                &client,
                configs.resource_url(),
                &resources.config.intent.name,
            )
            .await?,
        )?;
        let config_uid = resources
            .config
            .binding
            .as_ref()
            .ok_or(Denial {
                code: 403,
                message: "Config binding missing",
            })?
            .uid;
        metadata(
            &config,
            &resources.config.intent.name,
            Some(NAMESPACE),
            config_uid,
        )?;
        let mut config_view = config.clone();
        if let Some(m) = config_view["metadata"].as_object_mut() {
            for k in [
                "uid",
                "resourceVersion",
                "creationTimestamp",
                "generation",
                "managedFields",
            ] {
                m.remove(k);
            }
        }
        checked(
            config_view == resources.config.intent.expected_object,
            "Observed ConfigMap differs from frozen restore intent",
        )?;
        let jobs = Api::<Job>::namespaced(client.clone(), NAMESPACE);
        let job = required(get(&client, jobs.resource_url(), &resources.job.intent.name).await?)?;
        metadata(&job, &resources.job.intent.name, Some(NAMESPACE), a.job_uid)?;
        verify_job_object(&job, &a.authority.job_context.context, a.job_uid)?;
        checked(
            job.pointer("/spec/suspend") == Some(&json!(false)),
            "Suspended restore Job cannot select raw storage",
        )?;
        let pods = Api::<Pod>::namespaced(client.clone(), NAMESPACE);
        let pod = required(get(&client, pods.resource_url(), &resources.pod.intent.name).await?)?;
        pending_pod(&pod, a)?;
        let params = ListParams::default()
            .labels(&format!("batch.kubernetes.io/controller-uid={}", a.job_uid))
            .limit(2);
        let request = Request::new(pods.resource_url())
            .list(&params)
            .map_err(dependency)?;
        let page: Value = client.request(request).await.map_err(dependency)?;
        let listed = single_pod_page(&page, a)?;
        same_protected(&pod, &listed)?;
        Ok(WorkloadObservation {
            pvc,
            config,
            job,
            pod,
        })
    }
    async fn generated_pv_absent(&self, a: &Loaded) -> Decision<()> {
        let client = self.runtime.runtime().client_clone();
        let pvs = Api::<PersistentVolume>::all(client.clone());
        let name = &a.authority.resource_identities.pv.intent.name;
        checked(
            get(&client, pvs.resource_url(), name).await?.is_none(),
            "Generated raw PV exists; metadata reset cannot erase future authority",
        )
    }
}
fn pvc_validate_live(actual: &Value, old: &Value, a: &Loaded) -> Decision<()> {
    pvc(actual, &a.expected_pvc, a.pvc_uid)?;
    let mut actual = actual.clone();
    let mut old = old.clone();
    // The admission oldObject must still be the live original RV. Only fields
    // whose update has no authority (managedFields) may change independently.
    for v in [&mut actual, &mut old] {
        if let Some(m) = v["metadata"].as_object_mut() {
            m.remove("managedFields");
        }
    }
    checked(
        actual == old,
        "Live PVC differs from UPDATE oldObject, UID or resource version",
    )
}
fn cloud_binding(a: &Loaded) -> Decision<NodeTopologyCloudBinding> {
    let n = a.authority.node_identity.as_ref().ok_or(Denial {
        code: 403,
        message: "Registered Node identity missing",
    })?;
    let t = a.authority.node_topology.as_ref().ok_or(Denial {
        code: 403,
        message: "Certified Node topology missing",
    })?;
    Ok(NodeTopologyCloudBinding {
        account_id: n.cloud_account_id.clone(),
        region: n.region.clone(),
        instance_id: n.cloud_instance_id.clone(),
        zone_id: t.zone_id.clone(),
        vpc_id: t.describe_instance.vpc_id.clone(),
        vswitch_id: t.describe_instance.vswitch_id.clone(),
        private_ip: n.private_ip.parse().map_err(dependency)?,
        deployment: a.contract.mapping.deployment.clone(),
    })
}
fn live_node(value: &Value, a: &Loaded, b: &NodeTopologyCloudBinding) -> Decision<()> {
    let n = a.authority.node_identity.as_ref().ok_or(Denial {
        code: 403,
        message: "Registered Node identity missing",
    })?;
    checked(
        value["apiVersion"] == "v1"
            && value["kind"] == "Node"
            && value.as_object().is_some_and(|o| {
                o.keys().all(|k| {
                    ["apiVersion", "kind", "metadata", "spec", "status"].contains(&k.as_str())
                })
            }),
        "Node object ABI differs",
    )?;
    metadata(value, &n.node_name, None, n.node_uid)?;
    let node: Node = serde_json::from_value(value.clone()).map_err(dependency)?;
    checked(
        crate::backup_host::node_binding(&node, n.cluster_epoch).map_err(observation)?
            == n.binding(),
        "Live Node differs from registered boot or runtime profile",
    )?;
    let labels = node.metadata.labels.as_ref().ok_or(Denial {
        code: 403,
        message: "Node topology labels missing",
    })?;
    for (k, v) in CSI_KEYS.iter().zip([
        b.instance_id.as_str(),
        b.zone_id.as_str(),
        b.region.as_str(),
        b.zone_id.as_str(),
    ]) {
        checked(
            labels.get(*k).map(String::as_str) == Some(v),
            "Live Node topology differs from installation receipt",
        )?;
    }
    let status = node.status.as_ref().ok_or(Denial {
        code: 403,
        message: "Node status missing",
    })?;
    let info = status.node_info.as_ref().ok_or(Denial {
        code: 403,
        message: "Node operating system identity missing",
    })?;
    checked(
        info.operating_system == "linux"
            && info.architecture == "amd64"
            && status
                .conditions
                .as_ref()
                .is_some_and(|v| v.iter().filter(|c| c.type_ == "Ready").count() == 1)
            && status.addresses.as_ref().is_some_and(|v| {
                v.iter().filter(|x| x.type_ == "InternalIP").count() == 1
                    && v.iter()
                        .any(|x| x.type_ == "InternalIP" && x.address == b.private_ip.to_string())
            }),
        "Node OS or exact private address differs",
    )
}
fn live_csi(value: &Value, a: &Loaded, b: &NodeTopologyCloudBinding) -> Decision<()> {
    let n = a.authority.node_identity.as_ref().ok_or(Denial {
        code: 403,
        message: "Registered Node identity missing",
    })?;
    let t = a.authority.node_topology.as_ref().ok_or(Denial {
        code: 403,
        message: "Certified Node topology missing",
    })?;
    checked(
        exact(value, &["apiVersion", "kind", "metadata", "spec"])
            && value["apiVersion"] == "storage.k8s.io/v1"
            && value["kind"] == "CSINode"
            && exact(&value["spec"], &["drivers"]),
        "CSINode ABI differs",
    )?;
    metadata(value, &n.node_name, None, t.csi_registration.csi_node_uid)?;
    let csi: CSINode = serde_json::from_value(value.clone()).map_err(dependency)?;
    let owners = csi.metadata.owner_references.as_deref().unwrap_or_default();
    checked(
        owners.len() == 1
            && owners[0].api_version == "v1"
            && owners[0].kind == "Node"
            && owners[0].name == n.node_name
            && owners[0].uid == n.node_uid.to_string(),
        "CSINode must have the exact sole registered Node owner",
    )?;
    let raw_owners = value
        .pointer("/metadata/ownerReferences")
        .and_then(Value::as_array)
        .ok_or(Denial {
            code: 403,
            message: "CSINode owner metadata missing",
        })?;
    checked(
        raw_owners.len() == 1
            && raw_owners[0].as_object().is_some_and(|o| {
                o.keys().all(|k| {
                    [
                        "apiVersion",
                        "kind",
                        "name",
                        "uid",
                        "controller",
                        "blockOwnerDeletion",
                    ]
                    .contains(&k.as_str())
                }) && o.get("controller").is_none_or(Value::is_boolean)
                    && o.get("blockOwnerDeletion").is_none_or(Value::is_boolean)
            }),
        "CSINode owner metadata has unknown fields",
    )?;
    let drivers = &csi.spec.drivers;
    let mut names = BTreeSet::new();
    checked(
        drivers.len() <= 64 && drivers.iter().all(|d| names.insert(d.name.as_str())),
        "CSI driver registration duplicated",
    )?;
    let drivers = drivers
        .iter()
        .filter(|d| d.name == DRIVER)
        .collect::<Vec<_>>();
    checked(
        drivers.len() == 1,
        "Reviewed disk CSI registration missing or duplicated",
    )?;
    let d = drivers[0];
    let mut keys = d.topology_keys.clone().unwrap_or_default();
    keys.sort();
    checked(
        d.node_id == b.instance_id && keys == CSI_KEYS.map(str::to_owned),
        "CSI registration identity or exact topology keys differ",
    )?;
    // Typed Kubernetes DTOs ignore unknown root driver fields; check the actual
    // JSON as well, keeping only the documented registration fields.
    for driver in value["spec"]["drivers"].as_array().ok_or(Denial {
        code: 403,
        message: "CSI driver array malformed",
    })? {
        let object = driver.as_object().ok_or(Denial {
            code: 403,
            message: "CSI driver entry malformed",
        })?;
        checked(
            object
                .keys()
                .all(|k| ["name", "nodeID", "topologyKeys", "allocatable"].contains(&k.as_str()))
                && object
                    .get("allocatable")
                    .is_none_or(|v| exact(v, &["count"]) && v["count"].as_u64().is_some()),
            "CSI registration has unknown or malformed driver fields",
        )?;
    }
    Ok(())
}
struct NodeObservation {
    node: Value,
    csi: Value,
}
impl RestoreAdmissionService {
    async fn node_observation(
        &self,
        a: &Loaded,
        b: &NodeTopologyCloudBinding,
    ) -> Decision<NodeObservation> {
        let n = a.authority.node_identity.as_ref().ok_or(Denial {
            code: 403,
            message: "Registered Node identity missing",
        })?;
        let client = self.runtime.runtime().client_clone();
        let nodes = Api::<Node>::all(client.clone());
        let node = required(get(&client, nodes.resource_url(), &n.node_name).await?)?;
        live_node(&node, a, b)?;
        let csis = Api::<CSINode>::all(client.clone());
        let csi = required(get(&client, csis.resource_url(), &n.node_name).await?)?;
        live_csi(&csi, a, b)?;
        Ok(NodeObservation { node, csi })
    }
    pub(super) async fn decide_raw_scheduling(&self, r: &AdmissionRequest) -> Decision<()> {
        let started = Instant::now();
        let deadline = started.checked_add(TOTAL).ok_or(Denial {
            code: 403,
            message: "Raw scheduling deadline overflow",
        })?;
        // Existing apiserver/service four/five-second budgets remain authoritative.
        // This cap only bounds this private path if called directly by a worker/test.
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            Box::pin(self.raw_scheduling_inner(r, started)),
        )
        .await
        .map_err(|_| Denial {
            code: 403,
            message: "Raw scheduling original decision budget expired",
        })?
    }
    async fn raw_scheduling_inner(&self, r: &AdmissionRequest, started: Instant) -> Decision<()> {
        checked(
            r.resource.group.is_empty()
                && r.resource.version == "v1"
                && r.resource.resource == "persistentvolumeclaims"
                && r.operation == "UPDATE"
                && r.namespace == NAMESPACE
                && r.sub_resource.is_empty()
                && !r.dry_run
                && canonical_uuid(&r.uid),
            "Only real raw PVC metadata UPDATE is implemented",
        )?;
        let runtime = self.raw_scheduling.as_ref().ok_or(Denial {
            code: 403,
            message: "Raw scheduling runtime is not configured",
        })?;
        let kind = classify(self, runtime, r)?;
        options(r)?;
        let old = r.old_object.as_ref().ok_or(Denial {
            code: 403,
            message: "Raw scheduling oldObject required",
        })?;
        let new = r.object.as_ref().ok_or(Denial {
            code: 403,
            message: "Raw scheduling new object required",
        })?;
        let tenant = selector(old, "/metadata/labels/sandbox.platform~1tenant-id")?;
        let restore = selector(old, "/metadata/labels/sandbox.platform~1restore-id")?;
        checked(
            r.name == block_pvc_name(restore)
                && selector(new, "/metadata/labels/sandbox.platform~1tenant-id")? == tenant
                && selector(new, "/metadata/labels/sandbox.platform~1restore-id")? == restore,
            "Raw scheduling request scope differs",
        )?;
        let target = target_hint(kind, old, new)?;
        let reading = Instant::now();
        let mut tx = self.database.begin(tenant).await.map_err(dependency)?;
        let a = self
            .load_raw_scheduling(&mut tx, tenant, restore, kind, target.as_deref(), reading)
            .await?;
        checked(
            delta(kind, old, new, &a)? == target,
            "Scheduling delta differs from located current node",
        )?;
        check_budget(started, &a, None)?;
        tx.commit().await.map_err(dependency)?;
        check_budget(started, &a, None)?;
        self.runtime
            .verify_network(&a.authority.cloud_settings)
            .await
            .map_err(observation)?;
        self.runtime
            .verify_profile_secrets(&a.authority.cloud_settings)
            .await
            .map_err(observation)?;
        for purpose in [
            RestoreStoragePurpose::Normal,
            RestoreStoragePurpose::Raw,
            RestoreStoragePurpose::Delivery,
        ] {
            self.runtime
                .verify_restore_storage_class(&a.contract, purpose)
                .await
                .map_err(observation)?;
        }
        self.runtime
            .verify_restore_snapshot_class(&a.contract)
            .await
            .map_err(observation)?;
        check_budget(started, &a, None)?;
        let first = self.workload_observation(&a, old).await?;
        check_budget(started, &a, None)?;
        let node = if kind == Mutation::Reset {
            self.generated_pv_absent(&a).await?;
            None
        } else {
            let binding = cloud_binding(&a)?;
            let cloud = runtime
                .cloud_clients
                .get(&binding.instance_id)
                .ok_or(Denial {
                    code: 403,
                    message: "No exact reviewed admission cloud client for registered Node",
                })?;
            checked(
                cloud.binding() == &binding
                    && cloud.identity_matches(
                        &a.authority.cloud_settings.issuer,
                        &a.authority.cloud_settings.oidc_provider_arn,
                    ),
                "Independent admission cloud role binding differs from current node authority",
            )?;
            let actual = self.node_observation(&a, &binding).await?;
            let cloud_start = Utc::now();
            let observed = cloud.observe().await.map_err(|e| match e.code {
                CloudErrorCode::IdentityMismatch
                | CloudErrorCode::CredentialIdentityMismatch
                | CloudErrorCode::UnknownInstance
                | CloudErrorCode::InvalidState
                | CloudErrorCode::ObservationStale
                | CloudErrorCode::MalformedResponse
                | CloudErrorCode::Configuration => Denial {
                    code: 403,
                    message: "Fresh admission cloud identity differs",
                },
                _ => dependency(e),
            })?;
            checked(
                observed.binding() == &binding
                    && observed.observed_at() >= cloud_start
                    && observed.observed_at() <= Utc::now(),
                "Cloud observation is not fresh in this original admission decision",
            )?;
            check_budget(started, &a, None)?;
            Some((binding, actual))
        };
        let second = self.workload_observation(&a, old).await?;
        same_protected(&first.pvc, &second.pvc)?;
        same_protected(&first.config, &second.config)?;
        same_protected(&first.job, &second.job)?;
        same_protected(&first.pod, &second.pod)?;
        if let Some((binding, first)) = node {
            let second = self.node_observation(&a, &binding).await?;
            same_protected(&first.node, &second.node)?;
            same_protected(&first.csi, &second.csi)?;
        } else {
            self.generated_pv_absent(&a).await?;
        }
        check_budget(started, &a, None)?;
        let reading = Instant::now();
        let mut tx = self.database.begin(tenant).await.map_err(dependency)?;
        let current = self
            .load_raw_scheduling(&mut tx, tenant, restore, kind, target.as_deref(), reading)
            .await?;
        checked(
            current.pin == a.pin,
            "Scheduling authority, operation claim or enrolled node changed during observation",
        )?;
        checked(
            delta(kind, old, new, &current)? == target,
            "Scheduling body changed against final durable authority",
        )?;
        check_budget(started, &a, Some(&current))?;
        tx.commit().await.map_err(dependency)?;
        // Both SQL readers, every observation and the final acknowledgement share
        // the original first horizon. No retry can mint a new deadline or actor.
        check_budget(started, &a, Some(&current))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    fn pending() -> (Value, Value, Uuid) {
        let fixed: Value = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/restore/storage-canonical.json"
        ))
        .unwrap();
        let contract = RestoreStorageContract::parse(&fixed["contract"]).unwrap();
        let restore = Uuid::from_u128(3);
        let uid = Uuid::from_u128(9);
        let context = RestoreStorageContext {
            tenant_id: Uuid::from_u128(1),
            source_backup_id: Uuid::from_u128(2),
            restore_id: restore,
            target_project_id: Uuid::from_u128(4),
            instance_id: Uuid::from_u128(5),
            workspace_id: Uuid::from_u128(6),
            cluster_epoch: contract.cluster_epoch,
            target_namespace: "sandbox-tenant-test".into(),
            storage_contract: contract,
            size_bytes: 20 * 1024 * 1024 * 1024,
        };
        let expected = context.block_pvc().unwrap();
        let mut old = expected.clone();
        old["metadata"]["uid"] = json!(uid);
        old["metadata"]["resourceVersion"] = json!("21");
        old["metadata"]["creationTimestamp"] = json!("2026-10-08T00:00:00Z");
        old["metadata"]["finalizers"] = json!(["kubernetes.io/pvc-protection"]);
        old["status"] = json!({"phase":"Pending"});
        (expected, old, uid)
    }
    #[test]
    fn fixed_annotation_deltas_never_remap_or_grant_other_purpose() {
        let (expected, old, uid) = pending();
        let mut selected = old.clone();
        selected["metadata"]["annotations"] = json!({SELECTED:"kata-node-a"});
        assert_eq!(
            body_delta(Mutation::Select, &old, &selected, &expected, uid).unwrap(),
            Some("kata-node-a".into())
        );
        assert!(body_delta(Mutation::Select, &selected, &selected, &expected, uid).is_ok());
        let mut remapped = selected.clone();
        remapped["metadata"]["annotations"][SELECTED] = json!("kata-node-b");
        assert!(body_delta(Mutation::Select, &selected, &remapped, &expected, uid).is_err());
        let mut pair = selected.clone();
        pair["metadata"]["annotations"][STABLE] = json!(DRIVER);
        pair["metadata"]["annotations"][BETA] = json!(DRIVER);
        assert!(body_delta(Mutation::Provisioner, &selected, &pair, &expected, uid).is_ok());
        assert!(body_delta(Mutation::Provisioner, &pair, &pair, &expected, uid).is_ok());
        assert!(body_delta(Mutation::Select, &selected, &pair, &expected, uid).is_err());
        assert!(body_delta(Mutation::Provisioner, &old, &pair, &expected, uid).is_err());
        assert!(body_delta(Mutation::Provisioner, &pair, &selected, &expected, uid).is_err());
        let mut reset = pair.clone();
        reset["metadata"]["annotations"]
            .as_object_mut()
            .unwrap()
            .remove(SELECTED);
        assert!(body_delta(Mutation::Reset, &pair, &reset, &expected, uid).is_ok());
        assert!(body_delta(Mutation::Reset, &reset, &reset, &expected, uid).is_ok());
        assert!(body_delta(Mutation::Reset, &selected, &reset, &expected, uid).is_err());
        assert!(body_delta(Mutation::Select, &selected, &old, &expected, uid).is_err());
        for key in [STABLE, BETA] {
            let mut half = pair.clone();
            half["metadata"]["annotations"]
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(annotations(&half).is_err());
        }
    }
    #[test]
    fn raw_update_keeps_exact_protected_metadata_and_block_spec() {
        let (expected, old, uid) = pending();
        let mut selected = old.clone();
        selected["metadata"]["annotations"] = json!({SELECTED:"kata-node-a"});
        selected["metadata"]["managedFields"] = json!([{"manager":"kube-scheduler","operation":"Update","fieldsType":"FieldsV1","fieldsV1":{}}]);
        assert!(body_delta(Mutation::Select, &old, &selected, &expected, uid).is_ok());
        for (path, value) in [
            ("/metadata/resourceVersion", json!("22")),
            ("/metadata/uid", json!(Uuid::from_u128(10))),
            ("/metadata/finalizers", json!(["foreign/finalizer"])),
            ("/metadata/creationTimestamp", json!("2026-10-08T00:00:01Z")),
            ("/status/phase", json!("Bound")),
            ("/spec/volumeMode", json!("Filesystem")),
        ] {
            let mut changed = selected.clone();
            *changed.pointer_mut(path).unwrap() = value;
            assert!(
                body_delta(Mutation::Select, &old, &changed, &expected, uid).is_err(),
                "{path}"
            );
        }
        for (key, value) in [
            ("unknown", json!({"permission":true})),
            ("deletionTimestamp", json!("2026-10-08T00:00:01Z")),
            ("ownerReferences", json!([{"uid":Uuid::from_u128(10)}])),
        ] {
            let mut changed = selected.clone();
            changed["metadata"][key] = value;
            assert!(
                body_delta(Mutation::Select, &old, &changed, &expected, uid).is_err(),
                "{key}"
            );
        }
        for key in [
            "volumeName",
            "volumeAttributesClassName",
            "dataSource",
            "dataSourceRef",
        ] {
            let mut changed = selected.clone();
            changed["spec"][key] = json!("unreviewed");
            assert!(
                body_delta(Mutation::Select, &old, &changed, &expected, uid).is_err(),
                "{key}"
            );
        }
        let mut unknown = selected.clone();
        unknown["metadata"]["annotations"]["unknown/permission"] = json!("true");
        assert!(annotations(&unknown).is_err());
        let mut wrong = selected.clone();
        wrong["metadata"]["annotations"][STABLE] = json!("another.csi.driver");
        wrong["metadata"]["annotations"][BETA] = json!("another.csi.driver");
        assert!(annotations(&wrong).is_err());
    }
    fn source_storage_values() -> Value {
        let source = crate::backup_runtime::BackupSource {
            tenant_id: Uuid::from_u128(1),
            project_id: Uuid::from_u128(2),
            workspace_id: Uuid::from_u128(3),
            backup_id: Uuid::from_u128(4),
            cluster_epoch: Uuid::from_u128(5),
            namespace: "source-ns".into(),
            pvc_name: format!("ws-{}", Uuid::from_u128(3)),
            pvc_uid: Uuid::from_u128(6),
            pv_name: "source-pv".into(),
            pv_uid: Uuid::from_u128(7),
            cloud_disk: "d-source1".into(),
            storage_class: "source-class".into(),
            snapshot_class: "source-snapshot".into(),
            size_bytes: 20 * 1024 * 1024 * 1024,
        };
        json!({"source":source,"capture_attempt_id":Uuid::from_u128(8),
            "clone_receipt":{"attempt_id":Uuid::from_u128(8),"tenant_id":source.tenant_id,"backup_id":source.backup_id,
            "pvc_uid":Uuid::from_u128(9),"pv_uid":Uuid::from_u128(10),"pv_name":"clone-pv","cloud_disk":"d-clone1",
            "size_bytes":source.size_bytes,"recorded_at":"2026-10-09T00:00:00.000001+00:00"}})
    }
    #[test]
    fn bound_source_storage_strict_shapes_and_nonreused_ids() {
        // Ordinary parser comparison values only; this does not create Loaded,
        // RawBoundRead, a scope, signed cloud observation or any database proof.
        let valid = source_storage_values();
        assert!(BoundSourceStorage::parse(&valid).is_ok());
        for key in ["source", "capture_attempt_id", "clone_receipt"] {
            let mut v = valid.clone();
            v.as_object_mut().unwrap().remove(key);
            assert!(BoundSourceStorage::parse(&v).is_err(), "missing {key}");
        }
        for key in ["", "source", "clone_receipt"] {
            let mut v = valid.clone();
            if key.is_empty() {
                v["unknown"] = json!(true);
            } else {
                v[key]["unknown"] = json!(true);
            }
            assert!(BoundSourceStorage::parse(&v).is_err(), "unknown {key}");
        }
        for (path, value) in [
            ("/source/size_bytes", json!(21474836480.0)),
            ("/clone_receipt/size_bytes", json!(true)),
            ("/capture_attempt_id", json!(Uuid::nil())),
            ("/clone_receipt/attempt_id", json!(Uuid::from_u128(11))),
            ("/clone_receipt/tenant_id", json!(Uuid::from_u128(11))),
            ("/clone_receipt/backup_id", json!(Uuid::from_u128(11))),
            ("/clone_receipt/pvc_uid", valid["source"]["pvc_uid"].clone()),
            ("/clone_receipt/pv_uid", valid["source"]["pv_uid"].clone()),
            (
                "/clone_receipt/pv_uid",
                valid["clone_receipt"]["pvc_uid"].clone(),
            ),
            ("/clone_receipt/pv_name", valid["source"]["pv_name"].clone()),
            (
                "/clone_receipt/cloud_disk",
                valid["source"]["cloud_disk"].clone(),
            ),
            (
                "/clone_receipt/cloud_disk",
                json!(format!("d-{}", "a".repeat(127))),
            ),
            ("/source/pvc_name", json!("another-pvc")),
            ("/clone_receipt/size_bytes", json!(512)),
            ("/clone_receipt/recorded_at", json!("2026-10-09T24:00:00Z")),
        ] {
            let mut v = valid.clone();
            *v.pointer_mut(path).unwrap() = value;
            let e = BoundSourceStorage::parse(&v).err().unwrap();
            assert_eq!(e.code, 403, "{path}");
        }
    }
    #[test]
    fn bound_decoder_has_no_thirteen_key_or_unknown_shape_fallback() {
        let mut old = json!({"record":{},"cloud_settings":{},"target_namespace":"target-ns","vault":{},
            "operation_identity":{},"authz_identity":{},"job_context":{},"resource_identities":{},
            "pod_admission":{},"node_identity":{},"node_topology":{},"block_receipt":null,"disk_receipt":null});
        let decode = |pin: Value| {
            decode_raw_bound_base(
                &json!({"pin":pin,"valid_for_us":10_000_000}),
                Uuid::from_u128(1),
                Uuid::from_u128(2),
                "node-a",
                Instant::now(),
            )
        };
        let e = decode(old.clone()).err().unwrap();
        assert_eq!((e.code, e.message), (403, "Bound pin ABI differs"));
        old["unknown_source"] = source_storage_values();
        let e = decode(old.clone()).err().unwrap();
        assert_eq!((e.code, e.message), (403, "Bound source storage missing"));
        old.as_object_mut().unwrap().remove("unknown_source");
        old["source_storage"] = source_storage_values();
        let mut unknown = old.clone();
        unknown["unknown"] = json!(true);
        let e = decode(unknown).err().unwrap();
        assert_eq!((e.code, e.message), (403, "Bound pin ABI differs"));
        old["source_storage"]["clone_receipt"]["unknown"] = json!(true);
        let e = decode(old).err().unwrap();
        assert_eq!(
            (e.code, e.message),
            (403, "Bound source storage ABI differs")
        );
    }
    #[test]
    fn protocol_utc_rejects_leap_seconds_and_out_of_range_time() {
        for value in ["2026-10-08T23:59:59Z", "2026-10-08T23:59:59.000001+00:00"] {
            assert!(utc(&json!(value)).is_ok(), "{value}");
        }
        for value in [
            "2026-10-08T24:00:00Z",
            "2026-10-08T23:60:00Z",
            "2026-10-08T23:59:60Z",
            "2026-10-08T23:59:59.0000001Z",
            "2026-10-08T23:59:59+01:00",
        ] {
            assert!(utc(&json!(value)).is_err(), "{value}");
        }
    }
    #[test]
    fn builtin_controllers_cannot_exchange_scheduling_purpose() {
        let scheduler = ControllerIdentity::ControlPlane {
            username: "system:kube-scheduler".into(),
        };
        let kcm = ControllerIdentity::ControlPlane {
            username: "system:kube-controller-manager".into(),
        };
        assert!(controller_purpose(&scheduler, "system:kube-scheduler"));
        assert!(!controller_purpose(
            &scheduler,
            "system:kube-controller-manager"
        ));
        assert!(controller_purpose(&kcm, "system:kube-controller-manager"));
        assert!(!controller_purpose(&kcm, "system:kube-scheduler"));
        assert!(!controller_purpose(
            &ControllerIdentity::ServiceAccount {
                username: "system:serviceaccount:kube-system:scheduler".into(),
                uid: Uuid::nil().to_string()
            },
            "system:kube-scheduler"
        ));
    }
    #[tokio::test]
    async fn runtime_accepts_only_distinct_exact_csi_and_cloud_inventory() {
        let account = "1234567890123456";
        let config = crate::cloud_fencing::node_topology::NodeTopologyCloudConfig {
            account_id: account.into(),
            region: "cn-hangzhou".into(),
            role_arn: format!("acs:ram::{account}:role/admission-readonly"),
            role_id: "1234567890".into(),
            oidc_provider_arn: format!("acs:ram::{account}:oidc-provider/fixture"),
            oidc_issuer: "https://issuer.fixture.invalid".into(),
            oidc_audience: "sts.aliyuncs.com".into(),
            oidc_subject: "system:serviceaccount:sandbox-system:sandbox-admission".into(),
            oidc_token_file: "/__sandbox_private_topology_unit__/token".into(),
            requests_per_second: 1,
            max_in_flight: 1,
        };
        let binding = NodeTopologyCloudBinding {
            account_id: account.into(),
            region: "cn-hangzhou".into(),
            instance_id: "i-unitnode".into(),
            zone_id: "cn-hangzhou-a".into(),
            vpc_id: "vpc-unit".into(),
            vswitch_id: "vsw-unit".into(),
            private_ip: "10.0.0.5".parse().unwrap(),
            deployment: "sandbox".into(),
        };
        let client = AlibabaCloudAdmissionNodeTopology::for_test(
            config,
            binding,
            "http://127.0.0.1:1234/".parse().unwrap(),
        )
        .unwrap();
        let csi = ServiceIdentity {
            username: "system:serviceaccount:kube-system:sandbox-csi-controller".into(),
            uid: Uuid::from_u128(13).to_string(),
        };
        assert!(RawSchedulingRuntime::new(csi.clone(), vec![client.clone()]).is_ok());
        assert!(RawSchedulingRuntime::new(csi.clone(), vec![]).is_err());
        assert!(
            RawSchedulingRuntime::new(csi.clone(), vec![client.clone(), client.clone()]).is_err()
        );
        assert!(
            RawSchedulingRuntime::new(
                ServiceIdentity {
                    username: "system:serviceaccount:sandbox-system:sandbox-node-topology-owner"
                        .into(),
                    ..csi.clone()
                },
                vec![client.clone()]
            )
            .is_err()
        );
        assert!(
            RawSchedulingRuntime::new(
                ServiceIdentity {
                    uid: Uuid::nil().to_string(),
                    ..csi
                },
                vec![client]
            )
            .is_err()
        );
    }
}
