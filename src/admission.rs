//! Fail-closed validating admission. Only the dedicated mTLS listener may expose
//! this router: AdmissionReview.userInfo is trusted because the caller is an
//! authenticated kube-apiserver, never because the submitted object has labels.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::{get, post},
};
use k8s_openapi::api::core::v1::{Namespace, Node, PersistentVolume, PersistentVolumeClaim, Pod};
use kube::{
    Api, Client,
    core::{ApiResource, DynamicObject, GroupVersionKind},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

use crate::{
    db::{Actor, Database},
    runtime_manifest::{
        RuntimeManifestConfig, RuntimeManifestContext, TERMINATION_FINALIZER, build_manifests,
        container_name, validate_existing_pod, validate_existing_policy, validate_existing_pvc,
    },
};

#[path = "backup_admission_service.rs"]
mod backup_admission_service;
#[path = "backup_job_admission.rs"]
mod backup_job_admission;
#[path = "volume_deletion_admission.rs"]
mod volume_deletion_admission;

const PREFIX: &str = "sandbox.platform/";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceIdentity {
    pub username: String,
    pub uid: String,
}

impl ServiceIdentity {
    fn matches(&self, user: &UserInfo) -> bool {
        self.username == user.username && self.uid == user.uid
    }
    fn valid(&self) -> bool {
        let parts: Vec<_> = self.username.split(':').collect();
        parts.len() == 4
            && parts[0] == "system"
            && parts[1] == "serviceaccount"
            && parts[2..].iter().all(|p| !p.is_empty())
            && Uuid::parse_str(&self.uid).is_ok_and(|uid| !uid.is_nil())
    }
}

/// Certificate principals are restricted to built-in control-plane names.
/// OIDC must use a non-system username prefix; impersonation is privileged.
#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControllerIdentity {
    ServiceAccount { username: String, uid: String },
    ControlPlane { username: String },
}
impl ControllerIdentity {
    pub(crate) fn matches(&self, user: &UserInfo) -> bool {
        match self {
            Self::ServiceAccount { username, uid } => {
                username == &user.username && uid == &user.uid
            }
            Self::ControlPlane { username } => {
                username == &user.username
                    && user.uid.is_empty()
                    && user.groups.len() == 1
                    && user.groups[0] == "system:authenticated"
            }
        }
    }
    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::ServiceAccount { username, uid } => ServiceIdentity {
                username: username.clone(),
                uid: uid.clone(),
            }
            .valid(),
            Self::ControlPlane { username } => matches!(
                username.as_str(),
                "system:kube-scheduler" | "system:kube-controller-manager"
            ),
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionConfig {
    pub worker: ServiceIdentity,
    pub gateway: ServiceIdentity,
    pub termination: ServiceIdentity,
    #[serde(default)]
    pub volume_deleter: Option<ServiceIdentity>,
    #[serde(default)]
    pub backup: Option<crate::backup_admission::BackupAdmissionIdentities>,
    pub namespace_provisioner: ServiceIdentity,
    pub scheduler: ControllerIdentity,
    pub storage_controllers: Vec<ControllerIdentity>,
    pub policy_status_controllers: Vec<ControllerIdentity>,
    pub namespace_status_controllers: Vec<ControllerIdentity>,
    pub pod_garbage_collectors: Vec<ControllerIdentity>,
    pub certification_id: String,
    pub storage_provisioner: String,
    pub dns_namespace: String,
    pub dns_labels: BTreeMap<String, String>,
    pub ephemeral_storage_mib: i64,
    pub tmp_size_mib: i64,
}

impl AdmissionConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.worker.valid()
                && self.gateway.valid()
                && self.termination.valid()
                && self.namespace_provisioner.valid()
                && self.scheduler.valid(),
            "Admission identities must be exact service-account usernames and real non-nil UIDs"
        );
        anyhow::ensure!(
            [&self.worker, &self.gateway, &self.namespace_provisioner]
                .iter()
                .all(|identity| identity.username != self.termination.username
                    && identity.uid != self.termination.uid),
            "Termination must use a dedicated service-account identity"
        );
        if let Some(backup) = &self.backup {
            anyhow::ensure!(
                backup.controller.valid()
                    && backup.job_controller.valid()
                    && backup.controller.username
                        == "system:serviceaccount:sandbox-system:sandbox-backup-controller"
                    && match &backup.job_controller {
                        ControllerIdentity::ServiceAccount { username, uid } =>
                            username != &backup.controller.username && uid != &backup.controller.uid,
                        ControllerIdentity::ControlPlane { username } =>
                            username == "system:kube-controller-manager",
                    },
                "Backup admission requires separate exact controller and Job controller identities"
            );
        }
        if let Some(identity) = &self.volume_deleter {
            anyhow::ensure!(
                identity.valid()
                    && identity.username
                        == "system:serviceaccount:sandbox-system:sandbox-volume-deleter"
                    && [
                        &self.worker,
                        &self.gateway,
                        &self.termination,
                        &self.namespace_provisioner
                    ]
                    .iter()
                    .all(|other| other.username != identity.username && other.uid != identity.uid),
                "Volume deletion requires a distinct exact service-account identity"
            );
        }
        anyhow::ensure!(
            !self.storage_controllers.is_empty()
                && self.storage_controllers.len() <= 16
                && self
                    .storage_controllers
                    .iter()
                    .all(ControllerIdentity::valid),
            "Explicit storage controller service accounts are required"
        );
        anyhow::ensure!(
            !self.pod_garbage_collectors.is_empty()
                && self.pod_garbage_collectors.len() <= 16
                && self
                    .pod_garbage_collectors
                    .iter()
                    .all(ControllerIdentity::valid),
            "Explicit Pod garbage collector identities are required"
        );
        anyhow::ensure!(
            !self.policy_status_controllers.is_empty()
                && self.policy_status_controllers.len() <= 16
                && self
                    .policy_status_controllers
                    .iter()
                    .all(ControllerIdentity::valid),
            "Explicit Cilium status controller identities are required"
        );
        anyhow::ensure!(
            !self.namespace_status_controllers.is_empty()
                && self.namespace_status_controllers.len() <= 16
                && self
                    .namespace_status_controllers
                    .iter()
                    .all(ControllerIdentity::valid),
            "Explicit namespace status controller identities are required"
        );
        anyhow::ensure!(
            !self.certification_id.is_empty()
                && self.certification_id.len() <= 128
                && !self.certification_id.chars().any(char::is_control),
            "A deployment certification reference is required"
        );
        anyhow::ensure!(
            !self.storage_provisioner.is_empty()
                && self.storage_provisioner.len() <= 253
                && !self.storage_provisioner.chars().any(char::is_whitespace),
            "Invalid storage provisioner"
        );
        anyhow::ensure!(
            !self.dns_labels.is_empty()
                && (128..=32768).contains(&self.ephemeral_storage_mib)
                && self.tmp_size_mib > 0
                && self.tmp_size_mib <= self.ephemeral_storage_mib - 64,
            "Invalid runtime limits or DNS selector"
        );
        Ok(())
    }
    pub fn runtime(&self) -> RuntimeManifestConfig {
        RuntimeManifestConfig {
            runtime_class_name: "kata-qemu".into(),
            dns_namespace: self.dns_namespace.clone(),
            dns_labels: self.dns_labels.clone(),
            ephemeral_storage_mib: self.ephemeral_storage_mib,
            tmp_size_mib: self.tmp_size_mib,
        }
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    pub username: String,
    #[serde(default)]
    pub uid: String,
    #[serde(default)]
    pub groups: Vec<String>,
}
#[derive(Clone, Deserialize)]
pub struct Resource {
    #[serde(default)]
    pub group: String,
    pub version: String,
    pub resource: String,
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionRequest {
    pub uid: String,
    pub resource: Resource,
    pub operation: String,
    #[serde(default)]
    pub sub_resource: String,
    #[serde(default)]
    pub namespace: String,
    pub name: String,
    pub user_info: UserInfo,
    pub object: Option<Value>,
    pub old_object: Option<Value>,
    pub options: Option<Value>,
    #[serde(default)]
    pub dry_run: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionReview {
    pub api_version: String,
    pub kind: String,
    pub request: Option<AdmissionRequest>,
}

#[derive(Debug, Clone, Copy)]
pub struct Denial {
    pub code: u16,
    pub message: &'static str,
}
impl Denial {
    fn policy(message: &'static str) -> Self {
        Self { code: 403, message }
    }
    fn dependency() -> Self {
        Self {
            code: 503,
            message: "Admission dependency unavailable; no workload was authorized",
        }
    }
}
type Decision = Result<(), Denial>;

/// Facts loaded from operator-owned configuration, tenant-scoped SQL and
/// authenticated Kubernetes GET responses. None comes from a client label alone.
pub struct WorkloadAuthority {
    pub context: RuntimeManifestContext,
    pub create_allowed: bool,
    pub stop_allowed: bool,
    /// Fresh challenge and active lease allow this removal; not a client claim.
    pub termination_finalizer_allowed: bool,
    /// Append-only proof still permits completion after its challenge expires.
    pub termination_proven: bool,
    pub pod_uid: Option<String>,
    pub pvc_uid: Option<String>,
    pub policy_uid: Option<String>,
    pub node_binding_valid: bool,
    pub volume_binding_valid: bool,
}

fn checked(condition: bool, message: &'static str) -> Decision {
    if condition {
        Ok(())
    } else {
        Err(Denial::policy(message))
    }
}
fn string<'a>(object: &'a Value, pointer: &str) -> Option<&'a str> {
    object.pointer(pointer).and_then(Value::as_str)
}
fn object(request: &AdmissionRequest) -> Result<&Value, Denial> {
    request
        .object
        .as_ref()
        .or(request.old_object.as_ref())
        .ok_or(Denial::policy("Missing admission object"))
}
fn uid(object: &Value) -> Result<&str, Denial> {
    string(object, "/metadata/uid")
        .filter(|v| !v.is_empty() && v.len() <= 128)
        .ok_or(Denial::policy("Missing authoritative API UID"))
}
fn labels(object: &Value) -> Value {
    object
        .pointer("/metadata/labels")
        .cloned()
        .unwrap_or_else(|| json!({}))
}
fn annotations(object: &Value) -> Value {
    object
        .pointer("/metadata/annotations")
        .cloned()
        .unwrap_or_else(|| json!({}))
}
fn typed<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, Denial> {
    serde_json::from_value(value.clone()).map_err(|_| Denial::policy("Invalid Kubernetes object"))
}

fn identity(request: &AdmissionRequest, current: &Value, recorded: Option<&str>) -> Decision {
    checked(
        string(current, "/metadata/name") == Some(request.name.as_str())
            && string(current, "/metadata/namespace") == Some(request.namespace.as_str()),
        "Request and object identity differ",
    )?;
    let current_uid = uid(current)?;
    if request.operation == "CREATE" {
        // Generic apiserver storage assigns UID before validating admission.
        // The trusted server's new UID is not a license to replace a DB binding.
        checked(
            recorded.is_none() && request.old_object.is_none(),
            "An existing runtime identity cannot be recreated",
        )?;
    } else {
        let old = request
            .old_object
            .as_ref()
            .ok_or(Denial::policy("Old object is required"))?;
        checked(
            uid(old)? == current_uid && recorded.is_none_or(|value| value == current_uid),
            "UID differs from the existing object or recorded binding",
        )?;
        checked(
            labels(old) == labels(current),
            "Runtime identity labels are immutable",
        )?;
    }
    Ok(())
}

fn same_metadata(old: &Value, new: &Value) -> Decision {
    checked(
        labels(old) == labels(new)
            && annotations(old) == annotations(new)
            && old.pointer("/metadata/finalizers") == new.pointer("/metadata/finalizers")
            && old.pointer("/metadata/ownerReferences") == new.pointer("/metadata/ownerReferences"),
        "Status update changed protected metadata",
    )
}

// Kubernetes v1.36 PodGC changes only phase/observedGeneration and optionally
// DisruptionTarget before deleting an orphaned Pod. Never invent readiness.
fn garbage_collection_status(old: &Value, new: &Value) -> Decision {
    let mut before = old.get("status").cloned().unwrap_or_else(|| json!({}));
    let mut after = new.get("status").cloned().unwrap_or_else(|| json!({}));
    checked(
        string(&after, "/phase") == Some("Failed"),
        "PodGC may only mark a proven terminated Pod Failed",
    )?;
    for status in [&mut before, &mut after] {
        let value = status
            .as_object_mut()
            .ok_or(Denial::policy("Invalid PodGC status"))?;
        value.remove("phase");
        value.remove("observedGeneration");
        if let Some(conditions) = value.get_mut("conditions") {
            let values = conditions
                .as_array_mut()
                .ok_or(Denial::policy("Invalid conditions"))?;
            let disruptions: Vec<&Value> = values
                .iter()
                .filter(|condition| string(condition, "/type") == Some("DisruptionTarget"))
                .collect();
            checked(disruptions.len() <= 1, "Duplicate disruption conditions")?;
            values.retain(|condition| string(condition, "/type") != Some("DisruptionTarget"));
            if values.is_empty() {
                value.remove("conditions");
            }
        }
    }
    if let Some(conditions) = new.pointer("/status/conditions").and_then(Value::as_array) {
        for condition in conditions
            .iter()
            .filter(|condition| string(condition, "/type") == Some("DisruptionTarget"))
        {
            let unchanged = old
                .pointer("/status/conditions")
                .and_then(Value::as_array)
                .is_some_and(|values| values.contains(condition));
            checked(
                unchanged
                    || (string(condition, "/status") == Some("True")
                        && string(condition, "/reason") == Some("DeletionByPodGC")),
                "Unexpected PodGC disruption condition",
            )?;
        }
    }
    checked(
        before == after,
        "PodGC cannot change readiness or container status",
    )
}

/// Pure policy checks. The HTTP path must first establish WorkloadAuthority.
pub fn validate_workload(
    request: &AdmissionRequest,
    authority: &WorkloadAuthority,
    config: &AdmissionConfig,
) -> Decision {
    checked(
        matches!(request.operation.as_str(), "CREATE" | "UPDATE" | "DELETE"),
        "Unsupported workload operation",
    )?;
    let current = if request.operation == "DELETE" {
        request
            .old_object
            .as_ref()
            .ok_or(Denial::policy("Delete requires the stored object"))?
    } else {
        object(request)?
    };
    let mut render = authority.context.clone();
    // Revocation must prevent NEW compute, while stopping an existing revoked
    // image must remain possible. Immutable content is still rendered exactly.
    render.template_approved = true;
    render.security_policy_approved = true;
    let expected = build_manifests(&render, &config.runtime())
        .map_err(|_| Denial::policy("Controlled runtime specification is invalid"))?;
    let expected_object = match request.resource.resource.as_str() {
        "pods" => serde_json::to_value(&expected.pod),
        "persistentvolumeclaims" => serde_json::to_value(&expected.pvc),
        "ciliumnetworkpolicies" => serde_json::to_value(&expected.network_policy),
        _ => return Err(Denial::policy("Unsupported protected resource")),
    }
    .map_err(|_| Denial::dependency())?;
    checked(
        labels(current) == labels(&expected_object)
            && current.get("apiVersion") == expected_object.get("apiVersion")
            && current.get("kind") == expected_object.get("kind"),
        "Object kind or identity labels differ from the authoritative manifest",
    )?;
    let worker = config.worker.matches(&request.user_info);
    let termination = config.termination.matches(&request.user_info);
    match (
        request.resource.group.as_str(),
        request.resource.resource.as_str(),
    ) {
        ("", "pods") => {
            checked(request.resource.version == "v1", "Unsupported Pod version")?;
            checked(
                request.sub_resource.is_empty() || request.sub_resource == "status",
                "Pod subresource is prohibited",
            )?;
            identity(request, current, authority.pod_uid.as_deref())?;
            let mut pod: Pod = typed(current)?;
            let deleting = pod.metadata.deletion_timestamp.is_some();
            pod.metadata.deletion_timestamp = None;
            let protected =
                current.pointer("/metadata/finalizers") == Some(&json!([TERMINATION_FINALIZER]));
            let unprotected = current
                .pointer("/metadata/finalizers")
                .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty));
            // The immutable runtime verifier expects the original finalizer.
            // Normalize it only AFTER verifying durable termination evidence.
            if !protected {
                checked(
                    unprotected && authority.termination_proven && deleting,
                    "Unprotected Pod requires a recorded exact termination proof",
                )?;
                pod.metadata.finalizers = Some(vec![TERMINATION_FINALIZER.into()]);
            }
            validate_existing_pod(&pod, &expected.pod, authority.pod_uid.as_deref())
                .map_err(|_| Denial::policy("Pod differs from the controlled Kata workload"))?;
            if request.operation == "CREATE" {
                checked(
                    worker && authority.create_allowed && protected,
                    "Only an authorized current worker create/start may create a Pod",
                )?;
                checked(
                    current.pointer("/spec/nodeName").is_none(),
                    "A worker must not bypass scheduling with nodeName",
                )?;
            } else if request.operation == "DELETE" {
                let collected = unprotected
                    && authority.termination_proven
                    && config
                        .pod_garbage_collectors
                        .iter()
                        .any(|id| id.matches(&request.user_info));
                checked(
                    ((worker || termination) && authority.stop_allowed)
                        || (termination && authority.termination_proven && unprotected)
                        || collected,
                    "Pod deletion requires an accepted stop/delete/restart",
                )?;
                let options = request
                    .options
                    .as_ref()
                    .ok_or(Denial::policy("Deletion preconditions are required"))?;
                checked(
                    (collected
                        && options.get("gracePeriodSeconds") == Some(&json!(0))
                        && string(options, "/preconditions/uid")
                            .is_none_or(|value| Some(value) == string(current, "/metadata/uid")))
                        || (string(options, "/preconditions/uid") == Some(uid(current)?)
                            && string(options, "/preconditions/resourceVersion")
                                == string(current, "/metadata/resourceVersion")
                            && string(current, "/metadata/resourceVersion").is_some()
                            && options.get("gracePeriodSeconds") == Some(&json!(30))),
                    "Deletion requires exact UID/resourceVersion and normal grace",
                )?;
            } else {
                let old = request
                    .old_object
                    .as_ref()
                    .ok_or(Denial::policy("Old Pod required"))?;
                let removing = old.pointer("/metadata/finalizers")
                    == Some(&json!([TERMINATION_FINALIZER]))
                    && unprotected;
                if removing {
                    checked(
                        termination
                            && authority.stop_allowed
                            && authority.termination_finalizer_allowed
                            && request.sub_resource.is_empty()
                            && old.get("status") == current.get("status")
                            && string(old, "/metadata/deletionTimestamp").is_some()
                            && old.pointer("/metadata/deletionTimestamp")
                                == current.pointer("/metadata/deletionTimestamp"),
                        "Finalizer removal requires the dedicated termination controller and fresh proof",
                    )?;
                    let mut protected_current = current.clone();
                    protected_current["metadata"]["finalizers"] = json!([TERMINATION_FINALIZER]);
                    same_metadata(old, &protected_current)?;
                } else {
                    same_metadata(old, current)?;
                }
                checked(
                    old.get("spec") == current.get("spec"),
                    "Pod specification is immutable",
                )?;
                if request.sub_resource == "status" {
                    if config.scheduler.matches(&request.user_info) {
                        scheduler_status(old, current)?;
                    } else if unprotected
                        && authority.termination_proven
                        && config
                            .pod_garbage_collectors
                            .iter()
                            .any(|id| id.matches(&request.user_info))
                    {
                        garbage_collection_status(old, current)?;
                    } else {
                        let node = string(old, "/spec/nodeName")
                            .ok_or(Denial::policy("Unscheduled Pod status is not trusted"))?;
                        checked(
                            request.user_info.username == format!("system:node:{node}")
                                && request.user_info.groups.iter().any(|g| g == "system:nodes")
                                && authority.node_binding_valid,
                            "Only the authenticated assigned node may update Pod status",
                        )?;
                    }
                } else {
                    checked(
                        (worker || (termination && authority.termination_proven))
                            && old.get("status") == current.get("status"),
                        "Only a worker may perform a no-op Pod metadata update",
                    )?;
                }
            }
        }
        ("", "persistentvolumeclaims") => {
            checked(
                request.resource.version == "v1"
                    && (request.sub_resource.is_empty() || request.sub_resource == "status"),
                "Unsupported PVC subresource",
            )?;
            checked(
                request.operation != "DELETE",
                "Workspace deletion needs a separate verified reclamation workflow",
            )?;
            identity(request, current, authority.pvc_uid.as_deref())?;
            let pvc: PersistentVolumeClaim = typed(current)?;
            validate_existing_pvc(&pvc, &expected.pvc, authority.pvc_uid.as_deref())
                .map_err(|_| Denial::policy("PVC differs from the approved workspace"))?;
            let metadata = &pvc.metadata;
            checked(
                metadata.finalizers.as_ref().is_none_or(|values| {
                    values.iter().all(|v| v == "kubernetes.io/pvc-protection")
                }),
                "Unexpected PVC finalizer",
            )?;
            for (key, value) in metadata.annotations.as_ref().into_iter().flatten() {
                checked(
                    match key.as_str() {
                        "volume.kubernetes.io/storage-provisioner"
                        | "volume.beta.kubernetes.io/storage-provisioner" => {
                            value == &config.storage_provisioner
                        }
                        "pv.kubernetes.io/bind-completed"
                        | "pv.kubernetes.io/bound-by-controller" => value == "yes",
                        "volume.kubernetes.io/selected-node" => authority.node_binding_valid,
                        _ => false,
                    },
                    "Unexpected PVC annotation",
                )?;
            }
            if request.operation == "CREATE" {
                checked(
                    worker
                        && authority.create_allowed
                        && current.pointer("/spec/volumeName").is_none()
                        && annotations(current) == json!({}),
                    "PVC create requires current authorization and dynamic binding",
                )?;
            } else {
                // WaitForFirstConsumer selection is written by the scheduler,
                // not by the CSI provisioner. It may choose only a certified
                // node for a still-authorized unbound claim, never bind a PV.
                if config.scheduler.matches(&request.user_info) {
                    let old = request
                        .old_object
                        .as_ref()
                        .ok_or(Denial::policy("Old PVC required"))?;
                    checked(
                        request.sub_resource.is_empty()
                            && authority.create_allowed
                            && old.pointer("/spec/volumeName").is_none()
                            && current.pointer("/spec/volumeName").is_none()
                            && old.get("spec") == current.get("spec")
                            && old.get("status") == current.get("status")
                            && string(
                                current,
                                "/metadata/annotations/volume.kubernetes.io~1selected-node",
                            )
                            .is_some()
                            && authority.node_binding_valid,
                        "Scheduler may only select a certified node for a live unbound workspace",
                    )?;
                    let without_selection = |value: &Value| {
                        let mut value = value.clone();
                        if let Some(fields) = value
                            .pointer_mut("/metadata/annotations")
                            .and_then(Value::as_object_mut)
                        {
                            fields.remove("volume.kubernetes.io/selected-node");
                        }
                        value
                    };
                    same_metadata(&without_selection(old), &without_selection(current))?;
                    return Ok(());
                }
                checked(
                    config
                        .storage_controllers
                        .iter()
                        .any(|p| p.matches(&request.user_info)),
                    "Only registered storage controllers may update a PVC",
                )?;
                let old = request
                    .old_object
                    .as_ref()
                    .ok_or(Denial::policy("Old PVC required"))?;
                let old_volume = string(old, "/spec/volumeName");
                let new_volume = string(current, "/spec/volumeName");
                checked(
                    old_volume.is_none_or(|old| Some(old) == new_volume),
                    "A bound PVC cannot change its volume",
                )?;
                checked(
                    new_volume.is_none() || authority.volume_binding_valid,
                    "PV claimRef does not prove this exact PVC UID binding",
                )?;
                checked(
                    old.pointer("/metadata/finalizers").is_none_or(|value| {
                        value
                            == current
                                .pointer("/metadata/finalizers")
                                .unwrap_or(&Value::Null)
                    }),
                    "PVC protection cannot be removed",
                )?;
                if request.sub_resource == "status" {
                    same_metadata(old, current)?;
                    checked(
                        old.get("spec") == current.get("spec"),
                        "PVC status changed specification",
                    )?;
                }
            }
        }
        ("cilium.io", "ciliumnetworkpolicies") => {
            checked(
                request.resource.version == "v2"
                    && (request.sub_resource.is_empty() || request.sub_resource == "status"),
                "Unsupported network-policy subresource",
            )?;
            checked(
                request.operation != "DELETE",
                "Runtime network protection cannot be removed",
            )?;
            identity(request, current, authority.policy_uid.as_deref())?;
            checked(
                annotations(current) == json!({}),
                "Network-policy annotations are prohibited",
            )?;
            let policy = typed(current)?;
            validate_existing_policy(
                &policy,
                &expected.network_policy,
                authority.policy_uid.as_deref(),
            )
            .map_err(|_| {
                Denial::policy("Network policy differs from the approved deny-all/DNS profile")
            })?;
            if request.operation == "CREATE" {
                checked(
                    worker && authority.create_allowed,
                    "Only an authorized worker may create runtime policy",
                )?;
            } else if request.sub_resource == "status" {
                checked(
                    config
                        .policy_status_controllers
                        .iter()
                        .any(|p| p.matches(&request.user_info)),
                    "Only registered Cilium controllers may report status",
                )?;
                let old = request
                    .old_object
                    .as_ref()
                    .ok_or(Denial::policy("Old policy required"))?;
                same_metadata(old, current)?;
                checked(
                    old.get("spec") == current.get("spec")
                        && old.get("specs") == current.get("specs"),
                    "Status update changed policy rules",
                )?;
            } else {
                checked(worker, "Only the worker may write controlled policy")?;
            }
        }
        _ => {
            return Err(Denial::policy(
                "Resource is not supported in a protected namespace",
            ));
        }
    }
    Ok(())
}

fn scheduler_status(old: &Value, new: &Value) -> Decision {
    let strip = |object: &Value| -> Result<Value, Denial> {
        let mut status = object.get("status").cloned().unwrap_or_else(|| json!({}));
        let fields = status
            .as_object_mut()
            .ok_or(Denial::policy("Invalid Pod status"))?;
        if let Some(conditions) = fields.get_mut("conditions") {
            let conditions = conditions
                .as_array_mut()
                .ok_or(Denial::policy("Invalid Pod conditions"))?;
            conditions.retain(|c| string(c, "/type") != Some("PodScheduled"));
            if conditions.is_empty() {
                fields.remove("conditions");
            }
        }
        fields.remove("nominatedNodeName");
        Ok(status)
    };
    checked(
        strip(old)? == strip(new)?,
        "Scheduler may only report scheduling conditions",
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExecOptions {
    api_version: String,
    kind: String,
    container: String,
    command: Vec<String>,
    #[serde(default)]
    stdin: bool,
    #[serde(default)]
    stdout: bool,
    #[serde(default)]
    stderr: bool,
    #[serde(default)]
    tty: bool,
}

/// The only permitted exec protocol. UUID arguments carry binding, never user
/// argv/environment. The database gate consumes the independently assigned
/// AdmissionReview UID before this connection can be authorized.
pub fn execution_connect_identity(
    request: &AdmissionRequest,
    config: &AdmissionConfig,
) -> Result<(Uuid, Uuid), Denial> {
    let (kind, resource, attempt) = runner_connect_identity(request, config)?;
    checked(
        kind == RunnerConnection::Execution,
        "Expected execution protocol",
    )?;
    Ok((resource, attempt))
}

pub fn file_transfer_connect_identity(
    request: &AdmissionRequest,
    config: &AdmissionConfig,
) -> Result<(Uuid, Uuid), Denial> {
    let (kind, resource, attempt) = runner_connect_identity(request, config)?;
    checked(
        kind == RunnerConnection::FileTransfer,
        "Expected file transfer protocol",
    )?;
    Ok((resource, attempt))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RunnerConnection {
    Execution,
    FileTransfer,
}

fn runner_connect_identity(
    request: &AdmissionRequest,
    config: &AdmissionConfig,
) -> Result<(RunnerConnection, Uuid, Uuid), Denial> {
    checked(
        request.operation == "CONNECT"
            && request.resource.group.is_empty()
            && request.resource.version == "v1"
            && request.resource.resource == "pods"
            && request.sub_resource == "exec"
            && !request.dry_run
            && config.gateway.matches(&request.user_info),
        "Only the exact gateway may request a real execution connection",
    )?;
    let options: ExecOptions = typed(object(request)?)?;
    checked(
        options.api_version == "v1"
            && options.kind == "PodExecOptions"
            && options.stdin
            && options.stdout
            && options.stderr
            && !options.tty
            && options.command.len() == 6
            && options.command[0] == "/usr/local/bin/sandbox-runner"
            && ((options.command[1] == "exec" && options.command[2] == "--execution-id")
                || (options.command[1] == "file-transfer"
                    && options.command[2] == "--transfer-id"))
            && options.command[4] == "--dispatch-attempt-id",
        "Only the fixed non-TTY runner protocol is permitted",
    )?;
    let execution = Uuid::parse_str(&options.command[3])
        .map_err(|_| Denial::policy("Invalid execution identity"))?;
    let attempt = Uuid::parse_str(&options.command[5])
        .map_err(|_| Denial::policy("Invalid dispatch identity"))?;
    checked(
        !execution.is_nil()
            && !attempt.is_nil()
            && options.command[3] == execution.to_string()
            && options.command[5] == attempt.to_string(),
        "Canonical non-nil execution identities are required",
    )?;
    let kind = if options.command[1] == "exec" {
        RunnerConnection::Execution
    } else {
        RunnerConnection::FileTransfer
    };
    Ok((kind, execution, attempt))
}

pub struct AdmissionService {
    pub database: Database,
    pub kubernetes: Client,
    pub config: AdmissionConfig,
}

impl AdmissionService {
    pub async fn decide(&self, request: &AdmissionRequest) -> Decision {
        if request.resource.group.is_empty() && request.resource.resource == "namespaces" {
            return self.namespace(request).await;
        }
        if let Some(result) = self.backup_key_secret(request).await {
            return result;
        }
        if let Some(result) = self.backup_resource(request).await {
            return result;
        }
        if request.resource.group.is_empty() && request.resource.resource == "persistentvolumes" {
            return self.persistent_volume(request).await;
        }
        checked(
            !request.namespace.is_empty(),
            "Namespaced resource required",
        )?;
        let namespaces: Api<Namespace> = Api::all(self.kubernetes.clone());
        let namespace = namespaces
            .get(&request.namespace)
            .await
            .map_err(|_| Denial::dependency())?;
        let value = serde_json::to_value(namespace).map_err(|_| Denial::dependency())?;
        if string(&value, "/metadata/labels/sandbox.platform~1managed") != Some("true") {
            let candidate = object(request)?;
            let reserved = labels(candidate)
                .as_object()
                .is_some_and(|values| values.keys().any(|k| k.starts_with(PREFIX)))
                || request.name.starts_with("sbx-ws-")
                || request.name.starts_with("ws-")
                || request.name.starts_with("net-ws-")
                || candidate
                    .pointer("/spec/volumes")
                    .and_then(Value::as_array)
                    .is_some_and(|volumes| {
                        volumes.iter().any(|volume| {
                            string(volume, "/persistentVolumeClaim/claimName")
                                .is_some_and(|name| name.starts_with("ws-"))
                        })
                    });
            return checked(
                !reserved,
                "Sandbox resources require a registered protected namespace",
            );
        }
        checked(
            string(
                &value,
                "/metadata/annotations/sandbox.platform~1certification-id",
            ) == Some(self.config.certification_id.as_str()),
            "Namespace certification reference is not configured for this deployment",
        )?;
        let (tenant, project) = scope(&value)?;
        self.project(tenant, project, &request.namespace).await?;
        if request.resource.group == "networking.k8s.io"
            && request.resource.resource == "networkpolicies"
        {
            return self.baseline(request);
        }
        if request.resource.resource == "pods" && request.sub_resource == "exec" {
            return self
                .connect_execution(
                    request,
                    tenant,
                    project,
                    string(&value, "/metadata/labels/sandbox.platform~1cluster-epoch")
                        .unwrap_or(""),
                )
                .await;
        }
        if request.resource.resource == "pods" && request.sub_resource == "binding" {
            return self
                .binding(
                    request,
                    tenant,
                    project,
                    string(&value, "/metadata/labels/sandbox.platform~1cluster-epoch")
                        .unwrap_or(""),
                )
                .await;
        }
        if request.resource.resource == "persistentvolumeclaims"
            && self.deleted_workspace_pvc(request, tenant, project).await?
        {
            return Ok(());
        }
        let candidate = object(request)?;
        let instance = string(candidate, "/metadata/labels/sandbox.platform~1instance-id")
            .and_then(|v| Uuid::parse_str(v).ok())
            .ok_or(Denial::policy("Runtime instance binding is required"))?;
        let mut authority = self
            .authority(tenant, project, instance, &request.namespace)
            .await?;
        checked(
            string(&value, "/metadata/labels/sandbox.platform~1cluster-epoch")
                == Some(authority.context.cluster_epoch.to_string().as_str()),
            "Namespace epoch differs from the runtime binding",
        )?;
        if request.resource.resource == "pods" && request.operation != "CREATE" {
            self.termination_evidence(&mut authority, candidate).await?;
        }
        // Deleting a Pod must remain possible when its node is unavailable or
        // drained. Only scheduling/status and newly selected CSI nodes need a
        // node observation; deletion relies on the API server's stored UID/spec.
        if request.resource.resource == "pods"
            && request.sub_resource == "status"
            && !(authority.termination_proven
                && self
                    .config
                    .pod_garbage_collectors
                    .iter()
                    .any(|id| id.matches(&request.user_info)))
        {
            if let Some(node) = string(candidate, "/spec/nodeName") {
                authority.node_binding_valid = self.node(node, false).await?;
            }
        } else if request.resource.resource == "persistentvolumeclaims"
            && request.operation == "UPDATE"
            && let Some(node) = string(
                candidate,
                "/metadata/annotations/volume.kubernetes.io~1selected-node",
            )
        {
            let previous = request.old_object.as_ref().and_then(|old| {
                string(
                    old,
                    "/metadata/annotations/volume.kubernetes.io~1selected-node",
                )
            });
            authority.node_binding_valid = previous == Some(node) || self.node(node, true).await?;
        }
        if request.resource.resource == "persistentvolumeclaims"
            && let Some(volume) = string(candidate, "/spec/volumeName")
        {
            let volumes: Api<PersistentVolume> = Api::all(self.kubernetes.clone());
            let volume = volumes
                .get(volume)
                .await
                .map_err(|_| Denial::dependency())?;
            authority.volume_binding_valid = volume.spec.is_some_and(|spec| {
                spec.storage_class_name.as_deref() == Some(authority.context.storage_class.as_str())
                    && spec.claim_ref.is_some_and(|claim| {
                        claim.uid.as_deref() == uid(candidate).ok()
                            && claim.name.as_deref() == Some(request.name.as_str())
                            && claim.namespace.as_deref() == Some(request.namespace.as_str())
                    })
            });
        }
        if authority.context.workspace_snapshot.is_some()
            && ((request.resource.resource == "pods" && request.operation == "CREATE")
                || (request.resource.resource == "persistentvolumeclaims"
                    && request.operation != "DELETE"))
        {
            return self.restored_workload(request, &authority).await;
        }
        validate_workload(request, &authority, &self.config)
    }

    /// A same-named replacement PVC/PV cannot become the restored workspace.
    /// The Kube reads are observations; fresh compute authorization and exact
    /// immutable delivery identity are checked again under the SQL fence.
    async fn restored_workload(
        &self,
        request: &AdmissionRequest,
        previous: &WorkloadAuthority,
    ) -> Decision {
        let c = &previous.context;
        let mut tx = self
            .database
            .begin(c.tenant_id)
            .await
            .map_err(|_| Denial::dependency())?;
        let original = crate::workspace_restore::load(&mut tx, c)
            .await
            .map_err(|_| Denial::policy("Restore provenance is unavailable"))?
            .ok_or(Denial::policy("Restore delivery identity is missing"))?;
        tx.commit().await.map_err(|_| Denial::dependency())?;
        let expected = build_manifests(c, &self.config.runtime())
            .map_err(|_| Denial::policy("Restored runtime approval is invalid"))?;
        let name = expected
            .pvc
            .metadata
            .name
            .as_deref()
            .ok_or(Denial::dependency())?;
        let pvcs = Api::<PersistentVolumeClaim>::namespaced(self.kubernetes.clone(), &c.namespace);
        let pv = Api::<PersistentVolume>::all(self.kubernetes.clone());
        let observed_at = tokio::time::Instant::now();
        let pvc = pvcs.get(name).await.map_err(|_| Denial::dependency())?;
        validate_existing_pvc(&pvc, &expected.pvc, Some(&original.pvc_uid.to_string()))
            .map_err(|_| Denial::policy("Restored PVC identity or datasource changed"))?;
        checked(
            pvc.spec.as_ref().and_then(|s| s.volume_name.as_deref())
                == Some(original.pv_name.as_str())
                && pvc.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Bound"),
            "Restored workspace must remain Bound to its delivered PV",
        )?;
        let volume = pv
            .get(&original.pv_name)
            .await
            .map_err(|_| Denial::dependency())?;
        let encoded = serde_json::to_value(&volume).map_err(|_| Denial::dependency())?;
        crate::backup_runtime::validate_pv(
            &encoded,
            original.pvc_uid,
            name,
            &c.namespace,
            &c.storage_class,
            "Filesystem",
            original.size_bytes as u64,
        )
        .map_err(|_| Denial::policy("Restored PV claim, driver, mode or retention changed"))?;
        checked(
            volume.metadata.uid.as_deref() == Some(original.pv_uid.to_string().as_str())
                && volume
                    .spec
                    .as_ref()
                    .and_then(|s| s.csi.as_ref())
                    .is_some_and(|s| {
                        s.driver == self.config.storage_provisioner
                            && s.volume_handle == original.cloud_disk
                    }),
            "Restored PV UID or cloud disk changed",
        )?;
        // Re-read after the PV wait, then acquire the exact consumer fence.
        let again = pvcs.get(name).await.map_err(|_| Denial::dependency())?;
        validate_existing_pvc(&again, &expected.pvc, Some(&original.pvc_uid.to_string()))
            .map_err(|_| Denial::policy("Restored PVC was replaced during verification"))?;
        checked(
            again.spec.as_ref().and_then(|s| s.volume_name.as_deref())
                == Some(original.pv_name.as_str()),
            "Restored PVC changed PV during verification",
        )?;
        let mut tx = self
            .database
            .begin(c.tenant_id)
            .await
            .map_err(|_| Denial::dependency())?;
        let locked: Option<crate::workspace_restore::WorkspaceRestoreBinding> =
            sqlx::query_as("SELECT * FROM sandbox_lock_restored_runtime($1,$2,$3)")
                .bind(c.tenant_id)
                .bind(c.instance_id)
                .bind(c.workspace_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| Denial::policy("Restored runtime fence is unavailable"))?;
        checked(
            locked.as_ref() == Some(&original) && observed_at.elapsed() <= Duration::from_secs(10),
            "Restore delivery or observation changed while waiting for the runtime fence",
        )?;
        let mut fresh = self
            .authority_in(
                &mut tx,
                c.tenant_id,
                c.project_id,
                c.instance_id,
                &c.namespace,
            )
            .await?;
        let current = build_manifests(&fresh.context, &self.config.runtime())
            .map_err(|_| Denial::policy("Restored runtime approval was revoked"))?;
        checked(
            serde_json::to_value(expected.pod).map_err(|_| Denial::dependency())?
                == serde_json::to_value(current.pod).map_err(|_| Denial::dependency())?
                && fresh.pvc_uid.as_deref() == Some(original.pvc_uid.to_string().as_str()),
            "Restored compute generation or fixed PVC changed",
        )?;
        fresh.node_binding_valid = previous.node_binding_valid;
        fresh.volume_binding_valid = true;
        validate_workload(request, &fresh, &self.config)?;
        tx.commit().await.map_err(|_| Denial::dependency())?;
        Ok(())
    }

    async fn connect_execution(
        &self,
        request: &AdmissionRequest,
        tenant: Uuid,
        project: Uuid,
        namespace_epoch: &str,
    ) -> Decision {
        let (kind, execution, attempt) = runner_connect_identity(request, &self.config)?;
        let review = Uuid::parse_str(&request.uid)
            .map_err(|_| Denial::policy("Invalid admission request identity"))?;
        checked(!review.is_nil(), "Admission request identity is nil")?;
        let mut tx = self
            .database
            .begin(tenant)
            .await
            .map_err(|_| Denial::dependency())?;
        let instance: Option<Uuid> = sqlx::query_scalar(match kind {
            RunnerConnection::Execution => "SELECT instance_id FROM executions WHERE tenant_id=$1 AND project_id=$2 AND id=$3",
            RunnerConnection::FileTransfer => "SELECT instance_id FROM file_transfers WHERE tenant_id=$1 AND project_id=$2 AND id=$3",
        })
        .bind(tenant)
        .bind(project)
        .bind(execution)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| Denial::dependency())?;
        tx.commit().await.map_err(|_| Denial::dependency())?;
        let authority = self
            .authority(
                tenant,
                project,
                instance.ok_or(Denial::policy("No execution in this project"))?,
                &request.namespace,
            )
            .await?;
        checked(
            namespace_epoch == authority.context.cluster_epoch.to_string(),
            "Execution namespace epoch is stale",
        )?;
        let options: ExecOptions = typed(object(request)?)?;
        checked(
            options.container == container_name(authority.context.launch_id),
            "Execution container does not match the current launch",
        )?;
        let expected = build_manifests(&authority.context, &self.config.runtime())
            .map_err(|_| Denial::policy("Execution runtime approval is invalid"))?;
        checked(
            expected.pod.metadata.name.as_deref() == Some(request.name.as_str())
                && authority.pod_uid.is_some()
                && authority.pvc_uid.is_some()
                && authority.policy_uid.is_some(),
            "Execution runtime identity is not recorded",
        )?;
        let pods: Api<Pod> = Api::namespaced(self.kubernetes.clone(), &request.namespace);
        let pod = pods
            .get(&request.name)
            .await
            .map_err(|_| Denial::dependency())?;
        validate_existing_pod(&pod, &expected.pod, authority.pod_uid.as_deref())
            .map_err(|_| Denial::policy("Execution Pod identity or security profile changed"))?;
        let node = pod
            .spec
            .as_ref()
            .and_then(|spec| spec.node_name.as_deref())
            .ok_or(Denial::policy("Execution Pod is not scheduled"))?;
        checked(
            self.node(node, true).await?,
            "Execution node is not Ready in the Kata pool",
        )?;
        checked(
            pod.status.as_ref().is_some_and(|status| {
                status.phase.as_deref() == Some("Running")
                    && status.conditions.as_ref().is_some_and(|conditions| {
                        conditions
                            .iter()
                            .any(|c| c.type_ == "Ready" && c.status == "True")
                    })
                    && status
                        .container_statuses
                        .as_ref()
                        .is_some_and(|containers| {
                            containers.len() == 1
                                && containers[0].name == options.container
                                && containers[0].ready
                                && containers[0]
                                    .state
                                    .as_ref()
                                    .is_some_and(|state| state.running.is_some())
                        })
            }),
            "Execution Pod is not Ready",
        )?;
        let pvcs: Api<PersistentVolumeClaim> =
            Api::namespaced(self.kubernetes.clone(), &request.namespace);
        let pvc = pvcs
            .get(
                expected
                    .pvc
                    .metadata
                    .name
                    .as_deref()
                    .ok_or(Denial::dependency())?,
            )
            .await
            .map_err(|_| Denial::dependency())?;
        validate_existing_pvc(&pvc, &expected.pvc, authority.pvc_uid.as_deref())
            .map_err(|_| Denial::policy("Execution workspace identity changed"))?;
        checked(
            pvc.status
                .as_ref()
                .and_then(|status| status.phase.as_deref())
                == Some("Bound"),
            "Execution workspace is not Bound",
        )?;
        let policies: Api<DynamicObject> = Api::namespaced_with(
            self.kubernetes.clone(),
            &request.namespace,
            &ApiResource::from_gvk(&GroupVersionKind::gvk(
                "cilium.io",
                "v2",
                "CiliumNetworkPolicy",
            )),
        );
        let policy = policies
            .get(
                expected
                    .network_policy
                    .metadata
                    .name
                    .as_deref()
                    .ok_or(Denial::dependency())?,
            )
            .await
            .map_err(|_| Denial::dependency())?;
        validate_existing_policy(
            &policy,
            &expected.network_policy,
            authority.policy_uid.as_deref(),
        )
        .map_err(|_| Denial::policy("Execution network protection changed"))?;
        // Commit the one-use authorization before returning allowed=true. A
        // response lost after commit is ambiguous and cannot authorize a second
        // independently assigned request UID. The function rechecks all SQL
        // facts after these fresh Kubernetes observations and before consumption.
        let admitted: bool = match kind {
            RunnerConnection::Execution => {
                sqlx::query_scalar("SELECT sandbox_admit_execution_connect($1,$2,$3,$4)")
                    .bind(tenant)
                    .bind(execution)
                    .bind(attempt)
                    .bind(review)
                    .fetch_one(&self.database.pool)
                    .await
                    .map_err(|_| Denial::dependency())?
            }
            RunnerConnection::FileTransfer => {
                sqlx::query_scalar("SELECT sandbox_check_file_connect($1,$2,$3,$4,true)")
                    .bind(tenant)
                    .bind(execution)
                    .bind(attempt)
                    .bind(review)
                    .fetch_one(&self.database.pool)
                    .await
                    .map_err(|_| Denial::dependency())?
            }
        };
        checked(
            admitted,
            "Execution connection authorization is stale, revoked or already consumed",
        )
    }

    async fn project(&self, tenant: Uuid, project: Uuid, namespace: &str) -> Decision {
        let mut tx = self
            .database
            .begin(tenant)
            .await
            .map_err(|_| Denial::dependency())?;
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM projects WHERE tenant_id=$1 AND id=$2 AND runtime_namespace=$3)")
            .bind(tenant).bind(project).bind(namespace).fetch_one(&mut *tx).await.map_err(|_| Denial::dependency())?;
        tx.commit().await.map_err(|_| Denial::dependency())?;
        checked(
            exists,
            "Namespace does not match its authoritative project binding",
        )
    }

    async fn namespace(&self, request: &AdmissionRequest) -> Decision {
        let current = object(request)?;
        let reserved = |value: &Value| {
            labels(value)
                .as_object()
                .is_some_and(|v| v.keys().any(|key| key.starts_with(PREFIX)))
                || annotations(value)
                    .as_object()
                    .is_some_and(|v| v.keys().any(|key| key.starts_with(PREFIX)))
        };
        if !reserved(current) && !request.old_object.as_ref().is_some_and(reserved) {
            return Ok(());
        }
        checked(
            request.resource.version == "v1"
                && matches!(request.operation.as_str(), "CREATE" | "UPDATE")
                && (request.sub_resource.is_empty() || request.sub_resource == "status"),
            "Protected namespace deletion/finalization is prohibited",
        )?;
        checked(
            string(current, "/metadata/labels/sandbox.platform~1managed") == Some("true")
                && string(current, "/metadata/name") == Some(request.name.as_str())
                && string(
                    current,
                    "/metadata/annotations/sandbox.platform~1certification-id",
                ) == Some(self.config.certification_id.as_str()),
            "Protected namespace binding or certification reference is invalid",
        )?;
        uid(current)?;
        if let Some(old) = &request.old_object {
            checked(uid(old)? == uid(current)?, "Namespace UID is immutable")?;
            same_metadata(old, current)?;
            checked(
                old.get("spec") == current.get("spec"),
                "Namespace spec/finalizers are immutable",
            )?;
        } else {
            checked(
                request.operation == "CREATE",
                "Namespace update needs old object",
            )?;
        }
        if request.sub_resource == "status" {
            checked(
                request.operation == "UPDATE"
                    && self
                        .config
                        .namespace_status_controllers
                        .iter()
                        .any(|c| c.matches(&request.user_info)),
                "Only configured namespace controllers may update status",
            )?;
        } else {
            checked(
                self.config
                    .namespace_provisioner
                    .matches(&request.user_info),
                "Only the provisioner may create protected namespaces",
            )?;
        }
        let (tenant, project) = scope(current)?;
        self.project(tenant, project, &request.name).await?;
        let epoch: Uuid =
            sqlx::query_scalar("SELECT cluster_epoch FROM platform_configuration WHERE singleton")
                .fetch_one(&self.database.pool)
                .await
                .map_err(|_| Denial::dependency())?;
        checked(
            string(current, "/metadata/labels/sandbox.platform~1cluster-epoch")
                == Some(epoch.to_string().as_str()),
            "Namespace belongs to another deployment epoch",
        )
    }

    fn baseline(&self, request: &AdmissionRequest) -> Decision {
        let current = object(request)?;
        checked(
            request.resource.version == "v1"
                && request.sub_resource.is_empty()
                && matches!(request.operation.as_str(), "CREATE" | "UPDATE")
                && self
                    .config
                    .namespace_provisioner
                    .matches(&request.user_info)
                && request.name == "sandbox-default-deny"
                && string(current, "/apiVersion") == Some("networking.k8s.io/v1")
                && string(current, "/kind") == Some("NetworkPolicy")
                && string(current, "/metadata/name") == Some(request.name.as_str())
                && string(current, "/metadata/namespace") == Some(request.namespace.as_str())
                && current.get("spec")
                    == Some(&json!({"podSelector":{},"policyTypes":["Ingress","Egress"]}))
                && labels(current) == json!({})
                && annotations(current) == json!({})
                && current.pointer("/metadata/ownerReferences").is_none()
                && current.pointer("/metadata/finalizers").is_none(),
            "Only the fixed deny-all baseline may be provisioned",
        )?;
        uid(current)?;
        if let Some(old) = &request.old_object {
            checked(uid(old)? == uid(current)?, "Baseline UID is immutable")?;
        }
        Ok(())
    }

    async fn node(&self, name: &str, require_schedulable: bool) -> Result<bool, Denial> {
        let nodes: Api<Node> = Api::all(self.kubernetes.clone());
        let node = nodes.get(name).await.map_err(|_| Denial::dependency())?;
        Ok(node.metadata.uid.is_some()
            && node
                .metadata
                .labels
                .as_ref()
                .and_then(|v| v.get("sandbox.platform/worker-pool"))
                .map(String::as_str)
                == Some("kata")
            && (!require_schedulable
                || (node
                    .spec
                    .as_ref()
                    .is_none_or(|spec| spec.unschedulable != Some(true))
                    && node
                        .status
                        .as_ref()
                        .and_then(|s| s.conditions.as_ref())
                        .is_some_and(|conditions| {
                            conditions.iter().any(|condition| {
                                condition.type_ == "Ready" && condition.status == "True"
                            })
                        }))))
    }

    async fn guarded_node_binding(&self, context: &RuntimeManifestContext, name: &str) -> Decision {
        let nodes: Api<Node> = Api::all(self.kubernetes.clone());
        let node = nodes.get(name).await.map_err(|_| Denial::dependency())?;
        checked(
            node.metadata.deletion_timestamp.is_none()
                && node
                    .spec
                    .as_ref()
                    .is_none_or(|s| s.unschedulable != Some(true))
                && node
                    .status
                    .as_ref()
                    .and_then(|s| s.conditions.as_ref())
                    .is_some_and(|conditions| {
                        conditions
                            .iter()
                            .any(|c| c.type_ == "Ready" && c.status == "True")
                    })
                && node
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|l| l.get("sandbox.platform/worker-pool"))
                    .is_some_and(|v| v == "kata"),
            "Current node is not a ready dedicated Kata target",
        )?;
        let node_uid = node
            .metadata
            .uid
            .as_deref()
            .and_then(|v| Uuid::parse_str(v).ok())
            .ok_or(Denial::policy("Node UID is missing"))?;
        let boot = node
            .status
            .as_ref()
            .and_then(|s| s.node_info.as_ref())
            .and_then(|s| Uuid::parse_str(&s.boot_id).ok())
            .ok_or(Denial::policy("Node boot identity is missing"))?;
        let profile = node
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get("sandbox.platform/runtime-profile-sha256"))
            .ok_or(Denial::policy("Node runtime profile is missing"))?;
        let mut tx = self
            .database
            .begin(context.tenant_id)
            .await
            .map_err(|_| Denial::dependency())?;
        let allowed: bool =
            sqlx::query_scalar("SELECT sandbox_guarded_node_binding($1,$2,$3,$4,$5,$6)")
                .bind(context.tenant_id)
                .bind(context.instance_id)
                .bind(node_uid)
                .bind(name)
                .bind(boot)
                .bind(profile)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| Denial::dependency())?;
        tx.commit().await.map_err(|_| Denial::dependency())?;
        checked(
            allowed,
            "Node is not in the current certified guard admission set",
        )
    }

    async fn binding(
        &self,
        request: &AdmissionRequest,
        tenant: Uuid,
        project: Uuid,
        namespace_epoch: &str,
    ) -> Decision {
        checked(
            request.operation == "CREATE" && self.config.scheduler.matches(&request.user_info),
            "Only the registered scheduler may bind workloads",
        )?;
        let binding = object(request)?;
        checked(
            string(binding, "/target/kind") == Some("Node")
                && string(binding, "/metadata/name") == Some(request.name.as_str())
                && string(binding, "/metadata/namespace") == Some(request.namespace.as_str()),
            "Binding must target a Node",
        )?;
        let target =
            string(binding, "/target/name").ok_or(Denial::policy("Binding target missing"))?;
        checked(
            self.node(target, true).await?,
            "Scheduler target is outside the certified Kata node pool",
        )?;
        let pods: Api<Pod> = Api::namespaced(self.kubernetes.clone(), &request.namespace);
        let pod = pods
            .get(&request.name)
            .await
            .map_err(|_| Denial::dependency())?;
        let value = serde_json::to_value(&pod).map_err(|_| Denial::dependency())?;
        checked(
            uid(binding)? == uid(&value)?,
            "Scheduler binding UID differs from the actual Pod",
        )?;
        let instance = string(&value, "/metadata/labels/sandbox.platform~1instance-id")
            .and_then(|v| Uuid::parse_str(v).ok())
            .ok_or(Denial::policy("Pod identity missing"))?;
        let authority = self
            .authority(tenant, project, instance, &request.namespace)
            .await?;
        checked(
            authority.create_allowed
                && namespace_epoch == authority.context.cluster_epoch.to_string()
                && pod
                    .spec
                    .as_ref()
                    .is_some_and(|spec| spec.node_name.is_none()),
            "Pod is no longer eligible for scheduling",
        )?;
        self.guarded_node_binding(&authority.context, target)
            .await?;
        let expected = build_manifests(&authority.context, &self.config.runtime())
            .map_err(|_| Denial::policy("Invalid controlled runtime"))?;
        validate_existing_pod(&pod, &expected.pod, authority.pod_uid.as_deref())
            .map_err(|_| Denial::policy("Scheduler Pod has drifted from its authoritative binding"))
    }

    // Historical proof authorizes only post-finalizer status/GC. A new removal
    // additionally requires the current unexpired challenge and operation lease.
    async fn termination_evidence(
        &self,
        authority: &mut WorkloadAuthority,
        pod: &Value,
    ) -> Decision {
        // This alternative is born under a reviewed guard contract and has a
        // permanent DB permit fence. It also covers Pods that never got a node.
        let pod_uid = Uuid::parse_str(uid(pod)?).map_err(|_| Denial::policy("Invalid Pod UID"))?;
        let mut closed_tx = self
            .database
            .begin(authority.context.tenant_id)
            .await
            .map_err(|_| Denial::dependency())?;
        let closed: bool = sqlx::query_scalar("SELECT sandbox_never_authorized_pod($1,$2,$3)")
            .bind(authority.context.tenant_id)
            .bind(authority.context.instance_id)
            .bind(pod_uid)
            .fetch_one(&mut *closed_tx)
            .await
            .map_err(|_| Denial::dependency())?;
        closed_tx.commit().await.map_err(|_| Denial::dependency())?;
        if closed {
            // Each late API UID has its own fresh-GET receipt. The original
            // instance UID does not hide a later create after an earlier GC.
            authority.pod_uid = Some(pod_uid.to_string());
            authority.termination_proven = true;
            authority.termination_finalizer_allowed = true;
            authority.stop_allowed = true;
            return Ok(());
        }
        let Some(node_name) = string(pod, "/spec/nodeName") else {
            return Ok(());
        };
        let pod_uid = Uuid::parse_str(uid(pod)?).map_err(|_| Denial::policy("Invalid Pod UID"))?;
        let context = &authority.context;
        let mut tx = self
            .database
            .begin(context.tenant_id)
            .await
            .map_err(|_| Denial::dependency())?;
        let (proven, fresh): (bool, bool) = sqlx::query_as(r#"
            SELECT count(*)>0, COALESCE(bool_or(
                i.active_operation_id=o.id AND o.status='RUNNING'
                AND o.lease_token=ch.lease_token AND o.lease_owner IS NOT NULL
                AND o.lease_until>clock_timestamp() AND ch.expires_at>clock_timestamp()
                AND (o.kind IN('STOP','DELETE')
                  OR (o.kind='RESTART' AND o.restart_generation IS NULL))
            ),false)
            FROM local_termination_proofs p
            JOIN launch_permits l ON (l.tenant_id,l.project_id,l.id)=(p.tenant_id,p.project_id,p.permit_id)
            JOIN termination_challenges ch ON (ch.tenant_id,ch.project_id,ch.id,ch.permit_id)
                =(p.tenant_id,p.project_id,p.challenge_id,p.permit_id)
            JOIN operations o ON (o.tenant_id,o.project_id,o.id,o.instance_id,o.workspace_id)
                =(ch.tenant_id,ch.project_id,ch.operation_id,p.instance_id,p.workspace_id)
            JOIN instances i ON (i.tenant_id,i.project_id,i.id,i.workspace_id,i.runtime_generation,i.launch_id,i.cluster_epoch,i.pod_uid)
                =(p.tenant_id,p.project_id,p.instance_id,p.workspace_id,p.generation,p.launch_id,p.cluster_epoch,p.pod_uid)
            JOIN runtime_nodes n ON n.id=p.runtime_node_id AND n.id=l.runtime_node_id AND n.cluster_epoch=p.cluster_epoch
            CROSS JOIN platform_configuration c
            WHERE p.tenant_id=$1 AND p.project_id=$2 AND p.instance_id=$3 AND p.workspace_id=$4
                AND p.generation=$5 AND p.launch_id=$6 AND p.pod_uid=$7 AND p.cluster_epoch=$8
                AND l.namespace=$9 AND l.pod_name=$10 AND n.node_name=$11
                AND (l.instance_id,l.workspace_id,l.generation,l.launch_id,l.pod_uid,l.cluster_epoch)
                    =(p.instance_id,p.workspace_id,p.generation,p.launch_id,p.pod_uid,p.cluster_epoch)
                AND c.singleton AND c.cluster_epoch=p.cluster_epoch AND ch.reason=o.kind
                AND p.recorded_at>=ch.created_at AND p.recorded_at<ch.expires_at
                AND p.observed_at>=ch.created_at-interval '2 seconds'
                AND p.observed_at<=p.recorded_at+interval '2 seconds'
        "#).bind(context.tenant_id).bind(context.project_id).bind(context.instance_id)
            .bind(context.workspace_id).bind(context.generation).bind(context.launch_id).bind(pod_uid)
            .bind(context.cluster_epoch).bind(&context.namespace).bind(string(pod,"/metadata/name").ok_or(Denial::policy("Pod name required"))?)
            .bind(node_name).fetch_one(&mut *tx).await.map_err(|_| Denial::dependency())?;
        tx.commit().await.map_err(|_| Denial::dependency())?;
        authority.termination_proven = proven;
        authority.termination_finalizer_allowed = fresh;
        Ok(())
    }

    async fn authority(
        &self,
        tenant: Uuid,
        project: Uuid,
        instance: Uuid,
        namespace: &str,
    ) -> Result<WorkloadAuthority, Denial> {
        let mut tx = self
            .database
            .begin(tenant)
            .await
            .map_err(|_| Denial::dependency())?;
        let result = self
            .authority_in(&mut tx, tenant, project, instance, namespace)
            .await?;
        tx.commit().await.map_err(|_| Denial::dependency())?;
        Ok(result)
    }

    async fn authority_in(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant: Uuid,
        project: Uuid,
        instance: Uuid,
        namespace: &str,
    ) -> Result<WorkloadAuthority, Denial> {
        let row = sqlx::query("SELECT i.*,w.storage_class,w.size_gib,t.image_ref,t.image_digest,t.status='APPROVED' AS template_approved,p.status='APPROVED' AS policy_approved,p.rules,c.cluster_epoch AS current_epoch,c.safe_mode,o.kind AS operation_kind,o.status AS operation_status,o.restart_generation,o.actor_principal_id,clock_timestamp()<i.compute_lease_expires_at AS unexpired FROM instances i JOIN workspaces w ON (w.tenant_id,w.project_id,w.id)=(i.tenant_id,i.project_id,i.workspace_id) JOIN template_versions t ON (t.tenant_id,t.id)=(i.tenant_id,i.template_version_id) JOIN security_policy_versions p ON (p.tenant_id,p.id)=(i.tenant_id,i.security_policy_version_id) CROSS JOIN platform_configuration c LEFT JOIN operations o ON (o.tenant_id,o.id)=(i.tenant_id,i.active_operation_id) WHERE i.tenant_id=$1 AND i.project_id=$2 AND i.id=$3 AND i.namespace=$4")
            .bind(tenant).bind(project).bind(instance).bind(namespace).fetch_optional(&mut **tx).await.map_err(|_| Denial::dependency())?.ok_or(Denial::policy("No authoritative runtime binding"))?;
        macro_rules! field {
            ($name:literal) => {
                row.try_get($name).map_err(|_| Denial::dependency())?
            };
        }
        let mut context = RuntimeManifestContext {
            tenant_id: tenant,
            project_id: project,
            instance_id: instance,
            workspace_id: field!("workspace_id"),
            launch_id: field!("launch_id"),
            cluster_epoch: field!("cluster_epoch"),
            generation: field!("runtime_generation"),
            namespace: namespace.to_owned(),
            storage_class: field!("storage_class"),
            workspace_snapshot: None,
            image_ref: field!("image_ref"),
            image_digest: field!("image_digest"),
            template_approved: field!("template_approved"),
            security_policy_approved: field!("policy_approved"),
            security_policy_rules: field!("rules"),
            cpu_millis: field!("cpu_millis"),
            memory_mib: field!("memory_mib"),
            workspace_size_gib: field!("size_gib"),
        };
        crate::workspace_restore::apply(tx, &mut context)
            .await
            .map_err(|_| Denial::policy("Restore provenance is unavailable"))?;
        let kind: Option<String> = field!("operation_kind");
        let status: Option<String> = field!("operation_status");
        let restart_generation: Option<i64> = field!("restart_generation");
        let principal: Option<Uuid> = field!("actor_principal_id");
        let desired: String = field!("desired_state");
        let stopping: Option<chrono::DateTime<chrono::Utc>> = field!("stop_accepted_at");
        let safe: bool = field!("safe_mode");
        let unexpired: bool = field!("unexpired");
        let epoch: Uuid = field!("current_epoch");
        let active = status
            .as_deref()
            .is_some_and(|value| matches!(value, "QUEUED" | "RUNNING" | "WAITING"));
        let mut create_allowed = desired == "RUNNING"
            && stopping.is_none()
            && !safe
            && unexpired
            && epoch == context.cluster_epoch
            && context.template_approved
            && context.security_policy_approved
            && active;
        let permission = match kind.as_deref() {
            Some("CREATE") => "instances:create",
            Some("START") => "instances:start",
            Some("RESTART") if restart_generation == Some(context.generation) => {
                "instances:restart"
            }
            _ => {
                create_allowed = false;
                ""
            }
        };
        if create_allowed {
            let principal = principal.ok_or(Denial::policy("Operation actor is missing"))?;
            Database::authorize(
                tx,
                &Actor {
                    authorization: None,
                    tenant_id: tenant,
                    principal_id: principal,
                    request_id: Uuid::new_v4(),
                },
                project,
                permission,
            )
            .await
            .map_err(|error| {
                if error.status == StatusCode::FORBIDDEN {
                    Denial::policy("Operation authorization was revoked")
                } else {
                    Denial::dependency()
                }
            })?;
        }
        if create_allowed && kind.as_deref() == Some("RESTART") {
            Database::authorize(
                tx,
                &Actor {
                    authorization: None,
                    tenant_id: tenant,
                    principal_id: principal.ok_or(Denial::dependency())?,
                    request_id: Uuid::new_v4(),
                },
                project,
                "instances:hard_stop",
            )
            .await
            .map_err(|error| {
                if error.status == StatusCode::FORBIDDEN {
                    Denial::policy("Restart hard-stop authorization was revoked")
                } else {
                    Denial::dependency()
                }
            })?;
        }
        let resources: Vec<(String, String)> = sqlx::query_as("SELECT kind,provider_id FROM external_resources WHERE tenant_id=$1 AND project_id=$2 AND provider='kubernetes' AND ((kind='POD' AND instance_id=$3 AND generation=$5) OR (kind='PVC' AND workspace_id=$4 AND generation=1) OR (kind='CILIUM_POLICY' AND instance_id=$3 AND generation=1))")
            .bind(tenant).bind(project).bind(instance).bind(context.workspace_id).bind(context.generation).fetch_all(&mut **tx).await.map_err(|_| Denial::dependency())?;
        let mut identities = BTreeMap::new();
        for (kind, uid) in resources {
            checked(
                identities.insert(kind, uid).is_none(),
                "Ambiguous external resource UID binding",
            )?;
        }
        let pod_uid: Option<Uuid> = field!("pod_uid");
        let pod_uid = pod_uid.map(|uid| uid.to_string());
        if let (Some(pod), Some(external)) = (&pod_uid, identities.get("POD")) {
            checked(
                pod == external,
                "Pod UID differs across authoritative records",
            )?;
        }
        let stop_allowed = active
            && epoch == context.cluster_epoch
            && match kind.as_deref() {
                Some("STOP" | "DELETE") => matches!(desired.as_str(), "STOPPED" | "DELETED"),
                Some("RESTART") => restart_generation.is_none(),
                _ => false,
            };
        let result = WorkloadAuthority {
            context,
            create_allowed,
            stop_allowed,
            termination_finalizer_allowed: false,
            termination_proven: false,
            pod_uid: pod_uid.or_else(|| identities.remove("POD")),
            pvc_uid: identities.remove("PVC"),
            policy_uid: identities.remove("CILIUM_POLICY"),
            node_binding_valid: false,
            volume_binding_valid: false,
        };
        Ok(result)
    }
}

fn scope(namespace: &Value) -> Result<(Uuid, Uuid), Denial> {
    let id = |key| {
        string(namespace, key)
            .and_then(|value| Uuid::parse_str(value).ok())
            .filter(|value| !value.is_nil())
            .ok_or(Denial::policy(
                "Namespace has no valid operator-assigned tenant/project binding",
            ))
    };
    Ok((
        id("/metadata/labels/sandbox.platform~1tenant-id")?,
        id("/metadata/labels/sandbox.platform~1project-id")?,
    ))
}

pub fn router(service: Arc<AdmissionService>) -> Router {
    Router::new()
        .route("/validate", post(review))
        .route("/health/live", get(|| async { StatusCode::NO_CONTENT }))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .with_state(service)
}

async fn review(
    State(service): State<Arc<AdmissionService>>,
    Json(review): Json<AdmissionReview>,
) -> Result<Json<Value>, StatusCode> {
    if review.api_version != "admission.k8s.io/v1" || review.kind != "AdmissionReview" {
        return Err(StatusCode::BAD_REQUEST);
    }
    let request = review.request.ok_or(StatusCode::BAD_REQUEST)?;
    if request.uid.is_empty() || request.uid.len() > 128 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let decision = tokio::time::timeout(Duration::from_secs(4), service.decide(&request))
        .await
        .unwrap_or_else(|_| Err(Denial::dependency()));
    let response = match decision {
        Ok(()) => json!({"uid":request.uid,"allowed":true}),
        Err(error) => {
            tracing::warn!(admission_uid=%request.uid, resource=%request.resource.resource,
                operation=%request.operation, code=error.code, reason=error.message,
                "Sandbox admission rejected");
            json!({"uid":request.uid,"allowed":false,"status":{"code":error.code,"reason":"Forbidden","message":error.message}})
        }
    };
    // Do not log AdmissionReview objects, authentication headers or SQL values.
    Ok(Json(
        json!({"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","response":response}),
    ))
}

pub use crate::tls::mutual_tls;
