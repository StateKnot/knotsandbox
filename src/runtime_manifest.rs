//! Controlled Kubernetes objects, without network access or readiness claims.
//! The operator must certify the `kata-qemu` RuntimeClass handler, dedicated node
//! pool, Cilium always-enforce mode, CSI driver and namespace admission policy.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Pod};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::core::DynamicObject;
use serde_json::{Value, json};
use uuid::Uuid;

pub const TERMINATION_FINALIZER: &str = "sandbox.platform/termination-protection";
const LABEL_PREFIX: &str = "sandbox.platform/";

#[derive(Debug, Clone)]
pub struct RuntimeManifestContext {
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub instance_id: Uuid,
    pub workspace_id: Uuid,
    pub launch_id: Uuid,
    pub cluster_epoch: Uuid,
    pub generation: i64,
    pub namespace: String,
    pub storage_class: String,
    /// Only a persisted restore delivery receipt may select this datasource.
    pub workspace_snapshot: Option<String>,
    pub image_ref: String,
    pub image_digest: String,
    pub template_approved: bool,
    pub security_policy_approved: bool,
    pub security_policy_rules: Value,
    pub cpu_millis: i64,
    pub memory_mib: i64,
    pub workspace_size_gib: i64,
}

#[derive(Debug, Clone)]
pub struct RuntimeManifestConfig {
    pub runtime_class_name: String,
    pub dns_namespace: String,
    /// Kubernetes labels of the actual CoreDNS endpoints, e.g. k8s-app=kube-dns.
    /// An empty selector is rejected; DNS must not mean every pod in a namespace.
    pub dns_labels: BTreeMap<String, String>,
    pub ephemeral_storage_mib: i64,
    pub tmp_size_mib: i64,
}

#[derive(Debug)]
pub struct RuntimeManifests {
    pub pod: Pod,
    pub pvc: PersistentVolumeClaim,
    pub network_policy: DynamicObject,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("invalid controlled runtime configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("the template and security policy must be approved")]
    ApprovalRequired,
    #[error("the approved image must use an explicit sha256 digest")]
    InvalidImage,
    #[error("existing resource ownership differs: {0}")]
    OwnershipMismatch(&'static str),
    #[error("existing resource is already being deleted")]
    Deleting,
    #[error("existing resource has drifted from the controlled specification: {0}")]
    SpecificationDrift(&'static str),
    #[error("cannot encode the controlled Kubernetes object")]
    Encoding,
}

pub fn pod_name(workspace: Uuid) -> String {
    format!("sbx-ws-{workspace}")
}
pub fn pvc_name(workspace: Uuid) -> String {
    format!("ws-{workspace}")
}
pub fn container_name(launch: Uuid) -> String {
    format!("workload-{launch}")
}
pub fn network_policy_name(workspace: Uuid) -> String {
    format!("net-ws-{workspace}")
}

pub fn build_manifests(
    context: &RuntimeManifestContext,
    config: &RuntimeManifestConfig,
) -> Result<RuntimeManifests, ManifestError> {
    validate_context(context, config)?;
    let stable_labels = stable_labels(context);
    let mut launch_labels = stable_labels.clone();
    launch_labels.insert(
        format!("{LABEL_PREFIX}launch-id"),
        context.launch_id.to_string(),
    );
    launch_labels.insert(
        format!("{LABEL_PREFIX}generation"),
        context.generation.to_string(),
    );
    launch_labels.insert(
        format!("{LABEL_PREFIX}cluster-epoch"),
        context.cluster_epoch.to_string(),
    );
    let resources = json!({
        "cpu": (context.cpu_millis / 1000).to_string(),
        "memory": quantity_mib(context.memory_mib),
        "ephemeral-storage": quantity_mib(config.ephemeral_storage_mib),
    });
    let pod: Pod = serde_json::from_value(json!({
        "apiVersion":"v1", "kind":"Pod",
        "metadata": {
            "name":pod_name(context.workspace_id), "namespace":context.namespace,
            "labels":launch_labels, "finalizers":[TERMINATION_FINALIZER],
        },
        "spec": {
            "runtimeClassName":config.runtime_class_name,
            "nodeSelector":{"sandbox.platform/worker-pool":"kata"},
            "schedulerName":"default-scheduler", "preemptionPolicy":"Never",
            "tolerations":[
                {"key":"sandbox.platform/untrusted","operator":"Equal","value":"true","effect":"NoSchedule"},
                {"key":"node.kubernetes.io/not-ready","operator":"Exists","effect":"NoExecute","tolerationSeconds":300},
                {"key":"node.kubernetes.io/unreachable","operator":"Exists","effect":"NoExecute","tolerationSeconds":300}
            ],
            "serviceAccountName":"sandbox-workload", "automountServiceAccountToken":false,
            "enableServiceLinks":false, "restartPolicy":"Never", "terminationGracePeriodSeconds":30,
            "hostNetwork":false, "hostPID":false, "hostIPC":false, "shareProcessNamespace":false,
            "dnsPolicy":"ClusterFirst", "os":{"name":"linux"},
            "securityContext": {
                "runAsNonRoot":true,"runAsUser":1000,"runAsGroup":1000,
                "fsGroup":1000,"fsGroupChangePolicy":"OnRootMismatch",
                "seccompProfile":{"type":"RuntimeDefault"}
            },
            "containers":[{
                "name":container_name(context.launch_id),
                "image":format!("{}@{}",context.image_ref,context.image_digest),
                "imagePullPolicy":"IfNotPresent",
                "command":["/usr/local/bin/sandbox-runner","idle"],
                "workingDir":"/workspace", "stdin":false,"tty":false,
                "readinessProbe": {
                    "exec":{"command":["/usr/local/bin/sandbox-runner","health"]},
                    "initialDelaySeconds":1,"periodSeconds":10,"timeoutSeconds":2,
                    "successThreshold":1,"failureThreshold":3
                },
                "terminationMessagePath":"/dev/termination-log", "terminationMessagePolicy":"File",
                "securityContext": {
                    "runAsNonRoot":true,"runAsUser":1000,"runAsGroup":1000,
                    "privileged":false,"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,
                    "capabilities":{"drop":["ALL"]},"seccompProfile":{"type":"RuntimeDefault"}
                },
                "resources":{"requests":resources,"limits":resources},
                "volumeMounts":[
                    {"name":"workspace","mountPath":"/workspace","readOnly":false},
                    {"name":"tmp","mountPath":"/tmp","readOnly":false},
                    {"name":"run","mountPath":"/run","readOnly":false}
                ]
            }],
            "volumes":[
                {"name":"workspace","persistentVolumeClaim":{"claimName":pvc_name(context.workspace_id),"readOnly":false}},
                {"name":"tmp","emptyDir":{"sizeLimit":quantity_mib(config.tmp_size_mib)}},
                {"name":"run","emptyDir":{"sizeLimit":"64Mi"}}
            ]
        }
    })).map_err(|_| ManifestError::Encoding)?;
    // Persistent storage has stable ownership across launches. It deliberately
    // has no Pod ownerReference, launch label or generation label.
    let mut pvc_object = json!({
        "apiVersion":"v1","kind":"PersistentVolumeClaim",
        "metadata":{"name":pvc_name(context.workspace_id),"namespace":context.namespace,"labels":stable_labels},
        "spec": {
            "accessModes":["ReadWriteOnce"],"storageClassName":context.storage_class,"volumeMode":"Filesystem",
            "resources":{"requests":{"storage":quantity_mib(context.workspace_size_gib * 1024)}}
        }
    });
    if let Some(snapshot) = &context.workspace_snapshot {
        pvc_object["spec"]["dataSource"] =
            json!({"apiGroup":"snapshot.storage.k8s.io","kind":"VolumeSnapshot","name":snapshot});
    }
    let pvc: PersistentVolumeClaim =
        serde_json::from_value(pvc_object).map_err(|_| ManifestError::Encoding)?;
    let mut dns_selector = BTreeMap::new();
    dns_selector.insert(
        "k8s:io.kubernetes.pod.namespace".to_owned(),
        config.dns_namespace.clone(),
    );
    for (key, value) in &config.dns_labels {
        dns_selector.insert(format!("k8s:{key}"), value.clone());
    }
    // Stable instance selector protects every generation. The namespace-level
    // always-deny baseline must exist before this policy or any Pod is created.
    let network_policy: DynamicObject = serde_json::from_value(json!({
        "apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy",
        "metadata":{"name":network_policy_name(context.workspace_id),"namespace":context.namespace,"labels":stable_labels},
        "spec": {
            "endpointSelector":{"matchLabels":{"sandbox.platform/instance-id":context.instance_id.to_string()}},
            "enableDefaultDeny":{"ingress":true,"egress":true},
            "ingress":[],
            "egress":[{"toEndpoints":[{"matchLabels":dns_selector}],"toPorts":[{"ports":[{"port":"53","protocol":"UDP"},{"port":"53","protocol":"TCP"}]}]}]
        }
    })).map_err(|_| ManifestError::Encoding)?;
    Ok(RuntimeManifests {
        pod,
        pvc,
        network_policy,
    })
}

/// Verify an object obtained from the API; never adopt a same-name object based
/// on name alone. Once recorded, its UID must be supplied by the caller.
pub fn validate_existing_pod(
    existing: &Pod,
    expected: &Pod,
    expected_uid: Option<&str>,
) -> Result<(), ManifestError> {
    validate_metadata(&existing.metadata, &expected.metadata, expected_uid)?;
    // Kata and CNI annotations can change runtime/network behavior without
    // changing PodSpec. This baseline creates none and adopts none.
    if existing
        .metadata
        .annotations
        .as_ref()
        .is_some_and(|values| !values.is_empty())
    {
        return Err(ManifestError::SpecificationDrift(
            "unexpected Pod annotations",
        ));
    }
    if !existing
        .metadata
        .finalizers
        .as_ref()
        .is_some_and(|values| values.iter().any(|value| value == TERMINATION_FINALIZER))
    {
        return Err(ManifestError::SpecificationDrift(
            "missing termination finalizer",
        ));
    }
    let mut actual = serde_json::to_value(&existing.spec).map_err(|_| ManifestError::Encoding)?;
    let mut desired = serde_json::to_value(&expected.spec).map_err(|_| ManifestError::Encoding)?;
    // These two fields are filled by trusted Kubernetes admission/scheduling.
    // All container, privilege, volume, selector, DNS and service-account fields
    // still require exact equality; an injected sidecar is never adopted.
    let spec = actual
        .as_object_mut()
        .ok_or(ManifestError::SpecificationDrift("missing Pod spec"))?;
    spec.remove("nodeName");
    if let Some(overhead) = spec.remove("overhead") {
        let values = overhead
            .as_object()
            .ok_or(ManifestError::SpecificationDrift("runtime overhead"))?;
        if values.keys().any(|key| key != "cpu" && key != "memory") {
            return Err(ManifestError::SpecificationDrift(
                "runtime overhead resources",
            ));
        }
    }
    // Kubernetes records the effective priority even without a PriorityClass.
    if spec.get("priority") == Some(&json!(0)) {
        spec.remove("priority");
    }
    // v1 conversion returns this deprecated alias with the same account name.
    if spec.get("serviceAccount") == spec.get("serviceAccountName") {
        spec.remove("serviceAccount");
    }
    normalize_pod_defaults(&mut actual);
    normalize_pod_defaults(&mut desired);
    if actual != desired {
        return Err(ManifestError::SpecificationDrift("Pod spec"));
    }
    Ok(())
}

pub fn validate_existing_pvc(
    existing: &PersistentVolumeClaim,
    expected: &PersistentVolumeClaim,
    expected_uid: Option<&str>,
) -> Result<(), ManifestError> {
    validate_metadata(&existing.metadata, &expected.metadata, expected_uid)?;
    let mut actual = serde_json::to_value(&existing.spec).map_err(|_| ManifestError::Encoding)?;
    let desired = serde_json::to_value(&expected.spec).map_err(|_| ManifestError::Encoding)?;
    // Binding assigns volumeName. The worker separately checks the PV/CSI/cloud
    // volume identity and attachment evidence before treating it as usable.
    let spec = actual
        .as_object_mut()
        .ok_or(ManifestError::SpecificationDrift("missing PVC spec"))?;
    spec.remove("volumeName");
    if let Some(reference) = spec.remove("dataSourceRef")
        && (spec.get("dataSource") != Some(&reference) || reference.get("namespace").is_some())
    {
        return Err(ManifestError::SpecificationDrift("PVC datasource alias"));
    }
    if actual != desired {
        return Err(ManifestError::SpecificationDrift("PVC spec"));
    }
    Ok(())
}

pub fn validate_existing_policy(
    existing: &DynamicObject,
    expected: &DynamicObject,
    expected_uid: Option<&str>,
) -> Result<(), ManifestError> {
    validate_metadata(&existing.metadata, &expected.metadata, expected_uid)?;
    if existing.types != expected.types {
        return Err(ManifestError::SpecificationDrift("network policy type"));
    }
    let mut actual = existing.data.clone();
    if let Some(object) = actual.as_object_mut() {
        object.remove("status");
    }
    if actual != expected.data {
        return Err(ManifestError::SpecificationDrift("network policy spec"));
    }
    Ok(())
}

fn stable_labels(context: &RuntimeManifestContext) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "app.kubernetes.io/managed-by".to_owned(),
            "sandbox-platform".to_owned(),
        ),
        (
            format!("{LABEL_PREFIX}tenant-id"),
            context.tenant_id.to_string(),
        ),
        (
            format!("{LABEL_PREFIX}project-id"),
            context.project_id.to_string(),
        ),
        (
            format!("{LABEL_PREFIX}instance-id"),
            context.instance_id.to_string(),
        ),
        (
            format!("{LABEL_PREFIX}workspace-id"),
            context.workspace_id.to_string(),
        ),
    ])
}

fn validate_metadata(
    actual: &ObjectMeta,
    expected: &ObjectMeta,
    expected_uid: Option<&str>,
) -> Result<(), ManifestError> {
    if actual.name != expected.name || actual.namespace != expected.namespace {
        return Err(ManifestError::OwnershipMismatch("namespace/name"));
    }
    let actual_uid = actual
        .uid
        .as_deref()
        .filter(|uid| !uid.is_empty())
        .ok_or(ManifestError::OwnershipMismatch("missing API UID"))?;
    if expected_uid.is_some_and(|uid| uid != actual_uid) {
        return Err(ManifestError::OwnershipMismatch("UID"));
    }
    if actual.deletion_timestamp.is_some() {
        return Err(ManifestError::Deleting);
    }
    if actual
        .owner_references
        .as_ref()
        .is_some_and(|refs| !refs.is_empty())
    {
        return Err(ManifestError::OwnershipMismatch(
            "unexpected ownerReference",
        ));
    }
    let actual_labels = actual
        .labels
        .as_ref()
        .ok_or(ManifestError::OwnershipMismatch("labels"))?;
    let expected_labels = expected
        .labels
        .as_ref()
        .ok_or(ManifestError::OwnershipMismatch("expected labels"))?;
    if expected_labels
        .iter()
        .any(|(key, value)| actual_labels.get(key) != Some(value))
        || actual_labels
            .keys()
            .any(|key| key.starts_with(LABEL_PREFIX) && !expected_labels.contains_key(key))
    {
        return Err(ManifestError::OwnershipMismatch("labels"));
    }
    Ok(())
}

fn validate_context(
    context: &RuntimeManifestContext,
    config: &RuntimeManifestConfig,
) -> Result<(), ManifestError> {
    if [
        context.tenant_id,
        context.project_id,
        context.instance_id,
        context.workspace_id,
        context.launch_id,
        context.cluster_epoch,
    ]
    .iter()
    .any(Uuid::is_nil)
        || context.generation < 1
    {
        return Err(ManifestError::InvalidConfiguration("identity/generation"));
    }
    if !dns_label(&context.namespace) || !dns_subdomain(&context.storage_class) {
        return Err(ManifestError::InvalidConfiguration(
            "namespace/storage class",
        ));
    }
    if context.workspace_snapshot.as_ref().is_some_and(|snapshot| {
        snapshot
            .strip_prefix("sbx-rs-")
            .and_then(|id| Uuid::parse_str(id).ok())
            .is_none_or(|id| id.is_nil() || snapshot != &format!("sbx-rs-{id}"))
    }) {
        return Err(ManifestError::InvalidConfiguration(
            "restore snapshot identity",
        ));
    }
    if config.runtime_class_name != "kata-qemu" {
        return Err(ManifestError::InvalidConfiguration(
            "only certified kata-qemu is supported",
        ));
    }
    if !dns_label(&config.dns_namespace)
        || config.dns_labels.is_empty()
        || config.dns_labels.iter().any(|(key, value)| {
            !label_key(key) || !label_value(value) || key == "io.kubernetes.pod.namespace"
        })
    {
        return Err(ManifestError::InvalidConfiguration(
            "explicit DNS endpoint selector",
        ));
    }
    if !context.template_approved || !context.security_policy_approved {
        return Err(ManifestError::ApprovalRequired);
    }
    if context.security_policy_rules != json!({"profile":"deny-all","dns":true}) {
        return Err(ManifestError::InvalidConfiguration(
            "unsupported security policy rules",
        ));
    }
    let digest = context
        .image_digest
        .strip_prefix("sha256:")
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
    if digest.is_none()
        || !context.image_ref.contains('/')
        || context.image_ref.contains('@')
        || context.image_ref.chars().any(char::is_whitespace)
        || context.image_ref.contains("://")
        || context.image_ref.starts_with('/')
        || context.image_ref.ends_with('/')
        || context.image_ref.len() > 2048
    {
        return Err(ManifestError::InvalidImage);
    }
    if !matches!(
        (context.cpu_millis, context.memory_mib),
        (1000, 2048) | (2000, 4096) | (4000, 8192)
    ) || !(20..=1024).contains(&context.workspace_size_gib)
        || !(128..=32768).contains(&config.ephemeral_storage_mib)
        || config.tmp_size_mib < 1
        || config.tmp_size_mib > config.ephemeral_storage_mib - 64
    {
        return Err(ManifestError::InvalidConfiguration("resource bounds"));
    }
    Ok(())
}

fn dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}
pub(crate) fn quantity_mib(value: i64) -> String {
    if value % (1024 * 1024) == 0 {
        format!("{}Ti", value / (1024 * 1024))
    } else if value % 1024 == 0 {
        format!("{}Gi", value / 1024)
    } else {
        format!("{value}Mi")
    }
}

fn normalize_pod_defaults(spec: &mut Value) {
    // Go's v1 encoder omits these non-pointer false fields. Missing and false
    // are equivalent here, unlike automountToken, service links or escalation.
    for field in ["hostNetwork", "hostPID", "hostIPC"] {
        remove_false(spec, field);
    }
    if let Some(containers) = spec.get_mut("containers").and_then(Value::as_array_mut) {
        for container in containers {
            for field in ["stdin", "stdinOnce", "tty"] {
                remove_false(container, field);
            }
            if let Some(mounts) = container
                .get_mut("volumeMounts")
                .and_then(Value::as_array_mut)
            {
                for mount in mounts {
                    remove_false(mount, "readOnly");
                }
            }
        }
    }
    if let Some(volumes) = spec.get_mut("volumes").and_then(Value::as_array_mut) {
        for volume in volumes {
            if let Some(source) = volume.get_mut("persistentVolumeClaim") {
                remove_false(source, "readOnly");
            }
        }
    }
}

fn remove_false(value: &mut Value, field: &str) {
    if value.get(field) == Some(&Value::Bool(false))
        && let Some(object) = value.as_object_mut()
    {
        object.remove(field);
    }
}
fn dns_subdomain(value: &str) -> bool {
    value.len() <= 253 && value.split('.').all(dns_label)
}
fn label_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}
fn label_key(value: &str) -> bool {
    match value.split_once('/') {
        Some((prefix, name)) => dns_subdomain(prefix) && label_value(name),
        None => label_value(value),
    }
}
