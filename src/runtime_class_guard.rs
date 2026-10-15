//! A live configuration observation, not proof of a historical admission
//! decision or a particular API server's informer revision. Cluster operators
//! own the policy; workload identities have GET-only access to its fixed name.

use std::collections::BTreeMap;

use k8s_openapi::{
    api::{
        admissionregistration::v1::{ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding},
        node::v1::RuntimeClass,
    },
    apimachinery::pkg::{api::resource::Quantity, apis::meta::v1::ObjectMeta},
};
use kube::{Api, Client};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::runtime::RuntimeError;

const GUARD_NAME: &str = "sandbox-kata-runtimeclass-v1";
const CLASS_NAME: &str = "kata-qemu";

#[derive(Deserialize)]
struct GuardContract {
    policy: ValidatingAdmissionPolicy,
    binding: ValidatingAdmissionPolicyBinding,
}

/// No public constructor/Deserialize: only successful live reads produce this
/// value. RVs are opaque metadata; equality of configuration deliberately does
/// not require equal RVs after an unrelated status/metadata update.
pub(crate) struct ManagedRuntimeClass {
    class: RuntimeClass,
    class_uid: Uuid,
    policy_uid: Uuid,
    binding_uid: Uuid,
    content_sha256: [u8; 32],
}

impl ManagedRuntimeClass {
    pub(crate) fn same_configuration(&self, other: &Self) -> bool {
        self.class_uid == other.class_uid
            && self.policy_uid == other.policy_uid
            && self.binding_uid == other.binding_uid
            && self.content_sha256 == other.content_sha256
    }

    pub(crate) fn overhead(&self) -> Option<&BTreeMap<String, Quantity>> {
        self.class
            .overhead
            .as_ref()
            .and_then(|o| o.pod_fixed.as_ref())
    }
}

fn identity(meta: &ObjectMeta, name: &str) -> Result<Uuid, RuntimeError> {
    let uid = meta.uid.as_deref().and_then(|s| Uuid::parse_str(s).ok());
    if meta.name.as_deref() != Some(name)
        || meta.deletion_timestamp.is_some()
        || uid.is_none_or(|id| id.is_nil())
        || !meta.resource_version.as_deref().is_some_and(|rv| {
            !rv.is_empty() && rv.len() <= 256 && rv.bytes().all(|b| (33..=126).contains(&b))
        })
    {
        return Err(RuntimeError::InvalidRuntimeClass);
    }
    uid.ok_or(RuntimeError::InvalidRuntimeClass)
}

fn validate_guard(
    policy: &ValidatingAdmissionPolicy,
    binding: &ValidatingAdmissionPolicyBinding,
) -> Result<(Uuid, Uuid), RuntimeError> {
    let expected: GuardContract =
        serde_json::from_str(include_str!("../deploy/runtime-class-guard/guard.json"))
            .map_err(|_| RuntimeError::InvalidRuntimeClass)?;
    let policy_uid = identity(&policy.metadata, GUARD_NAME)?;
    let binding_uid = identity(&binding.metadata, GUARD_NAME)?;
    if policy.spec != expected.policy.spec
        || binding.spec != expected.binding.spec
        || !policy.metadata.generation.is_some_and(|g| g > 0)
        || !policy.status.as_ref().is_some_and(|status| {
            status.observed_generation == policy.metadata.generation
                && status.type_checking.as_ref().is_some_and(|checking| {
                    checking
                        .expression_warnings
                        .as_ref()
                        .is_none_or(Vec::is_empty)
                })
        })
    {
        return Err(RuntimeError::InvalidRuntimeClass);
    }
    Ok((policy_uid, binding_uid))
}

fn validate(
    class: RuntimeClass,
    policy: &ValidatingAdmissionPolicy,
    binding: &ValidatingAdmissionPolicyBinding,
) -> Result<ManagedRuntimeClass, RuntimeError> {
    let class_uid = identity(&class.metadata, CLASS_NAME)?;
    let (policy_uid, binding_uid) = validate_guard(policy, binding)?;
    if class.handler != CLASS_NAME
        || class
            .scheduling
            .as_ref()
            .and_then(|s| s.node_selector.as_ref())
            .and_then(|s| s.get("sandbox.platform/worker-pool"))
            .map(String::as_str)
            != Some("kata")
    {
        return Err(RuntimeError::InvalidRuntimeClass);
    }
    crate::runtime_resource_contract::validate_overhead(
        class.overhead.as_ref().and_then(|o| o.pod_fixed.as_ref()),
    )
    .map_err(|_| RuntimeError::InvalidRuntimeClass)?;
    let canonical = serde_json::to_vec(&serde_json::json!({
        "handler":class.handler, "overhead":class.overhead, "scheduling":class.scheduling,
    }))
    .map_err(|_| RuntimeError::InvalidRuntimeClass)?;
    if canonical.len() > 16 * 1024 {
        return Err(RuntimeError::InvalidRuntimeClass);
    }
    Ok(ManagedRuntimeClass {
        class,
        class_uid,
        policy_uid,
        binding_uid,
        content_sha256: Sha256::digest(canonical).into(),
    })
}

/// Call on both sides of a Pod read and compare the returned configuration.
/// No list/watch/cache or error-to-zero fallback is used. This observes the
/// guard's current configuration, not its historical installation time.
pub(crate) async fn read(client: Client) -> Result<ManagedRuntimeClass, RuntimeError> {
    // Typed Kubernetes GET state is large in unoptimized builds. Keep the
    // repeated I/O state off the worker/gateway task's bounded thread stack.
    Box::pin(read_inner(client)).await
}

async fn read_inner(client: Client) -> Result<ManagedRuntimeClass, RuntimeError> {
    let policies: Api<ValidatingAdmissionPolicy> = Api::all(client.clone());
    let bindings: Api<ValidatingAdmissionPolicyBinding> = Api::all(client.clone());
    let classes: Api<RuntimeClass> = Api::all(client);
    let policy = policies.get(GUARD_NAME).await?;
    let binding = bindings.get(GUARD_NAME).await?;
    let class = classes.get(CLASS_NAME).await?;
    validate(class, &policy, &binding)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> (
        RuntimeClass,
        ValidatingAdmissionPolicy,
        ValidatingAdmissionPolicyBinding,
    ) {
        let mut guard: GuardContract =
            serde_json::from_str(include_str!("../deploy/runtime-class-guard/guard.json")).unwrap();
        for (i, meta) in [&mut guard.policy.metadata, &mut guard.binding.metadata]
            .into_iter()
            .enumerate()
        {
            meta.uid = Some(Uuid::from_u128(i as u128 + 10).to_string());
            meta.resource_version = Some("opaque:rV-1".into());
            meta.generation = Some(1);
        }
        guard.policy.status = Some(
            serde_json::from_value(json!({
                "observedGeneration":1,"typeChecking":{"expressionWarnings":[]}
            }))
            .unwrap(),
        );
        let class = serde_json::from_value(json!({
            "metadata":{"name":CLASS_NAME,"uid":Uuid::from_u128(1),"resourceVersion":"opaque:rV-1"},
            "handler":CLASS_NAME,"scheduling":{"nodeSelector":{"sandbox.platform/worker-pool":"kata"}},
            "overhead":{"podFixed":{"cpu":"250m","memory":"128Mi"}}
        })).unwrap();
        (class, guard.policy, guard.binding)
    }

    #[test]
    fn identity_and_content_are_pinned_but_opaque_versions_can_advance() {
        let (class, policy, binding) = fixture();
        let first = validate(class.clone(), &policy, &binding).unwrap();
        let mut changed = class.clone();
        changed.metadata.resource_version = Some("not-a-number:2".into());
        assert!(first.same_configuration(&validate(changed, &policy, &binding).unwrap()));
        let mut replaced = class.clone();
        replaced.metadata.uid = Some(Uuid::from_u128(2).to_string());
        assert!(!first.same_configuration(&validate(replaced, &policy, &binding).unwrap()));
        let mut changed = class;
        changed
            .overhead
            .as_mut()
            .unwrap()
            .pod_fixed
            .as_mut()
            .unwrap()
            .insert("cpu".into(), Quantity("251m".into()));
        assert!(!first.same_configuration(&validate(changed, &policy, &binding).unwrap()));
        let mut replaced = binding;
        replaced.metadata.uid = Some(Uuid::from_u128(99).to_string());
        assert!(
            !first.same_configuration(&validate(first.class.clone(), &policy, &replaced).unwrap())
        );
    }

    #[test]
    fn missing_or_weakened_or_unchecked_guard_is_rejected() {
        let (class, policy, binding) = fixture();
        let mut weakened = policy.clone();
        weakened.spec.as_mut().unwrap().failure_policy = Some("Ignore".into());
        assert!(validate(class.clone(), &weakened, &binding).is_err());
        let mut audit_only = binding.clone();
        audit_only.spec.as_mut().unwrap().validation_actions = Some(vec!["Audit".into()]);
        assert!(validate(class.clone(), &policy, &audit_only).is_err());
        let mut unchecked = policy.clone();
        unchecked.status = None;
        assert!(validate(class.clone(), &unchecked, &binding).is_err());
        let mut stale = policy.clone();
        stale.metadata.generation = Some(2);
        assert!(validate(class.clone(), &stale, &binding).is_err());
        for rv in ["", "bad version", &"x".repeat(257)] {
            let mut invalid = class.clone();
            invalid.metadata.resource_version = Some(rv.into());
            assert!(validate(invalid, &policy, &binding).is_err());
        }
    }
}
