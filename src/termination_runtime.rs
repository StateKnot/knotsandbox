//! Kubernetes cleanup follows host termination; Kubernetes object absence alone
//! is never accepted as evidence of VM death or of cloud instance fencing.
#[cfg(test)]
#[path = "termination_runtime_tests.rs"]
mod tests;
use chrono::{DateTime, Utc};
use k8s_openapi::api::{
    core::v1::{PersistentVolume, PersistentVolumeClaim, Pod},
    storage::v1::VolumeAttachment,
};
use kube::{
    Api,
    api::{DeleteParams, ListParams, Patch, PatchParams, Preconditions},
};
use serde_json::json;
use uuid::Uuid;

use crate::{
    gateway_runtime::{GatewayRuntime, KnownRuntimeResources},
    nodeguard::protocol::{LaunchBinding, NodeBinding},
    runtime::{KubernetesRuntime, RuntimeError},
    runtime_manifest::{
        ManifestError, RuntimeManifestConfig, RuntimeManifestContext, TERMINATION_FINALIZER,
        pvc_name,
    },
    termination_client::VerifiedLocalTermination,
};

const CSI_DRIVER: &str = "diskplugin.csi.alibabacloud.com";

#[derive(Clone)]
pub struct TerminationRuntime {
    runtime: KubernetesRuntime,
    verifier: GatewayRuntime,
}

pub struct ObservedLaunch {
    pub node: NodeBinding,
    pub launch: LaunchBinding,
    pub resources: VerifiedLaunchResources,
}

/// The trusted API readback and the exact scheduled launch/node identity travel
/// together. Only observe_launch can mint this capability after every runtime
/// check; public JSON, manifests and nodeguard resource claims cannot mint it.
pub struct VerifiedLaunchResources {
    node: NodeBinding,
    launch: LaunchBinding,
    record: LaunchResourceRecord,
    observed_at: DateTime<Utc>,
}

/// Read-only values for the database adapter. Possessing or deserializing these
/// scalars alone does not construct a VerifiedLaunchResources capability.
pub(crate) struct LaunchResourceRecord {
    pub(crate) pod_resource_version: String,
    pub(crate) runtime_class_uid: Uuid,
    pub(crate) runtime_class_resource_version: String,
    pub(crate) runtime_class_config_sha256: String,
    pub(crate) workload_request_cpu_millis: i64,
    pub(crate) workload_request_memory_bytes: i64,
    pub(crate) workload_request_ephemeral_bytes: i64,
    pub(crate) workload_limit_cpu_millis: i64,
    pub(crate) workload_limit_memory_bytes: i64,
    pub(crate) workload_limit_ephemeral_bytes: i64,
    pub(crate) pod_overhead_cpu_millis: i64,
    pub(crate) pod_overhead_memory_bytes: i64,
    pub(crate) effective_request_cpu_millis: i64,
    pub(crate) effective_request_memory_bytes: i64,
    pub(crate) effective_request_ephemeral_bytes: i64,
    pub(crate) effective_limit_cpu_millis: i64,
    pub(crate) effective_limit_memory_bytes: i64,
    pub(crate) effective_limit_ephemeral_bytes: i64,
    pub(crate) class_overhead_cpu_millis: i64,
    pub(crate) class_overhead_memory_bytes: i64,
}

impl VerifiedLaunchResources {
    pub(crate) fn node(&self) -> &NodeBinding {
        &self.node
    }
    pub(crate) fn launch(&self) -> &LaunchBinding {
        &self.launch
    }
    pub(crate) fn record(&self) -> &LaunchResourceRecord {
        &self.record
    }
    pub(crate) fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

/// Constructed only after authenticated host evidence and fresh, exact-identity
/// API observations. No boolean/JSON ingress can manufacture this capability.
pub struct VerifiedPodCleanup {
    node: NodeBinding,
    launch: LaunchBinding,
    challenge_id: Uuid,
    resource_version: Option<String>,
    pod_absent_at: DateTime<Utc>,
    volume_checked_at: DateTime<Utc>,
}
impl VerifiedPodCleanup {
    pub(crate) fn node(&self) -> &NodeBinding {
        &self.node
    }
    pub(crate) fn launch(&self) -> &LaunchBinding {
        &self.launch
    }
    pub(crate) fn proof_challenge_id(&self) -> Uuid {
        self.challenge_id
    }
    pub(crate) fn pod_resource_version(&self) -> Option<&str> {
        self.resource_version.as_deref()
    }
    pub(crate) fn pod_absent_at(&self) -> DateTime<Utc> {
        self.pod_absent_at
    }
    pub(crate) fn volume_checked_at(&self) -> DateTime<Utc> {
        self.volume_checked_at
    }
}

impl TerminationRuntime {
    pub fn new(
        runtime: KubernetesRuntime,
        manifests: RuntimeManifestConfig,
        certification_id: String,
    ) -> Self {
        let verifier = GatewayRuntime::new(runtime.clone(), manifests, certification_id);
        Self { runtime, verifier }
    }

    pub async fn observe_launch(
        &self,
        context: &RuntimeManifestContext,
        known: &KnownRuntimeResources,
    ) -> Result<ObservedLaunch, RuntimeError> {
        let resources = self.verifier.verify_scheduled(context, known).await?;
        let node = NodeBinding {
            cluster_epoch: context.cluster_epoch,
            node_uid: parse_id(resources.node.metadata.uid.as_deref())?,
            node_name: resources
                .node
                .metadata
                .name
                .clone()
                .ok_or(RuntimeError::MissingIdentity)?,
            boot_id: parse_id(
                resources
                    .node
                    .status
                    .as_ref()
                    .and_then(|s| s.node_info.as_ref())
                    .map(|i| i.boot_id.as_str()),
            )?,
            profile_sha256: resources
                .node
                .metadata
                .annotations
                .as_ref()
                .and_then(|a| a.get("sandbox.platform/runtime-profile-sha256"))
                .cloned()
                .ok_or(RuntimeError::MissingIdentity)?,
        };
        let spec = resources
            .volume
            .spec
            .as_ref()
            .ok_or(RuntimeError::MissingIdentity)?;
        let csi = spec.csi.as_ref().ok_or(RuntimeError::MissingIdentity)?;
        require(
            csi.driver == CSI_DRIVER
                && spec.persistent_volume_reclaim_policy.as_deref() == Some("Retain"),
            "unapproved CSI driver or reclaim policy",
        )?;
        let launch = LaunchBinding {
            purpose: crate::nodeguard::protocol::LaunchPurpose::Workload,
            tenant_id: context.tenant_id,
            project_id: context.project_id,
            instance_id: context.instance_id,
            workspace_id: context.workspace_id,
            generation: context.generation,
            launch_id: context.launch_id,
            pod_uid: known.pod_uid,
            namespace: context.namespace.clone(),
            pod_name: resources.verified.pod_name,
            pvc_uid: parse_id(resources.pvc.metadata.uid.as_deref())?,
            pv_uid: parse_id(resources.volume.metadata.uid.as_deref())?,
            pv_name: resources
                .volume
                .metadata
                .name
                .ok_or(RuntimeError::MissingIdentity)?,
            csi_volume_handle: csi.volume_handle.clone(),
        };
        require(
            node.validate() && launch.validate(),
            "invalid scheduled identity binding",
        )?;
        require(
            resources.resources.pod_uid() == launch.pod_uid
                && resources.resources.node_name() == Some(node.node_name.as_str()),
            "resource observation differs from scheduled launch",
        )?;
        let quantities = resources.resources.quantities();
        let class = resources.resources.class();
        let record = LaunchResourceRecord {
            pod_resource_version: resources.resources.pod_resource_version().to_owned(),
            runtime_class_uid: class.uid(),
            runtime_class_resource_version: class.resource_version().to_owned(),
            runtime_class_config_sha256: class.config_sha256(),
            workload_request_cpu_millis: quantities.workload_cpu_millis(),
            workload_request_memory_bytes: quantities.workload_memory_bytes(),
            workload_request_ephemeral_bytes: quantities.workload_ephemeral_bytes(),
            // Both maps were independently parsed and equality was required by
            // the fixed ordinary CPU contract. No limit is inferred unchecked.
            workload_limit_cpu_millis: quantities.workload_cpu_millis(),
            workload_limit_memory_bytes: quantities.workload_memory_bytes(),
            workload_limit_ephemeral_bytes: quantities.workload_ephemeral_bytes(),
            pod_overhead_cpu_millis: quantities.overhead_cpu_millis(),
            pod_overhead_memory_bytes: quantities.overhead_memory_bytes(),
            effective_request_cpu_millis: quantities.effective_cpu_millis(),
            effective_request_memory_bytes: quantities.effective_memory_bytes(),
            effective_request_ephemeral_bytes: quantities.workload_ephemeral_bytes(),
            effective_limit_cpu_millis: quantities.effective_cpu_millis(),
            effective_limit_memory_bytes: quantities.effective_memory_bytes(),
            effective_limit_ephemeral_bytes: quantities.workload_ephemeral_bytes(),
            class_overhead_cpu_millis: quantities.class_overhead_cpu_millis(),
            class_overhead_memory_bytes: quantities.class_overhead_memory_bytes(),
        };
        let verified_resources = VerifiedLaunchResources {
            node: node.clone(),
            launch: launch.clone(),
            record,
            observed_at: resources.resources.observed_at(),
        };
        Ok(ObservedLaunch {
            node,
            launch,
            resources: verified_resources,
        })
    }

    /// Requests ordinary Kubernetes shutdown while the independent host gate
    /// closes. No finalizer or evidence is released here. Repeated requests
    /// preserve the exact UID and normal grace period.
    pub async fn request_stop(
        &self,
        node: &NodeBinding,
        launch: &LaunchBinding,
    ) -> Result<(), RuntimeError> {
        require(
            node.validate() && launch.validate(),
            "invalid termination target",
        )?;
        let pods: Api<Pod> = Api::namespaced(self.runtime.client_clone(), &launch.namespace);
        let Some(pod) = pods.get_opt(&launch.pod_name).await? else {
            return Ok(());
        };
        validate_pod_identity(&pod, node, launch)?;
        if pod.metadata.deletion_timestamp.is_none() {
            let rv = pod
                .metadata
                .resource_version
                .clone()
                .ok_or(RuntimeError::MissingIdentity)?;
            let params = DeleteParams {
                grace_period_seconds: Some(30),
                preconditions: Some(Preconditions {
                    uid: Some(launch.pod_uid.to_string()),
                    resource_version: Some(rv),
                }),
                ..Default::default()
            };
            pods.delete(&launch.pod_name, &params).await?;
        }
        Ok(())
    }

    /// One bounded observation, without a polling sleep or background task.
    /// Pending finalizers/attachments retain all activity and quota reservations.
    pub async fn cleanup(
        &self,
        proof: &VerifiedLocalTermination,
    ) -> Result<Option<VerifiedPodCleanup>, RuntimeError> {
        fresh(proof)?;
        let node = proof.node();
        let launch = proof.launch();
        let pods: Api<Pod> = Api::namespaced(self.runtime.client_clone(), &launch.namespace);
        let mut resource_version = None;
        if let Some(pod) = pods.get_opt(&launch.pod_name).await? {
            validate_pod_identity(&pod, node, launch)?;
            require(
                pod.metadata.deletion_timestamp.is_some(),
                "Pod deletion was not accepted",
            )?;
            let finalizers = pod.metadata.finalizers.as_deref().unwrap_or(&[]);
            require(
                finalizers.is_empty() || finalizers == [TERMINATION_FINALIZER],
                "unexpected Pod finalizer",
            )?;
            let rv = pod
                .metadata
                .resource_version
                .clone()
                .ok_or(RuntimeError::MissingIdentity)?;
            if !finalizers.is_empty() {
                let patch =
                    json!({"metadata":{"uid":launch.pod_uid,"resourceVersion":rv,"finalizers":[]}});
                pods.patch(
                    &launch.pod_name,
                    &PatchParams::default(),
                    &Patch::Merge(patch),
                )
                .await?;
            }
            resource_version = Some(rv);
        }
        if let Some(pod) = pods.get_opt(&launch.pod_name).await? {
            validate_pod_identity(&pod, node, launch)?;
            return Ok(None);
        }
        let pod_absent_at = Utc::now();
        self.verify_volume_binding(launch).await?;
        let attachments: Api<VolumeAttachment> = Api::all(self.runtime.client_clone());
        let mut token = String::new();
        let mut exhausted = false;
        for _ in 0..100 {
            let mut params = ListParams::default().limit(100);
            if !token.is_empty() {
                params = params.continue_token(&token);
            }
            let page = attachments.list(&params).await?;
            if page
                .items
                .iter()
                .any(|a| a.spec.source.persistent_volume_name.as_deref() == Some(&launch.pv_name))
            {
                return Ok(None);
            }
            token = page.metadata.continue_.unwrap_or_default();
            if token.is_empty() {
                exhausted = true;
                break;
            }
        }
        require(
            exhausted,
            "volume attachment observation exceeded bounded inventory",
        )?;
        // Check the immutable PVC/PV identities again after the paginated list.
        self.verify_volume_binding(launch).await?;
        if pods.get_opt(&launch.pod_name).await?.is_some() {
            return Err(ManifestError::OwnershipMismatch("Pod name reused during cleanup").into());
        }
        fresh(proof)?;
        Ok(Some(VerifiedPodCleanup {
            node: node.clone(),
            launch: launch.clone(),
            challenge_id: proof.challenge_id(),
            resource_version,
            pod_absent_at,
            volume_checked_at: Utc::now(),
        }))
    }

    async fn verify_volume_binding(&self, launch: &LaunchBinding) -> Result<(), RuntimeError> {
        let claims: Api<PersistentVolumeClaim> =
            Api::namespaced(self.runtime.client_clone(), &launch.namespace);
        let pvc = claims.get(&pvc_name(launch.workspace_id)).await?;
        require(
            parse_id(pvc.metadata.uid.as_deref())? == launch.pvc_uid
                && pvc.metadata.deletion_timestamp.is_none()
                && pvc
                    .spec
                    .as_ref()
                    .is_some_and(|s| s.volume_name.as_deref() == Some(&launch.pv_name))
                && pvc.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Bound"),
            "workspace PVC identity changed",
        )?;
        let volumes: Api<PersistentVolume> = Api::all(self.runtime.client_clone());
        let pv = volumes.get(&launch.pv_name).await?;
        require(
            parse_id(pv.metadata.uid.as_deref())? == launch.pv_uid
                && pv.metadata.deletion_timestamp.is_none()
                && pv.spec.as_ref().is_some_and(|s| {
                    s.csi.as_ref().is_some_and(|c| {
                        c.driver == CSI_DRIVER && c.volume_handle == launch.csi_volume_handle
                    }) && s.volume_mode.as_deref() == Some("Filesystem")
                        && s.access_modes.as_deref() == Some(&["ReadWriteOnce".to_owned()])
                        && s.persistent_volume_reclaim_policy.as_deref() == Some("Retain")
                        && s.claim_ref.as_ref().is_some_and(|c| {
                            c.uid.as_deref() == Some(&launch.pvc_uid.to_string())
                                && c.namespace.as_deref() == Some(&launch.namespace)
                                && c.name.as_deref() == Some(&pvc_name(launch.workspace_id))
                        })
                }),
            "persistent volume identity or retained-workspace policy changed",
        )?;
        Ok(())
    }
}

fn validate_pod_identity(
    pod: &Pod,
    node: &NodeBinding,
    launch: &LaunchBinding,
) -> Result<(), RuntimeError> {
    require(
        parse_id(pod.metadata.uid.as_deref())? == launch.pod_uid
            && pod.metadata.name.as_deref() == Some(&launch.pod_name)
            && pod.metadata.namespace.as_deref() == Some(&launch.namespace)
            && pod.spec.as_ref().is_some_and(|s| {
                s.node_name.as_deref() == Some(&node.node_name)
                    && s.runtime_class_name.as_deref() == Some("kata-qemu")
            }),
        "current Pod is not the terminated launch",
    )?;
    for (key, value) in [
        ("tenant-id", launch.tenant_id.to_string()),
        ("project-id", launch.project_id.to_string()),
        ("instance-id", launch.instance_id.to_string()),
        ("workspace-id", launch.workspace_id.to_string()),
        ("generation", launch.generation.to_string()),
        ("launch-id", launch.launch_id.to_string()),
        ("cluster-epoch", node.cluster_epoch.to_string()),
    ] {
        require(
            pod.metadata
                .labels
                .as_ref()
                .and_then(|l| l.get(&format!("sandbox.platform/{key}")))
                == Some(&value),
            "Pod ownership label changed",
        )?;
    }
    Ok(())
}
fn parse_id(value: Option<&str>) -> Result<Uuid, RuntimeError> {
    value
        .and_then(|s| Uuid::parse_str(s).ok())
        .filter(|id| !id.is_nil())
        .ok_or(RuntimeError::MissingIdentity)
}
fn fresh(proof: &VerifiedLocalTermination) -> Result<(), RuntimeError> {
    let now = Utc::now();
    require(
        proof.observed_at() <= now + chrono::Duration::seconds(2)
            && proof.observed_at() > now - chrono::Duration::seconds(30),
        "fresh host termination observation required",
    )
}
fn require(value: bool, detail: &'static str) -> Result<(), RuntimeError> {
    if value {
        Ok(())
    } else {
        Err(ManifestError::SpecificationDrift(detail).into())
    }
}
