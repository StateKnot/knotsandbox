//! Fresh, read-only observations immediately before committing an exec attempt.
//! These checks do not prove CNI enforcement or VM termination. CONNECT admission
//! revalidates live authority and consumes the durable, one-use dispatch receipt.

use k8s_openapi::api::core::v1::{Node, PersistentVolume, PersistentVolumeClaim, Pod};
use kube::{
    Api,
    core::{ApiResource, DynamicObject, GroupVersionKind},
};
use uuid::Uuid;

use crate::{
    execution::DispatchIdentity,
    runtime::{KubernetesRuntime, RuntimeError},
    runtime_manifest::{
        ManifestError, RuntimeManifestConfig, RuntimeManifestContext, build_manifests,
        container_name, network_policy_name, pod_name, pvc_name, validate_existing_policy,
        validate_existing_pvc,
    },
};

/// All three identities must come from the durable external-resource ledger.
#[derive(Debug, Clone)]
pub struct KnownRuntimeResources {
    pub pod_uid: Uuid,
    pub pvc_uid: String,
    pub policy_uid: String,
}

#[derive(Debug)]
pub struct VerifiedRuntime {
    pub identity: DispatchIdentity,
    pub namespace: String,
    pub pod_name: String,
    pub container: String,
}

/// Fresh scheduled resources, shared by the launch gate and execution verifier.
pub(crate) struct ScheduledRuntime {
    pub verified: VerifiedRuntime,
    pub pod: Pod,
    pub pvc: PersistentVolumeClaim,
    pub volume: PersistentVolume,
    pub node: Node,
    pub resources: crate::runtime::VerifiedPodResources,
}

#[derive(Clone)]
pub struct GatewayRuntime {
    runtime: KubernetesRuntime,
    manifests: RuntimeManifestConfig,
    certification_id: String,
}

impl GatewayRuntime {
    pub fn new(
        runtime: KubernetesRuntime,
        manifests: RuntimeManifestConfig,
        certification_id: String,
    ) -> Self {
        Self {
            runtime,
            manifests,
            certification_id,
        }
    }

    /// Never creates, adopts, repairs or opens a connection to a workload. Any
    /// disappearance, replacement, drift or incomplete observation fails closed.
    pub async fn verify(
        &self,
        context: &RuntimeManifestContext,
        known: &KnownRuntimeResources,
    ) -> Result<VerifiedRuntime, RuntimeError> {
        let scheduled = self.verify_scheduled(context, known).await?;
        require(
            scheduled.pod.status.as_ref().is_some_and(|s| {
                s.phase.as_deref() == Some("Running")
                    && s.conditions.as_ref().is_some_and(|cs| {
                        cs.iter().any(|c| c.type_ == "Ready" && c.status == "True")
                    })
                    && s.container_statuses.as_ref().is_some_and(|cs| {
                        cs.len() == 1
                            && cs[0].name == scheduled.verified.container
                            && cs[0].ready
                            && cs[0].state.as_ref().is_some_and(|s| {
                                s.running.is_some() && s.terminated.is_none() && s.waiting.is_none()
                            })
                    })
            }),
            "current workload is not Ready",
        )?;
        Ok(scheduled.verified)
    }

    pub(crate) async fn verify_scheduled(
        &self,
        context: &RuntimeManifestContext,
        known: &KnownRuntimeResources,
    ) -> Result<ScheduledRuntime, RuntimeError> {
        if known.pod_uid.is_nil() || known.pvc_uid.is_empty() || known.policy_uid.is_empty() {
            return Err(RuntimeError::MissingIdentity);
        }
        let expected = build_manifests(context, &self.manifests)?;
        self.runtime
            .verify_namespace(context, &self.certification_id)
            .await?;
        let client = self.runtime.client_clone();
        let policies: Api<DynamicObject> = Api::namespaced_with(
            client.clone(),
            &context.namespace,
            &ApiResource::from_gvk(&GroupVersionKind::gvk(
                "cilium.io",
                "v2",
                "CiliumNetworkPolicy",
            )),
        );
        let policy = policies
            .get(&network_policy_name(context.workspace_id))
            .await?;
        validate_existing_policy(&policy, &expected.network_policy, Some(&known.policy_uid))?;

        let pvcs: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), &context.namespace);
        let pvc = pvcs.get(&pvc_name(context.workspace_id)).await?;
        validate_existing_pvc(&pvc, &expected.pvc, Some(&known.pvc_uid))?;
        require(
            pvc.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Bound"),
            "workspace is not Bound",
        )?;
        let volume_name = pvc
            .spec
            .as_ref()
            .and_then(|s| s.volume_name.as_deref())
            .filter(|v| !v.is_empty())
            .ok_or(ManifestError::SpecificationDrift("missing bound volume"))?;
        let volumes: Api<PersistentVolume> = Api::all(client.clone());
        let volume = volumes.get(volume_name).await?;
        require(
            volume.metadata.uid.as_ref().is_some_and(|v| !v.is_empty())
                && volume.metadata.deletion_timestamp.is_none()
                && volume.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Bound")
                && volume.spec.as_ref().is_some_and(|s| {
                    s.storage_class_name.as_deref() == Some(context.storage_class.as_str())
                        && s.volume_mode.as_deref() == Some("Filesystem")
                        && s.access_modes.as_deref() == Some(&["ReadWriteOnce".to_owned()])
                        && s.csi
                            .as_ref()
                            .is_some_and(|c| !c.driver.is_empty() && !c.volume_handle.is_empty())
                        && s.claim_ref.as_ref().is_some_and(|claim| {
                            claim.uid.as_deref() == Some(known.pvc_uid.as_str())
                                && claim.namespace.as_deref() == Some(context.namespace.as_str())
                                && claim.name == pvc.metadata.name
                                && claim.kind.as_deref() == Some("PersistentVolumeClaim")
                        })
                }),
            "bound volume identity differs from the workspace",
        )?;

        let name = pod_name(context.workspace_id);
        let readback = self
            .runtime
            .read_pod(&expected.pod, &known.pod_uid.to_string())
            .await?;
        let pod = readback.pod;
        let container = container_name(context.launch_id);
        let node_name = pod
            .spec
            .as_ref()
            .and_then(|s| s.node_name.as_deref())
            .filter(|v| !v.is_empty())
            .ok_or(ManifestError::SpecificationDrift(
                "workload is not scheduled",
            ))?;
        let nodes: Api<Node> = Api::all(client);
        let node = nodes.get(node_name).await?;
        require(
            node.metadata.uid.as_ref().is_some_and(|v| !v.is_empty())
                && node.metadata.deletion_timestamp.is_none()
                && node
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|l| l.get("sandbox.platform/worker-pool"))
                    .map(String::as_str)
                    == Some("kata")
                && node.spec.as_ref().is_some_and(|s| {
                    s.unschedulable != Some(true)
                        && s.taints.as_ref().is_some_and(|ts| {
                            ts.iter().any(|t| {
                                t.key == "sandbox.platform/untrusted"
                                    && t.value.as_deref() == Some("true")
                                    && t.effect == "NoSchedule"
                            }) && ts.iter().all(|t| {
                                t.effect != "NoExecute"
                                    && (t.effect != "NoSchedule"
                                        || (t.key == "sandbox.platform/untrusted"
                                            && t.value.as_deref() == Some("true")))
                            })
                        })
                })
                && node
                    .status
                    .as_ref()
                    .and_then(|s| s.conditions.as_ref())
                    .is_some_and(|cs| cs.iter().any(|c| c.type_ == "Ready" && c.status == "True")),
            "execution node is not an available dedicated Kata node",
        )?;
        Ok(ScheduledRuntime {
            pod,
            pvc,
            volume,
            node,
            resources: readback.resources,
            verified: VerifiedRuntime {
                identity: DispatchIdentity {
                    runtime_generation: context.generation,
                    launch_id: context.launch_id,
                    pod_uid: known.pod_uid,
                    cluster_epoch: context.cluster_epoch,
                },
                namespace: context.namespace.clone(),
                pod_name: name,
                container,
            },
        })
    }
}

fn require(valid: bool, detail: &'static str) -> Result<(), RuntimeError> {
    if valid {
        Ok(())
    } else {
        Err(ManifestError::SpecificationDrift(detail).into())
    }
}
