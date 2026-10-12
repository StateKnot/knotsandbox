//! Trusted backup launch and cleanup observations. Only live Kubernetes reads
//! plus a verified nodeguard channel can construct these capabilities.
use crate::{
    backup_admission::verify_pod_object,
    backup_job::BackupJobRuntime,
    backup_ledger::JobPlan,
    backup_manifest::{NAMESPACE, block_pvc_name},
    backup_runtime::BoundBackupVolume,
    nodeguard::protocol::{BackupStage, LaunchBinding, LaunchPurpose, NodeBinding},
    runtime::RuntimeError,
    runtime_manifest::{ManifestError, TERMINATION_FINALIZER},
    termination_client::VerifiedLocalTermination,
};
use chrono::{DateTime, Utc};
use k8s_openapi::api::{
    core::v1::{Node, PersistentVolume, PersistentVolumeClaim, Pod},
    storage::v1::VolumeAttachment,
};
use kube::{
    Api,
    api::{DeleteParams, ListParams, Patch, PatchParams, Preconditions},
};
use serde_json::{Value, json};
use uuid::Uuid;

pub(crate) struct VerifiedBackupLaunch {
    pub node: NodeBinding,
    pub launch: LaunchBinding,
    pub observed_at: DateTime<Utc>,
    // Only this module's actual I/O may create an observation.
    _private: (),
}
pub(crate) struct VerifiedBackupCleanup {
    pub node: NodeBinding,
    pub launch: LaunchBinding,
    pub challenge_id: Uuid,
    pub pod_absent_at: DateTime<Utc>,
    pub volume_checked_at: DateTime<Utc>,
    _private: (),
}
fn require(ok: bool, why: &'static str) -> Result<(), RuntimeError> {
    if ok {
        Ok(())
    } else {
        Err(ManifestError::SpecificationDrift(why).into())
    }
}
fn id(v: Option<&str>) -> Result<Uuid, RuntimeError> {
    v.and_then(|s| Uuid::parse_str(s).ok())
        .filter(|u| !u.is_nil())
        .ok_or(RuntimeError::MissingIdentity)
}
fn encode(v: &impl serde::Serialize) -> Result<Value, RuntimeError> {
    serde_json::to_value(v).map_err(|_| RuntimeError::MissingIdentity)
}
pub(crate) fn node_binding(node: &Node, epoch: Uuid) -> Result<NodeBinding, RuntimeError> {
    let spec = node.spec.as_ref().ok_or(RuntimeError::MissingIdentity)?;
    require(
        node.metadata.deletion_timestamp.is_none()
            && node.metadata.labels.as_ref().is_some_and(|l| {
                ["sandbox.platform/node-pool", "sandbox.platform/worker-pool"]
                    .iter()
                    .all(|key| l.get(*key).is_some_and(|v| v == "kata"))
            })
            && spec.unschedulable != Some(true)
            && node
                .status
                .as_ref()
                .and_then(|s| s.conditions.as_ref())
                .is_some_and(|c| c.iter().any(|x| x.type_ == "Ready" && x.status == "True")),
        "backup node not ready",
    )?;
    let taints = spec.taints.as_deref().unwrap_or_default();
    require(
        taints.iter().any(|t| {
            t.key == "sandbox.platform/untrusted"
                && t.value.as_deref() == Some("true")
                && t.effect == "NoSchedule"
        }) && taints.iter().all(|t| {
            !matches!(t.effect.as_str(), "NoSchedule" | "NoExecute")
                || (t.key == "sandbox.platform/untrusted"
                    && t.value.as_deref() == Some("true")
                    && t.effect == "NoSchedule")
        }),
        "backup node is not certified dedicated pool",
    )?;
    let value = NodeBinding {
        cluster_epoch: epoch,
        node_uid: id(node.metadata.uid.as_deref())?,
        node_name: node
            .metadata
            .name
            .clone()
            .ok_or(RuntimeError::MissingIdentity)?,
        boot_id: id(node
            .status
            .as_ref()
            .and_then(|s| s.node_info.as_ref())
            .map(|i| i.boot_id.as_str()))?,
        profile_sha256: node
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get("sandbox.platform/runtime-profile-sha256"))
            .cloned()
            .ok_or(RuntimeError::MissingIdentity)?,
    };
    require(value.validate(), "backup node identity invalid")?;
    Ok(value)
}
impl BackupJobRuntime {
    pub(crate) async fn observe_launch(
        &self,
        plan: &JobPlan,
        pod_name: &str,
        volume: Option<&BoundBackupVolume>,
    ) -> Result<VerifiedBackupLaunch, RuntimeError> {
        self.verify_network(&plan.cloud).await?;
        self.verify_profile_secrets(&plan.cloud).await?;
        let job = plan.known_job.ok_or(RuntimeError::MissingIdentity)?;
        let pod_uid = plan.known_pod.ok_or(RuntimeError::MissingIdentity)?;
        let pods = Api::<Pod>::namespaced(self.runtime().client_clone(), NAMESPACE);
        let pod = pods.get(pod_name).await?;
        verify_pod_object(&encode(&pod)?, &plan.context, job, pod_uid)
            .map_err(|_| ManifestError::SpecificationDrift("backup launch Pod drift"))?;
        let node_name = pod
            .spec
            .as_ref()
            .and_then(|s| s.node_name.as_deref())
            .ok_or(RuntimeError::MissingIdentity)?;
        let nodes = Api::<Node>::all(self.runtime().client_clone());
        let node = node_binding(&nodes.get(node_name).await?, plan.backup.cluster_epoch)?;
        let (pvc_uid, pv_uid, pv_name, csi_volume_handle) = match plan.context.stage {
            BackupStage::Capture => {
                self.verify_clone_storage(&plan.clone_storage_class, &plan.cloud)
                    .await?;
                let v = volume.ok_or(RuntimeError::MissingIdentity)?;
                self.verify_block_binding(plan.context.attempt_id, v)
                    .await?;
                (v.pvc_uid, v.pv_uid, v.pv_name.clone(), v.cloud_disk.clone())
            }
            BackupStage::Seal => {
                require(volume.is_none(), "SEAL must have no tenant volume")?;
                (Uuid::nil(), Uuid::nil(), String::new(), String::new())
            }
            BackupStage::Restore => {
                return Err(
                    ManifestError::InvalidConfiguration("restore controller not enabled").into(),
                );
            }
        };
        let source = plan
            .backup
            .source()
            .map_err(|_| RuntimeError::MissingIdentity)?;
        let launch = LaunchBinding {
            purpose: LaunchPurpose::Backup {
                backup_id: plan.backup.id,
                attempt_id: plan.context.attempt_id,
                job_uid: job,
                stage: plan.context.stage,
                image_ref: plan.context.image.clone(),
                source_pvc_uid: source.pvc_uid,
            },
            tenant_id: plan.backup.tenant_id,
            project_id: plan.backup.project_id,
            instance_id: plan.backup.instance_id,
            workspace_id: plan.backup.workspace_id,
            generation: plan.backup.source_generation,
            launch_id: plan.context.attempt_id,
            pod_uid,
            namespace: NAMESPACE.into(),
            pod_name: pod_name.into(),
            pvc_uid,
            pv_uid,
            pv_name,
            csi_volume_handle,
        };
        require(launch.validate(), "invalid backup launch binding")?;
        let again = pods.get(pod_name).await?;
        verify_pod_object(&encode(&again)?, &plan.context, job, pod_uid)
            .map_err(|_| ManifestError::SpecificationDrift("backup launch Pod changed"))?;
        require(
            again.spec.as_ref().and_then(|s| s.node_name.as_deref()) == Some(node_name)
                && node_binding(&nodes.get(node_name).await?, plan.backup.cluster_epoch)? == node,
            "backup node changed during observation",
        )?;
        Ok(VerifiedBackupLaunch {
            node,
            launch,
            observed_at: Utc::now(),
            _private: (),
        })
    }
    pub(crate) async fn verify_block_binding(
        &self,
        attempt: Uuid,
        v: &BoundBackupVolume,
    ) -> Result<(), RuntimeError> {
        let name = block_pvc_name(attempt);
        let pvc =
            Api::<PersistentVolumeClaim>::namespaced(self.runtime().client_clone(), NAMESPACE)
                .get(&name)
                .await?;
        require(
            id(pvc.metadata.uid.as_deref())? == v.pvc_uid
                && pvc.metadata.deletion_timestamp.is_none()
                && pvc.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Bound")
                && pvc.spec.as_ref().is_some_and(|s| {
                    s.volume_name.as_deref() == Some(&v.pv_name)
                        && s.volume_mode.as_deref() == Some("Block")
                }),
            "backup block claim changed",
        )?;
        let pv = Api::<PersistentVolume>::all(self.runtime().client_clone())
            .get(&v.pv_name)
            .await?;
        require(
            id(pv.metadata.uid.as_deref())? == v.pv_uid
                && pv.metadata.deletion_timestamp.is_none()
                && pv.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Bound")
                && pv.spec.as_ref().is_some_and(|s| {
                    s.volume_mode.as_deref() == Some("Block")
                        && s.persistent_volume_reclaim_policy.as_deref() == Some("Retain")
                        && s.access_modes.as_deref() == Some(&["ReadWriteOnce".to_owned()])
                        && s.csi.as_ref().is_some_and(|c| {
                            c.driver == "diskplugin.csi.alibabacloud.com"
                                && c.volume_handle == v.cloud_disk
                        })
                        && s.claim_ref.as_ref().is_some_and(|r| {
                            r.uid.as_deref() == Some(v.pvc_uid.to_string().as_str())
                                && r.name.as_deref() == Some(&name)
                                && r.namespace.as_deref() == Some(NAMESPACE)
                        })
                }),
            "backup block volume changed",
        )?;
        Ok(())
    }
    /// Deletion retains the finalizer and therefore never constitutes termination.
    pub(crate) async fn request_close(
        &self,
        plan: &JobPlan,
        launch: &LaunchBinding,
    ) -> Result<(), RuntimeError> {
        let pods = Api::<Pod>::namespaced(self.runtime().client_clone(), NAMESPACE);
        let Some(pod) = pods.get_opt(&launch.pod_name).await? else {
            return Ok(());
        };
        verify_cleanup_pod(&pod, plan, launch)?;
        if pod.metadata.deletion_timestamp.is_none() {
            pods.delete(
                &launch.pod_name,
                &DeleteParams {
                    grace_period_seconds: Some(30),
                    preconditions: Some(Preconditions {
                        uid: Some(launch.pod_uid.to_string()),
                        resource_version: pod.metadata.resource_version.clone(),
                    }),
                    ..Default::default()
                },
            )
            .await?;
        }
        Ok(())
    }
    pub(crate) async fn finish_cleanup(
        &self,
        plan: &JobPlan,
        proof: &VerifiedLocalTermination,
    ) -> Result<Option<VerifiedBackupCleanup>, RuntimeError> {
        fresh(proof)?;
        let launch = proof.launch();
        require(
            launch.launch_id == plan.context.attempt_id
                && launch.tenant_id == plan.backup.tenant_id,
            "backup cleanup proof mismatch",
        )?;
        let pods = Api::<Pod>::namespaced(self.runtime().client_clone(), NAMESPACE);
        if let Some(pod) = pods.get_opt(&launch.pod_name).await? {
            verify_cleanup_pod(&pod, plan, launch)?;
            require(
                pod.spec.as_ref().and_then(|p| p.node_name.as_deref())
                    == Some(proof.node().node_name.as_str()),
                "Cleanup Pod assigned node differs from trusted proof",
            )?;
            require(
                pod.metadata.deletion_timestamp.is_some(),
                "backup Pod deletion not accepted",
            )?;
            // Job tracking may coexist. The reviewed Job controller may remove only
            // its own finalizer; nodeguard proof authorizes only our protection.
            let before = pod.metadata.finalizers.as_deref().unwrap_or_default();
            require(
                before
                    .iter()
                    .all(|s| s == TERMINATION_FINALIZER || s == "batch.kubernetes.io/job-tracking"),
                "unknown backup finalizer",
            )?;
            let after: Vec<_> = before
                .iter()
                .filter(|s| s.as_str() != TERMINATION_FINALIZER)
                .cloned()
                .collect();
            if after.len() != before.len() {
                let rv = pod
                    .metadata
                    .resource_version
                    .ok_or(RuntimeError::MissingIdentity)?;
                let patch = json!({"metadata":{"uid":launch.pod_uid,"resourceVersion":rv,"finalizers":after}});
                pods.patch(
                    &launch.pod_name,
                    &PatchParams::default(),
                    &Patch::Merge(patch),
                )
                .await?;
            }
        }
        if let Some(pod) = pods.get_opt(&launch.pod_name).await? {
            verify_cleanup_pod(&pod, plan, launch)?;
            return Ok(None);
        }
        let pod_absent_at = Utc::now();
        if matches!(
            launch.purpose,
            LaunchPurpose::Backup {
                stage: BackupStage::Capture,
                ..
            }
        ) {
            let volume = BoundBackupVolume {
                pvc_uid: launch.pvc_uid,
                pv_uid: launch.pv_uid,
                pv_name: launch.pv_name.clone(),
                cloud_disk: launch.csi_volume_handle.clone(),
                size_bytes: plan
                    .backup
                    .source()
                    .map_err(|_| RuntimeError::MissingIdentity)?
                    .size_bytes,
            };
            self.verify_block_binding(launch.launch_id, &volume).await?;
            let attachments = Api::<VolumeAttachment>::all(self.runtime().client_clone());
            let mut token = String::new();
            let mut complete = false;
            for _ in 0..100 {
                let mut params = ListParams::default().limit(100);
                if !token.is_empty() {
                    params = params.continue_token(&token)
                }
                let page = attachments.list(&params).await?;
                if page.items.iter().any(|a| {
                    a.spec.source.persistent_volume_name.as_deref() == Some(launch.pv_name.as_str())
                }) {
                    return Ok(None);
                }
                token = page.metadata.continue_.unwrap_or_default();
                if token.is_empty() {
                    complete = true;
                    break;
                }
            }
            require(
                complete,
                "backup volume attachment inventory exceeded bound",
            )?;
            self.verify_block_binding(launch.launch_id, &volume).await?;
        }
        require(
            pods.get_opt(&launch.pod_name).await?.is_none(),
            "backup Pod reappeared during cleanup",
        )?;
        fresh(proof)?;
        Ok(Some(VerifiedBackupCleanup {
            node: proof.node().clone(),
            launch: launch.clone(),
            challenge_id: proof.challenge_id(),
            pod_absent_at,
            volume_checked_at: Utc::now(),
            _private: (),
        }))
    }
}
fn verify_cleanup_pod(
    pod: &Pod,
    plan: &JobPlan,
    launch: &LaunchBinding,
) -> Result<(), RuntimeError> {
    let mut value = encode(pod)?;
    if let Some(meta) = value.get_mut("metadata").and_then(Value::as_object_mut) {
        meta.remove("deletionTimestamp");
        meta.remove("deletionGracePeriodSeconds");
        let finals = meta
            .get("finalizers")
            .and_then(Value::as_array)
            .ok_or(RuntimeError::MissingIdentity)?;
        require(
            finals
                .iter()
                .all(|v| v == TERMINATION_FINALIZER || v == "batch.kubernetes.io/job-tracking"),
            "Unknown backup cleanup finalizer",
        )?;
        meta.insert(
            "finalizers".into(),
            json!([TERMINATION_FINALIZER, "batch.kubernetes.io/job-tracking"]),
        );
    }
    verify_pod_object(
        &value,
        &plan.context,
        plan.known_job.ok_or(RuntimeError::MissingIdentity)?,
        launch.pod_uid,
    )
    .map_err(|_| ManifestError::SpecificationDrift("backup cleanup Pod drift"))?;
    require(
        pod.spec
            .as_ref()
            .and_then(|s| s.node_name.as_deref())
            .is_some(),
        "backup cleanup Pod node absent",
    )
}
fn fresh(proof: &VerifiedLocalTermination) -> Result<(), RuntimeError> {
    let age = Utc::now() - proof.observed_at();
    require(
        age.num_seconds() >= -2 && age.num_seconds() <= 25,
        "backup termination proof expired",
    )
}
