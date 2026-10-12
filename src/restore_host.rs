//! Actual host observations for an isolated restore writer. Guest completion,
//! Pod deletion and absence remain insufficient to release target accounting.
use super::{ledger::JobPlan, storage_contract::RestoreStoragePurpose};
use crate::{
    backup_admission::verify_pod_object,
    backup_host::node_binding,
    backup_job::BackupJobRuntime,
    backup_manifest::NAMESPACE,
    backup_object::BackupIdentity,
    backup_runtime::BoundBackupVolume,
    nodeguard::protocol::{BackupStage, LaunchBinding, LaunchPurpose, NodeBinding},
    runtime::RuntimeError,
    runtime_manifest::{ManifestError, TERMINATION_FINALIZER},
    termination_client::VerifiedLocalTermination,
};
use chrono::{DateTime, Utc};
use k8s_openapi::api::{
    core::v1::{Node, Pod},
    storage::v1::VolumeAttachment,
};
use kube::{
    Api,
    api::{DeleteParams, ListParams, Patch, PatchParams, Preconditions},
};
use serde_json::{Value, json};
use uuid::Uuid;

pub(crate) struct VerifiedRestoreLaunch {
    pub node: NodeBinding,
    pub launch: LaunchBinding,
    pub observed_at: DateTime<Utc>,
    _private: (),
}
pub(crate) struct VerifiedRestoreCleanup {
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
fn encode(v: &impl serde::Serialize) -> Result<Value, RuntimeError> {
    serde_json::to_value(v).map_err(|_| RuntimeError::MissingIdentity)
}
fn fresh(proof: &VerifiedLocalTermination) -> Result<(), RuntimeError> {
    let age = Utc::now() - proof.observed_at();
    require(
        (-2..=25).contains(&age.num_seconds()),
        "restore termination proof expired",
    )
}
fn source(plan: &JobPlan) -> Result<BackupIdentity, RuntimeError> {
    serde_json::from_value(plan.record.source_identity.clone())
        .map_err(|_| RuntimeError::MissingIdentity)
}
fn verify_pod(
    pod: &Pod,
    plan: &JobPlan,
    launch: &LaunchBinding,
    cleanup: bool,
) -> Result<(), RuntimeError> {
    let mut value = encode(pod)?;
    if cleanup {
        let metadata = value
            .get_mut("metadata")
            .and_then(Value::as_object_mut)
            .ok_or(RuntimeError::MissingIdentity)?;
        metadata.remove("deletionTimestamp");
        metadata.remove("deletionGracePeriodSeconds");
        let finals = metadata
            .get("finalizers")
            .and_then(Value::as_array)
            .ok_or(RuntimeError::MissingIdentity)?;
        require(
            finals
                .iter()
                .all(|v| v == TERMINATION_FINALIZER || v == "batch.kubernetes.io/job-tracking"),
            "unknown restore cleanup finalizer",
        )?;
        metadata.insert(
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
    .map_err(|_| ManifestError::SpecificationDrift("restore Pod specification drift"))?;
    Ok(())
}
impl BackupJobRuntime {
    pub(crate) async fn observe_restore_launch(
        &self,
        plan: &JobPlan,
        pod_name: &str,
        volume: &BoundBackupVolume,
    ) -> Result<VerifiedRestoreLaunch, RuntimeError> {
        self.verify_network(&plan.cloud).await?;
        self.verify_profile_secrets(&plan.cloud).await?;
        plan.storage_contract.validate_cloud(&plan.cloud)?;
        self.verify_restore_storage_class(&plan.storage_contract, RestoreStoragePurpose::Raw)
            .await?;
        self.verify_block_binding(plan.record.id, volume).await?;
        let source = source(plan)?;
        require(
            plan.context.stage == BackupStage::Restore
                && plan.context.attempt_id == plan.record.id
                && plan.context.backup_id == plan.record.backup_id
                && plan.context.cluster_epoch == plan.record.cluster_epoch
                && source.size_bytes == volume.size_bytes
                && source.source_pvc_uid != volume.pvc_uid
                && source.clone_pvc_uid != volume.pvc_uid,
            "restore launch target reuses historical source or context",
        )?;
        let pods = Api::<Pod>::namespaced(self.runtime().client_clone(), NAMESPACE);
        let pod = pods.get(pod_name).await?;
        let pod_uid = plan.known_pod.ok_or(RuntimeError::MissingIdentity)?;
        let node_name = pod
            .spec
            .as_ref()
            .and_then(|s| s.node_name.as_deref())
            .ok_or(RuntimeError::MissingIdentity)?;
        let nodes = Api::<Node>::all(self.runtime().client_clone());
        let node = node_binding(&nodes.get(node_name).await?, plan.record.cluster_epoch)?;
        let launch = LaunchBinding {
            purpose: LaunchPurpose::Backup {
                backup_id: plan.record.backup_id,
                attempt_id: plan.record.id,
                job_uid: plan.known_job.ok_or(RuntimeError::MissingIdentity)?,
                stage: BackupStage::Restore,
                image_ref: plan.context.image.clone(),
                source_pvc_uid: source.source_pvc_uid,
            },
            tenant_id: plan.record.tenant_id,
            project_id: plan.record.target_project_id,
            instance_id: plan.record.instance_id,
            workspace_id: plan.record.workspace_id,
            generation: 1,
            launch_id: plan.record.id,
            pod_uid,
            namespace: NAMESPACE.into(),
            pod_name: pod_name.into(),
            pvc_uid: volume.pvc_uid,
            pv_uid: volume.pv_uid,
            pv_name: volume.pv_name.clone(),
            csi_volume_handle: volume.cloud_disk.clone(),
        };
        require(launch.validate(), "invalid isolated restore launch binding")?;
        verify_pod(&pod, plan, &launch, false)?;
        let again = pods.get(pod_name).await?;
        verify_pod(&again, plan, &launch, false)?;
        require(
            again.spec.as_ref().and_then(|s| s.node_name.as_deref()) == Some(node_name)
                && node_binding(&nodes.get(node_name).await?, plan.record.cluster_epoch)? == node,
            "restore node changed during observation",
        )?;
        self.verify_block_binding(plan.record.id, volume).await?;
        Ok(VerifiedRestoreLaunch {
            node,
            launch,
            observed_at: Utc::now(),
            _private: (),
        })
    }
    pub(crate) async fn request_restore_close(
        &self,
        plan: &JobPlan,
        launch: &LaunchBinding,
    ) -> Result<(), RuntimeError> {
        let pods = Api::<Pod>::namespaced(self.runtime().client_clone(), NAMESPACE);
        let Some(pod) = pods.get_opt(&launch.pod_name).await? else {
            return Ok(());
        };
        verify_pod(&pod, plan, launch, true)?;
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
    pub(crate) async fn finish_restore_cleanup(
        &self,
        plan: &JobPlan,
        proof: &VerifiedLocalTermination,
    ) -> Result<Option<VerifiedRestoreCleanup>, RuntimeError> {
        fresh(proof)?;
        let launch = proof.launch();
        let source = source(plan)?;
        require(
            launch.tenant_id == plan.record.tenant_id
                && launch.project_id == plan.record.target_project_id
                && launch.instance_id == plan.record.instance_id
                && launch.workspace_id == plan.record.workspace_id
                && launch.launch_id == plan.record.id
                && launch.generation == 1
                && launch.pod_uid == plan.known_pod.ok_or(RuntimeError::MissingIdentity)?
                && launch.namespace == NAMESPACE
                && launch.pvc_uid != source.source_pvc_uid
                && launch.pvc_uid != source.clone_pvc_uid
                && launch.purpose
                    == LaunchPurpose::Backup {
                        backup_id: plan.record.backup_id,
                        attempt_id: plan.record.id,
                        job_uid: plan.known_job.ok_or(RuntimeError::MissingIdentity)?,
                        stage: BackupStage::Restore,
                        image_ref: plan.context.image.clone(),
                        source_pvc_uid: source.source_pvc_uid,
                    }
                && proof.node().cluster_epoch == plan.record.cluster_epoch,
            "restore cleanup proof does not bind this isolated writer",
        )?;
        let pods = Api::<Pod>::namespaced(self.runtime().client_clone(), NAMESPACE);
        if let Some(pod) = pods.get_opt(&launch.pod_name).await? {
            verify_pod(&pod, plan, launch, true)?;
            require(
                pod.spec.as_ref().and_then(|s| s.node_name.as_deref())
                    == Some(proof.node().node_name.as_str())
                    && pod.metadata.deletion_timestamp.is_some(),
                "restore cleanup Pod node or deletion intent changed",
            )?;
            let before = pod.metadata.finalizers.as_deref().unwrap_or_default();
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
                pods.patch(&launch.pod_name,&PatchParams::default(),&Patch::Merge(json!({"metadata":{"uid":launch.pod_uid,"resourceVersion":rv,"finalizers":after}}))).await?;
            }
        }
        if let Some(pod) = pods.get_opt(&launch.pod_name).await? {
            verify_pod(&pod, plan, launch, true)?;
            return Ok(None);
        }
        let pod_absent_at = Utc::now();
        let volume = BoundBackupVolume {
            pvc_uid: launch.pvc_uid,
            pv_uid: launch.pv_uid,
            pv_name: launch.pv_name.clone(),
            cloud_disk: launch.csi_volume_handle.clone(),
            size_bytes: source.size_bytes,
        };
        self.verify_block_binding(plan.record.id, &volume).await?;
        let attachments = Api::<VolumeAttachment>::all(self.runtime().client_clone());
        let mut token = String::new();
        let mut complete = false;
        for _ in 0..100 {
            let mut params = ListParams::default().limit(100);
            if !token.is_empty() {
                params = params.continue_token(&token);
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
            "restore volume attachment inventory exceeded bound",
        )?;
        self.verify_block_binding(plan.record.id, &volume).await?;
        require(
            pods.get_opt(&launch.pod_name).await?.is_none(),
            "restore Pod reappeared during cleanup",
        )?;
        fresh(proof)?;
        Ok(Some(VerifiedRestoreCleanup {
            node: proof.node().clone(),
            launch: launch.clone(),
            challenge_id: proof.challenge_id(),
            pod_absent_at,
            volume_checked_at: Utc::now(),
            _private: (),
        }))
    }
}
