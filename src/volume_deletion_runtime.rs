//! UID-bound Kubernetes cleanup. A successful DELETE response is never evidence
//! of physical disk destruction; the caller must first persist cloud absence.
use crate::{cloud_fencing::CloudDiskBinding, runtime::KubernetesRuntime};
use chrono::{DateTime, Utc};
use k8s_openapi::api::{
    core::v1::{Namespace, PersistentVolume, PersistentVolumeClaim, Pod},
    storage::v1::{StorageClass, VolumeAttachment},
};
use kube::{
    Api, Client,
    api::{DeleteParams, ListParams, Preconditions},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceStorageProfile {
    pub storage_class: String,
    pub kms_key_id: String,
    pub zones: Vec<String>,
    pub deployment: String,
    pub certification_id: String,
}
#[derive(Clone, Debug)]
pub(crate) struct VolumeTarget {
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub workspace_id: Uuid,
    pub cluster_epoch: Uuid,
    pub namespace: String,
    pub pvc_name: String,
    pub storage_class: String,
    pub size_gib: u32,
    pub pvc_uid: Uuid,
    pub pv_uid: Uuid,
    pub pv_name: String,
    pub handle: String,
    pub account_id: String,
    pub region: String,
}
#[derive(Clone)]
pub struct VolumeDeletionRuntime {
    client: Client,
    profile: WorkspaceStorageProfile,
}
pub(crate) struct VerifiedVolumePresent {
    pub binding: CloudDiskBinding,
}
pub(crate) struct VerifiedVolumeCleanup {
    pvc_uid: Uuid,
    pv_uid: Uuid,
    pvc_absent_at: DateTime<Utc>,
    pv_absent_at: DateTime<Utc>,
}
impl VerifiedVolumeCleanup {
    pub(crate) fn identities(&self) -> (Uuid, Uuid) {
        (self.pvc_uid, self.pv_uid)
    }
    pub(crate) fn observations(&self) -> (DateTime<Utc>, DateTime<Utc>) {
        (self.pvc_absent_at, self.pv_absent_at)
    }
}
impl VolumeDeletionRuntime {
    pub fn new(
        runtime: KubernetesRuntime,
        profile: WorkspaceStorageProfile,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !profile.storage_class.is_empty()
                && !profile.kms_key_id.is_empty()
                && !profile.deployment.is_empty()
                && !profile.certification_id.is_empty()
                && !profile.zones.is_empty()
                && profile.zones.len() <= 32,
            "Storage deletion profile is incomplete"
        );
        Ok(Self {
            client: runtime.client_clone(),
            profile,
        })
    }
    async fn namespace(&self, t: &VolumeTarget) -> anyhow::Result<()> {
        let ns = Api::<Namespace>::all(self.client.clone())
            .get(&t.namespace)
            .await?;
        let labels = ns
            .metadata
            .labels
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Namespace ownership missing"))?;
        for (key, value) in [
            ("sandbox.platform/managed", "true".into()),
            ("sandbox.platform/tenant-id", t.tenant_id.to_string()),
            ("sandbox.platform/project-id", t.project_id.to_string()),
            (
                "sandbox.platform/cluster-epoch",
                t.cluster_epoch.to_string(),
            ),
        ] {
            anyhow::ensure!(
                labels.get(key) == Some(&value),
                "Namespace identity changed"
            );
        }
        anyhow::ensure!(
            ns.metadata
                .annotations
                .as_ref()
                .and_then(|a| a.get("sandbox.platform/certification-id"))
                == Some(&self.profile.certification_id),
            "Namespace certification changed"
        );
        Ok(())
    }
    async fn no_writers(&self, t: &VolumeTarget) -> anyhow::Result<()> {
        let pods = Api::<Pod>::namespaced(self.client.clone(), &t.namespace);
        let mut params = ListParams::default().limit(100);
        for page in 0..100 {
            let rows = pods.list(&params).await?;
            anyhow::ensure!(
                !rows.items.iter().any(|p| p
                    .spec
                    .as_ref()
                    .and_then(|s| s.volumes.as_ref())
                    .is_some_and(|v| v.iter().any(|v| v
                        .persistent_volume_claim
                        .as_ref()
                        .is_some_and(|c| c.claim_name == t.pvc_name)))),
                "A Pod still references this workspace"
            );
            match rows.metadata.continue_ {
                Some(token) if !token.is_empty() => {
                    anyhow::ensure!(page < 99, "Pod inventory exceeds verification bound");
                    params = params.continue_token(&token);
                }
                _ => break,
            }
        }
        let attachments = Api::<VolumeAttachment>::all(self.client.clone());
        let mut params = ListParams::default().limit(100);
        for page in 0..100 {
            let rows = attachments.list(&params).await?;
            anyhow::ensure!(
                !rows
                    .items
                    .iter()
                    .any(|v| v.spec.source.persistent_volume_name.as_deref() == Some(&t.pv_name)),
                "A volume attachment still exists"
            );
            match rows.metadata.continue_ {
                Some(token) if !token.is_empty() => {
                    anyhow::ensure!(page < 99, "Attachment inventory exceeds verification bound");
                    params = params.continue_token(&token);
                }
                _ => break,
            }
        }
        Ok(())
    }
    fn pvc(
        &self,
        t: &VolumeTarget,
        p: &PersistentVolumeClaim,
        allow_deleting: bool,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            p.metadata.uid.as_deref() == Some(t.pvc_uid.to_string().as_str())
                && (allow_deleting || p.metadata.deletion_timestamp.is_none()),
            "PVC identity changed"
        );
        let s = p
            .spec
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("PVC spec missing"))?;
        anyhow::ensure!(
            s.volume_name.as_deref() == Some(&t.pv_name)
                && s.storage_class_name.as_deref() == Some(&t.storage_class)
                && s.volume_mode.as_deref() == Some("Filesystem")
                && s.access_modes.as_deref() == Some(&["ReadWriteOnce".into()]),
            "PVC binding changed"
        );
        Ok(())
    }
    fn pv(
        &self,
        t: &VolumeTarget,
        p: &PersistentVolume,
        allow_deleting: bool,
    ) -> anyhow::Result<String> {
        anyhow::ensure!(
            p.metadata.uid.as_deref() == Some(t.pv_uid.to_string().as_str())
                && (allow_deleting || p.metadata.deletion_timestamp.is_none()),
            "PV identity changed"
        );
        let s = p
            .spec
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("PV spec missing"))?;
        let claim = s
            .claim_ref
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("PV claim reference missing"))?;
        let csi = s
            .csi
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("PV CSI source missing"))?;
        anyhow::ensure!(
            s.persistent_volume_reclaim_policy.as_deref() == Some("Retain")
                && s.storage_class_name.as_deref() == Some(&t.storage_class)
                && s.volume_mode.as_deref() == Some("Filesystem")
                && s.access_modes.as_deref() == Some(&["ReadWriteOnce".into()])
                && claim.namespace.as_deref() == Some(&t.namespace)
                && claim.name.as_deref() == Some(&t.pvc_name)
                && claim.uid.as_deref() == Some(t.pvc_uid.to_string().as_str())
                && csi.driver == "diskplugin.csi.alibabacloud.com"
                && csi.volume_handle == t.handle,
            "PV storage or claim binding changed"
        );
        anyhow::ensure!(
            s.capacity
                .as_ref()
                .and_then(|c| c.get("storage"))
                .is_some_and(
                    |q| q.0 == crate::runtime_manifest::quantity_mib(i64::from(t.size_gib) * 1024)
                ),
            "PV capacity differs from the charged workspace"
        );
        let terms = s
            .node_affinity
            .as_ref()
            .and_then(|a| a.required.as_ref())
            .ok_or_else(|| anyhow::anyhow!("PV zone affinity missing"))?;
        let mut zones = std::collections::BTreeSet::new();
        for term in &terms.node_selector_terms {
            let matches = term
                .match_expressions
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("PV zone affinity missing"))?;
            let z: Vec<_> = matches
                .iter()
                .filter(|e| e.key == "topology.diskplugin.csi.alibabacloud.com/zone")
                .collect();
            anyhow::ensure!(
                z.len() == 1
                    && z[0].operator == "In"
                    && z[0].values.as_ref().is_some_and(|v| v.len() == 1),
                "PV zone must be explicit and singular"
            );
            if let Some(values) = &z[0].values {
                zones.extend(values.iter().cloned());
            }
        }
        anyhow::ensure!(zones.len() == 1, "PV zone is ambiguous");
        let zone = zones
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("PV zone missing"))?;
        anyhow::ensure!(
            self.profile.zones.contains(&zone),
            "PV zone is outside the reviewed storage profile"
        );
        Ok(zone)
    }
    pub(crate) async fn observe(&self, t: &VolumeTarget) -> anyhow::Result<VerifiedVolumePresent> {
        self.namespace(t).await?;
        anyhow::ensure!(
            t.pvc_name == format!("ws-{}", t.workspace_id),
            "Workspace PVC name binding changed"
        );
        anyhow::ensure!(
            t.storage_class == self.profile.storage_class,
            "Unexpected storage class"
        );
        let class = Api::<StorageClass>::all(self.client.clone())
            .get(&t.storage_class)
            .await?;
        let params = class
            .parameters
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Storage class parameters missing"))?;
        anyhow::ensure!(
            class.provisioner == "diskplugin.csi.alibabacloud.com"
                && class.reclaim_policy.as_deref() == Some("Retain")
                && params.get("encrypted").map(String::as_str) == Some("true")
                && params.get("kmsKeyId") == Some(&self.profile.kms_key_id)
                && params.get("diskTags/Deployment") == Some(&self.profile.deployment),
            "Storage class security profile changed"
        );
        let pvc = Api::<PersistentVolumeClaim>::namespaced(self.client.clone(), &t.namespace)
            .get(&t.pvc_name)
            .await?;
        let pv = Api::<PersistentVolume>::all(self.client.clone())
            .get(&t.pv_name)
            .await?;
        self.pvc(t, &pvc, false)?;
        let zone = self.pv(t, &pv, false)?;
        self.no_writers(t).await?;
        Ok(VerifiedVolumePresent {
            binding: CloudDiskBinding {
                account_id: t.account_id.clone(),
                region: t.region.clone(),
                disk_id: t.handle.clone(),
                zone_id: zone,
                deployment: self.profile.deployment.clone(),
                namespace: t.namespace.clone(),
                pvc_name: t.pvc_name.clone(),
                pv_name: t.pv_name.clone(),
                kms_key_id: self.profile.kms_key_id.clone(),
                size_gib: t.size_gib,
            },
        })
    }
    /// Called only after the durable cloud-absence receipt. UID preconditions
    /// prevent deletion of a replacement object that reuses a resource name.
    pub(crate) async fn cleanup(
        &self,
        t: &VolumeTarget,
    ) -> anyhow::Result<Option<VerifiedVolumeCleanup>> {
        self.namespace(t).await?;
        self.no_writers(t).await?;
        let pvcs = Api::<PersistentVolumeClaim>::namespaced(self.client.clone(), &t.namespace);
        let pvs = Api::<PersistentVolume>::all(self.client.clone());
        if let Some(pvc) = pvcs.get_opt(&t.pvc_name).await? {
            self.pvc(t, &pvc, true)?;
            if pvc.metadata.deletion_timestamp.is_none() {
                pvcs.delete(
                    &t.pvc_name,
                    &DeleteParams {
                        preconditions: Some(Preconditions {
                            uid: Some(t.pvc_uid.to_string()),
                            resource_version: pvc.metadata.resource_version,
                        }),
                        ..Default::default()
                    },
                )
                .await?;
            }
            return Ok(None);
        }
        let pvc_absent_at = Utc::now();
        if let Some(pv) = pvs.get_opt(&t.pv_name).await? {
            self.pv(t, &pv, true)?;
            if pv.metadata.deletion_timestamp.is_none() {
                pvs.delete(
                    &t.pv_name,
                    &DeleteParams {
                        preconditions: Some(Preconditions {
                            uid: Some(t.pv_uid.to_string()),
                            resource_version: pv.metadata.resource_version,
                        }),
                        ..Default::default()
                    },
                )
                .await?;
            }
            return Ok(None);
        }
        self.no_writers(t).await?;
        Ok(Some(VerifiedVolumeCleanup {
            pvc_uid: t.pvc_uid,
            pv_uid: t.pv_uid,
            pvc_absent_at,
            pv_absent_at: Utc::now(),
        }))
    }
}
