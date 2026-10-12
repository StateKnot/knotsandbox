//! Live CSI observations for a permanently closed restore writer. These private
//! receipts do not publish a workspace or waive the final cleanup requirement.
use super::{
    manifest::{RestoreSnapshotObservation, verify_raw_snapshot},
    snapshot_ledger::{RestoreDeliveryPlan, RestoreSnapshotPlan},
    storage_contract::RestoreStoragePurpose,
};
use crate::{
    backup_job::BackupJobRuntime,
    backup_manifest::NAMESPACE,
    backup_runtime::{BoundBackupVolume, dyn_api, ensure, validate_pv},
    runtime::RuntimeError,
    runtime_manifest::{ManifestError, validate_existing_pvc},
};
use chrono::{DateTime, Utc};
use k8s_openapi::api::{
    core::v1::{Namespace, PersistentVolume, PersistentVolumeClaim, Pod},
    networking::v1::NetworkPolicy,
    storage::v1::VolumeAttachment,
};
use kube::{
    Api,
    api::{ListParams, PostParams},
    core::DynamicObject,
};
use serde_json::{Value, json};
use uuid::Uuid;

pub(crate) struct VerifiedRestoreSnapshot {
    pub tenant_id: Uuid,
    pub restore_id: Uuid,
    pub snapshot_uid: Uuid,
    pub ready: Option<RestoreSnapshotObservation>,
    pub observed_at: DateTime<Utc>,
    _private: (),
}
pub(crate) struct VerifiedRestoreDelivery {
    pub tenant_id: Uuid,
    pub restore_id: Uuid,
    pub snapshot_uid: Uuid,
    pub content_uid: Uuid,
    pub pvc_uid: Uuid,
    pub bound: Option<BoundBackupVolume>,
    pub observed_at: DateTime<Utc>,
    _private: (),
}
fn require(ok: bool, why: &'static str) -> Result<(), RuntimeError> {
    if ok {
        Ok(())
    } else {
        Err(ManifestError::SpecificationDrift(why).into())
    }
}
fn uid(s: Option<&str>) -> Result<Uuid, RuntimeError> {
    s.and_then(|s| Uuid::parse_str(s).ok())
        .filter(|u| !u.is_nil())
        .ok_or(RuntimeError::MissingIdentity)
}
fn encode(v: &impl serde::Serialize) -> Result<Value, RuntimeError> {
    serde_json::to_value(v).map_err(|_| RuntimeError::MissingIdentity)
}
fn object(v: Value) -> Result<DynamicObject, RuntimeError> {
    serde_json::from_value(v).map_err(|_| RuntimeError::MissingIdentity)
}
impl BackupJobRuntime {
    async fn restore_writer_absent(&self, p: &RestoreSnapshotPlan) -> Result<bool, RuntimeError> {
        self.verify_block_binding(p.context.restore_id, &p.raw)
            .await?;
        let pods = Api::<Pod>::namespaced(self.runtime().client_clone(), NAMESPACE);
        if pods.get_opt(&p.closed_pod_name).await?.is_some() {
            return Ok(false);
        }
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
                a.spec.source.persistent_volume_name.as_deref() == Some(p.raw.pv_name.as_str())
            }) {
                return Ok(false);
            }
            token = page.metadata.continue_.unwrap_or_default();
            if token.is_empty() {
                complete = true;
                break;
            }
        }
        require(
            complete,
            "restore snapshot attachment inventory exceeded bound",
        )?;
        self.verify_block_binding(p.context.restore_id, &p.raw)
            .await?;
        Ok(pods.get_opt(&p.closed_pod_name).await?.is_none())
    }
    pub(crate) async fn reconcile_restore_snapshot(
        &self,
        p: &RestoreSnapshotPlan,
    ) -> Result<Option<VerifiedRestoreSnapshot>, RuntimeError> {
        self.verify_network(&p.cloud).await?;
        self.verify_profile_secrets(&p.cloud).await?;
        p.context.storage_contract.validate_cloud(&p.cloud)?;
        self.verify_restore_storage_class(&p.context.storage_contract, RestoreStoragePurpose::Raw)
            .await?;
        require(
            p.closed_at <= Utc::now() && p.raw.size_bytes == p.context.size_bytes,
            "restore snapshot has no closed exact raw device",
        )?;
        if !self.restore_writer_absent(p).await? {
            return Ok(None);
        }
        self.verify_restore_snapshot_class(&p.context.storage_contract)
            .await?;
        let api = dyn_api(self.runtime(), "VolumeSnapshot", Some(NAMESPACE));
        let expected = object(p.context.raw_snapshot()?)?;
        let snapshot = ensure(&api, &expected, p.known_snapshot).await?;
        let snapshot_uid = uid(snapshot.metadata.uid.as_deref())?;
        let value = encode(&snapshot)?;
        require(
            value.pointer("/status/error").is_none_or(Value::is_null),
            "restore raw snapshot reported an error",
        )?;
        let ready = if let Some(name) = value
            .pointer("/status/boundVolumeSnapshotContentName")
            .and_then(Value::as_str)
        {
            let content = dyn_api(self.runtime(), "VolumeSnapshotContent", None)
                .get(name)
                .await?;
            verify_raw_snapshot(
                &p.context,
                &value,
                &encode(&content)?,
                &p.raw.cloud_disk,
                p.closed_at,
                Some(snapshot_uid),
                p.known_content,
            )?
        } else {
            require(
                p.known_content.is_none(),
                "recorded restore content disappeared",
            )?;
            None
        };
        if !self.restore_writer_absent(p).await? {
            return Ok(None);
        }
        // Re-read both immutable CSI objects after checking the writer and raw
        // device, so an intermediate stale ReadyToUse response is insufficient.
        let again = api.get(&p.context.raw_snapshot_name()).await?;
        ensure_identity(&again, snapshot_uid)?;
        if let Some(ref observed) = ready {
            let content = dyn_api(self.runtime(), "VolumeSnapshotContent", None)
                .get(&observed.content_name)
                .await?;
            let rechecked = verify_raw_snapshot(
                &p.context,
                &encode(&again)?,
                &encode(&content)?,
                &p.raw.cloud_disk,
                p.closed_at,
                Some(snapshot_uid),
                Some(observed.content_uid),
            )?;
            require(
                rechecked.as_ref().is_some_and(|v| {
                    v.cloud_snapshot == observed.cloud_snapshot
                        && v.size_bytes == observed.size_bytes
                }),
                "restore snapshot readiness changed during observation",
            )?;
        }
        Ok(Some(VerifiedRestoreSnapshot {
            tenant_id: p.context.tenant_id,
            restore_id: p.context.restore_id,
            snapshot_uid,
            ready,
            observed_at: Utc::now(),
            _private: (),
        }))
    }
    async fn verify_restore_namespace(
        &self,
        p: &RestoreDeliveryPlan,
        certification_id: &str,
    ) -> Result<(), RuntimeError> {
        let c = &p.snapshot.context;
        let ns = Api::<Namespace>::all(self.runtime().client_clone())
            .get(&c.target_namespace)
            .await?;
        let labels = ns.metadata.labels.as_ref();
        require(
            !certification_id.is_empty()
                && certification_id.len() <= 128
                && !certification_id.chars().any(char::is_control)
                && ns.metadata.deletion_timestamp.is_none()
                && labels
                    .and_then(|m| m.get("sandbox.platform/managed"))
                    .map(String::as_str)
                    == Some("true")
                && ns
                    .metadata
                    .annotations
                    .as_ref()
                    .and_then(|m| m.get("sandbox.platform/certification-id"))
                    .map(String::as_str)
                    == Some(certification_id)
                && [
                    ("sandbox.platform/tenant-id", c.tenant_id),
                    ("sandbox.platform/project-id", c.target_project_id),
                    ("sandbox.platform/cluster-epoch", c.cluster_epoch),
                ]
                .iter()
                .all(|(k, v)| labels.and_then(|m| m.get(*k)) == Some(&v.to_string())),
            "restore delivery namespace is not independently certified",
        )?;
        let baseline =
            Api::<NetworkPolicy>::namespaced(self.runtime().client_clone(), &c.target_namespace)
                .get("sandbox-default-deny")
                .await?;
        require(
            baseline.metadata.deletion_timestamp.is_none()
                && baseline.spec.as_ref().is_some_and(|s| {
                    s.pod_selector == Some(Default::default())
                        && s.ingress.as_ref().is_none_or(Vec::is_empty)
                        && s.egress.as_ref().is_none_or(Vec::is_empty)
                        && s.policy_types.as_deref()
                            == Some(&["Ingress".to_owned(), "Egress".to_owned()])
                }),
            "restore target default-deny baseline changed",
        )
    }
    pub(crate) async fn reconcile_restore_delivery(
        &self,
        p: &RestoreDeliveryPlan,
        certification_id: &str,
    ) -> Result<VerifiedRestoreDelivery, RuntimeError> {
        self.verify_network(&p.snapshot.cloud).await?;
        self.verify_profile_secrets(&p.snapshot.cloud).await?;
        self.verify_restore_namespace(p, certification_id).await?;
        p.snapshot
            .context
            .storage_contract
            .validate_cloud(&p.snapshot.cloud)?;
        self.verify_restore_storage_class(
            &p.snapshot.context.storage_contract,
            RestoreStoragePurpose::Delivery,
        )
        .await?;
        let current = self
            .reconcile_restore_snapshot(&p.snapshot)
            .await?
            .and_then(|v| v.ready)
            .ok_or(ManifestError::SpecificationDrift(
                "restore raw snapshot is not ready",
            ))?;
        require(
            current.snapshot_uid == p.ready.snapshot_uid
                && current.content_uid == p.ready.content_uid
                && current.content_name == p.ready.content_name
                && current.cloud_snapshot == p.ready.cloud_snapshot
                && current.size_bytes == p.ready.size_bytes,
            "restore delivery source snapshot receipt changed",
        )?;
        let c = &p.snapshot.context;
        let contents = dyn_api(self.runtime(), "VolumeSnapshotContent", None);
        let snapshots = dyn_api(self.runtime(), "VolumeSnapshot", Some(&c.target_namespace));
        let content = ensure(
            &contents,
            &object(c.delivery_content(&current.cloud_snapshot)?)?,
            p.known_content,
        )
        .await?;
        let snapshot = ensure(
            &snapshots,
            &object(c.delivery_snapshot()?)?,
            p.known_snapshot,
        )
        .await?;
        let content_uid = uid(content.metadata.uid.as_deref())?;
        let snapshot_uid = uid(snapshot.metadata.uid.as_deref())?;
        require(
            content_uid != current.content_uid && snapshot_uid != current.snapshot_uid,
            "restore delivery reused raw snapshot objects",
        )?;
        let content = ensure(
            &contents,
            &object(c.delivery_content(&current.cloud_snapshot)?)?,
            Some(content_uid),
        )
        .await?;
        let snapshot = ensure(
            &snapshots,
            &object(c.delivery_snapshot()?)?,
            Some(snapshot_uid),
        )
        .await?;
        ensure_identity(&content, content_uid)?;
        ensure_identity(&snapshot, snapshot_uid)?;
        let v = encode(&content)?;
        let s = encode(&snapshot)?;
        require(
            v.pointer("/status/error").is_none_or(Value::is_null)
                && s.pointer("/status/error").is_none_or(Value::is_null),
            "restore delivery snapshot reported an error",
        )?;
        require(
            v.pointer("/spec/volumeSnapshotRef/uid")
                .is_none_or(|v| v == &json!(snapshot_uid))
                && s.pointer("/status/boundVolumeSnapshotContentName")
                    .is_none_or(|v| v == &json!(c.delivery_snapshot_name())),
            "restore delivery snapshot reference changed",
        )?;
        let ready = v.pointer("/status/readyToUse") == Some(&json!(true))
            && s.pointer("/status/readyToUse") == Some(&json!(true))
            && v.pointer("/spec/volumeSnapshotRef/uid") == Some(&json!(snapshot_uid))
            && s.pointer("/status/boundVolumeSnapshotContentName")
                == Some(&json!(c.delivery_snapshot_name()))
            && v.pointer("/status/snapshotHandle") == Some(&json!(current.cloud_snapshot));
        let expected: PersistentVolumeClaim = serde_json::from_value(c.filesystem_pvc()?)
            .map_err(|_| RuntimeError::MissingIdentity)?;
        let name = expected
            .metadata
            .name
            .as_deref()
            .ok_or(RuntimeError::MissingIdentity)?;
        let pvcs = Api::<PersistentVolumeClaim>::namespaced(
            self.runtime().client_clone(),
            &c.target_namespace,
        );
        let actual = match pvcs.get_opt(name).await? {
            Some(v) => v,
            None => {
                require(
                    p.known_pvc.is_none(),
                    "recorded restore workspace claim disappeared",
                )?;
                match pvcs.create(&PostParams::default(), &expected).await {
                    Ok(v) => v,
                    Err(kube::Error::Api(e)) if e.code == 409 => pvcs.get(name).await?,
                    Err(e) => return Err(e.into()),
                }
            }
        };
        let pvc_uid = uid(actual.metadata.uid.as_deref())?;
        validate_existing_pvc(
            &actual,
            &expected,
            p.known_pvc.map(|v| v.to_string()).as_deref(),
        )?;
        require(
            ![
                p.snapshot.raw.pvc_uid,
                p.source_pvc_uid,
                p.source_clone_pvc_uid,
            ]
            .contains(&pvc_uid),
            "restore workspace claim reused a historical or raw identity",
        )?;
        let bound = if actual.status.as_ref().and_then(|v| v.phase.as_deref()) == Some("Bound") {
            require(
                ready,
                "restore workspace bound before exact static snapshot readiness",
            )?;
            let name = actual
                .spec
                .as_ref()
                .and_then(|s| s.volume_name.as_deref())
                .ok_or(RuntimeError::MissingIdentity)?;
            let pv = Api::<PersistentVolume>::all(self.runtime().client_clone())
                .get(name)
                .await?;
            let pv_uid = uid(pv.metadata.uid.as_deref())?;
            require(
                p.known_pv.is_none_or(|v| v == pv_uid) && pv_uid != p.snapshot.raw.pv_uid,
                "restore workspace PV changed or reused raw device",
            )?;
            validate_pv(
                &encode(&pv)?,
                pvc_uid,
                expected
                    .metadata
                    .name
                    .as_deref()
                    .ok_or(RuntimeError::MissingIdentity)?,
                &c.target_namespace,
                &c.storage_contract.mapping.delivery.name,
                "Filesystem",
                c.size_bytes,
            )?;
            let cloud_disk = pv
                .spec
                .as_ref()
                .and_then(|s| s.csi.as_ref())
                .map(|s| s.volume_handle.as_str())
                .ok_or(RuntimeError::MissingIdentity)?;
            require(
                cloud_disk != p.snapshot.raw.cloud_disk
                    && cloud_disk.strip_prefix("d-").is_some_and(|v| {
                        !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric())
                    }),
                "restore filesystem delivery is not a distinct cloud disk",
            )?;
            Some(BoundBackupVolume {
                pvc_uid,
                pv_uid,
                pv_name: name.into(),
                cloud_disk: cloud_disk.into(),
                size_bytes: c.size_bytes,
            })
        } else {
            require(
                p.known_pv.is_none()
                    && actual
                        .spec
                        .as_ref()
                        .and_then(|s| s.volume_name.as_deref())
                        .is_none(),
                "recorded restore workspace became unbound",
            )?;
            None
        };
        let again = pvcs
            .get(
                expected
                    .metadata
                    .name
                    .as_deref()
                    .ok_or(RuntimeError::MissingIdentity)?,
            )
            .await?;
        validate_existing_pvc(&again, &expected, Some(pvc_uid.to_string().as_str()))?;
        if let Some(ref volume) = bound {
            require(
                again.spec.as_ref().and_then(|s| s.volume_name.as_deref())
                    == Some(volume.pv_name.as_str()),
                "restore workspace binding changed during observation",
            )?;
            let again = Api::<PersistentVolume>::all(self.runtime().client_clone())
                .get(&volume.pv_name)
                .await?;
            require(
                uid(again.metadata.uid.as_deref())? == volume.pv_uid,
                "restore workspace PV was replaced",
            )?;
            validate_pv(
                &encode(&again)?,
                pvc_uid,
                expected
                    .metadata
                    .name
                    .as_deref()
                    .ok_or(RuntimeError::MissingIdentity)?,
                &c.target_namespace,
                &c.storage_contract.mapping.delivery.name,
                "Filesystem",
                c.size_bytes,
            )?;
            require(
                again
                    .spec
                    .as_ref()
                    .and_then(|s| s.csi.as_ref())
                    .map(|s| s.volume_handle.as_str())
                    == Some(volume.cloud_disk.as_str()),
                "restore workspace disk identity changed",
            )?;
        }
        let again = ensure(
            &contents,
            &object(c.delivery_content(&current.cloud_snapshot)?)?,
            Some(content_uid),
        )
        .await?;
        let snapshot = ensure(
            &snapshots,
            &object(c.delivery_snapshot()?)?,
            Some(snapshot_uid),
        )
        .await?;
        let again = encode(&again)?;
        let snapshot = encode(&snapshot)?;
        require(
            again.pointer("/status/error").is_none_or(Value::is_null)
                && snapshot.pointer("/status/error").is_none_or(Value::is_null),
            "restore delivery snapshot reported a late error",
        )?;
        if bound.is_some() {
            require(
                again.pointer("/spec/volumeSnapshotRef/uid") == Some(&json!(snapshot_uid))
                    && again.pointer("/status/readyToUse") == Some(&json!(true))
                    && snapshot.pointer("/status/readyToUse") == Some(&json!(true))
                    && snapshot.pointer("/status/boundVolumeSnapshotContentName")
                        == Some(&json!(c.delivery_snapshot_name()))
                    && again.pointer("/status/snapshotHandle")
                        == Some(&json!(current.cloud_snapshot)),
                "restore delivery readiness changed during observation",
            )?;
        }
        self.verify_restore_namespace(p, certification_id).await?;
        Ok(VerifiedRestoreDelivery {
            tenant_id: c.tenant_id,
            restore_id: c.restore_id,
            snapshot_uid,
            content_uid,
            pvc_uid,
            bound,
            observed_at: Utc::now(),
            _private: (),
        })
    }
}
fn ensure_identity(v: &DynamicObject, expected: Uuid) -> Result<(), RuntimeError> {
    require(
        uid(v.metadata.uid.as_deref())? == expected && v.metadata.deletion_timestamp.is_none(),
        "restore snapshot resource replaced during observation",
    )
}
