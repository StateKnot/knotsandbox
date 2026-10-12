//! Private durable temporary storage controller. Production activation remains
//! closed until its ordered migration, dedicated credentials and cloud tests pass.
use crate::{
    cloud_fencing::{
        CloudDiskDeleteOutcome, CloudDiskIdentity, CloudDiskLookup, CloudDiskPreserveOutcome,
        restore_gc::{
            AlibabaCloudRestoreGc, RestoreSnapshotDeleteOutcome, RestoreSnapshotIdentity,
            RestoreSnapshotLookup,
        },
    },
    db::Database,
    error::ApiError,
};
use chrono::{DateTime, Utc};
use k8s_openapi::api::{core::v1::Pod, storage::v1::VolumeAttachment};
use kube::{
    Api, Client,
    api::{
        ApiResource, DeleteParams, DynamicObject, ListParams, Patch, PatchParams, Preconditions,
    },
};
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[derive(Clone, sqlx::FromRow)]
pub(super) struct GcClaim {
    pub tenant_id: Uuid,
    pub restore_id: Uuid,
    pub review_id: Uuid,
    pub lease_token: i64,
    pub lease_owner: String,
}
#[derive(sqlx::FromRow)]
struct Review {
    raw_identity: Value,
    snapshot_identity: Value,
    target_identity: Value,
    force_created_disk: bool,
}
#[derive(Clone, sqlx::FromRow)]
struct Resource {
    id: Uuid,
    kind: String,
    namespace: String,
    name: String,
    uid: Uuid,
}
pub(super) struct RestoreGcController {
    pub database: Database,
    pub client: Client,
    pub cloud: AlibabaCloudRestoreGc,
}
fn blocked() -> ApiError {
    ApiError::conflict(
        "RESTORE_GC_NOT_VERIFIED",
        "Temporary storage remains accounted until exact cleanup is verified",
    )
}
impl RestoreGcController {
    pub async fn candidates(&self) -> Result<Vec<(Uuid, Uuid)>, ApiError> {
        Ok(
            sqlx::query_as("SELECT * FROM sandbox_restore_gc_candidates(64)")
                .fetch_all(&self.database.pool)
                .await?,
        )
    }
    pub async fn claim(
        &self,
        tenant: Uuid,
        restore: Uuid,
        worker: &str,
    ) -> Result<Option<GcClaim>, ApiError> {
        let mut tx = self.database.begin(tenant).await?;
        let result=sqlx::query_as("SELECT tenant_id,restore_id,review_id,lease_token,lease_owner FROM sandbox_claim_restore_gc($1,$2,$3,300)")
            .bind(tenant).bind(restore).bind(worker).fetch_optional(&mut *tx).await?;
        tx.commit().await?;
        Ok(result)
    }
    async fn locked<'a>(&'a self, c: &GcClaim) -> Result<Transaction<'a, Postgres>, ApiError> {
        let mut tx = self.database.begin(c.tenant_id).await?;
        let current: bool =
            sqlx::query_scalar("SELECT sandbox_assert_restore_gc_claim($1,$2,$3,$4)")
                .bind(c.tenant_id)
                .bind(c.restore_id)
                .bind(&c.lease_owner)
                .bind(c.lease_token)
                .fetch_one(&mut *tx)
                .await?;
        if !current {
            return Err(blocked());
        }
        Ok(tx)
    }
    async fn dispatch(
        &self,
        c: &GcClaim,
        kind: &str,
        identity: &Value,
        force: bool,
    ) -> Result<Uuid, ApiError> {
        let mut tx = self.locked(c).await?;
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO restore_gc_dispatches(id,tenant_id,restore_id,review_id,lease_token,kind,identity,force_created_disk) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(id).bind(c.tenant_id).bind(c.restore_id).bind(c.review_id).bind(c.lease_token).bind(kind).bind(identity).bind(force).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(id)
    }
    async fn result(
        &self,
        c: &GcClaim,
        id: Uuid,
        outcome: &str,
        evidence: Value,
    ) -> Result<(), ApiError> {
        let mut tx = self.locked(c).await?;
        sqlx::query("INSERT INTO restore_gc_results(dispatch_id,tenant_id,restore_id,outcome,evidence) VALUES($1,$2,$3,$4,$5)")
            .bind(id).bind(c.tenant_id).bind(c.restore_id).bind(outcome).bind(evidence).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    async fn cloud_absent(
        &self,
        c: &GcClaim,
        id: Uuid,
        kind: &str,
        resource: &str,
        at: DateTime<Utc>,
        evidence: Value,
    ) -> Result<(), ApiError> {
        let mut tx = self.locked(c).await?;
        sqlx::query("INSERT INTO restore_gc_cloud_absences(tenant_id,restore_id,kind,resource_id,dispatch_id,observed_at,evidence) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING")
            .bind(c.tenant_id).bind(c.restore_id).bind(kind).bind(resource).bind(id).bind(at).bind(evidence).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    async fn wait(&self, c: &GcClaim, reason: &str) -> Result<(), ApiError> {
        let mut tx = self.database.begin(c.tenant_id).await?;
        let ok: bool = sqlx::query_scalar("SELECT sandbox_wait_restore_gc($1,$2,$3,$4,$5,1)")
            .bind(c.tenant_id)
            .bind(c.restore_id)
            .bind(&c.lease_owner)
            .bind(c.lease_token)
            .bind(reason)
            .fetch_one(&mut *tx)
            .await?;
        if !ok {
            return Err(blocked());
        }
        tx.commit().await?;
        Ok(())
    }
    async fn raw_quiescent(&self, raw: &CloudDiskIdentity) -> Result<(), ApiError> {
        let pods = Api::<Pod>::namespaced(self.client.clone(), &raw.binding.namespace)
            .list(&ListParams::default())
            .await
            .map_err(|_| blocked())?;
        let attachments = Api::<VolumeAttachment>::all(self.client.clone())
            .list(&ListParams::default())
            .await
            .map_err(|_| blocked())?;
        if pods
            .metadata
            .continue_
            .as_ref()
            .is_some_and(|v| !v.is_empty())
            || attachments
                .metadata
                .continue_
                .as_ref()
                .is_some_and(|v| !v.is_empty())
            || pods.items.iter().any(|p| {
                p.spec.as_ref().is_none_or(|s| {
                    s.volumes.as_ref().is_some_and(|v| {
                        v.iter().any(|v| {
                            v.persistent_volume_claim
                                .as_ref()
                                .is_some_and(|p| p.claim_name == raw.binding.pvc_name)
                        })
                    })
                })
            })
            || attachments.items.iter().any(|a| {
                a.spec.source.persistent_volume_name.as_deref() == Some(&raw.binding.pv_name)
            })
        {
            return Err(blocked());
        }
        Ok(())
    }
    pub async fn reconcile(&self, c: &GcClaim) -> Result<bool, ApiError> {
        if !self.reconcile_resources(c).await? {
            return Ok(false);
        }
        let mut tx = self.database.begin(c.tenant_id).await?;
        let finished: bool = sqlx::query_scalar("SELECT sandbox_finish_restore_gc($1,$2,$3,$4)")
            .bind(c.tenant_id)
            .bind(c.restore_id)
            .bind(&c.lease_owner)
            .bind(c.lease_token)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(finished)
    }
    // Provider cleanup and accounting are independently restartable steps.
    // Completion always rechecks the durable claim inside its own transaction.
    pub(super) async fn reconcile_resources(&self, c: &GcClaim) -> Result<bool, ApiError> {
        let mut tx = self.locked(c).await?;
        let review:Review=sqlx::query_as("SELECT raw_identity,snapshot_identity,target_identity,force_created_disk FROM restore_gc_reviews WHERE tenant_id=$1 AND restore_id=$2 AND id=$3")
            .bind(c.tenant_id).bind(c.restore_id).bind(c.review_id).fetch_one(&mut *tx).await?;
        let mut absences: Vec<String> = sqlx::query_scalar(
            "SELECT kind FROM restore_gc_cloud_absences WHERE tenant_id=$1 AND restore_id=$2",
        )
        .bind(c.tenant_id)
        .bind(c.restore_id)
        .fetch_all(&mut *tx)
        .await?;
        let resources:Vec<Resource>=sqlx::query_as("SELECT i.id,i.kind,i.namespace,i.name,b.uid FROM restore_resource_intents i JOIN restore_resource_bindings b ON b.tenant_id=i.tenant_id AND b.intent_id=i.id WHERE i.tenant_id=$1 AND i.restore_id=$2 AND i.kind IN('BLOCK_PVC','BLOCK_PV','RESTORED_SNAPSHOT','RESTORED_CONTENT','DELIVERY_SNAPSHOT','DELIVERY_CONTENT') ORDER BY CASE i.kind WHEN 'BLOCK_PVC' THEN 0 WHEN 'BLOCK_PV' THEN 1 WHEN 'RESTORED_SNAPSHOT' THEN 2 WHEN 'DELIVERY_SNAPSHOT' THEN 3 ELSE 4 END,i.id")
            .bind(c.tenant_id).bind(c.restore_id).fetch_all(&mut *tx).await?;
        tx.commit().await?;
        let raw: CloudDiskIdentity =
            serde_json::from_value(review.raw_identity.clone()).map_err(|_| blocked())?;
        let snapshot: RestoreSnapshotIdentity =
            serde_json::from_value(review.snapshot_identity.clone()).map_err(|_| blocked())?;
        let target: CloudDiskIdentity =
            serde_json::from_value(review.target_identity).map_err(|_| blocked())?;
        if !absences.iter().any(|v| v == "RAW_DISK") {
            self.raw_quiescent(&raw).await?;
            match self
                .cloud
                .observe_raw_disk(&raw.binding)
                .await
                .map_err(|_| blocked())?
            {
                CloudDiskLookup::Absent(a) => {
                    let id = self
                        .dispatch(c, "DELETE_RAW_DISK", &review.raw_identity, false)
                        .await?;
                    let CloudDiskLookup::Absent(a) = self
                        .cloud
                        .observe_raw_disk(a.binding())
                        .await
                        .map_err(|_| blocked())?
                    else {
                        return Err(blocked());
                    };
                    self.cloud_absent(
                        c,
                        id,
                        "RAW_DISK",
                        &raw.binding.disk_id,
                        a.evidence().received_at(),
                        json!(a),
                    )
                    .await?;
                    absences.push("RAW_DISK".into());
                }
                CloudDiskLookup::Present(o) => {
                    if serde_json::to_value(o.identity().map_err(|_| blocked())?).ok()
                        != Some(review.raw_identity.clone())
                    {
                        return Err(blocked());
                    }
                    if o.delete_auto_snapshot() {
                        let id = self
                            .dispatch(c, "PRESERVE_RAW_SNAPSHOTS", &review.raw_identity, false)
                            .await?;
                        let result = self
                            .cloud
                            .preserve_raw_automatic_snapshots(&raw, id)
                            .await
                            .map_err(|_| blocked())?;
                        let status =
                            if matches!(result, CloudDiskPreserveOutcome::OutcomeUnknown(_)) {
                                "UNKNOWN"
                            } else {
                                "ACCEPTED"
                            };
                        self.result(c, id, status, json!(result)).await?;
                        self.wait(c, "RAW_SNAPSHOT_PRESERVATION_QUERY_REQUIRED")
                            .await?;
                        return Ok(false);
                    }
                    let id = self
                        .dispatch(c, "DELETE_RAW_DISK", &review.raw_identity, false)
                        .await?;
                    let result = self
                        .cloud
                        .delete_raw_disk(&raw, id)
                        .await
                        .map_err(|_| blocked())?;
                    let status = if matches!(result, CloudDiskDeleteOutcome::OutcomeUnknown(_)) {
                        "UNKNOWN"
                    } else {
                        "ACCEPTED"
                    };
                    self.result(c, id, status, json!(result)).await?;
                    self.wait(c, "RAW_DISK_EXACT_ABSENCE_REQUIRED").await?;
                    return Ok(false);
                }
            }
        }
        if !absences.iter().any(|v| v == "SNAPSHOT") {
            match self
                .cloud
                .observe_snapshot(&snapshot.binding)
                .await
                .map_err(|_| blocked())?
            {
                RestoreSnapshotLookup::Absent(a) => {
                    let id = self
                        .dispatch(c, "DELETE_SNAPSHOT", &review.snapshot_identity, false)
                        .await?;
                    let RestoreSnapshotLookup::Absent(a) = self
                        .cloud
                        .observe_snapshot(a.binding())
                        .await
                        .map_err(|_| blocked())?
                    else {
                        return Err(blocked());
                    };
                    self.cloud_absent(
                        c,
                        id,
                        "SNAPSHOT",
                        &snapshot.binding.scope.snapshot_id,
                        a.evidence().received_at(),
                        json!(a),
                    )
                    .await?;
                }
                RestoreSnapshotLookup::Present(o) => {
                    if o.identity() != &snapshot
                        || (o.requires_force() && !review.force_created_disk)
                    {
                        return Err(blocked());
                    }
                    let force = o.requires_force();
                    let id = self
                        .dispatch(c, "DELETE_SNAPSHOT", &review.snapshot_identity, force)
                        .await?;
                    let result = self
                        .cloud
                        .delete_snapshot(&snapshot, id, force, Some(&target))
                        .await
                        .map_err(|_| blocked())?;
                    let status =
                        if matches!(result, RestoreSnapshotDeleteOutcome::OutcomeUnknown(_)) {
                            "UNKNOWN"
                        } else {
                            "ACCEPTED"
                        };
                    self.result(c, id, status, json!(result)).await?;
                    self.wait(c, "SNAPSHOT_EXACT_ABSENCE_REQUIRED").await?;
                    return Ok(false);
                }
            }
        }
        if resources.len() != 6 {
            return Err(blocked());
        }
        for resource in resources {
            self.cleanup(c, &resource, &raw, &snapshot).await?;
        }
        Ok(true)
    }
    async fn cleanup(
        &self,
        c: &GcClaim,
        r: &Resource,
        raw: &CloudDiskIdentity,
        snapshot: &RestoreSnapshotIdentity,
    ) -> Result<(), ApiError> {
        let (group, version, kind, plural, cluster) = match r.kind.as_str() {
            "BLOCK_PVC" => (
                "",
                "v1",
                "PersistentVolumeClaim",
                "persistentvolumeclaims",
                false,
            ),
            "BLOCK_PV" => ("", "v1", "PersistentVolume", "persistentvolumes", true),
            "RESTORED_SNAPSHOT" | "DELIVERY_SNAPSHOT" => (
                "snapshot.storage.k8s.io",
                "v1",
                "VolumeSnapshot",
                "volumesnapshots",
                false,
            ),
            "RESTORED_CONTENT" | "DELIVERY_CONTENT" => (
                "snapshot.storage.k8s.io",
                "v1",
                "VolumeSnapshotContent",
                "volumesnapshotcontents",
                true,
            ),
            _ => return Err(blocked()),
        };
        let ar = ApiResource {
            group: group.into(),
            version: version.into(),
            api_version: if group.is_empty() {
                version.into()
            } else {
                format!("{group}/{version}")
            },
            kind: kind.into(),
            plural: plural.into(),
        };
        let api: Api<DynamicObject> = if cluster {
            Api::all_with(self.client.clone(), &ar)
        } else {
            Api::namespaced_with(self.client.clone(), &r.namespace, &ar)
        };
        if let Some(mut object) = api.get_opt(&r.name).await.map_err(|_| blocked())? {
            let uid = object
                .metadata
                .uid
                .as_deref()
                .and_then(|v| Uuid::parse_str(v).ok());
            let mut rv = object
                .metadata
                .resource_version
                .clone()
                .filter(|v| !v.is_empty());
            if uid != Some(r.uid)
                || rv.is_none()
                || object.metadata.name.as_deref() != Some(&r.name)
                || (!cluster && object.metadata.namespace.as_deref() != Some(&r.namespace))
                || (r.kind.ends_with("CONTENT")
                    && object.data.pointer("/spec/deletionPolicy") != Some(&json!("Retain")))
                || (r.kind == "BLOCK_PV"
                    && (object.data.pointer("/spec/persistentVolumeReclaimPolicy")
                        != Some(&json!("Retain"))
                        || object.data.pointer("/spec/csi/volumeHandle")
                            != Some(&json!(raw.binding.disk_id))))
                || (r.kind == "BLOCK_PVC"
                    && object.data.pointer("/spec/volumeName") != Some(&json!(raw.binding.pv_name)))
                || (r.kind == "RESTORED_CONTENT"
                    && object.data.pointer("/status/snapshotHandle")
                        != Some(&json!(snapshot.binding.scope.snapshot_id)))
                || (r.kind == "DELIVERY_CONTENT"
                    && object.data.pointer("/spec/source/snapshotHandle")
                        != Some(&json!(snapshot.binding.scope.snapshot_id)))
            {
                return Err(blocked());
            }
            if object
                .metadata
                .finalizers
                .as_ref()
                .is_some_and(|v| v.iter().any(|f| f == "sandbox.platform/backup-protection"))
            {
                // Cloud resources are independently absent. Remove only our
                // own protection; Kubernetes/CSI finalizers remain untouched.
                let finalizers: Vec<String> = object
                    .metadata
                    .finalizers
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|v| v != "sandbox.platform/backup-protection")
                    .collect();
                let patch =
                    json!({"metadata":{"uid":r.uid,"resourceVersion":rv,"finalizers":finalizers}});
                let updated = api
                    .patch(&r.name, &PatchParams::default(), &Patch::Merge(&patch))
                    .await
                    .map_err(|_| blocked())?;
                if updated.metadata.uid != object.metadata.uid
                    || updated.data != object.data
                    || updated.metadata.finalizers.as_ref().is_some_and(|v| {
                        v.iter().any(|f| f == "sandbox.platform/backup-protection")
                    })
                {
                    return Err(blocked());
                }
                object = updated;
                rv = object
                    .metadata
                    .resource_version
                    .clone()
                    .filter(|v| !v.is_empty());
                if rv.is_none() {
                    return Err(blocked());
                }
            }
            let _ = api
                .delete(
                    &r.name,
                    &DeleteParams {
                        preconditions: Some(Preconditions {
                            uid: Some(r.uid.to_string()),
                            resource_version: rv,
                        }),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|_| blocked())?;
            if api.get_opt(&r.name).await.map_err(|_| blocked())?.is_some() {
                return Err(blocked());
            }
        }
        let mut tx = self.locked(c).await?;
        sqlx::query("INSERT INTO restore_gc_kube_absences(tenant_id,restore_id,intent_id,uid,observed_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
            .bind(c.tenant_id).bind(c.restore_id).bind(r.id).bind(r.uid).bind(Utc::now()).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
}
