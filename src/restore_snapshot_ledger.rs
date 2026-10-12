//! CSI stage intents are created only after exact successful readback and
//! trusted host closure. Private live observations are the only receipt input.
use super::{
    RestoreRecord,
    csi::{VerifiedRestoreDelivery, VerifiedRestoreSnapshot},
    ledger::{advance, current_cloud, current_source, lock_restore, resource_binding},
    manifest::{RestoreSnapshotObservation, RestoreStorageContext},
    policy,
    resources::{assert_new_storage, binding, intent},
};
use crate::{
    backup_job::BackupCloudSettings,
    backup_manifest::NAMESPACE,
    backup_runtime::BoundBackupVolume,
    db::Database,
    engine::{Claim, OperationEngine},
    error::ApiError,
    nodeguard::protocol::RegisterLaunchRequest,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(crate) struct RestoreSnapshotPlan {
    pub context: RestoreStorageContext,
    pub cloud: BackupCloudSettings,
    pub raw: BoundBackupVolume,
    pub closed_pod_name: String,
    pub closed_at: DateTime<Utc>,
    pub known_snapshot: Option<Uuid>,
    pub known_content: Option<Uuid>,
}
pub(crate) struct RestoreDeliveryPlan {
    pub snapshot: RestoreSnapshotPlan,
    pub ready: RestoreSnapshotObservation,
    pub source_pvc_uid: Uuid,
    pub source_clone_pvc_uid: Uuid,
    pub known_snapshot: Option<Uuid>,
    pub known_content: Option<Uuid>,
    pub known_pvc: Option<Uuid>,
    pub known_pv: Option<Uuid>,
}
#[derive(PartialEq, sqlx::FromRow)]
struct SnapshotReceipt {
    snapshot_uid: Uuid,
    content_uid: Uuid,
    content_name: String,
    cloud_snapshot: String,
    size_bytes: i64,
}
#[derive(PartialEq, sqlx::FromRow)]
struct DeliveryReceipt {
    workspace_id: Uuid,
    namespace: String,
    snapshot_name: String,
    snapshot_uid: Uuid,
    content_uid: Uuid,
    pvc_uid: Uuid,
    pv_uid: Uuid,
    pv_name: String,
    cloud_disk: String,
    cloud_snapshot: String,
    size_bytes: i64,
}
pub(super) async fn snapshot_plan(
    tx: &mut Transaction<'_, Postgres>,
    r: &RestoreRecord,
) -> Result<RestoreSnapshotPlan, ApiError> {
    let source = current_source(tx, r).await?;
    let cloud = current_cloud(tx, r, &source).await?;
    let (namespace, storage): (String, String) = sqlx::query_as(
        "SELECT namespace,storage_class FROM workspaces WHERE tenant_id=$1 AND id=$2",
    )
    .bind(r.tenant_id)
    .bind(r.workspace_id)
    .fetch_one(&mut **tx)
    .await?;
    let storage_contract = r.storage()?;
    if storage != storage_contract.mapping.delivery.name {
        return Err(policy::invalid());
    }
    let closure:Option<(Value,DateTime<Utc>)>=sqlx::query_as("SELECT permit.request,GREATEST(proof.observed_at,cleanup.pod_absent_at,cleanup.volume_checked_at,cleanup.recorded_at) FROM restore_launch_permits permit JOIN restore_termination_proofs proof ON proof.tenant_id=permit.tenant_id AND proof.permit_id=permit.id JOIN restore_cleanup_receipts cleanup ON cleanup.tenant_id=proof.tenant_id AND cleanup.proof_id=proof.id JOIN restore_io_reports io ON io.tenant_id=permit.tenant_id AND io.restore_id=permit.restore_id WHERE permit.tenant_id=$1 AND permit.restore_id=$2 AND cleanup.restore_id=permit.restore_id AND io.exit_code=0 AND io.bytes=$3 AND io.disk_sha256=$4 AND cleanup.pod_uid=(permit.request->'launch'->>'pod_uid')::uuid AND cleanup.pvc_uid=(permit.request->'launch'->>'pvc_uid')::uuid AND cleanup.pv_uid=(permit.request->'launch'->>'pv_uid')::uuid AND cleanup.cloud_disk=permit.request->'launch'->>'csi_volume_handle'")
        .bind(r.tenant_id).bind(r.id).bind(i64::try_from(source.identity.size_bytes).map_err(|_|policy::invalid())?).bind(&source.disk_sha256).fetch_optional(&mut **tx).await?;
    let (request,closed_at)=closure.ok_or_else(||policy::blocked("Restore snapshot requires successful full-device readback and exact trusted writer cleanup"))?;
    let request: RegisterLaunchRequest =
        serde_json::from_value(request).map_err(|_| policy::invalid())?;
    let launch = request.launch;
    if launch.tenant_id != r.tenant_id
        || launch.project_id != r.target_project_id
        || launch.instance_id != r.instance_id
        || launch.workspace_id != r.workspace_id
        || launch.launch_id != r.id
        || launch.namespace != NAMESPACE
        || launch.generation != 1
        || request.node.cluster_epoch != r.cluster_epoch
    {
        return Err(policy::blocked(
            "Restore snapshot closure identity differs from its target",
        ));
    }
    let raw:Option<(Uuid,Uuid,String,String,i64)>=sqlx::query_as("SELECT pvc_uid,pv_uid,pv_name,cloud_disk,size_bytes FROM restore_block_receipts WHERE tenant_id=$1 AND restore_id=$2").bind(r.tenant_id).bind(r.id).fetch_optional(&mut **tx).await?;
    let (pvc_uid, pv_uid, pv_name, cloud_disk, size) = raw.ok_or_else(policy::invalid)?;
    if pvc_uid != launch.pvc_uid
        || pv_uid != launch.pv_uid
        || pv_name != launch.pv_name
        || cloud_disk != launch.csi_volume_handle
        || size != i64::try_from(source.identity.size_bytes).map_err(|_| policy::invalid())?
    {
        return Err(policy::blocked(
            "Restore snapshot raw device differs from the permanently closed writer",
        ));
    }
    Ok(RestoreSnapshotPlan {
        context: RestoreStorageContext {
            tenant_id: r.tenant_id,
            source_backup_id: r.backup_id,
            restore_id: r.id,
            target_project_id: r.target_project_id,
            instance_id: r.instance_id,
            workspace_id: r.workspace_id,
            cluster_epoch: r.cluster_epoch,
            target_namespace: namespace,
            storage_contract,
            size_bytes: source.identity.size_bytes,
        },
        cloud,
        raw: BoundBackupVolume {
            pvc_uid,
            pv_uid,
            pv_name,
            cloud_disk,
            size_bytes: source.identity.size_bytes,
        },
        closed_pod_name: launch.pod_name,
        closed_at,
        known_snapshot: resource_binding(tx, r.tenant_id, r.id, "RESTORED_SNAPSHOT").await?,
        known_content: resource_binding(tx, r.tenant_id, r.id, "RESTORED_CONTENT").await?,
    })
}
impl Database {
    pub(crate) async fn prepare_restore_snapshot(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<RestoreSnapshotPlan, ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let r = lock_restore(&mut tx, engine, claim).await?;
        if !matches!(r.status.as_str(), "RESTORE_CLOSING" | "SNAPSHOT_PENDING") {
            return Err(policy::blocked(
                "Restore is outside closed-device snapshot preparation",
            ));
        }
        let p = snapshot_plan(&mut tx, &r).await?;
        let expected = p.context.raw_snapshot().map_err(|_| policy::invalid())?;
        intent(
            &mut tx,
            &r,
            "RESTORED_SNAPSHOT",
            NAMESPACE,
            &p.context.raw_snapshot_name(),
            Some(&expected),
        )
        .await?;
        if r.status == "RESTORE_CLOSING" {
            advance(&mut tx, &r, "SNAPSHOT_PENDING").await?;
        }
        tx.commit().await?;
        Ok(p)
    }
    pub(crate) async fn record_restore_snapshot(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        observed: &VerifiedRestoreSnapshot,
    ) -> Result<(), ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let r = lock_restore(&mut tx, engine, claim).await?;
        if r.status != "SNAPSHOT_PENDING" {
            return Err(policy::blocked(
                "Restore snapshot receipt arrived outside its stage",
            ));
        }
        let p = snapshot_plan(&mut tx, &r).await?;
        fresh(&mut tx, observed.observed_at).await?;
        if observed.tenant_id != r.tenant_id || observed.restore_id != r.id {
            return Err(policy::invalid());
        }
        binding(&mut tx, &r, "RESTORED_SNAPSHOT", observed.snapshot_uid).await?;
        if let Some(ref ready) = observed.ready {
            if ready.snapshot_uid != observed.snapshot_uid
                || ready.size_bytes != p.context.size_bytes
            {
                return Err(policy::invalid());
            }
            intent(
                &mut tx,
                &r,
                "RESTORED_CONTENT",
                "",
                &ready.content_name,
                None,
            )
            .await?;
            binding(&mut tx, &r, "RESTORED_CONTENT", ready.content_uid).await?;
            let expected = SnapshotReceipt {
                snapshot_uid: ready.snapshot_uid,
                content_uid: ready.content_uid,
                content_name: ready.content_name.clone(),
                cloud_snapshot: ready.cloud_snapshot.clone(),
                size_bytes: i64::try_from(ready.size_bytes).map_err(|_| policy::invalid())?,
            };
            let old:Option<SnapshotReceipt>=sqlx::query_as("SELECT snapshot_uid,content_uid,content_name,cloud_snapshot,size_bytes FROM restore_snapshot_receipts WHERE tenant_id=$1 AND restore_id=$2").bind(r.tenant_id).bind(r.id).fetch_optional(&mut *tx).await?;
            if old.is_some_and(|old| old != expected) {
                return Err(policy::blocked("Restore snapshot receipt changed"));
            }
            sqlx::query("INSERT INTO restore_snapshot_receipts(restore_id,tenant_id,snapshot_uid,content_uid,content_name,cloud_snapshot,size_bytes) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(restore_id) DO NOTHING")
                .bind(r.id).bind(r.tenant_id).bind(expected.snapshot_uid).bind(expected.content_uid).bind(expected.content_name).bind(expected.cloud_snapshot).bind(expected.size_bytes).execute(&mut *tx).await?;
            advance(&mut tx, &r, "DELIVERY_PENDING").await?;
        }
        tx.commit().await?;
        Ok(())
    }
    pub(crate) async fn prepare_restore_delivery(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<RestoreDeliveryPlan, ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let r = lock_restore(&mut tx, engine, claim).await?;
        if r.status != "DELIVERY_PENDING" {
            return Err(policy::blocked("Restore is outside filesystem delivery"));
        }
        let snapshot = snapshot_plan(&mut tx, &r).await?;
        let source = current_source(&mut tx, &r).await?;
        let receipt:SnapshotReceipt=sqlx::query_as("SELECT snapshot_uid,content_uid,content_name,cloud_snapshot,size_bytes FROM restore_snapshot_receipts WHERE tenant_id=$1 AND restore_id=$2").bind(r.tenant_id).bind(r.id).fetch_one(&mut *tx).await?;
        if receipt.size_bytes
            != i64::try_from(snapshot.context.size_bytes).map_err(|_| policy::invalid())?
            || snapshot.known_snapshot != Some(receipt.snapshot_uid)
            || snapshot.known_content != Some(receipt.content_uid)
        {
            return Err(policy::invalid());
        }
        for (kind, namespace, name, body) in [
            (
                "DELIVERY_CONTENT",
                "",
                snapshot.context.delivery_snapshot_name(),
                snapshot
                    .context
                    .delivery_content(&receipt.cloud_snapshot)
                    .map_err(|_| policy::invalid())?,
            ),
            (
                "DELIVERY_SNAPSHOT",
                snapshot.context.target_namespace.as_str(),
                snapshot.context.delivery_snapshot_name(),
                snapshot
                    .context
                    .delivery_snapshot()
                    .map_err(|_| policy::invalid())?,
            ),
            (
                "WORKSPACE_PVC",
                snapshot.context.target_namespace.as_str(),
                format!("ws-{}", r.workspace_id),
                snapshot
                    .context
                    .filesystem_pvc()
                    .map_err(|_| policy::invalid())?,
            ),
        ] {
            intent(&mut tx, &r, kind, namespace, &name, Some(&body)).await?;
        }
        let p = RestoreDeliveryPlan {
            snapshot,
            ready: RestoreSnapshotObservation {
                snapshot_uid: receipt.snapshot_uid,
                content_uid: receipt.content_uid,
                content_name: receipt.content_name,
                cloud_snapshot: receipt.cloud_snapshot,
                size_bytes: u64::try_from(receipt.size_bytes).map_err(|_| policy::invalid())?,
            },
            source_pvc_uid: source.identity.source_pvc_uid,
            source_clone_pvc_uid: source.identity.clone_pvc_uid,
            known_snapshot: resource_binding(&mut tx, r.tenant_id, r.id, "DELIVERY_SNAPSHOT")
                .await?,
            known_content: resource_binding(&mut tx, r.tenant_id, r.id, "DELIVERY_CONTENT").await?,
            known_pvc: resource_binding(&mut tx, r.tenant_id, r.id, "WORKSPACE_PVC").await?,
            known_pv: resource_binding(&mut tx, r.tenant_id, r.id, "WORKSPACE_PV").await?,
        };
        tx.commit().await?;
        Ok(p)
    }
    pub(crate) async fn record_restore_delivery(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        observed: &VerifiedRestoreDelivery,
    ) -> Result<(), ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let r = lock_restore(&mut tx, engine, claim).await?;
        if r.status != "DELIVERY_PENDING" {
            return Err(policy::blocked(
                "Restore filesystem receipt arrived outside its stage",
            ));
        }
        let p = snapshot_plan(&mut tx, &r).await?;
        let source = current_source(&mut tx, &r).await?;
        fresh(&mut tx, observed.observed_at).await?;
        if observed.tenant_id != r.tenant_id
            || observed.restore_id != r.id
            || [
                p.raw.pvc_uid,
                source.identity.source_pvc_uid,
                source.identity.clone_pvc_uid,
            ]
            .contains(&observed.pvc_uid)
        {
            return Err(policy::invalid());
        }
        binding(&mut tx, &r, "DELIVERY_CONTENT", observed.content_uid).await?;
        binding(&mut tx, &r, "DELIVERY_SNAPSHOT", observed.snapshot_uid).await?;
        binding(&mut tx, &r, "WORKSPACE_PVC", observed.pvc_uid).await?;
        if let Some(ref bound) = observed.bound {
            if bound.pvc_uid != observed.pvc_uid
                || bound.pv_uid == p.raw.pv_uid
                || bound.cloud_disk == p.raw.cloud_disk
                || bound.size_bytes != p.context.size_bytes
            {
                return Err(policy::invalid());
            }
            assert_new_storage(&mut tx, &r, bound).await?;
            intent(&mut tx, &r, "WORKSPACE_PV", "", &bound.pv_name, None).await?;
            binding(&mut tx, &r, "WORKSPACE_PV", bound.pv_uid).await?;
            let cloud_snapshot:String=sqlx::query_scalar("SELECT cloud_snapshot FROM restore_snapshot_receipts WHERE tenant_id=$1 AND restore_id=$2").bind(r.tenant_id).bind(r.id).fetch_one(&mut *tx).await?;
            let expected = DeliveryReceipt {
                workspace_id: r.workspace_id,
                namespace: p.context.target_namespace.clone(),
                snapshot_name: p.context.delivery_snapshot_name(),
                snapshot_uid: observed.snapshot_uid,
                content_uid: observed.content_uid,
                pvc_uid: observed.pvc_uid,
                pv_uid: bound.pv_uid,
                pv_name: bound.pv_name.clone(),
                cloud_disk: bound.cloud_disk.clone(),
                cloud_snapshot,
                size_bytes: i64::try_from(bound.size_bytes).map_err(|_| policy::invalid())?,
            };
            let old:Option<DeliveryReceipt>=sqlx::query_as("SELECT workspace_id,namespace,snapshot_name,snapshot_uid,content_uid,pvc_uid,pv_uid,pv_name,cloud_disk,cloud_snapshot,size_bytes FROM restore_delivery_receipts WHERE tenant_id=$1 AND restore_id=$2").bind(r.tenant_id).bind(r.id).fetch_optional(&mut *tx).await?;
            if old.is_some_and(|old| old != expected) {
                return Err(policy::blocked(
                    "Restore filesystem delivery receipt changed",
                ));
            }
            sqlx::query("INSERT INTO restore_delivery_receipts(restore_id,tenant_id,workspace_id,namespace,snapshot_name,snapshot_uid,content_uid,pvc_uid,pv_uid,pv_name,cloud_disk,cloud_snapshot,size_bytes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT(restore_id) DO NOTHING")
                .bind(r.id).bind(r.tenant_id).bind(expected.workspace_id).bind(expected.namespace).bind(expected.snapshot_name).bind(expected.snapshot_uid).bind(expected.content_uid).bind(expected.pvc_uid).bind(expected.pv_uid).bind(expected.pv_name).bind(expected.cloud_disk).bind(expected.cloud_snapshot).bind(expected.size_bytes).execute(&mut *tx).await?;
        }
        // WFFC alone cannot produce a bound receipt. No ordinary instance starts
        // and no workspace, hold, source reference or quota is released here.
        tx.commit().await?;
        Ok(())
    }
}

async fn fresh(
    tx: &mut Transaction<'_, Postgres>,
    observed: DateTime<Utc>,
) -> Result<(), ApiError> {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    if observed < now - Duration::seconds(30) || observed > now + Duration::seconds(2) {
        return Err(policy::blocked("Restore CSI observation is not fresh"));
    }
    Ok(())
}
