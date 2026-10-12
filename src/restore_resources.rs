//! Durable create-before-I/O intent and immutable Kube UIDs. WFFC raw disks may
//! be unbound until the single admitted Pod is scheduled; host registration
//! still requires the later exact Block-device receipt.
use super::{
    RestoreRecord,
    ledger::{advance, current_cloud, current_source, lock_restore, resource_binding},
    manifest::{RestoreStorageContext, generated_block_pv_name},
    policy,
    storage::RestoreBlockObservation,
};
use crate::{
    backup_job::{BackupCloudSettings, ObservedBackupPod},
    backup_manifest::{NAMESPACE, config_name},
    backup_object::BackupIdentity,
    backup_runtime::BoundBackupVolume,
    db::Database,
    engine::{Claim, OperationEngine},
    error::ApiError,
};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub(crate) struct RestoreStoragePlan {
    pub context: RestoreStorageContext,
    pub cloud: BackupCloudSettings,
    pub source: BackupIdentity,
    pub known_pvc: Option<Uuid>,
    pub known_pv: Option<Uuid>,
}
pub(super) async fn intent(
    tx: &mut Transaction<'_, Postgres>,
    r: &RestoreRecord,
    kind: &str,
    namespace: &str,
    name: &str,
    expected: Option<&Value>,
) -> Result<Uuid, ApiError> {
    let old = sqlx::query(
        "SELECT * FROM restore_resource_intents WHERE tenant_id=$1 AND restore_id=$2 AND kind=$3",
    )
    .bind(r.tenant_id)
    .bind(r.id)
    .bind(kind)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(old) = old {
        if old.try_get::<String, _>("namespace")? != namespace
            || old.try_get::<String, _>("name")? != name
            || old.try_get::<Option<Value>, _>("expected_object")?.as_ref() != expected
        {
            return Err(policy::blocked(
                "Restore cannot change a durable resource intent",
            ));
        }
        return Ok(old.try_get("id")?);
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO restore_resource_intents(id,tenant_id,restore_id,kind,namespace,name,expected_object) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(id).bind(r.tenant_id).bind(r.id).bind(kind).bind(namespace).bind(name).bind(expected).execute(&mut **tx).await?;
    Ok(id)
}
pub(super) async fn binding(
    tx: &mut Transaction<'_, Postgres>,
    r: &RestoreRecord,
    kind: &str,
    uid: Uuid,
) -> Result<(), ApiError> {
    if uid.is_nil() {
        return Err(policy::invalid());
    }
    if let Some(old) = resource_binding(tx, r.tenant_id, r.id, kind).await? {
        if old != uid {
            return Err(policy::blocked("Restore resource UID changed"));
        }
        return Ok(());
    }
    let id: Uuid = sqlx::query_scalar(
        "SELECT id FROM restore_resource_intents WHERE tenant_id=$1 AND restore_id=$2 AND kind=$3",
    )
    .bind(r.tenant_id)
    .bind(r.id)
    .bind(kind)
    .fetch_one(&mut **tx)
    .await?;
    sqlx::query("INSERT INTO restore_resource_bindings(intent_id,tenant_id,restore_id,uid) VALUES($1,$2,$3,$4)").bind(id).bind(r.tenant_id).bind(r.id).bind(uid).execute(&mut **tx).await?;
    Ok(())
}
impl Database {
    pub(crate) async fn prepare_restore_storage(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<RestoreStoragePlan, ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let r = lock_restore(&mut tx, engine, claim).await?;
        if !matches!(
            r.status.as_str(),
            "VERIFIED" | "BLOCK_PENDING" | "RESTORE_PENDING" | "RESTORE_RUNNING"
        ) {
            return Err(policy::blocked(
                "Restore is outside raw-storage preparation",
            ));
        }
        let source = current_source(&mut tx, &r).await?;
        let cloud = current_cloud(&mut tx, &r, &source).await?;
        let verified:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM restore_vault_receipts WHERE tenant_id=$1 AND restore_id=$2 AND manifest_sha256=$3)").bind(r.tenant_id).bind(r.id).bind(&r.source_manifest_sha256).fetch_one(&mut *tx).await?;
        if !verified {
            return Err(policy::blocked(
                "Independent source verification must precede raw target creation",
            ));
        }
        let (namespace, storage): (String, String) = sqlx::query_as(
            "SELECT namespace,storage_class FROM workspaces WHERE tenant_id=$1 AND id=$2",
        )
        .bind(r.tenant_id)
        .bind(r.workspace_id)
        .fetch_one(&mut *tx)
        .await?;
        let storage_contract = r.storage()?;
        if storage != storage_contract.mapping.delivery.name {
            return Err(policy::invalid());
        }
        let context = RestoreStorageContext {
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
        };
        let body = context.block_pvc().map_err(|_| policy::invalid())?;
        intent(
            &mut tx,
            &r,
            "BLOCK_PVC",
            NAMESPACE,
            &crate::backup_manifest::block_pvc_name(r.id),
            Some(&body),
        )
        .await?;
        let known_pvc = resource_binding(&mut tx, r.tenant_id, r.id, "BLOCK_PVC").await?;
        let known_pv = resource_binding(&mut tx, r.tenant_id, r.id, "BLOCK_PV").await?;
        if r.status == "VERIFIED" {
            advance(&mut tx, &r, "BLOCK_PENDING").await?;
        }
        tx.commit().await?;
        Ok(RestoreStoragePlan {
            context,
            cloud,
            source: source.identity,
            known_pvc,
            known_pv,
        })
    }
    pub(crate) async fn record_restore_block(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        observed: &RestoreBlockObservation,
    ) -> Result<(), ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let r = lock_restore(&mut tx, engine, claim).await?;
        if !matches!(
            r.status.as_str(),
            "BLOCK_PENDING" | "RESTORE_PENDING" | "RESTORE_RUNNING"
        ) {
            return Err(policy::blocked(
                "Restore raw observation arrived outside its stage",
            ));
        }
        let source = current_source(&mut tx, &r).await?;
        current_cloud(&mut tx, &r, &source).await?;
        if observed.tenant_id != r.tenant_id
            || observed.restore_id != r.id
            || observed.source_backup_id != r.backup_id
            || observed.pvc_uid == source.identity.source_pvc_uid
            || observed.pvc_uid == source.identity.clone_pvc_uid
        {
            return Err(policy::blocked(
                "Restore cannot bind a historical source claim",
            ));
        }
        binding(&mut tx, &r, "BLOCK_PVC", observed.pvc_uid).await?;
        let pv_name = generated_block_pv_name(observed.pvc_uid).map_err(|_| policy::invalid())?;
        // WFFC fixes the future provisioner identity without inventing a PV,
        // cloud handle, binding or writer permit before a consumer exists.
        intent(&mut tx, &r, "BLOCK_PV", "", &pv_name, None).await?;
        if let Some(volume) = &observed.bound {
            if volume.pvc_uid != observed.pvc_uid
                || volume.size_bytes != source.identity.size_bytes
                || volume.pv_name != pv_name
            {
                return Err(policy::blocked(
                    "Restore raw device size or claim differs from immutable source",
                ));
            }
            assert_new_storage(&mut tx, &r, volume).await?;
            binding(&mut tx, &r, "BLOCK_PV", volume.pv_uid).await?;
            let old:Option<(Uuid,Uuid,String,String,i64)>=sqlx::query_as("SELECT pvc_uid,pv_uid,pv_name,cloud_disk,size_bytes FROM restore_block_receipts WHERE tenant_id=$1 AND restore_id=$2").bind(r.tenant_id).bind(r.id).fetch_optional(&mut *tx).await?;
            let size = i64::try_from(volume.size_bytes).map_err(|_| policy::invalid())?;
            if old.is_some_and(|old| {
                old != (
                    volume.pvc_uid,
                    volume.pv_uid,
                    volume.pv_name.clone(),
                    volume.cloud_disk.clone(),
                    size,
                )
            }) {
                return Err(policy::blocked("Restore raw device receipt changed"));
            }
            sqlx::query("INSERT INTO restore_block_receipts(restore_id,tenant_id,pvc_uid,pv_uid,pv_name,cloud_disk,size_bytes) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(restore_id) DO NOTHING")
                .bind(r.id).bind(r.tenant_id).bind(volume.pvc_uid).bind(volume.pv_uid).bind(&volume.pv_name).bind(&volume.cloud_disk).bind(size).execute(&mut *tx).await?;
        }
        // WFFC: schedule the single Pod, then persist the actual bound device
        // before requesting its only host permit. No byte write is authorized here.
        if r.status == "BLOCK_PENDING" {
            advance(&mut tx, &r, "RESTORE_PENDING").await?;
        }
        tx.commit().await?;
        Ok(())
    }
    pub(crate) async fn restore_bound_volume(
        &self,
        tenant: Uuid,
        restore: Uuid,
    ) -> Result<Option<BoundBackupVolume>, ApiError> {
        let mut tx = self.begin(tenant).await?;
        let row = sqlx::query(
            "SELECT * FROM restore_block_receipts WHERE tenant_id=$1 AND restore_id=$2",
        )
        .bind(tenant)
        .bind(restore)
        .fetch_optional(&mut *tx)
        .await?;
        let result = row
            .map(|r| -> Result<_, ApiError> {
                Ok(BoundBackupVolume {
                    pvc_uid: r.try_get("pvc_uid")?,
                    pv_uid: r.try_get("pv_uid")?,
                    pv_name: r.try_get("pv_name")?,
                    cloud_disk: r.try_get("cloud_disk")?,
                    size_bytes: u64::try_from(r.try_get::<i64, _>("size_bytes")?)
                        .map_err(|_| policy::invalid())?,
                })
            })
            .transpose()?;
        tx.commit().await?;
        Ok(result)
    }
    pub(crate) async fn record_restore_job_objects(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        config: Uuid,
        job: Uuid,
    ) -> Result<(), ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let r = lock_restore(&mut tx, engine, claim).await?;
        if r.status != "RESTORE_PENDING" {
            return Err(policy::blocked(
                "Restore Job creation requires a recorded new raw claim",
            ));
        }
        let source = current_source(&mut tx, &r).await?;
        current_cloud(&mut tx, &r, &source).await?;
        let context:Value=sqlx::query_scalar("SELECT context FROM restore_job_contexts WHERE tenant_id=$1 AND restore_id=$2 AND deadline>clock_timestamp()")
            .bind(r.tenant_id).bind(r.id).fetch_one(&mut *tx).await?;
        let context: crate::backup_manifest::BackupManifestContext =
            serde_json::from_value(context).map_err(|_| policy::invalid())?;
        let manifests = crate::backup_manifest::build_backup_manifests(&context)
            .map_err(|_| policy::invalid())?;
        // These intents are normally recorded by preparation before the request;
        // recording may never be used to authorize an earlier Kube mutation.
        for (kind, name, body) in [
            ("CONFIG", config_name(r.id), manifests.config_map),
            (
                "JOB",
                crate::nodeguard::protocol::backup_job_name(
                    r.id,
                    crate::nodeguard::protocol::BackupStage::Restore,
                ),
                manifests.job,
            ),
        ] {
            let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM restore_resource_intents WHERE tenant_id=$1 AND restore_id=$2 AND kind=$3 AND namespace=$4 AND name=$5 AND expected_object=$6)")
                .bind(r.tenant_id).bind(r.id).bind(kind).bind(NAMESPACE).bind(name).bind(body).fetch_one(&mut *tx).await?;
            if !exists {
                return Err(policy::blocked(
                    "Restore Job/config mutation had no prior durable intent",
                ));
            }
        }
        binding(&mut tx, &r, "CONFIG", config).await?;
        binding(&mut tx, &r, "JOB", job).await?;
        tx.commit().await?;
        Ok(())
    }
    pub(crate) async fn record_restore_pod(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        job: Uuid,
        pod: &ObservedBackupPod,
    ) -> Result<(), ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let r = lock_restore(&mut tx, engine, claim).await?;
        if !matches!(r.status.as_str(), "RESTORE_PENDING" | "RESTORE_RUNNING") {
            return Err(policy::blocked("Closing restore cannot adopt another Pod"));
        }
        let source = current_source(&mut tx, &r).await?;
        current_cloud(&mut tx, &r, &source).await?;
        let admitted:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM restore_pod_admissions WHERE tenant_id=$1 AND restore_id=$2 AND job_uid=$3)").bind(r.tenant_id).bind(r.id).bind(job).fetch_one(&mut *tx).await?;
        if !admitted {
            return Err(policy::blocked(
                "Restore Pod lacks consume-once durable admission",
            ));
        }
        intent(&mut tx, &r, "POD", NAMESPACE, &pod.name, None).await?;
        binding(&mut tx, &r, "POD", pod.uid).await?;
        tx.commit().await?;
        Ok(())
    }
}
pub(crate) async fn job_intents(
    tx: &mut Transaction<'_, Postgres>,
    r: &RestoreRecord,
    context: &crate::backup_manifest::BackupManifestContext,
) -> Result<(), ApiError> {
    let manifests =
        crate::backup_manifest::build_backup_manifests(context).map_err(|_| policy::invalid())?;
    for (kind, name, body) in [
        ("CONFIG", config_name(r.id), manifests.config_map),
        (
            "JOB",
            crate::nodeguard::protocol::backup_job_name(
                r.id,
                crate::nodeguard::protocol::BackupStage::Restore,
            ),
            manifests.job,
        ),
    ] {
        intent(tx, r, kind, NAMESPACE, &name, Some(&body)).await?;
    }
    Ok(())
}

pub(super) async fn assert_new_storage(
    tx: &mut Transaction<'_, Postgres>,
    r: &RestoreRecord,
    v: &BoundBackupVolume,
) -> Result<(), ApiError> {
    let reused:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM backups b WHERE b.tenant_id=$1 AND b.id=$2 AND(b.source->>'pvc_uid'=$3 OR b.source->>'pv_uid'=$4 OR b.source->>'cloud_disk'=$5)) OR EXISTS(SELECT 1 FROM backup_clone_receipts clone WHERE clone.tenant_id=$1 AND clone.backup_id=$2 AND(clone.pvc_uid=$6 OR clone.pv_uid=$7 OR clone.cloud_disk=$5))")
  .bind(r.tenant_id).bind(r.backup_id).bind(v.pvc_uid.to_string()).bind(v.pv_uid.to_string()).bind(&v.cloud_disk).bind(v.pvc_uid).bind(v.pv_uid).fetch_one(&mut **tx).await?;
    if reused {
        return Err(policy::blocked(
            "Restore raw/delivery storage reuses a historical source or backup clone device",
        ));
    }
    Ok(())
}
