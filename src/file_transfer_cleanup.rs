//! Temp object retention and conservative UNKNOWN writer accounting.
use super::ledger::{blocked, db_now, event, load, lock_transfer, release_dimension};
use crate::{
    db::{Actor, Database},
    error::ApiError,
    file_store::{FilePartCleanupReceipt, FilePartIdentity, FilePartReceipt},
};
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;
pub struct FileCleanupBatch {
    pub tenant_id: Uuid,
    pub transfer_id: Uuid,
    pub parts: Vec<FilePartReceipt>,
    pub writer_outcome_unknown: bool,
}
impl Database {
    pub async fn file_cleanup_candidates(&self) -> Result<Vec<(Uuid, Uuid)>, ApiError> {
        Ok(
            sqlx::query_as("SELECT tenant_id,transfer_id FROM sandbox_file_cleanup_candidates(32)")
                .fetch_all(&self.pool)
                .await?,
        )
    }
    pub async fn prepare_file_cleanup(
        &self,
        tenant: Uuid,
        id: Uuid,
    ) -> Result<Option<FileCleanupBatch>, ApiError> {
        let (mut tx, r, _) = lock_transfer(self, tenant, id).await?;
        if r.content_status == "CLEANED"
            || r.content_expires_at > db_now(&mut tx).await?
            || !matches!(r.process_status.as_str(), "EXITED" | "VM_TERMINATED")
        {
            tx.commit().await?;
            return Ok(None);
        }
        let rows=sqlx::query("SELECT content_id,part_index,byte_length,sha256,object_key,put_state FROM file_transfer_parts WHERE tenant_id=$1 AND transfer_id=$2 AND status<>'CLEANED' ORDER BY part_index").bind(tenant).bind(id).fetch_all(&mut *tx).await?;
        let mut parts = Vec::new();
        let mut writer_outcome_unknown = false;
        for p in rows {
            writer_outcome_unknown |= p.try_get::<String, _>("put_state")? != "ACKED";
            parts.push(FilePartReceipt {
                identity: FilePartIdentity {
                    tenant_id: tenant,
                    transfer_id: id,
                    content_id: p.try_get("content_id")?,
                    index: p.try_get::<i32, _>("part_index")? as u32,
                },
                object_key: p.try_get("object_key")?,
                byte_length: p.try_get::<i64, _>("byte_length")? as u64,
                sha256: p.try_get("sha256")?,
            });
        }
        sqlx::query(
            "UPDATE file_transfers SET content_status='CLEANING' WHERE tenant_id=$1 AND id=$2",
        )
        .bind(tenant)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(FileCleanupBatch {
            tenant_id: tenant,
            transfer_id: id,
            parts,
            writer_outcome_unknown,
        }))
    }
    pub async fn record_file_part_cleanup(
        &self,
        receipt: &FilePartCleanupReceipt,
    ) -> Result<bool, ApiError> {
        receipt
            .part
            .validate()
            .map_err(|_| blocked("INVALID_FILE_PART"))?;
        let identity = receipt.part.identity;
        let (mut tx, r, _) = lock_transfer(self, identity.tenant_id, identity.transfer_id).await?;
        let now = db_now(&mut tx).await?;
        if r.content_status != "CLEANING"
            || !matches!(r.process_status.as_str(), "EXITED" | "VM_TERMINATED")
            || receipt.confirmed_absent_at < now - chrono::Duration::seconds(30)
            || receipt.confirmed_absent_at > now + chrono::Duration::seconds(2)
        {
            return Err(blocked("FILE_CLEANUP_FENCED"));
        }
        let p=sqlx::query("SELECT content_id,byte_length,sha256,object_key,put_state,status FROM file_transfer_parts WHERE tenant_id=$1 AND transfer_id=$2 AND part_index=$3 FOR UPDATE").bind(identity.tenant_id).bind(identity.transfer_id).bind(identity.index as i32).fetch_one(&mut *tx).await?;
        if p.try_get::<Uuid, _>("content_id")? != identity.content_id
            || p.try_get::<i64, _>("byte_length")? as u64 != receipt.part.byte_length
            || p.try_get::<String, _>("sha256")? != receipt.part.sha256
            || p.try_get::<String, _>("object_key")? != receipt.part.object_key
        {
            return Err(blocked("FILE_CLEANUP_IDENTITY_MISMATCH"));
        }
        if p.try_get::<String, _>("put_state")? != "ACKED" {
            tx.commit().await?;
            return Ok(false);
        } // absence cannot fence a previously ambiguous PUT.
        sqlx::query("INSERT INTO file_part_cleanup_receipts(tenant_id,project_id,transfer_id,part_index,confirmed_absent_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,transfer_id,part_index) DO NOTHING").bind(identity.tenant_id).bind(r.project_id).bind(r.id).bind(identity.index as i32).bind(receipt.confirmed_absent_at).execute(&mut *tx).await?;
        sqlx::query("UPDATE file_transfer_parts SET status='CLEANED',cleaned_at=COALESCE(cleaned_at,clock_timestamp()) WHERE tenant_id=$1 AND transfer_id=$2 AND part_index=$3").bind(identity.tenant_id).bind(r.id).bind(identity.index as i32).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(true)
    }
    pub async fn finish_file_cleanup(&self, tenant: Uuid, id: Uuid) -> Result<bool, ApiError> {
        let (mut tx, r, _) = lock_transfer(self, tenant, id).await?;
        if r.content_status == "CLEANED" {
            tx.commit().await?;
            return Ok(true);
        }
        if r.content_status != "CLEANING"
            || !matches!(r.process_status.as_str(), "EXITED" | "VM_TERMINATED")
        {
            return Err(blocked("FILE_CLEANUP_FENCED"));
        }
        let clean:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM file_transfer_parts WHERE tenant_id=$1 AND transfer_id=$2 AND(status<>'CLEANED' OR put_state<>'ACKED'))").bind(tenant).bind(id).fetch_one(&mut *tx).await?;
        if !clean {
            tx.commit().await?;
            return Ok(false);
        }
        sqlx::query(
            "UPDATE file_transfers SET content_status='CLEANED' WHERE tenant_id=$1 AND id=$2",
        )
        .bind(tenant)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        release_dimension(&mut tx, &r, "FILE_TRANSFER_BYTES", r.byte_limit.max(1)).await?;
        let principal_id = sqlx::query_scalar(
            "SELECT safety_principal_id FROM platform_configuration WHERE singleton",
        )
        .fetch_one(&mut *tx)
        .await?;
        event(
            &mut tx,
            &Actor {
                authorization: None, tenant_id: tenant, principal_id, request_id: Uuid::new_v4() },
            &r,
            "files:content_cleaned",
            json!({"retained_bytes_released":true,"storage_writer_status":"ACKNOWLEDGED","object_absence_confirmed":true}),
        )
        .await?;
        let current = load(&mut tx, tenant, id, false).await?;
        if current.content_status != "CLEANED" {
            return Err(blocked("FILE_CLEANUP_FENCED"));
        }
        tx.commit().await?;
        Ok(true)
    }
}
