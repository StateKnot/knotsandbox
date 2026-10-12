//! Completing a backup needs the independently verified vault and both isolated
//! host closures. Retained clone/storage accounting is never freed by Pod deletion.
use super::*;
use crate::{
    backup_manifest::{ATTEMPT_LABEL, BACKUP_LABEL, NAMESPACE, capture_name},
    backup_object::{BackupIdentity, BackupVaultExpectation, VerifiedBackupVault},
};

pub(crate) struct CaptureConfig {
    pub object: Value,
    pub known_uid: Option<Uuid>,
}
impl Database {
    pub(crate) async fn backup_record(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<BackupRecord, ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let b = lock_backup(&mut tx, engine, claim).await?;
        tx.commit().await?;
        Ok(b)
    }
    pub(crate) async fn prepare_capture_config(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<CaptureConfig, ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let b = lock_backup(&mut tx, engine, claim).await?;
        authorize_backup(&mut tx, &b).await?;
        if b.status != "SEAL_PENDING" {
            return Err(blocked(
                "Capture handoff only after trusted CAPTURE cleanup",
            ));
        }
        let report: Value = sqlx::query_scalar(
            "SELECT report FROM backup_capture_reports WHERE tenant_id=$1 AND backup_id=$2",
        )
        .bind(b.tenant_id)
        .bind(b.id)
        .fetch_one(&mut *tx)
        .await?;
        let closed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM backup_termination_proofs p JOIN backup_cleanup_receipts c ON c.tenant_id=p.tenant_id AND c.proof_id=p.id WHERE p.tenant_id=$1 AND p.attempt_id=$2)").bind(b.tenant_id).bind(b.capture_attempt_id).fetch_one(&mut *tx).await?;
        if !closed {
            return Err(blocked("CAPTURE is not closed"));
        }
        let object = json!({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":capture_name(b.id),"namespace":NAMESPACE,"labels":{BACKUP_LABEL:b.id,ATTEMPT_LABEL:b.capture_attempt_id,"sandbox.platform/tenant-id":b.tenant_id,"sandbox.platform/project-id":b.project_id,"sandbox.platform/cluster-epoch":b.cluster_epoch}},"immutable":true,"data":{"capture.json":report.to_string()}});
        resource_intent(
            &mut tx,
            b.tenant_id,
            b.id,
            Some(b.capture_attempt_id),
            "CAPTURE_REPORT",
            NAMESPACE,
            &capture_name(b.id),
            Some(&object),
        )
        .await?;
        let known_uid = binding(&mut tx, b.tenant_id, b.id, "CAPTURE_REPORT").await?;
        tx.commit().await?;
        Ok(CaptureConfig { object, known_uid })
    }
    pub(crate) async fn record_capture_config(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        uid: Uuid,
    ) -> Result<(), ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let b = lock_backup(&mut tx, engine, claim).await?;
        authorize_backup(&mut tx, &b).await?;
        let id:Uuid=sqlx::query_scalar("SELECT id FROM backup_resource_intents WHERE tenant_id=$1 AND backup_id=$2 AND kind='CAPTURE_REPORT'").bind(b.tenant_id).bind(b.id).fetch_one(&mut *tx).await?;
        bind_resource(&mut tx, b.tenant_id, b.id, id, uid).await?;
        tx.commit().await?;
        Ok(())
    }
    pub(crate) async fn backup_vault_expectation(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<BackupVaultExpectation, ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let b = lock_backup(&mut tx, engine, claim).await?;
        if b.status != "SEAL_CLOSING" {
            return Err(blocked(
                "SEAL must be permanently closed before vault verification",
            ));
        }
        both_closed(&mut tx, &b).await?;
        let result = vault_expectation(&mut tx, &b).await?;
        tx.commit().await?;
        Ok(result)
    }
    pub(crate) async fn complete_backup(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        proof: &VerifiedBackupVault,
    ) -> Result<(), ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let b = lock_backup(&mut tx, engine, claim).await?;
        if b.status != "SEAL_CLOSING" {
            return Err(blocked("Backup is not ready for vault completion"));
        }
        both_closed(&mut tx, &b).await?;
        let expected = vault_expectation(&mut tx, &b).await?;
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let settings:Option<Value>=sqlx::query_scalar("SELECT bp.settings FROM backup_profiles bp CROSS JOIN platform_configuration c WHERE bp.id=$1 AND bp.cluster_epoch=$2 AND c.cluster_epoch=$2 AND bp.enabled AND bp.certified_until>clock_timestamp()")
            .bind(b.profile_id).bind(b.cluster_epoch).fetch_optional(&mut *tx).await?;
        let cloud: crate::backup_job::BackupCloudSettings = serde_json::from_value(
            settings
                .ok_or_else(|| blocked("Current vault WORM/RAM/runtime certification required"))?,
        )
        .map_err(|_| internal("Approved profile invalid"))?;
        if proof.identity() != &expected.identity
            || proof.snapshot_id() != expected.snapshot_id
            || proof.disk_sha256() != expected.disk_sha256
            || proof.signing_key_sha256() != cloud.signing_key_sha256
            || proof.vault_endpoint() != cloud.vault_endpoint
            || proof.verified_at() < now - Duration::minutes(5)
            || proof.verified_at() > now + Duration::seconds(2)
        {
            return Err(blocked(
                "Vault proof does not bind current approved backup identity",
            ));
        }
        let manifest = json!({"manifest":proof.manifest(),"signing_key_sha256":proof.signing_key_sha256(),"vault_endpoint":proof.vault_endpoint()});
        sqlx::query("INSERT INTO backup_vault_receipts(backup_id,tenant_id,manifest_sha256,manifest,verified_at) VALUES($1,$2,$3,$4,$5)")
            .bind(b.id).bind(b.tenant_id).bind(proof.manifest_sha256()).bind(manifest).bind(proof.verified_at()).execute(&mut *tx).await?;
        advance(&mut tx, &b, "AVAILABLE").await?;
        finish_accounting(&mut tx, &b, true).await?;
        sqlx::query("INSERT INTO workspace_hold_releases(hold_id,tenant_id,reason) VALUES($1,$2,'Independent signed vault verified; all isolated writers closed')").bind(b.hold_id).bind(b.tenant_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE operations SET status='SUCCEEDED',stage='BACKUP_AVAILABLE',lease_owner=NULL,lease_until=NULL,wait_reason=NULL,error=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(b.tenant_id).bind(b.operation_id).execute(&mut *tx).await?;
        completion_audit(&mut tx, &b, "SUCCEEDED").await?;
        tx.commit().await?;
        Ok(())
    }
    /// This is only a cancellation reason. `cancel_quiescent_backup` separately
    /// requires every admitted writer's trusted closure and actual cleanup.
    pub(crate) async fn backup_completion_expired_or_failed(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<bool, ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let b = lock_backup(&mut tx, engine, claim).await?;
        let stop:bool=sqlx::query_scalar("SELECT $3<=clock_timestamp() OR EXISTS(SELECT 1 FROM backup_stage_results r WHERE r.tenant_id=$1 AND r.backup_id=$2 AND r.exit_code<>0) OR NOT EXISTS(SELECT 1 FROM backup_profiles p CROSS JOIN platform_configuration c WHERE p.id=$4 AND p.enabled AND p.certified_until>clock_timestamp() AND p.cluster_epoch=c.cluster_epoch AND c.cluster_epoch=$5)")
            .bind(b.tenant_id).bind(b.id).bind(b.deadline).bind(b.profile_id).bind(b.cluster_epoch).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(stop)
    }
    pub(crate) async fn cancel_quiescent_backup(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<bool, ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let b = lock_backup(&mut tx, engine, claim).await?;
        let safe:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM backup_pod_admissions a WHERE a.tenant_id=$1 AND a.backup_id=$2 AND NOT EXISTS(SELECT 1 FROM backup_termination_proofs p JOIN backup_cleanup_receipts c ON c.tenant_id=p.tenant_id AND c.proof_id=p.id WHERE p.tenant_id=a.tenant_id AND p.attempt_id=a.attempt_id)) AND NOT EXISTS(SELECT 1 FROM backup_launch_permits l WHERE l.tenant_id=$1 AND l.backup_id=$2 AND NOT EXISTS(SELECT 1 FROM backup_termination_proofs p JOIN backup_cleanup_receipts c ON c.tenant_id=p.tenant_id AND c.proof_id=p.id WHERE p.tenant_id=l.tenant_id AND p.permit_id=l.id))")
            .bind(b.tenant_id).bind(b.id).fetch_one(&mut *tx).await?;
        if !safe || matches!(b.status.as_str(), "AVAILABLE" | "CANCELLED") {
            return Ok(false);
        }
        advance(&mut tx, &b, "CANCELLED").await?;
        finish_accounting(&mut tx, &b, false).await?;
        sqlx::query("INSERT INTO workspace_hold_releases(hold_id,tenant_id,reason) VALUES($1,$2,'Permanent backup cancellation; all admitted writers have trusted cleanup')").bind(b.hold_id).bind(b.tenant_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE operations SET status='FAILED',stage='BACKUP_CANCELLED',error=$3,lease_owner=NULL,lease_until=NULL,wait_reason=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
            .bind(b.tenant_id).bind(b.operation_id).bind(json!({"code":"BACKUP_AUTHORITY_UNAVAILABLE","retryable":false,"retained_storage_accounted":true})).execute(&mut *tx).await?;
        completion_audit(&mut tx, &b, "FAILED").await?;
        tx.commit().await?;
        Ok(true)
    }
    pub(crate) async fn finish_failed_capture(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<bool, ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let b = lock_backup(&mut tx, engine, claim).await?;
        if b.status != "CAPTURE_CLOSING" {
            return Ok(false);
        }
        let safe:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM backup_capture_reports WHERE tenant_id=$1 AND backup_id=$2) AND EXISTS(SELECT 1 FROM backup_termination_proofs p JOIN backup_cleanup_receipts c ON c.tenant_id=p.tenant_id AND c.proof_id=p.id WHERE p.tenant_id=$1 AND p.attempt_id=$3)").bind(b.tenant_id).bind(b.id).bind(b.capture_attempt_id).fetch_one(&mut *tx).await?;
        if !safe {
            return Ok(false);
        }
        advance(&mut tx, &b, "CANCELLED").await?;
        finish_accounting(&mut tx, &b, false).await?;
        // Database trigger checks every admitted Pod and every permit, including
        // attempts whose remote create/registration response was lost.
        sqlx::query("INSERT INTO workspace_hold_releases(hold_id,tenant_id,reason) VALUES($1,$2,'Failed capture; every isolated writer has trusted termination and cleanup')").bind(b.hold_id).bind(b.tenant_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE operations SET status='FAILED',stage='BACKUP_CAPTURE_FAILED',error=$3,lease_owner=NULL,lease_until=NULL,wait_reason=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
            .bind(b.tenant_id).bind(b.operation_id).bind(json!({"code":"BACKUP_CAPTURE_FAILED","retryable":false,"retained_storage_accounted":true})).execute(&mut *tx).await?;
        completion_audit(&mut tx, &b, "FAILED").await?;
        tx.commit().await?;
        Ok(true)
    }
}
async fn both_closed(tx: &mut Transaction<'_, Postgres>, b: &BackupRecord) -> Result<(), ApiError> {
    let count:i64=sqlx::query_scalar("SELECT count(DISTINCT a.stage) FROM backup_attempts a JOIN backup_termination_proofs p ON p.tenant_id=a.tenant_id AND p.attempt_id=a.id JOIN backup_cleanup_receipts c ON c.tenant_id=p.tenant_id AND c.proof_id=p.id WHERE a.tenant_id=$1 AND a.backup_id=$2 AND a.stage IN('CAPTURE','SEAL')").bind(b.tenant_id).bind(b.id).fetch_one(&mut **tx).await?;
    if count != 2 {
        return Err(blocked(
            "CAPTURE and SEAL both need trusted termination and cleanup",
        ));
    }
    Ok(())
}
async fn vault_expectation(
    tx: &mut Transaction<'_, Postgres>,
    b: &BackupRecord,
) -> Result<BackupVaultExpectation, ApiError> {
    let context:Value=sqlx::query_scalar("SELECT context FROM backup_job_contexts WHERE tenant_id=$1 AND backup_id=$2 AND attempt_id=$3").bind(b.tenant_id).bind(b.id).bind(b.seal_attempt_id).fetch_one(&mut **tx).await?;
    let context: crate::backup_manifest::BackupManifestContext =
        serde_json::from_value(context).map_err(|_| internal("SEAL context invalid"))?;
    let mut config: Value =
        serde_json::from_str(&context.config_json).map_err(|_| internal("SEAL config invalid"))?;
    let object = config
        .as_object_mut()
        .ok_or_else(|| internal("SEAL config not object"))?;
    for key in [
        "roles",
        "issuer",
        "oidc_provider_arn",
        "runtime_certification_sha256",
        "deadline",
    ] {
        object.remove(key);
    }
    let identity: BackupIdentity =
        serde_json::from_value(config).map_err(|_| internal("SEAL backup identity invalid"))?;
    let report: Value = sqlx::query_scalar(
        "SELECT report FROM backup_capture_reports WHERE tenant_id=$1 AND backup_id=$2",
    )
    .bind(b.tenant_id)
    .bind(b.id)
    .fetch_one(&mut **tx)
    .await?;
    let snapshot_id = report
        .get("snapshot_id")
        .and_then(Value::as_str)
        .ok_or_else(|| internal("Capture snapshot invalid"))?
        .into();
    let disk_sha256 = report
        .pointer("/disk/sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| internal("Capture checksum invalid"))?
        .into();
    Ok(BackupVaultExpectation {
        identity,
        snapshot_id,
        disk_sha256,
        manifest_sha256: None,
    })
}
async fn finish_accounting(
    tx: &mut Transaction<'_, Postgres>,
    b: &BackupRecord,
    _available: bool,
) -> Result<(), ApiError> {
    let reservations:Vec<(Uuid,Uuid,i64,String,String)>=sqlx::query_as("SELECT r.id,r.quota_account_id,r.amount,r.status,q.dimension FROM quota_reservations r JOIN quota_accounts q ON q.tenant_id=r.tenant_id AND q.id=r.quota_account_id WHERE r.tenant_id=$1 AND r.operation_id=$2 AND r.status IN('PENDING','ALLOCATED') ORDER BY r.quota_account_id,r.id FOR UPDATE OF r,q")
        .bind(b.tenant_id).bind(b.operation_id).fetch_all(&mut **tx).await?;
    for (id, account, amount, status, dimension) in reservations {
        if matches!(dimension.as_str(), "CPU_MILLIS" | "MEMORY_MIB") {
            sqlx::query("UPDATE quota_accounts SET pending=pending-CASE WHEN $4='PENDING' THEN $3 ELSE 0 END,allocated=allocated-CASE WHEN $4='ALLOCATED' THEN $3 ELSE 0 END,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
                .bind(b.tenant_id).bind(account).bind(amount).bind(status).execute(&mut **tx).await?;
            sqlx::query("UPDATE quota_reservations SET status='RELEASED',released_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(b.tenant_id).bind(id).execute(&mut **tx).await?;
        } else if status == "PENDING" {
            sqlx::query("UPDATE quota_accounts SET pending=pending-$3,allocated=allocated+$3,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(b.tenant_id).bind(account).bind(amount).execute(&mut **tx).await?;
            sqlx::query("UPDATE quota_reservations SET status='ALLOCATED',updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(b.tenant_id).bind(id).execute(&mut **tx).await?;
        }
    }
    Ok(())
}
async fn completion_audit(
    tx: &mut Transaction<'_, Postgres>,
    b: &BackupRecord,
    outcome: &str,
) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details) SELECT $1,$2,actor_principal_id,request_id,$3,$4,'backups:complete',$5,$6 FROM operations WHERE tenant_id=$1 AND id=$3")
        .bind(b.tenant_id).bind(b.project_id).bind(b.operation_id).bind(b.id).bind(outcome).bind(json!({"retained_clone_accounted":true,"consistency":"STOPPED_CONSISTENT"})).execute(&mut **tx).await?;
    Ok(())
}
