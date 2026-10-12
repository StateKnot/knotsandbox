//! Recover compute-only DELETE from an already proven STOPPED launch.
//! Immutable host/cleanup receipts survive controller restarts. No cloud or
//! Kubernetes absence is fabricated, and workspace reservations remain held.
use super::*;

impl Database {
    pub async fn complete_stopped_instance_deletion(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<(), ApiError> {
        let (mut tx, s) = lock_current(self, claim.tenant_id, claim.operation_id).await?;
        engine.assert_claim(&mut tx, claim).await?;
        if s.kind != "DELETE"
            || s.observed_state != "STOPPED"
            || s.desired_state != "DELETED"
            || s.cluster_epoch != s.current_epoch
            || s.workspace_status != "AVAILABLE"
            || s.slot_held
        {
            return Err(blocked("INSTANCE_DELETE_NOT_READY"));
        }
        let proof: Option<Uuid> = sqlx::query_scalar("SELECT p.id FROM instances i JOIN local_termination_proofs p ON p.tenant_id=i.tenant_id AND p.id=i.last_termination_proof_id JOIN termination_cleanup_receipts c ON c.tenant_id=p.tenant_id AND c.proof_id=p.id WHERE i.tenant_id=$1 AND i.id=$2 AND p.instance_id=i.id AND p.workspace_id=i.workspace_id AND p.generation=i.runtime_generation AND p.launch_id=i.launch_id AND p.pod_uid=i.pod_uid AND p.cluster_epoch=i.cluster_epoch AND c.old_pod_uid=p.pod_uid")
            .bind(s.tenant_id).bind(s.instance_id).fetch_optional(&mut *tx).await?;
        let proof = proof.ok_or_else(|| blocked("INSTANCE_DELETE_TERMINATION_PROOF_REQUIRED"))?;
        let exact_pod_deleted: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM external_resources WHERE tenant_id=$1 AND instance_id=$2 AND workspace_id=$3 AND provider='kubernetes' AND kind='POD' AND provider_id=$4 AND generation=$5 AND owner_id=$2 AND status='DELETED')")
            .bind(s.tenant_id).bind(s.instance_id).bind(s.workspace_id).bind(s.pod_uid.map(|id| id.to_string())).bind(s.generation).fetch_one(&mut *tx).await?;
        let active_activity: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM executions WHERE tenant_id=$1 AND instance_id=$2 AND slot_held)")
            .bind(s.tenant_id).bind(s.instance_id).fetch_one(&mut *tx).await?;
        if !exact_pod_deleted || active_activity {
            return Err(blocked("INSTANCE_DELETE_ACTIVITY_OR_POD_REMAINS"));
        }
        sqlx::query("SELECT id FROM quota_accounts WHERE tenant_id=$1 AND (project_id=$2 OR project_id IS NULL) ORDER BY id FOR UPDATE")
            .bind(s.tenant_id).bind(s.project_id).fetch_all(&mut *tx).await?;
        let reservations: Vec<(Uuid, Uuid, i64, String, String)> = sqlx::query_as("SELECT r.id,r.quota_account_id,r.amount,r.status,q.dimension FROM quota_reservations r JOIN quota_accounts q ON q.tenant_id=r.tenant_id AND q.id=r.quota_account_id WHERE r.tenant_id=$1 AND r.resource_id=$2 AND r.status IN('PENDING','ALLOCATED') AND q.dimension IN('CPU_MILLIS','MEMORY_MIB','INSTANCES','EXECUTIONS') ORDER BY r.quota_account_id,r.id FOR UPDATE OF r")
            .bind(s.tenant_id).bind(s.instance_id).fetch_all(&mut *tx).await?;
        if reservations.len() != 2 || reservations.iter().any(|r| r.2 != 1 || r.4 != "INSTANCES") {
            return Err(blocked("INSTANCE_DELETE_QUOTA_LEDGER_MISMATCH"));
        }
        for (reservation, account, amount, status, _) in reservations {
            sqlx::query("UPDATE quota_accounts SET pending=pending-CASE WHEN $4='PENDING' THEN $3 ELSE 0 END,allocated=allocated-CASE WHEN $4='ALLOCATED' THEN $3 ELSE 0 END,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
                .bind(s.tenant_id).bind(account).bind(amount).bind(status).execute(&mut *tx).await?;
            sqlx::query("UPDATE quota_reservations SET status='RELEASED',released_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
                .bind(s.tenant_id).bind(reservation).execute(&mut *tx).await?;
        }
        deletion_events(&mut tx, &s, proof).await?;
        // Event sequencing can wait on another transaction. Fence once more
        // after that wait, immediately before publishing completion.
        engine.assert_claim(&mut tx, claim).await?;
        let epoch_valid: bool = sqlx::query_scalar(
            "SELECT cluster_epoch=$1 FROM platform_configuration WHERE singleton",
        )
        .bind(s.cluster_epoch)
        .fetch_one(&mut *tx)
        .await?;
        if !epoch_valid {
            return Err(blocked("CLUSTER_EPOCH_CHANGED"));
        }
        sqlx::query("UPDATE instances SET observed_state='DELETED',deleted_at=clock_timestamp(),observed_at=clock_timestamp(),active_operation_id=NULL,spec_version=spec_version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
            .bind(s.tenant_id).bind(s.instance_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE workspaces SET active_operation_id=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND active_operation_id=$3")
            .bind(s.tenant_id).bind(s.workspace_id).bind(s.operation_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE operations SET status='SUCCEEDED',stage='COMPLETED',error=NULL,wait_reason=NULL,lease_owner=NULL,lease_until=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
            .bind(s.tenant_id).bind(s.operation_id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
}

pub(super) async fn deletion_events(
    tx: &mut Transaction<'_, Postgres>,
    s: &Current,
    proof: Uuid,
) -> Result<(), ApiError> {
    let details = json!({"generation":s.generation,"launch_id":s.launch_id,"proof_id":proof,"workspace_preserved":true,"workspace_id":s.workspace_id});
    sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details) VALUES($1,$2,$3,$4,$5,$6,'instances:delete','SUCCEEDED',$7)")
        .bind(s.tenant_id).bind(s.project_id).bind(s.actor_principal_id).bind(s.request_id).bind(s.operation_id).bind(s.instance_id).bind(&details).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload) VALUES($1,$2,$3,$4,'instance.deleted',$5,$6,$7)")
        .bind(s.tenant_id).bind(s.project_id).bind(s.instance_id).bind(s.generation).bind(s.operation_id).bind(s.request_id).bind(details).execute(&mut **tx).await?;
    Ok(())
}
