//! Closure is committed before compute completion. A delayed controller cannot
//! insert a permit after closure; a permit committed before closure blocks this
//! route even when its host ACK was lost. Storage is deliberately retained.
use super::*;

impl Database {
    pub async fn complete_never_authorized_deletion(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<bool, ApiError> {
        let (mut tx, s) = lock_current(self, claim.tenant_id, claim.operation_id).await?;
        engine.assert_claim(&mut tx, claim).await?;
        if s.kind != "DELETE" || s.slot_held {
            return Ok(false);
        }
        let permitted: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM launch_permits WHERE tenant_id=$1 AND instance_id=$2 AND generation=$3 AND launch_id=$4 AND cluster_epoch=$5)")
            .bind(s.tenant_id).bind(s.instance_id).bind(s.generation).bind(s.launch_id).bind(s.cluster_epoch).fetch_one(&mut *tx).await?;
        if permitted {
            return Ok(false);
        }
        let closure: Option<Uuid> =
            sqlx::query_scalar("SELECT sandbox_close_never_authorized($1,$2,$3,$4)")
                .bind(claim.tenant_id)
                .bind(claim.operation_id)
                .bind(engine.worker_id())
                .bind(claim.lease_token)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        let Some(closure) = closure else {
            return Ok(false);
        };
        // The permanent closure survives a crash or a lost lease between these
        // transactions. A successor can complete once, without sending a Run.
        let (mut tx, s) = lock_current(self, claim.tenant_id, claim.operation_id).await?;
        engine.assert_claim(&mut tx, claim).await?;
        let proven: bool =
            sqlx::query_scalar("SELECT sandbox_never_authorized($1,$2,$3,$4,$5,$6,$7)")
                .bind(s.tenant_id)
                .bind(s.instance_id)
                .bind(s.workspace_id)
                .bind(s.generation)
                .bind(s.launch_id)
                .bind(s.cluster_epoch)
                .bind(closure)
                .fetch_one(&mut *tx)
                .await?;
        if !proven
            || s.kind != "DELETE"
            || s.desired_state != "DELETED"
            || s.slot_held
            || s.cluster_epoch != s.current_epoch
        {
            return Err(blocked("NEVER_AUTHORIZED_CLOSURE_NOT_CURRENT"));
        }
        sqlx::query("SELECT id FROM quota_accounts WHERE tenant_id=$1 AND (project_id=$2 OR project_id IS NULL) ORDER BY id FOR UPDATE")
            .bind(s.tenant_id).bind(s.project_id).fetch_all(&mut *tx).await?;
        let reservations: Vec<(Uuid,Uuid,i64,String,String)> = sqlx::query_as("SELECT r.id,r.quota_account_id,r.amount,r.status,q.dimension FROM quota_reservations r JOIN quota_accounts q ON q.tenant_id=r.tenant_id AND q.id=r.quota_account_id WHERE r.tenant_id=$1 AND r.resource_id=$2 AND r.status IN('PENDING','ALLOCATED') AND q.dimension IN('CPU_MILLIS','MEMORY_MIB','INSTANCES','EXECUTIONS') ORDER BY r.quota_account_id,r.id FOR UPDATE OF r")
            .bind(s.tenant_id).bind(s.instance_id).fetch_all(&mut *tx).await?;
        let restored = if s.restore_binding.is_some() {
            sqlx::query_scalar::<_, bool>("SELECT sandbox_restored_never_started($1,$2,$3)")
                .bind(s.tenant_id)
                .bind(s.instance_id)
                .bind(s.workspace_id)
                .fetch_one(&mut *tx)
                .await?
        } else {
            false
        };
        let dimensions = if restored {
            let released: i64 = sqlx::query_scalar("SELECT count(*) FROM quota_reservations reservation JOIN quota_accounts account ON account.tenant_id=reservation.tenant_id AND account.id=reservation.quota_account_id JOIN restores restore ON restore.tenant_id=reservation.tenant_id AND restore.operation_id=reservation.operation_id AND restore.instance_id=reservation.resource_id WHERE restore.tenant_id=$1 AND restore.instance_id=$2 AND reservation.status='RELEASED' AND((account.dimension='CPU_MILLIS' AND reservation.amount=2000) OR(account.dimension='MEMORY_MIB' AND reservation.amount=2048))")
                .bind(s.tenant_id).bind(s.instance_id).fetch_one(&mut *tx).await?;
            if released != 4 || reservations.len() != 2 {
                return Err(blocked("INSTANCE_DELETE_QUOTA_LEDGER_MISMATCH"));
            }
            vec![("INSTANCES", 1)]
        } else {
            if reservations.len() != 6 {
                return Err(blocked("INSTANCE_DELETE_QUOTA_LEDGER_MISMATCH"));
            }
            vec![
                ("CPU_MILLIS", s.cpu_millis),
                ("MEMORY_MIB", s.memory_mib),
                ("INSTANCES", 1),
            ]
        };
        for (dimension, amount) in dimensions {
            if reservations
                .iter()
                .filter(|r| r.4 == dimension && r.2 == amount)
                .count()
                != 2
            {
                return Err(blocked("INSTANCE_DELETE_QUOTA_LEDGER_MISMATCH"));
            }
        }
        for (reservation, account, amount, status, _) in reservations {
            sqlx::query("UPDATE quota_accounts SET pending=pending-CASE WHEN $4='PENDING' THEN $3 ELSE 0 END,allocated=allocated-CASE WHEN $4='ALLOCATED' THEN $3 ELSE 0 END,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
                .bind(s.tenant_id).bind(account).bind(amount).bind(status).execute(&mut *tx).await?;
            sqlx::query("UPDATE quota_reservations SET status='RELEASED',released_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
                .bind(s.tenant_id).bind(reservation).execute(&mut *tx).await?;
        }
        let details = json!({"generation":s.generation,"launch_id":s.launch_id,"proof_kind":"NEVER_AUTHORIZED","closure_id":closure,"workspace_preserved":true,"workspace_id":s.workspace_id});
        sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details) VALUES($1,$2,$3,$4,$5,$6,'instances:delete','SUCCEEDED',$7)")
            .bind(s.tenant_id).bind(s.project_id).bind(s.actor_principal_id).bind(s.request_id).bind(s.operation_id).bind(s.instance_id).bind(&details).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload) VALUES($1,$2,$3,$4,'instance.deleted',$5,$6,$7)")
            .bind(s.tenant_id).bind(s.project_id).bind(s.instance_id).bind(s.generation).bind(s.operation_id).bind(s.request_id).bind(details).execute(&mut *tx).await?;
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
        sqlx::query("UPDATE instances SET observed_state='DELETED',never_authorized_closure_id=$3,deleted_at=clock_timestamp(),observed_at=clock_timestamp(),active_operation_id=NULL,spec_version=spec_version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
            .bind(s.tenant_id).bind(s.instance_id).bind(closure).execute(&mut *tx).await?;
        sqlx::query("UPDATE workspaces SET active_operation_id=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND active_operation_id=$3")
            .bind(s.tenant_id).bind(s.workspace_id).bind(s.operation_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE operations SET status='SUCCEEDED',stage='COMPLETED',error=NULL,wait_reason=NULL,lease_owner=NULL,lease_until=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
            .bind(s.tenant_id).bind(s.operation_id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(true)
    }
}

#[cfg(test)]
#[path = "never_authorized_tests.rs"]
mod tests;
