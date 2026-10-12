//! Durable gateway outcomes. Guest exit codes describe workload reports; only
//! an authenticated exec-process terminal status can release a platform slot.
use crate::{
    db::Database,
    engine::{Claim, OperationEngine},
    error::ApiError,
    model::ExecutionResultRef,
    runner::RunSummary,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredOutputSegment {
    pub execution_id: Uuid,
    pub dispatch_attempt_id: Uuid,
    pub sequence: i64,
    pub first_frame_sequence: i64,
    pub last_frame_sequence: i64,
    pub raw_bytes: i64,
    pub object_bytes: i64,
    pub sha256: String,
    pub object_key: String,
}
impl StoredOutputSegment {
    pub fn validate(&self, tenant: Uuid) -> Result<(), ApiError> {
        if !(0..=4097).contains(&self.sequence)
            || !(0..=4097).contains(&self.first_frame_sequence)
            || self.last_frame_sequence < self.first_frame_sequence
            || self.last_frame_sequence > 4097
            || !(0..=262144).contains(&self.raw_bytes)
            || !(1..=524288).contains(&self.object_bytes)
            || !valid_sha(&self.sha256)
            || self.object_key
                != format!(
                    "tenants/{tenant}/executions/{}/attempts/{}/segments/{}-{}.ndjson",
                    self.execution_id, self.dispatch_attempt_id, self.sequence, self.sha256
                )
        {
            return Err(ApiError::invalid("Invalid durable output segment receipt"));
        }
        Ok(())
    }
}

pub struct NormalProcessCompletion {
    /// Taken only from Kubernetes exec channel 3, never parsed from guest stdout.
    pub trusted_process_exit_code: i32,
    pub guest_report: RunSummary,
    pub output_status: String,
    pub manifest: Option<ExecutionResultRef>,
}

#[derive(sqlx::FromRow)]
struct Activity {
    execution_id: Uuid,
    project_id: Uuid,
    instance_id: Uuid,
    operation_id: Uuid,
    dispatch_attempt_id: Option<Uuid>,
    status: String,
    slot_held: bool,
    identity_matches: bool,
    activity_matches: bool,
    can_complete: bool,
    termination_status: String,
    version: i64,
    request_id: Uuid,
    actor_principal_id: Uuid,
}

impl Database {
    /// Call only after the immutable object PUT returned success (or a verified
    /// read-back proved the identical key+checksum). Index commit publishes it.
    pub async fn record_execution_output_segment(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        segment: &StoredOutputSegment,
    ) -> Result<(), ApiError> {
        segment.validate(claim.tenant_id)?;
        let (mut tx, activity) = lock_activity(
            self,
            engine,
            claim,
            segment.execution_id,
            segment.dispatch_attempt_id,
        )
        .await?;
        if !matches!(activity.status.as_str(), "DISPATCHING" | "RUNNING")
            || !activity.slot_held
            || activity.termination_status != "NOT_REQUESTED"
        {
            return Err(conflict("EXECUTION_OUTPUT_CLOSED"));
        }
        let previous=sqlx::query("SELECT sha256,object_key,first_frame_sequence,last_frame_sequence,raw_bytes,object_bytes FROM execution_output_segments WHERE tenant_id=$1 AND execution_id=$2 AND dispatch_attempt_id=$3 AND sequence=$4")
            .bind(claim.tenant_id).bind(segment.execution_id).bind(segment.dispatch_attempt_id).bind(segment.sequence).fetch_optional(&mut *tx).await?;
        if let Some(row) = previous {
            if row.try_get::<String, _>("sha256")? != segment.sha256
                || row.try_get::<String, _>("object_key")? != segment.object_key
                || row.try_get::<i64, _>("first_frame_sequence")? != segment.first_frame_sequence
                || row.try_get::<i64, _>("last_frame_sequence")? != segment.last_frame_sequence
                || row.try_get::<i64, _>("raw_bytes")? != segment.raw_bytes
                || row.try_get::<i64, _>("object_bytes")? != segment.object_bytes
            {
                return Err(conflict("OUTPUT_SEGMENT_CONFLICT"));
            }
            tx.commit().await?;
            return Ok(());
        }
        let (count,last,raw,stored):(i64,Option<i64>,i64,i64)=sqlx::query_as("SELECT count(*),max(last_frame_sequence),COALESCE(sum(raw_bytes),0)::bigint,COALESCE(sum(object_bytes),0)::bigint FROM execution_output_segments WHERE tenant_id=$1 AND execution_id=$2 AND dispatch_attempt_id=$3")
            .bind(claim.tenant_id).bind(segment.execution_id).bind(segment.dispatch_attempt_id).fetch_one(&mut *tx).await?;
        if segment.sequence != count
            || last.is_some_and(|last| segment.first_frame_sequence <= last)
            || raw + segment.raw_bytes > 16 * 1024 * 1024
            || stored + segment.object_bytes > 32 * 1024 * 1024
        {
            return Err(conflict("OUTPUT_SEGMENT_ORDER_OR_LIMIT"));
        }
        sqlx::query("INSERT INTO execution_output_segments(tenant_id,project_id,execution_id,dispatch_attempt_id,sequence,first_frame_sequence,last_frame_sequence,raw_bytes,object_bytes,sha256,object_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
            .bind(claim.tenant_id).bind(activity.project_id).bind(segment.execution_id).bind(segment.dispatch_attempt_id).bind(segment.sequence).bind(segment.first_frame_sequence).bind(segment.last_frame_sequence).bind(segment.raw_bytes).bind(segment.object_bytes).bind(&segment.sha256).bind(&segment.object_key).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload) VALUES($1,$2,$3,$4,'execution.output_persisted',$5,$6,$7)")
            .bind(claim.tenant_id).bind(activity.project_id).bind(segment.execution_id).bind(segment.sequence+1).bind(claim.operation_id).bind(activity.request_id).bind(json!({"sequence":segment.sequence,"sha256":segment.sha256,"object_bytes":segment.object_bytes})).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Atomic normal completion, quota release and outbox. It never sets whole
    /// VM termination to CONFIRMED and cannot resolve an OUTCOME_UNKNOWN result.
    pub async fn complete_execution_process(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        id: Uuid,
        attempt: Uuid,
        completion: &NormalProcessCompletion,
    ) -> Result<(), ApiError> {
        if completion.trusted_process_exit_code != 0
            || completion.guest_report.timed_out
            || completion.guest_report.cancelled
            || completion
                .guest_report
                .exit_code
                .is_some_and(|c| !(0..=255).contains(&c))
            || !matches!(completion.output_status.as_str(), "COMPLETE" | "TRUNCATED")
        {
            return Err(ApiError::invalid(
                "Normal completion requires a successful trusted process terminal status",
            ));
        }
        if let Some(reference) = &completion.manifest {
            let expected = format!(
                "tenants/{}/executions/{id}/attempts/{attempt}/manifest-{}.json",
                claim.tenant_id, reference.sha256
            );
            if reference.object_key != expected
                || !valid_sha(&reference.sha256)
                || reference.size_bytes == 0
                || reference.size_bytes > 1024 * 1024
            {
                return Err(ApiError::invalid("Invalid persisted manifest reference"));
            }
        }
        if matches!(completion.output_status.as_str(), "COMPLETE" | "TRUNCATED")
            && completion.manifest.is_none()
        {
            return Err(ApiError::invalid(
                "Complete output requires a persisted manifest",
            ));
        }
        let (mut tx, a) = lock_activity(self, engine, claim, id, attempt).await?;
        if !a.can_complete
            || !a.slot_held
            || a.termination_status != "NOT_REQUESTED"
            || !matches!(a.status.as_str(), "DISPATCHING" | "RUNNING")
        {
            return Err(conflict("EXECUTION_COMPLETION_FENCED"));
        }
        let rows:Vec<(Uuid,Uuid,i64,String)>=sqlx::query_as("SELECT r.id,r.quota_account_id,r.amount,r.status FROM quota_reservations r JOIN quota_accounts q ON q.tenant_id=r.tenant_id AND q.id=r.quota_account_id WHERE r.tenant_id=$1 AND r.operation_id=$2 AND r.resource_id=$3 AND q.dimension='EXECUTIONS' AND r.status IN ('PENDING','ALLOCATED') ORDER BY r.quota_account_id,r.id")
            .bind(claim.tenant_id).bind(claim.operation_id).bind(a.instance_id).fetch_all(&mut *tx).await?;
        if rows.len() != 2 || rows.iter().any(|r| r.2 != 1) {
            return Err(conflict("EXECUTION_QUOTA_LEDGER_MISMATCH"));
        }
        for (_, account, _, _) in &rows {
            sqlx::query("SELECT id FROM quota_accounts WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
                .bind(claim.tenant_id)
                .bind(account)
                .fetch_one(&mut *tx)
                .await?;
        }
        for (reservation, account, amount, status) in rows {
            sqlx::query("UPDATE quota_accounts SET pending=pending-CASE WHEN $4='PENDING' THEN $3 ELSE 0 END,allocated=allocated-CASE WHEN $4='ALLOCATED' THEN $3 ELSE 0 END,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
                .bind(claim.tenant_id).bind(account).bind(amount).bind(status).execute(&mut *tx).await?;
            sqlx::query("UPDATE quota_reservations SET status='RELEASED',released_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(claim.tenant_id).bind(reservation).execute(&mut *tx).await?;
        }
        let status = if completion.guest_report.exit_code == Some(0)
            && completion.guest_report.signal.is_none()
        {
            "SUCCEEDED"
        } else {
            "FAILED"
        };
        let manifest = completion
            .manifest
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| ApiError::invalid("Invalid manifest"))?;
        sqlx::query("UPDATE executions SET status=$3,slot_held=false,exit_code=$4,output_status=$5,output_manifest=$6,exec_process_attempt_id=$7,exec_process_exited_at=clock_timestamp(),exec_process_exit_code=0,activity_completion_kind='EXEC_PROCESS_EXITED',result_source='GUEST_REPORTED',completed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
            .bind(claim.tenant_id).bind(id).bind(status).bind(completion.guest_report.exit_code).bind(&completion.output_status).bind(manifest).bind(attempt).execute(&mut *tx).await?;
        sqlx::query("UPDATE instances SET slot_held=false,activity_kind=NULL,activity_id=NULL,activity_generation=NULL,idle_since=clock_timestamp(),last_activity_at=clock_timestamp(),spec_version=spec_version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
            .bind(claim.tenant_id).bind(a.instance_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE operations SET status='SUCCEEDED',stage='EXEC_PROCESS_COMPLETED',lease_owner=NULL,lease_until=NULL,wait_reason=NULL,error=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
            .bind(claim.tenant_id).bind(claim.operation_id).execute(&mut *tx).await?;
        let payload = json!({"status":status,"exit_code":completion.guest_report.exit_code,"result_source":"GUEST_REPORTED","activity_completion_kind":"EXEC_PROCESS_EXITED","vm_termination_confirmed":false,"dispatch_attempt_id":attempt,"output_status":completion.output_status});
        sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details) VALUES($1,$2,$3,$4,$5,$6,'executions:process_completed','SUCCEEDED',$7)")
            .bind(claim.tenant_id).bind(a.project_id).bind(a.actor_principal_id).bind(a.request_id).bind(claim.operation_id).bind(id).bind(&payload).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload) VALUES($1,$2,$3,$4,'execution.process_completed',$5,$6,$7)")
            .bind(claim.tenant_id).bind(a.project_id).bind(id).bind(a.version+1).bind(claim.operation_id).bind(a.request_id).bind(payload).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
}
async fn lock_activity<'a>(
    db: &'a Database,
    engine: &OperationEngine,
    claim: &Claim,
    id: Uuid,
    attempt: Uuid,
) -> Result<(Transaction<'a, Postgres>, Activity), ApiError> {
    let mut tx = db.begin(claim.tenant_id).await?;
    let (instance,workspace):(Uuid,Uuid)=sqlx::query_as("SELECT e.instance_id,i.workspace_id FROM executions e JOIN instances i ON i.tenant_id=e.tenant_id AND i.id=e.instance_id WHERE e.tenant_id=$1 AND e.id=$2")
        .bind(claim.tenant_id).bind(id).fetch_one(&mut *tx).await?;
    sqlx::query("SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(claim.tenant_id)
        .bind(workspace)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("SELECT id FROM instances WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(claim.tenant_id)
        .bind(instance)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("SELECT id FROM executions WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(claim.tenant_id)
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    engine.assert_claim(&mut tx, claim).await?;
    let a:Activity=sqlx::query_as("SELECT e.id AS execution_id,e.project_id,e.instance_id,e.operation_id,e.dispatch_attempt_id,e.status,e.slot_held,e.termination_status,e.version,o.request_id,o.actor_principal_id,COALESCE((e.runtime_generation,e.launch_id,e.pod_uid,e.cluster_epoch)=(i.runtime_generation,i.launch_id,i.pod_uid,i.cluster_epoch) AND i.cluster_epoch=c.cluster_epoch,false) AS identity_matches,COALESCE(i.slot_held AND i.activity_id=e.id AND i.activity_kind='EXECUTION' AND i.activity_generation=e.runtime_generation,false) AS activity_matches,(e.exec_admission_uid IS NOT NULL AND e.exec_admitted_at IS NOT NULL AND i.desired_state='RUNNING' AND i.active_operation_id IS NULL AND i.stop_accepted_at IS NULL AND e.cancel_requested_at IS NULL AND e.deadline>clock_timestamp() AND i.compute_lease_expires_at>clock_timestamp()) AS can_complete FROM executions e JOIN instances i ON i.tenant_id=e.tenant_id AND i.id=e.instance_id JOIN operations o ON o.tenant_id=e.tenant_id AND o.id=e.operation_id CROSS JOIN platform_configuration c WHERE e.tenant_id=$1 AND e.id=$2 AND c.singleton")
        .bind(claim.tenant_id).bind(id).fetch_one(&mut *tx).await?;
    if a.execution_id != id
        || a.operation_id != claim.operation_id
        || a.dispatch_attempt_id != Some(attempt)
        || !a.identity_matches
        || !a.activity_matches
    {
        return Err(conflict("EXECUTION_COMPLETION_FENCED"));
    }
    Ok((tx, a))
}
fn valid_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn conflict(code: &'static str) -> ApiError {
    ApiError::conflict(
        code,
        "Gateway evidence does not match the current authorized activity",
    )
}
