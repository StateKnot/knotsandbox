//! Durable read-only diagnoses. Reports describe bounded historical evidence;
//! neither a missing Pod nor missing/zero metrics prove a VM has terminated.
use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{
    db::{Actor, Database, Idempotency, insert_operation, load_instance, load_operation},
    engine::{Claim, OperationEngine},
    error::ApiError,
    model::Operation,
    request::request_digest,
};

pub const RULESET: &str = "control-plane/v1";
pub const DEADLINE_SECONDS: i64 = 120;
pub const RETENTION_DAYS: i64 = 30;
pub const PENDING_LIMIT: i64 = 32;
pub const DAILY_LIMIT: i64 = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateDiagnosis {
    #[serde(default = "yes")]
    pub include_operations: bool,
    #[serde(default = "yes")]
    pub include_executions: bool,
}
const fn yes() -> bool {
    true
}
impl Default for CreateDiagnosis {
    fn default() -> Self {
        Self {
            include_operations: true,
            include_executions: true,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnosis {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub instance_id: Uuid,
    pub operation_id: Uuid,
    pub requested_generation: i64,
    pub requested_launch_id: Uuid,
    pub cluster_epoch: Uuid,
    pub ruleset_version: String,
    pub status: String,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub deadline: DateTime<Utc>,
    pub retention_until: DateTime<Utc>,
    pub snapshot_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub failure_code: Option<String>,
    pub report: Option<DiagnosticReport>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct DiagnosisAccepted {
    pub resource: Diagnosis,
    pub operation: Operation,
    pub idempotency_expires_at: DateTime<Utc>,
}
pub struct DiagnosisMutationResult {
    pub status: u16,
    pub body: DiagnosisAccepted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub overall: DiagnosticStatus,
    pub checks: Vec<DiagnosticCheck>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiagnosticStatus {
    Healthy,
    Warning,
    Critical,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceScope {
    Instance,
    Operations,
    Executions,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticCheck {
    pub rule: String,
    pub status: DiagnosticStatus,
    pub code: String,
    pub evidence_scope: EvidenceScope,
    pub evidence: Vec<DiagnosticEvidence>,
    /// A documentation/runbook key, never an executable remediation command.
    pub recommendation: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticEvidence {
    pub source: EvidenceSource,
    pub observed_at: Option<DateTime<Utc>>,
    pub resource_id: Option<Uuid>,
    pub state: Option<String>,
    pub deadline: Option<DateTime<Utc>>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceSource {
    ControlPlaneSnapshot,
    LifecycleReconciler,
    LaunchValidation,
    NodeCertification,
    OperationLedger,
    ExecutionLedger,
}

#[derive(sqlx::FromRow)]
struct Stored {
    id: Uuid,
    tenant_id: Uuid,
    project_id: Uuid,
    instance_id: Uuid,
    workspace_id: Uuid,
    operation_id: Uuid,
    actor_principal_id: Uuid,
    requested_generation: i64,
    requested_launch_id: Uuid,
    cluster_epoch: Uuid,
    ruleset_version: String,
    include_operations: bool,
    include_executions: bool,
    status: String,
    version: i64,
    created_at: DateTime<Utc>,
    deadline: DateTime<Utc>,
    retention_until: DateTime<Utc>,
    snapshot_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
    failure_code: Option<String>,
    report: Option<Value>,
}
impl Stored {
    fn view(self) -> Result<Diagnosis, ApiError> {
        let report = self
            .report
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| internal())?;
        Ok(Diagnosis {
            id: self.id,
            tenant_id: self.tenant_id,
            project_id: self.project_id,
            instance_id: self.instance_id,
            operation_id: self.operation_id,
            requested_generation: self.requested_generation,
            requested_launch_id: self.requested_launch_id,
            cluster_epoch: self.cluster_epoch,
            ruleset_version: self.ruleset_version,
            status: self.status,
            version: self.version,
            created_at: self.created_at,
            deadline: self.deadline,
            retention_until: self.retention_until,
            snapshot_at: self.snapshot_at,
            completed_at: self.completed_at,
            failure_code: self.failure_code,
            report,
        })
    }
}
fn internal() -> ApiError {
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_ERROR",
        "Diagnostic evidence cannot be decoded",
    )
}
async fn authorization(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    project: Uuid,
    action: &str,
) -> Result<(), ApiError> {
    Database::authorize_resource(tx, actor, project, action).await?;
    Database::authorize_resource(tx, actor, project, "instances:read").await
}
async fn optional_scope(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    project: Uuid,
    action: &str,
) -> Result<bool, ApiError> {
    match Database::authorize(tx, actor, project, action).await {
        Ok(()) => Ok(true),
        Err(e) if e.status == StatusCode::FORBIDDEN => Ok(false),
        Err(e) => Err(e),
    }
}
async fn load(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    id: Uuid,
) -> Result<Stored, ApiError> {
    sqlx::query_as("SELECT * FROM diagnoses WHERE tenant_id=$1 AND id=$2")
        .bind(tenant)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(ApiError::not_found)
}

impl Database {
    pub async fn create_diagnosis(
        &self,
        actor: &Actor,
        instance: Uuid,
        request: &CreateDiagnosis,
        key: &str,
    ) -> Result<DiagnosisMutationResult, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let target = load_instance(&mut tx, actor.tenant_id, instance, false).await?;
        authorization(&mut tx, actor, target.project_id, "diagnoses:create").await?;
        let digest = request_digest(request, None)?;
        let idempotency = Idempotency::new(actor, instance, "diagnoses:create", key, &digest);
        let previous = idempotency.replay_json(&mut tx).await?;
        // Authorization must survive both the idempotency wait and replay.
        authorization(&mut tx, actor, target.project_id, "diagnoses:create").await?;
        if let Some((status, body)) = previous {
            let body = serde_json::from_value(body).map_err(|_| internal())?;
            tx.commit().await?;
            return Ok(DiagnosisMutationResult { status, body });
        }
        // Dedicated admission serialization; never lock the instance/workspace
        // write slot or quota accounts just to ask why a workload is unhealthy.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('diagnoses:'||$1::text,0))")
            .bind(actor.tenant_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT sandbox_expire_tenant_diagnoses($1,128)")
            .bind(actor.tenant_id)
            .execute(&mut *tx)
            .await?;
        let (pending,daily,same):(i64,i64,bool)=sqlx::query_as("SELECT count(*) FILTER(WHERE status='PENDING'),count(*) FILTER(WHERE created_at>clock_timestamp()-interval '24 hours'),COALESCE(bool_or(status='PENDING' AND instance_id=$2),false) FROM diagnoses WHERE tenant_id=$1 AND (status='PENDING' OR created_at>clock_timestamp()-interval '24 hours')").bind(actor.tenant_id).bind(instance).fetch_one(&mut *tx).await?;
        if same {
            return Err(ApiError::conflict(
                "DIAGNOSIS_IN_PROGRESS",
                "A diagnosis for this instance is already pending",
            ));
        }
        if pending >= PENDING_LIMIT || daily >= DAILY_LIMIT {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "DIAGNOSIS_QUOTA_EXCEEDED",
                "Tenant diagnosis admission limit reached",
            ));
        }
        let (generation,launch,epoch,now):(i64,Uuid,Uuid,DateTime<Utc>)=sqlx::query_as("SELECT i.runtime_generation,i.launch_id,c.cluster_epoch,clock_timestamp() FROM instances i CROSS JOIN platform_configuration c WHERE i.tenant_id=$1 AND i.id=$2 AND c.singleton").bind(actor.tenant_id).bind(instance).fetch_one(&mut *tx).await?;
        let id = Uuid::new_v4();
        let op = Uuid::new_v4();
        let deadline = now + Duration::seconds(DEADLINE_SECONDS);
        insert_operation(&mut tx,actor,op,target.project_id,instance,target.workspace_id,"DIAGNOSE",&json!({"diagnosis_id":id,"ruleset_version":RULESET,"include_operations":request.include_operations,"include_executions":request.include_executions}),deadline).await?;
        sqlx::query("INSERT INTO diagnoses(id,tenant_id,project_id,instance_id,workspace_id,operation_id,actor_principal_id,requested_generation,requested_launch_id,cluster_epoch,ruleset_version,include_operations,include_executions,created_at,deadline,retention_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)")
            .bind(id).bind(actor.tenant_id).bind(target.project_id).bind(instance).bind(target.workspace_id).bind(op).bind(actor.principal_id).bind(generation).bind(launch).bind(epoch).bind(RULESET).bind(request.include_operations).bind(request.include_executions).bind(now).bind(deadline).bind(now+Duration::days(RETENTION_DAYS)).execute(&mut *tx).await?;
        let resource = load(&mut tx, actor.tenant_id, id).await?.view()?;
        let operation = load_operation(&mut tx, actor.tenant_id, op).await?;
        let body = DiagnosisAccepted {
            resource,
            operation,
            idempotency_expires_at: now + Duration::days(7),
        };
        record(
            &mut tx,
            actor,
            &body.resource,
            "diagnoses.accepted",
            "ACCEPTED",
        )
        .await?;
        idempotency
            .persist_json(
                &mut tx,
                target.project_id,
                op,
                id,
                &serde_json::to_value(&body).map_err(|_| internal())?,
                202,
                now,
                body.idempotency_expires_at,
            )
            .await?;
        authorization(&mut tx, actor, target.project_id, "diagnoses:create").await?;
        tx.commit().await?;
        Ok(DiagnosisMutationResult { status: 202, body })
    }

    pub async fn get_diagnosis(&self, actor: &Actor, id: Uuid) -> Result<Diagnosis, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let stored = load(&mut tx, actor.tenant_id, id).await?;
        authorization(&mut tx, actor, stored.project_id, "diagnoses:read").await?;
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let mut result = stored.view()?;
        if result.retention_until <= now {
            // No maintenance lag can extend public payload retention.
            result.status = "EXPIRED".into();
            result.report = None;
        } else if let Some(report) = result.report.as_mut() {
            redact(
                report,
                optional_scope(&mut tx, actor, result.project_id, "operations:read").await?,
                optional_scope(&mut tx, actor, result.project_id, "executions:read").await?,
            );
        }
        authorization(&mut tx, actor, result.project_id, "diagnoses:read").await?;
        tx.commit().await?;
        Ok(result)
    }

    pub async fn maintain_diagnoses(&self) -> Result<i32, ApiError> {
        let mut tx = self.pool.begin().await?;
        let n = sqlx::query_scalar("SELECT sandbox_maintain_diagnoses(128)")
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(n)
    }

    /// Retriable computation, one durable publication. No external probes or
    /// repair writes, and no workspace/instance row lock at any stage.
    pub async fn reconcile_diagnosis(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<(), ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        engine.assert_claim(&mut tx, claim).await?;
        let stored: Stored =
            sqlx::query_as("SELECT * FROM diagnoses WHERE tenant_id=$1 AND operation_id=$2")
                .bind(claim.tenant_id)
                .bind(claim.operation_id)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        let actor = Actor {
            authorization: None,
            tenant_id: stored.tenant_id,
            principal_id: stored.actor_principal_id,
            request_id: Uuid::new_v4(),
        };
        let computed = self.diagnosis_snapshot(&actor, &stored).await;
        let mut tx = self.begin(claim.tenant_id).await?;
        engine.assert_claim(&mut tx, claim).await?;
        sqlx::query("SELECT id FROM diagnoses WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
            .bind(claim.tenant_id)
            .bind(stored.id)
            .fetch_one(&mut *tx)
            .await?;
        let mut failure = None;
        let mut report = match computed {
            Ok(report) => Some(report),
            Err(e) if e.status == StatusCode::NOT_FOUND => {
                failure = Some("AUTHORITY_REVOKED");
                None
            }
            Err(e) if e.code == "DIAGNOSIS_TARGET_CHANGED" => {
                failure = Some("TARGET_CHANGED");
                None
            }
            Err(e) => return Err(e),
        };
        match authorization(&mut tx, &actor, stored.project_id, "diagnoses:create").await {
            Ok(()) => {}
            Err(e) if e.status == StatusCode::NOT_FOUND => {
                failure = Some("AUTHORITY_REVOKED");
                report = None;
            }
            Err(e) => return Err(e),
        }
        let (current,now):(bool,DateTime<Utc>)=sqlx::query_as("SELECT i.runtime_generation=$3 AND i.launch_id=$4 AND c.cluster_epoch=$5,clock_timestamp() FROM instances i CROSS JOIN platform_configuration c WHERE i.tenant_id=$1 AND i.id=$2 AND c.singleton").bind(stored.tenant_id).bind(stored.instance_id).bind(stored.requested_generation).bind(stored.requested_launch_id).bind(stored.cluster_epoch).fetch_one(&mut *tx).await?;
        if !current {
            failure = Some("TARGET_CHANGED");
            report = None;
        }
        if now >= stored.deadline {
            failure = Some("DEADLINE_EXCEEDED");
            report = None;
        }
        if let Some((_, r)) = report.as_mut() {
            redact(
                r,
                optional_scope(&mut tx, &actor, stored.project_id, "operations:read").await?,
                optional_scope(&mut tx, &actor, stored.project_id, "executions:read").await?,
            );
        }
        let snapshot_at = report.as_ref().map(|(at, _)| *at);
        let payload = report
            .map(|(_, r)| serde_json::to_value(r))
            .transpose()
            .map_err(|_| internal())?;
        let state = if failure.is_some() {
            "FAILED"
        } else {
            "COMPLETE"
        };
        sqlx::query("UPDATE diagnoses SET status=$3,snapshot_at=$4,completed_at=$5,report=$6,failure_code=$7 WHERE tenant_id=$1 AND id=$2 AND status='PENDING'").bind(stored.tenant_id).bind(stored.id).bind(state).bind(snapshot_at).bind(now).bind(payload).bind(failure).execute(&mut *tx).await?;
        let mut view = load(&mut tx, stored.tenant_id, stored.id).await?.view()?;
        let request_id: Uuid =
            sqlx::query_scalar("SELECT request_id FROM operations WHERE tenant_id=$1 AND id=$2")
                .bind(claim.tenant_id)
                .bind(claim.operation_id)
                .fetch_one(&mut *tx)
                .await?;
        record(
            &mut tx,
            &Actor {
                authorization: None,
                request_id,
                ..actor.clone()
            },
            &view,
            if failure.is_some() {
                "diagnoses.failed"
            } else {
                "diagnoses.completed"
            },
            if failure.is_some() {
                "FAILED"
            } else {
                "SUCCEEDED"
            },
        )
        .await?;
        // Event-stream head contention can outlive the lease/deadline. Fence
        // again after that wait and before exposing a final report.
        engine.assert_claim(&mut tx, claim).await?;
        if failure.is_none() {
            authorization(&mut tx, &actor, stored.project_id, "diagnoses:create").await?;
            let valid:bool=sqlx::query_scalar("SELECT clock_timestamp()<$3 AND c.cluster_epoch=$4 AND i.runtime_generation=$5 AND i.launch_id=$6 FROM instances i CROSS JOIN platform_configuration c WHERE i.tenant_id=$1 AND i.id=$2 AND c.singleton").bind(stored.tenant_id).bind(stored.instance_id).bind(stored.deadline).bind(stored.cluster_epoch).bind(stored.requested_generation).bind(stored.requested_launch_id).fetch_one(&mut *tx).await?;
            if !valid {
                return Err(ApiError::conflict(
                    "DIAGNOSIS_TARGET_CHANGED",
                    "Diagnostic evidence changed before publication",
                ));
            }
            if let Some(r) = view.report.as_mut() {
                // The serialized report has no unbounded I/O, but optional
                // evidence grants must also survive the publication wait.
                let ops =
                    optional_scope(&mut tx, &actor, stored.project_id, "operations:read").await?;
                let execs =
                    optional_scope(&mut tx, &actor, stored.project_id, "executions:read").await?;
                if r.checks.iter().any(|c| {
                    c.code != "EVIDENCE_REDACTED"
                        && ((c.evidence_scope == EvidenceScope::Operations && !ops)
                            || (c.evidence_scope == EvidenceScope::Executions && !execs))
                }) {
                    return Err(ApiError::conflict(
                        "DIAGNOSIS_AUTHORITY_CHANGED",
                        "Diagnostic evidence authorization changed; recompute",
                    ));
                }
            }
        }
        sqlx::query("UPDATE operations SET status=$3,stage='DIAGNOSIS_COMPLETE',error=$4,wait_reason=NULL,lease_owner=NULL,lease_until=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
            .bind(claim.tenant_id).bind(claim.operation_id).bind(if failure.is_some(){"FAILED"}else{"SUCCEEDED"}).bind(failure.map(|_|json!({"code":"OPERATION_FAILED","retryable":false}))).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
}

async fn record(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    d: &Diagnosis,
    event: &str,
    outcome: &str,
) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details) VALUES($1,$2,$3,$4,$5,$6,CASE WHEN $7='ACCEPTED' THEN 'diagnoses:create' ELSE 'diagnoses:complete' END,$7,$8)").bind(d.tenant_id).bind(d.project_id).bind(actor.principal_id).bind(actor.request_id).bind(d.operation_id).bind(d.id).bind(outcome).bind(json!({"ruleset_version":RULESET,"status":d.status,"failure_code":d.failure_code})).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8)").bind(d.tenant_id).bind(d.project_id).bind(d.id).bind(d.version).bind(event).bind(d.operation_id).bind(actor.request_id).bind(json!({"status":d.status,"failure_code":d.failure_code})).execute(&mut **tx).await?;
    Ok(())
}

#[path = "diagnostics_rules.rs"]
mod rules;
use rules::redact;
