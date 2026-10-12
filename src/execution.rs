//! Command acceptance and the durable, single-attempt dispatch boundary. This
//! module never opens a Kubernetes exec connection and never trusts guest output
//! as evidence that a VM or an execution slot has terminated.

use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{
    db::{
        Actor, Database, Idempotency, insert_operation, load_instance, load_operation,
        reserve_quota, runnable_epoch,
    },
    engine::{Claim, OperationEngine},
    error::ApiError,
    model::{
        AcceptedExecution, CancelExecution, CreateExecution, Execution, ExecutionResultRef,
        Instance,
    },
    request::request_digest,
    runner::ExecRequest,
};

#[derive(Debug)]
pub struct ExecutionMutationResult {
    pub status: u16,
    pub body: AcceptedExecution,
}

/// A trusted dispatcher supplies this only after a fresh Kubernetes GET has
/// verified exact identity, readiness, PVC and network policy. DB evidence alone
/// is not sufficient authorization to make the remote exec call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchIdentity {
    pub runtime_generation: i64,
    pub launch_id: Uuid,
    pub pod_uid: Uuid,
    pub cluster_epoch: Uuid,
}

// Deliberately not Debug/Serialize: contains user-supplied command arguments and
// environment values. Only a trusted dispatcher may consume this in memory.
pub struct PreparedExecution {
    pub dispatch_attempt_id: Uuid,
    pub request: ExecRequest,
    pub namespace: String,
    pub pod_name: String,
    pub identity: DispatchIdentity,
    pub deadline: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct ExecutionRow {
    #[sqlx(flatten)]
    resource: Execution,
    launch_id: Uuid,
    pod_uid: Uuid,
    cluster_epoch: Option<Uuid>,
    dispatch_attempt_id: Option<Uuid>,
    output_manifest: Option<Value>,
}

impl ExecutionRow {
    fn identity(&self) -> Result<DispatchIdentity, ApiError> {
        Ok(DispatchIdentity {
            runtime_generation: self.resource.runtime_generation,
            launch_id: self.launch_id,
            pod_uid: self.pod_uid,
            cluster_epoch: self.cluster_epoch.ok_or_else(|| {
                ApiError::conflict(
                    "EXECUTION_RECONCILIATION_REQUIRED",
                    "Execution has no verified cluster epoch",
                )
            })?,
        })
    }
    fn public(mut self) -> Execution {
        if let Some(value) = self.output_manifest {
            let prefix = format!(
                "tenants/{}/executions/{}/",
                self.resource.tenant_id, self.resource.id
            );
            let reference = serde_json::from_value::<ExecutionResultRef>(value)
                .ok()
                .filter(|reference| {
                    reference.object_key.starts_with(&prefix)
                        && reference.object_key.len() > prefix.len()
                        && reference.object_key.len() <= 512
                        && !reference
                            .object_key
                            .split('/')
                            .any(|part| matches!(part, "" | "." | ".."))
                        && reference
                            .object_key
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
                        && reference.sha256.len() == 64
                        && reference
                            .sha256
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        && reference.size_bytes <= 64 * 1024 * 1024
                });
            if reference.is_none() {
                // Corrupt/untrusted output metadata must not block observing the
                // current ETag or accepting a safety cancellation.
                self.resource.output_status = "LOST".into();
                tracing::warn!(tenant_id=%self.resource.tenant_id,execution_id=%self.resource.id,"invalid execution output reference was withheld");
            }
            self.resource.result_ref = reference;
        }
        self.resource
    }
}

impl Database {
    pub async fn get_execution(&self, actor: &Actor, id: Uuid) -> Result<Execution, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let execution = load_execution(&mut tx, actor.tenant_id, id, false).await?;
        Self::authorize_resource(
            &mut tx,
            actor,
            execution.resource.project_id,
            "executions:read",
        )
        .await?;
        let result = execution.public();
        tx.commit().await?;
        Ok(result)
    }

    pub async fn create_execution(
        &self,
        actor: &Actor,
        instance_id: Uuid,
        request: &CreateExecution,
        key: &str,
        expected: i64,
    ) -> Result<ExecutionMutationResult, ApiError> {
        self.create_execution_inner(actor, instance_id, request, key, expected, None)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn create_execution_with_automation(
        &self,
        actor: &Actor,
        instance_id: Uuid,
        request: &CreateExecution,
        key: &str,
        expected: i64,
        fence: &crate::automation_authority::AutomationAcceptanceFence,
    ) -> Result<ExecutionMutationResult, ApiError> {
        self.create_execution_inner(actor, instance_id, request, key, expected, Some(fence))
            .await
    }

    async fn create_execution_inner(
        &self,
        actor: &Actor,
        instance_id: Uuid,
        request: &CreateExecution,
        key: &str,
        expected: i64,
        fence: Option<&crate::automation_authority::AutomationAcceptanceFence>,
    ) -> Result<ExecutionMutationResult, ApiError> {
        if let Some(fence) = fence {
            fence.check_request(request, key, expected)?;
        }
        let execution_id = fence.map_or_else(Uuid::new_v4, |f| f.produced_resource_id);
        let command = request.runner_request(execution_id)?;
        let mut tx = self.begin(actor.tenant_id).await?;
        if let Some(fence) = fence {
            fence.bind(&mut tx).await?;
        }
        let initial = load_instance(&mut tx, actor.tenant_id, instance_id, false).await?;
        Self::authorize_resource(&mut tx, actor, initial.project_id, "executions:create").await?;
        Self::authorize_resource(&mut tx, actor, initial.project_id, "instances:hard_stop").await?;
        let digest = request_digest(request, Some(expected))?;
        let idem = Idempotency::new(actor, instance_id, "executions:create", key, &digest);
        if let Some(result) = replay(&idem, &mut tx).await? {
            tx.commit().await?;
            return Ok(result);
        }
        lock_workspace(&mut tx, actor.tenant_id, initial.workspace_id).await?;
        let instance = load_instance(&mut tx, actor.tenant_id, instance_id, true).await?;
        Self::authorize_resource(&mut tx, actor, instance.project_id, "executions:create").await?;
        Self::authorize_resource(&mut tx, actor, instance.project_id, "instances:hard_stop")
            .await?;
        check_version(instance.spec_version, expected)?;
        let now = now(&mut tx).await?;
        let epoch = runnable_epoch(&mut tx).await?;
        let identity = ready_identity(&mut tx, &instance, epoch, now).await?;
        if instance.slot_held {
            return Err(ApiError::conflict(
                "INSTANCE_BUSY",
                "The instance already has an active execution, terminal or file operation",
            ));
        }
        let deadline = now + Duration::seconds(command.timeout_seconds as i64);
        if deadline > instance.compute_lease_expires_at {
            return Err(ApiError::conflict(
                "EXECUTION_EXCEEDS_LEASE",
                "Renew the compute lease before requesting this execution timeout",
            ));
        }
        let operation_id = Uuid::new_v4();
        let stored = json!({"protocol_version":1,"classification":"NON_SENSITIVE","on_timeout":request.on_timeout,"runner":command});
        insert_operation(
            &mut tx,
            actor,
            operation_id,
            instance.project_id,
            instance.id,
            instance.workspace_id,
            "EXECUTE",
            &stored,
            deadline,
        )
        .await?;
        sqlx::query("INSERT INTO executions(id,tenant_id,project_id,instance_id,operation_id,runtime_generation,launch_id,pod_uid,cluster_epoch,deadline,timeout_seconds,client_reference) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
            .bind(execution_id).bind(actor.tenant_id).bind(instance.project_id).bind(instance.id).bind(operation_id)
            .bind(identity.runtime_generation).bind(identity.launch_id).bind(identity.pod_uid).bind(identity.cluster_epoch).bind(deadline).bind(command.timeout_seconds as i32).bind(&request.client_reference).execute(&mut *tx).await?;
        reserve_quota(
            &mut tx,
            actor,
            instance.project_id,
            operation_id,
            instance.id,
            instance.workspace_id,
            &[("EXECUTIONS", 1)],
        )
        .await?;
        sqlx::query("UPDATE instances SET slot_held=true,activity_kind='EXECUTION',activity_id=$3,activity_generation=runtime_generation,idle_since=NULL,last_activity_at=$4,spec_version=spec_version+1,updated_at=$4 WHERE tenant_id=$1 AND id=$2")
            .bind(actor.tenant_id).bind(instance.id).bind(execution_id).bind(now).execute(&mut *tx).await?;
        let result = finish(
            &mut tx,
            actor,
            &idem,
            execution_id,
            operation_id,
            "executions:create",
            now,
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }

    pub async fn cancel_execution(
        &self,
        actor: &Actor,
        id: Uuid,
        request: &CancelExecution,
        key: &str,
        expected: i64,
    ) -> Result<ExecutionMutationResult, ApiError> {
        if !request.hard_stop_instance {
            return Err(ApiError::invalid(
                "Cancellation requires hard_stop_instance=true and stops the entire instance",
            ));
        }
        let mut tx = self.begin(actor.tenant_id).await?;
        let initial = load_execution(&mut tx, actor.tenant_id, id, false).await?;
        Self::authorize_resource(
            &mut tx,
            actor,
            initial.resource.project_id,
            "executions:cancel",
        )
        .await?;
        Self::authorize_resource(
            &mut tx,
            actor,
            initial.resource.project_id,
            "instances:hard_stop",
        )
        .await?;
        let digest = request_digest(request, Some(expected))?;
        let idem = Idempotency::new(actor, id, "executions:cancel", key, &digest);
        if let Some(result) = replay(&idem, &mut tx).await? {
            tx.commit().await?;
            return Ok(result);
        }
        let initial_instance = load_instance(
            &mut tx,
            actor.tenant_id,
            initial.resource.instance_id,
            false,
        )
        .await?;
        lock_workspace(&mut tx, actor.tenant_id, initial_instance.workspace_id).await?;
        let instance =
            load_instance(&mut tx, actor.tenant_id, initial.resource.instance_id, true).await?;
        let execution = load_execution(&mut tx, actor.tenant_id, id, true).await?;
        Self::authorize_resource(&mut tx, actor, instance.project_id, "executions:cancel").await?;
        Self::authorize_resource(&mut tx, actor, instance.project_id, "instances:hard_stop")
            .await?;
        check_version(execution.resource.version, expected)?;
        if !execution.resource.slot_held || execution.resource.termination_status == "CONFIRMED" {
            return Err(ApiError::conflict(
                "EXECUTION_ALREADY_TERMINATED",
                "This execution no longer owns a live activity slot",
            ));
        }
        let now = now(&mut tx).await?;
        let stop_id = request_stop_locked(
            &mut tx,
            actor,
            &instance,
            &execution,
            "EXECUTION_CANCELLED",
            now,
        )
        .await?;
        let result = finish(&mut tx, actor, &idem, id, stop_id, "executions:cancel", now).await?;
        tx.commit().await?;
        Ok(result)
    }

    /// Internal safety boundary for a previously accepted hard-stop policy.
    /// Revocation of the initiating user's grant cannot prevent stopping unsafe
    /// compute. This never releases activity slots, execution quota or data.
    pub async fn stop_execution_for_safety(
        &self,
        tenant: Uuid,
        id: Uuid,
        reason: &str,
    ) -> Result<Option<Uuid>, ApiError> {
        let stop_reason = match reason {
            "TIMEOUT" => "EXECUTION_TIMEOUT",
            "OUTPUT_FAILURE" | "TRANSPORT_LOST" => "SECURITY",
            _ => return Err(ApiError::invalid("Unknown execution safety-stop reason")),
        };
        let mut tx = self.begin(tenant).await?;
        let initial = load_execution(&mut tx, tenant, id, false).await?;
        let initial_instance =
            load_instance(&mut tx, tenant, initial.resource.instance_id, false).await?;
        lock_workspace(&mut tx, tenant, initial_instance.workspace_id).await?;
        let instance = load_instance(&mut tx, tenant, initial.resource.instance_id, true).await?;
        let execution = load_execution(&mut tx, tenant, id, true).await?;
        if !execution.resource.slot_held || execution.resource.termination_status == "CONFIRMED" {
            tx.commit().await?;
            return Ok(None);
        }
        let now = now(&mut tx).await?;
        if reason == "TIMEOUT" && now < execution.resource.deadline {
            return Err(ApiError::conflict(
                "EXECUTION_NOT_DUE",
                "Execution deadline has not elapsed",
            ));
        }
        // The operation request is immutable. An old record without explicit
        // consent must not silently acquire the authority to hard-stop compute.
        let policy: bool = sqlx::query_scalar("SELECT COALESCE(request->>'on_timeout'='HARD_STOP_INSTANCE',false) FROM operations WHERE tenant_id=$1 AND id=$2")
            .bind(tenant).bind(execution.resource.operation_id).fetch_one(&mut *tx).await?;
        if !policy {
            return Err(ApiError::conflict(
                "INVALID_EXECUTION_REQUEST",
                "Stored execution has no explicit hard-stop policy",
            ));
        }
        if reason != "TIMEOUT" && execution.dispatch_attempt_id.is_none() {
            return Err(ApiError::conflict(
                "DISPATCH_NOT_ATTEMPTED",
                "Transport and output failures require a persisted dispatch attempt",
            ));
        }
        assert_current_activity(&mut tx, &instance, &execution).await?;
        if execution.resource.termination_status == "PENDING"
            && let Some(stop_id) = execution.resource.cancel_operation_id
        {
            assert_active_stop(&mut tx, &instance, stop_id).await?;
            tx.commit().await?;
            return Ok(Some(stop_id));
        }
        let principal = sqlx::query_scalar(
            "SELECT safety_principal_id FROM platform_configuration WHERE singleton",
        )
        .fetch_one(&mut *tx)
        .await?;
        let actor = Actor {
            authorization: None,
            tenant_id: tenant,
            principal_id: principal,
            request_id: Uuid::new_v4(),
        };
        let stop_id =
            request_stop_locked(&mut tx, &actor, &instance, &execution, stop_reason, now).await?;
        event(
            &mut tx,
            &actor,
            id,
            instance.project_id,
            stop_id,
            execution.resource.version + 1,
            "executions:safety_stop",
            json!({"reason":reason,"instance_id":instance.id,"termination_confirmed":false}),
        )
        .await?;
        tx.commit().await?;
        Ok(Some(stop_id))
    }

    /// A successful return commits DISPATCHING before the caller can send stdin.
    /// A lost response is ambiguous: never call Kubernetes exec again for this
    /// execution, even if this method is retried with the same worker claim.
    pub async fn begin_execution_dispatch(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        id: Uuid,
        observed: DispatchIdentity,
    ) -> Result<PreparedExecution, ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let initial = load_execution(&mut tx, claim.tenant_id, id, false).await?;
        let initial_instance = load_instance(
            &mut tx,
            claim.tenant_id,
            initial.resource.instance_id,
            false,
        )
        .await?;
        lock_workspace(&mut tx, claim.tenant_id, initial_instance.workspace_id).await?;
        let instance =
            load_instance(&mut tx, claim.tenant_id, initial.resource.instance_id, true).await?;
        let execution = load_execution(&mut tx, claim.tenant_id, id, true).await?;
        if execution.resource.operation_id != claim.operation_id {
            return Err(ApiError::conflict(
                "WORKER_LEASE_LOST",
                "The worker claim does not belong to this execution",
            ));
        }
        engine.assert_claim(&mut tx, claim).await?;
        if execution.dispatch_attempt_id.is_some() {
            return Err(ApiError::conflict(
                "DISPATCH_ALREADY_ATTEMPTED",
                "A dispatch attempt was already persisted; never automatically resend this command",
            ));
        }
        if execution.resource.status != "QUEUED"
            || execution.resource.cancel_requested_at.is_some()
            || execution.resource.termination_status != "NOT_REQUESTED"
        {
            return Err(ApiError::conflict(
                "EXECUTION_NOT_DISPATCHABLE",
                "Execution is cancelled or is no longer queued",
            ));
        }
        let now = now(&mut tx).await?;
        let epoch = runnable_epoch(&mut tx).await?;
        let identity = ready_identity(&mut tx, &instance, epoch, now).await?;
        if identity != execution.identity()? || identity != observed {
            return Err(ApiError::conflict(
                "EXECUTION_IDENTITY_CHANGED",
                "Current verified launch does not match execution acceptance",
            ));
        }
        assert_activity(&mut tx, &instance, id).await?;
        let operation=sqlx::query("SELECT kind,request,actor_principal_id,request_id,cancel_requested FROM operations WHERE tenant_id=$1 AND id=$2")
            .bind(claim.tenant_id).bind(claim.operation_id).fetch_one(&mut *tx).await?;
        if operation.try_get::<String, _>("kind")? != "EXECUTE"
            || operation.try_get::<bool, _>("cancel_requested")?
        {
            return Err(ApiError::conflict(
                "EXECUTION_NOT_DISPATCHABLE",
                "The execution operation was cancelled",
            ));
        }
        let actor = Actor {
            authorization: None,
            tenant_id: claim.tenant_id,
            principal_id: operation.try_get("actor_principal_id")?,
            request_id: operation.try_get("request_id")?,
        };
        Self::authorize_resource(&mut tx, &actor, instance.project_id, "executions:create").await?;
        Self::authorize_resource(&mut tx, &actor, instance.project_id, "instances:hard_stop")
            .await?;
        let stored: Value = operation.try_get("request")?;
        let mut request: ExecRequest = serde_json::from_value(
            stored.get("runner").cloned().unwrap_or(Value::Null),
        )
        .map_err(|_| {
            ApiError::conflict(
                "INVALID_EXECUTION_REQUEST",
                "Stored runner parameters are invalid",
            )
        })?;
        if request.execution_id != id
            || stored.get("classification").and_then(Value::as_str) != Some("NON_SENSITIVE")
            || stored.get("on_timeout").and_then(Value::as_str) != Some("HARD_STOP_INSTANCE")
        {
            return Err(ApiError::conflict(
                "INVALID_EXECUTION_REQUEST",
                "Stored runner identity, classification or explicit timeout policy is invalid",
            ));
        }
        request
            .validate(std::path::Path::new("/workspace"))
            .map_err(|_| {
                ApiError::conflict(
                    "INVALID_EXECUTION_REQUEST",
                    "Stored runner parameters violate the protocol",
                )
            })?;
        if serde_json::to_vec(&request)
            .map_err(|_| {
                ApiError::conflict(
                    "INVALID_EXECUTION_REQUEST",
                    "Stored runner parameters cannot be encoded",
                )
            })?
            .len()
            > crate::runner::MAX_INPUT_BYTES
        {
            return Err(ApiError::conflict(
                "INVALID_EXECUTION_REQUEST",
                "Stored runner request exceeds the protocol input limit",
            ));
        }
        let remaining = (execution
            .resource
            .deadline
            .min(instance.compute_lease_expires_at)
            - now)
            .num_seconds();
        if remaining < 1 {
            return Err(ApiError::conflict(
                "EXECUTION_DEADLINE_EXPIRED",
                "Execution deadline elapsed before a dispatch attempt",
            ));
        }
        request.timeout_seconds = request.timeout_seconds.min(remaining as u64);
        let attempt = Uuid::new_v4();
        sqlx::query("UPDATE executions SET status='DISPATCHING',dispatch_attempt_id=$3,dispatch_attempted_at=$4,dispatch_lease_token=$5 WHERE tenant_id=$1 AND id=$2")
            .bind(claim.tenant_id).bind(id).bind(attempt).bind(now).bind(claim.lease_token).execute(&mut *tx).await?;
        sqlx::query(
            "UPDATE operations SET stage='DISPATCHING',updated_at=$3 WHERE tenant_id=$1 AND id=$2",
        )
        .bind(claim.tenant_id)
        .bind(claim.operation_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        let (namespace, pod_name): (String, String) =
            sqlx::query_as("SELECT namespace,pod_name FROM instances WHERE tenant_id=$1 AND id=$2")
                .bind(claim.tenant_id)
                .bind(instance.id)
                .fetch_one(&mut *tx)
                .await?;
        event(
            &mut tx,
            &actor,
            id,
            instance.project_id,
            claim.operation_id,
            execution.resource.version + 1,
            "executions:dispatch",
            json!({"dispatch_attempt_id":attempt,"runtime_generation":identity.runtime_generation}),
        )
        .await?;
        tx.commit().await?;
        Ok(PreparedExecution {
            dispatch_attempt_id: attempt,
            request,
            namespace,
            pod_name,
            identity,
            deadline: execution.resource.deadline,
        })
    }

    /// Monotonic loss recording needs the exact persisted attempt ID. It cannot
    /// clear the slot, manufacture a result, or authorize another dispatch.
    pub async fn mark_execution_outcome_unknown(
        &self,
        tenant: Uuid,
        id: Uuid,
        attempt: Uuid,
    ) -> Result<(), ApiError> {
        let mut tx = self.begin(tenant).await?;
        let initial = load_execution(&mut tx, tenant, id, false).await?;
        let initial_instance =
            load_instance(&mut tx, tenant, initial.resource.instance_id, false).await?;
        lock_workspace(&mut tx, tenant, initial_instance.workspace_id).await?;
        load_instance(&mut tx, tenant, initial.resource.instance_id, true).await?;
        let execution = load_execution(&mut tx, tenant, id, true).await?;
        if execution.dispatch_attempt_id != Some(attempt) {
            return Err(ApiError::conflict(
                "DISPATCH_IDENTITY_MISMATCH",
                "Unknown dispatch attempt",
            ));
        }
        if matches!(
            execution.resource.status.as_str(),
            "DISPATCHING" | "RUNNING"
        ) {
            sqlx::query("UPDATE executions SET status='OUTCOME_UNKNOWN',termination_status=CASE WHEN termination_status='NOT_REQUESTED' THEN 'UNKNOWN' ELSE termination_status END,output_status=CASE WHEN output_status='PENDING' THEN 'LOST' ELSE output_status END WHERE tenant_id=$1 AND id=$2")
                .bind(tenant).bind(id).execute(&mut *tx).await?;
            sqlx::query("UPDATE operations SET status='WAITING',stage='OUTCOME_UNKNOWN',wait_reason='DISPATCH_RESULT_UNKNOWN_NO_REPLAY',next_attempt_at=clock_timestamp()+interval '5 minutes',lease_owner=NULL,lease_until=NULL,lease_token=lease_token+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND status IN ('QUEUED','RUNNING','WAITING')")
                .bind(tenant).bind(execution.resource.operation_id).execute(&mut *tx).await?;
            let principal = sqlx::query_scalar(
                "SELECT safety_principal_id FROM platform_configuration WHERE singleton",
            )
            .fetch_one(&mut *tx)
            .await?;
            let actor = Actor {
                authorization: None,
                tenant_id: tenant,
                principal_id: principal,
                request_id: Uuid::new_v4(),
            };
            event(
                &mut tx,
                &actor,
                id,
                execution.resource.project_id,
                execution.resource.operation_id,
                execution.resource.version + 1,
                "executions:outcome_unknown",
                json!({"dispatch_attempt_id":attempt,"automatic_replay_allowed":false}),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

async fn assert_current_activity(
    tx: &mut Transaction<'_, Postgres>,
    instance: &Instance,
    execution: &ExecutionRow,
) -> Result<(), ApiError> {
    assert_activity(tx, instance, execution.resource.id).await?;
    if current_identity(tx, instance).await? != execution.identity()? {
        return Err(ApiError::conflict(
            "EXECUTION_RECONCILIATION_REQUIRED",
            "The execution does not belong to the current instance launch",
        ));
    }
    Ok(())
}

async fn assert_active_stop(
    tx: &mut Transaction<'_, Postgres>,
    instance: &Instance,
    stop_id: Uuid,
) -> Result<(), ApiError> {
    let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM operations o JOIN workspaces w ON w.tenant_id=o.tenant_id AND w.id=o.workspace_id WHERE o.tenant_id=$1 AND o.id=$2 AND o.instance_id=$3 AND o.kind='STOP' AND o.status IN ('QUEUED','RUNNING','WAITING') AND w.active_operation_id=o.id)")
        .bind(instance.tenant_id).bind(stop_id).bind(instance.id).fetch_one(&mut **tx).await?;
    if instance.active_operation_id != Some(stop_id) || !active {
        return Err(ApiError::conflict(
            "OPERATION_RECONCILIATION_REQUIRED",
            "The accepted safety stop no longer has a matching active operation",
        ));
    }
    Ok(())
}

async fn request_stop_locked(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    instance: &Instance,
    execution: &ExecutionRow,
    reason: &str,
    now: DateTime<Utc>,
) -> Result<Uuid, ApiError> {
    assert_current_activity(tx, instance, execution).await?;
    let stop_id = if let Some(active) = instance.active_operation_id {
        let op = sqlx::query(
            "SELECT kind,status FROM operations WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(actor.tenant_id)
        .bind(active)
        .fetch_one(&mut **tx)
        .await?;
        if op.try_get::<String, _>("kind")? != "STOP"
            || !matches!(
                op.try_get::<String, _>("status")?.as_str(),
                "QUEUED" | "RUNNING" | "WAITING"
            )
        {
            return Err(ApiError::conflict(
                "OPERATION_RECONCILIATION_REQUIRED",
                "A conflicting lifecycle operation must be reconciled",
            ));
        }
        active
    } else {
        if instance.desired_state != "RUNNING" || instance.stop_accepted_at.is_some() {
            return Err(ApiError::conflict(
                "EXECUTION_RECONCILIATION_REQUIRED",
                "The instance has no active stop operation to reconcile termination",
            ));
        }
        let stop = Uuid::new_v4();
        insert_operation(tx, actor, stop, instance.project_id, instance.id, instance.workspace_id,
            "STOP", &json!({"reason":reason,"execution_id":execution.resource.id,"hard_stop_instance":true}), now + Duration::minutes(30)).await?;
        sqlx::query(
            "UPDATE operations SET compute_lease_id=$3,stop_reason=$4 WHERE tenant_id=$1 AND id=$2",
        )
        .bind(actor.tenant_id)
        .bind(stop)
        .bind(instance.compute_lease_id)
        .bind(reason)
        .execute(&mut **tx)
        .await?;
        sqlx::query("UPDATE instances SET desired_state='STOPPED',active_operation_id=$3,stop_reason=$4,stop_accepted_at=$5,idle_since=NULL,spec_version=spec_version+1,updated_at=$5 WHERE tenant_id=$1 AND id=$2")
            .bind(actor.tenant_id).bind(instance.id).bind(stop).bind(reason).bind(now).execute(&mut **tx).await?;
        stop
    };
    let moved = sqlx::query("UPDATE workspaces SET active_operation_id=$3,updated_at=$4 WHERE tenant_id=$1 AND id=$2 AND (active_operation_id IS NULL OR active_operation_id=$3)")
        .bind(actor.tenant_id).bind(instance.workspace_id).bind(stop_id).bind(now).execute(&mut **tx).await?;
    if moved.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "WORKSPACE_RECONCILIATION_REQUIRED",
            "The workspace has a conflicting operation",
        ));
    }
    sqlx::query("UPDATE operations SET status='CANCELLED',stage='CANCELLED_BY_HARD_STOP',cancel_requested=true,lease_owner=NULL,lease_until=NULL,lease_token=lease_token+1,completed_at=$3,updated_at=$3 WHERE tenant_id=$1 AND id=$2 AND status IN ('QUEUED','RUNNING','WAITING')")
        .bind(actor.tenant_id).bind(execution.resource.operation_id).bind(now).execute(&mut **tx).await?;
    let timed_out = reason == "EXECUTION_TIMEOUT" && execution.dispatch_attempt_id.is_none();
    sqlx::query("UPDATE executions SET cancel_requested_at=COALESCE(cancel_requested_at,$3),cancel_operation_id=$4,termination_status='PENDING',status=CASE WHEN status IN ('DISPATCHING','RUNNING') THEN 'OUTCOME_UNKNOWN' WHEN $5 AND status='QUEUED' THEN 'TIMED_OUT' ELSE status END,completed_at=CASE WHEN $5 AND status='QUEUED' THEN $3 ELSE completed_at END WHERE tenant_id=$1 AND id=$2")
        .bind(actor.tenant_id).bind(execution.resource.id).bind(now).bind(stop_id).bind(timed_out).execute(&mut **tx).await?;
    Ok(stop_id)
}

async fn load_execution(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    id: Uuid,
    lock: bool,
) -> Result<ExecutionRow, ApiError> {
    let sql = if lock {
        "SELECT * FROM executions WHERE tenant_id=$1 AND id=$2 FOR UPDATE"
    } else {
        "SELECT * FROM executions WHERE tenant_id=$1 AND id=$2"
    };
    sqlx::query_as(sql)
        .bind(tenant)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(ApiError::not_found)
}
pub(crate) async fn lock_workspace(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    id: Uuid,
) -> Result<(), ApiError> {
    sqlx::query("SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(tenant)
        .bind(id)
        .fetch_one(&mut **tx)
        .await?;
    Ok(())
}
async fn current_identity(
    tx: &mut Transaction<'_, Postgres>,
    instance: &Instance,
) -> Result<DispatchIdentity, ApiError> {
    let row=sqlx::query("SELECT runtime_generation,launch_id,pod_uid,cluster_epoch FROM instances WHERE tenant_id=$1 AND id=$2")
        .bind(instance.tenant_id).bind(instance.id).fetch_one(&mut **tx).await?;
    Ok(DispatchIdentity {
        runtime_generation: row.try_get("runtime_generation")?,
        launch_id: row.try_get("launch_id")?,
        pod_uid: row.try_get::<Option<Uuid>, _>("pod_uid")?.ok_or_else(|| {
            ApiError::conflict("INSTANCE_NOT_READY", "Current Pod identity is not known")
        })?,
        cluster_epoch: row.try_get("cluster_epoch")?,
    })
}
pub(crate) async fn ready_identity(
    tx: &mut Transaction<'_, Postgres>,
    instance: &Instance,
    epoch: Uuid,
    now: DateTime<Utc>,
) -> Result<DispatchIdentity, ApiError> {
    if instance.desired_state != "RUNNING"
        || instance.observed_state != "RUNNING"
        || instance.active_operation_id.is_some()
        || instance.stop_accepted_at.is_some()
    {
        return Err(ApiError::conflict(
            "INSTANCE_NOT_READY",
            "The instance has not completed its current launch or has a lifecycle operation",
        ));
    }
    if instance.compute_lease_expires_at <= now {
        return Err(ApiError::conflict(
            "COMPUTE_LEASE_EXPIRED",
            "The compute lease has expired",
        ));
    }
    let current = current_identity(tx, instance).await?;
    let verified:bool=sqlx::query_scalar("SELECT COALESCE(i.ready_generation=i.runtime_generation AND i.ready_launch_id=i.launch_id AND i.ready_pod_uid=i.pod_uid AND i.ready_cluster_epoch=i.cluster_epoch AND i.ready_observed_at>=i.compute_lease_started_at AND i.ready_observed_at<=clock_timestamp() AND w.status='IN_USE' AND w.active_operation_id IS NULL AND w.delete_requested_at IS NULL,false) FROM instances i JOIN workspaces w ON w.tenant_id=i.tenant_id AND w.id=i.workspace_id WHERE i.tenant_id=$1 AND i.id=$2")
        .bind(instance.tenant_id).bind(instance.id).fetch_one(&mut **tx).await?;
    if current.cluster_epoch != epoch || !verified {
        return Err(ApiError::conflict(
            "INSTANCE_NOT_READY",
            "Ready evidence does not match the current launch, epoch or workspace",
        ));
    }
    Ok(current)
}
async fn assert_activity(
    tx: &mut Transaction<'_, Postgres>,
    instance: &Instance,
    execution: Uuid,
) -> Result<(), ApiError> {
    let matches:bool=sqlx::query_scalar("SELECT slot_held AND activity_kind='EXECUTION' AND activity_id=$3 AND activity_generation=runtime_generation FROM instances WHERE tenant_id=$1 AND id=$2")
        .bind(instance.tenant_id).bind(instance.id).bind(execution).fetch_one(&mut **tx).await?;
    if !matches {
        return Err(ApiError::conflict(
            "EXECUTION_RECONCILIATION_REQUIRED",
            "Execution no longer owns the instance activity slot",
        ));
    }
    Ok(())
}
async fn now(tx: &mut Transaction<'_, Postgres>) -> Result<DateTime<Utc>, ApiError> {
    Ok(sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?)
}
pub(crate) fn check_version(actual: i64, expected: i64) -> Result<(), ApiError> {
    if actual != expected {
        return Err(ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "VERSION_MISMATCH",
            "The resource changed; read its current ETag before a new mutation",
        ));
    }
    Ok(())
}
async fn replay(
    idem: &Idempotency,
    tx: &mut Transaction<'_, Postgres>,
) -> Result<Option<ExecutionMutationResult>, ApiError> {
    let Some((status, value)) = idem.replay_json(tx).await? else {
        return Ok(None);
    };
    let body = serde_json::from_value(value).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INVALID_RECEIPT",
            "Stored execution receipt cannot be decoded",
        )
    })?;
    Ok(Some(ExecutionMutationResult { status, body }))
}
#[allow(clippy::too_many_arguments)]
async fn finish(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    idem: &Idempotency,
    execution: Uuid,
    operation: Uuid,
    action: &str,
    now: DateTime<Utc>,
) -> Result<ExecutionMutationResult, ApiError> {
    let resource = load_execution(tx, actor.tenant_id, execution, false)
        .await?
        .public();
    let instance = load_instance(tx, actor.tenant_id, resource.instance_id, false).await?;
    let op = load_operation(tx, actor.tenant_id, operation).await?;
    event(tx,actor,execution,resource.project_id,operation,resource.version,action,json!({"instance_id":instance.id,"status":resource.status,"termination_status":resource.termination_status})).await?;
    let body = AcceptedExecution {
        resource,
        operation: op,
        instance_id: instance.id,
        instance_spec_version: instance.spec_version,
        idempotency_expires_at: now + Duration::days(7),
    };
    let value = serde_json::to_value(&body)
        .map_err(|_| ApiError::invalid("Cannot encode execution receipt"))?;
    idem.persist_json(
        tx,
        instance.project_id,
        operation,
        execution,
        &value,
        202,
        now,
        body.idempotency_expires_at,
    )
    .await?;
    Ok(ExecutionMutationResult { status: 202, body })
}
#[allow(clippy::too_many_arguments)]
async fn event(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    execution: Uuid,
    project: Uuid,
    operation: Uuid,
    version: i64,
    action: &str,
    details: Value,
) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details) VALUES($1,$2,$3,$4,$5,$6,$7,'ACCEPTED',$8)")
        .bind(actor.tenant_id).bind(project).bind(actor.principal_id).bind(actor.request_id).bind(operation).bind(execution).bind(action).bind(&details).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(actor.tenant_id).bind(project).bind(execution).bind(version).bind(format!("{action}.accepted")).bind(operation).bind(actor.request_id).bind(details).execute(&mut **tx).await?;
    Ok(())
}
