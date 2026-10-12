//! Transactional lifecycle acceptance. Runtime effects belong to the worker;
//! accepting a stop never proves termination or releases an activity/quota.

use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{
    db::{
        Actor, Database, Idempotency, MutationResult, domain_error, insert_operation,
        load_instance, load_operation, record_acceptance, reserve_quota, runnable_epoch,
    },
    domain::{ComputeLease, InstanceAction, LifecycleState, OperationKind},
    error::ApiError,
    model::{Accepted, Instance, RenewRequest, StartRequest},
    request::request_digest,
};

impl Database {
    #[allow(clippy::too_many_arguments)]
    pub async fn renew_instance(
        &self,
        actor: &Actor,
        id: Uuid,
        request: &RenewRequest,
        key: &str,
        expected: i64,
        max_ttl: i64,
    ) -> Result<MutationResult, ApiError> {
        self.renew_instance_inner(actor, id, request, key, expected, max_ttl, None)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn renew_instance_with_automation(
        &self,
        actor: &Actor,
        id: Uuid,
        request: &RenewRequest,
        key: &str,
        expected: i64,
        max_ttl: i64,
        fence: &crate::automation_authority::AutomationAcceptanceFence,
    ) -> Result<MutationResult, ApiError> {
        self.renew_instance_inner(actor, id, request, key, expected, max_ttl, Some(fence))
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn renew_instance_inner(
        &self,
        actor: &Actor,
        id: Uuid,
        request: &RenewRequest,
        key: &str,
        expected: i64,
        max_ttl: i64,
        fence: Option<&crate::automation_authority::AutomationAcceptanceFence>,
    ) -> Result<MutationResult, ApiError> {
        if let Some(fence) = fence {
            fence.check_request(request, key, expected)?;
        }
        let mut tx = self.begin(actor.tenant_id).await?;
        if let Some(fence) = fence {
            fence.bind(&mut tx).await?;
        }
        let initial = load_instance(&mut tx, actor.tenant_id, id, false).await?;
        Self::authorize_resource(&mut tx, actor, initial.project_id, "instances:renew").await?;
        let digest = request_digest(request, Some(expected))?;
        let idem = Idempotency::new(actor, id, "instances:renew", key, &digest);
        if let Some(previous) = idem.replay(&mut tx).await? {
            tx.commit().await?;
            return Ok(previous);
        }
        // RENEW inserts an operation with a workspace FK. Its deferred check
        // also locks the workspace, so explicit lock ordering must match stop.
        sqlx::query("SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
            .bind(actor.tenant_id)
            .bind(initial.workspace_id)
            .fetch_one(&mut *tx)
            .await?;
        let instance = load_instance(&mut tx, actor.tenant_id, id, true).await?;
        Self::authorize_resource(&mut tx, actor, instance.project_id, "instances:renew").await?;
        let now = database_now(&mut tx).await?;
        check_version(&instance, expected)?;
        state(&instance)?
            .validate(InstanceAction::Renew)
            .map_err(domain_error)?;
        if let Some(active_id) = instance.active_operation_id {
            let active = load_operation(&mut tx, actor.tenant_id, active_id).await?;
            if !matches!(active.kind.as_str(), "CREATE" | "START")
                || !matches!(active.status.as_str(), "QUEUED" | "RUNNING" | "WAITING")
            {
                return Err(ApiError::conflict(
                    "OPERATION_CONFLICT",
                    "Only create/start may run concurrently with renewal",
                ));
            }
        }
        runnable_epoch(&mut tx).await?;
        let project_limit =
            project_ttl_limit(&mut tx, actor.tenant_id, instance.project_id).await?;
        let renewed = lease(&instance)
            .renew(
                now,
                request.expires_at,
                instance.compute_lease_version,
                max_ttl.min(project_limit),
                instance.stop_accepted_at.is_some(),
            )
            .map_err(domain_error)?;
        // The scoped definer exposes no global node/report inventory. Pending
        // launches without an assignment can renew; an assigned launch must
        // remain inside its current node's reviewed certification horizon.
        let (assigned, certified_until): (bool, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT assigned,valid_until FROM sandbox_instance_certification($1,$2)",
        )
        .bind(actor.tenant_id)
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        if (assigned && certified_until.is_none_or(|expiry| renewed.expires_at > expiry))
            || (!assigned && instance.observed_state == "RUNNING")
        {
            return Err(ApiError::conflict(
                "CERTIFICATION_LEASE_LIMIT",
                "Renew the assigned node certification before extending this compute lease",
            ));
        }
        let operation_id = Uuid::new_v4();
        insert_operation(
            &mut tx,
            actor,
            operation_id,
            instance.project_id,
            id,
            instance.workspace_id,
            "RENEW",
            &serde_json::to_value(request)
                .map_err(|_| ApiError::invalid("Invalid renewal request"))?,
            renewed.expires_at,
        )
        .await?;
        sqlx::query("UPDATE operations SET status='SUCCEEDED',stage='COMPLETED',compute_lease_id=$3,completed_at=$4,updated_at=$4 WHERE tenant_id=$1 AND id=$2")
            .bind(actor.tenant_id).bind(operation_id).bind(renewed.id).bind(now).execute(&mut *tx).await?;
        // Preserve active CREATE/START: renewal changes the lease, not orchestration ownership.
        sqlx::query("UPDATE instances SET compute_lease_expires_at=$3,compute_lease_version=$4,spec_version=spec_version+1,updated_at=$5 WHERE tenant_id=$1 AND id=$2")
            .bind(actor.tenant_id).bind(id).bind(renewed.expires_at).bind(renewed.version).bind(now).execute(&mut *tx).await?;
        let result = finish_acceptance(
            &mut tx,
            actor,
            id,
            operation_id,
            "instances:renew",
            &idem,
            now,
            200,
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn lifecycle_action(
        &self,
        actor: &Actor,
        id: Uuid,
        action: InstanceAction,
        request: &StartRequest,
        key: &str,
        expected: i64,
        default_ttl: i64,
        max_ttl: i64,
    ) -> Result<MutationResult, ApiError> {
        self.lifecycle_action_inner(
            actor,
            id,
            action,
            request,
            key,
            expected,
            default_ttl,
            max_ttl,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn lifecycle_action_with_automation(
        &self,
        actor: &Actor,
        id: Uuid,
        action: InstanceAction,
        request: &StartRequest,
        key: &str,
        expected: i64,
        default_ttl: i64,
        max_ttl: i64,
        fence: &crate::automation_authority::AutomationAcceptanceFence,
    ) -> Result<MutationResult, ApiError> {
        self.lifecycle_action_inner(
            actor,
            id,
            action,
            request,
            key,
            expected,
            default_ttl,
            max_ttl,
            Some(fence),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn lifecycle_action_inner(
        &self,
        actor: &Actor,
        id: Uuid,
        action: InstanceAction,
        request: &StartRequest,
        key: &str,
        expected: i64,
        default_ttl: i64,
        max_ttl: i64,
        fence: Option<&crate::automation_authority::AutomationAcceptanceFence>,
    ) -> Result<MutationResult, ApiError> {
        if let Some(fence) = fence {
            fence.check_request(request, key, expected)?;
        }
        let (permission, operation_kind) = match action {
            InstanceAction::Start => ("instances:start", "START"),
            InstanceAction::Stop => ("instances:stop", "STOP"),
            InstanceAction::Restart => ("instances:restart", "RESTART"),
            InstanceAction::Delete => ("instances:delete", "DELETE"),
            _ => return Err(ApiError::invalid("Unsupported lifecycle action")),
        };
        if action != InstanceAction::Start && request.ttl_seconds.is_some() {
            return Err(ApiError::invalid(
                "Only start accepts ttl_seconds; restart preserves the current compute lease",
            ));
        }
        let mut tx = self.begin(actor.tenant_id).await?;
        if let Some(fence) = fence {
            fence.bind(&mut tx).await?;
        }
        let initial = load_instance(&mut tx, actor.tenant_id, id, false).await?;
        Self::authorize_resource(&mut tx, actor, initial.project_id, permission).await?;
        // This implementation terminates the entire VM. An empty activity slot
        // does not prove there are no guest background processes.
        if action != InstanceAction::Start {
            Self::authorize_resource(&mut tx, actor, initial.project_id, "instances:hard_stop")
                .await?;
        }
        let digest = request_digest(request, Some(expected))?;
        let idem = Idempotency::new(actor, id, permission, key, &digest);
        if let Some(previous) = idem.replay(&mut tx).await? {
            tx.commit().await?;
            return Ok(previous);
        }

        // The workspace binding is immutable. All workspace lifecycle paths use
        // workspace -> instance order so reclaim cannot race a new start.
        let workspace = sqlx::query("SELECT status,active_operation_id,delete_requested_at FROM workspaces WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE")
            .bind(actor.tenant_id).bind(initial.project_id).bind(initial.workspace_id).fetch_one(&mut *tx).await?;
        let instance = load_instance(&mut tx, actor.tenant_id, id, true).await?;
        Self::authorize_resource(&mut tx, actor, instance.project_id, permission).await?;
        if action != InstanceAction::Start {
            Self::authorize_resource(&mut tx, actor, instance.project_id, "instances:hard_stop")
                .await?;
        }
        let now = database_now(&mut tx).await?;
        check_version(&instance, expected)?;
        let lifecycle = state(&instance)?;
        let mut preempted = None;
        if matches!(action, InstanceAction::Stop | InstanceAction::Delete)
            && instance.active_operation_id.is_some()
        {
            let active_id = instance
                .active_operation_id
                .ok_or_else(ApiError::not_found)?;
            let active = sqlx::query(
                "SELECT kind,status FROM operations WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
            )
            .bind(actor.tenant_id)
            .bind(active_id)
            .fetch_one(&mut *tx)
            .await?;
            let active_kind: OperationKind = active
                .try_get::<String, _>("kind")?
                .parse()
                .map_err(domain_error)?;
            let recover_unstarted_stop =
                if action == InstanceAction::Delete && active_kind == OperationKind::Stop {
                    sqlx::query_scalar::<_, bool>(
                        "SELECT sandbox_never_authorized_stop_candidate($1,$2)",
                    )
                    .bind(actor.tenant_id)
                    .bind(id)
                    .fetch_one(&mut *tx)
                    .await?
                } else {
                    false
                };
            if !recover_unstarted_stop {
                lifecycle
                    .validate_safety_stop(Some(active_kind))
                    .map_err(domain_error)?;
            }
            let status: String = active.try_get("status")?;
            if !matches!(status.as_str(), "QUEUED" | "RUNNING" | "WAITING") {
                return Err(ApiError::conflict(
                    "OPERATION_CONFLICT",
                    "The active operation requires reconciliation",
                ));
            }
            preempted = Some(active_id);
        } else {
            lifecycle.validate(action).map_err(domain_error)?;
        }

        let operation_id = Uuid::new_v4();
        let current_lease = lease(&instance);
        let mut new_lease = None;
        let mut epoch = None;
        if matches!(action, InstanceAction::Start | InstanceAction::Restart) {
            epoch = Some(runnable_epoch(&mut tx).await?);
            let approved: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM template_versions WHERE tenant_id=$1 AND id=$2 AND status='APPROVED') AND EXISTS(SELECT 1 FROM security_policy_versions WHERE tenant_id=$1 AND id=$3 AND status='APPROVED')")
                .bind(actor.tenant_id).bind(instance.template_version_id).bind(instance.security_policy_version_id).fetch_one(&mut *tx).await?;
            if !approved {
                return Err(ApiError::conflict(
                    "RUNTIME_POLICY_REVOKED",
                    "The template and security profile must remain approved before starting compute",
                ));
            }
        }
        if action == InstanceAction::Start {
            let workspace_status: String = workspace.try_get("status")?;
            let workspace_operation: Option<Uuid> = workspace.try_get("active_operation_id")?;
            let deleting: Option<DateTime<Utc>> = workspace.try_get("delete_requested_at")?;
            if workspace_status != "AVAILABLE"
                || workspace_operation.is_some()
                || deleting.is_some()
            {
                return Err(ApiError::conflict(
                    "WORKSPACE_BUSY",
                    "The workspace is unavailable or its deletion has already been accepted",
                ));
            }
            let ttl = request.ttl_seconds.unwrap_or(default_ttl);
            if !(60..=max_ttl).contains(&ttl) {
                return Err(ApiError::invalid(
                    "ttl_seconds is outside the configured range",
                ));
            }
            let project_limit =
                project_ttl_limit(&mut tx, actor.tenant_id, instance.project_id).await?;
            new_lease = Some(
                ComputeLease::new(Uuid::new_v4(), now, ttl, max_ttl.min(project_limit))
                    .map_err(domain_error)?,
            );
            let unreleased: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM quota_reservations r JOIN quota_accounts q ON q.tenant_id=r.tenant_id AND q.id=r.quota_account_id WHERE r.tenant_id=$1 AND r.resource_id=$2 AND r.status<>'RELEASED' AND q.dimension IN ('CPU_MILLIS','MEMORY_MIB'))")
                .bind(actor.tenant_id).bind(id).fetch_one(&mut *tx).await?;
            if unreleased {
                return Err(ApiError::conflict(
                    "COMPUTE_QUOTA_RECONCILIATION_REQUIRED",
                    "The previous compute allocation has not been released after confirmed termination",
                ));
            }
        } else if action == InstanceAction::Restart {
            current_lease
                .validate_admission(now, instance.stop_accepted_at.is_some())
                .map_err(domain_error)?;
        }

        if let Some(old_operation) = preempted {
            // Fences DB progress of the old worker. Its in-flight external calls
            // are still handled by the fixed-name/finalizer stop reconciliation.
            sqlx::query("UPDATE operations SET status='CANCELLED',stage=$4,cancel_requested=true,lease_owner=NULL,lease_until=NULL,lease_token=lease_token+1,wait_reason=NULL,completed_at=$3,updated_at=$3 WHERE tenant_id=$1 AND id=$2")
                .bind(actor.tenant_id).bind(old_operation).bind(now).bind(if action == InstanceAction::Delete { "SUPERSEDED_BY_DELETE" } else { "SUPERSEDED_BY_STOP" }).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details) VALUES($1,$2,$3,$4,$5,$6,'operations:cancel','ACCEPTED',$7)")
                .bind(actor.tenant_id).bind(instance.project_id).bind(actor.principal_id).bind(actor.request_id).bind(old_operation).bind(id)
                .bind(serde_json::json!({"superseded_by":operation_id,"reason":"USER_REQUESTED","termination_confirmed":false})).execute(&mut *tx).await?;
        }
        // This bounds worker alert/escalation timing. Expiry never authorizes
        // releasing resources; a timed-out stop remains pending reconciliation.
        let deadline = match action {
            InstanceAction::Start => {
                new_lease
                    .as_ref()
                    .ok_or_else(|| ApiError::invalid("Missing start lease"))?
                    .expires_at
            }
            InstanceAction::Restart => current_lease.expires_at,
            _ => now + Duration::minutes(30),
        };
        insert_operation(
            &mut tx,
            actor,
            operation_id,
            instance.project_id,
            id,
            instance.workspace_id,
            operation_kind,
            &serde_json::to_value(request)
                .map_err(|_| ApiError::invalid("Invalid lifecycle request"))?,
            deadline,
        )
        .await?;

        if let Some(new_lease) = new_lease {
            sqlx::query("UPDATE instances SET desired_state='RUNNING',spec_version=spec_version+1,runtime_generation=runtime_generation+1,launch_id=$3,pod_uid=NULL,cluster_epoch=$4,active_operation_id=$5,compute_lease_id=$6,compute_lease_version=$7,compute_lease_started_at=$8,compute_lease_expires_at=$9,stop_reason=NULL,stop_accepted_at=NULL,idle_since=NULL,updated_at=$8 WHERE tenant_id=$1 AND id=$2")
                .bind(actor.tenant_id).bind(id).bind(Uuid::new_v4()).bind(epoch).bind(operation_id).bind(new_lease.id).bind(new_lease.version).bind(now).bind(new_lease.expires_at).execute(&mut *tx).await?;
            sqlx::query("UPDATE workspaces SET active_operation_id=$3,updated_at=$4 WHERE tenant_id=$1 AND id=$2")
                .bind(actor.tenant_id).bind(instance.workspace_id).bind(operation_id).bind(now).execute(&mut *tx).await?;
            reserve_quota(
                &mut tx,
                actor,
                instance.project_id,
                operation_id,
                id,
                instance.workspace_id,
                &[
                    ("CPU_MILLIS", instance.cpu_millis),
                    ("MEMORY_MIB", instance.memory_mib),
                ],
            )
            .await?;
            sqlx::query("UPDATE operations SET compute_lease_id=$3 WHERE tenant_id=$1 AND id=$2")
                .bind(actor.tenant_id)
                .bind(operation_id)
                .bind(new_lease.id)
                .execute(&mut *tx)
                .await?;
        } else if action == InstanceAction::Restart {
            // Keep launch identity and generation until the worker proves the
            // previous VM stopped. The active operation closes new admissions.
            sqlx::query("UPDATE instances SET spec_version=spec_version+1,active_operation_id=$3,idle_since=NULL,updated_at=$4 WHERE tenant_id=$1 AND id=$2")
                .bind(actor.tenant_id).bind(id).bind(operation_id).bind(now).execute(&mut *tx).await?;
            sqlx::query("UPDATE operations SET compute_lease_id=$3 WHERE tenant_id=$1 AND id=$2")
                .bind(actor.tenant_id)
                .bind(operation_id)
                .bind(current_lease.id)
                .execute(&mut *tx)
                .await?;
        } else {
            let desired = if action == InstanceAction::Delete {
                "DELETED"
            } else {
                "STOPPED"
            };
            sqlx::query("UPDATE instances SET desired_state=$3,spec_version=spec_version+1,active_operation_id=$4,stop_reason=COALESCE(stop_reason,'USER_REQUESTED'),stop_accepted_at=COALESCE(stop_accepted_at,$5),idle_since=NULL,updated_at=$5 WHERE tenant_id=$1 AND id=$2")
                .bind(actor.tenant_id).bind(id).bind(desired).bind(operation_id).bind(now).execute(&mut *tx).await?;
            sqlx::query("UPDATE operations SET compute_lease_id=$3,stop_reason='USER_REQUESTED' WHERE tenant_id=$1 AND id=$2")
                .bind(actor.tenant_id).bind(operation_id).bind(current_lease.id).execute(&mut *tx).await?;
            if let Some(old_operation) = preempted {
                sqlx::query("UPDATE workspaces SET active_operation_id=$4,updated_at=$5 WHERE tenant_id=$1 AND id=$2 AND active_operation_id=$3")
                    .bind(actor.tenant_id).bind(instance.workspace_id).bind(old_operation).bind(operation_id).bind(now).execute(&mut *tx).await?;
            }
        }
        let result = finish_acceptance(
            &mut tx,
            actor,
            id,
            operation_id,
            permission,
            &idem,
            now,
            202,
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }
}

fn state(instance: &Instance) -> Result<LifecycleState, ApiError> {
    Ok(LifecycleState {
        desired: instance.desired_state.parse().map_err(domain_error)?,
        observed: instance.observed_state.parse().map_err(domain_error)?,
        has_active_operation: instance.active_operation_id.is_some(),
        has_activity: instance.slot_held,
        stop_accepted: instance.stop_accepted_at.is_some(),
    })
}

fn lease(instance: &Instance) -> ComputeLease {
    ComputeLease {
        id: instance.compute_lease_id,
        version: instance.compute_lease_version,
        started_at: instance.compute_lease_started_at,
        expires_at: instance.compute_lease_expires_at,
    }
}

fn check_version(instance: &Instance, expected: i64) -> Result<(), ApiError> {
    if instance.spec_version != expected {
        return Err(ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "VERSION_MISMATCH",
            "The instance changed; read its current ETag before a new mutation",
        ));
    }
    Ok(())
}

async fn database_now(tx: &mut Transaction<'_, Postgres>) -> Result<DateTime<Utc>, ApiError> {
    Ok(sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?)
}

async fn project_ttl_limit(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    project: Uuid,
) -> Result<i64, ApiError> {
    Ok(
        sqlx::query_scalar("SELECT max_ttl_seconds FROM projects WHERE tenant_id=$1 AND id=$2")
            .bind(tenant)
            .bind(project)
            .fetch_one(&mut **tx)
            .await?,
    )
}

#[allow(clippy::too_many_arguments)]
async fn finish_acceptance(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    instance_id: Uuid,
    operation_id: Uuid,
    action: &str,
    idem: &Idempotency,
    now: DateTime<Utc>,
    status: i16,
) -> Result<MutationResult, ApiError> {
    let resource = load_instance(tx, actor.tenant_id, instance_id, false).await?;
    let operation = load_operation(tx, actor.tenant_id, operation_id).await?;
    record_acceptance(tx, actor, &resource, &operation, action).await?;
    let body = Accepted {
        resource,
        operation,
        idempotency_expires_at: now + Duration::days(7),
    };
    idem.persist(tx, &body, status, now).await?;
    // The caller owns the transaction; it commits after building the receipt.
    Ok(MutationResult {
        status: status as u16,
        body,
    })
}
