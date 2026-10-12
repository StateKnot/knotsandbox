//! Workspace data destruction has its own authorization and durable intent.
//! Instance DELETE never calls this API or transfers storage ownership.
use crate::{
    db::{Actor, Database, Idempotency, load_operation},
    error::ApiError,
    model::Operation,
    request::request_digest,
};
use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Workspace {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub size_gib: i64,
    pub status: String,
    pub spec_version: i64,
    pub active_operation_id: Option<Uuid>,
    pub retention_until: Option<DateTime<Utc>>,
    pub delete_requested_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteWorkspace {
    pub confirm_workspace_id: Uuid,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkspaceAccepted {
    pub resource: Workspace,
    pub operation: Operation,
    pub idempotency_expires_at: DateTime<Utc>,
}
pub struct WorkspaceMutationResult {
    pub status: u16,
    pub body: WorkspaceAccepted,
}

impl Database {
    pub async fn get_workspace(&self, actor: &Actor, id: Uuid) -> Result<Workspace, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let row: Workspace =
            sqlx::query_as("SELECT * FROM workspaces WHERE tenant_id=$1 AND id=$2")
                .bind(actor.tenant_id)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(ApiError::not_found)?;
        Self::authorize_resource(&mut tx, actor, row.project_id, "workspaces:read").await?;
        tx.commit().await?;
        Ok(row)
    }

    pub async fn delete_workspace(
        &self,
        actor: &Actor,
        id: Uuid,
        request: &DeleteWorkspace,
        key: &str,
        expected: i64,
    ) -> Result<WorkspaceMutationResult, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let initial: Option<Uuid> =
            sqlx::query_scalar("SELECT project_id FROM workspaces WHERE tenant_id=$1 AND id=$2")
                .bind(actor.tenant_id)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        let project = initial.ok_or_else(ApiError::not_found)?;
        Self::authorize_resource(&mut tx, actor, project, "workspaces:delete").await?;
        if request.confirm_workspace_id != id || id.is_nil() {
            return Err(ApiError::invalid(
                "confirm_workspace_id must match this workspace UUID",
            ));
        }
        let digest = request_digest(request, Some(expected))?;
        let idem = Idempotency::new(actor, id, "workspaces:delete", key, &digest);
        if let Some((status, receipt)) = idem.replay_json(&mut tx).await? {
            // The advisory lock can wait. Recheck revocation before replaying.
            Self::authorize_resource(&mut tx, actor, project, "workspaces:delete").await?;
            let body = serde_json::from_value(receipt).map_err(|_| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INVALID_RECEIPT",
                    "Stored workspace receipt cannot be decoded",
                )
            })?;
            tx.commit().await?;
            return Ok(WorkspaceMutationResult { status, body });
        }
        let current: Workspace =
            sqlx::query_as("SELECT * FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
                .bind(actor.tenant_id)
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
        Self::authorize_resource(&mut tx, actor, project, "workspaces:delete").await?;
        if expected != current.spec_version {
            return Err(ApiError::new(
                StatusCode::PRECONDITION_FAILED,
                "VERSION_MISMATCH",
                "The workspace has changed",
            ));
        }
        if current.status != "AVAILABLE"
            || current.active_operation_id.is_some()
            || current.delete_requested_at.is_some()
        {
            return Err(ApiError::conflict(
                "WORKSPACE_BUSY",
                "Workspace destruction requires an available, inactive workspace",
            ));
        }
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        // NULL opts out of automatic expiry, not explicit authorized destruction.
        if current.retention_until.is_some_and(|until| until > now) {
            return Err(ApiError::conflict(
                "WORKSPACE_RETENTION_ACTIVE",
                "The workspace retention period has not ended",
            ));
        }
        let closed: bool = sqlx::query_scalar("SELECT sandbox_workspace_writers_closed($1,$2)")
            .bind(actor.tenant_id)
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
        if !closed {
            return Err(ApiError::conflict(
                "WORKSPACE_DELETION_BLOCKED",
                "A writer, termination proof or retention hold prevents workspace destruction",
            ));
        }
        let epoch: Uuid =
            sqlx::query_scalar("SELECT cluster_epoch FROM platform_configuration WHERE singleton")
                .fetch_one(&mut *tx)
                .await?;
        let operation = Uuid::new_v4();
        sqlx::query("INSERT INTO operations(id,tenant_id,project_id,workspace_id,kind,request,actor_principal_id,request_id,deadline) VALUES($1,$2,$3,$4,'DELETE_WORKSPACE',$5,$6,$7,$8)")
            .bind(operation).bind(actor.tenant_id).bind(project).bind(id).bind(json!(request)).bind(actor.principal_id).bind(actor.request_id).bind(now+Duration::hours(24)).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO workspace_delete_intents(operation_id,tenant_id,project_id,workspace_id,cluster_epoch,confirmed_workspace_id,accepted_version) VALUES($1,$2,$3,$4,$5,$4,$6)")
            .bind(operation).bind(actor.tenant_id).bind(project).bind(id).bind(epoch).bind(expected).execute(&mut *tx).await?;
        let resource:Workspace=sqlx::query_as("UPDATE workspaces SET status='DELETING',spec_version=spec_version+1,active_operation_id=$3,delete_authorization_ref=$3::text,delete_requested_at=$4,updated_at=$4 WHERE tenant_id=$1 AND id=$2 RETURNING *")
            .bind(actor.tenant_id).bind(id).bind(operation).bind(now).fetch_one(&mut *tx).await?;
        sqlx::query(
            "UPDATE operations SET next_attempt_at=next_attempt_at WHERE tenant_id=$1 AND id=$2",
        )
        .bind(actor.tenant_id)
        .bind(operation)
        .execute(&mut *tx)
        .await?;
        let operation = load_operation(&mut tx, actor.tenant_id, operation).await?;
        let body = WorkspaceAccepted {
            resource,
            operation,
            idempotency_expires_at: now + Duration::days(7),
        };
        idem.persist_json(
            &mut tx,
            project,
            body.operation.id,
            id,
            &json!(&body),
            202,
            now,
            body.idempotency_expires_at,
        )
        .await?;
        sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details) VALUES($1,$2,$3,$4,$5,$6,'workspaces:delete','ACCEPTED',$7)")
            .bind(actor.tenant_id).bind(project).bind(actor.principal_id).bind(actor.request_id).bind(body.operation.id).bind(id).bind(json!({"confirmed_workspace_id":id,"automatic_reclamation":false})).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload) VALUES($1,$2,$3,$4,'workspace.delete.accepted',$5,$6,$7)")
            .bind(actor.tenant_id).bind(project).bind(id).bind(body.resource.spec_version).bind(body.operation.id).bind(actor.request_id).bind(json!({"status":"DELETING"})).execute(&mut *tx).await?;
        // Sequencing or locks may have outlived the authorizing grant.
        Self::authorize_resource(&mut tx, actor, project, "workspaces:delete").await?;
        tx.commit().await?;
        Ok(WorkspaceMutationResult { status: 202, body })
    }
}
