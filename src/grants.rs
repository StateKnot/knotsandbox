//! Project grant management with bounded delegation. Tenant management writes
//! serialize independently of lifecycle locks; ordinary authorization never
//! acquires this lock.
use crate::{
    db::{Actor, Database},
    error::ApiError,
    history::{CursorSigner, HistoryPage, HistoryQuery, HistoryRow, authorize_window},
    request::request_digest,
};
use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub const PROJECT_ACTIONS: &[&str] = &[
    "*",
    "instances:create",
    "instances:read",
    "instances:start",
    "instances:stop",
    "instances:restart",
    "instances:renew",
    "instances:delete",
    "instances:hard_stop",
    "workspaces:read",
    "workspaces:delete",
    "backups:create",
    "backups:read",
    "diagnoses:create",
    "diagnoses:read",
    "operations:read",
    "events:read",
    "audit:read",
    "capabilities:read",
    "executions:create",
    "executions:read",
    "executions:cancel",
    "executions:output:read",
    "files:read",
    "files:write",
    "automations:read",
    "automations:write",
    "grants:read",
    "grants:write",
];
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ProjectGrant {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub principal_id: Uuid,
    pub action: String,
    pub enabled: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
impl HistoryRow for ProjectGrant {
    fn time(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn id(&self) -> Uuid {
        self.id
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateGrant {
    pub principal_id: Uuid,
    pub action: String,
    #[serde(deserialize_with = "required_expiry")]
    pub expires_at: Option<DateTime<Utc>>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateGrant {
    pub enabled: bool,
    #[serde(deserialize_with = "required_expiry")]
    pub expires_at: Option<DateTime<Utc>>,
}
fn required_expiry<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<DateTime<Utc>>, D::Error> {
    Option::deserialize(d)
}
#[derive(Debug, Serialize, Deserialize)]
pub struct GrantReceipt {
    pub resource: ProjectGrant,
    pub idempotency_expires_at: DateTime<Utc>,
}
pub struct GrantMutationResult {
    pub status: u16,
    pub body: GrantReceipt,
}
enum Change<'a> {
    Create(&'a CreateGrant),
    Update(Uuid, &'a UpdateGrant, i64),
    Revoke(Uuid, i64),
}

impl Database {
    pub async fn list_project_grants(
        &self,
        actor: &Actor,
        query: &HistoryQuery,
        signer: &CursorSigner,
    ) -> Result<HistoryPage<ProjectGrant>, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let window = authorize_window(&mut tx, actor, query, "grants:read", signer).await?;
        let rows=sqlx::query_as::<_,ProjectGrant>("SELECT * FROM grants WHERE tenant_id=$1 AND project_id=$2 AND created_at<=$3 AND ($4::timestamptz IS NULL OR (created_at,id)<($4,$5)) ORDER BY created_at DESC,id DESC LIMIT $6")
            .bind(actor.tenant_id).bind(query.project_id).bind(window.cutoff).bind(window.after_time).bind(window.after_id).bind(window.limit+1).fetch_all(&mut *tx).await?;
        let result = window.page(rows, query, actor, "grants:read", signer)?;
        tx.commit().await?;
        Ok(result)
    }
    pub async fn get_project_grant(
        &self,
        actor: &Actor,
        project: Uuid,
        id: Uuid,
    ) -> Result<ProjectGrant, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        Self::authorize_resource(&mut tx, actor, project, "grants:read").await?;
        let grant = load_grant(&mut tx, actor.tenant_id, project, id).await?;
        tx.commit().await?;
        Ok(grant)
    }
    pub async fn create_project_grant(
        &self,
        actor: &Actor,
        project: Uuid,
        request: &CreateGrant,
        key: &str,
    ) -> Result<GrantMutationResult, ApiError> {
        if request.action == "*" || !PROJECT_ACTIONS.contains(&request.action.as_str()) {
            return Err(ApiError::invalid("Unsupported project action"));
        }
        self.change_grant(actor, project, Change::Create(request), key)
            .await
    }
    pub async fn update_project_grant(
        &self,
        actor: &Actor,
        project: Uuid,
        id: Uuid,
        request: &UpdateGrant,
        key: &str,
        expected: i64,
    ) -> Result<GrantMutationResult, ApiError> {
        self.change_grant(actor, project, Change::Update(id, request, expected), key)
            .await
    }
    pub async fn revoke_project_grant(
        &self,
        actor: &Actor,
        project: Uuid,
        id: Uuid,
        key: &str,
        expected: i64,
    ) -> Result<GrantMutationResult, ApiError> {
        self.change_grant(actor, project, Change::Revoke(id, expected), key)
            .await
    }
    async fn change_grant(
        &self,
        actor: &Actor,
        project: Uuid,
        change: Change<'_>,
        key: &str,
    ) -> Result<GrantMutationResult, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        Self::authorize_resource(&mut tx, actor, project, "grants:write").await?;
        sqlx::query("SELECT sandbox_lock_identity_tenant($1)")
            .bind(actor.tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(grant_error)?;
        Self::authorize_resource(&mut tx, actor, project, "grants:write").await?;
        let (
            id,
            principal,
            action,
            expiry,
            enabled,
            expected,
            mutation,
            idem_action,
            target,
            body,
            status,
        ) = match change {
            Change::Create(request) => (
                Uuid::new_v4(),
                request.principal_id,
                request.action.clone(),
                request.expires_at,
                true,
                None,
                "CREATE",
                "grants:create",
                project,
                serde_json::to_value(request),
                201,
            ),
            Change::Update(id, request, version) => {
                let current = load_grant(&mut tx, actor.tenant_id, project, id).await?;
                (
                    id,
                    current.principal_id,
                    current.action,
                    request.expires_at,
                    request.enabled,
                    Some(version),
                    "UPDATE",
                    "grants:update",
                    id,
                    serde_json::to_value(request),
                    200,
                )
            }
            Change::Revoke(id, version) => {
                let current = load_grant(&mut tx, actor.tenant_id, project, id).await?;
                (
                    id,
                    current.principal_id,
                    current.action,
                    current.expires_at,
                    false,
                    Some(version),
                    "REVOKE",
                    "grants:revoke",
                    id,
                    Ok(json!({})),
                    200,
                )
            }
        };
        let body = body.map_err(|_| ApiError::invalid("Invalid grant request"))?;
        // Recheck both action and expiry authority before replaying any receipt.
        if enabled {
            // Management permission cannot delegate an absent OAuth action.
            Self::authorize_identity(&mut tx, actor, &action).await?;
        }
        sqlx::query("SELECT sandbox_check_grant_delegation($1,$2,$3,$4,$5)")
            .bind(actor.principal_id)
            .bind(project)
            .bind(&action)
            .bind(expiry)
            .bind(enabled)
            .execute(&mut *tx)
            .await
            .map_err(grant_error)?;
        let digest = request_digest(&body, expected)?;
        let key_hash = format!("{:x}", Sha256::digest(key.as_bytes()));
        if let Some(previous) =
            management_replay(&mut tx, actor, idem_action, target, &key_hash, &digest).await?
        {
            tx.commit().await?;
            return Ok(previous);
        }
        let resource = sqlx::query_as::<_, ProjectGrant>(
            "SELECT * FROM sandbox_mutate_project_grant($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(actor.principal_id)
        .bind(project)
        .bind(mutation)
        .bind(id)
        .bind(principal)
        .bind(&action)
        .bind(expiry)
        .bind(enabled)
        .bind(expected)
        .fetch_one(&mut *tx)
        .await
        .map_err(grant_error)?;
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let details = json!({"principal_id":resource.principal_id,"action":resource.action,"enabled":resource.enabled,"expires_at":resource.expires_at,"version":resource.version});
        sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,resource_id,action,outcome,details) VALUES($1,$2,$3,$4,$5,$6,'SUCCEEDED',$7)")
            .bind(actor.tenant_id).bind(project).bind(actor.principal_id).bind(actor.request_id).bind(id).bind(idem_action).bind(&details).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,request_id,payload) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(actor.tenant_id).bind(project).bind(id).bind(resource.version).bind(format!("{idem_action}.succeeded")).bind(actor.request_id).bind(details).execute(&mut *tx).await?;
        let receipt = GrantReceipt {
            resource,
            idempotency_expires_at: now + Duration::days(7),
        };
        let value = serde_json::to_value(&receipt)
            .map_err(|_| ApiError::invalid("Cannot encode grant receipt"))?;
        sqlx::query("INSERT INTO management_receipts(tenant_id,project_id,principal_id,action,target_id,key_hash,request_hash,resource_id,response_status,response_body,created_at,expires_at,tombstone_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
            .bind(actor.tenant_id).bind(project).bind(actor.principal_id).bind(idem_action).bind(target).bind(key_hash).bind(digest).bind(id).bind(status as i16).bind(value).bind(now).bind(receipt.idempotency_expires_at).bind(receipt.idempotency_expires_at+Duration::days(90)).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(GrantMutationResult {
            status,
            body: receipt,
        })
    }
}
async fn load_grant(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    project: Uuid,
    id: Uuid,
) -> Result<ProjectGrant, ApiError> {
    sqlx::query_as("SELECT * FROM grants WHERE tenant_id=$1 AND project_id=$2 AND id=$3")
        .bind(tenant)
        .bind(project)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(ApiError::not_found)
}
async fn management_replay(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    action: &str,
    target: Uuid,
    key_hash: &str,
    digest: &[u8],
) -> Result<Option<GrantMutationResult>, ApiError> {
    let previous=sqlx::query("SELECT request_hash,response_status,response_body,expires_at>clock_timestamp() AS fresh FROM management_receipts WHERE tenant_id=$1 AND principal_id=$2 AND action=$3 AND target_id=$4 AND key_hash=$5")
        .bind(actor.tenant_id).bind(actor.principal_id).bind(action).bind(target).bind(key_hash).fetch_optional(&mut **tx).await?;
    let Some(row) = previous else { return Ok(None) };
    if row.try_get::<Vec<u8>, _>("request_hash")?.as_slice() != digest {
        return Err(ApiError::conflict(
            "IDEMPOTENCY_CONFLICT",
            "This key was used with different grant parameters",
        ));
    }
    if !row.try_get::<bool, _>("fresh")? {
        return Err(ApiError::new(
            StatusCode::GONE,
            "IDEMPOTENCY_EXPIRED",
            "The retained management receipt has expired; reconcile the current grant",
        ));
    }
    let body = serde_json::from_value::<GrantReceipt>(row.try_get::<Value, _>("response_body")?)
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INVALID_RECEIPT",
                "Stored grant receipt cannot be decoded",
            )
        })?;
    Ok(Some(GrantMutationResult {
        status: row.try_get::<i16, _>("response_status")? as u16,
        body,
    }))
}
fn grant_error(error: sqlx::Error) -> ApiError {
    match error.as_database_error().and_then(|e| e.code()).as_deref() {
        Some("P4040") => ApiError::not_found(),
        Some("P4030") => ApiError::new(
            StatusCode::FORBIDDEN,
            "DELEGATION_DENIED",
            "Requested grant exceeds current action, scope or expiry authority",
        ),
        Some("P4000") => ApiError::invalid("Invalid grant scope, action or expiry"),
        Some("P4090" | "23505") => ApiError::conflict(
            "GRANT_ALREADY_EXISTS",
            "A grant for this principal and action already exists; update its current version",
        ),
        Some("P4120") => ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "VERSION_MISMATCH",
            "The grant changed; read its current ETag before a new mutation",
        ),
        _ => error.into(),
    }
}
