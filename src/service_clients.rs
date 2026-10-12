//! Tenant-scoped registrations of existing OIDC service subjects. The IdP owns
//! account creation, credentials and rotation; this module never handles secrets.
use crate::{
    db::{Actor, Database},
    error::ApiError,
    history::{CursorSigner, HistoryPage, HistoryQuery, HistoryRow, Window},
    request::request_digest,
};
use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub const TENANT_IDENTITY_ACTIONS: &[&str] = &[
    "service_clients:read",
    "service_clients:write",
    crate::tenant_audit::READ_ACTION,
];
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ServiceClient {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub principal_id: Uuid,
    pub issuer: String,
    pub subject: String,
    pub client_id: Option<String>,
    pub display_name: String,
    /// Tenant registration state. It never changes the IdP/global identity.
    pub enabled: bool,
    pub identity_enabled: bool,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
impl HistoryRow for ServiceClient {
    fn time(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn id(&self) -> Uuid {
        self.id
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterServiceClient {
    pub issuer: String,
    pub subject: String,
    pub client_id: String,
    pub display_name: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateServiceClient {
    pub enabled: bool,
    pub display_name: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceClientReceipt {
    pub resource: ServiceClient,
    pub idempotency_expires_at: DateTime<Utc>,
}
pub struct ServiceClientMutationResult {
    pub status: u16,
    pub body: ServiceClientReceipt,
}
enum Change<'a> {
    Register(&'a RegisterServiceClient),
    Update(Uuid, &'a UpdateServiceClient, i64),
}
impl Database {
    pub async fn list_service_clients(
        &self,
        actor: &Actor,
        limit: Option<i64>,
        cursor: Option<String>,
        signer: &CursorSigner,
    ) -> Result<HistoryPage<ServiceClient>, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        authorize(&mut tx, actor, "service_clients:read").await?;
        // Nil is an internal tenant-scope marker, never a user-selected project.
        let query = HistoryQuery {
            project_id: Uuid::nil(),
            instance_id: None,
            limit,
            cursor,
        };
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let window = Window::new(&query, actor, "service_clients:read", signer, now)?;
        let rows = sqlx::query_as::<_, ServiceClient>(
            "SELECT * FROM sandbox_read_service_clients($1,NULL,$2,$3,$4,$5)",
        )
        .bind(actor.principal_id)
        .bind(window.cutoff)
        .bind(window.after_time)
        .bind(window.after_id)
        .bind((window.limit + 1) as i32)
        .fetch_all(&mut *tx)
        .await
        .map_err(client_error)?;
        let result = window.page(rows, &query, actor, "service_clients:read", signer)?;
        tx.commit().await?;
        Ok(result)
    }
    pub async fn get_service_client(
        &self,
        actor: &Actor,
        id: Uuid,
    ) -> Result<ServiceClient, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        authorize(&mut tx, actor, "service_clients:read").await?;
        let result = sqlx::query_as::<_, ServiceClient>(
            "SELECT * FROM sandbox_read_service_clients($1,$2,clock_timestamp(),NULL,NULL,1)",
        )
        .bind(actor.principal_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(client_error)?
        .ok_or_else(ApiError::not_found)?;
        tx.commit().await?;
        Ok(result)
    }
    pub async fn register_service_client(
        &self,
        actor: &Actor,
        request: &RegisterServiceClient,
        trusted_issuer: &str,
        key: &str,
    ) -> Result<ServiceClientMutationResult, ApiError> {
        if request.issuer != trusted_issuer
            || !valid_text(&request.subject, 512)
            || !crate::auth::valid_client_id(&request.client_id)
            || !valid_text(&request.display_name, 128)
        {
            return Err(ApiError::invalid(
                "Service identity must use the configured issuer and valid subject/name",
            ));
        }
        self.change_service_client(actor, Change::Register(request), key)
            .await
    }
    pub async fn update_service_client(
        &self,
        actor: &Actor,
        id: Uuid,
        request: &UpdateServiceClient,
        key: &str,
        expected: i64,
    ) -> Result<ServiceClientMutationResult, ApiError> {
        if !valid_text(&request.display_name, 128) {
            return Err(ApiError::invalid(
                "Service name must contain 1..128 non-control characters",
            ));
        }
        self.change_service_client(actor, Change::Update(id, request, expected), key)
            .await
    }
    async fn change_service_client(
        &self,
        actor: &Actor,
        change: Change<'_>,
        key: &str,
    ) -> Result<ServiceClientMutationResult, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        authorize(&mut tx, actor, "service_clients:write").await?;
        sqlx::query("SELECT sandbox_lock_identity_tenant($1)")
            .bind(actor.tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(client_error)?;
        authorize(&mut tx, actor, "service_clients:write").await?;
        let (
            id,
            issuer,
            subject,
            client,
            name,
            enabled,
            expected,
            mutation,
            action,
            target,
            body,
            status,
        ) = match change {
            Change::Register(r) => (
                Uuid::new_v4(),
                Some(r.issuer.as_str()),
                Some(r.subject.as_str()),
                Some(r.client_id.as_str()),
                r.display_name.as_str(),
                true,
                None,
                "CREATE",
                "service_clients:create",
                actor.tenant_id,
                serde_json::to_value(r),
                201,
            ),
            Change::Update(id, r, version) => (
                id,
                None,
                None,
                None,
                r.display_name.as_str(),
                r.enabled,
                Some(version),
                "UPDATE",
                "service_clients:update",
                id,
                serde_json::to_value(r),
                200,
            ),
        };
        let body = body.map_err(|_| ApiError::invalid("Invalid service client request"))?;
        let digest = request_digest(&body, expected)?;
        let key_hash = format!("{:x}", Sha256::digest(key.as_bytes()));
        if let Some(replay) = replay(&mut tx, actor, action, target, &key_hash, &digest).await? {
            tx.commit().await?;
            return Ok(replay);
        }
        // Restoring a registration reactivates existing grants. Its token must
        // cover each restored action as well as the SQL live grant/expiry gate.
        if mutation == "UPDATE" && enabled {
            let restored: Vec<String> = sqlx::query_scalar("SELECT g.action FROM grants g JOIN tenant_principals p ON p.tenant_id=g.tenant_id AND p.principal_id=g.principal_id WHERE p.tenant_id=$1 AND p.id=$2 AND NOT p.enabled AND g.enabled AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>clock_timestamp())")
                .bind(actor.tenant_id).bind(id).fetch_all(&mut *tx).await?;
            if !restored.is_empty() {
                Database::authorize_identity(&mut tx, actor, "grants:write").await?;
            }
            for restored_action in restored {
                Database::authorize_identity(&mut tx, actor, &restored_action).await?;
            }
        }
        let resource = sqlx::query_as::<_, ServiceClient>(
            "SELECT * FROM sandbox_mutate_service_client($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(actor.principal_id)
        .bind(mutation)
        .bind(id)
        .bind(issuer)
        .bind(subject)
        .bind(client)
        .bind(name)
        .bind(enabled)
        .bind(expected)
        .fetch_one(&mut *tx)
        .await
        .map_err(client_error)?;
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        // No token, client secret, subject or untrusted display name enters audit.
        let details = json!({"principal_id":resource.principal_id,"enabled":resource.enabled,"version":resource.version});
        sqlx::query("INSERT INTO audit_events(tenant_id,actor_principal_id,request_id,resource_id,action,outcome,details) VALUES($1,$2,$3,$4,$5,'SUCCEEDED',$6)")
            .bind(actor.tenant_id).bind(actor.principal_id).bind(actor.request_id).bind(resource.id).bind(action).bind(details).execute(&mut *tx).await?;
        let receipt = ServiceClientReceipt {
            resource,
            idempotency_expires_at: now + Duration::days(7),
        };
        let value = serde_json::to_value(&receipt)
            .map_err(|_| ApiError::invalid("Cannot encode service client receipt"))?;
        sqlx::query("INSERT INTO management_receipts(tenant_id,principal_id,action,target_id,key_hash,request_hash,resource_id,response_status,response_body,created_at,expires_at,tombstone_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
            .bind(actor.tenant_id).bind(actor.principal_id).bind(action).bind(target).bind(key_hash).bind(digest).bind(receipt.resource.id).bind(status as i16).bind(value).bind(now).bind(receipt.idempotency_expires_at).bind(receipt.idempotency_expires_at+Duration::days(90)).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(ServiceClientMutationResult {
            status,
            body: receipt,
        })
    }
}
async fn authorize(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    action: &str,
) -> Result<(), ApiError> {
    Database::authorize_identity(tx, actor, action).await?;
    sqlx::query("SELECT sandbox_authorize_service_clients($1,$2)")
        .bind(actor.principal_id)
        .bind(action)
        .execute(&mut **tx)
        .await
        .map_err(client_error)?;
    Ok(())
}
async fn replay(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    action: &str,
    target: Uuid,
    key_hash: &str,
    digest: &[u8],
) -> Result<Option<ServiceClientMutationResult>, ApiError> {
    let previous=sqlx::query("SELECT request_hash,response_status,response_body,expires_at>clock_timestamp() AS fresh FROM management_receipts WHERE tenant_id=$1 AND principal_id=$2 AND action=$3 AND target_id=$4 AND key_hash=$5")
        .bind(actor.tenant_id).bind(actor.principal_id).bind(action).bind(target).bind(key_hash).fetch_optional(&mut **tx).await?;
    let Some(row) = previous else { return Ok(None) };
    if row.try_get::<Vec<u8>, _>("request_hash")?.as_slice() != digest {
        return Err(ApiError::conflict(
            "IDEMPOTENCY_CONFLICT",
            "This key was used with different service client parameters",
        ));
    }
    if !row.try_get::<bool, _>("fresh")? {
        return Err(ApiError::new(
            StatusCode::GONE,
            "IDEMPOTENCY_EXPIRED",
            "The retained management receipt has expired; reconcile the current service client",
        ));
    }
    let body =
        serde_json::from_value::<ServiceClientReceipt>(row.try_get::<Value, _>("response_body")?)
            .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INVALID_RECEIPT",
                "Stored service client receipt cannot be decoded",
            )
        })?;
    Ok(Some(ServiceClientMutationResult {
        status: row.try_get::<i16, _>("response_status")? as u16,
        body,
    }))
}
fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.chars().count() <= max && !value.chars().any(char::is_control)
}
fn client_error(error: sqlx::Error) -> ApiError {
    match error.as_database_error().and_then(|e| e.code()).as_deref() {
        Some("P4040") => ApiError::not_found(),
        Some("P4030") => ApiError::new(
            StatusCode::FORBIDDEN,
            "DELEGATION_DENIED",
            "Restoring this client exceeds current scope, action or expiry authority",
        ),
        Some("P4000") => ApiError::invalid("Invalid service client parameters"),
        Some("P4090" | "23505") => ApiError::conflict(
            "SERVICE_CLIENT_ALREADY_EXISTS",
            "A registration already exists; update its current version",
        ),
        Some("P4120") => ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "VERSION_MISMATCH",
            "The client changed; read its current ETag before a new mutation",
        ),
        _ => error.into(),
    }
}
