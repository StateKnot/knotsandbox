//! Durable installation authority. A successful check is not a bearer capability
//! or a cacheable promise; consumers must check again after external I/O.
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::{admin::AdminError, auth::VerifiedIdentity, db::Database, error::ApiError};

pub const MAX_OPERATOR_GRANT_BYTES: usize = 16 * 1024;
pub const NODE_IMAGE_READ_ACTION: &str = "node_images:read";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantNodeImageReader {
    #[serde(skip)]
    allow_loopback_http: bool,
    pub grant_id: Uuid,
    pub installation_id: Uuid,
    pub cluster_epoch: Uuid,
    pub issuer: String,
    pub subject: String,
    pub client_id: String,
    pub expires_at: DateTime<Utc>,
    pub reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeNodeImageReader {
    pub grant_id: Uuid,
    pub installation_id: Uuid,
    pub cluster_epoch: Uuid,
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorAccess {
    pub installation_id: Uuid,
    pub cluster_epoch: Uuid,
    pub grant_id: Uuid,
    pub action: String,
    pub expires_at: DateTime<Utc>,
}

fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, AdminError> {
    if bytes.len() > MAX_OPERATOR_GRANT_BYTES {
        return Err(AdminError::Invalid("operator request exceeds 16384 bytes"));
    }
    serde_json::from_slice(bytes).map_err(|_| AdminError::Invalid("invalid operator request JSON"))
}

fn validate_scope(ids: [Uuid; 3], reason: &str) -> Result<(), AdminError> {
    if ids.iter().any(Uuid::is_nil)
        || reason.trim().is_empty()
        || reason.len() > 256
        || reason.chars().any(char::is_control)
    {
        return Err(AdminError::Invalid("invalid operator scope or reason"));
    }
    Ok(())
}

impl GrantNodeImageReader {
    pub fn parse(bytes: &[u8], allow_loopback_http: bool) -> Result<Self, AdminError> {
        let mut request: Self = parse(bytes)?;
        request.allow_loopback_http = allow_loopback_http;
        request.validate(allow_loopback_http)?;
        Ok(request)
    }

    fn validate(&self, allow_loopback_http: bool) -> Result<(), AdminError> {
        validate_scope(
            [self.grant_id, self.installation_id, self.cluster_epoch],
            &self.reason,
        )?;
        crate::admin::validate_issuer(&self.issuer, allow_loopback_http)?;
        if self.subject.trim().is_empty()
            || self.subject.len() > 512
            || self.subject.chars().any(char::is_control)
            || self.issuer.chars().any(char::is_control)
            || !crate::auth::valid_client_id(&self.client_id)
        {
            return Err(AdminError::Invalid("invalid operator identity"));
        }
        // The authoritative time/24-hour check is inside the locked SQL action.
        Ok(())
    }
}
impl RevokeNodeImageReader {
    pub fn parse(bytes: &[u8]) -> Result<Self, AdminError> {
        let request: Self = parse(bytes)?;
        request.validate()?;
        Ok(request)
    }
    fn validate(&self) -> Result<(), AdminError> {
        validate_scope(
            [self.grant_id, self.installation_id, self.cluster_epoch],
            &self.reason,
        )
    }
}

async fn require_owner(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>) -> Result<(), AdminError> {
    let owner: bool = sqlx::query_scalar("SELECT bool_and(pg_has_role(current_user,c.relowner,'USAGE')) FROM pg_class c WHERE c.oid=ANY(ARRAY['public.node_image_reader_grants'::regclass,'public.node_image_reader_audit'::regclass,'public.principal_identities'::regclass,'public.principals'::regclass,'public.platform_configuration'::regclass])")
        .fetch_one(&mut **tx).await?;
    if !owner {
        return Err(AdminError::OwnerRequired);
    }
    Ok(())
}

pub async fn grant_node_image_reader(
    database: &Database,
    request: &GrantNodeImageReader,
) -> Result<OperatorAccess, AdminError> {
    // Library callers cannot skip identifier validation by constructing the type.
    // HTTP issuer use remains confined to the existing explicit local dev profile.
    request.validate(request.allow_loopback_http)?;
    let mut tx = database.pool.begin().await?;
    require_owner(&mut tx).await?;
    let grant_id: Uuid =
        sqlx::query_scalar("SELECT sandbox_grant_node_image_reader($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(request.grant_id)
            .bind(request.installation_id)
            .bind(request.cluster_epoch)
            .bind(&request.issuer)
            .bind(&request.subject)
            .bind(&request.client_id)
            .bind(request.expires_at)
            .bind(&request.reason)
            .fetch_one(&mut *tx)
            .await?;
    let expires_at =
        sqlx::query_scalar("SELECT expires_at FROM node_image_reader_grants WHERE id=$1")
            .bind(grant_id)
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(OperatorAccess {
        installation_id: request.installation_id,
        cluster_epoch: request.cluster_epoch,
        grant_id,
        action: NODE_IMAGE_READ_ACTION.into(),
        expires_at,
    })
}

pub async fn revoke_node_image_reader(
    database: &Database,
    request: &RevokeNodeImageReader,
) -> Result<(), AdminError> {
    request.validate()?;
    let mut tx = database.pool.begin().await?;
    require_owner(&mut tx).await?;
    sqlx::query("SELECT sandbox_revoke_node_image_reader($1,$2,$3,$4)")
        .bind(request.grant_id)
        .bind(request.installation_id)
        .bind(request.cluster_epoch)
        .bind(&request.reason)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

impl Database {
    /// Uses a fresh statement snapshot, exact SERVICE identity, current singleton
    /// scope and the original grant ID. No tenant Actor or caller scope exists.
    pub async fn node_image_access(
        &self,
        identity: &VerifiedIdentity,
    ) -> Result<OperatorAccess, ApiError> {
        if identity.expires_at <= Utc::now().timestamp() {
            return Err(crate::request::unauthenticated());
        }
        if !identity.permits(NODE_IMAGE_READ_ACTION) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "INSUFFICIENT_SCOPE",
                "OAuth action scope is missing",
            ));
        }
        let row = sqlx::query("SELECT installation_id,cluster_epoch,grant_id,expires_at FROM sandbox_node_image_access($1,$2,$3,$4)")
            .bind(&identity.issuer).bind(&identity.subject).bind(&identity.client_id).bind(identity.expires_at)
            .fetch_optional(&self.pool).await?.ok_or_else(ApiError::forbidden)?;
        if identity.expires_at <= Utc::now().timestamp() {
            return Err(crate::request::unauthenticated());
        }
        Ok(OperatorAccess {
            installation_id: row.try_get("installation_id")?,
            cluster_epoch: row.try_get("cluster_epoch")?,
            grant_id: row.try_get("grant_id")?,
            action: NODE_IMAGE_READ_ACTION.into(),
            expires_at: row.try_get("expires_at")?,
        })
    }
}
