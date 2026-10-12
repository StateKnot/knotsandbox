//! Tenant administration history is separate from project history. A signed
//! continuation never replaces current tenant, identity or grant authority.

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{
    db::{Actor, Database},
    error::ApiError,
    history::{CursorSigner, HistoryPage, HistoryQuery, HistoryRow, Window},
};

pub const READ_ACTION: &str = "tenant_audit:read";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantAuditQuery {
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

/// The SQL reader only returns project_id IS NULL rows. Keep the explicit null
/// in the public contract so consumers cannot mistake these for project grants.
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct TenantAuditRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Option<Uuid>,
    pub actor_principal_id: Option<Uuid>,
    pub request_id: Uuid,
    pub operation_id: Option<Uuid>,
    pub resource_id: Option<Uuid>,
    pub action: String,
    pub outcome: String,
    pub occurred_at: DateTime<Utc>,
}

impl HistoryRow for TenantAuditRecord {
    fn time(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn id(&self) -> Uuid {
        self.id
    }
}

impl Database {
    pub async fn list_tenant_audit_records(
        &self,
        actor: &Actor,
        query: &TenantAuditQuery,
        signer: &CursorSigner,
    ) -> Result<HistoryPage<TenantAuditRecord>, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        authorize(&mut tx, actor).await?;
        // Nil is an internal cursor scope marker, never a caller-supplied
        // project. The action also isolates it from account/project cursors.
        let scope = HistoryQuery {
            project_id: Uuid::nil(),
            instance_id: None,
            limit: query.limit,
            cursor: query.cursor.clone(),
        };
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let window = Window::new(&scope, actor, READ_ACTION, signer, now)?;
        let rows = sqlx::query_as::<_, TenantAuditRecord>(
            "SELECT a.id,a.tenant_id,a.project_id,a.actor_principal_id,a.request_id,\
             a.operation_id,a.resource_id,a.action,a.outcome,a.occurred_at \
             FROM audit_events a WHERE a.tenant_id=$1 AND a.project_id IS NULL \
             AND a.occurred_at<=$2 \
             AND ($3::timestamptz IS NULL OR (a.occurred_at,a.id)<($3,$4)) \
             ORDER BY a.occurred_at DESC,a.id DESC LIMIT $5",
        )
        .bind(actor.tenant_id)
        .bind(window.cutoff)
        .bind(window.after_time)
        .bind(window.after_id)
        .bind(window.limit + 1)
        .fetch_all(&mut *tx)
        .await?;
        // Reading may wait for a table lock. A fresh statement snapshot and
        // database clock prevent expired tokens/grants or revocations during
        // that wait from surviving a previously successful authorization.
        authorize(&mut tx, actor).await?;
        let page = window.page(rows, &scope, actor, READ_ACTION, signer)?;
        tx.commit().await?;
        Ok(page)
    }
}

async fn authorize(tx: &mut Transaction<'_, Postgres>, actor: &Actor) -> Result<(), ApiError> {
    let identity = actor.authorization.as_ref();
    if identity.is_some_and(|identity| !identity.permits(READ_ACTION)) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "INSUFFICIENT_SCOPE",
            "OAuth action scope is missing",
        ));
    }
    // Tenant membership is explicit even for the trusted in-process form of
    // Actor. A controller's SYSTEM exception in sandbox_principal_enabled
    // cannot supply tenant membership. The materialized checks finish before
    // the clock is read, including after a concurrent lock wait. No global
    // identity table access is added.
    let (identity_live, allowed, token_live): (bool, bool, bool) = sqlx::query_as(
        r#"WITH identity AS MATERIALIZED (
            SELECT CASE WHEN $3::text IS NULL THEN true ELSE EXISTS(
                SELECT 1 FROM sandbox_resolve_identity($3,$4,$5) i
                WHERE i.principal_id=$2 AND i.enabled) END AS live
        ), permitted AS MATERIALIZED (
            SELECT sandbox_principal_enabled($2) AND EXISTS(
                SELECT 1 FROM tenant_principals tp WHERE tp.tenant_id=$1
                AND tp.principal_id=$2 AND tp.enabled) AS principal_live,
                coalesce(bool_or(g.expires_at IS NULL) FILTER(WHERE t.enabled),false) AS indefinite,
                max(g.expires_at) FILTER(WHERE t.enabled) AS grant_until
            FROM grants g JOIN tenants t ON t.id=g.tenant_id
            WHERE g.tenant_id=$1 AND g.principal_id=$2 AND g.project_id IS NULL
                AND g.action IN('tenant_audit:read','*') AND g.enabled AND g.revoked_at IS NULL
        ), evaluated AS MATERIALIZED (
            SELECT identity.live,permitted.*,clock_timestamp() AS as_of
            FROM identity CROSS JOIN permitted
        ) SELECT live,principal_live AND (indefinite OR coalesce(grant_until>as_of,false)),
            ($6::bigint IS NULL OR as_of<to_timestamp($6::double precision)) FROM evaluated"#,
    )
    .bind(actor.tenant_id)
    .bind(actor.principal_id)
    .bind(identity.map(|identity| identity.issuer.as_str()))
    .bind(identity.map(|identity| identity.subject.as_str()))
    .bind(identity.and_then(|identity| identity.client_id.as_deref()))
    .bind(identity.map(|identity| identity.expires_at))
    .fetch_one(&mut **tx)
    .await?;
    if !identity_live
        || !token_live
        || identity.is_some_and(|identity| identity.expires_at <= Utc::now().timestamp())
    {
        return Err(crate::request::unauthenticated());
    }
    if !allowed {
        return Err(ApiError::not_found());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_audit_queries_reject_project_and_instance_filters() {
        assert!(serde_json::from_str::<TenantAuditQuery>(r#"{"limit":2,"cursor":null}"#).is_ok());
        for field in ["project_id", "instance_id", "action", "tenant_id"] {
            let value = serde_json::json!({field:Uuid::new_v4()});
            assert!(serde_json::from_value::<TenantAuditQuery>(value).is_err());
        }
    }
}
