//! Project exception inbox. Source metadata is immutable and transactionally
//! derived from real run events; ACK is a separate one-way management fact.
//! HTTP audit request IDs identify transport requests. The ACK domain event's
//! request ID is the causal original run so old/current event coordinators both
//! exclude notification feedback. ACK never means resolution or guest closure.
use super::ledger;
use crate::{
    auth::VerifiedIdentity,
    db::{Actor, Database},
    error::ApiError,
    history::{CursorSigner, HistoryPage, HistoryQuery, Window},
    request::request_digest,
};
use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

const COLUMNS: &str = "id,tenant_id,project_id,instance_id,automation_id,run_id,source_event_id,source_run_version,source_status,created_at,acknowledged_at,acknowledged_by,version";
const ACK_ACTION: &str = "automations:notifications:acknowledge";

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct AutomationNotification {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub instance_id: Uuid,
    pub automation_id: Uuid,
    pub run_id: Uuid,
    pub source_event_id: Uuid,
    pub source_run_version: i64,
    pub source_status: String,
    pub created_at: DateTime<Utc>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub acknowledged_by: Option<Uuid>,
    pub version: i64,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct AutomationNotificationReceipt {
    pub resource: AutomationNotification,
    pub idempotency_expires_at: DateTime<Utc>,
}
pub struct AutomationNotificationMutationResult {
    pub status: u16,
    pub body: AutomationNotificationReceipt,
}
impl crate::history::HistoryRow for AutomationNotification {
    fn time(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn id(&self) -> Uuid {
        self.id
    }
}

impl Database {
    pub async fn check_automation_notification_schema(&self) -> anyhow::Result<()> {
        let complete: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=42 AND success) AND EXISTS(SELECT 1 FROM pg_class WHERE oid=to_regclass('public.automation_notifications') AND relrowsecurity AND relforcerowsecurity) AND NOT EXISTS(SELECT 1 FROM (VALUES('automation_notifications','immutable_automation_notification'),('automation_notifications','automation_notification_no_delete'),('domain_events','domain_event_stream_automation_notification_capture')) expected(table_name,trigger_name) WHERE NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('public.'||expected.table_name) AND tgname=expected.trigger_name AND NOT tgisinternal AND tgenabled IN('O','A')))"
        ).fetch_one(&self.pool).await?;
        anyhow::ensure!(complete, "automation notification schema is incomplete");
        let readable: bool = sqlx::query_scalar(
            "SELECT has_table_privilege(current_user,'automation_notifications','SELECT')",
        )
        .fetch_one(&self.pool)
        .await?;
        anyhow::ensure!(readable, "automation notification read grant is missing");
        let lockable: bool = sqlx::query_scalar(
            "SELECT has_function_privilege(current_user,'sandbox_lock_automation_notification_head(uuid,uuid)','EXECUTE')",
        ).fetch_one(&self.pool).await?;
        anyhow::ensure!(
            lockable,
            "automation notification head lock grant is missing"
        );
        for column in ["acknowledged_at", "acknowledged_by", "version"] {
            let writable: bool = sqlx::query_scalar(
                "SELECT has_column_privilege(current_user,'automation_notifications',$1,'UPDATE')",
            )
            .bind(column)
            .fetch_one(&self.pool)
            .await?;
            anyhow::ensure!(
                writable,
                "automation notification acknowledgement grants are incomplete"
            );
        }
        let exposed: bool = sqlx::query_scalar("SELECT has_table_privilege(current_user,'automation_notifications','INSERT,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_function_privilege(current_user,'sandbox_capture_automation_notification()','EXECUTE') OR EXISTS(SELECT 1 FROM unnest(ARRAY['id','tenant_id','project_id','instance_id','automation_id','run_id','source_event_id','source_run_version','source_status','created_at']) c WHERE has_column_privilege(current_user,'automation_notifications',c,'UPDATE'))").fetch_one(&self.pool).await?;
        anyhow::ensure!(
            !exposed,
            "automation notification sources must not be forgeable"
        );
        Ok(())
    }

    pub async fn get_automation_notification(
        &self,
        actor: &Actor,
        id: Uuid,
    ) -> Result<AutomationNotification, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let notification = load(&mut tx, actor.tenant_id, id, false).await?;
        Self::authorize_resource(&mut tx, actor, notification.project_id, "automations:read")
            .await?;
        tx.commit().await?;
        Ok(notification)
    }

    pub async fn list_automation_notifications(
        &self,
        actor: &Actor,
        query: &HistoryQuery,
        signer: &CursorSigner,
    ) -> Result<HistoryPage<AutomationNotification>, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        Self::authorize_resource(&mut tx, actor, query.project_id, "automations:read").await?;
        let window = Window::new(
            query,
            actor,
            "automation-notifications",
            signer,
            ledger::now(&mut tx).await?,
        )?;
        let sql = format!(
            "SELECT {COLUMNS} FROM automation_notifications WHERE tenant_id=$1 AND project_id=$2 AND($3::uuid IS NULL OR instance_id=$3) AND created_at<=$4 AND($5::timestamptz IS NULL OR(created_at,id)<($5,$6)) ORDER BY created_at DESC,id DESC LIMIT $7"
        );
        let rows = sqlx::query_as(&sql)
            .bind(actor.tenant_id)
            .bind(query.project_id)
            .bind(query.instance_id)
            .bind(window.cutoff)
            .bind(window.after_time)
            .bind(window.after_id)
            .bind(window.limit + 1)
            .fetch_all(&mut *tx)
            .await?;
        let page = window.page(rows, query, actor, "automation-notifications", signer)?;
        Self::authorize_resource(&mut tx, actor, query.project_id, "automations:read").await?;
        tx.commit().await?;
        Ok(page)
    }

    pub async fn acknowledge_automation_notification(
        &self,
        actor: &Actor,
        identity: &VerifiedIdentity,
        id: Uuid,
        key: &str,
        expected: i64,
    ) -> Result<AutomationNotificationMutationResult, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let initial = load(&mut tx, actor.tenant_id, id, false).await?;
        authorize_ack(&mut tx, actor, identity, initial.project_id).await?;
        let digest = request_digest(&json!({}), Some(expected))?;
        let key_hash = hex::encode(Sha256::digest(key.as_bytes()));
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!(
                "{}:{}:{ACK_ACTION}:{id}:{key_hash}",
                actor.tenant_id, actor.principal_id
            ))
            .execute(&mut *tx)
            .await?;
        if let Some(row)=sqlx::query("SELECT request_hash,response_body,response_status,expires_at>clock_timestamp() AS fresh FROM management_receipts WHERE tenant_id=$1 AND principal_id=$2 AND action=$3 AND target_id=$4 AND key_hash=$5").bind(actor.tenant_id).bind(actor.principal_id).bind(ACK_ACTION).bind(id).bind(&key_hash).fetch_optional(&mut *tx).await? {
            if row.try_get::<Vec<u8>,_>("request_hash")?!=digest {
                return Err(ApiError::conflict("IDEMPOTENCY_CONFLICT","The notification key already has another request"));
            }
            if !row.try_get::<bool,_>("fresh")? {
                return Err(ApiError::new(StatusCode::GONE,"IDEMPOTENCY_EXPIRED","Read the current notification before a new request"));
            }
            let result=AutomationNotificationMutationResult { status:row.try_get::<i16,_>("response_status")? as u16, body:serde_json::from_value(row.try_get("response_body")?).map_err(|_|ApiError::invalid("Stored notification receipt is invalid"))? };
            authorize_ack(&mut tx,actor,identity,initial.project_id).await?;
            tx.commit().await?;
            return Ok(result);
        }
        // Event producers hold this head before the source trigger touches a
        // notification. Use the same order, including duplicate-source events.
        sqlx::query("SELECT sandbox_lock_automation_notification_head($1,$2)")
            .bind(actor.tenant_id)
            .bind(initial.project_id)
            .execute(&mut *tx)
            .await?;
        authorize_ack(&mut tx, actor, identity, initial.project_id).await?;
        let mut notification = load(&mut tx, actor.tenant_id, id, true).await?;
        authorize_ack(&mut tx, actor, identity, notification.project_id).await?;
        if notification.version != expected {
            return Err(ApiError::new(
                StatusCode::PRECONDITION_FAILED,
                "VERSION_MISMATCH",
                "Read the current notification ETag before acknowledgement",
            ));
        }
        if notification.acknowledged_at.is_none() {
            let sql = format!(
                "UPDATE automation_notifications SET acknowledged_at=clock_timestamp(),acknowledged_by=$3,version=2 WHERE tenant_id=$1 AND id=$2 RETURNING {COLUMNS}"
            );
            notification = sqlx::query_as(&sql)
                .bind(actor.tenant_id)
                .bind(id)
                .bind(actor.principal_id)
                .fetch_one(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,resource_id,action,outcome) VALUES($1,$2,$3,$4,$5,$6,'SUCCEEDED')").bind(actor.tenant_id).bind(notification.project_id).bind(actor.principal_id).bind(actor.request_id).bind(id).bind(ACK_ACTION).execute(&mut *tx).await?;
            // Preserve the causal run ID so existing event workers exclude this
            // notification feedback; the separate audit retains the HTTP ID.
            sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,request_id,payload) VALUES($1,$2,$3,$4,'automation-notifications:acknowledged',$5,$6)").bind(actor.tenant_id).bind(notification.project_id).bind(id).bind(notification.version).bind(notification.run_id).bind(json!({"notification_id":id,"run_id":notification.run_id,"acknowledged":true})).execute(&mut *tx).await?;
        }
        // Event-head waits may cross token/grant expiry or a live revocation.
        // Recheck complete actor/token authority and the DB clock afterwards.
        authorize_ack(&mut tx, actor, identity, notification.project_id).await?;
        let now = ledger::now(&mut tx).await?;
        let project = notification.project_id;
        let body = AutomationNotificationReceipt {
            resource: notification,
            idempotency_expires_at: now + Duration::days(7),
        };
        sqlx::query("INSERT INTO management_receipts(tenant_id,project_id,principal_id,action,target_id,key_hash,request_hash,resource_id,response_status,response_body,created_at,expires_at,tombstone_until) VALUES($1,$2,$3,$4,$5,$6,$7,$5,200,$8,$9,$10,$11)").bind(actor.tenant_id).bind(project).bind(actor.principal_id).bind(ACK_ACTION).bind(id).bind(&key_hash).bind(&digest).bind(json!(body)).bind(now).bind(body.idempotency_expires_at).bind(body.idempotency_expires_at+Duration::days(90)).execute(&mut *tx).await?;
        authorize_ack(&mut tx, actor, identity, project).await?;
        tx.commit().await?;
        Ok(AutomationNotificationMutationResult { status: 200, body })
    }
}

async fn load(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    id: Uuid,
    locked: bool,
) -> Result<AutomationNotification, ApiError> {
    let sql = format!(
        "SELECT {COLUMNS} FROM automation_notifications WHERE tenant_id=$1 AND id=$2{}",
        if locked { " FOR UPDATE" } else { "" }
    );
    sqlx::query_as(&sql)
        .bind(tenant)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(ApiError::not_found)
}
async fn authorize_ack(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    identity: &VerifiedIdentity,
    project: Uuid,
) -> Result<(), ApiError> {
    Database::authorize_resource(tx, actor, project, "automations:write").await?;
    if !identity.permits("automations:write") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "INSUFFICIENT_SCOPE",
            "OAuth action scope is missing",
        ));
    }
    ledger::identity_live(tx, actor, identity).await
}
