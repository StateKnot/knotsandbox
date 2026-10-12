use super::*;
use crate::{
    auth::VerifiedIdentity,
    db::{Actor, Database},
    error::ApiError,
    history::{CursorSigner, HistoryPage, HistoryQuery, Window},
    request::request_digest,
};
use axum::http::StatusCode;
use chrono::Duration;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};

pub(super) const AUTOMATION_COLUMNS: &str = "a.id,a.tenant_id,a.project_id,a.instance_id,a.workspace_id,a.creator_principal_id,a.name,a.action_kind,a.trigger_kind,a.scheduled_at,a.cron_expression,a.event_type,a.event_aggregate_id,a.next_due_at,a.status,a.version,a.run_budget,a.emitted_runs,a.minimum_interval_seconds,a.grace_seconds,d.expires_at AS delegation_expires_at,d.revoked_at AS delegation_revoked_at,a.created_at,a.updated_at";
pub(super) const RUN_COLUMNS: &str = "id,tenant_id,project_id,automation_id,automation_version,version,scheduled_for,source_event_id,source_event_sequence,skipped_through,operation_kind,expected_resource_version,expected_generation,status,operation_id,failure_code,deadline,created_at,updated_at,completed_at";

impl Database {
    /// Production startup check. A draft table or manually raised MAX(version)
    /// never establishes migration readiness or the required current grants.
    pub async fn check_automation_api_schema(&self) -> anyhow::Result<()> {
        self.verify_runtime_role().await?;
        self.check_identity_api_schema().await?;
        require_formal_schema(self).await?;
        let correct_role: bool =
            sqlx::query_scalar("SELECT current_user='sandbox_app' AND session_user='sandbox_app'")
                .fetch_one(&self.pool)
                .await?;
        anyhow::ensure!(
            correct_role,
            "automation API requires its dedicated app login"
        );
        let private_exposed: bool = sqlx::query_scalar(
            "SELECT has_table_privilege(current_user,'automation_claims','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_table_privilege(current_user,'automation_runs','INSERT,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_column_privilege(current_user,'automation_runs','lease_token','SELECT') OR has_column_privilege(current_user,'automation_runs','lease_token','UPDATE') OR has_column_privilege(current_user,'automation_runs','dispatch_attempt_id','UPDATE') OR has_function_privilege(current_user,'sandbox_claim_automation(text)','EXECUTE') OR has_function_privilege(current_user,'sandbox_bind_automation_run_claim(uuid,uuid,text,bigint)','EXECUTE')",
        )
        .fetch_one(&self.pool)
        .await?;
        anyhow::ensure!(
            !private_exposed,
            "automation API cannot enumerate or forge private claims"
        );
        for table in ["automations", "automation_delegations"] {
            for permission in ["SELECT", "INSERT", "UPDATE"] {
                let granted: bool =
                    sqlx::query_scalar("SELECT has_table_privilege(current_user,$1,$2)")
                        .bind(table)
                        .bind(permission)
                        .fetch_one(&self.pool)
                        .await?;
                anyhow::ensure!(granted, "automation API table grants are incomplete");
            }
        }
        for column in RUN_COLUMNS.split(',') {
            let granted: bool = sqlx::query_scalar(
                "SELECT has_column_privilege(current_user,'automation_runs',$1,'SELECT')",
            )
            .bind(column)
            .fetch_one(&self.pool)
            .await?;
            anyhow::ensure!(granted, "automation API run history grants are incomplete");
        }
        for column in ["status", "failure_code", "completed_at", "updated_at"] {
            let granted: bool = sqlx::query_scalar(
                "SELECT has_column_privilege(current_user,'automation_runs',$1,'UPDATE')",
            )
            .bind(column)
            .fetch_one(&self.pool)
            .await?;
            anyhow::ensure!(granted, "automation API cancellation grants are incomplete");
        }
        for function in [
            "sandbox_automation_authorized(uuid,uuid)",
            "sandbox_check_automation_delegation(uuid,uuid,text[],timestamptz)",
            "sandbox_automation_required_actions(text,boolean)",
        ] {
            let granted: bool =
                sqlx::query_scalar("SELECT has_function_privilege(current_user,$1,'EXECUTE')")
                    .bind(function)
                    .fetch_one(&self.pool)
                    .await?;
            anyhow::ensure!(granted, "automation API function grants are incomplete");
        }
        self.check_automation_notification_schema().await?;
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn create_automation(
        &self,
        actor: &Actor,
        identity: &VerifiedIdentity,
        instance: Uuid,
        request: &CreateAutomation,
        key: &str,
        expected: i64,
        max_ttl: i64,
    ) -> Result<AutomationMutationResult, ApiError> {
        request.action.validate(max_ttl)?;
        request.validate_fixed_parameters()?;
        let mut tx = self.begin(actor.tenant_id).await?;
        let (project, workspace, version) =
            lock_resources(&mut tx, actor.tenant_id, instance).await?;
        Self::authorize_resource(&mut tx, actor, project, "automations:write").await?;
        identity_live(&mut tx, actor, identity).await?;
        let required = request
            .action
            .required_actions(matches!(request.trigger, AutomationTrigger::Event { .. }));
        for action in &required {
            if !identity.permits(action) {
                return Err(ApiError::new(
                    StatusCode::FORBIDDEN,
                    "INSUFFICIENT_SCOPE",
                    "OAuth action scope is missing",
                ));
            }
            Self::authorize_resource(&mut tx, actor, project, action).await?;
        }
        let digest = request_digest(request, Some(expected))?;
        let key_hash = management_lock(&mut tx, actor, "automations:create", instance, key).await?;
        if let Some(result) = replay(
            &mut tx,
            actor,
            "automations:create",
            instance,
            &key_hash,
            &digest,
        )
        .await?
        {
            tx.commit().await?;
            return Ok(result);
        }
        let now = now(&mut tx).await?;
        if !contract::delegation_lifetime_is_valid(request.delegation_expires_at, now) {
            return Err(ApiError::invalid(
                "Delegation lifetime must be over 60 seconds and at most 366 days",
            ));
        }
        sqlx::query("SELECT sandbox_check_automation_delegation($1,$2,$3,$4)")
            .bind(actor.principal_id)
            .bind(project)
            .bind(&required)
            .bind(request.delegation_expires_at)
            .execute(&mut *tx)
            .await
            .map_err(authority_error)?;
        let (trigger_kind, scheduled, cron, event_type, aggregate, next_due) =
            match &request.trigger {
                AutomationTrigger::Once { at } => {
                    if *at <= now || *at >= request.delegation_expires_at {
                        return Err(ApiError::invalid(
                            "One-shot time must be in the delegation lifetime",
                        ));
                    }
                    ("ONCE", Some(*at), None, None, None, Some(*at))
                }
                AutomationTrigger::CronUtc { expression } => {
                    let parsed = rules::UtcCron::parse(expression).map_err(|_| {
                        ApiError::invalid(
                            "Expected bounded seven-field UTC cron with second 0 and wildcard year",
                        )
                    })?;
                    let due = parsed
                        .next_after(now, request.delegation_expires_at)
                        .map_err(|_| {
                            ApiError::invalid("No cron occurrence within delegation lifetime")
                        })?;
                    (
                        "CRON_UTC",
                        None,
                        Some(parsed.expression().to_owned()),
                        None,
                        None,
                        Some(due),
                    )
                }
                AutomationTrigger::Event {
                    event_type,
                    aggregate_id,
                } => {
                    if aggregate_id.is_nil()
                        || event_type.is_empty()
                        || event_type.len() > contract::EVENT_TYPE_BYTES_MAX
                        || !event_type.bytes().all(|b| {
                            b.is_ascii_lowercase() || b.is_ascii_digit() || b"._:-".contains(&b)
                        })
                    {
                        return Err(ApiError::invalid(
                            "Event trigger requires an exact aggregate UUID and bounded event type",
                        ));
                    }
                    (
                        "EVENT",
                        None,
                        None,
                        Some(event_type.clone()),
                        Some(*aggregate_id),
                        None,
                    )
                }
            };
        if version != expected {
            return Err(version_error());
        }
        // Bound persistent pollers independently of finite per-rule run budgets.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('automation-limit:'||$1,0))")
            .bind(actor.tenant_id.to_string())
            .execute(&mut *tx)
            .await?;
        let(count,total):(i64,i64)=sqlx::query_as("SELECT count(*) FILTER(WHERE a.project_id=$2),count(*) FROM automations a JOIN automation_delegations d ON d.tenant_id=a.tenant_id AND d.id=a.delegation_id WHERE a.tenant_id=$1 AND a.status IN('ACTIVE','PAUSED') AND d.revoked_at IS NULL AND d.expires_at>clock_timestamp()")
            .bind(actor.tenant_id).bind(project).fetch_one(&mut *tx).await?;
        if count >= contract::LIVE_POLICIES_PER_PROJECT
            || total >= contract::LIVE_POLICIES_PER_TENANT
        {
            return Err(ApiError::conflict(
                "AUTOMATION_LIMIT",
                "Project or tenant automation limit reached",
            ));
        }
        let id = Uuid::new_v4();
        let delegation = Uuid::new_v4();
        sqlx::query("INSERT INTO automation_delegations(id,tenant_id,project_id,principal_id,identity_issuer,identity_subject,instance_id,workspace_id,allowed_actions,expires_at,created_at,identity_client_id,identity_binding_generation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,(SELECT binding_generation FROM sandbox_resolve_identity($5,$6,$12) WHERE principal_id=$4 AND enabled))")
            .bind(delegation).bind(actor.tenant_id).bind(project).bind(actor.principal_id)
            .bind(&identity.issuer).bind(&identity.subject).bind(instance).bind(workspace)
            .bind(required).bind(request.delegation_expires_at).bind(now).bind(&identity.client_id).execute(&mut *tx).await?;
        let event_epoch = if trigger_kind == "EVENT" {
            Some(
                sqlx::query_scalar::<_, Uuid>(
                    "SELECT epoch FROM event_stream_heads WHERE tenant_id=$1 AND project_id=$2",
                )
                .bind(actor.tenant_id)
                .bind(project)
                .fetch_one(&mut *tx)
                .await?,
            )
        } else {
            None
        };
        // Start at the current committed stream head; creation never replays
        // pre-existing events. The event-head audit below provides serialization.
        sqlx::query("INSERT INTO automations(id,tenant_id,project_id,delegation_id,instance_id,workspace_id,creator_principal_id,name,action_kind,action,trigger_kind,scheduled_at,cron_expression,event_type,event_aggregate_id,next_due_at,run_budget,minimum_interval_seconds,grace_seconds,event_stream_epoch,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$21)")
            .bind(id).bind(actor.tenant_id).bind(project).bind(delegation).bind(instance).bind(workspace).bind(actor.principal_id)
            .bind(&request.name).bind(request.action.kind()).bind(json!(request.action)).bind(trigger_kind).bind(scheduled).bind(cron).bind(event_type).bind(aggregate).bind(next_due)
            .bind(request.run_budget as i32).bind(request.minimum_interval_seconds as i32).bind(request.grace_seconds as i32).bind(event_epoch).bind(now).execute(&mut *tx).await?;
        event(
            &mut tx,
            actor,
            project,
            id,
            "automations:create",
            "ACCEPTED",
        )
        .await?;
        let sequence: i64 = sqlx::query_scalar(
            "SELECT last_sequence FROM event_stream_heads WHERE tenant_id=$1 AND project_id=$2",
        )
        .bind(actor.tenant_id)
        .bind(project)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query("UPDATE automations SET event_sequence=$3 WHERE tenant_id=$1 AND id=$2")
            .bind(actor.tenant_id)
            .bind(id)
            .bind(sequence)
            .execute(&mut *tx)
            .await?;
        // Event-head waits do not extend token or delegation authority.
        identity_live(&mut tx, actor, identity).await?;
        Self::authorize_resource(&mut tx, actor, project, "automations:write").await?;
        if !authorized(&mut tx, actor.tenant_id, id).await? {
            return Err(ApiError::forbidden());
        }
        let resource = load(&mut tx, actor.tenant_id, id).await?;
        let result = persist(
            &mut tx,
            actor,
            "automations:create",
            instance,
            &key_hash,
            &digest,
            resource,
            201,
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }

    pub async fn get_automation(&self, actor: &Actor, id: Uuid) -> Result<Automation, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let resource = load(&mut tx, actor.tenant_id, id).await?;
        Self::authorize_resource(&mut tx, actor, resource.project_id, "automations:read").await?;
        tx.commit().await?;
        Ok(resource)
    }
    pub async fn list_automations(
        &self,
        actor: &Actor,
        query: &HistoryQuery,
        signer: &CursorSigner,
    ) -> Result<HistoryPage<Automation>, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        Self::authorize_resource(&mut tx, actor, query.project_id, "automations:read").await?;
        let window = Window::new(query, actor, "automations", signer, now(&mut tx).await?)?;
        let sql = format!(
            "SELECT {AUTOMATION_COLUMNS} FROM automations a JOIN automation_delegations d ON d.tenant_id=a.tenant_id AND d.id=a.delegation_id WHERE a.tenant_id=$1 AND a.project_id=$2 AND($3::uuid IS NULL OR a.instance_id=$3) AND a.created_at<=$4 AND($5::timestamptz IS NULL OR(a.created_at,a.id)<($5,$6)) ORDER BY a.created_at DESC,a.id DESC LIMIT $7"
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
        let page = window.page(rows, query, actor, "automations", signer)?;
        tx.commit().await?;
        Ok(page)
    }
    pub async fn get_automation_run(
        &self,
        actor: &Actor,
        id: Uuid,
    ) -> Result<AutomationRun, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let resource: AutomationRun = sqlx::query_as(&format!(
            "SELECT {RUN_COLUMNS} FROM automation_runs WHERE tenant_id=$1 AND id=$2"
        ))
        .bind(actor.tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
        Self::authorize_resource(&mut tx, actor, resource.project_id, "automations:read").await?;
        tx.commit().await?;
        Ok(resource)
    }
    pub async fn list_automation_runs(
        &self,
        actor: &Actor,
        id: Uuid,
        query: &HistoryQuery,
        signer: &CursorSigner,
    ) -> Result<HistoryPage<AutomationRun>, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let a = load(&mut tx, actor.tenant_id, id).await?;
        if a.project_id != query.project_id || query.instance_id.is_some_and(|i| i != a.instance_id)
        {
            return Err(ApiError::not_found());
        }
        Self::authorize_resource(&mut tx, actor, a.project_id, "automations:read").await?;
        let kind = format!("automation-runs:{id}");
        let window = Window::new(query, actor, &kind, signer, now(&mut tx).await?)?;
        let sql = format!(
            "SELECT {RUN_COLUMNS} FROM automation_runs WHERE tenant_id=$1 AND automation_id=$2 AND created_at<=$3 AND($4::timestamptz IS NULL OR(created_at,id)<($4,$5)) ORDER BY created_at DESC,id DESC LIMIT $6"
        );
        let rows = sqlx::query_as(&sql)
            .bind(actor.tenant_id)
            .bind(id)
            .bind(window.cutoff)
            .bind(window.after_time)
            .bind(window.after_id)
            .bind(window.limit + 1)
            .fetch_all(&mut *tx)
            .await?;
        let page = window.page(rows, query, actor, &kind, signer)?;
        tx.commit().await?;
        Ok(page)
    }
    pub async fn change_automation(
        &self,
        actor: &Actor,
        identity: &VerifiedIdentity,
        id: Uuid,
        change: &AutomationChange,
        key: &str,
        expected: i64,
    ) -> Result<AutomationMutationResult, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let initial = load(&mut tx, actor.tenant_id, id).await?;
        lock_resources(&mut tx, actor.tenant_id, initial.instance_id).await?;
        Self::authorize_resource(&mut tx, actor, initial.project_id, "automations:write").await?;
        identity_live(&mut tx, actor, identity).await?;
        if matches!(change, AutomationChange::Resume) {
            authorize_resume(&mut tx, actor, identity, &initial).await?;
        }
        let digest = request_digest(change, Some(expected))?;
        let hash = management_lock(&mut tx, actor, "automations:change", id, key).await?;
        if let Some(result) =
            replay(&mut tx, actor, "automations:change", id, &hash, &digest).await?
        {
            if matches!(change, AutomationChange::Resume) {
                authorize_resume(&mut tx, actor, identity, &initial).await?;
            }
            tx.commit().await?;
            return Ok(result);
        }
        sqlx::query("SELECT id FROM automations WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
            .bind(actor.tenant_id)
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
        let current = load(&mut tx, actor.tenant_id, id).await?;
        if current.version != expected {
            return Err(version_error());
        }
        let status = match change {
            AutomationChange::Pause if current.status == "ACTIVE" => "PAUSED",
            AutomationChange::Resume if current.status == "PAUSED" => "ACTIVE",
            AutomationChange::Revoke if matches!(current.status.as_str(), "ACTIVE" | "PAUSED") => {
                "REVOKED"
            }
            _ => {
                return Err(ApiError::conflict(
                    "AUTOMATION_STATE",
                    "Automation cannot perform this change",
                ));
            }
        };
        sqlx::query(
            "UPDATE automations SET status=$3,version=version+1 WHERE tenant_id=$1 AND id=$2",
        )
        .bind(actor.tenant_id)
        .bind(id)
        .bind(status)
        .execute(&mut *tx)
        .await?;
        if matches!(change, AutomationChange::Revoke) {
            sqlx::query("UPDATE automation_delegations d SET revoked_at=clock_timestamp() FROM automations a WHERE a.tenant_id=$1 AND a.id=$2 AND d.tenant_id=a.tenant_id AND d.id=a.delegation_id").bind(actor.tenant_id).bind(id).execute(&mut *tx).await?;
        }
        // Resource locks also fence previous acceptance transactions. A run
        // with an operation is retained until its real effects close.
        let cancelled: Vec<Uuid> = sqlx::query_scalar("UPDATE automation_runs SET status='CANCELLED',failure_code='AUTOMATION_CHANGED',completed_at=clock_timestamp() WHERE tenant_id=$1 AND automation_id=$2 AND operation_id IS NULL AND status IN('PENDING','CLAIMED','DISPATCHING','OUTCOME_UNKNOWN') RETURNING id")
            .bind(actor.tenant_id).bind(id).fetch_all(&mut *tx).await?;
        for run in cancelled {
            event(
                &mut tx,
                &Actor {
                    authorization: None,
                    tenant_id: actor.tenant_id,
                    principal_id: current.creator_principal_id,
                    request_id: run,
                },
                current.project_id,
                run,
                "automations:run",
                "CANCELLED",
            )
            .await?;
        }
        if matches!(change, AutomationChange::Resume)
            && !authorized(&mut tx, actor.tenant_id, id).await?
        {
            return Err(ApiError::forbidden());
        }
        event(
            &mut tx,
            actor,
            current.project_id,
            id,
            "automations:change",
            status,
        )
        .await?;
        Self::authorize_resource(&mut tx, actor, current.project_id, "automations:write").await?;
        identity_live(&mut tx, actor, identity).await?;
        if matches!(change, AutomationChange::Resume)
            && !authorized(&mut tx, actor.tenant_id, id).await?
        {
            return Err(ApiError::forbidden());
        }
        let resource = load(&mut tx, actor.tenant_id, id).await?;
        let result = persist(
            &mut tx,
            actor,
            "automations:change",
            id,
            &hash,
            &digest,
            resource,
            200,
        )
        .await?;
        if matches!(change, AutomationChange::Resume) {
            authorize_resume(&mut tx, actor, identity, &current).await?;
        }
        tx.commit().await?;
        Ok(result)
    }
}

pub(super) async fn require_formal_schema(database: &Database) -> anyhow::Result<()> {
    let ready: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=39 AND success)",
    )
    .fetch_one(&database.pool)
    .await?;
    anyhow::ensure!(
        ready,
        "automations require successful formal migration 0039"
    );
    let complete: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS(SELECT 1 FROM unnest(ARRAY['automation_delegations','automations','automation_runs']) name LEFT JOIN pg_class c ON c.oid=to_regclass('public.'||name) WHERE c.oid IS NULL OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity) AND to_regclass('public.automation_claims') IS NOT NULL AND NOT EXISTS(SELECT 1 FROM (VALUES('automation_delegations','automation_delegation_no_delete'),('automation_delegations','immutable_automation_delegation'),('automations','automation_no_delete'),('automations','immutable_automation'),('automations','automation_queue'),('automation_runs','automation_run_no_delete'),('automation_runs','immutable_automation_run'),('automation_runs','automation_run_queue'),('operations','automation_acceptance_gate'),('operations','automation_operation_link'),('operations','automation_final_acceptance')) expected(table_name,trigger_name) WHERE NOT EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=to_regclass('public.'||expected.table_name) AND t.tgname=expected.trigger_name AND NOT t.tgisinternal AND t.tgenabled IN('O','A'))) AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.operations'::regclass AND tgname='automation_final_acceptance' AND tgdeferrable AND tginitdeferred)",
    )
    .fetch_one(&database.pool)
    .await?;
    anyhow::ensure!(complete, "automation component schema is incomplete");
    Ok(())
}
pub(super) async fn lock_resources(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    instance: Uuid,
) -> Result<(Uuid, Uuid, i64), ApiError> {
    let (project, workspace): (Uuid, Uuid) = sqlx::query_as(
        "SELECT project_id,workspace_id FROM instances WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant)
    .bind(instance)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(ApiError::not_found)?;
    sqlx::query("SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(tenant)
        .bind(workspace)
        .fetch_one(&mut **tx)
        .await?;
    let version: i64 = sqlx::query_scalar(
        "SELECT spec_version FROM instances WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(tenant)
    .bind(instance)
    .fetch_one(&mut **tx)
    .await?;
    Ok((project, workspace, version))
}
pub(super) async fn now(tx: &mut Transaction<'_, Postgres>) -> Result<DateTime<Utc>, ApiError> {
    Ok(sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?)
}
pub(super) async fn stream_live(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    id: Uuid,
) -> Result<bool, ApiError> {
    Ok(sqlx::query_scalar("SELECT a.trigger_kind<>'EVENT' OR EXISTS(SELECT 1 FROM event_stream_heads h WHERE(h.tenant_id,h.project_id,h.epoch)=(a.tenant_id,a.project_id,a.event_stream_epoch)) FROM automations a WHERE a.tenant_id=$1 AND a.id=$2").bind(tenant).bind(id).fetch_one(&mut **tx).await?)
}
pub(super) async fn authorized(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    id: Uuid,
) -> Result<bool, ApiError> {
    Ok(
        sqlx::query_scalar("SELECT sandbox_automation_authorized($1,$2)")
            .bind(tenant)
            .bind(id)
            .fetch_one(&mut **tx)
            .await?,
    )
}
pub(super) async fn load(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    id: Uuid,
) -> Result<Automation, ApiError> {
    sqlx::query_as(&format!("SELECT {AUTOMATION_COLUMNS} FROM automations a JOIN automation_delegations d ON d.tenant_id=a.tenant_id AND d.id=a.delegation_id WHERE a.tenant_id=$1 AND a.id=$2"))
        .bind(tenant).bind(id).fetch_optional(&mut **tx).await?.ok_or_else(ApiError::not_found)
}
pub(super) async fn identity_live(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    identity: &VerifiedIdentity,
) -> Result<(), ApiError> {
    let live:bool=sqlx::query_scalar("SELECT $4::bigint>extract(epoch FROM clock_timestamp()) AND EXISTS(SELECT 1 FROM sandbox_resolve_identity($1,$2,$5) p WHERE p.principal_id=$3 AND p.enabled AND p.kind IN('USER','SERVICE'))")
        .bind(&identity.issuer).bind(&identity.subject).bind(actor.principal_id).bind(identity.expires_at).bind(&identity.client_id).fetch_one(&mut **tx).await?;
    if !live {
        return Err(ApiError::forbidden());
    }
    Ok(())
}
async fn management_lock(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    action: &str,
    target: Uuid,
    key: &str,
) -> Result<String, ApiError> {
    let hash = hex::encode(Sha256::digest(key.as_bytes()));
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!(
            "{}:{}:{action}:{target}:{hash}",
            actor.tenant_id, actor.principal_id
        ))
        .execute(&mut **tx)
        .await?;
    Ok(hash)
}
async fn replay(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    action: &str,
    target: Uuid,
    hash: &str,
    digest: &[u8],
) -> Result<Option<AutomationMutationResult>, ApiError> {
    let row=sqlx::query("SELECT request_hash,response_body,response_status,expires_at>clock_timestamp() AS fresh FROM management_receipts WHERE tenant_id=$1 AND principal_id=$2 AND action=$3 AND target_id=$4 AND key_hash=$5")
        .bind(actor.tenant_id).bind(actor.principal_id).bind(action).bind(target).bind(hash).fetch_optional(&mut **tx).await?;
    let Some(row) = row else { return Ok(None) };
    if row.try_get::<Vec<u8>, _>("request_hash")?.as_slice() != digest {
        return Err(ApiError::conflict(
            "IDEMPOTENCY_CONFLICT",
            "The automation key already has another request",
        ));
    }
    if !row.try_get::<bool, _>("fresh")? {
        return Err(ApiError::new(
            StatusCode::GONE,
            "IDEMPOTENCY_EXPIRED",
            "Reconcile the current automation before a new request",
        ));
    }
    Ok(Some(AutomationMutationResult {
        status: row.try_get::<i16, _>("response_status")? as u16,
        body: serde_json::from_value(row.try_get("response_body")?)
            .map_err(|_| ApiError::invalid("Stored automation receipt is invalid"))?,
    }))
}
#[allow(clippy::too_many_arguments)]
async fn persist(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    action: &str,
    target: Uuid,
    hash: &str,
    digest: &[u8],
    resource: Automation,
    status: u16,
) -> Result<AutomationMutationResult, ApiError> {
    let now = now(tx).await?;
    let project = resource.project_id;
    let id = resource.id;
    let body = AutomationReceipt {
        resource,
        idempotency_expires_at: now + Duration::days(7),
    };
    sqlx::query("INSERT INTO management_receipts(tenant_id,project_id,principal_id,action,target_id,key_hash,request_hash,resource_id,response_status,response_body,created_at,expires_at,tombstone_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
        .bind(actor.tenant_id).bind(project).bind(actor.principal_id).bind(action).bind(target).bind(hash).bind(digest).bind(id).bind(status as i16).bind(json!(body)).bind(now).bind(body.idempotency_expires_at).bind(body.idempotency_expires_at+Duration::days(90)).execute(&mut **tx).await?;
    Ok(AutomationMutationResult { status, body })
}
pub(super) async fn event(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    project: Uuid,
    id: Uuid,
    action: &str,
    outcome: &str,
) -> Result<(), ApiError> {
    let version: i64 = if action == "automations:run" {
        sqlx::query_scalar("SELECT version FROM automation_runs WHERE tenant_id=$1 AND id=$2")
            .bind(actor.tenant_id)
            .bind(id)
            .fetch_one(&mut **tx)
            .await?
    } else {
        sqlx::query_scalar("SELECT version FROM automations WHERE tenant_id=$1 AND id=$2")
            .bind(actor.tenant_id)
            .bind(id)
            .fetch_one(&mut **tx)
            .await?
    };
    let audit_outcome = match outcome {
        "SUCCEEDED" | "SKIPPED" => "SUCCEEDED",
        "FAILED" | "CANCELLED" => "FAILED",
        "UNKNOWN" | "OUTCOME_UNKNOWN" => "UNKNOWN",
        _ => "ACCEPTED",
    };
    sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,resource_id,action,outcome) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(actor.tenant_id).bind(project).bind(actor.principal_id).bind(actor.request_id).bind(id).bind(action).bind(audit_outcome).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,request_id,payload) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(actor.tenant_id).bind(project).bind(id).bind(version).bind(format!("{action}.changed")).bind(actor.request_id).bind(json!({"status":outcome})).execute(&mut **tx).await?;
    Ok(())
}
fn version_error() -> ApiError {
    ApiError::new(
        StatusCode::PRECONDITION_FAILED,
        "VERSION_MISMATCH",
        "Read the current resource ETag before changing the automation",
    )
}
fn authority_error(error: sqlx::Error) -> ApiError {
    if error
        .as_database_error()
        .is_some_and(|e| e.code().as_deref() == Some("P4030"))
    {
        ApiError::forbidden()
    } else {
        error.into()
    }
}

async fn authorize_resume(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    identity: &VerifiedIdentity,
    automation: &Automation,
) -> Result<(), ApiError> {
    let actions: Vec<String> =
        sqlx::query_scalar("SELECT sandbox_automation_required_actions($1,$2)")
            .bind(&automation.action_kind)
            .bind(automation.trigger_kind == "EVENT")
            .fetch_one(&mut **tx)
            .await?;
    for action in actions {
        if !identity.permits(&action) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "INSUFFICIENT_SCOPE",
                "OAuth action scope is missing",
            ));
        }
        Database::authorize_resource(tx, actor, automation.project_id, &action).await?;
    }
    Ok(())
}
