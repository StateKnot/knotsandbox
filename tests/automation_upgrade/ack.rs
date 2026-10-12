//! Persisted schema-42 ACK facts and their replay through the current interface.
//! The owner fixture represents committed history, never an old runtime binary.
use super::{Scope, tenant_tx};
use anyhow::{Context, ensure};
use axum::{Router, http::StatusCode, routing::get};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use sandbox_platform::{
    auth::{AuthConfig, JwtAuthenticator, ScopeProfile, VerifiedIdentity},
    automation::notifications::{AutomationNotification, AutomationNotificationReceipt},
    db::Database,
    error::ApiError,
    history::{CursorSigner, HistoryQuery},
    request::request_digest,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

const ACTION: &str = "automations:notifications:acknowledge";
const COLUMNS: &str = "id,tenant_id,project_id,instance_id,automation_id,run_id,source_event_id,source_run_version,source_status,created_at,acknowledged_at,acknowledged_by,version";

pub(super) struct HistoricalAck {
    pub(super) id: Uuid,
    pub(super) key: String,
    pub(super) body: Value,
    pub(super) request_id: Uuid,
}

pub(super) async fn seed_schema42_ack(
    owner: &PgPool,
    scope: &Scope,
    id: Uuid,
) -> anyhow::Result<HistoricalAck> {
    let key = format!("schema42-ack-{id}");
    let request_id = Uuid::new_v4();
    let mut tx = tenant_tx(owner, scope.tenant).await?;
    let ready: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=42 AND success) AND NOT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=43)")
        .fetch_one(&mut *tx).await?;
    ensure!(
        ready,
        "Historical ACK must be committed at schema 42 before migration 43"
    );
    let sql = format!(
        "UPDATE automation_notifications SET acknowledged_at=clock_timestamp(),acknowledged_by=$3,version=2 WHERE tenant_id=$1 AND id=$2 AND version=1 RETURNING {COLUMNS}"
    );
    let resource: AutomationNotification = sqlx::query_as(&sql)
        .bind(scope.tenant)
        .bind(id)
        .bind(scope.principal)
        .fetch_one(&mut *tx)
        .await?;
    ensure!(resource.project_id == scope.project && resource.source_event_id == id);
    sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,resource_id,action,outcome) VALUES($1,$2,$3,$4,$5,$6,'SUCCEEDED')")
        .bind(scope.tenant).bind(scope.project).bind(scope.principal).bind(request_id).bind(id).bind(ACTION).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,request_id,payload) VALUES($1,$2,$3,2,'automation-notifications:acknowledged',$4,$5)")
        .bind(scope.tenant).bind(scope.project).bind(id).bind(resource.run_id)
        .bind(json!({"notification_id":id,"run_id":resource.run_id,"acknowledged":true})).execute(&mut *tx).await?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    let receipt = AutomationNotificationReceipt {
        resource,
        idempotency_expires_at: now + Duration::days(7),
    };
    let body = serde_json::to_value(&receipt)?;
    let digest = request_digest(&json!({}), Some(1)).map_err(api_failure)?;
    sqlx::query("INSERT INTO management_receipts(tenant_id,project_id,principal_id,action,target_id,key_hash,request_hash,resource_id,response_status,response_body,created_at,expires_at,tombstone_until) VALUES($1,$2,$3,$4,$5,$6,$7,$5,200,$8,$9,$10,$11)")
        .bind(scope.tenant).bind(scope.project).bind(scope.principal).bind(ACTION).bind(id)
        .bind(hex::encode(Sha256::digest(key.as_bytes()))).bind(digest).bind(&body).bind(now)
        .bind(receipt.idempotency_expires_at).bind(receipt.idempotency_expires_at + Duration::days(90))
        .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(HistoricalAck {
        id,
        key,
        body,
        request_id,
    })
}

fn api_failure(error: ApiError) -> anyhow::Error {
    anyhow::anyhow!("ACK interface failed: {} {}", error.status, error.code)
}

struct SignedIdentity {
    identity: VerifiedIdentity,
    server: tokio::task::JoinHandle<Result<(), std::io::Error>>,
}
impl Drop for SignedIdentity {
    fn drop(&mut self) {
        self.server.abort();
    }
}
async fn signed_identity(scope: &Scope) -> anyhow::Result<SignedIdentity> {
    let jwk: Value = serde_json::from_str(include_str!("../fixtures/auth/jwk-a.json"))?;
    let kid = jwk["kid"]
        .as_str()
        .context("Signing fixture has no kid")?
        .to_owned();
    let keys = json!({"keys":[jwk]});
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/jwks",
                get(move || {
                    let keys = keys.clone();
                    async move { axum::Json(keys) }
                }),
            ),
        )
        .await
    });
    let verified = async {
        let authenticator = JwtAuthenticator::new(AuthConfig {
            issuer: "https://issuer.example.test".into(),
            audience: "sandbox-api".into(),
            jwks_url: format!("http://{address}/jwks"),
            required_scopes: vec!["automations:read".into(), "automations:write".into()],
            scope_profile: ScopeProfile::ActionScopes,
            jwks_ttl_seconds: 300,
            clock_skew_seconds: 0,
            allow_loopback_http: true,
            max_token_lifetime_seconds: 300,
        })?;
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some(kid);
        let now = Utc::now().timestamp();
        let token = encode(&header,
            &json!({"iss":"https://issuer.example.test","sub":scope.principal.to_string(),"aud":"sandbox-api","client_id":"historical-client","iat":now,"exp":now+300,"jti":Uuid::new_v4().to_string(),"scope":"automations:read automations:write"}),
            &EncodingKey::from_rsa_der(include_bytes!("../fixtures/auth/rsa-a.der")))?;
        Ok::<_, anyhow::Error>(authenticator.verify(&token).await?)
    }.await;
    match verified {
        Ok(identity) => Ok(SignedIdentity { identity, server }),
        Err(error) => {
            server.abort();
            Err(error)
        }
    }
}

async fn facts(
    owner: &PgPool,
    scope: &Scope,
    business_only: bool,
) -> anyhow::Result<BTreeMap<String, Value>> {
    let mut tx = tenant_tx(owner, scope.tenant).await?;
    let mut facts = BTreeMap::new();
    for table in [
        "instances",
        "workspaces",
        "operations",
        "executions",
        "idempotency_keys",
        "quota_accounts",
        "quota_reservations",
        "workspace_holds",
        "workspace_hold_releases",
        "launch_permits",
        "backups",
        "file_transfers",
        "file_cleanup_schedule",
        "automation_delegations",
        "automations",
        "automation_runs",
        "automation_claims",
        "instance_timers",
        "operation_dispatch",
    ] {
        let sql = format!(
            "SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM {table} r WHERE tenant_id=$1"
        );
        facts.insert(
            table.into(),
            sqlx::query_scalar(&sql)
                .bind(scope.tenant)
                .fetch_one(&mut *tx)
                .await?,
        );
    }
    if !business_only {
        for table in [
            "automation_notifications",
            "management_receipts",
            "domain_events",
            "audit_events",
            "event_stream_heads",
            "event_stream_positions",
        ] {
            let sql = format!(
                "SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM {table} r WHERE tenant_id=$1"
            );
            facts.insert(
                table.into(),
                sqlx::query_scalar(&sql)
                    .bind(scope.tenant)
                    .fetch_one(&mut *tx)
                    .await?,
            );
        }
    }
    tx.commit().await?;
    Ok(facts)
}

async fn source(owner: &PgPool, scope: &Scope, id: Uuid) -> anyhow::Result<Value> {
    let mut tx = tenant_tx(owner, scope.tenant).await?;
    let value = sqlx::query_scalar("SELECT to_jsonb(n)-ARRAY['acknowledged_at','acknowledged_by','version'] FROM automation_notifications n WHERE tenant_id=$1 AND id=$2")
        .bind(scope.tenant).bind(id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(value)
}

async fn set_grant(
    owner: &PgPool,
    scope: &Scope,
    action: &str,
    enabled: bool,
) -> anyhow::Result<()> {
    let mut tx = tenant_tx(owner, scope.tenant).await?;
    let result = sqlx::query("UPDATE grants SET enabled=$4 WHERE tenant_id=$1 AND principal_id=$2 AND project_id=$3 AND action=$5 AND revoked_at IS NULL")
        .bind(scope.tenant).bind(scope.principal).bind(scope.project).bind(enabled).bind(action).execute(&mut *tx).await?;
    ensure!(
        result.rows_affected() == 1,
        "Exactly one historical project grant must change"
    );
    tx.commit().await?;
    Ok(())
}

pub(super) async fn verify_post_upgrade_ack(
    database: &Database,
    owner: &PgPool,
    scopes: &[Scope],
    historical: &HistoricalAck,
    unread_id: Uuid,
) -> anyhow::Result<()> {
    let scope = scopes.first().context("Missing historical ACK scope")?;
    ensure!(
        historical.id != unread_id,
        "A new ACK must target a distinct unread notification"
    );
    database.check_automation_api_schema().await?;
    let signed = signed_identity(scope).await?;
    let actor = database
        .resolve_actor(&signed.identity, scope.tenant, Uuid::new_v4())
        .await
        .map_err(api_failure)?;
    ensure!(
        actor.principal_id == scope.principal
            && actor.authorization.as_ref() == Some(&signed.identity),
        "Verified signing identity must resolve through the current product identity interface"
    );
    let business_before = facts(owner, scope, true).await?;
    let immutable_before = source(owner, scope, unread_id).await?;
    let existing_before = facts(owner, scope, false).await?;
    let mut other_tenants = Vec::new();
    for other in &scopes[1..] {
        other_tenants.push(facts(owner, other, false).await?);
    }
    let replay = database
        .acknowledge_automation_notification(
            &actor,
            &signed.identity,
            historical.id,
            &historical.key,
            1,
        )
        .await
        .map_err(api_failure)?;
    ensure!(
        replay.status == 200 && serde_json::to_value(replay.body)? == historical.body,
        "The schema-42 receipt must replay its original response and original ETag"
    );
    ensure!(
        facts(owner, scope, false).await? == existing_before,
        "Historical receipt replay must not modify any facts"
    );
    let mismatch = database
        .acknowledge_automation_notification(
            &actor,
            &signed.identity,
            historical.id,
            &historical.key,
            2,
        )
        .await
        .err()
        .context("Changed digest unexpectedly replayed")?;
    ensure!(mismatch.status == StatusCode::CONFLICT && mismatch.code == "IDEMPOTENCY_CONFLICT");
    let stale = database
        .acknowledge_automation_notification(
            &actor,
            &signed.identity,
            historical.id,
            "schema43-stale-key",
            1,
        )
        .await
        .err()
        .context("New key with stale ETag unexpectedly committed")?;
    ensure!(stale.status == StatusCode::PRECONDITION_FAILED && stale.code == "VERSION_MISMATCH");
    ensure!(
        facts(owner, scope, false).await? == existing_before,
        "Conflicting ACK requests left side effects"
    );

    // Revoking read disables the current read interface. Write permission is a
    // separate capability and is tested independently below.
    set_grant(owner, scope, "automations:read", false).await?;
    let hidden = database
        .get_automation_notification(&actor, historical.id)
        .await
        .err()
        .context("Revoked read unexpectedly succeeded")?;
    ensure!(hidden.status == StatusCode::NOT_FOUND);
    let signer = CursorSigner::from_json(include_str!("../fixtures/history/cursor-keys.json"))?;
    let query = HistoryQuery {
        project_id: scope.project,
        instance_id: Some(scope.instance),
        limit: Some(100),
        cursor: None,
    };
    let hidden = database
        .list_automation_notifications(&actor, &query, &signer)
        .await
        .err()
        .context("Revoked list unexpectedly succeeded")?;
    ensure!(hidden.status == StatusCode::NOT_FOUND);
    set_grant(owner, scope, "automations:read", true).await?;
    set_grant(owner, scope, "automations:write", false).await?;
    let denied = database
        .acknowledge_automation_notification(
            &actor,
            &signed.identity,
            historical.id,
            &historical.key,
            1,
        )
        .await
        .err()
        .context("Revoked writer replayed a receipt")?;
    ensure!(denied.status == StatusCode::NOT_FOUND);
    set_grant(owner, scope, "automations:write", true).await?;
    for table in ["principal_identities", "principals"] {
        let selector = if table == "principals" {
            "id"
        } else {
            "principal_id"
        };
        let sql = format!("UPDATE {table} SET enabled=$2 WHERE {selector}=$1");
        let changed = sqlx::query(&sql)
            .bind(scope.principal)
            .bind(false)
            .execute(owner)
            .await?;
        ensure!(
            changed.rows_affected() == 1,
            "Exactly one historical identity must be disabled"
        );
        let denied = database
            .acknowledge_automation_notification(
                &actor,
                &signed.identity,
                historical.id,
                &historical.key,
                1,
            )
            .await
            .err()
            .context("Disabled identity replayed a receipt")?;
        ensure!(denied.status == StatusCode::UNAUTHORIZED);
        let changed = sqlx::query(&sql)
            .bind(scope.principal)
            .bind(true)
            .execute(owner)
            .await?;
        ensure!(changed.rows_affected() == 1);
    }
    ensure!(
        facts(owner, scope, false).await? == existing_before,
        "Denied replay or reads modified notification history"
    );

    let key = format!("schema43-new-ack-{unread_id}");
    let ack = database
        .acknowledge_automation_notification(&actor, &signed.identity, unread_id, &key, 1)
        .await
        .map_err(api_failure)?;
    ensure!(
        ack.status == 200
            && ack.body.resource.version == 2
            && ack.body.resource.acknowledged_by == Some(scope.principal)
    );
    let ack_body = serde_json::to_value(&ack.body)?;
    let after_ack = facts(owner, scope, false).await?;
    let replay = database
        .acknowledge_automation_notification(&actor, &signed.identity, unread_id, &key, 1)
        .await
        .map_err(api_failure)?;
    ensure!(replay.status == 200 && serde_json::to_value(replay.body)? == ack_body);
    ensure!(
        facts(owner, scope, false).await? == after_ack,
        "Duplicate same-key ACK must not duplicate receipt, audit or event"
    );
    ensure!(
        source(owner, scope, unread_id).await? == immutable_before
            && facts(owner, scope, true).await? == business_before,
        "ACK changed immutable source, run, workspace, resource authority or quota facts"
    );
    let independent = database
        .acknowledge_automation_notification(
            &actor,
            &signed.identity,
            unread_id,
            "schema43-already-acknowledged",
            2,
        )
        .await
        .map_err(api_failure)?;
    ensure!(
        independent.status == 200
            && serde_json::to_value(independent.body.resource)? == ack_body["resource"]
    );
    let independent_facts = facts(owner, scope, false).await?;
    for table in [
        "automation_notifications",
        "domain_events",
        "audit_events",
        "event_stream_heads",
        "event_stream_positions",
    ] {
        ensure!(
            independent_facts[table] == after_ack[table],
            "A new key on an acknowledged notice duplicated {table}"
        );
    }
    let replay = database
        .acknowledge_automation_notification(
            &actor,
            &signed.identity,
            unread_id,
            "schema43-already-acknowledged",
            2,
        )
        .await
        .map_err(api_failure)?;
    ensure!(replay.status == 200 && facts(owner, scope, false).await? == independent_facts);
    let mut tx = tenant_tx(owner, scope.tenant).await?;
    let historical_count: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM management_receipts WHERE tenant_id=$1 AND action=$2 AND target_id=$3),(SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action=$2 AND resource_id=$3 AND request_id=$4),(SELECT count(*) FROM domain_events e JOIN automation_notifications n ON n.tenant_id=e.tenant_id AND n.id=e.aggregate_id WHERE e.tenant_id=$1 AND e.aggregate_id=$3 AND e.event_type='automation-notifications:acknowledged' AND e.request_id=n.run_id)")
        .bind(scope.tenant).bind(ACTION).bind(historical.id).bind(historical.request_id).fetch_one(&mut *tx).await?;
    ensure!(
        historical_count == (1, 1, 1),
        "Historical ACK receipt/audit/causal event must remain singular"
    );
    let current_count: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM management_receipts WHERE tenant_id=$1 AND action=$2 AND target_id=$3),(SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action=$2 AND resource_id=$3 AND request_id=$4),(SELECT count(*) FROM domain_events e JOIN automation_notifications n ON n.tenant_id=e.tenant_id AND n.id=e.aggregate_id WHERE e.tenant_id=$1 AND e.aggregate_id=$3 AND e.event_type='automation-notifications:acknowledged' AND e.request_id=n.run_id)")
        .bind(scope.tenant).bind(ACTION).bind(unread_id).bind(actor.request_id).fetch_one(&mut *tx).await?;
    ensure!(
        current_count == (2, 1, 1),
        "Only distinct valid idempotency keys may create two receipts; ACK audit/event remain singular"
    );
    tx.commit().await?;
    for (other, before) in scopes[1..].iter().zip(other_tenants) {
        ensure!(
            facts(owner, other, false).await? == before,
            "ACK modified another tenant's history"
        );
        let mut tx = tenant_tx(owner, other.tenant).await?;
        let unread: i64 = sqlx::query_scalar("SELECT count(*) FROM automation_notifications WHERE tenant_id=$1 AND acknowledged_at IS NULL")
            .bind(other.tenant).fetch_one(&mut *tx).await?;
        ensure!(
            unread > 0,
            "The upgrade fixture must preserve genuine unread notifications"
        );
        tx.commit().await?;
    }
    Ok(())
}

// This is a source-writer contract fixture, not a claim that the coordinator
// process resolved a real dispatch. It follows the production transition and
// event/audit shape using the actual unprivileged coordinator login.
pub(super) async fn verify_dual_status_progression(
    database: &Database,
    owner: &PgPool,
    coordinator: &PgPool,
    scopes: &[Scope],
    run: Uuid,
    unknown_id: Uuid,
) -> anyhow::Result<()> {
    let scope = scopes.first().context("Missing progression scope")?;
    let other = scopes.get(1).context("Progression needs a second tenant")?;
    let signed = signed_identity(scope).await?;
    let actor = database
        .resolve_actor(&signed.identity, scope.tenant, Uuid::new_v4())
        .await
        .map_err(api_failure)?;
    ensure!(actor.authorization.as_ref() == Some(&signed.identity));
    let other_signed = signed_identity(other).await?;
    let other_actor = database
        .resolve_actor(&other_signed.identity, other.tenant, Uuid::new_v4())
        .await
        .map_err(api_failure)?;
    let other_before = super::snapshot(owner, &scopes[1..]).await?;
    let mut other_notifications = Vec::new();
    for scope in &scopes[1..] {
        other_notifications.push(facts(owner, scope, false).await?);
    }
    let unknown = database
        .get_automation_notification(&actor, unknown_id)
        .await
        .map_err(api_failure)?;
    ensure!(
        unknown.run_id == run
            && unknown.source_status == "OUTCOME_UNKNOWN"
            && unknown.source_run_version == 4
            && unknown.version == 2
            && unknown.acknowledged_by == Some(scope.principal)
            && unknown.acknowledged_at.is_some(),
        "Progression must start with the genuinely acknowledged UNKNOWN source"
    );
    let unknown_before = serde_json::to_value(&unknown)?;
    let unknown_source_before = source(owner, scope, unknown_id).await?;
    let history_before = facts(owner, scope, false).await?;
    let unknown_key = format!("schema43-new-ack-{unknown_id}");
    let mut tx = tenant_tx(owner, scope.tenant).await?;
    let unknown_receipt: Value = sqlx::query_scalar("SELECT response_body FROM management_receipts WHERE tenant_id=$1 AND principal_id=$2 AND action=$3 AND target_id=$4 AND key_hash=$5")
        .bind(scope.tenant).bind(scope.principal).bind(ACTION).bind(unknown_id)
        .bind(hex::encode(Sha256::digest(unknown_key.as_bytes())))
        .fetch_one(&mut *tx).await?;
    let run_before: Value = sqlx::query_scalar(
        "SELECT to_jsonb(r) FROM automation_runs r WHERE tenant_id=$1 AND id=$2",
    )
    .bind(scope.tenant)
    .bind(run)
    .fetch_one(&mut *tx)
    .await?;
    let automation: Uuid = serde_json::from_value(run_before["automation_id"].clone())?;
    let delegation: Uuid = serde_json::from_value(run_before["delegation_id"].clone())?;
    let expiry: Value = sqlx::query_scalar(
        "SELECT to_jsonb(expires_at) FROM automation_delegations WHERE tenant_id=$1 AND id=$2",
    )
    .bind(scope.tenant)
    .bind(delegation)
    .fetch_one(&mut *tx)
    .await?;
    let unknown_event_before: Value =
        sqlx::query_scalar("SELECT to_jsonb(e) FROM domain_events e WHERE tenant_id=$1 AND id=$2")
            .bind(scope.tenant)
            .bind(unknown_id)
            .fetch_one(&mut *tx)
            .await?;
    ensure!(
        run_before["status"] == "OUTCOME_UNKNOWN"
            && run_before["version"] == 5
            && run_before["operation_id"].is_null()
            && run_before["completed_at"].is_null()
    );
    ensure!(
        unknown_event_before["aggregate_id"] == json!(run)
            && unknown_event_before["aggregate_version"] == 4
            && unknown_event_before["request_id"] == json!(run)
            && unknown_event_before["payload"] == json!({"status":"OUTCOME_UNKNOWN"})
    );
    tx.commit().await?;
    let business_before = facts(owner, scope, true).await?;

    let mut tx = tenant_tx(coordinator, scope.tenant).await?;
    let login: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(&mut *tx)
        .await?;
    ensure!(
        login == "sandbox_automation",
        "Progression must use the real coordinator login"
    );
    let version: i64 = sqlx::query_scalar("UPDATE automation_runs SET status='FAILED',failure_code='DEPENDENCY_UNAVAILABLE',completed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND status='OUTCOME_UNKNOWN' AND version=5 AND operation_id IS NULL RETURNING version")
        .bind(scope.tenant).bind(run).fetch_one(&mut *tx).await?;
    ensure!(
        version == 6,
        "The immutable run guard must advance its version once"
    );
    sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,resource_id,action,outcome) VALUES($1,$2,$3,$4,$4,'automations:run','FAILED')")
        .bind(scope.tenant).bind(scope.project).bind(scope.principal).bind(run)
        .execute(&mut *tx).await?;
    let failed_id = super::write_event(
        &mut tx,
        scope,
        run,
        version,
        run,
        json!({"status":"FAILED"}),
    )
    .await?;
    tx.commit().await?;

    let business_after = facts(owner, scope, true).await?;
    let mut permitted_changes = business_before.clone();
    for table in ["automation_runs", "automation_claims"] {
        permitted_changes.insert(table.into(), business_after[table].clone());
    }
    ensure!(
        permitted_changes == business_after,
        "Source progression changed unrelated business facts"
    );
    for (table, key, target) in [
        ("automation_runs", "id", run),
        ("automation_claims", "automation_id", automation),
    ] {
        let before = business_before[table]
            .as_array()
            .context("Historical fact array missing")?;
        let after = business_after[table]
            .as_array()
            .context("Current fact array missing")?;
        let target = json!(target);
        let unrelated_before: Vec<_> = before.iter().filter(|row| row[key] != target).collect();
        let unrelated_after: Vec<_> = after.iter().filter(|row| row[key] != target).collect();
        ensure!(
            unrelated_before == unrelated_after,
            "Progression modified an unrelated {table} row"
        );
        let old = before
            .iter()
            .find(|row| row[key] == target)
            .context("Original progression row missing")?;
        let current = after
            .iter()
            .find(|row| row[key] == target)
            .context("Current progression row missing")?;
        let mutable: &[&str] = if table == "automation_runs" {
            &[
                "status",
                "failure_code",
                "completed_at",
                "version",
                "updated_at",
            ]
        } else {
            &["eligible_at"]
        };
        let mut original = old
            .as_object()
            .context("Original fact is not an object")?
            .clone();
        let mut updated = current
            .as_object()
            .context("Current fact is not an object")?
            .clone();
        for field in mutable {
            original.remove(*field);
            updated.remove(*field);
        }
        ensure!(
            original == updated,
            "Progression changed immutable {table} fields"
        );
        if table == "automation_runs" {
            ensure!(
                current["status"] == "FAILED"
                    && current["version"] == version
                    && !current["completed_at"].is_null()
            );
        } else {
            ensure!(
                current["eligible_at"] == expiry,
                "The normal queue trigger must route the completed run to its delegation expiry"
            );
        }
    }
    let failed = database
        .get_automation_notification(&actor, failed_id)
        .await
        .map_err(api_failure)?;
    ensure!(
        failed.id != unknown_id
            && failed.tenant_id == scope.tenant
            && failed.project_id == scope.project
            && failed.instance_id == scope.instance
            && failed.automation_id == automation
            && failed.run_id == run
            && failed.source_event_id == failed_id
            && failed.source_run_version == version
            && failed.source_status == "FAILED"
            && failed.version == 1
            && failed.acknowledged_at.is_none()
            && failed.acknowledged_by.is_none(),
        "Reading UNKNOWN must not acknowledge the later, independent FAILED source"
    );
    let failed_source_before = source(owner, scope, failed_id).await?;
    ensure!(
        serde_json::to_value(
            database
                .get_automation_notification(&actor, unknown_id)
                .await
                .map_err(api_failure)?
        )? == unknown_before
            && source(owner, scope, unknown_id).await? == unknown_source_before,
        "Resolution overwrote the original acknowledged UNKNOWN source"
    );
    let before_duplicate = facts(owner, scope, false).await?;
    let all_before_duplicate = super::snapshot(owner, scopes).await?;
    let mut tx = tenant_tx(coordinator, scope.tenant).await?;
    // Terminal runs cannot advance to manufacture a new event version. A
    // repeated event at their final version is rejected by the real immutable
    // event uniqueness constraint, rolling back all preceding transaction work.
    sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,resource_id,action,outcome) VALUES($1,$2,$3,$4,$4,'automations:run','FAILED')")
        .bind(scope.tenant).bind(scope.project).bind(scope.principal).bind(run)
        .execute(&mut *tx).await?;
    let error = super::write_event(
        &mut tx,
        scope,
        run,
        version,
        run,
        json!({"status":"FAILED"}),
    )
    .await
    .err()
    .context("A repeated terminal FAILED source unexpectedly committed")?;
    let db_error = error
        .as_database_error()
        .context("The repeated FAILED source must fail a database constraint")?;
    ensure!(
        db_error.code().as_deref() == Some("23505")
            && db_error.constraint()
                == Some("domain_events_tenant_id_aggregate_id_aggregate_version_even_key"),
        "The repeated terminal source must fail its exact event uniqueness constraint"
    );
    tx.rollback().await?;
    ensure!(
        facts(owner, scope, false).await? == before_duplicate
            && super::snapshot(owner, scopes).await? == all_before_duplicate,
        "Rejected repeated FAILED source must roll back its audit, stream head/positions, notification and all business facts"
    );
    let mut tx = tenant_tx(owner, scope.tenant).await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM automation_notifications WHERE tenant_id=$1 AND run_id=$2",
    )
    .bind(scope.tenant)
    .bind(run)
    .fetch_one(&mut *tx)
    .await?;
    let source_count: (i64, i64) = sqlx::query_as(r#"SELECT (SELECT count(*) FROM domain_events WHERE tenant_id=$1 AND id=$3 AND project_id=$2 AND aggregate_id=$4 AND aggregate_version=$5 AND event_type='automations:run.changed' AND request_id=$4 AND payload='{"status":"FAILED"}'::jsonb),(SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND project_id=$2 AND resource_id=$4 AND request_id=$4 AND action='automations:run' AND outcome='FAILED')"#)
        .bind(scope.tenant).bind(scope.project).bind(failed_id).bind(run).bind(version).fetch_one(&mut *tx).await?;
    let failed_event_before: Value =
        sqlx::query_scalar("SELECT to_jsonb(e) FROM domain_events e WHERE tenant_id=$1 AND id=$2")
            .bind(scope.tenant)
            .bind(failed_id)
            .fetch_one(&mut *tx)
            .await?;
    ensure!(
        count == 2 && source_count == (1, 1),
        "The run must have two status notices, one committed FAILED source and one transition audit"
    );
    tx.commit().await?;

    let signer = CursorSigner::from_json(include_str!("../fixtures/history/cursor-keys.json"))?;
    let mut query = HistoryQuery {
        project_id: scope.project,
        instance_id: Some(scope.instance),
        limit: Some(1),
        cursor: None,
    };
    let mut ids = BTreeSet::new();
    let mut run_ids = BTreeSet::new();
    let mut cutoff = None;
    let mut first_cursor = None;
    for _ in 0..10 {
        let page = database
            .list_automation_notifications(&actor, &query, &signer)
            .await
            .map_err(api_failure)?;
        ensure!(
            page.items.len() == 1,
            "The fixture must yield nonempty single-record pages"
        );
        ensure!(
            cutoff.is_none_or(|value| value == page.cutoff),
            "Pagination changed its original cutoff"
        );
        cutoff = Some(page.cutoff);
        for notification in page.items {
            ensure!(
                notification.tenant_id == scope.tenant
                    && notification.project_id == scope.project
                    && notification.instance_id == scope.instance
                    && ids.insert(notification.id),
                "Pagination crossed scope or duplicated a notification"
            );
            if notification.run_id == run {
                run_ids.insert(notification.id);
            }
        }
        let Some(cursor) = page.next_cursor else {
            break;
        };
        if first_cursor.is_none() {
            first_cursor = Some(cursor.clone());
        }
        query.cursor = Some(cursor);
    }
    ensure!(
        ids.len() == 3 && run_ids == BTreeSet::from([unknown_id, failed_id]),
        "Pagination did not expose both independent run-status records exactly once"
    );
    let first_cursor = first_cursor.context("The fixture must exercise a real signed cursor")?;
    let sibling = HistoryQuery {
        project_id: scope.sibling,
        cursor: None,
        ..query.clone()
    };
    ensure!(
        database
            .list_automation_notifications(&actor, &sibling, &signer)
            .await
            .map_err(api_failure)?
            .items
            .is_empty()
    );
    for (reader, project, instance) in [
        (&actor, scope.sibling, scope.instance),
        (&other_actor, other.project, other.instance),
    ] {
        let transplanted = HistoryQuery {
            project_id: project,
            instance_id: Some(instance),
            limit: Some(1),
            cursor: Some(first_cursor.clone()),
        };
        let denied = database
            .list_automation_notifications(reader, &transplanted, &signer)
            .await
            .err()
            .context("A transplanted history cursor unexpectedly succeeded")?;
        ensure!(denied.status == StatusCode::BAD_REQUEST && denied.code == "INVALID_CURSOR");
    }
    for id in [unknown_id, failed_id] {
        let hidden = database
            .get_automation_notification(&other_actor, id)
            .await
            .err()
            .context("Cross-tenant notification read unexpectedly succeeded")?;
        ensure!(hidden.status == StatusCode::NOT_FOUND);
    }
    let hidden = database
        .acknowledge_automation_notification(
            &other_actor,
            &other_signed.identity,
            failed_id,
            "foreign-failed-ack",
            1,
        )
        .await
        .err()
        .context("Cross-tenant FAILED acknowledgement unexpectedly succeeded")?;
    ensure!(hidden.status == StatusCode::NOT_FOUND);

    let before_replay = facts(owner, scope, false).await?;
    let replay = database
        .acknowledge_automation_notification(&actor, &signed.identity, unknown_id, &unknown_key, 1)
        .await
        .map_err(api_failure)?;
    ensure!(
        replay.status == 200
            && serde_json::to_value(replay.body)? == unknown_receipt
            && facts(owner, scope, false).await? == before_replay,
        "A resolved run must still replay its original UNKNOWN key and ETag without rewriting history"
    );
    // The target ID scopes idempotency. Reusing the same textual key for a
    // distinct notice must produce its own receipt, never the UNKNOWN body.
    let failed_key = unknown_key.clone();
    let acknowledged = database
        .acknowledge_automation_notification(&actor, &signed.identity, failed_id, &failed_key, 1)
        .await
        .map_err(api_failure)?;
    ensure!(
        acknowledged.status == 200
            && acknowledged.body.resource.version == 2
            && acknowledged.body.resource.acknowledged_by == Some(scope.principal)
    );
    let failed_receipt = serde_json::to_value(acknowledged.body)?;
    ensure!(
        failed_receipt["resource"]["id"] == json!(failed_id)
            && failed_receipt["resource"]["source_status"] == "FAILED"
            && failed_receipt != unknown_receipt,
        "A shared textual key across targets replayed the wrong notification receipt"
    );
    let after_ack = facts(owner, scope, false).await?;
    let replay = database
        .acknowledge_automation_notification(&actor, &signed.identity, failed_id, &failed_key, 1)
        .await
        .map_err(api_failure)?;
    ensure!(
        replay.status == 200
            && serde_json::to_value(replay.body)? == failed_receipt
            && facts(owner, scope, false).await? == after_ack,
        "FAILED replay duplicated its receipt, audit or causal event"
    );
    let replay = database
        .acknowledge_automation_notification(&actor, &signed.identity, unknown_id, &unknown_key, 1)
        .await
        .map_err(api_failure)?;
    ensure!(
        replay.status == 200
            && serde_json::to_value(replay.body)? == unknown_receipt
            && facts(owner, scope, false).await? == after_ack,
        "Independent target receipts did not replay their own original bodies"
    );
    ensure!(
        facts(owner, scope, true).await? == business_after
            && source(owner, scope, failed_id).await? == failed_source_before
            && serde_json::to_value(
                database
                    .get_automation_notification(&actor, unknown_id)
                    .await
                    .map_err(api_failure)?
            )? == unknown_before,
        "FAILED ACK modified the completed run, UNKNOWN source or other business facts"
    );
    set_grant(owner, scope, "automations:write", false).await?;
    let denied = database
        .acknowledge_automation_notification(&actor, &signed.identity, failed_id, &failed_key, 1)
        .await
        .err()
        .context("Revoked current writer replayed its historical FAILED receipt")?;
    ensure!(denied.status == StatusCode::NOT_FOUND);
    set_grant(owner, scope, "automations:write", true).await?;
    ensure!(
        facts(owner, scope, false).await? == after_ack,
        "Denied FAILED replay modified committed history"
    );
    let mut tx = tenant_tx(owner, scope.tenant).await?;
    let ack_count: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM management_receipts WHERE tenant_id=$1 AND action=$2 AND target_id=$3),(SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action=$2 AND resource_id=$3 AND request_id=$4),(SELECT count(*) FROM domain_events WHERE tenant_id=$1 AND aggregate_id=$3 AND event_type='automation-notifications:acknowledged' AND request_id=$5)")
        .bind(scope.tenant).bind(ACTION).bind(failed_id).bind(actor.request_id).bind(run).fetch_one(&mut *tx).await?;
    ensure!(
        ack_count == (1, 1, 1),
        "FAILED must have exactly one receipt, one transport audit and one causal ACK event"
    );
    for (id, before) in [
        (unknown_id, unknown_event_before),
        (failed_id, failed_event_before),
    ] {
        let current: Value = sqlx::query_scalar(
            "SELECT to_jsonb(e) FROM domain_events e WHERE tenant_id=$1 AND id=$2",
        )
        .bind(scope.tenant)
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        ensure!(
            current == before,
            "Acknowledgement changed its original source event"
        );
    }
    tx.commit().await?;
    let history_after = facts(owner, scope, false).await?;
    for (table, column) in [
        ("automation_notifications", "id"),
        ("management_receipts", "target_id"),
        ("audit_events", "resource_id"),
        ("domain_events", "aggregate_id"),
    ] {
        let original: Vec<_> = history_before[table]
            .as_array()
            .context("Original notification history missing")?
            .iter()
            .filter(|row| row[column] == json!(unknown_id))
            .collect();
        let current: Vec<_> = history_after[table]
            .as_array()
            .context("Current notification history missing")?
            .iter()
            .filter(|row| row[column] == json!(unknown_id))
            .collect();
        ensure!(
            original == current,
            "FAILED progression or ACK changed existing UNKNOWN {table}"
        );
    }
    ensure!(
        super::snapshot(owner, &scopes[1..]).await? == other_before,
        "Progression or acknowledgement modified another tenant's complete historical facts"
    );
    for (scope, before) in scopes[1..].iter().zip(other_notifications) {
        ensure!(
            facts(owner, scope, false).await? == before,
            "Progression modified another tenant's notification or event history"
        );
    }
    Ok(())
}
