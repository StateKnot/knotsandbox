//! Explicit loopback integration: real Keycloak, Chrome, compiled console and
//! production BFF/API/PG transactions. No synthetic tokens or response bodies.
//! Actual committed account PATCH and diagnosis POST responses are dropped by
//! Chrome's driver to exercise durable same-key retry; API results stay real.
//! The test-only OIDC transport permits literal loopback HTTP to the real IdP;
//! frontend TLS uses a public fixture and does not certify cloud PKI or HA.
use super::*;
use crate::{
    auth::{AuthConfig, JwtAuthenticator},
    bff_crypto::SessionKeys,
    bff_oidc::{BrowserOidc, OidcSettings},
    engine::OperationEngine,
    history::CursorSigner,
    test_support_db as support,
};
use anyhow::{Context, ensure};
use axum::{Extension, extract::OriginalUri, http::Uri};
use axum_server::tls_rustls::RustlsConfig;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::FutureExt;
use serde_json::{Value, json};
use std::{net::TcpListener, path::PathBuf, process::Stdio};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[path = "bff_notification_live_tests.rs"]
mod notifications;

#[derive(Clone)]
struct CallbackDiagnostics {
    owner: sqlx::PgPool,
    tenant: Uuid,
    issuer: String,
}
async fn diagnose_callback(
    State(scope): State<CallbackDiagnostics>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if request.uri().path() != "/auth/callback" {
        return next.run(request).await;
    }
    let has_binding = cookie(request.headers(), LOGIN_COOKIE).is_ok_and(|v| v.is_some());
    let fields: std::collections::BTreeMap<_, _> =
        url::form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes()).collect();
    let issuer_matches = fields.get("iss").is_none_or(|v| v == &scope.issuer);
    let has_code = fields.contains_key("code");
    let provider_error = fields.contains_key("error");
    let response = next.run(request).await;
    if response.status().is_client_error() || response.status().is_server_error() {
        // Counts/booleans only. Never print query values, cookies, tokens or
        // provider error bodies, even when this explicit integration fails.
        if let Ok(mut tx) = scope.owner.begin().await {
            let _ = sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
                .bind(scope.tenant.to_string())
                .execute(&mut *tx)
                .await;
            let counts: Result<(i64,i64), _> = sqlx::query_as("SELECT (SELECT count(*) FROM browser_login_challenges WHERE tenant_id=$1 AND consumed_at IS NOT NULL),(SELECT count(*) FROM browser_sessions WHERE tenant_id=$1)").bind(scope.tenant).fetch_one(&mut *tx).await;
            if let Ok((consumed, sessions)) = counts {
                eprintln!(
                    "LOCAL_CALLBACK_DIAGNOSTICS {}",
                    json!({"binding_present":has_binding,"issuer_matches":issuer_matches,"code_present":has_code,"provider_error":provider_error,"consumed_challenges":consumed,"sessions":sessions})
                );
            }
        }
    }
    response
}

fn required(name: &str) -> anyhow::Result<String> {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .with_context(|| format!("Live browser test requires {name}"))
}

#[derive(Clone)]
struct IdpProxy {
    backend: String,
    realm: String,
    client: reqwest::Client,
}
async fn proxy_idp(
    State(proxy): State<IdpProxy>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !(uri.path().starts_with(&format!("/realms/{}/", proxy.realm))
        || uri.path().starts_with("/resources/"))
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut request = proxy.client.request(
        method,
        format!(
            "{}{}",
            proxy.backend,
            uri.path_and_query().map_or("/", |v| v.as_str())
        ),
    );
    for name in ["content-type", "cookie", "accept", "user-agent"] {
        if let Some(value) = headers.get(name) {
            request = request.header(name, value);
        }
    }
    let Ok(response) = request.body(body).send().await else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let status = response.status();
    let headers = response.headers().clone();
    let Ok(bytes) = response.bytes().await else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    if bytes.len() > 2 * 1024 * 1024 {
        return StatusCode::BAD_GATEWAY.into_response();
    }
    let mut out = (status, bytes).into_response();
    for (name, value) in &headers {
        if !["connection", "transfer-encoding", "content-length"].contains(&name.as_str()) {
            out.headers_mut().append(name, value.clone());
        }
    }
    out
}

async fn static_console(
    OriginalUri(uri): OriginalUri,
    Extension(root): Extension<PathBuf>,
) -> Response {
    // Serve only the reviewed built console, without a development proxy or any
    // endpoint replacement. Unknown API and auth paths remain true 404s.
    let path = uri.path();
    let file = if matches!(path, "/" | "/index.html") {
        "index.html"
    } else if path.starts_with("/assets/")
        && path[8..]
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"-_.".contains(&v))
        && !path[8..].is_empty()
    {
        &path[1..]
    } else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let target = root.join(file);
    let Ok(bytes) = tokio::fs::read(target).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if bytes.len() > 2 * 1024 * 1024 {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let mime = if file.ends_with(".js") {
        "text/javascript"
    } else if file.ends_with(".css") {
        "text/css"
    } else {
        "text/html; charset=utf-8"
    };
    (
        [("content-type", mime), ("cache-control", "no-store")],
        bytes,
    )
        .into_response()
}

async fn serve_https(
    listener: TcpListener,
    router: Router,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    listener.set_nonblocking(true)?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = RustlsConfig::from_pem(
        include_bytes!("../tests/fixtures/admission/server.pem").to_vec(),
        include_bytes!("../tests/fixtures/admission/server.key").to_vec(),
    )
    .await?;
    let server = axum_server::from_tcp_rustls(listener, config)?;
    Ok(tokio::spawn(async move {
        let _ = server.serve(router.into_make_service()).await;
    }))
}

async fn exchange_admin(client: &reqwest::Client, backend: &str) -> anyhow::Result<String> {
    let password = required("SANDBOX_KEYCLOAK_ADMIN_PASSWORD")?;
    let response = client
        .post(format!(
            "{backend}/realms/master/protocol/openid-connect/token"
        ))
        .form(&[
            ("grant_type", "password"),
            ("client_id", "admin-cli"),
            ("username", "sandbox-dev-admin"),
            ("password", password.as_str()),
        ])
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::OK,
        "Local Keycloak admin authentication failed"
    );
    let body: Value = response.json().await?;
    body.get("access_token")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .context("Keycloak administrator response lacks an access token")
}

async fn phase(
    reader: &mut BufReader<tokio::process::ChildStdout>,
    expected: &str,
) -> anyhow::Result<()> {
    let mut line = String::new();
    let count =
        tokio::time::timeout(Duration::from_secs(45), reader.read_line(&mut line)).await??;
    ensure!(
        count > 0 && count <= 256,
        "Browser driver ended before the expected phase"
    );
    let receipt: Value = serde_json::from_str(&line)?;
    ensure!(
        receipt == json!({"phase": expected}),
        "Unexpected browser coordination phase"
    );
    Ok(())
}

async fn diagnosis_facts(fixture: &support::Fixture, instance: Uuid) -> anyhow::Result<Value> {
    let mut tx = fixture.owner_transaction().await?;
    let facts: Value = sqlx::query_scalar("SELECT jsonb_build_object('instance',to_jsonb(i),'workspace',to_jsonb(w),'executions',(SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY e.id),'[]'::jsonb) FROM executions e WHERE e.tenant_id=i.tenant_id AND e.instance_id=i.id)) FROM instances i JOIN workspaces w ON(w.tenant_id,w.project_id,w.id)=(i.tenant_id,i.project_id,i.workspace_id) WHERE i.tenant_id=$1 AND i.id=$2")
        .bind(fixture.actor.tenant_id).bind(instance).fetch_one(&mut *tx).await?;
    ensure!(
        facts["instance"].is_object()
            && facts["workspace"].is_object()
            && facts["executions"].is_array()
            && facts["instance"]["id"] == json!(instance)
            && facts["instance"]["tenant_id"] == json!(fixture.actor.tenant_id)
            && facts["workspace"]["id"] == facts["instance"]["workspace_id"]
            && facts["workspace"]["tenant_id"] == json!(fixture.actor.tenant_id),
        "diagnosis facts must contain the actual tenant instance/workspace and all activity rows"
    );
    tx.commit().await?;
    Ok(facts)
}

// The existing owner fixture controls grants and dispatch timing only. The
// report is published by the authenticated normal worker through production
// claim/reconcile, without a fabricated report or lifecycle reconciliation.
async fn browser_diagnoses(
    fixture: &support::Fixture,
    verified: &support::VerifiedFixtureConnections,
    instance: Uuid,
    before: &Value,
    input: &mut tokio::process::ChildStdin,
    output: &mut BufReader<tokio::process::ChildStdout>,
) -> anyhow::Result<()> {
    phase(output, "diagnoses_replayed").await?;
    let mut tx = fixture.owner_transaction().await?;
    let counts: (i64, i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM diagnoses WHERE tenant_id=$1 AND instance_id=$2 AND actor_principal_id=$3),(SELECT count(*) FROM operations WHERE tenant_id=$1 AND instance_id=$2 AND actor_principal_id=$3 AND kind='DIAGNOSE'),(SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND actor_principal_id=$3 AND action='diagnoses:create' AND outcome='ACCEPTED'),(SELECT count(*) FROM idempotency_keys WHERE tenant_id=$1 AND principal_id=$3 AND target_id=$2 AND operation_name='diagnoses:create')")
        .bind(fixture.actor.tenant_id).bind(instance).bind(fixture.actor.principal_id).fetch_one(&mut *tx).await?;
    ensure!(
        counts == (1, 1, 1, 1),
        "the actual lost POST reply and replay create exactly one diagnosis, operation, audit and idempotency receipt"
    );
    let stored: Value = sqlx::query_scalar("SELECT to_jsonb(d) FROM diagnoses d WHERE tenant_id=$1 AND instance_id=$2 AND actor_principal_id=$3")
        .bind(fixture.actor.tenant_id).bind(instance).bind(fixture.actor.principal_id).fetch_one(&mut *tx).await?;
    ensure!(
        stored["status"] == "PENDING"
            && stored["report"].is_null()
            && stored["include_operations"] == false
            && stored["include_executions"] == false,
        "the normal UI request keeps optional evidence disabled and has no pre-seeded report"
    );
    let operation = Uuid::parse_str(
        stored["operation_id"]
            .as_str()
            .context("diagnosis operation identity missing")?,
    )?;
    let diagnosis = Uuid::parse_str(
        stored["id"]
            .as_str()
            .context("diagnosis identity missing")?,
    )?;
    ensure!(
        stored["instance_id"] == json!(instance)
            && stored["project_id"] == json!(fixture.request.project_id)
            && stored["tenant_id"] == json!(fixture.actor.tenant_id),
        "diagnosis identity is the real requested tenant/project/instance"
    );
    // Same test scheduling hint used by the real diagnosis integration suite;
    // sandbox_claim_operation still supplies and authenticates the lease.
    sqlx::query("UPDATE operations SET next_attempt_at=(SELECT COALESCE(min(eligible_at),clock_timestamp())-interval '1 day' FROM operation_dispatch WHERE queue_role='WORKER'),lease_until=CASE WHEN lease_until IS NOT NULL THEN (SELECT COALESCE(min(eligible_at),clock_timestamp())-interval '1 day' FROM operation_dispatch WHERE queue_role='WORKER') ELSE NULL END WHERE tenant_id=$1 AND id=$2")
        .bind(fixture.actor.tenant_id).bind(operation).execute(&mut *tx).await?;
    tx.commit().await?;
    ensure!(
        &diagnosis_facts(fixture, instance).await? == before,
        "diagnosis acceptance/replay never changes the full instance/workspace/activity rows"
    );
    let worker = verified
        .runtime("TEST_WORKER_DATABASE_URL", "sandbox_worker", 4)
        .await?
        .database_for("sandbox_worker")?;
    crate::service_lifecycle::with_database_drain(worker.pool.clone(), async {
        let engine = OperationEngine::new(
            worker.clone(),
            format!("browser-diagnosis-{}", Uuid::new_v4()),
        )?;
        let claim = engine
            .claim()
            .await
            .map_err(support::api_failure)?
            .context("normal worker diagnosis claim missing")?;
        ensure!(
            claim.tenant_id == fixture.actor.tenant_id && claim.operation_id == operation,
            "the normal worker must claim this exact browser diagnosis"
        );
        worker
            .reconcile_diagnosis(&engine, &claim)
            .await
            .map_err(support::api_failure)?;
        Ok(())
    })
    .await?;
    let mut tx = fixture.owner_transaction().await?;
    let complete: Value =
        sqlx::query_scalar("SELECT to_jsonb(d) FROM diagnoses d WHERE tenant_id=$1 AND id=$2")
            .bind(fixture.actor.tenant_id)
            .bind(diagnosis)
            .fetch_one(&mut *tx)
            .await?;
    ensure!(
        complete["status"] == "COMPLETE"
            && complete["report"].is_object()
            && complete["snapshot_at"].is_string()
            && complete["completed_at"].is_string()
            && complete["instance_id"] == json!(instance)
            && complete["operation_id"] == json!(operation),
        "the production worker publishes a complete report with the original identity"
    );
    let completion: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM operations WHERE tenant_id=$1 AND id=$2 AND kind='DIAGNOSE' AND status='SUCCEEDED' AND stage='DIAGNOSIS_COMPLETE' AND lease_owner IS NULL AND lease_until IS NULL),(SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND operation_id=$2 AND resource_id=$3 AND action='diagnoses:complete' AND outcome='SUCCEEDED'),(SELECT count(*) FROM domain_events WHERE tenant_id=$1 AND operation_id=$2 AND aggregate_id=$3 AND event_type='diagnoses.completed')")
        .bind(fixture.actor.tenant_id).bind(operation).bind(diagnosis).fetch_one(&mut *tx).await?;
    ensure!(
        completion == (1, 1, 1),
        "one normal completion operation/audit/event and released worker lease"
    );
    tx.commit().await?;
    ensure!(
        &diagnosis_facts(fixture, instance).await? == before,
        "report publication leaves the whole instance/workspace/activity rows unchanged"
    );
    input
        .write_all(b"{\"phase\":\"diagnosis_complete\"}\n")
        .await?;
    phase(output, "diagnosis_report_checked").await?;
    let mut tx = fixture.owner_transaction().await?;
    let revoked = sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND project_id=$2 AND principal_id=$3 AND action='diagnoses:read' AND enabled AND revoked_at IS NULL")
        .bind(fixture.actor.tenant_id).bind(fixture.request.project_id).bind(fixture.actor.principal_id).execute(&mut *tx).await?;
    ensure!(
        revoked.rows_affected() == 1,
        "revoke this browser actor's one real diagnosis read grant"
    );
    tx.commit().await?;
    input
        .write_all(b"{\"phase\":\"diagnosis_read_revoked\"}\n")
        .await?;
    phase(output, "diagnosis_read_denied").await?;
    let mut tx = fixture.owner_transaction().await?;
    let restored = sqlx::query("UPDATE grants SET enabled=true WHERE tenant_id=$1 AND project_id=$2 AND principal_id=$3 AND action IN('diagnoses:read','operations:read') AND NOT enabled AND revoked_at IS NULL")
        .bind(fixture.actor.tenant_id).bind(fixture.request.project_id).bind(fixture.actor.principal_id).execute(&mut *tx).await?;
    ensure!(
        restored.rows_affected() == 2,
        "restore diagnosis read and the original operation read grant before the old stop chain"
    );
    tx.commit().await?;
    input
        .write_all(b"{\"phase\":\"diagnosis_permissions_restored\"}\n")
        .await?;
    phase(output, "diagnoses_complete").await?;
    ensure!(
        &diagnosis_facts(fixture, instance).await? == before,
        "report reads/revocation/recovery leave all original instance/workspace/activity facts intact"
    );
    input
        .write_all(b"{\"phase\":\"diagnoses_checked\"}\n")
        .await?;
    println!(
        "VERIFIED real Chrome control-plane diagnosis: health capability remains false; committed POST lost reply/reload same-key body replay is unique; normal worker claim/reconcile COMPLETE structured evidence and Requests report without operations:read; real diagnosis-read revocation 404 clears evidence; full instance/workspace/activity rows unchanged; original permissions restored before stop"
    );
    Ok(())
}

// This event consumer fixture changes only its events:read grant and the
// scheduling hint for its newly accepted exact DIAGNOSE operation. Domain
// events/stream positions are created solely by normal API/worker transactions.
async fn browser_events(
    fixture: &support::Fixture,
    verified: &support::VerifiedFixtureConnections,
    instance: Uuid,
    before: &Value,
    input: &mut tokio::process::ChildStdin,
    output: &mut BufReader<tokio::process::ChildStdout>,
) -> anyhow::Result<()> {
    phase(output, "events_accepted_stopped").await?;
    let mut tx = fixture.owner_transaction().await?;
    let accepted: Value = sqlx::query_scalar("SELECT to_jsonb(d) FROM diagnoses d WHERE tenant_id=$1 AND instance_id=$2 AND actor_principal_id=$3 AND status='PENDING'")
        .bind(fixture.actor.tenant_id).bind(instance).bind(fixture.actor.principal_id).fetch_one(&mut *tx).await?;
    let diagnosis = Uuid::parse_str(
        accepted["id"]
            .as_str()
            .context("event producer diagnosis identity missing")?,
    )?;
    let operation = Uuid::parse_str(
        accepted["operation_id"]
            .as_str()
            .context("event producer operation identity missing")?,
    )?;
    ensure!(
        accepted["tenant_id"] == json!(fixture.actor.tenant_id)
            && accepted["project_id"] == json!(fixture.request.project_id)
            && accepted["instance_id"] == json!(instance)
            && accepted["include_operations"] == false
            && accepted["include_executions"] == false
            && accepted["report"].is_null()
            && accepted["completed_at"].is_null(),
        "the real CSRF HTTP producer accepts only its new pending diagnosis without a report"
    );
    let counts: (i64,i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM diagnoses WHERE tenant_id=$1 AND instance_id=$2 AND actor_principal_id=$3),(SELECT count(*) FROM operations WHERE tenant_id=$1 AND id=$4 AND actor_principal_id=$3 AND kind='DIAGNOSE' AND status='QUEUED'),(SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND operation_id=$4 AND resource_id=$5 AND action='diagnoses:create' AND outcome='ACCEPTED'),(SELECT count(*) FROM domain_events WHERE tenant_id=$1 AND operation_id=$4 AND aggregate_id=$5 AND event_type='diagnoses.accepted'),(SELECT count(*) FROM idempotency_keys WHERE tenant_id=$1 AND principal_id=$3 AND target_id=$2 AND operation_name='diagnoses:create')")
        .bind(fixture.actor.tenant_id).bind(instance).bind(fixture.actor.principal_id).bind(operation).bind(diagnosis).fetch_one(&mut *tx).await?;
    ensure!(
        counts == (2, 1, 1, 1, 2),
        "one additional normal diagnosis/operation/audit/event/receipt; old diagnosis remains intact"
    );
    let accepted_sequence: i64 = sqlx::query_scalar("SELECT p.sequence FROM domain_events e JOIN event_stream_positions p ON(p.tenant_id,p.project_id,p.event_id)=(e.tenant_id,e.project_id,e.id) WHERE e.tenant_id=$1 AND e.project_id=$2 AND e.operation_id=$3 AND e.aggregate_id=$4 AND e.event_type='diagnoses.accepted'")
        .bind(fixture.actor.tenant_id).bind(fixture.request.project_id).bind(operation).bind(diagnosis).fetch_one(&mut *tx).await?;
    // The same normal worker claim scheduling seam as browser_diagnoses.
    sqlx::query("UPDATE operations SET next_attempt_at=(SELECT COALESCE(min(eligible_at),clock_timestamp())-interval '1 day' FROM operation_dispatch WHERE queue_role='WORKER'),lease_until=CASE WHEN lease_until IS NOT NULL THEN (SELECT COALESCE(min(eligible_at),clock_timestamp())-interval '1 day' FROM operation_dispatch WHERE queue_role='WORKER') ELSE NULL END WHERE tenant_id=$1 AND id=$2")
        .bind(fixture.actor.tenant_id).bind(operation).execute(&mut *tx).await?;
    tx.commit().await?;
    ensure!(
        &diagnosis_facts(fixture, instance).await? == before,
        "event production does not mutate the full instance/workspace/activity facts"
    );
    let worker = verified
        .runtime("TEST_WORKER_DATABASE_URL", "sandbox_worker", 4)
        .await?
        .database_for("sandbox_worker")?;
    crate::service_lifecycle::with_database_drain(worker.pool.clone(), async {
        let engine =
            OperationEngine::new(worker.clone(), format!("browser-events-{}", Uuid::new_v4()))?;
        let claim = engine
            .claim()
            .await
            .map_err(support::api_failure)?
            .context("normal event producer worker claim missing")?;
        ensure!(
            claim.tenant_id == fixture.actor.tenant_id && claim.operation_id == operation,
            "normal worker claims this exact browser event producer"
        );
        worker
            .reconcile_diagnosis(&engine, &claim)
            .await
            .map_err(support::api_failure)?;
        Ok(())
    })
    .await?;
    let mut tx = fixture.owner_transaction().await?;
    let complete: Value =
        sqlx::query_scalar("SELECT to_jsonb(d) FROM diagnoses d WHERE tenant_id=$1 AND id=$2")
            .bind(fixture.actor.tenant_id)
            .bind(diagnosis)
            .fetch_one(&mut *tx)
            .await?;
    ensure!(
        complete["status"] == "COMPLETE"
            && complete["report"].is_object()
            && complete["operation_id"] == json!(operation)
            && complete["instance_id"] == json!(instance)
            && complete["project_id"] == json!(fixture.request.project_id)
            && complete["tenant_id"] == json!(fixture.actor.tenant_id),
        "the normal worker publishes the original event producer report"
    );
    let completion: (i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM operations WHERE tenant_id=$1 AND id=$2 AND kind='DIAGNOSE' AND status='SUCCEEDED' AND stage='DIAGNOSIS_COMPLETE' AND lease_owner IS NULL AND lease_until IS NULL),(SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND operation_id=$2 AND resource_id=$3 AND action='diagnoses:complete' AND outcome='SUCCEEDED'),(SELECT count(*) FROM domain_events WHERE tenant_id=$1 AND operation_id=$2 AND aggregate_id=$3 AND event_type='diagnoses.completed')")
        .bind(fixture.actor.tenant_id).bind(operation).bind(diagnosis).fetch_one(&mut *tx).await?;
    ensure!(
        completion == (1, 1, 1),
        "normal completion operation/audit/event each persist once"
    );
    let positions: (i64,i64,i64) = sqlx::query_as("SELECT count(*),min(p.sequence),max(p.sequence) FROM domain_events e JOIN event_stream_positions p ON(p.tenant_id,p.project_id,p.event_id)=(e.tenant_id,e.project_id,e.id) WHERE e.tenant_id=$1 AND e.project_id=$2 AND e.operation_id=$3 AND e.aggregate_id=$4 AND e.event_type IN('diagnoses.accepted','diagnoses.completed')")
        .bind(fixture.actor.tenant_id).bind(fixture.request.project_id).bind(operation).bind(diagnosis).fetch_one(&mut *tx).await?;
    ensure!(
        positions == (2, accepted_sequence, accepted_sequence + 1),
        "the two real domain events have unique consecutive committed stream positions"
    );
    tx.commit().await?;
    ensure!(
        &diagnosis_facts(fixture, instance).await? == before,
        "normal event producer completion leaves full instance/workspace/activity facts unchanged"
    );
    input
        .write_all(b"{\"phase\":\"events_diagnosis_complete\"}\n")
        .await?;
    phase(output, "events_completed_received").await?;
    let mut tx = fixture.owner_transaction().await?;
    let revoked = sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND project_id=$2 AND principal_id=$3 AND action='events:read' AND enabled AND revoked_at IS NULL")
        .bind(fixture.actor.tenant_id).bind(fixture.request.project_id).bind(fixture.actor.principal_id).execute(&mut *tx).await?;
    ensure!(
        revoked.rows_affected() == 1,
        "disable only this actor's one events read grant"
    );
    tx.commit().await?;
    input
        .write_all(b"{\"phase\":\"events_read_revoked\"}\n")
        .await?;
    phase(output, "events_read_denied").await?;
    let mut tx = fixture.owner_transaction().await?;
    let restored = sqlx::query("UPDATE grants SET enabled=true WHERE tenant_id=$1 AND project_id=$2 AND principal_id=$3 AND action='events:read' AND NOT enabled AND revoked_at IS NULL")
        .bind(fixture.actor.tenant_id).bind(fixture.request.project_id).bind(fixture.actor.principal_id).execute(&mut *tx).await?;
    ensure!(
        restored.rows_affected() == 1,
        "restore only the original events read grant"
    );
    tx.commit().await?;
    input
        .write_all(b"{\"phase\":\"events_read_restored\"}\n")
        .await?;
    phase(output, "events_complete").await?;
    ensure!(
        &diagnosis_facts(fixture, instance).await? == before,
        "event reads/reconnection/revocation never mutate instance/workspace/activity facts"
    );
    input.write_all(b"{\"phase\":\"events_checked\"}\n").await?;
    println!(
        "VERIFIED real Chrome BFF project events: cookie-only GET checkpoint before actual CSRF diagnosis POST; accepted event, stop with original cursor, normal worker completion, exact Last-Event-ID replay of completed event; real events:read revocation clears cached events and restores only through explicit baseline; unique persisted event positions/audits and unchanged full instance/workspace/activity facts"
    );
    Ok(())
}

// The normal formal automation API owns every policy/delegation mutation. This
// helper only changes the existing actor's read grants and observes committed
// facts through tenant-scoped owner transactions; no scheduler is started.
async fn browser_automations(
    fixture: &support::Fixture,
    instance: Uuid,
    before: &Value,
    input: &mut tokio::process::ChildStdin,
    output: &mut BufReader<tokio::process::ChildStdout>,
) -> anyhow::Result<()> {
    phase(output, "automations_ready").await?;
    let mut tx = fixture.owner_transaction().await?;
    let operations: Value = sqlx::query_scalar("SELECT COALESCE(jsonb_agg(to_jsonb(o) ORDER BY o.id),'[]'::jsonb) FROM operations o WHERE o.tenant_id=$1 AND o.instance_id=$2")
        .bind(fixture.actor.tenant_id).bind(instance).fetch_one(&mut *tx).await?;
    let initial: (i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM automations WHERE tenant_id=$1 AND instance_id=$2),(SELECT count(*) FROM automation_delegations WHERE tenant_id=$1 AND instance_id=$2),(SELECT count(*) FROM grants WHERE tenant_id=$1 AND project_id=$3 AND principal_id=$4 AND action='instances:renew' AND enabled AND revoked_at IS NULL AND(expires_at IS NULL OR expires_at>clock_timestamp()))")
        .bind(fixture.actor.tenant_id).bind(instance).bind(fixture.request.project_id).bind(fixture.actor.principal_id).fetch_one(&mut *tx).await?;
    ensure!(
        operations.is_array() && initial == (0, 0, 1),
        "automation starts with no policy/delegation and exactly the actor's existing RENEW grant"
    );
    tx.commit().await?;
    ensure!(
        &diagnosis_facts(fixture, instance).await? == before,
        "automation entry preserves all instance/workspace/execution facts"
    );
    input
        .write_all(b"{\"phase\":\"automations_start\"}\n")
        .await?;
    phase(output, "automations_replayed").await?;
    let mut tx = fixture.owner_transaction().await?;
    let accepted: Value = sqlx::query_scalar("SELECT jsonb_build_object('policy',to_jsonb(a),'delegation',to_jsonb(d),'future',a.scheduled_at>clock_timestamp()+interval '10 minutes' AND a.scheduled_at<d.expires_at AND d.expires_at<clock_timestamp()+interval '2 hours') FROM automations a JOIN automation_delegations d ON(d.tenant_id,d.project_id,d.id)=(a.tenant_id,a.project_id,a.delegation_id) WHERE a.tenant_id=$1 AND a.instance_id=$2 AND a.creator_principal_id=$3")
        .bind(fixture.actor.tenant_id).bind(instance).bind(fixture.actor.principal_id).fetch_one(&mut *tx).await?;
    let policy = &accepted["policy"];
    let id = Uuid::parse_str(
        policy["id"]
            .as_str()
            .context("actual automation policy identity missing")?,
    )?;
    ensure!(
        policy.is_object()
            && accepted["delegation"].is_object()
            && policy["tenant_id"] == json!(fixture.actor.tenant_id)
            && policy["project_id"] == json!(fixture.request.project_id)
            && policy["instance_id"] == json!(instance)
            && policy["workspace_id"] == before["workspace"]["id"]
            && policy["creator_principal_id"] == json!(fixture.actor.principal_id)
            && policy["status"] == "ACTIVE"
            && policy["version"] == 1
            && policy["action"] == json!({"kind":"RENEW","ttl_seconds":3600})
            && policy["trigger_kind"] == "ONCE"
            && policy["run_budget"] == 1
            && policy["emitted_runs"] == 0
            && policy["minimum_interval_seconds"] == 60
            && policy["grace_seconds"] == 300
            && accepted["future"] == true
            && accepted["delegation"]["tenant_id"] == policy["tenant_id"]
            && accepted["delegation"]["project_id"] == policy["project_id"]
            && accepted["delegation"]["instance_id"] == policy["instance_id"]
            && accepted["delegation"]["workspace_id"] == policy["workspace_id"]
            && accepted["delegation"]["principal_id"] == policy["creator_principal_id"]
            && accepted["delegation"]["id"] == policy["delegation_id"]
            && accepted["delegation"]["allowed_actions"]
                == json!(["instances:renew", "automations:write"])
            && accepted["delegation"]["revoked_at"].is_null(),
        "the real HTTP policy is bounded future ONCE RENEW and linked to its exact actor delegation"
    );
    let replay: (i64,i64,i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM automations WHERE tenant_id=$1 AND instance_id=$2),(SELECT count(*) FROM automation_delegations WHERE tenant_id=$1 AND instance_id=$2),(SELECT count(*) FROM management_receipts WHERE tenant_id=$1 AND principal_id=$3 AND target_id=$2 AND resource_id=$4 AND action='automations:create' AND response_status=201),(SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND actor_principal_id=$3 AND resource_id=$4 AND action='automations:create' AND outcome='ACCEPTED'),(SELECT count(*) FROM domain_events WHERE tenant_id=$1 AND aggregate_id=$4 AND event_type='automations:create.changed'),(SELECT count(*) FROM automation_runs WHERE tenant_id=$1 AND automation_id=$4)")
        .bind(fixture.actor.tenant_id).bind(instance).bind(fixture.actor.principal_id).bind(id).fetch_one(&mut *tx).await?;
    ensure!(
        replay == (1, 1, 1, 1, 1, 0),
        "lost-ACK original-key UI replay commits one policy/delegation/receipt/audit/event and no run"
    );
    let revoked = sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND project_id=$2 AND principal_id=$3 AND action='operations:read' AND enabled AND revoked_at IS NULL")
        .bind(fixture.actor.tenant_id).bind(fixture.request.project_id).bind(fixture.actor.principal_id).execute(&mut *tx).await?;
    ensure!(
        revoked.rows_affected() == 1,
        "disable exactly the real operation-read grant for automation metadata reads"
    );
    tx.commit().await?;
    input
        .write_all(b"{\"phase\":\"automation_operation_read_revoked\"}\n")
        .await?;
    phase(output, "automations_changed").await?;
    let mut tx = fixture.owner_transaction().await?;
    let changed: Value = sqlx::query_scalar("SELECT jsonb_build_object('policy',to_jsonb(a),'delegation',to_jsonb(d)) FROM automations a JOIN automation_delegations d ON(d.tenant_id,d.project_id,d.id)=(a.tenant_id,a.project_id,a.delegation_id) WHERE a.tenant_id=$1 AND a.id=$2")
        .bind(fixture.actor.tenant_id).bind(id).fetch_one(&mut *tx).await?;
    ensure!(
        changed["policy"].is_object()
            && changed["delegation"].is_object()
            && changed["policy"]["id"] == json!(id)
            && changed["policy"]["status"] == "REVOKED"
            && changed["policy"]["version"] == 4
            && changed["delegation"]["revoked_at"].is_string(),
        "pause/resume/permanent revoke publish the original policy's successive versions"
    );
    let mut expected_policy = accepted["policy"].clone();
    expected_policy["status"] = json!("REVOKED");
    expected_policy["version"] = json!(4);
    expected_policy["updated_at"] = changed["policy"]["updated_at"].clone();
    let mut expected_delegation = accepted["delegation"].clone();
    expected_delegation["revoked_at"] = changed["delegation"]["revoked_at"].clone();
    ensure!(
        changed["policy"] == expected_policy && changed["delegation"] == expected_delegation,
        "all original policy/delegation fields remain equal except exact normal transition fields"
    );
    let counts: (i64,i64,i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM management_receipts WHERE tenant_id=$1 AND principal_id=$2 AND resource_id=$3 AND action='automations:create'),(SELECT count(*) FROM management_receipts WHERE tenant_id=$1 AND principal_id=$2 AND target_id=$3 AND resource_id=$3 AND action='automations:change' AND response_status=200),(SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND actor_principal_id=$2 AND resource_id=$3 AND action='automations:create' AND outcome='ACCEPTED'),(SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND actor_principal_id=$2 AND resource_id=$3 AND action='automations:change' AND outcome='ACCEPTED'),(SELECT count(*) FROM domain_events WHERE tenant_id=$1 AND aggregate_id=$3 AND event_type IN('automations:create.changed','automations:change.changed')),(SELECT count(*) FROM automation_runs WHERE tenant_id=$1 AND automation_id=$3)")
        .bind(fixture.actor.tenant_id).bind(fixture.actor.principal_id).bind(id).fetch_one(&mut *tx).await?;
    ensure!(
        counts == (1, 3, 1, 3, 4, 0),
        "normal create/pause/resume/revoke each persist once; failed CSRF/stale-version requests create no receipt/audit/event/run"
    );
    let current_operations: Value = sqlx::query_scalar("SELECT COALESCE(jsonb_agg(to_jsonb(o) ORDER BY o.id),'[]'::jsonb) FROM operations o WHERE o.tenant_id=$1 AND o.instance_id=$2")
        .bind(fixture.actor.tenant_id).bind(instance).fetch_one(&mut *tx).await?;
    ensure!(
        current_operations == operations,
        "future policy management does not create or mutate any instance operation"
    );
    let revoked = sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND project_id=$2 AND principal_id=$3 AND action='automations:read' AND enabled AND revoked_at IS NULL")
        .bind(fixture.actor.tenant_id).bind(fixture.request.project_id).bind(fixture.actor.principal_id).execute(&mut *tx).await?;
    ensure!(
        revoked.rows_affected() == 1,
        "disable exactly the original automation-read grant"
    );
    tx.commit().await?;
    ensure!(
        &diagnosis_facts(fixture, instance).await? == before,
        "policy management preserves the entire instance/workspace/execution snapshot"
    );
    input
        .write_all(b"{\"phase\":\"automation_read_revoked\"}\n")
        .await?;
    phase(output, "automation_read_denied").await?;
    let mut tx = fixture.owner_transaction().await?;
    let restored = sqlx::query("UPDATE grants SET enabled=true WHERE tenant_id=$1 AND project_id=$2 AND principal_id=$3 AND action IN('automations:read','operations:read') AND NOT enabled AND revoked_at IS NULL")
        .bind(fixture.actor.tenant_id).bind(fixture.request.project_id).bind(fixture.actor.principal_id).execute(&mut *tx).await?;
    ensure!(
        restored.rows_affected() == 2,
        "restore only the two original read grants before the existing stop/revocation chain"
    );
    tx.commit().await?;
    input
        .write_all(b"{\"phase\":\"automations_permissions_restored\"}\n")
        .await?;
    phase(output, "automations_complete").await?;
    ensure!(
        &diagnosis_facts(fixture, instance).await? == before,
        "automation metadata reads and permission changes preserve all instance/workspace/execution facts"
    );
    input
        .write_all(b"{\"phase\":\"automations_checked\"}\n")
        .await?;
    println!(
        "VERIFIED real Chrome BFF automations: future bounded ONCE RENEW normal CSRF creation; committed lost-ACK original-key/body/ETag reload replay; one policy/delegation/receipt/audit, pause/resume/revoke exact versions, stale ETag and CSRF rejection; runs without operations:read, real read revocation clears evidence; zero runs and unchanged full instance/workspace/execution/operation facts"
    );
    Ok(())
}

#[derive(Clone, Copy)]
enum ConsoleMode {
    Acceptance,
    Manual,
}

struct ManualDemo {
    directory: PathBuf,
    seconds: u64,
}

impl ManualDemo {
    fn from_environment() -> anyhow::Result<Self> {
        let directory = PathBuf::from(required("SANDBOX_BROWSER_EVIDENCE_DIR")?);
        let metadata = std::fs::symlink_metadata(&directory)?;
        ensure!(
            directory.is_absolute()
                && metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && directory.canonicalize()? == directory
                && !directory
                    .components()
                    .any(|component| component.as_os_str() == "target"),
            "Manual demo requires a canonical private evidence directory outside build caches"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                metadata.permissions().mode() & 0o777 == 0o700,
                "Manual demo evidence requires 0700 directory permissions"
            );
        }
        let seconds: u64 = required("SANDBOX_MANUAL_DEMO_SECONDS")?
            .parse()
            .context("Manual demo lifetime must be an integer")?;
        ensure!(
            (1800..=7200).contains(&seconds),
            "Manual demo lifetime must be 1800..7200 seconds"
        );
        Ok(Self { directory, seconds })
    }

    fn write_private(&self, name: &str, document: &Value) -> anyhow::Result<()> {
        let temporary = self
            .directory
            .join(format!(".demo-{}.tmp", Uuid::new_v4().simple()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        serde_json::to_writer(&mut file, document)?;
        file.sync_all()?;
        // Publish complete bytes atomically without replacing an existing
        // credential, readiness file or symlink, even on an interrupted retry.
        std::fs::hard_link(&temporary, self.directory.join(name))?;
        std::fs::remove_file(temporary)?;
        Ok(())
    }

    fn stopped(&self) -> anyhow::Result<bool> {
        match std::fs::symlink_metadata(self.directory.join("demo-stop")) {
            Ok(metadata) => {
                ensure!(
                    metadata.is_file() && !metadata.file_type().is_symlink(),
                    "Manual demo stop signal must be a regular file"
                );
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}

async fn manual_console_demo(
    demo: &ManualDemo,
    fixture: &support::Fixture,
    verified: &support::VerifiedFixtureConnections,
    realm: &str,
    config: &Value,
) -> anyhow::Result<()> {
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(demo.seconds as i64);
    let worker = verified
        .runtime("TEST_WORKER_DATABASE_URL", "sandbox_worker", 4)
        .await?
        .database_for("sandbox_worker")?;
    let engine = OperationEngine::new(
        worker.clone(),
        format!("manual-demo-diagnosis-{}", Uuid::new_v4()),
    )?;
    demo.write_private(
        "demo-login.json",
        &json!({"username":config["username"],"password":config["password"],
            "tenant":config["tenant"],"project":config["project"],"origin":config["origin"]}),
    )?;
    demo.write_private(
        "demo-ready.json",
        &json!({"status":"READY_NOT_ACCEPTANCE","origin":config["origin"],
            "tenant":config["tenant"],"project":config["project"],
            "instance":config["instance"],"name":config["name"],"realm":realm,
            "template_version_id":fixture.request.template_version_id,
            "security_profile_id":fixture.request.security_profile_id,
            "expires_at":expires_at,"accounts":config["accounts"],
            "runtime_vm_running":false,"cloud_certified":false,
            "scope":"Real local Keycloak/BFF/API/PostgreSQL control-plane demo. Instance creation is queued; no Kubernetes/Kata VM, cloud metrics, storage or backup certification. Only normal control-plane diagnosis work is reconciled."}),
    )?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(demo.seconds);
    crate::service_lifecycle::with_database_drain(worker.pool.clone(), async {
        while tokio::time::Instant::now() < deadline && !demo.stopped()? {
            // A short owner scheduling barrier lets the normal SKIP LOCKED
            // claim select DIAGNOSE only. No queue times, outcomes or instance
            // state are rewritten, and this never starts a compute runtime.
            let mut barrier = fixture.owner_transaction().await?;
            sqlx::query("SELECT id FROM operations WHERE tenant_id=$1 AND kind<>'DIAGNOSE' AND status IN('QUEUED','RUNNING','WAITING') FOR UPDATE")
                .bind(fixture.actor.tenant_id).fetch_all(&mut *barrier).await?;
            let claim = engine.claim().await.map_err(support::api_failure)?;
            barrier.commit().await?;
            if let Some(claim) = claim {
                ensure!(claim.tenant_id == fixture.actor.tenant_id,
                    "Manual demo worker may claim only its isolated tenant");
                worker.reconcile_diagnosis(&engine, &claim).await.map_err(support::api_failure)?;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Ok(())
    }).await?;
    // This credential belongs only to the random realm removed immediately
    // afterwards. Keep evidence, but do not retain its cleartext password.
    std::fs::remove_file(demo.directory.join("demo-login.json"))?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real loopback Keycloak, disposable PG roles, compiled console and installed Chrome"]
async fn real_keycloak_chrome_console_bff_and_api_enforce_live_revocation() -> anyhow::Result<()> {
    Box::pin(run_console(ConsoleMode::Acceptance)).await
}

#[tokio::test]
#[ignore = "Explicit local interactive demo; never an automated acceptance result"]
async fn real_keycloak_console_manual_demo() -> anyhow::Result<()> {
    Box::pin(run_console(ConsoleMode::Manual)).await
}

async fn run_console(mode: ConsoleMode) -> anyhow::Result<()> {
    let _serial = support::serial().await;
    // Shared Cargo caches can retain an embedded manifest directory from an
    // earlier source snapshot. Bind all external test inputs to this attempt.
    let root = PathBuf::from(required("SANDBOX_TEST_SOURCE_ROOT")?);
    let node = required("SANDBOX_TEST_NODE")?;
    ensure!(
        root.is_absolute() && root.canonicalize()? == root && root.join("Cargo.toml").is_file(),
        "Use the absolute canonical source root verified by this attempt"
    );
    ensure!(
        std::path::Path::new(&node).is_absolute(),
        "Use an absolute reviewed Node 24 executable"
    );
    let manual = match mode {
        ConsoleMode::Acceptance => None,
        ConsoleMode::Manual => Some(ManualDemo::from_environment()?),
    };
    let issuer_url = url::Url::parse(&required("SANDBOX_OIDC_ISSUER")?)?;
    ensure!(
        issuer_url.scheme() == "http"
            && issuer_url.host_str() == Some("127.0.0.1")
            && issuer_url.username().is_empty()
            && issuer_url.password().is_none(),
        "This test may create a realm only in the literal-loopback development Keycloak"
    );
    let backend = issuer_url.origin().ascii_serialization();
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(10))
        .build()?;
    let admin = exchange_admin(&client, &backend).await?;
    let realm = format!("sandbox-browser-{}", Uuid::new_v4().simple());
    let user = Uuid::new_v4();
    let username = format!("browser-{}", user.simple());
    let password = random_token()?;
    let secret = random_token()?;
    let client_id = format!("sandbox-browser-{}", Uuid::new_v4().simple());
    let api_listener = TcpListener::bind("127.0.0.1:0")?;
    // `localhost` and the literal IP are different browser sites. Both bind the
    // actual loopback interface, including on macOS without a 127.0.0.2 alias.
    // Cookies must not work merely because the ports differ.
    let idp_listener = TcpListener::bind("127.0.0.1:0")?;
    let origin = format!("https://{}", api_listener.local_addr()?);
    let frontend = format!("https://localhost:{}", idp_listener.local_addr()?.port());
    let issuer = format!("{frontend}/realms/{realm}");
    let mut document: Value =
        serde_json::from_str(include_str!("../deploy/keycloak/realm.template.json"))?;
    document["realm"] = json!(realm);
    document["attributes"] = json!({"frontendUrl": frontend, "sandboxLocalAcceptance": realm});
    // Use the production provisioning document. A separately hand-written
    // client fixture can conceal a missing subject mapper or scope policy.
    let provisioning_python = std::env::var_os("IDENTITY_PYTHON")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(".local/cluster-venv/bin/python"));
    let provisioning = tokio::process::Command::new(provisioning_python)
        .arg(root.join("deploy/identity/browser_client.py"))
        .args([
            "render",
            "--client-id",
            &client_id,
            "--public-origin",
            "https://console.example.test",
        ])
        .stderr(Stdio::null())
        .output()
        .await?;
    ensure!(
        provisioning.status.success(),
        "Browser client provisioning rejected"
    );
    let mut browser_client: Value = serde_json::from_slice(&provisioning.stdout)?;
    // Only the redirect is relocated to the random loopback test listener.
    // Production provisioning deliberately accepts the reviewed port 443.
    browser_client["redirectUris"] = json!([format!("{origin}/auth/callback")]);
    browser_client["secret"] = json!(secret);
    let machine_template = document["clients"][0].clone();
    let machines: Vec<(String, String)> = (0..2)
        .map(|_| {
            Ok((
                format!("sandbox-account-{}", Uuid::new_v4().simple()),
                random_token()?,
            ))
        })
        .collect::<anyhow::Result<_>>()?;
    let mut clients = vec![browser_client];
    for (id, credential) in &machines {
        let mut machine = machine_template.clone();
        machine["clientId"] = json!(id);
        machine["secret"] = json!(credential);
        clients.push(machine);
    }
    document["clients"] = json!(clients);
    document["users"] = json!([{"id":user, "username":username,"enabled":true,
        "email":format!("{username}@example.test"),"firstName":"Test","lastName":"Browser",
        "emailVerified":true,"requiredActions":[],
        "credentials":[{"type":"password","value":password,"temporary":false}]}]);
    let created = client
        .post(format!("{backend}/admin/realms"))
        .bearer_auth(&admin)
        .json(&document)
        .send()
        .await?;
    ensure!(
        created.status() == StatusCode::CREATED,
        "Unique local browser realm could not be created"
    );
    let mut tasks = Vec::new();
    let outcome = std::panic::AssertUnwindSafe(async {
        let verified = support::Fixture::prepare_verified_connections().await?;
        let mut fixture = support::Fixture::new_with_verified_connections(10, &verified).await?;
        sqlx::raw_sql(include_str!("../scripts/sql/browser-role.sql")).execute(&fixture.owner).await?;
        sqlx::raw_sql(include_str!("../scripts/sql/worker-role.sql")).execute(&fixture.owner).await?;
        let principal = Uuid::new_v4();
        let old_principal = fixture.actor.principal_id;
        let mut tx = fixture.owner_transaction().await?;
        sqlx::query("INSERT INTO principals(id,kind,display_name) VALUES($1,'USER','Real browser test user')")
            .bind(principal).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO principal_identities(principal_id,issuer,subject) VALUES($1,$2,$3)")
            .bind(principal).bind(&issuer).bind(user.to_string()).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO tenant_principals(tenant_id,principal_id,display_name) VALUES($1,$2,'Real browser test user')")
            .bind(fixture.actor.tenant_id).bind(principal).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) SELECT tenant_id,project_id,$3,action FROM grants WHERE tenant_id=$1 AND principal_id=$2")
            .bind(fixture.actor.tenant_id).bind(old_principal).bind(principal).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,'capabilities:read')")
            .bind(fixture.actor.tenant_id).bind(fixture.request.project_id).bind(principal).execute(&mut *tx).await?;
        for (project, action) in [
            (None, "service_clients:read"), (None, "service_clients:write"),
            (Some(fixture.request.project_id), "grants:read"),
            (Some(fixture.request.project_id), "grants:write"),
            (Some(fixture.request.project_id), "diagnoses:create"),
            (Some(fixture.request.project_id), "diagnoses:read"),
            (Some(fixture.request.project_id), "events:read"),
            (Some(fixture.request.project_id), "automations:read"),
            (Some(fixture.request.project_id), "automations:write"),
        ] {
            sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4)")
                .bind(fixture.actor.tenant_id).bind(project).bind(principal).bind(action).execute(&mut *tx).await?;
        }
        if manual.is_some() {
            sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,'audit:read')")
                .bind(fixture.actor.tenant_id).bind(fixture.request.project_id).bind(principal).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        fixture.actor.principal_id = principal;
        fixture.request.name = "real-identity-workspace".into();
        if let Some(demo) = &manual {
            fixture.request.ttl_seconds = Some(demo.seconds as i64);
        }
        let instance = fixture.create("real-browser-create").await.map_err(support::api_failure)?.body.resource;
        let backend_realm = format!("{backend}/realms/{realm}");
        let settings = OidcSettings { issuer:issuer.clone(), authorization_url:format!("{issuer}/protocol/openid-connect/auth"),
            token_url:format!("{backend_realm}/protocol/openid-connect/token"), jwks_url:format!("{backend_realm}/protocol/openid-connect/certs"),
            client_id:client_id.clone(),public_origin:origin.clone(),scopes:vec!["openid".into(),"sandbox:access".into()] };
        let auth = JwtAuthenticator::new(AuthConfig {
            scope_profile: Default::default(), issuer:issuer.clone(), audience:"sandbox-api".into(),jwks_url:settings.jwks_url.clone(),
            required_scopes:vec!["sandbox:access".into()],jwks_ttl_seconds:300,clock_skew_seconds:0,allow_loopback_http:true,max_token_lifetime_seconds:300 })?;
        // Real service tokens remain in Rust. Only their verified subject and
        // configured issuer are sent to the browser as registration metadata.
        let mut machine_tokens = Vec::new();
        let mut account_clients = Vec::new();
        for (index, (id, credential)) in machines.iter().enumerate() {
            let response = client.post(format!("{backend_realm}/protocol/openid-connect/token"))
                .form(&[("grant_type", "client_credentials"), ("client_id", id.as_str()),
                    ("client_secret", credential.as_str()), ("scope", "sandbox:access")])
                .send().await?;
            ensure!(response.status() == StatusCode::OK, "Real account service token request failed");
            let value: Value = response.json().await?;
            let token = value["access_token"].as_str().context("real service access token missing")?.to_owned();
            let identity = auth.verify(&token).await?;
            ensure!(identity.issuer == issuer && identity.client_id.as_deref() == Some(id.as_str()),
                "service identity is derived from the actual verified Keycloak token");
            account_clients.push(json!({"subject":identity.subject,"client_id":id,"display_name":format!("Live machine {}",index+1)}));
            machine_tokens.push(token);
        }
        let keys = tempfile::tempdir()?;
        let key_file = keys.path().join("keys.json");
        std::fs::write(&key_file,json!({"active":"test","keys":[{"id":"test","key":URL_SAFE_NO_PAD.encode([47;32])}]}).to_string())?;
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(&key_file,std::fs::Permissions::from_mode(0o600))?; }
        let app = Arc::new(AppState { database:fixture.database.clone(),auth,
            cursor_signer:CursorSigner::from_json(include_str!("../tests/fixtures/history/cursor-keys.json"))?,
            output_reader:None,metrics:None,default_ttl_seconds:300,max_ttl_seconds:86400 });
        let browser = Arc::new(BrowserRuntime::new(app.clone(),BrowserConfig{
            oidc:BrowserOidc::test_transport(settings,secret.clone())?,keys:SessionKeys::from_file(&key_file)? }));
        browser.check_schema().await?;
        let proxy = Router::new().fallback(proxy_idp).layer(DefaultBodyLimit::max(128*1024))
            .with_state(IdpProxy { backend:backend.clone(),realm:realm.clone(),client:client.clone() });
        tasks.push(serve_https(idp_listener,proxy).await?);
        let automations = Arc::new(crate::automation::api::AutomationApiRuntime { app: app.clone() });
        automations.check_schema().await?;
        let router = crate::api::router_with_automations(app.clone(),tokio_util::sync::CancellationToken::new(),Some(browser.clone()),None,Some(automations))
            .fallback(static_console)
            .layer(Extension(root.join("console/dist")))
            .layer(axum::middleware::from_fn_with_state(CallbackDiagnostics { owner: fixture.owner.clone(), tenant: fixture.actor.tenant_id, issuer: issuer.clone() }, diagnose_callback));
        tasks.push(serve_https(api_listener,router).await?);
        ensure!(root.join("console/dist/index.html").is_file(),"Build the real console before running the live browser test");
        let config = json!({"origin":origin,"tenant":fixture.actor.tenant_id,"project":instance.project_id,
            "instance":instance.id,"name":instance.name,"username":username,"password":password,
            "accounts":{"issuer":issuer,"clients":account_clients}});
        if let Some(demo) = &manual {
            return Box::pin(manual_console_demo(demo, &fixture, &verified, &realm, &config)).await;
        }
        let mut command = tokio::process::Command::new(node);
        command.current_dir(&root).arg("scripts/tests/browser-live.mjs")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).kill_on_drop(true);
        let mut child = command.spawn()?;
        let mut input = child.stdin.take().context("Browser input pipe missing")?;
        let mut output = BufReader::new(child.stdout.take().context("Browser output pipe missing")?);
        input.write_all(format!("{config}\n").as_bytes()).await?;
        let machine_api = reqwest::Client::builder().no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(reqwest::Certificate::from_pem(include_bytes!("../tests/fixtures/admission/server-ca.pem"))?)
            .connect_timeout(Duration::from_secs(2)).timeout(Duration::from_secs(10)).build()?;
        for (browser_phase, response_phase, expected) in [
            ("machine_granted", "machine_read_allowed", StatusCode::OK),
            ("machine_disabled", "machine_read_denied", StatusCode::NOT_FOUND),
            ("machine_enabled", "machine_read_restored", StatusCode::OK),
            ("machine_grant_disabled", "machine_grant_read_denied", StatusCode::NOT_FOUND),
            ("machine_grant_enabled", "machine_grant_read_restored", StatusCode::OK),
            ("machine_grant_revoked", "machine_grant_denied", StatusCode::NOT_FOUND),
        ] {
            phase(&mut output, browser_phase).await?;
            let response = machine_api.get(format!("{origin}/v1/instances/{}",instance.id))
                .bearer_auth(&machine_tokens[0]).header("X-Tenant-ID",fixture.actor.tenant_id.to_string()).send().await?;
            ensure!(response.status()==expected,"Real original machine token obeys current tenant registration/project grant state");
            if expected==StatusCode::NOT_FOUND {
                let value:Value=response.json().await?;
                ensure!(value["code"]==json!("RESOURCE_NOT_FOUND"),"machine denial uses the formal resource privacy response");
            }
            input.write_all(format!("{{\"phase\":\"{response_phase}\"}}\n").as_bytes()).await?;
        }
        phase(&mut output,"accounts_complete").await?;
        let mut tx = fixture.owner_transaction().await?;
        let counts:(i64,i64,i64,i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM management_receipts WHERE tenant_id=$1 AND action='service_clients:create'),(SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='service_clients:create'),(SELECT count(*) FROM management_receipts WHERE tenant_id=$1 AND action='service_clients:update'),(SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='service_clients:update'),(SELECT count(*) FROM management_receipts WHERE tenant_id=$1 AND action='grants:create'),(SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='grants:create')")
            .bind(fixture.actor.tenant_id).fetch_one(&mut *tx).await?;
        ensure!(counts==(2,2,2,2,1,1),"actual account mutations and ACK replay have one receipt/audit per intent");
        let revoked:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM management_receipts WHERE tenant_id=$1 AND action='grants:revoke'),(SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='grants:revoke')")
            .bind(fixture.actor.tenant_id).fetch_one(&mut *tx).await?;
        ensure!(revoked==(1,1),"real bodyless grant revocation commits exactly once");
        let updated:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM management_receipts WHERE tenant_id=$1 AND action='grants:update'),(SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='grants:update')")
            .bind(fixture.actor.tenant_id).fetch_one(&mut *tx).await?;
        ensure!(updated==(2,2),"project grant disable and restore each commit once");
        tx.commit().await?;
        let mut tx = fixture.owner_transaction().await?;
        let revoked = sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND project_id=$2 AND principal_id=$3 AND action='operations:read' AND enabled AND revoked_at IS NULL")
            .bind(fixture.actor.tenant_id).bind(fixture.request.project_id).bind(principal).execute(&mut *tx).await?;
        ensure!(revoked.rows_affected() == 1, "the diagnosis-only interval temporarily removes the real browser operation-read grant");
        tx.commit().await?;
        let before = diagnosis_facts(&fixture, instance.id).await?;
        input.write_all(b"{\"phase\":\"accounts_checked\"}\n").await?;
        Box::pin(browser_diagnoses(&fixture, &verified, instance.id, &before, &mut input, &mut output)).await?;
        Box::pin(browser_events(&fixture, &verified, instance.id, &before, &mut input, &mut output)).await?;
        Box::pin(browser_automations(&fixture, instance.id, &before, &mut input, &mut output)).await?;
        Box::pin(notifications::browser_notifications(&fixture, &verified, &browser, instance.id, &mut input, &mut output)).await?;
        phase(&mut output,"accepted").await?;
        let mut tx = fixture.owner_transaction().await?;
        let stop: i64 = sqlx::query_scalar("SELECT count(*) FROM operations WHERE tenant_id=$1 AND instance_id=$2 AND kind='STOP'")
            .bind(fixture.actor.tenant_id).bind(instance.id).fetch_one(&mut *tx).await?;
        let audit: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND resource_id=$2 AND actor_principal_id=$3 AND action='instances:stop' AND outcome='ACCEPTED'")
            .bind(fixture.actor.tenant_id).bind(instance.id).bind(principal).fetch_one(&mut *tx).await?;
        ensure!(stop == 1 && audit == 1,"The real browser mutation must have one operation and one actor audit");
        sqlx::query("UPDATE grants SET enabled=false,revoked_at=clock_timestamp() WHERE tenant_id=$1 AND principal_id=$2 AND action='instances:read'")
            .bind(fixture.actor.tenant_id).bind(principal).execute(&mut *tx).await?;
        tx.commit().await?;
        let mut tx = fixture.owner_transaction().await?;
        sqlx::query("UPDATE grants SET enabled=false,revoked_at=clock_timestamp() WHERE tenant_id=$1 AND principal_id=$2 AND action IN('service_clients:read','service_clients:write','grants:read','grants:write')")
            .bind(fixture.actor.tenant_id).bind(principal).execute(&mut *tx).await?;
        tx.commit().await?;
        input.write_all(b"{\"phase\":\"grants_revoked\"}\n").await?;
        phase(&mut output,"grant_denied").await?;
        let mut tx = fixture.owner_transaction().await?;
        sqlx::query("UPDATE tenant_principals SET enabled=false WHERE tenant_id=$1 AND principal_id=$2")
            .bind(fixture.actor.tenant_id).bind(principal).execute(&mut *tx).await?;
        tx.commit().await?;
        input.write_all(b"{\"phase\":\"member_disabled\"}\n").await?;
        phase(&mut output,"member_denied").await?;
        drop(input);
        let status = tokio::time::timeout(Duration::from_secs(10),child.wait()).await??;
        ensure!(status.success(),"Live browser driver did not complete");
        Ok::<_,anyhow::Error>(())
    }).catch_unwind().await;
    for task in tasks {
        task.abort();
    }
    if let Some(demo) = &manual {
        match std::fs::remove_file(demo.directory.join("demo-login.json")) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                // Keep attempting realm deletion below even when local
                // credential removal fails; never log the credential itself.
                eprintln!("LOCAL_MANUAL_DEMO_CREDENTIAL_CLEANUP_UNCONFIRMED");
            }
        }
    }
    // Delete only the random realm created by this test. No old database,
    // application realm or unrelated identity is removed.
    // A manual session outlives the initial short-lived administrator token.
    // Refresh only for cleanup; do not retain or disclose its bearer value.
    let cleanup = async {
        let admin = match mode {
            ConsoleMode::Acceptance => admin,
            ConsoleMode::Manual => exchange_admin(&client, &backend).await?,
        };
        client
            .delete(format!("{backend}/admin/realms/{realm}"))
            .bearer_auth(&admin)
            .send()
            .await
            .map_err(anyhow::Error::from)
    }
    .await;
    let outcome = outcome.map_err(|_| {
        anyhow::anyhow!("Live browser acceptance panicked; private details omitted")
    })?;
    outcome?;
    ensure!(
        cleanup?.status() == StatusCode::NO_CONTENT,
        "New local test realm cleanup failed"
    );
    match mode {
        ConsoleMode::Acceptance => println!(
            "VERIFIED real Keycloak/Chrome account console: two actual service identities registered and cursor-paged; client and project grant enable/disable obey the original real token; strong ETag/stale rejection, committed lost-ACK same-key reload retry, CSRF, bodyless revoke, live authorization denial and exact receipt/audit counts; no browser bearer/token persistence"
        ),
        ConsoleMode::Manual => println!("DEMO_STOPPED_NOT_ACCEPTANCE realm_cleanup_confirmed"),
    }
    Ok(())
}
