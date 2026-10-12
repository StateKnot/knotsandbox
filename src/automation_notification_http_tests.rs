//! Real signed public HTTP and generated Node SDK exercise an exception produced
//! by a normal business rejection. No test fabricates a run outcome or receipt.
use super::{
    AutomationReceipt,
    api::AutomationApiRuntime,
    tests::{Ready, automation_test_runtime},
};
use crate::{
    api::AppState,
    auth::{AuthConfig, JwtAuthenticator, ScopeProfile},
    history::CursorSigner,
    test_support_db::{self, api_failure},
};
use anyhow::{Context, ensure};
use axum::{Json, Router, http::StatusCode, routing::get};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::{collections::BTreeSet, sync::Arc};
use tokio::io::AsyncWriteExt;
use tower::ServiceExt;
use uuid::Uuid;

fn token(principal: Uuid, scopes: &str) -> anyhow::Result<String> {
    let now = Utc::now().timestamp();
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("at+jwt".into());
    header.kid = Some("key-a".into());
    Ok(encode(
        &header,
        &json!({"iss":"https://issuer.example.test","sub":principal.to_string(),
            "aud":"sandbox-api","client_id":"automation-http-test",
            "jti":Uuid::new_v4().to_string(),"iat":now,"exp":now+300,"scope":scopes}),
        &EncodingKey::from_rsa_der(include_bytes!("../tests/fixtures/auth/rsa-a.der")),
    )?)
}

async fn business_facts(r: &Ready, automation: Uuid, run: Uuid) -> anyhow::Result<Value> {
    let mut tx = r.f.owner_transaction().await?;
    let value = sqlx::query_scalar(
        "SELECT jsonb_build_object('run',(SELECT to_jsonb(r) FROM automation_runs r WHERE r.tenant_id=$1 AND r.id=$2),'instance',(SELECT to_jsonb(i) FROM instances i WHERE i.tenant_id=$1 AND i.id=$3),'operations',coalesce((SELECT jsonb_agg(to_jsonb(o) ORDER BY o.id) FROM operations o WHERE o.tenant_id=$1 AND o.instance_id=$3),'[]'::jsonb),'automation',(SELECT to_jsonb(a) FROM automations a WHERE a.tenant_id=$1 AND a.id=$4),'delegation',(SELECT to_jsonb(d) FROM automation_delegations d JOIN automations a ON a.tenant_id=d.tenant_id AND a.delegation_id=d.id WHERE a.tenant_id=$1 AND a.id=$4))",
    )
    .bind(r.f.actor.tenant_id).bind(run).bind(r.instance.id).bind(automation)
    .fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(value)
}

async fn sdk_ack(
    origin: &str,
    r: &Ready,
    token: &str,
    notification: Uuid,
) -> anyhow::Result<Value> {
    let mut child = tokio::process::Command::new("node")
        .arg("tests/fixtures/automation/notifications-http.mjs")
        .kill_on_drop(true)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let mut input = child.stdin.take().context("private SDK stdin")?;
    input
        .write_all(&serde_json::to_vec(&json!({"baseUrl":origin,
        "tenantId":r.f.actor.tenant_id,"token":token,"projectId":r.f.request.project_id,
        "instanceId":r.instance.id,"notificationId":notification}))?)
        .await?;
    input.shutdown().await?;
    drop(input);
    let result = tokio::time::timeout(std::time::Duration::from_secs(10), child.wait_with_output())
        .await??;
    ensure!(
        result.status.success(),
        "signed notification SDK helper failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(serde_json::from_slice(&result.stdout)?)
}

#[test]
#[ignore = "requires dedicated formal automation PostgreSQL, signed loopback HTTP and built Node SDK"]
fn signed_http_and_node_sdk_notifications_preserve_business_facts_and_live_authority()
-> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
        let _serial = test_support_db::serial().await;
        let r = Ready::new().await?;
        let mut tx = r.f.owner_transaction().await?;
        sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,'capabilities:read')")
            .bind(r.f.actor.tenant_id).bind(r.f.request.project_id).bind(r.f.actor.principal_id)
            .execute(&mut *tx).await?;
        tx.commit().await?;
        let jwks = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let jwks_address = jwks.local_addr()?;
        let key: Value = serde_json::from_str(include_str!("../tests/fixtures/auth/jwk-a.json"))?;
        let runtime = Arc::new(AutomationApiRuntime {
            app: Arc::new(AppState {
                database: r.f.database.clone(),
                auth: JwtAuthenticator::new(AuthConfig {
                    scope_profile: ScopeProfile::ActionScopes,
                    issuer: "https://issuer.example.test".into(),
                    audience: "sandbox-api".into(),
                    jwks_url: format!("http://{jwks_address}/jwks"),
                    required_scopes: vec!["sandbox:access".into()],
                    jwks_ttl_seconds: 300,
                    clock_skew_seconds: 0,
                    allow_loopback_http: true,
                    max_token_lifetime_seconds: 300,
                })?,
                cursor_signer: CursorSigner::from_json(r#"{"active":{"kid":"notification-http","key_base64":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="},"previous":[]}"#)?,
                output_reader: None,
                metrics: None,
                default_ttl_seconds: 300,
                max_ttl_seconds: 86400,
            }),
        });
        runtime.check_schema().await?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let app = crate::api::router_with_automations(
            runtime.app.clone(), tokio_util::sync::CancellationToken::new(),
            None, None, Some(runtime.clone()),
        );
        let jwks_server = tokio::spawn(async move {
            axum::serve(jwks, Router::new().route("/jwks", get(move || {
                let key = key.clone();
                async move { Json(json!({"keys":[key]})) }
            }))).await
        });
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let result = async {
            let access = token(r.f.actor.principal_id,
                "sandbox:access capabilities:read automations:read automations:write instances:renew instances:read")?;
            let read_only = token(r.f.actor.principal_id, "sandbox:access capabilities:read automations:read")?;
            let client = reqwest::Client::builder().no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(10)).build()?;
            let get = |path: &str| client.get(format!("{origin}{path}"))
                .bearer_auth(&access).header("x-tenant-id", r.f.actor.tenant_id.to_string());
            let post = |path: &str, key: &str, etag: Option<&str>, body: &Value| {
                let req = client.post(format!("{origin}{path}"))
                    .bearer_auth(&access).header("x-tenant-id", r.f.actor.tenant_id.to_string())
                    .header("idempotency-key", key).json(body);
                if let Some(etag) = etag { req.header("if-match", etag) } else { req }
            };
            let cap_path = format!("/v1/capabilities?project_id={}", r.f.request.project_id);
            let caps = get(&cap_path).send().await?;
            ensure!(caps.status() == StatusCode::OK);
            let caps: Value = caps.json().await?;
            ensure!(caps["api_features"]["automation_notifications"] == true);
            ensure!(caps["automation"]["schema_version"] == 1 && caps["runtime_certification"] == "NOT_ASSERTED");
            let closed = crate::api::router(runtime.app.clone());
            let response = closed.clone().oneshot(axum::http::Request::builder()
                .uri(&cap_path).header("authorization", format!("Bearer {access}"))
                .header("x-tenant-id", r.f.actor.tenant_id.to_string())
                .body(axum::body::Body::empty())?).await?;
            ensure!(response.status() == StatusCode::OK);
            let closed_caps: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
            ensure!(closed_caps["api_features"]["automation_notifications"] == false && closed_caps["automation"].is_null());
            let response = closed.oneshot(axum::http::Request::builder()
                .uri(format!("/v1/automation-notifications?project_id={}", r.f.request.project_id))
                .header("authorization", format!("Bearer {access}"))
                .header("x-tenant-id", r.f.actor.tenant_id.to_string())
                .body(axum::body::Body::empty())?).await?;
            ensure!(response.status() == StatusCode::NOT_FOUND);

            // The source comes from a normal signed rule create, real worker
            // preparation, and another signed business acceptance changing the
            // instance version before the automation acceptor can renew it.
            let mut request = r.request();
            request.trigger = super::AutomationTrigger::Once { at: Utc::now() + Duration::seconds(5) };
            let create_path = format!("/v1/instances/{}/automations", r.instance.id);
            let created = post(&create_path, "notification-http-create",
                Some(&format!("\"{}\"", r.instance.spec_version)), &json!(request)).send().await?;
            ensure!(created.status() == StatusCode::CREATED, "normal signed automation create must succeed");
            let created: AutomationReceipt = created.json().await?;
            let claim = r.due_claim().await?;
            ensure!(r.worker.prepare(&claim).await.map_err(api_failure)?.is_some());
            let renewed = post(&format!("/v1/instances/{}/actions/renew", r.instance.id),
                "notification-http-manual-renew", Some(&format!("\"{}\"", r.instance.spec_version)),
                &json!({"expires_at": Utc::now() + Duration::hours(3)})).send().await?;
            ensure!(renewed.status() == StatusCode::OK, "normal manual renewal must change instance version");
            r.worker.run_claim(&claim).await.map_err(api_failure)?;

            let list_path = format!("/v1/automation-notifications?project_id={}&instance_id={}&limit=1",
                r.f.request.project_id, r.instance.id);
            let listed = get(&list_path).send().await?;
            ensure!(listed.status() == StatusCode::OK);
            let listed: Value = listed.json().await?;
            ensure!(listed["items"].as_array().context("notification list")?.len() == 1);
            ensure!(listed["cutoff"].is_string() && listed["next_cursor"].is_null());
            let notification = &listed["items"][0];
            ensure!(notification["source_status"] == "FAILED" && notification["version"] == 1);
            ensure!(notification["acknowledged_at"].is_null() && notification["acknowledged_by"].is_null());
            let keys: BTreeSet<_> = notification.as_object().context("notification object")?.keys().map(String::as_str).collect();
            ensure!(keys == BTreeSet::from(["id","tenant_id","project_id","instance_id","automation_id","run_id",
                "source_event_id","source_run_version","source_status","created_at","acknowledged_at","acknowledged_by","version"]),
                "notification must expose only fixed metadata");
            let id: Uuid = serde_json::from_value(notification["id"].clone())?;
            let run: Uuid = serde_json::from_value(notification["run_id"].clone())?;
            ensure!(notification["automation_id"] == json!(created.resource.id));
            let detail_path = format!("/v1/automation-notifications/{id}");
            let ack_path = format!("{detail_path}/actions/acknowledge");
            let detail = get(&detail_path).send().await?;
            ensure!(detail.status() == StatusCode::OK && detail.headers()["etag"] == "\"1\"");
            ensure!(detail.json::<Value>().await? == *notification);
            ensure!(get("/v1/automation-notifications").send().await?.status() == StatusCode::BAD_REQUEST);
            ensure!(get(&format!("/v1/automation-notifications?project_id={}&cursor=invalid", r.f.request.project_id))
                .send().await?.status() == StatusCode::BAD_REQUEST);
            ensure!(get(&format!("/v1/automation-notifications?project_id={}", Uuid::new_v4()))
                .send().await?.status() == StatusCode::NOT_FOUND);
            ensure!(get(&format!("/v1/automation-notifications/{}", Uuid::new_v4()))
                .send().await?.status() == StatusCode::NOT_FOUND);
            ensure!(client.get(format!("{origin}{detail_path}")).send().await?.status() == StatusCode::UNAUTHORIZED);
            ensure!(client.get(format!("{origin}{detail_path}")).bearer_auth(&access)
                .header("x-tenant-id", Uuid::new_v4().to_string()).send().await?.status() == StatusCode::NOT_FOUND);
            let before = business_facts(&r, created.resource.id, run).await?;
            ensure!(before["run"]["status"] == "FAILED" && before["run"]["operation_id"].is_null());
            let mut tx = r.f.owner_transaction().await?;
            let real_source: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM domain_events e JOIN automation_runs r ON r.tenant_id=e.tenant_id AND r.id=e.aggregate_id WHERE e.tenant_id=$1 AND e.id=$2 AND e.request_id=r.id AND e.aggregate_version=r.version AND e.event_type='automations:run.changed' AND e.payload->>'status'='FAILED' AND r.status='FAILED')")
                .bind(r.f.actor.tenant_id).bind(id).fetch_one(&mut *tx).await?;
            ensure!(real_source, "normal failed acceptance must atomically produce the notification source");
            tx.commit().await?;

            for (index, invalid) in [json!([]), Value::Null, json!({"resolved":true})].iter().enumerate() {
                ensure!(post(&ack_path, &format!("notification-invalid-{index}"), Some("\"1\""), invalid)
                    .send().await?.status() == StatusCode::BAD_REQUEST, "ACK must require strictly empty JSON object");
            }
            ensure!(post(&ack_path, "notification-no-version", None, &json!({}))
                .send().await?.status() == StatusCode::PRECONDITION_REQUIRED);
            ensure!(post(&ack_path, "notification-stale", Some("\"999\""), &json!({}))
                .send().await?.status() == StatusCode::PRECONDITION_FAILED);
            ensure!(post(&ack_path, "notification-weak", Some("W/\"1\""), &json!({}))
                .send().await?.status() == StatusCode::BAD_REQUEST);
            let scope_denied = client.post(format!("{origin}{ack_path}")).bearer_auth(&read_only)
                .header("x-tenant-id", r.f.actor.tenant_id.to_string())
                .header("idempotency-key", "notification-scope-denied").header("if-match", "\"1\"")
                .json(&json!({})).send().await?;
            ensure!(scope_denied.status() == StatusCode::NOT_FOUND, "current token must contain automations:write");
            ensure!(get(&detail_path).send().await?.json::<Value>().await?["version"] == 1);

            let sdk = sdk_ack(&origin, &r, &access, id).await?;
            ensure!(sdk["mutation_requests"] == 2 && sdk["first_response_discarded"] == true);
            let receipt = &sdk["receipt"];
            let first_http_request: Uuid = serde_json::from_value(sdk["first_http_request_id"].clone())?;
            ensure!(receipt["resource"]["version"] == 2);
            ensure!(receipt["resource"]["acknowledged_by"] == json!(r.f.actor.principal_id));
            let replay = post(&ack_path, "notification-sdk-ack", Some("\"1\""), &json!({})).send().await?;
            ensure!(replay.status() == StatusCode::OK && replay.headers()["etag"] == "\"2\"");
            ensure!(replay.json::<Value>().await? == *receipt, "HTTP replay must preserve original SDK receipt");
            let replay_scope_denied = client.post(format!("{origin}{ack_path}")).bearer_auth(&read_only)
                .header("x-tenant-id", r.f.actor.tenant_id.to_string())
                .header("idempotency-key", "notification-sdk-ack").header("if-match", "\"1\"")
                .json(&json!({})).send().await?;
            ensure!(replay_scope_denied.status() == StatusCode::NOT_FOUND,
                "receipt replay must recheck current token action scope");
            ensure!(post(&ack_path, "notification-sdk-ack", Some("\"2\""), &json!({}))
                .send().await?.status() == StatusCode::CONFLICT);
            ensure!(post(&ack_path, "notification-new-stale", Some("\"1\""), &json!({}))
                .send().await?.status() == StatusCode::PRECONDITION_FAILED);
            let current = post(&ack_path, "notification-already-ack", Some("\"2\""), &json!({})).send().await?;
            ensure!(current.status() == StatusCode::OK && current.json::<Value>().await?["resource"] == receipt["resource"]);

            let mut tx = r.f.owner_transaction().await?;
            sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='automations:read'")
                .bind(r.f.actor.tenant_id).bind(r.f.actor.principal_id).execute(&mut *tx).await?;
            tx.commit().await?;
            ensure!(get(&detail_path).send().await?.status() == StatusCode::NOT_FOUND);
            ensure!(get(&list_path).send().await?.status() == StatusCode::NOT_FOUND);
            ensure!(post(&ack_path, "notification-write-only", Some("\"2\""), &json!({}))
                .send().await?.status() == StatusCode::OK, "ACK requires live write independently of read grants");
            let mut tx = r.f.owner_transaction().await?;
            sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='automations:write'")
                .bind(r.f.actor.tenant_id).bind(r.f.actor.principal_id).execute(&mut *tx).await?;
            tx.commit().await?;
            ensure!(post(&ack_path, "notification-sdk-ack", Some("\"1\""), &json!({}))
                .send().await?.status() == StatusCode::NOT_FOUND, "receipt replay must recheck current database write grant");
            ensure!(business_facts(&r, created.resource.id, run).await? == before,
                "ACK must not mutate full run, instance, operations, rule budget or delegation facts");
            let mut tx = r.f.owner_transaction().await?;
            let ack_audits: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND resource_id=$2 AND action='automations:notifications:acknowledge'")
                .bind(r.f.actor.tenant_id).bind(id).fetch_one(&mut *tx).await?;
            let actual_http_audit: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM audit_events WHERE tenant_id=$1 AND resource_id=$2 AND action='automations:notifications:acknowledge' AND request_id=$3 AND request_id<>$4)")
                .bind(r.f.actor.tenant_id).bind(id).bind(first_http_request).bind(run).fetch_one(&mut *tx).await?;
            let causal_events: i64 = sqlx::query_scalar("SELECT count(*) FROM domain_events e WHERE e.tenant_id=$1 AND e.aggregate_id=$2 AND e.event_type='automation-notifications:acknowledged' AND e.request_id=$3 AND EXISTS(SELECT 1 FROM automation_runs r WHERE r.tenant_id=e.tenant_id AND(r.id=e.request_id OR r.operation_id=e.operation_id))")
                .bind(r.f.actor.tenant_id).bind(id).bind(run).fetch_one(&mut *tx).await?;
            ensure!(ack_audits == 1 && causal_events == 1 && actual_http_audit,
                "lost reply, replay and already ACK requests must produce one audit and one non-retriggering causal event");
            let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM management_receipts WHERE tenant_id=$1 AND target_id=$2 AND action='automations:notifications:acknowledge'")
                .bind(r.f.actor.tenant_id).bind(id).fetch_one(&mut *tx).await?;
            ensure!(receipts == 3, "only original SDK ACK and two authorized current-version requests commit receipts");
            let unchanged_source: bool = sqlx::query_scalar("SELECT source_status='FAILED' AND source_run_version=$3 AND version=2 FROM automation_notifications WHERE tenant_id=$1 AND id=$2")
                .bind(r.f.actor.tenant_id).bind(id)
                .bind(notification["source_run_version"].as_i64().context("source run version")?)
                .fetch_one(&mut *tx).await?;
            ensure!(unchanged_source);
            tx.commit().await?;
            Ok::<(), anyhow::Error>(())
        }.await;
        server.abort();
        jwks_server.abort();
        let _ = server.await;
        let _ = jwks_server.await;
        result
    })
}
