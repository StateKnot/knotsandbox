//! Real ordinary-role TLS PostgreSQL, real JWT/JWKS and real mTLS registration.
//! The Kubernetes and host observations are explicit fixtures, not VM evidence.
use crate::{
    api::{AppState, router},
    auth::{AuthConfig, JwtAuthenticator},
    history::CursorSigner,
    termination_ledger::tests::FixtureRuntime,
    test_support_db::{self, Fixture, api_failure},
};
use anyhow::{Context, ensure};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use chrono::Utc;
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;
use uuid::Uuid;

struct Server(tokio::task::JoinHandle<()>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct AbortRegistration(tokio::task::AbortHandle);
impl Drop for AbortRegistration {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn app(f: &Fixture) -> anyhow::Result<(Router, String, Server)> {
    f.bind_client_id("resource-observation-http").await?;
    let jwk: Value = serde_json::from_str(include_str!("../tests/fixtures/auth/jwk-a.json"))?;
    let kid = jwk["kid"].as_str().context("kid")?.to_owned();
    let keys = json!({"keys":[jwk]});
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = Server(tokio::spawn(async move {
        let app = Router::new().route(
            "/jwks",
            get(move || {
                let keys = keys.clone();
                async move { axum::Json(keys) }
            }),
        );
        assert!(axum::serve(listener, app).await.is_ok());
    }));
    let auth = JwtAuthenticator::new(AuthConfig {
        scope_profile: Default::default(),
        issuer: "https://issuer.example.test".into(),
        audience: "sandbox-api".into(),
        jwks_url: format!("http://{address}/jwks"),
        required_scopes: vec!["sandbox:access".into()],
        jwks_ttl_seconds: 300,
        clock_skew_seconds: 0,
        allow_loopback_http: true,
        max_token_lifetime_seconds: 300,
    })?;
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("at+jwt".into());
    header.kid = Some(kid);
    let now = Utc::now().timestamp();
    let token = encode(
        &header,
        &json!({"iss":"https://issuer.example.test",
        "sub":f.actor.principal_id.to_string(),"aud":"sandbox-api","client_id":"resource-observation-http",
        "jti":Uuid::new_v4().to_string(),"iat":now,"exp":now+300,"scope":"sandbox:access"}),
        &EncodingKey::from_rsa_der(include_bytes!("../tests/fixtures/auth/rsa-a.der")),
    )?;
    let signer =
        CursorSigner::from_json(include_str!("../tests/fixtures/history/cursor-keys.json"))?;
    Ok((
        router(Arc::new(AppState {
            output_reader: None,
            metrics: None,
            database: f.database.clone(),
            auth,
            cursor_signer: signer,
            default_ttl_seconds: 300,
            max_ttl_seconds: 86400,
        })),
        token,
        server,
    ))
}
async fn page(
    app: &Router,
    path: &str,
    token: &str,
    tenant: Uuid,
) -> anyhow::Result<(StatusCode, Value)> {
    let request = Request::builder()
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-tenant-id", tenant.to_string())
        .body(Body::empty())?;
    let response =
        tokio::time::timeout(Duration::from_secs(4), app.clone().oneshot(request)).await??;
    let status = response.status();
    ensure!(response.headers()["cache-control"] == "no-store");
    Ok((
        status,
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?,
    ))
}
async fn sdk(input: Value) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new("node")
        .arg("tests/fixtures/resource-accounting/observed-sdk-http.mjs")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdin = child.stdin.take().context("SDK stdin")?;
    stdin.write_all(&serde_json::to_vec(&input)?).await?;
    drop(stdin);
    let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output()).await??;
    ensure!(
        output.status.success(),
        "actual observed-resource SDK acceptance failed; private output withheld"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires normally migrated TLS PostgreSQL, ordinary termination role, Node SDK and actual mTLS fixture"]
async fn signed_pages_pin_first_page_absence_across_an_earlier_insert_later_commit_and_recheck_revocation()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let runtime = FixtureRuntime::new(false).await?;
    let f = &runtime.f;
    let id = runtime.launch.instance_id;
    let (app, token, _jwks) = app(f).await?;
    let base = format!("/v1/instances/{id}/resource-accounting?limit=2");
    // Warm the actual JWKS fetch before the bounded database lock window.
    ensure!(page(&app, &base, &token, f.actor.tenant_id).await?.0 == StatusCode::OK);
    let permit = runtime
        .engine
        .database
        .prepare_launch_permit(
            f.actor.tenant_id,
            runtime.create_op,
            &runtime.node,
            &runtime.launch,
        )
        .await
        .map_err(api_failure)?;
    let ack = runtime.guard.client.register(&permit.request).await?;
    let overhead = json!({"cpu":"40m","memory":"9007199254740993"});
    let resources = runtime
        .observe_resources_with(Some(&overhead), "opaque:pod-first", "opaque:class-first")
        .await?;

    // This real table lock stops the production transaction only after it has
    // inserted its own verified observation and ACK. No trigger or row is changed.
    let mut lock = f.owner_transaction().await?;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *lock)
        .await?;
    sqlx::query("LOCK TABLE runtime_node_journal_highwater IN SHARE MODE")
        .execute(&mut *lock)
        .await?;
    let db = runtime.engine.database.clone();
    let registration = tokio::spawn(async move {
        db.record_launch_registration(&permit, &ack, &resources)
            .await
    });
    let _abort = AbortRegistration(registration.abort_handle());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid WHERE a.datname=current_database() AND a.usename='sandbox_termination' AND l.locktype='relation' AND l.relation='public.runtime_node_journal_highwater'::regclass AND NOT l.granted AND $1=ANY(pg_blocking_pids(a.pid)))")
            .bind(blocker_pid).fetch_one(&f.owner).await?;
        if waiting {
            break;
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "production registration did not reach exact post-insert lock barrier"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (status, first) = page(&app, &base, &token, f.actor.tenant_id).await?;
    ensure!(
        status == StatusCode::OK
            && first["pod_resource_evidence"] == "NOT_CAPTURED"
            && first["pod_resource_observation"].is_null()
    );
    let cursor = first["receipts"]["next_cursor"]
        .as_str()
        .context("first page continuation")?;
    ensure!(cursor.len() <= 2048);
    lock.commit().await?;
    tokio::time::timeout(Duration::from_secs(4), registration)
        .await??
        .map_err(api_failure)?;
    let mut tx = f.owner_transaction().await?;
    let inserted_before_cutoff: bool = sqlx::query_scalar("SELECT recorded_at <= $3 FROM launch_pod_resource_observations WHERE tenant_id=$1 AND instance_id=$2")
        .bind(f.actor.tenant_id).bind(id).bind(first["receipts"]["cutoff"].as_str().context("cutoff")?.parse::<chrono::DateTime<Utc>>()?)
        .fetch_one(&mut *tx).await?;
    tx.commit().await?;
    ensure!(
        inserted_before_cutoff,
        "counterexample must really have INSERT before the first-page cutoff"
    );
    let continuation = format!("{base}&cursor={cursor}");
    let (status, second) = page(&app, &continuation, &token, f.actor.tenant_id).await?;
    ensure!(
        status == StatusCode::OK
            && second["pod_resource_evidence"] == "NOT_CAPTURED"
            && second["pod_resource_observation"].is_null()
    );
    ensure!(second["receipts"]["cutoff"] == first["receipts"]["cutoff"]);
    let (status, captured) = page(&app, &base, &token, f.actor.tenant_id).await?;
    ensure!(
        status == StatusCode::OK && captured["pod_resource_evidence"] == "KUBERNETES_API_READBACK"
    );
    let observation = captured["pod_resource_observation"].clone();
    ensure!(
        observation["instance_id"] == json!(id)
            && observation["pod_uid"] == json!(runtime.launch.pod_uid)
    );
    ensure!(
        observation["pod_overhead"]["memory_bytes"] == "9007199254740993"
            && observation["effective_request"]["memory_bytes"] == "9007201402224641"
    );
    ensure!(observation["runtime_class"]["resource_version"] == "opaque:class-first");
    let captured_cursor = captured["receipts"]["next_cursor"]
        .as_str()
        .context("captured continuation")?;
    let (status, captured_next) = page(
        &app,
        &format!("{base}&cursor={captured_cursor}"),
        &token,
        f.actor.tenant_id,
    )
    .await?;
    ensure!(status == StatusCode::OK && captured_next["pod_resource_observation"] == observation);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let serving = app.clone();
    let _server = Server(tokio::spawn(async move {
        assert!(axum::serve(listener, serving).await.is_ok());
    }));
    let sdk_base = json!({"baseUrl":format!("http://{address}"),"tenantId":f.actor.tenant_id,"token":token,"instanceId":id});
    let mut input = sdk_base.clone();
    input["phase"] = json!("MISSING_PINNED");
    input["cursor"] = json!(cursor);
    sdk(input).await?;
    let mut input = sdk_base.clone();
    input["phase"] = json!("CAPTURED");
    input["observation"] = observation.clone();
    sdk(input).await?;
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND action='instances:read'")
        .bind(f.actor.tenant_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    ensure!(
        page(
            &app,
            &format!("{base}&cursor={captured_cursor}"),
            &token,
            f.actor.tenant_id
        )
        .await?
        .0 == StatusCode::NOT_FOUND
    );
    let mut input = sdk_base;
    input["phase"] = json!("REVOKED");
    sdk(input).await?;
    Ok(())
}
