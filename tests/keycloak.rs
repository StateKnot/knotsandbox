// The shared database fixture also exposes helpers used only by database.rs.
#[allow(dead_code)]
mod support;

use std::{env, sync::Arc, time::Duration};

use anyhow::{Context, ensure};
use axum::{
    Router,
    body::Body,
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode},
};
use chrono::Duration as ChronoDuration;
use http_body_util::BodyExt;
use sandbox_platform::{
    api::{AppState, router},
    auth::{AuthConfig, JwtAuthenticator},
    model::{Accepted, Instance, Operation, RenewRequest},
};
use serde::Deserialize;
use serde_json::{Value, json};
use support::Fixture;
use tokio::io::AsyncWriteExt;
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
}

struct ApiClient {
    router: Router,
    authorization: HeaderValue,
    tenant_id: Uuid,
}

impl ApiClient {
    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        mutation: Option<(&str, Option<&str>)>,
        expected_status: StatusCode,
    ) -> anyhow::Result<(HeaderMap, Value)> {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", &self.authorization)
            .header("x-tenant-id", self.tenant_id.to_string());
        if let Some((key, etag)) = mutation {
            request = request.header("idempotency-key", key);
            if let Some(etag) = etag {
                request = request.header("if-match", etag);
            }
        }
        let body = match body {
            Some(value) => {
                request = request.header("content-type", "application/json");
                Body::from(serde_json::to_vec(&value)?)
            }
            None => Body::empty(),
        };
        let response = self.router.clone().oneshot(request.body(body)?).await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await?.to_bytes();
        let body: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            status == expected_status,
            "API returned {status}; expected {expected_status}; code={}",
            body.get("code").and_then(Value::as_str).unwrap_or("absent")
        );
        ensure!(
            headers
                .get("cache-control")
                .is_some_and(|v| v == "no-store")
        );
        Uuid::parse_str(header(&headers, "x-request-id")?)?;
        Ok((headers, body))
    }
}

fn required(name: &str) -> anyhow::Result<String> {
    let value = env::var(name)
        .with_context(|| format!("{name} is required; load the development environment"))?;
    ensure!(!value.is_empty(), "{name} must not be empty");
    Ok(value)
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> anyhow::Result<&'a str> {
    headers
        .get(name)
        .with_context(|| format!("Expected response header {name}"))?
        .to_str()
        .context("Response header is not ASCII")
}

#[tokio::test]
#[ignore = "Requires real Keycloak, PostgreSQL, both TEST_*DATABASE_URLs and SANDBOX_MACHINE_* credentials"]
async fn live_machine_token_authorizes_api_and_obeys_database_revocation() -> anyhow::Result<()> {
    let issuer = required("SANDBOX_OIDC_ISSUER")?;
    let issuer_url = Url::parse(&issuer).context("Invalid OIDC issuer")?;
    let allow_loopback_http = issuer_url.scheme() == "http"
        && matches!(issuer_url.host_str(), Some("127.0.0.1" | "[::1]"));
    let auth = JwtAuthenticator::new(AuthConfig {
        scope_profile: Default::default(),
        issuer: issuer.clone(),
        audience: "sandbox-api".to_owned(),
        jwks_url: required("SANDBOX_OIDC_JWKS_URL")?,
        required_scopes: vec!["sandbox:access".to_owned()],
        jwks_ttl_seconds: 300,
        clock_skew_seconds: 0,
        allow_loopback_http,
        max_token_lifetime_seconds: 300,
    })?;
    let client_id = required("SANDBOX_MACHINE_CLIENT_ID")?;
    let secret = required("SANDBOX_MACHINE_CLIENT_SECRET")?;
    let response = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(10))
        .https_only(!allow_loopback_http)
        .build()?
        .post(format!("{issuer}/protocol/openid-connect/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id.as_str()),
            ("client_secret", secret.as_str()),
            ("scope", "sandbox:access"),
        ])
        .send()
        .await?;
    // Never print the token endpoint body, credentials, or bearer token.
    ensure!(
        response.status().is_success(),
        "Keycloak token request failed: {}",
        response.status()
    );
    let token: TokenResponse = response
        .json()
        .await
        .context("Invalid Keycloak token response")?;
    ensure!(token.token_type.eq_ignore_ascii_case("bearer"));
    // This fetches the real realm JWKS and verifies the signature and full profile.
    let identity = auth.verify(&token.access_token).await?;
    ensure!(identity.client_id.as_deref() == Some(client_id.as_str()));
    ensure!(identity.issuer == issuer);

    let _test_scope = support::serial().await;
    let fixture = Fixture::new(10).await?;
    sqlx::query("INSERT INTO principal_identities(principal_id,issuer,subject,service_client_id,service_binding_generation) VALUES($1,$2,$3,$4,1)")
        .bind(fixture.actor.principal_id)
        .bind(&identity.issuer)
        .bind(&identity.subject)
        .bind(&identity.client_id)
        .execute(&fixture.owner)
        .await
        .context("Cannot register the test service identity; run this suite serially")?;
    // Always remove this mapping after a returned test error so the fixed real
    // service-account subject can be registered by a fresh fixture on the next run.
    let outcome = async {
        let mut authorization = HeaderValue::from_str(&format!("Bearer {}", token.access_token))?;
        authorization.set_sensitive(true);
        let client = ApiClient {
            router: router(Arc::new(AppState {
                output_reader: None,
                metrics: None,
        cursor_signer: sandbox_platform::history::CursorSigner::from_json(include_str!("fixtures/history/cursor-keys.json"))?,
                database: fixture.database.clone(), auth,
                default_ttl_seconds: 300, max_ttl_seconds: 86400,
            })),
            authorization,
            tenant_id: fixture.actor.tenant_id,
        };
        live_node_sdk(client.router.clone(), &token.access_token, &fixture).await?;
        let create_body = serde_json::to_value(&fixture.request)?;
        let (headers, body) = client.request(Method::POST, "/v1/instances", Some(create_body.clone()), Some(("keycloak-create", None)), StatusCode::ACCEPTED).await?;
        let created: Accepted = serde_json::from_value(body)?;
        let path = format!("/v1/instances/{}", created.resource.id);
        let create_etag = header(&headers, "etag")?;
        ensure!(header(&headers, "location")? == format!("/v1/operations/{}", created.operation.id));
        let request_id = Uuid::parse_str(header(&headers, "x-request-id")?)?;
        let mut tx = fixture.owner_transaction().await?;
        let audit_actor: Uuid = sqlx::query_scalar("SELECT actor_principal_id FROM audit_events WHERE request_id=$1 AND action='instances:create'")
            .bind(request_id).fetch_one(&mut *tx).await?;
        ensure!(audit_actor == fixture.actor.principal_id);
        tx.commit().await?;

        let (_, body) = client.request(Method::GET, &path, None, None, StatusCode::OK).await?;
        let read: Instance = serde_json::from_value(body)?;
        ensure!(read.id == created.resource.id && read.tenant_id == fixture.actor.tenant_id);
        let renewal = RenewRequest { expires_at: read.compute_lease_expires_at + ChronoDuration::seconds(300) };
        let (headers, body) = client.request(Method::POST, &format!("{path}/actions/renew"), Some(serde_json::to_value(renewal)?), Some(("keycloak-renew", Some(create_etag))), StatusCode::OK).await?;
        let renewed: Accepted = serde_json::from_value(body)?;
        ensure!(renewed.resource.compute_lease_version == read.compute_lease_version + 1);
        ensure!(renewed.resource.active_operation_id == Some(created.operation.id));
        let (_, body) = client.request(Method::POST, &format!("{path}/actions/stop"), Some(json!({})), Some(("keycloak-stop", Some(header(&headers, "etag")?))), StatusCode::ACCEPTED).await?;
        let stopped: Accepted = serde_json::from_value(body)?;
        ensure!(stopped.resource.desired_state == "STOPPED" && stopped.operation.kind == "STOP");
        let (_, body) = client.request(Method::GET, &format!("/v1/operations/{}", stopped.operation.id), None, None, StatusCode::OK).await?;
        let operation: Operation = serde_json::from_value(body)?;
        ensure!(operation.id == stopped.operation.id && operation.status == "QUEUED");

        let mut tx = fixture.owner_transaction().await?;
        sqlx::query("UPDATE grants SET enabled=false,revoked_at=clock_timestamp() WHERE tenant_id=$1 AND principal_id=$2 AND action IN ('instances:create','instances:read')")
            .bind(fixture.actor.tenant_id).bind(fixture.actor.principal_id).execute(&mut *tx).await?;
        tx.commit().await?;
        // Reuse the same still-valid token and original idempotency key: neither
        // authentication caching nor stored success receipts may bypass revocation.
        let (_, problem) = client.request(Method::POST, "/v1/instances", Some(create_body), Some(("keycloak-create", None)), StatusCode::FORBIDDEN).await?;
        ensure!(problem["code"] == "PERMISSION_DENIED");
        let (_, problem) = client.request(Method::GET, &path, None, None, StatusCode::NOT_FOUND).await?;
        ensure!(problem["code"] == "RESOURCE_NOT_FOUND");
        sqlx::query("UPDATE principals SET enabled=false WHERE id=$1")
            .bind(fixture.actor.principal_id).execute(&fixture.owner).await?;
        let (_, problem) = client.request(Method::GET, &format!("/v1/operations/{}", stopped.operation.id), None, None, StatusCode::FORBIDDEN).await?;
        ensure!(problem["code"] == "PERMISSION_DENIED");
        Ok::<(), anyhow::Error>(())
    }.await;
    let cleanup = sqlx::query(
        "DELETE FROM principal_identities WHERE principal_id=$1 AND issuer=$2 AND subject=$3",
    )
    .bind(fixture.actor.principal_id)
    .bind(&identity.issuer)
    .bind(&identity.subject)
    .execute(&fixture.owner)
    .await;
    outcome?;
    ensure!(
        cleanup?.rows_affected() == 1,
        "Test identity cleanup failed"
    );
    Ok(())
}

async fn live_node_sdk(
    router: Router,
    access_token: &str,
    fixture: &Fixture,
) -> anyhow::Result<()> {
    #[derive(Deserialize)]
    struct SdkReceipt {
        instance_id: Uuid,
        create_operation_id: Uuid,
        stop_operation_id: Uuid,
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    ensure!(
        root.join("sdk/typescript/dist/index.js").is_file(),
        "Build the TypeScript SDK before running the real identity integration test"
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let outcome = async {
        let input = serde_json::to_vec(&json!({
            "baseUrl":format!("http://{address}"),
            "tenantId":fixture.actor.tenant_id,
            "accessToken":access_token,
            "createRequest":fixture.request,
        }))?;
        let mut child = tokio::process::Command::new("node")
            .arg("sdk/typescript/test/integration.mjs")
            .current_dir(root)
            .env_clear()
            .env("PATH", env::var_os("PATH").unwrap_or_default())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("Cannot start Node.js SDK integration process")?;
        let mut stdin = child.stdin.take().context("Node.js input pipe unavailable")?;
        stdin.write_all(&input).await?;
        stdin.shutdown().await?;
        drop(stdin);
        let output = tokio::time::timeout(Duration::from_secs(25), child.wait_with_output())
            .await.context("SDK integration exceeded its deadline")??;
        if !output.status.success() {
            // Only the fixed failure code is admitted into test diagnostics.
            let code = std::str::from_utf8(&output.stderr).unwrap_or("").trim();
            let safe = code.len() <= 100 && !code.is_empty() && code.bytes().all(|b| b.is_ascii_uppercase() || b == b'_');
            anyhow::bail!("Real Node.js SDK integration failed: {}", if safe {code} else {"REDACTED_CHILD_ERROR"});
        }
        let receipt: SdkReceipt = serde_json::from_slice(&output.stdout).context("Invalid SDK test receipt")?;
        let mut tx = fixture.owner_transaction().await?;
        let counts: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM instances WHERE tenant_id=$1), (SELECT count(*) FROM operations WHERE tenant_id=$1 AND kind='CREATE'), (SELECT count(*) FROM operations WHERE tenant_id=$1 AND kind='STOP')")
            .bind(fixture.actor.tenant_id).fetch_one(&mut *tx).await?;
        ensure!(counts == (1,1,1), "SDK retries created duplicate resources or operations");
        let bound: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM instances i JOIN operations c ON c.tenant_id=i.tenant_id AND c.instance_id=i.id JOIN operations s ON s.tenant_id=i.tenant_id AND s.instance_id=i.id WHERE i.tenant_id=$1 AND i.id=$2 AND c.id=$3 AND c.kind='CREATE' AND s.id=$4 AND s.kind='STOP' AND s.status='QUEUED' AND i.active_operation_id=s.id)")
            .bind(fixture.actor.tenant_id).bind(receipt.instance_id).bind(receipt.create_operation_id).bind(receipt.stop_operation_id)
            .fetch_one(&mut *tx).await?;
        ensure!(bound, "SDK receipt does not match persisted operation identities");
        tx.commit().await?;
        Ok::<(), anyhow::Error>(())
    }.await;
    server.abort();
    let _ = server.await;
    outcome
}
