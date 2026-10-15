#[allow(dead_code)]
mod support;

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
use sandbox_platform::{
    api::{AppState, router},
    auth::{AuthConfig, JwtAuthenticator},
    history::CursorSigner,
    resource_accounting::ResourceAccountingQuery,
};
use serde_json::{Value, json};
use std::{collections::HashSet, sync::Arc, time::Duration};
use support::{Fixture, api_failure};
use tower::ServiceExt;
use uuid::Uuid;

fn signer() -> anyhow::Result<CursorSigner> {
    CursorSigner::from_json(include_str!("fixtures/history/cursor-keys.json"))
}
fn query() -> ResourceAccountingQuery {
    ResourceAccountingQuery {
        launch_id: None,
        limit: Some(2),
        cursor: None,
    }
}
struct Server(tokio::task::JoinHandle<()>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn app(f: &Fixture) -> anyhow::Result<(Router, String, Server)> {
    f.bind_client_id("resource-accounting-test").await?;
    let jwk: Value = serde_json::from_str(include_str!("fixtures/auth/jwk-a.json"))?;
    let kid = jwk["kid"].as_str().context("kid")?.to_owned();
    let keys = json!({"keys":[jwk]});
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = Server(tokio::spawn(async move {
        let result = axum::serve(
            listener,
            Router::new().route(
                "/jwks",
                get(move || {
                    let keys = keys.clone();
                    async move { axum::Json(keys) }
                }),
            ),
        )
        .await;
        assert!(result.is_ok(), "local JWKS server failed");
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
        "sub":f.actor.principal_id.to_string(),"aud":"sandbox-api","client_id":"resource-accounting-test",
        "jti":Uuid::new_v4().to_string(),"iat":now,"exp":now+300,"scope":"sandbox:access"}),
        &EncodingKey::from_rsa_der(include_bytes!("fixtures/auth/rsa-a.der")),
    )?;
    Ok((
        router(Arc::new(AppState {
            output_reader: None,
            metrics: None,
            database: f.database.clone(),
            auth,
            cursor_signer: signer()?,
            default_ttl_seconds: 300,
            max_ttl_seconds: 86400,
        })),
        token,
        server,
    ))
}
fn request(path: &str, token: &str, tenant: Uuid) -> anyhow::Result<Request<Body>> {
    Ok(Request::builder()
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-tenant-id", tenant.to_string())
        .body(Body::empty())?)
}
async fn value(response: axum::response::Response) -> anyhow::Result<Value> {
    Ok(serde_json::from_slice(
        &response.into_body().collect().await?.to_bytes(),
    )?)
}

#[tokio::test]
#[ignore = "requires disposable normally migrated TLS PostgreSQL and generated Node SDK"]
async fn signed_resource_http_and_node_sdk_preserve_decimal_quantities_and_revocation()
-> anyhow::Result<()> {
    let _scope = support::serial().await;
    let f = Fixture::new(10).await?;
    // These are real account limits at capture time, never fabricated receipts.
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE quota_accounts SET limit_value=CASE WHEN dimension='CPU_MILLIS' THEN 9007199254740993 ELSE 9223372036854775807 END WHERE tenant_id=$1")
        .bind(f.actor.tenant_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let created = f
        .create("resource-http-create")
        .await
        .map_err(api_failure)?;
    let id = created.body.resource.id;
    let other = Fixture::new(10).await?;
    let foreign = other
        .create("resource-http-foreign")
        .await
        .map_err(api_failure)?
        .body
        .resource
        .id;
    let (app, token, _jwks) = app(&f).await?;
    let base = format!("/v1/instances/{id}/resource-accounting?limit=2");
    let mut path = base.clone();
    let mut ids = HashSet::new();
    let mut cutoff = None;
    let mut first_cursor = None;
    loop {
        let response = app
            .clone()
            .oneshot(request(&path, &token, f.actor.tenant_id)?)
            .await?;
        ensure!(response.status() == StatusCode::OK);
        ensure!(response.headers()["cache-control"] == "no-store");
        let body = value(response).await?;
        ensure!(
            body["request_evidence"] == "CAPTURED"
                && body["pod_resource_evidence"] == "NOT_CAPTURED"
        );
        ensure!(body["contract"]["cpu_millis"] == "1000" && body["contract"]["generation"] == "1");
        if let Some(cutoff) = &cutoff {
            ensure!(&body["receipts"]["cutoff"] == cutoff);
        } else {
            cutoff = Some(body["receipts"]["cutoff"].clone());
        }
        for receipt in body["receipts"]["items"].as_array().context("receipts")? {
            ensure!(ids.insert(receipt["id"].as_str().context("receipt id")?.to_owned()));
            ensure!(receipt["amount"].is_string() && receipt["account_version"].is_string());
            ensure!(
                receipt["limit_value"]
                    == if receipt["dimension"] == "CPU_MILLIS" {
                        "9007199254740993"
                    } else {
                        "9223372036854775807"
                    }
            );
        }
        if let Some(cursor) = body["receipts"]["next_cursor"].as_str() {
            first_cursor.get_or_insert(cursor.to_owned());
            path = format!("{base}&cursor={cursor}");
        } else {
            break;
        }
    }
    ensure!(ids.len() == 8);
    for path in [
        format!("/v1/instances/{foreign}/resource-accounting"),
        format!(
            "/v1/instances/{id}/resource-accounting?launch_id={}",
            Uuid::new_v4()
        ),
    ] {
        ensure!(
            app.clone()
                .oneshot(request(&path, &token, f.actor.tenant_id)?)
                .await?
                .status()
                == StatusCode::NOT_FOUND
        );
    }
    for suffix in [
        "&limit=3".to_owned(),
        "&launch_id=00000000-0000-4000-8000-000000000001".to_owned(),
    ] {
        let path = format!(
            "{base}&cursor={}{}",
            first_cursor.as_ref().context("cursor")?,
            suffix
        );
        ensure!(
            app.clone()
                .oneshot(request(&path, &token, f.actor.tenant_id)?)
                .await?
                .status()
                .is_client_error()
        );
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let serving = app.clone();
    let _server = Server(tokio::spawn(async move {
        assert!(axum::serve(listener, serving).await.is_ok());
    }));
    run_sdk(
        &json!({"baseUrl":format!("http://{address}"),"tenantId":f.actor.tenant_id,
        "token":token,"instanceId":id,"phase":"AVAILABLE"}),
    )
    .await?;
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND action='instances:read'")
        .bind(f.actor.tenant_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    ensure!(
        app.oneshot(request(
            &format!("{base}&cursor={}", first_cursor.context("cursor")?),
            &token,
            f.actor.tenant_id
        )?)
        .await?
        .status()
            == StatusCode::NOT_FOUND
    );
    run_sdk(
        &json!({"baseUrl":format!("http://{address}"),"tenantId":f.actor.tenant_id,
        "token":token,"instanceId":id,"phase":"REVOKED"}),
    )
    .await?;
    Ok(())
}

async fn run_sdk(input: &Value) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new("node")
        .arg("tests/fixtures/resource-accounting/sdk-http.mjs")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdin = child.stdin.take().context("SDK stdin")?;
    stdin.write_all(&serde_json::to_vec(input)?).await?;
    drop(stdin);
    let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output()).await??;
    ensure!(
        output.status.success(),
        "actual resource SDK interface failed; private output withheld"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable normally migrated TLS PostgreSQL"]
async fn resource_page_rechecks_grant_after_actual_database_lock_wait() -> anyhow::Result<()> {
    let _scope = support::serial().await;
    let f = Fixture::new(10).await?;
    let id = f
        .create("resource-slow")
        .await
        .map_err(api_failure)?
        .body
        .resource
        .id;
    let mut lock = f.owner_transaction().await?;
    sqlx::query("LOCK TABLE quota_resource_receipts IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await?;
    let db = f.database.clone();
    let actor = f.actor.clone();
    let read = tokio::spawn(async move {
        db.resource_accounting(
            &actor,
            id,
            &query(),
            &signer().map_err(|_| sandbox_platform::error::ApiError::invalid("fixture key"))?,
        )
        .await
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=current_user AND wait_event_type='Lock' AND query LIKE '%FROM quota_resource_receipts r%')")
            .fetch_one(&f.database.pool).await?;
        if waiting {
            break;
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "actual ledger query did not reach lock wait"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND action='instances:read'")
        .bind(f.actor.tenant_id)
        .execute(&mut *lock)
        .await?;
    lock.commit().await?;
    let error = match read.await? {
        Err(error) => error,
        Ok(_) => anyhow::bail!("revocation while waiting must hide page"),
    };
    ensure!(error.status == StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable normally migrated TLS PostgreSQL"]
async fn ordinary_preflight_rejects_disabled_trigger_same_name_noop_and_column_write_grant()
-> anyhow::Result<()> {
    let _scope = support::serial().await;
    let f = Fixture::new(10).await?;
    f.database.verify_runtime_role().await?;
    for damage in [
        "ALTER TABLE quota_reservations DISABLE TRIGGER quota_resource_capture",
        "CREATE OR REPLACE FUNCTION sandbox_capture_quota_resource() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN RETURN NEW; END $$",
        "CREATE OR REPLACE FUNCTION sandbox_prevent_audit_mutation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN RETURN NEW; END $$",
        "GRANT UPDATE(amount) ON quota_resource_receipts TO sandbox_app",
        "ALTER TABLE launch_resource_contracts NO FORCE ROW LEVEL SECURITY",
    ] {
        // Uncommitted DDL is checked on the same owner transaction only when
        // committed. Restore exact reviewed bytes/grants after each real damage.
        let function_body = sqlx::query_scalar::<_, String>(
            "SELECT pg_get_functiondef('public.sandbox_capture_quota_resource()'::regprocedure)",
        )
        .fetch_one(&f.owner)
        .await?;
        let append_body = sqlx::query_scalar::<_, String>(
            "SELECT pg_get_functiondef('public.sandbox_prevent_audit_mutation()'::regprocedure)",
        )
        .fetch_one(&f.owner)
        .await?;
        sqlx::raw_sql(damage).execute(&f.owner).await?;
        let refused = f.database.verify_runtime_role().await;
        sqlx::raw_sql(&function_body).execute(&f.owner).await?;
        sqlx::raw_sql(&append_body).execute(&f.owner).await?;
        sqlx::raw_sql("ALTER TABLE quota_reservations ENABLE TRIGGER quota_resource_capture; ALTER TABLE launch_resource_contracts FORCE ROW LEVEL SECURITY; REVOKE UPDATE(amount) ON quota_resource_receipts FROM sandbox_app")
            .execute(&f.owner).await?;
        ensure!(
            refused.is_err(),
            "ordinary preflight accepted changed accounting guard"
        );
        f.database.verify_runtime_role().await?;
    }
    Ok(())
}
