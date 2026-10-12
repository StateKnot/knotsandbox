//! Real TCP HTTP contract for cold backup acceptance and live product grants.
#![allow(clippy::unwrap_used)]
use super::*;
use crate::{
    api::{AppState, router},
    auth::{AuthConfig, JwtAuthenticator},
    history::CursorSigner,
};
use axum::{Json, Router, routing::get};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use std::{sync::Arc, time::Duration};

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and loopback HTTP/TLS"]
async fn actual_http_backup_receipt_replay_preconditions_and_grant_revocation() -> anyhow::Result<()>
{
    let _serial = test_support_db::serial().await;
    let f = Fixture::new(true).await?;
    let jwks = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let jwks_address = jwks.local_addr()?;
    let jwks_server = tokio::spawn(async move {
        axum::serve(jwks, Router::new().route("/jwks", get(|| async {
            Json(json!({"keys":[serde_json::from_str::<Value>(include_str!("../tests/fixtures/auth/jwk-a.json")).unwrap()]}))
        }))).await.unwrap();
    });
    f.base.f.bind_client_id("backup-contract-test").await?;
    let app = router(Arc::new(AppState {
        database: f.base.f.database.clone(),
        auth: JwtAuthenticator::new(AuthConfig {
            scope_profile: Default::default(),
            issuer: "https://issuer.example.test".into(),
            audience: "sandbox-api".into(),
            jwks_url: format!("http://{jwks_address}/jwks"),
            required_scopes: vec!["sandbox:access".into()],
            jwks_ttl_seconds: 300,
            clock_skew_seconds: 0,
            allow_loopback_http: true,
            max_token_lifetime_seconds: 300,
        })?,
        cursor_signer: CursorSigner::from_json(include_str!(
            "../tests/fixtures/history/cursor-keys.json"
        ))?,
        output_reader: None,
        metrics: None,
        default_ttl_seconds: 300,
        max_ttl_seconds: 86400,
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let api_server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let outcome = async {
        let now = Utc::now().timestamp();
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into()); header.kid = Some("key-a".into());
        let token = encode(&header, &json!({
            "iss":"https://issuer.example.test","sub":f.base.f.actor.principal_id.to_string(),"aud":"sandbox-api",
            "client_id":"backup-contract-test","jti":Uuid::new_v4().to_string(),"iat":now,"exp":now+300,"scope":"sandbox:access"
        }), &EncodingKey::from_rsa_der(include_bytes!("../tests/fixtures/auth/rsa-a.der")))?;
        let client = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(10)).build()?;
        let endpoint = format!("http://{address}/v1/workspaces/{}/backups", f.base.launch.workspace_id);
        let body = json!({"profile_id":f.profile,"retention_days":31});
        let post = |key: &str, etag: Option<&str>, value: Value| {
            let mut request = client.post(&endpoint).bearer_auth(&token)
                .header("x-tenant-id", f.base.f.actor.tenant_id.to_string()).header("idempotency-key", key).json(&value);
            if let Some(etag) = etag { request = request.header("if-match", etag); }
            request
        };
        assert_eq!(post("backup-http-missing",None,body.clone()).send().await?.status(), StatusCode::PRECONDITION_REQUIRED);
        assert_eq!(post("backup-http-weak",Some("W/\"1\""),body.clone()).send().await?.status(), StatusCode::BAD_REQUEST);
        assert_eq!(post("backup-http-stale",Some("\"99\""),body.clone()).send().await?.status(), StatusCode::PRECONDITION_FAILED);
        let accepted = post("backup-http-original",Some("\"1\""),body.clone()).send().await?;
        assert_eq!(accepted.status(), StatusCode::ACCEPTED);
        assert_eq!(accepted.headers()["cache-control"], "no-store");
        let workspace_etag = accepted.headers()["x-workspace-etag"].to_str()?.to_owned();
        let location = accepted.headers()["location"].to_str()?.to_owned();
        let receipt: BackupAccepted = accepted.json().await?;
        assert_eq!(workspace_etag, format!("\"{}\"",receipt.workspace_version));
        assert_eq!(location, format!("/v1/operations/{}",receipt.operation.id));
        assert_eq!(receipt.resource.status,"QUEUED");
        assert_eq!(receipt.resource.consistency,"STOPPED_CONSISTENT");
        let replay = post("backup-http-original",Some("\"1\""),body.clone()).send().await?;
        assert_eq!(replay.status(),StatusCode::ACCEPTED);
        let replay: BackupAccepted = replay.json().await?;
        assert_eq!(replay.resource.id,receipt.resource.id);
        assert_eq!(replay.operation.id,receipt.operation.id);
        assert_eq!(post("backup-http-original",Some("\"1\""),json!({"profile_id":f.profile,"retention_days":32})).send().await?.status(),StatusCode::CONFLICT);
        let get_backup = |tenant: Uuid| client.get(format!("http://{address}/v1/backups/{}", receipt.resource.id))
            .bearer_auth(&token).header("x-tenant-id",tenant.to_string());
        let got = get_backup(f.base.f.actor.tenant_id).send().await?;
        assert_eq!(got.status(),StatusCode::OK);
        assert_eq!(got.headers()["etag"],format!("\"{}\"",receipt.resource.version));
        let data: Value = got.json().await?;
        assert!(data.get("source").is_none() && data.get("settings").is_none() && data.get("tenant_id").is_none());
        assert_eq!(get_backup(Uuid::new_v4()).send().await?.status(),StatusCode::NOT_FOUND);
        let mut tx = f.base.f.owner_transaction().await?;
        sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action IN('backups:create','backups:read')")
            .bind(f.base.f.actor.tenant_id).bind(f.base.f.actor.principal_id).execute(&mut *tx).await?;
        tx.commit().await?;
        assert_eq!(get_backup(f.base.f.actor.tenant_id).send().await?.status(),StatusCode::NOT_FOUND);
        assert_eq!(post("backup-http-original",Some("\"1\""),body).send().await?.status(),StatusCode::NOT_FOUND);
        Ok::<_,anyhow::Error>(())
    }.await;
    api_server.abort();
    jwks_server.abort();
    f.base.guard.shutdown().await?;
    outcome
}
