#![allow(clippy::unwrap_used)]
use super::*;
use axum::{body::Body, routing::get};
use chrono::{DateTime, Utc};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CERT: &[u8] = include_bytes!("../tests/fixtures/admission/server.pem");
const KEY: &[u8] = include_bytes!("../tests/fixtures/admission/server.key");
const CA: &[u8] = include_bytes!("../tests/fixtures/admission/server-ca.pem");
fn fixture_tls() -> ApiTls {
    ApiTls::from_pem(CERT, KEY, CA, "127.0.0.1").unwrap()
}
fn time(value: &str) -> UnixTime {
    let t = DateTime::parse_from_rfc3339(value).unwrap().timestamp() as u64;
    UnixTime::since_unix_epoch(Duration::from_secs(t))
}
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .timeout(Duration::from_secs(3))
        .add_root_certificate(reqwest::Certificate::from_pem(CA).unwrap())
        .build()
        .unwrap()
}
async fn running(
    app: Router,
    tls: Option<ApiTls>,
) -> (
    SocketAddr,
    CancellationToken,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = CancellationToken::new();
    let task = tokio::spawn(serve(listener, tls, app, stop.clone()));
    (addr, stop, task)
}

#[test]
fn certificate_san_chain_key_validity_and_shutdown_horizon_fail_closed() {
    let tls = fixture_tls();
    tls.validity.check(UnixTime::now()).unwrap();
    for name in [
        "wrong.fixture.invalid",
        "http://localhost",
        "LOCALHOST",
        "localhost.",
        "*",
        "",
    ] {
        assert!(ApiTls::from_pem(CERT, KEY, CA, name).is_err());
    }
    assert!(
        ApiTls::from_pem(
            CERT,
            KEY,
            include_bytes!("../tests/fixtures/admission/apiserver-ca.pem"),
            "localhost"
        )
        .is_err()
    );
    assert!(
        ApiTls::from_pem(
            CERT,
            include_bytes!("../tests/fixtures/admission/apiserver.key"),
            CA,
            "localhost"
        )
        .is_err()
    );
    assert!(
        ApiTls::from_pem(b"PRIVATE-CERT-MARKER", KEY, CA, "localhost")
            .err()
            .unwrap()
            .to_string()
            .find("PRIVATE-CERT-MARKER")
            .is_none()
    );
    for timestamp in [
        "2025-01-01T00:00:00Z",
        "2037-01-01T00:00:00Z",
        "2036-09-30T04:30:15Z",
    ] {
        assert!(tls.validity.check(time(timestamp)).is_err());
    }
    tls.validity.check(time("2036-09-30T04:29:00Z")).unwrap();
}

#[cfg(unix)]
#[test]
fn bounded_private_key_files_allow_reviewed_projected_secrets_without_group_write() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("tls.crt");
    let key = dir.path().join("tls.key");
    let ca = dir.path().join("ca.crt");
    std::fs::write(&cert, CERT).unwrap();
    std::fs::write(&key, KEY).unwrap();
    std::fs::write(&ca, CA).unwrap();
    let files = ApiTlsFiles {
        certificate: cert.clone(),
        private_key: key.clone(),
        ca: ca.clone(),
        server_name: "127.0.0.1".into(),
    };
    for mode in [0o400, 0o600] {
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
        files.load().unwrap();
    }
    let link = dir.path().join("projected.key");
    symlink(&key, &link).unwrap();
    ApiTlsFiles {
        private_key: link,
        ..files.clone()
    }
    .load()
    .unwrap();
    for mode in [0o644, 0o640, 0o660, 0o444, 0o700] {
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(files.load().is_err());
    }
    assert!(private_mode_allowed(0, 10001, 0o440, 10001, 10001));
    assert!(!private_mode_allowed(10002, 10001, 0o440, 10001, 10001));
    assert!(!private_mode_allowed(0, 10002, 0o440, 10001, 10001));
    assert!(!private_mode_allowed(0, 0, 0o440, 0, 0));
    assert!(!private_mode_allowed(0, 10001, 0o640, 10001, 10001));
    assert!(!private_mode_allowed(10001, 10001, 0o4600, 10001, 10001));
    assert!(
        ApiTlsFiles {
            private_key: dir.path().into(),
            ..files.clone()
        }
        .load()
        .is_err()
    );
    assert!(
        ApiTlsFiles {
            private_key: "relative-key".into(),
            ..files.clone()
        }
        .load()
        .is_err()
    );
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&key, vec![b'x'; 16385]).unwrap();
    assert!(files.load().is_err());
}

#[tokio::test]
async fn real_https_api_transport_rejects_plaintext_and_untrusted_peer_then_drains()
-> anyhow::Result<()> {
    let (addr, stop, task) = running(
        Router::new().route("/health/live", get(|| async { StatusCode::NO_CONTENT })),
        Some(fixture_tls()),
    )
    .await;
    let result = async {
        assert_eq!(
            client()
                .get(format!("https://{addr}/health/live"))
                .send()
                .await?
                .status(),
            StatusCode::NO_CONTENT
        );
        for version in [
            reqwest::tls::Version::TLS_1_2,
            reqwest::tls::Version::TLS_1_3,
        ] {
            let c = reqwest::Client::builder()
                .no_proxy()
                .https_only(true)
                .timeout(Duration::from_secs(3))
                .min_tls_version(version)
                .max_tls_version(version)
                .add_root_certificate(reqwest::Certificate::from_pem(CA)?)
                .build()?;
            assert_eq!(
                c.get(format!("https://{addr}/health/live"))
                    .send()
                    .await?
                    .status(),
                StatusCode::NO_CONTENT
            );
        }
        let untrusted = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()?;
        assert!(
            untrusted
                .get(format!("https://{addr}/health/live"))
                .send()
                .await
                .is_err()
        );
        assert!(
            untrusted
                .get(format!("http://{addr}/health/live"))
                .send()
                .await
                .is_err()
        );
        let mut incomplete = tokio::net::TcpStream::connect(addr).await?;
        incomplete.write_all(&[0x16]).await?;
        let mut byte = [0];
        let closed =
            tokio::time::timeout(Duration::from_secs(4), incomplete.read(&mut byte)).await?;
        assert!(closed.is_err() || closed? == 0);
        Ok::<_, anyhow::Error>(())
    }
    .await;
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(2), task).await???;
    result
}

#[tokio::test]
async fn shared_cancellation_closes_https_stream_and_readiness_is_never_success_during_drain()
-> anyhow::Result<()> {
    use futures_util::stream;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let stop = CancellationToken::new();
    let body_stop = stop.clone();
    let app=Router::new().route("/stream",get(move|| {let s=body_stop.clone();async move {Body::from_stream(stream::unfold(s,|s|async move {tokio::select! {biased;_=s.cancelled()=>None,_=tokio::time::sleep(Duration::from_millis(10))=>Some((Ok::<_,std::io::Error>(axum::body::Bytes::from_static(b"data\n")),s))}}))}}));
    let task = tokio::spawn(serve(listener, Some(fixture_tls()), app, stop.clone()));
    let mut response = client()
        .get(format!("https://{addr}/stream"))
        .send()
        .await?;
    assert!(response.chunk().await?.is_some());
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(2), async {
        while response.chunk().await?.is_some() {}
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    tokio::time::timeout(Duration::from_secs(2), task).await???;
    use tower::ServiceExt;
    let boundary = Router::new()
        .route("/health/ready", get(|| async { StatusCode::NO_CONTENT }))
        .layer(axum::middleware::from_fn_with_state(stop, drain_boundary));
    let reply = boundary
        .oneshot(
            axum::http::Request::builder()
                .uri("/health/ready")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(reply.status(), StatusCode::SERVICE_UNAVAILABLE);
    Ok(())
}

#[tokio::test]
async fn nonloopback_listener_cannot_call_transport_without_tls() -> anyhow::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:0").await?;
    assert!(
        serve(listener, None, Router::new(), CancellationToken::new())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicit disposable PostgreSQL and real loopback HTTPS sockets"]
async fn real_pg_https_signed_oidc_api_smoke() -> anyhow::Result<()> {
    use crate::{
        api::{AppState, router_with_shutdown},
        auth::{AuthConfig, JwtAuthenticator},
        history::CursorSigner,
        test_support_db as support,
    };
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use serde_json::{Value, json};
    let _serial = support::serial().await;
    // The common Fixture::new initializer changes global safe_mode. This smoke
    // must coexist with other suites: only create an independent tenant here.
    let runtime_url = std::env::var("TEST_DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("TEST_DATABASE_URL is required"))?;
    let owner_url = std::env::var("TEST_MIGRATION_DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("TEST_MIGRATION_DATABASE_URL is required"))?;
    let runtime_target = url::Url::parse(&runtime_url)?;
    let owner_target = url::Url::parse(&owner_url)?;
    anyhow::ensure!(
        runtime_target.host_str() == owner_target.host_str()
            && runtime_target.port_or_known_default() == owner_target.port_or_known_default()
            && runtime_target.path() == owner_target.path()
            && runtime_target.username() != owner_target.username(),
        "Dedicated runtime and owner identities must target the same disposable database"
    );
    let owner = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&owner_url)
        .await?;
    anyhow::ensure!(
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=37 AND success)"
        )
        .fetch_one(&owner)
        .await?,
        "Normal production migrations through 0037 are required"
    );
    let database = crate::db::Database::connect(&runtime_url, 4).await?;
    database.verify_runtime_role().await?;
    let tenant_id = uuid::Uuid::new_v4();
    let principal_id = uuid::Uuid::new_v4();
    let project_id = uuid::Uuid::new_v4();
    let mut tx = owner.begin().await?;
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(tenant_id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO tenants(id,name) VALUES($1,'TLS smoke tenant')")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO principals(id,kind,display_name) VALUES($1,'SERVICE','TLS smoke service')",
    )
    .bind(principal_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO principal_identities(principal_id,issuer,subject,service_client_id,service_binding_generation) VALUES($1,'https://issuer.example.test',$2,'fixture-client',1)").bind(principal_id).bind(principal_id.to_string()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO projects(id,tenant_id,name,max_ttl_seconds,runtime_namespace,storage_class) VALUES($1,$2,'TLS smoke project',86400,$3,'integration-storage')").bind(project_id).bind(tenant_id).bind(format!("tls-{}",project_id.simple())).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,'instances:read')").bind(tenant_id).bind(project_id).bind(principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let jwks_addr = listener.local_addr()?;
    let jwks_task = tokio::spawn(async move {
        axum::serve(listener,Router::new().route("/jwks",get(||async {axum::Json(json!({"keys":[serde_json::from_str::<Value>(include_str!("../tests/fixtures/auth/jwk-a.json")).unwrap()]}))}))).await
    });
    let auth = JwtAuthenticator::new(AuthConfig {
        scope_profile: Default::default(),
        issuer: "https://issuer.example.test".into(),
        audience: "sandbox-api".into(),
        jwks_url: format!("http://{jwks_addr}/jwks"),
        required_scopes: vec!["sandbox:access".into()],
        jwks_ttl_seconds: 60,
        clock_skew_seconds: 0,
        allow_loopback_http: true,
        max_token_lifetime_seconds: 300,
    })?;
    let state = Arc::new(AppState {
        database: database.clone(),
        auth,
        cursor_signer: CursorSigner::from_json(include_str!(
            "../tests/fixtures/history/cursor-keys.json"
        ))?,
        output_reader: None,
        metrics: None,
        default_ttl_seconds: 3600,
        max_ttl_seconds: 86400,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let stop = CancellationToken::new();
    let task = tokio::spawn(serve(
        listener,
        Some(fixture_tls()),
        router_with_shutdown(state, stop.clone()),
        stop.clone(),
    ));
    let result=async {
        let client=client();
        assert_eq!(client.get(format!("https://{addr}/health/ready")).send().await?.status(),StatusCode::NO_CONTENT);
        let path=format!("https://{addr}/v1/instances?project_id={project_id}");
        assert_eq!(client.get(&path).header("x-tenant-id",tenant_id.to_string()).send().await?.status(),StatusCode::UNAUTHORIZED);
        let mut header=Header::new(Algorithm::RS256);header.kid=Some("key-a".into());header.typ=Some("at+jwt".into());let now=Utc::now().timestamp();
        let claims=json!({"iss":"https://issuer.example.test","aud":"sandbox-api","sub":principal_id.to_string(),"client_id":"fixture-client","jti":uuid::Uuid::new_v4(),"iat":now,"exp":now+120,"scope":"sandbox:access"});
        let token=jsonwebtoken::encode(&header,&claims,&EncodingKey::from_rsa_der(include_bytes!("../tests/fixtures/auth/rsa-a.der")))?;
        let response=client.get(&path).header("x-tenant-id",tenant_id.to_string()).bearer_auth(&token).send().await?;
        assert_eq!(response.status(),StatusCode::OK);assert_eq!(response.json::<Value>().await?["items"],json!([]));
        let wrong=jsonwebtoken::encode(&header,&claims,&EncodingKey::from_rsa_der(include_bytes!("../tests/fixtures/auth/rsa-b.der")))?;
        assert_eq!(client.get(&path).header("x-tenant-id",tenant_id.to_string()).bearer_auth(wrong).send().await?.status(),StatusCode::UNAUTHORIZED);
        Ok::<_,anyhow::Error>(())
    }.await;
    stop.cancel();
    task.await??;
    jwks_task.abort();
    database.pool.close().await;
    owner.close().await;
    result
}
