// The shared database fixture exposes helpers used by other integration crates.
#[allow(dead_code)]
mod support;

use std::{env, io::Write, process::Stdio, sync::Arc, time::Duration};

use anyhow::{Context, ensure};
use axum::{
    Router,
    http::{HeaderValue, StatusCode},
    routing::get,
};
use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use sandbox_platform::{
    api::{AppState, router},
    auth::{AuthConfig, JwtAuthenticator, ScopeProfile, VerifiedIdentity},
    db::Database,
    operator_access::{
        GrantNodeImageReader, OperatorAccess, RevokeNodeImageReader, grant_node_image_reader,
        revoke_node_image_reader,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};
use support::Fixture;
use url::Url;
use uuid::Uuid;

const ACCESS_PATH: &str = "/v1/operator/access";

#[path = "operator_access/node_images.rs"]
mod node_images;

fn grant_document() -> Value {
    json!({
        "grant_id": Uuid::new_v4(), "installation_id": Uuid::new_v4(), "cluster_epoch": Uuid::new_v4(),
        "issuer": "https://issuer.example.test", "subject": "reviewed-service-subject",
        "client_id": "reviewed-operator-client", "expires_at": (Utc::now() + ChronoDuration::hours(1)).to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        "reason": "Reviewed node image observation access"
    })
}

fn revoke_document(grant: &Value) -> Value {
    json!({"grant_id": grant["grant_id"], "installation_id": grant["installation_id"],
           "cluster_epoch": grant["cluster_epoch"], "reason": "Reviewed permanent revocation"})
}

#[test]
fn operator_request_parsers_enforce_strict_bounded_json_and_non_nil_scope() -> anyhow::Result<()> {
    let grant = grant_document();
    let revoke = revoke_document(&grant);
    for value in [&grant, &revoke] {
        let check = |bytes: &[u8]| {
            if value.get("issuer").is_some() {
                GrantNodeImageReader::parse(bytes, false).is_ok()
            } else {
                RevokeNodeImageReader::parse(bytes).is_ok()
            }
        };
        ensure!(check(&serde_json::to_vec(value)?));
        let mut at_limit = serde_json::to_vec(value)?;
        at_limit.resize(16 * 1024, b' ');
        ensure!(check(&at_limit), "A 16 KiB request must be accepted");
        at_limit.push(b' ');
        ensure!(!check(&at_limit), "The byte limit must reject 16385 bytes");
        for field in ["grant_id", "installation_id", "cluster_epoch"] {
            for invalid in [
                json!(Uuid::nil()),
                json!("not-a-uuid"),
                Value::Null,
                json!(1),
            ] {
                let mut bad = (*value).clone();
                bad[field] = invalid;
                ensure!(
                    !check(&serde_json::to_vec(&bad)?),
                    "Invalid scope field {field}"
                );
            }
        }
        let mut unknown = (*value).clone();
        unknown["unreviewed"] = json!(true);
        ensure!(!check(&serde_json::to_vec(&unknown)?));
        for field in value.as_object().context("Request object")?.keys() {
            let mut missing = (*value).clone();
            missing
                .as_object_mut()
                .context("Request object")?
                .remove(field);
            ensure!(
                !check(&serde_json::to_vec(&missing)?),
                "Required field {field}"
            );
        }
        let valid = serde_json::to_string(value)?;
        let duplicate = format!("{{\"grant_id\":{},{}", value["grant_id"], &valid[1..]);
        ensure!(!check(duplicate.as_bytes()));
        for malformed in [b"[]".as_slice(), b"null", b"{", b"\xff"] {
            ensure!(!check(malformed));
        }
    }
    Ok(())
}

#[test]
fn operator_request_text_limits_count_utf8_bytes_and_reject_controls() -> anyhow::Result<()> {
    let grant = grant_document();
    let revoke = revoke_document(&grant);
    for value in [&grant, &revoke] {
        for reason in ["r".repeat(256), "界".repeat(85) + "a"] {
            let mut valid = (*value).clone();
            valid["reason"] = json!(reason);
            if value.get("issuer").is_some() {
                ensure!(GrantNodeImageReader::parse(&serde_json::to_vec(&valid)?, false).is_ok());
            } else {
                ensure!(RevokeNodeImageReader::parse(&serde_json::to_vec(&valid)?).is_ok());
            }
        }
        for reason in [
            String::new(),
            " \u{2003} ".into(),
            "r".repeat(257),
            "界".repeat(86),
            "review\nreason".into(),
            "review\0reason".into(),
        ] {
            let mut bad = (*value).clone();
            bad["reason"] = json!(reason);
            if value.get("issuer").is_some() {
                ensure!(GrantNodeImageReader::parse(&serde_json::to_vec(&bad)?, false).is_err());
            } else {
                ensure!(RevokeNodeImageReader::parse(&serde_json::to_vec(&bad)?).is_err());
            }
        }
    }
    for subject in ["s".repeat(512), "界".repeat(170) + "ab"] {
        let mut valid = grant.clone();
        valid["subject"] = json!(subject);
        ensure!(GrantNodeImageReader::parse(&serde_json::to_vec(&valid)?, false).is_ok());
    }
    for subject in [
        String::new(),
        " ".into(),
        "s".repeat(513),
        "界".repeat(171),
        "reviewed\nsubject".into(),
    ] {
        let mut bad = grant.clone();
        bad["subject"] = json!(subject);
        ensure!(GrantNodeImageReader::parse(&serde_json::to_vec(&bad)?, false).is_err());
    }
    for client in [
        "reviewed-client".to_owned(),
        "c".repeat(256),
        "界".repeat(85) + "a",
        "c".repeat(257),
        String::new(),
        " ".into(),
        "bad\nclient".into(),
    ] {
        let mut value = grant.clone();
        value["client_id"] = json!(client);
        ensure!(
            GrantNodeImageReader::parse(&serde_json::to_vec(&value)?, false).is_ok()
                == sandbox_platform::auth::valid_client_id(&client)
        );
    }
    Ok(())
}

#[test]
fn operator_grant_issuer_requires_explicit_literal_loopback_development() -> anyhow::Result<()> {
    let mut grant = grant_document();
    for issuer in [
        "http://127.0.0.1:8080/realms/test",
        "http://[::1]:8080/realms/test",
    ] {
        grant["issuer"] = json!(issuer);
        let bytes = serde_json::to_vec(&grant)?;
        ensure!(GrantNodeImageReader::parse(&bytes, false).is_err());
        ensure!(GrantNodeImageReader::parse(&bytes, true).is_ok());
    }
    for issuer in [
        "http://localhost:8080/realms/test",
        "http://10.0.0.1/realms/test",
        "http://127.0.0.1.attacker.invalid/realms/test",
        "https://user:password@issuer.example.test/realm",
        "https://issuer.example.test/realm?secret=value",
        "https://issuer.example.test/realm#fragment",
        "file:///realm",
        "not-a-url",
    ] {
        grant["issuer"] = json!(issuer);
        ensure!(GrantNodeImageReader::parse(&serde_json::to_vec(&grant)?, true).is_err());
    }
    grant["issuer"] = json!("https://issuer.example.test/realm");
    for expiry in [
        json!("not-a-time"),
        json!("2026-10-16T00:00:00"),
        json!("2026-02-30T00:00:00Z"),
        json!(0),
        Value::Null,
    ] {
        grant["expires_at"] = expiry;
        ensure!(GrantNodeImageReader::parse(&serde_json::to_vec(&grant)?, false).is_err());
    }
    Ok(())
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
}

fn required(name: &str) -> anyhow::Result<String> {
    let value = env::var(name).with_context(|| format!("{name} is required"))?;
    ensure!(!value.is_empty(), "{name} must not be empty");
    Ok(value)
}

async fn live_machine_identity() -> anyhow::Result<(JwtAuthenticator, VerifiedIdentity, HeaderValue)>
{
    let issuer = required("SANDBOX_OIDC_ISSUER")?;
    let issuer_url = Url::parse(&issuer).context("Invalid test issuer")?;
    let allow_loopback_http = issuer_url.scheme() == "http"
        && matches!(issuer_url.host_str(), Some("127.0.0.1" | "[::1]"));
    let auth = JwtAuthenticator::new(AuthConfig {
        issuer: issuer.clone(),
        audience: "sandbox-api".into(),
        jwks_url: required("SANDBOX_OIDC_JWKS_URL")?,
        required_scopes: vec!["sandbox:access".into()],
        scope_profile: Default::default(),
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
    // Credentials, the token endpoint body and the bearer are never diagnostic output.
    ensure!(
        response.status().is_success(),
        "Keycloak token request failed with status {}",
        response.status()
    );
    let token: TokenResponse = response.json().await.context("Invalid Keycloak response")?;
    ensure!(token.token_type.eq_ignore_ascii_case("bearer"));
    let identity = auth.verify(&token.access_token).await?;
    ensure!(identity.issuer == issuer);
    ensure!(identity.client_id.as_deref() == Some(client_id.as_str()));
    let mut authorization = HeaderValue::from_str(&format!("Bearer {}", token.access_token))?;
    authorization.set_sensitive(true);
    Ok((auth, identity, authorization))
}

fn app(fixture: &Fixture, auth: JwtAuthenticator) -> anyhow::Result<Router> {
    Ok(router(Arc::new(AppState {
        database: fixture.database.clone(),
        auth,
        cursor_signer: sandbox_platform::history::CursorSigner::from_json(include_str!(
            "fixtures/history/cursor-keys.json"
        ))?,
        output_reader: None,
        metrics: None,
        default_ttl_seconds: 300,
        max_ttl_seconds: 86400,
    })))
}

async fn operator_response(
    app: &Router,
    authorization: Option<&HeaderValue>,
    path: &str,
    expected: StatusCode,
) -> anyhow::Result<Value> {
    // This is a real development loopback HTTP exchange, not certification of
    // the sandboxd TLS listener or production identity-provider deployment.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let shutdown = tokio_util::sync::CancellationToken::new();
    let server_shutdown = shutdown.clone();
    let router = app.clone();
    let mut server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(server_shutdown.cancelled_owned())
            .await
    });
    let collected = async {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .read_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(10))
            .build()?;
        // Installation access is deliberately requested without x-tenant-id.
        let mut request = client
            .get(format!("http://{address}{path}"))
            .header("connection", "close");
        if let Some(authorization) = authorization {
            request = request.header("authorization", authorization);
        }
        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;
        Ok::<_, anyhow::Error>((status, headers, bytes))
    }
    .await;
    shutdown.cancel();
    let retired = match tokio::time::timeout(Duration::from_secs(2), &mut server).await {
        Ok(Ok(Ok(()))) => true,
        Ok(_) => false,
        Err(_) => {
            server.abort();
            let _joined = server.await;
            false
        }
    };
    if !retired {
        return Err(match collected {
            Ok(_) => anyhow::anyhow!("Operator HTTP fixture did not retire normally"),
            Err(error) => error.context("Operator HTTP fixture retirement also failed"),
        });
    }
    // No status/body assertion can bypass cancellation and the actual task join.
    let (status, headers, bytes) = collected?;
    ensure!(
        status == expected,
        "Operator access returned {status}; expected {expected}"
    );
    ensure!(
        headers
            .get("cache-control")
            .is_some_and(|value| value == "no-store")
    );
    ensure!(
        headers
            .get("x-content-type-options")
            .is_some_and(|value| value == "nosniff")
    );
    if expected == StatusCode::UNAUTHORIZED {
        ensure!(
            headers
                .get("www-authenticate")
                .is_some_and(|value| value == "Bearer")
        );
    }
    let request_id = headers
        .get("x-request-id")
        .context("Missing request identifier")?
        .to_str()?
        .to_owned();
    Uuid::parse_str(&request_id)?;
    let body: Value = serde_json::from_slice(&bytes).context("Invalid operator response")?;
    if !expected.is_success() {
        ensure!(body["request_id"] == request_id);
        ensure!(body["status"] == expected.as_u16());
    }
    Ok(body)
}

#[tokio::test]
#[ignore = "Requires real Keycloak, disposable PostgreSQL and SANDBOX_MACHINE_* credentials"]
async fn real_keycloak_without_installation_grant_is_forbidden() -> anyhow::Result<()> {
    let _serial = support::serial().await;
    let fixture = Fixture::new(1).await?;
    let (auth, identity, authorization) = match live_machine_identity().await {
        Ok(live) => live,
        Err(error) => {
            fixture.database.pool.close().await;
            fixture.owner.close().await;
            return Err(error);
        }
    };
    // Explicit owner fixture metadata binds an existing SERVICE to the verified
    // real client. Existing tenant instances:read grants confer no global access.
    sqlx::query("INSERT INTO principal_identities(principal_id,issuer,subject,service_client_id,service_binding_generation) VALUES($1,$2,$3,$4,1)")
        .bind(fixture.actor.principal_id)
        .bind(&identity.issuer)
        .bind(&identity.subject)
        .bind(&identity.client_id)
        .execute(&fixture.owner)
        .await
        .context("Cannot register the isolated live service identity")?;
    let outcome = async {
        let app = app(&fixture, auth)?;
        let denied = operator_response(
            &app,
            Some(&authorization),
            ACCESS_PATH,
            StatusCode::FORBIDDEN,
        )
        .await?;
        ensure!(denied["code"] == "PERMISSION_DENIED");
        let anonymous =
            operator_response(&app, None, ACCESS_PATH, StatusCode::UNAUTHORIZED).await?;
        ensure!(anonymous["code"] == "UNAUTHENTICATED");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    // Remove only this fixture's live subject mapping even after an HTTP error.
    let cleanup = sqlx::query(
        "DELETE FROM principal_identities WHERE principal_id=$1 AND issuer=$2 AND subject=$3",
    )
    .bind(fixture.actor.principal_id)
    .bind(&identity.issuer)
    .bind(&identity.subject)
    .execute(&fixture.owner)
    .await;
    fixture.database.pool.close().await;
    fixture.owner.close().await;
    outcome?;
    ensure!(
        cleanup?.rows_affected() == 1,
        "Live identity cleanup failed"
    );
    Ok(())
}

async fn prepare_live_fixture()
-> anyhow::Result<(Fixture, JwtAuthenticator, VerifiedIdentity, HeaderValue)> {
    let fixture = Fixture::new(1).await?;
    // Sign only after normal migrations/schema checks and serial waiting finish.
    let setup = async {
        let (auth, identity, authorization) = live_machine_identity().await?;
        sqlx::query("INSERT INTO principal_identities(principal_id,issuer,subject,service_client_id,service_binding_generation) VALUES($1,$2,$3,$4,1)")
            .bind(fixture.actor.principal_id)
            .bind(&identity.issuer)
            .bind(&identity.subject)
            .bind(&identity.client_id)
            .execute(&fixture.owner)
            .await?;
        Ok::<_, anyhow::Error>((auth, identity, authorization))
    }.await;
    match setup {
        Ok((auth, identity, authorization)) => Ok((fixture, auth, identity, authorization)),
        Err(error) => {
            fixture.database.pool.close().await;
            fixture.owner.close().await;
            Err(error)
        }
    }
}

async fn finish_live_fixture(
    fixture: Fixture,
    identity: &VerifiedIdentity,
    outcome: anyhow::Result<()>,
) -> anyhow::Result<()> {
    // A failed USER-kind injection must not block retirement through 0040's
    // SERVICE binding-shape guard. Restore only this exact fixture principal.
    let restored = sqlx::query("UPDATE principals p SET kind='SERVICE' WHERE p.id=$1 AND EXISTS(SELECT 1 FROM principal_identities i WHERE i.principal_id=p.id AND i.issuer=$2 AND i.subject=$3)")
        .bind(fixture.actor.principal_id)
        .bind(&identity.issuer)
        .bind(&identity.subject)
        .execute(&fixture.owner)
        .await;
    // Grants retain a foreign key to identity history. Retire only this test's
    // mapping, preserving that history and freeing the fixed real IdP subject.
    let cleanup = sqlx::query("UPDATE principal_identities SET enabled=false,subject=$4 WHERE principal_id=$1 AND issuer=$2 AND subject=$3")
        .bind(fixture.actor.principal_id)
        .bind(&identity.issuer)
        .bind(&identity.subject)
        .bind(format!("retired-operator-test-{}", Uuid::new_v4()))
        .execute(&fixture.owner)
        .await;
    fixture.database.pool.close().await;
    fixture.owner.close().await;
    if !restored
        .as_ref()
        .is_ok_and(|result| result.rows_affected() == 1)
        || !cleanup
            .as_ref()
            .is_ok_and(|result| result.rows_affected() == 1)
    {
        return Err(match outcome {
            Ok(()) => anyhow::anyhow!("Live identity retirement failed"),
            Err(error) => error.context("Live identity retirement also failed"),
        });
    }
    outcome
}

async fn live_grant_document(
    fixture: &Fixture,
    identity: &VerifiedIdentity,
) -> anyhow::Result<Value> {
    let (installation, epoch): (Uuid, Uuid) = sqlx::query_as(
        "SELECT installation_id,cluster_epoch FROM platform_configuration WHERE singleton",
    )
    .fetch_one(&fixture.owner)
    .await?;
    let mut document = grant_document();
    document["installation_id"] = json!(installation);
    document["cluster_epoch"] = json!(epoch);
    document["issuer"] = json!(identity.issuer);
    document["subject"] = json!(identity.subject);
    document["client_id"] = json!(identity.client_id.as_deref().context("SERVICE client")?);
    Ok(document)
}

async fn expect_operator_access(
    app: &Router,
    authorization: &HeaderValue,
    grant: &GrantNodeImageReader,
) -> anyhow::Result<()> {
    let body = operator_response(app, Some(authorization), ACCESS_PATH, StatusCode::OK).await?;
    ensure!(body.as_object().context("Access object")?.len() == 5);
    let access: OperatorAccess = serde_json::from_value(body)?;
    ensure!(access.installation_id == grant.installation_id);
    ensure!(access.cluster_epoch == grant.cluster_epoch);
    ensure!(access.grant_id == grant.grant_id);
    ensure!(access.action == "node_images:read");
    ensure!(access.expires_at == grant.expires_at);
    Ok(())
}

async fn apply_operator_cli(document: &Value, revoke: bool) -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let mut request = tempfile::NamedTempFile::new_in(temporary.path())?;
    request.write_all(&serde_json::to_vec(document)?)?;
    request.flush()?;
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_sandbox-admin"));
    command
        .arg("node-image-reader")
        .arg("--file")
        .arg(request.path())
        .arg("--apply")
        .arg("--allow-loopback-http")
        .env(
            "SANDBOX_ADMIN_DATABASE_URL",
            required("TEST_MIGRATION_DATABASE_URL")?,
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if revoke {
        command.arg("--revoke");
    }
    let mut child = command
        .spawn()
        .context("Cannot start the actual sandbox-admin binary")?;
    let status = match tokio::time::timeout(Duration::from_secs(15), child.wait()).await {
        Ok(result) => result?,
        Err(_) => {
            let stopped = child.start_kill();
            let reaped = child.wait().await;
            stopped?;
            reaped?;
            anyhow::bail!("Operator CLI exceeded its test deadline and was reaped");
        }
    };
    // The real process gets the owner URL only through its environment. Its
    // output is never copied into test logs; HTTP supplies the observable result.
    ensure!(status.success(), "Operator CLI failed with status {status}");
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real Keycloak, disposable PostgreSQL and SANDBOX_MACHINE_* credentials"]
async fn real_keycloak_installation_access_requires_owner_grant_and_permanent_revocation()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let (fixture, auth, identity, authorization) = prepare_live_fixture().await?;
    let outcome = async {
        let app = app(&fixture, auth)?;
        let owner = Database {
            pool: fixture.owner.clone(),
        };
        let document = live_grant_document(&fixture, &identity).await?;
        let grant = GrantNodeImageReader::parse(&serde_json::to_vec(&document)?, true)?;
        let revoke =
            RevokeNodeImageReader::parse(&serde_json::to_vec(&revoke_document(&document))?)?;
        // Neither project instances:read nor a tenant-wide wildcard grants
        // installation authority, even though the SERVICE is correctly bound.
        operator_response(
            &app,
            Some(&authorization),
            ACCESS_PATH,
            StatusCode::FORBIDDEN,
        )
        .await?;
        let mut tx = fixture.owner_transaction().await?;
        sqlx::query(
            "INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,NULL,$2,'*')",
        )
        .bind(fixture.actor.tenant_id)
        .bind(fixture.actor.principal_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        operator_response(
            &app,
            Some(&authorization),
            ACCESS_PATH,
            StatusCode::FORBIDDEN,
        )
        .await?;
        ensure!(matches!(
            grant_node_image_reader(&fixture.database, &grant).await,
            Err(sandbox_platform::admin::AdminError::OwnerRequired)
        ));
        ensure!(matches!(
            revoke_node_image_reader(&fixture.database, &revoke).await,
            Err(sandbox_platform::admin::AdminError::OwnerRequired)
        ));
        let mut strict =
            GrantNodeImageReader::parse(&serde_json::to_vec(&grant_document())?, false)?;
        strict.issuer = "http://127.0.0.1:8080/realms/test".into();
        ensure!(
            matches!(
                grant_node_image_reader(&owner, &strict).await,
                Err(sandbox_platform::admin::AdminError::Invalid(_))
            ),
            "Mutating a parsed request cannot enable the development issuer profile"
        );
        for statement in [
            "SELECT id FROM node_image_reader_grants LIMIT 0",
            "SELECT id FROM node_image_reader_audit LIMIT 0",
            "SELECT sandbox_grant_node_image_reader(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)",
            "SELECT sandbox_revoke_node_image_reader(NULL,NULL,NULL,NULL)",
        ] {
            support::require_pg_error(
                sqlx::query(statement).execute(&fixture.database.pool).await,
                "42501",
            )?;
        }
        // SQL checks time against its own clock after acquiring authority locks.
        let now: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&fixture.owner)
            .await?;
        for expiry in [
            now - ChronoDuration::seconds(1),
            now + ChronoDuration::hours(25),
        ] {
            let mut invalid = GrantNodeImageReader::parse(&serde_json::to_vec(&document)?, true)?;
            invalid.grant_id = Uuid::new_v4();
            invalid.expires_at = expiry;
            ensure!(grant_node_image_reader(&owner, &invalid).await.is_err());
            operator_response(
                &app,
                Some(&authorization),
                ACCESS_PATH,
                StatusCode::FORBIDDEN,
            )
            .await?;
        }
        for field in ["installation_id", "cluster_epoch", "client_id", "subject"] {
            let mut wrong = document.clone();
            wrong[field] = if matches!(field, "installation_id" | "cluster_epoch") {
                json!(Uuid::new_v4())
            } else {
                json!("unregistered-operator-identity")
            };
            let invalid = GrantNodeImageReader::parse(&serde_json::to_vec(&wrong)?, true)?;
            ensure!(
                grant_node_image_reader(&owner, &invalid).await.is_err(),
                "Unexpected grant for {field}"
            );
        }
        apply_operator_cli(&document, false).await?;
        let accepted = grant_node_image_reader(&owner, &grant).await?;
        ensure!(accepted.grant_id == grant.grant_id);
        expect_operator_access(&app, &authorization, &grant).await?;
        ensure!(grant_node_image_reader(&owner, &grant).await? == accepted);
        // Exact-ID retry is safe; changing the reason/expiry under that ID is not.
        for field in ["reason", "expires_at"] {
            let mut changed = document.clone();
            changed[field] = if field == "reason" {
                json!("Different reviewed purpose")
            } else {
                json!((grant.expires_at + ChronoDuration::minutes(1)).to_rfc3339())
            };
            let conflict = GrantNodeImageReader::parse(&serde_json::to_vec(&changed)?, true)?;
            ensure!(grant_node_image_reader(&owner, &conflict).await.is_err());
            expect_operator_access(&app, &authorization, &grant).await?;
        }
        for query in [
            "installation_id=PRIVATE-MARKER",
            "tenant_id=PRIVATE-MARKER",
            "unknown=PRIVATE-MARKER",
            "x=1&x=2",
            "node_id=PRIVATE-MARKER",
        ] {
            let problem = operator_response(
                &app,
                Some(&authorization),
                &format!("{ACCESS_PATH}?{query}"),
                StatusCode::BAD_REQUEST,
            )
            .await?;
            ensure!(!problem.to_string().contains("PRIVATE-MARKER"));
        }
        // A wrong administrative scope must not revoke the actual authority.
        let mut wrong_revoke =
            RevokeNodeImageReader::parse(&serde_json::to_vec(&revoke_document(&document))?)?;
        wrong_revoke.installation_id = Uuid::new_v4();
        ensure!(
            revoke_node_image_reader(&owner, &wrong_revoke)
                .await
                .is_err()
        );
        expect_operator_access(&app, &authorization, &grant).await?;
        apply_operator_cli(&revoke_document(&document), true).await?;
        operator_response(
            &app,
            Some(&authorization),
            ACCESS_PATH,
            StatusCode::FORBIDDEN,
        )
        .await?;
        revoke_node_image_reader(&owner, &revoke).await?;
        ensure!(
            grant_node_image_reader(&owner, &grant).await.is_err(),
            "Revoked IDs cannot be revived"
        );
        operator_response(
            &app,
            Some(&authorization),
            ACCESS_PATH,
            StatusCode::FORBIDDEN,
        )
        .await?;
        let mut replacement = GrantNodeImageReader::parse(&serde_json::to_vec(&document)?, true)?;
        replacement.grant_id = Uuid::new_v4();
        grant_node_image_reader(&owner, &replacement).await?;
        expect_operator_access(&app, &authorization, &replacement).await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    finish_live_fixture(fixture, &identity, outcome).await
}

#[tokio::test]
#[ignore = "Requires real Keycloak, disposable PostgreSQL and SANDBOX_MACHINE_* credentials"]
async fn real_keycloak_identity_and_installation_scope_aba_never_revive_operator_access()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let (fixture, auth, identity, authorization) = prepare_live_fixture().await?;
    let mut original_scope = None;
    let outcome = async {
        let app = app(&fixture, auth)?;
        let owner = Database { pool: fixture.owner.clone() };
        let document = live_grant_document(&fixture, &identity).await?;
        let mut grant = GrantNodeImageReader::parse(&serde_json::to_vec(&document)?, true)?;
        original_scope = Some((grant.installation_id, grant.cluster_epoch));
        grant_node_image_reader(&owner, &grant).await?;
        expect_operator_access(&app, &authorization, &grant).await?;
        let current_client = identity.client_id.as_deref().context("SERVICE client")?;
        let alternate_client = format!("operator-rotation-{}", Uuid::new_v4());
        for (expected, next) in [(current_client, alternate_client.as_str()), (alternate_client.as_str(), current_client)] {
            sqlx::query("SELECT sandbox_bind_service_identity($1,$2,$3,$4,'Reviewed operator test rotation')")
                .bind(&identity.issuer).bind(&identity.subject).bind(expected).bind(next).execute(&fixture.owner).await?;
            operator_response(&app, Some(&authorization), ACCESS_PATH, StatusCode::FORBIDDEN).await?;
            ensure!(grant_node_image_reader(&owner, &grant).await.is_err());
        }
        grant.grant_id = Uuid::new_v4();
        grant_node_image_reader(&owner, &grant).await?;
        expect_operator_access(&app, &authorization, &grant).await?;
        for enabled in [false, true] {
            sqlx::query("UPDATE principals SET enabled=$2 WHERE id=$1")
                .bind(fixture.actor.principal_id).bind(enabled).execute(&fixture.owner).await?;
            operator_response(&app, Some(&authorization), ACCESS_PATH, StatusCode::FORBIDDEN).await?;
        }
        ensure!(grant_node_image_reader(&owner, &grant).await.is_err());
        grant.grant_id = Uuid::new_v4();
        grant_node_image_reader(&owner, &grant).await?;
        expect_operator_access(&app, &authorization, &grant).await?;
        for enabled in [false, true] {
            sqlx::query("UPDATE principal_identities SET enabled=$4 WHERE principal_id=$1 AND issuer=$2 AND subject=$3")
                .bind(fixture.actor.principal_id).bind(&identity.issuer).bind(&identity.subject).bind(enabled).execute(&fixture.owner).await?;
            operator_response(&app, Some(&authorization), ACCESS_PATH, StatusCode::FORBIDDEN).await?;
        }
        ensure!(grant_node_image_reader(&owner, &grant).await.is_err());
        grant.grant_id = Uuid::new_v4();
        grant_node_image_reader(&owner, &grant).await?;
        expect_operator_access(&app, &authorization, &grant).await?;
        sqlx::query("UPDATE principals SET authz_version=authz_version+1 WHERE id=$1")
            .bind(fixture.actor.principal_id).execute(&fixture.owner).await?;
        operator_response(&app, Some(&authorization), ACCESS_PATH, StatusCode::FORBIDDEN).await?;
        ensure!(grant_node_image_reader(&owner, &grant).await.is_err());
        grant.grant_id = Uuid::new_v4();
        grant_node_image_reader(&owner, &grant).await?;
        for kind in ["USER", "SERVICE"] {
            sqlx::query("UPDATE principals SET kind=$2 WHERE id=$1")
                .bind(fixture.actor.principal_id).bind(kind).execute(&fixture.owner).await?;
            operator_response(&app, Some(&authorization), ACCESS_PATH, StatusCode::FORBIDDEN).await?;
            let mut request = GrantNodeImageReader::parse(&serde_json::to_vec(&document)?, true)?;
            if kind == "USER" {
                request.grant_id = Uuid::new_v4();
            } else {
                request.grant_id = grant.grant_id;
            }
            ensure!(grant_node_image_reader(&owner, &request).await.is_err());
        }
        grant.grant_id = Uuid::new_v4();
        grant_node_image_reader(&owner, &grant).await?;
        expect_operator_access(&app, &authorization, &grant).await?;
        let foreign_epoch = Uuid::new_v4();
        for epoch in [foreign_epoch, grant.cluster_epoch] {
            sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton")
                .bind(epoch).execute(&fixture.owner).await?;
            operator_response(&app, Some(&authorization), ACCESS_PATH, StatusCode::FORBIDDEN).await?;
        }
        ensure!(grant_node_image_reader(&owner, &grant).await.is_err(), "Epoch ABA cannot revive a prior grant ID");
        grant.grant_id = Uuid::new_v4();
        grant_node_image_reader(&owner, &grant).await?;
        expect_operator_access(&app, &authorization, &grant).await?;
        for installation in [Uuid::new_v4(), grant.installation_id] {
            sqlx::query("UPDATE platform_configuration SET installation_id=$1 WHERE singleton")
                .bind(installation).execute(&fixture.owner).await?;
            operator_response(&app, Some(&authorization), ACCESS_PATH, StatusCode::FORBIDDEN).await?;
        }
        ensure!(grant_node_image_reader(&owner, &grant).await.is_err(), "Installation ABA cannot revive a prior grant ID");
        grant.grant_id = Uuid::new_v4();
        grant_node_image_reader(&owner, &grant).await?;
        expect_operator_access(&app, &authorization, &grant).await?;
        Ok::<(), anyhow::Error>(())
    }.await;
    let restore = if let Some((installation, epoch)) = original_scope {
        sqlx::query(
            "UPDATE platform_configuration SET installation_id=$1,cluster_epoch=$2 WHERE singleton",
        )
        .bind(installation)
        .bind(epoch)
        .execute(&fixture.owner)
        .await
        .map(|_| ())
    } else {
        Ok(())
    };
    let outcome = match restore {
        Ok(()) => outcome,
        Err(_) => Err(match outcome {
            Ok(()) => anyhow::anyhow!("Operator fixture scope restoration failed"),
            Err(error) => error.context("Operator fixture scope restoration also failed"),
        }),
    };
    finish_live_fixture(fixture, &identity, outcome).await
}

fn scoped_bearer(
    subject: &str,
    client: &str,
    scope: &str,
    kid: &str,
    expired: bool,
) -> anyhow::Result<HeaderValue> {
    let now = Utc::now().timestamp();
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("at+jwt".into());
    header.kid = Some(kid.into());
    let token = encode(
        &header,
        &json!({
            "iss": "https://issuer.example.test", "sub": subject, "aud": "sandbox-api", "client_id": client,
            "jti": Uuid::new_v4().to_string(), "iat": if expired { now - 120 } else { now },
            "exp": if expired { now - 1 } else { now + 300 }, "scope": scope
        }),
        &EncodingKey::from_rsa_der(include_bytes!("fixtures/auth/rsa-a.der")),
    )?;
    let mut bearer = HeaderValue::from_str(&format!("Bearer {token}"))?;
    bearer.set_sensitive(true);
    Ok(bearer)
}

#[tokio::test]
#[ignore = "Requires disposable PostgreSQL; uses the public RSA/JWKS protocol fixture"]
async fn action_scopes_require_exact_node_image_read_and_cannot_extend_an_expired_jwt()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let fixture = Fixture::new(1).await?;
    let jwk: Value = serde_json::from_str(include_str!("fixtures/auth/jwk-a.json"))?;
    let kid = jwk["kid"]
        .as_str()
        .context("Fixture signing key ID")?
        .to_owned();
    let keys = json!({"keys": [jwk]});
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
    let outcome = async {
        let client_id = "operator-scope-test";
        fixture.bind_client_id(client_id).await?;
        let auth = JwtAuthenticator::new(AuthConfig {
            issuer: "https://issuer.example.test".into(),
            audience: "sandbox-api".into(),
            jwks_url: format!("http://{address}/jwks"),
            required_scopes: vec!["sandbox:access".into()],
            scope_profile: ScopeProfile::ActionScopes,
            jwks_ttl_seconds: 300,
            clock_skew_seconds: 0,
            allow_loopback_http: true,
            max_token_lifetime_seconds: 300,
        })?;
        let app = app(&fixture, auth)?;
        let (installation, epoch): (Uuid, Uuid) = sqlx::query_as(
            "SELECT installation_id,cluster_epoch FROM platform_configuration WHERE singleton",
        )
        .fetch_one(&fixture.owner)
        .await?;
        let mut document = grant_document();
        document["installation_id"] = json!(installation);
        document["cluster_epoch"] = json!(epoch);
        document["subject"] = json!(fixture.actor.principal_id.to_string());
        document["client_id"] = json!(client_id);
        let grant = GrantNodeImageReader::parse(&serde_json::to_vec(&document)?, false)?;
        let owner = Database {
            pool: fixture.owner.clone(),
        };
        grant_node_image_reader(&owner, &grant).await?;
        let subject = fixture.actor.principal_id.to_string();
        for scope in [
            "sandbox:access",
            "sandbox:access *",
            "sandbox:access instances:read",
            "sandbox:access node_images:write",
        ] {
            let bearer = scoped_bearer(&subject, client_id, scope, &kid, false)?;
            let denied =
                operator_response(&app, Some(&bearer), ACCESS_PATH, StatusCode::FORBIDDEN).await?;
            ensure!(denied["code"] == "INSUFFICIENT_SCOPE");
        }
        let allowed = scoped_bearer(
            &subject,
            client_id,
            "sandbox:access node_images:read",
            &kid,
            false,
        )?;
        expect_operator_access(&app, &allowed, &grant).await?;
        let other_client = scoped_bearer(
            &subject,
            "unbound-client",
            "sandbox:access node_images:read",
            &kid,
            false,
        )?;
        operator_response(
            &app,
            Some(&other_client),
            ACCESS_PATH,
            StatusCode::FORBIDDEN,
        )
        .await?;
        let expired = scoped_bearer(
            &subject,
            client_id,
            "sandbox:access node_images:read",
            &kid,
            true,
        )?;
        operator_response(&app, Some(&expired), ACCESS_PATH, StatusCode::UNAUTHORIZED).await?;
        expect_operator_access(&app, &allowed, &grant).await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    server.abort();
    let joined = server.await;
    fixture.database.pool.close().await;
    fixture.owner.close().await;
    outcome?;
    ensure!(
        joined.is_err_and(|error| error.is_cancelled()),
        "Fixture JWKS server did not retire normally"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable PostgreSQL and distinct normal app/owner logins"]
async fn normal_startup_rejects_missing_operator_execute_and_private_table_privilege_drift()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let fixture = Fixture::new(1).await?;
    let outcome = async {
        fixture.database.verify_runtime_role().await?;
        for (inject, restore) in [
            ("REVOKE EXECUTE ON FUNCTION sandbox_node_image_access(text,text,text,bigint) FROM sandbox_app",
             "GRANT EXECUTE ON FUNCTION sandbox_node_image_access(text,text,text,bigint) TO sandbox_app"),
            ("GRANT SELECT ON node_image_reader_grants TO sandbox_app", "REVOKE SELECT ON node_image_reader_grants FROM sandbox_app"),
            ("GRANT UPDATE(installation_id) ON platform_configuration TO sandbox_app",
             "REVOKE UPDATE(installation_id) ON platform_configuration FROM sandbox_app"),
        ] {
            sqlx::query(inject).execute(&fixture.owner).await?;
            let rejected = fixture.database.verify_runtime_role().await.is_err();
            // Restore through the owner even if the public startup gate failed
            // to notice the injected drift; all further checks use normal roles.
            let restored = sqlx::query(restore).execute(&fixture.owner).await;
            ensure!(restored.is_ok(), "Operator startup fixture restoration failed");
            ensure!(rejected, "Normal startup accepted operator privilege drift");
            fixture.database.verify_runtime_role().await?;
        }
        Ok::<(), anyhow::Error>(())
    }.await;
    fixture.database.pool.close().await;
    fixture.owner.close().await;
    outcome
}

#[tokio::test]
#[ignore = "Requires real Keycloak, disposable PostgreSQL and distinct normal owner sessions"]
async fn real_keycloak_operator_grant_expiring_during_principal_lock_wait_is_denied()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let (fixture, auth, identity, authorization) = prepare_live_fixture().await?;
    let outcome = async {
        let app = app(&fixture, auth)?;
        let waiting_database = Database::connect(&required("TEST_MIGRATION_DATABASE_URL")?, 1).await?;
        let attempted = async {
            let (waiting_pid, login, lock_timeout): (i32, String, String) = sqlx::query_as(
                "SELECT pg_backend_pid(),session_user::text,current_setting('lock_timeout')",
            ).fetch_one(&waiting_database.pool).await?;
            ensure!(login == "sandbox_owner" && lock_timeout == "3s");
            let document = live_grant_document(&fixture, &identity).await?;
            let mut request = GrantNodeImageReader::parse(&serde_json::to_vec(&document)?, true)?;
            let mut blocker = fixture.owner.begin().await?;
            let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *blocker).await?;
            let _: Uuid = sqlx::query_scalar("SELECT id FROM principals WHERE id=$1 FOR UPDATE")
                .bind(fixture.actor.principal_id).fetch_one(&mut *blocker).await?;
            let expires: chrono::DateTime<Utc> = sqlx::query_scalar(
                "SELECT clock_timestamp()+interval '1 second'",
            ).fetch_one(&mut *blocker).await?;
            request.expires_at = expires;
            let database = waiting_database.clone();
            let mut pending = tokio::spawn(async move {
                grant_node_image_reader(&database, &request).await
            });
            let observed = async {
                let observation_deadline = tokio::time::Instant::now() + Duration::from_millis(750);
                loop {
                    // The fixture owner pool has two connections: one is the
                    // blocker, the other observes the separate normal owner PID.
                    let (waiting, still_valid): (bool, bool) = tokio::time::timeout_at(
                        observation_deadline,
                        sqlx::query_as("SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE a.pid=$1 AND a.usename=current_user AND a.datname=current_database() AND a.state='active' AND a.wait_event_type='Lock' AND $2=ANY(pg_blocking_pids(a.pid)) AND a.query LIKE 'SELECT sandbox_grant_node_image_reader%'),clock_timestamp()<$3")
                            .bind(waiting_pid).bind(blocker_pid).bind(expires).fetch_one(&fixture.owner),
                    ).await.context("Operator grant lock observation deadline expired")??;
                    if waiting {
                        ensure!(still_valid, "Grant was not valid when its real lock wait was observed");
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                let expiration_deadline = tokio::time::Instant::now() + Duration::from_millis(1250);
                loop {
                    let expired: bool = tokio::time::timeout_at(
                        expiration_deadline,
                        sqlx::query_scalar("SELECT clock_timestamp()>=$1")
                            .bind(expires).fetch_one(&fixture.owner),
                    ).await.context("Operator grant expiry observation deadline expired")??;
                    if expired {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Ok::<(), anyhow::Error>(())
            }.await;
            // Release the blocker and join the real library operation before
            // propagating any observation failure or checking authorization.
            let released = blocker.rollback().await;
            let completed = match tokio::time::timeout(Duration::from_secs(3), &mut pending).await {
                Ok(result) => result,
                Err(_) => {
                    pending.abort();
                    let joined = pending.await;
                    observed?; released?;
                    ensure!(joined.is_err_and(|error| error.is_cancelled()));
                    anyhow::bail!("Operator grant task did not retire after releasing its lock");
                }
            };
            observed?;
            released?;
            ensure!(matches!(completed?, Err(sandbox_platform::admin::AdminError::Database(code)) if code == "P4000"),
                    "Expired grant must fail its locked SQL time check, not the original lock timeout");
            let original_timeout: String = sqlx::query_scalar("SHOW lock_timeout")
                .fetch_one(&waiting_database.pool).await?;
            ensure!(original_timeout == "3s");
            operator_response(&app, Some(&authorization), ACCESS_PATH, StatusCode::FORBIDDEN).await?;
            Ok::<(), anyhow::Error>(())
        }.await;
        waiting_database.pool.close().await;
        attempted
    }.await;
    finish_live_fixture(fixture, &identity, outcome).await
}
