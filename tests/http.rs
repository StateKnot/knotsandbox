#![allow(clippy::unwrap_used)]

use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::Utc;
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use sandbox_platform::{
    api::{AppState, router},
    auth::{AuthConfig, JwtAuthenticator},
    db::Database,
};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use tokio::{net::TcpListener, task::JoinHandle};
use tower::ServiceExt;
use uuid::Uuid;

const INSTANCE: &str = "00000000-0000-4000-8000-000000000001";
const ISSUER: &str = "https://identity.example.invalid/realms/sandbox";

#[tokio::test]
async fn execution_routes_authenticate_and_reject_unknown_or_ambiguous_input_without_echoing_it() {
    let valid = json!({"argv":["/bin/true"],"public_env":{},"cwd":"/workspace","timeout_seconds":60,"on_timeout":"HARD_STOP_INSTANCE","output_limit_bytes":1024});
    for (method, path, body) in [
        (
            "POST",
            format!("/v1/instances/{INSTANCE}/executions"),
            valid.to_string(),
        ),
        ("GET", format!("/v1/executions/{INSTANCE}"), String::new()),
        (
            "GET",
            format!("/v1/executions/{INSTANCE}/output"),
            String::new(),
        ),
        (
            "POST",
            format!("/v1/executions/{INSTANCE}/cancel"),
            r#"{"hard_stop_instance":true}"#.into(),
        ),
    ] {
        let response = no_identity_network_app()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        problem(response, StatusCode::UNAUTHORIZED).await;
    }
    for body in [
        r#"{"argv":["true"],"public_env":{"TASK":"one","TASK":"PRIVATE-MARKER"},"cwd":"/workspace","timeout_seconds":1,"on_timeout":"HARD_STOP_INSTANCE","output_limit_bytes":0}"#,
        r#"{"argv":["true"],"public_env":{},"secret_env":{"TOKEN":"PRIVATE-MARKER"},"cwd":"/workspace","timeout_seconds":1,"on_timeout":"HARD_STOP_INSTANCE","output_limit_bytes":0}"#,
        r#"{"argv":["true"],"public_env":{},"cwd":"/workspace","timeout_seconds":1,"output_limit_bytes":0}"#,
    ] {
        let response = no_identity_network_app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/instances/{INSTANCE}/executions"))
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let rejected = problem(response, StatusCode::UNPROCESSABLE_ENTITY).await;
        assert!(!rejected.to_string().contains("PRIVATE-MARKER"));
    }
}

#[tokio::test]
async fn output_query_rejects_object_paths_and_unbounded_pages_without_echoing_input() {
    for query in [
        "object_key=PRIVATE-OBJECT-MARKER",
        "after_segment=-2",
        "after_segment=4096",
        "limit=0",
        "limit=3",
        "limit=1&limit=2",
        "after_segment=1&after_segment=2",
    ] {
        let response = no_identity_network_app()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/executions/{INSTANCE}/output?{query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let rejected = problem(response, StatusCode::BAD_REQUEST).await;
        assert!(!rejected.to_string().contains("PRIVATE-OBJECT-MARKER"));
    }
}

fn app(jwks_url: String) -> Router {
    let database = Database {
        // The tested paths must reject before database access. No mock accepts
        // authorization and no test substitutes a fake authenticated principal.
        pool: PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(50))
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .unwrap(),
    };
    let auth = JwtAuthenticator::new(AuthConfig {
        scope_profile: Default::default(),
        issuer: ISSUER.into(),
        audience: "sandbox-api".into(),
        jwks_url,
        required_scopes: vec!["sandbox:access".into()],
        jwks_ttl_seconds: 300,
        clock_skew_seconds: 0,
        allow_loopback_http: true,
        max_token_lifetime_seconds: 300,
    })
    .unwrap();
    router(Arc::new(AppState {
        output_reader: None,
        metrics: None,
        cursor_signer: sandbox_platform::history::CursorSigner::from_json(include_str!(
            "fixtures/history/cursor-keys.json"
        ))
        .unwrap(),
        database,
        auth,
        default_ttl_seconds: 3600,
        max_ttl_seconds: 86400,
    }))
}

fn no_identity_network_app() -> Router {
    app("https://identity.example.invalid/jwks".into())
}

async fn problem(response: Response, expected: StatusCode) -> Value {
    assert_eq!(response.status(), expected);
    assert_eq!(
        response.headers()["content-type"],
        "application/problem+json"
    );
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    let request_id = response.headers()["x-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    Uuid::parse_str(&request_id).unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["request_id"], request_id);
    assert_eq!(body["status"], expected.as_u16());
    assert!(
        body["type"]
            .as_str()
            .unwrap()
            .starts_with("urn:sandbox:error:")
    );
    body
}

#[tokio::test]
async fn missing_or_malformed_bearer_has_challenge_and_one_server_request_id() {
    let forged_id = Uuid::new_v4().to_string();
    let response = no_identity_network_app()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/instances/{INSTANCE}"))
                .header("x-request-id", &forged_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()["www-authenticate"], "Bearer");
    assert_ne!(response.headers()["x-request-id"], forged_id);
    let body = problem(response, StatusCode::UNAUTHORIZED).await;
    assert_eq!(body["code"], "UNAUTHENTICATED");
    assert_eq!(body["retryable"], false);

    for credential in [
        "Basic ignored",
        "Bearer",
        "Bearer bad token",
        "Bearer not-a-jwt",
    ] {
        let response = no_identity_network_app()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/instances/{INSTANCE}"))
                    .header("authorization", credential)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers()["www-authenticate"], "Bearer");
        let body = problem(response, StatusCode::UNAUTHORIZED).await;
        assert!(!body.to_string().contains(credential));
    }
}

#[tokio::test]
async fn route_and_method_errors_use_the_public_problem_contract() {
    let response = no_identity_network_app()
        .oneshot(
            Request::builder()
                .uri("/no-such-route")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = problem(response, StatusCode::NOT_FOUND).await;
    assert_eq!(body["code"], "RESOURCE_NOT_FOUND");
    let response = no_identity_network_app()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/v1/instances/{INSTANCE}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    problem(response, StatusCode::METHOD_NOT_ALLOWED).await;
}

#[tokio::test]
async fn invalid_path_and_query_extractors_never_bypass_problem_json() {
    for uri in [
        "/v1/instances/not-a-uuid",
        "/v1/operations/not-a-uuid",
        "/v1/instances",
        "/v1/operations",
        "/v1/capabilities",
        "/v1/capabilities?project_id=not-a-uuid",
        "/v1/events",
        "/v1/audit-records",
        "/v1/events?project_id=not-a-uuid",
        "/v1/audit-records?project_id=00000000-0000-4000-8000-000000000001&unsupported=true",
        "/v1/instances?project_id=not-a-uuid",
        "/v1/instances?project_id=00000000-0000-4000-8000-000000000001&limit=abc",
        "/v1/instances?project_id=00000000-0000-4000-8000-000000000001&unsupported=true",
    ] {
        let response = no_identity_network_app()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        problem(response, StatusCode::BAD_REQUEST).await;
    }
}

#[tokio::test]
async fn oversized_and_invalid_json_are_bounded_before_database_access() {
    let oversized = json!({"padding": "s".repeat(64 * 1024)}).to_string();
    let response = no_identity_network_app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/instances")
                .header("content-type", "application/json")
                .body(Body::from(oversized))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = problem(response, StatusCode::PAYLOAD_TOO_LARGE).await;
    assert!(body.to_string().len() < 1024);
    let response = no_identity_network_app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/instances")
                .header("content-type", "application/json")
                .body(Body::from("{invalid json containing private-value"))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = problem(response, StatusCode::BAD_REQUEST).await;
    assert!(!body.to_string().contains("private-value"));
}

#[tokio::test]
async fn liveness_does_not_require_database_or_identity_provider() {
    let response = no_identity_network_app()
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(response.headers()["cache-control"], "no-store");
    Uuid::parse_str(response.headers()["x-request-id"].to_str().unwrap()).unwrap();
    assert!(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty()
    );
}

struct LocalJwks {
    url: String,
    task: JoinHandle<()>,
}
impl Drop for LocalJwks {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn local_jwks(status: StatusCode) -> LocalJwks {
    let key: Value = serde_json::from_str(include_str!("fixtures/auth/jwk-a.json")).unwrap();
    let body = json!({"keys":[key]}).to_string();
    let app = Router::new().route(
        "/jwks",
        get(move || {
            let body = body.clone();
            async move { (status, body).into_response() }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/jwks", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    LocalJwks { url, task }
}

fn token(scope: &str) -> String {
    let now = Utc::now().timestamp();
    let claims = json!({"iss":ISSUER,"sub":"service-account-test","aud":"sandbox-api",
        "iat":now,"exp":now+300,"client_id":"test-client","jti":"http-test","scope":scope});
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("at+jwt".into());
    header.kid = Some("key-a".into());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_der(include_bytes!("fixtures/auth/rsa-a.der")),
    )
    .unwrap()
}

#[tokio::test]
async fn identity_outage_is_retryable_503_not_a_bad_credentials_response() {
    let jwks = local_jwks(StatusCode::SERVICE_UNAVAILABLE).await;
    let response = app(jwks.url.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/v1/instances/{INSTANCE}"))
                .header(
                    "authorization",
                    format!("Bearer {}", token("sandbox:access")),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(!response.headers().contains_key("www-authenticate"));
    let body = problem(response, StatusCode::SERVICE_UNAVAILABLE).await;
    assert_eq!(body["code"], "IDENTITY_UNAVAILABLE");
    assert_eq!(body["retryable"], true);
}

#[tokio::test]
async fn signed_token_without_required_scope_is_403_before_any_database_access() {
    let jwks = local_jwks(StatusCode::OK).await;
    let response = app(jwks.url.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/v1/instances/{INSTANCE}"))
                .header(
                    "authorization",
                    format!("Bearer {}", token("unrelated:scope")),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.headers()["www-authenticate"],
        "Bearer error=\"insufficient_scope\""
    );
    let body = problem(response, StatusCode::FORBIDDEN).await;
    assert_eq!(body["code"], "INSUFFICIENT_SCOPE");
}

#[tokio::test]
async fn lifecycle_actions_validate_json_and_reject_unauthenticated_calls_without_side_effects() {
    for (action, body) in [
        ("start", "{}"),
        ("start", "{\"ttl_seconds\":300}"),
        ("stop", "{}"),
        ("restart", "{}"),
        ("renew", "{\"expires_at\":\"2026-10-03T12:00:00Z\"}"),
    ] {
        let response = no_identity_network_app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/instances/{INSTANCE}/actions/{action}"))
                    .header("content-type", "application/json")
                    .header("if-match", "\"1\"")
                    .header("idempotency-key", "test-original-key")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        problem(response, StatusCode::UNAUTHORIZED).await;
    }
    for (action, body) in [
        ("start", "{\"arbitrary\":true}"),
        ("stop", "{\"ttl_seconds\":300}"),
        ("restart", "{\"ttl_seconds\":300}"),
        ("renew", "{}"),
        ("renew", "{\"expires_at\":\"not-a-time\"}"),
    ] {
        let response = no_identity_network_app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/instances/{INSTANCE}/actions/{action}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        problem(response, StatusCode::UNPROCESSABLE_ENTITY).await;
    }
    // DELETE has no JSON extractor: no body or Content-Type is required.
    let response = no_identity_network_app()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/instances/{INSTANCE}"))
                .header("if-match", "\"1\"")
                .header("idempotency-key", "test-original-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    problem(response, StatusCode::UNAUTHORIZED).await;
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL; creates an isolated temporary schema without altering shared platform configuration"]
async fn readiness_requires_initialization_but_safe_mode_remains_queryable() -> anyhow::Result<()> {
    use sqlx::{Executor, postgres::PgPoolOptions};
    let url = std::env::var("TEST_MIGRATION_DATABASE_URL")?;
    let owner = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await?;
    let schema = format!("readiness_{}", uuid::Uuid::new_v4().simple());
    owner
        .execute(format!("CREATE SCHEMA {schema}").as_str())
        .await?;
    let result=async {
        owner.execute(format!("CREATE TABLE {schema}.platform_configuration(singleton boolean PRIMARY KEY CHECK(singleton),safe_mode boolean NOT NULL)").as_str()).await?;
        let pool=PgPoolOptions::new().max_connections(1).after_connect({let schema=schema.clone();move|conn,_|{let schema=schema.clone();Box::pin(async move{sqlx::query("SELECT set_config('search_path',$1,false)").bind(schema).execute(conn).await?;Ok(())})}}).connect(&url).await?;
        let auth=JwtAuthenticator::new(AuthConfig{
            scope_profile: Default::default(),issuer:ISSUER.into(),audience:"sandbox-api".into(),jwks_url:"https://identity.example.invalid/jwks".into(),required_scopes:vec!["sandbox:access".into()],jwks_ttl_seconds:300,clock_skew_seconds:0,allow_loopback_http:false,max_token_lifetime_seconds:300})?;
        let app=router(Arc::new(AppState{output_reader:None,metrics:None,database:Database{pool:pool.clone()},auth,cursor_signer:sandbox_platform::history::CursorSigner::from_json(include_str!("fixtures/history/cursor-keys.json"))?,default_ttl_seconds:300,max_ttl_seconds:86400}));
        let request=||Request::builder().uri("/health/ready").body(Body::empty());
        let missing=app.clone().oneshot(request()?).await?;
        let missing=problem(missing,StatusCode::SERVICE_UNAVAILABLE).await;
        assert_eq!(missing["code"],"PLATFORM_NOT_INITIALIZED");
        owner.execute(format!("INSERT INTO {schema}.platform_configuration VALUES(true,true)").as_str()).await?;
        let safe=app.oneshot(request()?).await?;
        assert_eq!(safe.status(),StatusCode::NO_CONTENT);
        pool.close().await;
        Ok::<_,anyhow::Error>(())
    }.await;
    owner
        .execute(format!("DROP SCHEMA {schema} CASCADE").as_str())
        .await?;
    owner.close().await;
    result
}
