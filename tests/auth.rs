#![allow(clippy::unwrap_used)]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
};
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use sandbox_platform::auth::{AuthConfig, AuthError, JwtAuthenticator};
use serde_json::{Value, json};
use tokio::{net::TcpListener, sync::RwLock, task::JoinHandle};

const KEY_A: &[u8] = include_bytes!("fixtures/auth/rsa-a.der");
const KEY_B: &[u8] = include_bytes!("fixtures/auth/rsa-b.der");
const ISSUER: &str = "https://identity.example.invalid/realms/sandbox";

#[derive(Clone)]
struct ResponseSpec {
    status: StatusCode,
    body: String,
    headers: HeaderMap,
    delay: Duration,
}

#[derive(Clone)]
struct MockState {
    response: Arc<RwLock<ResponseSpec>>,
    requests: Arc<AtomicUsize>,
}

struct MockJwks {
    url: String,
    state: MockState,
    task: JoinHandle<()>,
}

impl MockJwks {
    async fn start(keys: Vec<Value>) -> Self {
        let state = MockState {
            response: Arc::new(RwLock::new(ResponseSpec {
                status: StatusCode::OK,
                body: json!({"keys": keys}).to_string(),
                headers: HeaderMap::new(),
                delay: Duration::ZERO,
            })),
            requests: Arc::new(AtomicUsize::new(0)),
        };
        let app = Router::new()
            .route(
                "/jwks",
                get(|State(state): State<MockState>| async move {
                    state.requests.fetch_add(1, Ordering::SeqCst);
                    let response = state.response.read().await.clone();
                    tokio::time::sleep(response.delay).await;
                    (response.status, response.headers, response.body).into_response()
                }),
            )
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            url: format!("http://{address}/jwks"),
            state,
            task,
        }
    }

    fn config(&self) -> AuthConfig {
        AuthConfig {
            scope_profile: Default::default(),
            issuer: ISSUER.to_owned(),
            audience: "sandbox-api".to_owned(),
            jwks_url: self.url.clone(),
            required_scopes: vec!["sandbox:access".to_owned()],
            jwks_ttl_seconds: 300,
            clock_skew_seconds: 0,
            allow_loopback_http: true,
            max_token_lifetime_seconds: 300,
        }
    }

    fn requests(&self) -> usize {
        self.state.requests.load(Ordering::SeqCst)
    }

    async fn keys(&self, keys: Vec<Value>) {
        self.state.response.write().await.body = json!({"keys": keys}).to_string();
    }
}

impl Drop for MockJwks {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn jwk(label: &str) -> Value {
    serde_json::from_str(match label {
        "a" => include_str!("fixtures/auth/jwk-a.json"),
        "b" => include_str!("fixtures/auth/jwk-b.json"),
        _ => panic!("unknown test fixture"),
    })
    .unwrap()
}

fn claims() -> Value {
    let now = Utc::now().timestamp();
    json!({"iss": ISSUER, "sub": "service-account-job-runner", "aud": "sandbox-api",
        "iat": now - 1, "exp": now + 299, "jti": "test-access-token", "client_id": "job-runner",
        "scope": "sandbox:access instances:read"})
}

fn sign(claims: &Value, kid: &str, pem: &[u8], typ: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    header.typ = Some(typ.to_owned());
    encode(&header, claims, &EncodingKey::from_rsa_der(pem)).unwrap()
}

#[tokio::test]
async fn validates_signed_standard_and_keycloak_access_tokens() {
    let server = MockJwks::start(vec![jwk("a")]).await;
    let auth = JwtAuthenticator::new(server.config()).unwrap();
    let identity = auth
        .verify(&sign(&claims(), "key-a", KEY_A, "at+jwt"))
        .await
        .unwrap();
    assert_eq!(identity.issuer, ISSUER);
    assert_eq!(identity.subject, "service-account-job-runner");
    assert_eq!(identity.client_id.as_deref(), Some("job-runner"));
    assert_eq!(identity.scopes, ["instances:read", "sandbox:access"]);
    let mut keycloak = claims();
    keycloak.as_object_mut().unwrap().remove("client_id");
    keycloak["typ"] = json!("Bearer");
    keycloak["azp"] = json!("job-runner");
    keycloak["aud"] = json!(["account", "sandbox-api"]);
    auth.verify(&sign(&keycloak, "key-a", KEY_A, "JWT"))
        .await
        .unwrap();
    auth.verify(&sign(&claims(), "key-a", KEY_A, "application/at+jwt"))
        .await
        .unwrap();
    assert_eq!(server.requests(), 1, "fresh keys must be cached");
}

#[tokio::test]
async fn rejects_wrong_signature_issuer_audience_and_time_claims() {
    let server = MockJwks::start(vec![jwk("a")]).await;
    let auth = JwtAuthenticator::new(server.config()).unwrap();
    assert_eq!(
        auth.verify(&sign(&claims(), "key-a", KEY_B, "at+jwt"))
            .await,
        Err(AuthError::InvalidToken)
    );
    let now = Utc::now().timestamp();
    let cases = [
        ("iss", json!("https://attacker.invalid")),
        ("iss", json!(format!("{ISSUER}/"))),
        ("aud", json!("other-api")),
        ("aud", json!([])),
        ("exp", json!(now - 10)),
        ("exp", json!(now + 600)),
        ("iat", json!(now + 60)),
        ("iat", json!(now - 3600)),
        ("iat", json!(-1)),
        ("nbf", json!(now + 60)),
        ("nbf", json!(-1)),
        ("sub", json!("")),
        ("sub", json!("\u{0000}")),
        ("iat", json!("yesterday")),
        ("exp", json!(i64::MAX)),
    ];
    for (field, value) in cases {
        let mut value_claims = claims();
        value_claims[field] = value;
        assert_eq!(
            auth.verify(&sign(&value_claims, "key-a", KEY_A, "at+jwt"))
                .await,
            Err(AuthError::InvalidToken),
            "must reject invalid {field}"
        );
    }
    for field in ["iss", "aud", "sub", "exp", "iat"] {
        let mut value_claims = claims();
        value_claims.as_object_mut().unwrap().remove(field);
        assert_eq!(
            auth.verify(&sign(&value_claims, "key-a", KEY_A, "at+jwt"))
                .await,
            Err(AuthError::InvalidToken),
            "must require {field}"
        );
    }
}

#[tokio::test]
async fn id_tokens_and_ambiguous_client_profiles_are_not_access_tokens() {
    let server = MockJwks::start(vec![jwk("a")]).await;
    let auth = JwtAuthenticator::new(server.config()).unwrap();
    // Matching issuer/audience/signature alone must never admit an ID token.
    let mut id_token = claims();
    id_token["typ"] = json!("ID");
    id_token["azp"] = json!("job-runner");
    for typ in ["JWT", "at+jwt", "application/at+jwt"] {
        assert_eq!(
            auth.verify(&sign(&id_token, "key-a", KEY_A, typ)).await,
            Err(AuthError::InvalidTokenType)
        );
    }
    assert_eq!(
        auth.verify(&sign(&claims(), "key-a", KEY_A, "JWT")).await,
        Err(AuthError::InvalidTokenType)
    );
    for field in ["client_id", "jti"] {
        let mut value = claims();
        value.as_object_mut().unwrap().remove(field);
        assert_eq!(
            auth.verify(&sign(&value, "key-a", KEY_A, "at+jwt")).await,
            Err(AuthError::InvalidTokenType)
        );
    }
    let mut ambiguous = claims();
    ambiguous["azp"] = json!("different-client");
    assert_eq!(
        auth.verify(&sign(&ambiguous, "key-a", KEY_A, "at+jwt"))
            .await,
        Err(AuthError::InvalidToken)
    );
    let mut keycloak = claims();
    keycloak["typ"] = json!("Bearer");
    assert_eq!(
        auth.verify(&sign(&keycloak, "key-a", KEY_A, "JWT")).await,
        Err(AuthError::InvalidTokenType)
    );
}

#[tokio::test]
async fn scopes_and_header_constraints_are_enforced() {
    let server = MockJwks::start(vec![jwk("a")]).await;
    let auth = JwtAuthenticator::new(server.config()).unwrap();
    let mut value = claims();
    value["scope"] = json!("instances:read");
    assert_eq!(
        auth.verify(&sign(&value, "key-a", KEY_A, "at+jwt")).await,
        Err(AuthError::InsufficientScope)
    );
    value["scope"] = json!("sandbox:access\tinstances:read");
    assert_eq!(
        auth.verify(&sign(&value, "key-a", KEY_A, "at+jwt")).await,
        Err(AuthError::InvalidToken)
    );
    let mut hs_header = Header::new(Algorithm::HS256);
    hs_header.kid = Some("key-a".into());
    hs_header.typ = Some("at+jwt".into());
    let token = encode(
        &hs_header,
        &claims(),
        &EncodingKey::from_secret(b"wrong-key"),
    )
    .unwrap();
    assert_eq!(
        auth.verify(&token).await,
        Err(AuthError::UnsupportedAlgorithm)
    );
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("at+jwt".into());
    header.kid = Some("key-a".into());
    header.jku = Some("http://127.0.0.1/attacker-key".into());
    let token = encode(&header, &claims(), &EncodingKey::from_rsa_der(KEY_A)).unwrap();
    assert_eq!(auth.verify(&token).await, Err(AuthError::InvalidToken));
    header.jku = None;
    header.crit = Some(vec!["custom".into()]);
    let token = encode(&header, &claims(), &EncodingKey::from_rsa_der(KEY_A)).unwrap();
    assert_eq!(auth.verify(&token).await, Err(AuthError::InvalidToken));
    assert_eq!(
        auth.verify(&"x".repeat(16 * 1024 + 1)).await,
        Err(AuthError::InvalidToken)
    );
    assert_eq!(auth.verify("not.a.jwt").await, Err(AuthError::InvalidToken));
}

#[tokio::test]
async fn key_rotation_refreshes_once_and_unknown_kids_cannot_create_a_refresh_storm() {
    let server = MockJwks::start(vec![jwk("a")]).await;
    let auth = Arc::new(JwtAuthenticator::new(server.config()).unwrap());
    auth.verify(&sign(&claims(), "key-a", KEY_A, "at+jwt"))
        .await
        .unwrap();
    server.keys(vec![jwk("a"), jwk("b")]).await;
    let rotated = sign(&claims(), "key-b", KEY_B, "at+jwt");
    let mut handles = Vec::new();
    for _ in 0..32 {
        let auth = Arc::clone(&auth);
        let token = rotated.clone();
        handles.push(tokio::spawn(async move { auth.verify(&token).await }));
    }
    for handle in handles {
        handle.await.unwrap().unwrap();
    }
    assert_eq!(server.requests(), 2);
    for i in 0..32 {
        assert_eq!(
            auth.verify(&sign(&claims(), &format!("unknown-{i}"), KEY_A, "at+jwt"))
                .await,
            Err(AuthError::UnknownKey)
        );
    }
    assert_eq!(
        server.requests(),
        2,
        "unknown kids are globally rate limited"
    );
}

#[tokio::test]
async fn cold_unknown_kids_are_single_flight_and_misses_are_not_stored_per_kid() {
    let server = MockJwks::start(vec![jwk("a")]).await;
    let auth = Arc::new(JwtAuthenticator::new(server.config()).unwrap());
    let token = sign(&claims(), "unknown", KEY_A, "at+jwt");
    let mut handles = Vec::new();
    for _ in 0..32 {
        let auth = Arc::clone(&auth);
        let token = token.clone();
        handles.push(tokio::spawn(async move { auth.verify(&token).await }));
    }
    for handle in handles {
        assert_eq!(handle.await.unwrap(), Err(AuthError::UnknownKey));
    }
    assert_eq!(server.requests(), 1);
}

#[tokio::test]
async fn expired_cache_fails_closed_and_refresh_failures_have_backoff() {
    let server = MockJwks::start(vec![jwk("a")]).await;
    let mut config = server.config();
    config.jwks_ttl_seconds = 1;
    let auth = Arc::new(JwtAuthenticator::new(config).unwrap());
    let token = sign(&claims(), "key-a", KEY_A, "at+jwt");
    auth.verify(&token).await.unwrap();
    server.state.response.write().await.status = StatusCode::SERVICE_UNAVAILABLE;
    // Cached keys remain usable for their original lifetime, but never beyond it.
    auth.verify(&token).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(auth.verify(&token).await, Err(AuthError::JwksUnavailable));
    for _ in 0..10 {
        assert_eq!(auth.verify(&token).await, Err(AuthError::JwksUnavailable));
    }
    assert_eq!(server.requests(), 2);
}

#[tokio::test]
async fn expired_cache_replaces_keys_instead_of_retaining_removed_keys() {
    let server = MockJwks::start(vec![jwk("a")]).await;
    let mut config = server.config();
    config.jwks_ttl_seconds = 1;
    let auth = JwtAuthenticator::new(config).unwrap();
    let old = sign(&claims(), "key-a", KEY_A, "at+jwt");
    auth.verify(&old).await.unwrap();
    server.keys(vec![jwk("b")]).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let new = sign(&claims(), "key-b", KEY_B, "at+jwt");
    auth.verify(&new).await.unwrap();
    assert_eq!(auth.verify(&old).await, Err(AuthError::UnknownKey));
}

#[tokio::test]
async fn jwks_redirects_oversized_documents_duplicates_and_weak_keys_are_rejected() {
    let redirected = MockJwks::start(vec![jwk("a")]).await;
    let server = MockJwks::start(vec![jwk("a")]).await;
    {
        let mut response = server.state.response.write().await;
        response.status = StatusCode::FOUND;
        response
            .headers
            .insert("location", redirected.url.parse().unwrap());
    }
    let auth = JwtAuthenticator::new(server.config()).unwrap();
    let token = sign(&claims(), "key-a", KEY_A, "at+jwt");
    assert_eq!(auth.verify(&token).await, Err(AuthError::JwksUnavailable));
    assert_eq!(redirected.requests(), 0);
    let cases = [
        json!({"keys": [jwk("a"), jwk("a")]}).to_string(),
        json!({"keys": []}).to_string(),
        json!({"keys": (0..33).map(|i| { let mut k=jwk("a"); k["kid"]=json!(format!("k{i}")); k }).collect::<Vec<_>>()} ).to_string(),
        "x".repeat(128 * 1024 + 1),
        "{invalid-json".into(),
        json!({"keys": [{"kty":"RSA", "kid":"key-a", "n":"AQ", "e":"AQAB"}]}).to_string(),
    ];
    for body in cases {
        let server = MockJwks::start(vec![jwk("a")]).await;
        server.state.response.write().await.body = body;
        let auth = JwtAuthenticator::new(server.config()).unwrap();
        assert_eq!(auth.verify(&token).await, Err(AuthError::InvalidJwks));
    }
}

#[tokio::test]
async fn jwks_signing_usage_and_algorithm_are_enforced() {
    let token = sign(&claims(), "key-a", KEY_A, "at+jwt");
    for (field, value) in [
        ("use", json!("enc")),
        ("alg", json!("RS512")),
        ("key_ops", json!(["encrypt"])),
        ("e", json!("Aw")),
    ] {
        let mut key = jwk("a");
        key[field] = value;
        let server = MockJwks::start(vec![key]).await;
        let auth = JwtAuthenticator::new(server.config()).unwrap();
        assert_eq!(auth.verify(&token).await, Err(AuthError::InvalidJwks));
    }
}

#[tokio::test]
async fn configuration_rejects_non_tls_and_unsafe_development_urls() {
    let server = MockJwks::start(vec![jwk("a")]).await;
    let mut config = server.config();
    config.allow_loopback_http = false;
    assert!(matches!(
        JwtAuthenticator::new(config),
        Err(AuthError::InvalidConfig(_))
    ));
    for url in [
        "http://localhost/jwks",
        "http://10.0.0.1/jwks",
        "https://user:pass@issuer.test/jwks",
        "https://issuer.test/jwks#fragment",
        "file:///keys",
    ] {
        let mut config = server.config();
        config.jwks_url = url.into();
        assert!(matches!(
            JwtAuthenticator::new(config),
            Err(AuthError::InvalidConfig(_))
        ));
    }
    let mut config = server.config();
    config.clock_skew_seconds = 61;
    assert!(matches!(
        JwtAuthenticator::new(config),
        Err(AuthError::InvalidConfig(_))
    ));
    let mut config = server.config();
    config.max_token_lifetime_seconds = 0;
    assert!(matches!(
        JwtAuthenticator::new(config),
        Err(AuthError::InvalidConfig(_))
    ));
}

#[tokio::test]
async fn slow_jwks_is_bounded_by_the_http_deadline() {
    let server = MockJwks::start(vec![jwk("a")]).await;
    server.state.response.write().await.delay = Duration::from_secs(20);
    let auth = JwtAuthenticator::new(server.config()).unwrap();
    let token = sign(&claims(), "key-a", KEY_A, "at+jwt");
    let result = tokio::time::timeout(Duration::from_secs(7), auth.verify(&token)).await;
    assert_eq!(result.unwrap(), Err(AuthError::JwksUnavailable));
}

#[tokio::test]
async fn operator_selected_action_scopes_cap_the_verified_identity() {
    use sandbox_platform::auth::ScopeProfile;
    let server = MockJwks::start(vec![jwk("a")]).await;
    let generic = JwtAuthenticator::new(server.config()).unwrap();
    let token = sign(&claims(), "key-a", KEY_A, "at+jwt");
    assert!(
        generic
            .verify(&token)
            .await
            .unwrap()
            .permits("instances:create")
    );
    let mut config = server.config();
    config.scope_profile = ScopeProfile::ActionScopes;
    let auth = JwtAuthenticator::new(config).unwrap();
    let identity = auth.verify(&token).await.unwrap();
    assert!(identity.permits("instances:read"));
    for action in [
        "instances:create",
        "instances:start",
        "executions:output:read",
        "automations:write",
    ] {
        assert!(!identity.permits(action));
    }
    let mut wildcard = claims();
    wildcard["scope"] = json!("sandbox:access *");
    let identity = auth
        .verify(&sign(&wildcard, "key-a", KEY_A, "at+jwt"))
        .await
        .unwrap();
    assert!(!identity.permits("*") && !identity.permits("instances:create"));
}
