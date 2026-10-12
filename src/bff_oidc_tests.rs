#![allow(clippy::unwrap_used)]
use super::*;
use crate::auth::AuthConfig;
use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tokio::net::TcpListener;
use uuid::Uuid;

const ISSUER: &str = "https://identity.fixture.invalid/realms/sandbox";
const SECRET: &str = "FIXTURE_BROWSER_CLIENT_SECRET_0123456789";
#[derive(Clone)]
struct StateData {
    response: Arc<Mutex<(StatusCode, String)>>,
    requests: Arc<Mutex<Vec<(HeaderMap, String)>>>,
}
struct Fixture {
    oidc: BrowserOidc,
    auth: JwtAuthenticator,
    state: StateData,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn jwt(claims: Value, id: bool) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("key-a".into());
    header.typ = Some(if id { "JWT" } else { "at+jwt" }.into());
    jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_der(include_bytes!("../tests/fixtures/auth/rsa-a.der")),
    )
    .unwrap()
}
fn response(nonce: &str) -> Value {
    let now = Utc::now().timestamp();
    json!({"access_token":jwt(json!({"iss":ISSUER,"aud":"sandbox-api","sub":"fixture-user","client_id":"sandbox-browser","jti":Uuid::new_v4(),"iat":now,"exp":now+240,"scope":"sandbox:access"}),false),"id_token":jwt(json!({"iss":ISSUER,"aud":"sandbox-browser","sub":"fixture-user","iat":now,"exp":now+240,"nonce":nonce}),true),"refresh_token":"fixture-refresh-value","expires_in":240,"token_type":"Bearer"})
}
impl Fixture {
    async fn start() -> Self {
        let state = StateData {
            response: Arc::new(Mutex::new((StatusCode::OK, "{}".into()))),
            requests: Arc::new(Mutex::new(vec![])),
        };
        let app=Router::new().route("/token",post(|State(s):State<StateData>,headers:HeaderMap,body:String|async move {
            s.requests.lock().await.push((headers,body));let (status,body)=s.response.lock().await.clone();(status,[("content-type","application/json")],body).into_response()
        })).route("/jwks",get(||async{axum::Json(json!({"keys":[serde_json::from_str::<Value>(include_str!("../tests/fixtures/auth/jwk-a.json")).unwrap()]}))})).with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let settings = OidcSettings {
            issuer: ISSUER.into(),
            authorization_url: "https://identity.fixture.invalid/auth".into(),
            token_url: format!("{base}/token"),
            jwks_url: format!("{base}/jwks"),
            client_id: "sandbox-browser".into(),
            public_origin: "https://console.fixture.invalid".into(),
            scopes: vec!["openid".into(), "sandbox:access".into()],
        };
        let auth = JwtAuthenticator::new(AuthConfig {
            scope_profile: Default::default(),
            issuer: ISSUER.into(),
            audience: "sandbox-api".into(),
            jwks_url: settings.jwks_url.clone(),
            required_scopes: vec!["sandbox:access".into()],
            jwks_ttl_seconds: 60,
            clock_skew_seconds: 0,
            allow_loopback_http: true,
            max_token_lifetime_seconds: 300,
        })
        .unwrap();
        let oidc = BrowserOidc::with_transport(settings, SECRET.into(), true).unwrap();
        Self {
            oidc,
            auth,
            state,
            task,
        }
    }
    async fn token_response(&self, v: Value) {
        *self.state.response.lock().await = (StatusCode::OK, v.to_string());
    }
}

#[tokio::test]
async fn code_exchange_uses_pkce_basic_nonce_and_binds_access_identity() {
    let f = Fixture::start().await;
    let login = f.oidc.begin().unwrap();
    let url = Url::parse(&login.authorization_url).unwrap();
    let parameters = url.query_pairs().collect::<BTreeMap<_, _>>();
    assert_eq!(parameters["code_challenge_method"], "S256");
    assert_eq!(parameters["response_type"], "code");
    assert_eq!(
        parameters["redirect_uri"],
        "https://console.fixture.invalid/auth/callback"
    );
    assert_eq!(parameters["state"], login.state);
    assert!(!login.authorization_url.contains(SECRET));
    assert!(!login.authorization_url.contains(&login.secrets.verifier));
    f.token_response(response(&login.secrets.nonce)).await;
    let verified = f
        .oidc
        .exchange("fixture-code".into(), &login.secrets, &f.auth)
        .await
        .unwrap();
    assert_eq!(verified.identity.subject, "fixture-user");
    assert_eq!(
        verified.tokens.refresh_token.as_deref(),
        Some("fixture-refresh-value")
    );
    let sent = f.state.requests.lock().await;
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].0["authorization"],
        format!(
            "Basic {}",
            STANDARD.encode(format!("sandbox-browser:{SECRET}"))
        )
    );
    let body = url::form_urlencoded::parse(sent[0].1.as_bytes()).collect::<BTreeMap<_, _>>();
    assert_eq!(body["code_verifier"], login.secrets.verifier);
    assert_eq!(body["grant_type"], "authorization_code");
}

#[tokio::test]
async fn invalid_id_token_identity_nonce_hash_or_missing_id_rejects_without_retry() {
    let f = Fixture::start().await;
    let login = f.oidc.begin().unwrap();
    for defect in ["nonce", "subject", "audience", "hash", "missing", "expired"] {
        let now = Utc::now().timestamp();
        let mut claims = json!({"iss":ISSUER,"aud":"sandbox-browser","sub":"fixture-user","iat":now,"exp":now+240,"nonce":login.secrets.nonce});
        match defect {
            "nonce" => claims["nonce"] = json!("different"),
            "subject" => claims["sub"] = json!("other-user"),
            "audience" => claims["aud"] = json!("other-client"),
            "hash" => claims["at_hash"] = json!("incorrect"),
            "expired" => claims["exp"] = json!(now - 1),
            _ => {}
        }
        let mut tokens = response(&login.secrets.nonce);
        tokens["id_token"] = json!(jwt(claims, true));
        if defect == "missing" {
            tokens.as_object_mut().unwrap().remove("id_token");
        }
        f.token_response(tokens).await;
        let before = f.state.requests.lock().await.len();
        assert!(matches!(
            f.oidc
                .exchange("fixture-code".into(), &login.secrets, &f.auth)
                .await,
            Err(OidcError::Rejected)
        ));
        assert_eq!(f.state.requests.lock().await.len(), before + 1);
    }
    *f.state.response.lock().await = (StatusCode::FOUND, "{}".into());
    let before = f.state.requests.lock().await.len();
    assert!(
        f.oidc
            .exchange("fixture-code".into(), &login.secrets, &f.auth)
            .await
            .is_err()
    );
    assert_eq!(f.state.requests.lock().await.len(), before + 1);
}

#[tokio::test]
async fn refresh_retains_subject_allows_missing_id_and_never_replays_rejected_exchange() {
    let f = Fixture::start().await;
    let login = f.oidc.begin().unwrap();
    f.token_response(response(&login.secrets.nonce)).await;
    let old = f
        .oidc
        .exchange("fixture-code".into(), &login.secrets, &f.auth)
        .await
        .unwrap();
    let mut updated = response(&login.secrets.nonce);
    updated.as_object_mut().unwrap().remove("id_token");
    updated.as_object_mut().unwrap().remove("refresh_token");
    f.token_response(updated).await;
    let fresh = f
        .oidc
        .refresh_tokens(&old.tokens, "fixture-user", &f.auth)
        .await
        .unwrap();
    assert_eq!(fresh.tokens.refresh_token, old.tokens.refresh_token);
    assert!(
        f.oidc
            .refresh_tokens(&old.tokens, "another-subject", &f.auth)
            .await
            .is_err()
    );
    *f.state.response.lock().await = (
        StatusCode::BAD_REQUEST,
        json!({"error":"invalid_grant","error_description":"SECRET_ERROR_MUST_NOT_ECHO"})
            .to_string(),
    );
    let before = f.state.requests.lock().await.len();
    let error = f
        .oidc
        .refresh_tokens(&old.tokens, "fixture-user", &f.auth)
        .await
        .err()
        .unwrap();
    assert_eq!(error, OidcError::Rejected);
    assert!(!error.to_string().contains("SECRET_ERROR_MUST_NOT_ECHO"));
    assert_eq!(f.state.requests.lock().await.len(), before + 1);
    assert!(BrowserOidc::new(f.oidc.settings.clone(), SECRET.into()).is_err());
}
