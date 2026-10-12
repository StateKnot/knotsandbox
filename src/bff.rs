//! Browser-facing OIDC BFF. All provider credentials stay in encrypted server storage.
use crate::{
    api::AppState,
    bff_config::BrowserConfig,
    bff_crypto::{Purpose, random_token, token_hash},
    bff_ledger::SessionRecord,
    bff_oidc::{BrowserTokens, LoginSecrets, OidcError},
    error::ApiError,
};
use axum::{
    Json, Router,
    body::Body,
    extract::{
        DefaultBodyLimit, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{future::Future, sync::Arc, time::Duration};
use uuid::Uuid;

const SESSION_COOKIE: &str = "__Host-sandbox-session";
const LOGIN_COOKIE: &str = "__Host-sandbox-login";
pub struct BrowserRuntime {
    pub(crate) app: Arc<AppState>,
    pub(crate) config: BrowserConfig,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    tokens: BrowserTokens,
    csrf_token: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BeginLogin {
    tenant_id: Uuid,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Callback {
    state: String,
    code: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
    session_state: Option<String>,
    iss: Option<String>,
}
#[derive(Serialize)]
struct SessionView {
    tenant_id: Uuid,
    principal_id: Uuid,
    csrf_token: String,
    absolute_expires_at: DateTime<Utc>,
    idle_expires_at: DateTime<Utc>,
}
fn rejected() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "BROWSER_LOGIN_REQUIRED",
        "Begin a new browser login",
    )
}
fn busy() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "BROWSER_SESSION_BUSY",
        "Browser session is being refreshed; try the request again",
    )
}
fn oidc_error(error: OidcError) -> ApiError {
    match error {
        OidcError::Busy => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "BROWSER_IDENTITY_BUSY",
            "Identity exchange capacity exceeded; begin a new login",
        ),
        _ => rejected(),
    }
}
fn digest(value: &str) -> Result<String, ApiError> {
    if !(20..=256).contains(&value.len())
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(rejected());
    }
    Ok(hex::encode(Sha256::digest(value.as_bytes())))
}
fn cookie(headers: &HeaderMap, name: &str) -> Result<Option<String>, ApiError> {
    let mut value = None;
    for header in headers.get_all("cookie") {
        let header = header.to_str().map_err(|_| rejected())?;
        if header.len() > 8192 {
            return Err(rejected());
        }
        for entry in header.split(';') {
            let Some((key, token)) = entry.trim().split_once('=') else {
                continue;
            };
            if key == name {
                if value.is_some() || token_hash(token).is_err() {
                    return Err(rejected());
                }
                value = Some(token.to_owned());
            }
        }
    }
    Ok(value)
}
fn cookie_header(
    name: &str,
    value: &str,
    age: i64,
    same_site: &str,
) -> Result<HeaderValue, ApiError> {
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; Max-Age={age}; Secure; HttpOnly; SameSite={same_site}"
    ))
    .map_err(|_| rejected())
}
fn clear_cookie(name: &str, same_site: &str) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{name}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite={same_site}"
    ))
    .unwrap_or_else(|_| HeaderValue::from_static("invalid=; Max-Age=0"))
}
fn hash_cookie(value: &str) -> Result<String, ApiError> {
    token_hash(value).map_err(|_| rejected())
}
impl BrowserRuntime {
    pub fn new(app: Arc<AppState>, config: BrowserConfig) -> Self {
        Self { app, config }
    }
    pub async fn check_schema(&self) -> anyhow::Result<()> {
        let installed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=37 AND success)",
        )
        .fetch_one(&self.app.database.pool)
        .await?;
        anyhow::ensure!(
            installed,
            "browser sessions require normally applied migration 0037"
        );
        for function in [
            "sandbox_browser_login_create(uuid,uuid,uuid,text,text,bytea)",
            "sandbox_browser_login_consume(text,text)",
            "sandbox_browser_session_create(uuid,uuid,text,text,text,text,timestamptz,bytea,uuid)",
            "sandbox_browser_session_read(text,boolean)",
            "sandbox_browser_refresh_begin(text,bigint)",
            "sandbox_browser_refresh_finish(text,bigint,timestamptz,bytea)",
            "sandbox_browser_session_revoke(text,text,bigint,uuid)",
            "sandbox_browser_cleanup(uuid)",
        ] {
            let allowed: bool =
                sqlx::query_scalar("SELECT has_function_privilege(current_user,$1,'EXECUTE')")
                    .bind(function)
                    .fetch_one(&self.app.database.pool)
                    .await?;
            anyhow::ensure!(allowed, "browser session runtime grants are incomplete");
        }
        Ok(())
    }
    /// The API parent owns this future and awaits it before closing its pool.
    /// A dispatched cleanup query finishes even if shutdown arrives in flight.
    pub async fn run_cleanup(
        &self,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> anyhow::Result<()> {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let result = cleanup_loop(shutdown, interval, || {
            sqlx::query_scalar::<_, i64>("SELECT sandbox_browser_cleanup($1)")
                .bind(Uuid::new_v4())
                .fetch_one(&self.app.database.pool)
        })
        .await;
        tracing::info!("browser session cleanup stopped");
        result
    }
    pub fn attach(self: Arc<Self>, api: Router) -> Router {
        let auth = Router::new()
            .route("/auth/login", post(begin_login))
            .route("/auth/callback", get(callback))
            .route("/auth/session", get(session))
            .route("/auth/logout", post(logout))
            .layer(DefaultBodyLimit::max(4096))
            .with_state(self.clone());
        api.merge(auth)
            .layer(middleware::from_fn_with_state(self, browser_boundary))
    }
    fn origin(&self, headers: &HeaderMap, required: bool) -> Result<(), ApiError> {
        let mut origins = headers.get_all("origin").iter();
        let origin = origins.next();
        if origins.next().is_some()
            || origin.is_some_and(|v| {
                v.to_str().ok() != Some(&self.config.oidc.settings().public_origin)
            })
            || (required && origin.is_none())
        {
            return Err(ApiError::forbidden());
        }
        Ok(())
    }
    fn decrypt(&self, record: &SessionRecord) -> Result<Payload, ApiError> {
        let bytes = self
            .config
            .keys
            .decrypt(
                Purpose::Session,
                record.id,
                record.cluster_epoch,
                &record.payload,
            )
            .map_err(|_| rejected())?;
        let payload: Payload = serde_json::from_slice(&bytes).map_err(|_| rejected())?;
        if hash_cookie(&payload.csrf_token)? != record.csrf_hash {
            return Err(rejected());
        }
        Ok(payload)
    }
    async fn credentials(&self, hash: &str) -> Result<(SessionRecord, Payload), ApiError> {
        let mut record = self
            .app
            .database
            .browser_session_read(hash, true)
            .await?
            .ok_or_else(rejected)?;
        if record.status != "ACTIVE" {
            return Err(busy());
        }
        let mut payload = self.decrypt(&record)?;
        if record.access_expires_at <= Utc::now() + chrono::Duration::seconds(30) {
            record = match self
                .app
                .database
                .browser_refresh_begin(hash, record.version)
                .await?
            {
                Some(v) => v,
                None => return Err(busy()),
            };
            // This committed state is the only permission to send a refresh request.
            let refresh = self
                .config
                .oidc
                .refresh_tokens(&payload.tokens, &record.subject, &self.app.auth)
                .await;
            let refreshed = match refresh {
                Ok(v) => v,
                Err(_) => {
                    self.app
                        .database
                        .browser_session_revoke(hash.to_owned(), None, Some(record.version))
                        .await?;
                    return Err(rejected());
                }
            };
            payload.tokens = refreshed.tokens;
            let bytes = serde_json::to_vec(&payload).map_err(|_| rejected())?;
            let encrypted = self
                .config
                .keys
                .encrypt(Purpose::Session, record.id, record.cluster_epoch, &bytes)
                .map_err(|_| rejected())?;
            let expiry =
                DateTime::from_timestamp(refreshed.identity.expires_at, 0).ok_or_else(rejected)?;
            if !self
                .app
                .database
                .browser_refresh_finish(hash, record.version, expiry, &encrypted)
                .await?
            {
                return Err(rejected());
            }
            record = self
                .app
                .database
                .browser_session_read(hash, false)
                .await?
                .ok_or_else(rejected)?;
            if record.status != "ACTIVE" {
                return Err(rejected());
            }
        }
        let identity = self
            .app
            .auth
            .verify(&payload.tokens.access_token)
            .await
            .map_err(|_| rejected())?;
        if identity.issuer != record.issuer
            || identity.subject != record.subject
            || identity.client_id.as_deref() != Some(self.config.oidc.settings().client_id.as_str())
        {
            return Err(rejected());
        }
        let current = self
            .app
            .database
            .browser_session_read(hash, false)
            .await?
            .ok_or_else(rejected)?;
        if current.status != "ACTIVE"
            || current.id != record.id
            || current.version != record.version
            || current.tenant_id != record.tenant_id
            || current.principal_id != record.principal_id
            || current.cluster_epoch != record.cluster_epoch
            || current.access_expires_at <= Utc::now()
            || identity.expires_at <= Utc::now().timestamp()
        {
            return Err(rejected());
        }
        record = current;
        Ok((record, payload))
    }
}

// Keep the tick and the dispatched operation in the same owned future. In
// particular, cancellation must not drop a query whose database effect may
// already have committed. The callback is the actual SQL operation in production.
async fn cleanup_loop<F, Fut>(
    shutdown: tokio_util::sync::CancellationToken,
    mut interval: tokio::time::Interval,
    mut cleanup: F,
) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<i64, sqlx::Error>>,
{
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            _ = interval.tick() => {},
        }
        if shutdown.is_cancelled() {
            return Ok(());
        }
        if cleanup().await.is_err() {
            tracing::warn!("browser session cleanup unavailable");
        }
    }
}

#[cfg(test)]
#[path = "bff_cleanup_tests.rs"]
mod cleanup_tests;

#[cfg(test)]
#[path = "bff_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "bff_live_tests.rs"]
mod live_tests;
async fn begin_login(
    State(runtime): State<Arc<BrowserRuntime>>,
    headers: HeaderMap,
    payload: Result<Json<BeginLogin>, JsonRejection>,
) -> Result<Response, ApiError> {
    runtime.origin(&headers, true)?;
    if headers.contains_key("authorization") {
        return Err(ApiError::invalid(
            "Browser login does not accept a bearer credential",
        ));
    }
    let Json(input) = payload.map_err(|_| ApiError::invalid("Login requires a tenant UUID"))?;
    if input.tenant_id.is_nil() {
        return Err(ApiError::invalid("Login requires a tenant UUID"));
    }
    let login = runtime.config.oidc.begin().map_err(oidc_error)?;
    let binding = random_token().map_err(|_| rejected())?;
    let id = Uuid::new_v4();
    let epoch = runtime.app.database.browser_epoch().await?;
    let plaintext = serde_json::to_vec(&login.secrets).map_err(|_| rejected())?;
    let encrypted = runtime
        .config
        .keys
        .encrypt(Purpose::Login, id, epoch, &plaintext)
        .map_err(|_| rejected())?;
    if !runtime
        .app
        .database
        .browser_login_create(
            id,
            input.tenant_id,
            epoch,
            &digest(&login.state)?,
            &hash_cookie(&binding)?,
            &encrypted,
        )
        .await?
    {
        return Err(busy());
    }
    let mut response =
        Json(serde_json::json!({"authorization_url":login.authorization_url})).into_response();
    response.headers_mut().append(
        "set-cookie",
        cookie_header(LOGIN_COOKIE, &binding, 300, "Lax")?,
    );
    Ok(response)
}
async fn callback(
    State(runtime): State<Arc<BrowserRuntime>>,
    headers: HeaderMap,
    query: Result<Query<Callback>, QueryRejection>,
) -> Response {
    let result = complete_login(&runtime, &headers, query).await;
    let mut response = match result {
        Ok(v) => v,
        Err(e) => e.into_response(),
    };
    response
        .headers_mut()
        .append("set-cookie", clear_cookie(LOGIN_COOKIE, "Lax"));
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    response
}
async fn complete_login(
    runtime: &BrowserRuntime,
    headers: &HeaderMap,
    query: Result<Query<Callback>, QueryRejection>,
) -> Result<Response, ApiError> {
    if headers.contains_key("authorization") {
        return Err(rejected());
    }
    let Query(query) = query.map_err(|_| rejected())?;
    // Provider error fields are never echoed or logged.
    if query
        .error_description
        .as_ref()
        .is_some_and(|s| s.len() > 4096)
        || query.session_state.as_ref().is_some_and(|s| s.len() > 4096)
    {
        return Err(rejected());
    }
    let binding = cookie(headers, LOGIN_COOKIE)?.ok_or_else(rejected)?;
    let login = runtime
        .app
        .database
        .browser_login_consume(&digest(&query.state)?, &hash_cookie(&binding)?)
        .await?
        .ok_or_else(rejected)?;
    if query.error.is_some()
        || query
            .iss
            .as_ref()
            .is_some_and(|s| s != &runtime.config.oidc.settings().issuer)
    {
        return Err(rejected());
    }
    let code = query.code.ok_or_else(rejected)?;
    let bytes = runtime
        .config
        .keys
        .decrypt(
            Purpose::Login,
            login.id,
            login.cluster_epoch,
            &login.payload,
        )
        .map_err(|_| rejected())?;
    let secrets: LoginSecrets = serde_json::from_slice(&bytes).map_err(|_| rejected())?;
    let verified = runtime
        .config
        .oidc
        .exchange(code, &secrets, &runtime.app.auth)
        .await
        .map_err(oidc_error)?;
    let session_cookie = random_token().map_err(|_| rejected())?;
    let csrf = random_token().map_err(|_| rejected())?;
    let id = Uuid::new_v4();
    let payload = Payload {
        tokens: verified.tokens,
        csrf_token: csrf.clone(),
    };
    let encrypted = runtime
        .config
        .keys
        .encrypt(
            Purpose::Session,
            id,
            login.cluster_epoch,
            &serde_json::to_vec(&payload).map_err(|_| rejected())?,
        )
        .map_err(|_| rejected())?;
    let expiry = DateTime::from_timestamp(verified.identity.expires_at, 0).ok_or_else(rejected)?;
    if login.tenant_id.is_nil()
        || !runtime
            .app
            .database
            .browser_session_create(
                login.id,
                id,
                hash_cookie(&session_cookie)?,
                hash_cookie(&csrf)?,
                verified.identity.issuer,
                verified.identity.subject,
                expiry,
                encrypted,
            )
            .await?
    {
        return Err(rejected());
    }
    let mut response = (StatusCode::SEE_OTHER, [("location", "/")]).into_response();
    response.headers_mut().append(
        "set-cookie",
        cookie_header(SESSION_COOKIE, &session_cookie, 28800, "Strict")?,
    );
    Ok(response)
}
async fn session(
    State(runtime): State<Arc<BrowserRuntime>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    runtime.origin(&headers, false)?;
    if headers.contains_key("authorization") {
        return Err(rejected());
    }
    let hash = hash_cookie(&cookie(&headers, SESSION_COOKIE)?.ok_or_else(rejected)?)?;
    let (record, payload) = runtime.credentials(&hash).await?;
    Ok(Json(SessionView {
        tenant_id: record.tenant_id,
        principal_id: record.principal_id,
        csrf_token: payload.csrf_token,
        absolute_expires_at: record.absolute_expires_at,
        idle_expires_at: record.idle_expires_at,
    })
    .into_response())
}
async fn logout(
    State(runtime): State<Arc<BrowserRuntime>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    runtime.origin(&headers, true)?;
    if headers.contains_key("authorization") {
        return Err(rejected());
    }
    let hash = hash_cookie(&cookie(&headers, SESSION_COOKIE)?.ok_or_else(rejected)?)?;
    let csrf = csrf_hash(&headers)?;
    if !runtime
        .app
        .database
        .browser_session_revoke(hash, Some(csrf), None)
        .await?
    {
        return Err(ApiError::forbidden());
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .append("set-cookie", clear_cookie(SESSION_COOKIE, "Strict"));
    Ok(response)
}
fn csrf_hash(headers: &HeaderMap) -> Result<String, ApiError> {
    let mut v = headers.get_all("x-csrf-token").iter();
    let h = v.next().ok_or_else(ApiError::forbidden)?;
    if v.next().is_some() {
        return Err(ApiError::forbidden());
    }
    hash_cookie(h.to_str().map_err(|_| ApiError::forbidden())?).map_err(|_| ApiError::forbidden())
}
async fn browser_boundary(
    State(runtime): State<Arc<BrowserRuntime>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    if !request.uri().path().starts_with("/v1/") {
        return next.run(request).await;
    }
    let value = match cookie(request.headers(), SESSION_COOKIE) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let Some(value) = value else {
        return next.run(request).await;
    };
    let hash = match hash_cookie(&value) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    if request.headers().contains_key("authorization") {
        return ApiError::invalid("Cookie and bearer credentials cannot be combined")
            .into_response();
    }
    let result = async {
        runtime.origin(
            request.headers(),
            !matches!(
                *request.method(),
                Method::GET | Method::HEAD | Method::OPTIONS
            ),
        )?;
        let (record, payload) = runtime.credentials(&hash).await?;
        if !matches!(
            *request.method(),
            Method::GET | Method::HEAD | Method::OPTIONS
        ) && csrf_hash(request.headers())? != record.csrf_hash
        {
            return Err(ApiError::forbidden());
        }
        let tenant = crate::request::tenant_id(request.headers())?;
        if tenant != record.tenant_id {
            return Err(ApiError::forbidden());
        }
        let bearer = HeaderValue::from_str(&format!("Bearer {}", payload.tokens.access_token))
            .map_err(|_| rejected())?;
        request.headers_mut().insert("authorization", bearer);
        Ok(())
    }
    .await;
    if let Err(e) = result {
        return e.into_response();
    }
    let response = next.run(request).await;
    if response.headers().get("content-type").is_some_and(|v| {
        v.as_bytes().starts_with(b"text/event-stream")
            || v.as_bytes().starts_with(b"application/octet-stream")
    }) {
        let (parts, body) = response.into_parts();
        let stream = body.into_data_stream();
        let guarded = futures_util::stream::unfold(
            (stream, runtime, hash, tokio::time::Instant::now()),
            |(mut stream, runtime, hash, mut checked)| async move {
                loop {
                    if checked.elapsed() >= Duration::from_secs(10) {
                        if !matches!(runtime.app.database.browser_session_read(&hash,false).await,Ok(Some(ref r)) if r.status=="ACTIVE")
                        {
                            return None;
                        }
                        checked = tokio::time::Instant::now();
                    }
                    tokio::select! {
                     item=stream.next()=>return item.map(|v|(v,(stream,runtime,hash,checked))),
                     ()=tokio::time::sleep_until(checked+Duration::from_secs(10))=>{},
                    }
                }
            },
        );
        Response::from_parts(parts, Body::from_stream(guarded))
    } else {
        response
    }
}
