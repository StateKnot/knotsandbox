use std::{sync::Arc, time::Duration};

use axum::{
    Extension, Json, Router,
    body::Body,
    extract::{
        DefaultBodyLimit, Path, Query, State,
        rejection::{JsonRejection, PathRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    auth::{AuthError, JwtAuthenticator, VerifiedIdentity},
    db::{Actor, Database, MutationResult},
    domain::InstanceAction,
    error::{ApiError, REQUEST_ID},
    execution::ExecutionMutationResult,
    grants::{CreateGrant, GrantMutationResult, UpdateGrant},
    history::{CursorSigner, HistoryQuery},
    model::{CancelExecution, CreateExecution, CreateInstance, RenewRequest, StartRequest},
    request,
    service_clients::{RegisterServiceClient, ServiceClientMutationResult, UpdateServiceClient},
};

pub struct AppState {
    pub database: Database,
    pub auth: JwtAuthenticator,
    pub cursor_signer: CursorSigner,
    pub output_reader: Option<Arc<crate::output_store::OssOutputReader>>,
    pub metrics: Option<crate::metrics::PrometheusMetrics>,
    pub default_ttl_seconds: i64,
    pub max_ttl_seconds: i64,
}

#[derive(Clone, Copy)]
struct ConfiguredFeatures {
    files: bool,
    automations: bool,
}

pub fn router(state: Arc<AppState>) -> Router {
    router_with_shutdown(state, tokio_util::sync::CancellationToken::new())
}

pub fn router_with_shutdown(
    state: Arc<AppState>,
    shutdown: tokio_util::sync::CancellationToken,
) -> Router {
    router_with_browser(state, shutdown, None)
}

pub fn router_with_browser(
    state: Arc<AppState>,
    shutdown: tokio_util::sync::CancellationToken,
    browser: Option<Arc<crate::bff::BrowserRuntime>>,
) -> Router {
    router_with_components(state, shutdown, browser, None)
}

pub fn router_with_components(
    state: Arc<AppState>,
    shutdown: tokio_util::sync::CancellationToken,
    browser: Option<Arc<crate::bff::BrowserRuntime>>,
    files: Option<Arc<crate::file_api::FileApiRuntime>>,
) -> Router {
    router_with_automations(state, shutdown, browser, files, None)
}

/// The caller checks each configured component before binding its listener.
/// Capability flags describe these mounted routes, never coordinator health.
pub fn router_with_automations(
    state: Arc<AppState>,
    shutdown: tokio_util::sync::CancellationToken,
    browser: Option<Arc<crate::bff::BrowserRuntime>>,
    files: Option<Arc<crate::file_api::FileApiRuntime>>,
    automations: Option<Arc<crate::automation::api::AutomationApiRuntime>>,
) -> Router {
    let configured_features = ConfiguredFeatures {
        files: files.is_some(),
        automations: automations.is_some(),
    };
    let router = Router::new()
        .route("/health/live", get(|| async { StatusCode::NO_CONTENT }))
        .route("/health/ready", get(ready))
        .route("/v1/capabilities", get(get_capabilities))
        .route(
            "/v1/service-clients",
            get(list_service_clients).post(register_service_client),
        )
        .route(
            "/v1/service-clients/{id}",
            get(get_service_client).patch(update_service_client),
        )
        .route(
            "/v1/projects/{id}/grants",
            get(list_project_grants).post(create_project_grant),
        )
        .route(
            "/v1/projects/{id}/grants/{grant_id}",
            get(get_project_grant)
                .patch(update_project_grant)
                .delete(revoke_project_grant),
        )
        .route("/v1/instances", get(list_instances).post(create_instance))
        .route(
            "/v1/instances/{id}",
            get(get_instance).delete(delete_instance),
        )
        .route("/v1/instances/{id}/details", get(get_instance_details))
        .route(
            "/v1/instances/{id}/resource-accounting",
            get(get_resource_accounting),
        )
        .route("/v1/instances/{id}/security", get(get_instance_security))
        .route("/v1/instances/{id}/metrics", get(get_instance_metrics))
        .route(
            "/v1/instances/{id}/diagnoses",
            axum::routing::post(create_diagnosis),
        )
        .route("/v1/diagnoses/{id}", get(get_diagnosis))
        .route(
            "/v1/instances/{id}/actions/start",
            axum::routing::post(start_instance),
        )
        .route(
            "/v1/instances/{id}/actions/stop",
            axum::routing::post(stop_instance),
        )
        .route(
            "/v1/instances/{id}/actions/restart",
            axum::routing::post(restart_instance),
        )
        .route(
            "/v1/instances/{id}/actions/renew",
            axum::routing::post(renew_instance),
        )
        .route(
            "/v1/workspaces/{id}",
            get(get_workspace).delete(delete_workspace),
        )
        .route(
            "/v1/workspaces/{id}/backups",
            axum::routing::post(create_backup),
        )
        .route("/v1/backups/{id}", get(get_backup))
        .route("/v1/operations", get(list_operations))
        .route("/v1/operations/{id}", get(get_operation))
        .route("/v1/events", get(list_events))
        .route("/v1/events/stream", get(crate::event_stream::stream_events))
        .route("/v1/audit-records", get(list_audit_records))
        .route("/v1/tenant-audit-records", get(list_tenant_audit_records))
        .route(
            "/v1/instances/{id}/executions",
            axum::routing::post(create_execution),
        )
        .route("/v1/executions/{id}", get(get_execution))
        .route("/v1/executions/{id}/output", get(get_execution_output))
        .route(
            "/v1/executions/{id}/output/stream",
            get(crate::execution_output_stream::stream_output),
        )
        .route(
            "/v1/executions/{id}/cancel",
            axum::routing::post(cancel_execution),
        )
        .fallback(|| async { ApiError::not_found() })
        .method_not_allowed_fallback(|| async {
            ApiError::new(
                StatusCode::METHOD_NOT_ALLOWED,
                "METHOD_NOT_ALLOWED",
                "Method is not supported for this resource",
            )
        })
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state);
    let router = match files {
        Some(files) => router.merge(files.routes()),
        None => router,
    };
    let router = match automations {
        Some(automations) => router.merge(automations.routes()),
        None => router,
    };
    let router = match browser {
        Some(browser) => browser.attach(router),
        None => router,
    };
    router
        .layer(Extension(configured_features))
        .layer(axum::Extension(crate::event_stream::StreamRuntime::new(
            shutdown,
        )))
        .layer(middleware::from_fn(request_boundary))
}

pub(crate) async fn request_boundary(request: Request<Body>, next: Next) -> Response {
    // Never trust a caller-supplied correlation identifier as our audit identity.
    let id = Uuid::new_v4();
    REQUEST_ID.scope(id, async move {
        let started = std::time::Instant::now();
        static CONCURRENT_REQUESTS:tokio::sync::Semaphore=tokio::sync::Semaphore::const_new(256);
        let mut response = if request.uri().path()=="/health/live" {
            next.run(request).await
        } else { match CONCURRENT_REQUESTS.try_acquire() {
            Ok(_permit)=>match tokio::time::timeout(Duration::from_secs(20), next.run(request)).await {
                Ok(response) => response,
                Err(_) => ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "REQUEST_TIMEOUT", "Request deadline exceeded; retry mutations only with their original idempotency key").into_response(),
            },
            Err(_)=>ApiError::new(StatusCode::SERVICE_UNAVAILABLE,"API_OVERLOADED","This replica is at its request concurrency limit").into_response(),
        }};
        if let Ok(value) = HeaderValue::from_str(&id.to_string()) { response.headers_mut().insert("x-request-id", value); }
        response.headers_mut().insert("cache-control", HeaderValue::from_static("no-store"));
        response.headers_mut().insert("x-content-type-options", HeaderValue::from_static("nosniff"));
        tracing::info!(request_id=%id,status=response.status().as_u16(),elapsed_ms=started.elapsed().as_millis(),"http request completed");
        response
    }).await
}

async fn ready(State(state): State<Arc<AppState>>) -> Result<StatusCode, ApiError> {
    let configured = sqlx::query_scalar::<_, bool>(
        "SELECT singleton FROM platform_configuration WHERE singleton",
    )
    .fetch_optional(&state.database.pool)
    .await?;
    if configured != Some(true) {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "PLATFORM_NOT_INITIALIZED",
            "Platform initialization is incomplete",
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn actor(state: &AppState, headers: &HeaderMap) -> Result<Actor, ApiError> {
    authenticate(state, headers).await.map(|(actor, _)| actor)
}

pub(crate) async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(Actor, VerifiedIdentity), ApiError> {
    let token = request::bearer(headers)?;
    let identity = state.auth.verify(token).await.map_err(|e| match e {
        AuthError::JwksUnavailable | AuthError::InvalidJwks => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "IDENTITY_UNAVAILABLE",
            "Identity verification is temporarily unavailable",
        ),
        AuthError::InsufficientScope => ApiError::new(
            StatusCode::FORBIDDEN,
            "INSUFFICIENT_SCOPE",
            "Required OAuth scope is missing",
        ),
        _ => request::unauthenticated(),
    })?;
    let actor = state
        .database
        .resolve_actor(
            &identity,
            request::tenant_id(headers)?,
            crate::error::request_id(),
        )
        .await?;
    Ok((actor, identity))
}

fn json_body<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    // The framework error can echo submitted fields. Keep response/logs bounded and private.
    payload.map(|Json(value)| value).map_err(|e| {
        ApiError::new(
            e.status(),
            "INVALID_JSON",
            "Body must match the endpoint JSON schema",
        )
    })
}

async fn create_instance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    payload: Result<Json<CreateInstance>, JsonRejection>,
) -> Result<Response, ApiError> {
    let request = json_body(payload)?;
    let actor = actor(&state, &headers).await?;
    let result = state
        .database
        .create_instance(
            &actor,
            &request,
            request::idempotency_key(&headers)?,
            state.default_ttl_seconds,
            state.max_ttl_seconds,
        )
        .await?;
    mutation_response(result)
}

pub fn mutation_response(result: MutationResult) -> Result<Response, ApiError> {
    let location = format!("/v1/operations/{}", result.body.operation.id);
    let etag = format!("\"{}\"", result.body.resource.spec_version);
    let status = StatusCode::from_u16(result.status)
        .map_err(|_| ApiError::invalid("Invalid receipt status"))?;
    Ok((
        status,
        [
            ("location", location),
            ("etag", etag),
            ("retry-after", "2".to_owned()),
        ],
        Json(result.body),
    )
        .into_response())
}

async fn get_instance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path(id) = path.map_err(|_| ApiError::invalid("Resource id must be a UUID"))?;
    let actor = actor(&state, &headers).await?;
    let instance = state.database.get_instance(&actor, id).await?;
    Ok((
        [("etag", format!("\"{}\"", instance.spec_version))],
        Json(instance),
    )
        .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstanceQuery {
    project_id: Uuid,
    limit: Option<i64>,
    after: Option<Uuid>,
}

async fn list_instances(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    query: Result<Query<InstanceQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::invalid("Invalid instance list query"))?;
    let actor = actor(&state, &headers).await?;
    let limit = query.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return Err(ApiError::invalid("limit must be 1..100"));
    }
    let mut rows = state
        .database
        .list_instances(&actor, query.project_id, limit + 1, query.after)
        .await?;
    let next = if rows.len() > limit as usize {
        rows.pop();
        rows.last().map(|row| row.id)
    } else {
        None
    };
    Ok(Json(serde_json::json!({"items":rows,"next_after":next})).into_response())
}

async fn get_operation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path(id) = path.map_err(|_| ApiError::invalid("Resource id must be a UUID"))?;
    let actor = actor(&state, &headers).await?;
    Ok(Json(state.database.get_operation(&actor, id).await?).into_response())
}

async fn renew_instance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    payload: Result<Json<RenewRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Path(id) = path.map_err(|_| ApiError::invalid("Resource id must be a UUID"))?;
    let body = json_body(payload)?;
    let actor = actor(&state, &headers).await?;
    mutation_response(
        state
            .database
            .renew_instance(
                &actor,
                id,
                &body,
                request::idempotency_key(&headers)?,
                request::expected_version(&headers)?,
                state.max_ttl_seconds,
            )
            .await?,
    )
}

async fn lifecycle(
    state: Arc<AppState>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    body: StartRequest,
    action: InstanceAction,
) -> Result<Response, ApiError> {
    let Path(id) = path.map_err(|_| ApiError::invalid("Resource id must be a UUID"))?;
    let actor = actor(&state, &headers).await?;
    mutation_response(
        state
            .database
            .lifecycle_action(
                &actor,
                id,
                action,
                &body,
                request::idempotency_key(&headers)?,
                request::expected_version(&headers)?,
                state.default_ttl_seconds,
                state.max_ttl_seconds,
            )
            .await?,
    )
}

async fn start_instance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    payload: Result<Json<StartRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    lifecycle(
        state,
        headers,
        path,
        json_body(payload)?,
        InstanceAction::Start,
    )
    .await
}

async fn stop_instance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    payload: Result<Json<crate::model::EmptyRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    json_body(payload)?;
    lifecycle(
        state,
        headers,
        path,
        StartRequest::default(),
        InstanceAction::Stop,
    )
    .await
}

async fn restart_instance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    payload: Result<Json<crate::model::EmptyRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    json_body(payload)?;
    lifecycle(
        state,
        headers,
        path,
        StartRequest::default(),
        InstanceAction::Restart,
    )
    .await
}

async fn delete_instance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
) -> Result<Response, ApiError> {
    lifecycle(
        state,
        headers,
        path,
        StartRequest::default(),
        InstanceAction::Delete,
    )
    .await
}

async fn create_execution(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    payload: Result<Json<CreateExecution>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Path(id) = path.map_err(|_| ApiError::invalid("Resource id must be a UUID"))?;
    let body = json_body(payload)?;
    let actor = actor(&state, &headers).await?;
    execution_response(
        state
            .database
            .create_execution(
                &actor,
                id,
                &body,
                request::idempotency_key(&headers)?,
                request::expected_version(&headers)?,
            )
            .await?,
    )
}

async fn get_execution(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path(id) = path.map_err(|_| ApiError::invalid("Resource id must be a UUID"))?;
    let actor = actor(&state, &headers).await?;
    let execution = state.database.get_execution(&actor, id).await?;
    Ok((
        [("etag", format!("\"{}\"", execution.version))],
        Json(execution),
    )
        .into_response())
}

async fn cancel_execution(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    payload: Result<Json<CancelExecution>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Path(id) = path.map_err(|_| ApiError::invalid("Resource id must be a UUID"))?;
    let body = json_body(payload)?;
    let actor = actor(&state, &headers).await?;
    execution_response(
        state
            .database
            .cancel_execution(
                &actor,
                id,
                &body,
                request::idempotency_key(&headers)?,
                request::expected_version(&headers)?,
            )
            .await?,
    )
}

fn execution_response(result: ExecutionMutationResult) -> Result<Response, ApiError> {
    let status = StatusCode::from_u16(result.status)
        .map_err(|_| ApiError::invalid("Invalid receipt status"))?;
    Ok((
        status,
        [
            (
                "location",
                format!("/v1/executions/{}", result.body.resource.id),
            ),
            ("etag", format!("\"{}\"", result.body.resource.version)),
            (
                "x-instance-etag",
                format!("\"{}\"", result.body.instance_spec_version),
            ),
            ("retry-after", "2".to_owned()),
        ],
        Json(result.body),
    )
        .into_response())
}

async fn list_operations(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    query: Result<Query<HistoryQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::invalid("Invalid history query parameters"))?;
    let actor = actor(&state, &headers).await?;
    Ok(Json(
        state
            .database
            .list_operations(&actor, &query, &state.cursor_signer)
            .await?,
    )
    .into_response())
}

async fn list_events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    query: Result<Query<HistoryQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::invalid("Invalid history query parameters"))?;
    let actor = actor(&state, &headers).await?;
    Ok(Json(
        state
            .database
            .list_events(&actor, &query, &state.cursor_signer)
            .await?,
    )
    .into_response())
}

async fn list_audit_records(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    query: Result<Query<HistoryQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::invalid("Invalid history query parameters"))?;
    let actor = actor(&state, &headers).await?;
    Ok(Json(
        state
            .database
            .list_audit_records(&actor, &query, &state.cursor_signer)
            .await?,
    )
    .into_response())
}

async fn list_tenant_audit_records(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    query: Result<Query<crate::tenant_audit::TenantAuditQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) =
        query.map_err(|_| ApiError::invalid("Invalid tenant audit query parameters"))?;
    let actor = actor(&state, &headers).await?;
    Ok(Json(
        state
            .database
            .list_tenant_audit_records(&actor, &query, &state.cursor_signer)
            .await?,
    )
    .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilitiesQuery {
    project_id: Uuid,
}

async fn get_capabilities(
    Extension(configured): Extension<ConfiguredFeatures>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    query: Result<Query<CapabilitiesQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::invalid("A valid project_id is required"))?;
    let actor = actor(&state, &headers).await?;
    let mut capabilities = state
        .database
        .capabilities(
            &actor,
            query.project_id,
            state.default_ttl_seconds,
            state.max_ttl_seconds,
        )
        .await?;
    capabilities.api_features.execution_output_download = state.output_reader.is_some();
    capabilities.api_features.execution_output_streaming = state.output_reader.is_some();
    capabilities.api_features.runtime_metrics = state.metrics.is_some();
    capabilities.api_features.file_transfer = configured.files;
    capabilities.api_features.scheduled_tasks = configured.automations;
    capabilities.api_features.event_automation = configured.automations;
    capabilities.api_features.automation_notifications = configured.automations;
    capabilities.automation = configured
        .automations
        .then(crate::automation::contract::capabilities);
    Ok(Json(capabilities).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionOutputQuery {
    #[serde(default = "initial_output_segment")]
    after_segment: i64,
    #[serde(default = "default_output_limit")]
    limit: i64,
}

fn initial_output_segment() -> i64 {
    -1
}
fn default_output_limit() -> i64 {
    1
}

async fn get_execution_output(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    query: Result<Query<ExecutionOutputQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Path(id) = path.map_err(|_| ApiError::invalid("Resource id must be a UUID"))?;
    let Query(query) = query.map_err(|_| ApiError::invalid("Invalid output page parameters"))?;
    if !(-1..=4095).contains(&query.after_segment) || !(1..=2).contains(&query.limit) {
        return Err(ApiError::invalid(
            "after_segment must be -1..4095 and limit must be 1..2",
        ));
    }
    let actor = actor(&state, &headers).await?;
    let reader = state.output_reader.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "OUTPUT_STORAGE_UNAVAILABLE",
            "Execution output reading is not configured",
        )
    })?;
    Ok(Json(
        state
            .database
            .execution_output(&actor, id, query.after_segment, query.limit, reader)
            .await?,
    )
    .into_response())
}

async fn get_instance_details(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path(id) = path.map_err(|_| ApiError::invalid("Resource id must be a UUID"))?;
    let actor = actor(&state, &headers).await?;
    let details = state.database.instance_details(&actor, id).await?;
    Ok((
        [(
            "x-instance-etag",
            format!("\"{}\"", details.instance.spec_version),
        )],
        Json(details),
    )
        .into_response())
}

async fn get_instance_security(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path(id) = path.map_err(|_| ApiError::invalid("Resource id must be a UUID"))?;
    let (actor, identity) = authenticate(&state, &headers).await?;
    let result = state
        .database
        .get_instance_security(&actor, &identity, id)
        .await?;
    Ok((
        [("x-instance-etag", format!("\"{}\"", result.spec_version))],
        Json(result),
    )
        .into_response())
}

async fn get_resource_accounting(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    query: Result<Query<crate::resource_accounting::ResourceAccountingQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::invalid("Invalid resource accounting query"))?;
    let Path(id) = path.map_err(|_| ApiError::invalid("Invalid instance ID"))?;
    let (actor, identity) = authenticate(&state, &headers).await?;
    let result = state
        .database
        .resource_accounting(&actor, id, &query, &state.cursor_signer)
        .await;
    let current = state
        .database
        .resolve_actor(&identity, actor.tenant_id, actor.request_id)
        .await?;
    if current.principal_id != actor.principal_id
        || identity.expires_at <= chrono::Utc::now().timestamp()
    {
        return Err(request::unauthenticated());
    }
    Ok(Json(result?).into_response())
}

async fn get_instance_metrics(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    id: Result<Path<Uuid>, PathRejection>,
    query: Result<Query<crate::instance_metrics::InstanceMetricQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let (actor, identity) = authenticate(&state, &headers).await?;
    let Path(id) = id.map_err(|_| ApiError::invalid("Invalid instance ID"))?;
    let Query(query) = query.map_err(|_| ApiError::invalid("Invalid metrics query"))?;
    let result = state
        .database
        .instance_metrics(&actor, id, &query, state.metrics.as_ref())
        .await;
    // The issuer/subject mapping can be revoked independently of the product
    // principal or project grant while the external query is in progress.
    let current = state
        .database
        .resolve_actor(&identity, actor.tenant_id, actor.request_id)
        .await?;
    if current.principal_id != actor.principal_id {
        return Err(request::unauthenticated());
    }
    if identity.expires_at <= chrono::Utc::now().timestamp() {
        return Err(request::unauthenticated());
    }
    Ok(Json(result?).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantListQuery {
    limit: Option<i64>,
    cursor: Option<String>,
}
async fn list_project_grants(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    query: Result<Query<GrantListQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Path(project) = path.map_err(|_| ApiError::invalid("Project id must be a UUID"))?;
    let Query(query) = query.map_err(|_| ApiError::invalid("Invalid grant list query"))?;
    let actor = actor(&state, &headers).await?;
    let query = HistoryQuery {
        project_id: project,
        instance_id: None,
        limit: query.limit,
        cursor: query.cursor,
    };
    Ok(Json(
        state
            .database
            .list_project_grants(&actor, &query, &state.cursor_signer)
            .await?,
    )
    .into_response())
}
async fn get_project_grant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<(Uuid, Uuid)>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path((project, id)) =
        path.map_err(|_| ApiError::invalid("Project and grant ids must be UUIDs"))?;
    let actor = actor(&state, &headers).await?;
    let grant = state
        .database
        .get_project_grant(&actor, project, id)
        .await?;
    Ok(([("etag", format!("\"{}\"", grant.version))], Json(grant)).into_response())
}
async fn create_project_grant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    payload: Result<Json<CreateGrant>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Path(project) = path.map_err(|_| ApiError::invalid("Project id must be a UUID"))?;
    let request = json_body(payload)?;
    let actor = actor(&state, &headers).await?;
    grant_response(
        state
            .database
            .create_project_grant(
                &actor,
                project,
                &request,
                request::idempotency_key(&headers)?,
            )
            .await?,
    )
}
async fn update_project_grant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<(Uuid, Uuid)>, PathRejection>,
    payload: Result<Json<UpdateGrant>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Path((project, id)) =
        path.map_err(|_| ApiError::invalid("Project and grant ids must be UUIDs"))?;
    let request = json_body(payload)?;
    let actor = actor(&state, &headers).await?;
    grant_response(
        state
            .database
            .update_project_grant(
                &actor,
                project,
                id,
                &request,
                request::idempotency_key(&headers)?,
                request::expected_version(&headers)?,
            )
            .await?,
    )
}
async fn revoke_project_grant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<(Uuid, Uuid)>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path((project, id)) =
        path.map_err(|_| ApiError::invalid("Project and grant ids must be UUIDs"))?;
    let actor = actor(&state, &headers).await?;
    grant_response(
        state
            .database
            .revoke_project_grant(
                &actor,
                project,
                id,
                request::idempotency_key(&headers)?,
                request::expected_version(&headers)?,
            )
            .await?,
    )
}
fn grant_response(result: GrantMutationResult) -> Result<Response, ApiError> {
    let status = StatusCode::from_u16(result.status)
        .map_err(|_| ApiError::invalid("Invalid grant receipt status"))?;
    let location = format!(
        "/v1/projects/{}/grants/{}",
        result.body.resource.project_id, result.body.resource.id
    );
    let etag = format!("\"{}\"", result.body.resource.version);
    Ok((
        status,
        [("location", location), ("etag", etag)],
        Json(result.body),
    )
        .into_response())
}

async fn list_service_clients(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    query: Result<Query<GrantListQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::invalid("Invalid service client page query"))?;
    let actor = actor(&state, &headers).await?;
    Ok(Json(
        state
            .database
            .list_service_clients(&actor, query.limit, query.cursor, &state.cursor_signer)
            .await?,
    )
    .into_response())
}
async fn get_service_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path(id) = path.map_err(|_| ApiError::invalid("Service client id must be a UUID"))?;
    let actor = actor(&state, &headers).await?;
    let result = state.database.get_service_client(&actor, id).await?;
    Ok(([("etag", format!("\"{}\"", result.version))], Json(result)).into_response())
}
async fn register_service_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    payload: Result<Json<RegisterServiceClient>, JsonRejection>,
) -> Result<Response, ApiError> {
    let request = json_body(payload)?;
    let actor = actor(&state, &headers).await?;
    service_client_response(
        state
            .database
            .register_service_client(
                &actor,
                &request,
                state.auth.issuer(),
                request::idempotency_key(&headers)?,
            )
            .await?,
    )
}
async fn update_service_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    payload: Result<Json<UpdateServiceClient>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Path(id) = path.map_err(|_| ApiError::invalid("Service client id must be a UUID"))?;
    let request = json_body(payload)?;
    let actor = actor(&state, &headers).await?;
    service_client_response(
        state
            .database
            .update_service_client(
                &actor,
                id,
                &request,
                request::idempotency_key(&headers)?,
                request::expected_version(&headers)?,
            )
            .await?,
    )
}
fn service_client_response(result: ServiceClientMutationResult) -> Result<Response, ApiError> {
    let status = StatusCode::from_u16(result.status)
        .map_err(|_| ApiError::invalid("Invalid service client receipt status"))?;
    let location = format!("/v1/service-clients/{}", result.body.resource.id);
    let etag = format!("\"{}\"", result.body.resource.version);
    Ok((
        status,
        [("location", location), ("etag", etag)],
        Json(result.body),
    )
        .into_response())
}

async fn create_diagnosis(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    payload: Result<Json<crate::diagnostics::CreateDiagnosis>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Path(id) = path.map_err(|_| ApiError::invalid("Resource id must be a UUID"))?;
    let body = json_body(payload)?;
    let actor = actor(&state, &headers).await?;
    let result = state
        .database
        .create_diagnosis(&actor, id, &body, request::idempotency_key(&headers)?)
        .await?;
    let status = StatusCode::from_u16(result.status)
        .map_err(|_| ApiError::invalid("Invalid receipt status"))?;
    Ok((
        status,
        [
            (
                "location",
                format!("/v1/operations/{}", result.body.operation.id),
            ),
            (
                "content-location",
                format!("/v1/diagnoses/{}", result.body.resource.id),
            ),
            ("etag", format!("\"{}\"", result.body.resource.version)),
            ("retry-after", "2".into()),
        ],
        Json(result.body),
    )
        .into_response())
}
async fn get_diagnosis(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path(id) = path.map_err(|_| ApiError::invalid("Resource id must be a UUID"))?;
    let actor = actor(&state, &headers).await?;
    let diagnosis = state.database.get_diagnosis(&actor, id).await?;
    Ok((
        [("etag", format!("\"{}\"", diagnosis.version))],
        Json(diagnosis),
    )
        .into_response())
}

async fn create_backup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    payload: Result<Json<crate::backup_ledger::CreateBackup>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Path(id) = path.map_err(|_| ApiError::invalid("Resource id must be a UUID"))?;
    let body = json_body(payload)?;
    let actor = actor(&state, &headers).await?;
    let result = state
        .database
        .create_backup(
            &actor,
            id,
            &body,
            request::idempotency_key(&headers)?,
            request::expected_version(&headers)?,
        )
        .await?;
    let status = StatusCode::from_u16(result.status)
        .map_err(|_| ApiError::invalid("Invalid receipt status"))?;
    Ok((
        status,
        [
            (
                "location",
                format!("/v1/operations/{}", result.body.operation.id),
            ),
            (
                "x-workspace-etag",
                format!("\"{}\"", result.body.workspace_version),
            ),
            ("retry-after", "2".into()),
        ],
        Json(result.body),
    )
        .into_response())
}
async fn get_backup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path(id) = path.map_err(|_| ApiError::invalid("Resource id must be a UUID"))?;
    let actor = actor(&state, &headers).await?;
    let backup = state.database.get_backup(&actor, id).await?;
    Ok(([("etag", format!("\"{}\"", backup.version))], Json(backup)).into_response())
}

async fn get_workspace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path(id) = path.map_err(|_| ApiError::invalid("Resource id must be a UUID"))?;
    let actor = actor(&state, &headers).await?;
    let workspace = state.database.get_workspace(&actor, id).await?;
    Ok((
        [("etag", format!("\"{}\"", workspace.spec_version))],
        Json(workspace),
    )
        .into_response())
}
async fn delete_workspace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    payload: Result<Json<crate::workspaces::DeleteWorkspace>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Path(id) = path.map_err(|_| ApiError::invalid("Resource id must be a UUID"))?;
    let body = json_body(payload)?;
    let actor = actor(&state, &headers).await?;
    let result = state
        .database
        .delete_workspace(
            &actor,
            id,
            &body,
            request::idempotency_key(&headers)?,
            request::expected_version(&headers)?,
        )
        .await?;
    let status = StatusCode::from_u16(result.status)
        .map_err(|_| ApiError::invalid("Invalid receipt status"))?;
    Ok((
        status,
        [
            (
                "location",
                format!("/v1/operations/{}", result.body.operation.id),
            ),
            ("etag", format!("\"{}\"", result.body.resource.spec_version)),
            ("retry-after", "2".into()),
        ],
        Json(result.body),
    )
        .into_response())
}
