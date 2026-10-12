//! Versioned automation management. This router uses the same identity resolver,
//! request boundary and durable receipts as the core management API.
use crate::{
    api::{AppState, authenticate},
    automation::{AutomationChange, AutomationMutationResult, CreateAutomation},
    error::ApiError,
    history::HistoryQuery,
    request,
};
use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, Path, Query, State,
        rejection::{JsonRejection, PathRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

pub struct AutomationApiRuntime {
    pub app: Arc<AppState>,
}
impl AutomationApiRuntime {
    pub async fn check_schema(&self) -> anyhow::Result<()> {
        self.app.database.check_automation_api_schema().await
    }
    pub fn routes(self: Arc<Self>) -> Router {
        Router::new()
            .route("/v1/instances/{id}/automations", post(create))
            .route("/v1/automations", get(list))
            .route("/v1/automations/{id}", get(read))
            .route("/v1/automations/{id}/runs", get(runs))
            .route("/v1/automation-runs/{id}", get(read_run))
            .route("/v1/automation-notifications", get(list_notifications))
            .route("/v1/automation-notifications/{id}", get(read_notification))
            .route(
                "/v1/automation-notifications/{id}/actions/acknowledge",
                post(acknowledge_notification),
            )
            .route("/v1/automations/{id}/actions/pause", post(pause))
            .route("/v1/automations/{id}/actions/resume", post(resume))
            .route("/v1/automations/{id}/actions/revoke", post(revoke))
            .layer(DefaultBodyLimit::max(64 * 1024))
            .with_state(self)
    }
}
fn json<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    payload.map(|Json(v)| v).map_err(|e| {
        ApiError::new(
            e.status(),
            "INVALID_JSON",
            "Body must match the endpoint JSON schema",
        )
    })
}
fn id(path: Result<Path<Uuid>, PathRejection>) -> Result<Uuid, ApiError> {
    path.map(|Path(id)| id)
        .map_err(|_| ApiError::invalid("Resource id must be a UUID"))
}
fn query(input: Result<Query<HistoryQuery>, QueryRejection>) -> Result<HistoryQuery, ApiError> {
    input
        .map(|Query(q)| q)
        .map_err(|_| ApiError::invalid("Invalid scoped history query"))
}
fn receipt(result: AutomationMutationResult) -> Result<Response, ApiError> {
    let status = StatusCode::from_u16(result.status)
        .map_err(|_| ApiError::invalid("Invalid persisted management receipt"))?;
    let location = format!("/v1/automations/{}", result.body.resource.id);
    Ok((
        status,
        [
            ("location", location.clone()),
            ("content-location", location),
            ("etag", format!("\"{}\"", result.body.resource.version)),
        ],
        Json(result.body),
    )
        .into_response())
}
async fn create(
    State(runtime): State<Arc<AutomationApiRuntime>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    payload: Result<Json<CreateAutomation>, JsonRejection>,
) -> Result<Response, ApiError> {
    let input = json(payload)?;
    let (actor, identity) = authenticate(&runtime.app, &headers).await?;
    receipt(
        runtime
            .app
            .database
            .create_automation(
                &actor,
                &identity,
                id(path)?,
                &input,
                request::idempotency_key(&headers)?,
                request::expected_version(&headers)?,
                runtime.app.max_ttl_seconds,
            )
            .await?,
    )
}
async fn read(
    State(runtime): State<Arc<AutomationApiRuntime>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
) -> Result<Response, ApiError> {
    let (actor, _) = authenticate(&runtime.app, &headers).await?;
    let resource = runtime
        .app
        .database
        .get_automation(&actor, id(path)?)
        .await?;
    Ok((
        [("etag", format!("\"{}\"", resource.version))],
        Json(resource),
    )
        .into_response())
}
async fn read_run(
    State(runtime): State<Arc<AutomationApiRuntime>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
) -> Result<Response, ApiError> {
    let (actor, _) = authenticate(&runtime.app, &headers).await?;
    let resource = runtime
        .app
        .database
        .get_automation_run(&actor, id(path)?)
        .await?;
    Ok((
        [("etag", format!("\"{}\"", resource.version))],
        Json(resource),
    )
        .into_response())
}
async fn list(
    State(runtime): State<Arc<AutomationApiRuntime>>,
    headers: HeaderMap,
    input: Result<Query<HistoryQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let (actor, _) = authenticate(&runtime.app, &headers).await?;
    Ok(Json(
        runtime
            .app
            .database
            .list_automations(&actor, &query(input)?, &runtime.app.cursor_signer)
            .await?,
    )
    .into_response())
}
async fn runs(
    State(runtime): State<Arc<AutomationApiRuntime>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    input: Result<Query<HistoryQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let (actor, _) = authenticate(&runtime.app, &headers).await?;
    Ok(Json(
        runtime
            .app
            .database
            .list_automation_runs(
                &actor,
                id(path)?,
                &query(input)?,
                &runtime.app.cursor_signer,
            )
            .await?,
    )
    .into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyBody {}
async fn change(
    runtime: Arc<AutomationApiRuntime>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    payload: Result<Json<EmptyBody>, JsonRejection>,
    action: AutomationChange,
) -> Result<Response, ApiError> {
    json(payload)?;
    let (actor, identity) = authenticate(&runtime.app, &headers).await?;
    receipt(
        runtime
            .app
            .database
            .change_automation(
                &actor,
                &identity,
                id(path)?,
                &action,
                request::idempotency_key(&headers)?,
                request::expected_version(&headers)?,
            )
            .await?,
    )
}
async fn pause(
    State(runtime): State<Arc<AutomationApiRuntime>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    payload: Result<Json<EmptyBody>, JsonRejection>,
) -> Result<Response, ApiError> {
    change(runtime, headers, path, payload, AutomationChange::Pause).await
}
async fn resume(
    State(runtime): State<Arc<AutomationApiRuntime>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    payload: Result<Json<EmptyBody>, JsonRejection>,
) -> Result<Response, ApiError> {
    change(runtime, headers, path, payload, AutomationChange::Resume).await
}
async fn revoke(
    State(runtime): State<Arc<AutomationApiRuntime>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    payload: Result<Json<EmptyBody>, JsonRejection>,
) -> Result<Response, ApiError> {
    change(runtime, headers, path, payload, AutomationChange::Revoke).await
}

async fn list_notifications(
    State(runtime): State<Arc<AutomationApiRuntime>>,
    headers: HeaderMap,
    input: Result<Query<HistoryQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let (actor, _) = authenticate(&runtime.app, &headers).await?;
    Ok(Json(
        runtime
            .app
            .database
            .list_automation_notifications(&actor, &query(input)?, &runtime.app.cursor_signer)
            .await?,
    )
    .into_response())
}
async fn read_notification(
    State(runtime): State<Arc<AutomationApiRuntime>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
) -> Result<Response, ApiError> {
    let (actor, _) = authenticate(&runtime.app, &headers).await?;
    let resource = runtime
        .app
        .database
        .get_automation_notification(&actor, id(path)?)
        .await?;
    Ok((
        [("etag", format!("\"{}\"", resource.version))],
        Json(resource),
    )
        .into_response())
}
async fn acknowledge_notification(
    State(runtime): State<Arc<AutomationApiRuntime>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    payload: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Response, ApiError> {
    let body = json(payload)?;
    if !body.as_object().is_some_and(serde_json::Map::is_empty) {
        return Err(ApiError::invalid(
            "Acknowledgement body must be an empty JSON object",
        ));
    }
    let (actor, identity) = authenticate(&runtime.app, &headers).await?;
    let id = id(path)?;
    let result = runtime
        .app
        .database
        .acknowledge_automation_notification(
            &actor,
            &identity,
            id,
            request::idempotency_key(&headers)?,
            request::expected_version(&headers)?,
        )
        .await?;
    let status = StatusCode::from_u16(result.status)
        .map_err(|_| ApiError::invalid("Stored notification status is invalid"))?;
    Ok((
        status,
        [
            (
                "content-location",
                format!("/v1/automation-notifications/{id}"),
            ),
            ("etag", format!("\"{}\"", result.body.resource.version)),
        ],
        Json(result.body),
    )
        .into_response())
}
