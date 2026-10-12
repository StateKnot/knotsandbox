//! Resumable execution output, indexed by committed immutable OSS segments.
//! A drained output stream never implies that the sandbox VM has terminated.
use std::{convert::Infallible, sync::Arc, time::Duration};

use axum::{
    Extension,
    extract::{
        Path, Query, State,
        rejection::{PathRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response, Sse, sse::Event},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    api::{AppState, authenticate},
    db::{Actor, Database},
    error::{ApiError, REQUEST_ID},
    event_stream::{Connection, StreamRuntime, last_event_id},
    execution_output::{ExecutionOutputPage, ExecutionOutputSegment},
    history::CursorSigner,
    output_store::OssOutputReader,
};

const CURSOR_TTL: i64 = 86_400;
// Only future issuance accepts skew; expiration remains strict.
const CURSOR_FUTURE_ISSUE_SKEW_SECONDS: i64 = 60;
const MAX_FRAME_BYTES: usize = 768 * 1024;
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const STREAM_LIFETIME: Duration = Duration::from_secs(300);

/// No query token, raw offset or silent latest reset: a fresh stream replays
/// committed output from segment zero; reconnect uses the signed header cursor.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StreamQuery {}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    kind: String,
    tenant_id: Uuid,
    principal_id: Uuid,
    execution_id: Uuid,
    cluster_epoch: Uuid,
    dispatch_attempt_id: Option<Uuid>,
    after_segment: i64,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
struct Position {
    cluster_epoch: Uuid,
    attempt: Option<Uuid>,
    after: i64,
}
impl Position {
    fn cursor(
        &self,
        actor: &Actor,
        id: Uuid,
        signer: &CursorSigner,
        now: DateTime<Utc>,
    ) -> Result<String, ApiError> {
        signer.encode_payload(&Cursor {
            version: 1,
            kind: "execution_output_stream".into(),
            tenant_id: actor.tenant_id,
            principal_id: actor.principal_id,
            execution_id: id,
            cluster_epoch: self.cluster_epoch,
            dispatch_attempt_id: self.attempt,
            after_segment: self.after,
            issued_at: now,
            expires_at: now + chrono::Duration::seconds(CURSOR_TTL),
        })
    }
}

#[derive(sqlx::FromRow)]
struct Head {
    project_id: Uuid,
    cluster_epoch: Uuid,
    dispatch_attempt_id: Option<Uuid>,
    last_segment: i64,
    output_status: String,
    writer_closed: bool,
}

impl Database {
    async fn output_head(&self, actor: &Actor, id: Uuid) -> Result<Head, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let head: Head = sqlx::query_as(
            "SELECT e.project_id,c.cluster_epoch,e.dispatch_attempt_id,COALESCE((SELECT max(s.sequence) FROM execution_output_segments s WHERE s.tenant_id=e.tenant_id AND s.execution_id=e.id),-1) AS last_segment,e.output_status,(e.status NOT IN('QUEUED','DISPATCHING','RUNNING')) AS writer_closed FROM executions e CROSS JOIN platform_configuration c WHERE e.tenant_id=$1 AND e.id=$2 AND c.singleton",
        ).bind(actor.tenant_id).bind(id).fetch_optional(&mut *tx).await?.ok_or_else(ApiError::not_found)?;
        Self::authorize_resource(&mut tx, actor, head.project_id, "executions:output:read").await?;
        tx.commit().await?;
        Ok(head)
    }

    async fn open_output_stream(
        &self,
        actor: &Actor,
        id: Uuid,
        encoded: Option<&str>,
        signer: &CursorSigner,
    ) -> Result<Position, ApiError> {
        let head = self.output_head(actor, id).await?;
        let mut position = if let Some(encoded) = encoded {
            let cursor: Cursor = signer.decode_payload(encoded)?;
            validate_cursor(&cursor, actor, id, Utc::now())?;
            Position {
                cluster_epoch: cursor.cluster_epoch,
                attempt: cursor.dispatch_attempt_id,
                after: cursor.after_segment,
            }
        } else {
            Position {
                cluster_epoch: head.cluster_epoch,
                attempt: head.dispatch_attempt_id,
                after: -1,
            }
        };
        validate_position(&mut position, &head)?;
        Ok(position)
    }
}

fn validate_cursor(
    c: &Cursor,
    actor: &Actor,
    id: Uuid,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    if c.version != 1
        || c.kind != "execution_output_stream"
        || c.tenant_id != actor.tenant_id
        || c.principal_id != actor.principal_id
        || c.execution_id != id
        || !(-1..=4095).contains(&c.after_segment)
        || (c.after_segment >= 0 && c.dispatch_attempt_id.is_none())
        || c.dispatch_attempt_id.is_some_and(|id| id.is_nil())
        || c.cluster_epoch.is_nil()
        || c.issued_at > now + chrono::Duration::seconds(CURSOR_FUTURE_ISSUE_SKEW_SECONDS)
        || c.expires_at <= c.issued_at
        || c.expires_at > c.issued_at + chrono::Duration::seconds(CURSOR_TTL)
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "INVALID_CURSOR",
            "Cursor does not match this execution output stream",
        ));
    }
    if c.expires_at <= now {
        return Err(ApiError::new(
            StatusCode::GONE,
            "OUTPUT_CURSOR_EXPIRED",
            "Output cursor expired; explicitly reconcile retained output",
        ));
    }
    Ok(())
}

fn validate_position(p: &mut Position, h: &Head) -> Result<(), ApiError> {
    if p.cluster_epoch != h.cluster_epoch
        || p.attempt.is_some_and(|a| Some(a) != h.dispatch_attempt_id)
    {
        return Err(ApiError::new(
            StatusCode::GONE,
            "OUTPUT_HISTORY_UNAVAILABLE",
            "Output identity changed; explicitly reconcile retained output",
        ));
    }
    if p.after > h.last_segment {
        return Err(ApiError::conflict(
            "OUTPUT_CURSOR_AHEAD",
            "Cursor is ahead of committed output; explicit reconciliation is required",
        ));
    }
    if p.attempt.is_none() {
        if p.after != -1 {
            return Err(integrity());
        }
        p.attempt = h.dispatch_attempt_id;
    }
    Ok(())
}

fn integrity() -> ApiError {
    let mut error = ApiError::new(
        StatusCode::BAD_GATEWAY,
        "OUTPUT_INTEGRITY_FAILED",
        "Stored output does not match the immutable execution index",
    );
    error.retryable = false;
    error
}

struct Stream {
    state: Arc<AppState>,
    reader: Arc<OssOutputReader>,
    headers: HeaderMap,
    actor: Actor,
    execution_id: Uuid,
    position: Position,
    pending: Option<ExecutionOutputSegment>,
    // RAII permit stays attached even while the HTTP consumer stops polling.
    _connection: Connection,
    shutdown: CancellationToken,
    deadline: Instant,
    last_frame: Instant,
    checkpoint: bool,
    closed: bool,
}

pub(crate) async fn stream_output(
    State(state): State<Arc<AppState>>,
    Extension(runtime): Extension<StreamRuntime>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    query: Result<Query<StreamQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Path(id) = path.map_err(|_| ApiError::invalid("Invalid execution UUID"))?;
    let _ = query.map_err(|_| {
        ApiError::invalid("Execution output streams do not accept query parameters")
    })?;
    let last_id = last_event_id(&headers)?;
    let (actor, identity) = authenticate(&state, &headers).await?;
    let connection = runtime.acquire(&actor)?;
    let position = state
        .database
        .open_output_stream(&actor, id, last_id, &state.cursor_signer)
        .await?;
    let reader = state.output_reader.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "OUTPUT_STORAGE_UNAVAILABLE",
            "Execution output storage is unavailable",
        )
    })?;
    let remaining = DateTime::from_timestamp(identity.expires_at, 0)
        .and_then(|expires| (expires - Utc::now()).to_std().ok())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(crate::request::unauthenticated)?;
    let now = Instant::now();
    let stream = Stream {
        state,
        reader,
        headers,
        actor,
        execution_id: id,
        position,
        pending: None,
        _connection: connection,
        shutdown: runtime.shutdown_token(),
        deadline: now + STREAM_LIFETIME.min(remaining),
        last_frame: now,
        checkpoint: true,
        closed: false,
    };
    let body = futures_util::stream::unfold(stream, |mut stream| async move {
        if stream.closed {
            return None;
        }
        let request_id = stream.actor.request_id;
        match REQUEST_ID.scope(request_id, stream.next()).await {
            Ok(Some(event)) => Some((Ok::<_, Infallible>(event), stream)),
            Ok(None) => None,
            Err(error) => {
                stream.closed = true;
                stream.pending = None;
                let data = serde_json::json!({"code":error.code,"retryable":error.retryable,"request_id":request_id});
                Some((
                    Ok(Event::default()
                        .event("stream.error")
                        .data(data.to_string())),
                    stream,
                ))
            }
        }
    });
    let mut response = Sse::new(body).into_response();
    response
        .headers_mut()
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    Ok(response)
}

impl Stream {
    async fn validate(&mut self) -> Result<Head, ApiError> {
        let result = tokio::time::timeout(Duration::from_secs(10), async {
            let (actor, identity) = authenticate(&self.state, &self.headers).await?;
            if actor.principal_id != self.actor.principal_id
                || actor.tenant_id != self.actor.tenant_id
                || identity.expires_at <= Utc::now().timestamp()
            {
                return Err(crate::request::unauthenticated());
            }
            self.state
                .database
                .output_head(&actor, self.execution_id)
                .await
        })
        .await
        .map_err(|_| unavailable("Output authorization deadline exceeded"))??;
        validate_position(&mut self.position, &result)?;
        Ok(result)
    }

    fn frame(&self, name: &'static str, data: serde_json::Value) -> Result<Event, ApiError> {
        let data = serde_json::to_string(&data).map_err(|_| integrity())?;
        if data.len() > MAX_FRAME_BYTES {
            return Err(integrity());
        }
        Ok(Event::default()
            .event(name)
            .id(self.position.cursor(
                &self.actor,
                self.execution_id,
                &self.state.cursor_signer,
                Utc::now(),
            )?)
            .data(data))
    }

    async fn next(&mut self) -> Result<Option<Event>, ApiError> {
        loop {
            if self.closed || self.shutdown.is_cancelled() || Instant::now() >= self.deadline {
                return Ok(None);
            }
            let shutdown = self.shutdown.clone();
            let deadline = self.deadline;
            let head = tokio::select! {
                _ = shutdown.cancelled() => return Ok(None),
                _ = tokio::time::sleep_until(deadline) => return Ok(None),
                head = self.validate() => head?,
            };
            if self.checkpoint {
                self.checkpoint = false;
                self.last_frame = Instant::now();
                return self.frame("output.checkpoint", serde_json::json!({"execution_id":self.execution_id,"after_segment":self.position.after})).map(Some);
            }
            if let Some(segment) = self.pending.take() {
                if segment.sequence != self.position.after + 1
                    || segment.sequence > head.last_segment
                {
                    return Err(integrity());
                }
                self.position.after = segment.sequence;
                self.last_frame = Instant::now();
                return self
                    .frame(
                        "output.segment",
                        serde_json::json!({"execution_id":self.execution_id,"segment":segment}),
                    )
                    .map(Some);
            }
            let read = tokio::time::timeout(
                Duration::from_secs(20),
                self.state.database.execution_output(
                    &self.actor,
                    self.execution_id,
                    self.position.after,
                    1,
                    &self.reader,
                ),
            );
            let mut page = tokio::select! {
                _ = shutdown.cancelled() => return Ok(None),
                _ = tokio::time::sleep_until(deadline) => return Ok(None),
                result = read => result.map_err(|_| unavailable("Output storage read deadline exceeded"))??,
            };
            // Recheck identity, JWT and epoch AFTER object I/O, before any bytes
            // leave. Database::execution_output separately rechecks output grant.
            let head = tokio::select! {
                _ = shutdown.cancelled() => return Ok(None),
                _ = tokio::time::sleep_until(deadline) => return Ok(None),
                head = self.validate() => head?,
            };
            if page.segments.len() > 1 {
                return Err(integrity());
            }
            if let Some(segment) = page.segments.pop() {
                self.pending = Some(segment);
                continue;
            }
            if drained(&page, &head, &self.position)? {
                let event = self.frame("output.end", serde_json::json!({
                    "execution_id":self.execution_id,"after_segment":self.position.after,
                    "output_status":page.output_status,"manifest_verified":page.manifest_verified,
                    "final_segment_sequence":page.final_segment_sequence,
                }))?;
                self.closed = true;
                return Ok(Some(event));
            }
            if self.last_frame.elapsed() >= HEARTBEAT_INTERVAL {
                self.last_frame = Instant::now();
                return Ok(Some(Event::default().comment("heartbeat")));
            }
            tokio::select! {
                _ = shutdown.cancelled() => return Ok(None),
                _ = tokio::time::sleep_until(deadline) => return Ok(None),
                _ = tokio::time::sleep(POLL_INTERVAL) => {},
            }
        }
    }
}

fn drained(page: &ExecutionOutputPage, head: &Head, position: &Position) -> Result<bool, ApiError> {
    if page.has_more
        || head.last_segment != position.after
        || page.output_status != head.output_status
        || !head.writer_closed
    {
        return Ok(false);
    }
    match page.output_status.as_str() {
        "COMPLETE" | "TRUNCATED" => {
            if !page.manifest_verified || page.final_segment_sequence != Some(position.after) {
                return Err(integrity());
            }
            Ok(true)
        }
        "PARTIAL" | "LOST" => Ok(true),
        // PENDING cannot certify even an empty final output; wait for the
        // controller to resolve it instead of treating missing output as zero.
        "PENDING" => Ok(false),
        _ => Err(integrity()),
    }
}

fn unavailable(detail: &'static str) -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "OUTPUT_STORAGE_UNAVAILABLE",
        detail,
    )
}

#[cfg(test)]
#[path = "execution_output_stream_tests.rs"]
mod tests;
