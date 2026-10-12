//! Commit-ordered, resumable project events. Positions are transactionally
//! allocated by PostgreSQL, never inferred from timestamps or BIGSERIAL values.

use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Extension,
    extract::{Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response, Sse, sse::Event},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    api::{AppState, authenticate},
    db::{Actor, Database, load_instance},
    error::{ApiError, REQUEST_ID},
    history::{CursorSigner, EventRecord},
};

const CURSOR_TTL: i64 = 86_400;
// Only future issuance accepts skew; expiration remains strict.
const CURSOR_FUTURE_ISSUE_SKEW_SECONDS: i64 = 60;
const BATCH_SIZE: usize = 64;
const MAX_BUFFER_BYTES: usize = 256 * 1024;
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const STREAM_LIFETIME: Duration = Duration::from_secs(300);

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Replay {
    #[default]
    Latest,
    All,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventStreamQuery {
    pub project_id: Uuid,
    pub instance_id: Option<Uuid>,
    #[serde(default)]
    pub replay: Replay,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    kind: String,
    tenant_id: Uuid,
    principal_id: Uuid,
    project_id: Uuid,
    instance_id: Option<Uuid>,
    epoch: Uuid,
    cluster_epoch: Uuid,
    sequence: i64,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// A position is scoped to one project and epoch. The public read methods still
/// reauthorize the actor on every call; it is not an authorization capability.
#[derive(Clone, Debug)]
pub struct StreamPosition {
    epoch: Uuid,
    cluster_epoch: Uuid,
    sequence: i64,
}
impl StreamPosition {
    pub fn sequence(&self) -> i64 {
        self.sequence
    }

    pub fn cursor(
        &self,
        actor: &Actor,
        query: &EventStreamQuery,
        signer: &CursorSigner,
        now: DateTime<Utc>,
    ) -> Result<String, ApiError> {
        signer.encode_payload(&Cursor {
            version: 1,
            kind: "project_event_stream".into(),
            tenant_id: actor.tenant_id,
            principal_id: actor.principal_id,
            project_id: query.project_id,
            instance_id: query.instance_id,
            epoch: self.epoch,
            cluster_epoch: self.cluster_epoch,
            sequence: self.sequence,
            issued_at: now,
            expires_at: now + chrono::Duration::seconds(CURSOR_TTL),
        })
    }
}

#[derive(Debug)]
pub struct StreamEntry {
    pub position: StreamPosition,
    pub event: Option<EventRecord>,
}

#[derive(sqlx::FromRow)]
struct Head {
    epoch: Uuid,
    cluster_epoch: Uuid,
    last_sequence: i64,
}

impl Database {
    pub async fn open_event_stream(
        &self,
        actor: &Actor,
        query: &EventStreamQuery,
        encoded: Option<&str>,
        signer: &CursorSigner,
    ) -> Result<StreamPosition, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        authorize(&mut tx, actor, query).await?;
        let head = head(&mut tx, actor, query).await?;
        let position = if let Some(encoded) = encoded {
            let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(&mut *tx)
                .await?;
            let cursor: Cursor = signer.decode_payload(encoded)?;
            validate_cursor(&cursor, actor, query, now)?;
            StreamPosition {
                epoch: cursor.epoch,
                cluster_epoch: cursor.cluster_epoch,
                sequence: cursor.sequence,
            }
        } else {
            StreamPosition {
                epoch: head.epoch,
                cluster_epoch: head.cluster_epoch,
                sequence: match query.replay {
                    Replay::Latest => head.last_sequence,
                    Replay::All => 0,
                },
            }
        };
        validate_position(&position, &head)?;
        tx.commit().await?;
        Ok(position)
    }

    /// Scan at most 64 committed positions, including nonmatching instance
    /// events. This bounds a filtered subscription's work even in a busy project.
    pub async fn read_event_batch(
        &self,
        actor: &Actor,
        query: &EventStreamQuery,
        position: &StreamPosition,
    ) -> Result<VecDeque<StreamEntry>, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        authorize(&mut tx, actor, query).await?;
        let head = head(&mut tx, actor, query).await?;
        validate_position(position, &head)?;
        #[derive(sqlx::FromRow)]
        struct Row {
            sequence: i64,
            matches: bool,
            #[sqlx(flatten)]
            event: EventRecord,
        }
        let rows = sqlx::query_as::<_, Row>(
            "SELECT p.sequence,($3::uuid IS NULL OR e.aggregate_id=$3 OR EXISTS(SELECT 1 FROM operations o WHERE o.tenant_id=e.tenant_id AND o.id=e.operation_id AND o.instance_id=$3)) AS matches,e.id,e.tenant_id,e.project_id,e.aggregate_id,e.aggregate_version,e.event_type,e.schema_version,e.operation_id,e.request_id,e.occurred_at FROM event_stream_positions p JOIN domain_events e ON e.id=p.event_id AND e.tenant_id=p.tenant_id AND e.project_id=p.project_id WHERE p.tenant_id=$1 AND p.project_id=$2 AND p.sequence>$4 AND p.sequence<=$5 ORDER BY p.sequence LIMIT 64",
        )
        .bind(actor.tenant_id)
        .bind(query.project_id)
        .bind(query.instance_id)
        .bind(position.sequence)
        .bind(head.last_sequence)
        .fetch_all(&mut *tx)
        .await?;
        let expected = (head.last_sequence - position.sequence).min(BATCH_SIZE as i64) as usize;
        if rows.len() != expected {
            return Err(history_unavailable());
        }
        let mut entries = VecDeque::new();
        for (offset, row) in rows.into_iter().enumerate() {
            if row.sequence != position.sequence + offset as i64 + 1 {
                return Err(history_unavailable());
            }
            entries.push_back(StreamEntry {
                position: StreamPosition {
                    epoch: head.epoch,
                    cluster_epoch: head.cluster_epoch,
                    sequence: row.sequence,
                },
                event: row.matches.then_some(row.event),
            });
        }
        tx.commit().await?;
        Ok(entries)
    }

    async fn authorize_event_stream(
        &self,
        actor: &Actor,
        query: &EventStreamQuery,
        position: &StreamPosition,
    ) -> Result<(), ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        authorize(&mut tx, actor, query).await?;
        validate_position(position, &head(&mut tx, actor, query).await?)?;
        tx.commit().await?;
        Ok(())
    }
}

async fn authorize(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    query: &EventStreamQuery,
) -> Result<(), ApiError> {
    Database::authorize_resource(tx, actor, query.project_id, "events:read").await?;
    if let Some(id) = query.instance_id {
        let instance = load_instance(tx, actor.tenant_id, id, false).await?;
        if instance.project_id != query.project_id {
            return Err(ApiError::not_found());
        }
    }
    Ok(())
}

async fn head(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    query: &EventStreamQuery,
) -> Result<Head, ApiError> {
    sqlx::query_as("SELECT h.epoch,h.last_sequence,c.cluster_epoch FROM event_stream_heads h CROSS JOIN platform_configuration c WHERE h.tenant_id=$1 AND h.project_id=$2 AND c.singleton")
        .bind(actor.tenant_id)
        .bind(query.project_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(history_unavailable)
}

fn validate_cursor(
    cursor: &Cursor,
    actor: &Actor,
    query: &EventStreamQuery,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    if cursor.version != 1
        || cursor.kind != "project_event_stream"
        || cursor.tenant_id != actor.tenant_id
        || cursor.principal_id != actor.principal_id
        || cursor.project_id != query.project_id
        || cursor.instance_id != query.instance_id
        || cursor.sequence < 0
        || cursor.issued_at > now + chrono::Duration::seconds(CURSOR_FUTURE_ISSUE_SKEW_SECONDS)
        || cursor.expires_at <= cursor.issued_at
        || cursor.expires_at > cursor.issued_at + chrono::Duration::seconds(CURSOR_TTL)
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "INVALID_CURSOR",
            "Cursor is invalid or does not match this event stream",
        ));
    }
    if cursor.expires_at <= now {
        return Err(ApiError::new(
            StatusCode::GONE,
            "EVENT_CURSOR_EXPIRED",
            "Event cursor expired; explicitly refresh state or replay retained events",
        ));
    }
    Ok(())
}

fn validate_position(position: &StreamPosition, head: &Head) -> Result<(), ApiError> {
    if position.epoch != head.epoch || position.cluster_epoch != head.cluster_epoch {
        return Err(history_unavailable());
    }
    if position.sequence > head.last_sequence {
        return Err(ApiError::conflict(
            "EVENT_CURSOR_AHEAD",
            "Cursor is ahead of committed history; explicit reconciliation is required",
        ));
    }
    Ok(())
}

fn history_unavailable() -> ApiError {
    ApiError::new(
        StatusCode::GONE,
        "EVENT_HISTORY_UNAVAILABLE",
        "Retained history cannot satisfy this cursor; explicitly reconcile current state",
    )
}

#[derive(Default)]
struct Counts {
    total: usize,
    tenants: HashMap<Uuid, usize>,
    principals: HashMap<(Uuid, Uuid), usize>,
}

#[derive(Clone)]
pub(crate) struct StreamRuntime {
    counts: Arc<Mutex<Counts>>,
    shutdown: CancellationToken,
}
impl StreamRuntime {
    pub(crate) fn new(shutdown: CancellationToken) -> Self {
        Self {
            counts: Arc::new(Mutex::new(Counts::default())),
            shutdown,
        }
    }

    pub(crate) fn acquire(&self, actor: &Actor) -> Result<Connection, ApiError> {
        let mut counts = self.counts.lock().map_err(|_| overloaded())?;
        let key = (actor.tenant_id, actor.principal_id);
        if counts.total >= 64
            || counts.tenants.get(&actor.tenant_id).copied().unwrap_or(0) >= 16
            || counts.principals.get(&key).copied().unwrap_or(0) >= 4
        {
            return Err(overloaded());
        }
        counts.total += 1;
        *counts.tenants.entry(actor.tenant_id).or_default() += 1;
        *counts.principals.entry(key).or_default() += 1;
        Ok(Connection {
            runtime: self.clone(),
            key,
        })
    }

    pub(crate) fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }
}

pub(crate) struct Connection {
    runtime: StreamRuntime,
    key: (Uuid, Uuid),
}
impl Drop for Connection {
    fn drop(&mut self) {
        // Cleanup after unwinding is still safe: this map only contains counts.
        let mut counts = self
            .runtime
            .counts
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        counts.total -= 1;
        if let Some(count) = counts.tenants.get_mut(&self.key.0) {
            *count -= 1;
            if *count == 0 {
                counts.tenants.remove(&self.key.0);
            }
        }
        if let Some(count) = counts.principals.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                counts.principals.remove(&self.key);
            }
        }
    }
}

fn overloaded() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "EVENT_STREAM_LIMIT",
        "Event stream connection limit reached on this replica",
    )
}

struct Stream {
    state: Arc<AppState>,
    headers: HeaderMap,
    actor: Actor,
    query: EventStreamQuery,
    position: StreamPosition,
    pending: VecDeque<StreamEntry>,
    connection: Connection,
    deadline: Instant,
    last_frame: Instant,
    checkpoint: bool,
    closed: bool,
}

pub(crate) async fn stream_events(
    State(state): State<Arc<AppState>>,
    Extension(runtime): Extension<StreamRuntime>,
    headers: HeaderMap,
    query: Result<Query<EventStreamQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::invalid("Invalid event stream query"))?;
    let last_id = last_event_id(&headers)?;
    let (actor, identity) = authenticate(&state, &headers).await?;
    let connection = runtime.acquire(&actor)?;
    let position = state
        .database
        .open_event_stream(&actor, &query, last_id, &state.cursor_signer)
        .await?;
    let remaining = DateTime::from_timestamp(identity.expires_at, 0)
        .and_then(|expires| (expires - Utc::now()).to_std().ok())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(crate::request::unauthenticated)?;
    let now = Instant::now();
    let stream = Stream {
        state,
        headers,
        actor,
        query,
        position,
        pending: VecDeque::new(),
        connection,
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
        let next = REQUEST_ID.scope(request_id, stream.next()).await;
        match next {
            Ok(Some(event)) => Some((Ok::<_, Infallible>(event), stream)),
            Ok(None) => None,
            Err(error) => {
                stream.closed = true;
                stream.pending.clear();
                // No raw database/provider errors, query values, or event payloads.
                let data = serde_json::json!({"code":error.code,"retryable":error.retryable,"request_id":request_id});
                let event = Event::default()
                    .event("stream.error")
                    .data(data.to_string());
                Some((Ok(event), stream))
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

pub(crate) fn last_event_id(headers: &HeaderMap) -> Result<Option<&str>, ApiError> {
    let mut values = headers.get_all("last-event-id").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ApiError::invalid("Last-Event-ID must occur exactly once"));
    }
    let value = value
        .to_str()
        .map_err(|_| ApiError::invalid("Invalid Last-Event-ID"))?;
    if value.is_empty() || value.len() > 2048 {
        return Err(ApiError::invalid("Invalid Last-Event-ID"));
    }
    Ok(Some(value))
}

impl Stream {
    async fn next(&mut self) -> Result<Option<Event>, ApiError> {
        loop {
            if self.connection.runtime.shutdown.is_cancelled() || Instant::now() >= self.deadline {
                return Ok(None);
            }
            // The HTTP middleware finishes at response headers. Each body frame
            // therefore performs its own bounded, current authentication check.
            let validation = tokio::time::timeout(Duration::from_secs(10), async {
                let (actor, identity) = authenticate(&self.state, &self.headers).await?;
                if actor.principal_id != self.actor.principal_id
                    || actor.tenant_id != self.actor.tenant_id
                    || identity.expires_at <= Utc::now().timestamp()
                {
                    return Err(crate::request::unauthenticated());
                }
                self.state
                    .database
                    .authorize_event_stream(&actor, &self.query, &self.position)
                    .await
            });
            tokio::select! {
                _ = self.connection.runtime.shutdown.cancelled() => return Ok(None),
                _ = tokio::time::sleep_until(self.deadline) => return Ok(None),
                result = validation => result.map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE,"DEPENDENCY_UNAVAILABLE","Stream authorization deadline exceeded"))??,
            }
            if self.checkpoint {
                self.checkpoint = false;
                self.last_frame = Instant::now();
                return self.frame(None).map(Some);
            }
            if let Some(entry) = self.pending.pop_front() {
                self.position = entry.position;
                self.last_frame = Instant::now();
                return self.frame(entry.event.as_ref()).map(Some);
            }
            let batch = tokio::time::timeout(
                Duration::from_secs(10),
                self.state
                    .database
                    .read_event_batch(&self.actor, &self.query, &self.position),
            );
            self.pending = tokio::select! {
                _ = self.connection.runtime.shutdown.cancelled() => return Ok(None),
                _ = tokio::time::sleep_until(self.deadline) => return Ok(None),
                result = batch => result.map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE,"DEPENDENCY_UNAVAILABLE","Stream read deadline exceeded"))??,
            };
            // Envelope strings are bounded in the database. Check the aggregate
            // serialized size as well; never queue command/output/private payloads.
            let mut size = 0usize;
            let mut keep = 0usize;
            for entry in &self.pending {
                let bytes = serde_json::to_vec(&entry.event)
                    .map_err(|_| ApiError::invalid("Cannot encode event envelope"))?;
                let next = size.saturating_add(bytes.len() + 2048);
                if next > MAX_BUFFER_BYTES {
                    break;
                }
                size = next;
                keep += 1;
            }
            if keep == 0 && !self.pending.is_empty() {
                return Err(ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "EVENT_BUFFER_LIMIT",
                    "Reconnect using the last received event ID",
                ));
            }
            // Entries beyond the budget are not acknowledged. The next query
            // begins at the last frame actually yielded, so they remain readable.
            self.pending.truncate(keep);
            if !self.pending.is_empty() {
                continue;
            }
            if self.last_frame.elapsed() >= HEARTBEAT_INTERVAL {
                self.last_frame = Instant::now();
                return Ok(Some(Event::default().comment("heartbeat")));
            }
            tokio::select! {
                _ = self.connection.runtime.shutdown.cancelled() => return Ok(None),
                _ = tokio::time::sleep_until(self.deadline) => return Ok(None),
                _ = tokio::time::sleep(POLL_INTERVAL) => {},
            }
        }
    }

    fn frame(&self, event: Option<&EventRecord>) -> Result<Event, ApiError> {
        let cursor = self.position.cursor(
            &self.actor,
            &self.query,
            &self.state.cursor_signer,
            Utc::now(),
        )?;
        // sequence is a decimal string: JavaScript numbers lose integer precision.
        let data = if let Some(event) = event {
            serde_json::json!({"sequence":self.position.sequence.to_string(),"event":event})
        } else {
            serde_json::json!({"sequence":self.position.sequence.to_string()})
        };
        Ok(Event::default()
            .id(cursor)
            .event(if event.is_some() {
                "domain.event"
            } else {
                "stream.checkpoint"
            })
            .data(data.to_string()))
    }
}

#[cfg(test)]
#[path = "event_stream_tests.rs"]
mod tests;
