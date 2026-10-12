//! Bounded data endpoints. The public API never accepts cloud keys and never
//! repeats an uncertain PUT or a guest dispatch.
use crate::{
    api::{AppState, authenticate},
    error::ApiError,
    event_stream::{Connection, StreamRuntime},
    file_store::{FILE_PART_BYTES, OssFileReader, OssFileWriter},
    file_transfer::{CreateFileTransfer, FileTransferMutationResult, ledger::FileContentSnapshot},
    request,
};
use axum::{
    Extension, Json, Router,
    body::{Body, Bytes},
    extract::{
        DefaultBodyLimit, FromRequestParts, Path, State,
        rejection::{BytesRejection, JsonRejection, PathRejection},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use futures_util::{FutureExt, TryStreamExt};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::{Arc, LazyLock};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

static DATA_CHANNELS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(32)));
pub struct FileApiRuntime {
    pub app: Arc<AppState>,
    pub writer: OssFileWriter,
    pub reader: OssFileReader,
    pub max_file_bytes: u64,
}

#[cfg(test)]
mod request_body_tests {
    // Assertions intentionally unwrap the local, in-memory HTTP fixture.
    #![allow(clippy::expect_used)]
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    #[tokio::test]
    async fn saturated_upload_rejects_before_polling_body_and_releases_slot_after_response() {
        let held: Vec<_> = (0..32)
            .map(|_| channel().expect("free file channel"))
            .collect();
        let reads = Arc::new(AtomicUsize::new(0));
        let observed = reads.clone();
        let stream = futures_util::stream::once(async move {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok::<_, std::io::Error>(Bytes::from(vec![0u8; FILE_PART_BYTES]))
        });
        let app = Router::new().route(
            "/upload",
            put(|_permit: FileDataChannel, _body: Bytes| async { StatusCode::NO_CONTENT })
                .layer(DefaultBodyLimit::max(FILE_PART_BYTES)),
        );
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri("/upload")
                    .body(Body::from_stream(stream))
                    .expect("upload request"),
            )
            .await
            .expect("local HTTP service");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        drop(held);
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri("/upload")
                    .body(Body::from(vec![0u8; FILE_PART_BYTES]))
                    .expect("upload request"),
            )
            .await
            .expect("local HTTP service");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(DATA_CHANNELS.available_permits(), 32);
    }
}
impl FileApiRuntime {
    pub async fn check_schema(&self) -> anyhow::Result<()> {
        let available: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=36 AND success) AND current_user='sandbox_app' AND COALESCE(has_table_privilege(current_user,to_regclass('public.file_transfers'),'SELECT,INSERT,UPDATE'),false) AND COALESCE(has_table_privilege(current_user,to_regclass('public.file_transfer_parts'),'SELECT,INSERT,UPDATE'),false)")
            .fetch_one(&self.app.database.pool).await?;
        anyhow::ensure!(
            available,
            "file endpoints require the current schema and dedicated API table grants"
        );
        self.writer.check_credentials().await?;
        self.reader.check_credentials().await?;
        Ok(())
    }
    pub fn routes(self: Arc<Self>) -> Router {
        Router::new()
            .route("/v1/instances/{id}/file-transfers", post(create))
            .route("/v1/file-transfers/{id}", get(read))
            .route(
                "/v1/file-transfers/{id}/content/{index}",
                put(upload_part).layer(DefaultBodyLimit::max(FILE_PART_BYTES)),
            )
            .route("/v1/file-transfers/{id}/content/commit", post(commit))
            .route("/v1/file-transfers/{id}/content", get(download))
            .with_state(self)
    }
}
fn channel() -> Result<OwnedSemaphorePermit, ApiError> {
    DATA_CHANNELS.clone().try_acquire_owned().map_err(|_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "FILE_CHANNEL_OVERLOADED",
            "This replica's file data channels are full",
        )
    })
}
// Acquire before Axum collects the upload body. A saturated replica must not
// buffer another MiB per connection while waiting to enter the handler.
struct FileDataChannel {
    _permit: OwnedSemaphorePermit,
}
impl<S: Send + Sync> FromRequestParts<S> for FileDataChannel {
    type Rejection = ApiError;
    async fn from_request_parts(
        _: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self {
            _permit: channel()?,
        })
    }
}
fn unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "FILE_STORAGE_UNAVAILABLE",
        "Temporary file storage is unavailable; inspect transfer status before retrying",
    )
}
fn changed() -> ApiError {
    ApiError::conflict(
        "FILE_CONTENT_CHANGED",
        "File content is no longer available at this version",
    )
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
fn accepted(result: FileTransferMutationResult) -> Result<Response, ApiError> {
    let status = StatusCode::from_u16(result.status).map_err(|_| unavailable())?;
    Ok((
        status,
        [
            (
                "location",
                format!("/v1/operations/{}", result.body.operation.id),
            ),
            (
                "content-location",
                format!("/v1/file-transfers/{}", result.body.resource.id),
            ),
            ("etag", format!("\"{}\"", result.body.resource.version)),
            (
                "x-instance-etag",
                format!("\"{}\"", result.body.instance_version),
            ),
            ("retry-after", "2".into()),
        ],
        Json(result.body),
    )
        .into_response())
}
async fn create(
    State(runtime): State<Arc<FileApiRuntime>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    payload: Result<Json<CreateFileTransfer>, JsonRejection>,
) -> Result<Response, ApiError> {
    let instance = id(path)?;
    let input = json(payload)?;
    let (actor, _) = authenticate(&runtime.app, &headers).await?;
    accepted(
        runtime
            .app
            .database
            .create_file_transfer(
                &actor,
                instance,
                &input,
                request::idempotency_key(&headers)?,
                request::expected_version(&headers)?,
                runtime.max_file_bytes,
            )
            .await?,
    )
}
async fn read(
    State(runtime): State<Arc<FileApiRuntime>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
) -> Result<Response, ApiError> {
    let (actor, _) = authenticate(&runtime.app, &headers).await?;
    let transfer = runtime
        .app
        .database
        .get_file_transfer(&actor, id(path)?)
        .await?;
    Ok((
        [("etag", format!("\"{}\"", transfer.version))],
        Json(transfer),
    )
        .into_response())
}
#[derive(Serialize)]
struct PartAcknowledgement {
    index: u32,
    byte_length: u64,
    sha256: String,
    transfer_version: i64,
}
async fn upload_part(
    State(runtime): State<Arc<FileApiRuntime>>,
    headers: HeaderMap,
    path: Result<Path<(Uuid, u32)>, PathRejection>,
    _channel: FileDataChannel,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, ApiError> {
    let Path((transfer, index)) =
        path.map_err(|_| ApiError::invalid("Transfer id and part index are invalid"))?;
    if request::single_header(&headers, "content-type")? != "application/octet-stream" {
        return Err(ApiError::invalid(
            "File parts require application/octet-stream",
        ));
    }
    let bytes = body.map_err(|e| {
        ApiError::new(
            e.status(),
            "INVALID_FILE_PART_BODY",
            "File part exceeds its byte limit or is incomplete",
        )
    })?;
    let length: u64 = request::single_header(&headers, "content-length")?
        .parse()
        .map_err(|_| ApiError::invalid("Content-Length must be a byte count"))?;
    if length != bytes.len() as u64 || bytes.is_empty() || bytes.len() > FILE_PART_BYTES {
        return Err(ApiError::invalid("File part length is invalid"));
    }
    let sha = request::single_header(&headers, "x-content-sha256")?;
    if hex::encode(Sha256::digest(&bytes)) != sha {
        return Err(ApiError::invalid(
            "File part checksum does not match its body",
        ));
    }
    let (actor, _) = authenticate(&runtime.app, &headers).await?;
    let intent = runtime
        .app
        .database
        .begin_file_part_upload(
            &actor,
            transfer,
            index,
            length,
            sha,
            request::expected_version(&headers)?,
        )
        .await?;
    if !intent.already_stored {
        // Durable reservation precedes the only PUT attempt. Uncertain failures
        // stay charged and do not authorize another PUT at this part identity.
        let receipt = match runtime
            .writer
            .put_part(intent.receipt.identity, bytes.to_vec())
            .await
        {
            Ok(receipt) => receipt,
            Err(_) => {
                let _ = runtime
                    .app
                    .database
                    .mark_file_part_put_unknown(&intent)
                    .await;
                return Err(unavailable());
            }
        };
        let (current, _) = authenticate(&runtime.app, &headers).await?;
        if current.principal_id != actor.principal_id {
            return Err(request::unauthenticated());
        }
        runtime
            .app
            .database
            .publish_file_part(&current, &intent, &receipt)
            .await?;
    }
    Ok((
        [("etag", format!("\"{}\"", intent.transfer_version))],
        Json(PartAcknowledgement {
            index,
            byte_length: length,
            sha256: sha.into(),
            transfer_version: intent.transfer_version,
        }),
    )
        .into_response())
}
async fn commit(
    State(runtime): State<Arc<FileApiRuntime>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
    payload: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Response, ApiError> {
    let _permit = channel()?;
    if json(payload)? != serde_json::json!({}) {
        return Err(ApiError::invalid(
            "Content commit body must be an empty object",
        ));
    }
    let (actor, identity) = authenticate(&runtime.app, &headers).await?;
    accepted(
        runtime
            .app
            .database
            .commit_file_upload(
                &actor,
                id(path)?,
                request::expected_version(&headers)?,
                request::idempotency_key(&headers)?,
                &runtime.reader,
                &identity,
            )
            .await?,
    )
}

struct Download {
    runtime: Arc<FileApiRuntime>,
    headers: HeaderMap,
    snapshot: FileContentSnapshot,
    index: usize,
    hash: Sha256,
    bytes: u64,
    done: bool,
    deadline: tokio::time::Instant,
    shutdown: tokio_util::sync::CancellationToken,
    request_id: Uuid,
    principal_id: Uuid,
    _connection: Connection,
    _permit: OwnedSemaphorePermit,
}
async fn download(
    Extension(stream_runtime): Extension<StreamRuntime>,
    State(runtime): State<Arc<FileApiRuntime>>,
    headers: HeaderMap,
    path: Result<Path<Uuid>, PathRejection>,
) -> Result<Response, ApiError> {
    let permit = channel()?;
    let (actor, identity) = authenticate(&runtime.app, &headers).await?;
    let connection = stream_runtime.acquire(&actor)?;
    let remaining = identity
        .expires_at
        .saturating_sub(chrono::Utc::now().timestamp());
    if remaining <= 0 {
        return Err(request::unauthenticated());
    }
    let snapshot = runtime
        .app
        .database
        .file_content_snapshot(&actor, id(path)?)
        .await?;
    let length = snapshot.resource.observed_bytes.ok_or_else(changed)?;
    let checksum = snapshot
        .resource
        .observed_sha256
        .clone()
        .ok_or_else(changed)?;
    let version = snapshot.resource.version;
    let stream = futures_util::stream::try_unfold(
        Download {
            runtime,
            headers,
            snapshot,
            index: 0,
            hash: Sha256::new(),
            bytes: 0,
            done: false,
            deadline: tokio::time::Instant::now()
                + std::time::Duration::from_secs((remaining as u64).min(300)),
            shutdown: stream_runtime.shutdown_token(),
            request_id: actor.request_id,
            principal_id: actor.principal_id,
            _connection: connection,
            _permit: permit,
        },
        |mut download| {
            let deadline = download.deadline;
            let shutdown = download.shutdown.clone();
            let request_id = download.request_id;
            async move {
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => Err(unavailable()),
                    _ = tokio::time::sleep_until(deadline) => Err(request::unauthenticated()),
                    result = crate::error::REQUEST_ID.scope(request_id, async move {
                if download.done {
                    return Ok(None);
                }
                if download.index == download.snapshot.parts.len() {
                    download.done = true;
                    if download.snapshot.resource.observed_bytes != Some(download.bytes)
                        || download.snapshot.resource.observed_sha256.as_deref()
                            != Some(hex::encode(download.hash.clone().finalize()).as_str())
                    {
                        return Err(changed());
                    }
                    return Ok(None);
                }
                let (actor, _) = authenticate(&download.runtime.app, &download.headers).await?;
                if actor.principal_id != download.principal_id {
                    return Err(request::unauthenticated());
                }
                let current = download
                    .runtime
                    .app
                    .database
                    .file_content_snapshot(&actor, download.snapshot.resource.id)
                    .await?;
                if current.content_id != download.snapshot.content_id
                    || current.resource.version != download.snapshot.resource.version
                    || current.parts != download.snapshot.parts
                {
                    return Err(changed());
                }
                let part = &download.snapshot.parts[download.index];
                let bytes = download
                    .runtime
                    .reader
                    .read_part(part)
                    .await
                    .map_err(|_| unavailable())?;
                let (actor, _) = authenticate(&download.runtime.app, &download.headers).await?;
                if actor.principal_id != download.principal_id {
                    return Err(request::unauthenticated());
                }
                let current = download
                    .runtime
                    .app
                    .database
                    .file_content_snapshot(&actor, download.snapshot.resource.id)
                    .await?;
                if current.content_id != download.snapshot.content_id
                    || current.resource.version != download.snapshot.resource.version
                    || current.parts != download.snapshot.parts
                {
                    return Err(changed());
                }
                download.bytes += bytes.len() as u64;
                download.hash.update(&bytes);
                download.index += 1;
                if download.index == download.snapshot.parts.len()
                    && (download.snapshot.resource.observed_bytes != Some(download.bytes)
                        || download.snapshot.resource.observed_sha256.as_deref() != Some(hex::encode(download.hash.clone().finalize()).as_str())) {
                    return Err(changed());
                }
                Ok(Some((Bytes::from(bytes), download)))
                    }) => result,
                }
            }
            .boxed()
        },
    );
    Ok((
        [
            ("content-type", "application/octet-stream".into()),
            ("content-length", length.to_string()),
            ("x-content-sha256", checksum),
            ("etag", format!("\"{version}\"")),
        ],
        Body::from_stream(
            stream.map_err(|_: ApiError| std::io::Error::other("file data stream terminated")),
        ),
    )
        .into_response())
}
