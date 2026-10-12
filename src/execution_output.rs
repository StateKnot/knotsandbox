//! Tenant-authorized, bounded output pages derived only from committed receipts.
//! A verified manifest indexes objects; it does not attest unread object bytes.
use crate::{
    db::{Actor, Database},
    error::ApiError,
    gateway_ledger::StoredOutputSegment,
    model::ExecutionResultRef,
    output_store::{OssOutputReader, OutputStoreError},
    runner::OutputStream,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct ExecutionOutputPage {
    pub execution_id: Uuid,
    pub snapshot_at: DateTime<Utc>,
    pub output_status: String,
    pub manifest_verified: bool,
    pub has_more: bool,
    pub final_segment_sequence: Option<i64>,
    pub segments: Vec<ExecutionOutputSegment>,
    pub next_after_segment: Option<i64>,
}
#[derive(Debug, Serialize)]
pub struct ExecutionOutputSegment {
    pub sequence: i64,
    pub frames: Vec<ExecutionOutputFrame>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionOutputFrame {
    pub sequence: u64,
    pub stream: OutputStream,
    pub offset: u64,
    pub data: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u8,
    tenant_id: Uuid,
    execution_id: Uuid,
    dispatch_attempt_id: Uuid,
    output_status: String,
    segments: Vec<ManifestSegment>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestSegment {
    sequence: i64,
    first_frame_sequence: i64,
    last_frame_sequence: i64,
    raw_bytes: i64,
    object_bytes: i64,
    sha256: String,
}

impl Database {
    pub async fn execution_output(
        &self,
        actor: &Actor,
        id: Uuid,
        after_segment: i64,
        limit: i64,
        reader: &OssOutputReader,
    ) -> Result<ExecutionOutputPage, ApiError> {
        if !(-1..=4095).contains(&after_segment) || !(1..=2).contains(&limit) {
            return Err(ApiError::invalid(
                "after_segment must be -1..=4095 and limit 1..=2",
            ));
        }
        // Pagination and SSE share one per-process I/O budget. A long-lived
        // stream must not bypass the output endpoint's concurrency ceiling.
        static OUTPUT_READS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(16);
        let _permit = OUTPUT_READS.try_acquire().map_err(|_| {
            ApiError::new(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "OUTPUT_READ_OVERLOADED",
                "This replica is at its output read concurrency limit",
            )
        })?;
        let mut tx = self.pool.begin().await?;
        // Single-snapshot consistency matters: a completion commit must not be
        // combined with an older segment set when verifying the manifest index.
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(actor.tenant_id.to_string())
            .execute(&mut *tx)
            .await?;
        let row=sqlx::query("SELECT project_id,dispatch_attempt_id,output_status,output_manifest,clock_timestamp() AS snapshot_at FROM executions WHERE tenant_id=$1 AND id=$2")
            .bind(actor.tenant_id).bind(id).fetch_optional(&mut *tx).await?.ok_or_else(ApiError::not_found)?;
        let project: Uuid = row.try_get("project_id")?;
        Self::authorize_resource(&mut tx, actor, project, "executions:output:read").await?;
        let status: String = row.try_get("output_status")?;
        let snapshot_at: DateTime<Utc> = row.try_get("snapshot_at")?;
        let attempt: Option<Uuid> = row.try_get("dispatch_attempt_id")?;
        let reference: Option<serde_json::Value> = row.try_get("output_manifest")?;
        let records=sqlx::query("SELECT execution_id,dispatch_attempt_id,sequence,first_frame_sequence,last_frame_sequence,raw_bytes,object_bytes,sha256,object_key FROM execution_output_segments WHERE tenant_id=$1 AND execution_id=$2 ORDER BY sequence LIMIT 4097")
            .bind(actor.tenant_id).bind(id).fetch_all(&mut *tx).await?;
        let mut receipts = Vec::with_capacity(records.len());
        for row in records {
            receipts.push(StoredOutputSegment {
                execution_id: row.try_get("execution_id")?,
                dispatch_attempt_id: row.try_get("dispatch_attempt_id")?,
                sequence: row.try_get("sequence")?,
                first_frame_sequence: row.try_get("first_frame_sequence")?,
                last_frame_sequence: row.try_get("last_frame_sequence")?,
                raw_bytes: row.try_get("raw_bytes")?,
                object_bytes: row.try_get("object_bytes")?,
                sha256: row.try_get("sha256")?,
                object_key: row.try_get("object_key")?,
            });
        }
        tx.commit().await?;
        validate_index(actor.tenant_id, id, attempt, &receipts)?;
        let page: Vec<_> = receipts
            .iter()
            .filter(|r| r.sequence > after_segment)
            .take(limit as usize)
            .collect();
        let manifest_check = async {
            match reference {
                Some(reference) => {
                    let reference: ExecutionResultRef =
                        serde_json::from_value(reference).map_err(|_| integrity())?;
                    let attempt = attempt.ok_or_else(integrity)?;
                    let expected = format!(
                        "tenants/{}/executions/{id}/attempts/{attempt}/manifest-{}.json",
                        actor.tenant_id, reference.sha256
                    );
                    if reference.object_key != expected {
                        return Err(integrity());
                    }
                    let bytes = reader
                        .read_verified(
                            &reference.object_key,
                            &reference.sha256,
                            reference.size_bytes,
                            1024 * 1024,
                        )
                        .await
                        .map_err(storage_error)?;
                    let manifest: Manifest =
                        serde_json::from_slice(&bytes).map_err(|_| integrity())?;
                    if manifest.schema_version != 1
                        || manifest.tenant_id != actor.tenant_id
                        || manifest.execution_id != id
                        || manifest.dispatch_attempt_id != attempt
                        || manifest.output_status != status
                        || !matches!(status.as_str(), "COMPLETE" | "TRUNCATED")
                        || manifest.segments.len() != receipts.len()
                        || manifest.segments.iter().zip(&receipts).any(|(a, b)| {
                            a.sequence != b.sequence
                                || a.first_frame_sequence != b.first_frame_sequence
                                || a.last_frame_sequence != b.last_frame_sequence
                                || a.raw_bytes != b.raw_bytes
                                || a.object_bytes != b.object_bytes
                                || a.sha256 != b.sha256
                        })
                    {
                        return Err(integrity());
                    }
                    Ok(true)
                }
                None if matches!(status.as_str(), "COMPLETE" | "TRUNCATED") => Err(integrity()),
                None => Ok(false),
            }
        };
        // At most three concurrent bounded reads (manifest and two segments).
        // These futures are owned by the request; timeout/drop spawns no I/O task.
        let page_check = futures_util::future::try_join_all(page.iter().map(|receipt| async {
            let bytes = reader
                .read_verified(
                    &receipt.object_key,
                    &receipt.sha256,
                    receipt.object_bytes as u64,
                    524288,
                )
                .await
                .map_err(storage_error)?;
            Ok::<_, ApiError>(ExecutionOutputSegment {
                sequence: receipt.sequence,
                frames: decode_segment(&bytes, receipt)?,
            })
        }));
        let (manifest_verified, segments) = tokio::try_join!(manifest_check, page_check)?;
        let mut offsets = [None; 2];
        for segment in &segments {
            for frame in &segment.frames {
                let stream = match frame.stream {
                    OutputStream::Stdout => 0,
                    OutputStream::Stderr => 1,
                };
                if offsets[stream].is_some_and(|end| frame.offset != end) {
                    return Err(integrity());
                }
                let decoded = STANDARD.decode(&frame.data).map_err(|_| integrity())?;
                offsets[stream] = Some(frame.offset + decoded.len() as u64);
            }
        }
        // A fresh shared authorization context rechecks the original issuer/sub,
        // client binding, principal, expiry, action scope and current local grant
        // after storage I/O, before returning any output frames.
        let mut tx = self.begin(actor.tenant_id).await?;
        Self::authorize_resource(&mut tx, actor, project, "executions:output:read").await?;
        tx.commit().await?;
        let next_after_segment = segments.last().map(|segment| segment.sequence);
        let last = next_after_segment.unwrap_or(after_segment);
        Ok(ExecutionOutputPage {
            execution_id: id,
            snapshot_at,
            output_status: status,
            manifest_verified,
            has_more: receipts.iter().any(|r| r.sequence > last),
            final_segment_sequence: if manifest_verified {
                Some(receipts.last().map_or(-1, |r| r.sequence))
            } else {
                None
            },
            segments,
            next_after_segment,
        })
    }
}

fn validate_index(
    tenant: Uuid,
    id: Uuid,
    attempt: Option<Uuid>,
    receipts: &[StoredOutputSegment],
) -> Result<(), ApiError> {
    if receipts.len() > 4096 {
        return Err(integrity());
    }
    let mut last = None;
    let mut raw = 0_i64;
    let mut stored = 0_i64;
    for (n, r) in receipts.iter().enumerate() {
        if r.validate(tenant).is_err()
            || r.execution_id != id
            || Some(r.dispatch_attempt_id) != attempt
            || r.sequence != n as i64
            || last.is_some_and(|last| r.first_frame_sequence <= last)
        {
            return Err(integrity());
        }
        last = Some(r.last_frame_sequence);
        raw += r.raw_bytes;
        stored += r.object_bytes;
    }
    if raw > 16 * 1024 * 1024 || stored > 32 * 1024 * 1024 {
        return Err(integrity());
    }
    Ok(())
}
fn decode_segment(
    bytes: &[u8],
    receipt: &StoredOutputSegment,
) -> Result<Vec<ExecutionOutputFrame>, ApiError> {
    if !bytes.ends_with(b"\n") {
        return Err(integrity());
    }
    let mut frames = Vec::new();
    let mut raw = 0_i64;
    let mut previous = None;
    let mut offsets = [None; 2];
    for line in bytes[..bytes.len() - 1].split(|b| *b == b'\n') {
        if line.is_empty() || line.len() > 12 * 1024 || frames.len() >= 4096 {
            return Err(integrity());
        }
        let frame: ExecutionOutputFrame = serde_json::from_slice(line).map_err(|_| integrity())?;
        if frame.sequence > 4097
            || previous.is_some_and(|n| frame.sequence <= n)
            || frame.data.len() > 8192
        {
            return Err(integrity());
        }
        let decoded = STANDARD.decode(&frame.data).map_err(|_| integrity())?;
        if decoded.is_empty()
            || decoded.len() > 6144
            || STANDARD.encode(&decoded) != frame.data
            || frame.offset > 16 * 1024 * 1024
            || frame.offset + decoded.len() as u64 > 16 * 1024 * 1024
        {
            return Err(integrity());
        }
        let stream = match frame.stream {
            OutputStream::Stdout => 0,
            OutputStream::Stderr => 1,
        };
        if offsets[stream].is_some_and(|end| frame.offset != end) {
            return Err(integrity());
        }
        offsets[stream] = Some(frame.offset + decoded.len() as u64);
        raw += decoded.len() as i64;
        previous = Some(frame.sequence);
        frames.push(frame);
    }
    if frames.first().map(|f| f.sequence as i64) != Some(receipt.first_frame_sequence)
        || frames.last().map(|f| f.sequence as i64) != Some(receipt.last_frame_sequence)
        || raw != receipt.raw_bytes
    {
        return Err(integrity());
    }
    Ok(frames)
}
fn integrity() -> ApiError {
    let mut error = ApiError::new(
        axum::http::StatusCode::BAD_GATEWAY,
        "OUTPUT_INTEGRITY_FAILED",
        "Stored output does not match the immutable execution index",
    );
    error.retryable = false;
    error
}
fn storage_error(error: OutputStoreError) -> ApiError {
    match error {
        OutputStoreError::InvalidObject | OutputStoreError::Conflict => integrity(),
        _ => ApiError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "OUTPUT_STORAGE_UNAVAILABLE",
            "Execution output storage is unavailable",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn receipt(bytes: &[u8]) -> StoredOutputSegment {
        StoredOutputSegment {
            execution_id: Uuid::new_v4(),
            dispatch_attempt_id: Uuid::new_v4(),
            sequence: 0,
            first_frame_sequence: 1,
            last_frame_sequence: 2,
            raw_bytes: 2,
            object_bytes: bytes.len() as i64,
            sha256: "a".repeat(64),
            object_key: String::new(),
        }
    }
    #[test]
    fn malformed_or_noncontiguous_segment_content_is_rejected() {
        let bytes=b"{\"sequence\":1,\"stream\":\"stdout\",\"offset\":0,\"data\":\"YQ==\"}\n{\"sequence\":2,\"stream\":\"stdout\",\"offset\":1,\"data\":\"Yg==\"}\n";
        assert!(decode_segment(bytes, &receipt(bytes)).is_ok());
        for corrupt in [
            String::from_utf8_lossy(bytes).replace("\"offset\":1", "\"offset\":2"),
            String::from_utf8_lossy(bytes).replace("\"sequence\":2", "\"sequence\":1"),
            String::from_utf8_lossy(bytes).replace("\"data\":\"Yg==\"", "\"data\":\"?\""),
            String::from_utf8_lossy(bytes).replace(
                "\"offset\":1",
                "\"offset\":1,\"url\":\"https://attacker.example\"",
            ),
            String::from_utf8_lossy(bytes).trim_end().to_owned(),
        ] {
            assert!(decode_segment(corrupt.as_bytes(), &receipt(bytes)).is_err());
        }
        let mut wrong = receipt(bytes);
        wrong.raw_bytes = 3;
        assert!(decode_segment(bytes, &wrong).is_err());
    }
}
