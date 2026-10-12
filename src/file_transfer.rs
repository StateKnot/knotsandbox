//! Single-file transfer intent and immutable content/dispatch identity. Cloud
//! staging and a guest process are separate facts; neither implies VM death.
#[path = "file_transfer_path.rs"]
pub mod path;
#[path = "file_transfer_protocol.rs"]
pub mod protocol;

use crate::{error::ApiError, model::Operation};
use chrono::{DateTime, Utc};
use path::{MAX_FILE_BYTES, RelativeFilePath};
use protocol::{FileDirection, valid_sha};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const fn default_timeout() -> u32 {
    300
}
const fn default_max_bytes() -> u64 {
    MAX_FILE_BYTES
}
/// The timeout affects the whole instance, including unrelated guest activity.
/// Both directions therefore require instances:hard_stop at every admission.
#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "direction",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum CreateFileTransfer {
    Upload {
        path: RelativeFilePath,
        byte_length: u64,
        sha256: String,
        #[serde(default)]
        replace: bool,
        #[serde(default = "default_timeout")]
        timeout_seconds: u32,
    },
    Download {
        path: RelativeFilePath,
        #[serde(default = "default_max_bytes")]
        max_bytes: u64,
        #[serde(default = "default_timeout")]
        timeout_seconds: u32,
    },
}
pub(crate) struct TransferSpec<'a> {
    pub direction: FileDirection,
    pub path: &'a RelativeFilePath,
    pub byte_limit: u64,
    pub expected_sha256: Option<&'a str>,
    pub replace: bool,
    pub timeout_seconds: u32,
}
impl CreateFileTransfer {
    pub(crate) fn validate(&self, configured_max_bytes: u64) -> Result<TransferSpec<'_>, ApiError> {
        if configured_max_bytes == 0 || configured_max_bytes > MAX_FILE_BYTES {
            return Err(ApiError::invalid(
                "Configured single-file cap must be 1..=100 MiB",
            ));
        }
        let spec = match self {
            Self::Upload {
                path,
                byte_length,
                sha256,
                replace,
                timeout_seconds,
            } => {
                if !valid_sha(sha256) {
                    return Err(ApiError::invalid(
                        "Upload requires a lowercase SHA-256 checksum",
                    ));
                }
                TransferSpec {
                    direction: FileDirection::Upload,
                    path,
                    byte_limit: *byte_length,
                    expected_sha256: Some(sha256),
                    replace: *replace,
                    timeout_seconds: *timeout_seconds,
                }
            }
            Self::Download {
                path,
                max_bytes,
                timeout_seconds,
            } => TransferSpec {
                direction: FileDirection::Download,
                path,
                byte_limit: *max_bytes,
                expected_sha256: None,
                replace: false,
                timeout_seconds: *timeout_seconds,
            },
        };
        if spec.byte_limit > configured_max_bytes || !(1..=300).contains(&spec.timeout_seconds) {
            return Err(ApiError::invalid(
                "File byte limit or transfer timeout exceeds the configured cap",
            ));
        }
        Ok(spec)
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct FileTransfer {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub instance_id: Uuid,
    pub workspace_id: Uuid,
    pub operation_id: Uuid,
    pub runtime_generation: i64,
    pub direction: FileDirection,
    pub path: RelativeFilePath,
    pub status: String,
    pub version: i64,
    pub byte_limit: u64,
    pub expected_sha256: Option<String>,
    pub observed_bytes: Option<u64>,
    pub observed_sha256: Option<String>,
    pub replace: bool,
    pub slot_held: bool,
    pub process_status: String,
    pub content_status: String,
    /// PENDING/ACKNOWLEDGED/OUTCOME_UNKNOWN describe OSS writes separately.
    pub storage_writer_status: String,
    pub timeout_policy: String,
    pub deadline: DateTime<Utc>,
    pub content_expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}
#[derive(Serialize, Deserialize)]
pub struct FileTransferAccepted {
    pub resource: FileTransfer,
    pub operation: Operation,
    pub instance_version: i64,
    pub idempotency_expires_at: DateTime<Utc>,
}
pub struct FileTransferMutationResult {
    pub status: u16,
    pub body: FileTransferAccepted,
}

#[path = "file_transfer_ledger.rs"]
pub mod ledger;

#[path = "file_transfer_runner.rs"]
pub mod runner;

#[path = "file_transfer_transport.rs"]
pub mod transport;

#[path = "file_transfer_cleanup.rs"]
pub mod cleanup;

#[path = "file_transfer_gateway.rs"]
pub mod gateway;
