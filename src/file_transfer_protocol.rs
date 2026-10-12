//! A separate bounded file protocol; guest bytes never select cloud keys or
//! authorize another transfer. The Kubernetes process status remains separate.
use super::path::{MAX_FILE_BYTES, RelativeFilePath};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const PROTOCOL_VERSION: u8 = 1;
pub const RAW_CHUNK_BYTES: usize = 6144;
pub const MAX_LINE_BYTES: usize = 12 * 1024;
pub const MAX_WIRE_BYTES: u64 = 150 * 1024 * 1024;
const MAX_FRAMES: u64 = MAX_FILE_BYTES / RAW_CHUNK_BYTES as u64 + 4;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FileDirection {
    Upload,
    Download,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileBinding {
    pub transfer_id: Uuid,
    pub dispatch_attempt_id: Uuid,
}
impl FileBinding {
    pub fn validate(self) -> Result<(), FileProtocolError> {
        if self.transfer_id.is_nil() || self.dispatch_attempt_id.is_nil() {
            Err(FileProtocolError("INVALID_BINDING"))
        } else {
            Ok(())
        }
    }
}
// Deliberately no Debug: the relative path is tenant data.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRequest {
    pub protocol_version: u8,
    pub transfer_id: Uuid,
    pub dispatch_attempt_id: Uuid,
    pub direction: FileDirection,
    pub path: RelativeFilePath,
    pub byte_limit: u64,
    pub expected_length: Option<u64>,
    pub expected_sha256: Option<String>,
    pub replace: bool,
}
impl FileRequest {
    pub fn validate(&self, binding: FileBinding) -> Result<(), FileProtocolError> {
        binding.validate()?;
        if self.protocol_version != PROTOCOL_VERSION
            || self.transfer_id != binding.transfer_id
            || self.dispatch_attempt_id != binding.dispatch_attempt_id
            || self.byte_limit > MAX_FILE_BYTES
        {
            return Err(FileProtocolError("INVALID_REQUEST_BINDING_OR_LIMIT"));
        }
        match self.direction {
            FileDirection::Upload => {
                if self.expected_length != Some(self.byte_limit)
                    || self
                        .expected_sha256
                        .as_deref()
                        .is_none_or(|v| !valid_sha(v))
                {
                    return Err(FileProtocolError("UPLOAD_REQUIRES_EXACT_CONTENT"));
                }
            }
            FileDirection::Download => {
                if self.expected_length.is_some() || self.expected_sha256.is_some() || self.replace
                {
                    return Err(FileProtocolError("INVALID_DOWNLOAD_PARAMETERS"));
                }
            }
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileFrame {
    pub protocol_version: u8,
    pub transfer_id: Uuid,
    pub dispatch_attempt_id: Uuid,
    pub sequence: u64,
    pub event: FileEvent,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum FileEvent {
    Started,
    Data { offset: u64, data: String },
    Complete { byte_length: u64, sha256: String },
    Error { code: FileFailureCode },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FileFailureCode {
    InvalidPath,
    PathUnavailable,
    NotRegular,
    SizeLimit,
    ChecksumMismatch,
    TargetExists,
    FileChanged,
    IoFailed,
    DeadlineExceeded,
}
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid file protocol: {0}")]
pub struct FileProtocolError(pub &'static str);
#[derive(Debug)]
pub enum DecodedFileEvent {
    Started,
    Data { offset: u64, bytes: Vec<u8> },
    Complete { byte_length: u64, sha256: String },
    Error(FileFailureCode),
}
/// This decoder is used by the control plane, independently of runner checks.
/// Output does not prove VM death or freeze the guest filesystem after transfer.
pub struct FileDecoder {
    binding: FileBinding,
    direction: FileDirection,
    limit: u64,
    expected_sha: Option<String>,
    buffer: Vec<u8>,
    wire_bytes: u64,
    next_sequence: u64,
    offset: u64,
    sha: Sha256,
    started: bool,
    terminal: bool,
}
impl FileDecoder {
    pub fn new(request: &FileRequest) -> Result<Self, FileProtocolError> {
        let binding = FileBinding {
            transfer_id: request.transfer_id,
            dispatch_attempt_id: request.dispatch_attempt_id,
        };
        request.validate(binding)?;
        Ok(Self {
            binding,
            direction: request.direction,
            limit: request.byte_limit,
            expected_sha: request.expected_sha256.clone(),
            buffer: Vec::with_capacity(1024),
            wire_bytes: 0,
            next_sequence: 0,
            offset: 0,
            sha: Sha256::new(),
            started: false,
            terminal: false,
        })
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<DecodedFileEvent>, FileProtocolError> {
        if bytes.len() > 64 * 1024 {
            return Err(FileProtocolError("INPUT_CHUNK_LIMIT"));
        }
        self.wire_bytes = self
            .wire_bytes
            .checked_add(bytes.len() as u64)
            .ok_or(FileProtocolError("WIRE_LIMIT"))?;
        if self.wire_bytes > MAX_WIRE_BYTES {
            return Err(FileProtocolError("WIRE_LIMIT"));
        }
        let mut events = Vec::new();
        for byte in bytes {
            if *byte == b'\n' {
                if self.buffer.is_empty() {
                    return Err(FileProtocolError("EMPTY_FRAME"));
                }
                let line = std::mem::take(&mut self.buffer);
                events.push(self.frame(&line)?);
                self.buffer = Vec::with_capacity(1024);
            } else {
                if self.buffer.len() >= MAX_LINE_BYTES {
                    return Err(FileProtocolError("FRAME_LIMIT"));
                }
                self.buffer.push(*byte);
            }
        }
        Ok(events)
    }
    fn frame(&mut self, line: &[u8]) -> Result<DecodedFileEvent, FileProtocolError> {
        if self.terminal {
            return Err(FileProtocolError("AFTER_TERMINAL"));
        }
        let frame: FileFrame =
            serde_json::from_slice(line).map_err(|_| FileProtocolError("INVALID_FRAME"))?;
        if frame.protocol_version != PROTOCOL_VERSION
            || frame.transfer_id != self.binding.transfer_id
            || frame.dispatch_attempt_id != self.binding.dispatch_attempt_id
            || frame.sequence != self.next_sequence
            || self.next_sequence >= MAX_FRAMES
        {
            return Err(FileProtocolError("IDENTITY_OR_SEQUENCE"));
        }
        self.next_sequence += 1;
        match frame.event {
            FileEvent::Started => {
                if self.started || frame.sequence != 0 {
                    return Err(FileProtocolError("DUPLICATE_START"));
                }
                self.started = true;
                Ok(DecodedFileEvent::Started)
            }
            FileEvent::Data { offset, data } => {
                if !self.started
                    || self.direction != FileDirection::Download
                    || offset != self.offset
                    || data.len() > 8192
                {
                    return Err(FileProtocolError("INVALID_DATA"));
                }
                let bytes = STANDARD
                    .decode(data)
                    .map_err(|_| FileProtocolError("INVALID_BASE64"))?;
                if bytes.is_empty() || bytes.len() > RAW_CHUNK_BYTES {
                    return Err(FileProtocolError("DATA_LIMIT"));
                }
                self.offset = self
                    .offset
                    .checked_add(bytes.len() as u64)
                    .ok_or(FileProtocolError("SIZE_LIMIT"))?;
                if self.offset > self.limit {
                    return Err(FileProtocolError("SIZE_LIMIT"));
                }
                self.sha.update(&bytes);
                Ok(DecodedFileEvent::Data { offset, bytes })
            }
            FileEvent::Complete {
                byte_length,
                sha256,
            } => {
                if !self.started || !valid_sha(&sha256) || byte_length > self.limit {
                    return Err(FileProtocolError("INVALID_COMPLETION"));
                }
                let correct = match self.direction {
                    FileDirection::Upload => {
                        byte_length == self.limit
                            && self.expected_sha.as_deref() == Some(sha256.as_str())
                    }
                    FileDirection::Download => {
                        byte_length == self.offset
                            && hex::encode(self.sha.clone().finalize()) == sha256
                    }
                };
                if !correct {
                    return Err(FileProtocolError("CHECKSUM_OR_SIZE_MISMATCH"));
                }
                self.terminal = true;
                Ok(DecodedFileEvent::Complete {
                    byte_length,
                    sha256,
                })
            }
            FileEvent::Error { code } => {
                if !self.started {
                    return Err(FileProtocolError("ERROR_BEFORE_START"));
                }
                self.terminal = true;
                Ok(DecodedFileEvent::Error(code))
            }
        }
    }
    pub fn finish(&self) -> Result<(), FileProtocolError> {
        if !self.buffer.is_empty() || !self.terminal {
            Err(FileProtocolError("INCOMPLETE_PROTOCOL"))
        } else {
            Ok(())
        }
    }
}
pub fn encode_frame(
    binding: FileBinding,
    sequence: u64,
    event: FileEvent,
) -> Result<Vec<u8>, FileProtocolError> {
    binding.validate()?;
    let mut bytes = serde_json::to_vec(&FileFrame {
        protocol_version: PROTOCOL_VERSION,
        transfer_id: binding.transfer_id,
        dispatch_attempt_id: binding.dispatch_attempt_id,
        sequence,
        event,
    })
    .map_err(|_| FileProtocolError("ENCODING"))?;
    if bytes.len() > MAX_LINE_BYTES {
        return Err(FileProtocolError("FRAME_LIMIT"));
    }
    bytes.push(b'\n');
    Ok(bytes)
}
pub fn valid_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
