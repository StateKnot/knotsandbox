//! Independent limits for hostile guest NDJSON. Runner-enforced limits are not
//! trusted by the control plane. Kubernetes channel 3 is parsed separately.
use crate::runner::{Frame, OutputStream, RunSummary, RunnerEvent};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Status;
use serde_json::Value;
use uuid::Uuid;

pub const MAX_GUEST_LINE_BYTES: usize = 12 * 1024;
pub const MAX_GUEST_WIRE_BYTES: usize = 24 * 1024 * 1024;
pub const MAX_GUEST_OUTPUT_FRAMES: u64 = 4096;
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid or over-limit guest protocol: {0}")]
pub struct ProtocolError(pub &'static str);

#[derive(Debug)]
pub enum GuestEvent {
    Started,
    Output {
        sequence: u64,
        stream: OutputStream,
        offset: u64,
        bytes: Vec<u8>,
    },
    Terminal(GuestTerminal),
}
#[derive(Debug, Clone)]
pub enum GuestTerminal {
    Exited(RunSummary),
    TimedOut(RunSummary),
    Error(String),
}

pub struct GuestDecoder {
    execution_id: Uuid,
    buffer: Vec<u8>,
    wire_bytes: usize,
    next_sequence: u64,
    started: bool,
    terminal: bool,
    output_frames: u64,
    output_limit: u64,
    observed_bytes: u64,
    retained_bytes: u64,
    offsets: [u64; 2],
    pub truncated: bool,
}
impl GuestDecoder {
    pub fn new(execution_id: Uuid, output_limit: u64) -> Result<Self, ProtocolError> {
        if execution_id.is_nil() || output_limit > crate::runner::MAX_OUTPUT_BYTES {
            return Err(ProtocolError("INVALID_LIMIT"));
        }
        Ok(Self {
            execution_id,
            buffer: Vec::with_capacity(1024),
            wire_bytes: 0,
            next_sequence: 0,
            started: false,
            terminal: false,
            output_frames: 0,
            output_limit,
            observed_bytes: 0,
            retained_bytes: 0,
            offsets: [0, 0],
            truncated: false,
        })
    }
    /// Feed a bounded WebSocket chunk. Returned data is bounded by the chunk
    /// size; callers must put it into a bounded persistence queue immediately.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<GuestEvent>, ProtocolError> {
        if bytes.len() > 64 * 1024 {
            return Err(ProtocolError("INPUT_CHUNK_LIMIT"));
        }
        self.wire_bytes = self
            .wire_bytes
            .checked_add(bytes.len())
            .ok_or(ProtocolError("WIRE_LIMIT"))?;
        if self.wire_bytes > MAX_GUEST_WIRE_BYTES {
            return Err(ProtocolError("WIRE_LIMIT"));
        }
        let mut events = Vec::new();
        for byte in bytes {
            if *byte == b'\n' {
                if self.buffer.is_empty() {
                    return Err(ProtocolError("EMPTY_FRAME"));
                }
                let line = std::mem::take(&mut self.buffer);
                events.push(self.frame(&line)?);
                self.buffer = Vec::with_capacity(1024);
            } else {
                if self.buffer.len() >= MAX_GUEST_LINE_BYTES {
                    return Err(ProtocolError("LINE_LIMIT"));
                }
                self.buffer.push(*byte);
            }
        }
        Ok(events)
    }
    pub fn finish(&self) -> Result<(), ProtocolError> {
        if !self.buffer.is_empty() || !self.terminal {
            return Err(ProtocolError("INCOMPLETE_PROTOCOL"));
        }
        Ok(())
    }
    fn frame(&mut self, line: &[u8]) -> Result<GuestEvent, ProtocolError> {
        if self.terminal {
            return Err(ProtocolError("AFTER_TERMINAL"));
        }
        let value: Value =
            serde_json::from_slice(line).map_err(|_| ProtocolError("INVALID_JSON"))?;
        let kind = value
            .get("type")
            .and_then(Value::as_str)
            .ok_or(ProtocolError("MISSING_TYPE"))?;
        let allowed: &[&str] = match kind {
            "started" => &["pid"],
            "output" => &["stream", "data"],
            "exited" | "timed_out" => &[
                "exit_code",
                "signal",
                "timed_out",
                "cancelled",
                "output_complete",
                "output_truncated",
                "bytes_observed",
                "bytes_emitted",
                "termination_confirmed",
            ],
            "error" => &["code", "termination_confirmed"],
            _ => return Err(ProtocolError("UNKNOWN_TYPE")),
        };
        if value.as_object().is_none_or(|m| {
            m.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "type" | "protocol_version" | "execution_id" | "sequence"
                ) && !allowed.contains(&key.as_str())
            })
        }) {
            return Err(ProtocolError("UNKNOWN_FIELD"));
        }
        let frame: Frame =
            serde_json::from_slice(line).map_err(|_| ProtocolError("INVALID_FRAME"))?;
        if frame.protocol_version != 1
            || frame.execution_id != Some(self.execution_id)
            || frame.sequence != self.next_sequence
        {
            return Err(ProtocolError("IDENTITY_OR_SEQUENCE"));
        }
        self.next_sequence += 1;
        match frame.event {
            RunnerEvent::Started { pid } => {
                if self.started || frame.sequence != 0 || pid == 0 {
                    return Err(ProtocolError("INVALID_STARTED"));
                }
                self.started = true;
                Ok(GuestEvent::Started)
            }
            RunnerEvent::Output { stream, data } => {
                if !self.started
                    || data.len() > 8192
                    || self.output_frames >= MAX_GUEST_OUTPUT_FRAMES
                {
                    return Err(ProtocolError("OUTPUT_FRAME_LIMIT"));
                }
                let mut decoded = STANDARD
                    .decode(data)
                    .map_err(|_| ProtocolError("INVALID_BASE64"))?;
                if decoded.is_empty() || decoded.len() > 6144 {
                    return Err(ProtocolError("OUTPUT_CHUNK_LIMIT"));
                }
                self.output_frames += 1;
                let index = match stream {
                    OutputStream::Stdout => 0,
                    OutputStream::Stderr => 1,
                };
                let offset = self.offsets[index];
                self.offsets[index] += decoded.len() as u64;
                self.observed_bytes += decoded.len() as u64;
                let retain =
                    (self.output_limit - self.retained_bytes).min(decoded.len() as u64) as usize;
                self.truncated |= retain < decoded.len();
                decoded.truncate(retain);
                self.retained_bytes += retain as u64;
                Ok(GuestEvent::Output {
                    sequence: frame.sequence,
                    stream,
                    offset,
                    bytes: decoded,
                })
            }
            RunnerEvent::Exited { mut result } | RunnerEvent::TimedOut { mut result } => {
                if !self.started
                    || result.bytes_emitted != self.observed_bytes
                    || result.bytes_observed < result.bytes_emitted
                    || result.exit_code.is_some_and(|c| !(0..=255).contains(&c))
                    || result.signal.is_some_and(|s| !(1..=128).contains(&s))
                {
                    return Err(ProtocolError("INVALID_TERMINAL"));
                }
                // No guest field can attest trusted process or VM termination.
                result.termination_confirmed = false;
                result.output_truncated |= self.truncated;
                self.terminal = true;
                if kind == "timed_out" || result.timed_out || result.cancelled {
                    Ok(GuestEvent::Terminal(GuestTerminal::TimedOut(result)))
                } else {
                    Ok(GuestEvent::Terminal(GuestTerminal::Exited(result)))
                }
            }
            RunnerEvent::Error { code, .. } => {
                if code.is_empty()
                    || code.len() > 64
                    || !code
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                {
                    return Err(ProtocolError("INVALID_ERROR"));
                }
                self.terminal = true;
                Ok(GuestEvent::Terminal(GuestTerminal::Error(code)))
            }
        }
    }
}

/// Only authenticated Kubernetes channel 3 may supply this value. Stdout JSON
/// that resembles a Status is still guest data and must never call this path.
pub fn process_exit_from_kubernetes_status(status: &Status) -> Option<i32> {
    if status.status.as_deref() == Some("Success") {
        return Some(0);
    }
    if status.status.as_deref() != Some("Failure")
        || status.reason.as_deref() != Some("NonZeroExitCode")
    {
        return None;
    }
    let causes = status.details.as_ref()?.causes.as_ref()?;
    let codes: Vec<_> = causes
        .iter()
        .filter(|c| c.reason.as_deref() == Some("ExitCode"))
        .collect();
    if codes.len() != 1 {
        return None;
    }
    codes[0]
        .message
        .as_deref()?
        .parse::<i32>()
        .ok()
        .filter(|n| (1..=255).contains(n))
}
