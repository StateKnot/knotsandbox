//! Fixed workspace file helper. No shell, archives, host paths or cloud credentials.
use super::protocol::FileBinding;
#[cfg(target_os = "linux")]
use super::protocol::FileRequest;
#[derive(Debug, thiserror::Error)]
pub enum FileRunnerError {
    #[error("file request rejected")]
    Request,
    #[error("file process I/O unavailable")]
    Io,
    #[error("file helper requires Linux openat2")]
    Platform,
}
/// File I/O can block in a hostile guest filesystem. The gateway's immutable
/// deadline requests whole-instance hard stop and retains UNKNOWN until proof.
/// Local timeout/cancellation is never used to manufacture process completion.
#[cfg(target_os = "linux")]
pub fn run_file_transfer(
    input: &mut impl std::io::Read,
    output: &mut impl std::io::Write,
    workspace: &std::path::Path,
    binding: FileBinding,
) -> Result<(), FileRunnerError> {
    use super::{
        path::{FilePathError, WorkspaceDirectory},
        protocol::{FileDirection, FileEvent, FileFailureCode, RAW_CHUNK_BYTES, encode_frame},
    };
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::io::{BufRead, BufReader, Read, Write};
    let mut input = BufReader::with_capacity(8192, input);
    let mut header = Vec::with_capacity(1024);
    // read_until alone would allocate an attacker-selected header without bound.
    loop {
        let bytes = input.fill_buf().map_err(|_| FileRunnerError::Io)?;
        if bytes.is_empty() {
            return Err(FileRunnerError::Request);
        }
        let n = bytes
            .iter()
            .position(|b| *b == b'\n')
            .map_or(bytes.len(), |n| n + 1);
        if header.len() + n > 16 * 1024 {
            return Err(FileRunnerError::Request);
        }
        let complete = bytes[n - 1] == b'\n';
        header.extend_from_slice(&bytes[..n]);
        input.consume(n);
        if complete {
            break;
        }
    }
    let request: FileRequest =
        serde_json::from_slice(&header).map_err(|_| FileRunnerError::Request)?;
    request
        .validate(binding)
        .map_err(|_| FileRunnerError::Request)?;
    output
        .write_all(&encode_frame(binding, 0, FileEvent::Started).map_err(|_| FileRunnerError::Io)?)
        .map_err(|_| FileRunnerError::Io)?;
    output.flush().map_err(|_| FileRunnerError::Io)?;
    let mut sequence = 1_u64;
    let directory = WorkspaceDirectory::open(workspace);
    let result = directory.and_then(|directory| match request.direction {
        FileDirection::Upload => directory.upload(
            &request.path,
            &mut input,
            request.byte_limit,
            request
                .expected_sha256
                .as_deref()
                .ok_or(FilePathError::Checksum)?,
            request.replace,
        ),
        FileDirection::Download => {
            // No body is valid for a download. Wait for the v5 input close before opening
            // tenant files, so hidden trailing request data cannot be silently accepted.
            let mut extra = [0_u8; 1];
            if input.read(&mut extra).map_err(|_| FilePathError::Io)? != 0 {
                return Err(FilePathError::Io);
            }
            struct Frames<'a, W> {
                output: &'a mut W,
                binding: FileBinding,
                sequence: &'a mut u64,
                offset: u64,
                pending: Vec<u8>,
            }
            impl<W: Write> Frames<'_, W> {
                fn emit_pending(&mut self) -> std::io::Result<()> {
                    if !self.pending.is_empty() {
                        let frame = encode_frame(
                            self.binding,
                            *self.sequence,
                            FileEvent::Data {
                                offset: self.offset,
                                data: STANDARD.encode(&self.pending),
                            },
                        )
                        .map_err(std::io::Error::other)?;
                        self.output.write_all(&frame)?;
                        self.output.flush()?;
                        *self.sequence += 1;
                        self.offset += self.pending.len() as u64;
                        self.pending.clear();
                    }
                    Ok(())
                }
            }
            impl<W: Write> Write for Frames<'_, W> {
                fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                    let mut remaining = bytes;
                    while !remaining.is_empty() {
                        let n = remaining.len().min(RAW_CHUNK_BYTES - self.pending.len());
                        self.pending.extend_from_slice(&remaining[..n]);
                        remaining = &remaining[n..];
                        if self.pending.len() == RAW_CHUNK_BYTES {
                            self.emit_pending()?;
                        }
                    }
                    Ok(bytes.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    self.emit_pending()?;
                    self.output.flush()
                }
            }
            let file = directory.open_download(&request.path, request.byte_limit)?;
            let mut frames = Frames {
                output,
                binding,
                sequence: &mut sequence,
                offset: 0,
                pending: Vec::with_capacity(RAW_CHUNK_BYTES),
            };
            let digest = file.stream_to(&mut frames)?;
            frames.flush().map_err(|_| FilePathError::Io)?;
            Ok(digest)
        }
    });
    let event = match result {
        Ok(digest) => FileEvent::Complete {
            byte_length: digest.byte_length,
            sha256: digest.sha256,
        },
        Err(error) => FileEvent::Error {
            code: match error {
                FilePathError::InvalidPath => FileFailureCode::InvalidPath,
                FilePathError::Resolution => FileFailureCode::PathUnavailable,
                FilePathError::NotRegular => FileFailureCode::NotRegular,
                FilePathError::Size => FileFailureCode::SizeLimit,
                FilePathError::Checksum => FileFailureCode::ChecksumMismatch,
                FilePathError::Exists => FileFailureCode::TargetExists,
                FilePathError::Changed => FileFailureCode::FileChanged,
                FilePathError::Io => FileFailureCode::IoFailed,
            },
        },
    };
    output
        .write_all(&encode_frame(binding, sequence, event).map_err(|_| FileRunnerError::Io)?)
        .map_err(|_| FileRunnerError::Io)?;
    output.flush().map_err(|_| FileRunnerError::Io)?;
    // A well-formed Error frame is a successful helper process, describing only a
    // guest-reported failure. The gateway still requires trusted exec status.
    Ok(())
}
#[cfg(not(target_os = "linux"))]
pub fn run_file_transfer(
    _input: &mut impl std::io::Read,
    _output: &mut impl std::io::Write,
    _workspace: &std::path::Path,
    _binding: FileBinding,
) -> Result<(), FileRunnerError> {
    Err(FileRunnerError::Platform)
}
