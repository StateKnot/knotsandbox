//! One-shot guest process runner. Every receipt is untrusted workload output;
//! local process cleanup never proves that the sandbox VM has terminated.

#[cfg(target_os = "linux")]
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::{
    collections::BTreeMap,
    path::{Component, Path},
    time::Duration,
};

#[cfg(target_os = "linux")]
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(target_os = "linux")]
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_INPUT_BYTES: usize = 64 * 1024;
pub const MAX_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
pub const RAW_CHUNK_BYTES: usize = 6144; // base64 payload is at most 8192 bytes.

/// The API-server-visible identity of this single exec connection. It is a
/// correlation binding, not a guest-side deduplication or authorization token.
#[derive(Clone, Copy)]
pub struct ExecBinding {
    pub execution_id: Uuid,
    pub dispatch_attempt_id: Uuid,
}
const INPUT_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(target_os = "linux")]
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const OUTPUT_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(target_os = "linux")]
const MAX_OUTPUT_FRAMES: u64 = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecRequest {
    pub execution_id: Uuid,
    pub argv: Vec<String>,
    #[serde(deserialize_with = "deserialize_environment")]
    pub env: BTreeMap<String, String>,
    pub cwd: String,
    pub timeout_seconds: u64,
    pub output_limit_bytes: u64,
}

pub fn deserialize_environment<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct UniqueEnvironment;
    impl<'de> serde::de::Visitor<'de> for UniqueEnvironment {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an environment map with unique names")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> Result<Self::Value, M::Error> {
            let mut values = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if values.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate environment name"));
                }
            }
            Ok(values)
        }
    }
    deserializer.deserialize_map(UniqueEnvironment)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RunnerError {
    #[error("input exceeds the protocol limit")]
    InputTooLarge,
    #[error("input EOF was not received before the input deadline")]
    InputTimeout,
    #[error("input is not one valid protocol object")]
    InvalidJson,
    #[error("invalid execution request: {0}")]
    InvalidRequest(&'static str),
    #[error("safe execution requires Linux")]
    UnsupportedPlatform,
    #[error("working directory is unavailable or outside the workspace")]
    WorkingDirectory,
    #[error("cannot spawn the requested command")]
    SpawnFailed,
    #[error("cannot read the control channel")]
    InputChannel,
    #[error("cannot write the result channel")]
    OutputChannel,
    #[error("cannot observe the child exit")]
    ChildWait,
    #[error("execution was cancelled")]
    Cancelled,
}

impl RunnerError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InputTooLarge => "INPUT_TOO_LARGE",
            Self::InputTimeout => "INPUT_TIMEOUT",
            Self::InvalidJson => "INVALID_JSON",
            Self::InvalidRequest(_) => "INVALID_REQUEST",
            Self::UnsupportedPlatform => "UNSUPPORTED_PLATFORM",
            Self::WorkingDirectory => "INVALID_CWD",
            Self::SpawnFailed => "SPAWN_FAILED",
            Self::InputChannel => "INPUT_CHANNEL_FAILED",
            Self::OutputChannel => "OUTPUT_CHANNEL_FAILED",
            Self::ChildWait => "CHILD_WAIT_FAILED",
            Self::Cancelled => "CANCELLED",
        }
    }
}

impl ExecRequest {
    pub fn validate(&self, workspace_root: &Path) -> Result<(), RunnerError> {
        if self.execution_id.is_nil()
            || !(1..=3600).contains(&self.timeout_seconds)
            || self.output_limit_bytes > MAX_OUTPUT_BYTES
        {
            return Err(RunnerError::InvalidRequest("identity/time/output limit"));
        }
        if self.argv.is_empty()
            || self.argv.len() > 64
            || self.argv[0].is_empty()
            || self.argv.iter().any(|arg| arg.contains('\0'))
            || self
                .argv
                .iter()
                .try_fold(0usize, |size, arg| size.checked_add(arg.len() + 1))
                .is_none_or(|size| size > MAX_INPUT_BYTES)
        {
            return Err(RunnerError::InvalidRequest("argv"));
        }
        let env_size = self.env.iter().try_fold(0usize, |size, (key, value)| {
            size.checked_add(key.len() + value.len() + 2)
        });
        if self.env.len() > 64
            || env_size.is_none_or(|size| size > 16 * 1024)
            || self.env.iter().any(|(key, value)| {
                !valid_env_key(key)
                    || value.len() > 4096
                    || value.contains('\0')
                    || key.starts_with("SANDBOX_")
                    || matches!(key.as_str(), "PATH" | "HOME" | "TMPDIR")
            })
        {
            return Err(RunnerError::InvalidRequest("environment"));
        }
        let cwd = Path::new(&self.cwd);
        if self.cwd.contains('\0')
            || !workspace_root.is_absolute()
            || !cwd.is_absolute()
            || !cwd.starts_with(workspace_root)
            || cwd
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::Prefix(_)))
        {
            return Err(RunnerError::WorkingDirectory);
        }
        Ok(())
    }
}

fn valid_env_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 128
        && key
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub cancelled: bool,
    pub output_complete: bool,
    pub output_truncated: bool,
    pub bytes_observed: u64,
    pub bytes_emitted: u64,
    /// Always false: guest code cannot attest VM termination to the platform.
    pub termination_confirmed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RunnerEvent {
    Started {
        pid: u32,
    },
    Output {
        stream: OutputStream,
        data: String,
    },
    Exited {
        #[serde(flatten)]
        result: RunSummary,
    },
    TimedOut {
        #[serde(flatten)]
        result: RunSummary,
    },
    Error {
        code: String,
        termination_confirmed: bool,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Frame {
    pub protocol_version: u8,
    pub execution_id: Option<Uuid>,
    pub sequence: u64,
    #[serde(flatten)]
    pub event: RunnerEvent,
}

/// Reads through EOF before any process can start. A second JSON object,
/// duplicate struct fields, trailing non-whitespace, or unknown field is invalid.
pub async fn read_request<R: AsyncRead + Unpin>(input: R) -> Result<ExecRequest, RunnerError> {
    let mut bytes = Vec::with_capacity(4096);
    let mut bounded = input.take((MAX_INPUT_BYTES + 1) as u64);
    tokio::time::timeout(INPUT_TIMEOUT, bounded.read_to_end(&mut bytes))
        .await
        .map_err(|_| RunnerError::InputTimeout)?
        .map_err(|_| RunnerError::InputChannel)?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(RunnerError::InputTooLarge);
    }
    serde_json::from_slice(&bytes).map_err(|_| RunnerError::InvalidJson)
}

pub async fn run_exec<R, W>(
    input: R,
    mut output: W,
    workspace_root: &Path,
    cancellation: CancellationToken,
    binding: ExecBinding,
) -> Result<RunSummary, RunnerError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    if binding.execution_id.is_nil() || binding.dispatch_attempt_id.is_nil() {
        let error = RunnerError::InvalidRequest("dispatch identity");
        report_error(&mut output, None, &error).await?;
        return Err(error);
    }
    let input_result = tokio::select! {
        biased;
        _=cancellation.cancelled()=>Err(RunnerError::Cancelled),
        result=read_request(input)=>result,
    };
    let request = match input_result {
        Ok(request) => request,
        Err(error) => {
            report_error(&mut output, None, &error).await?;
            return Err(error);
        }
    };
    if request.execution_id != binding.execution_id {
        let error = RunnerError::InvalidRequest("execution identity mismatch");
        report_error(&mut output, Some(binding.execution_id), &error).await?;
        return Err(error);
    }
    execute_request(request, output, workspace_root, cancellation).await
}

#[cfg(not(target_os = "linux"))]
pub async fn execute_request<W>(
    request: ExecRequest,
    mut output: W,
    workspace_root: &Path,
    _cancellation: CancellationToken,
) -> Result<RunSummary, RunnerError>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let error = request
        .validate(workspace_root)
        .err()
        .unwrap_or(RunnerError::UnsupportedPlatform);
    report_error(&mut output, Some(request.execution_id), &error).await?;
    Err(error)
}

#[cfg(target_os = "linux")]
pub async fn execute_request<W>(
    request: ExecRequest,
    mut output: W,
    workspace_root: &Path,
    cancellation: CancellationToken,
) -> Result<RunSummary, RunnerError>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    use std::{
        os::{fd::AsRawFd, unix::process::ExitStatusExt},
        process::Stdio,
    };
    use tokio::process::Command;

    if let Err(error) = request.validate(workspace_root) {
        report_error(&mut output, Some(request.execution_id), &error).await?;
        return Err(error);
    }
    let directory = match open_working_directory(workspace_root, Path::new(&request.cwd)) {
        Ok(directory) => directory,
        Err(error) => {
            report_error(&mut output, Some(request.execution_id), &error).await?;
            return Err(error);
        }
    };
    if cancellation.is_cancelled() {
        let error = RunnerError::Cancelled;
        report_error(&mut output, Some(request.execution_id), &error).await?;
        return Err(error);
    }
    let mut command = Command::new(&request.argv[0]);
    command
        .args(&request.argv[1..])
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", workspace_root)
        .env("TMPDIR", "/tmp")
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("SANDBOX_RUNNER_PROTOCOL", PROTOCOL_VERSION.to_string())
        .env("SANDBOX_EXECUTION_ID", request.execution_id.to_string())
        .envs(&request.env)
        .current_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            let error = RunnerError::SpawnFailed;
            report_error(&mut output, Some(request.execution_id), &error).await?;
            return Err(error);
        }
    };
    // std performs chdir before exec closes this CLOEXEC descriptor.
    drop(directory);
    let pid = child.id().ok_or(RunnerError::SpawnFailed)?;
    let stdout = child.stdout.take().ok_or(RunnerError::SpawnFailed)?;
    let stderr = child.stderr.take().ok_or(RunnerError::SpawnFailed)?;
    let (sender, receiver) = mpsc::channel(16);
    let output_failed = CancellationToken::new();
    let failed_for_writer = output_failed.clone();
    let execution_id = request.execution_id;
    let mut writer = tokio::spawn(async move {
        let result = write_frames(output, execution_id, receiver).await;
        if result.is_err() {
            failed_for_writer.cancel();
        }
        result
    });
    sender
        .send(RunnerEvent::Started { pid })
        .await
        .map_err(|_| RunnerError::OutputChannel)?;
    let accounting = Arc::new(OutputAccounting::new(request.output_limit_bytes));
    let mut out_reader = tokio::spawn(drain(
        stdout,
        OutputStream::Stdout,
        sender.clone(),
        accounting.clone(),
        output_failed.clone(),
    ));
    let mut err_reader = tokio::spawn(drain(
        stderr,
        OutputStream::Stderr,
        sender.clone(),
        accounting.clone(),
        output_failed.clone(),
    ));
    enum Completion {
        Exited(std::io::Result<std::process::ExitStatus>),
        TimedOut,
        Cancelled,
        OutputFailed,
    }
    let completion = tokio::select! {
        status=child.wait()=>Completion::Exited(status),
        _=tokio::time::sleep(Duration::from_secs(request.timeout_seconds))=>Completion::TimedOut,
        _=cancellation.cancelled()=>Completion::Cancelled,
        _=output_failed.cancelled()=>Completion::OutputFailed,
    };
    let timed_out = matches!(completion, Completion::TimedOut);
    let cancelled = matches!(completion, Completion::Cancelled);
    let (status, wait_failed) = match completion {
        Completion::Exited(result) => match result {
            Ok(status) => (Some(status), false),
            Err(_) => (None, true),
        },
        _ => {
            kill_process_group(pid);
            let _ = child.start_kill();
            match tokio::time::timeout(Duration::from_secs(1), child.wait()).await {
                Ok(Ok(status)) => (Some(status), false),
                _ => (None, true),
            }
        }
    };
    if wait_failed {
        kill_process_group(pid);
        let _ = child.start_kill();
    }
    let mut out_finished = false;
    let mut err_finished = false;
    let drained = tokio::time::timeout(DRAIN_TIMEOUT, async {
        let out = (&mut out_reader).await;
        out_finished = true;
        let err = (&mut err_reader).await;
        err_finished = true;
        matches!(out, Ok(true)) && matches!(err, Ok(true))
    })
    .await;
    let output_complete =
        matches!(drained, Ok(true)) && !accounting.truncated.load(Ordering::Relaxed);
    if drained.is_err() {
        // A descendant can keep pipe descriptors after the direct child exits.
        // Bound cleanup and never mistake killpg for proof against setsid.
        kill_process_group(pid);
        if !out_finished {
            out_reader.abort();
            let _ = out_reader.await;
        }
        if !err_finished {
            err_reader.abort();
            let _ = err_reader.await;
        }
    }
    if output_failed.is_cancelled() {
        kill_process_group(pid);
        writer.abort();
        let _ = writer.await;
        return Err(RunnerError::OutputChannel);
    }
    let summary = RunSummary {
        exit_code: status.as_ref().and_then(std::process::ExitStatus::code),
        signal: status.as_ref().and_then(ExitStatusExt::signal),
        timed_out,
        cancelled,
        output_complete,
        output_truncated: accounting.truncated.load(Ordering::Relaxed),
        bytes_observed: accounting.observed.load(Ordering::Relaxed),
        bytes_emitted: accounting.emitted.load(Ordering::Relaxed),
        termination_confirmed: false,
    };
    let terminal = if cancelled {
        RunnerEvent::Error {
            code: "CANCELLED".to_owned(),
            termination_confirmed: false,
        }
    } else if timed_out {
        RunnerEvent::TimedOut {
            result: summary.clone(),
        }
    } else if wait_failed {
        RunnerEvent::Error {
            code: RunnerError::ChildWait.code().to_owned(),
            termination_confirmed: false,
        }
    } else {
        RunnerEvent::Exited {
            result: summary.clone(),
        }
    };
    if !matches!(
        tokio::time::timeout(OUTPUT_TIMEOUT, sender.send(terminal)).await,
        Ok(Ok(()))
    ) {
        writer.abort();
        let _ = writer.await;
        kill_process_group(pid);
        return Err(RunnerError::OutputChannel);
    }
    drop(sender);
    match tokio::time::timeout(OUTPUT_TIMEOUT, &mut writer).await {
        Ok(Ok(Ok(()))) => {}
        Ok(_) => {
            kill_process_group(pid);
            return Err(RunnerError::OutputChannel);
        }
        Err(_) => {
            writer.abort();
            let _ = writer.await;
            kill_process_group(pid);
            return Err(RunnerError::OutputChannel);
        }
    }
    if wait_failed && !timed_out && !cancelled {
        return Err(RunnerError::ChildWait);
    }
    Ok(summary)
}

#[cfg(target_os = "linux")]
fn open_working_directory(root: &Path, cwd: &Path) -> Result<std::os::fd::OwnedFd, RunnerError> {
    use nix::{
        fcntl::{OFlag, open, openat},
        sys::stat::Mode,
    };
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut directory =
        open(root, flags, Mode::empty()).map_err(|_| RunnerError::WorkingDirectory)?;
    let relative = cwd
        .strip_prefix(root)
        .map_err(|_| RunnerError::WorkingDirectory)?;
    for component in relative.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(name) => {
                directory = openat(&directory, Path::new(name), flags, Mode::empty())
                    .map_err(|_| RunnerError::WorkingDirectory)?;
            }
            _ => return Err(RunnerError::WorkingDirectory),
        }
    }
    Ok(directory)
}

#[cfg(target_os = "linux")]
fn kill_process_group(pid: u32) {
    if let Ok(raw) = i32::try_from(pid) {
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(raw),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
}

#[cfg(target_os = "linux")]
struct OutputAccounting {
    limit: u64,
    observed: AtomicU64,
    emitted: AtomicU64,
    frames: AtomicU64,
    truncated: AtomicBool,
}

#[cfg(target_os = "linux")]
impl OutputAccounting {
    fn new(limit: u64) -> Self {
        Self {
            limit,
            observed: AtomicU64::new(0),
            emitted: AtomicU64::new(0),
            frames: AtomicU64::new(0),
            truncated: AtomicBool::new(false),
        }
    }
    fn allocate(&self, bytes: usize) -> usize {
        let _ = self
            .observed
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |total| {
                Some(total.saturating_add(bytes as u64))
            });
        // Tiny writes must not turn a bounded byte allowance into millions of
        // JSON headers. Hitting this framing bound truncates but keeps draining.
        if self
            .frames
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < MAX_OUTPUT_FRAMES).then_some(count + 1)
            })
            .is_err()
        {
            self.truncated.store(true, Ordering::Relaxed);
            return 0;
        }
        let previous = self
            .emitted
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |total| {
                Some(total.saturating_add(bytes as u64).min(self.limit))
            })
            .unwrap_or(self.limit);
        let allowed = (self.limit.saturating_sub(previous)).min(bytes as u64) as usize;
        if allowed < bytes {
            self.truncated.store(true, Ordering::Relaxed);
        }
        allowed
    }
}

#[cfg(target_os = "linux")]
async fn drain<R: AsyncRead + Unpin>(
    mut input: R,
    stream: OutputStream,
    sender: mpsc::Sender<RunnerEvent>,
    accounting: Arc<OutputAccounting>,
    failed: CancellationToken,
) -> bool {
    let mut buffer = [0u8; RAW_CHUNK_BYTES];
    loop {
        let read = tokio::select! { result=input.read(&mut buffer)=>result, _=failed.cancelled()=>return false };
        let count = match read {
            Ok(0) => return true,
            Ok(count) => count,
            Err(_) => return false,
        };
        let allowed = accounting.allocate(count);
        if allowed > 0 {
            let event = RunnerEvent::Output {
                stream,
                data: STANDARD.encode(&buffer[..allowed]),
            };
            if tokio::select! { result=sender.send(event)=>result.is_err(), _=failed.cancelled()=>true }
            {
                return false;
            }
        }
        // Read and discard after truncation; never deadlock a verbose command by
        // leaving either stdout or stderr pipe full.
    }
}

#[cfg(target_os = "linux")]
async fn write_frames<W: AsyncWrite + Unpin>(
    mut output: W,
    execution_id: Uuid,
    mut receiver: mpsc::Receiver<RunnerEvent>,
) -> Result<(), RunnerError> {
    let mut sequence = 0;
    while let Some(event) = receiver.recv().await {
        let frame = Frame {
            protocol_version: PROTOCOL_VERSION,
            execution_id: Some(execution_id),
            sequence,
            event,
        };
        write_frame(&mut output, &frame).await?;
        sequence += 1;
    }
    Ok(())
}

async fn write_frame<W: AsyncWrite + Unpin>(
    output: &mut W,
    frame: &Frame,
) -> Result<(), RunnerError> {
    let mut bytes = serde_json::to_vec(frame).map_err(|_| RunnerError::OutputChannel)?;
    bytes.push(b'\n');
    output
        .write_all(&bytes)
        .await
        .map_err(|_| RunnerError::OutputChannel)?;
    output.flush().await.map_err(|_| RunnerError::OutputChannel)
}

async fn report_error<W: AsyncWrite + Unpin>(
    output: &mut W,
    id: Option<Uuid>,
    error: &RunnerError,
) -> Result<(), RunnerError> {
    let frame = Frame {
        protocol_version: PROTOCOL_VERSION,
        execution_id: id,
        sequence: 0,
        event: RunnerEvent::Error {
            code: error.code().to_owned(),
            termination_confirmed: false,
        },
    };
    tokio::time::timeout(OUTPUT_TIMEOUT, write_frame(output, &frame))
        .await
        .map_err(|_| RunnerError::OutputChannel)?
}

/// Nonblocking pipe/socket stdio avoids an uncancellable blocking stdio thread
/// keeping the runner alive when the Kubernetes exec consumer stops reading.
#[cfg(unix)]
pub mod stdio {
    use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
    use std::{
        io,
        os::fd::{AsFd, OwnedFd},
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, unix::AsyncFd};

    pub struct Descriptor(AsyncFd<OwnedFd>);
    impl Descriptor {
        pub fn duplicate(fd: impl AsFd) -> io::Result<Self> {
            let owned = nix::unistd::dup(fd).map_err(io::Error::from)?;
            fcntl(&owned, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(io::Error::from)?;
            let flags = fcntl(&owned, FcntlArg::F_GETFL).map_err(io::Error::from)?;
            fcntl(
                &owned,
                FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK),
            )
            .map_err(io::Error::from)?;
            Ok(Self(AsyncFd::new(owned)?))
        }
    }
    impl AsyncRead for Descriptor {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            loop {
                let mut guard = std::task::ready!(self.0.poll_read_ready(cx))?;
                match guard.try_io(|fd| {
                    nix::unistd::read(fd.get_ref(), buffer.initialize_unfilled())
                        .map_err(io::Error::from)
                }) {
                    Ok(Ok(count)) => {
                        buffer.advance(count);
                        return Poll::Ready(Ok(()));
                    }
                    Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Ok(Err(error)) => return Poll::Ready(Err(error)),
                    Err(_) => continue,
                }
            }
        }
    }
    impl AsyncWrite for Descriptor {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            loop {
                let mut guard = std::task::ready!(self.0.poll_write_ready(cx))?;
                match guard
                    .try_io(|fd| nix::unistd::write(fd.get_ref(), buffer).map_err(io::Error::from))
                {
                    Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Ok(result) => return Poll::Ready(result),
                    Err(_) => continue,
                }
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}
