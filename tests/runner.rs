#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{collections::BTreeMap, path::Path};

use sandbox_platform::runner::{
    ExecBinding, ExecRequest, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES, RunnerError, read_request,
};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

fn request(cwd: &Path, argv: &[&str]) -> ExecRequest {
    ExecRequest {
        execution_id: Uuid::new_v4(),
        argv: argv.iter().map(|value| (*value).to_owned()).collect(),
        env: BTreeMap::new(),
        cwd: cwd.to_string_lossy().into_owned(),
        timeout_seconds: 5,
        output_limit_bytes: 65536,
    }
}

#[test]
fn validation_rejects_path_escape_reserved_env_and_resource_overflow() {
    let root = Path::new("/workspace");
    let valid = request(root, &["printf", "ok"]);
    assert!(valid.validate(root).is_ok());
    for cwd in ["/workspace-other", "/etc", "/workspace/../etc", "relative"] {
        let changed = ExecRequest {
            cwd: cwd.to_owned(),
            ..valid.clone()
        };
        assert_eq!(changed.validate(root), Err(RunnerError::WorkingDirectory));
    }
    for key in [
        "SANDBOX_EXECUTION_ID",
        "SANDBOX_CUSTOM",
        "PATH",
        "HOME",
        "TMPDIR",
        "1INVALID",
    ] {
        let changed = ExecRequest {
            env: BTreeMap::from([(key.to_owned(), "value".to_owned())]),
            ..valid.clone()
        };
        assert!(changed.validate(root).is_err());
    }
    for timeout in [0, 3601, u64::MAX] {
        assert!(
            ExecRequest {
                timeout_seconds: timeout,
                ..valid.clone()
            }
            .validate(root)
            .is_err()
        );
    }
    assert!(
        ExecRequest {
            output_limit_bytes: MAX_OUTPUT_BYTES + 1,
            ..valid.clone()
        }
        .validate(root)
        .is_err()
    );
    assert!(
        ExecRequest {
            argv: vec!["x".repeat(MAX_INPUT_BYTES + 1)],
            ..valid.clone()
        }
        .validate(root)
        .is_err()
    );
    assert!(
        ExecRequest {
            argv: vec!["true".to_owned(); 65],
            ..valid.clone()
        }
        .validate(root)
        .is_err()
    );
    assert!(
        ExecRequest {
            argv: vec!["bad\0executable".to_owned()],
            ..valid
        }
        .validate(root)
        .is_err()
    );
}

#[tokio::test]
async fn one_strict_json_object_and_bounded_input_are_required() {
    let valid = request(Path::new("/workspace"), &["true"]);
    let bytes = serde_json::to_vec(&valid).unwrap();
    assert_eq!(
        read_request(bytes.as_slice()).await.unwrap().execution_id,
        valid.execution_id
    );
    let mut extra = serde_json::to_value(&valid).unwrap();
    extra["shell"] = serde_json::json!(true);
    assert_eq!(
        read_request(serde_json::to_vec(&extra).unwrap().as_slice())
            .await
            .unwrap_err(),
        RunnerError::InvalidJson
    );
    let two = format!("{}{}", String::from_utf8(bytes.clone()).unwrap(), "{}");
    assert_eq!(
        read_request(two.as_bytes()).await.unwrap_err(),
        RunnerError::InvalidJson
    );
    let duplicate = String::from_utf8(bytes)
        .unwrap()
        .replace("\"env\":{}", "\"env\":{\"A\":\"1\",\"A\":\"2\"}");
    assert_eq!(
        read_request(duplicate.as_bytes()).await.unwrap_err(),
        RunnerError::InvalidJson
    );
    let oversized = vec![b' '; MAX_INPUT_BYTES + 1];
    assert_eq!(
        read_request(oversized.as_slice()).await.unwrap_err(),
        RunnerError::InputTooLarge
    );
}

#[tokio::test]
async fn parsing_waits_for_eof_instead_of_starting_after_a_json_prefix() {
    let valid = request(Path::new("/workspace"), &["true"]);
    let (mut sender, receiver) = tokio::io::duplex(4096);
    let task = tokio::spawn(read_request(receiver));
    sender
        .write_all(&serde_json::to_vec(&valid).unwrap())
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert!(!task.is_finished());
    sender.shutdown().await.unwrap();
    assert_eq!(
        task.await.unwrap().unwrap().execution_id,
        valid.execution_id
    );
}

#[tokio::test]
async fn cancellation_before_eof_does_not_wait_for_input_or_start_a_process() {
    let (_sender, receiver) = tokio::io::duplex(4096);
    let cancellation = tokio_util::sync::CancellationToken::new();
    cancellation.cancel();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        sandbox_platform::runner::run_exec(
            receiver,
            tokio::io::sink(),
            Path::new("/workspace"),
            cancellation,
            ExecBinding {
                execution_id: Uuid::new_v4(),
                dispatch_attempt_id: Uuid::new_v4(),
            },
        ),
    )
    .await
    .unwrap();
    assert_eq!(result.unwrap_err(), RunnerError::Cancelled);
}

#[tokio::test]
async fn stdin_cannot_substitute_a_different_execution_identity() {
    let request = request(Path::new("/workspace"), &["true"]);
    let input = serde_json::to_vec(&request).unwrap();
    let result = sandbox_platform::runner::run_exec(
        input.as_slice(),
        tokio::io::sink(),
        Path::new("/workspace"),
        tokio_util::sync::CancellationToken::new(),
        ExecBinding {
            execution_id: Uuid::new_v4(),
            dispatch_attempt_id: Uuid::new_v4(),
        },
    )
    .await;
    assert_eq!(
        result.unwrap_err(),
        RunnerError::InvalidRequest("execution identity mismatch")
    );
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn non_linux_execution_fails_closed_instead_of_weaker_path_resolution() {
    use sandbox_platform::runner::execute_request;
    let result = execute_request(
        request(Path::new("/workspace"), &["true"]),
        tokio::io::sink(),
        Path::new("/workspace"),
        tokio_util::sync::CancellationToken::new(),
    )
    .await;
    assert_eq!(result.unwrap_err(), RunnerError::UnsupportedPlatform);
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use sandbox_platform::runner::{Frame, OutputStream, RunSummary, RunnerEvent, execute_request};
    use std::{
        os::unix::fs::symlink,
        time::{Duration, Instant},
    };
    use tokio::io::AsyncReadExt;
    use tokio_util::sync::CancellationToken;

    async fn capture(
        request: ExecRequest,
        root: &Path,
    ) -> (Result<RunSummary, RunnerError>, Vec<Frame>) {
        let (output, mut reader) = tokio::io::duplex(64 * 1024);
        let collector = tokio::spawn(async move {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).await.unwrap();
            bytes
        });
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            execute_request(request, output, root, CancellationToken::new()),
        )
        .await
        .unwrap();
        let bytes = collector.await.unwrap();
        let frames: Vec<Frame> = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        for (index, frame) in frames.iter().enumerate() {
            assert_eq!(frame.sequence, index as u64);
            assert_eq!(frame.protocol_version, 1);
        }
        (result, frames)
    }

    fn output(frames: &[Frame]) -> (Vec<u8>, Vec<u8>) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        for frame in frames {
            if let RunnerEvent::Output { stream, data } = &frame.event {
                assert!(data.len() <= 8192);
                let decoded = STANDARD.decode(data).unwrap();
                assert!(decoded.len() <= 6144);
                match stream {
                    OutputStream::Stdout => stdout.extend(decoded),
                    OutputStream::Stderr => stderr.extend(decoded),
                }
            }
        }
        (stdout, stderr)
    }

    #[tokio::test]
    async fn real_command_preserves_exit_code_stdout_stderr_and_binary_bytes() {
        let root = tempfile::tempdir().unwrap();
        let (result, frames) = capture(
            request(
                root.path(),
                &[
                    "/bin/sh",
                    "-c",
                    "printf '\\377\\000'; printf problem >&2; exit 7",
                ],
            ),
            root.path(),
        )
        .await;
        let summary = result.unwrap();
        assert_eq!(summary.exit_code, Some(7));
        assert!(!summary.termination_confirmed);
        assert!(summary.output_complete);
        assert!(matches!(
            frames.first().unwrap().event,
            RunnerEvent::Started { .. }
        ));
        assert!(matches!(
            frames.last().unwrap().event,
            RunnerEvent::Exited { .. }
        ));
        assert_eq!(output(&frames), (vec![255, 0], b"problem".to_vec()));
    }

    #[tokio::test]
    async fn argv_is_never_shell_interpolated_and_child_stdin_is_null() {
        let root = tempfile::tempdir().unwrap();
        let literal = "$(touch should-not-exist); literal";
        let (result, frames) = capture(
            request(root.path(), &["/usr/bin/printf", "%s", literal]),
            root.path(),
        )
        .await;
        assert_eq!(result.unwrap().exit_code, Some(0));
        assert_eq!(output(&frames).0, literal.as_bytes());
        assert!(!root.path().join("should-not-exist").exists());
        let (result, frames) = capture(
            request(
                root.path(),
                &[
                    "/bin/sh",
                    "-c",
                    "if read value; then exit 9; else printf eof; fi",
                ],
            ),
            root.path(),
        )
        .await;
        assert_eq!(result.unwrap().exit_code, Some(0));
        assert_eq!(output(&frames).0, b"eof");
    }

    #[tokio::test]
    async fn environment_is_cleared_and_only_allowlisted_defaults_and_input_remain() {
        let root = tempfile::tempdir().unwrap();
        let mut req = request(root.path(), &["/usr/bin/env"]);
        req.env.insert("HELLO".to_owned(), "world".to_owned());
        let (_, frames) = capture(req, root.path()).await;
        let stdout = String::from_utf8(output(&frames).0).unwrap();
        let values: BTreeMap<_, _> = stdout
            .lines()
            .map(|line| line.split_once('=').unwrap())
            .collect();
        assert_eq!(values.len(), 8);
        assert_eq!(values["PATH"], "/usr/local/bin:/usr/bin:/bin");
        assert_eq!(values["HELLO"], "world");
        assert_eq!(values["HOME"], root.path().to_str().unwrap());
    }

    #[tokio::test]
    async fn output_quota_truncates_both_streams_but_continues_draining_to_exit() {
        let root = tempfile::tempdir().unwrap();
        let mut req = request(
            root.path(),
            &[
                "/bin/sh",
                "-c",
                "head -c 1048576 /dev/zero; head -c 1048576 /dev/zero >&2",
            ],
        );
        req.output_limit_bytes = 1024;
        let (result, frames) = capture(req, root.path()).await;
        let summary = result.unwrap();
        let (stdout, stderr) = output(&frames);
        assert_eq!(summary.exit_code, Some(0));
        assert!(summary.output_truncated);
        assert!(!summary.output_complete);
        assert_eq!(summary.bytes_observed, 2 * 1048576);
        assert_eq!(summary.bytes_emitted, 1024);
        assert_eq!(stdout.len() + stderr.len(), 1024);
    }

    #[tokio::test]
    async fn timeout_kills_cooperatively_but_never_claims_vm_termination() {
        let root = tempfile::tempdir().unwrap();
        let mut req = request(root.path(), &["/bin/sh", "-c", "sleep 30 & wait"]);
        req.timeout_seconds = 1;
        let started = Instant::now();
        let (result, frames) = capture(req, root.path()).await;
        let summary = result.unwrap();
        assert!(summary.timed_out);
        assert!(!summary.termination_confirmed);
        assert!(started.elapsed() < Duration::from_secs(6));
        assert!(matches!(
            frames.last().unwrap().event,
            RunnerEvent::TimedOut { .. }
        ));
    }

    #[tokio::test]
    async fn descendants_holding_pipes_cannot_prevent_a_bounded_partial_result() {
        let root = tempfile::tempdir().unwrap();
        let started = Instant::now();
        let (result, _) = capture(
            request(root.path(), &["/bin/sh", "-c", "sleep 30 & exit 0"]),
            root.path(),
        )
        .await;
        let summary = result.unwrap();
        assert_eq!(summary.exit_code, Some(0));
        assert!(!summary.output_complete);
        assert!(!summary.termination_confirmed);
        assert!(started.elapsed() < Duration::from_secs(6));
    }

    #[tokio::test]
    async fn slow_protocol_reader_does_not_disable_execution_timeout() {
        let root = tempfile::tempdir().unwrap();
        let mut req = request(
            root.path(),
            &["/bin/sh", "-c", "head -c 1048576 /dev/zero; sleep 30"],
        );
        req.timeout_seconds = 1;
        let (writer, _unread) = tokio::io::duplex(1);
        let started = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(8),
            execute_request(req, writer, root.path(), CancellationToken::new()),
        )
        .await
        .unwrap();
        assert_eq!(result.unwrap_err(), RunnerError::OutputChannel);
        assert!(started.elapsed() < Duration::from_secs(8));
    }

    #[tokio::test]
    async fn symlink_cwd_escape_is_rejected_and_nested_directory_is_pinned() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.path().join("escape")).unwrap();
        let (result, frames) = capture(
            request(&root.path().join("escape"), &["/bin/pwd"]),
            root.path(),
        )
        .await;
        assert_eq!(result.unwrap_err(), RunnerError::WorkingDirectory);
        assert!(matches!(frames[0].event, RunnerEvent::Error { .. }));
        let nested = root.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let (result, frames) = capture(request(&nested, &["/bin/pwd"]), root.path()).await;
        assert_eq!(result.unwrap().exit_code, Some(0));
        assert_eq!(
            String::from_utf8(output(&frames).0).unwrap().trim(),
            nested.to_str().unwrap()
        );
    }

    #[tokio::test]
    async fn spawn_failure_is_a_protocol_error_without_a_started_receipt() {
        let root = tempfile::tempdir().unwrap();
        let (result, frames) = capture(
            request(root.path(), &["/no/such/controlled-test-binary"]),
            root.path(),
        )
        .await;
        assert_eq!(result.unwrap_err(), RunnerError::SpawnFailed);
        assert_eq!(frames.len(), 1);
        assert!(matches!(frames[0].event, RunnerEvent::Error { .. }));
    }
}
