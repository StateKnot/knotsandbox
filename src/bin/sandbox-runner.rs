use std::{path::Path, process::ExitCode, time::Duration};

use sandbox_platform::runner::{
    ExecBinding, PROTOCOL_VERSION, RunnerError, run_exec, stdio::Descriptor,
};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

enum Command {
    Idle,
    Health,
    Exec(ExecBinding),
    FileTransfer(sandbox_platform::file_transfer::protocol::FileBinding),
}

fn parse_command(args: &[String]) -> Option<Command> {
    match args {
        [action] if action == "idle" => Some(Command::Idle),
        [action] if action == "health" => Some(Command::Health),
        [
            action,
            execution_flag,
            execution_id,
            attempt_flag,
            attempt_id,
        ] if action == "exec"
            && execution_flag == "--execution-id"
            && attempt_flag == "--dispatch-attempt-id" =>
        {
            let execution_id = Uuid::parse_str(execution_id).ok()?;
            let dispatch_attempt_id = Uuid::parse_str(attempt_id).ok()?;
            if execution_id.is_nil() || dispatch_attempt_id.is_nil() {
                return None;
            }
            Some(Command::Exec(ExecBinding {
                execution_id,
                dispatch_attempt_id,
            }))
        }
        [action, transfer_flag, transfer_id, attempt_flag, attempt_id]
            if action == "file-transfer"
                && transfer_flag == "--transfer-id"
                && attempt_flag == "--dispatch-attempt-id" =>
        {
            let transfer_id = Uuid::parse_str(transfer_id).ok()?;
            let dispatch_attempt_id = Uuid::parse_str(attempt_id).ok()?;
            if transfer_id.is_nil() || dispatch_attempt_id.is_nil() {
                return None;
            }
            Some(Command::FileTransfer(
                sandbox_platform::file_transfer::protocol::FileBinding {
                    transfer_id,
                    dispatch_attempt_id,
                },
            ))
        }
        _ => None,
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = parse_command(&args) else {
        eprintln!(
            "usage: sandbox-runner idle|health|exec --execution-id UUID --dispatch-attempt-id UUID|file-transfer --transfer-id UUID --dispatch-attempt-id UUID"
        );
        return ExitCode::from(64);
    };
    match command {
        Command::Idle => match idle().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(70),
        },
        Command::Health => {
            let result = async {
                let mut output = Descriptor::duplicate(std::io::stdout())?;
                let mut message=serde_json::to_vec(&serde_json::json!({
                    "protocol_version":PROTOCOL_VERSION,"runner_version":env!("CARGO_PKG_VERSION"),"status":"ok"
                })).map_err(std::io::Error::other)?;
                message.push(b'\n');
                output.write_all(&message).await
            };
            match tokio::time::timeout(Duration::from_secs(2), result).await {
                Ok(Ok(())) => ExitCode::SUCCESS,
                _ => ExitCode::from(70),
            }
        }
        Command::FileTransfer(binding) => {
            let result = sandbox_platform::file_transfer::runner::run_file_transfer(
                &mut std::io::stdin().lock(),
                &mut std::io::stdout().lock(),
                Path::new("/workspace"),
                binding,
            );
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::from(70),
            }
        }
        Command::Exec(binding) => {
            let input = match Descriptor::duplicate(std::io::stdin()) {
                Ok(input) => input,
                Err(_) => return ExitCode::from(70),
            };
            let output = match Descriptor::duplicate(std::io::stdout()) {
                Ok(output) => output,
                Err(_) => return ExitCode::from(70),
            };
            let cancellation = CancellationToken::new();
            let signal_cancellation = cancellation.clone();
            let signals = tokio::spawn(async move {
                if shutdown_signal().await.is_ok() {
                    signal_cancellation.cancel();
                }
            });
            let result = run_exec(
                input,
                output,
                Path::new("/workspace"),
                cancellation,
                binding,
            )
            .await;
            signals.abort();
            let _ = signals.await;
            match result {
                Ok(_) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("runner error: {}", error.code());
                    match error {
                        RunnerError::InputTooLarge
                        | RunnerError::InputTimeout
                        | RunnerError::InvalidJson
                        | RunnerError::InvalidRequest(_)
                        | RunnerError::WorkingDirectory => ExitCode::from(64),
                        _ => ExitCode::from(70),
                    }
                }
            }
        }
    }
}

async fn shutdown_signal() -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    tokio::select! { _=terminate.recv()=>{}, _=interrupt.recv()=>{} }
    Ok(())
}

/// PID 1 never discovers or runs workspace files. It only waits for shutdown
/// and reaps orphaned children, so repeated executions cannot leak zombies.
async fn idle() -> std::io::Result<()> {
    use nix::{
        errno::Errno,
        sys::wait::{WaitPidFlag, WaitStatus, waitpid},
        unistd::Pid,
    };
    use tokio::signal::unix::{SignalKind, signal};
    let mut children = signal(SignalKind::child())?;
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            result=&mut shutdown=>return result,
            _=children.recv()=>{
                loop {
                    match waitpid(Pid::from_raw(-1),Some(WaitPidFlag::WNOHANG)) {
                        Ok(WaitStatus::Exited(..)|WaitStatus::Signaled(..))=>continue,
                        Ok(_)|Err(Errno::ECHILD)=>break,
                        Err(_)=>break,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_transfer_requires_fixed_flags_and_non_nil_identities() {
        let transfer = Uuid::new_v4().to_string();
        let attempt = Uuid::new_v4().to_string();
        let valid = [
            "file-transfer",
            "--transfer-id",
            &transfer,
            "--dispatch-attempt-id",
            &attempt,
        ]
        .map(str::to_owned);
        assert!(matches!(
            parse_command(&valid),
            Some(Command::FileTransfer(_))
        ));
        for index in [2, 4] {
            let mut bad = valid.clone();
            bad[index] = Uuid::nil().to_string();
            assert!(parse_command(&bad).is_none());
        }
        let mut wrong_flag = valid.clone();
        wrong_flag[1] = "--execution-id".into();
        assert!(parse_command(&wrong_flag).is_none());
        let mut extra = valid.to_vec();
        extra.push("--workspace=/tmp".into());
        assert!(parse_command(&extra).is_none());
    }

    #[test]
    fn exec_requires_both_explicit_non_nil_identities_and_no_extra_arguments() {
        let execution = Uuid::new_v4().to_string();
        let attempt = Uuid::new_v4().to_string();
        let valid = [
            "exec",
            "--execution-id",
            &execution,
            "--dispatch-attempt-id",
            &attempt,
        ]
        .map(str::to_owned);
        assert!(matches!(parse_command(&valid), Some(Command::Exec(_))));
        assert!(parse_command(&["exec".into()]).is_none());
        for index in [2, 4] {
            let mut bad = valid.clone();
            bad[index] = Uuid::nil().to_string();
            assert!(parse_command(&bad).is_none());
            bad[index] = "invalid".into();
            assert!(parse_command(&bad).is_none());
        }
        let mut extra = valid.to_vec();
        extra.push("--shell".into());
        assert!(parse_command(&extra).is_none());
        assert!(parse_command(&["health".into(), "extra".into()]).is_none());
        assert!(matches!(
            parse_command(&["idle".into()]),
            Some(Command::Idle)
        ));
        assert!(matches!(
            parse_command(&["health".into()]),
            Some(Command::Health)
        ));
    }
}
