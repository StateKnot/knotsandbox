//! Dedicated durable automation worker. Database role and grants are checked
//! after ordinary migrations; no Kubernetes, guest or cloud credentials.
use clap::Parser;
use sandbox_platform::automation::cli::{AutomationWorkerArgs, run};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sandbox_platform::logging::init()?;
    let args = AutomationWorkerArgs::parse();
    let shutdown = CancellationToken::new();
    let signal_token = shutdown.clone();
    let signal = tokio::spawn(async move {
        #[cfg(unix)]
        {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut terminate) => {
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {},
                        _ = terminate.recv() => {},
                    }
                }
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        signal_token.cancel();
    });
    let outcome = run(args, shutdown.clone()).await;
    shutdown.cancel();
    signal.abort();
    let _ = signal.await;
    outcome
}
