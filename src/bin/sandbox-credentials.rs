use clap::Parser;
use sandbox_platform::cloud_fencing::credential_agent::{
    CredentialAgent, CredentialAgentConfig, check_credentials,
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version,
    about = "Mint and atomically rotate a dedicated storage workload's short-lived credentials"
)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long, conflicts_with = "check")]
    once: bool,
    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sandbox_platform::logging::init()?;
    let args = Args::parse();
    let config = CredentialAgentConfig::from_file(&args.config)?;
    if args.check {
        return check_credentials(&config);
    }
    let shutdown = tokio_util::sync::CancellationToken::new();
    let signals = shutdown.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut terminate) => {
                    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
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
        signals.cancel();
    });
    CredentialAgent::new(config)?.run(args.once, shutdown).await
}
