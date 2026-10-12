use clap::Parser;
use sandbox_platform::{
    admission::{AdmissionConfig, AdmissionService, router},
    db::{Database, DatabaseProcessRole},
    service_lifecycle::with_database_drain,
    tls::{AdmissionTlsFiles, read_admission_configuration, serve_admission},
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(
    name = "sandbox-admission",
    about = "mTLS-only validating admission for controlled sandbox workloads"
)]
struct Args {
    /// Check only the fixed local listener; does not read config or secrets.
    #[arg(long)]
    probe_local: bool,
    #[arg(long, default_value = "0.0.0.0:8443", conflicts_with = "probe_local")]
    listen: SocketAddr,
    #[arg(
        long,
        required_unless_present = "probe_local",
        conflicts_with = "probe_local"
    )]
    config: Option<PathBuf>,
    // The env also exists in exec probes but is unused on that path.
    #[arg(
        long,
        env = "SANDBOX_ADMISSION_DATABASE_URL",
        hide_env_values = true,
        required_unless_present = "probe_local"
    )]
    database_url: Option<String>,
    #[arg(
        long,
        required_unless_present = "probe_local",
        conflicts_with = "probe_local"
    )]
    tls_certificate: Option<PathBuf>,
    #[arg(
        long,
        required_unless_present = "probe_local",
        conflicts_with = "probe_local"
    )]
    tls_key: Option<PathBuf>,
    #[arg(
        long,
        required_unless_present = "probe_local",
        conflicts_with = "probe_local"
    )]
    apiserver_client_ca: Option<PathBuf>,
}

fn required<T>(value: Option<T>) -> anyhow::Result<T> {
    value.ok_or_else(|| anyhow::anyhow!("Required admission startup option missing"))
}

fn validate_database_url(value: &str) -> anyhow::Result<()> {
    sandbox_platform::config::validate_database_url(value, false)?;
    let url =
        url::Url::parse(value).map_err(|_| anyhow::anyhow!("Invalid admission database URL"))?;
    anyhow::ensure!(
        url.username() == "sandbox_admission",
        "Admission requires its dedicated database role"
    );
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.probe_local {
        tokio::time::timeout(
            Duration::from_secs(1),
            tokio::net::TcpStream::connect("127.0.0.1:8443"),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Admission local listener probe timed out"))?
        .map_err(|_| anyhow::anyhow!("Admission local listener unavailable"))?;
        return Ok(());
    }
    sandbox_platform::logging::init()?;
    let database_url = required(args.database_url)?;
    validate_database_url(&database_url)?;
    let config: AdmissionConfig =
        serde_json::from_slice(&read_admission_configuration(&required(args.config)?)?)
            .map_err(|_| anyhow::anyhow!("Invalid admission configuration"))?;
    config.validate()?;
    let tls = AdmissionTlsFiles {
        certificate: required(args.tls_certificate)?,
        private_key: required(args.tls_key)?,
        apiserver_ca: required(args.apiserver_client_ca)?,
    }
    .load()?;
    let database =
        Database::connect_for_process(&database_url, 20, DatabaseProcessRole::Admission).await?;
    with_database_drain(
        database.pool.clone(),
        run_connected(args.listen, database, config, tls),
    )
    .await
}

async fn run_connected(
    listen: SocketAddr,
    database: Database,
    config: AdmissionConfig,
    tls: axum_server::tls_rustls::RustlsConfig,
) -> anyhow::Result<()> {
    database.verify_runtime_role().await?;
    let mut kube_config = kube::Config::infer()
        .await
        .map_err(|_| anyhow::anyhow!("Cannot load trusted Kubernetes configuration"))?;
    anyhow::ensure!(
        !kube_config.accept_invalid_certs && kube_config.cluster_url.scheme_str() == Some("https"),
        "Kubernetes API must use verified HTTPS"
    );
    kube_config.connect_timeout = Some(Duration::from_secs(2));
    kube_config.read_timeout = Some(Duration::from_secs(3));
    let kubernetes = kube::Client::try_from(kube_config)
        .map_err(|_| anyhow::anyhow!("Cannot create trusted Kubernetes client"))?;
    let service = Arc::new(AdmissionService {
        database,
        kubernetes,
        config,
    });
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    let signal_task = tokio::spawn(async move {
        #[cfg(unix)]
        {
            if let Ok(mut term) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
            } else {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        signal.cancel();
    });
    let result = serve_admission(listener, tls, router(service), shutdown).await;
    signal_task.abort();
    let _ = signal_task.await;
    result.map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_probe_has_a_fixed_target_and_does_not_require_startup_secrets() {
        assert!(Args::try_parse_from(["sandbox-admission", "--probe-local"]).is_ok());
        assert!(
            Args::try_parse_from([
                "sandbox-admission",
                "--probe-local",
                "--listen",
                "127.0.0.1:1"
            ])
            .is_err()
        );
        assert!(
            Args::try_parse_from([
                "sandbox-admission",
                "--probe-local",
                "--config",
                "/ignored.json"
            ])
            .is_err()
        );
        assert!(Args::try_parse_from(["sandbox-admission"]).is_err());
    }

    #[test]
    fn production_admission_requires_canonical_verified_tls_and_its_own_role() {
        const URL: &str = "postgres://sandbox_admission:PUBLIC_TEST_ONLY@database.example.test:5432/sandbox?sslmode=verify-full&sslrootcert=/etc/sandbox-admission-db-ca/ca.crt";
        assert!(validate_database_url(URL).is_ok());
        for invalid in [
            URL.replace("verify-full", "require"),
            URL.replace("sandbox_admission", "sandbox_owner"),
            URL.replace("sslrootcert=/", "sslrootcert=relative/"),
            format!("{URL}&host=other.example.test"),
        ] {
            assert!(validate_database_url(&invalid).is_err());
        }
    }
}
