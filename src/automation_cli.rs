//! Dedicated worker process: no Kubernetes/OSS/guest credentials, callbacks or
//! saved JWTs. Production entry requires a normally migrated schema and grants.
use super::controller::AutomationController;
use crate::{
    db::{Database, DatabaseProcessRole},
    service_lifecycle::{run_pair, with_database_drain},
};
use axum::{Router, extract::State, http::StatusCode, routing::get};
use clap::Parser;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(
    version,
    about = "Reconcile durable UTC schedules and bounded event automations"
)]
pub struct AutomationWorkerArgs {
    #[arg(long, env = "SANDBOX_AUTOMATION_DATABASE_URL", hide_env_values = true)]
    pub database_url: String,
    #[arg(
        long,
        env = "SANDBOX_AUTOMATION_DB_MAX_CONNECTIONS",
        default_value_t = 4
    )]
    pub db_max_connections: u32,
    #[arg(
        long,
        env = "SANDBOX_AUTOMATION_DEFAULT_TTL_SECONDS",
        default_value_t = 3600
    )]
    pub default_ttl_seconds: i64,
    #[arg(
        long,
        env = "SANDBOX_AUTOMATION_MAX_TTL_SECONDS",
        default_value_t = 86400
    )]
    pub max_ttl_seconds: i64,
    #[arg(
        long,
        env = "SANDBOX_AUTOMATION_HEALTH_LISTEN",
        default_value = "0.0.0.0:8091"
    )]
    pub health_listen: SocketAddr,
    #[arg(long)]
    pub check: bool,
}
impl AutomationWorkerArgs {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            (4..=16).contains(&self.db_max_connections),
            "automation DB pool must be 4..16"
        );
        anyhow::ensure!(
            (60..=604800).contains(&self.max_ttl_seconds)
                && (60..=self.max_ttl_seconds).contains(&self.default_ttl_seconds),
            "invalid automation TTL bounds"
        );
        crate::config::validate_database_url(&self.database_url, false)?;
        let url = url::Url::parse(&self.database_url)
            .map_err(|_| anyhow::anyhow!("invalid automation database configuration"))?;
        anyhow::ensure!(
            url.username() == "sandbox_automation",
            "automation database requires its dedicated login and TLS verify-full"
        );
        Ok(())
    }
}
#[derive(Clone)]
struct Health {
    controller: Arc<AutomationController>,
    shutdown: CancellationToken,
}
async fn ready(State(state): State<Health>) -> StatusCode {
    if state.shutdown.is_cancelled() || !state.controller.is_ready() {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    // A successful prior poll cannot mask revoked runtime privileges. Share the
    // startup check with readiness, keep its existing two-second budget, and
    // expose neither SQL errors nor role/owner metadata in probe responses.
    let result =
        tokio::time::timeout(Duration::from_secs(2), state.controller.check_schema()).await;
    if matches!(result, Ok(Ok(()))) && !state.shutdown.is_cancelled() && state.controller.is_ready()
    {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
/// The binary only installs signals/logging then passes its shutdown token here.
pub async fn run(args: AutomationWorkerArgs, shutdown: CancellationToken) -> anyhow::Result<()> {
    args.validate()?;
    let database = Database::connect_for_process(
        &args.database_url,
        args.db_max_connections,
        DatabaseProcessRole::Automation,
    )
    .await?;
    with_database_drain(
        database.pool.clone(),
        run_connected(args, database, shutdown),
    )
    .await
}

async fn run_connected(
    args: AutomationWorkerArgs,
    database: Database,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let controller = Arc::new(
        AutomationController::new(
            database.clone(),
            uuid::Uuid::new_v4().to_string(),
            args.default_ttl_seconds,
            args.max_ttl_seconds,
        )
        .map_err(|_| anyhow::anyhow!("invalid automation worker configuration"))?,
    );
    controller
        .check_schema()
        .await
        .map_err(|_| anyhow::anyhow!("automation worker runtime verification failed"))?;
    if args.check {
        return Ok(());
    }
    let listener = tokio::net::TcpListener::bind(args.health_listen).await?;
    let health = Router::new()
        .route("/health/live", get(|| async { StatusCode::NO_CONTENT }))
        .route("/health/ready", get(ready))
        .with_state(Health {
            controller: controller.clone(),
            shutdown: shutdown.clone(),
        });
    let health_shutdown = shutdown.clone();
    run_pair(
        shutdown.clone(),
        controller.run(shutdown),
        serve_health(listener, health, health_shutdown),
    )
    .await
}

async fn serve_health(
    listener: tokio::net::TcpListener,
    health: Router,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let signal = shutdown.clone();
    let mut server = tokio::spawn(async move {
        axum::serve(listener, health)
            .with_graceful_shutdown(async move { signal.cancelled().await })
            .await
    });
    // The controller and health parent share one shutdown. An unexpected health
    // exit cancels the controller; an accepted durable run still finishes first.
    tokio::select! {
        result = &mut server => result??,
        _ = shutdown.cancelled() => {
            // Probe requests own no durable work. Keep the existing five-second
            // grace, then abort and join this health parent before pool drain.
            match tokio::time::timeout(Duration::from_secs(5), &mut server).await {
                Ok(result) => result??,
                Err(_) => {
                    server.abort();
                    let _ = server.await;
                    tracing::warn!("automation health listener drain deadline exceeded");
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dedicated_worker_configuration_rejects_wrong_role_tls_and_unbounded_pool() {
        let good = "postgresql://sandbox_automation:TEST_ONLY@database.example.test/sandbox?sslmode=verify-full&sslrootcert=/etc/sandbox-automation-db-ca/ca.crt";
        let parse = |url: &str| {
            AutomationWorkerArgs::try_parse_from(["sandbox-automation", "--database-url", url])
        };
        assert!(parse(good).is_ok_and(|a| a.validate().is_ok()));
        for url in [
            "postgresql://sandbox_app:TEST_ONLY@database.example.test/sandbox?sslmode=verify-full&sslrootcert=/etc/sandbox-automation-db-ca/ca.crt",
            "postgresql://sandbox_automation:TEST_ONLY@database.example.test/sandbox?sslmode=verify-full",
            "postgresql://sandbox_automation:TEST_ONLY@database.example.test/sandbox?sslmode=prefer",
            "postgresql://sandbox_automation:TEST_ONLY@database.example.test/sandbox?sslmode=verify-full&sslmode=disable",
            "postgresql://sandbox_automation:TEST_ONLY@database.example.test/sandbox?sslmode=verify-full&ssl-mode=disable",
            "postgresql://sandbox_automation:TEST_ONLY@database.example.test/sandbox?sslmode=verify-full&user=sandbox_app",
            "postgresql://sandbox_automation:TEST_ONLY@database.example.test/sandbox?sslmode=verify-full&unknown=TEST_ONLY",
            "postgresql://sandbox_automation:TEST_ONLY@database.example.test/sandbox?sslmode=verify-full&sslrootcert=relative.pem",
            "postgresql://sandbox_automation:TEST_ONLY@database.example.test/sandbox?sslmode=verify-full&sslrootcert=/run/../ca.pem",
            "postgresql://sandbox_automation:TEST_ONLY@database.example.test/sandbox?sslmode=verify-full&sslrootcert=/run/ca.pem&ssl-ca=/override.pem",
            "postgresql://sandbox_automation:TEST_ONLY@database.example.test/sandbox?sslmode=verify-full&sslrootcert=/run/ca.pem&sslrootcert=/override.pem",
            "postgresql://sandbox_automation:TEST_ONLY@127.0.0.1/sandbox?sslmode=disable",
        ] {
            assert!(parse(url).is_ok_and(|a| match a.validate() {
                Err(error) => !error.to_string().contains("TEST_ONLY"),
                Ok(()) => false,
            }));
        }
        assert!(
            AutomationWorkerArgs::try_parse_from([
                "sandbox-automation",
                "--database-url",
                good,
                "--db-max-connections",
                "128"
            ])
            .is_ok_and(|a| a.validate().is_err())
        );
    }

    #[tokio::test]
    async fn health_parent_joins_after_controller_error_without_masking_it() -> anyhow::Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let shutdown = CancellationToken::new();
        let health_shutdown = shutdown.clone();
        let (probe_tx, probe_rx) = tokio::sync::oneshot::channel();
        let health = Router::new().route("/health/live", get(|| async { StatusCode::NO_CONTENT }));
        let (outcome, probe) = tokio::join!(
            run_pair(
                shutdown.clone(),
                async {
                    probe_rx.await?;
                    anyhow::bail!("CONTROLLED_CONTROLLER_FAILURE")
                },
                serve_health(listener, health, health_shutdown),
            ),
            async {
                let response = tokio::time::timeout(
                    Duration::from_secs(1),
                    reqwest::get(format!("http://{address}/health/live")),
                )
                .await??;
                anyhow::ensure!(response.status() == StatusCode::NO_CONTENT);
                probe_tx
                    .send(())
                    .map_err(|_| anyhow::anyhow!("health observer disconnected"))?;
                Ok::<(), anyhow::Error>(())
            },
        );
        probe?;
        anyhow::ensure!(shutdown.is_cancelled());
        let error = outcome
            .err()
            .ok_or_else(|| anyhow::anyhow!("controller error was lost"))?;
        assert_eq!(error.to_string(), "CONTROLLED_CONTROLLER_FAILURE");
        Ok(())
    }
}
