use std::sync::Arc;

use clap::Parser;
use sandbox_platform::{
    api::{AppState, router_with_automations},
    auth::JwtAuthenticator,
    config::{Config, Role},
    db::{Database, DatabaseProcessRole},
    service_lifecycle::{run_pair, with_database_drain},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let arguments: Vec<_> = std::env::args_os().collect();
    if arguments.get(1).is_some_and(|arg| arg == "secrets-init") {
        return sandbox_platform::api_secret_init::command(arguments);
    }
    if arguments
        .get(1)
        .is_some_and(|arg| arg == "resource-accounting-check")
    {
        anyhow::ensure!(
            arguments.len() == 2,
            "resource-accounting-check accepts no arguments"
        );
        let url = std::env::var("SANDBOX_DATABASE_URL")
            .map_err(|_| anyhow::anyhow!("SANDBOX_DATABASE_URL is required"))?;
        let database = Database::connect(&url, 1).await?;
        let result = database.verify_runtime_role().await;
        database.pool.close().await;
        return result;
    }
    sandbox_platform::logging::init()?;
    let config = Config::parse();
    config.validate()?;
    let api_tls = if matches!(config.role, Role::Api) {
        config
            .api_tls_files()?
            .map(|files| files.load())
            .transpose()?
    } else {
        None
    };
    let process_role = match config.role {
        Role::Api => DatabaseProcessRole::Api,
        Role::Worker => DatabaseProcessRole::Worker,
        Role::Gateway => DatabaseProcessRole::Gateway,
        Role::Termination => DatabaseProcessRole::Termination,
        Role::Fencing => DatabaseProcessRole::Fencing,
        Role::VolumeDeleter => DatabaseProcessRole::VolumeDeleter,
        Role::Backup => DatabaseProcessRole::Backup,
        Role::Migrate => DatabaseProcessRole::Migrate,
    };
    let database = Database::connect_for_process(
        &config.database_url,
        config.db_max_connections,
        process_role,
    )
    .await?;
    with_database_drain(
        database.pool.clone(),
        run_connected(config, database, api_tls),
    )
    .await
}

async fn run_connected(
    config: Config,
    database: Database,
    api_tls: Option<sandbox_platform::api_tls::ApiTls>,
) -> anyhow::Result<()> {
    if matches!(config.role, Role::Migrate) {
        // Backfills need a bounded maintenance budget distinct from the API's
        // 10-second query limit. Pin this one owner connection; never relax the
        // runtime pool's timeouts or hold a second connection during migration.
        let mut connection = database.pool.acquire().await?;
        sqlx::query("SET statement_timeout='5min'")
            .execute(&mut *connection)
            .await?;
        sqlx::migrate!("./migrations").run(&mut *connection).await?;
        sqlx::raw_sql(include_str!("../../scripts/sql/roles.sql"))
            .execute(&mut *connection)
            .await?;
        let browser_installed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=37 AND success)",
        )
        .fetch_one(&mut *connection)
        .await?;
        if browser_installed {
            sqlx::raw_sql(include_str!("../../scripts/sql/browser-role.sql"))
                .execute(&mut *connection)
                .await?;
        }
        // A DBA provisions LOGIN identities separately. Apply only the narrow
        // component grants for identities that exist; any grant failure aborts.
        for (role, grants) in [
            (
                "sandbox_worker",
                include_str!("../../scripts/sql/worker-role.sql"),
            ),
            (
                "sandbox_gateway",
                include_str!("../../scripts/sql/gateway-role.sql"),
            ),
            (
                "sandbox_admission",
                include_str!("../../scripts/sql/admission-role.sql"),
            ),
            (
                "sandbox_termination",
                include_str!("../../scripts/sql/termination-role.sql"),
            ),
            (
                "sandbox_fencing",
                include_str!("../../scripts/sql/fencing-role.sql"),
            ),
            (
                "sandbox_volume_deleter",
                include_str!("../../scripts/sql/volume-deleter-role.sql"),
            ),
            (
                "sandbox_backup",
                include_str!("../../scripts/sql/backup-role.sql"),
            ),
        ] {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)")
                    .bind(role)
                    .fetch_one(&mut *connection)
                    .await?;
            if exists {
                sqlx::raw_sql(grants).execute(&mut *connection).await?;
            }
        }
        // API grants are installed even before a DBA provisions the optional
        // coordinator login. The script validates and grants that login only
        // when it exists; it never creates accounts or repairs a migration ledger.
        sqlx::raw_sql(include_str!("../../scripts/sql/automation-role.sql"))
            .execute(&mut *connection)
            .await?;
        tracing::info!("database migrations applied");
        return Ok(());
    }
    database.verify_runtime_role().await?;
    match config.role {
        Role::Api => {
            database.check_identity_api_schema().await?;
            let auth = JwtAuthenticator::new(config.auth_config()?)?;
            let cursor_signer = sandbox_platform::history::CursorSigner::from_json(
                &config.cursor_signing_key_json()?,
            )?;
            let output_reader = if let Some(output_config) = config.output_reader_config()? {
                let reader = sandbox_platform::output_store::OssOutputReader::new(output_config)?;
                reader.check_credentials().await?;
                Some(Arc::new(reader))
            } else {
                None
            };
            let state = Arc::new(AppState {
                database,
                auth,
                cursor_signer,
                output_reader,
                metrics: match config.metrics_config()? {
                    Some(config) => {
                        Some(sandbox_platform::metrics::PrometheusMetrics::new(config).await?)
                    }
                    None => None,
                },
                default_ttl_seconds: config.default_ttl_seconds,
                max_ttl_seconds: config.max_ttl_seconds,
            });
            let browser = config.browser_config()?.map(|browser| {
                Arc::new(sandbox_platform::bff::BrowserRuntime::new(
                    state.clone(),
                    browser,
                ))
            });
            if let Some(browser) = &browser {
                browser.check_schema().await?;
            }
            let files = match config.file_storage_config()? {
                Some(settings) => {
                    let files = Arc::new(sandbox_platform::file_api::FileApiRuntime {
                        app: state.clone(),
                        writer: sandbox_platform::file_store::OssFileWriter::new(
                            settings.api_upload(),
                        )?,
                        reader: sandbox_platform::file_store::OssFileReader::new(
                            settings.reader(),
                        )?,
                        max_file_bytes: settings.max_file_bytes,
                    });
                    files.check_schema().await?;
                    Some(files)
                }
                None => None,
            };
            let automations = Arc::new(sandbox_platform::automation::api::AutomationApiRuntime {
                app: state.clone(),
            });
            automations.check_schema().await?;
            let listener = tokio::net::TcpListener::bind(config.listen).await?;
            tracing::info!(address=%config.listen,tls=api_tls.is_some(),"API listening");
            let cancellation = tokio_util::sync::CancellationToken::new();
            let signal = cancellation.clone();
            let signal_task = tokio::spawn(async move {
                shutdown().await;
                signal.cancel();
            });
            let serve = sandbox_platform::api_tls::serve(
                listener,
                api_tls,
                router_with_automations(
                    state,
                    cancellation.clone(),
                    browser.clone(),
                    files,
                    Some(automations),
                ),
                cancellation.clone(),
            );
            let result = match browser {
                Some(browser) => {
                    run_pair(
                        cancellation.clone(),
                        serve,
                        browser.run_cleanup(cancellation),
                    )
                    .await
                }
                None => serve.await,
            };
            signal_task.abort();
            let _ = signal_task.await;
            result?;
        }
        Role::Worker => {
            let file_cleanup = match config.file_storage_config()? {
                Some(settings) => Some(sandbox_platform::file_cleanup::FileCleanupController::new(
                    database.clone(),
                    sandbox_platform::file_store::OssFileCleaner::new(settings.cleanup())?,
                )),
                None => None,
            };
            let (key, value) = config
                .dns_label
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("SANDBOX_DNS_LABEL must be key=value"))?;
            let runtime = sandbox_platform::runtime::KubernetesRuntime::connect().await?;
            let worker = sandbox_platform::worker::Worker::new(
                database,
                runtime,
                uuid::Uuid::new_v4().to_string(),
                config.deployment_certification_id.ok_or_else(|| {
                    anyhow::anyhow!("SANDBOX_DEPLOYMENT_CERTIFICATION_ID is required")
                })?,
                config.worker_concurrency,
                config.dns_namespace,
                [(key.to_owned(), value.to_owned())].into(),
            )?;
            let cancellation = tokio_util::sync::CancellationToken::new();
            let signal = cancellation.clone();
            let signal_task = tokio::spawn(async move {
                shutdown().await;
                signal.cancel();
            });
            tracing::info!(
                "durable compute worker started; trusted termination uses a separate controller"
            );
            let result = match file_cleanup {
                Some(cleanup) => {
                    run_pair(
                        cancellation.clone(),
                        worker.run(cancellation.clone()),
                        cleanup.run(cancellation),
                    )
                    .await
                }
                None => worker.run(cancellation).await,
            };
            signal_task.abort();
            let _ = signal_task.await;
            result?;
        }
        Role::Termination => {
            let credentials = config.nodeguard_credentials()?;
            let (key, value) = config
                .dns_label
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("SANDBOX_DNS_LABEL must be key=value"))?;
            let runtime = sandbox_platform::runtime::KubernetesRuntime::connect().await?;
            let controller = sandbox_platform::termination::TerminationController::new(
                database,
                runtime,
                credentials,
                uuid::Uuid::new_v4().to_string(),
                sandbox_platform::termination::TerminationControllerConfig {
                    concurrency: config.termination_concurrency,
                    certification_id: config.deployment_certification_id.ok_or_else(|| {
                        anyhow::anyhow!("SANDBOX_DEPLOYMENT_CERTIFICATION_ID is required")
                    })?,
                    manifests: sandbox_platform::runtime_manifest::RuntimeManifestConfig {
                        runtime_class_name: "kata-qemu".into(),
                        dns_namespace: config.dns_namespace,
                        dns_labels: [(key.to_owned(), value.to_owned())].into(),
                        ephemeral_storage_mib: 1024,
                        tmp_size_mib: 256,
                    },
                },
            )?;
            let cancellation = tokio_util::sync::CancellationToken::new();
            let signal = cancellation.clone();
            let signal_task = tokio::spawn(async move {
                shutdown().await;
                signal.cancel();
            });
            tracing::info!("trusted lifecycle controller started");
            let result = controller.run(cancellation).await;
            signal_task.abort();
            let _ = signal_task.await;
            result?;
        }
        Role::Fencing => {
            let cloud = sandbox_platform::cloud_fencing::AlibabaCloudFencing::new(
                config.cloud_fencing_config()?,
            )?;
            let controller = sandbox_platform::node_fencing::NodeFencingController::new(
                database,
                cloud,
                uuid::Uuid::new_v4().to_string(),
            )?;
            let cancellation = tokio_util::sync::CancellationToken::new();
            let signal = cancellation.clone();
            let signal_task = tokio::spawn(async move {
                shutdown().await;
                signal.cancel();
            });
            tracing::info!(
                "SYSTEM node fencing controller started; observations do not release tenant resources"
            );
            let result = controller.run(cancellation).await;
            signal_task.abort();
            let _ = signal_task.await;
            result?;
        }
        Role::VolumeDeleter => {
            let settings = config.volume_deletion_config()?;
            let cloud =
                sandbox_platform::cloud_fencing::AlibabaCloudVolumeDeletion::new(settings.cloud)?;
            let runtime = sandbox_platform::volume_deletion_runtime::VolumeDeletionRuntime::new(
                sandbox_platform::runtime::KubernetesRuntime::connect().await?,
                settings.storage,
            )?;
            let controller = sandbox_platform::volume_deletion::VolumeDeletionController::new(
                sandbox_platform::engine::OperationEngine::new(
                    database,
                    uuid::Uuid::new_v4().to_string(),
                )?,
                runtime,
                cloud,
                settings.concurrency,
            )?;
            let cancellation = tokio_util::sync::CancellationToken::new();
            let signal = cancellation.clone();
            let signal_task = tokio::spawn(async move {
                shutdown().await;
                signal.cancel();
            });
            tracing::info!("dedicated workspace destruction controller started");
            let result = controller.run(cancellation).await;
            signal_task.abort();
            let _ = signal_task.await;
            result?;
        }
        Role::Backup => {
            let vault = sandbox_platform::backup_object::BackupVaultVerifier::new(
                config.backup_vault_config()?,
            )?;
            vault.check_credentials().await?;
            let controller = sandbox_platform::backup_controller::BackupController::new(
                database,
                sandbox_platform::runtime::KubernetesRuntime::connect().await?,
                config.nodeguard_credentials()?,
                Arc::new(vault),
                uuid::Uuid::new_v4().to_string(),
                config.backup_concurrency,
            )?;
            let cancellation = tokio_util::sync::CancellationToken::new();
            let signal = cancellation.clone();
            let signal_task = tokio::spawn(async move {
                shutdown().await;
                signal.cancel();
            });
            tracing::info!("dedicated cold backup controller started");
            let result = controller.run(cancellation).await;
            signal_task.abort();
            let _ = signal_task.await;
            result?;
        }
        Role::Gateway => {
            let file_settings = config.file_storage_config()?;
            let (key, value) = config
                .dns_label
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("SANDBOX_DNS_LABEL must be key=value"))?;
            let output = sandbox_platform::output_store::OssOutputStore::new(
                sandbox_platform::output_store::OssOutputConfig {
                    endpoint: config.output_oss_endpoint.ok_or_else(|| {
                        anyhow::anyhow!("SANDBOX_OUTPUT_OSS_ENDPOINT is required")
                    })?,
                    bucket: config
                        .output_oss_bucket
                        .ok_or_else(|| anyhow::anyhow!("SANDBOX_OUTPUT_OSS_BUCKET is required"))?,
                    kms_key_id: config.output_oss_kms_key_id.ok_or_else(|| {
                        anyhow::anyhow!("SANDBOX_OUTPUT_OSS_KMS_KEY_ID is required")
                    })?,
                    sts_credentials_file: config
                        .output_sts_file
                        .ok_or_else(|| anyhow::anyhow!("SANDBOX_OUTPUT_STS_FILE is required"))?,
                },
            )?;
            let runtime = sandbox_platform::runtime::KubernetesRuntime::connect().await?;
            let certification_id = config.deployment_certification_id.ok_or_else(|| {
                anyhow::anyhow!("SANDBOX_DEPLOYMENT_CERTIFICATION_ID is required")
            })?;
            let manifests = sandbox_platform::runtime_manifest::RuntimeManifestConfig {
                runtime_class_name: "kata-qemu".into(),
                dns_namespace: config.dns_namespace,
                dns_labels: [(key.to_owned(), value.to_owned())].into(),
                ephemeral_storage_mib: 1024,
                tmp_size_mib: 256,
            };
            let file_gateway = match file_settings {
                Some(settings) => Some(sandbox_platform::file_transfer::gateway::FileGateway::new(
                    database.clone(),
                    runtime.clone(),
                    sandbox_platform::file_store::OssFileWriter::new(settings.gateway())?,
                    uuid::Uuid::new_v4().to_string(),
                    certification_id.clone(),
                    config.file_gateway_concurrency,
                    manifests.clone(),
                )?),
                None => None,
            };
            let gateway = sandbox_platform::gateway::Gateway::new(
                database,
                runtime,
                output,
                uuid::Uuid::new_v4().to_string(),
                certification_id,
                config.gateway_concurrency,
                manifests,
            )?;
            let cancellation = tokio_util::sync::CancellationToken::new();
            let signal = cancellation.clone();
            let signal_task = tokio::spawn(async move {
                shutdown().await;
                signal.cancel();
            });
            tracing::info!(
                "execution gateway starting; safety STOP completion requires trusted VM termination evidence"
            );
            let result = match file_gateway {
                Some(files) => {
                    run_pair(
                        cancellation.clone(),
                        gateway.run(cancellation.clone()),
                        files.run(cancellation),
                    )
                    .await
                }
                None => gateway.run(cancellation).await,
            };
            signal_task.abort();
            let _ = signal_task.await;
            result?;
        }
        Role::Migrate => unreachable!("migration handled above"),
    }
    Ok(())
}

async fn shutdown() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { _=interrupt=>{}, _=terminate=>{} }
    tracing::info!("shutdown requested");
}
