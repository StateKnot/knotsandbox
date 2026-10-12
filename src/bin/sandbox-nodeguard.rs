#[cfg(target_os = "linux")]
mod linux {
    use clap::Parser;
    use sandbox_platform::{
        nodeguard::{
            cri::CriProxy,
            cri_proto::runtime_service_server::RuntimeServiceServer,
            host::{HostObserver, HostProfile},
            journal::GateJournal,
            metrics_server,
            protocol::NodeBinding,
            server,
        },
        tls::{control_mutual_tls, metrics_mutual_tls, serve_control, serve_metrics},
    };
    use serde::Deserialize;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{File, OpenOptions},
        net::SocketAddr,
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        path::{Path, PathBuf},
        sync::Arc,
        time::Duration,
    };
    use tokio_util::sync::CancellationToken;
    #[derive(Parser)]
    #[command(
        name = "sandbox-nodeguard",
        about = "Trusted host CRI gate and kernel termination observer"
    )]
    pub struct Args {
        #[arg(long, default_value = "/etc/sandbox-nodeguard/config.json")]
        config: PathBuf,
        /// One-time provisioning only, before enabling managed runtime traffic.
        #[arg(long)]
        initialize_journal: bool,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        node: NodeBinding,
        profile_file: PathBuf,
        listen: SocketAddr,
        tls_certificate: PathBuf,
        tls_key: PathBuf,
        controller_client_ca: PathBuf,
        metrics: Option<MetricsConfig>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct MetricsConfig {
        listen: SocketAddr,
        deployment: String,
        scraper_client_ca: PathBuf,
    }
    fn control_address(address: SocketAddr) -> anyhow::Result<()> {
        let private = match address.ip() {
            std::net::IpAddr::V4(ip) => ip.is_private(),
            std::net::IpAddr::V6(ip) => ip.is_unique_local(),
        };
        anyhow::ensure!(
            private && address.port() == 9444,
            "Host control must bind a private RFC1918/ULA address on port 9444"
        );
        Ok(())
    }
    fn read(path: &Path, private: bool) -> anyhow::Result<Vec<u8>> {
        let m = std::fs::symlink_metadata(path)?;
        anyhow::ensure!(
            m.is_file()
                && m.uid() == 0
                && m.mode() & if private { 0o077 } else { 0o022 } == 0
                && m.len() <= 1024 * 1024,
            "Untrusted host configuration or certificate permissions"
        );
        Ok(std::fs::read(path)?)
    }
    fn directory(path: &Path) -> anyhow::Result<()> {
        if !path.exists() {
            std::fs::create_dir_all(path)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
        let m = std::fs::symlink_metadata(path)?;
        anyhow::ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
            "Host guard directory must be root-owned mode 0700"
        );
        Ok(())
    }
    pub async fn run() -> anyhow::Result<()> {
        sandbox_platform::logging::init()?;
        let args = Args::parse();
        let config: Config = serde_json::from_slice(&read(&args.config, true)?)?;
        control_address(config.listen)?;
        let profile_bytes = read(&config.profile_file, true)?;
        anyhow::ensure!(
            hex::encode(Sha256::digest(&profile_bytes)) == config.node.profile_sha256,
            "Certified runtime profile hash differs"
        );
        let profile: HostProfile = serde_json::from_slice(&profile_bytes)?;
        let observer = Arc::new(HostObserver::new(profile, config.node.clone())?);
        directory(Path::new("/var/lib/sandbox-nodeguard"))?;
        directory(Path::new("/run/sandbox-nodeguard"))?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open("/var/lib/sandbox-nodeguard/daemon.lock")?;
        lock.try_lock()?; // Held for the entire process; no second journal writer.
        let database_path = Path::new("/var/lib/sandbox-nodeguard/state.sqlite3");
        let marker_path = Path::new("/var/lib/sandbox-nodeguard/initialized.json");
        if args.initialize_journal {
            use std::io::Write;
            anyhow::ensure!(
                !database_path.exists(),
                "Refusing to replace an existing journal; node fencing and re-enrollment are required"
            );
            let mut marker = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(marker_path)?;
            marker.write_all(&serde_json::to_vec(&config.node)?)?;
            marker.sync_all()?;
            File::open("/var/lib/sandbox-nodeguard")?.sync_all()?;
        } else {
            let enrolled: NodeBinding = serde_json::from_slice(&read(marker_path, true)?)?;
            anyhow::ensure!(
                enrolled == config.node,
                "A changed boot/profile/node requires fresh trusted enrollment"
            );
            let meta = std::fs::symlink_metadata(database_path)?;
            anyhow::ensure!(
                meta.is_file() && meta.uid() == 0,
                "The initialized journal is missing or untrusted; never reconstruct it from an empty state"
            );
        }
        let journal = GateJournal::open(
            Path::new("/var/lib/sandbox-nodeguard/state.sqlite3"),
            config.node,
        )
        .await?;
        // Keep an outer journal owner so every startup error after open(), as
        // well as normal listener shutdown, drains SQLite under daemon.lock.
        let outcome = async {
        let proxy = Arc::new(CriProxy::connect(journal.clone(), observer).await?);
        let covered = proxy.verify_startup().await.is_ok();
        if args.initialize_journal {
            anyhow::ensure!(
                covered,
                "Provisioning cannot establish initial runtime coverage; keep the node isolated"
            );
            return Ok(());
        }
        if !covered {
            tracing::error!(
                "nodeguard remains closed: startup coverage or prior runtime result is unknown"
            );
        }
        let tls = control_mutual_tls(
            &read(&config.tls_certificate, false)?,
            &read(&config.tls_key, true)?,
            &read(&config.controller_client_ca, false)?,
        )?;
        let metrics = if let Some(metrics) = config.metrics {
            use rustls::pki_types::{CertificateDer, pem::PemObject};
            anyhow::ensure!(
                metrics.listen.ip() == config.listen.ip()
                    && metrics.listen.port() == 9445
                    && config.listen.port() == 9444,
                "Metrics must use the same private host address on the dedicated port 9445"
            );
            let metrics_ca = read(&metrics.scraper_client_ca, false)?;
            let control_ca = read(&config.controller_client_ca, false)?;
            let readers =
                CertificateDer::pem_slice_iter(&metrics_ca).collect::<Result<Vec<_>, _>>()?;
            let controllers =
                CertificateDer::pem_slice_iter(&control_ca).collect::<Result<Vec<_>, _>>()?;
            anyhow::ensure!(
                !readers.is_empty()
                    && !controllers.is_empty()
                    && !readers.iter().any(|r| controllers.contains(r)),
                "Scraper trust roots must be distinct from controller trust roots"
            );
            let tls = metrics_mutual_tls(
                &read(&config.tls_certificate, false)?,
                &read(&config.tls_key, true)?,
                &metrics_ca,
            )?;
            Some((
                tokio::net::TcpListener::bind(metrics.listen).await?,
                tls,
                metrics_server::router(proxy.clone(), metrics.deployment)?,
            ))
        } else {
            None
        };
        let socket = Path::new("/run/sandbox-nodeguard/cri.sock");
        if socket.exists() {
            std::fs::remove_file(socket)?;
        }
        let listener = tokio::net::UnixListener::bind(socket)?;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
        let transport = sandbox_platform::nodeguard::cri::RuntimeTransport::new();
        let incoming = futures_util::stream::unfold((listener, transport.clone()), |(listener, transport)| async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _))
                        if stream
                            .peer_cred()
                            .is_ok_and(|credentials| credentials.uid() == 0) =>
                    {
                        return Some((transport.wrap(stream), (listener, transport)));
                    }
                    Ok(_) => continue,
                    Err(error) => return Some((Err(error), (listener, transport))),
                }
            }
        });
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        tokio::spawn(async move {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
            tokio::select! {_=tokio::signal::ctrl_c()=>{},_=async{if let Some(ref mut term)=term{term.recv().await;}else{std::future::pending::<()>().await;}}=>{}}
            stop.cancel();
        });
        let runtime = tonic::transport::Server::builder()
            .concurrency_limit_per_connection(64)
            .add_service(
                RuntimeServiceServer::new((*proxy).clone())
                    .max_decoding_message_size(16 * 1024 * 1024)
                    .max_encoding_message_size(16 * 1024 * 1024),
            )
            .serve_with_incoming_shutdown(incoming, cancel.cancelled());
        // End only pure READ handshakes/watch bodies on cancellation. Keep
        // the actual tonic parent until its remaining connections drain;
        // mutation/observer/SQLite ownership is settled below as before.
        let runtime = proxy.serve_read_parent(runtime, &cancel, &transport);
        let control = serve_control(
            tokio::net::TcpListener::bind(config.listen).await?,
            tls,
            server::router(proxy.clone()),
            cancel.clone(),
        );
        let metrics_cancel = cancel.clone();
        let metrics = async move {
            if let Some((listener, tls, router)) = metrics {
                serve_metrics(listener, tls, router, metrics_cancel).await
            } else {
                metrics_cancel.cancelled().await;
                Ok(())
            }
        };
        let listeners = super::listeners::join(
            cancel.clone(),
            async { Ok(runtime.await?) },
            async { Ok(control.await?) },
            async { Ok(metrics.await?) },
        )
        .await;
        super::listeners::wait_work(&proxy.tasks, Duration::from_secs(30)).await;
        listeners?;
        Ok(())
        }.await;
        super::listeners::finish_journal(
            journal,
            Path::new("/var/lib/sandbox-nodeguard"),
            lock,
            outcome,
        )
        .await
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn host_control_refuses_wildcard_public_loopback_and_wrong_port() -> anyhow::Result<()> {
            for address in [
                "10.0.1.2:9444",
                "172.16.1.2:9444",
                "192.168.1.2:9444",
                "[fd00::2]:9444",
            ] {
                control_address(address.parse()?)?;
            }
            for address in [
                "0.0.0.0:9444",
                "[::]:9444",
                "127.0.0.1:9444",
                "[::1]:9444",
                "1.1.1.1:9444",
                "169.254.169.254:9444",
                "[fe80::2]:9444",
                "10.0.1.2:8443",
                "10.0.1.2:0",
            ] {
                assert!(control_address(address.parse()?).is_err());
            }
            Ok(())
        }
    }
}

#[cfg(any(target_os = "linux", test))]
mod listeners {
    use std::{future::Future, time::Duration};
    use tokio_util::sync::CancellationToken;

    /// The original startup/listener failure is retained after actual SQLite
    /// shutdown and directory sync. Never release the OS lock while a cancelled
    /// SQLx awaiter can still own commands in its connection worker.
    pub async fn finish_journal(
        journal: sandbox_platform::nodeguard::journal::GateJournal,
        directory: &std::path::Path,
        lock: std::fs::File,
        outcome: anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        journal.shutdown().await;
        let durable = std::fs::File::open(directory).and_then(|file| file.sync_all());
        if let Err(error) = &durable {
            tracing::error!(%error, "nodeguard journal directory sync failed before releasing ownership");
        }
        drop(lock);
        outcome?;
        Ok(durable?)
    }

    /// The deadline reports unresolved work; it never cancels kernel work.
    /// The caller must retain its daemon lock while this function waits for
    /// actual completion, even after the warning horizon. External fencing or
    /// SIGKILL is an operator decision, never local termination evidence.
    pub async fn wait_work(tasks: &tokio_util::task::TaskTracker, warn_after: Duration) {
        tasks.close();
        if tokio::time::timeout(warn_after, tasks.wait())
            .await
            .is_err()
        {
            tracing::error!(
                "nodeguard shutdown retains unresolved host/runtime work and daemon lock"
            );
            tasks.wait().await;
        }
    }

    /// Every listener receives cancellation and is awaited even when another
    /// listener fails first. CONTROL/metrics own their bounded 3s drain; CRI
    /// stops accepting immediately. Its 3s warning never drops the graceful
    /// parent: tonic owns per-connection tasks beyond that parent future.
    pub async fn join<R, C, M>(
        cancel: CancellationToken,
        runtime: R,
        control: C,
        metrics: M,
    ) -> anyhow::Result<()>
    where
        R: Future<Output = anyhow::Result<()>>,
        C: Future<Output = anyhow::Result<()>>,
        M: Future<Output = anyhow::Result<()>>,
    {
        tokio::pin!(runtime, control, metrics);
        let (finished, first) = tokio::select! {
            result = &mut runtime => (0, result),
            result = &mut control => (1, result),
            result = &mut metrics => (2, result),
        };
        cancel.cancel();
        let (runtime, control, metrics) = tokio::join!(
            async {
                if finished == 0 {
                    return Ok(());
                }
                match tokio::time::timeout(Duration::from_secs(3), runtime.as_mut()).await {
                    Ok(result) => result,
                    Err(_) => {
                        tracing::warn!(
                            "CRI graceful shutdown remains pending; retaining its parent and daemon lock"
                        );
                        runtime.await
                    }
                }
            },
            async { if finished == 1 { Ok(()) } else { control.await } },
            async { if finished == 2 { Ok(()) } else { metrics.await } },
        );
        first?;
        runtime?;
        control?;
        metrics?;
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        struct PendingDrop(Arc<AtomicBool>);
        impl Drop for PendingDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        #[tokio::test]
        async fn startup_configuration_failure_drains_cancelled_sqlite_before_releasing_daemon_lock()
        -> anyhow::Result<()> {
            use sandbox_platform::nodeguard::{journal::GateJournal, protocol::*};
            use sqlx::{Connection, sqlite::SqliteConnectOptions};
            use uuid::Uuid;

            let directory = tempfile::tempdir()?;
            let db = directory.path().join("state.sqlite3");
            let node = NodeBinding {
                cluster_epoch: Uuid::new_v4(),
                node_uid: Uuid::new_v4(),
                node_name: "public-startup-fixture".into(),
                boot_id: Uuid::new_v4(),
                profile_sha256: "a".repeat(64),
            };
            let journal = GateJournal::open(&db, node.clone()).await?;
            let workspace = Uuid::new_v4();
            let registration = RegisterLaunchRequest {
                protocol: PROTOCOL_VERSION,
                permit_id: Uuid::new_v4(),
                node,
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(1),
                launch: LaunchBinding {
                    purpose: LaunchPurpose::Workload,
                    tenant_id: Uuid::new_v4(),
                    project_id: Uuid::new_v4(),
                    instance_id: Uuid::new_v4(),
                    workspace_id: workspace,
                    generation: 1,
                    launch_id: Uuid::new_v4(),
                    pod_uid: Uuid::new_v4(),
                    namespace: "public-startup-fixture".into(),
                    pod_name: format!("sbx-ws-{workspace}"),
                    pvc_uid: Uuid::new_v4(),
                    pv_uid: Uuid::new_v4(),
                    pv_name: "public-startup-volume".into(),
                    csi_volume_handle: "d-publicFixture".into(),
                },
            };
            let path = directory.path().join("daemon.lock");
            let lock = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(&path)?;
            lock.try_lock()?;
            let contender = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)?;
            let mut external = sqlx::SqliteConnection::connect_with(
                &SqliteConnectOptions::new()
                    .filename(&db)
                    .busy_timeout(Duration::from_secs(5)),
            )
            .await?;
            sqlx::query("BEGIN IMMEDIATE")
                .execute(&mut external)
                .await?;
            let active = journal.clone();
            let pending = tokio::spawn(async move { active.register(&registration).await });
            // This deliberately issued SQLx command simulates a cancelled
            // startup awaiter. A configuration error itself does not create a
            // pending UPDATE and this fixture does not assert otherwise.
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(!pending.is_finished());
            pending.abort();
            let _ = pending.await;
            let mut cleanup = tokio::spawn(async move {
                let outcome = async {
                    serde_json::from_str::<serde_json::Value>("INVALID_PUBLIC_CONFIG")?;
                    Ok(())
                }
                .await;
                finish_journal(journal, directory.path(), lock, outcome).await
            });
            assert!(
                tokio::time::timeout(Duration::from_millis(100), &mut cleanup)
                    .await
                    .is_err()
            );
            assert!(
                contender.try_lock().is_err(),
                "Startup error cannot relinquish a live SQLite worker"
            );
            sqlx::query("ROLLBACK").execute(&mut external).await?;
            let original = tokio::time::timeout(Duration::from_secs(2), cleanup).await??;
            assert!(
                original.is_err(),
                "The original invalid configuration must remain an error"
            );
            contender.try_lock()?;
            external.close().await?;
            Ok(())
        }

        #[tokio::test]
        async fn a_listener_failure_cancels_and_joins_every_remaining_listener_before_return()
        -> anyhow::Result<()> {
            for winner in 0..3 {
                let token = CancellationToken::new();
                let completed = Arc::new(tokio::sync::Barrier::new(2));
                let mut branches = Vec::new();
                for id in 0..3 {
                    let (token, completed) = (token.clone(), completed.clone());
                    branches.push(async move {
                        if id == winner {
                            return Err(anyhow::anyhow!("Controlled listener failure"));
                        }
                        token.cancelled().await;
                        // An early drop/select loser cannot reach this barrier.
                        completed.wait().await;
                        Ok(())
                    });
                }
                let [runtime, control, metrics]: [_; 3] = branches
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Fixture requires three listeners"))?;
                let result = tokio::time::timeout(
                    Duration::from_secs(1),
                    join(token.clone(), runtime, control, metrics),
                )
                .await?;
                assert!(result.is_err());
                assert!(token.is_cancelled());
            }
            Ok(())
        }

        #[tokio::test]
        async fn unresolved_cri_transport_warns_without_dropping_its_graceful_parent()
        -> anyhow::Result<()> {
            let dropped = Arc::new(AtomicBool::new(false));
            let running = Arc::new(AtomicBool::new(true));
            let release = Arc::new(tokio::sync::Notify::new());
            let captured = dropped.clone();
            let (complete, observe_running) = (release.clone(), running.clone());
            let runtime = async move {
                let _guard = PendingDrop(captured);
                complete.notified().await;
                observe_running.store(false, Ordering::SeqCst);
                Ok(())
            };
            let token = CancellationToken::new();
            let metrics_stop = token.clone();
            let mut joined = tokio::spawn(join(token, runtime, async { Ok(()) }, async move {
                metrics_stop.cancelled().await;
                Ok(())
            }));
            assert!(
                tokio::time::timeout(Duration::from_millis(3100), &mut joined)
                    .await
                    .is_err()
            );
            assert!(
                !dropped.load(Ordering::SeqCst),
                "The tonic parent must stay alive after its warning horizon"
            );
            assert!(
                running.load(Ordering::SeqCst),
                "Transport warning does not close background work"
            );
            release.notify_one();
            tokio::time::timeout(Duration::from_secs(1), joined).await???;
            assert!(dropped.load(Ordering::SeqCst));
            assert!(!running.load(Ordering::SeqCst));
            Ok(())
        }

        #[tokio::test]
        async fn warning_horizon_keeps_real_daemon_lock_until_blocking_work_exits()
        -> anyhow::Result<()> {
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("daemon.lock");
            let lock = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(&path)?;
            lock.try_lock()?;
            let contender = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)?;
            let tasks = tokio_util::task::TaskTracker::new();
            let (release, blocked) = std::sync::mpsc::channel();
            tasks.spawn_blocking(move || {
                let _ = blocked.recv();
            });
            let finished = Arc::new(AtomicBool::new(false));
            let recorded = finished.clone();
            let mut waiter = tokio::spawn(async move {
                wait_work(&tasks, Duration::from_millis(30)).await;
                drop(lock);
                recorded.store(true, Ordering::SeqCst);
            });
            tokio::time::sleep(Duration::from_millis(80)).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(30), &mut waiter)
                    .await
                    .is_err()
            );
            assert!(!finished.load(Ordering::SeqCst));
            assert!(
                contender.try_lock().is_err(),
                "Warning must not release live daemon ownership"
            );
            release.send(())?;
            tokio::time::timeout(Duration::from_secs(1), waiter).await??;
            assert!(finished.load(Ordering::SeqCst));
            contender.try_lock()?;
            Ok(())
        }
    }
}
#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    linux::run().await
}
#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!(
        "sandbox-nodeguard requires the certified Linux host runtime; this operating system cannot provide termination evidence"
    )
}
