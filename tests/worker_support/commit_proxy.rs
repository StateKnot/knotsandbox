//! Test-only PostgreSQL Lost-ACK injection with verified TLS on both legs.
//! Authentication and SQL are forwarded opaquely and are never recorded. The
//! caller arms only its owned checkpoint and independently verifies its committed
//! UID/stage/event and backend identity before dropping the held acknowledgement.

use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI32, Ordering},
    },
    time::Duration,
};

use crate::db::Database;
use anyhow::{Context, ensure};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 4, 210, 22, 47];
const HANDSHAKE_LIMIT: Duration = Duration::from_secs(3);
const CONNECTION_LIMIT: Duration = Duration::from_secs(45);
const MAX_CONNECTIONS: usize = 4;
const MAX_BACKEND_PIDS: usize = 16;
const MAX_FRAME: u32 = 1024 * 1024;

pub struct CommitProxy {
    pub arm: Arc<AtomicBool>,
    pub arrived: Arc<Notify>,
    pub target_backend_pid: Arc<AtomicI32>,
    fault: CancellationToken,
    stop: CancellationToken,
    pids: Arc<Mutex<BTreeSet<i32>>>,
    task: Option<JoinHandle<anyhow::Result<()>>>,
}

#[derive(Clone)]
struct WireConfig {
    upstream: SocketAddr,
    server_name: ServerName<'static>,
    acceptor: TlsAcceptor,
    connector: TlsConnector,
    arm: Arc<AtomicBool>,
    fired: Arc<AtomicBool>,
    arrived: Arc<Notify>,
    target_backend_pid: Arc<AtomicI32>,
    fault: CancellationToken,
    stop: CancellationToken,
    pids: Arc<Mutex<BTreeSet<i32>>>,
}

#[derive(Debug)]
struct AckIntentionallyLost;

impl fmt::Display for AckIntentionallyLost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("owned checkpoint COMMIT acknowledgement intentionally lost")
    }
}
impl Error for AckIntentionallyLost {}

impl CommitProxy {
    #[allow(
        dead_code,
        reason = "shared helper also serves the termination lib-test seam"
    )]
    pub async fn connect() -> anyhow::Result<(Self, Database)> {
        Self::connect_role("TEST_WORKER_DATABASE_URL", "sandbox_worker").await
    }

    #[allow(
        dead_code,
        reason = "shared helper also serves the worker integration seam"
    )]
    pub async fn connect_termination() -> anyhow::Result<(Self, Database)> {
        Self::connect_role("TEST_TERMINATION_DATABASE_URL", "sandbox_termination").await
    }

    async fn connect_role(environment: &str, role: &str) -> anyhow::Result<(Self, Database)> {
        let (mut url, upstream, ca_path) = checked_fixture(environment, role)?;
        let directory = ca_path.parent().context("private fixture CA directory")?;
        let ca = bounded_file(&ca_path, 64 * 1024)?;
        let certificate = bounded_file(&directory.join("server.crt"), 128 * 1024)?;
        let key = bounded_file(&directory.join("server.key"), 64 * 1024)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        for certificate in CertificateDer::pem_slice_iter(&ca) {
            roots.add(certificate.context("invalid private fixture trust certificate")?)?;
        }
        ensure!(!roots.is_empty(), "private fixture trust must not be empty");
        let chain = CertificateDer::pem_slice_iter(&certificate)
            .collect::<Result<Vec<_>, _>>()
            .context("invalid private fixture server certificate")?;
        let private_key =
            PrivateKeyDer::from_pem_slice(&key).context("invalid private fixture server key")?;
        let server = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(chain, private_key)?;
        let client = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name = ServerName::try_from(
            url.host_str()
                .context("literal loopback fixture host")?
                .to_owned(),
        )
        .map_err(|_| anyhow::anyhow!("invalid private fixture TLS server name"))?;
        let listener = TcpListener::bind(SocketAddr::new(upstream.ip(), 0)).await?;
        let port = listener.local_addr()?.port();
        // Keep the hostname, CA and verify-full parameters exactly. Only this
        // owned listener port replaces the same-database upstream port.
        url.set_port(Some(port))
            .map_err(|_| anyhow::anyhow!("invalid owned proxy port"))?;
        let wire = WireConfig {
            upstream,
            server_name,
            acceptor: TlsAcceptor::from(Arc::new(server)),
            connector: TlsConnector::from(Arc::new(client)),
            arm: Arc::new(AtomicBool::new(false)),
            fired: Arc::new(AtomicBool::new(false)),
            arrived: Arc::new(Notify::new()),
            target_backend_pid: Arc::new(AtomicI32::new(0)),
            fault: CancellationToken::new(),
            stop: CancellationToken::new(),
            pids: Arc::new(Mutex::new(BTreeSet::new())),
        };
        let mut proxy = Self {
            arm: wire.arm.clone(),
            arrived: wire.arrived.clone(),
            target_backend_pid: wire.target_backend_pid.clone(),
            fault: wire.fault.clone(),
            stop: wire.stop.clone(),
            pids: wire.pids.clone(),
            task: Some(tokio::spawn(serve(listener, wire))),
        };
        let connected =
            tokio::time::timeout(Duration::from_secs(10), Database::connect(url.as_str(), 1)).await;
        let database = match connected {
            Ok(Ok(database)) => database,
            _ => {
                proxy.stop_and_join().await?;
                anyhow::bail!("private verify-full runtime proxy connection failed");
            }
        };
        let verification_step = AtomicI32::new(0);
        let verified = tokio::time::timeout(Duration::from_secs(5), async {
            database.verify_runtime_role().await?;
            verification_step.store(1,Ordering::SeqCst);
            let verified: bool = sqlx::query_scalar(
                "SELECT session_user::text=$1 AND current_user::text=$1 AND current_database() LIKE '%_test' AND EXISTS(SELECT 1 FROM pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl)",
            )
            .bind(role)
            .fetch_one(&database.pool)
            .await?;
            verification_step.store(2,Ordering::SeqCst);
            ensure!(verified, "actual backend must retain exact runtime role and TLS");
            Ok::<(), anyhow::Error>(())
        })
        .await;
        if !matches!(verified, Ok(Ok(()))) {
            let step = verification_step.load(Ordering::SeqCst);
            let outcome = match &verified {
                Err(_) => "TIMEOUT",
                Ok(Err(error)) if error.downcast_ref::<sqlx::Error>().is_some() => "SQLX_ERROR",
                _ => "CONTRACT_REJECTED",
            };
            proxy.finish(&database).await?;
            anyhow::bail!(
                "private runtime backend identity/TLS verification failed (step={step}, outcome={outcome})"
            );
        }
        Ok((proxy, database))
    }

    /// Lose only the one armed acknowledgement; other/replacement connections
    /// remain available for ordinary deferred persistence and recovery.
    pub fn drop_ack(&self) {
        self.fault.cancel();
    }

    pub fn backend_pids(&self) -> anyhow::Result<Vec<i32>> {
        Ok(self
            .pids
            .lock()
            .map_err(|_| anyhow::anyhow!("private proxy PID registry poisoned"))?
            .iter()
            .copied()
            .collect())
    }

    /// The caller first settles its worker. Cancellation closes owned socket
    /// halves, joins all children, then drains the exact supplied pool. Actual
    /// PID/backend_start absence is checked independently by the owner fixture.
    pub async fn finish(&mut self, database: &Database) -> anyhow::Result<()> {
        let joined = self.stop_and_join().await;
        let closed = tokio::time::timeout(Duration::from_secs(5), database.pool.close()).await;
        joined?;
        closed.context("private proxy worker pool did not drain")?;
        Ok(())
    }

    async fn stop_and_join(&mut self) -> anyhow::Result<()> {
        self.stop.cancel();
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        match tokio::time::timeout(Duration::from_secs(5), &mut task).await {
            Ok(result) => result.context("private TLS proxy owner task failed")?,
            Err(error) => {
                task.abort();
                let _ = task.await;
                Err(error).context("private TLS proxy children did not join")
            }
        }
    }
}

impl Drop for CommitProxy {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn checked_fixture(
    environment: &str,
    role: &str,
) -> anyhow::Result<(url::Url, SocketAddr, PathBuf)> {
    let url = url::Url::parse(&std::env::var(environment)?)
        .map_err(|_| anyhow::anyhow!("invalid private runtime fixture URL"))?;
    let target = url::Url::parse(&std::env::var("TEST_DATABASE_URL")?)
        .map_err(|_| anyhow::anyhow!("invalid private database fixture URL"))?;
    let ip: IpAddr = url
        .host_str()
        .context("literal private fixture host")?
        .parse()
        .context("private ACK fixture requires a literal loopback IP")?;
    ensure!(
        matches!(url.scheme(), "postgres" | "postgresql")
            && ip.is_loopback()
            && url.username() == role
            && url.path().ends_with("_test")
            && url.host_str() == target.host_str()
            && url.port_or_known_default() == target.port_or_known_default()
            && url.path() == target.path(),
        "private ACK fixture requires exact runtime login and same loopback test database"
    );
    let parameters: Vec<_> = url.query_pairs().collect();
    ensure!(
        parameters
            .iter()
            .filter(|(key, value)| key == "sslmode" && value == "verify-full")
            .count()
            == 1
            && parameters
                .iter()
                .filter(|(key, _)| key == "sslmode")
                .count()
                == 1
            && !parameters.iter().any(|(key, _)| {
                matches!(
                    key.as_ref(),
                    "host"
                        | "hostaddr"
                        | "port"
                        | "user"
                        | "password"
                        | "options"
                        | "sslcert"
                        | "sslkey"
                )
            }),
        "private ACK fixture must retain explicit verify-full without authority overrides"
    );
    let ca = PathBuf::from(std::env::var("TEST_AUTOMATION_TLS_ROOTCERT")?);
    ensure!(ca.is_absolute(), "private fixture CA path must be absolute");
    let configured: Vec<_> = parameters
        .iter()
        .filter(|(key, _)| key == "sslrootcert")
        .collect();
    ensure!(configured.len() == 1, "exactly one fixture CA is required");
    ensure!(
        Path::new(configured[0].1.as_ref()).canonicalize()? == ca.canonicalize()?,
        "client and backend must use the same private fixture CA"
    );
    let upstream = SocketAddr::new(ip, url.port().unwrap_or(5432));
    Ok((url, upstream, ca))
}

fn bounded_file(path: &Path, maximum: usize) -> anyhow::Result<Vec<u8>> {
    ensure!(
        path.metadata()?.is_file() && path.metadata()?.len() <= maximum as u64,
        "private TLS input exceeds its fixed size bound"
    );
    let bytes = std::fs::read(path)?;
    ensure!(bytes.len() <= maximum, "private TLS input changed size");
    Ok(bytes)
}

async fn serve(listener: TcpListener, wire: WireConfig) -> anyhow::Result<()> {
    let mut children = JoinSet::new();
    let result = loop {
        tokio::select! {
            biased;
            _ = wire.stop.cancelled() => break Ok(()),
            Some(joined) = children.join_next(), if !children.is_empty() => {
                match joined {
                    Ok(Ok(())) => {},
                    Ok(Err(error)) => break Err(error),
                    Err(_) => break Err(anyhow::anyhow!("private TLS proxy child failed")),
                }
            },
            accepted = listener.accept() => {
                let (mut socket, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(_) => break Err(anyhow::anyhow!("private TLS proxy accept failed")),
                };
                if !peer.ip().is_loopback() || children.len() >= MAX_CONNECTIONS {
                    let _ = socket.shutdown().await;
                    continue;
                }
                let child_wire = wire.clone();
                children.spawn(async move {
                    tokio::select! {
                        biased;
                        _ = child_wire.stop.cancelled() => Ok(()),
                        result = tokio::time::timeout(CONNECTION_LIMIT, forward(socket, &child_wire)) => {
                            result.context("private TLS proxy connection exceeded I/O lifetime")?
                        },
                    }
                });
            },
        }
    };
    wire.stop.cancel();
    // Every child observes this cancellation and drops both TLS socket halves.
    // JoinSet is never merely dropped on the ordinary finish/error path.
    let drained = tokio::time::timeout(Duration::from_secs(3), async {
        let mut failure = None;
        while let Some(joined) = children.join_next().await {
            if let Err(error) = joined
                .context("private TLS proxy child teardown failed")
                .and_then(|result| result)
                && failure.is_none()
            {
                failure = Some(error);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    })
    .await;
    if drained.is_err() {
        children.abort_all();
        while children.join_next().await.is_some() {}
    }
    result?;
    drained.context("private TLS proxy children exceeded teardown deadline")??;
    Ok(())
}

async fn forward(mut incoming: TcpStream, wire: &WireConfig) -> anyhow::Result<()> {
    incoming.set_nodelay(true)?;
    let (frontend, backend) = tokio::time::timeout(HANDSHAKE_LIMIT, async {
        let mut request = [0; 8];
        incoming.read_exact(&mut request).await?;
        ensure!(
            request == SSL_REQUEST,
            "private client must negotiate PostgreSQL TLS"
        );
        incoming.write_all(b"S").await?;
        incoming.flush().await?;
        let frontend = wire.acceptor.accept(incoming).await?;
        let mut upstream = TcpStream::connect(wire.upstream).await?;
        upstream.set_nodelay(true)?;
        upstream.write_all(&SSL_REQUEST).await?;
        let mut accepted = [0];
        upstream.read_exact(&mut accepted).await?;
        ensure!(
            accepted == *b"S",
            "private backend must negotiate PostgreSQL TLS"
        );
        let backend = wire
            .connector
            .connect(wire.server_name.clone(), upstream)
            .await?;
        Ok::<_, anyhow::Error>((frontend, backend))
    })
    .await
    .context("private PostgreSQL TLS handshakes exceeded deadline")??;
    let (mut frontend_read, mut frontend_write) = tokio::io::split(frontend);
    let (mut backend_read, mut backend_write) = tokio::io::split(backend);
    let result = tokio::try_join!(
        async {
            // Startup credentials, SCRAM/channel-binding exchanges and SQL stay
            // opaque. tokio's copy uses a bounded transfer buffer.
            tokio::io::copy(&mut frontend_read, &mut backend_write).await?;
            backend_write.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        },
        async {
            let mut backend_pid = None;
            loop {
                let mut tag = [0];
                match backend_read.read_exact(&mut tag).await {
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return Ok(());
                    }
                    Err(error) => return Err(error.into()),
                }
                let mut encoded = [0; 4];
                backend_read.read_exact(&mut encoded).await?;
                let length = u32::from_be_bytes(encoded);
                ensure!(
                    (4..=MAX_FRAME).contains(&length),
                    "private backend frame exceeds bound"
                );
                let mut payload = vec![0; usize::try_from(length - 4)?];
                backend_read.read_exact(&mut payload).await?;
                if tag[0] == b'K' {
                    ensure!(payload.len() == 8, "invalid private backend identity frame");
                    let pid = i32::from_be_bytes(payload[..4].try_into()?);
                    ensure!(
                        pid > 0 && backend_pid.is_none(),
                        "invalid or repeated backend PID"
                    );
                    backend_pid = Some(pid);
                    // The other four bytes are the cancellation secret. Never
                    // inspect, retain separately, format or expose those bytes.
                    let mut pids = wire
                        .pids
                        .lock()
                        .map_err(|_| anyhow::anyhow!("private PID registry poisoned"))?;
                    ensure!(
                        pids.len() < MAX_BACKEND_PIDS,
                        "private proxy reconnect budget exhausted"
                    );
                    pids.insert(pid);
                }
                if tag[0] == b'C'
                    && payload == b"COMMIT\0"
                    && wire.arm.swap(false, Ordering::SeqCst)
                    && wire
                        .fired
                        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                {
                    let pid =
                        backend_pid.context("armed COMMIT requires established backend PID")?;
                    wire.target_backend_pid.store(pid, Ordering::SeqCst);
                    wire.arrived.notify_one();
                    // PostgreSQL has emitted actual COMMIT CommandComplete.
                    // This frame and subsequent ReadyForQuery are not sent.
                    wire.fault.cancelled().await;
                    return Err(AckIntentionallyLost.into());
                }
                frontend_write.write_all(&tag).await?;
                frontend_write.write_all(&encoded).await?;
                frontend_write.write_all(&payload).await?;
                // TLS may accept plaintext while ciphertext is still pending.
                // PostgreSQL clients can await this final ReadyForQuery frame
                // before sending any more traffic; drain it explicitly.
                frontend_write.flush().await?;
            }
        }
    );
    match result {
        Ok(_) => Ok(()),
        Err(error) if error.is::<AckIntentionallyLost>() => Ok(()),
        Err(error) => Err(error),
    }
}
