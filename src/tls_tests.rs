use super::*;
use axum::routing::get;
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SERVER: &[u8] = include_bytes!("../tests/fixtures/admission/server.pem");
const KEY: &[u8] = include_bytes!("../tests/fixtures/admission/server.key");
const SCRAPER_CA: &[u8] = include_bytes!("../tests/fixtures/admission/apiserver-ca.pem");
const SCRAPER: &[u8] = include_bytes!("../tests/fixtures/admission/apiserver.pem");
const SCRAPER_KEY: &[u8] = include_bytes!("../tests/fixtures/admission/apiserver.key");

fn limits() -> ListenerLimits {
    ListenerLimits {
        http2: false,
        connections: 2,
        handshake: Duration::from_millis(200),
        headers: Duration::from_millis(150),
        idle: Duration::from_millis(400),
        write_stall: Duration::from_millis(100),
        lifetime: Duration::from_millis(800),
        shutdown: Duration::from_millis(100),
    }
}
async fn listen(
    app: Router,
    limits: ListenerLimits,
    config: Option<ServerConfig>,
) -> anyhow::Result<(
    SocketAddr,
    CancellationToken,
    tokio::task::JoinHandle<io::Result<()>>,
)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let tls = RustlsConfig::from_config(Arc::new(match config {
        Some(c) => c,
        None => bounded_tls_config(SERVER, KEY, SCRAPER_CA, limits)?,
    }));
    let cancel = CancellationToken::new();
    let task = tokio::spawn(serve_bounded_with_limits(
        listener,
        tls,
        app,
        cancel.clone(),
        limits,
    ));
    Ok((address, cancel, task))
}
fn client(identity: bool) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .http1_only()
        .timeout(Duration::from_secs(2))
        .add_root_certificate(reqwest::Certificate::from_pem(include_bytes!(
            "../tests/fixtures/admission/server-ca.pem"
        ))?);
    if identity {
        builder = builder.identity(reqwest::Identity::from_pem(
            &[SCRAPER, SCRAPER_KEY].concat(),
        )?);
    }
    Ok(builder.build()?)
}
fn blocking_client(
    address: SocketAddr,
) -> anyhow::Result<rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>> {
    let mut roots = RootCertStore::empty();
    for c in
        CertificateDer::pem_slice_iter(include_bytes!("../tests/fixtures/admission/server-ca.pem"))
    {
        roots.add(c?)?;
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_client_auth_cert(
        CertificateDer::pem_slice_iter(SCRAPER).collect::<Result<Vec<_>, _>>()?,
        PrivateKeyDer::from_pem_slice(SCRAPER_KEY)?,
    )?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connection =
        rustls::ClientConnection::new(Arc::new(config), ServerName::try_from("127.0.0.1")?)?;
    let socket = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(1))?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    Ok(rustls::StreamOwned::new(connection, socket))
}

#[tokio::test]
async fn real_tls_requires_scraper_and_closes_keepalive_after_one_response() -> anyhow::Result<()> {
    let (address, cancel, task) = listen(
        Router::new().route("/metrics", get(|| async { "ok" })),
        limits(),
        None,
    )
    .await?;
    let result = async {
        assert!(
            client(false)?
                .get(format!("https://{address}/metrics"))
                .send()
                .await
                .is_err()
        );
        let text = tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
            use std::io::{Read, Write};
            let mut stream = blocking_client(address)?;
            stream.write_all(
                b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
            )?;
            let mut result = String::new();
            stream.read_to_string(&mut result)?;
            Ok(result)
        })
        .await??;
        assert!(
            text.contains("200 OK") && text.contains("connection: close") && text.ends_with("ok")
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    cancel.cancel();
    task.await??;
    result
}

#[tokio::test]
async fn handshake_and_headers_are_bounded_and_full_capacity_shutdown_is_cancellable()
-> anyhow::Result<()> {
    let mut bound = limits();
    bound.connections = 1;
    let (address, cancel, task) = listen(
        Router::new().route("/metrics", get(|| async { "ok" })),
        bound,
        None,
    )
    .await?;
    let result = async {
        let mut incomplete = tokio::net::TcpStream::connect(address).await?;
        let began = Instant::now();
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), incomplete.read(&mut byte)).await??,
            0
        );
        assert!(began.elapsed() >= bound.handshake);
        let elapsed = tokio::task::spawn_blocking(move || -> anyhow::Result<Duration> {
            use std::io::{Read, Write};
            let mut stream = blocking_client(address)?;
            stream.write_all(b"GET /metrics HTTP/1.1\r\nHost: ")?;
            let started = Instant::now();
            let mut response = Vec::new();
            // Header timeout may close without a TLS close_notify; both forms
            // are fail-closed. A socket timeout is not accepted as evidence.
            if let Err(e) = stream.read_to_end(&mut response) {
                anyhow::ensure!(
                    e.kind() != io::ErrorKind::WouldBlock && e.kind() != io::ErrorKind::TimedOut,
                    "Header deadline did not close connection"
                );
            }
            anyhow::ensure!(
                !String::from_utf8_lossy(&response).contains("200 OK"),
                "Incomplete headers reached handler"
            );
            Ok(started.elapsed())
        })
        .await??;
        assert!(elapsed < Duration::from_secs(1));
        Ok::<_, anyhow::Error>(())
    }
    .await;
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), task).await???;
    result
}

#[tokio::test]
async fn hard_lifetime_cancels_a_pending_handler_and_releases_connection_slot() -> anyhow::Result<()>
{
    let mut bound = limits();
    bound.connections = 1;
    bound.lifetime = Duration::from_millis(200);
    let (started, mut entered) = tokio::sync::mpsc::channel(1);
    let app = Router::new()
        .route(
            "/hold",
            get(move || {
                let started = started.clone();
                async move {
                    let _ = started.send(()).await;
                    std::future::pending::<&'static str>().await
                }
            }),
        )
        .route("/metrics", get(|| async { "ok" }));
    let (address, cancel, task) = listen(app, bound, None).await?;
    let result = async {
        let request = tokio::spawn(client(true)?.get(format!("https://{address}/hold")).send());
        tokio::time::timeout(Duration::from_secs(1), entered.recv())
            .await?
            .ok_or_else(|| anyhow::anyhow!("Handler not entered"))?;
        let began = Instant::now();
        let mut waiting = tokio::spawn(
            client(true)?
                .get(format!("https://{address}/metrics"))
                .send(),
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(30), &mut waiting)
                .await
                .is_err(),
            "A second TLS connection cannot pass the occupied lifetime slot"
        );
        assert!(request.await?.is_err());
        let good = waiting.await??;
        assert_eq!(good.status(), reqwest::StatusCode::OK);
        assert!(began.elapsed() < Duration::from_secs(1));
        Ok::<_, anyhow::Error>(())
    }
    .await;
    cancel.cancel();
    task.await??;
    result
}

#[tokio::test]
async fn shutdown_cancels_full_handshake_capacity_with_clients_still_connected()
-> anyhow::Result<()> {
    let mut bound = limits();
    bound.connections = 1;
    bound.handshake = Duration::from_secs(5);
    bound.idle = Duration::from_secs(5);
    bound.lifetime = Duration::from_secs(10);
    let (address, cancel, task) = listen(Router::new(), bound, None).await?;
    let occupied = tokio::net::TcpStream::connect(address).await?;
    let queued = tokio::net::TcpStream::connect(address).await?;
    // Keep both clients open until after the listener exits. Neither connection
    // nor handshake completion can be what releases the shutdown wait.
    tokio::time::sleep(Duration::from_millis(20)).await;
    cancel.cancel();
    tokio::time::timeout(Duration::from_millis(500), task).await???;
    drop((occupied, queued));
    Ok(())
}

#[tokio::test]
async fn stalled_writes_and_idle_reads_have_independent_deadlines() -> anyhow::Result<()> {
    let mut bound = limits();
    bound.idle = Duration::from_secs(1);
    bound.write_stall = Duration::from_millis(30);
    let (stream, _reader) = tokio::io::duplex(1);
    let mut io = BoundedIo::new(stream, bound);
    let began = Instant::now();
    assert_eq!(
        io.write_all(&[1; 1024])
            .await
            .err()
            .ok_or_else(|| anyhow::anyhow!("Write must stall"))?
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert!(began.elapsed() < bound.idle);
    bound.idle = Duration::from_millis(30);
    let (stream, _writer) = tokio::io::duplex(1);
    let mut io = BoundedIo::new(stream, bound);
    assert_eq!(
        io.read(&mut [0])
            .await
            .err()
            .ok_or_else(|| anyhow::anyhow!("Read must idle"))?
            .kind(),
        io::ErrorKind::TimedOut
    );
    Ok(())
}

#[derive(Debug)]
struct FixedTime(UnixTime);
impl rustls::time_provider::TimeProvider for FixedTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(self.0)
    }
}

#[tokio::test]
async fn real_tls_rejects_chain_expiring_before_hard_deadline_without_changing_control_tls()
-> anyhow::Result<()> {
    // Immutable public fixtures expire together at this checked-in timestamp.
    let expiry = chrono::DateTime::parse_from_rfc3339("2036-09-30T04:30:31Z")?.timestamp() as u64;
    let limits = ListenerLimits::METRICS;
    let mut config = bounded_tls_config(SERVER, KEY, SCRAPER_CA, limits)?;
    assert!(!config.session_storage.can_cache());
    assert_eq!(config.send_tls13_tickets, 0);
    config.time_provider = Arc::new(FixedTime(UnixTime::since_unix_epoch(Duration::from_secs(
        expiry - 5,
    ))));
    let (address, cancel, task) = listen(
        Router::new().route("/metrics", get(|| async { "ok" })),
        limits,
        Some(config),
    )
    .await?;
    let result = client(true)?
        .get(format!("https://{address}/metrics"))
        .send()
        .await;
    cancel.cancel();
    task.await??;
    assert!(
        result.is_err(),
        "A chain valid now but expiring within the connection lifetime must fail"
    );
    let mut roots = RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(SCRAPER_CA) {
        roots.add(c?)?;
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()?;
    let certificate = CertificateDer::from_pem_slice(SCRAPER)?;
    assert!(
        verifier
            .verify_client_cert(
                &certificate,
                &[],
                UnixTime::since_unix_epoch(Duration::from_secs(expiry - 5))
            )
            .is_ok(),
        "Ordinary current-time client verification still accepts this chain"
    );
    Ok(())
}

#[tokio::test]
async fn admission_chain_must_cover_connection_lifetime_and_cannot_resume() -> anyhow::Result<()> {
    let expiry = chrono::DateTime::parse_from_rfc3339("2036-09-30T04:30:31Z")?.timestamp() as u64;
    let mut config = bounded_tls_config(SERVER, KEY, SCRAPER_CA, ListenerLimits::ADMISSION)?;
    assert_eq!(
        config.alpn_protocols,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
    assert!(!config.session_storage.can_cache());
    assert_eq!(config.send_tls13_tickets, 0);
    config.time_provider = Arc::new(FixedTime(UnixTime::since_unix_epoch(Duration::from_secs(
        expiry - 5,
    ))));
    let (address, cancel, task) = listen(
        Router::new().route("/validate", get(|| async { "ok" })),
        ListenerLimits::ADMISSION,
        Some(config),
    )
    .await?;
    let result = client(true)?
        .get(format!("https://{address}/validate"))
        .send()
        .await;
    cancel.cancel();
    task.await??;
    assert!(
        result.is_err(),
        "Currently valid client chain must be refused before it could expire on this connection"
    );
    Ok(())
}

#[tokio::test]
async fn admission_http2_capacity_fails_closed_and_recovers_without_queuing_bodies()
-> anyhow::Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let first = Arc::new(AtomicBool::new(true));
    let slots = Arc::new(Semaphore::new(1));
    let app = Router::new()
        .route(
            "/validate",
            get({
                let (started, release) = (started.clone(), release.clone());
                move || {
                    let (started, release, first) =
                        (started.clone(), release.clone(), first.clone());
                    async move {
                        if first.swap(false, Ordering::SeqCst) {
                            started.notify_one();
                            release.notified().await;
                        }
                        "ok"
                    }
                }
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            slots.clone(),
            request_capacity,
        ));
    let mut bound = limits();
    bound.http2 = true;
    bound.idle = Duration::from_secs(2);
    bound.lifetime = Duration::from_secs(3);
    let (address, cancel, task) = listen(app, bound, None).await?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(2))
        .add_root_certificate(reqwest::Certificate::from_pem(include_bytes!(
            "../tests/fixtures/admission/server-ca.pem"
        ))?)
        .identity(reqwest::Identity::from_pem(
            &[SCRAPER, SCRAPER_KEY].concat(),
        )?)
        .build()?;
    let url = format!("https://{address}/validate");
    let request = tokio::spawn({
        let client = client.clone();
        let url = url.clone();
        async move { client.get(url).send().await }
    });
    let result = async {
        tokio::time::timeout(Duration::from_secs(1), started.notified()).await?;
        let denied = client.get(&url).send().await?;
        assert_eq!(denied.version(), reqwest::Version::HTTP_2);
        assert_eq!(denied.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        assert!(denied.bytes().await?.is_empty());
        assert_eq!(slots.available_permits(), 0);
        release.notify_one();
        assert_eq!(request.await??.status(), reqwest::StatusCode::OK);
        assert_eq!(client.get(&url).send().await?.text().await?, "ok");
        assert_eq!(slots.available_permits(), 1);
        Ok::<_, anyhow::Error>(())
    }
    .await;
    release.notify_one();
    cancel.cancel();
    task.await??;
    result
}

async fn control_listener(
    app: Router,
) -> anyhow::Result<(
    SocketAddr,
    CancellationToken,
    tokio::task::JoinHandle<io::Result<()>>,
)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let cancel = CancellationToken::new();
    let task = tokio::spawn(serve_control(
        listener,
        control_mutual_tls(SERVER, KEY, SCRAPER_CA)?,
        app,
        cancel.clone(),
    ));
    Ok((address, cancel, task))
}

fn control_client(http2: bool) -> anyhow::Result<reqwest::Client> {
    let builder = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .add_root_certificate(reqwest::Certificate::from_pem(include_bytes!(
            "../tests/fixtures/admission/server-ca.pem"
        ))?)
        .identity(reqwest::Identity::from_pem(
            &[SCRAPER, SCRAPER_KEY].concat(),
        )?);
    Ok(if http2 {
        builder.http2_prior_knowledge()
    } else {
        builder.http1_only()
    }
    .build()?)
}

#[tokio::test]
async fn control_transport_requires_mtls_and_preserves_the_real_close_budget() -> anyhow::Result<()>
{
    let (address, cancel, task) = control_listener(Router::new().route(
        "/close",
        get(|| async {
            // Real close permits 3s CRI stop followed by 4s host observation.
            // A 5s metrics/admission idle timeout would abort this response.
            tokio::time::sleep(Duration::from_secs(7)).await;
            "observed"
        }),
    ))
    .await?;
    let result = async {
        assert!(
            client(false)?
                .get(format!("https://{address}/close"))
                .send()
                .await
                .is_err()
        );
        let started = Instant::now();
        let response = control_client(true)?
            .get(format!("https://{address}/close"))
            .send()
            .await?;
        assert_eq!(response.version(), reqwest::Version::HTTP_2);
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.text().await?, "observed");
        assert!(started.elapsed() >= Duration::from_secs(7));
        Ok::<_, anyhow::Error>(())
    }
    .await;
    cancel.cancel();
    task.await??;
    result
}

#[tokio::test]
async fn production_control_capacity_is_global_and_recovers_across_http_versions()
-> anyhow::Result<()> {
    let (entered, mut observed) = tokio::sync::mpsc::channel(16);
    let release = Arc::new(tokio::sync::Notify::new());
    let app = Router::new()
        .route(
            "/hold",
            get({
                let release = release.clone();
                move || {
                    let (entered, release) = (entered.clone(), release.clone());
                    async move {
                        let notified = release.notified();
                        tokio::pin!(notified);
                        // Register before reporting entry, so notify_waiters cannot
                        // race with an already counted handler's first poll.
                        notified.as_mut().enable();
                        let _ = entered.send(()).await;
                        notified.await;
                        "done"
                    }
                }
            }),
        )
        .route("/node", get(|| async { "identity" }));
    let (address, cancel, task) = control_listener(app).await?;
    let client = control_client(false)?;
    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let client = client.clone();
        requests.spawn(async move { client.get(format!("https://{address}/hold")).send().await });
    }
    let result = async {
        for _ in 0..16 {
            tokio::time::timeout(Duration::from_secs(2), observed.recv())
                .await?
                .ok_or_else(|| anyhow::anyhow!("Control handler not entered"))?;
        }
        let h2 = control_client(true)?;
        let denied = tokio::time::timeout(
            Duration::from_secs(1),
            h2.get(format!("https://{address}/node")).send(),
        )
        .await??;
        assert_eq!(denied.version(), reqwest::Version::HTTP_2);
        assert_eq!(denied.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        assert!(denied.bytes().await?.is_empty());
        release.notify_waiters();
        while let Some(request) = requests.join_next().await {
            assert_eq!(request??.text().await?, "done");
        }
        assert_eq!(
            h2.get(format!("https://{address}/node"))
                .send()
                .await?
                .text()
                .await?,
            "identity"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    release.notify_waiters();
    requests.abort_all();
    while requests.join_next().await.is_some() {}
    cancel.cancel();
    task.await??;
    result
}

#[tokio::test]
async fn control_chain_must_cover_its_full_connection_and_cannot_resume() -> anyhow::Result<()> {
    let expiry = chrono::DateTime::parse_from_rfc3339("2036-09-30T04:30:31Z")?.timestamp() as u64;
    let mut config = bounded_tls_config(SERVER, KEY, SCRAPER_CA, ListenerLimits::CONTROL)?;
    assert_eq!(
        config.alpn_protocols,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
    assert!(!config.session_storage.can_cache());
    assert_eq!(config.send_tls13_tickets, 0);
    config.time_provider = Arc::new(FixedTime(UnixTime::since_unix_epoch(Duration::from_secs(
        expiry - 5,
    ))));
    let (address, cancel, task) = listen(
        Router::new().route("/node", get(|| async { "identity" })),
        ListenerLimits::CONTROL,
        Some(config),
    )
    .await?;
    let result = control_client(true)?
        .get(format!("https://{address}/node"))
        .send()
        .await;
    cancel.cancel();
    task.await??;
    assert!(
        result.is_err(),
        "A client chain expiring during the control connection must be rejected"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn admission_files_reject_public_key_permissions_and_non_regular_configuration()
-> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir()?;
    let certificate = dir.path().join("server.pem");
    let key = dir.path().join("server.key");
    let ca = dir.path().join("apiserver-ca.pem");
    for (path, bytes) in [(&certificate, SERVER), (&key, KEY), (&ca, SCRAPER_CA)] {
        std::fs::write(path, bytes)?;
    }
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
    let files = AdmissionTlsFiles {
        certificate,
        private_key: key.clone(),
        apiserver_ca: ca,
    };
    assert!(files.load().is_ok());
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644))?;
    assert!(files.load().is_err());
    let fifo = dir.path().join("config.json");
    nix::unistd::mkfifo(
        &fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )?;
    assert!(read_admission_configuration(&fifo).is_err());
    assert!(read_admission_configuration(std::path::Path::new("relative.json")).is_err());
    Ok(())
}
