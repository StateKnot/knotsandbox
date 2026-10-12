use axum_server::tls_rustls::RustlsConfig;
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use std::sync::Arc;

use axum::Router;
use axum_server::{accept::Accept, tls_rustls::RustlsAcceptor};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use rustls::{
    DigitallySignedStruct, DistinguishedName, SignatureScheme,
    client::danger::HandshakeSignatureValid,
    pki_types::UnixTime,
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
    sync::Semaphore,
    task::JoinSet,
    time::{Instant, Sleep},
};
use tokio_util::sync::CancellationToken;

/// One source of truth for the connection deadline and certificate-validity
/// horizon. Each purpose chooses its connection and HTTP limits explicitly.
#[derive(Clone, Copy)]
struct ListenerLimits {
    http2: bool,
    connections: usize,
    handshake: Duration,
    headers: Duration,
    idle: Duration,
    write_stall: Duration,
    lifetime: Duration,
    shutdown: Duration,
}
impl ListenerLimits {
    const METRICS: Self = Self {
        http2: false,
        connections: 32,
        handshake: Duration::from_secs(3),
        headers: Duration::from_secs(2),
        idle: Duration::from_secs(5),
        write_stall: Duration::from_secs(5),
        lifetime: Duration::from_secs(15),
        shutdown: Duration::from_secs(3),
    };
    const ADMISSION: Self = Self {
        http2: true,
        connections: 32,
        handshake: Duration::from_secs(3),
        headers: Duration::from_secs(2),
        idle: Duration::from_secs(5),
        write_stall: Duration::from_secs(5),
        lifetime: Duration::from_secs(10),
        shutdown: Duration::from_secs(3),
    };
    const CONTROL: Self = Self {
        http2: true,
        connections: 32,
        handshake: Duration::from_secs(3),
        headers: Duration::from_secs(2),
        // A close can legitimately spend 3s stopping CRI and 4s observing
        // kernel termination before returning. Do not apply the scraper's
        // shorter idle deadline to this protocol.
        idle: Duration::from_secs(12),
        write_stall: Duration::from_secs(5),
        lifetime: Duration::from_secs(15),
        shutdown: Duration::from_secs(3),
    };
}

/// Require client certificates from a purpose-specific CA. Each listener must
/// select its own authority; sharing user/node/controller/scraper CAs would
/// silently expand the callers authorized to use that listener.
pub fn mutual_tls(
    server_certificate: &[u8],
    server_key: &[u8],
    client_ca: &[u8],
) -> anyhow::Result<RustlsConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(client_ca) {
        roots.add(certificate?)?;
    }
    anyhow::ensure!(!roots.is_empty(), "A dedicated client CA is required");
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build()?;
    let certificates =
        CertificateDer::pem_slice_iter(server_certificate).collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(server_key)?;
    let mut tls = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, key)?;
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(tls)))
}

#[derive(Debug)]
struct LifetimeVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    lifetime: Duration,
}
impl ClientCertVerifier for LifetimeVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }
    fn verify_client_cert(
        &self,
        certificate: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.inner
            .verify_client_cert(certificate, intermediates, now)?;
        // UnixTime is whole seconds. Round the entire connection lifetime up
        // and add a second, never accepting a chain that expires mid-connection.
        let horizon = now
            .as_secs()
            .checked_add(self.lifetime.as_secs())
            .and_then(|n| n.checked_add(2))
            .ok_or(rustls::Error::General("Invalid TLS lifetime".into()))?;
        self.inner.verify_client_cert(
            certificate,
            intermediates,
            UnixTime::since_unix_epoch(Duration::from_secs(horizon)),
        )
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn bounded_tls_config(
    server_certificate: &[u8],
    server_key: &[u8],
    client_ca: &[u8],
    limits: ListenerLimits,
) -> anyhow::Result<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(client_ca) {
        roots.add(certificate?)?;
    }
    anyhow::ensure!(!roots.is_empty(), "A dedicated client CA is required");
    let inner =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build()?;
    let verifier = Arc::new(LifetimeVerifier {
        inner,
        lifetime: limits.lifetime,
    });
    let certificates =
        CertificateDer::pem_slice_iter(server_certificate).collect::<Result<Vec<_>, _>>()?;
    let mut tls = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, PrivateKeyDer::from_pem_slice(server_key)?)?;
    tls.alpn_protocols = if limits.http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    // Every connection must validate the current chain, including its horizon.
    tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    tls.send_tls13_tickets = 0;
    Ok(tls)
}

pub fn metrics_mutual_tls(
    server_certificate: &[u8],
    server_key: &[u8],
    scraper_ca: &[u8],
) -> anyhow::Result<RustlsConfig> {
    Ok(RustlsConfig::from_config(Arc::new(bounded_tls_config(
        server_certificate,
        server_key,
        scraper_ca,
        ListenerLimits::METRICS,
    )?)))
}

/// A separate apiserver-client CA is required. Client leaf/intermediate
/// validity covers the entire connection; resumed handshakes are disabled.
pub fn admission_mutual_tls(
    server_certificate: &[u8],
    server_key: &[u8],
    apiserver_ca: &[u8],
) -> anyhow::Result<RustlsConfig> {
    Ok(RustlsConfig::from_config(Arc::new(bounded_tls_config(
        server_certificate,
        server_key,
        apiserver_ca,
        ListenerLimits::ADMISSION,
    )?)))
}

/// Host control uses its dedicated controller-client CA, with current client
/// chain validation covering the entire bounded connection and no resumption.
pub fn control_mutual_tls(
    server_certificate: &[u8],
    server_key: &[u8],
    controller_ca: &[u8],
) -> anyhow::Result<RustlsConfig> {
    Ok(RustlsConfig::from_config(Arc::new(bounded_tls_config(
        server_certificate,
        server_key,
        controller_ca,
        ListenerLimits::CONTROL,
    )?)))
}

pub struct AdmissionTlsFiles {
    pub certificate: std::path::PathBuf,
    pub private_key: std::path::PathBuf,
    pub apiserver_ca: std::path::PathBuf,
}
impl AdmissionTlsFiles {
    pub fn load(&self) -> anyhow::Result<RustlsConfig> {
        admission_mutual_tls(
            &crate::api_tls::read(&self.certificate, 96 * 1024, false)?,
            &crate::api_tls::read(&self.private_key, 16 * 1024, true)?,
            &crate::api_tls::read(&self.apiserver_ca, 64 * 1024, false)?,
        )
    }
}
pub fn read_admission_configuration(path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    crate::api_tls::read(path, 1024 * 1024, false)
}

async fn request_capacity(
    axum::extract::State(slots): axum::extract::State<Arc<Semaphore>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Ok(_permit) = slots.try_acquire_owned() else {
        // Refuse before reading the body. Admission treats this as fail-closed;
        // host controllers retain resources and retry their bound challenge.
        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    next.run(request).await
}

/// Bounded mTLS admission transport. HTTP/2 pooling remains available, while
/// the whole connection and every authenticated chain share a fixed horizon.
pub async fn serve_admission(
    listener: TcpListener,
    tls: RustlsConfig,
    app: Router,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let app = app.layer(axum::middleware::from_fn_with_state(
        Arc::new(Semaphore::new(32)),
        request_capacity,
    ));
    serve_bounded_with_limits(listener, tls, app, shutdown, ListenerLimits::ADMISSION).await
}

/// Limit host control sockets and in-flight requests across HTTP versions and
/// connections. Capacity exhaustion never waits with an unread request body.
pub async fn serve_control(
    listener: TcpListener,
    tls: RustlsConfig,
    app: Router,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let app = app.layer(axum::middleware::from_fn_with_state(
        Arc::new(Semaphore::new(16)),
        request_capacity,
    ));
    serve_bounded_with_limits(listener, tls, app, shutdown, ListenerLimits::CONTROL).await
}

/// Accept only as many sockets as there are lifetime permits. The cap includes
/// incomplete TLS, HTTP parsing, application work and response transmission.
/// A cancelled/full listener never waits for a connection slot during shutdown.
pub async fn serve_metrics(
    listener: TcpListener,
    tls: RustlsConfig,
    app: Router,
    shutdown: CancellationToken,
) -> io::Result<()> {
    serve_bounded_with_limits(listener, tls, app, shutdown, ListenerLimits::METRICS).await
}

async fn serve_bounded_with_limits(
    listener: TcpListener,
    tls: RustlsConfig,
    app: Router,
    shutdown: CancellationToken,
    limits: ListenerLimits,
) -> io::Result<()> {
    let slots = Arc::new(Semaphore::new(limits.connections));
    let mut connections = JoinSet::new();
    let acceptor = RustlsAcceptor::new(tls).handshake_timeout(limits.handshake);
    let result = loop {
        while connections.try_join_next().is_some() {}
        let permit = tokio::select! {
            biased;
            _ = shutdown.cancelled() => break Ok(()),
            permit = slots.clone().acquire_owned() => permit.map_err(|_| io::Error::other("TLS listener closed"))?,
        };
        let accepted = tokio::select! {
            biased;
            _ = shutdown.cancelled() => break Ok(()),
            accepted = listener.accept() => accepted,
        };
        let (socket, _) = match accepted {
            Ok(value) => value,
            Err(error) => break Err(error),
        };
        let started = Instant::now();
        let acceptor = acceptor.clone();
        let app = app.clone();
        let stop = shutdown.clone();
        connections.spawn(async move {
            let _permit = permit;
            let connection = async {
                socket.set_nodelay(true)?;
                let io = BoundedIo::new(socket, limits);
                let (tls, app) = tokio::select! {
                    biased;
                    _ = stop.cancelled() => return Ok::<_, io::Error>(()),
                    accepted = acceptor.accept(io, app) => accepted?,
                };
                let mut builder = Builder::new(TokioExecutor::new());
                if !limits.http2 {
                    builder = builder.http1_only();
                }
                builder
                    .http1()
                    .timer(TokioTimer::new())
                    .header_read_timeout(limits.headers)
                    .max_buf_size(8192)
                    .keep_alive(limits.http2);
                if limits.http2 {
                    builder
                        .http2()
                        .timer(TokioTimer::new())
                        .max_concurrent_streams(4)
                        .max_header_list_size(8192)
                        .initial_stream_window_size(32768)
                        .initial_connection_window_size(131072)
                        .max_send_buf_size(32768);
                }
                let connection =
                    builder.serve_connection(TokioIo::new(tls), TowerToHyperService::new(app));
                tokio::pin!(connection);
                tokio::select! {
                    _ = stop.cancelled() => {
                        connection.as_mut().graceful_shutdown();
                        let _ = tokio::time::timeout(limits.shutdown, connection).await;
                    }
                    _ = &mut connection => {}
                }
                Ok(())
            };
            // Drop the async handlers/body streams at the whole connection
            // deadline. spawn_blocking kernel work cannot be cancelled this
            // way; host control separately holds its work permit and tracks
            // that closure until it actually exits.
            let _ = tokio::time::timeout_at(started + limits.lifetime, connection).await;
        });
    };
    shutdown.cancel();
    if tokio::time::timeout(limits.shutdown, async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    result
}

struct BoundedIo<T> {
    inner: T,
    idle: Pin<Box<Sleep>>,
    stalled_write: Option<Pin<Box<Sleep>>>,
    limits: ListenerLimits,
}
impl<T> BoundedIo<T> {
    fn new(inner: T, limits: ListenerLimits) -> Self {
        Self {
            inner,
            idle: Box::pin(tokio::time::sleep(limits.idle)),
            stalled_write: None,
            limits,
        }
    }
    fn poll_deadlines(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.idle.as_mut().poll(cx).is_ready()
            || self
                .stalled_write
                .as_mut()
                .is_some_and(|t| t.as_mut().poll(cx).is_ready())
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TLS connection deadline",
            ));
        }
        Ok(())
    }
    fn progress(&mut self) {
        self.idle.as_mut().reset(Instant::now() + self.limits.idle);
    }
    fn writing(&mut self, cx: &mut Context<'_>) {
        let timer = self
            .stalled_write
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(self.limits.write_stall)));
        let _ = timer.as_mut().poll(cx);
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for BoundedIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.poll_deadlines(cx)?;
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            this.progress();
        }
        result
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for BoundedIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.poll_deadlines(cx)?;
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        match result {
            Poll::Pending => this.writing(cx),
            Poll::Ready(Ok(n)) if n > 0 => {
                this.stalled_write = None;
                this.progress();
            }
            _ => {}
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.poll_deadlines(cx)?;
        let result = Pin::new(&mut this.inner).poll_flush(cx);
        if result.is_pending() {
            this.writing(cx);
        } else if matches!(result, Poll::Ready(Ok(()))) {
            this.stalled_write = None;
        }
        result
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "tls_tests.rs"]
mod tests;
