//! API transport: direct TLS with a reviewed CA/SAN, no production HTTP fallback.
use axum::{Router, extract::State, http::StatusCode, middleware::Next, response::IntoResponse};
use axum_server::{
    Handle,
    tls_rustls::{RustlsAcceptor, RustlsConfig},
};
use rustls::{
    RootCertStore, ServerConfig,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
};
use std::{
    future::Future,
    io::Read,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

const GRACE: Duration = Duration::from_secs(30);
const RECHECK: Duration = Duration::from_secs(1);
// Includes shutdown + monitor/whole-second clock rounding; old connections
// close before the leaf or intermediate certificate's validity ends.
const VALIDITY_HORIZON: u64 = 34;

#[derive(Clone)]
pub struct ApiTlsFiles {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub ca: PathBuf,
    pub server_name: String,
}

#[derive(Clone)]
struct Validity {
    certificates: Vec<CertificateDer<'static>>,
    verifier: Arc<WebPkiServerVerifier>,
    server_name: ServerName<'static>,
}
impl Validity {
    fn check(&self, now: UnixTime) -> anyhow::Result<()> {
        let until = now
            .as_secs()
            .checked_add(VALIDITY_HORIZON)
            .ok_or_else(|| anyhow::anyhow!("Invalid API TLS clock"))?;
        for timestamp in [now, UnixTime::since_unix_epoch(Duration::from_secs(until))] {
            self.verifier
                .verify_server_cert(
                    &self.certificates[0],
                    &self.certificates[1..],
                    &self.server_name,
                    &[],
                    timestamp,
                )
                .map_err(|_| {
                    anyhow::anyhow!("API TLS certificate chain, SAN or validity check failed")
                })?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct ApiTls {
    config: RustlsConfig,
    validity: Validity,
}

fn private_mode_allowed(uid: u32, gid: u32, mode: u32, euid: u32, egid: u32) -> bool {
    ((uid == euid || uid == 0) && [0o400, 0o600].contains(&mode))
        || (uid == 0 && gid == egid && gid != 0 && mode == 0o440)
}

pub(crate) fn read(path: &Path, limit: usize, private: bool) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(path.is_absolute(), "API TLS paths must be absolute");
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Projected Secret symlinks are allowed; validate the opened target.
        options.custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits());
    }
    let file = options
        .open(path)
        .map_err(|_| anyhow::anyhow!("Cannot open API TLS file"))?;
    let meta = file
        .metadata()
        .map_err(|_| anyhow::anyhow!("Cannot inspect API TLS file"))?;
    anyhow::ensure!(meta.is_file(), "API TLS requires regular files");
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = meta.permissions().mode() & 0o7777;
        if private {
            anyhow::ensure!(
                private_mode_allowed(
                    meta.uid(),
                    meta.gid(),
                    mode,
                    nix::unistd::geteuid().as_raw(),
                    nix::unistd::getegid().as_raw()
                ),
                "API TLS key requires owner-only permissions or root-owned 0440 with the API primary group"
            );
        } else {
            anyhow::ensure!(
                mode & 0o7022 == 0,
                "API TLS certificate and CA must not be group/world writable or special"
            );
        }
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("Cannot read API TLS file"))?;
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= limit,
        "API TLS file exceeds size limit or is empty"
    );
    Ok(bytes)
}

impl ApiTlsFiles {
    pub fn load(&self) -> anyhow::Result<ApiTls> {
        ApiTls::from_pem(
            &read(&self.certificate, 96 * 1024, false)?,
            &read(&self.private_key, 16 * 1024, true)?,
            &read(&self.ca, 64 * 1024, false)?,
            &self.server_name,
        )
    }
}

impl ApiTls {
    fn from_pem(certificate: &[u8], key: &[u8], ca: &[u8], name: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !name.is_empty()
                && name.len() <= 253
                && name.is_ascii()
                && name == name.to_ascii_lowercase()
                && !name.ends_with('.')
                && !name.contains(['/', ':', '*', '@']),
            "API TLS requires a canonical DNS name or IPv4 SAN"
        );
        let server_name = ServerName::try_from(name.to_owned())
            .map_err(|_| anyhow::anyhow!("Invalid API TLS server name"))?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let certificates = CertificateDer::pem_slice_iter(certificate)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| anyhow::anyhow!("Invalid API TLS certificate PEM"))?;
        anyhow::ensure!(
            !certificates.is_empty() && certificates.len() <= 8,
            "API TLS requires a bounded certificate chain"
        );
        let mut roots = RootCertStore::empty();
        for root in CertificateDer::pem_slice_iter(ca) {
            roots
                .add(root.map_err(|_| anyhow::anyhow!("Invalid API TLS CA PEM"))?)
                .map_err(|_| anyhow::anyhow!("Invalid API TLS CA certificate"))?;
        }
        anyhow::ensure!(
            !roots.is_empty() && roots.len() <= 16,
            "API TLS requires a bounded reviewed CA bundle"
        );
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .map_err(|_| anyhow::anyhow!("Invalid API TLS verifier"))?;
        let validity = Validity {
            certificates: certificates.clone(),
            verifier,
            server_name,
        };
        validity.check(UnixTime::now())?;
        let key = PrivateKeyDer::from_pem_slice(key)
            .map_err(|_| anyhow::anyhow!("Invalid API TLS private key PEM"))?;
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .map_err(|_| {
                anyhow::anyhow!("API TLS certificate/private key mismatch or unsupported key")
            })?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        // Certificate checks remain meaningful for every handshake/connection.
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        Ok(Self {
            config: RustlsConfig::from_config(Arc::new(config)),
            validity,
        })
    }
}

fn configure_http(
    builder: &mut hyper_util::server::conn::auto::Builder<hyper_util::rt::TokioExecutor>,
) {
    builder
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(5))
        .max_buf_size(32768);
    builder
        .http2()
        .timer(hyper_util::rt::TokioTimer::new())
        .max_concurrent_streams(128)
        .max_header_list_size(32768)
        .keep_alive_interval(Some(Duration::from_secs(15)))
        .keep_alive_timeout(Duration::from_secs(5));
}

async fn drain_boundary(
    State(shutdown): State<CancellationToken>,
    request: axum::extract::Request,
    next: Next,
) -> axum::response::Response {
    if shutdown.is_cancelled() && request.uri().path() != "/health/live" {
        let mut response = crate::error::ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "API_DRAINING",
            "This API replica is shutting down; retain the original idempotency key",
        )
        .into_response();
        response.headers_mut().insert(
            "cache-control",
            axum::http::HeaderValue::from_static("no-store"),
        );
        return response;
    }
    next.run(request).await
}

/// Only explicit loopback development may omit TLS. All production replicas
/// share this cancellation token with SSE/output/file response bodies.
pub async fn serve(
    listener: TcpListener,
    tls: Option<ApiTls>,
    app: Router,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        tls.is_some() || listener.local_addr()?.ip().is_loopback(),
        "Non-loopback API listener requires TLS"
    );
    if let Some(tls) = &tls {
        tls.validity.check(UnixTime::now())?;
    }
    let validity = tls.as_ref().map(|tls| tls.validity.clone());
    let handle = Handle::new();
    let app = app.layer(axum::middleware::from_fn_with_state(
        shutdown.clone(),
        drain_boundary,
    ));
    let server: Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>> = match tls {
        Some(tls) => {
            let mut server = axum_server::from_tcp(listener.into_std()?)?
                .acceptor(RustlsAcceptor::new(tls.config).handshake_timeout(Duration::from_secs(3)))
                .handle(handle.clone());
            configure_http(server.http_builder());
            Box::pin(server.serve(app.into_make_service()))
        }
        None => {
            let mut server = axum_server::from_tcp(listener.into_std()?)?.handle(handle.clone());
            configure_http(server.http_builder());
            Box::pin(server.serve(app.into_make_service()))
        }
    };
    tokio::pin!(server);
    let mut monitor = tokio::time::interval(RECHECK);
    monitor.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut invalid_certificate = false;
    loop {
        tokio::select! {
            biased;
            result = &mut server => { shutdown.cancel(); return result.map_err(Into::into); },
            () = shutdown.cancelled() => break,
            _ = monitor.tick(), if validity.is_some() => {
                if validity.as_ref().is_some_and(|guard| guard.check(UnixTime::now()).is_err()) {
                    invalid_certificate = true;
                    shutdown.cancel();
                    break;
                }
            }
        }
    }
    handle.graceful_shutdown(Some(GRACE));
    let drained = tokio::time::timeout(GRACE, &mut server).await;
    if drained.is_err() {
        handle.shutdown();
    }
    drained.map_err(|_| anyhow::anyhow!("API graceful shutdown exceeded 30 seconds"))??;
    anyhow::ensure!(
        !invalid_certificate,
        "API TLS validity ended; restart with a renewed reviewed certificate"
    );
    Ok(())
}

#[cfg(test)]
#[path = "api_tls_tests.rs"]
mod tests;
