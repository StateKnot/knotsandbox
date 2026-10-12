//! Structured logging with non-overridable credential and HTTP transport exclusions.
use tracing_subscriber::{EnvFilter, filter::filter_fn, fmt::MakeWriter, prelude::*};

pub fn init() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("sandbox_platform=info,sandboxd=info"));
    initialize(filter, std::io::stdout)
}

fn initialize<W>(filter: EnvFilter, writer: W) -> anyhow::Result<()>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    // reqsign-core 3.3.2 logs credential providers with Debug, including at WARN
    // on a load error. Provider Debug can contain AK/secret/STS token. Blocking
    // only DEBUG, or adding an overridable EnvFilter directive, is insufficient.
    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(filter_fn(|metadata| {
            !sensitive_dependency(metadata.target())
        }))
        .with(tracing_subscriber::fmt::layer().json().with_writer(writer));
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_| anyhow::anyhow!("Cannot install the required safe tracing subscriber"))?;
    // log facade records use normalized metadata in the tracing bridge. Deny
    // them before bridging as well, irrespective of RUST_LOG specificity.
    tracing_log::LogTracer::builder()
        .ignore_crate("reqsign")
        .ignore_crate("reqwest")
        .ignore_crate("hyper")
        .ignore_crate("hyper_util")
        .ignore_crate("h2")
        .ignore_crate("http_body")
        .ignore_crate("http_body_util")
        .init()
        .map_err(|_| anyhow::anyhow!("Cannot install the required safe dependency logger"))?;
    Ok(())
}

// STS OIDC uses a query credential in Alibaba's official RPC schema. Transport
// URI/frame diagnostics must stay disabled even when an operator enables trace.
fn sensitive_dependency(target: &str) -> bool {
    [
        "reqsign",
        "reqwest",
        "hyper",
        "hyper_util",
        "h2",
        "http_body",
        "http_body_util",
    ]
    .iter()
    .any(|prefix| target.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| std::io::Error::other("capture poisoned"))?
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn trace_configuration_cannot_reenable_credential_provider_messages() -> anyhow::Result<()> {
        let output = Capture::default();
        let writer = output.clone();
        initialize(
            EnvFilter::new("trace,reqsign_core::api=trace,reqsign_aliyun_oss=trace"),
            move || writer.clone(),
        )?;
        log::debug!(target: "reqsign_core::api", "Trying credential provider: PRIVATE_CREDENTIAL_MARKER");
        log::warn!(target: "reqsign_core::api", "Error loading credential from provider PRIVATE_CREDENTIAL_MARKER");
        log::error!(target: "reqsign_aliyun_oss::sign_request", "PRIVATE_CREDENTIAL_MARKER");
        tracing::error!(target: "reqsign_core::future", "PRIVATE_CREDENTIAL_MARKER");
        tracing::trace!(target: "reqwest::async_impl::client", "https://sts.example/?OIDCToken=PRIVATE_CREDENTIAL_MARKER");
        tracing::error!(target: "hyper_util::client::legacy", "PRIVATE_CREDENTIAL_MARKER");
        log::trace!(target: "hyper::proto::h1", "PRIVATE_CREDENTIAL_MARKER");
        log::warn!(target: "h2::codec", "PRIVATE_CREDENTIAL_MARKER");
        tracing::debug!(target: "http_body_util", "PRIVATE_CREDENTIAL_MARKER");
        tracing::info!(target: "sandbox_platform", "SAFE_APPLICATION_EVENT");
        log::warn!(target: "unrelated_dependency", "SAFE_DEPENDENCY_EVENT");
        let captured = output
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("capture poisoned"))?;
        let text = std::str::from_utf8(&captured)?;
        assert!(!text.contains("PRIVATE_CREDENTIAL_MARKER"));
        assert!(text.contains("SAFE_APPLICATION_EVENT"));
        assert!(text.contains("SAFE_DEPENDENCY_EVENT"));
        Ok(())
    }
}
