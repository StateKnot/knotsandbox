//! Trusted, host-only CRI admission and termination observation.
#[cfg(any(target_os = "linux", test))]
mod backup_gate;
#[cfg(any(target_os = "linux", test))]
mod capacity;
#[cfg(target_os = "linux")]
pub mod cri;
#[cfg(any(target_os = "linux", test))]
mod cri_transport;
#[cfg(any(target_os = "linux", test))]
mod cri_work;
pub mod host;
pub mod image_observation;
pub mod journal;
#[cfg(any(target_os = "linux", test))]
pub mod metrics;
#[cfg(target_os = "linux")]
pub mod metrics_server;
pub mod protocol;
#[cfg(any(target_os = "linux", test))]
mod runtime_observation;
#[cfg(any(target_os = "linux", test))]
pub mod server;
#[allow(clippy::all)]
#[allow(rustdoc::invalid_html_tags)]
pub mod cri_proto {
    include!("generated/runtime.v1.rs");
}

#[derive(Debug, thiserror::Error)]
pub enum GuardError {
    #[error("nodeguard identity or protocol is invalid")]
    Invalid,
    #[error("nodeguard identity differs from the enrolled node/launch")]
    IdentityMismatch,
    #[error("managed starts are closed or the node requires fencing")]
    Closed,
    #[error("a start is already in flight")]
    InFlight,
    #[error("the runtime outcome is unknown; fencing is required")]
    Unknown,
    #[error("the registration or challenge has expired")]
    Expired,
    #[error("the host journal cannot establish its durable state")]
    Journal(#[from] sqlx::Error),
    #[error("the host observation is unavailable")]
    Io(#[from] std::io::Error),
    #[error("the host journal record is invalid")]
    Encoding(#[from] serde_json::Error),
}
