//! A termination response becomes evidence only after an authenticated exchange
//! with the exact enrolled node and validation against a fresh DB challenge.
//! This client has no endpoint, PID, executable or filesystem input from tenants.
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use chrono::{DateTime, Utc};
use reqwest::{Certificate, Client, Identity};
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

use crate::nodeguard::protocol::{
    CloseRequest, CloseResponse, GateState, LaunchBinding, MAX_CONTROL_BODY, MAX_SANDBOX_ATTEMPTS,
    NodeBinding, NodeIdentityResponse, ObservationState, PROTOCOL_VERSION, ProcessRole,
    RegisterLaunchRequest, RegisterLaunchResponse, valid_sha256,
};

const MAX_CHALLENGE_SECONDS: i64 = 30;
const CLOCK_SKEW_SECONDS: i64 = 2;
const MAX_PEM_BYTES: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum TerminationClientError {
    #[error("trusted nodeguard connection configuration is invalid")]
    Configuration,
    #[error("nodeguard TLS or transport exchange failed")]
    Transport,
    #[error("nodeguard did not return a successful bounded protocol response")]
    Response,
    #[error("nodeguard response does not match the enrolled identity or challenge")]
    Identity,
    #[error("nodeguard registration or challenge has expired")]
    Expired,
    #[error("nodeguard termination evidence is incomplete or inconsistent")]
    Evidence,
}

/// Dedicated trust material supplied by the operator. Does not implement Debug.
#[derive(Clone)]
pub struct NodeguardCredentials {
    roots: Vec<Certificate>,
    identity: Identity,
}

impl NodeguardCredentials {
    pub fn from_files(
        ca_path: &std::path::Path,
        identity_path: &std::path::Path,
    ) -> anyhow::Result<Self> {
        let read = |path: &std::path::Path, secret| {
            crate::api_tls::read(path, MAX_PEM_BYTES, secret)
                .map_err(|_| anyhow::anyhow!("Nodeguard trust requires absolute bounded regular files, immutable public CA permissions and an owner-only identity or root-owned 0440 with the process primary group"))
        };
        Ok(Self::from_pem(
            &read(ca_path, false)?,
            &read(identity_path, true)?,
        )?)
    }

    pub fn from_pem(
        server_ca: &[u8],
        client_identity: &[u8],
    ) -> Result<Self, TerminationClientError> {
        if server_ca.is_empty()
            || server_ca.len() > MAX_PEM_BYTES
            || client_identity.is_empty()
            || client_identity.len() > MAX_PEM_BYTES
        {
            return Err(TerminationClientError::Configuration);
        }
        let roots = Certificate::from_pem_bundle(server_ca)
            .map_err(|_| TerminationClientError::Configuration)?;
        if roots.is_empty() {
            return Err(TerminationClientError::Configuration);
        }
        let identity = Identity::from_pem(client_identity)
            .map_err(|_| TerminationClientError::Configuration)?;
        Ok(Self { roots, identity })
    }
}

#[derive(Clone)]
pub struct NodeguardClient {
    client: Client,
    origin: String,
    node: NodeBinding,
}

/// No Deserialize implementation or public constructor: wire JSON is not proof.
pub struct VerifiedLocalTermination {
    response: Box<CloseResponse>,
}
impl VerifiedLocalTermination {
    pub(crate) fn response(&self) -> &CloseResponse {
        &self.response
    }
    pub fn node(&self) -> &NodeBinding {
        &self.response.node
    }
    pub fn launch(&self) -> &LaunchBinding {
        &self.response.launch
    }
    pub fn challenge_id(&self) -> uuid::Uuid {
        self.response.challenge_id
    }
    pub fn observed_at(&self) -> DateTime<Utc> {
        self.response.observed_at
    }
}

pub struct VerifiedLaunchRegistration {
    response: RegisterLaunchResponse,
}
impl VerifiedLaunchRegistration {
    pub(crate) fn response(&self) -> &RegisterLaunchResponse {
        &self.response
    }
}

pub enum TerminationObservation {
    Pending(ObservationState),
    Verified(VerifiedLocalTermination),
}

impl NodeguardClient {
    pub(crate) fn node_binding(&self) -> &NodeBinding {
        &self.node
    }

    /// Only operator-enrolled RFC1918 / IPv6 ULA endpoints are accepted. TLS
    /// verifies the fixed NodeUID SAN; the address never goes through DNS.
    pub fn new(
        node: NodeBinding,
        address: SocketAddr,
        credentials: &NodeguardCredentials,
    ) -> Result<Self, TerminationClientError> {
        if !private_address(address.ip()) {
            return Err(TerminationClientError::Configuration);
        }
        Self::build(node, address, credentials)
    }

    fn build(
        node: NodeBinding,
        address: SocketAddr,
        credentials: &NodeguardCredentials,
    ) -> Result<Self, TerminationClientError> {
        if !node.validate() || address.port() == 0 {
            return Err(TerminationClientError::Configuration);
        }
        let server_name = format!("{}.nodeguard.sandbox.internal", node.node_uid);
        let mut builder = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .tls_built_in_root_certs(false)
            .identity(credentials.identity.clone())
            .resolve(&server_name, address)
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            // Each control call gets a fresh connection and certificate check.
            // Reusing a connection near its 15s lifetime would truncate a
            // legitimate 3s CRI stop + 4s host observation. H1 with no idle
            // pool also prevents reuse of an already active H2 connection.
            .http1_only()
            .pool_max_idle_per_host(0);
        for root in &credentials.roots {
            builder = builder.add_root_certificate(root.clone());
        }
        let client = builder
            .build()
            .map_err(|_| TerminationClientError::Configuration)?;
        Ok(Self {
            client,
            origin: format!("https://{server_name}:{}", address.port()),
            node,
        })
    }

    pub async fn verify_node(&self) -> Result<(), TerminationClientError> {
        let response: NodeIdentityResponse = self
            .read(self.client.get(format!("{}/v1/node", self.origin)))
            .await?;
        if response.protocol != PROTOCOL_VERSION || response.node != self.node {
            return Err(TerminationClientError::Identity);
        }
        Ok(())
    }

    pub async fn register(
        &self,
        request: &RegisterLaunchRequest,
    ) -> Result<VerifiedLaunchRegistration, TerminationClientError> {
        self.check_binding(request.protocol, &request.node, &request.launch)?;
        if request.permit_id.is_nil() {
            return Err(TerminationClientError::Identity);
        }
        if request.expires_at <= Utc::now() {
            return Err(TerminationClientError::Expired);
        }
        let response: RegisterLaunchResponse = self.post("/v1/launches/register", request).await?;
        if response.protocol != PROTOCOL_VERSION
            || response.permit_id != request.permit_id
            || response.node != request.node
            || response.launch != request.launch
        {
            return Err(TerminationClientError::Identity);
        }
        if request.expires_at <= Utc::now() {
            return Err(TerminationClientError::Expired);
        }
        if response.state != GateState::Open
            || response.journal_revision <= 0
            || response.effective_expires_at < request.expires_at
        {
            return Err(TerminationClientError::Evidence);
        }
        Ok(VerifiedLaunchRegistration { response })
    }

    /// The caller creates a new bounded, durable challenge on each observation.
    /// A timeout is never retried here and never interpreted as a stopped VM.
    pub async fn close(
        &self,
        request: &CloseRequest,
    ) -> Result<TerminationObservation, TerminationClientError> {
        self.check_binding(request.protocol, &request.node, &request.launch)?;
        let sent_at = Utc::now();
        if request.challenge_id.is_nil() {
            return Err(TerminationClientError::Identity);
        }
        if request.challenge_expires_at <= sent_at
            || request.challenge_expires_at
                > sent_at + chrono::Duration::seconds(MAX_CHALLENGE_SECONDS)
        {
            return Err(TerminationClientError::Expired);
        }
        let response: CloseResponse = self.post("/v1/launches/close", request).await?;
        validate_close(request, &response, sent_at, Utc::now())?;
        if response.state == ObservationState::Terminated {
            Ok(TerminationObservation::Verified(VerifiedLocalTermination {
                response: Box::new(response),
            }))
        } else {
            Ok(TerminationObservation::Pending(response.state))
        }
    }

    fn check_binding(
        &self,
        protocol: u32,
        node: &NodeBinding,
        launch: &LaunchBinding,
    ) -> Result<(), TerminationClientError> {
        if protocol != PROTOCOL_VERSION || node != &self.node || !launch.validate() {
            return Err(TerminationClientError::Identity);
        }
        Ok(())
    }

    async fn post<Q: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        request: &Q,
    ) -> Result<R, TerminationClientError> {
        let body = serde_json::to_vec(request).map_err(|_| TerminationClientError::Response)?;
        if body.len() > MAX_CONTROL_BODY {
            return Err(TerminationClientError::Response);
        }
        self.read(
            self.client
                .post(format!("{}{path}", self.origin))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body),
        )
        .await
    }

    async fn read<R: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<R, TerminationClientError> {
        let mut response = request
            .send()
            .await
            .map_err(|_| TerminationClientError::Transport)?;
        if response.status() != reqwest::StatusCode::OK
            || response
                .content_length()
                .is_some_and(|n| n > MAX_CONTROL_BODY as u64)
            || !response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok())
                .is_some_and(|h| h.split(';').next() == Some("application/json"))
        {
            return Err(TerminationClientError::Response);
        }
        let mut body = Vec::with_capacity(4096);
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| TerminationClientError::Transport)?
        {
            if chunk.len() > MAX_CONTROL_BODY.saturating_sub(body.len()) {
                return Err(TerminationClientError::Response);
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| TerminationClientError::Response)
    }
}

fn private_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private(),
        IpAddr::V6(ip) => ip.is_unique_local(),
    }
}

fn validate_close(
    request: &CloseRequest,
    response: &CloseResponse,
    sent_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
) -> Result<(), TerminationClientError> {
    if response.protocol != PROTOCOL_VERSION
        || response.challenge_id != request.challenge_id
        || response.node != request.node
        || response.launch != request.launch
    {
        return Err(TerminationClientError::Identity);
    }
    let skew = chrono::Duration::seconds(CLOCK_SKEW_SECONDS);
    if received_at >= request.challenge_expires_at
        || response.observed_at > received_at + skew
        || response.observed_at < sent_at - skew
        || response.observed_at >= request.challenge_expires_at
    {
        return Err(TerminationClientError::Expired);
    }
    let Some(e) = &response.evidence else {
        return if response.state == ObservationState::Terminated {
            Err(TerminationClientError::Evidence)
        } else {
            Ok(())
        };
    };
    if response.state != ObservationState::Terminated
        || e.journal_revision <= 0
        || e.observed_sandboxes.len() > MAX_SANDBOX_ATTEMPTS
        || e.forwarded_starts != e.observed_sandboxes.len() as u64
        || e.closed_at > e.processes_exited_at
        || e.processes_exited_at > e.pod_mounts_absent_at
        || e.pod_mounts_absent_at > response.observed_at
    {
        return Err(TerminationClientError::Evidence);
    }
    let mut sandbox_ids = HashSet::new();
    let mut cgroups = HashSet::new();
    let mut process_ids = HashSet::new();
    for sandbox in &e.observed_sandboxes {
        if sandbox.sandbox_id.is_empty()
            || sandbox.sandbox_id.len() > 128
            || !sandbox
                .sandbox_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || !sandbox_ids.insert(sandbox.sandbox_id.as_str())
            || sandbox.registered_at > e.processes_exited_at
            || sandbox.cgroup.inode == 0
            || !cgroups.insert((sandbox.cgroup.device, sandbox.cgroup.inode))
            || !relative_cgroup(&sandbox.cgroup.relative_path)
            || sandbox.processes.len() != 3
        {
            return Err(TerminationClientError::Evidence);
        }
        let mut roles = [false; 3];
        for process in &sandbox.processes {
            let index = match process.role {
                ProcessRole::Hypervisor => 0,
                ProcessRole::Virtiofs => 1,
                ProcessRole::Shim => 2,
            };
            if roles[index]
                || process.pid <= 1
                || process.start_time_ticks == 0
                || !valid_sha256(&process.executable_sha256)
                || !process_ids.insert((process.pid, process.start_time_ticks))
            {
                return Err(TerminationClientError::Evidence);
            }
            roles[index] = true;
        }
    }
    Ok(())
}

fn relative_cgroup(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && !value.starts_with('/')
        && value.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.:@\\".contains(&b))
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub(crate) mod test_support {
    use super::*;
    use crate::nodeguard::protocol::{CloseReason, LocalTerminationEvidence};
    use axum::{
        Json, Router,
        extract::State,
        routing::{get, post},
    };
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    pub fn node() -> NodeBinding {
        NodeBinding {
            cluster_epoch: Uuid::new_v4(),
            node_uid: Uuid::parse_str("10000000-0000-4000-8000-000000000001").expect("test UUID"),
            node_name: "kata-test-1".into(),
            boot_id: Uuid::new_v4(),
            profile_sha256: "a".repeat(64),
        }
    }
    pub fn launch() -> LaunchBinding {
        let workspace_id = Uuid::new_v4();
        LaunchBinding {
            purpose: crate::nodeguard::protocol::LaunchPurpose::Workload,
            tenant_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            instance_id: Uuid::new_v4(),
            workspace_id,
            generation: 1,
            launch_id: Uuid::new_v4(),
            pod_uid: Uuid::new_v4(),
            namespace: "sandbox-test".into(),
            pod_name: format!("sbx-ws-{workspace_id}"),
            pvc_uid: Uuid::new_v4(),
            pv_uid: Uuid::new_v4(),
            pv_name: format!("pvc-{}", Uuid::new_v4()),
            csi_volume_handle: "d-test".into(),
        }
    }
    pub fn request(node: NodeBinding, launch: LaunchBinding) -> CloseRequest {
        CloseRequest {
            protocol: PROTOCOL_VERSION,
            challenge_id: Uuid::new_v4(),
            node,
            launch,
            reason: CloseReason::Stop,
            challenge_expires_at: Utc::now() + chrono::Duration::seconds(25),
        }
    }
    pub fn response(request: &CloseRequest) -> CloseResponse {
        let now = Utc::now();
        CloseResponse {
            protocol: PROTOCOL_VERSION,
            challenge_id: request.challenge_id,
            node: request.node.clone(),
            launch: request.launch.clone(),
            state: ObservationState::Terminated,
            observed_at: now,
            evidence: Some(LocalTerminationEvidence {
                journal_revision: 2,
                observed_sandboxes: vec![],
                forwarded_starts: 0,
                closed_at: now,
                processes_exited_at: now,
                pod_mounts_absent_at: now,
            }),
        }
    }
    pub fn credentials() -> NodeguardCredentials {
        NodeguardCredentials::from_pem(
            include_bytes!("../tests/fixtures/nodeguard/server-ca.pem"),
            &[
                include_bytes!("../tests/fixtures/nodeguard/client.pem").as_slice(),
                include_bytes!("../tests/fixtures/nodeguard/client.key").as_slice(),
            ]
            .concat(),
        )
        .expect("public test credentials")
    }
    pub struct FixtureGuard {
        pub client: NodeguardClient,
        pub address: SocketAddr,
        /// The test server echoes a dynamic challenge unless an override is set.
        pub override_response: Arc<Mutex<Option<CloseResponse>>>,
        pub registrations: Arc<std::sync::atomic::AtomicUsize>,
        // Used by the restore draft's separate test build; its API remains closed.
        #[allow(dead_code)]
        pub registration_revision: Arc<std::sync::atomic::AtomicI64>,
        pub acknowledged_expiry: Arc<Mutex<Option<DateTime<Utc>>>>,
        pub transport_mode: Arc<std::sync::atomic::AtomicU8>,
        pub close_requests: Arc<std::sync::atomic::AtomicUsize>,
        /// Counts server arrivals, not attempted client calls.
        pub identity_verifications: Arc<std::sync::atomic::AtomicUsize>,
        shutdown: tokio_util::sync::CancellationToken,
        task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    }
    impl FixtureGuard {
        pub async fn start(node: NodeBinding) -> anyhow::Result<Self> {
            Self::start_with_server_identity(
                node,
                include_bytes!("../tests/fixtures/nodeguard/server.pem"),
                include_bytes!("../tests/fixtures/nodeguard/server.key"),
                &credentials(),
            )
            .await
        }
        // Public test credentials only. Both paths retain actual mTLS and the
        // production client's exact NodeUID DNS SAN verification.
        pub async fn start_with_server_identity(
            node: NodeBinding,
            server_certificate: &[u8],
            server_key: &[u8],
            credentials: &NodeguardCredentials,
        ) -> anyhow::Result<Self> {
            let tls = crate::tls::control_mutual_tls(
                server_certificate,
                server_key,
                include_bytes!("../tests/fixtures/nodeguard/client-ca.pem"),
            )?;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let shutdown = tokio_util::sync::CancellationToken::new();
            let override_response = Arc::new(Mutex::new(None::<CloseResponse>));
            let registrations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let registration_revision = Arc::new(std::sync::atomic::AtomicI64::new(1));
            let revision = registration_revision.clone();
            let acknowledged_expiry = Arc::new(Mutex::new(None));
            let expiry = acknowledged_expiry.clone();
            let transport_mode = Arc::new(std::sync::atomic::AtomicU8::new(0));
            let mode = transport_mode.clone();
            let close_requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let closes = close_requests.clone();
            let identity_verifications = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let identities = identity_verifications.clone();
            let n = node.clone();
            let counts = registrations.clone();
            let app = Router::new()
                .route(
                    "/v1/node",
                    get(move || {
                        let node = n.clone();
                        let identities = identities.clone();
                        async move {
                            identities.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            Json(NodeIdentityResponse {
                                protocol: PROTOCOL_VERSION,
                                node,
                            })
                        }
                    }),
                )
                .route(
                    "/v1/launches/register",
                    post(move |Json(r): Json<RegisterLaunchRequest>| {
                        let counts = counts.clone();
                        let expiry = expiry.clone();
                        let revision = revision.clone();
                        async move {
                            counts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            Json(RegisterLaunchResponse {
                                protocol: r.protocol,
                                permit_id: r.permit_id,
                                node: r.node,
                                launch: r.launch,
                                state: GateState::Open,
                                journal_revision: revision
                                    .load(std::sync::atomic::Ordering::SeqCst),
                                effective_expires_at: expiry
                                    .lock()
                                    .expect("test mutex")
                                    .unwrap_or(r.expires_at),
                            })
                        }
                    }),
                )
                .route(
                    "/v1/launches/close",
                    post(
                        move |State(state): State<Arc<Mutex<Option<CloseResponse>>>>,
                              Json(r): Json<CloseRequest>| {
                            use axum::response::IntoResponse;
                            let mode = mode.clone();
                            let closes = closes.clone();
                            async move {
                                closes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                match mode.load(std::sync::atomic::Ordering::SeqCst) {
                                    1 => {
                                        return axum::http::Response::builder()
                                            .status(307)
                                            .header("location", "https://forbidden-node.invalid/")
                                            .body(axum::body::Body::empty())
                                            .expect("test response");
                                    }
                                    2 => {
                                        return axum::http::Response::builder()
                                            .header("content-type", "application/json")
                                            .body(axum::body::Body::from_stream(
                                                futures_util::stream::repeat_with(|| {
                                                    Ok::<_, std::io::Error>(
                                                        axum::body::Bytes::from_static(
                                                            &[b'x'; 16384],
                                                        ),
                                                    )
                                                }),
                                            ))
                                            .expect("test response");
                                    }
                                    3 => {
                                        return axum::http::Response::builder()
                                            .status(503)
                                            .header("content-type", "application/json")
                                            .body(axum::body::Body::from("{}"))
                                            .expect("test response");
                                    }
                                    4 => tokio::time::sleep(Duration::from_secs(7)).await,
                                    _ => {}
                                }
                                let result = state
                                    .lock()
                                    .expect("test mutex")
                                    .clone()
                                    .unwrap_or_else(|| response(&r));
                                Json(result).into_response()
                            }
                        },
                    ),
                )
                .with_state(override_response.clone());
            let task = tokio::spawn(crate::tls::serve_control(
                listener,
                tls,
                app,
                shutdown.clone(),
            ));
            let client = NodeguardClient::build(node, address, credentials)?;
            Ok(Self {
                client,
                address,
                override_response,
                registrations,
                registration_revision,
                acknowledged_expiry,
                transport_mode,
                close_requests,
                identity_verifications,
                shutdown,
                task: Some(task),
            })
        }
        pub async fn shutdown(mut self) -> anyhow::Result<()> {
            self.shutdown.cancel();
            if let Some(task) = self.task.take() {
                task.await??;
            }
            Ok(())
        }
    }
    impl Drop for FixtureGuard {
        fn drop(&mut self) {
            self.shutdown.cancel();
            if let Some(task) = self.task.take() {
                task.abort();
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::nodeguard::protocol::{CgroupIdentity, ProcessIdentity, SandboxObservation};

    #[test]
    fn stale_or_inconsistent_wire_evidence_never_becomes_verified() {
        let request = request(node(), launch());
        let valid = response(&request);
        let now = Utc::now();
        validate_close(&request, &valid, now, now).unwrap();
        type WireMutation = Box<dyn Fn(&mut CloseResponse)>;
        let attacks: Vec<WireMutation> = vec![
            Box::new(|r| r.challenge_id = uuid::Uuid::new_v4()),
            Box::new(|r| r.node.boot_id = uuid::Uuid::new_v4()),
            Box::new(|r| r.node.profile_sha256 = "b".repeat(64)),
            Box::new(|r| r.launch.pv_uid = uuid::Uuid::new_v4()),
            Box::new(|r| r.launch.generation += 1),
            Box::new(|r| r.observed_at -= chrono::Duration::seconds(10)),
            Box::new(|r| r.observed_at += chrono::Duration::seconds(10)),
            Box::new(|r| r.evidence = None),
            Box::new(|r| r.evidence.as_mut().unwrap().forwarded_starts = 1),
            Box::new(|r| r.evidence.as_mut().unwrap().journal_revision = 0),
            Box::new(|r| r.evidence.as_mut().unwrap().closed_at += chrono::Duration::seconds(1)),
            Box::new(|r| r.state = ObservationState::WaitingUnmount),
        ];
        for mutate in attacks {
            let mut bad = valid.clone();
            mutate(&mut bad);
            assert!(validate_close(&request, &bad, now, now).is_err());
        }
        let mut waiting = valid.clone();
        waiting.state = ObservationState::UnknownStart;
        waiting.evidence = None;
        validate_close(&request, &waiting, now, now).unwrap();
        assert!(validate_close(&request, &valid, now, request.challenge_expires_at).is_err());
    }

    #[test]
    fn every_forwarded_vm_requires_distinct_complete_host_process_identity() {
        let request = request(node(), launch());
        let mut valid = response(&request);
        let now = Utc::now();
        let evidence = valid.evidence.as_mut().unwrap();
        evidence.forwarded_starts = 1;
        evidence.observed_sandboxes.push(SandboxObservation {
            sandbox_id: "a".repeat(64),
            cgroup: CgroupIdentity {
                relative_path: "kubepods.slice/pod-test.slice/kata-sandbox".into(),
                device: 32,
                inode: 4096,
            },
            processes: [
                ProcessRole::Hypervisor,
                ProcessRole::Virtiofs,
                ProcessRole::Shim,
            ]
            .into_iter()
            .enumerate()
            .map(|(i, role)| ProcessIdentity {
                role,
                pid: 100 + i as u32,
                start_time_ticks: 1000,
                executable_sha256: "a".repeat(64),
            })
            .collect(),
            registered_at: valid.observed_at,
        });
        validate_close(&request, &valid, now, now).unwrap();
        let mut bad = valid.clone();
        bad.evidence.as_mut().unwrap().observed_sandboxes[0]
            .processes
            .pop();
        assert!(validate_close(&request, &bad, now, now).is_err());
        let mut bad = valid.clone();
        let e = bad.evidence.as_mut().unwrap();
        e.observed_sandboxes.push(e.observed_sandboxes[0].clone());
        e.forwarded_starts = 2;
        assert!(validate_close(&request, &bad, now, now).is_err());
        let mut bad = valid.clone();
        bad.evidence.as_mut().unwrap().observed_sandboxes[0]
            .cgroup
            .relative_path = "../somewhere".into();
        assert!(validate_close(&request, &bad, now, now).is_err());
    }

    #[tokio::test]
    async fn actual_mtls_channel_binds_node_and_never_retries_or_accepts_replayed_proof()
    -> anyhow::Result<()> {
        let node = node();
        let guard = FixtureGuard::start(node.clone()).await?;
        guard.client.verify_node().await?;
        let launch = launch();
        let request = request(node.clone(), launch.clone());
        let registration = RegisterLaunchRequest {
            protocol: PROTOCOL_VERSION,
            permit_id: uuid::Uuid::new_v4(),
            node: node.clone(),
            launch,
            expires_at: request.challenge_expires_at,
        };
        let receipt = guard.client.register(&registration).await?;
        assert_eq!(receipt.response().permit_id, registration.permit_id);
        assert_eq!(
            guard
                .registrations
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        let TerminationObservation::Verified(proof) = guard.client.close(&request).await? else {
            panic!("expected verified test server response")
        };
        assert_eq!(proof.response().challenge_id, request.challenge_id);
        let mut bad = response(&request);
        bad.challenge_id = uuid::Uuid::new_v4();
        *guard.override_response.lock().unwrap() = Some(bad);
        assert!(matches!(
            guard.client.close(&request).await,
            Err(TerminationClientError::Identity)
        ));
        let mut wrong_node = node.clone();
        wrong_node.node_uid = uuid::Uuid::new_v4();
        assert!(
            NodeguardClient::build(wrong_node, guard.address, &credentials())?
                .verify_node()
                .await
                .is_err()
        );
        let outsider = NodeguardCredentials::from_pem(
            include_bytes!("../tests/fixtures/nodeguard/server-ca.pem"),
            &[
                include_bytes!("../tests/fixtures/admission/outsider.pem").as_slice(),
                include_bytes!("../tests/fixtures/admission/outsider.key").as_slice(),
            ]
            .concat(),
        )?;
        assert!(
            NodeguardClient::build(node.clone(), guard.address, &outsider)?
                .verify_node()
                .await
                .is_err()
        );
        let wrong_server_ca = NodeguardCredentials::from_pem(
            include_bytes!("../tests/fixtures/admission/server-ca.pem"),
            &[
                include_bytes!("../tests/fixtures/nodeguard/client.pem").as_slice(),
                include_bytes!("../tests/fixtures/nodeguard/client.key").as_slice(),
            ]
            .concat(),
        )?;
        assert!(
            NodeguardClient::build(node.clone(), guard.address, &wrong_server_ca)?
                .verify_node()
                .await
                .is_err()
        );
        assert!(NodeguardClient::new(node, guard.address, &credentials()).is_err());
        guard.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn real_transport_rejects_unbounded_stream_redirect_and_shortened_ack_without_retries()
    -> anyhow::Result<()> {
        use std::sync::atomic::Ordering;
        let node = node();
        let guard = FixtureGuard::start(node.clone()).await?;
        let request = request(node.clone(), launch());
        for mode in 1..=3 {
            guard.transport_mode.store(mode, Ordering::SeqCst);
            let before = guard.close_requests.load(Ordering::SeqCst);
            assert!(matches!(
                guard.client.close(&request).await,
                Err(TerminationClientError::Response)
            ));
            assert_eq!(guard.close_requests.load(Ordering::SeqCst), before + 1);
        }
        let registration = RegisterLaunchRequest {
            protocol: PROTOCOL_VERSION,
            permit_id: uuid::Uuid::new_v4(),
            node,
            launch: request.launch.clone(),
            expires_at: request.challenge_expires_at,
        };
        *guard.acknowledged_expiry.lock().unwrap() =
            Some(registration.expires_at - chrono::Duration::seconds(1));
        assert!(matches!(
            guard.client.register(&registration).await,
            Err(TerminationClientError::Evidence)
        ));
        let mut expired = registration;
        expired.expires_at = Utc::now() - chrono::Duration::seconds(1);
        let before = guard.registrations.load(Ordering::SeqCst);
        assert!(matches!(
            guard.client.register(&expired).await,
            Err(TerminationClientError::Expired)
        ));
        assert_eq!(guard.registrations.load(Ordering::SeqCst), before);
        guard.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn idle_control_calls_cannot_consume_the_next_close_connection_budget()
    -> anyhow::Result<()> {
        use std::sync::atomic::Ordering;
        let node = node();
        let guard = FixtureGuard::start(node.clone()).await?;
        guard.client.verify_node().await?;
        // A pooled connection would now have fewer than 7s of its 15s
        // lifetime left. The following real 7s response must use a new one.
        tokio::time::sleep(Duration::from_secs(9)).await;
        guard.transport_mode.store(4, Ordering::SeqCst);
        let request = request(node, launch());
        let result = guard.client.close(&request).await;
        assert_eq!(guard.close_requests.load(Ordering::SeqCst), 1);
        assert!(matches!(result?, TerminationObservation::Verified(_)));
        guard.shutdown().await?;
        Ok(())
    }
}
