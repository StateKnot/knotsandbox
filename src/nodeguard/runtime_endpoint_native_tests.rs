//! Actual UDS peers exercise the production reconnect and CONTROL request gates.
//! Replies originate from the owned official daemon, but substitute servers are
//! transport fixtures, not containerd, Kata, mTLS or continuous-config evidence.
use crate::nodeguard::{
    cri::{CriProxy, RuntimeTransport},
    cri_proto::{
        ListPodSandboxRequest, ListPodSandboxResponse, RunPodSandboxRequest, StatusRequest,
        StatusResponse, VersionRequest, VersionResponse,
        runtime_service_client::RuntimeServiceClient, runtime_service_server::RuntimeService,
    },
    host::{HostObserver, HostProfile},
    journal::GateJournal,
    protocol::{
        GateState, LaunchBinding, LaunchPurpose, NodeBinding, PROTOCOL_VERSION,
        RegisterLaunchRequest, RegisterLaunchResponse,
    },
    server,
};
use anyhow::{Context, ensure};
use axum::{body::Body, http::Request as HttpRequest};
use chrono::Utc;
use prost::Message;
use sha2::{Digest, Sha256};
use std::{
    convert::Infallible,
    fs::{File, OpenOptions},
    future::Future,
    io::{Read, Write},
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::process::{Child, Command};
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status, transport::Endpoint};
use tower::{Service, ServiceExt};
use uuid::Uuid;

const SOCKET: &str = "/run/containerd/containerd.sock";
const CHILD_CASE: &str = "nodeguard::runtime_endpoint::native_tests::root_owned_runtime_peer_child";

fn absent(path: &Path) -> anyhow::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
    }
}

fn bounded_file(path: &Path, limit: usize) -> anyhow::Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "root-owned regular fixture file required"
    );
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "bounded fixture file required");
    Ok(bytes)
}

fn private_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(bytes)?)
}

#[derive(Clone, Copy)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}
impl SocketIdentity {
    fn read(path: &Path) -> anyhow::Result<Self> {
        let metadata = std::fs::symlink_metadata(path)?;
        ensure!(
            metadata.file_type().is_socket() && metadata.uid() == 0,
            "owned socket required"
        );
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    fn matches(self, path: &Path) -> bool {
        Self::read(path).is_ok_and(|other| self.device == other.device && self.inode == other.inode)
    }
    fn remove(self, path: &Path) -> anyhow::Result<()> {
        ensure!(
            self.matches(path),
            "refusing to unlink a replaced fixture socket"
        );
        Ok(std::fs::remove_file(path)?)
    }
}

struct OriginalSocket {
    backup: PathBuf,
    identity: SocketIdentity,
    restored: bool,
}
impl OriginalSocket {
    fn take() -> anyhow::Result<Self> {
        let identity = SocketIdentity::read(Path::new(SOCKET))?;
        let backup = PathBuf::from(format!("/run/containerd/official-{}.sock", Uuid::new_v4()));
        ensure!(absent(&backup)?, "new owned backup path required");
        std::fs::rename(SOCKET, &backup)?;
        let saved = Self {
            backup,
            identity,
            restored: false,
        };
        ensure!(
            identity.matches(&saved.backup),
            "original socket identity must survive rename"
        );
        Ok(saved)
    }
    fn restore(&mut self) -> anyhow::Result<()> {
        ensure!(
            absent(Path::new(SOCKET))?,
            "never overwrite an unexpected socket"
        );
        ensure!(
            self.identity.matches(&self.backup),
            "exact original socket required"
        );
        std::fs::rename(&self.backup, SOCKET)?;
        ensure!(
            self.identity.matches(Path::new(SOCKET)),
            "original socket restore must retain its inode"
        );
        self.restored = true;
        Ok(())
    }
}
impl Drop for OriginalSocket {
    fn drop(&mut self) {
        if !self.restored
            && absent(Path::new(SOCKET)).unwrap_or(false)
            && self.identity.matches(&self.backup)
        {
            let _ = std::fs::rename(&self.backup, SOCKET);
        }
    }
}

#[derive(Clone)]
struct Replies {
    version: VersionResponse,
    status: StatusResponse,
}
#[derive(Clone)]
struct PeerServer {
    replies: Replies,
    events: Arc<Mutex<File>>,
}
impl PeerServer {
    fn event(&self, event: &[u8]) -> Result<(), Status> {
        self.events
            .lock()
            .map_err(|_| Status::internal("fixture log unavailable"))?
            .write_all(event)
            .map_err(|_| Status::internal("fixture log unavailable"))
    }
}
type RpcReply<T> = Pin<Box<dyn Future<Output = Result<Response<T>, Status>> + Send>>;
impl tonic::server::UnaryService<VersionRequest> for PeerServer {
    type Response = VersionResponse;
    type Future = RpcReply<VersionResponse>;
    fn call(&mut self, _: Request<VersionRequest>) -> Self::Future {
        let event = self.event(b"VERSION\n");
        let response = self.replies.version.clone();
        Box::pin(async move {
            event?;
            Ok(Response::new(response))
        })
    }
}
impl tonic::server::UnaryService<StatusRequest> for PeerServer {
    type Response = StatusResponse;
    type Future = RpcReply<StatusResponse>;
    fn call(&mut self, request: Request<StatusRequest>) -> Self::Future {
        let event = if request.get_ref().verbose {
            self.event(b"STATUS\n")
        } else {
            Err(Status::invalid_argument("verbose fixture read required"))
        };
        let response = self.replies.status.clone();
        Box::pin(async move {
            event?;
            Ok(Response::new(response))
        })
    }
}
impl tonic::server::UnaryService<ListPodSandboxRequest> for PeerServer {
    type Response = ListPodSandboxResponse;
    type Future = RpcReply<ListPodSandboxResponse>;
    fn call(&mut self, _: Request<ListPodSandboxRequest>) -> Self::Future {
        let event = self.event(b"LIST\n");
        Box::pin(async move {
            event?;
            Ok(Response::new(ListPodSandboxResponse::default()))
        })
    }
}
impl tonic::server::NamedService for PeerServer {
    const NAME: &'static str = "runtime.v1.RuntimeService";
}
impl Service<tonic::codegen::http::Request<tonic::body::Body>> for PeerServer {
    type Response = tonic::codegen::http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;
    fn poll_ready(&mut self, _: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: tonic::codegen::http::Request<tonic::body::Body>) -> Self::Future {
        let service = self.clone();
        let path = request.uri().path().to_owned();
        Box::pin(async move {
            Ok(match path.as_str() {
                "/runtime.v1.RuntimeService/Version" => {
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                        VersionResponse,
                        VersionRequest,
                    >::default())
                    .unary(service, request)
                    .await
                }
                "/runtime.v1.RuntimeService/Status" => {
                    tonic::server::Grpc::new(
                        tonic_prost::ProstCodec::<StatusResponse, StatusRequest>::default(),
                    )
                    .unary(service, request)
                    .await
                }
                "/runtime.v1.RuntimeService/ListPodSandbox" => {
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                        ListPodSandboxResponse,
                        ListPodSandboxRequest,
                    >::default())
                    .unary(service, request)
                    .await
                }
                _ => match service.event(b"FORBIDDEN\n") {
                    Ok(()) => {
                        Status::permission_denied("only fixture reads are available").into_http()
                    }
                    Err(error) => error.into_http(),
                },
            })
        })
    }
}

struct LocalServer {
    identity: SocketIdentity,
    transport: RuntimeTransport,
    stop: CancellationToken,
    task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
}
impl LocalServer {
    fn start(replies: Replies, events: &Path) -> anyhow::Result<Self> {
        ensure!(
            absent(Path::new(SOCKET))?,
            "never replace an existing endpoint"
        );
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(events)?;
        let listener = tokio::net::UnixListener::bind(SOCKET)?;
        let identity = SocketIdentity::read(Path::new(SOCKET))?;
        let service = PeerServer {
            replies,
            events: Arc::new(Mutex::new(file)),
        };
        let transport = RuntimeTransport::new();
        let accepted = transport.clone();
        let incoming = futures_util::stream::unfold(listener, move |listener| {
            let accepted = accepted.clone();
            async move {
                Some((
                    listener
                        .accept()
                        .await
                        .and_then(|(stream, _)| accepted.wrap(stream)),
                    listener,
                ))
            }
        });
        let stop = CancellationToken::new();
        let ending = stop.clone();
        let task = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(incoming, ending.cancelled_owned()),
        );
        Ok(Self {
            identity,
            transport,
            stop,
            task,
        })
    }
    async fn finish(self) -> anyhow::Result<()> {
        self.stop.cancel();
        self.transport.close_io();
        let result = self.task.await;
        self.transport.wait_closed().await;
        let removed = self.identity.remove(Path::new(SOCKET));
        result??;
        removed
    }
}

async fn raw_client(
    transport: RuntimeTransport,
) -> anyhow::Result<RuntimeServiceClient<tonic::transport::Channel>> {
    let channel = Endpoint::from_static("http://[::]:50051")
        .connect_timeout(Duration::from_secs(5))
        .connect_with_connector(tower::service_fn(move |_| {
            let transport = transport.clone();
            async move {
                transport
                    .wrap(tokio::net::UnixStream::connect(SOCKET).await?)
                    .map(hyper_util::rt::TokioIo::new)
            }
        }))
        .await?;
    Ok(RuntimeServiceClient::new(channel).max_decoding_message_size(256 * 1024))
}

async fn capture_official_replies() -> anyhow::Result<Replies> {
    let transport = RuntimeTransport::new();
    let outcome = async {
        let mut client = raw_client(transport.clone()).await?;
        let version = tokio::time::timeout(
            Duration::from_secs(5),
            client.version(VersionRequest {
                version: "0.1.0".into(),
            }),
        )
        .await??
        .into_inner();
        ensure!(
            version.runtime_name == "containerd"
                && version.runtime_version.trim_start_matches('v') == "2.3.5"
                && version.runtime_api_version == "v1"
        );
        let status = tokio::time::timeout(
            Duration::from_secs(5),
            client.status(StatusRequest { verbose: true }),
        )
        .await??
        .into_inner();
        Ok::<_, anyhow::Error>(Replies { version, status })
    }
    .await;
    transport.close_io();
    transport.wait_closed().await;
    outcome
}

struct ChildServer {
    child: Child,
    directory: PathBuf,
    identity: SocketIdentity,
}
impl ChildServer {
    async fn start(directory: &Path, replies: &Replies) -> anyhow::Result<Self> {
        private_file(
            &directory.join("version.pb"),
            &replies.version.encode_to_vec(),
        )?;
        private_file(
            &directory.join("status.pb"),
            &replies.status.encode_to_vec(),
        )?;
        let log = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("child.log"))?;
        let mut child = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                CHILD_CASE,
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .env("SANDBOX_NATIVE_PEER_CHILD_DIR", directory)
            .stdout(log.try_clone()?)
            .stderr(log)
            .kill_on_drop(true)
            .spawn()?;
        let ready = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                ensure!(
                    child.try_wait()?.is_none(),
                    "owned peer child exited before readiness"
                );
                if directory.join("ready").is_file() {
                    let pid = String::from_utf8(bounded_file(&directory.join("ready"), 32)?)?
                        .parse::<u32>()?;
                    ensure!(
                        Some(pid) == child.id() && pid != std::process::id(),
                        "actual independent root child PID required"
                    );
                    return SocketIdentity::read(Path::new(SOCKET));
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        let failure = match ready {
            Ok(Ok(identity)) => {
                return Ok(Self {
                    child,
                    directory: directory.to_owned(),
                    identity,
                });
            }
            Ok(Err(error)) => error,
            Err(error) => anyhow::Error::from(error).context("peer child readiness deadline"),
        };
        let _ = child.start_kill();
        let _ = child.wait().await;
        let metadata = std::fs::symlink_metadata(directory)?;
        let log = bounded_file(&directory.join("child.log"), 8192)?;
        Err(failure.context(format!(
            "owned child directory uid={} mode={:o}; bounded child output: {}",
            metadata.uid(),
            metadata.mode() & 0o777,
            String::from_utf8_lossy(&log)
        )))
    }
    async fn finish(mut self) -> anyhow::Result<()> {
        let signalled = private_file(&self.directory.join("stop"), b"");
        let waited = tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await;
        let status = match waited {
            Ok(status) => status.map_err(anyhow::Error::from),
            Err(_) => {
                let _ = self.child.start_kill();
                let _ = self.child.wait().await;
                Err(anyhow::anyhow!(
                    "owned peer child did not retire within its original fixture deadline"
                ))
            }
        };
        // The graceful child normally removes its socket. Unexpected remnants
        // may be removed only if they still match this exact child's inode.
        let removed = if !absent(Path::new(SOCKET))? {
            self.identity.remove(Path::new(SOCKET))
        } else {
            Ok(())
        };
        signalled?;
        if !status?.success() {
            let log = bounded_file(&self.directory.join("child.log"), 8192)?;
            anyhow::bail!("owned peer child failed: {}", String::from_utf8_lossy(&log));
        }
        removed
    }
}

fn registration(node: NodeBinding) -> RegisterLaunchRequest {
    let workspace_id = Uuid::new_v4();
    RegisterLaunchRequest {
        protocol: PROTOCOL_VERSION,
        permit_id: Uuid::new_v4(),
        node,
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        launch: LaunchBinding {
            purpose: LaunchPurpose::Workload,
            tenant_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            instance_id: Uuid::new_v4(),
            workspace_id,
            generation: 1,
            launch_id: Uuid::new_v4(),
            pod_uid: Uuid::new_v4(),
            namespace: "native-runtime-peer".into(),
            pod_name: format!("sbx-ws-{workspace_id}"),
            pvc_uid: Uuid::new_v4(),
            pv_uid: Uuid::new_v4(),
            pv_name: "pv-native-runtime-peer".into(),
            csi_volume_handle: "d-native-runtime-peer".into(),
        },
    }
}
async fn control_register(
    proxy: Arc<CriProxy>,
    request: &RegisterLaunchRequest,
) -> anyhow::Result<(axum::http::StatusCode, Vec<u8>)> {
    let response = server::router(proxy)
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/v1/launches/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(request)?))?,
        )
        .await?;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await?
        .to_vec();
    Ok((status, body))
}

async fn replacement_health(events: &Path, replies: &Replies) -> anyhow::Result<Vec<u8>> {
    let transport = RuntimeTransport::new();
    let outcome = async {
        let mut probe = raw_client(transport.clone()).await?;
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            probe.version(VersionRequest {
                version: "0.1.0".into(),
            }),
        )
        .await??
        .into_inner();
        ensure!(
            response == replies.version,
            "replacement must really serve the healthy pinned Version response"
        );
        let events = bounded_file(events, 8192)?;
        ensure!(
            events == b"VERSION\n",
            "one independent replacement health RPC required"
        );
        Ok::<_, anyhow::Error>(events)
    }
    .await;
    transport.close_io();
    transport.wait_closed().await;
    outcome
}

async fn control_must_remain_drained(
    proxy: Arc<CriProxy>,
    node: NodeBinding,
) -> anyhow::Result<()> {
    ensure!(
        proxy.tasks.is_closed() && proxy.read_shutdown.is_cancelled(),
        "permanent rejection must retain the volatile drain"
    );
    ensure!(
        tokio::time::timeout(
            Duration::from_secs(5),
            RuntimeService::run_pod_sandbox(
                &*proxy,
                Request::new(RunPodSandboxRequest {
                    runtime_handler: "runc".into(),
                    config: None
                })
            )
        )
        .await?
        .is_err(),
        "new CRI mutation work must be rejected before reaching the replacement peer"
    );
    let (status, body) = control_register(proxy, &registration(node)).await?;
    ensure!(status == axum::http::StatusCode::SERVICE_UNAVAILABLE);
    ensure!(
        serde_json::from_slice::<serde_json::Value>(&body)?
            == serde_json::json!({"error":"GUARD_UNAVAILABLE"}),
        "normal CONTROL must refuse new work after volatile drain"
    );
    Ok(())
}

async fn replacement_round(
    profile: &HostProfile,
    profile_bytes: &[u8],
    replies: &Replies,
    child_peer: bool,
) -> anyhow::Result<()> {
    let directory = tempfile::Builder::new()
        .prefix("runtime-peer-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/run")?;
    let node = NodeBinding {
        cluster_epoch: Uuid::new_v4(),
        node_uid: Uuid::new_v4(),
        node_name: "native-runtime-peer-fixture".into(),
        boot_id: Uuid::parse_str(
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        )?,
        profile_sha256: hex::encode(Sha256::digest(profile_bytes)),
    };
    let observer = Arc::new(HostObserver::new(profile.clone(), node.clone())?);
    let journal =
        GateJournal::open(&directory.path().join("journal.sqlite3"), node.clone()).await?;
    let mut original = None;
    let mut replacement = None;
    let mut child = None;
    let mut proxy = None;
    let direct_binding = super::RuntimeEndpoint::default();
    let outcome = async {
        original = Some(LocalServer::start(
            replies.clone(),
            &directory.path().join("original.events"),
        )?);
        let original_identity = original.as_ref().context("original owned peer")?.identity;
        // The direct production interface shares the same kernel checks as
        // CRI's connector and proves rejection cannot later relearn a peer.
        drop(tokio::time::timeout(Duration::from_secs(5), direct_binding.connect()).await??);
        drop(tokio::time::timeout(Duration::from_secs(5), direct_binding.connect()).await??);
        ensure!(
            !direct_binding.is_rejected(),
            "the original socket and root peer may reconnect normally"
        );
        let connected = Arc::new(CriProxy::connect(journal.clone(), observer).await?);
        proxy = Some(connected.clone());
        connected.verify_startup().await?;
        let request = registration(node.clone());
        let (status, body) = control_register(connected.clone(), &request).await?;
        ensure!(
            status == axum::http::StatusCode::OK,
            "normal CONTROL registration must initially succeed"
        );
        let response: RegisterLaunchResponse = serde_json::from_slice(&body)?;
        ensure!(
            response.state == GateState::Open
                && response.node == node
                && response.launch == request.launch
        );
        original
            .take()
            .context("owned original server")?
            .finish()
            .await?;

        let events = if child_peer {
            child = Some(ChildServer::start(directory.path(), replies).await?);
            directory.path().join("child.events")
        } else {
            replacement = Some(LocalServer::start(
                replies.clone(),
                &directory.path().join("replacement.events"),
            )?);
            directory.path().join("replacement.events")
        };
        ensure!(
            !original_identity.matches(Path::new(SOCKET)),
            "the counterexample must replace the real socket inode"
        );
        let before = replacement_health(&events, replies).await?;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                ensure!(
                    RuntimeService::version(
                        &*connected,
                        Request::new(VersionRequest {
                            version: "0.1.0".into()
                        })
                    )
                    .await
                    .is_err(),
                    "an old proxy must not accept a replacement peer"
                );
                if connected.tasks.is_closed() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context(
            "actual Tonic reconnect must permanently drain within the original five seconds",
        )??;
        ensure!(
            connected.read_shutdown.is_cancelled(),
            "identity rejection must cancel pure reads"
        );
        ensure!(
            bounded_file(&events, 8192)? == before,
            "the replacement must receive no old-proxy business RPC"
        );
        control_must_remain_drained(connected.clone(), node.clone()).await?;
        ensure!(
            bounded_file(&events, 8192)? == before,
            "drained CRI mutation and CONTROL must forward no RPC to the replacement"
        );
        ensure!(
            tokio::time::timeout(Duration::from_secs(5), direct_binding.connect())
                .await?
                .is_err()
        );
        ensure!(
            direct_binding.is_rejected(),
            "a replaced listener must permanently reject the binding"
        );

        if let Some(server) = replacement.take() {
            server.finish().await?;
        }
        if let Some(server) = child.take() {
            server.finish().await?;
        }
        let next_events = directory.path().join("next-root-peer.events");
        replacement = Some(LocalServer::start(replies.clone(), &next_events)?);
        let next_before = replacement_health(&next_events, replies).await?;
        ensure!(
            tokio::time::timeout(Duration::from_secs(5), direct_binding.connect())
                .await?
                .is_err()
                && direct_binding.is_rejected(),
            "a later healthy root listener cannot revive a rejected binding"
        );
        ensure!(
            tokio::time::timeout(
                Duration::from_secs(5),
                RuntimeService::version(
                    &*connected,
                    Request::new(VersionRequest {
                        version: "0.1.0".into()
                    })
                )
            )
            .await?
            .is_err(),
            "an already drained proxy must not revive for a later healthy root listener"
        );
        control_must_remain_drained(connected, node).await?;
        ensure!(
            bounded_file(&next_events, 8192)? == next_before,
            "sticky rejection must forward no RPC to a later healthy listener"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Some(proxy) = proxy {
        proxy.close_reads();
        proxy.tasks.close();
        proxy.tasks.wait().await;
        drop(proxy);
    }
    let initial_cleanup = if let Some(server) = original {
        server.finish().await
    } else {
        Ok(())
    };
    let replacement_cleanup = if let Some(server) = replacement {
        server.finish().await
    } else {
        Ok(())
    };
    let child_cleanup = if let Some(server) = child {
        server.finish().await
    } else {
        Ok(())
    };
    journal.shutdown().await;
    outcome?;
    initial_cleanup?;
    replacement_cleanup?;
    child_cleanup
}

#[tokio::test]
#[ignore = "Owned root Linux helper; invoked only by the exact isolated runtime-peer parent case"]
async fn root_owned_runtime_peer_child() -> anyhow::Result<()> {
    ensure!(
        rustix::process::geteuid().is_root(),
        "root fixture peer required"
    );
    let directory = PathBuf::from(std::env::var("SANDBOX_NATIVE_PEER_CHILD_DIR")?);
    ensure!(
        directory.starts_with("/run")
            && directory
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("runtime-peer-"))
    );
    let metadata = std::fs::symlink_metadata(&directory)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o077 == 0,
        "private parent-owned fixture directory required"
    );
    let replies = Replies {
        version: VersionResponse::decode(
            bounded_file(&directory.join("version.pb"), 4096)?.as_slice(),
        )?,
        status: StatusResponse::decode(
            bounded_file(&directory.join("status.pb"), 256 * 1024)?.as_slice(),
        )?,
    };
    let server = LocalServer::start(replies, &directory.join("child.events"))?;
    let outcome = async {
        private_file(
            &directory.join("ready.pending"),
            std::process::id().to_string().as_bytes(),
        )?;
        std::fs::rename(directory.join("ready.pending"), directory.join("ready"))?;
        loop {
            if directory.join("stop").is_file() {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    .await;
    let retired = server.finish().await;
    outcome?;
    retired
}

#[tokio::test]
#[ignore = "Requires the exact isolated native containerd 2.3.5 fixture; no shim or VM is started"]
async fn root_reconnect_binding_drains_control_without_forwarding_to_replacements()
-> anyhow::Result<()> {
    ensure!(
        rustix::process::geteuid().is_root(),
        "owned root Linux fixture required"
    );
    ensure!(std::env::var("SANDBOX_NATIVE_IMAGE_PROFILE")? == "/fixture/host-profile.json");
    let profile_bytes = bounded_file(Path::new("/fixture/host-profile.json"), 64 * 1024)?;
    let profile: HostProfile = serde_json::from_slice(&profile_bytes)?;
    let replies = capture_official_replies().await?;
    let mut original = OriginalSocket::take()?;
    let outcome = async {
        replacement_round(&profile, &profile_bytes, &replies, false).await?;
        replacement_round(&profile, &profile_bytes, &replies, true).await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let restored = original.restore();
    outcome?;
    restored?;
    let restored_replies = capture_official_replies().await?;
    ensure!(
        restored_replies.version == replies.version,
        "official daemon must remain healthy after exact socket restoration"
    );
    println!("NODEGUARD_NATIVE_RUNTIME_PEER_BINDING_VERIFIED");
    Ok(())
}
