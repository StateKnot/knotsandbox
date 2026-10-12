//! Real TCP/HTTP2 gRPC calls and cancellation use the production owned-work
//! helper. The backend explicitly simulates containerd lookup/effects; this
//! neither instantiates the Linux HostObserver nor certifies Linux CRI wiring.
use super::*;
use crate::nodeguard::cri_proto::{
    ContainerEventResponse, CreateContainerRequest, CreateContainerResponse, GetEventsRequest,
    PodSandboxStatusRequest, PodSandboxStatusResponse,
    runtime_service_client::RuntimeServiceClient,
};
use std::{
    convert::Infallible,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, body::Body, codegen::http, transport::Channel};
use tower::Service;

#[derive(Default)]
struct Backend {
    lookups: AtomicUsize,
    effects: AtomicUsize,
    lookup_entered: Notify,
    lookup_release: Notify,
    effect_entered: Notify,
    effect_release: Notify,
    lookup_dropped: Arc<AtomicUsize>,
    watches: AtomicUsize,
    watch_dropped: Arc<AtomicUsize>,
    watch_burst: bool,
    watch_produced: Arc<AtomicUsize>,
}
impl Backend {
    fn release(&self) {
        self.lookup_release.notify_one();
        self.effect_release.notify_one();
    }
}
struct ReleaseOnDrop(Arc<Backend>);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

type HttpFuture =
    Pin<Box<dyn Future<Output = Result<http::Response<Body>, Infallible>> + Send + 'static>>;

#[derive(Clone)]
struct RuntimeFixture {
    backend: Arc<Backend>,
}
struct LookupService(Arc<Backend>);
impl tonic::server::UnaryService<PodSandboxStatusRequest> for LookupService {
    type Response = PodSandboxStatusResponse;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Self::Response>, Status>> + Send>>;
    fn call(&mut self, _: Request<PodSandboxStatusRequest>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            let _drop = AwaiterDrop(state.lookup_dropped.clone());
            state.lookups.fetch_add(1, Ordering::SeqCst);
            state.lookup_entered.notify_one();
            state.lookup_release.notified().await;
            Ok(Response::new(PodSandboxStatusResponse::default()))
        })
    }
}
struct EventsService(Arc<Backend>);
struct WatchedEvents {
    events: ReadStream<ContainerEventResponse>,
    _drop: AwaiterDrop,
}
impl Stream for WatchedEvents {
    type Item = Result<ContainerEventResponse, Status>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().events.as_mut().poll_next(cx)
    }
}
impl tonic::server::ServerStreamingService<GetEventsRequest> for EventsService {
    type Response = ContainerEventResponse;
    type ResponseStream = ReadStream<ContainerEventResponse>;
    type Future =
        Pin<Box<dyn Future<Output = Result<Response<Self::ResponseStream>, Status>> + Send>>;
    fn call(&mut self, _: Request<GetEventsRequest>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            state.watches.fetch_add(1, Ordering::SeqCst);
            let first = futures_util::stream::once(async {
                Ok(ContainerEventResponse {
                    container_id: "public-first-event".into(),
                    ..Default::default()
                })
            });
            let following: ReadStream<ContainerEventResponse> = if state.watch_burst {
                let produced = state.watch_produced.clone();
                Box::pin(futures_util::stream::iter((0..16).map(move |_| {
                    produced.fetch_add(1, Ordering::SeqCst);
                    Ok(ContainerEventResponse {
                        container_id: "p".repeat(128 * 1024),
                        ..Default::default()
                    })
                })))
            } else {
                Box::pin(futures_util::stream::pending())
            };
            let events = first.chain(following);
            let mut response = Response::new(Box::pin(WatchedEvents {
                events: Box::pin(events),
                _drop: AwaiterDrop(state.watch_dropped.clone()),
            }) as ReadStream<ContainerEventResponse>);
            response.metadata_mut().insert(
                "x-public-watch",
                "preserved"
                    .parse()
                    .map_err(|_| Status::internal("fixture metadata"))?,
            );
            Ok(response)
        })
    }
}
struct EffectService(Arc<Backend>);
impl tonic::server::UnaryService<CreateContainerRequest> for EffectService {
    type Response = CreateContainerResponse;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Self::Response>, Status>> + Send>>;
    fn call(&mut self, _: Request<CreateContainerRequest>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            state.effects.fetch_add(1, Ordering::SeqCst);
            state.effect_entered.notify_one();
            state.effect_release.notified().await;
            Ok(Response::new(CreateContainerResponse {
                container_id: "public-simulated-effect".into(),
            }))
        })
    }
}
impl Service<http::Request<Body>> for RuntimeFixture {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = HttpFuture;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let backend = self.backend.clone();
        Box::pin(async move {
            let response = match request.uri().path() {
                "/runtime.v1.RuntimeService/PodSandboxStatus" => {
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::default())
                        .unary(LookupService(backend), request)
                        .await
                }
                "/runtime.v1.RuntimeService/CreateContainer" => {
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::default())
                        .unary(EffectService(backend), request)
                        .await
                }
                "/runtime.v1.RuntimeService/GetContainerEvents" => {
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::default())
                        .server_streaming(EventsService(backend), request)
                        .await
                }
                _ => Status::unimplemented("Fixture RPC").into_http(),
            };
            Ok(response)
        })
    }
}
impl tonic::server::NamedService for RuntimeFixture {
    const NAME: &'static str = "runtime.v1.RuntimeService";
}

#[derive(Clone)]
struct GuardedCreateFixture {
    tasks: TaskTracker,
    read_shutdown: CancellationToken,
    upstream: RuntimeServiceClient<Channel>,
    awaiters_dropped: Arc<AtomicUsize>,
    peers: Arc<Mutex<Vec<std::net::SocketAddr>>>,
}
impl GuardedCreateFixture {
    fn record_peer<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let peer = request
            .extensions()
            .get::<tonic::transport::server::TcpConnectInfo>()
            .and_then(|info| info.remote_addr())
            .ok_or_else(|| Status::internal("Actual TCP peer required"))?;
        self.peers
            .lock()
            .map_err(|_| Status::internal("Fixture peer lock"))?
            .push(peer);
        Ok(())
    }
}
struct AwaiterDrop(Arc<AtomicUsize>);
impl Drop for AwaiterDrop {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
impl tonic::server::UnaryService<CreateContainerRequest> for GuardedCreateFixture {
    type Response = CreateContainerResponse;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Self::Response>, Status>> + Send>>;
    fn call(&mut self, request: Request<CreateContainerRequest>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            this.record_peer(&request)?;
            let _drop = AwaiterDrop(this.awaiters_dropped.clone());
            let tasks = this.tasks;
            let mut upstream = this.upstream;
            owned_rpc(&tasks, move || async move {
                if request.get_ref().pod_sandbox_id != "public-system-passthrough" {
                    // Actual upstream gRPC lookup precedes the simulated effect.
                    upstream
                        .pod_sandbox_status(PodSandboxStatusRequest {
                            pod_sandbox_id: request.get_ref().pod_sandbox_id.clone(),
                            verbose: false,
                        })
                        .await?;
                }
                upstream.create_container(request).await
            })
            .await
        })
    }
}
impl tonic::server::UnaryService<PodSandboxStatusRequest> for GuardedCreateFixture {
    type Response = PodSandboxStatusResponse;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Self::Response>, Status>> + Send>>;
    fn call(&mut self, request: Request<PodSandboxStatusRequest>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            this.record_peer(&request)?;
            let _drop = AwaiterDrop(this.awaiters_dropped.clone());
            let tasks = this.tasks;
            let mut upstream = this.upstream;
            read_rpc(&tasks, &this.read_shutdown, move || async move {
                upstream.pod_sandbox_status(request).await
            })
            .await
        })
    }
}
impl tonic::server::ServerStreamingService<GetEventsRequest> for GuardedCreateFixture {
    type Response = ContainerEventResponse;
    type ResponseStream = ReadStream<ContainerEventResponse>;
    type Future =
        Pin<Box<dyn Future<Output = Result<Response<Self::ResponseStream>, Status>> + Send>>;
    fn call(&mut self, request: Request<GetEventsRequest>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            this.record_peer(&request)?;
            let mut upstream = this.upstream;
            let response = read_rpc(&this.tasks, &this.read_shutdown, move || async move {
                upstream.get_container_events(request).await
            })
            .await?;
            Ok(read_stream_response(response, this.read_shutdown))
        })
    }
}
impl Service<http::Request<Body>> for GuardedCreateFixture {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = HttpFuture;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let service = self.clone();
        Box::pin(async move {
            let response = match request.uri().path() {
                "/runtime.v1.RuntimeService/PodSandboxStatus" => {
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                        PodSandboxStatusResponse,
                        PodSandboxStatusRequest,
                    >::default())
                    .unary(service, request)
                    .await
                }
                "/runtime.v1.RuntimeService/GetContainerEvents" => {
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                        ContainerEventResponse,
                        GetEventsRequest,
                    >::default())
                    .server_streaming(service, request)
                    .await
                }
                _ => {
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                        CreateContainerResponse,
                        CreateContainerRequest,
                    >::default())
                    .unary(service, request)
                    .await
                }
            };
            Ok(response)
        })
    }
}
impl tonic::server::NamedService for GuardedCreateFixture {
    const NAME: &'static str = "runtime.v1.RuntimeService";
}

struct Server {
    client: RuntimeServiceClient<Channel>,
    address: std::net::SocketAddr,
    transport: RuntimeTransport,
    cancel: CancellationToken,
    task: Option<tokio::task::JoinHandle<Result<(), tonic::transport::Error>>>,
}
impl Server {
    async fn stop(mut self) -> anyhow::Result<()> {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            tokio::time::timeout(Duration::from_secs(5), task).await???;
        }
        assert_eq!(self.transport.connection_count(), 0);
        Ok(())
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
async fn serve<S>(
    service: S,
    reads: Option<(TaskTracker, CancellationToken)>,
) -> anyhow::Result<Server>
where
    S: Service<http::Request<Body>, Response = http::Response<Body>, Error = Infallible>
        + tonic::server::NamedService
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send + 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let transport = RuntimeTransport::new();
    let incoming = futures_util::stream::unfold(
        (listener, transport.clone()),
        |(listener, transport)| async {
            Some((
                listener
                    .accept()
                    .await
                    .and_then(|(stream, _)| transport.wrap(stream)),
                (listener, transport),
            ))
        },
    );
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let signal = stop.clone();
    let parent = tonic::transport::Server::builder()
        .concurrency_limit_per_connection(64)
        .add_service(service)
        .serve_with_incoming_shutdown(incoming, signal.cancelled_owned());
    let connection_owner = transport.clone();
    let task = tokio::spawn(async move {
        serve_read_parent(
            &stop,
            parent,
            || {
                if let Some((tasks, reads)) = reads {
                    begin_drain(&tasks, &reads);
                }
            },
            &connection_owner,
        )
        .await
    });
    Ok(Server {
        client: RuntimeServiceClient::connect(format!("http://{address}")).await?,
        address,
        transport,
        cancel,
        task: Some(task),
    })
}

async fn cancelled_lookup_then_effect(system_passthrough: bool) -> anyhow::Result<()> {
    let backend = Arc::new(Backend::default());
    let _release = ReleaseOnDrop(backend.clone());
    let upstream = serve(
        RuntimeFixture {
            backend: backend.clone(),
        },
        None,
    )
    .await?;
    let tasks = TaskTracker::new();
    let dropped = Arc::new(AtomicUsize::new(0));
    let proxy = serve(
        GuardedCreateFixture {
            tasks: tasks.clone(),
            read_shutdown: CancellationToken::new(),
            upstream: upstream.client.clone(),
            awaiters_dropped: dropped.clone(),
            peers: Arc::default(),
        },
        None,
    )
    .await?;
    let request = CreateContainerRequest {
        pod_sandbox_id: if system_passthrough {
            "public-system-passthrough"
        } else {
            "public-managed-lookup"
        }
        .into(),
        ..Default::default()
    };
    let mut client = proxy.client.clone();
    let original = request.clone();
    let caller = tokio::spawn(async move { client.create_container(original).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        if system_passthrough {
            backend.effect_entered.notified().await;
        } else {
            backend.lookup_entered.notified().await;
        }
    })
    .await?;
    caller.abort();
    let _ = caller.await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while dropped.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    tasks.close();
    assert_eq!(
        tasks.len(),
        1,
        "Cancellation must retain the entire owned RPC"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), tasks.wait())
            .await
            .is_err()
    );
    let denied = proxy
        .client
        .clone()
        .create_container(request.clone())
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("Closing runtime accepted a new request"))?;
    assert_eq!(denied.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        backend.lookups.load(Ordering::SeqCst),
        usize::from(!system_passthrough)
    );
    assert_eq!(
        backend.effects.load(Ordering::SeqCst),
        usize::from(system_passthrough)
    );
    if !system_passthrough {
        backend.lookup_release.notify_one();
        tokio::time::timeout(Duration::from_secs(2), backend.effect_entered.notified()).await?;
        assert_eq!(backend.effects.load(Ordering::SeqCst), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), tasks.wait())
                .await
                .is_err()
        );
    }
    backend.effect_release.notify_one();
    tokio::time::timeout(Duration::from_secs(2), tasks.wait()).await?;
    assert_eq!(
        backend.effects.load(Ordering::SeqCst),
        1,
        "No request replay"
    );
    let denied = proxy
        .client
        .clone()
        .create_container(request)
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("Drained runtime accepted a new request"))?;
    assert_eq!(denied.code(), tonic::Code::FailedPrecondition);
    assert_eq!(backend.effects.load(Ordering::SeqCst), 1);
    proxy.stop().await?;
    upstream.stop().await?;
    Ok(())
}

#[tokio::test]
async fn real_grpc_cancel_during_prelookup_keeps_single_owned_effect_until_ack()
-> anyhow::Result<()> {
    cancelled_lookup_then_effect(false).await
}

#[tokio::test]
async fn real_grpc_cancelled_system_passthrough_keeps_the_dispatch_until_ack() -> anyhow::Result<()>
{
    cancelled_lookup_then_effect(true).await
}

#[tokio::test]
async fn already_closed_tracker_cannot_call_even_the_work_factory() -> anyhow::Result<()> {
    let tasks = TaskTracker::new();
    tasks.close();
    let calls = Arc::new(AtomicUsize::new(0));
    let recorded = calls.clone();
    let result = owned_rpc(&tasks, move || {
        recorded.fetch_add(1, Ordering::SeqCst);
        async { Ok::<_, Status>(()) }
    })
    .await;
    assert_eq!(
        result.err().map(|s| s.code()),
        Some(tonic::Code::FailedPrecondition)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    tokio::time::timeout(Duration::from_secs(1), tasks.wait()).await?;
    Ok(())
}

#[tokio::test]
async fn real_grpc_read_cancel_returns_token_without_detached_work_and_closed_read_has_no_io()
-> anyhow::Result<()> {
    let backend = Arc::new(Backend::default());
    let _release = ReleaseOnDrop(backend.clone());
    let upstream = serve(
        RuntimeFixture {
            backend: backend.clone(),
        },
        None,
    )
    .await?;
    let tasks = TaskTracker::new();
    let dropped = Arc::new(AtomicUsize::new(0));
    let proxy = serve(
        GuardedCreateFixture {
            tasks: tasks.clone(),
            read_shutdown: CancellationToken::new(),
            upstream: upstream.client.clone(),
            awaiters_dropped: dropped.clone(),
            peers: Arc::default(),
        },
        None,
    )
    .await?;
    let request = PodSandboxStatusRequest {
        pod_sandbox_id: "public-read-only".into(),
        verbose: false,
    };
    let mut client = proxy.client.clone();
    let original = request.clone();
    let caller = tokio::spawn(async move { client.pod_sandbox_status(original).await });
    tokio::time::timeout(Duration::from_secs(2), backend.lookup_entered.notified()).await?;
    assert_eq!(tasks.len(), 1);
    caller.abort();
    let _ = caller.await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while dropped.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    assert_eq!(
        tasks.len(),
        0,
        "Cancelled read must not leave an owned background task"
    );
    tasks.close();
    tokio::time::timeout(Duration::from_secs(1), tasks.wait()).await?;
    let denied = proxy
        .client
        .clone()
        .pod_sandbox_status(request)
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("Closed runtime accepted a read"))?;
    assert_eq!(denied.code(), tonic::Code::FailedPrecondition);
    assert_eq!(backend.lookups.load(Ordering::SeqCst), 1);
    assert_eq!(backend.effects.load(Ordering::SeqCst), 0);
    backend.release();
    proxy.stop().await?;
    upstream.stop().await?;
    Ok(())
}

#[tokio::test]
async fn read_body_preserves_metadata_extensions_and_returns_unavailable_before_eof()
-> anyhow::Result<()> {
    let shutdown = CancellationToken::new();
    let source = futures_util::stream::once(async { Ok::<_, Status>(17_u64) })
        .chain(futures_util::stream::pending());
    let mut response = Response::new(source);
    response
        .metadata_mut()
        .insert("x-public-watch", "preserved".parse()?);
    response.extensions_mut().insert(23_u64);
    let response = read_stream_response(response, shutdown.clone());
    assert_eq!(
        response
            .metadata()
            .get("x-public-watch")
            .and_then(|value| value.to_str().ok()),
        Some("preserved")
    );
    assert_eq!(response.extensions().get::<u64>(), Some(&23));
    let mut stream = response.into_inner();
    assert_eq!(stream.next().await.transpose()?, Some(17));
    shutdown.cancel();
    assert_eq!(
        stream
            .next()
            .await
            .and_then(Result::err)
            .map(|error| error.code()),
        Some(tonic::Code::Unavailable)
    );
    assert!(stream.next().await.is_none());
    Ok(())
}

#[tokio::test]
async fn unexpected_parent_return_closes_reads_and_preserves_the_transport_error()
-> anyhow::Result<()> {
    let global = CancellationToken::new();
    let reads = CancellationToken::new();
    let tasks = TaskTracker::new();
    let transport = RuntimeTransport::new();
    let result = serve_read_parent(
        &global,
        async { Err::<(), _>("public-fixture-error") },
        || begin_drain(&tasks, &reads),
        &transport,
    )
    .await;
    assert_eq!(result, Err("public-fixture-error"));
    assert!(reads.is_cancelled());
    assert!(tasks.is_closed());
    let invoked = Arc::new(AtomicUsize::new(0));
    let factory_calls = invoked.clone();
    let result = read_rpc(&tasks, &reads, move || {
        factory_calls.fetch_add(1, Ordering::SeqCst);
        async { Ok::<_, Status>(()) }
    })
    .await;
    assert_eq!(
        result.err().map(|status| status.code()),
        Some(tonic::Code::FailedPrecondition)
    );
    assert_eq!(invoked.load(Ordering::SeqCst), 0);
    let factory_calls = invoked.clone();
    let result = owned_rpc(&tasks, move || {
        factory_calls.fetch_add(1, Ordering::SeqCst);
        async { Ok::<_, Status>(()) }
    })
    .await;
    assert_eq!(
        result.err().map(|status| status.code()),
        Some(tonic::Code::FailedPrecondition)
    );
    assert_eq!(invoked.load(Ordering::SeqCst), 0);
    assert!(tasks.is_empty());
    Ok(())
}

#[tokio::test]
async fn real_grpc_shutdown_cancels_pending_read_headers_and_closed_reads_perform_no_io()
-> anyhow::Result<()> {
    let backend = Arc::new(Backend::default());
    let _release = ReleaseOnDrop(backend.clone());
    let upstream = serve(
        RuntimeFixture {
            backend: backend.clone(),
        },
        None,
    )
    .await?;
    let tasks = TaskTracker::new();
    let reads = CancellationToken::new();
    let dropped = Arc::new(AtomicUsize::new(0));
    let proxy = serve(
        GuardedCreateFixture {
            tasks: tasks.clone(),
            read_shutdown: reads.clone(),
            upstream: upstream.client.clone(),
            awaiters_dropped: dropped.clone(),
            peers: Arc::default(),
        },
        Some((tasks.clone(), reads.clone())),
    )
    .await?;
    let request = PodSandboxStatusRequest {
        pod_sandbox_id: "public-pending-read".into(),
        verbose: false,
    };
    let original = request.clone();
    let mut caller_client = proxy.client.clone();
    let caller = tokio::spawn(async move { caller_client.pod_sandbox_status(original).await });
    tokio::time::timeout(Duration::from_secs(2), backend.lookup_entered.notified()).await?;
    assert_eq!(tasks.len(), 1);
    reads.cancel();
    let error = tokio::time::timeout(Duration::from_secs(2), caller)
        .await??
        .err()
        .ok_or_else(|| anyhow::anyhow!("Shutdown completed pending read headers"))?;
    assert_eq!(error.code(), tonic::Code::Unavailable);
    assert!(tasks.is_empty());
    let error = proxy
        .client
        .clone()
        .pod_sandbox_status(request)
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("Shutdown read started another upstream call"))?;
    assert_eq!(error.code(), tonic::Code::Unavailable);
    assert_eq!(backend.lookups.load(Ordering::SeqCst), 1);
    assert_eq!(backend.effects.load(Ordering::SeqCst), 0);
    tokio::time::timeout(Duration::from_secs(2), async {
        while backend.lookup_dropped.load(Ordering::SeqCst) != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    proxy.stop().await?;
    upstream.stop().await?;
    Ok(())
}

async fn shutdown_active_watch_with_optional_owned_effect(
    owned_effect: bool,
) -> anyhow::Result<()> {
    let backend = Arc::new(Backend::default());
    let _release = ReleaseOnDrop(backend.clone());
    let upstream = serve(
        RuntimeFixture {
            backend: backend.clone(),
        },
        None,
    )
    .await?;
    let tasks = TaskTracker::new();
    let reads = CancellationToken::new();
    let peers = Arc::new(Mutex::new(Vec::new()));
    let mut proxy = serve(
        GuardedCreateFixture {
            tasks: tasks.clone(),
            read_shutdown: reads.clone(),
            upstream: upstream.client.clone(),
            awaiters_dropped: Arc::default(),
            peers: peers.clone(),
        },
        Some((tasks.clone(), reads.clone())),
    )
    .await?;
    let response = proxy
        .client
        .clone()
        .get_container_events(GetEventsRequest {})
        .await?;
    assert_eq!(
        response
            .metadata()
            .get("x-public-watch")
            .and_then(|value| value.to_str().ok()),
        Some("preserved")
    );
    let mut watch = response.into_inner();
    let first = tokio::time::timeout(Duration::from_secs(2), watch.message())
        .await??
        .ok_or_else(|| anyhow::anyhow!("Real event frame required"))?;
    assert_eq!(first.container_id, "public-first-event");
    assert!(tasks.is_empty());
    let caller = if owned_effect {
        let mut client = proxy.client.clone();
        let caller = tokio::spawn(async move {
            client
                .create_container(CreateContainerRequest {
                    pod_sandbox_id: "public-system-passthrough".into(),
                    ..Default::default()
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), backend.effect_entered.notified()).await?;
        let peers = peers
            .lock()
            .map_err(|_| anyhow::anyhow!("Fixture peer lock"))?;
        assert_eq!(peers.len(), 2);
        assert_eq!(
            peers[0], peers[1],
            "READ and accepted mutation share the actual TCP connection"
        );
        Some(caller)
    } else {
        None
    };
    proxy.cancel.cancel();
    let error = tokio::time::timeout(Duration::from_secs(2), watch.message())
        .await?
        .err()
        .ok_or_else(|| anyhow::anyhow!("Truncated watch must return terminal UNAVAILABLE"))?;
    assert_eq!(error.code(), tonic::Code::Unavailable);
    assert!(watch.message().await?.is_none());
    assert!(reads.is_cancelled());
    assert!(tasks.is_closed(), "Shutdown must reject late mutations");
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let invoked = factory_calls.clone();
    let denied = owned_rpc(&tasks, move || {
        invoked.fetch_add(1, Ordering::SeqCst);
        async { Ok::<_, Status>(()) }
    })
    .await;
    assert_eq!(
        denied.err().map(|status| status.code()),
        Some(tonic::Code::FailedPrecondition)
    );
    assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
    if let Some(mut caller) = caller {
        assert_eq!(
            tasks.len(),
            1,
            "Read shutdown cannot cancel the accepted mutation owner"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut caller)
                .await
                .is_err()
        );
        let parent = proxy
            .task
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Actual tonic parent required"))?;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), parent)
                .await
                .is_err(),
            "Read cancellation cannot force-drop the real tonic parent with a pending mutation"
        );
        backend.effect_release.notify_one();
        let response = tokio::time::timeout(Duration::from_secs(2), caller).await???;
        assert_eq!(
            response.into_inner().container_id,
            "public-simulated-effect"
        );
        assert_eq!(
            backend.effects.load(Ordering::SeqCst),
            1,
            "No mutation replay"
        );
    }
    // The client still retains its watch object/Channel. Only its read RPC has
    // ended; no client drop or forced parent abort is needed for graceful exit.
    proxy.stop().await?;
    tasks.close();
    tokio::time::timeout(Duration::from_secs(2), tasks.wait()).await?;
    tokio::time::timeout(Duration::from_secs(2), async {
        while backend.watch_dropped.load(Ordering::SeqCst) != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    assert_eq!(backend.watches.load(Ordering::SeqCst), 1);
    drop(watch);
    upstream.stop().await?;
    Ok(())
}

#[tokio::test]
async fn real_grpc_watch_shutdown_ends_the_actual_graceful_parent_without_client_drop()
-> anyhow::Result<()> {
    shutdown_active_watch_with_optional_owned_effect(false).await
}

#[tokio::test]
async fn real_grpc_read_stream_shutdown_preserves_same_connection_owned_mutation_until_ack()
-> anyhow::Result<()> {
    shutdown_active_watch_with_optional_owned_effect(true).await
}

async fn shutdown_stalled_read_with_optional_owned_effect(
    owned_effect: bool,
) -> anyhow::Result<()> {
    let backend = Arc::new(Backend {
        watch_burst: true,
        ..Default::default()
    });
    let _release = ReleaseOnDrop(backend.clone());
    let upstream = serve(
        RuntimeFixture {
            backend: backend.clone(),
        },
        None,
    )
    .await?;
    let tasks = TaskTracker::new();
    let reads = CancellationToken::new();
    let peers = Arc::new(Mutex::new(Vec::new()));
    let mut proxy = serve(
        GuardedCreateFixture {
            tasks: tasks.clone(),
            read_shutdown: reads.clone(),
            upstream: upstream.client.clone(),
            awaiters_dropped: Arc::default(),
            peers: peers.clone(),
        },
        Some((tasks.clone(), reads.clone())),
    )
    .await?;
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", proxy.address))?
        .initial_stream_window_size(1024)
        .initial_connection_window_size(65_535)
        .connect()
        .await?;
    let mut client = RuntimeServiceClient::new(channel);
    let mut watch = client
        .get_container_events(GetEventsRequest {})
        .await?
        .into_inner();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), watch.message())
            .await??
            .ok_or_else(|| anyhow::anyhow!("Initial actual event required"))?
            .container_id,
        "public-first-event"
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while backend.watch_produced.load(Ordering::SeqCst) < 3 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    // No further client body polling: a 128 KiB DATA message exceeds the
    // advertised 1 KiB receive window, so hyper waits outside read_stream.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let caller = if owned_effect {
        let mut client = client.clone();
        let caller = tokio::spawn(async move {
            client
                .create_container(CreateContainerRequest {
                    pod_sandbox_id: "public-system-passthrough".into(),
                    ..Default::default()
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), backend.effect_entered.notified()).await?;
        let peers = peers
            .lock()
            .map_err(|_| anyhow::anyhow!("Fixture peer lock"))?;
        assert_eq!(peers.len(), 2);
        assert_eq!(
            peers[0], peers[1],
            "Stalled READ and mutation share the actual TCP connection"
        );
        Some(caller)
    } else {
        None
    };
    let began = std::time::Instant::now();
    proxy.cancel.cancel();
    let parent = proxy
        .task
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("Actual parent required"))?;
    assert!(
        tokio::time::timeout(Duration::from_millis(250), parent)
            .await
            .is_err(),
        "Normal graceful drain must not close the blocked connection before its 3s budget"
    );
    assert!(reads.is_cancelled());
    assert!(tasks.is_closed());
    assert_eq!(tasks.len(), usize::from(owned_effect));
    let parent = proxy
        .task
        .take()
        .ok_or_else(|| anyhow::anyhow!("Actual parent required"))?;
    tokio::time::timeout(Duration::from_secs(5), parent).await???;
    assert!(began.elapsed() >= Duration::from_secs(3));
    assert_eq!(
        proxy.transport.connection_count(),
        0,
        "All real server IO owners have dropped"
    );
    if let Some(caller) = caller {
        // This ACK is unknown due solely to transport loss. It is neither a
        // business failure nor proof that the admitted effect has finished.
        let error = tokio::time::timeout(Duration::from_secs(2), caller)
            .await??
            .err()
            .ok_or_else(|| anyhow::anyhow!("Lost transport cannot claim an ACK"))?;
        assert!(matches!(
            error.code(),
            tonic::Code::Unavailable
                | tonic::Code::Unknown
                | tonic::Code::Cancelled
                | tonic::Code::Internal
        ));
        assert_eq!(
            tasks.len(),
            1,
            "IO shutdown cannot release the admitted owner"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), tasks.wait())
                .await
                .is_err()
        );
        assert_eq!(backend.effects.load(Ordering::SeqCst), 1);
        backend.effect_release.notify_one();
        tokio::time::timeout(Duration::from_secs(2), tasks.wait()).await?;
        assert_eq!(
            backend.effects.load(Ordering::SeqCst),
            1,
            "No replay after unknown ACK"
        );
    } else {
        assert!(tasks.is_empty());
    }
    // The caller still holds the unread body. No client reset and no parent
    // abort were needed: the bound closed the actual server FD and drained it.
    proxy.stop().await?;
    drop(watch);
    upstream.stop().await?;
    Ok(())
}

#[tokio::test]
async fn real_grpc_stalled_read_body_closes_actual_io_after_grace_without_client_reset()
-> anyhow::Result<()> {
    shutdown_stalled_read_with_optional_owned_effect(false).await
}

#[tokio::test]
async fn real_grpc_stalled_read_transport_loss_keeps_unknown_mutation_owned_until_real_ack()
-> anyhow::Result<()> {
    shutdown_stalled_read_with_optional_owned_effect(true).await
}

#[tokio::test]
async fn actual_tcp_parent_error_waits_for_io_owner_and_closed_wrap_drops_the_fd()
-> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;
    use tonic::transport::server::Connected;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let mut client = tokio::net::TcpStream::connect(address).await?;
    let (server, _) = listener.accept().await?;
    let transport = RuntimeTransport::new();
    let mut io = transport.wrap(server)?;
    assert_eq!(io.connect_info().remote_addr(), Some(client.local_addr()?));
    let closed = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let child_closed = closed.clone();
    let child_release = release.clone();
    let child = tokio::spawn(async move {
        let result = io.read(&mut [0_u8; 1]).await;
        child_closed.notify_one();
        child_release.notified().await;
        drop(io);
        result
    });
    let parent_transport = transport.clone();
    let parent = tokio::spawn(async move {
        serve_read_parent(
            &CancellationToken::new(),
            async { Err::<(), _>("public-parent-error") },
            || {},
            &parent_transport,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), closed.notified()).await?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), client.read(&mut [0_u8; 1])).await??,
        0
    );
    assert_eq!(
        transport.connection_count(),
        1,
        "FD is closed, but real IO owner is still alive"
    );
    assert!(
        !parent.is_finished(),
        "Parent error cannot bypass child IO drain"
    );
    let mut second_client = tokio::net::TcpStream::connect(address).await?;
    let (second_server, _) = listener.accept().await?;
    assert!(transport.wrap(second_server).is_err());
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), second_client.read(&mut [0_u8; 1])).await??,
        0
    );
    assert_eq!(transport.connection_count(), 1);
    release.notify_one();
    let error = tokio::time::timeout(Duration::from_secs(2), child)
        .await??
        .err()
        .ok_or_else(|| anyhow::anyhow!("Transport close must interrupt read"))?;
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), parent).await??,
        Err("public-parent-error")
    );
    assert_eq!(transport.connection_count(), 0);
    Ok(())
}
