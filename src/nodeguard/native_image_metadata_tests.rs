// Real HTTP/2 protocol fixtures for the production read adapter. No runtime
// peer, root-host, snapshot, pull or cloud certification is inferred from TCP.
use super::*;
use anyhow::{Context, ensure};
use futures_util::{Stream, StreamExt};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context as TaskContext, Poll},
};
use tonic::{Response, Status, body::Body, codegen::http};
use tower::Service;

const PRIVATE: &str = "PRIVATE_NATIVE_PROVIDER_DETAIL_MUST_NOT_ESCAPE";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    None,
    Offset,
    Extra,
    Truncated,
    EmptyFrame,
    TooManyFrames,
    DuplicateOffset,
    InfoDigest,
    InfoSize,
    MissingInfo,
    FinalRoot,
    RootDigest,
    WrongVersion,
    ProviderSecret,
    StreamError,
    OversizedFrame,
    Deadline,
}

struct Fixture {
    reference: String,
    root: Descriptor,
    selected: String,
    config: String,
    blobs: BTreeMap<String, Vec<u8>>,
}
impl Fixture {
    fn new(index: bool) -> Self {
        fn descriptor(bytes: &[u8], media: &str) -> Descriptor {
            Descriptor {
                digest: format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
                size: bytes.len() as i64,
                media_type: media.into(),
                annotations: HashMap::new(),
            }
        }
        fn json_descriptor(value: &Descriptor) -> serde_json::Value {
            json!({"mediaType":value.media_type,"digest":value.digest,"size":value.size})
        }
        let layer = format!("sha256:{}", "a".repeat(64));
        let config = json!({"os":"linux","architecture":"amd64",
            "config":{"Env":[PRIVATE]},"rootfs":{"type":"layers","diff_ids":[layer]}})
        .to_string()
        .into_bytes();
        let config_descriptor = descriptor(&config, "application/vnd.oci.image.config.v1+json");
        let manifest = json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
            "config":json_descriptor(&config_descriptor),"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":layer,"size":17}]}).to_string().into_bytes();
        let manifest_descriptor =
            descriptor(&manifest, "application/vnd.oci.image.manifest.v1+json");
        let mut blobs = BTreeMap::from([
            (config_descriptor.digest.clone(), config),
            (manifest_descriptor.digest.clone(), manifest),
        ]);
        let root = if index {
            let mut selected = json_descriptor(&manifest_descriptor);
            selected["platform"] = json!({"os":"linux","architecture":"amd64"});
            let bytes = json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[selected]}).to_string().into_bytes();
            let descriptor = descriptor(&bytes, "application/vnd.oci.image.index.v1+json");
            blobs.insert(descriptor.digest.clone(), bytes);
            descriptor
        } else {
            manifest_descriptor.clone()
        };
        Self {
            reference: format!("registry.example.test/sandbox/native@{}", root.digest),
            root,
            selected: manifest_descriptor.digest,
            config: config_descriptor.digest,
            blobs,
        }
    }
}

struct State {
    fixture: Fixture,
    fault: Fault,
    calls: Mutex<Vec<&'static str>>,
    bad_namespace: AtomicBool,
    gets: AtomicUsize,
    active_streams: Arc<AtomicUsize>,
}
impl State {
    fn request<T>(&self, request: &Request<T>, method: &'static str) -> Result<(), Status> {
        self.calls
            .lock()
            .map_err(|_| Status::internal(PRIVATE))?
            .push(method);
        let values: Vec<_> = request
            .metadata()
            .get_all("containerd-namespace")
            .iter()
            .collect();
        if values.len() != 1
            || values[0].as_bytes() != b"k8s.io"
            || !request.metadata().contains_key("grpc-timeout")
        {
            self.bad_namespace.store(true, Ordering::SeqCst);
            return Err(Status::permission_denied(PRIVATE));
        }
        Ok(())
    }
    fn forbidden(&self) -> http::Response<Body> {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push("FORBIDDEN");
        }
        Status::permission_denied(PRIVATE).into_http()
    }
}

#[derive(Clone)]
struct Versions(Arc<State>);
#[derive(Clone)]
struct Images(Arc<State>);
#[derive(Clone)]
struct Content(Arc<State>);
type Reply<T> = Pin<Box<dyn Future<Output = Result<Response<T>, Status>> + Send>>;
type HttpReply = Pin<Box<dyn Future<Output = Result<http::Response<Body>, Infallible>> + Send>>;
impl tonic::server::NamedService for Versions {
    const NAME: &'static str = "runtime.v1.RuntimeService";
}
impl tonic::server::NamedService for Images {
    const NAME: &'static str = "containerd.services.images.v1.Images";
}
impl tonic::server::NamedService for Content {
    const NAME: &'static str = "containerd.services.content.v1.Content";
}
impl tonic::server::UnaryService<VersionRequest> for Versions {
    type Response = VersionResponse;
    type Future = Reply<VersionResponse>;
    fn call(&mut self, request: Request<VersionRequest>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            state.request(&request, "VERSION")?;
            Ok(Response::new(VersionResponse {
                version: "fixture".into(),
                runtime_name: "containerd".into(),
                runtime_version: if state.fault == Fault::WrongVersion {
                    "2.3.4"
                } else {
                    "v2.3.5"
                }
                .into(),
                runtime_api_version: "v1".into(),
            }))
        })
    }
}
impl tonic::server::UnaryService<images::GetImageRequest> for Images {
    type Response = images::GetImageResponse;
    type Future = Reply<images::GetImageResponse>;
    fn call(&mut self, request: Request<images::GetImageRequest>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            state.request(&request, "GET")?;
            if request.get_ref().name != state.fixture.reference {
                return Err(Status::not_found(PRIVATE));
            }
            let mut target = state.fixture.root.clone();
            let call = state.gets.fetch_add(1, Ordering::SeqCst);
            if state.fault == Fault::RootDigest {
                target.digest = format!("sha256:{}", "b".repeat(64));
            }
            if state.fault == Fault::FinalRoot && call > 0 {
                target.size += 1;
            }
            Ok(Response::new(images::GetImageResponse {
                image: Some(images::Image {
                    name: request.into_inner().name,
                    target: Some(target),
                    labels: HashMap::from([("private".into(), PRIVATE.into())]),
                    ..Default::default()
                }),
            }))
        })
    }
}
impl tonic::server::UnaryService<content::InfoRequest> for Content {
    type Response = content::InfoResponse;
    type Future = Reply<content::InfoResponse>;
    fn call(&mut self, request: Request<content::InfoRequest>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            state.request(&request, "INFO")?;
            if state.fault == Fault::ProviderSecret {
                return Err(Status::internal(PRIVATE));
            }
            if state.fault == Fault::Deadline {
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            let bytes = state
                .fixture
                .blobs
                .get(&request.get_ref().digest)
                .ok_or_else(|| Status::not_found(PRIVATE))?;
            if state.fault == Fault::MissingInfo {
                return Ok(Response::new(content::InfoResponse { info: None }));
            }
            Ok(Response::new(content::InfoResponse {
                info: Some(content::Info {
                    digest: if state.fault == Fault::InfoDigest {
                        PRIVATE.into()
                    } else {
                        request.get_ref().digest.clone()
                    },
                    size: if state.fault == Fault::InfoSize {
                        i64::MAX
                    } else {
                        bytes.len() as i64
                    },
                    ..Default::default()
                }),
            }))
        })
    }
}
struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
type Frames = Pin<Box<dyn Stream<Item = Result<content::ReadContentResponse, Status>> + Send>>;
impl tonic::server::ServerStreamingService<content::ReadContentRequest> for Content {
    type Response = content::ReadContentResponse;
    type ResponseStream = Frames;
    type Future = Reply<Frames>;
    fn call(&mut self, request: Request<content::ReadContentRequest>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            state.request(&request, "READ")?;
            let wanted = request.into_inner();
            let original = state
                .fixture
                .blobs
                .get(&wanted.digest)
                .ok_or_else(|| Status::not_found(PRIVATE))?;
            if wanted.offset != 0 || wanted.size != original.len() as i64 + 1 {
                return Err(Status::invalid_argument(PRIVATE));
            }
            state.active_streams.fetch_add(1, Ordering::SeqCst);
            let active = Active(state.active_streams.clone());
            if state.fault == Fault::Deadline {
                return Ok(Response::new(Box::pin(
                    futures_util::stream::pending::<Result<content::ReadContentResponse, Status>>()
                        .map(move |value| {
                            let _ = &active;
                            value
                        }),
                ) as Frames));
            }
            let mut bytes = original.clone();
            if state.fault == Fault::Extra {
                bytes.push(b'!');
            }
            if state.fault == Fault::Truncated {
                bytes.pop();
            }
            if state.fault == Fault::OversizedFrame {
                bytes = vec![b'x'; MAX_BLOB + 2048];
            }
            let mut frames = if state.fault == Fault::TooManyFrames {
                bytes
                    .iter()
                    .enumerate()
                    .map(|(offset, byte)| {
                        Ok(content::ReadContentResponse {
                            offset: offset as i64,
                            data: vec![*byte],
                        })
                    })
                    .collect::<Vec<_>>()
            } else if state.fault == Fault::DuplicateOffset {
                let half = bytes.len() / 2;
                vec![
                    Ok(content::ReadContentResponse {
                        offset: 0,
                        data: bytes[..half].to_vec(),
                    }),
                    Ok(content::ReadContentResponse {
                        offset: 0,
                        data: bytes[half..].to_vec(),
                    }),
                ]
            } else {
                vec![Ok(content::ReadContentResponse {
                    offset: if state.fault == Fault::Offset { 1 } else { 0 },
                    data: bytes,
                })]
            };
            if state.fault == Fault::EmptyFrame {
                frames.insert(
                    0,
                    Ok(content::ReadContentResponse {
                        offset: 0,
                        data: Vec::new(),
                    }),
                );
            }
            if state.fault == Fault::StreamError {
                frames.push(Err(Status::internal(PRIVATE)));
            }
            Ok(Response::new(
                Box::pin(futures_util::stream::iter(frames).map(move |value| {
                    let _ = &active;
                    value
                })) as Frames,
            ))
        })
    }
}

macro_rules! unary_http {
    ($service:ty, $path:literal, $request:ty, $response:ty) => {
        impl Service<http::Request<Body>> for $service {
            type Response = http::Response<Body>;
            type Error = Infallible;
            type Future = HttpReply;
            fn poll_ready(&mut self, _: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }
            fn call(&mut self, request: http::Request<Body>) -> Self::Future {
                let service = self.clone();
                Box::pin(async move {
                    if request.uri().path() != $path {
                        return Ok(service.0.forbidden());
                    }
                    Ok(tonic::server::Grpc::new(
                        tonic_prost::ProstCodec::<$response, $request>::default(),
                    )
                    .unary(service, request)
                    .await)
                })
            }
        }
    };
}
unary_http!(
    Versions,
    "/runtime.v1.RuntimeService/Version",
    VersionRequest,
    VersionResponse
);
unary_http!(
    Images,
    "/containerd.services.images.v1.Images/Get",
    images::GetImageRequest,
    images::GetImageResponse
);
impl Service<http::Request<Body>> for Content {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = HttpReply;
    fn poll_ready(&mut self, _: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let service = self.clone();
        let path = request.uri().path().to_owned();
        Box::pin(async move {
            Ok(match path.as_str() {
                "/containerd.services.content.v1.Content/Info" => {
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                        content::InfoResponse,
                        content::InfoRequest,
                    >::default())
                    .unary(service, request)
                    .await
                }
                "/containerd.services.content.v1.Content/Read" => {
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                        content::ReadContentResponse,
                        content::ReadContentRequest,
                    >::default())
                    .server_streaming(service, request)
                    .await
                }
                _ => service.0.forbidden(),
            })
        })
    }
}

async fn actual_wire(
    fault: Fault,
    index: bool,
) -> anyhow::Result<(
    Result<NativeImageMetadata, NativeImageMetadataError>,
    Arc<State>,
)> {
    let state = Arc::new(State {
        fixture: Fixture::new(index),
        fault,
        calls: Mutex::new(Vec::new()),
        bad_namespace: AtomicBool::new(false),
        gets: AtomicUsize::new(0),
        active_streams: Arc::new(AtomicUsize::new(0)),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let stop = tokio_util::sync::CancellationToken::new();
    let ending = stop.clone();
    let served_io = RuntimeTransport::new();
    let accepted_io = served_io.clone();
    let incoming = futures_util::stream::unfold(listener, move |listener| {
        let accepted_io = accepted_io.clone();
        async move {
            Some((
                listener
                    .accept()
                    .await
                    .and_then(|(stream, _)| accepted_io.wrap(stream)),
                listener,
            ))
        }
    });
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(Versions(state.clone()))
            .add_service(Images(state.clone()))
            .add_service(Content(state.clone()))
            .serve_with_incoming_shutdown(incoming, ending.cancelled_owned()),
    );
    let owner = IoOwner(RuntimeTransport::new());
    let transport = owner.0.clone();
    let deadline = Instant::now() + ATTEMPT;
    let outcome = timeout_at(deadline, async {
        let channel = tonic::transport::Endpoint::from_static("http://[::]:50051")
            .connect_timeout(ATTEMPT)
            .connect_with_connector(tower::service_fn(move |_| {
                let transport = transport.clone();
                async move {
                    transport
                        .wrap(tokio::net::TcpStream::connect(address).await?)
                        .map(hyper_util::rt::TokioIo::new)
                }
            }))
            .await
            .map_err(|_| NativeImageMetadataError::RuntimeUnavailable)?;
        inspect_channel(
            channel,
            &state.fixture.reference,
            &state.fixture.root.digest,
            "linux/amd64",
            deadline,
        )
        .await
    })
    .await
    .map_err(|_| NativeImageMetadataError::DeadlineExceeded)
    .and_then(|result| result);
    owner.finish().await;
    stop.cancel();
    served_io.close_io();
    let served = server.await;
    served_io.wait_closed().await;
    served??;
    ensure!(
        owner.0.connection_count() == 0 && served_io.connection_count() == 0,
        "the real client/server transport owners must retire before return"
    );
    ensure!(
        state.active_streams.load(Ordering::SeqCst) == 0,
        "no content stream may survive success, failure or timeout"
    );
    ensure!(
        !state.bad_namespace.load(Ordering::SeqCst),
        "every actual RPC must carry one fixed namespace and a deadline"
    );
    ensure!(
        !state
            .calls
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture lock"))?
            .contains(&"FORBIDDEN"),
        "only fixed read methods may be sent"
    );
    Ok((outcome, state))
}

#[tokio::test]
async fn actual_native_protocol_checks_metadata_in_one_fixed_namespace_without_reading_layers()
-> anyhow::Result<()> {
    for index in [false, true] {
        let (outcome, state) = actual_wire(Fault::None, index).await?;
        let report = serde_json::to_value(outcome?)?;
        ensure!(
            report["scope"] == "NATIVE_CONTAINERD_METADATA_ONLY" && report["namespace"] == "k8s.io"
        );
        ensure!(report["metadata"]["selected_manifest"]["digest"] == state.fixture.selected);
        ensure!(report["metadata"]["config"]["digest"] == state.fixture.config);
        ensure!(
            report["metadata"]["approval_checked"] == false
                && report["metadata"]["layer_payloads_verified"] == false
                && report["metadata"]["preparation_allowed"] == false
        );
        ensure!(
            !report.to_string().contains(PRIVATE),
            "provider labels and OCI Env must not escape the metadata receipt"
        );
        let calls = state
            .calls
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture lock"))?;
        let expected = if index {
            vec![
                "VERSION", "GET", "INFO", "READ", "INFO", "READ", "INFO", "READ", "GET",
            ]
        } else {
            vec!["VERSION", "GET", "INFO", "READ", "INFO", "READ", "GET"]
        };
        ensure!(
            *calls == expected,
            "the real protocol must request only the selected metadata closure and its two root bookends"
        );
    }
    Ok(())
}

#[tokio::test]
async fn actual_native_protocol_rejects_stream_info_and_root_conflicts_without_provider_details()
-> anyhow::Result<()> {
    for fault in [
        Fault::Offset,
        Fault::Extra,
        Fault::Truncated,
        Fault::EmptyFrame,
        Fault::TooManyFrames,
        Fault::DuplicateOffset,
        Fault::InfoDigest,
        Fault::InfoSize,
        Fault::MissingInfo,
        Fault::FinalRoot,
        Fault::RootDigest,
        Fault::WrongVersion,
        Fault::ProviderSecret,
        Fault::StreamError,
        Fault::OversizedFrame,
    ] {
        let (outcome, _) = actual_wire(fault, true).await?;
        let error = outcome
            .err()
            .with_context(|| format!("fault {fault:?} unexpectedly produced a receipt"))?;
        let expected = match fault {
            Fault::FinalRoot => NativeImageMetadataError::ImageChanged,
            Fault::RootDigest => NativeImageMetadataError::RootMismatch,
            Fault::WrongVersion => NativeImageMetadataError::RuntimeIdentityMismatch,
            Fault::ProviderSecret | Fault::StreamError => {
                NativeImageMetadataError::RuntimeUnavailable
            }
            _ => NativeImageMetadataError::ResponseInvalid,
        };
        ensure!(
            error == expected,
            "wrong failure classification for {fault:?}: {}",
            error.code()
        );
        ensure!(!error.to_string().contains(PRIVATE) && error.to_string() == error.code());
    }
    Ok(())
}

#[tokio::test]
async fn actual_native_protocol_has_one_original_five_second_deadline_and_retires_pending_stream()
-> anyhow::Result<()> {
    let started = std::time::Instant::now();
    let (outcome, state) = actual_wire(Fault::Deadline, false).await?;
    ensure!(matches!(
        outcome,
        Err(NativeImageMetadataError::DeadlineExceeded)
    ));
    ensure!(
        started.elapsed() >= Duration::from_secs(4) && started.elapsed() < Duration::from_secs(6),
        "the total five-second budget must not renew after the delayed Info call"
    );
    ensure!(
        state
            .calls
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture lock"))?
            .as_slice()
            == ["VERSION", "GET", "INFO", "READ"]
    );
    Ok(())
}

#[test]
fn independent_digest_and_repository_request_inputs_reject_tags_and_ambiguous_references() {
    let expected = format!("sha256:{}", "a".repeat(64));
    assert!(
        validate_reference(
            &format!("registry.example.test:5000/team/image@{expected}"),
            &expected
        )
        .is_ok()
    );
    for reference in [
        "registry.example.test/team/image:tag".to_owned(),
        format!("registry.example.test/team/image:tag@{expected}"),
        format!("https://registry.example.test/team/image@{expected}"),
        format!("registry.example.test//image@{expected}"),
        format!("registry.example.test/../image@{expected}"),
        format!("registry.example.test/UPPER@{expected}"),
        format!("image@{expected}"),
        format!("registry.example.test/team/image@sha256:{}", "b".repeat(64)),
    ] {
        assert_eq!(
            validate_reference(&reference, &expected),
            Err(NativeImageMetadataError::InvalidReference)
        );
    }
}
