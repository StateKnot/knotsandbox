//! Root-local inspection of existing containerd metadata in the fixed CRI namespace.
//! No image, content, lease or snapshot mutation is available through this module.
use crate::image_artifact::{ImageArtifactError, VerifiedImageMetadata};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct NativeImageMetadata {
    scope: &'static str,
    namespace: &'static str,
    reference: String,
    runtime_version: &'static str,
    observed_at: chrono::DateTime<chrono::Utc>,
    metadata: VerifiedImageMetadata,
}

/// Errors contain only stable codes, never a provider status, reference or path.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NativeImageMetadataError {
    #[error("UNSUPPORTED_RUNTIME")]
    UnsupportedRuntime,
    #[error("INVALID_IMAGE_REFERENCE")]
    InvalidReference,
    #[error("RUNTIME_UNAVAILABLE")]
    RuntimeUnavailable,
    #[error("RUNTIME_IDENTITY_MISMATCH")]
    RuntimeIdentityMismatch,
    #[error("RUNTIME_METADATA_UNAVAILABLE")]
    MetadataUnavailable,
    #[error("RUNTIME_RESPONSE_INVALID")]
    ResponseInvalid,
    #[error("RUNTIME_IMAGE_CHANGED")]
    ImageChanged,
    #[error("RUNTIME_ROOT_MISMATCH")]
    RootMismatch,
    #[error("RUNTIME_DEADLINE_EXCEEDED")]
    DeadlineExceeded,
    #[error("{0}")]
    Metadata(#[from] ImageArtifactError),
}
impl NativeImageMetadataError {
    pub fn code(self) -> &'static str {
        match self {
            Self::UnsupportedRuntime => "UNSUPPORTED_RUNTIME",
            Self::InvalidReference => "INVALID_IMAGE_REFERENCE",
            Self::RuntimeUnavailable => "RUNTIME_UNAVAILABLE",
            Self::RuntimeIdentityMismatch => "RUNTIME_IDENTITY_MISMATCH",
            Self::MetadataUnavailable => "RUNTIME_METADATA_UNAVAILABLE",
            Self::ResponseInvalid => "RUNTIME_RESPONSE_INVALID",
            Self::ImageChanged => "RUNTIME_IMAGE_CHANGED",
            Self::RootMismatch => "RUNTIME_ROOT_MISMATCH",
            Self::DeadlineExceeded => "RUNTIME_DEADLINE_EXCEEDED",
            Self::Metadata(error) => error.code(),
        }
    }
}

/// Inspect an existing exact image reference. The digest is an independently
/// supplied expectation, not an approval established by this operation.
/// Linux root is required; the socket and containerd namespace are not inputs.
pub async fn inspect(
    reference: &str,
    expected_digest: &str,
    platform: &str,
) -> Result<NativeImageMetadata, NativeImageMetadataError> {
    crate::image_artifact::validate_request(expected_digest, platform)?;
    validate_reference(reference, expected_digest)?;
    #[cfg(target_os = "linux")]
    {
        if !rustix::process::geteuid().is_root() {
            return Err(NativeImageMetadataError::UnsupportedRuntime);
        }
        backend::inspect_local(reference, expected_digest, platform).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(NativeImageMetadataError::UnsupportedRuntime)
    }
}

fn validate_reference(reference: &str, expected: &str) -> Result<(), NativeImageMetadataError> {
    let (repository, digest) = reference
        .split_once('@')
        .ok_or(NativeImageMetadataError::InvalidReference)?;
    // Same repository character/tag policy as the approved-template importer;
    // require an explicit qualified path for containerd's exact name lookup.
    if reference.len() > 2048
        || digest != expected
        || repository.is_empty()
        || !repository.contains('/')
        || repository.contains("://")
        || repository
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || repository
            .rsplit('/')
            .next()
            .is_some_and(|part| part.contains(':'))
        || !repository
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-:/".contains(&b))
    {
        return Err(NativeImageMetadataError::InvalidReference);
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
mod backend {
    use super::*;
    use crate::{
        image_artifact::{MetadataBlobRequest, MetadataPlan},
        nodeguard::{
            cri_proto::{VersionRequest, VersionResponse},
            cri_transport::RuntimeTransport,
        },
    };
    use prost::Message;
    use std::time::Duration;
    use tokio::time::{Instant, timeout_at};
    use tonic::{Code, Request, transport::Channel};

    const NAMESPACE: &str = "k8s.io";
    const ATTEMPT: Duration = Duration::from_secs(5);
    const MAX_BLOB: usize = 1024 * 1024;
    const SMALL_REPLY: usize = 64 * 1024;
    const MAX_FRAMES: usize = 64;

    // Upstream-generated messages stay private. No generated RPC client or
    // writer is exposed, including to the host administrator's CLI consumer.
    #[allow(dead_code, clippy::all, rustdoc::invalid_html_tags)]
    mod wire {
        pub mod google {
            pub mod protobuf {
                include!("generated/google.protobuf.rs");
            }
        }
        pub mod containerd {
            pub mod types {
                include!("generated/containerd.types.rs");
            }
            pub mod services {
                pub mod images {
                    pub mod v1 {
                        include!("generated/containerd.services.images.v1.rs");
                    }
                }
                pub mod content {
                    pub mod v1 {
                        include!("generated/containerd.services.content.v1.rs");
                    }
                }
            }
        }
    }
    use wire::containerd::{
        services::{content::v1 as content, images::v1 as images},
        types::Descriptor,
    };

    fn provider(error: tonic::Status) -> NativeImageMetadataError {
        match error.code() {
            Code::NotFound => NativeImageMetadataError::MetadataUnavailable,
            Code::DeadlineExceeded => NativeImageMetadataError::DeadlineExceeded,
            Code::OutOfRange | Code::DataLoss | Code::ResourceExhausted => {
                NativeImageMetadataError::ResponseInvalid
            }
            _ => NativeImageMetadataError::RuntimeUnavailable,
        }
    }

    struct IoOwner(RuntimeTransport);
    impl Drop for IoOwner {
        fn drop(&mut self) {
            self.0.close_io();
        }
    }
    impl IoOwner {
        async fn finish(&self) {
            self.0.close_io();
            self.0.wait_closed().await;
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) async fn inspect_local(
        reference: &str,
        expected: &str,
        platform: &str,
    ) -> Result<NativeImageMetadata, NativeImageMetadataError> {
        let owner = IoOwner(RuntimeTransport::new());
        let transport = owner.0.clone();
        let endpoint = crate::nodeguard::runtime_endpoint::RuntimeEndpoint::default();
        let deadline = Instant::now() + ATTEMPT;
        let result = timeout_at(deadline, async {
            let channel = tonic::transport::Endpoint::from_static("http://[::]:50051")
                .connect_timeout(ATTEMPT)
                .buffer_size(1)
                .connect_with_connector(tower::service_fn(move |_| {
                    let endpoint = endpoint.clone();
                    let transport = transport.clone();
                    async move {
                        let stream = endpoint.connect().await?;
                        transport.wrap(stream).map(hyper_util::rt::TokioIo::new)
                    }
                }))
                .await
                .map_err(|_| NativeImageMetadataError::RuntimeUnavailable)?;
            inspect_channel(channel, reference, expected, platform, deadline).await
        })
        .await
        .map_err(|_| NativeImageMetadataError::DeadlineExceeded)
        .and_then(|value| value);
        // The cancellation guard also closes IO if this future is dropped.
        // On every normal return, including timeout, join the actual IO owner.
        owner.finish().await;
        result
    }

    fn request<T>(value: T, deadline: Instant) -> Result<Request<T>, NativeImageMetadataError> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|value| !value.is_zero())
            .ok_or(NativeImageMetadataError::DeadlineExceeded)?;
        let mut request = Request::new(value);
        request.metadata_mut().insert(
            "containerd-namespace",
            tonic::metadata::MetadataValue::from_static(NAMESPACE),
        );
        request.set_timeout(remaining);
        Ok(request)
    }

    async fn unary<Req, Resp>(
        channel: Channel,
        value: Req,
        path: &'static str,
        limit: usize,
        deadline: Instant,
    ) -> Result<Resp, NativeImageMetadataError>
    where
        Req: Message + Send + Sync + 'static,
        Resp: Message + Default + Send + Sync + 'static,
    {
        let mut client = tonic::client::Grpc::new(channel)
            .max_decoding_message_size(limit)
            .max_encoding_message_size(4096);
        client
            .ready()
            .await
            .map_err(|_| NativeImageMetadataError::RuntimeUnavailable)?;
        client
            .unary(
                request(value, deadline)?,
                tonic::codegen::http::uri::PathAndQuery::from_static(path),
                tonic_prost::ProstCodec::default(),
            )
            .await
            .map(tonic::Response::into_inner)
            .map_err(provider)
    }

    async fn image(
        channel: Channel,
        reference: &str,
        expected: &str,
        deadline: Instant,
    ) -> Result<Descriptor, NativeImageMetadataError> {
        let reply: images::GetImageResponse = unary(
            channel,
            images::GetImageRequest {
                name: reference.to_owned(),
            },
            "/containerd.services.images.v1.Images/Get",
            SMALL_REPLY,
            deadline,
        )
        .await?;
        let image = reply
            .image
            .ok_or(NativeImageMetadataError::ResponseInvalid)?;
        if image.name != reference {
            return Err(NativeImageMetadataError::ResponseInvalid);
        }
        let target = image
            .target
            .ok_or(NativeImageMetadataError::ResponseInvalid)?;
        if target.digest != expected {
            return Err(NativeImageMetadataError::RootMismatch);
        }
        if !(1..=MAX_BLOB as i64).contains(&target.size) {
            return Err(NativeImageMetadataError::ResponseInvalid);
        }
        if !matches!(
            target.media_type.as_str(),
            "application/vnd.oci.image.index.v1+json"
                | "application/vnd.oci.image.manifest.v1+json"
        ) {
            return Err(NativeImageMetadataError::RootMismatch);
        }
        Ok(target)
    }

    async fn blob(
        channel: Channel,
        requested: MetadataBlobRequest,
        deadline: Instant,
    ) -> Result<Vec<u8>, NativeImageMetadataError> {
        if requested.size.is_some_and(|size| size > MAX_BLOB as u64) {
            return Err(ImageArtifactError::MetadataLimitExceeded.into());
        }
        let info: content::InfoResponse = unary(
            channel.clone(),
            content::InfoRequest {
                digest: requested.digest.clone(),
            },
            "/containerd.services.content.v1.Content/Info",
            SMALL_REPLY,
            deadline,
        )
        .await?;
        let info = info.info.ok_or(NativeImageMetadataError::ResponseInvalid)?;
        if info.digest != requested.digest
            || !(0..=MAX_BLOB as i64).contains(&info.size)
            || requested
                .size
                .is_some_and(|size| u64::try_from(info.size).ok() != Some(size))
        {
            return Err(NativeImageMetadataError::ResponseInvalid);
        }
        let expected_size =
            usize::try_from(info.size).map_err(|_| NativeImageMetadataError::ResponseInvalid)?;
        let mut client = tonic::client::Grpc::new(channel)
            .max_decoding_message_size(MAX_BLOB + 1024)
            .max_encoding_message_size(4096);
        client
            .ready()
            .await
            .map_err(|_| NativeImageMetadataError::RuntimeUnavailable)?;
        // Ask for one extra byte: a successful prefix is not the whole object.
        let response: tonic::Response<tonic::Streaming<content::ReadContentResponse>> = client
            .server_streaming(
                request(
                    content::ReadContentRequest {
                        digest: requested.digest,
                        offset: 0,
                        size: info.size + 1,
                    },
                    deadline,
                )?,
                tonic::codegen::http::uri::PathAndQuery::from_static(
                    "/containerd.services.content.v1.Content/Read",
                ),
                tonic_prost::ProstCodec::default(),
            )
            .await
            .map_err(provider)?;
        let mut stream = response.into_inner();
        let mut bytes = Vec::with_capacity(expected_size);
        let mut frames = 0usize;
        while let Some(frame) = stream.message().await.map_err(provider)? {
            frames += 1;
            if frames > MAX_FRAMES
                || frame.data.is_empty()
                || frame.offset != bytes.len() as i64
                || frame.data.len() > expected_size.saturating_sub(bytes.len())
            {
                return Err(NativeImageMetadataError::ResponseInvalid);
            }
            bytes.extend_from_slice(&frame.data);
        }
        if bytes.len() != expected_size {
            return Err(NativeImageMetadataError::ResponseInvalid);
        }
        Ok(bytes)
    }

    async fn inspect_channel(
        channel: Channel,
        reference: &str,
        expected: &str,
        platform: &str,
        deadline: Instant,
    ) -> Result<NativeImageMetadata, NativeImageMetadataError> {
        let version: VersionResponse = unary(
            channel.clone(),
            VersionRequest {
                version: "0.1.0".into(),
            },
            "/runtime.v1.RuntimeService/Version",
            4096,
            deadline,
        )
        .await?;
        if version.runtime_name != "containerd"
            || version.runtime_version.trim_start_matches('v') != "2.3.5"
            || version.runtime_api_version != "v1"
        {
            return Err(NativeImageMetadataError::RuntimeIdentityMismatch);
        }
        let initial = image(channel.clone(), reference, expected, deadline).await?;
        let root = blob(
            channel.clone(),
            MetadataBlobRequest {
                digest: expected.to_owned(),
                size: Some(initial.size as u64),
            },
            deadline,
        )
        .await?;
        let plan = MetadataPlan::from_root(&root, expected, platform, 0)?;
        let manifest = match plan.manifest_request() {
            Some(requested) => Some(blob(channel.clone(), requested, deadline).await?),
            None => None,
        };
        let config_plan = plan.with_manifest(manifest.as_deref())?;
        let config = blob(channel.clone(), config_plan.config_request(), deadline).await?;
        let metadata = config_plan.finish(&config)?;
        if !metadata.root_matches(&initial.media_type, &initial.digest, initial.size) {
            return Err(NativeImageMetadataError::RootMismatch);
        }
        let final_target = image(channel, reference, expected, deadline).await?;
        if initial != final_target {
            return Err(NativeImageMetadataError::ImageChanged);
        }
        Ok(NativeImageMetadata {
            scope: "NATIVE_CONTAINERD_METADATA_ONLY",
            namespace: NAMESPACE,
            reference: reference.to_owned(),
            runtime_version: "2.3.5",
            observed_at: chrono::Utc::now(),
            metadata,
        })
    }

    #[cfg(test)]
    mod tests {
        include!("native_image_metadata_tests.rs");
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "native_image_metadata_cli_tests.rs"]
mod cli_tests;
