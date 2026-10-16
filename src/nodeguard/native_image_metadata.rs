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

/// A current CRI index identity observation, not evidence of how an image was
/// pulled, which snapshotter was used, or whether its unpacked data still exists.
#[derive(Debug, Serialize)]
pub struct NativeCriImageMetadata {
    scope: &'static str,
    cri_image_id: String,
    approval_checked: bool,
    pull_selection_checked: bool,
    runtime_handler_checked: bool,
    snapshotter_checked: bool,
    unpack_checked: bool,
    gc_protection_checked: bool,
    preparation_allowed: bool,
    native: NativeImageMetadata,
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
    #[error("CRI_IMAGE_UNAVAILABLE")]
    CriImageUnavailable,
    #[error("CRI_IMAGE_MISMATCH")]
    CriImageMismatch,
    #[error("CRI_IMAGE_CHANGED")]
    CriImageChanged,
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
            Self::CriImageUnavailable => "CRI_IMAGE_UNAVAILABLE",
            Self::CriImageMismatch => "CRI_IMAGE_MISMATCH",
            Self::CriImageChanged => "CRI_IMAGE_CHANGED",
            Self::Metadata(error) => error.code(),
        }
    }
}

/// Bind this daemon's current CRI index resolution to independently verified
/// OCI metadata. No runtime handler is accepted: containerd 2.3.5 ImageStatus
/// ignores it and uses a host-platform image index, not a pull-time selection.
pub async fn inspect_cri(
    reference: &str,
    expected_digest: &str,
    platform: &str,
) -> Result<NativeCriImageMetadata, NativeImageMetadataError> {
    crate::image_artifact::validate_request(expected_digest, platform)?;
    validate_reference(reference, expected_digest)?;
    #[cfg(target_os = "linux")]
    {
        if !rustix::process::geteuid().is_root() {
            return Err(NativeImageMetadataError::UnsupportedRuntime);
        }
        backend::inspect_cri_local(reference, expected_digest, platform).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(NativeImageMetadataError::UnsupportedRuntime)
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
            cri_proto::{
                ImageSpec, ImageStatusRequest, ImageStatusResponse, VersionRequest, VersionResponse,
            },
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
    const MAX_CRI_ALIASES: usize = 128;
    const MAX_CRI_ALIAS_BYTES: usize = 48 * 1024;

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
        // Tonic 0.14 reports its local grpc-timeout expiry as Cancelled while
        // retaining TimeoutExpired in the source chain. A remote Cancelled,
        // including the same message text, has no such local typed evidence.
        if error.code() == Code::Cancelled {
            let mut source = std::error::Error::source(&error);
            while let Some(cause) = source {
                if cause.is::<tonic::TimeoutExpired>() {
                    return NativeImageMetadataError::DeadlineExceeded;
                }
                source = cause.source();
            }
        }
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
        with_local_channel(|channel, deadline| {
            inspect_channel(channel, reference, expected, platform, deadline)
        })
        .await
    }

    #[cfg(target_os = "linux")]
    pub(super) async fn inspect_cri_local(
        reference: &str,
        expected: &str,
        platform: &str,
    ) -> Result<NativeCriImageMetadata, NativeImageMetadataError> {
        with_local_channel(|channel, deadline| {
            inspect_cri_channel(channel, reference, expected, platform, deadline)
        })
        .await
    }

    #[cfg(target_os = "linux")]
    async fn with_local_channel<T, F, Fut>(operation: F) -> Result<T, NativeImageMetadataError>
    where
        F: FnOnce(Channel, Instant) -> Fut,
        Fut: std::future::Future<Output = Result<T, NativeImageMetadataError>>,
    {
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
            operation(channel, deadline).await
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

    async fn verify_version(
        channel: Channel,
        deadline: Instant,
    ) -> Result<(), NativeImageMetadataError> {
        let version: VersionResponse = unary(
            channel,
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
        Ok(())
    }

    async fn read_metadata(
        channel: Channel,
        reference: &str,
        expected: &str,
        platform: &str,
        deadline: Instant,
    ) -> Result<(Descriptor, VerifiedImageMetadata), NativeImageMetadataError> {
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
        Ok((initial, metadata))
    }

    async fn finish_metadata(
        channel: Channel,
        reference: &str,
        expected: &str,
        initial: Descriptor,
        metadata: VerifiedImageMetadata,
        deadline: Instant,
    ) -> Result<NativeImageMetadata, NativeImageMetadataError> {
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

    async fn inspect_channel(
        channel: Channel,
        reference: &str,
        expected: &str,
        platform: &str,
        deadline: Instant,
    ) -> Result<NativeImageMetadata, NativeImageMetadataError> {
        verify_version(channel.clone(), deadline).await?;
        let (initial, metadata) =
            read_metadata(channel.clone(), reference, expected, platform, deadline).await?;
        finish_metadata(channel, reference, expected, initial, metadata, deadline).await
    }

    #[derive(Debug, Eq, PartialEq)]
    struct CriIdentity {
        image_id: String,
        exact_reference_present: bool,
    }

    async fn cri_identity(
        channel: Channel,
        reference: &str,
        deadline: Instant,
    ) -> Result<CriIdentity, NativeImageMetadataError> {
        let response: ImageStatusResponse = unary(
            channel,
            ImageStatusRequest {
                image: Some(ImageSpec {
                    image: reference.to_owned(),
                    ..Default::default()
                }),
                verbose: false,
            },
            "/runtime.v1.ImageService/ImageStatus",
            SMALL_REPLY,
            deadline,
        )
        .await?;
        if !response.info.is_empty() {
            return Err(NativeImageMetadataError::ResponseInvalid);
        }
        let image = response
            .image
            .ok_or(NativeImageMetadataError::CriImageUnavailable)?;
        if image.id.len() != 71
            || !image.id.starts_with("sha256:")
            || !image.id.as_bytes()[7..]
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            || image
                .repo_tags
                .len()
                .saturating_add(image.repo_digests.len())
                > MAX_CRI_ALIASES
        {
            return Err(NativeImageMetadataError::ResponseInvalid);
        }
        let mut alias_bytes = 0usize;
        for alias in image.repo_tags.iter().chain(&image.repo_digests) {
            if alias.is_empty()
                || alias.len() > 2048
                || !alias.is_ascii()
                || alias.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(NativeImageMetadataError::ResponseInvalid);
            }
            alias_bytes = alias_bytes.saturating_add(alias.len());
            if alias_bytes > MAX_CRI_ALIAS_BYTES {
                return Err(NativeImageMetadataError::ResponseInvalid);
            }
        }
        // Other aliases, user/config fields, size and pinned are neither returned
        // nor evidence for this exact-reference/config identity observation.
        Ok(CriIdentity {
            image_id: image.id,
            exact_reference_present: image.repo_digests.iter().any(|digest| digest == reference),
        })
    }

    async fn inspect_cri_channel(
        channel: Channel,
        reference: &str,
        expected: &str,
        platform: &str,
        deadline: Instant,
    ) -> Result<NativeCriImageMetadata, NativeImageMetadataError> {
        verify_version(channel.clone(), deadline).await?;
        let before = cri_identity(channel.clone(), reference, deadline).await?;
        if !before.exact_reference_present {
            return Err(NativeImageMetadataError::CriImageMismatch);
        }
        let (initial, metadata) =
            read_metadata(channel.clone(), reference, expected, platform, deadline).await?;
        let after = cri_identity(channel.clone(), reference, deadline).await?;
        if before != after {
            return Err(NativeImageMetadataError::CriImageChanged);
        }
        if before.image_id != metadata.config_digest() {
            return Err(NativeImageMetadataError::CriImageMismatch);
        }
        let native =
            finish_metadata(channel, reference, expected, initial, metadata, deadline).await?;
        Ok(NativeCriImageMetadata {
            scope: "CRI_INDEX_CONFIG_IDENTITY_ONLY",
            cri_image_id: before.image_id,
            approval_checked: false,
            pull_selection_checked: false,
            runtime_handler_checked: false,
            snapshotter_checked: false,
            unpack_checked: false,
            gc_protection_checked: false,
            preparation_allowed: false,
            native,
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

#[cfg(all(test, target_os = "linux"))]
#[path = "cri_image_metadata_cli_tests.rs"]
mod cri_cli_tests;
