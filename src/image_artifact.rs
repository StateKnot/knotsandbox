//! Bounded verification of an expected OCI image's metadata and layer streams.
//!
//! The caller supplies the expected digest. Metadata inspection leaves payloads
//! unread; the separate payload interface requires explicit byte budgets. No
//! operation establishes approval, interprets tar entries, unpacks content, or
//! prepares a runtime. A separate exporter writes only a canonical approved-root
//! OCI closure for an externally restricted bootstrap executor.
use std::{collections::BTreeMap, path::Path};

use serde::{Deserialize, Serialize, de};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const MAX_BLOB_BYTES: usize = 1024 * 1024;
const MAX_METADATA_BYTES: u64 = 3 * 1024 * 1024;
const MAX_INDEX_ENTRIES: usize = 128;
const MAX_LAYERS: usize = 256;

mod payloads;
pub use payloads::{PayloadLimits, VerifiedImagePayloads, verify_oci_payloads};
mod bootstrap_archive;
pub use bootstrap_archive::{
    BootstrapArchiveLimits, ExportedBootstrapArchive, export_bootstrap_archive,
};

/// A metadata-only receipt; no field conveys approval or preparation authority.
#[derive(Debug, Serialize)]
pub struct VerifiedImageMetadata {
    scope: &'static str,
    approval_checked: bool,
    layer_payloads_verified: bool,
    preparation_allowed: bool,
    platform: Platform,
    root: DescriptorIdentity,
    index: Option<DescriptorIdentity>,
    selected_manifest: DescriptorIdentity,
    config: DescriptorIdentity,
    layers: Vec<LayerIdentity>,
    declared_layer_bytes: String,
    unique_declared_layer_bytes: String,
    metadata_bytes_read: String,
}

/// Stable errors deliberately contain neither input paths nor upstream data.
#[derive(Debug, Clone, Copy, Eq, PartialEq, thiserror::Error)]
pub enum ImageArtifactError {
    #[error("INVALID_DIGEST")]
    InvalidDigest,
    #[error("UNSUPPORTED_PLATFORM")]
    UnsupportedPlatform,
    #[error("UNSUPPORTED_LAYOUT")]
    UnsupportedLayout,
    #[error("METADATA_UNAVAILABLE")]
    MetadataUnavailable,
    #[error("METADATA_CHANGED")]
    MetadataChanged,
    #[error("METADATA_LIMIT_EXCEEDED")]
    MetadataLimitExceeded,
    #[error("INVALID_METADATA")]
    InvalidMetadata,
    #[error("DIGEST_MISMATCH")]
    DigestMismatch,
    #[error("SIZE_MISMATCH")]
    SizeMismatch,
    #[error("UNSUPPORTED_MEDIA_TYPE")]
    UnsupportedMediaType,
    #[error("UNSUPPORTED_DESCRIPTOR")]
    UnsupportedDescriptor,
    #[error("PLATFORM_MISMATCH")]
    PlatformMismatch,
    #[error("AMBIGUOUS_PLATFORM")]
    AmbiguousPlatform,
    #[error("DESCRIPTOR_CONFLICT")]
    DescriptorConflict,
    #[error("INTEGER_OVERFLOW")]
    IntegerOverflow,
    #[error("INVALID_PAYLOAD_LIMITS")]
    InvalidPayloadLimits,
    #[error("PAYLOAD_LIMIT_EXCEEDED")]
    PayloadLimitExceeded,
    #[error("UNSUPPORTED_PAYLOAD_MEDIA_TYPE")]
    UnsupportedPayloadMediaType,
    #[error("INVALID_LAYER_ENCODING")]
    InvalidLayerEncoding,
    #[error("DIFF_ID_MISMATCH")]
    DiffIdMismatch,
    #[error("PAYLOAD_DEADLINE_EXCEEDED")]
    PayloadDeadlineExceeded,
    #[error("INVALID_BOOTSTRAP_ARCHIVE_LIMITS")]
    InvalidBootstrapArchiveLimits,
    #[error("INVALID_BOOTSTRAP_REFERENCE")]
    InvalidBootstrapReference,
    #[error("UNSUPPORTED_BOOTSTRAP_ROOT")]
    UnsupportedBootstrapRoot,
    #[error("BOOTSTRAP_ARCHIVE_LIMIT_EXCEEDED")]
    BootstrapArchiveLimitExceeded,
    #[error("BOOTSTRAP_ARCHIVE_DEADLINE_EXCEEDED")]
    BootstrapArchiveDeadlineExceeded,
    #[error("BOOTSTRAP_ARCHIVE_WRITE_FAILED")]
    BootstrapArchiveWriteFailed,
}

impl ImageArtifactError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidDigest => "INVALID_DIGEST",
            Self::UnsupportedPlatform => "UNSUPPORTED_PLATFORM",
            Self::UnsupportedLayout => "UNSUPPORTED_LAYOUT",
            Self::MetadataUnavailable => "METADATA_UNAVAILABLE",
            Self::MetadataChanged => "METADATA_CHANGED",
            Self::MetadataLimitExceeded => "METADATA_LIMIT_EXCEEDED",
            Self::InvalidMetadata => "INVALID_METADATA",
            Self::DigestMismatch => "DIGEST_MISMATCH",
            Self::SizeMismatch => "SIZE_MISMATCH",
            Self::UnsupportedMediaType => "UNSUPPORTED_MEDIA_TYPE",
            Self::UnsupportedDescriptor => "UNSUPPORTED_DESCRIPTOR",
            Self::PlatformMismatch => "PLATFORM_MISMATCH",
            Self::AmbiguousPlatform => "AMBIGUOUS_PLATFORM",
            Self::DescriptorConflict => "DESCRIPTOR_CONFLICT",
            Self::IntegerOverflow => "INTEGER_OVERFLOW",
            Self::InvalidPayloadLimits => "INVALID_PAYLOAD_LIMITS",
            Self::PayloadLimitExceeded => "PAYLOAD_LIMIT_EXCEEDED",
            Self::UnsupportedPayloadMediaType => "UNSUPPORTED_PAYLOAD_MEDIA_TYPE",
            Self::InvalidLayerEncoding => "INVALID_LAYER_ENCODING",
            Self::DiffIdMismatch => "DIFF_ID_MISMATCH",
            Self::PayloadDeadlineExceeded => "PAYLOAD_DEADLINE_EXCEEDED",
            Self::InvalidBootstrapArchiveLimits => "INVALID_BOOTSTRAP_ARCHIVE_LIMITS",
            Self::InvalidBootstrapReference => "INVALID_BOOTSTRAP_REFERENCE",
            Self::UnsupportedBootstrapRoot => "UNSUPPORTED_BOOTSTRAP_ROOT",
            Self::BootstrapArchiveLimitExceeded => "BOOTSTRAP_ARCHIVE_LIMIT_EXCEEDED",
            Self::BootstrapArchiveDeadlineExceeded => "BOOTSTRAP_ARCHIVE_DEADLINE_EXCEEDED",
            Self::BootstrapArchiveWriteFailed => "BOOTSTRAP_ARCHIVE_WRITE_FAILED",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct Platform {
    os: String,
    architecture: String,
    variant: Option<String>,
}

impl Platform {
    fn parse(value: &str) -> Result<Self, ImageArtifactError> {
        if value.len() > 45 {
            return Err(ImageArtifactError::UnsupportedPlatform);
        }
        let parts: Vec<_> = value.split('/').collect();
        if !(2..=3).contains(&parts.len()) {
            return Err(ImageArtifactError::UnsupportedPlatform);
        }
        let platform = Self {
            os: parts[0].to_owned(),
            architecture: parts[1].to_owned(),
            variant: parts.get(2).map(|value| (*value).to_owned()),
        };
        platform.validate()?;
        Ok(platform)
    }

    fn read(value: &Value) -> Result<Self, ImageArtifactError> {
        let object = object(value)?;
        match object.get("os.version") {
            None | Some(Value::Null | Value::String(_)) => {}
            _ => return Err(ImageArtifactError::InvalidMetadata),
        }
        for key in ["os.features", "features"] {
            match object.get(key) {
                None | Some(Value::Null) => {}
                Some(Value::Array(features)) if features.iter().all(Value::is_string) => {}
                _ => return Err(ImageArtifactError::InvalidMetadata),
            }
        }
        let platform = Self {
            os: string(object, "os")?.to_owned(),
            architecture: string(object, "architecture")?.to_owned(),
            variant: match object.get("variant") {
                None | Some(Value::Null) => None,
                Some(Value::String(value)) => Some(value.clone()),
                _ => return Err(ImageArtifactError::InvalidMetadata),
            },
        };
        if [&platform.os, &platform.architecture].iter().any(|value| {
            value.is_empty()
                || value.len() > 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        }) || !platform.valid_variant()
        {
            return Err(ImageArtifactError::UnsupportedPlatform);
        }
        Ok(platform)
    }

    fn validate(&self) -> Result<(), ImageArtifactError> {
        if self.os != "linux"
            || !matches!(self.architecture.as_str(), "amd64" | "arm64")
            || !self.valid_variant()
        {
            return Err(ImageArtifactError::UnsupportedPlatform);
        }
        Ok(())
    }

    fn valid_variant(&self) -> bool {
        !self.variant.as_ref().is_some_and(|variant| {
            variant.is_empty()
                || variant.len() > 32
                || !variant.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
                || !variant.as_bytes()[0].is_ascii_alphanumeric()
        })
    }
}

#[derive(Debug, Clone, Serialize)]
struct DescriptorIdentity {
    media_type: String,
    digest: String,
    size_bytes: String,
}

#[derive(Clone)]
struct Descriptor {
    identity: DescriptorIdentity,
    size: u64,
}

impl Descriptor {
    fn read(value: &Value) -> Result<Self, ImageArtifactError> {
        let value = object(value)?;
        let digest = string(value, "digest")?;
        validate_digest(digest)?;
        let size = value
            .get("size")
            .and_then(Value::as_u64)
            .ok_or(ImageArtifactError::InvalidMetadata)?;
        // OCI descriptor sizes are signed 64-bit integers. Retain exact
        // integer parsing even above JavaScript's exact integer range.
        if size > i64::MAX as u64 {
            return Err(ImageArtifactError::InvalidMetadata);
        }
        Ok(Self {
            identity: DescriptorIdentity {
                media_type: string(value, "mediaType")?.to_owned(),
                digest: digest.to_owned(),
                size_bytes: size.to_string(),
            },
            size,
        })
    }

    fn root(media_type: &str, digest: &str, size: usize) -> Self {
        Self {
            identity: DescriptorIdentity {
                media_type: media_type.to_owned(),
                digest: digest.to_owned(),
                size_bytes: size.to_string(),
            },
            size: size as u64,
        }
    }
}

#[derive(Debug, Serialize)]
struct LayerIdentity {
    #[serde(flatten)]
    descriptor: DescriptorIdentity,
    diff_id: String,
}

/// Verify only a bounded OCI metadata closure at the caller's expected digest.
///
/// Platforms are exact `linux/amd64[/variant]` or `linux/arm64[/variant]`;
/// absent variants are never inferred. The layout and all path components must
/// be real directories, and metadata must be regular files. No layer payload,
/// registry, database, runtime, or subprocess is accessed.
pub fn verify_oci_metadata(
    layout: &Path,
    expected_digest: &str,
    platform: &str,
) -> Result<VerifiedImageMetadata, ImageArtifactError> {
    validate_request(expected_digest, platform)?;
    let mut layout = Layout::open(layout)?;
    verify_metadata_in(&mut layout, expected_digest, platform)
}

fn verify_metadata_in(
    layout: &mut Layout,
    expected_digest: &str,
    platform: &str,
) -> Result<VerifiedImageMetadata, ImageArtifactError> {
    let layout_marker = layout.marker()?;
    if string(object(&layout_marker)?, "imageLayoutVersion")? != "1.0.0" {
        return Err(ImageArtifactError::UnsupportedLayout);
    }
    let initial_metadata_bytes = layout.bytes_read;
    let root_bytes = layout.blob(expected_digest, None)?;
    let plan = MetadataPlan::from_root(
        &root_bytes,
        expected_digest,
        platform,
        initial_metadata_bytes,
    )?;
    let manifest_bytes = plan
        .manifest_request()
        .map(|request| layout.blob(&request.digest, request.size))
        .transpose()?;
    let plan = plan.with_manifest(manifest_bytes.as_deref())?;
    let request = plan.config_request();
    let config_bytes = layout.blob(&request.digest, request.size)?;
    plan.finish(&config_bytes)
}

/// Validate caller-controlled identifiers before any adapter accesses storage.
pub(crate) fn validate_request(
    expected_digest: &str,
    platform: &str,
) -> Result<(), ImageArtifactError> {
    validate_digest(expected_digest)?;
    Platform::parse(platform)?;
    Ok(())
}

/// The next metadata blob required by an already authenticated descriptor.
/// No layer payload is ever requested by a metadata plan.
pub(crate) struct MetadataBlobRequest {
    pub(crate) digest: String,
    pub(crate) size: Option<u64>,
}

/// Storage-independent OCI verification shared by the offline and native
/// adapters. Owning each stage keeps the aggregate budget and descriptor
/// registry attached to the same authenticated root throughout selection.
pub(crate) struct MetadataPlan {
    platform: Platform,
    root: Descriptor,
    index: Option<DescriptorIdentity>,
    manifest: Descriptor,
    direct_manifest: Option<Value>,
    budget: MetadataBudget,
    identities: DescriptorRegistry,
}

impl MetadataPlan {
    pub(crate) fn from_root(
        root_bytes: &[u8],
        expected_digest: &str,
        platform: &str,
        initial_metadata_bytes: u64,
    ) -> Result<Self, ImageArtifactError> {
        validate_digest(expected_digest)?;
        let platform = Platform::parse(platform)?;
        let mut budget = MetadataBudget {
            bytes_read: initial_metadata_bytes,
        };
        budget.verify(root_bytes, expected_digest, None)?;
        let root_value = parse_json(root_bytes)?;
        let root_object = object(&root_value)?;
        validate_document(root_object)?;
        let root = Descriptor::root(
            string(root_object, "mediaType")?,
            expected_digest,
            root_bytes.len(),
        );
        let mut identities = DescriptorRegistry::default();
        identities.register(&root)?;
        let (index, manifest, direct_manifest) = match root.identity.media_type.as_str() {
            OCI_MANIFEST => (None, root.clone(), Some(root_value)),
            OCI_INDEX => (
                Some(root.identity.clone()),
                select_manifest(root_object, &platform, &mut identities)?,
                None,
            ),
            _ => return Err(ImageArtifactError::UnsupportedMediaType),
        };
        Ok(Self {
            platform,
            root,
            index,
            manifest,
            direct_manifest,
            budget,
            identities,
        })
    }

    pub(crate) fn manifest_request(&self) -> Option<MetadataBlobRequest> {
        self.index.as_ref().map(|_| MetadataBlobRequest {
            digest: self.manifest.identity.digest.clone(),
            size: Some(self.manifest.size),
        })
    }

    pub(crate) fn with_manifest(
        mut self,
        bytes: Option<&[u8]>,
    ) -> Result<ConfigurationPlan, ImageArtifactError> {
        let manifest_value = match (self.direct_manifest, bytes) {
            (Some(value), None) => value,
            (None, Some(bytes)) => {
                self.budget.verify(
                    bytes,
                    &self.manifest.identity.digest,
                    Some(self.manifest.size),
                )?;
                let value = parse_json(bytes)?;
                if string(object(&value)?, "mediaType")? != OCI_MANIFEST {
                    return Err(ImageArtifactError::UnsupportedMediaType);
                }
                value
            }
            // Adapters must fetch exactly the stage's requested closure.
            _ => return Err(ImageArtifactError::InvalidMetadata),
        };
        let manifest_object = object(&manifest_value)?;
        validate_document(manifest_object)?;
        let config_value = manifest_object
            .get("config")
            .ok_or(ImageArtifactError::InvalidMetadata)?;
        validate_target(object(config_value)?)?;
        let config = Descriptor::read(config_value)?;
        if config.identity.media_type != OCI_CONFIG {
            return Err(ImageArtifactError::UnsupportedMediaType);
        }
        self.identities.register(&config)?;
        let layers = manifest_object
            .get("layers")
            .and_then(Value::as_array)
            .ok_or(ImageArtifactError::InvalidMetadata)?;
        if layers.len() > MAX_LAYERS {
            return Err(ImageArtifactError::MetadataLimitExceeded);
        }
        Ok(ConfigurationPlan {
            platform: self.platform,
            root: self.root,
            index: self.index,
            manifest: self.manifest,
            config,
            manifest_value,
            budget: self.budget,
            identities: self.identities,
        })
    }
}

pub(crate) struct ConfigurationPlan {
    platform: Platform,
    root: Descriptor,
    index: Option<DescriptorIdentity>,
    manifest: Descriptor,
    config: Descriptor,
    manifest_value: Value,
    budget: MetadataBudget,
    identities: DescriptorRegistry,
}

impl ConfigurationPlan {
    pub(crate) fn config_request(&self) -> MetadataBlobRequest {
        MetadataBlobRequest {
            digest: self.config.identity.digest.clone(),
            size: Some(self.config.size),
        }
    }

    pub(crate) fn finish(
        self,
        config_bytes: &[u8],
    ) -> Result<VerifiedImageMetadata, ImageArtifactError> {
        let Self {
            platform,
            root,
            index,
            manifest,
            config,
            manifest_value,
            mut budget,
            mut identities,
        } = self;
        budget.verify(config_bytes, &config.identity.digest, Some(config.size))?;
        let manifest_object = object(&manifest_value)?;
        let layers = manifest_object
            .get("layers")
            .and_then(Value::as_array)
            .ok_or(ImageArtifactError::InvalidMetadata)?;
        let config_json = parse_json(config_bytes)?;
        if Platform::read(&config_json)? != platform {
            return Err(ImageArtifactError::PlatformMismatch);
        }
        validate_platform_constraints(object(&config_json)?)?;
        let rootfs = object(&config_json)?
            .get("rootfs")
            .ok_or(ImageArtifactError::InvalidMetadata)?;
        let rootfs = object(rootfs)?;
        if string(rootfs, "type")? != "layers" {
            return Err(ImageArtifactError::InvalidMetadata);
        }
        let diff_ids = rootfs
            .get("diff_ids")
            .and_then(Value::as_array)
            .ok_or(ImageArtifactError::InvalidMetadata)?;
        if layers.len() != diff_ids.len() {
            return Err(ImageArtifactError::InvalidMetadata);
        }
        let mut verified_layers = Vec::with_capacity(layers.len());
        let mut unique_layers = BTreeMap::new();
        let mut declared_layer_bytes = 0_u64;
        let mut unique_declared_layer_bytes = 0_u64;
        for (layer, diff_id) in layers.iter().zip(diff_ids) {
            validate_target(object(layer)?)?;
            let layer = Descriptor::read(layer)?;
            if !matches!(
                layer.identity.media_type.as_str(),
                "application/vnd.oci.image.layer.v1.tar"
                    | "application/vnd.oci.image.layer.v1.tar+gzip"
                    | "application/vnd.oci.image.layer.v1.tar+zstd"
            ) {
                return Err(ImageArtifactError::UnsupportedMediaType);
            }
            identities.register(&layer)?;
            let diff_id = diff_id
                .as_str()
                .ok_or(ImageArtifactError::InvalidMetadata)?;
            validate_digest(diff_id)?;
            // An uncompressed tar's manifest digest and DiffID describe the same
            // byte stream; compressed layer declarations cannot use this check.
            if layer.identity.media_type == "application/vnd.oci.image.layer.v1.tar"
                && layer.identity.digest != diff_id
            {
                return Err(ImageArtifactError::InvalidMetadata);
            }
            declared_layer_bytes = declared_layer_bytes
                .checked_add(layer.size)
                .ok_or(ImageArtifactError::IntegerOverflow)?;
            if unique_layers
                .insert(layer.identity.digest.clone(), layer.size)
                .is_none()
            {
                unique_declared_layer_bytes = unique_declared_layer_bytes
                    .checked_add(layer.size)
                    .ok_or(ImageArtifactError::IntegerOverflow)?;
            }
            verified_layers.push(LayerIdentity {
                descriptor: layer.identity,
                diff_id: diff_id.to_owned(),
            });
        }
        Ok(VerifiedImageMetadata {
            scope: "OCI_METADATA_ONLY",
            approval_checked: false,
            layer_payloads_verified: false,
            preparation_allowed: false,
            platform,
            root: root.identity,
            index,
            selected_manifest: manifest.identity,
            config: config.identity,
            layers: verified_layers,
            declared_layer_bytes: declared_layer_bytes.to_string(),
            unique_declared_layer_bytes: unique_declared_layer_bytes.to_string(),
            metadata_bytes_read: budget.bytes_read.to_string(),
        })
    }
}

impl VerifiedImageMetadata {
    /// Identity of the authenticated configuration, never a preparation permit.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn config_digest(&self) -> &str {
        &self.config.digest
    }

    /// Derive the final and immediate parent ChainID only from authenticated
    /// config DiffIDs, in layer order. An empty rootfs has no snapshot key.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn rootfs_chain(&self) -> Option<RootfsChain> {
        let mut layers = self.layers.iter();
        let mut chain_id = layers.next()?.diff_id.clone();
        let mut parent_chain_id = None;
        for layer in layers {
            parent_chain_id = Some(chain_id.clone());
            let mut digest = Sha256::new();
            digest.update(chain_id.as_bytes());
            digest.update(b" ");
            digest.update(layer.diff_id.as_bytes());
            chain_id = format!("sha256:{}", hex::encode(digest.finalize()));
        }
        Some(RootfsChain {
            chain_id,
            parent_chain_id,
        })
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn config_matches(&self, digest: &str, size: i64) -> bool {
        size >= 0 && self.config.digest == digest && self.config.size_bytes == size.to_string()
    }

    /// Bind a native Images.Get target to the closure's authenticated root.
    /// This comparison grants neither preparation authority nor approval.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn root_matches(&self, media: &str, digest: &str, size: i64) -> bool {
        size >= 0
            && self.root.media_type == media
            && self.root.digest == digest
            && self.root.size_bytes == size.to_string()
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RootfsChain {
    pub(crate) chain_id: String,
    pub(crate) parent_chain_id: Option<String>,
}

struct MetadataBudget {
    bytes_read: u64,
}

impl MetadataBudget {
    fn verify(
        &mut self,
        bytes: &[u8],
        digest: &str,
        expected_size: Option<u64>,
    ) -> Result<(), ImageArtifactError> {
        if bytes.len() > MAX_BLOB_BYTES {
            return Err(ImageArtifactError::MetadataLimitExceeded);
        }
        if expected_size.is_some_and(|size| size != bytes.len() as u64) {
            return Err(ImageArtifactError::SizeMismatch);
        }
        self.bytes_read = self
            .bytes_read
            .checked_add(bytes.len() as u64)
            .filter(|size| *size <= MAX_METADATA_BYTES)
            .ok_or(ImageArtifactError::MetadataLimitExceeded)?;
        if format!("sha256:{:x}", Sha256::digest(bytes)) != digest {
            return Err(ImageArtifactError::DigestMismatch);
        }
        Ok(())
    }
}

fn select_manifest(
    root: &Map<String, Value>,
    target: &Platform,
    identities: &mut DescriptorRegistry,
) -> Result<Descriptor, ImageArtifactError> {
    let entries = root
        .get("manifests")
        .and_then(Value::as_array)
        .ok_or(ImageArtifactError::InvalidMetadata)?;
    if entries.len() > MAX_INDEX_ENTRIES {
        return Err(ImageArtifactError::MetadataLimitExceeded);
    }
    let mut selected = None;
    for entry in entries {
        let entry_object = object(entry)?;
        match string(entry_object, "mediaType")? {
            OCI_INDEX => return Err(ImageArtifactError::UnsupportedMediaType),
            OCI_MANIFEST => {}
            // Unknown index children are opaque extensions, not executable
            // candidates. Their digest algorithm and descriptor interpretation
            // need not be supported by this image-only profile.
            _ => continue,
        }
        let descriptor = Descriptor::read(entry)?;
        identities.register(&descriptor)?;
        let entry = entry_object;
        let Some(candidate_value) = entry.get("platform") else {
            continue;
        };
        let candidate = Platform::read(candidate_value)?;
        if candidate != *target {
            continue;
        }
        if selected.is_some() {
            return Err(ImageArtifactError::AmbiguousPlatform);
        }
        validate_platform_constraints(object(candidate_value)?)?;
        validate_target(entry)?;
        selected = Some(descriptor);
    }
    selected.ok_or(ImageArtifactError::PlatformMismatch)
}

fn validate_platform_constraints(value: &Map<String, Value>) -> Result<(), ImageArtifactError> {
    // These are constraints, not descriptive labels. Never discard them and
    // accidentally accept a selected image requiring unsupported features.
    match value.get("os.version") {
        None | Some(Value::Null) => {}
        Some(Value::String(version)) if version.is_empty() => {}
        _ => return Err(ImageArtifactError::UnsupportedPlatform),
    }
    for key in ["os.features", "features"] {
        match value.get(key) {
            None | Some(Value::Null) => {}
            Some(Value::Array(features)) if features.is_empty() => {}
            _ => return Err(ImageArtifactError::UnsupportedPlatform),
        }
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), ImageArtifactError> {
    if !value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return Err(ImageArtifactError::InvalidDigest);
    }
    Ok(())
}

fn object(value: &Value) -> Result<&Map<String, Value>, ImageArtifactError> {
    value.as_object().ok_or(ImageArtifactError::InvalidMetadata)
}

fn string<'a>(value: &'a Map<String, Value>, key: &str) -> Result<&'a str, ImageArtifactError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(ImageArtifactError::InvalidMetadata)
}

fn validate_document(value: &Map<String, Value>) -> Result<(), ImageArtifactError> {
    if value.get("schemaVersion").and_then(Value::as_u64) != Some(2) {
        return Err(ImageArtifactError::InvalidMetadata);
    }
    validate_target(value)
}

fn validate_target(value: &Map<String, Value>) -> Result<(), ImageArtifactError> {
    if ["subject", "artifactType", "data"]
        .iter()
        .any(|key| value.contains_key(*key))
    {
        return Err(ImageArtifactError::UnsupportedDescriptor);
    }
    match value.get("urls") {
        None | Some(Value::Null) => {}
        Some(Value::Array(urls)) if urls.is_empty() => {}
        _ => return Err(ImageArtifactError::UnsupportedDescriptor),
    }
    Ok(())
}

#[derive(Default)]
struct DescriptorRegistry(BTreeMap<String, (u64, String)>);

impl DescriptorRegistry {
    fn register(&mut self, descriptor: &Descriptor) -> Result<(), ImageArtifactError> {
        let value = (descriptor.size, descriptor.identity.media_type.clone());
        if self
            .0
            .get(&descriptor.identity.digest)
            .is_some_and(|old| old != &value)
        {
            return Err(ImageArtifactError::DescriptorConflict);
        }
        self.0.insert(descriptor.identity.digest.clone(), value);
        Ok(())
    }
}

// Value's normal deserializer accepts duplicate object members. Check every
// object, including ignored OCI extensions, before interpreting selected fields.
struct StrictJson(Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = StrictJson;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("JSON without duplicate object members")
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Bool(value)))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Number(Number::from(value))))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Number(Number::from(value))))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                Number::from_f64(value)
                    .map(|number| StrictJson(Value::Number(number)))
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::String(value.to_owned())))
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::String(value)))
            }

            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Null))
            }

            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Null))
            }

            fn visit_seq<A: de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictJson>()? {
                    values.push(value.0);
                }
                Ok(StrictJson(Value::Array(values)))
            }

            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON member"));
                    }
                    values.insert(key, map.next_value::<StrictJson>()?.0);
                }
                Ok(StrictJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

fn parse_json(bytes: &[u8]) -> Result<Value, ImageArtifactError> {
    serde_json::from_slice::<StrictJson>(bytes)
        .map(|value| value.0)
        .map_err(|_| ImageArtifactError::InvalidMetadata)
}

#[cfg(unix)]
struct Layout {
    root: std::fs::File,
    blobs: std::fs::File,
    bytes_read: u64,
}

#[cfg(unix)]
impl Layout {
    fn open(path: &Path) -> Result<Self, ImageArtifactError> {
        use nix::{
            fcntl::{OFlag, open, openat},
            sys::stat::Mode,
        };
        use std::path::Component;
        let flags = OFlag::O_RDONLY
            | OFlag::O_DIRECTORY
            | OFlag::O_NOFOLLOW
            | OFlag::O_NONBLOCK
            | OFlag::O_CLOEXEC;
        let mut directory = open(
            if path.is_absolute() {
                Path::new("/")
            } else {
                Path::new(".")
            },
            flags,
            Mode::empty(),
        )
        .map_err(|_| ImageArtifactError::MetadataUnavailable)?;
        if path.as_os_str().is_empty() {
            return Err(ImageArtifactError::UnsupportedLayout);
        }
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => {
                    directory = openat(&directory, Path::new(name), flags, Mode::empty())
                        .map_err(|_| ImageArtifactError::MetadataUnavailable)?;
                }
                _ => return Err(ImageArtifactError::UnsupportedLayout),
            }
        }
        let blob_directory = openat(&directory, "blobs", flags, Mode::empty())
            .map_err(|_| ImageArtifactError::MetadataUnavailable)?;
        let sha256_directory = openat(&blob_directory, "sha256", flags, Mode::empty())
            .map_err(|_| ImageArtifactError::MetadataUnavailable)?;
        Ok(Self {
            root: std::fs::File::from(directory),
            blobs: std::fs::File::from(sha256_directory),
            bytes_read: 0,
        })
    }

    fn marker(&mut self) -> Result<Value, ImageArtifactError> {
        let bytes = read_metadata(&self.root, "oci-layout", 4096, None)?;
        self.account(bytes.len())?;
        parse_json(&bytes)
    }

    fn blob(&mut self, digest: &str, size: Option<u64>) -> Result<Vec<u8>, ImageArtifactError> {
        let name = digest
            .strip_prefix("sha256:")
            .ok_or(ImageArtifactError::InvalidDigest)?;
        read_metadata(&self.blobs, name, MAX_BLOB_BYTES, size)
    }

    fn account(&mut self, size: usize) -> Result<(), ImageArtifactError> {
        self.bytes_read = self
            .bytes_read
            .checked_add(size as u64)
            .ok_or(ImageArtifactError::MetadataLimitExceeded)?;
        if self.bytes_read > MAX_METADATA_BYTES {
            return Err(ImageArtifactError::MetadataLimitExceeded);
        }
        Ok(())
    }
}

#[cfg(unix)]
fn read_metadata(
    directory: &std::fs::File,
    name: &str,
    limit: usize,
    expected_size: Option<u64>,
) -> Result<Vec<u8>, ImageArtifactError> {
    use nix::{
        fcntl::{OFlag, openat},
        sys::stat::Mode,
    };
    use std::{io::Read, os::unix::fs::MetadataExt};
    let descriptor = openat(
        directory,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ImageArtifactError::MetadataUnavailable)?;
    let file = std::fs::File::from(descriptor);
    let before = file
        .metadata()
        .map_err(|_| ImageArtifactError::MetadataUnavailable)?;
    if !before.is_file() {
        return Err(ImageArtifactError::MetadataUnavailable);
    }
    if before.len() > limit as u64 {
        return Err(ImageArtifactError::MetadataLimitExceeded);
    }
    if expected_size.is_some_and(|expected| expected != before.len()) {
        return Err(ImageArtifactError::SizeMismatch);
    }
    let mut bytes = Vec::new();
    (&file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ImageArtifactError::MetadataUnavailable)?;
    let after = file
        .metadata()
        .map_err(|_| ImageArtifactError::MetadataUnavailable)?;
    if bytes.len() > limit {
        return Err(ImageArtifactError::MetadataLimitExceeded);
    }
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || bytes.len() as u64 != before.len()
    {
        return Err(ImageArtifactError::MetadataChanged);
    }
    Ok(bytes)
}

#[cfg(not(unix))]
struct Layout {
    bytes_read: u64,
}

#[cfg(not(unix))]
impl Layout {
    fn open(_: &Path) -> Result<Self, ImageArtifactError> {
        Err(ImageArtifactError::UnsupportedLayout)
    }

    fn marker(&mut self) -> Result<Value, ImageArtifactError> {
        Err(ImageArtifactError::UnsupportedLayout)
    }

    fn blob(&mut self, _: &str, _: Option<u64>) -> Result<Vec<u8>, ImageArtifactError> {
        Err(ImageArtifactError::UnsupportedLayout)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use anyhow::Context;

    const ROOT: &str = "sha256:bbcc60ed9423dd84b19a56d09759aec31ee3db1b729455f9414646808b624379";
    const MANIFEST: &str =
        "sha256:0a14e0296c0ab0d00e9b8c9053f9cab062c5848a9e763ecd3bb5288dcb8fbb57";
    const CONFIG: &str = "sha256:7bfed7d6080f5d9aa427991b771a274ee4845f93232f914a49afbe3f895a141c";
    const ROOT_BYTES: &[u8] = include_bytes!(
        "../tests/fixtures/image-artifact/blobs/sha256/bbcc60ed9423dd84b19a56d09759aec31ee3db1b729455f9414646808b624379"
    );
    const MANIFEST_BYTES: &[u8] = include_bytes!(
        "../tests/fixtures/image-artifact/blobs/sha256/0a14e0296c0ab0d00e9b8c9053f9cab062c5848a9e763ecd3bb5288dcb8fbb57"
    );
    const CONFIG_BYTES: &[u8] = include_bytes!(
        "../tests/fixtures/image-artifact/blobs/sha256/7bfed7d6080f5d9aa427991b771a274ee4845f93232f914a49afbe3f895a141c"
    );
    const MARKER_BYTES: &[u8] = include_bytes!("../tests/fixtures/image-artifact/oci-layout");

    fn from_index(initial_metadata_bytes: u64) -> Result<MetadataPlan, ImageArtifactError> {
        MetadataPlan::from_root(ROOT_BYTES, ROOT, "linux/amd64", initial_metadata_bytes)
    }

    #[test]
    fn storage_adapters_share_selection_receipts_and_root_identity() -> anyhow::Result<()> {
        let layout = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/image-artifact");
        let offline = verify_oci_metadata(&layout, ROOT, "linux/amd64")?;
        let plan = from_index(MARKER_BYTES.len() as u64)?;
        let request = plan
            .manifest_request()
            .ok_or_else(|| anyhow::anyhow!("index must select one manifest"))?;
        assert_eq!(request.digest, MANIFEST);
        assert_eq!(request.size, Some(554));
        let plan = plan.with_manifest(Some(MANIFEST_BYTES))?;
        let request = plan.config_request();
        assert_eq!(request.digest, CONFIG);
        assert_eq!(request.size, Some(362));
        let shared = plan.finish(CONFIG_BYTES)?;
        assert_eq!(
            serde_json::to_value(&shared)?,
            serde_json::to_value(offline)?
        );
        assert!(shared.root_matches(OCI_INDEX, ROOT, 507));
        for (media, digest, size) in [
            (OCI_MANIFEST, ROOT, 507),
            (OCI_INDEX, MANIFEST, 507),
            (OCI_INDEX, ROOT, -1),
            (OCI_INDEX, ROOT, 506),
            (OCI_INDEX, ROOT, 508),
        ] {
            assert!(!shared.root_matches(media, digest, size));
        }

        let native = from_index(0)?
            .with_manifest(Some(MANIFEST_BYTES))?
            .finish(CONFIG_BYTES)?;
        assert_eq!(native.metadata_bytes_read, "1423");
        assert!(!native.approval_checked);
        assert!(!native.layer_payloads_verified);
        assert!(!native.preparation_allowed);
        Ok(())
    }

    #[test]
    fn direct_manifest_requests_only_configuration_and_never_a_layer() -> anyhow::Result<()> {
        let plan = MetadataPlan::from_root(MANIFEST_BYTES, MANIFEST, "linux/amd64", 0)?;
        assert!(plan.manifest_request().is_none());
        let plan = plan.with_manifest(None)?;
        assert_eq!(plan.config_request().digest, CONFIG);
        let receipt = plan.finish(CONFIG_BYTES)?;
        assert!(receipt.root_matches(OCI_MANIFEST, MANIFEST, 554));
        assert!(receipt.index.is_none());
        assert_eq!(receipt.metadata_bytes_read, "916");
        assert_eq!(receipt.layers.len(), 2);
        assert_eq!(receipt.unique_declared_layer_bytes, "31");
        Ok(())
    }

    fn verified_diff_ids(diff_ids: &[String]) -> Result<VerifiedImageMetadata, ImageArtifactError> {
        let config = serde_json::json!({
            "os":"linux", "architecture":"amd64",
            "rootfs":{"type":"layers", "diff_ids":diff_ids},
        })
        .to_string()
        .into_bytes();
        let config_digest = format!("sha256:{}", hex::encode(Sha256::digest(&config)));
        let layers: Vec<_> = diff_ids
            .iter()
            .map(|diff_id| {
                serde_json::json!({"mediaType":"application/vnd.oci.image.layer.v1.tar",
                    "digest":diff_id, "size":17})
            })
            .collect();
        let manifest = serde_json::json!({
            "schemaVersion":2, "mediaType":OCI_MANIFEST,
            "config":{"mediaType":OCI_CONFIG,"digest":config_digest,"size":config.len()},
            "layers":layers,
        })
        .to_string()
        .into_bytes();
        let manifest_digest = format!("sha256:{}", hex::encode(Sha256::digest(&manifest)));
        MetadataPlan::from_root(&manifest, &manifest_digest, "linux/amd64", 0)?
            .with_manifest(None)?
            .finish(&config)
    }

    #[test]
    fn authenticated_diff_ids_derive_ordered_chain_and_immediate_parent() -> anyhow::Result<()> {
        let diffs: Vec<_> = ['a', 'b', 'c']
            .iter()
            .map(|value| format!("sha256:{}", value.to_string().repeat(64)))
            .collect();
        let first = verified_diff_ids(&diffs[..1])?
            .rootfs_chain()
            .context("one authenticated layer has a ChainID")?;
        assert_eq!(first.chain_id, diffs[0]);
        assert_eq!(first.parent_chain_id, None);
        // Independently calculated OCI identity vectors, not another call to
        // the implementation under test or compressed layer descriptor hashes.
        let two = verified_diff_ids(&diffs[..2])?
            .rootfs_chain()
            .context("two authenticated layers have a ChainID")?;
        assert_eq!(
            two.chain_id,
            "sha256:ccd722928bd92476ba1745586fed6e45a102504185ad88cd89e01ff116fd146c"
        );
        assert_eq!(two.parent_chain_id.as_deref(), Some(diffs[0].as_str()));
        let three = verified_diff_ids(&diffs)?
            .rootfs_chain()
            .context("three authenticated layers have a ChainID")?;
        assert_eq!(
            three.chain_id,
            "sha256:c1377126441fb2f5ec2c21ae2a60255331d639e830f0ee1b40a36e52d4c40588"
        );
        assert_eq!(three.parent_chain_id, Some(two.chain_id.clone()));
        assert_ne!(
            verified_diff_ids(&[diffs[1].clone(), diffs[0].clone()])?
                .rootfs_chain()
                .context("reversed authenticated layers have a ChainID")?
                .chain_id,
            two.chain_id
        );
        Ok(())
    }

    #[test]
    fn empty_authenticated_rootfs_has_no_snapshot_key() -> anyhow::Result<()> {
        let metadata = verified_diff_ids(&[])?;
        assert_eq!(metadata.rootfs_chain(), None);
        assert!(metadata.config_matches(
            metadata.config_digest(),
            metadata.config.size_bytes.parse()?
        ));
        assert!(!metadata.config_matches(metadata.config_digest(), -1));
        assert!(!metadata.config_matches(ROOT, metadata.config.size_bytes.parse()?));
        Ok(())
    }

    #[test]
    fn snapshot_chain_derivation_obeys_the_existing_authenticated_layer_limit() -> anyhow::Result<()>
    {
        let diff_ids = vec![format!("sha256:{}", "a".repeat(64)); MAX_LAYERS];
        let chain = verified_diff_ids(&diff_ids)?
            .rootfs_chain()
            .context("the maximum authenticated layer count has a ChainID")?;
        assert_eq!(
            chain.chain_id,
            "sha256:7b1ada5e5929b10511be68a8b487a327f9f343b3b6ff3f2a61ffd7e24084595d"
        );
        assert!(chain.parent_chain_id.is_some());
        let mut excessive = diff_ids;
        excessive.push(format!("sha256:{}", "a".repeat(64)));
        assert!(matches!(
            verified_diff_ids(&excessive),
            Err(ImageArtifactError::MetadataLimitExceeded)
        ));
        Ok(())
    }

    #[test]
    fn every_stage_authenticates_its_requested_bytes_before_parsing() -> anyhow::Result<()> {
        let mut root = ROOT_BYTES.to_vec();
        root[0] = b' ';
        assert!(matches!(
            MetadataPlan::from_root(&root, ROOT, "linux/amd64", 0),
            Err(ImageArtifactError::DigestMismatch)
        ));
        let mut manifest = MANIFEST_BYTES.to_vec();
        manifest[0] = b' ';
        assert!(matches!(
            from_index(0)?.with_manifest(Some(&manifest)),
            Err(ImageArtifactError::DigestMismatch)
        ));
        assert!(matches!(
            from_index(0)?.with_manifest(Some(&MANIFEST_BYTES[..553])),
            Err(ImageArtifactError::SizeMismatch)
        ));
        let mut config = CONFIG_BYTES.to_vec();
        config[0] = b' ';
        assert!(matches!(
            from_index(0)?
                .with_manifest(Some(MANIFEST_BYTES))?
                .finish(&config),
            Err(ImageArtifactError::DigestMismatch)
        ));
        assert!(matches!(
            from_index(0)?
                .with_manifest(Some(MANIFEST_BYTES))?
                .finish(&CONFIG_BYTES[..361]),
            Err(ImageArtifactError::SizeMismatch)
        ));
        assert!(matches!(
            from_index(0)?.with_manifest(None),
            Err(ImageArtifactError::InvalidMetadata)
        ));
        assert!(matches!(
            MetadataPlan::from_root(MANIFEST_BYTES, MANIFEST, "linux/amd64", 0)?
                .with_manifest(Some(MANIFEST_BYTES)),
            Err(ImageArtifactError::InvalidMetadata)
        ));
        Ok(())
    }

    #[test]
    fn closure_budget_is_carried_across_all_stages_including_adapter_bytes() -> anyhow::Result<()> {
        let closure_bytes = (ROOT_BYTES.len() + MANIFEST_BYTES.len() + CONFIG_BYTES.len()) as u64;
        let initial = MAX_METADATA_BYTES - closure_bytes;
        let receipt = from_index(initial)?
            .with_manifest(Some(MANIFEST_BYTES))?
            .finish(CONFIG_BYTES)?;
        assert_eq!(receipt.metadata_bytes_read, MAX_METADATA_BYTES.to_string());
        assert!(matches!(
            from_index(initial + 1)?
                .with_manifest(Some(MANIFEST_BYTES))?
                .finish(CONFIG_BYTES),
            Err(ImageArtifactError::MetadataLimitExceeded)
        ));
        assert!(matches!(
            from_index(u64::MAX),
            Err(ImageArtifactError::MetadataLimitExceeded)
        ));
        assert!(matches!(
            MetadataPlan::from_root(&vec![b' '; MAX_BLOB_BYTES + 1], ROOT, "linux/amd64", 0),
            Err(ImageArtifactError::MetadataLimitExceeded)
        ));
        assert!(matches!(
            from_index(0)?.with_manifest(Some(&vec![b' '; MAX_BLOB_BYTES + 1])),
            Err(ImageArtifactError::MetadataLimitExceeded)
        ));
        assert!(matches!(
            from_index(0)?
                .with_manifest(Some(MANIFEST_BYTES))?
                .finish(&vec![b' '; MAX_BLOB_BYTES + 1]),
            Err(ImageArtifactError::MetadataLimitExceeded)
        ));
        Ok(())
    }
}
