//! Bounded, offline verification of an expected OCI image's metadata closure.
//!
//! The caller supplies the expected digest. This module neither establishes
//! approval nor reads layer payloads, unpacks content, or prepares a runtime.
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
    validate_digest(expected_digest)?;
    let platform = Platform::parse(platform)?;
    let mut layout = Layout::open(layout)?;
    let layout_marker = layout.marker()?;
    if string(object(&layout_marker)?, "imageLayoutVersion")? != "1.0.0" {
        return Err(ImageArtifactError::UnsupportedLayout);
    }
    let root_bytes = layout.blob(expected_digest, None)?;
    let root_value = parse_json(&root_bytes)?;
    let root_object = object(&root_value)?;
    validate_document(root_object)?;
    let root = Descriptor::root(
        string(root_object, "mediaType")?,
        expected_digest,
        root_bytes.len(),
    );
    let mut identities = DescriptorRegistry::default();
    identities.register(&root)?;
    let (index, manifest, manifest_value) = match root.identity.media_type.as_str() {
        OCI_MANIFEST => (None, root.clone(), root_value),
        OCI_INDEX => {
            let selected = select_manifest(root_object, &platform, &mut identities)?;
            let bytes = layout.blob(&selected.identity.digest, Some(selected.size))?;
            let value = parse_json(&bytes)?;
            if string(object(&value)?, "mediaType")? != OCI_MANIFEST {
                return Err(ImageArtifactError::UnsupportedMediaType);
            }
            (Some(root.identity.clone()), selected, value)
        }
        _ => return Err(ImageArtifactError::UnsupportedMediaType),
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
    identities.register(&config)?;
    let layers = manifest_object
        .get("layers")
        .and_then(Value::as_array)
        .ok_or(ImageArtifactError::InvalidMetadata)?;
    if layers.len() > MAX_LAYERS {
        return Err(ImageArtifactError::MetadataLimitExceeded);
    }
    let config_bytes = layout.blob(&config.identity.digest, Some(config.size))?;
    let config_json = parse_json(&config_bytes)?;
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
        metadata_bytes_read: layout.bytes_read.to_string(),
    })
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
        let bytes = read_metadata(&self.blobs, name, MAX_BLOB_BYTES, size)?;
        self.account(bytes.len())?;
        if hex::encode(Sha256::digest(&bytes)) != name {
            return Err(ImageArtifactError::DigestMismatch);
        }
        Ok(bytes)
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
