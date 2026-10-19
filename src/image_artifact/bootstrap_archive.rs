//! Canonical OCI archive output for an externally restricted bootstrap executor.
//!
//! The exporter does not contact a runtime, interpret layer tar entries, grant
//! approval, or establish kernel memory/FD/filesystem limits. Its output may be
//! partial on error; consumers must require successful completion before import.
use super::*;
use std::{
    io::Write,
    time::{Duration, Instant},
};

const BLOCK: u64 = 512;
const BUFFER_BYTES: usize = 16 * 1024;
const MAX_TAR_ENTRY_BYTES: u64 = (1_u64 << 33) - 1;
const MAX_DEADLINE: Duration = Duration::from_secs(300);
const MARKER: &[u8] = br#"{"imageLayoutVersion":"1.0.0"}"#;

/// Logical work/output bounds, independent of the executor's operating-system
/// resource limits. The cooperative deadline must be positive and at most 300s.
#[derive(Clone, Copy, Debug)]
pub struct BootstrapArchiveLimits {
    payloads: PayloadLimits,
    max_archive_bytes: u64,
    deadline: Duration,
}

impl BootstrapArchiveLimits {
    pub fn new(
        payloads: PayloadLimits,
        max_archive_bytes: u64,
        deadline: Duration,
    ) -> Result<Self, ImageArtifactError> {
        if max_archive_bytes == 0 || deadline.is_zero() || deadline > MAX_DEADLINE {
            return Err(ImageArtifactError::InvalidBootstrapArchiveLimits);
        }
        Ok(Self {
            payloads,
            max_archive_bytes,
            deadline,
        })
    }
}

/// Successful stream completion. This is not approval or store preparation.
#[derive(Debug, Serialize)]
pub struct ExportedBootstrapArchive {
    #[serde(flatten)]
    metadata: VerifiedImageMetadata,
    reference: String,
    diff_ids_verified: bool,
    layer_archive_semantics_checked: bool,
    unpack_performed: bool,
    physical_storage_bound_verified: bool,
    archive_bytes_written: String,
    archive_digest: String,
    archive_entries: usize,
}

/// Verify payloads and write one canonical single-manifest OCI USTAR stream.
///
/// Only direct OCI manifest roots are supported. Expected root indexes retain
/// their existing metadata/payload verification support but cannot be exported
/// by this narrower bootstrap interface. The wrapper contains exactly one
/// caller-validated repository@root-digest name; source annotations never name
/// imported images. Output contains only generated layout/index entries and the
/// authenticated manifest, config and unique selected layer blobs.
///
/// Source entries are read sequentially from the original pinned directory FDs,
/// with fixed 16KiB buffers and descriptor identity/size/SHA/EOF checks. No input
/// directory is enumerated. Deadline checks cannot preempt blocked I/O; the
/// external executor must independently enforce its wall-clock and OS limits.
pub fn export_bootstrap_archive<W: Write + ?Sized>(
    layout: &Path,
    expected_digest: &str,
    platform: &str,
    reference: &str,
    limits: BootstrapArchiveLimits,
    output: &mut W,
) -> Result<ExportedBootstrapArchive, ImageArtifactError> {
    let deadline = Instant::now()
        .checked_add(limits.deadline)
        .ok_or(ImageArtifactError::InvalidBootstrapArchiveLimits)?;
    validate_request(expected_digest, platform)?;
    validate_reference(reference, expected_digest)?;
    #[cfg(unix)]
    {
        let mut layout = Layout::open(layout)?;
        check_deadline(deadline)?;
        let metadata = verify_metadata_in(&mut layout, expected_digest, platform)?;
        check_deadline(deadline)?;
        if metadata.index.is_some() || metadata.root.media_type != OCI_MANIFEST {
            return Err(ImageArtifactError::UnsupportedBootstrapRoot);
        }
        let index = wrapper(&metadata, reference)?;
        let entries = blob_entries(&metadata);
        let archive_bytes = archive_size(&index, &entries)?;
        if archive_bytes > limits.max_archive_bytes {
            return Err(ImageArtifactError::BootstrapArchiveLimitExceeded);
        }
        let mut metadata = payloads::verify_in(&layout, metadata, limits.payloads, deadline)
            .map_err(|error| match error {
                ImageArtifactError::PayloadDeadlineExceeded => {
                    ImageArtifactError::BootstrapArchiveDeadlineExceeded
                }
                other => other,
            })?
            .into_metadata();
        check_deadline(deadline)?;
        let mut archive = ArchiveWriter {
            output,
            bytes: 0,
            digest: Sha256::new(),
            limit: limits.max_archive_bytes,
            deadline,
        };
        archive.inline("oci-layout", MARKER)?;
        archive.inline("index.json", &index)?;
        for entry in &entries {
            unix::stream_blob(&layout.blobs, entry, &mut archive)?;
        }
        archive.write(&[0_u8; 1024])?;
        check_deadline(deadline)?;
        archive
            .output
            .flush()
            .map_err(|_| ImageArtifactError::BootstrapArchiveWriteFailed)?;
        check_deadline(deadline)?;
        if archive.bytes != archive_bytes {
            return Err(ImageArtifactError::BootstrapArchiveWriteFailed);
        }
        metadata.scope = "OCI_BOOTSTRAP_ARCHIVE";
        Ok(ExportedBootstrapArchive {
            metadata,
            reference: reference.to_owned(),
            diff_ids_verified: true,
            layer_archive_semantics_checked: false,
            unpack_performed: false,
            physical_storage_bound_verified: false,
            archive_bytes_written: archive.bytes.to_string(),
            archive_digest: format!("sha256:{:x}", archive.digest.finalize()),
            archive_entries: entries.len() + 2,
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (layout, limits, output, deadline);
        Err(ImageArtifactError::UnsupportedLayout)
    }
}

fn validate_reference(reference: &str, expected: &str) -> Result<(), ImageArtifactError> {
    let (repository, digest) = reference
        .split_once('@')
        .ok_or(ImageArtifactError::InvalidBootstrapReference)?;
    let (authority, path) = repository
        .split_once('/')
        .ok_or(ImageArtifactError::InvalidBootstrapReference)?;
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    // Canonical subset of the pinned CRI's distribution/reference v0.6.0.
    // Reject names CRI normalizes: team/image, index.docker.io/* and
    // docker.io/<single-name>. IPv6 authorities are outside this offline scope.
    if reference.len() > 2048
        || digest != expected
        || host.len() > 253
        || !(host == "localhost" || host.contains('.') || port.is_some())
        || authority == "index.docker.io"
        || (authority == "docker.io" && !path.contains('/'))
        || !host.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && part
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| alphanumeric(*byte))
                && part
                    .as_bytes()
                    .last()
                    .is_some_and(|byte| alphanumeric(*byte))
                && part.bytes().all(|byte| alphanumeric(byte) || byte == b'-')
        })
        || port.is_some_and(|port| {
            port.is_empty()
                || !port.bytes().all(|byte| byte.is_ascii_digit())
                || !port.parse::<u16>().is_ok_and(|port| port != 0)
        })
        || path.len() > 255
        || !path.split('/').all(path_component)
    {
        return Err(ImageArtifactError::InvalidBootstrapReference);
    }
    Ok(())
}

fn alphanumeric(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

fn path_component(component: &str) -> bool {
    let bytes = component.as_bytes();
    let mut position = 0;
    loop {
        let start = position;
        while bytes.get(position).is_some_and(|byte| alphanumeric(*byte)) {
            position += 1;
        }
        if start == position {
            return false;
        }
        match bytes.get(position) {
            None => return true,
            Some(b'.') => position += 1,
            Some(b'_') => {
                position += 1;
                if bytes.get(position) == Some(&b'_') {
                    position += 1;
                }
            }
            Some(b'-') => {
                while bytes.get(position) == Some(&b'-') {
                    position += 1;
                }
            }
            _ => return false,
        }
    }
}

fn check_deadline(deadline: Instant) -> Result<(), ImageArtifactError> {
    if Instant::now() >= deadline {
        Err(ImageArtifactError::BootstrapArchiveDeadlineExceeded)
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn wrapper(
    metadata: &VerifiedImageMetadata,
    reference: &str,
) -> Result<Vec<u8>, ImageArtifactError> {
    let mut platform = serde_json::json!({
        "os": metadata.platform.os,
        "architecture": metadata.platform.architecture,
    });
    if let Some(variant) = &metadata.platform.variant {
        platform["variant"] = Value::String(variant.clone());
    }
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_INDEX,
        "manifests": [{
            "mediaType": OCI_MANIFEST,
            "digest": metadata.root.digest,
            "size": size(&metadata.root)?,
            "platform": platform,
            "annotations": {"io.containerd.image.name": reference},
        }],
    }))
    .map_err(|_| ImageArtifactError::InvalidMetadata)
}

#[cfg(unix)]
fn blob_entries(metadata: &VerifiedImageMetadata) -> Vec<DescriptorIdentity> {
    let mut unique = BTreeMap::new();
    let mut entries = Vec::with_capacity(metadata.layers.len() + 2);
    for descriptor in std::iter::once(&metadata.root)
        .chain(std::iter::once(&metadata.config))
        .chain(metadata.layers.iter().map(|layer| &layer.descriptor))
    {
        if unique.insert(&descriptor.digest, ()).is_none() {
            entries.push(descriptor.clone());
        }
    }
    entries
}

fn size(descriptor: &DescriptorIdentity) -> Result<u64, ImageArtifactError> {
    descriptor
        .size_bytes
        .parse()
        .map_err(|_| ImageArtifactError::InvalidMetadata)
}

fn padded_size(size: u64) -> Result<u64, ImageArtifactError> {
    if size > MAX_TAR_ENTRY_BYTES {
        return Err(ImageArtifactError::BootstrapArchiveLimitExceeded);
    }
    size.div_ceil(BLOCK)
        .checked_mul(BLOCK)
        .and_then(|bytes| bytes.checked_add(BLOCK))
        .ok_or(ImageArtifactError::BootstrapArchiveLimitExceeded)
}

#[cfg(unix)]
fn archive_size(index: &[u8], entries: &[DescriptorIdentity]) -> Result<u64, ImageArtifactError> {
    let mut total = 1024_u64;
    for bytes in std::iter::once(MARKER.len() as u64)
        .chain(std::iter::once(index.len() as u64))
        .chain(entries.iter().map(size).collect::<Result<Vec<_>, _>>()?)
    {
        total = total
            .checked_add(padded_size(bytes)?)
            .ok_or(ImageArtifactError::BootstrapArchiveLimitExceeded)?;
    }
    Ok(total)
}

// Only our short fixed ASCII names are ever encoded. No path, uid, timestamp,
// mode, link type or extended header is taken from the source filesystem.
fn header(name: &str, size: u64) -> Result<[u8; 512], ImageArtifactError> {
    if name.is_empty() || name.len() > 100 || !name.is_ascii() || size > MAX_TAR_ENTRY_BYTES {
        return Err(ImageArtifactError::BootstrapArchiveLimitExceeded);
    }
    let mut header = [0_u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..108].copy_from_slice(b"0000444\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    let size = format!("{size:011o}\0");
    header[124..136].copy_from_slice(size.as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    Ok(header)
}

struct ArchiveWriter<'a, W: Write + ?Sized> {
    output: &'a mut W,
    bytes: u64,
    digest: Sha256,
    limit: u64,
    deadline: Instant,
}

impl<W: Write + ?Sized> ArchiveWriter<'_, W> {
    fn write(&mut self, mut bytes: &[u8]) -> Result<(), ImageArtifactError> {
        if self
            .bytes
            .checked_add(bytes.len() as u64)
            .is_none_or(|next| next > self.limit)
        {
            return Err(ImageArtifactError::BootstrapArchiveLimitExceeded);
        }
        while !bytes.is_empty() {
            check_deadline(self.deadline)?;
            let written = match self.output.write(bytes) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) | Ok(0) => return Err(ImageArtifactError::BootstrapArchiveWriteFailed),
                Ok(written) => written,
            };
            check_deadline(self.deadline)?;
            self.digest.update(&bytes[..written]);
            self.bytes += written as u64;
            bytes = &bytes[written..];
        }
        Ok(())
    }

    fn inline(&mut self, name: &str, bytes: &[u8]) -> Result<(), ImageArtifactError> {
        self.write(&header(name, bytes.len() as u64)?)?;
        self.write(bytes)?;
        self.padding(bytes.len() as u64)
    }

    fn padding(&mut self, bytes: u64) -> Result<(), ImageArtifactError> {
        let padding = (BLOCK - bytes % BLOCK) % BLOCK;
        self.write(&[0_u8; 512][..padding as usize])
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use nix::{
        fcntl::{OFlag, openat},
        sys::stat::Mode,
    };
    use std::{fs::File, io::Read, os::unix::fs::MetadataExt};

    #[derive(Clone, Copy, Eq, PartialEq)]
    struct Identity {
        device: u64,
        inode: u64,
        length: u64,
        mode: u32,
        links: u64,
        modified: (i64, i64),
        changed: (i64, i64),
    }

    impl Identity {
        fn read(file: &File) -> Result<Self, ImageArtifactError> {
            let metadata = file
                .metadata()
                .map_err(|_| ImageArtifactError::MetadataUnavailable)?;
            if !metadata.is_file() {
                return Err(ImageArtifactError::MetadataUnavailable);
            }
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                length: metadata.len(),
                mode: metadata.mode(),
                links: metadata.nlink(),
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
            })
        }
    }

    fn open(directory: &File, name: &str) -> Result<File, ImageArtifactError> {
        openat(
            directory,
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| ImageArtifactError::MetadataUnavailable)
    }

    pub(super) fn stream_blob<W: Write + ?Sized>(
        directory: &File,
        descriptor: &DescriptorIdentity,
        archive: &mut ArchiveWriter<'_, W>,
    ) -> Result<(), ImageArtifactError> {
        check_deadline(archive.deadline)?;
        let name = descriptor
            .digest
            .strip_prefix("sha256:")
            .ok_or(ImageArtifactError::InvalidDigest)?;
        let mut file = open(directory, name)?;
        let before = Identity::read(&file)?;
        let expected_size = size(descriptor)?;
        if before.length != expected_size {
            return Err(ImageArtifactError::SizeMismatch);
        }
        archive.write(&header(&format!("blobs/sha256/{name}"), expected_size)?)?;
        let mut buffer = [0_u8; BUFFER_BYTES];
        let mut remaining = expected_size;
        let mut digest = Sha256::new();
        while remaining > 0 {
            check_deadline(archive.deadline)?;
            let limit = remaining.min(buffer.len() as u64) as usize;
            let count = file
                .read(&mut buffer[..limit])
                .map_err(|_| ImageArtifactError::MetadataUnavailable)?;
            check_deadline(archive.deadline)?;
            if count == 0 {
                return Err(ImageArtifactError::SizeMismatch);
            }
            digest.update(&buffer[..count]);
            archive.write(&buffer[..count])?;
            remaining -= count as u64;
        }
        check_deadline(archive.deadline)?;
        if file
            .read(&mut buffer[..1])
            .map_err(|_| ImageArtifactError::MetadataUnavailable)?
            != 0
        {
            return Err(ImageArtifactError::SizeMismatch);
        }
        check_deadline(archive.deadline)?;
        let after = Identity::read(&file)?;
        let entry = open(directory, name)
            .and_then(|file| Identity::read(&file))
            .map_err(|_| ImageArtifactError::MetadataChanged)?;
        check_deadline(archive.deadline)?;
        if before != after || before != entry {
            return Err(ImageArtifactError::MetadataChanged);
        }
        if format!("sha256:{:x}", digest.finalize()) != descriptor.digest {
            return Err(ImageArtifactError::DigestMismatch);
        }
        archive.padding(expected_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_limits_and_deadlines_are_explicit_and_independent() -> anyhow::Result<()> {
        let payloads = PayloadLimits::new(1, 1, 1, 1)?;
        for (bytes, deadline) in [
            (0, Duration::from_secs(1)),
            (1, Duration::ZERO),
            (1, Duration::from_secs(301)),
        ] {
            assert!(matches!(
                BootstrapArchiveLimits::new(payloads, bytes, deadline),
                Err(ImageArtifactError::InvalidBootstrapArchiveLimits)
            ));
        }
        BootstrapArchiveLimits::new(payloads, 1, MAX_DEADLINE)?;
        assert_eq!(
            check_deadline(Instant::now() - Duration::from_secs(1)),
            Err(ImageArtifactError::BootstrapArchiveDeadlineExceeded)
        );
        assert_eq!(
            padded_size(MAX_TAR_ENTRY_BYTES + 1),
            Err(ImageArtifactError::BootstrapArchiveLimitExceeded)
        );
        Ok(())
    }

    #[test]
    fn output_errors_never_expose_the_writer_message() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("PRIVATE_OUTPUT_SENTINEL"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut broken = Broken;
        let mut archive = ArchiveWriter {
            output: &mut broken,
            bytes: 0,
            digest: Sha256::new(),
            limit: 512,
            deadline: Instant::now() + Duration::from_secs(1),
        };
        assert_eq!(
            archive.write(b"x"),
            Err(ImageArtifactError::BootstrapArchiveWriteFailed)
        );
    }

    #[cfg(unix)]
    #[test]
    fn replacement_of_an_open_blob_is_rejected_even_with_identical_bytes() -> anyhow::Result<()> {
        struct ReplacingWriter {
            victim: std::path::PathBuf,
            replacement: std::path::PathBuf,
            replaced: bool,
        }
        impl Write for ReplacingWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                // stream_blob has opened the source before writing its header.
                // This synchronous hook tests replacement without a race/timer.
                if !self.replaced {
                    std::fs::rename(&self.replacement, &self.victim)?;
                    self.replaced = true;
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let directory = tempfile::tempdir()?;
        let bytes = b"identical verified bytes";
        let digest = format!("sha256:{:x}", Sha256::digest(bytes));
        let victim = directory.path().join(&digest[7..]);
        let replacement = directory.path().join("replacement");
        std::fs::write(&victim, bytes)?;
        std::fs::write(&replacement, bytes)?;
        let mut output = ReplacingWriter {
            victim,
            replacement,
            replaced: false,
        };
        let mut archive = ArchiveWriter {
            output: &mut output,
            bytes: 0,
            digest: Sha256::new(),
            limit: 4096,
            deadline: Instant::now() + Duration::from_secs(5),
        };
        assert_eq!(
            unix::stream_blob(
                &std::fs::File::open(directory.path())?,
                &DescriptorIdentity {
                    media_type: "unused".to_owned(),
                    digest,
                    size_bytes: bytes.len().to_string(),
                },
                &mut archive,
            ),
            Err(ImageArtifactError::MetadataChanged)
        );
        assert!(output.replaced);
        Ok(())
    }
}
