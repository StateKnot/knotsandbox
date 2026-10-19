//! Read-only payload stream integrity checks with caller-supplied byte budgets.
//!
//! These bounds limit this utility's streaming work. They are not a kernel
//! memory reservation, a filesystem quota, or a restricted preparation executor.
use super::*;
use std::time::{Duration, Instant};

const BUFFER_BYTES: usize = 16 * 1024;
const MAX_GZIP_MEMBERS: u32 = 1024;
const PAYLOAD_BUDGET: Duration = Duration::from_secs(5);

/// Positive per-layer and total logical byte ceilings, including repeated layers.
#[derive(Clone, Copy, Debug)]
pub struct PayloadLimits {
    max_layer_bytes: u64,
    max_total_layer_bytes: u64,
    max_decoded_layer_bytes: u64,
    max_total_decoded_bytes: u64,
}

impl PayloadLimits {
    pub fn new(
        max_layer_bytes: u64,
        max_total_layer_bytes: u64,
        max_decoded_layer_bytes: u64,
        max_total_decoded_bytes: u64,
    ) -> Result<Self, ImageArtifactError> {
        if max_layer_bytes == 0
            || max_total_layer_bytes == 0
            || max_decoded_layer_bytes == 0
            || max_total_decoded_bytes == 0
            || max_layer_bytes > max_total_layer_bytes
            || max_decoded_layer_bytes > max_total_decoded_bytes
        {
            return Err(ImageArtifactError::InvalidPayloadLimits);
        }
        Ok(Self {
            max_layer_bytes,
            max_total_layer_bytes,
            max_decoded_layer_bytes,
            max_total_decoded_bytes,
        })
    }
}

/// Observed byte-stream integrity, without interpreting or applying tar entries.
#[derive(Debug, Serialize)]
pub struct VerifiedImagePayloads {
    #[serde(flatten)]
    metadata: VerifiedImageMetadata,
    diff_ids_verified: bool,
    archive_semantics_checked: bool,
    unpack_performed: bool,
    physical_storage_bound_verified: bool,
    encoded_bytes_read: String,
    decoded_bytes_read: String,
    logical_decoded_bytes: String,
    decoded_layer_bytes: Vec<String>,
    unique_layers_verified: usize,
    gzip_members_verified: u32,
}

/// Verify every selected layer's encoded SHA-256 and decoded stream DiffID.
///
/// Only plain tar and gzip streams are supported; zstd is rejected. No tar
/// entries are interpreted, no files are written, and no runtime is contacted.
/// At most 1024 gzip members are decoded across unique layer blobs. A real
/// extra-byte probe checks exact byte ceilings and requires decoder EOF.
/// A five-second cooperative budget is checked around I/O and decoding work;
/// it cannot preempt a blocked filesystem operation. The original layout FDs
/// are retained, layers are opened sequentially, and repeated blobs are reused
/// only while their file identity still matches the verified observation.
pub fn verify_oci_payloads(
    layout: &Path,
    expected_digest: &str,
    platform: &str,
    limits: PayloadLimits,
) -> Result<VerifiedImagePayloads, ImageArtifactError> {
    let deadline = Instant::now() + PAYLOAD_BUDGET;
    validate_request(expected_digest, platform)?;
    #[cfg(unix)]
    {
        let mut layout = Layout::open(layout)?;
        check_deadline(deadline)?;
        let metadata = verify_metadata_in(&mut layout, expected_digest, platform)?;
        check_deadline(deadline)?;
        unix::verify(&layout, metadata, limits, deadline)
    }
    #[cfg(not(unix))]
    {
        let _ = (layout, limits, deadline);
        Err(ImageArtifactError::UnsupportedLayout)
    }
}

fn check_deadline(deadline: Instant) -> Result<(), ImageArtifactError> {
    if Instant::now() >= deadline {
        Err(ImageArtifactError::PayloadDeadlineExceeded)
    } else {
        Ok(())
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use flate2::bufread::GzDecoder;
    use nix::{
        fcntl::{OFlag, openat},
        sys::stat::Mode,
    };
    use std::{
        fs::File,
        io::{self, BufRead, BufReader, Read},
        os::unix::fs::MetadataExt,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FileIdentity {
        device: u64,
        inode: u64,
        length: u64,
        mode: u32,
        links: u64,
        modified: (i64, i64),
        changed: (i64, i64),
    }

    impl FileIdentity {
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

    fn open_layer(directory: &File, name: &str) -> Result<File, ImageArtifactError> {
        openat(
            directory,
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| ImageArtifactError::MetadataUnavailable)
    }

    fn unchanged(
        directory: &File,
        name: &str,
        file: &File,
        before: FileIdentity,
        deadline: Instant,
    ) -> Result<(), ImageArtifactError> {
        check_deadline(deadline)?;
        let current = FileIdentity::read(file)?;
        // Reopening relative to the same original directory FD detects an
        // atomic pathname replacement even when the original FD stayed valid.
        let entry = open_layer(directory, name)
            .and_then(|file| FileIdentity::read(&file))
            .map_err(|_| ImageArtifactError::MetadataChanged)?;
        check_deadline(deadline)?;
        if current != before || entry != before {
            return Err(ImageArtifactError::MetadataChanged);
        }
        Ok(())
    }

    struct CachedLayer {
        identity: FileIdentity,
        diff_id: String,
        decoded_bytes: u64,
    }

    pub(super) fn verify(
        layout: &Layout,
        mut metadata: VerifiedImageMetadata,
        limits: PayloadLimits,
        deadline: Instant,
    ) -> Result<VerifiedImagePayloads, ImageArtifactError> {
        let mut logical_encoded = 0_u64;
        // Reject unsupported codecs and encoded budget overruns before opening
        // any layer. The metadata command's wider media support is unchanged.
        for layer in &metadata.layers {
            check_deadline(deadline)?;
            if !matches!(
                layer.descriptor.media_type.as_str(),
                "application/vnd.oci.image.layer.v1.tar"
                    | "application/vnd.oci.image.layer.v1.tar+gzip"
            ) {
                return Err(ImageArtifactError::UnsupportedPayloadMediaType);
            }
            let size = layer
                .descriptor
                .size_bytes
                .parse::<u64>()
                .map_err(|_| ImageArtifactError::InvalidMetadata)?;
            logical_encoded = logical_encoded
                .checked_add(size)
                .ok_or(ImageArtifactError::PayloadLimitExceeded)?;
            if size > limits.max_layer_bytes || logical_encoded > limits.max_total_layer_bytes {
                return Err(ImageArtifactError::PayloadLimitExceeded);
            }
        }

        let mut cached: BTreeMap<String, CachedLayer> = BTreeMap::new();
        let mut encoded_bytes_read = 0_u64;
        let mut decoded_bytes_read = 0_u64;
        let mut logical_decoded_bytes = 0_u64;
        let mut decoded_layer_bytes = Vec::with_capacity(metadata.layers.len());
        let mut gzip_members_verified = 0_u32;
        for layer in &metadata.layers {
            check_deadline(deadline)?;
            let name = layer
                .descriptor
                .digest
                .strip_prefix("sha256:")
                .ok_or(ImageArtifactError::InvalidDigest)?;
            let file = open_layer(&layout.blobs, name)?;
            let before = FileIdentity::read(&file)?;
            let expected_size = layer
                .descriptor
                .size_bytes
                .parse::<u64>()
                .map_err(|_| ImageArtifactError::InvalidMetadata)?;
            if before.length != expected_size {
                return Err(ImageArtifactError::SizeMismatch);
            }
            check_deadline(deadline)?;
            let decoded = if let Some(previous) = cached.get(&layer.descriptor.digest) {
                if previous.identity != before {
                    return Err(ImageArtifactError::MetadataChanged);
                }
                if previous.diff_id != layer.diff_id {
                    return Err(ImageArtifactError::DiffIdMismatch);
                }
                unchanged(&layout.blobs, name, &file, before, deadline)?;
                previous.decoded_bytes
            } else {
                let remaining = limits
                    .max_total_decoded_bytes
                    .checked_sub(logical_decoded_bytes)
                    .ok_or(ImageArtifactError::PayloadLimitExceeded)?;
                let (file, encoded, decoded) = verify_layer(
                    file,
                    layer,
                    limits.max_decoded_layer_bytes.min(remaining),
                    deadline,
                    &mut gzip_members_verified,
                )?;
                unchanged(&layout.blobs, name, &file, before, deadline)?;
                encoded_bytes_read = encoded_bytes_read
                    .checked_add(encoded)
                    .ok_or(ImageArtifactError::IntegerOverflow)?;
                decoded_bytes_read = decoded_bytes_read
                    .checked_add(decoded)
                    .ok_or(ImageArtifactError::IntegerOverflow)?;
                cached.insert(
                    layer.descriptor.digest.clone(),
                    CachedLayer {
                        identity: before,
                        diff_id: layer.diff_id.clone(),
                        decoded_bytes: decoded,
                    },
                );
                decoded
            };
            logical_decoded_bytes = logical_decoded_bytes
                .checked_add(decoded)
                .ok_or(ImageArtifactError::PayloadLimitExceeded)?;
            if decoded > limits.max_decoded_layer_bytes
                || logical_decoded_bytes > limits.max_total_decoded_bytes
            {
                return Err(ImageArtifactError::PayloadLimitExceeded);
            }
            decoded_layer_bytes.push(decoded.to_string());
        }
        check_deadline(deadline)?;
        metadata.scope = "OCI_PAYLOAD_STREAMS";
        metadata.layer_payloads_verified = true;
        Ok(VerifiedImagePayloads {
            metadata,
            diff_ids_verified: true,
            archive_semantics_checked: false,
            unpack_performed: false,
            physical_storage_bound_verified: false,
            encoded_bytes_read: encoded_bytes_read.to_string(),
            decoded_bytes_read: decoded_bytes_read.to_string(),
            logical_decoded_bytes: logical_decoded_bytes.to_string(),
            decoded_layer_bytes,
            unique_layers_verified: cached.len(),
            gzip_members_verified,
        })
    }

    // Carry only our closed error enum through decoder I/O. Filesystem and
    // decoder messages, which may contain untrusted data, never reach callers.
    #[derive(Debug, thiserror::Error)]
    #[error("{0}")]
    struct StreamFailure(ImageArtifactError);

    fn stream_error(error: ImageArtifactError) -> io::Error {
        io::Error::other(StreamFailure(error))
    }

    fn classify(error: io::Error, fallback: ImageArtifactError) -> ImageArtifactError {
        error
            .get_ref()
            .and_then(|error| error.downcast_ref::<StreamFailure>())
            .map_or(fallback, |error| error.0)
    }

    struct EncodedReader {
        file: File,
        expected_size: u64,
        bytes: u64,
        digest: Sha256,
        reached_eof: bool,
        deadline: Instant,
    }

    impl Read for EncodedReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            check_deadline(self.deadline).map_err(stream_error)?;
            if output.is_empty() {
                return Ok(0);
            }
            let remaining = self.expected_size - self.bytes;
            let length = remaining.min(output.len() as u64) as usize;
            // Probe beyond the declared end, rather than fabricating EOF when
            // a byte counter reaches the descriptor size.
            let read = self
                .file
                .read(&mut output[..length.max(1)])
                .map_err(|_| stream_error(ImageArtifactError::MetadataUnavailable))?;
            check_deadline(self.deadline).map_err(stream_error)?;
            if remaining == 0 && read != 0 {
                return Err(stream_error(ImageArtifactError::SizeMismatch));
            }
            if read == 0 {
                self.reached_eof = true;
                if self.bytes != self.expected_size {
                    return Err(stream_error(ImageArtifactError::SizeMismatch));
                }
            }
            self.digest.update(&output[..read]);
            self.bytes += read as u64;
            Ok(read)
        }
    }

    impl EncodedReader {
        fn finish(self, expected_digest: &str) -> Result<(File, u64), ImageArtifactError> {
            check_deadline(self.deadline)?;
            if !self.reached_eof || self.bytes != self.expected_size {
                return Err(ImageArtifactError::SizeMismatch);
            }
            if format!("sha256:{}", hex::encode(self.digest.finalize())) != expected_digest {
                return Err(ImageArtifactError::DigestMismatch);
            }
            Ok((self.file, self.bytes))
        }
    }

    struct DecodedStream {
        digest: Sha256,
        bytes: u64,
        limit: u64,
        deadline: Instant,
    }

    impl DecodedStream {
        fn consume(&mut self, reader: &mut impl Read) -> Result<(), ImageArtifactError> {
            let mut output = [0_u8; BUFFER_BYTES];
            loop {
                check_deadline(self.deadline)?;
                // A real extra-byte probe is required at the exact ceiling;
                // both decoder trailers and the next gzip member still matter.
                let remaining = self.limit - self.bytes;
                let length = remaining.min((BUFFER_BYTES - 1) as u64) as usize + 1;
                let read = reader
                    .read(&mut output[..length])
                    .map_err(|error| classify(error, ImageArtifactError::InvalidLayerEncoding))?;
                check_deadline(self.deadline)?;
                if read == 0 {
                    return Ok(());
                }
                if read as u64 > remaining {
                    return Err(ImageArtifactError::PayloadLimitExceeded);
                }
                self.digest.update(&output[..read]);
                self.bytes += read as u64;
            }
        }
    }

    fn verify_layer(
        file: File,
        layer: &LayerIdentity,
        decoded_limit: u64,
        deadline: Instant,
        members: &mut u32,
    ) -> Result<(File, u64, u64), ImageArtifactError> {
        let encoded = EncodedReader {
            file,
            expected_size: layer
                .descriptor
                .size_bytes
                .parse()
                .map_err(|_| ImageArtifactError::InvalidMetadata)?,
            bytes: 0,
            digest: Sha256::new(),
            reached_eof: false,
            deadline,
        };
        let mut reader = BufReader::with_capacity(BUFFER_BYTES, encoded);
        let mut decoded = DecodedStream {
            digest: Sha256::new(),
            bytes: 0,
            limit: decoded_limit,
            deadline,
        };
        if layer.descriptor.media_type == "application/vnd.oci.image.layer.v1.tar" {
            decoded.consume(&mut reader)?;
        } else {
            let mut blob_members = 0_u32;
            loop {
                check_deadline(deadline)?;
                let empty = reader
                    .fill_buf()
                    .map_err(|error| classify(error, ImageArtifactError::InvalidLayerEncoding))?
                    .is_empty();
                check_deadline(deadline)?;
                if empty {
                    if blob_members == 0 {
                        return Err(ImageArtifactError::InvalidLayerEncoding);
                    }
                    break;
                }
                if *members >= MAX_GZIP_MEMBERS {
                    return Err(ImageArtifactError::PayloadLimitExceeded);
                }
                *members += 1;
                blob_members += 1;
                // A single-member decoder returns control even for an empty
                // member; our global member and time ceilings bound such work.
                let mut decoder = GzDecoder::new(&mut reader);
                check_deadline(deadline)?;
                decoded.consume(&mut decoder)?;
            }
        }
        let (file, encoded_bytes) = reader.into_inner().finish(&layer.descriptor.digest)?;
        if format!("sha256:{}", hex::encode(decoded.digest.finalize())) != layer.diff_id {
            return Err(ImageArtifactError::DiffIdMismatch);
        }
        check_deadline(deadline)?;
        Ok((file, encoded_bytes, decoded.bytes))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{fs, io::Write};

        #[test]
        fn encoded_stream_requires_real_eof_after_the_declared_size() -> anyhow::Result<()> {
            let mut file = tempfile::tempfile()?;
            file.write_all(b"extra")?;
            use std::io::{Seek, SeekFrom};
            file.seek(SeekFrom::Start(0))?;
            let mut reader = EncodedReader {
                file,
                expected_size: 4,
                bytes: 0,
                digest: Sha256::new(),
                reached_eof: false,
                deadline: Instant::now() + PAYLOAD_BUDGET,
            };
            let mut buffer = [0_u8; BUFFER_BYTES];
            assert_eq!(reader.read(&mut buffer)?, 4);
            let error = reader
                .read(&mut buffer)
                .err()
                .ok_or_else(|| anyhow::anyhow!("growth was accepted as EOF"))?;
            assert_eq!(
                classify(error, ImageArtifactError::InvalidLayerEncoding),
                ImageArtifactError::SizeMismatch
            );
            Ok(())
        }

        #[test]
        fn retained_file_does_not_hide_an_atomic_directory_entry_replacement() -> anyhow::Result<()>
        {
            let directory = tempfile::tempdir()?;
            let directory_fd = File::open(directory.path())?;
            fs::write(directory.path().join("layer"), b"first")?;
            let original = open_layer(&directory_fd, "layer")?;
            let before = FileIdentity::read(&original)?;
            fs::write(directory.path().join("replacement"), b"first")?;
            fs::rename(
                directory.path().join("replacement"),
                directory.path().join("layer"),
            )?;
            assert_eq!(
                unchanged(
                    &directory_fd,
                    "layer",
                    &original,
                    before,
                    Instant::now() + PAYLOAD_BUDGET,
                ),
                Err(ImageArtifactError::MetadataChanged)
            );
            Ok(())
        }
    }
}
