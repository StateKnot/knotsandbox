//! Host-only CRI-reported inventory and snapshot usage. These reports cannot
//! establish complete image-cache bytes, capacity, reclaimability or a hit.
//! A configured snapshotter is certified intent, not ImageFsInfo attribution:
//! the CRI response has no per-entry snapshotter identity.
use super::{GuardError, protocol::NodeBinding};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;

pub const RPC_TIMEOUT: Duration = Duration::from_secs(2);
pub const COLLECTION_INTERVAL: Duration = Duration::from_secs(15);
pub const STALE_AFTER: Duration = Duration::from_secs(60);
pub const MAX_INVENTORY_BYTES: usize = 1024 * 1024;
pub const MAX_IMAGES: usize = 1024;
pub const MAX_FILESYSTEM_BYTES: usize = 64 * 1024;
pub const MAX_FILESYSTEMS: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageObservationConfig {
    pub snapshotter: String,
    pub image_filesystem: PathBuf,
}
impl ImageObservationConfig {
    pub fn validate(&self) -> Result<(), GuardError> {
        if self.snapshotter != "overlayfs"
            || self.image_filesystem
                != Path::new("/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs")
        {
            return Err(GuardError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationSource {
    RuntimeReported,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Completeness {
    Unknown,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct InventoryStatus {
    pub observation_success: bool,
    pub image_count: Option<String>,
    /// Sum of runtime-reported compressed logical sizes, never physical usage.
    pub compressed_logical_bytes: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct FilesystemObservation {
    pub filesystem_id: String,
    pub runtime_reported_at_ns: String,
    pub used_bytes: Option<String>,
    pub inodes_used: Option<String>,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct FilesystemStatus {
    pub observation_success: bool,
    pub entries: Vec<FilesystemObservation>,
}
#[derive(Clone, Debug, Serialize)]
pub struct ImageObservationStatus {
    pub enabled: bool,
    pub node: NodeBinding,
    pub source: ObservationSource,
    pub completeness: Completeness,
    pub observed_at: Option<DateTime<Utc>>,
    pub filesystem_report_scope: &'static str,
    pub inventory_report_scope: &'static str,
    pub inventory: InventoryStatus,
    pub filesystems: FilesystemStatus,
}
impl ImageObservationStatus {
    fn unknown(node: NodeBinding, enabled: bool) -> Self {
        Self {
            enabled,
            node,
            source: ObservationSource::RuntimeReported,
            completeness: Completeness::Unknown,
            observed_at: None,
            filesystem_report_scope: "RUNTIME_SNAPSHOTSTORE_REPORTED_USAGE",
            inventory_report_scope: "CRI_INDEX_COMPRESSED_LOGICAL",
            inventory: InventoryStatus::default(),
            filesystems: FilesystemStatus::default(),
        }
    }
}

struct CachedStatus {
    status: ImageObservationStatus,
    sampled: Option<Instant>,
}

pub struct ImageObserver {
    node: NodeBinding,
    channel: Option<Channel>,
    enabled: bool,
    latest: Mutex<CachedStatus>,
    run_slot: tokio::sync::Semaphore,
    started: std::sync::atomic::AtomicBool,
    #[cfg(target_os = "linux")]
    host: Option<Arc<linux::HostContext>>,
    #[cfg(target_os = "linux")]
    host_slots: Arc<tokio::sync::Semaphore>,
    #[cfg(target_os = "linux")]
    host_tasks: tokio_util::task::TaskTracker,
}
impl Drop for ImageObserver {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.host_tasks.close();
        }
    }
}
impl ImageObserver {
    pub fn disabled(node: NodeBinding) -> Arc<Self> {
        Arc::new(Self {
            latest: Mutex::new(CachedStatus {
                status: ImageObservationStatus::unknown(node.clone(), false),
                sampled: None,
            }),
            node,
            channel: None,
            enabled: false,
            run_slot: tokio::sync::Semaphore::new(1),
            started: std::sync::atomic::AtomicBool::new(false),
            #[cfg(target_os = "linux")]
            host: None,
            #[cfg(target_os = "linux")]
            host_slots: Arc::new(tokio::sync::Semaphore::new(1)),
            #[cfg(target_os = "linux")]
            host_tasks: tokio_util::task::TaskTracker::new(),
        })
    }
    /// Construct from the enrolled local profile without contacting runtime.
    /// The joined background owner connects only to the fixed privileged UDS.
    pub async fn connect(node: NodeBinding, profile_file: &Path) -> Result<Arc<Self>, GuardError> {
        #[cfg(target_os = "linux")]
        {
            let path = profile_file.to_owned();
            let enrolled = node.clone();
            let host = tokio::task::spawn_blocking(move || linux::HostContext::new(enrolled, path))
                .await
                .map_err(|_| GuardError::Unknown)??;
            Ok(Arc::new(Self {
                latest: Mutex::new(CachedStatus {
                    status: ImageObservationStatus::unknown(node.clone(), true),
                    sampled: None,
                }),
                node,
                channel: None,
                enabled: true,
                run_slot: tokio::sync::Semaphore::new(1),
                started: std::sync::atomic::AtomicBool::new(false),
                host: Some(Arc::new(host)),
                host_slots: Arc::new(tokio::sync::Semaphore::new(1)),
                host_tasks: tokio_util::task::TaskTracker::new(),
            }))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (node, profile_file);
            Err(GuardError::Invalid)
        }
    }
    pub fn status(&self) -> ImageObservationStatus {
        let unknown = || ImageObservationStatus::unknown(self.node.clone(), self.enabled);
        match self.latest.lock() {
            Ok(cache) if cache.sampled.is_some_and(|at| at.elapsed() < STALE_AFTER) => {
                let mut status = cache.status.clone();
                let now = Utc::now();
                if status.filesystems.entries.iter().any(|entry| {
                    entry
                        .runtime_reported_at_ns
                        .parse::<i64>()
                        .ok()
                        .is_none_or(|timestamp| !runtime_timestamp_is_fresh(timestamp, now))
                }) {
                    status.filesystems = FilesystemStatus::default();
                }
                status
            }
            _ => unknown(),
        }
    }
    fn clear(&self) {
        if let Ok(mut cache) = self.latest.lock() {
            *cache = CachedStatus {
                status: ImageObservationStatus::unknown(self.node.clone(), self.enabled),
                sampled: None,
            };
        }
    }
    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) -> Result<(), GuardError> {
        if self.started.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return Err(GuardError::InFlight);
        }
        let _slot = self
            .run_slot
            .try_acquire()
            .map_err(|_| GuardError::InFlight)?;
        struct ClearOnDrop(Arc<ImageObserver>);
        impl Drop for ClearOnDrop {
            fn drop(&mut self) {
                self.0.clear();
                #[cfg(target_os = "linux")]
                {
                    self.0.host_tasks.close();
                }
            }
        }
        let _clear = ClearOnDrop(self.clone());
        if !self.enabled {
            shutdown.cancelled().await;
            return Ok(());
        }
        // The optional runtime handshake belongs to this joined background
        // owner, never construction of the original CRI/control listeners.
        #[cfg(target_os = "linux")]
        let peer = super::runtime_endpoint::RuntimeEndpoint::default();
        #[cfg(target_os = "linux")]
        let mut backend: Option<linux::RuntimeConnection> = None;
        loop {
            self.clear();
            let channel = self.channel.clone();
            #[cfg(target_os = "linux")]
            let channel = if channel.is_some() {
                channel
            } else {
                if backend.is_none() {
                    // Recheck the certified small files before an optional
                    // handshake too: a profile changed since construction
                    // must not cause any runtime RPC under stale authority.
                    let approved = tokio::select! {
                        biased;
                        _ = shutdown.cancelled() => break,
                        result = async {
                            if let Some(host) = &self.host {
                                let host = host.clone();
                                self.host_work(move || { let read = host.begin()?; host.finish(read)?; Ok(()) }).await
                            } else { Ok(()) }
                        } => result,
                    };
                    if approved.is_ok() {
                        backend = Some(linux::RuntimeConnection::new(peer.clone()));
                        let result = tokio::select! {
                            biased;
                            _ = shutdown.cancelled() => break,
                            result = tokio::time::timeout(RPC_TIMEOUT, async {
                                if let Some(connection) = backend.as_mut() { connection.initialize().await }
                                else { Err(GuardError::Unknown) }
                            }) => result,
                        };
                        if !matches!(result, Ok(Ok(())))
                            && let Some(connection) = backend.take()
                        {
                            connection.finish().await;
                        }
                    }
                }
                backend.as_ref().and_then(linux::RuntimeConnection::channel)
            };
            if let Some(channel) = channel {
                let status = tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => break,
                    status = self.read_report(channel) => status,
                };
                if let Ok(mut cache) = self.latest.lock() {
                    *cache = CachedStatus {
                        status,
                        sampled: Some(Instant::now()),
                    };
                }
            }
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep(COLLECTION_INTERVAL) => {}
            }
        }
        #[cfg(target_os = "linux")]
        {
            self.host_tasks.close();
            if let Some(connection) = backend {
                connection.finish().await;
            }
            self.host_tasks.wait().await;
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    async fn host_work<T, F>(&self, work: F) -> Result<T, GuardError>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, GuardError> + Send + 'static,
    {
        let token = self.host_tasks.token();
        if self.host_tasks.is_closed() {
            return Err(GuardError::Closed);
        }
        let permit = self
            .host_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| GuardError::InFlight)?;
        let task = tokio::task::spawn_blocking(move || {
            let _token = token;
            let _permit = permit;
            work()
        });
        tokio::time::timeout(RPC_TIMEOUT, task)
            .await
            .map_err(|_| GuardError::Expired)?
            .map_err(|_| GuardError::Unknown)?
    }
    async fn read_report(&self, channel: Channel) -> ImageObservationStatus {
        use super::cri_proto::{
            ImageFsInfoRequest, ImageFsInfoResponse, ListImagesRequest, ListImagesResponse,
        };
        let mut status = ImageObservationStatus::unknown(self.node.clone(), true);
        #[cfg(target_os = "linux")]
        let host_read = if let Some(host) = &self.host {
            let host = host.clone();
            match self.host_work(move || host.begin()).await {
                Ok(read) => Some(read),
                Err(_) => return status,
            }
        } else {
            None
        };
        let images = bounded_unary::<ListImagesRequest, ListImagesResponse>(
            channel.clone(),
            ListImagesRequest::default(),
            ResponseShape::Inventory,
            "/runtime.v1.ImageService/ListImages",
            MAX_INVENTORY_BYTES,
        )
        .await;
        // These are independent facts: an inventory error must not skip the
        // filesystem RPC, and a filesystem error must not erase valid inventory.
        let usage = bounded_unary::<ImageFsInfoRequest, ImageFsInfoResponse>(
            channel,
            ImageFsInfoRequest::default(),
            ResponseShape::Filesystems,
            "/runtime.v1.ImageService/ImageFsInfo",
            MAX_FILESYSTEM_BYTES,
        )
        .await;
        #[cfg(target_os = "linux")]
        let filesystem_id = if let (Some(host), Some(read)) = (&self.host, host_read) {
            let host = host.clone();
            match self.host_work(move || host.finish(read)).await {
                Ok(identity) => identity,
                Err(_) => return status,
            }
        } else {
            None
        };
        if let Ok(images) = images {
            status.inventory = inventory_status(images).unwrap_or_default();
        }
        #[cfg(target_os = "linux")]
        if let (Some(host), Some(filesystem_id), Ok(usage)) = (&self.host, filesystem_id, usage) {
            status.filesystems = filesystem_status(usage, &host.config, &filesystem_id, Utc::now())
                .unwrap_or_default();
        }
        #[cfg(not(target_os = "linux"))]
        let _ = usage;
        status.observed_at = Some(Utc::now());
        status
    }
    #[cfg(test)]
    fn test_channel(node: NodeBinding, channel: Channel) -> Arc<Self> {
        Arc::new(Self {
            latest: Mutex::new(CachedStatus {
                status: ImageObservationStatus::unknown(node.clone(), true),
                sampled: None,
            }),
            node,
            channel: Some(channel),
            enabled: true,
            run_slot: tokio::sync::Semaphore::new(1),
            started: std::sync::atomic::AtomicBool::new(false),
            #[cfg(target_os = "linux")]
            host: None,
            #[cfg(target_os = "linux")]
            host_slots: Arc::new(tokio::sync::Semaphore::new(1)),
            #[cfg(target_os = "linux")]
            host_tasks: tokio_util::task::TaskTracker::new(),
        })
    }
}

fn inventory_status(response: super::cri_proto::ListImagesResponse) -> Result<InventoryStatus, ()> {
    use std::collections::BTreeMap;
    if response.images.len() > MAX_IMAGES {
        return Err(());
    }
    let mut unique = BTreeMap::new();
    let mut total = 0_u64;
    for image in response.images {
        if image.id.is_empty() || image.id.len() > 256 || image.size == 0 {
            return Err(());
        }
        if let Some(previous) = unique.get(&image.id) {
            // Repeated IDs cannot inflate inventory. Contradictory logical
            // sizes invalidate the whole inventory instead of picking a value.
            if *previous != image.size {
                return Err(());
            }
            continue;
        }
        total = total.checked_add(image.size).ok_or(())?;
        unique.insert(image.id, image.size);
    }
    Ok(InventoryStatus {
        observation_success: true,
        image_count: Some(unique.len().to_string()),
        compressed_logical_bytes: Some(total.to_string()),
    })
}

fn runtime_timestamp_is_fresh(timestamp: i64, now: DateTime<Utc>) -> bool {
    timestamp > 0
        && now
            .timestamp_nanos_opt()
            .and_then(|now| now.checked_sub(timestamp))
            .is_some_and(|age| {
                age >= -5_000_000_000
                    && i64::try_from(STALE_AFTER.as_nanos()).is_ok_and(|limit| age <= limit)
            })
}

#[cfg(any(target_os = "linux", test))]
fn filesystem_status(
    response: super::cri_proto::ImageFsInfoResponse,
    config: &ImageObservationConfig,
    filesystem_id: &str,
    now: DateTime<Utc>,
) -> Result<FilesystemStatus, ()> {
    if response.image_filesystems.len() + response.container_filesystems.len() > MAX_FILESYSTEMS {
        return Err(());
    }
    let mut entries = Vec::new();
    let mut seen = false;
    for usage in response.image_filesystems {
        let path = usage.fs_id.as_ref().ok_or(())?.mountpoint.as_str();
        // The path is only a host-side candidate match. It does not name an
        // actual snapshotter and never reaches status, labels or errors.
        if Path::new(path) != config.image_filesystem || seen || usage.timestamp <= 0 {
            return Err(());
        }
        seen = true;
        if !runtime_timestamp_is_fresh(usage.timestamp, now) {
            return Err(());
        }
        entries.push(FilesystemObservation {
            filesystem_id: filesystem_id.into(),
            runtime_reported_at_ns: usage.timestamp.to_string(),
            used_bytes: usage.used_bytes.map(|v| v.value.to_string()),
            inodes_used: usage.inodes_used.map(|v| v.value.to_string()),
        });
    }
    // Container-filesystem rows are neither image-cache usage nor additive to
    // these rows. Their presence cannot turn this report into a physical total.
    Ok(FilesystemStatus {
        observation_success: true,
        entries,
    })
}

#[derive(Clone, Copy)]
enum ResponseShape {
    Inventory,
    Filesystems,
    Image,
    Spec,
    Annotation,
    Usage,
    FilesystemId,
    Scalar,
}
const MAX_PROTO_FIELDS: usize = 16_384;
const MAX_PROTO_STRING: usize = 4096;

/// This is a preflight for the two pinned CRI responses, not a replacement
/// protobuf implementation. It rejects allocation-amplifying repeated message
/// and metadata headers *before* the official prost decoder allocates them.
fn scan_response(bytes: &[u8], shape: ResponseShape) -> Result<(), tonic::Status> {
    struct Budget {
        fields: usize,
        images: usize,
        filesystems: usize,
    }
    fn scan(
        mut bytes: &[u8],
        shape: ResponseShape,
        budget: &mut Budget,
        depth: usize,
    ) -> Result<(), ()> {
        use prost::bytes::Buf;
        use prost::encoding::{DecodeContext, WireType, decode_key, decode_varint, skip_field};
        if depth > 4 {
            return Err(());
        }
        while bytes.has_remaining() {
            budget.fields = budget.fields.checked_add(1).ok_or(())?;
            if budget.fields > MAX_PROTO_FIELDS {
                return Err(());
            }
            let (tag, wire) = decode_key(&mut bytes).map_err(|_| ())?;
            if matches!(wire, WireType::StartGroup | WireType::EndGroup) {
                return Err(());
            }
            if wire != WireType::LengthDelimited {
                skip_field(wire, tag, &mut bytes, DecodeContext::default()).map_err(|_| ())?;
                continue;
            }
            let length =
                usize::try_from(decode_varint(&mut bytes).map_err(|_| ())?).map_err(|_| ())?;
            if length > bytes.len() {
                return Err(());
            }
            let (field, rest) = bytes.split_at(length);
            bytes = rest;
            let child = match (shape, tag) {
                (ResponseShape::Inventory, 1) => {
                    budget.images += 1;
                    if budget.images > MAX_IMAGES {
                        return Err(());
                    }
                    Some(ResponseShape::Image)
                }
                (ResponseShape::Filesystems, 1 | 2) => {
                    budget.filesystems += 1;
                    if budget.filesystems > MAX_FILESYSTEMS {
                        return Err(());
                    }
                    Some(ResponseShape::Usage)
                }
                (ResponseShape::Image, 5) | (ResponseShape::Usage, 3 | 4) => {
                    Some(ResponseShape::Scalar)
                }
                (ResponseShape::Image, 7) => Some(ResponseShape::Spec),
                (ResponseShape::Spec, 2) => Some(ResponseShape::Annotation),
                (ResponseShape::Usage, 2) => Some(ResponseShape::FilesystemId),
                _ => None,
            };
            if let Some(child) = child {
                scan(field, child, budget, depth + 1)?;
            } else if matches!(
                shape,
                ResponseShape::Image
                    | ResponseShape::Spec
                    | ResponseShape::Annotation
                    | ResponseShape::FilesystemId
            ) && length > MAX_PROTO_STRING
            {
                return Err(());
            }
        }
        Ok(())
    }
    scan(
        bytes,
        shape,
        &mut Budget {
            fields: 0,
            images: 0,
            filesystems: 0,
        },
        0,
    )
    .map_err(|_| {
        tonic::Status::resource_exhausted(
            "Image observation response exceeds its structural budget",
        )
    })
}

struct BoundedCodec<Req, Resp> {
    shape: ResponseShape,
    marker: std::marker::PhantomData<(Req, Resp)>,
}
struct BoundedDecoder<Resp> {
    shape: ResponseShape,
    inner: tonic_prost::ProstDecoder<Resp>,
}
impl<Req, Resp> tonic::codec::Codec for BoundedCodec<Req, Resp>
where
    Req: prost::Message + Send + 'static,
    Resp: prost::Message + Default + Send + 'static,
{
    type Encode = Req;
    type Decode = Resp;
    type Encoder = tonic_prost::ProstEncoder<Req>;
    type Decoder = BoundedDecoder<Resp>;
    fn encoder(&mut self) -> Self::Encoder {
        tonic_prost::ProstEncoder::new(tonic::codec::BufferSettings::default())
    }
    fn decoder(&mut self) -> Self::Decoder {
        BoundedDecoder {
            shape: self.shape,
            inner: tonic_prost::ProstDecoder::new(tonic::codec::BufferSettings::default()),
        }
    }
}
impl<Resp: prost::Message + Default> tonic::codec::Decoder for BoundedDecoder<Resp> {
    type Item = Resp;
    type Error = tonic::Status;
    fn decode(
        &mut self,
        buf: &mut tonic::codec::DecodeBuf<'_>,
    ) -> Result<Option<Resp>, tonic::Status> {
        use prost::bytes::Buf;
        // tonic's pinned DecodeBuf is backed by one contiguous BytesMut.
        if buf.chunk().len() != buf.remaining() {
            return Err(tonic::Status::internal(
                "Image response buffer is not contiguous",
            ));
        }
        scan_response(buf.chunk(), self.shape)?;
        tonic::codec::Decoder::decode(&mut self.inner, buf)
    }
}
async fn bounded_unary<Req, Resp>(
    channel: Channel,
    request: Req,
    shape: ResponseShape,
    path: &'static str,
    max_bytes: usize,
) -> Result<Resp, tonic::Status>
where
    Req: prost::Message + Send + 'static,
    Resp: prost::Message + Default + Send + 'static,
{
    let call = async {
        let mut client = tonic::client::Grpc::new(channel)
            .max_decoding_message_size(max_bytes)
            .max_encoding_message_size(1024);
        client
            .ready()
            .await
            .map_err(|_| tonic::Status::unavailable("Image observation service is unavailable"))?;
        let mut request = tonic::Request::new(request);
        request.set_timeout(RPC_TIMEOUT);
        client
            .unary(
                request,
                tonic::codegen::http::uri::PathAndQuery::from_static(path),
                BoundedCodec::<Req, Resp> {
                    shape,
                    marker: std::marker::PhantomData,
                },
            )
            .await
            .map(tonic::Response::into_inner)
    };
    tokio::time::timeout(RPC_TIMEOUT, call)
        .await
        .map_err(|_| tonic::Status::deadline_exceeded("Image observation timed out"))?
}

#[cfg(test)]
#[path = "image_observation_tests.rs"]
mod tests;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::nodeguard::{
        cri_transport::RuntimeTransport, host::HostProfile, runtime_endpoint::RuntimeEndpoint,
    };
    use rustix::fs::{AtFlags, Mode, OFlags, StatxFlags, openat, statx};
    use sha2::{Digest, Sha256};
    use std::{
        fs::File,
        os::unix::fs::{FileExt, MetadataExt},
        path::Component,
    };

    const MAX_PROFILE_BYTES: usize = 64 * 1024;
    const MAX_CONFIG_BYTES: usize = 1024 * 1024;
    #[cfg(test)]
    const SOCKET: &str = "/run/containerd/containerd.sock";

    fn invalid() -> GuardError {
        GuardError::IdentityMismatch
    }
    fn canonical(path: &Path) -> bool {
        path.is_absolute()
            && path.as_os_str().len() <= 4096
            && path
                .components()
                .all(|v| matches!(v, Component::RootDir | Component::Normal(_)))
    }
    fn directory(path: &Path) -> Result<File, GuardError> {
        if !canonical(path) {
            return Err(invalid());
        }
        let mut current = File::open("/")?;
        for part in path.components() {
            if let Component::Normal(part) = part {
                current = File::from(
                    openat(
                        &current,
                        part,
                        OFlags::RDONLY
                            | OFlags::DIRECTORY
                            | OFlags::NOFOLLOW
                            | OFlags::NONBLOCK
                            | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|v| GuardError::Io(v.into()))?,
                );
                let metadata = current.metadata()?;
                if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 || metadata.nlink() == 0 {
                    return Err(invalid());
                }
            }
        }
        Ok(current)
    }
    fn file(path: &Path) -> Result<File, GuardError> {
        if !canonical(path) {
            return Err(invalid());
        }
        let parent = directory(path.parent().ok_or_else(invalid)?)?;
        let fd = File::from(
            openat(
                parent,
                path.file_name().ok_or_else(invalid)?,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|v| GuardError::Io(v.into()))?,
        );
        let metadata = fd.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.nlink() == 0
        {
            return Err(invalid());
        }
        Ok(fd)
    }
    fn contents(fd: &File, limit: usize) -> Result<Vec<u8>, GuardError> {
        if fd.metadata()?.len() > limit as u64 {
            return Err(invalid());
        }
        let mut output = Vec::new();
        let mut block = [0_u8; 8192];
        loop {
            let n = fd.read_at(&mut block, output.len() as u64)?;
            if n == 0 {
                break;
            }
            if n > limit.saturating_sub(output.len()) {
                return Err(invalid());
            }
            output.extend_from_slice(&block[..n]);
        }
        Ok(output)
    }
    #[derive(Clone, Copy, Eq, PartialEq)]
    struct FileIdentity {
        device: u64,
        inode: u64,
    }
    fn file_identity(fd: &File) -> Result<FileIdentity, GuardError> {
        let metadata = fd.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 || metadata.nlink() == 0 {
            return Err(invalid());
        }
        Ok(FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    struct PinnedInput {
        path: PathBuf,
        fd: File,
        identity: FileIdentity,
        digest: String,
        limit: usize,
    }
    impl PinnedInput {
        fn begin(path: &Path, expected: &str, limit: usize) -> Result<(Self, Vec<u8>), GuardError> {
            let fd = file(path)?;
            let identity = file_identity(&fd)?;
            let bytes = contents(&fd, limit)?;
            if hex::encode(Sha256::digest(&bytes)) != expected || file_identity(&fd)? != identity {
                return Err(invalid());
            }
            Ok((
                Self {
                    path: path.to_owned(),
                    fd,
                    identity,
                    digest: expected.into(),
                    limit,
                },
                bytes,
            ))
        }
        fn finish(&self) -> Result<(), GuardError> {
            let current = file(&self.path)?;
            if file_identity(&self.fd)? != self.identity
                || file_identity(&current)? != self.identity
                || hex::encode(Sha256::digest(contents(&self.fd, self.limit)?)) != self.digest
                || hex::encode(Sha256::digest(contents(&current, self.limit)?)) != self.digest
            {
                return Err(invalid());
            }
            Ok(())
        }
    }
    #[derive(Clone, Copy, Eq, PartialEq)]
    struct FilesystemIdentity {
        file: FileIdentity,
        mount: u64,
    }
    fn filesystem_identity(fd: &File) -> Result<FilesystemIdentity, GuardError> {
        if !fd.metadata()?.is_dir() {
            return Err(invalid());
        }
        let stat = statx(
            fd,
            "",
            AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW,
            StatxFlags::MNT_ID,
        )
        .map_err(|v| GuardError::Io(v.into()))?;
        if stat.stx_mask & StatxFlags::MNT_ID.bits() == 0 || stat.stx_mnt_id == 0 {
            return Err(invalid());
        }
        Ok(FilesystemIdentity {
            file: file_identity(fd)?,
            mount: stat.stx_mnt_id,
        })
    }
    struct PinnedFilesystem {
        path: PathBuf,
        fd: File,
        identity: FilesystemIdentity,
    }
    impl PinnedFilesystem {
        fn begin(path: &Path) -> Result<Self, GuardError> {
            let fd = directory(path)?;
            let identity = filesystem_identity(&fd)?;
            Ok(Self {
                path: path.to_owned(),
                fd,
                identity,
            })
        }
        fn finish(self, node: &NodeBinding) -> Result<String, GuardError> {
            let current = directory(&self.path)?;
            if filesystem_identity(&self.fd)? != self.identity
                || filesystem_identity(&current)? != self.identity
            {
                return Err(invalid());
            }
            // Domain separation and complete enrolled identity prevent reuse
            // across nodes/boots/profiles. No raw host path enters the output.
            Ok(hex::encode(Sha256::digest(
                format!(
                    "sandbox-node-image-fs-v1\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
                    node.cluster_epoch,
                    node.node_uid,
                    node.boot_id,
                    node.profile_sha256,
                    self.identity.file.device,
                    self.identity.file.inode,
                    self.identity.mount
                )
                .as_bytes(),
            )))
        }
    }
    fn boot(node: &NodeBinding) -> Result<(), GuardError> {
        let actual = contents(&File::open("/proc/sys/kernel/random/boot_id")?, 64)?;
        if std::str::from_utf8(&actual).map_err(|_| invalid())?.trim() != node.boot_id.to_string() {
            return Err(invalid());
        }
        let current = std::fs::metadata("/proc/self/ns/mnt")?;
        let initial = std::fs::metadata("/proc/1/ns/mnt")?;
        if current.dev() != initial.dev() || current.ino() != initial.ino() {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) struct HostContext {
        node: NodeBinding,
        profile_file: PathBuf,
        config_file: PathBuf,
        config_sha256: String,
        pub(super) config: ImageObservationConfig,
    }
    pub(super) struct HostRead {
        profile: PinnedInput,
        config: PinnedInput,
        filesystem: Option<PinnedFilesystem>,
    }
    impl HostContext {
        pub(super) fn new(node: NodeBinding, profile_file: PathBuf) -> Result<Self, GuardError> {
            if !node.validate() {
                return Err(invalid());
            }
            boot(&node)?;
            let (pinned, bytes) =
                PinnedInput::begin(&profile_file, &node.profile_sha256, MAX_PROFILE_BYTES)?;
            let profile: HostProfile = serde_json::from_slice(&bytes)?;
            profile.validate()?;
            let config = profile.image_observation.ok_or(GuardError::Invalid)?;
            config.validate()?;
            let (runtime, _) = PinnedInput::begin(
                &profile.containerd_configuration.path,
                &profile.containerd_configuration.sha256,
                MAX_CONFIG_BYTES,
            )?;
            pinned.finish()?;
            runtime.finish()?;
            Ok(Self {
                node,
                profile_file,
                config_file: profile.containerd_configuration.path,
                config_sha256: profile.containerd_configuration.sha256,
                config,
            })
        }
        pub(super) fn begin(&self) -> Result<HostRead, GuardError> {
            boot(&self.node)?;
            let (profile, _) = PinnedInput::begin(
                &self.profile_file,
                &self.node.profile_sha256,
                MAX_PROFILE_BYTES,
            )?;
            let (config, _) =
                PinnedInput::begin(&self.config_file, &self.config_sha256, MAX_CONFIG_BYTES)?;
            let filesystem = PinnedFilesystem::begin(&self.config.image_filesystem).ok();
            boot(&self.node)?;
            Ok(HostRead {
                profile,
                config,
                filesystem,
            })
        }
        pub(super) fn finish(&self, read: HostRead) -> Result<Option<String>, GuardError> {
            read.profile.finish()?;
            read.config.finish()?;
            boot(&self.node)?;
            Ok(read.filesystem.and_then(|fs| fs.finish(&self.node).ok()))
        }
    }
    pub(super) struct RuntimeConnection {
        transport: RuntimeTransport,
        channel: Option<Channel>,
        peer: RuntimeEndpoint,
    }
    impl Drop for RuntimeConnection {
        fn drop(&mut self) {
            self.transport.close_io();
        }
    }
    impl RuntimeConnection {
        pub(super) fn new(peer: RuntimeEndpoint) -> Self {
            Self {
                transport: RuntimeTransport::new(),
                channel: None,
                peer,
            }
        }
        pub(super) fn channel(&self) -> Option<Channel> {
            self.channel.clone()
        }
        pub(super) async fn initialize(&mut self) -> Result<(), GuardError> {
            let connector_transport = self.transport.clone();
            let endpoint = self.peer.clone();
            let channel = tonic::transport::Endpoint::from_static("http://[::]:50051")
                .connect_timeout(RPC_TIMEOUT)
                .buffer_size(1)
                .concurrency_limit(2)
                .connect_with_connector(tower::service_fn(move |_| {
                    let transport = connector_transport.clone();
                    let endpoint = endpoint.clone();
                    async move {
                        let stream = endpoint.connect().await?;
                        transport.wrap(stream).map(hyper_util::rt::TokioIo::new)
                    }
                }))
                .await
                .map_err(|_| GuardError::Unknown)?;
            // Store the real IO owner before awaiting Version, so a cancelled
            // handshake is still closed and joined by run's common cleanup.
            self.channel = Some(channel.clone());
            let mut request = tonic::Request::new(super::super::cri_proto::VersionRequest {
                version: "0.1.0".into(),
            });
            request.set_timeout(RPC_TIMEOUT);
            let version =
                super::super::cri_proto::runtime_service_client::RuntimeServiceClient::new(channel)
                    .max_decoding_message_size(4096)
                    .version(request)
                    .await
                    .map_err(|_| GuardError::Unknown)?
                    .into_inner();
            if version.runtime_name != "containerd"
                || version.runtime_version.trim_start_matches('v') != "2.3.5"
                || version.runtime_api_version != "v1"
            {
                return Err(GuardError::IdentityMismatch);
            }
            Ok(())
        }
        pub(super) async fn finish(mut self) {
            self.transport.close_io();
            self.channel.take();
            self.transport.wait_closed().await;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::nodeguard::host::PinnedFile;
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};

        struct OwnedRoot {
            path: PathBuf,
            mounted: bool,
        }
        impl OwnedRoot {
            fn new() -> anyhow::Result<Self> {
                anyhow::ensure!(
                    rustix::process::geteuid().is_root(),
                    "requires an owned root Linux container"
                );
                let path = PathBuf::from(format!(
                    "/root/sandbox-image-observation-{}",
                    uuid::Uuid::new_v4()
                ));
                std::fs::create_dir(&path)?;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
                Ok(Self {
                    path,
                    mounted: false,
                })
            }
        }
        impl Drop for OwnedRoot {
            fn drop(&mut self) {
                if self.mounted
                    && !std::process::Command::new("umount")
                        .arg(self.path.join("fs"))
                        .status()
                        .is_ok_and(|v| v.success())
                {
                    return;
                }
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
        fn enrolled(root: &Path) -> anyhow::Result<(NodeBinding, PathBuf, PathBuf)> {
            let mut files = Vec::new();
            for name in [
                "qemu",
                "virtiofs",
                "shim",
                "kata",
                "containerd",
                "kubelet",
                "environment",
            ] {
                let path = root.join(name);
                std::fs::write(
                    &path,
                    b"synthetic identity-only fixture, not a runtime binary",
                )?;
                files.push(PinnedFile {
                    path,
                    sha256: hex::encode(Sha256::digest(
                        b"synthetic identity-only fixture, not a runtime binary",
                    )),
                });
            }
            let profile = HostProfile {
                protocol: 1,
                runtime_handler: "kata-qemu".into(),
                containerd_version: "2.3.5".into(),
                qemu: files[0].clone(),
                virtiofs: files[1].clone(),
                shim: files[2].clone(),
                kata_configuration: files[3].clone(),
                containerd_configuration: files[4].clone(),
                kubelet_configuration: files[5].clone(),
                kubelet_environment: files[6].clone(),
                image_observation: Some(ImageObservationConfig {
                    snapshotter: "overlayfs".into(),
                    image_filesystem: "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs"
                        .into(),
                }),
            };
            let bytes = serde_json::to_vec(&profile)?;
            let profile_file = root.join("profile.json");
            std::fs::write(&profile_file, &bytes)?;
            let boot_id = uuid::Uuid::parse_str(
                std::str::from_utf8(&contents(
                    &File::open("/proc/sys/kernel/random/boot_id")?,
                    64,
                )?)?
                .trim(),
            )?;
            let node = NodeBinding {
                cluster_epoch: uuid::Uuid::new_v4(),
                node_uid: uuid::Uuid::new_v4(),
                node_name: "synthetic-profile-file-fixture".into(),
                boot_id,
                profile_sha256: hex::encode(Sha256::digest(bytes)),
            };
            Ok((node, profile_file, files[4].path.clone()))
        }
        #[test]
        #[ignore = "Requires root in an owned Linux container; synthetic profile identity and real kernel FD checks"]
        fn root_profile_config_boot_and_directory_replacement_invalidate_pinned_readback()
        -> anyhow::Result<()> {
            let root = OwnedRoot::new()?;
            let (node, profile_file, config_file) = enrolled(&root.path)?;
            let mut host = HostContext::new(node.clone(), profile_file.clone())?;
            let read = host.begin()?;
            host.finish(read)?;
            let original = std::fs::read(&profile_file)?;
            let read = host.begin()?;
            std::fs::write(&profile_file, b"changed profile")?;
            anyhow::ensure!(
                host.finish(read).is_err(),
                "profile mutation must invalidate all report values"
            );
            std::fs::write(&profile_file, &original)?;
            let config = std::fs::read(&config_file)?;
            let read = host.begin()?;
            std::fs::write(&config_file, b"changed runtime configuration")?;
            anyhow::ensure!(
                host.finish(read).is_err(),
                "containerd configuration mutation must invalidate all report values"
            );
            std::fs::write(&config_file, &config)?;
            host.node.boot_id = uuid::Uuid::new_v4();
            anyhow::ensure!(
                host.begin().is_err(),
                "a different enrolled boot cannot reuse the old report"
            );
            host.node.boot_id = node.boot_id;
            let fs = root.path.join("fs");
            std::fs::create_dir(&fs)?;
            let initial = PinnedFilesystem::begin(&fs)?;
            let first_id = initial.finish(&node)?;
            let next = PinnedFilesystem::begin(&fs)?;
            std::fs::rename(&fs, root.path.join("old-fs"))?;
            std::fs::create_dir(&fs)?;
            anyhow::ensure!(
                next.finish(&node).is_err(),
                "replaced path cannot reuse its pinned inode"
            );
            let second_id = PinnedFilesystem::begin(&fs)?.finish(&node)?;
            anyhow::ensure!(
                first_id != second_id && !first_id.contains("/"),
                "opaque FS identity must change on directory replacement"
            );
            Ok(())
        }
        #[test]
        #[ignore = "Requires root plus CAP_SYS_ADMIN and mount/umount inside an owned Linux test container"]
        fn root_same_inode_bind_mount_change_is_rejected_by_actual_mount_id() -> anyhow::Result<()>
        {
            let mut root = OwnedRoot::new()?;
            let (node, _, _) = enrolled(&root.path)?;
            let fs = root.path.join("fs");
            std::fs::create_dir(&fs)?;
            let pinned = PinnedFilesystem::begin(&fs)?;
            let before = pinned.identity;
            anyhow::ensure!(
                std::process::Command::new("mount")
                    .arg("--bind")
                    .arg(&fs)
                    .arg(&fs)
                    .status()?
                    .success(),
                "owned bind mount failed"
            );
            root.mounted = true;
            let after = filesystem_identity(&directory(&fs)?)?;
            anyhow::ensure!(
                before.file == after.file && before.mount != after.mount,
                "counterexample must preserve the inode and change the actual kernel mount ID"
            );
            anyhow::ensure!(
                pinned.finish(&node).is_err(),
                "same inode under another mount must invalidate the report"
            );
            anyhow::ensure!(
                std::process::Command::new("umount")
                    .arg(&fs)
                    .status()?
                    .success(),
                "owned bind mount cleanup failed"
            );
            root.mounted = false;
            Ok(())
        }
        #[tokio::test]
        #[ignore = "Requires an owned root Linux fixture with no containerd daemon or socket"]
        async fn root_approved_constructor_remains_unknown_without_a_runtime_handshake()
        -> anyhow::Result<()> {
            anyhow::ensure!(
                !Path::new(SOCKET).exists(),
                "this counterexample requires the owned fixture to have no runtime backend"
            );
            let root = OwnedRoot::new()?;
            let (node, profile_file, _) = enrolled(&root.path)?;
            let observer=ImageObserver::connect(node.clone(),&profile_file).await
                .map_err(|_|anyhow::anyhow!("approved observer construction must not require an optional runtime handshake"))?;
            let status = observer.status();
            anyhow::ensure!(
                status.enabled
                    && status.node == node
                    && status.observed_at.is_none()
                    && !status.inventory.observation_success
                    && status.inventory.image_count.is_none()
                    && !status.filesystems.observation_success
                    && status.filesystems.entries.is_empty(),
                "approved but unavailable optional runtime must remain enabled and UNKNOWN"
            );
            let stop = CancellationToken::new();
            stop.cancel();
            observer.clone().run(stop).await?;
            anyhow::ensure!(observer.status().enabled && observer.status().observed_at.is_none());
            Ok(())
        }
        #[derive(Clone)]
        struct PendingVersion {
            calls: Arc<std::sync::atomic::AtomicUsize>,
            active: Arc<std::sync::atomic::AtomicUsize>,
            other: Arc<std::sync::atomic::AtomicUsize>,
            stop: CancellationToken,
        }
        impl tonic::server::NamedService for PendingVersion {
            const NAME: &'static str = "runtime.v1.RuntimeService";
        }
        impl tonic::server::UnaryService<super::super::super::cri_proto::VersionRequest>
            for PendingVersion
        {
            type Response = super::super::super::cri_proto::VersionResponse;
            type Future = std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                        > + Send,
                >,
            >;
            fn call(
                &mut self,
                _: tonic::Request<super::super::super::cri_proto::VersionRequest>,
            ) -> Self::Future {
                let this = self.clone();
                Box::pin(async move {
                    use std::sync::atomic::Ordering;
                    struct Active(Arc<std::sync::atomic::AtomicUsize>);
                    impl Drop for Active {
                        fn drop(&mut self) {
                            self.0.fetch_sub(1, Ordering::SeqCst);
                        }
                    }
                    this.calls.fetch_add(1, Ordering::SeqCst);
                    this.active.fetch_add(1, Ordering::SeqCst);
                    let _active = Active(this.active);
                    this.stop.cancelled().await;
                    Err(tonic::Status::cancelled(
                        "Owned handshake fixture is stopping",
                    ))
                })
            }
        }
        impl tonic::codegen::Service<tonic::codegen::http::Request<tonic::body::Body>> for PendingVersion {
            type Response = tonic::codegen::http::Response<tonic::body::Body>;
            type Error = std::convert::Infallible;
            type Future = std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
            >;
            fn poll_ready(
                &mut self,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), Self::Error>> {
                std::task::Poll::Ready(Ok(()))
            }
            fn call(
                &mut self,
                request: tonic::codegen::http::Request<tonic::body::Body>,
            ) -> Self::Future {
                let this = self.clone();
                Box::pin(async move {
                    if request.uri().path() != "/runtime.v1.RuntimeService/Version" {
                        this.other.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        return Ok(
                            tonic::Status::unimplemented("Only the handshake is expected")
                                .into_http(),
                        );
                    }
                    Ok(tonic::server::Grpc::new(tonic_prost::ProstCodec::default())
                        .unary(this, request)
                        .await)
                })
            }
        }
        struct OwnedSocket {
            device: u64,
            inode: u64,
            parent_created: bool,
        }
        impl Drop for OwnedSocket {
            fn drop(&mut self) {
                if std::fs::symlink_metadata(SOCKET).is_ok_and(|v| {
                    v.file_type().is_socket() && v.dev() == self.device && v.ino() == self.inode
                }) {
                    let _ = std::fs::remove_file(SOCKET);
                }
                if self.parent_created {
                    let _ = std::fs::remove_dir("/run/containerd");
                }
            }
        }
        #[tokio::test]
        #[ignore = "Requires an owned root Linux fixture with no existing containerd daemon/socket"]
        async fn root_cancelled_optional_handshake_closes_actual_io_without_waiting_for_its_deadline()
        -> anyhow::Result<()> {
            use std::sync::atomic::{AtomicUsize, Ordering};
            anyhow::ensure!(
                !Path::new(SOCKET).exists(),
                "never replace an existing runtime endpoint"
            );
            let root = OwnedRoot::new()?;
            let (node, profile_file, _) = enrolled(&root.path)?;
            let parent_created = !Path::new("/run/containerd").exists();
            if parent_created {
                std::fs::create_dir("/run/containerd")?;
                std::fs::set_permissions(
                    "/run/containerd",
                    std::fs::Permissions::from_mode(0o700),
                )?;
            }
            let listener = tokio::net::UnixListener::bind(SOCKET)?;
            std::fs::set_permissions(SOCKET, std::fs::Permissions::from_mode(0o600))?;
            let metadata = std::fs::symlink_metadata(SOCKET)?;
            let _socket = OwnedSocket {
                device: metadata.dev(),
                inode: metadata.ino(),
                parent_created,
            };
            let backend = PendingVersion {
                calls: Arc::new(AtomicUsize::new(0)),
                active: Arc::new(AtomicUsize::new(0)),
                other: Arc::new(AtomicUsize::new(0)),
                stop: CancellationToken::new(),
            };
            let service = backend.clone();
            let server_stop = CancellationToken::new();
            let server_cancel = server_stop.clone();
            let server = tokio::spawn(async move {
                tonic::transport::Server::builder()
                    .add_service(service)
                    .serve_with_incoming_shutdown(
                        futures_util::stream::unfold(listener, |listener| async move {
                            Some((listener.accept().await.map(|(stream, _)| stream), listener))
                        }),
                        server_cancel.cancelled(),
                    )
                    .await
            });
            let stop = CancellationToken::new();
            let mut collector = None;
            let outcome=async {
                let observer=ImageObserver::connect(node,&profile_file).await?;
                anyhow::ensure!(backend.calls.load(Ordering::SeqCst)==0 && observer.status().enabled,
                    "construction must validate local configuration without any runtime handshake");
                collector=Some(tokio::spawn(observer.clone().run(stop.clone())));
                tokio::time::timeout(RPC_TIMEOUT,async {while backend.active.load(Ordering::SeqCst)!=1 {tokio::time::sleep(Duration::from_millis(5)).await;}}).await?;
                stop.cancel();
                if let Some(task)=collector.as_mut() {
                    let joined=tokio::time::timeout(Duration::from_secs(1),task).await?;
                    collector=None;
                    joined??;
                }
                tokio::time::timeout(Duration::from_secs(1),async {while backend.active.load(Ordering::SeqCst)!=0 {tokio::time::sleep(Duration::from_millis(5)).await;}}).await?;
                anyhow::ensure!(observer.status().enabled && observer.status().observed_at.is_none() && backend.calls.load(Ordering::SeqCst)==1 && backend.other.load(Ordering::SeqCst)==0,
                    "cancelled initialization must clear status and release the actual read connection without later image calls");
                anyhow::ensure!(matches!(observer.clone().run(CancellationToken::new()).await,Err(GuardError::InFlight)));
                Ok::<_,anyhow::Error>(())
            }.await;
            stop.cancel();
            backend.stop.cancel();
            server_stop.cancel();
            let collected = if let Some(task) = collector {
                Some(task.await)
            } else {
                None
            };
            let served = server.await;
            if let Some(collected) = collected {
                collected??;
            }
            served??;
            outcome
        }
    }
}
