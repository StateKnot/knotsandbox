use super::*;
use crate::nodeguard::cri_proto::{
    image_service_server::{ImageService, ImageServiceServer},
    *,
};
use anyhow::Context;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tonic::{Request, Response, Status};
use uuid::Uuid;

#[derive(Clone, Default)]
struct Images {
    inventory_calls: Arc<AtomicUsize>,
    filesystem_calls: Arc<AtomicUsize>,
    write_calls: Arc<AtomicUsize>,
    inventory_response: Arc<Mutex<Option<Result<ListImagesResponse, Status>>>>,
    filesystem_response: Arc<Mutex<Option<Result<ImageFsInfoResponse, Status>>>>,
    stall_inventory: Arc<AtomicBool>,
    active_inventory: Arc<AtomicUsize>,
    pending_stop: CancellationToken,
}
#[tonic::async_trait]
impl ImageService for Images {
    async fn list_images(
        &self,
        request: Request<ListImagesRequest>,
    ) -> Result<Response<ListImagesResponse>, Status> {
        assert!(request.into_inner().filter.is_none());
        self.inventory_calls.fetch_add(1, Ordering::SeqCst);
        struct Active(Arc<AtomicUsize>);
        impl Drop for Active {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        self.active_inventory.fetch_add(1, Ordering::SeqCst);
        let _active = Active(self.active_inventory.clone());
        if self.stall_inventory.load(Ordering::SeqCst) {
            self.pending_stop.cancelled().await;
            return Err(Status::cancelled("Owned test backend is stopping"));
        }
        if let Some(response) = self
            .inventory_response
            .lock()
            .map_err(|_| Status::internal("Inventory fixture lock is poisoned"))?
            .clone()
        {
            return response.map(Response::new);
        }
        Ok(Response::new(ListImagesResponse {
            images: vec![Image {
                id: "PRIVATE_CONFIG_DIGEST_NOT_A_MANIFEST".into(),
                repo_tags: vec!["PRIVATE_REPOSITORY:TAG".into()],
                repo_digests: vec!["PRIVATE_REPOSITORY@sha256:PRIVATE".into()],
                size: 9007199254740993,
                pinned: true,
                ..Default::default()
            }],
        }))
    }
    type StreamImagesStream = futures_util::stream::Empty<Result<StreamImagesResponse, Status>>;
    async fn stream_images(
        &self,
        _: Request<StreamImagesRequest>,
    ) -> Result<Response<Self::StreamImagesStream>, Status> {
        Err(Status::unimplemented("not a streaming inventory contract"))
    }
    async fn image_status(
        &self,
        _: Request<ImageStatusRequest>,
    ) -> Result<Response<ImageStatusResponse>, Status> {
        Err(Status::unimplemented("not part of the baseline"))
    }
    async fn pull_image(
        &self,
        _: Request<PullImageRequest>,
    ) -> Result<Response<PullImageResponse>, Status> {
        self.write_calls.fetch_add(1, Ordering::SeqCst);
        Err(Status::permission_denied("read only"))
    }
    async fn remove_image(
        &self,
        _: Request<RemoveImageRequest>,
    ) -> Result<Response<RemoveImageResponse>, Status> {
        self.write_calls.fetch_add(1, Ordering::SeqCst);
        Err(Status::permission_denied("read only"))
    }
    async fn image_fs_info(
        &self,
        _: Request<ImageFsInfoRequest>,
    ) -> Result<Response<ImageFsInfoResponse>, Status> {
        self.filesystem_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(response) = self
            .filesystem_response
            .lock()
            .map_err(|_| Status::internal("Filesystem fixture lock is poisoned"))?
            .clone()
        {
            return response.map(Response::new);
        }
        Ok(Response::new(ImageFsInfoResponse::default()))
    }
}

fn node() -> NodeBinding {
    NodeBinding {
        cluster_epoch: Uuid::new_v4(),
        node_uid: Uuid::new_v4(),
        node_name: "test-only-node".into(),
        boot_id: Uuid::new_v4(),
        profile_sha256: "a".repeat(64),
    }
}

#[tokio::test]
async fn real_image_service_inventory_without_vms_preserves_logical_bytes_and_unknown_completeness()
-> anyhow::Result<()> {
    let backend = Images::default();
    let service = backend.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server_stop = CancellationToken::new();
    let server_shutdown = server_stop.clone();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(ImageServiceServer::new(service))
            .serve_with_incoming_shutdown(
                futures_util::stream::unfold(listener, |listener| async move {
                    Some((listener.accept().await.map(|(stream, _)| stream), listener))
                }),
                server_shutdown.cancelled(),
            )
            .await
    });
    let mut collector = None;
    let stop = CancellationToken::new();
    let outcome = async {
        let channel = Channel::from_shared(format!("http://{address}"))?
            .connect()
            .await?;
        let binding = node();
        let observer = ImageObserver::test_channel(binding.clone(), channel);
        collector = Some(tokio::spawn(observer.clone().run(stop.clone())));
        let status = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let status = observer.status();
                if status.observed_at.is_some() {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .context("normal observer did not complete its first real RPC cycle")?;
        anyhow::ensure!(
            backend.inventory_calls.load(Ordering::SeqCst) == 1
                && backend.filesystem_calls.load(Ordering::SeqCst) == 1,
            "the ordinary collector must read both actual ImageService RPCs exactly once"
        );
        anyhow::ensure!(
            backend.write_calls.load(Ordering::SeqCst) == 0,
            "baseline must have no write RPCs"
        );
        anyhow::ensure!(
            status.node == binding,
            "readback must retain exact enrolled node identity"
        );
        anyhow::ensure!(
            status.inventory.observation_success,
            "real ImageService inventory readback must replace UNKNOWN even without any VM"
        );
        anyhow::ensure!(
            status.inventory.image_count.as_deref() == Some("1")
                && status.inventory.compressed_logical_bytes.as_deref() == Some("9007199254740993"),
            "runtime logical counts must retain decimal precision without claiming physical storage"
        );
        let json = serde_json::to_value(&status)?;
        anyhow::ensure!(
            json["source"] == "RUNTIME_REPORTED" && json["completeness"] == "UNKNOWN",
            "successful transport cannot certify completeness"
        );
        let encoded = serde_json::to_string(&status)?;
        anyhow::ensure!(
            !encoded.contains("PRIVATE_")
                && !encoded.contains("/var/lib/")
                && json.get("capacity_bytes").is_none()
                && json.get("available_bytes").is_none(),
            "status must not leak inventory names or invent capacity"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    stop.cancel();
    let collector_result = if let Some(collector) = collector {
        collector
            .await
            .map_err(anyhow::Error::from)
            .and_then(|v| v.map_err(Into::into))
    } else {
        Ok(())
    };
    server_stop.cancel();
    let server_result = server.await;
    collector_result?;
    server_result??;
    outcome
}

struct ImageServer {
    backend: Images,
    channel: Channel,
    stop: CancellationToken,
    task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
}
impl ImageServer {
    async fn start(backend: Images) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let stop = CancellationToken::new();
        let shutdown = stop.clone();
        let service = backend.clone();
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(ImageServiceServer::new(service))
                .serve_with_incoming_shutdown(
                    futures_util::stream::unfold(listener, |listener| async move {
                        Some((listener.accept().await.map(|(stream, _)| stream), listener))
                    }),
                    shutdown.cancelled(),
                )
                .await
        });
        let result = Channel::from_shared(format!("http://{address}"))?
            .connect()
            .await;
        match result {
            Ok(channel) => Ok(Self {
                backend,
                channel,
                stop,
                task,
            }),
            Err(error) => {
                stop.cancel();
                task.await??;
                Err(error.into())
            }
        }
    }
    async fn finish(self) -> anyhow::Result<()> {
        // Release only this fixture's pending reads even when a cancellation
        // assertion failed. Assertions sample active work before this cleanup.
        self.backend.pending_stop.cancel();
        self.stop.cancel();
        drop(self.channel);
        self.task.await??;
        Ok(())
    }
    async fn first_status(&self) -> anyhow::Result<ImageObservationStatus> {
        let observer = ImageObserver::test_channel(node(), self.channel.clone());
        let stop = CancellationToken::new();
        let task = tokio::spawn(observer.clone().run(stop.clone()));
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let status = observer.status();
                if status.observed_at.is_some() {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        stop.cancel();
        let joined = task.await;
        let cleared = observer.status();
        joined??;
        anyhow::ensure!(
            cleared.observed_at.is_none()
                && !cleared.inventory.observation_success
                && cleared.filesystems.entries.is_empty(),
            "shutdown must clear the last readback"
        );
        Ok(result?)
    }
}
fn image(id: &str, size: u64) -> Image {
    Image {
        id: id.into(),
        size,
        ..Default::default()
    }
}

#[tokio::test]
async fn real_inventory_deduplicates_ids_and_rejects_conflicts_overflow_and_missing_values()
-> anyhow::Result<()> {
    let backend = Images::default();
    let server = ImageServer::start(backend.clone()).await?;
    let outcome = async {
        for (images, expected) in [
            (vec![], Some(("0", "0"))),
            (vec![image("same", 7), image("same", 7)], Some(("1", "7"))),
            (vec![image("same", 7), image("same", 8)], None),
            (vec![image("a", u64::MAX), image("b", 1)], None),
            (vec![image("", 3)], None),
            (vec![image("a", 0)], None),
        ] {
            *backend
                .inventory_response
                .lock()
                .map_err(|_| anyhow::anyhow!("Inventory fixture lock is poisoned"))? =
                Some(Ok(ListImagesResponse { images }));
            let status = server.first_status().await?;
            if let Some((count, bytes)) = expected {
                anyhow::ensure!(
                    status.inventory.observation_success
                        && status.inventory.image_count.as_deref() == Some(count)
                        && status.inventory.compressed_logical_bytes.as_deref() == Some(bytes)
                );
            } else {
                anyhow::ensure!(
                    !status.inventory.observation_success
                        && status.inventory.image_count.is_none()
                        && status.inventory.compressed_logical_bytes.is_none()
                );
            }
        }
        anyhow::ensure!(
            backend.inventory_calls.load(Ordering::SeqCst) == 6
                && backend.filesystem_calls.load(Ordering::SeqCst) == 6
                && backend.write_calls.load(Ordering::SeqCst) == 0
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    server.finish().await?;
    outcome
}

#[tokio::test]
async fn real_rpc_failures_are_independent_redacted_and_do_not_retain_old_success()
-> anyhow::Result<()> {
    let backend = Images::default();
    let server = ImageServer::start(backend.clone()).await?;
    let outcome = async {
        *backend
            .inventory_response
            .lock()
            .map_err(|_| anyhow::anyhow!("Inventory fixture lock is poisoned"))? =
            Some(Err(Status::unavailable("PRIVATE_REGISTRY_TOKEN_AND_PATH")));
        let status = server.first_status().await?;
        anyhow::ensure!(
            !status.inventory.observation_success
                && backend.filesystem_calls.load(Ordering::SeqCst) == 1
        );
        anyhow::ensure!(!serde_json::to_string(&status)?.contains("PRIVATE_"));
        *backend
            .inventory_response
            .lock()
            .map_err(|_| anyhow::anyhow!("Inventory fixture lock is poisoned"))? = None;
        *backend
            .filesystem_response
            .lock()
            .map_err(|_| anyhow::anyhow!("Filesystem fixture lock is poisoned"))? =
            Some(Err(Status::unavailable("PRIVATE_FS_PATH")));
        let status = server.first_status().await?;
        anyhow::ensure!(
            status.inventory.observation_success
                && !status.filesystems.observation_success
                && status.filesystems.entries.is_empty()
        );
        anyhow::ensure!(
            backend.inventory_calls.load(Ordering::SeqCst) == 2
                && backend.filesystem_calls.load(Ordering::SeqCst) == 2
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    server.finish().await?;
    outcome
}

#[derive(Default, Debug)]
struct DecodeTripwire;
impl prost::Message for DecodeTripwire {
    fn encode_raw(&self, _: &mut impl prost::bytes::BufMut) {}
    fn merge_field(
        &mut self,
        _: u32,
        _: prost::encoding::WireType,
        _: &mut impl prost::bytes::Buf,
        _: prost::encoding::DecodeContext,
    ) -> Result<(), prost::DecodeError> {
        panic!("typed prost decoder was reached before the response allocation budget rejected it")
    }
    fn encoded_len(&self) -> usize {
        0
    }
    fn clear(&mut self) {}
}

#[tokio::test]
async fn real_wire_and_predecode_item_metadata_budgets_reject_before_typed_allocation()
-> anyhow::Result<()> {
    let backend = Images::default();
    let server = ImageServer::start(backend.clone()).await?;
    let outcome = async {
        let mut metadata = image("metadata", 1);
        metadata.repo_tags = vec![String::new(); MAX_PROTO_FIELDS + 1];
        let mut oversized = image("wire", 1);
        oversized.repo_tags = vec!["x".repeat(MAX_INVENTORY_BYTES + 1)];
        for images in [
            vec![Image::default(); MAX_IMAGES + 1],
            vec![metadata],
            vec![oversized],
        ] {
            *backend
                .inventory_response
                .lock()
                .map_err(|_| anyhow::anyhow!("Inventory fixture lock is poisoned"))? =
                Some(Ok(ListImagesResponse { images }));
            let result = bounded_unary::<ListImagesRequest, DecodeTripwire>(
                server.channel.clone(),
                ListImagesRequest::default(),
                ResponseShape::Inventory,
                "/runtime.v1.ImageService/ListImages",
                MAX_INVENTORY_BYTES,
            )
            .await;
            anyhow::ensure!(
                result.is_err(),
                "oversized wire or structural count must be rejected before decoding any entry"
            );
        }
        *backend
            .filesystem_response
            .lock()
            .map_err(|_| anyhow::anyhow!("Filesystem fixture lock is poisoned"))? =
            Some(Ok(ImageFsInfoResponse {
                image_filesystems: vec![FilesystemUsage::default(); MAX_FILESYSTEMS + 1],
                container_filesystems: vec![],
            }));
        let result = bounded_unary::<ImageFsInfoRequest, DecodeTripwire>(
            server.channel.clone(),
            ImageFsInfoRequest::default(),
            ResponseShape::Filesystems,
            "/runtime.v1.ImageService/ImageFsInfo",
            MAX_FILESYSTEM_BYTES,
        )
        .await;
        anyhow::ensure!(result.is_err());
        Ok::<_, anyhow::Error>(())
    }
    .await;
    server.finish().await?;
    outcome
}

#[tokio::test]
async fn disabled_double_run_and_shutdown_perform_no_unowned_extra_rpc() -> anyhow::Result<()> {
    let server = ImageServer::start(Images::default()).await?;
    let disabled = ImageObserver::disabled(node());
    let disabled_stop = CancellationToken::new();
    let disabled_task = tokio::spawn(disabled.clone().run(disabled_stop.clone()));
    tokio::task::yield_now().await;
    disabled_stop.cancel();
    let disabled_join = disabled_task.await;
    let result = async {
        disabled_join??;
        anyhow::ensure!(
            !disabled.status().enabled
                && server.backend.inventory_calls.load(Ordering::SeqCst) == 0
                && server.backend.filesystem_calls.load(Ordering::SeqCst) == 0
        );
        let observer = ImageObserver::test_channel(node(), server.channel.clone());
        let stop = CancellationToken::new();
        let first = tokio::spawn(observer.clone().run(stop.clone()));
        let ready = tokio::time::timeout(Duration::from_secs(2), async {
            while observer.status().observed_at.is_none() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        let second = observer.clone().run(CancellationToken::new()).await;
        stop.cancel();
        let joined = first.await;
        ready?;
        joined??;
        anyhow::ensure!(
            matches!(second, Err(GuardError::InFlight))
                && server.backend.inventory_calls.load(Ordering::SeqCst) == 1
                && server.backend.filesystem_calls.load(Ordering::SeqCst) == 1
        );
        anyhow::ensure!(
            !observer.status().inventory.observation_success
                && observer.status().observed_at.is_none()
        );
        let restarted = observer.clone().run(CancellationToken::new()).await;
        anyhow::ensure!(
            matches!(restarted, Err(GuardError::InFlight)),
            "a retired collector cannot silently start a new RPC owner"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    server.finish().await?;
    result
}

#[tokio::test]
async fn pending_read_cancel_and_deadline_do_not_accumulate_detached_inventory_work()
-> anyhow::Result<()> {
    let backend = Images::default();
    backend.stall_inventory.store(true, Ordering::SeqCst);
    let server = ImageServer::start(backend.clone()).await?;
    let observer = ImageObserver::test_channel(node(), server.channel.clone());
    let stop = CancellationToken::new();
    let task = tokio::spawn(observer.clone().run(stop.clone()));
    let outcome = async {
        tokio::time::timeout(Duration::from_secs(2), async {
            while backend.active_inventory.load(Ordering::SeqCst) != 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        anyhow::ensure!(matches!(
            observer.clone().run(CancellationToken::new()).await,
            Err(GuardError::InFlight)
        ));
        // Cancel the real caller while the server has admitted its read.
        stop.cancel();
        Ok::<_, anyhow::Error>(())
    }
    .await;
    stop.cancel();
    let joined = task.await;
    let drained = tokio::time::timeout(Duration::from_secs(3), async {
        while backend.active_inventory.load(Ordering::SeqCst) != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    let counts = (
        backend.inventory_calls.load(Ordering::SeqCst),
        backend.filesystem_calls.load(Ordering::SeqCst),
    );
    server.finish().await?;
    joined??;
    outcome?;
    drained?;
    anyhow::ensure!(
        counts == (1, 0) && observer.status().observed_at.is_none(),
        "cancelled read must end without a detached next RPC"
    );
    Ok(())
}

#[test]
fn filesystem_projection_retains_original_time_and_missing_fields_without_inventing_totals()
-> anyhow::Result<()> {
    let now = Utc::now();
    let timestamp = now.timestamp_nanos_opt().context("timestamp")? - 1_000_000_000;
    let config = ImageObservationConfig {
        snapshotter: "overlayfs".into(),
        image_filesystem: "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs".into(),
    };
    let usage = FilesystemUsage {
        timestamp,
        fs_id: Some(FilesystemIdentifier {
            mountpoint: config.image_filesystem.to_string_lossy().into_owned(),
        }),
        used_bytes: None,
        inodes_used: Some(UInt64Value { value: 0 }),
    };
    let response = ImageFsInfoResponse {
        image_filesystems: vec![usage.clone()],
        container_filesystems: vec![usage.clone()],
    };
    let status = filesystem_status(response, &config, "opaque-fixture-fs-identity", now)
        .map_err(|_| anyhow::anyhow!("valid partial runtime report rejected"))?;
    anyhow::ensure!(
        status.observation_success
            && status.entries.len() == 1
            && status.entries[0].used_bytes.is_none()
            && status.entries[0].inodes_used.as_deref() == Some("0")
            && status.entries[0].runtime_reported_at_ns == timestamp.to_string()
    );
    let output = serde_json::to_value(status)?;
    anyhow::ensure!(
        !output.to_string().contains("/var/lib/") && output.get("capacity_bytes").is_none()
    );
    for invalid in [
        FilesystemUsage {
            timestamp: 0,
            ..usage.clone()
        },
        FilesystemUsage {
            timestamp: timestamp - 61_000_000_000,
            ..usage.clone()
        },
        FilesystemUsage {
            timestamp: timestamp + 7_000_000_000,
            ..usage.clone()
        },
        FilesystemUsage {
            fs_id: None,
            ..usage.clone()
        },
        FilesystemUsage {
            fs_id: Some(FilesystemIdentifier {
                mountpoint: "/PRIVATE_UNAPPROVED_PATH".into(),
            }),
            ..usage.clone()
        },
    ] {
        anyhow::ensure!(
            filesystem_status(
                ImageFsInfoResponse {
                    image_filesystems: vec![invalid],
                    container_filesystems: vec![]
                },
                &config,
                "opaque",
                now
            )
            .is_err()
        );
    }
    anyhow::ensure!(
        filesystem_status(
            ImageFsInfoResponse {
                image_filesystems: vec![usage.clone(), usage],
                container_filesystems: vec![]
            },
            &config,
            "opaque",
            now
        )
        .is_err(),
        "duplicate filesystem rows cannot inflate totals"
    );
    Ok(())
}

#[test]
fn stale_cache_returns_unknown_values_and_the_original_binding() -> anyhow::Result<()> {
    let observer = ImageObserver::disabled(node());
    {
        let mut cache = observer
            .latest
            .lock()
            .map_err(|_| anyhow::anyhow!("Observation cache fixture lock is poisoned"))?;
        cache.status.inventory = InventoryStatus {
            observation_success: true,
            image_count: Some("1".into()),
            compressed_logical_bytes: Some("7".into()),
        };
        cache.status.observed_at = Some(Utc::now());
        cache.sampled = Some(Instant::now() - STALE_AFTER);
    }
    let status = observer.status();
    assert_eq!(status.node, observer.node);
    assert!(
        !status.inventory.observation_success
            && status.inventory.image_count.is_none()
            && status.observed_at.is_none()
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn cancelled_blocking_host_read_retains_its_real_slot_until_the_closure_exits()
-> anyhow::Result<()> {
    let observer = ImageObserver::disabled(node());
    let active = observer.clone();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (finish_tx, finish_rx) = std::sync::mpsc::channel();
    let waiter = tokio::spawn(async move {
        active
            .host_work(move || {
                let _ = entered_tx.send(());
                finish_rx.recv().map_err(|_| GuardError::Unknown)?;
                Ok(())
            })
            .await
    });
    let entered = tokio::time::timeout(Duration::from_secs(2), entered_rx).await;
    waiter.abort();
    let _ = waiter.await;
    let outcome = async {
        entered??;
        anyhow::ensure!(
            observer.host_tasks.len() == 1 && observer.host_slots.available_permits() == 0,
            "dropping the awaiter cannot release a running kernel read's owner"
        );
        let extra = observer
            .host_work(|| Err::<(), _>(GuardError::Unknown))
            .await;
        anyhow::ensure!(
            matches!(extra, Err(GuardError::InFlight)) && observer.host_tasks.len() == 1,
            "no second blocking read may accumulate behind the first"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let _ = finish_tx.send(());
    observer.host_tasks.close();
    tokio::time::timeout(Duration::from_secs(2), observer.host_tasks.wait()).await?;
    anyhow::ensure!(observer.host_tasks.is_empty() && observer.host_slots.available_permits() == 1);
    outcome
}

#[tokio::test]
async fn real_inventory_deadline_does_not_skip_filesystem_or_retain_server_work()
-> anyhow::Result<()> {
    let backend = Images::default();
    backend.stall_inventory.store(true, Ordering::SeqCst);
    let server = ImageServer::start(backend.clone()).await?;
    let outcome = async {
        let status = server.first_status().await?;
        anyhow::ensure!(
            !status.inventory.observation_success && status.inventory.image_count.is_none()
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while backend.active_inventory.load(Ordering::SeqCst) != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        anyhow::ensure!(
            backend.inventory_calls.load(Ordering::SeqCst) == 1
                && backend.filesystem_calls.load(Ordering::SeqCst) == 1
                && backend.write_calls.load(Ordering::SeqCst) == 0,
            "the independent filesystem read must still run after the fixed inventory deadline"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    server.finish().await?;
    outcome
}

#[tokio::test]
async fn next_real_collection_failure_clears_prior_success_at_the_normal_interval()
-> anyhow::Result<()> {
    let backend = Images::default();
    let server = ImageServer::start(backend.clone()).await?;
    let observer = ImageObserver::test_channel(node(), server.channel.clone());
    let stop = CancellationToken::new();
    let task = tokio::spawn(observer.clone().run(stop.clone()));
    let outcome = async {
        let first = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let status = observer.status();
                if status.inventory.observation_success {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        *backend
            .inventory_response
            .lock()
            .map_err(|_| anyhow::anyhow!("Inventory fixture lock is poisoned"))? =
            Some(Err(Status::unavailable("PRIVATE_NEXT_CYCLE_INVENTORY")));
        *backend
            .filesystem_response
            .lock()
            .map_err(|_| anyhow::anyhow!("Filesystem fixture lock is poisoned"))? =
            Some(Err(Status::unavailable("PRIVATE_NEXT_CYCLE_FILESYSTEM")));
        // Keep the actual production collection interval. Wait for its real
        // second outcome rather than shortening policy or guessing completion.
        let next = tokio::time::timeout(COLLECTION_INTERVAL + Duration::from_secs(5), async {
            loop {
                let status = observer.status();
                if status.observed_at.is_some() && status.observed_at != first.observed_at {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        anyhow::ensure!(
            !next.inventory.observation_success
                && next.inventory.image_count.is_none()
                && next.inventory.compressed_logical_bytes.is_none()
                && !next.filesystems.observation_success
                && next.filesystems.entries.is_empty(),
            "a failed next observation cannot repeat the previous success"
        );
        anyhow::ensure!(
            backend.inventory_calls.load(Ordering::SeqCst) == 2
                && backend.filesystem_calls.load(Ordering::SeqCst) == 2
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    stop.cancel();
    let joined = task.await;
    server.finish().await?;
    joined??;
    outcome
}

#[test]
fn status_expires_runtime_filesystem_timestamp_independently_of_fresh_inventory_cache()
-> anyhow::Result<()> {
    let observer = ImageObserver::disabled(node());
    let now = Utc::now();
    let sampled_at = now - chrono::Duration::seconds(30);
    let reported_at = now - chrono::Duration::seconds(61);
    let reported_ns = reported_at
        .timestamp_nanos_opt()
        .context("runtime timestamp")?;
    let config = ImageObservationConfig {
        snapshotter: "overlayfs".into(),
        image_filesystem: "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs".into(),
    };
    // The report was only 31 seconds old when collected, so the normal
    // assembler legitimately accepted it. The cache itself is still fresh.
    let filesystems = filesystem_status(
        ImageFsInfoResponse {
            image_filesystems: vec![FilesystemUsage {
                timestamp: reported_ns,
                fs_id: Some(FilesystemIdentifier {
                    mountpoint: config.image_filesystem.to_string_lossy().into_owned(),
                }),
                used_bytes: Some(UInt64Value { value: 17 }),
                inodes_used: Some(UInt64Value { value: 3 }),
            }],
            container_filesystems: vec![],
        },
        &config,
        "opaque-fs-fixture",
        sampled_at,
    )
    .map_err(|_| anyhow::anyhow!("31-second-old report must be valid at collection"))?;
    anyhow::ensure!(filesystems.observation_success && filesystems.entries.len() == 1);
    {
        let mut cache = observer
            .latest
            .lock()
            .map_err(|_| anyhow::anyhow!("Observation cache fixture lock is poisoned"))?;
        cache.status.enabled = true;
        cache.status.observed_at = Some(sampled_at);
        cache.status.inventory = InventoryStatus {
            observation_success: true,
            image_count: Some("1".into()),
            compressed_logical_bytes: Some("7".into()),
        };
        cache.status.filesystems = filesystems;
        cache.sampled = Some(Instant::now() - Duration::from_secs(30));
    }
    let status = observer.status();
    anyhow::ensure!(
        status.inventory.observation_success
            && status.inventory.image_count.as_deref() == Some("1")
            && status.inventory.compressed_logical_bytes.as_deref() == Some("7")
            && status.observed_at == Some(sampled_at),
        "fresh inventory and collector timestamp must be preserved independently"
    );
    anyhow::ensure!(
        !status.filesystems.observation_success && status.filesystems.entries.is_empty(),
        "status must clear the expired original filesystem report while preserving fresh inventory"
    );
    Ok(())
}
