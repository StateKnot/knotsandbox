//! CRI forwarding uses the official pinned v1 protobuf. Only a closed, durable
//! managed-start gate is added; containerd remains the runtime implementation.
use super::cri_proto::runtime_service_client as cri_proto_client_alias;
pub use super::cri_transport::{RuntimeIo, RuntimeTransport};
use super::{
    GuardError,
    cri_proto::*,
    host::HostObserver,
    journal::{GateJournal, StartKind},
    protocol::LaunchBinding,
};
use cri_proto_client_alias::RuntimeServiceClient;
use std::{future::Future, sync::Arc, time::Duration};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tonic::{
    Request, Response, Status,
    transport::{Channel, Endpoint},
};
use uuid::Uuid;

#[derive(Clone)]
pub struct CriProxy {
    pub journal: GateJournal,
    pub observer: Arc<HostObserver>,
    pub upstream: RuntimeServiceClient<Channel>,
    pub tasks: TaskTracker,
    pub(crate) read_shutdown: CancellationToken,
}
fn failure(_: impl std::fmt::Display) -> Status {
    Status::failed_precondition(
        "Managed runtime identity or durable launch gate cannot be established",
    )
}
impl CriProxy {
    /// Register before checking the closing flag: a pre-close request remains
    /// visible to drain, while a post-close request performs no I/O. The owned
    /// task spans classification/authorization and each side effect, including
    /// system passthrough; dropping an HTTP/2 awaiter never cancels it.
    async fn owned_rpc<T, F, Fut>(&self, work: F) -> Result<T, Status>
    where
        T: Send + 'static,
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, Status>> + Send + 'static,
    {
        let this = self.clone();
        super::cri_work::owned_rpc(&self.tasks, move || work(this)).await
    }
    /// Reads have the same admission gate, but no detached owner after caller
    /// cancellation. Otherwise cancelled health/list calls could accumulate
    /// without a mutation ledger to bound their lifetime. Shutdown ends only
    /// read handshakes/bodies, so watches cannot retain the real tonic parent.
    async fn read_rpc<T, F, Fut>(&self, work: F) -> Result<T, Status>
    where
        T: Send + 'static,
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, Status>> + Send + 'static,
    {
        let this = self.clone();
        super::cri_work::read_rpc(&self.tasks, &self.read_shutdown, move || work(this)).await
    }
    pub fn close_reads(&self) {
        self.read_shutdown.cancel();
    }
    pub async fn serve_read_parent<P, T>(
        &self,
        parent: P,
        shutdown: &CancellationToken,
        transport: &RuntimeTransport,
    ) -> T
    where
        P: Future<Output = T>,
    {
        super::cri_work::serve_read_parent(
            shutdown,
            parent,
            || super::cri_work::begin_drain(&self.tasks, &self.read_shutdown),
            transport,
        )
        .await
    }
    pub async fn connect(
        journal: GateJournal,
        observer: Arc<HostObserver>,
    ) -> anyhow::Result<Self> {
        let tasks = TaskTracker::new();
        let read_shutdown = CancellationToken::new();
        let endpoint = super::runtime_endpoint::RuntimeEndpoint::default();
        let connector_tasks = tasks.clone();
        let connector_reads = read_shutdown.clone();
        let channel = Endpoint::from_static("http://[::]:50051")
            .connect_timeout(Duration::from_secs(5))
            .connect_with_connector(tower::service_fn(move |_| {
                let endpoint = endpoint.clone();
                let tasks = connector_tasks.clone();
                let reads = connector_reads.clone();
                async move {
                    let result = endpoint.connect().await;
                    if endpoint.is_rejected() {
                        super::cri_work::begin_drain(&tasks, &reads);
                    }
                    result.map(hyper_util::rt::TokioIo::new)
                }
            }))
            .await?;
        let upstream = RuntimeServiceClient::new(channel)
            .max_decoding_message_size(16 * 1024 * 1024)
            .max_encoding_message_size(16 * 1024 * 1024);
        Ok(Self {
            journal,
            observer,
            upstream,
            tasks,
            read_shutdown,
        })
    }
    pub async fn verify_startup(&self) -> Result<(), GuardError> {
        let version = tokio::time::timeout(
            Duration::from_secs(5),
            self.upstream.clone().version(VersionRequest {
                version: "0.1.0".into(),
            }),
        )
        .await
        .map_err(|_| GuardError::Expired)?
        .map_err(|_| GuardError::Unknown)?
        .into_inner();
        if version.runtime_name != "containerd"
            || version.runtime_version.trim_start_matches('v') != "2.3.5"
            || version.runtime_api_version != "v1"
        {
            return Err(GuardError::IdentityMismatch);
        }
        super::runtime_profile::verify(
            self.upstream.clone(),
            self.observer.expected_kata_configuration(),
        )
        .await?;
        let sandboxes = tokio::time::timeout(
            Duration::from_secs(5),
            self.upstream
                .clone()
                .list_pod_sandbox(ListPodSandboxRequest::default()),
        )
        .await
        .map_err(|_| GuardError::Expired)?
        .map_err(|_| GuardError::Unknown)?
        .into_inner()
        .items;
        for sandbox in sandboxes {
            if sandbox.runtime_handler == "kata-qemu" || managed_label(&sandbox.labels) {
                let pod = self.journal.pod_for_sandbox(&sandbox.id).await?;
                if sandbox.runtime_handler != "kata-qemu"
                    || sandbox
                        .metadata
                        .as_ref()
                        .is_none_or(|m| m.uid != pod.to_string())
                {
                    return Err(GuardError::Unknown);
                }
            } else if !system_handler(&sandbox.runtime_handler) {
                return Err(GuardError::IdentityMismatch);
            }
        }
        let observations = self.journal.unterminated_observations().await?;
        let observer = self.observer.clone();
        tokio::task::spawn_blocking(move || observer.restore(&observations))
            .await
            .map_err(|_| GuardError::Unknown)??;
        self.journal.verify_coverage().await
    }
    async fn sandbox(&self, id: &str) -> Result<Option<Uuid>, Status> {
        if let Ok(pod) = self.journal.pod_for_sandbox(id).await {
            return Ok(Some(pod));
        }
        let response = self
            .upstream
            .clone()
            .pod_sandbox_status(PodSandboxStatusRequest {
                pod_sandbox_id: id.to_owned(),
                verbose: false,
            })
            .await?
            .into_inner()
            .status
            .ok_or_else(|| failure("Missing sandbox"))?;
        if response.id != id
            || !system_handler(&response.runtime_handler)
            || managed_label(&response.labels)
        {
            return Err(failure("Unknown managed sandbox"));
        }
        Ok(None)
    }
    async fn container(&self, id: &str) -> Result<Option<Uuid>, Status> {
        if let Ok(pod) = self.journal.pod_for_container(id).await {
            return Ok(Some(pod));
        }
        let rows = self
            .upstream
            .clone()
            .list_containers(ListContainersRequest {
                filter: Some(ContainerFilter {
                    id: id.to_owned(),
                    ..Default::default()
                }),
            })
            .await?
            .into_inner()
            .containers;
        if rows.len() != 1 || rows[0].id != id {
            return Err(failure("Unknown container"));
        }
        self.sandbox(&rows[0].pod_sandbox_id).await
    }
    async fn allow_container(&self, id: &str) -> Result<(), Status> {
        if let Some(pod) = self.container(id).await? {
            self.journal.require_open(pod).await.map_err(failure)?;
        }
        Ok(())
    }
    async fn allow_interactive_container(&self, id: &str) -> Result<(), Status> {
        self.allow_container(id).await?;
        if let Some(pod) = self.container(id).await?
            && !matches!(
                self.journal.launch(pod).await.map_err(failure)?.purpose,
                super::protocol::LaunchPurpose::Workload
            )
        {
            return Err(failure(
                "Backup tasks have no interactive execution channel",
            ));
        }
        Ok(())
    }
    async fn allow_sandbox(&self, id: &str) -> Result<(), Status> {
        if let Some(pod) = self.sandbox(id).await? {
            self.journal.require_open(pod).await.map_err(failure)?;
        }
        Ok(())
    }
    async fn run_owned(
        &self,
        request: RunPodSandboxRequest,
    ) -> Result<RunPodSandboxResponse, Status> {
        let config = request
            .config
            .as_ref()
            .ok_or_else(|| failure("Missing configuration"))?;
        let metadata = config
            .metadata
            .as_ref()
            .ok_or_else(|| failure("Missing metadata"))?;
        let pod = Uuid::parse_str(&metadata.uid).map_err(failure)?;
        let launch = self.journal.launch(pod).await.map_err(failure)?;
        if metadata.name != launch.pod_name
            || metadata.namespace != launch.namespace
            || !purpose_labels_match(&config.labels, &launch)
        {
            return Err(failure("Launch identity changed"));
        }
        let cgroup = config
            .linux
            .as_ref()
            .ok_or_else(|| failure("Linux is required"))?
            .cgroup_parent
            .as_str();
        // Only the kubelet's fixed systemd cgroup for this exact Pod UID may be used.
        if !super::host::pod_cgroup_root(pod, cgroup).is_ok_and(|root| root == cgroup) {
            return Err(failure("Cgroup differs from Pod"));
        }
        let permit = self
            .journal
            .begin_start(pod, StartKind::Run)
            .await
            .map_err(failure)?;
        let response = tokio::time::timeout(
            Duration::from_secs(120),
            super::runtime_observation::observe_run(
                launch.launch_id,
                self.upstream.clone().run_pod_sandbox(request),
            ),
        )
        .await;
        let result = async {
            let response = response
                .map_err(|_| failure("Unknown runtime timeout"))??
                .into_inner();
            let observer = self.observer.clone();
            let sandbox_id = response.pod_sandbox_id.clone();
            let observed =
                tokio::task::spawn_blocking(move || observer.capture(&sandbox_id, &launch))
                    .await
                    .map_err(failure)?
                    .map_err(failure)?;
            self.journal
                .settle(&permit, Some(&observed), None)
                .await
                .map_err(failure)?;
            Ok(response)
        }
        .await;
        if result.is_err() {
            let _ = self.journal.mark_unknown(&permit).await;
        }
        result
    }
    async fn create_owned(
        &self,
        request: CreateContainerRequest,
        pod: Uuid,
    ) -> Result<CreateContainerResponse, Status> {
        let launch = self.journal.launch(pod).await.map_err(failure)?;
        if request
            .config
            .as_ref()
            .is_none_or(|c| !controlled_container(c, &launch))
        {
            return Err(failure("Uncontrolled container"));
        }
        let sandbox_id = request.pod_sandbox_id.clone();
        let permit = self
            .journal
            .begin_start(pod, StartKind::Create)
            .await
            .map_err(failure)?;
        let result = async {
            let response = tokio::time::timeout(
                Duration::from_secs(120),
                self.upstream.clone().create_container(request),
            )
            .await
            .map_err(|_| failure("Unknown create timeout"))??
            .into_inner();
            self.journal
                .settle(&permit, None, Some((&response.container_id, &sandbox_id)))
                .await
                .map_err(failure)?;
            Ok(response)
        }
        .await;
        if result.is_err() {
            let _ = self.journal.mark_unknown(&permit).await;
        }
        result
    }
    async fn start_owned(
        &self,
        request: StartContainerRequest,
        pod: Uuid,
    ) -> Result<StartContainerResponse, Status> {
        let permit = self
            .journal
            .begin_start(pod, StartKind::Start)
            .await
            .map_err(failure)?;
        let result = async {
            let response = tokio::time::timeout(
                Duration::from_secs(120),
                self.upstream.clone().start_container(request),
            )
            .await
            .map_err(|_| failure("Unknown start timeout"))??
            .into_inner();
            self.journal
                .settle(&permit, None, None)
                .await
                .map_err(failure)?;
            Ok(response)
        }
        .await;
        if result.is_err() {
            let _ = self.journal.mark_unknown(&permit).await;
        }
        result
    }
}
fn controlled_container(config: &ContainerConfig, launch: &LaunchBinding) -> bool {
    super::backup_gate::controlled_container(config, launch)
}
fn purpose_labels_match(
    labels: &std::collections::HashMap<String, String>,
    launch: &LaunchBinding,
) -> bool {
    super::backup_gate::purpose_labels_match(labels, launch)
}
fn system_handler(value: &str) -> bool {
    matches!(value, "" | "runc")
}
fn managed_label(labels: &std::collections::HashMap<String, String>) -> bool {
    labels.contains_key("sandbox.platform/backup-id")
        || labels.contains_key("sandbox.platform/backup-attempt-id")
        || labels.contains_key("sandbox.platform/purpose")
        || labels.contains_key("sandbox.platform/instance-id")
        || labels
            .get("sandbox.platform/managed")
            .is_some_and(|v| v == "true")
}

#[tonic::async_trait]
impl super::cri_proto::runtime_service_server::RuntimeService for CriProxy {
    async fn run_pod_sandbox(
        &self,
        request: Request<RunPodSandboxRequest>,
    ) -> Result<Response<RunPodSandboxResponse>, Status> {
        self.owned_rpc(move |this| async move {
            let request = request.into_inner();
            let managed = request
                .config
                .as_ref()
                .is_some_and(|c| managed_label(&c.labels));
            if system_handler(&request.runtime_handler) && !managed {
                return this.upstream.clone().run_pod_sandbox(request).await;
            }
            if request.runtime_handler != "kata-qemu" {
                return Err(failure("Unsupported managed profile"));
            }
            this.run_owned(request).await.map(Response::new)
        })
        .await
    }
    async fn create_container(
        &self,
        request: Request<CreateContainerRequest>,
    ) -> Result<Response<CreateContainerResponse>, Status> {
        self.owned_rpc(move |this| async move {
            let request = request.into_inner();
            let Some(pod) = this.sandbox(&request.pod_sandbox_id).await? else {
                return this.upstream.clone().create_container(request).await;
            };
            this.create_owned(request, pod).await.map(Response::new)
        })
        .await
    }
    async fn start_container(
        &self,
        request: Request<StartContainerRequest>,
    ) -> Result<Response<StartContainerResponse>, Status> {
        self.owned_rpc(move |this| async move {
            let request = request.into_inner();
            let Some(pod) = this.container(&request.container_id).await? else {
                return this.upstream.clone().start_container(request).await;
            };
            this.start_owned(request, pod).await.map(Response::new)
        })
        .await
    }
    async fn version(
        &self,
        request: Request<VersionRequest>,
    ) -> Result<Response<VersionResponse>, Status> {
        self.read_rpc(move |this| async move { this.upstream.clone().version(request).await })
            .await
    }
    async fn stop_pod_sandbox(
        &self,
        request: Request<StopPodSandboxRequest>,
    ) -> Result<Response<StopPodSandboxResponse>, Status> {
        self.owned_rpc(
            move |this| async move { this.upstream.clone().stop_pod_sandbox(request).await },
        )
        .await
    }
    async fn remove_pod_sandbox(
        &self,
        request: Request<RemovePodSandboxRequest>,
    ) -> Result<Response<RemovePodSandboxResponse>, Status> {
        self.owned_rpc(move |this| async move {
            this.upstream.clone().remove_pod_sandbox(request).await
        })
        .await
    }
    async fn pod_sandbox_status(
        &self,
        request: Request<PodSandboxStatusRequest>,
    ) -> Result<Response<PodSandboxStatusResponse>, Status> {
        self.read_rpc(
            move |this| async move { this.upstream.clone().pod_sandbox_status(request).await },
        )
        .await
    }
    async fn list_pod_sandbox(
        &self,
        request: Request<ListPodSandboxRequest>,
    ) -> Result<Response<ListPodSandboxResponse>, Status> {
        self.read_rpc(
            move |this| async move { this.upstream.clone().list_pod_sandbox(request).await },
        )
        .await
    }
    type StreamPodSandboxesStream = super::cri_work::ReadStream<StreamPodSandboxesResponse>;
    async fn stream_pod_sandboxes(
        &self,
        request: Request<StreamPodSandboxesRequest>,
    ) -> Result<Response<Self::StreamPodSandboxesStream>, Status> {
        self.read_rpc(move |this| async move {
            this.upstream.clone().stream_pod_sandboxes(request).await
        })
        .await
        .map(|response| super::cri_work::read_stream_response(response, self.read_shutdown.clone()))
    }
    async fn stop_container(
        &self,
        request: Request<StopContainerRequest>,
    ) -> Result<Response<StopContainerResponse>, Status> {
        self.owned_rpc(
            move |this| async move { this.upstream.clone().stop_container(request).await },
        )
        .await
    }
    async fn remove_container(
        &self,
        request: Request<RemoveContainerRequest>,
    ) -> Result<Response<RemoveContainerResponse>, Status> {
        self.owned_rpc(
            move |this| async move { this.upstream.clone().remove_container(request).await },
        )
        .await
    }
    async fn list_containers(
        &self,
        request: Request<ListContainersRequest>,
    ) -> Result<Response<ListContainersResponse>, Status> {
        self.read_rpc(
            move |this| async move { this.upstream.clone().list_containers(request).await },
        )
        .await
    }
    type StreamContainersStream = super::cri_work::ReadStream<StreamContainersResponse>;
    async fn stream_containers(
        &self,
        request: Request<StreamContainersRequest>,
    ) -> Result<Response<Self::StreamContainersStream>, Status> {
        self.read_rpc(
            move |this| async move { this.upstream.clone().stream_containers(request).await },
        )
        .await
        .map(|response| super::cri_work::read_stream_response(response, self.read_shutdown.clone()))
    }
    async fn container_status(
        &self,
        request: Request<ContainerStatusRequest>,
    ) -> Result<Response<ContainerStatusResponse>, Status> {
        self.read_rpc(
            move |this| async move { this.upstream.clone().container_status(request).await },
        )
        .await
    }
    async fn update_container_resources(
        &self,
        request: Request<UpdateContainerResourcesRequest>,
    ) -> Result<Response<UpdateContainerResourcesResponse>, Status> {
        self.owned_rpc(move |this| async move {
            this.allow_container(&request.get_ref().container_id)
                .await?;
            this.upstream
                .clone()
                .update_container_resources(request)
                .await
        })
        .await
    }
    async fn reopen_container_log(
        &self,
        request: Request<ReopenContainerLogRequest>,
    ) -> Result<Response<ReopenContainerLogResponse>, Status> {
        self.owned_rpc(move |this| async move {
            this.allow_container(&request.get_ref().container_id)
                .await?;
            this.upstream.clone().reopen_container_log(request).await
        })
        .await
    }
    async fn exec_sync(
        &self,
        request: Request<ExecSyncRequest>,
    ) -> Result<Response<ExecSyncResponse>, Status> {
        self.owned_rpc(move |this| async move {
            this.allow_interactive_container(&request.get_ref().container_id)
                .await?;
            this.upstream.clone().exec_sync(request).await
        })
        .await
    }
    async fn exec(&self, request: Request<ExecRequest>) -> Result<Response<ExecResponse>, Status> {
        self.owned_rpc(move |this| async move {
            this.allow_interactive_container(&request.get_ref().container_id)
                .await?;
            this.upstream.clone().exec(request).await
        })
        .await
    }
    async fn attach(
        &self,
        request: Request<AttachRequest>,
    ) -> Result<Response<AttachResponse>, Status> {
        self.owned_rpc(move |this| async move {
            this.allow_interactive_container(&request.get_ref().container_id)
                .await?;
            this.upstream.clone().attach(request).await
        })
        .await
    }
    async fn port_forward(
        &self,
        request: Request<PortForwardRequest>,
    ) -> Result<Response<PortForwardResponse>, Status> {
        self.owned_rpc(move |this| async move {
            this.allow_sandbox(&request.get_ref().pod_sandbox_id)
                .await?;
            if let Some(pod) = this.sandbox(&request.get_ref().pod_sandbox_id).await?
                && !matches!(
                    this.journal.launch(pod).await.map_err(failure)?.purpose,
                    super::protocol::LaunchPurpose::Workload
                )
            {
                return Err(failure("Backup tasks expose no ports"));
            }
            this.upstream.clone().port_forward(request).await
        })
        .await
    }
    async fn container_stats(
        &self,
        request: Request<ContainerStatsRequest>,
    ) -> Result<Response<ContainerStatsResponse>, Status> {
        self.read_rpc(
            move |this| async move { this.upstream.clone().container_stats(request).await },
        )
        .await
    }
    async fn list_container_stats(
        &self,
        request: Request<ListContainerStatsRequest>,
    ) -> Result<Response<ListContainerStatsResponse>, Status> {
        self.read_rpc(move |this| async move {
            this.upstream.clone().list_container_stats(request).await
        })
        .await
    }
    type StreamContainerStatsStream = super::cri_work::ReadStream<StreamContainerStatsResponse>;
    async fn stream_container_stats(
        &self,
        request: Request<StreamContainerStatsRequest>,
    ) -> Result<Response<Self::StreamContainerStatsStream>, Status> {
        self.read_rpc(move |this| async move {
            this.upstream.clone().stream_container_stats(request).await
        })
        .await
        .map(|response| super::cri_work::read_stream_response(response, self.read_shutdown.clone()))
    }
    async fn pod_sandbox_stats(
        &self,
        request: Request<PodSandboxStatsRequest>,
    ) -> Result<Response<PodSandboxStatsResponse>, Status> {
        self.read_rpc(
            move |this| async move { this.upstream.clone().pod_sandbox_stats(request).await },
        )
        .await
    }
    async fn list_pod_sandbox_stats(
        &self,
        request: Request<ListPodSandboxStatsRequest>,
    ) -> Result<Response<ListPodSandboxStatsResponse>, Status> {
        self.read_rpc(move |this| async move {
            this.upstream.clone().list_pod_sandbox_stats(request).await
        })
        .await
    }
    type StreamPodSandboxStatsStream = super::cri_work::ReadStream<StreamPodSandboxStatsResponse>;
    async fn stream_pod_sandbox_stats(
        &self,
        request: Request<StreamPodSandboxStatsRequest>,
    ) -> Result<Response<Self::StreamPodSandboxStatsStream>, Status> {
        self.read_rpc(move |this| async move {
            this.upstream
                .clone()
                .stream_pod_sandbox_stats(request)
                .await
        })
        .await
        .map(|response| super::cri_work::read_stream_response(response, self.read_shutdown.clone()))
    }
    async fn update_runtime_config(
        &self,
        request: Request<UpdateRuntimeConfigRequest>,
    ) -> Result<Response<UpdateRuntimeConfigResponse>, Status> {
        self.owned_rpc(move |this| async move {
            this.upstream.clone().update_runtime_config(request).await
        })
        .await
    }
    async fn status(
        &self,
        request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        self.read_rpc(move |this| async move { this.upstream.clone().status(request).await })
            .await
    }
    async fn checkpoint_container(
        &self,
        request: Request<CheckpointContainerRequest>,
    ) -> Result<Response<CheckpointContainerResponse>, Status> {
        self.owned_rpc(move |this| async move {
            if this
                .container(&request.get_ref().container_id)
                .await?
                .is_some()
            {
                return Err(failure("Managed checkpoint is prohibited"));
            }
            this.upstream.clone().checkpoint_container(request).await
        })
        .await
    }
    type GetContainerEventsStream = super::cri_work::ReadStream<ContainerEventResponse>;
    async fn get_container_events(
        &self,
        request: Request<GetEventsRequest>,
    ) -> Result<Response<Self::GetContainerEventsStream>, Status> {
        self.read_rpc(move |this| async move {
            this.upstream.clone().get_container_events(request).await
        })
        .await
        .map(|response| super::cri_work::read_stream_response(response, self.read_shutdown.clone()))
    }
    async fn list_metric_descriptors(
        &self,
        request: Request<ListMetricDescriptorsRequest>,
    ) -> Result<Response<ListMetricDescriptorsResponse>, Status> {
        self.read_rpc(move |this| async move {
            this.upstream.clone().list_metric_descriptors(request).await
        })
        .await
    }
    async fn list_pod_sandbox_metrics(
        &self,
        request: Request<ListPodSandboxMetricsRequest>,
    ) -> Result<Response<ListPodSandboxMetricsResponse>, Status> {
        self.read_rpc(move |this| async move {
            this.upstream
                .clone()
                .list_pod_sandbox_metrics(request)
                .await
        })
        .await
    }
    type StreamPodSandboxMetricsStream =
        super::cri_work::ReadStream<StreamPodSandboxMetricsResponse>;
    async fn stream_pod_sandbox_metrics(
        &self,
        request: Request<StreamPodSandboxMetricsRequest>,
    ) -> Result<Response<Self::StreamPodSandboxMetricsStream>, Status> {
        self.read_rpc(move |this| async move {
            this.upstream
                .clone()
                .stream_pod_sandbox_metrics(request)
                .await
        })
        .await
        .map(|response| super::cri_work::read_stream_response(response, self.read_shutdown.clone()))
    }
    async fn runtime_config(
        &self,
        request: Request<RuntimeConfigRequest>,
    ) -> Result<Response<RuntimeConfigResponse>, Status> {
        self.read_rpc(
            move |this| async move { this.upstream.clone().runtime_config(request).await },
        )
        .await
    }
    async fn update_pod_sandbox_resources(
        &self,
        request: Request<UpdatePodSandboxResourcesRequest>,
    ) -> Result<Response<UpdatePodSandboxResourcesResponse>, Status> {
        self.owned_rpc(move |this| async move {
            this.allow_sandbox(&request.get_ref().pod_sandbox_id)
                .await?;
            this.upstream
                .clone()
                .update_pod_sandbox_resources(request)
                .await
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::super::cri_proto::runtime_service_server::{RuntimeService, RuntimeServiceServer};
    use super::*;
    use crate::nodeguard::protocol::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;
    struct Runtime {
        calls: Arc<AtomicUsize>,
        entered: Arc<Notify>,
        release: Arc<Notify>,
    }
    #[tonic::async_trait]
    impl RuntimeService for Runtime {
        async fn run_pod_sandbox(
            &self,
            request: Request<RunPodSandboxRequest>,
        ) -> Result<Response<RunPodSandboxResponse>, Status> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if request.get_ref().runtime_handler == "runc" {
                return Ok(Response::new(RunPodSandboxResponse {
                    pod_sandbox_id: "b".repeat(64),
                }));
            }
            self.entered.notify_one();
            self.release.notified().await;
            Err(Status::unavailable("injected ambiguous transport failure"))
        }
        async fn version(
            &self,
            _: Request<VersionRequest>,
        ) -> Result<Response<VersionResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn stop_pod_sandbox(
            &self,
            _: Request<StopPodSandboxRequest>,
        ) -> Result<Response<StopPodSandboxResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn remove_pod_sandbox(
            &self,
            _: Request<RemovePodSandboxRequest>,
        ) -> Result<Response<RemovePodSandboxResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn pod_sandbox_status(
            &self,
            _: Request<PodSandboxStatusRequest>,
        ) -> Result<Response<PodSandboxStatusResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn list_pod_sandbox(
            &self,
            _: Request<ListPodSandboxRequest>,
        ) -> Result<Response<ListPodSandboxResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        type StreamPodSandboxesStream =
            futures_util::stream::Empty<Result<StreamPodSandboxesResponse, Status>>;
        async fn stream_pod_sandboxes(
            &self,
            _: Request<StreamPodSandboxesRequest>,
        ) -> Result<Response<Self::StreamPodSandboxesStream>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn create_container(
            &self,
            _: Request<CreateContainerRequest>,
        ) -> Result<Response<CreateContainerResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn start_container(
            &self,
            _: Request<StartContainerRequest>,
        ) -> Result<Response<StartContainerResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn stop_container(
            &self,
            _: Request<StopContainerRequest>,
        ) -> Result<Response<StopContainerResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn remove_container(
            &self,
            _: Request<RemoveContainerRequest>,
        ) -> Result<Response<RemoveContainerResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn list_containers(
            &self,
            _: Request<ListContainersRequest>,
        ) -> Result<Response<ListContainersResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        type StreamContainersStream =
            futures_util::stream::Empty<Result<StreamContainersResponse, Status>>;
        async fn stream_containers(
            &self,
            _: Request<StreamContainersRequest>,
        ) -> Result<Response<Self::StreamContainersStream>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn container_status(
            &self,
            _: Request<ContainerStatusRequest>,
        ) -> Result<Response<ContainerStatusResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn update_container_resources(
            &self,
            _: Request<UpdateContainerResourcesRequest>,
        ) -> Result<Response<UpdateContainerResourcesResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn reopen_container_log(
            &self,
            _: Request<ReopenContainerLogRequest>,
        ) -> Result<Response<ReopenContainerLogResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn exec_sync(
            &self,
            _: Request<ExecSyncRequest>,
        ) -> Result<Response<ExecSyncResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn exec(&self, _: Request<ExecRequest>) -> Result<Response<ExecResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn attach(
            &self,
            _: Request<AttachRequest>,
        ) -> Result<Response<AttachResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn port_forward(
            &self,
            _: Request<PortForwardRequest>,
        ) -> Result<Response<PortForwardResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn container_stats(
            &self,
            _: Request<ContainerStatsRequest>,
        ) -> Result<Response<ContainerStatsResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn list_container_stats(
            &self,
            _: Request<ListContainerStatsRequest>,
        ) -> Result<Response<ListContainerStatsResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        type StreamContainerStatsStream =
            futures_util::stream::Empty<Result<StreamContainerStatsResponse, Status>>;
        async fn stream_container_stats(
            &self,
            _: Request<StreamContainerStatsRequest>,
        ) -> Result<Response<Self::StreamContainerStatsStream>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn pod_sandbox_stats(
            &self,
            _: Request<PodSandboxStatsRequest>,
        ) -> Result<Response<PodSandboxStatsResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn list_pod_sandbox_stats(
            &self,
            _: Request<ListPodSandboxStatsRequest>,
        ) -> Result<Response<ListPodSandboxStatsResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        type StreamPodSandboxStatsStream =
            futures_util::stream::Empty<Result<StreamPodSandboxStatsResponse, Status>>;
        async fn stream_pod_sandbox_stats(
            &self,
            _: Request<StreamPodSandboxStatsRequest>,
        ) -> Result<Response<Self::StreamPodSandboxStatsStream>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn update_runtime_config(
            &self,
            _: Request<UpdateRuntimeConfigRequest>,
        ) -> Result<Response<UpdateRuntimeConfigResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn status(
            &self,
            _: Request<StatusRequest>,
        ) -> Result<Response<StatusResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn checkpoint_container(
            &self,
            _: Request<CheckpointContainerRequest>,
        ) -> Result<Response<CheckpointContainerResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        type GetContainerEventsStream =
            futures_util::stream::Empty<Result<ContainerEventResponse, Status>>;
        async fn get_container_events(
            &self,
            _: Request<GetEventsRequest>,
        ) -> Result<Response<Self::GetContainerEventsStream>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn list_metric_descriptors(
            &self,
            _: Request<ListMetricDescriptorsRequest>,
        ) -> Result<Response<ListMetricDescriptorsResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn list_pod_sandbox_metrics(
            &self,
            _: Request<ListPodSandboxMetricsRequest>,
        ) -> Result<Response<ListPodSandboxMetricsResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        type StreamPodSandboxMetricsStream =
            futures_util::stream::Empty<Result<StreamPodSandboxMetricsResponse, Status>>;
        async fn stream_pod_sandbox_metrics(
            &self,
            _: Request<StreamPodSandboxMetricsRequest>,
        ) -> Result<Response<Self::StreamPodSandboxMetricsStream>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn runtime_config(
            &self,
            _: Request<RuntimeConfigRequest>,
        ) -> Result<Response<RuntimeConfigResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
        async fn update_pod_sandbox_resources(
            &self,
            _: Request<UpdatePodSandboxResourcesRequest>,
        ) -> Result<Response<UpdatePodSandboxResourcesResponse>, Status> {
            Err(Status::unimplemented("test runtime"))
        }
    }
    fn registration() -> RegisterLaunchRequest {
        let workspace_id = Uuid::new_v4();
        RegisterLaunchRequest {
            protocol: 1,
            permit_id: Uuid::new_v4(),
            node: NodeBinding {
                cluster_epoch: Uuid::new_v4(),
                node_uid: Uuid::new_v4(),
                node_name: "node-1".into(),
                boot_id: Uuid::new_v4(),
                profile_sha256: "a".repeat(64),
            },
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
            launch: LaunchBinding {
                purpose: crate::nodeguard::protocol::LaunchPurpose::Workload,
                tenant_id: Uuid::new_v4(),
                project_id: Uuid::new_v4(),
                instance_id: Uuid::new_v4(),
                workspace_id,
                generation: 1,
                launch_id: Uuid::new_v4(),
                pod_uid: Uuid::new_v4(),
                namespace: "sandbox-test".into(),
                pod_name: format!("sbx-ws-{workspace_id}"),
                pvc_uid: Uuid::new_v4(),
                pv_uid: Uuid::new_v4(),
                pv_name: "pvc-test".into(),
                csi_volume_handle: "d-test".into(),
            },
        }
    }
    fn run(r: &RegisterLaunchRequest) -> RunPodSandboxRequest {
        RunPodSandboxRequest {
            runtime_handler: "kata-qemu".into(),
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: r.launch.pod_name.clone(),
                    namespace: r.launch.namespace.clone(),
                    uid: r.launch.pod_uid.to_string(),
                    attempt: 0,
                }),
                linux: Some(LinuxPodSandboxConfig {
                    cgroup_parent: format!(
                        "/kubepods.slice/kubepods-pod{}.slice",
                        r.launch.pod_uid.to_string().replace('-', "_")
                    ),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        }
    }
    #[tokio::test]
    async fn real_grpc_closed_gate_and_cancelled_caller_never_replay_ambiguous_run()
    -> anyhow::Result<()> {
        let calls = Arc::new(AtomicUsize::new(0));
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let incoming = futures_util::stream::unfold(listener, |l| async {
            let item = l.accept().await.map(|(s, _)| s);
            Some((item, l))
        });
        let server = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(RuntimeServiceServer::new(Runtime {
                    calls: calls.clone(),
                    entered: entered.clone(),
                    release: release.clone(),
                }))
                .serve_with_incoming(incoming),
        );
        let r = registration();
        let directory = tempfile::tempdir()?;
        let journal =
            GateJournal::open(&directory.path().join("journal.sqlite3"), r.node.clone()).await?;
        journal.verify_coverage().await?;
        journal.register(&r).await?;
        let channel = Endpoint::from_shared(format!("http://{address}"))?
            .connect()
            .await?;
        let proxy = CriProxy {
            journal,
            observer: Arc::new(HostObserver::test_unobserved(r.node.clone())),
            upstream: RuntimeServiceClient::new(channel),
            tasks: TaskTracker::new(),
            read_shutdown: CancellationToken::new(),
        };
        let mut system = run(&r);
        system.runtime_handler = "runc".into();
        assert!(proxy.run_pod_sandbox(Request::new(system)).await.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let request = run(&r);
        let handle = {
            let p = proxy.clone();
            tokio::spawn(async move { p.run_pod_sandbox(Request::new(request)).await })
        };
        entered.notified().await;
        handle.abort();
        let close = CloseRequest {
            protocol: 1,
            challenge_id: Uuid::new_v4(),
            node: r.node.clone(),
            launch: r.launch.clone(),
            reason: CloseReason::Stop,
            challenge_expires_at: chrono::Utc::now() + chrono::Duration::minutes(1),
        };
        assert_eq!(
            proxy.journal.close(&close).await?.state,
            ObservationState::WaitingInFlight
        );
        assert!(proxy.run_pod_sandbox(Request::new(run(&r))).await.is_err());
        release.notify_one();
        proxy.tasks.close();
        tokio::time::timeout(Duration::from_secs(5), proxy.tasks.wait()).await?;
        assert_eq!(
            proxy.journal.close(&close).await?.state,
            ObservationState::UnknownStart
        );
        assert!(proxy.run_pod_sandbox(Request::new(run(&r))).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        server.abort();
        Ok(())
    }
}
