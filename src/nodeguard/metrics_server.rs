//! Dedicated read-only scrape surface. Serve only with its own scraper-client
//! CA, never the controller CA and never on the CRI control router.
use super::{GuardError, cri::CriProxy};
use crate::metrics::{RuntimeMetric, RuntimeMetricBinding};
use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use std::{
    collections::BTreeSet,
    fmt::Write,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone)]
struct MetricsState {
    proxy: Arc<CriProxy>,
    deployment: String,
    slots: Arc<tokio::sync::Semaphore>,
}

pub fn router(proxy: Arc<CriProxy>, deployment: String) -> Result<Router, GuardError> {
    if deployment.is_empty()
        || deployment.len() > 63
        || !deployment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        return Err(GuardError::Invalid);
    }
    Ok(Router::new()
        .route("/metrics", get(scrape))
        .with_state(MetricsState {
            proxy,
            deployment,
            slots: Arc::new(tokio::sync::Semaphore::new(1)),
        }))
}
async fn scrape(State(state): State<MetricsState>) -> Response {
    let result = async {
        let slot = state
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| GuardError::Unknown)?;
        let observations = state.proxy.journal.metric_observations().await?;
        let node = state.proxy.journal.node().clone();
        let observer = state.proxy.observer.clone();
        tokio::task::spawn_blocking(move || {
            let _slot=slot;
            let deadline=Instant::now()+Duration::from_secs(2);
            let mut output=String::new();
            for (metric,kind,help) in [
                (RuntimeMetric::VmCpuCores,"counter","CPU seconds charged to the host VM cgroup including virtualization overhead."),
                (RuntimeMetric::VmMemoryBytes,"gauge","Bytes in host VM cgroup memory.current including cache."),
                (RuntimeMetric::VmIoReadBytesPerSecond,"counter","Sum of host VM cgroup io.stat rbytes across devices."),
                (RuntimeMetric::VmIoWriteBytesPerSecond,"counter","Sum of host VM cgroup io.stat wbytes across devices."),
                (RuntimeMetric::VmTasks,"gauge","Host tasks (threads) in the VM cgroup, not guest processes."),
            ] {
                writeln!(output,"# HELP {} {help}\n# TYPE {} {kind}",metric.name(),metric.name()).map_err(|_|GuardError::Unknown)?;
            }
            output.push_str("# HELP sandbox_vm_observation_success Whether this scrape obtained all bound host counters; never a health or termination proof.\n# TYPE sandbox_vm_observation_success gauge\n");
            let mut seen=BTreeSet::new();
            for (launch,observation) in observations {
                if Instant::now()>=deadline { return Err(GuardError::Expired) }
                if !seen.insert((launch.tenant_id,launch.instance_id,launch.generation,launch.launch_id)) { return Err(GuardError::IdentityMismatch) }
                let binding=RuntimeMetricBinding{tenant_id:launch.tenant_id,project_id:launch.project_id,instance_id:launch.instance_id,generation:launch.generation,launch_id:launch.launch_id,cluster_epoch:node.cluster_epoch,node_uid:node.node_uid,host_boot_id:node.boot_id};
                let labels=binding.labels(&state.deployment).map_err(|_|GuardError::Invalid)?.iter().map(|(k,v)|format!("{k}=\"{v}\"")).collect::<Vec<_>>().join(",");
                if let Ok(c)=observer.metrics(&observation) {
                    for (metric,value) in [
                        (RuntimeMetric::VmCpuCores,c.cpu_usage_usec as f64/1_000_000.0),
                        (RuntimeMetric::VmMemoryBytes,c.memory_bytes as f64),
                        (RuntimeMetric::VmIoReadBytesPerSecond,c.io_read_bytes as f64),
                        (RuntimeMetric::VmIoWriteBytesPerSecond,c.io_write_bytes as f64),
                        (RuntimeMetric::VmTasks,c.tasks as f64),
                    ] { writeln!(output,"{}{{{labels}}} {value}",metric.name()).map_err(|_|GuardError::Unknown)?; }
                    writeln!(output,"sandbox_vm_observation_success{{{labels}}} 1").map_err(|_|GuardError::Unknown)?;
                } else {
                    // Failed reads must not become a new zero resource sample.
                    writeln!(output,"sandbox_vm_observation_success{{{labels}}} 0").map_err(|_|GuardError::Unknown)?;
                }
                if output.len()>2*1024*1024 { return Err(GuardError::Unknown) }
            }
            Ok::<_,GuardError>(output)
        }).await.map_err(|_|GuardError::Unknown)?
    };
    match tokio::time::timeout(Duration::from_secs(3), result).await {
        Ok(Ok(output)) => (
            [
                ("content-type", "text/plain; version=0.0.4; charset=utf-8"),
                ("cache-control", "no-store"),
            ],
            output,
        )
            .into_response(),
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nodeguard::{
        host::HostObserver,
        journal::{GateJournal, StartKind},
        protocol::*,
    };
    use chrono::Utc;
    use uuid::Uuid;
    async fn listen(
        app: Router,
        ca: &[u8],
    ) -> anyhow::Result<(
        String,
        axum_server::Handle<std::net::SocketAddr>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    )> {
        let tls = crate::tls::mutual_tls(
            include_bytes!("../../tests/fixtures/admission/server.pem"),
            include_bytes!("../../tests/fixtures/admission/server.key"),
            ca,
        )?;
        let tcp = std::net::TcpListener::bind("127.0.0.1:0")?;
        tcp.set_nonblocking(true)?;
        let address = tcp.local_addr()?;
        let handle = axum_server::Handle::new();
        let stop = handle.clone();
        let server = axum_server::from_tcp_rustls(tcp, tls)?
            .handle(handle)
            .serve(app.into_make_service());
        Ok((format!("https://{address}"), stop, tokio::spawn(server)))
    }
    fn client(identity: Option<(&[u8], &[u8])>) -> anyhow::Result<reqwest::Client> {
        let mut c = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(reqwest::Certificate::from_pem(include_bytes!(
                "../../tests/fixtures/admission/server-ca.pem"
            ))?);
        if let Some((certificate, key)) = identity {
            c = c.identity(reqwest::Identity::from_pem(&[certificate, key].concat())?);
        }
        Ok(c.build()?)
    }
    #[tokio::test]
    async fn dedicated_scraper_certificate_cannot_reach_control_and_unknown_observation_is_not_zero()
    -> anyhow::Result<()> {
        let node = NodeBinding {
            cluster_epoch: Uuid::new_v4(),
            node_uid: Uuid::new_v4(),
            node_name: "test-host".into(),
            boot_id: Uuid::new_v4(),
            profile_sha256: "a".repeat(64),
        };
        let workspace = Uuid::new_v4();
        let launch = LaunchBinding {
            purpose: LaunchPurpose::Workload,
            tenant_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            instance_id: Uuid::new_v4(),
            workspace_id: workspace,
            generation: 1,
            launch_id: Uuid::new_v4(),
            pod_uid: Uuid::new_v4(),
            namespace: "test-project".into(),
            pod_name: format!("sbx-ws-{workspace}"),
            pvc_uid: Uuid::new_v4(),
            pv_uid: Uuid::new_v4(),
            pv_name: "pvc-test".into(),
            csi_volume_handle: "d-test".into(),
        };
        let dir = tempfile::tempdir()?;
        let journal = GateJournal::open(&dir.path().join("state.sqlite3"), node.clone()).await?;
        journal.verify_coverage().await?;
        journal
            .register(&RegisterLaunchRequest {
                protocol: 1,
                permit_id: Uuid::new_v4(),
                node: node.clone(),
                launch: launch.clone(),
                expires_at: Utc::now() + chrono::Duration::minutes(1),
            })
            .await?;
        let permit = journal.begin_start(launch.pod_uid, StartKind::Run).await?;
        journal
            .settle(
                &permit,
                Some(&SandboxObservation {
                    sandbox_id: "a".repeat(64),
                    cgroup: CgroupIdentity {
                        relative_path: "test/not-observed".into(),
                        device: 1,
                        inode: 2,
                    },
                    processes: vec![ProcessIdentity {
                        role: ProcessRole::Hypervisor,
                        pid: 999,
                        start_time_ticks: 1,
                        executable_sha256: "a".repeat(64),
                    }],
                    registered_at: Utc::now(),
                }),
                None,
            )
            .await?;
        let proxy = Arc::new(CriProxy {
            journal: journal.clone(),
            observer: Arc::new(HostObserver::test_unobserved(node)),
            upstream: super::super::cri_proto::runtime_service_client::RuntimeServiceClient::new(
                tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
            ),
            tasks: tokio_util::task::TaskTracker::new(),
            read_shutdown: tokio_util::sync::CancellationToken::new(),
        });
        let (metrics, stop_metrics, metrics_task) = listen(
            router(proxy.clone(), "production-a".into())?,
            include_bytes!("../../tests/fixtures/admission/apiserver-ca.pem"),
        )
        .await?;
        let (control, stop_control, control_task) = listen(
            super::super::server::router(proxy),
            include_bytes!("../../tests/fixtures/nodeguard/client-ca.pem"),
        )
        .await?;
        let result = async {
            let scraper = client(Some((
                include_bytes!("../../tests/fixtures/admission/apiserver.pem"),
                include_bytes!("../../tests/fixtures/admission/apiserver.key"),
            )))?;
            let controller = client(Some((
                include_bytes!("../../tests/fixtures/nodeguard/client.pem"),
                include_bytes!("../../tests/fixtures/nodeguard/client.key"),
            )))?;
            let anonymous = client(None)?;
            assert!(
                anonymous
                    .get(format!("{metrics}/metrics"))
                    .send()
                    .await
                    .is_err()
            );
            assert!(
                controller
                    .get(format!("{metrics}/metrics"))
                    .send()
                    .await
                    .is_err()
            );
            assert!(
                scraper
                    .get(format!("{control}/v1/node"))
                    .send()
                    .await
                    .is_err()
            );
            assert_eq!(
                controller
                    .get(format!("{control}/v1/node"))
                    .send()
                    .await?
                    .status(),
                200
            );
            assert_eq!(
                scraper
                    .post(format!("{metrics}/v1/launches/close"))
                    .send()
                    .await?
                    .status(),
                404
            );
            let response = scraper.get(format!("{metrics}/metrics")).send().await?;
            assert_eq!(response.status(), 200);
            let text = response.text().await?;
            assert!(
                text.lines()
                    .any(|l| l.starts_with("sandbox_vm_observation_success{") && l.ends_with(" 0"))
            );
            assert!(!text.contains("sandbox_vm_cpu_seconds_total{"));
            assert!(!text.contains("sandbox_vm_memory_bytes{"));
            journal.require_open(launch.pod_uid).await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        stop_metrics.graceful_shutdown(Some(Duration::from_secs(1)));
        stop_control.graceful_shutdown(Some(Duration::from_secs(1)));
        metrics_task.await??;
        control_task.await??;
        result
    }
}
