//! Host control API. The executable serves this router exclusively behind the
//! bounded `tls::serve_control` transport and dedicated controller-client CA;
//! ordinary application JWTs are never accepted.
use std::{
    io,
    sync::{Arc, OnceLock},
};
use tokio::sync::Semaphore;
use tokio_util::task::TaskTracker;

const MAX_OBSERVER_WORK: usize = 16;
static OBSERVER_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();

/// The permit belongs to the blocking closure, never its HTTP awaiter. A
/// disconnected controller cannot admit another task while kernel work from
/// its previous request still runs. No queue grows behind a blocked observer.
async fn observer_work<F, T>(tasks: &TaskTracker, work: F) -> io::Result<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let token = tasks.token();
    if tasks.is_closed() {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "Host observer is draining",
        ));
    }
    let permit = OBSERVER_SLOTS
        .get_or_init(|| Arc::new(Semaphore::new(MAX_OBSERVER_WORK)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "Host observer capacity exhausted",
            )
        })?;
    tokio::task::spawn_blocking(move || {
        // Register before checking closure. A concurrent drain either sees
        // this task until actual exit, or this call rejects all host I/O.
        let _token = token;
        let _permit = permit;
        work()
    })
    .await
    .map_err(|_| io::Error::other("Host observation did not complete"))
}

#[cfg(test)]
static TEST_WORK_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(target_os = "linux")]
pub use linux::router;

#[cfg(target_os = "linux")]
mod linux {
    use super::observer_work;
    use crate::nodeguard::{GuardError, cri::CriProxy, protocol::*};
    use axum::{
        Json, Router,
        extract::{DefaultBodyLimit, State},
        http::StatusCode,
        response::{IntoResponse, Response},
        routing::{get, post},
    };
    use chrono::Utc;
    use futures_util::{StreamExt, stream};
    use std::{sync::Arc, time::Duration};

    pub fn router(proxy: Arc<CriProxy>) -> Router {
        Router::new()
            .route("/v1/node", get(identity))
            .route("/v1/launches/register", post(register))
            .route("/v1/launches/close", post(close))
            .layer(DefaultBodyLimit::max(MAX_CONTROL_BODY))
            .with_state(proxy)
    }
    async fn identity(State(proxy): State<Arc<CriProxy>>) -> Json<NodeIdentityResponse> {
        Json(NodeIdentityResponse {
            protocol: PROTOCOL_VERSION,
            node: proxy.journal.node().clone(),
        })
    }
    async fn register(
        State(proxy): State<Arc<CriProxy>>,
        Json(request): Json<RegisterLaunchRequest>,
    ) -> Result<Json<RegisterLaunchResponse>, ControlError> {
        let _request = request_token(&proxy)?;
        Ok(Json(proxy.journal.register(&request).await?))
    }
    async fn close(
        State(proxy): State<Arc<CriProxy>>,
        Json(request): Json<CloseRequest>,
    ) -> Result<Json<CloseResponse>, ControlError> {
        let _request = request_token(&proxy)?;
        let snapshot = proxy.journal.close(&request).await?;
        let mut response = CloseResponse {
            protocol: PROTOCOL_VERSION,
            challenge_id: request.challenge_id,
            node: snapshot.node.clone(),
            launch: snapshot.launch.clone(),
            state: snapshot.state,
            observed_at: Utc::now(),
            evidence: None,
        };
        if matches!(
            snapshot.state,
            ObservationState::UnknownStart | ObservationState::WaitingInFlight
        ) {
            return Ok(Json(response));
        }
        if let Some(mut saved) = proxy
            .journal
            .saved_termination(snapshot.launch.pod_uid)
            .await?
        {
            if saved.forwarded_starts != snapshot.forwarded_starts
                || saved.observed_sandboxes != snapshot.sandboxes
                || saved.closed_at != snapshot.closed_at
                || snapshot.forwarded_starts != snapshot.sandboxes.len() as u64
            {
                return Err(ControlError(GuardError::IdentityMismatch));
            }
            saved.journal_revision = snapshot.revision;
            // Death under an irrevocably closed gate is irreversible. Mount absence
            // is not: a delayed CSI NodePublish may have mounted since the last call.
            let observer = proxy.observer.clone();
            let launch = snapshot.launch.clone();
            let observations = saved.observed_sandboxes.clone();
            let absent = observer_work(&proxy.tasks, move || {
                // A preceding request may have committed death before losing
                // its connection or cleanup slot. Retry must release the same
                // pinned handles, even if that first request never acknowledged.
                observer.release_handles(&observations)?;
                observer.mounts_absent(&launch)
            })
            .await??;
            response.observed_at = Utc::now();
            if response.observed_at >= request.challenge_expires_at {
                return Err(ControlError(GuardError::Expired));
            }
            if absent {
                saved.pod_mounts_absent_at = response.observed_at;
                response.state = ObservationState::Terminated;
                response.evidence = Some(saved);
            } else {
                response.state = ObservationState::WaitingUnmount;
            }
            return Ok(Json(response));
        }
        if snapshot.forwarded_starts != snapshot.sandboxes.len() as u64 {
            response.state = ObservationState::UnknownStart;
            return Ok(Json(response));
        }
        // Stop RPC completion is deliberately ignored as evidence. The kernel-side
        // checks below must independently establish death of every registered VM.
        let upstream = proxy.upstream.clone();
        let sandbox_ids: Vec<String> = snapshot
            .sandboxes
            .iter()
            .map(|s| s.sandbox_id.clone())
            .collect();
        stream::iter(sandbox_ids)
            .map(|id| {
                let mut upstream = upstream.clone();
                async move {
                    let _ = tokio::time::timeout(
                        Duration::from_secs(3),
                        upstream.stop_pod_sandbox(
                            crate::nodeguard::cri_proto::StopPodSandboxRequest {
                                pod_sandbox_id: id,
                            },
                        ),
                    )
                    .await;
                }
            })
            .buffer_unordered(MAX_SANDBOX_ATTEMPTS)
            .collect::<Vec<_>>()
            .await;
        let observer = proxy.observer.clone();
        let observations = snapshot.sandboxes.clone();
        let deadline = std::time::Instant::now() + Duration::from_secs(4);
        let exited = observer_work(&proxy.tasks, move || {
            observer.terminate(&observations, deadline)
        })
        .await??;
        if !exited {
            response.state = ObservationState::WaitingProcessExit;
            response.observed_at = Utc::now();
            return Ok(Json(response));
        }
        let exited_at = Utc::now();
        let observer = proxy.observer.clone();
        let launch = snapshot.launch.clone();
        let absent = observer_work(&proxy.tasks, move || observer.mounts_absent(&launch)).await??;
        if !absent {
            response.state = ObservationState::WaitingUnmount;
            response.observed_at = Utc::now();
            return Ok(Json(response));
        }
        let absent_at = Utc::now();
        if absent_at >= request.challenge_expires_at {
            return Err(ControlError(GuardError::Expired));
        }
        response.state = ObservationState::Terminated;
        response.evidence = Some(LocalTerminationEvidence {
            journal_revision: snapshot.revision,
            observed_sandboxes: snapshot.sandboxes,
            forwarded_starts: snapshot.forwarded_starts,
            closed_at: snapshot.closed_at,
            processes_exited_at: exited_at,
            pod_mounts_absent_at: absent_at,
        });
        proxy
            .journal
            .save_termination(
                snapshot.launch.pod_uid,
                response
                    .evidence
                    .as_ref()
                    .ok_or(ControlError(GuardError::Unknown))?,
            )
            .await?;
        let observer = proxy.observer.clone();
        let observations = response
            .evidence
            .as_ref()
            .ok_or(ControlError(GuardError::Unknown))?
            .observed_sandboxes
            .clone();
        observer_work(&proxy.tasks, move || {
            observer.release_handles(&observations)
        })
        .await??;
        response.observed_at = Utc::now();
        if response.observed_at >= request.challenge_expires_at {
            return Err(ControlError(GuardError::Expired));
        }
        Ok(Json(response))
    }
    struct ControlError(GuardError);
    fn request_token(
        proxy: &CriProxy,
    ) -> Result<tokio_util::task::task_tracker::TaskTrackerToken, ControlError> {
        let token = proxy.tasks.token();
        if proxy.tasks.is_closed() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Host control is draining",
            )
            .into());
        }
        Ok(token)
    }
    impl From<std::io::Error> for ControlError {
        fn from(value: std::io::Error) -> Self {
            Self(GuardError::Io(value))
        }
    }
    impl From<GuardError> for ControlError {
        fn from(value: GuardError) -> Self {
            Self(value)
        }
    }
    impl IntoResponse for ControlError {
        fn into_response(self) -> Response {
            let (status, code) = match self.0 {
                GuardError::Invalid => (StatusCode::BAD_REQUEST, "INVALID_IDENTITY"),
                GuardError::IdentityMismatch => (StatusCode::CONFLICT, "IDENTITY_MISMATCH"),
                GuardError::Closed | GuardError::InFlight | GuardError::Unknown => {
                    (StatusCode::CONFLICT, "GUARD_CLOSED")
                }
                GuardError::Expired => (StatusCode::CONFLICT, "EXPIRED_CHALLENGE"),
                _ => (StatusCode::SERVICE_UNAVAILABLE, "GUARD_UNAVAILABLE"),
            };
            (status, Json(serde_json::json!({"error":code}))).into_response()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::nodeguard::{host::HostObserver, journal::GateJournal};
        use axum::{body::Body, http::Request};
        use tonic::transport::Endpoint;
        use tower::ServiceExt;
        use uuid::Uuid;

        async fn post(app: Router, request: &CloseRequest) -> anyhow::Result<CloseResponse> {
            let response = app
                .oneshot(
                    Request::post("/v1/launches/close")
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_vec(request)?))?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), MAX_CONTROL_BODY).await?;
            Ok(serde_json::from_slice(&body)?)
        }
        #[tokio::test]
        async fn never_started_control_route_persists_death_and_refreshes_mount_observation()
        -> anyhow::Result<()> {
            let _test_lock = super::super::TEST_WORK_LOCK.lock().await;
            let node = NodeBinding {
                cluster_epoch: Uuid::new_v4(),
                node_uid: Uuid::new_v4(),
                node_name: "node-test".into(),
                boot_id: Uuid::parse_str(
                    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
                )?,
                profile_sha256: "a".repeat(64),
            };
            let workspace_id = Uuid::new_v4();
            let launch = LaunchBinding {
                purpose: crate::nodeguard::protocol::LaunchPurpose::Workload,
                tenant_id: Uuid::new_v4(),
                project_id: Uuid::new_v4(),
                instance_id: Uuid::new_v4(),
                workspace_id,
                generation: 1,
                launch_id: Uuid::new_v4(),
                pod_uid: Uuid::new_v4(),
                namespace: "project-test".into(),
                pod_name: format!("sbx-ws-{workspace_id}"),
                pvc_uid: Uuid::new_v4(),
                pv_uid: Uuid::new_v4(),
                pv_name: "pv-test".into(),
                csi_volume_handle: "d-test".into(),
            };
            let dir = tempfile::tempdir()?;
            let journal =
                GateJournal::open(&dir.path().join("state.sqlite3"), node.clone()).await?;
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
            let proxy = Arc::new(CriProxy {
                journal: journal.clone(),
                observer: Arc::new(HostObserver::test_unobserved(node.clone())),
                upstream:
                    crate::nodeguard::cri_proto::runtime_service_client::RuntimeServiceClient::new(
                        Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
                    ),
                tasks: tokio_util::task::TaskTracker::new(),
                read_shutdown: tokio_util::sync::CancellationToken::new(),
            });
            let request = CloseRequest {
                protocol: 1,
                challenge_id: Uuid::new_v4(),
                node,
                launch,
                reason: CloseReason::Stop,
                challenge_expires_at: Utc::now() + chrono::Duration::seconds(30),
            };
            let first = post(router(proxy.clone()), &request).await?;
            assert_eq!(first.state, ObservationState::Terminated);
            let evidence = first
                .evidence
                .ok_or_else(|| anyhow::anyhow!("missing local evidence"))?;
            assert_eq!(evidence.forwarded_starts, 0);
            assert!(evidence.observed_sandboxes.is_empty());
            let mut second_request = request.clone();
            second_request.challenge_id = Uuid::new_v4();
            let second = post(router(proxy.clone()), &second_request).await?;
            let second_evidence = second
                .evidence
                .ok_or_else(|| anyhow::anyhow!("missing cached death"))?;
            assert_eq!(
                second_evidence.processes_exited_at,
                evidence.processes_exited_at
            );
            assert!(second_evidence.journal_revision > evidence.journal_revision);
            assert!(second_evidence.pod_mounts_absent_at > evidence.pod_mounts_absent_at);
            assert!(second.observed_at >= second_evidence.pod_mounts_absent_at);
            assert!(journal.require_open(request.launch.pod_uid).await.is_err());
            let mut expired = request;
            expired.challenge_expires_at = Utc::now() - chrono::Duration::seconds(1);
            let result = router(proxy)
                .oneshot(
                    Request::post("/v1/launches/close")
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_vec(&expired)?))?,
                )
                .await?;
            assert_eq!(result.status(), StatusCode::CONFLICT);
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod work_tests;
