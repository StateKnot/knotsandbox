//! Actual H2/mTLS cancellation and SQLite closure, with an explicitly controlled
//! blocking kernel-work stand-in. This does not certify Linux/Kata observations.
use super::*;
use crate::nodeguard::{journal::GateJournal, protocol::*};
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use chrono::Utc;
use std::{
    sync::{
        Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Default)]
struct BlockingWork {
    release: Mutex<bool>,
    changed: Condvar,
}
impl BlockingWork {
    fn run(&self) {
        let mut released = self
            .release
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !*released {
            released = self
                .changed
                .wait(released)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
    fn release(&self) {
        *self
            .release
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.changed.notify_all();
    }
}
// A failing assertion must still release every non-cancellable test closure.
struct ReleaseOnDrop(Arc<BlockingWork>);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}
struct RequestDrop(Arc<AtomicUsize>);
impl Drop for RequestDrop {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
#[derive(Clone)]
struct WorkState {
    tasks: TaskTracker,
    work: Arc<BlockingWork>,
    entered: tokio::sync::mpsc::UnboundedSender<()>,
    dropped: Arc<AtomicUsize>,
    proofs: Arc<AtomicUsize>,
    journal: GateJournal,
}
async fn observe(State(state): State<WorkState>, Json(request): Json<CloseRequest>) -> StatusCode {
    let _drop = RequestDrop(state.dropped.clone());
    let Ok(snapshot) = state.journal.close(&request).await else {
        return StatusCode::CONFLICT;
    };
    let work = state.work.clone();
    let entered = state.entered.clone();
    if observer_work(&state.tasks, move || {
        let _ = entered.send(());
        work.run();
    })
    .await
    .is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    // Only the still-live HTTP awaiter can reach this durable proof step.
    let at = Utc::now();
    if state
        .journal
        .save_termination(
            request.launch.pod_uid,
            &LocalTerminationEvidence {
                journal_revision: snapshot.revision,
                forwarded_starts: snapshot.forwarded_starts,
                observed_sandboxes: snapshot.sandboxes,
                closed_at: snapshot.closed_at,
                processes_exited_at: at,
                pod_mounts_absent_at: at,
            },
        )
        .await
        .is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    state.proofs.fetch_add(1, Ordering::SeqCst);
    StatusCode::OK
}
async fn listen(
    state: WorkState,
) -> anyhow::Result<(
    std::net::SocketAddr,
    CancellationToken,
    tokio::task::JoinHandle<io::Result<()>>,
)> {
    listen_router(
        Router::new()
            .route("/observe", post(observe))
            .with_state(state),
    )
    .await
}
async fn listen_router(
    app: Router,
) -> anyhow::Result<(
    std::net::SocketAddr,
    CancellationToken,
    tokio::task::JoinHandle<io::Result<()>>,
)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let cancel = CancellationToken::new();
    let task = tokio::spawn(crate::tls::serve_control(
        listener,
        crate::tls::control_mutual_tls(
            include_bytes!("../../tests/fixtures/admission/server.pem"),
            include_bytes!("../../tests/fixtures/admission/server.key"),
            include_bytes!("../../tests/fixtures/admission/apiserver-ca.pem"),
        )?,
        app,
        cancel.clone(),
    ));
    Ok((address, cancel, task))
}
fn client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(10))
        .add_root_certificate(reqwest::Certificate::from_pem(include_bytes!(
            "../../tests/fixtures/admission/server-ca.pem"
        ))?)
        .identity(reqwest::Identity::from_pem(
            &[
                include_bytes!("../../tests/fixtures/admission/apiserver.pem").as_slice(),
                include_bytes!("../../tests/fixtures/admission/apiserver.key").as_slice(),
            ]
            .concat(),
        )?)
        .build()?)
}
async fn requests_dropped(dropped: &AtomicUsize, count: usize) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        while dropped.load(Ordering::SeqCst) < count {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(())
}

fn fixture_registration() -> RegisterLaunchRequest {
    let node = NodeBinding {
        cluster_epoch: Uuid::new_v4(),
        node_uid: Uuid::new_v4(),
        node_name: "public-work-fixture".into(),
        boot_id: Uuid::new_v4(),
        profile_sha256: "a".repeat(64),
    };
    let workspace_id = Uuid::new_v4();
    RegisterLaunchRequest {
        protocol: PROTOCOL_VERSION,
        permit_id: Uuid::new_v4(),
        node: node.clone(),
        launch: LaunchBinding {
            purpose: LaunchPurpose::Workload,
            tenant_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            instance_id: Uuid::new_v4(),
            workspace_id,
            generation: 1,
            launch_id: Uuid::new_v4(),
            pod_uid: Uuid::new_v4(),
            namespace: "public-work-fixture".into(),
            pod_name: format!("sbx-ws-{workspace_id}"),
            pvc_uid: Uuid::new_v4(),
            pv_uid: Uuid::new_v4(),
            pv_name: "public-pv-fixture".into(),
            csi_volume_handle: "d-public-fixture".into(),
        },
        expires_at: Utc::now() + chrono::Duration::minutes(1),
    }
}

#[tokio::test]
async fn real_h2_cancel_keeps_blocking_work_bounded_tracked_and_closure_irrevocable()
-> anyhow::Result<()> {
    let _test_lock = TEST_WORK_LOCK.lock().await;
    let registration = fixture_registration();
    let node = registration.node.clone();
    let directory = tempfile::tempdir()?;
    let journal =
        GateJournal::open(&directory.path().join("journal.sqlite3"), node.clone()).await?;
    journal.verify_coverage().await?;
    journal.register(&registration).await?;
    let request = CloseRequest {
        protocol: PROTOCOL_VERSION,
        challenge_id: Uuid::new_v4(),
        node,
        launch: registration.launch.clone(),
        reason: CloseReason::Stop,
        challenge_expires_at: Utc::now() + chrono::Duration::seconds(30),
    };
    let work = Arc::new(BlockingWork::default());
    let _release = ReleaseOnDrop(work.clone());
    let (entered, mut observed) = tokio::sync::mpsc::unbounded_channel();
    let tasks = TaskTracker::new();
    let dropped = Arc::new(AtomicUsize::new(0));
    let proofs = Arc::new(AtomicUsize::new(0));
    let state = WorkState {
        tasks: tasks.clone(),
        work: work.clone(),
        entered,
        dropped: dropped.clone(),
        proofs: proofs.clone(),
        journal: journal.clone(),
    };
    let (address, cancel, listener) = listen(state.clone()).await?;
    let mut clients = Vec::new();
    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..MAX_OBSERVER_WORK {
        let client = client()?;
        let (sent, request) = (client.clone(), request.clone());
        requests.spawn(async move {
            sent.post(format!("https://{address}/observe"))
                .json(&request)
                .send()
                .await
        });
        clients.push(client);
    }
    for _ in 0..MAX_OBSERVER_WORK {
        tokio::time::timeout(Duration::from_secs(3), observed.recv())
            .await?
            .ok_or_else(|| anyhow::anyhow!("Blocking worker did not enter"))?;
    }
    assert_eq!(tasks.len(), MAX_OBSERVER_WORK);
    requests.abort_all();
    while requests.join_next().await.is_some() {}
    requests_dropped(&dropped, MAX_OBSERVER_WORK).await?;
    assert_eq!(
        tasks.len(),
        MAX_OBSERVER_WORK,
        "HTTP cancellation must retain worker tokens"
    );
    assert_eq!(proofs.load(Ordering::SeqCst), 0);
    assert!(
        journal
            .saved_termination(request.launch.pod_uid)
            .await?
            .is_none()
    );
    assert!(journal.require_open(request.launch.pod_uid).await.is_err());
    assert!(
        journal.register(&registration).await.is_err(),
        "Cancelled CLOSE cannot reopen a UID"
    );
    let rejected = tokio::time::timeout(
        Duration::from_secs(1),
        client()?
            .post(format!("https://{address}/observe"))
            .json(&request)
            .send(),
    )
    .await??;
    assert_eq!(rejected.version(), reqwest::Version::HTTP_2);
    assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        observed.try_recv().is_err(),
        "Full observer capacity must not queue work"
    );
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(4), listener).await???;
    tasks.close();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), tasks.wait())
            .await
            .is_err(),
        "Transport drain is not evidence that non-cancellable kernel work exited"
    );
    work.release();
    tokio::time::timeout(Duration::from_secs(2), tasks.wait()).await?;
    assert_eq!(proofs.load(Ordering::SeqCst), 0);
    assert!(
        journal
            .saved_termination(request.launch.pod_uid)
            .await?
            .is_none()
    );
    assert_eq!(
        OBSERVER_SLOTS
            .get()
            .ok_or_else(|| anyhow::anyhow!("Missing global slots"))?
            .available_permits(),
        MAX_OBSERVER_WORK
    );
    // A new runtime tracker may use the returned global slots. The old tracker
    // remains closed; it is never reopened as a shutdown shortcut.
    let new_tasks = TaskTracker::new();
    let new_state = WorkState {
        tasks: new_tasks.clone(),
        ..state
    };
    let (address, cancel, listener) = listen(new_state).await?;
    let response = client()?
        .post(format!("https://{address}/observe"))
        .json(&request)
        .send()
        .await?;
    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(proofs.load(Ordering::SeqCst), 1);
    assert!(
        journal
            .saved_termination(request.launch.pod_uid)
            .await?
            .is_some()
    );
    assert!(journal.register(&registration).await.is_err());
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(4), listener).await???;
    new_tasks.close();
    tokio::time::timeout(Duration::from_secs(2), new_tasks.wait()).await?;
    drop(clients);
    journal.shutdown().await;
    Ok(())
}

#[derive(Clone)]
struct SavedState {
    journal: GateJournal,
    tasks: TaskTracker,
    handles: Arc<Mutex<Vec<std::fs::File>>>,
    committed: tokio::sync::mpsc::UnboundedSender<()>,
    dropped: Arc<AtomicUsize>,
    mounts_present: Arc<std::sync::atomic::AtomicBool>,
    mount_reads: Arc<AtomicUsize>,
}
// A controlled commit/ACK cancellation fixture. The owned File is real; the
// kernel death/mount observations are explicit stand-ins, not HostObserver proof.
async fn saved_retry(
    State(state): State<SavedState>,
    Json(request): Json<CloseRequest>,
) -> StatusCode {
    let _drop = RequestDrop(state.dropped.clone());
    let Ok(snapshot) = state.journal.close(&request).await else {
        return StatusCode::CONFLICT;
    };
    let Ok(saved) = state
        .journal
        .saved_termination(request.launch.pod_uid)
        .await
    else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    let Some(saved) = saved else {
        let at = Utc::now();
        if state
            .journal
            .save_termination(
                request.launch.pod_uid,
                &LocalTerminationEvidence {
                    journal_revision: snapshot.revision,
                    forwarded_starts: snapshot.forwarded_starts,
                    observed_sandboxes: snapshot.sandboxes,
                    closed_at: snapshot.closed_at,
                    processes_exited_at: at,
                    pod_mounts_absent_at: at,
                },
            )
            .await
            .is_err()
        {
            return StatusCode::SERVICE_UNAVAILABLE;
        }
        let _ = state.committed.send(());
        // Cancel the actual H2 request after durable proof and before handle
        // cleanup. A subsequent call must use the saved-proof branch.
        return std::future::pending::<StatusCode>().await;
    };
    if saved.forwarded_starts != snapshot.forwarded_starts
        || saved.observed_sandboxes != snapshot.sandboxes
        || saved.closed_at != snapshot.closed_at
    {
        return StatusCode::CONFLICT;
    }
    let (handles, present, reads) = (
        state.handles.clone(),
        state.mounts_present.clone(),
        state.mount_reads.clone(),
    );
    let Ok(absent) = observer_work(&state.tasks, move || {
        handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        reads.fetch_add(1, Ordering::SeqCst);
        !present.load(Ordering::SeqCst)
    })
    .await
    else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    if Utc::now() >= request.challenge_expires_at {
        StatusCode::CONFLICT
    } else if absent {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    }
}

#[tokio::test]
async fn actual_h2_cancel_after_durable_proof_then_saved_retry_releases_real_handles_and_refreshes_mounts()
-> anyhow::Result<()> {
    let _test_lock = TEST_WORK_LOCK.lock().await;
    let registration = fixture_registration();
    let directory = tempfile::tempdir()?;
    let journal = GateJournal::open(
        &directory.path().join("journal.sqlite3"),
        registration.node.clone(),
    )
    .await?;
    journal.verify_coverage().await?;
    journal.register(&registration).await?;
    let handle_path = directory.path().join("pinned-handle.fixture");
    let handle = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&handle_path)?;
    handle.try_lock()?;
    let contender = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&handle_path)?;
    let handles = Arc::new(Mutex::new(vec![handle]));
    let (committed, mut commit_seen) = tokio::sync::mpsc::unbounded_channel();
    let dropped = Arc::new(AtomicUsize::new(0));
    let mounts_present = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let mount_reads = Arc::new(AtomicUsize::new(0));
    let tasks = TaskTracker::new();
    let state = SavedState {
        journal: journal.clone(),
        tasks: tasks.clone(),
        handles,
        committed,
        dropped: dropped.clone(),
        mounts_present: mounts_present.clone(),
        mount_reads: mount_reads.clone(),
    };
    let (address, cancel, listener) = listen_router(
        Router::new()
            .route("/retry", post(saved_retry))
            .with_state(state),
    )
    .await?;
    let client = client()?;
    let request = CloseRequest {
        protocol: PROTOCOL_VERSION,
        challenge_id: Uuid::new_v4(),
        node: registration.node.clone(),
        launch: registration.launch.clone(),
        reason: CloseReason::Stop,
        challenge_expires_at: Utc::now() + chrono::Duration::seconds(30),
    };
    let (sent, copy) = (client.clone(), request.clone());
    let first = tokio::spawn(async move {
        sent.post(format!("https://{address}/retry"))
            .json(&copy)
            .send()
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), commit_seen.recv())
        .await?
        .ok_or_else(|| anyhow::anyhow!("Durable proof was not committed"))?;
    let original = journal
        .saved_termination(request.launch.pod_uid)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Missing saved proof"))?;
    assert!(
        contender.try_lock().is_err(),
        "Original cancelled request still owns pinned FD"
    );
    first.abort();
    let _ = first.await;
    requests_dropped(&dropped, 1).await?;
    assert_eq!(mount_reads.load(Ordering::SeqCst), 0);
    assert!(journal.register(&registration).await.is_err());
    let waiting = client
        .post(format!("https://{address}/retry"))
        .json(&request)
        .send()
        .await?;
    assert_eq!(waiting.version(), reqwest::Version::HTTP_2);
    assert_eq!(
        waiting.status(),
        StatusCode::ACCEPTED,
        "Saved death never substitutes for fresh mount absence"
    );
    contender.try_lock()?;
    assert_eq!(mount_reads.load(Ordering::SeqCst), 1);
    mounts_present.store(false, Ordering::SeqCst);
    let retry = client
        .post(format!("https://{address}/retry"))
        .json(&request)
        .send()
        .await?;
    assert_eq!(retry.status(), StatusCode::OK);
    assert_eq!(mount_reads.load(Ordering::SeqCst), 2);
    assert_eq!(
        journal
            .saved_termination(request.launch.pod_uid)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Saved proof was lost"))?
            .processes_exited_at,
        original.processes_exited_at
    );
    let mut expired = request.clone();
    expired.challenge_expires_at = Utc::now() - chrono::Duration::seconds(1);
    assert_eq!(
        client
            .post(format!("https://{address}/retry"))
            .json(&expired)
            .send()
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert!(journal.register(&registration).await.is_err());
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(4), listener).await???;
    tasks.close();
    tokio::time::timeout(Duration::from_secs(2), tasks.wait()).await?;
    journal.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn closed_tracker_rejects_host_io_with_no_late_work_or_lost_slots() -> anyhow::Result<()> {
    let _test_lock = TEST_WORK_LOCK.lock().await;
    let tasks = TaskTracker::new();
    tasks.close();
    tasks.wait().await;
    let called = Arc::new(AtomicUsize::new(0));
    let work = called.clone();
    assert!(
        observer_work(&tasks, move || work.fetch_add(1, Ordering::SeqCst))
            .await
            .is_err()
    );
    assert_eq!(called.load(Ordering::SeqCst), 0);
    assert!(tasks.is_empty());
    assert_eq!(
        OBSERVER_SLOTS
            .get_or_init(|| Arc::new(Semaphore::new(MAX_OBSERVER_WORK)))
            .available_permits(),
        MAX_OBSERVER_WORK
    );
    Ok(())
}

#[tokio::test]
async fn cancelled_sqlite_worker_is_drained_before_the_real_daemon_lock_is_released()
-> anyhow::Result<()> {
    use sqlx::{Connection, sqlite::SqliteConnectOptions};
    let registration = fixture_registration();
    let directory = tempfile::tempdir()?;
    let db_path = directory.path().join("journal.sqlite3");
    let journal = GateJournal::open(&db_path, registration.node.clone()).await?;
    journal.verify_coverage().await?;
    let lock_path = directory.path().join("daemon.lock");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)?;
    lock.try_lock()?;
    let contender = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)?;
    let mut external = sqlx::SqliteConnection::connect_with(
        &SqliteConnectOptions::new()
            .filename(&db_path)
            .create_if_missing(false)
            .busy_timeout(Duration::from_secs(5)),
    )
    .await?;
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut external)
        .await?;
    let active = journal.clone();
    let (entered, started) = tokio::sync::oneshot::channel();
    let pending = tokio::spawn(async move {
        let _ = entered.send(());
        active.register(&registration).await
    });
    started.await?;
    // The journal's single SQLite connection has an issued BEGIN blocked on
    // the real external writer. Cancel the SQLx awaiter, not that worker.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!pending.is_finished());
    pending.abort();
    let _ = pending.await;
    let mut drain = tokio::spawn(async move {
        journal.shutdown().await;
        std::fs::File::open(directory.path())?.sync_all()?;
        drop(lock);
        Ok::<_, anyhow::Error>(())
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut drain)
            .await
            .is_err(),
        "Pool close must wait for already submitted SQLite work"
    );
    assert!(
        contender.try_lock().is_err(),
        "Pending SQLite command must retain daemon ownership"
    );
    sqlx::query("ROLLBACK").execute(&mut external).await?;
    tokio::time::timeout(Duration::from_secs(2), drain).await???;
    contender.try_lock()?;
    external.close().await?;
    Ok(())
}
