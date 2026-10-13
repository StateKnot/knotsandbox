//! Same-lease continuous reconciliation against real PostgreSQL. Runtime
//! transport/launch evidence are explicit owned fixtures, never VM isolation.
#[path = "worker_support/commit_proxy.rs"]
mod commit_proxy;
#[allow(dead_code)]
mod support;
#[allow(dead_code)]
mod worker_support;

use std::{sync::atomic::Ordering, time::Duration};

use anyhow::{Context, ensure};
use sandbox_platform::worker::Worker;
use serde_json::Value;
use sqlx::PgPool;
use support::{Fixture, api_failure};
use tokio::{task::JoinHandle, time::Instant};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use worker_support::{MockKube, fixture, register_mock_launch, worker};

struct Running {
    task: Option<JoinHandle<anyhow::Result<()>>>,
    shutdown: CancellationToken,
    pool: PgPool,
}

impl Running {
    fn start(worker: Worker) -> Self {
        let pool = worker.engine.database.pool.clone();
        let shutdown = CancellationToken::new();
        let signal = shutdown.clone();
        Self {
            task: Some(tokio::spawn(worker.run(signal))),
            shutdown,
            pool,
        }
    }

    async fn settle(&mut self, mock: &MockKube) -> anyhow::Result<()> {
        self.shutdown.cancel();
        mock.resume.add_permits(32);
        let mut task = self.task.take().context("owned worker handle missing")?;
        let result = tokio::time::timeout(Duration::from_secs(30), &mut task).await;
        if result.is_err() {
            task.abort();
            let _ = task.await;
        }
        result.context("worker drain bound exceeded")???;
        Ok(())
    }

    async fn finish(&mut self, mock: &MockKube) -> anyhow::Result<()> {
        let joined = self.settle(mock).await;
        self.pool.close().await;
        joined
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn paused(mock: &MockKube) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(23), mock.paused.acquire())
        .await
        .context("owned checkpoint runtime barrier was not reached")??
        .forget();
    Ok(())
}

async fn state(
    f: &Fixture,
    op: Uuid,
) -> anyhow::Result<(String, String, Option<String>, i32, i64)> {
    let mut tx = f.owner_transaction().await?;
    let row=sqlx::query_as("SELECT status,stage,wait_reason,attempts,lease_token FROM operations WHERE tenant_id=$1 AND id=$2")
        .bind(f.actor.tenant_id).bind(op).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(row)
}

async fn wait_stage(
    f: &Fixture,
    op: Uuid,
    expected: &str,
    seconds: u64,
) -> anyhow::Result<(String, String, Option<String>, i32, i64)> {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        let row = state(f, op).await?;
        if row.1 == expected {
            return Ok(row);
        }
        ensure!(
            Instant::now() < deadline,
            "expected durable stage was not observed: {expected}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn checkpoints(f: &Fixture, op: Uuid) -> anyhow::Result<Vec<(i64, Value)>> {
    let mut tx = f.owner_transaction().await?;
    let rows=sqlx::query_as("SELECT aggregate_version,payload FROM domain_events WHERE tenant_id=$1 AND operation_id=$2 AND event_type='operation.progressed' ORDER BY aggregate_version")
        .bind(f.actor.tenant_id).bind(op).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    Ok(rows)
}

async fn settle_fixture(f: &Fixture) -> anyhow::Result<()> {
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET next_attempt_at=clock_timestamp()+interval '1 day' WHERE tenant_id=$1 AND status IN('QUEUED','RUNNING','WAITING')")
        .bind(f.actor.tenant_id).execute(&mut *tx).await?;
    tx.commit().await?;
    f.database.pool.close().await;
    f.owner.close().await;
    Ok(())
}

async fn pending_quota(f: &Fixture) -> anyhow::Result<()> {
    let mut tx = f.owner_transaction().await?;
    let (pending, allocated): (i64, i64) = sqlx::query_as(
        "SELECT sum(pending)::bigint,sum(allocated)::bigint FROM quota_accounts WHERE tenant_id=$1",
    )
    .bind(f.actor.tenant_id)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(
        pending > 0 && allocated == 0,
        "unconfirmed runtime must retain pending quota"
    );
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable TLS PostgreSQL and a real pre-COMMIT table lock"]
async fn continuous_precommit_failure_rolls_back_checkpoint_and_stops_batch() -> anyhow::Result<()>
{
    let _serial = support::serial().await;
    let f = fixture().await?;
    let a = f
        .create("continuous-precommit")
        .await
        .map_err(api_failure)?;
    let op = a.body.operation.id;
    let mock = MockKube::new(&f, &a.body.resource, op).await?;
    let w = worker(&f, &mock, "continuous-precommit").await?;
    let outcome =
        worker_support::checkpoint_faults::verify_precommit_rollback(&f, &mock, op, &w).await;
    let closed = settle_fixture(&f).await;
    outcome?;
    closed?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable TLS PostgreSQL and dedicated worker login"]
async fn continuous_checkpoints_share_one_claim_and_only_trusted_ready_completes()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let f = fixture().await?;
    let accepted = f.create("continuous-ready").await.map_err(api_failure)?;
    let op = accepted.body.operation.id;
    let instance = &accepted.body.resource;
    let mock = MockKube::new(&f, instance, op).await?;
    mock.require_committed_predecessor
        .store(true, Ordering::SeqCst);
    mock.pause_pod_get.store(true, Ordering::SeqCst);
    let w = worker(&f, &mock, "continuous-ready").await?;
    let mut running = Running::start(w);
    let outcome = async {
        paused(&mock).await?;
        let row = state(&f, op).await?;
        ensure!(row == ("RUNNING".into(), "POD_RECORDED".into(), None, 1, 1));
        let events = checkpoints(&f, op).await?;
        ensure!(events.len() == 3);
        for ((version, payload), (expected, kind)) in
            events
                .iter()
                .zip([(1, "CILIUM_POLICY"), (2, "PVC"), (3, "POD")])
        {
            ensure!(
                *version == expected
                    && payload["resource_kind"] == kind
                    && payload["lease_token"] == 1
            );
        }
        pending_quota(&f).await?;
        register_mock_launch(&f, op, instance.id).await?;
        mock.resume.add_permits(1);
        let row = wait_stage(&f, op, "COMPLETED", 5).await?;
        ensure!(row.0 == "SUCCEEDED" && row.3 == 1 && row.4 == 1);
        for kind in ["CiliumNetworkPolicy", "PersistentVolumeClaim", "Pod"] {
            ensure!(mock.posts(kind)? == 1);
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleanup = running.finish(&mock).await;
    let closed = settle_fixture(&f).await;
    outcome?;
    cleanup?;
    closed?;
    println!("WORKER_CONTINUATION_ONE_CLAIM_THREE_COMMITTED_CHECKPOINTS_TRUSTED_READY_VERIFIED");
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable TLS PostgreSQL; Kubernetes observations are fixtures"]
async fn continuous_not_ready_preserves_five_second_retry_and_pending_quota() -> anyhow::Result<()>
{
    let _serial = support::serial().await;
    let f = fixture().await?;
    let a = f
        .create("continuous-not-ready")
        .await
        .map_err(api_failure)?;
    let op = a.body.operation.id;
    let mock = MockKube::new(&f, &a.body.resource, op).await?;
    mock.not_ready.store(true, Ordering::SeqCst);
    mock.require_committed_predecessor
        .store(true, Ordering::SeqCst);
    let w = worker(&f, &mock, "continuous-wait").await?;
    let engine = w.engine.clone();
    let mut running = Running::start(w);
    let outcome=async {
        let row=wait_stage(&f,op,"WAITING_READY",5).await?;
        ensure!(row==("WAITING".into(),"WAITING_READY".into(),Some("CURRENT_LAUNCH_NOT_READY".into()),1,1));
        let mut tx=f.owner_transaction().await?;
        let delay:f64=sqlx::query_scalar("SELECT extract(epoch FROM(next_attempt_at-updated_at))::float8 FROM operations WHERE tenant_id=$1 AND id=$2")
            .bind(f.actor.tenant_id).bind(op).fetch_one(&mut *tx).await?;
        ensure!((4.99..=5.01).contains(&delay)); tx.commit().await?;
        ensure!(engine.claim().await.map_err(api_failure)?.is_none());
        ensure!(checkpoints(&f,op).await?.len()==3); pending_quota(&f).await?;
        for kind in ["CiliumNetworkPolicy","PersistentVolumeClaim","Pod"] { ensure!(mock.posts(kind)?==1); }
        Ok::<_,anyhow::Error>(())
    }.await;
    let cleanup = running.finish(&mock).await;
    let closed = settle_fixture(&f).await;
    outcome?;
    cleanup?;
    closed?;
    println!("WORKER_CONTINUATION_NOT_READY_FIVE_SECOND_RETRY_NO_EARLY_CLAIM_VERIFIED");
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable TLS PostgreSQL and real authorization/lease state"]
async fn continuous_checkpoint_rechecks_revocation_epoch_and_expired_lease() -> anyhow::Result<()> {
    let _serial = support::serial().await;
    for fault in ["GRANT", "LEASE", "POLICY", "EPOCH"] {
        let f = fixture().await?;
        let a = f
            .create(&format!("continuous-fence-{fault}"))
            .await
            .map_err(api_failure)?;
        let op = a.body.operation.id;
        let mock = MockKube::new(&f, &a.body.resource, op).await?;
        mock.pause_policy_get.store(true, Ordering::SeqCst);
        let w = worker(&f, &mock, &format!("continuous-fence-{fault}")).await?;
        let mut running = Running::start(w);
        let outcome=async {
            paused(&mock).await?; ensure!(checkpoints(&f,op).await?.len()==1);
            let mut tx=f.owner_transaction().await?;
            match fault {
                "GRANT"=>{sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND action='instances:create'").bind(f.actor.tenant_id).execute(&mut *tx).await?;},
                "LEASE"=>{sqlx::query("UPDATE operations SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(op).execute(&mut *tx).await?;},
                "POLICY"=>{sqlx::query("UPDATE security_policy_versions SET status='REVOKED' WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(f.request.security_profile_id).execute(&mut *tx).await?;},
                "EPOCH"=>{sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton").bind(Uuid::new_v4()).execute(&mut *tx).await?;},
                _=>anyhow::bail!("invalid owned test fault"),
            }
            // Freeze only this disposable fixture's future claims after the
            // intentional lease loss, avoiding a second attempt during probes.
            sqlx::query("UPDATE operations SET next_attempt_at=clock_timestamp()+interval '1 day' WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(op).execute(&mut *tx).await?;
            tx.commit().await?; mock.resume.add_permits(1);
            if fault!="LEASE" { let row=wait_stage(&f,op,"RECONCILE_BLOCKED",5).await?;ensure!(row.0=="WAITING"); }
            ensure!(mock.posts("CiliumNetworkPolicy")?==1 && mock.posts("PersistentVolumeClaim")?==0 && mock.posts("Pod")?==0);
            ensure!(checkpoints(&f,op).await?.len()==1);pending_quota(&f).await?;
            Ok::<_,anyhow::Error>(())
        }.await;
        let cleanup = running.finish(&mock).await;
        let after_drain = async {
            ensure!(mock.posts("PersistentVolumeClaim")? == 0 && mock.posts("Pod")? == 0);
            ensure!(checkpoints(&f, op).await?.len() == 1);
            pending_quota(&f).await
        }
        .await;
        let closed = settle_fixture(&f).await;
        outcome?;
        cleanup?;
        after_drain?;
        closed?;
    }
    println!("WORKER_CONTINUATION_CURRENT_GRANT_LEASE_APPROVAL_EPOCH_FENCES_VERIFIED");
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable TLS PostgreSQL and a bounded runtime transport fixture"]
async fn continuous_batch_retains_one_total_timeout_and_heartbeat() -> anyhow::Result<()> {
    let _serial = support::serial().await;
    let f = fixture().await?;
    let a = f
        .create("continuous-total-budget")
        .await
        .map_err(api_failure)?;
    let op = a.body.operation.id;
    let mock = MockKube::new(&f, &a.body.resource, op).await?;
    mock.slow_posts.store(true, Ordering::SeqCst);
    mock.pause_pvc_get.store(true, Ordering::SeqCst);
    mock.require_committed_predecessor
        .store(true, Ordering::SeqCst);
    let w = worker(&f, &mock, "continuous-total-budget").await?;
    let started = Instant::now();
    let mut running = Running::start(w);
    let outcome=async {
        paused(&mock).await?;
        ensure!(state(&f,op).await?==("RUNNING".into(),"VOLUME_RECORDED".into(),None,1,1));
        let mut tx=f.owner_transaction().await?;
        let remaining:f64=sqlx::query_scalar("SELECT extract(epoch FROM(lease_until-clock_timestamp()))::float8 FROM operations WHERE tenant_id=$1 AND id=$2")
            .bind(f.actor.tenant_id).bind(op).fetch_one(&mut *tx).await?;
        ensure!(remaining>15.0,"heartbeat must extend the original lease without reclaiming");
        tx.commit().await?;
        let row=wait_stage(&f,op,"RECONCILE_BLOCKED",10).await?;
        ensure!(row==("WAITING".into(),"RECONCILE_BLOCKED".into(),Some("RUNTIME_REQUEST_TIMEOUT".into()),1,1));
        ensure!((24.0..32.0).contains(&started.elapsed().as_secs_f64()),"batch must share the original 25-second wall-clock budget");
        ensure!(checkpoints(&f,op).await?.len()==2);
        ensure!(mock.posts("Pod")?==0);
        pending_quota(&f).await
    }.await;
    let cleanup = running.finish(&mock).await;
    let closed = settle_fixture(&f).await;
    outcome?;
    cleanup?;
    closed?;
    println!("WORKER_CONTINUATION_SINGLE_TOTAL_BUDGET_HEARTBEAT_NO_POD_VERIFIED");
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable verify-full PostgreSQL; drops a real committed checkpoint ACK"]
async fn continuous_lost_commit_ack_stops_old_batch_and_recovers_same_uid() -> anyhow::Result<()> {
    let _serial = support::serial().await;
    let f = fixture().await?;
    let a = f.create("continuous-lost-ack").await.map_err(api_failure)?;
    let op = a.body.operation.id;
    let mut mock = MockKube::new(&f, &a.body.resource, op).await?;
    // Install and verify the ordinary dedicated worker identity first. This
    // separate same-role monitor can see exact backend identities, never SQL.
    let monitor = worker(&f, &mock, "continuous-ack-monitor").await?;
    let (mut proxy, database) = commit_proxy::CommitProxy::connect().await?;
    mock.arm_commit = Some(proxy.arm.clone());
    mock.require_committed_predecessor
        .store(true, Ordering::SeqCst);
    mock.pause_pod_get.store(true, Ordering::SeqCst);
    let w = Worker::new(
        database.clone(),
        mock.runtime(),
        "continuous-lost-ack".into(),
        "integration-evidence-reference".into(),
        1,
        "kube-system".into(),
        [("k8s-app".into(), "kube-dns".into())].into(),
    )?;
    let mut running = Running::start(w);
    let outcome=async {
        tokio::time::timeout(Duration::from_secs(10),proxy.arrived.notified()).await.context("actual armed checkpoint COMMIT ACK was not intercepted")?;
        let pid=proxy.target_backend_pid.load(Ordering::SeqCst);
        ensure!(pid>0);
        let identity:(i32,chrono::DateTime<chrono::Utc>)=sqlx::query_as("SELECT pid,backend_start FROM pg_stat_activity WHERE pid=$1 AND usename='sandbox_worker' AND datname=current_database()")
            .bind(pid).fetch_one(&monitor.engine.database.pool).await?;
        // These owner reads prove COMMIT actually released its locks and made
        // all three checkpoint facts visible before the ACK socket is lost.
        ensure!(state(&f,op).await?==("RUNNING".into(),"POLICY_RECORDED".into(),None,1,1));
        let events=checkpoints(&f,op).await?;
        ensure!(events.len()==1 && events[0].1["resource_kind"]=="CILIUM_POLICY" && events[0].1["lease_token"]==1);
        ensure!(mock.posts("PersistentVolumeClaim")?==0 && mock.posts("Pod")?==0);
        pending_quota(&f).await?;
        proxy.drop_ack();
        paused(&mock).await?;
        let row=state(&f,op).await?;
        ensure!(row==("RUNNING".into(),"POD_RECORDED".into(),None,2,2),"unknown ACK must release/reclaim instead of continuing the old lease");
        let recovered=checkpoints(&f,op).await?;
        ensure!(recovered.len()==3 && recovered[0]==events[0]);
        for (version,payload) in &recovered[1..] { ensure!(*version>=2 && payload["lease_token"]==2); }
        for kind in ["CiliumNetworkPolicy","PersistentVolumeClaim","Pod"] { ensure!(mock.posts(kind)?==1); }
        register_mock_launch(&f,op,a.body.resource.id).await?;
        mock.resume.add_permits(1);
        let ready=wait_stage(&f,op,"COMPLETED",5).await?;
        ensure!(ready.0=="SUCCEEDED" && ready.3==2 && ready.4==2);
        let retired:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND backend_start=$2)")
            .bind(identity.0).bind(identity.1).fetch_one(&monitor.engine.database.pool).await?;
        ensure!(retired,"lost-ACK backend must actually retire");
        Ok::<_,anyhow::Error>(())
    }.await;
    proxy.drop_ack();
    // Join business work, then let the owned proxy close/join its transport
    // children before awaiting the pool whose TLS close uses that transport.
    let cleanup = running.settle(&mock).await;
    let pids = proxy.backend_pids();
    let drained = proxy.finish(&database).await;
    let backend_absence=async {
        let pids=pids?;
        let deadline=Instant::now()+Duration::from_secs(3);
        loop {
            let remaining:i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE pid=ANY($1) AND datname=current_database() AND usename='sandbox_worker'")
                .bind(&pids).fetch_one(&monitor.engine.database.pool).await?;
            if remaining==0 { break; }
            ensure!(Instant::now()<deadline,"owned proxy backend did not retire after awaited drain");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_,anyhow::Error>(())
    }.await;
    monitor.engine.database.pool.close().await;
    let closed = settle_fixture(&f).await;
    outcome?;
    cleanup?;
    drained?;
    backend_absence?;
    closed?;
    println!("WORKER_CONTINUATION_REAL_TLS_COMMITTED_ACK_LOSS_NEW_LEASE_SAME_UID_DRAIN_VERIFIED");
    Ok(())
}
