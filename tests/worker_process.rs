#![cfg(unix)]
//! Owned sandboxd worker, PostgreSQL ACL drift/lock timeout and awaited pool
//! close. Kubernetes points to an owned socket-rejecting loopback port; no guest, cloud,
//! credentials from the user's shell or physical termination is exercised.
#[allow(dead_code)]
mod support;

use anyhow::{Context, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use sandbox_platform::db::Database;
use sqlx::{PgPool, Postgres, Transaction};
use std::{
    collections::BTreeSet,
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};
use support::{Fixture, api_failure};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    task::JoinHandle,
    time::Instant,
};
use uuid::Uuid;

const OBSERVE: Duration = Duration::from_secs(5);
const EXIT: Duration = Duration::from_secs(12);
type Backends = BTreeSet<(i32, DateTime<Utc>)>;
type Reader = JoinHandle<anyhow::Result<Vec<u8>>>;

async fn sessions(pool: &PgPool) -> anyhow::Result<Backends> {
    let deadline = Instant::now() + OBSERVE;
    let rows=tokio::time::timeout_at(deadline,async{
        let mut tx=pool.begin().await?;
        sqlx::query("SET TRANSACTION READ ONLY").execute(&mut *tx).await?;
        let rows=sqlx::query_as("SELECT pid,backend_start FROM pg_stat_activity WHERE datname=current_database() AND usename=current_user AND backend_type='client backend'")
            .fetch_all(&mut *tx).await?;
        tx.commit().await?;
        Ok::<Vec<(i32,DateTime<Utc>)>,anyhow::Error>(rows)
    }).await.context("Worker backend observation exceeded original bound")??;
    ensure!(
        Instant::now() < deadline,
        "Worker backend COMMIT acknowledgment was late"
    );
    Ok(rows.into_iter().collect())
}

async fn absent(pool: &PgPool, baseline: &Backends) -> anyhow::Result<()> {
    let deadline = Instant::now() + OBSERVE;
    loop {
        let actual = tokio::time::timeout_at(deadline, sessions(pool))
            .await
            .context("Physical worker backend absence exceeded original bound")??;
        ensure!(
            Instant::now() < deadline,
            "Physical backend absence acknowledgment was late"
        );
        if actual == *baseline {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn process_identity(pool: &PgPool, baseline: &Backends, pod: Uuid) -> anyhow::Result<Uuid> {
    let deadline = Instant::now() + OBSERVE;
    let rows:Vec<(i32,DateTime<Utc>,String)>=tokio::time::timeout_at(deadline,
        sqlx::query_as("SELECT pid,backend_start,application_name FROM pg_stat_activity WHERE datname=current_database() AND usename=current_user AND backend_type='client backend'")
            .fetch_all(pool)).await.context("Worker process label observation exceeded original bound")??;
    let mut identity = None;
    let mut count = 0;
    for (pid, start, label) in rows {
        if baseline.contains(&(pid, start)) {
            continue;
        }
        count += 1;
        let fields: Vec<_> = label.split('.').collect();
        ensure!(
            fields.len() == 4 && fields[0] == "sbx1" && fields[1] == "worker" && label.len() <= 63,
            "Actual owned binary did not retain its fixed worker role"
        );
        let decode = |value: &str| -> anyhow::Result<Uuid> {
            let bytes = URL_SAFE_NO_PAD.decode(value)?;
            ensure!(
                value.len() == 22 && bytes.len() == 16 && URL_SAFE_NO_PAD.encode(&bytes) == value,
                "Full UUID encoding was truncated or noncanonical"
            );
            Ok(Uuid::from_slice(&bytes)?)
        };
        let process = decode(fields[2])?;
        ensure!(
            decode(fields[3])? == pod && !process.is_nil(),
            "Worker backend does not belong to the exact configured Pod"
        );
        if let Some(previous) = identity {
            ensure!(
                previous == process,
                "One owned process changed its connection identity"
            );
        }
        identity = Some(process);
    }
    ensure!(
        Instant::now() < deadline && (1..=4).contains(&count),
        "Owned worker connections were missing, late or above pool cap"
    );
    identity.context("Actual worker process UUID was not observed")
}

async fn read_output(
    mut reader: impl AsyncRead + Unpin,
    observed: Arc<Mutex<Vec<u8>>>,
) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            return Ok(output);
        }
        ensure!(
            output.len() + n <= 32768,
            "Owned worker output exceeded fixed bound"
        );
        output.extend_from_slice(&chunk[..n]);
        *observed
            .lock()
            .map_err(|_| anyhow::anyhow!("Output observer lock poisoned"))? = output.clone();
    }
}

struct Owned {
    child: Child,
    out: Reader,
    err: Reader,
    observed: Arc<Mutex<Vec<u8>>>,
}
impl Owned {
    fn spawn(url: &str, kubeconfig: &std::path::Path, pod: Uuid) -> anyhow::Result<Self> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sandboxd"));
        command
            .env_clear()
            .env("SANDBOX_DATABASE_URL", url)
            .env("KUBECONFIG", kubeconfig)
            .env("SANDBOX_PROCESS_POD_UID", pod.to_string())
            .env("RUST_LOG", "sandbox_platform=info,sandboxd=info")
            .args([
                "--role",
                "worker",
                "--db-max-connections",
                "4",
                "--worker-concurrency",
                "1",
                "--deployment-certification-id",
                "test-only-worker-process-no-runtime-certification",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        sandbox_platform::config::validate_database_url(url, false)?;
        let mut child = command
            .spawn()
            .context("Cannot start owned actual worker binary")?;
        let observed = Arc::new(Mutex::new(Vec::new()));
        let out = tokio::spawn(read_output(
            child.stdout.take().context("Owned worker stdout missing")?,
            observed.clone(),
        ));
        let err = tokio::spawn(read_output(
            child.stderr.take().context("Owned worker stderr missing")?,
            Arc::new(Mutex::new(Vec::new())),
        ));
        Ok(Self {
            child,
            out,
            err,
            observed,
        })
    }
    fn output_contains(&self, needle: &str) -> anyhow::Result<bool> {
        let observed = self
            .observed
            .lock()
            .map_err(|_| anyhow::anyhow!("Output observer poisoned"))?;
        Ok(String::from_utf8_lossy(&observed).contains(needle))
    }
    async fn started(&mut self) -> anyhow::Result<()> {
        let deadline = Instant::now() + OBSERVE;
        loop {
            ensure!(
                self.child.try_wait()?.is_none(),
                "Actual worker exited before normal startup verification"
            );
            ensure!(
                Instant::now() < deadline,
                "Actual worker startup exceeded original bound"
            );
            if self.output_contains("worker queue grants verified; lifecycle timer supervised")? {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    async fn exited(&mut self, success: bool) -> anyhow::Result<()> {
        let deadline = Instant::now() + EXIT;
        let status = tokio::time::timeout_at(deadline, self.child.wait())
            .await
            .context("Actual worker did not exit inside original bound")??;
        ensure!(
            Instant::now() < deadline && status.success() == success,
            "Actual worker did not preserve the intended exit result"
        );
        Ok(())
    }
    async fn cleanup(mut self) -> anyhow::Result<(String, String)> {
        let deadline = Instant::now() + OBSERVE;
        let child = tokio::time::timeout_at(deadline, async {
            if self.child.try_wait()?.is_none() {
                self.child.kill().await?;
            }
            self.child.wait().await?;
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("Owned worker cleanup exceeded original bound");
        let out = tokio::time::timeout_at(deadline, &mut self.out).await;
        if out.is_err() {
            self.out.abort();
            let _ = self.out.await;
        }
        let err = tokio::time::timeout_at(deadline, &mut self.err).await;
        if err.is_err() {
            self.err.abort();
            let _ = self.err.await;
        }
        child??;
        Ok((
            String::from_utf8(out.context("Owned stdout join timed out")???)?,
            String::from_utf8(err.context("Owned stderr join timed out")???)?,
        ))
    }
}

async fn grant(pool: &PgPool, sql: &str) -> anyhow::Result<()> {
    let deadline = Instant::now() + OBSERVE;
    tokio::time::timeout_at(deadline, sqlx::query(sql).execute(pool))
        .await
        .context("Disposable worker ACL change exceeded original bound")??;
    ensure!(
        Instant::now() < deadline,
        "Worker ACL acknowledgment was late"
    );
    Ok(())
}

async fn permanent_trial(
    f: &Fixture,
    monitor: &Database,
    url: &str,
    kubeconfig: &std::path::Path,
    pod: Uuid,
    timer: bool,
) -> anyhow::Result<()> {
    let baseline = sessions(&monitor.pool).await?;
    let mut owned = Owned::spawn(url, kubeconfig, pod)?;
    let (revoke, restore, marker) = if timer {
        (
            "REVOKE EXECUTE ON FUNCTION sandbox_due_instances(integer) FROM sandbox_worker",
            "GRANT EXECUTE ON FUNCTION sandbox_due_instances(integer) TO sandbox_worker",
            "worker timer stopped after fatal error",
        )
    } else {
        (
            "REVOKE EXECUTE ON FUNCTION sandbox_claim_operation(text) FROM sandbox_worker",
            "GRANT EXECUTE ON FUNCTION sandbox_claim_operation(text) TO sandbox_worker",
            "worker claim stopped after fatal error",
        )
    };
    let outcome = async {
        owned.started().await?;
        let identity = process_identity(&monitor.pool, &baseline, pod).await?;
        grant(&f.owner, revoke).await?;
        owned.exited(false).await?;
        absent(&monitor.pool, &baseline).await?;
        Ok::<Uuid, anyhow::Error>(identity)
    }
    .await;
    // Restore even when an injection ACK times out: the server may already have
    // committed the ACL change. This fixture's expected grant was checked by
    // normal worker startup on its independently provisioned disposable DB.
    let restore_result = grant(&f.owner, restore).await;
    let cleanup = owned.cleanup().await;
    let absence = absent(&monitor.pool, &baseline).await;
    outcome?;
    restore_result?;
    absence?;
    let (out, err) = cleanup?;
    ensure!(
        out.contains("42501")
            && out.matches("database connection pool drained").count() == 1
            && err.contains(marker)
            && !err.contains("permission denied for"),
        "Permanent ACL drift was not supervised, sanitized and drained"
    );
    println!(
        "WORKER_PROCESS {} FATAL_NONZERO_PHYSICAL_BACKENDS_ABSENT",
        if timer { "TIMER" } else { "CLAIM" }
    );
    Ok(())
}

async fn rollback(lock: &mut Option<Transaction<'_, Postgres>>) -> anyhow::Result<()> {
    if let Some(tx) = lock.take() {
        tokio::time::timeout(OBSERVE, tx.rollback())
            .await
            .context("Owned timer lock rollback timed out")??;
    }
    Ok(())
}

async fn transient_trial(
    f: &Fixture,
    monitor: &Database,
    url: &str,
    kubeconfig: &std::path::Path,
    pod: Uuid,
) -> anyhow::Result<()> {
    let baseline = sessions(&monitor.pool).await?;
    let mut owned = Owned::spawn(url, kubeconfig, pod)?;
    let mut lock = None;
    let outcome=async{
        owned.started().await?;
        let identity=process_identity(&monitor.pool,&baseline,pod).await?;
        lock=Some(f.owner.begin().await?);
        let held=lock.as_mut().context("Owned timer lock missing")?;
        let blocker:i32=sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut **held).await?;
        sqlx::query("LOCK TABLE instance_timers IN ACCESS EXCLUSIVE MODE").execute(&mut **held).await?;
        let deadline=Instant::now()+Duration::from_secs(22);
        let mut first=None;
        loop{
            ensure!(owned.child.try_wait()?.is_none(),"Retryable timer lock timeout killed the actual worker");
            let starts:Vec<DateTime<Utc>>=sqlx::query_scalar("SELECT query_start FROM pg_stat_activity WHERE datname=current_database() AND usename=current_user AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%sandbox_due_instances%'")
                .bind(blocker).fetch_all(&monitor.pool).await?;
            ensure!(Instant::now()<deadline,"Two actual timer attempts were not observed inside original bound");
            if let Some(start)=starts.first(){
                match first{
                    None=>first=Some(*start),
                    Some(previous) if *start!=previous=>{
                        ensure!(*start-previous>=chrono::Duration::seconds(8) && owned.output_contains("DEPENDENCY_UNAVAILABLE")?,
                            "Normal three-second lock timeout and five-second timer backoff were bypassed");
                        break;
                    },
                    _=>{},
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        ensure!(process_identity(&monitor.pool,&baseline,pod).await?==identity,"Transient retry replaced the owned process");
        rollback(&mut lock).await?;
        // A normal API acceptance creates durable intent; the owner seeds only
        // historical test timestamps. The worker must naturally accept one STOP.
        let created=f.create("worker-transient-expiry").await.map_err(api_failure)?;
        let mut tx=f.owner_transaction().await?;
        sqlx::query("UPDATE instances SET compute_lease_started_at='1970-01-01T00:00:00Z',compute_lease_expires_at='1970-01-01T00:01:00Z' WHERE tenant_id=$1 AND id=$2")
            .bind(f.actor.tenant_id).bind(created.body.resource.id).execute(&mut *tx).await?;
        tx.commit().await?;
        let deadline=Instant::now()+Duration::from_secs(12);
        loop{
            ensure!(owned.child.try_wait()?.is_none(),"Transient recovery killed the worker");
            let mut tx=f.owner_transaction().await?;
            let stopped:i64=sqlx::query_scalar("SELECT count(*) FROM operations WHERE tenant_id=$1 AND instance_id=$2 AND kind='STOP' AND stop_reason='LEASE_EXPIRED'")
                .bind(f.actor.tenant_id).bind(created.body.resource.id).fetch_one(&mut *tx).await?;
            tx.commit().await?;
            ensure!(Instant::now()<deadline && stopped<=1,"Original expiry was lost, delayed or accepted more than once");
            if stopped==1{break;}
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        ensure!(process_identity(&monitor.pool,&baseline,pod).await?==identity,"Expiry recovery restarted the process");
        let pid=owned.child.id().context("Owned worker PID missing")?;
        kill(Pid::from_raw(i32::try_from(pid)?),Signal::SIGTERM)?;
        owned.exited(true).await?;
        absent(&monitor.pool,&baseline).await?;
        Ok::<(),anyhow::Error>(())
    }.await;
    let release = rollback(&mut lock).await;
    let cleanup = owned.cleanup().await;
    let absence = absent(&monitor.pool, &baseline).await;
    outcome?;
    release?;
    absence?;
    let (out, err) = cleanup?;
    ensure!(
        out.contains("DEPENDENCY_UNAVAILABLE")
            && out.matches("database connection pool drained").count() == 1
            && err.is_empty(),
        "Transient timer recovery did not preserve normal signal exit and pool drain"
    );
    println!(
        "WORKER_PROCESS TRANSIENT SAME_PROCESS_BACKOFF_RECOVERY_ONE_STOP_PHYSICAL_BACKENDS_ABSENT"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires a fresh literal-loopback disposable PostgreSQL DB with explicit TEST_*DATABASE_URL roles"]
async fn actual_worker_supervises_runtime_acl_drift_and_recovers_timer_lock_timeout()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let url = std::env::var("TEST_WORKER_DATABASE_URL").context("Worker process URL required")?;
    let parsed = url::Url::parse(&url)?;
    let expected = url::Url::parse(&std::env::var("TEST_DATABASE_URL")?)?;
    ensure!(
        parsed.username() == "sandbox_worker"
            && parsed.path().starts_with("/sandbox_worker_process_")
            && parsed.path().ends_with("_test")
            && parsed.path() == expected.path()
            && parsed.host_str() == expected.host_str()
            && parsed.port_or_known_default() == expected.port_or_known_default()
            && parsed.host_str().is_some_and(|host| host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())),
        "Actual worker process needs its exact login on the fresh literal-loopback fixture database"
    );
    sandbox_platform::config::validate_database_url(&url, false)?;
    let f = Fixture::new(10).await?;
    let fresh: i64 = sqlx::query_scalar("SELECT count(*) FROM instance_timers")
        .fetch_one(&f.owner)
        .await?;
    ensure!(
        fresh == 0,
        "Worker process suite must use a fresh DB, never clear existing timer intent"
    );
    sqlx::raw_sql(include_str!("../scripts/sql/worker-role.sql"))
        .execute(&f.owner)
        .await?;
    let monitor = Database::connect(&url, 1).await?;
    monitor.verify_runtime_role().await?;
    let files = tempfile::tempdir()?;
    let kubeconfig = files.path().join("kubeconfig.json");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("https://{}", listener.local_addr()?);
    // Own the endpoint throughout the trial and immediately close every socket.
    // No HTTP request, simulated guest response or shared kubeconfig is used.
    let reject_shutdown = tokio_util::sync::CancellationToken::new();
    let reject_signal = reject_shutdown.clone();
    let rejector = tokio::spawn(async move {
        loop {
            tokio::select! {
                _=reject_signal.cancelled()=>return Ok::<(),anyhow::Error>(()),
                socket=listener.accept()=>{let (stream,_)=socket?;drop(stream);},
            }
        }
    });
    std::fs::write(
        &kubeconfig,
        serde_json::to_vec(&serde_json::json!({
            "apiVersion":"v1","kind":"Config","current-context":"owned-local-test",
            "clusters":[{"name":"owned-local-test","cluster":{"server":endpoint}}],
            "contexts":[{"name":"owned-local-test","context":{"cluster":"owned-local-test","user":"owned-local-test"}}],
            "users":[{"name":"owned-local-test","user":{"token":"test-only-local-worker-no-authority"}}]
        }))?,
    )?;
    let pod = Uuid::new_v4();
    let outcome = async {
        permanent_trial(&f, &monitor, &url, &kubeconfig, pod, false).await?;
        permanent_trial(&f, &monitor, &url, &kubeconfig, pod, true).await?;
        transient_trial(&f, &monitor, &url, &kubeconfig, pod).await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    reject_shutdown.cancel();
    let reject_result = rejector.await;
    monitor.pool.close().await;
    f.database.pool.close().await;
    f.owner.close().await;
    outcome?;
    reject_result??;
    println!("WORKER_PROCESS_ACTUAL_ACL_TIMER_TRANSIENT_DRAIN_VERIFIED");
    Ok(())
}
