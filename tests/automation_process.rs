#![cfg(unix)]
//! Actual automation binary/TLS/PostgreSQL lifecycle. No migrations, grants,
//! private schema, guest effects or cloud/runtime certification are created here.
use std::{collections::BTreeMap, path::Path, process::Stdio, time::Duration};

use anyhow::{Context, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use sandbox_platform::db::Database;
use sqlx::{PgPool, Postgres, Transaction};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    task::JoinHandle,
    time::Instant,
};
use uuid::Uuid;

const OBSERVE: Duration = Duration::from_secs(5);
const LOCK_WINDOW: Duration = Duration::from_secs(2);
const READY: Duration = Duration::from_secs(10);
const EXIT: Duration = Duration::from_secs(10);
type Backend = (i32, DateTime<Utc>);
type Backends = BTreeMap<Backend, (String, bool, bool)>;
type OutputReader = JoinHandle<anyhow::Result<Vec<u8>>>;

#[path = "automation_process/faults.rs"]
mod faults;

fn protected_url(environment: &str, role: &str, ca: &Path) -> anyhow::Result<url::Url> {
    let value = std::env::var(environment).context("Protected process database URL is required")?;
    let mut parsed = url::Url::parse(&value)
        .map_err(|_| anyhow::anyhow!("Protected process database URL is invalid"))?;
    ensure!(
        matches!(parsed.scheme(), "postgres" | "postgresql")
            && parsed.username() == role
            && parsed
                .password()
                .is_some_and(|password| !password.is_empty())
            && parsed.query().is_none()
            && parsed.fragment().is_none()
            && parsed.host_str().is_some_and(|host| host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback()))
            && parsed.path().starts_with("/sandbox_automation_")
            && parsed.path().ends_with("_test")
            && parsed.path().len() <= 64
            && parsed
                .path()
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/_".contains(&byte)),
        "Process test requires the exact LOGIN and a dedicated literal-loopback database URL without query overrides"
    );
    parsed
        .query_pairs_mut()
        .append_pair("sslmode", "verify-full")
        .append_pair(
            "sslrootcert",
            ca.to_str().context("Test CA path must be UTF-8")?,
        );
    sandbox_platform::config::validate_database_url(parsed.as_str(), false)?;
    Ok(parsed)
}

async fn sessions(pool: &PgPool, blocker: Option<i32>) -> anyhow::Result<Backends> {
    let deadline = Instant::now() + OBSERVE;
    let rows = tokio::time::timeout_at(deadline, async {
        let mut tx = pool.begin().await?;
        sqlx::query("SET TRANSACTION READ ONLY").execute(&mut *tx).await?;
        let rows: Vec<(i32, DateTime<Utc>, String, bool, bool)> = sqlx::query_as(
            "SELECT a.pid,a.backend_start,a.application_name,COALESCE($1=ANY(pg_blocking_pids(a.pid)),false),s.ssl FROM pg_stat_activity a JOIN pg_stat_ssl s ON s.pid=a.pid WHERE a.datname=current_database() AND a.usename=current_user AND a.backend_type='client backend' ORDER BY a.pid",
        ).bind(blocker).fetch_all(&mut *tx).await?;
        tx.commit().await?;
        Ok::<_, anyhow::Error>(rows)
    }).await.context("Same-LOGIN backend observation exceeded original bound")??;
    ensure!(
        Instant::now() < deadline,
        "Backend observation COMMIT acknowledgment was late"
    );
    Ok(rows
        .into_iter()
        .map(|(pid, start, label, blocked, ssl)| ((pid, start), (label, blocked, ssl)))
        .collect())
}

fn child_backends(rows: &Backends, baseline: &Backends) -> Backends {
    rows.iter()
        .filter(|(identity, _)| !baseline.contains_key(*identity))
        .map(|(identity, value)| (*identity, value.clone()))
        .collect()
}

fn process_identity(rows: &Backends, pod: Uuid) -> anyhow::Result<Uuid> {
    ensure!(
        !rows.is_empty() && rows.len() <= 4,
        "Owned binary backend count is missing or above its configured pool cap"
    );
    let mut identity = None;
    let mut full_label: Option<&str> = None;
    for (label, _, ssl) in rows.values() {
        ensure!(
            *ssl,
            "Actual automation binary backend did not negotiate PostgreSQL TLS"
        );
        // Telemetry is comparison data only. The owned process, same LOGIN and
        // fresh PID/backend_start set establish which rows belong to this trial.
        ensure!(
            label.is_ascii() && label.len() == 61 && label.len() <= 63,
            "Automation process label must preserve both UUIDs within PostgreSQL's byte bound"
        );
        let parts: Vec<_> = label.split('.').collect();
        ensure!(
            parts.len() == 4 && parts[0] == "sbx1" && parts[1] == "automation",
            "Actual binary did not use its fixed automation process role"
        );
        let mut ids = Vec::new();
        for encoded in &parts[2..] {
            ensure!(
                encoded.len() == 22,
                "Process and Pod UUID encodings must retain all 128 bits"
            );
            let bytes = URL_SAFE_NO_PAD
                .decode(encoded)
                .context("Actual process UUID encoding is invalid")?;
            ensure!(
                bytes.len() == 16 && URL_SAFE_NO_PAD.encode(&bytes) == *encoded,
                "Actual process UUID encoding is noncanonical"
            );
            let id = Uuid::from_slice(&bytes).context("Actual process UUID bytes are invalid")?;
            ensure!(!id.is_nil(), "Actual process UUID cannot be nil");
            ids.push(id);
        }
        ensure!(
            ids[1] == pod,
            "Actual binary did not bind the exact configured Pod UID"
        );
        if let Some(previous) = identity {
            ensure!(
                previous == ids[0],
                "One binary has different process UUIDs across its connections"
            );
        }
        if let Some(previous) = full_label {
            ensure!(
                previous == label.as_str(),
                "One binary has different full connection labels"
            );
        }
        identity = Some(ids[0]);
        full_label = Some(label);
    }
    identity.context("Actual binary process UUID was not observed")
}

async fn bounded_output(reader: impl AsyncRead + Unpin) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader.take(16_385).read_to_end(&mut output).await?;
    ensure!(
        output.len() <= 16_384,
        "Owned process output exceeded fixed bound"
    );
    Ok(output)
}

async fn join_reader(task: &mut OutputReader) -> anyhow::Result<Vec<u8>> {
    let deadline = Instant::now() + OBSERVE;
    match tokio::time::timeout_at(deadline, &mut *task).await {
        Ok(joined) => {
            ensure!(
                Instant::now() < deadline,
                "Owned output reader returned after its original deadline"
            );
            joined.context("Owned output reader task failed")?
        }
        Err(_) => {
            task.abort();
            let _ = task.await;
            anyhow::bail!("Owned output reader exceeded original deadline")
        }
    }
}

async fn finish_reader(reader: &mut Option<OutputReader>) -> anyhow::Result<Vec<u8>> {
    match reader.take() {
        Some(mut task) => join_reader(&mut task).await,
        None => Ok(Vec::new()),
    }
}

async fn rollback_lock(lock: &mut Option<Transaction<'_, Postgres>>) -> anyhow::Result<()> {
    if let Some(tx) = lock.take() {
        let deadline = Instant::now() + OBSERVE;
        tokio::time::timeout_at(deadline, tx.rollback())
            .await
            .context("Owned startup lock ROLLBACK acknowledgment exceeded original bound")??;
        ensure!(
            Instant::now() < deadline,
            "Owned startup lock ROLLBACK acknowledgment was late"
        );
    }
    Ok(())
}

async fn cleanup_child(child: &mut Option<Child>, failed: bool) -> anyhow::Result<()> {
    let deadline = Instant::now() + OBSERVE;
    tokio::time::timeout_at(deadline, async {
        if let Some(child) = child
            && failed
            && child.try_wait()?.is_none()
        {
            child.kill().await?;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("Owned idle child cleanup exceeded original bound")??;
    ensure!(
        Instant::now() < deadline,
        "Owned idle child cleanup returned late"
    );
    Ok(())
}

async fn require_absent(pool: &PgPool, baseline: &Backends) -> anyhow::Result<()> {
    let deadline = Instant::now() + OBSERVE;
    loop {
        let current = tokio::time::timeout_at(deadline, sessions(pool, None))
            .await
            .context("Exited binary physical backend observation exceeded original bound")??;
        ensure!(
            Instant::now() < deadline,
            "Physical absence observation COMMIT acknowledgment was late"
        );
        if current == *baseline {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Trial {
    Check,
    BindError,
    Ready,
}

impl Trial {
    fn stage(self) -> &'static str {
        match self {
            Self::Check => "CHECK",
            Self::BindError => "BIND_ERROR",
            Self::Ready => "READY_SIGTERM",
        }
    }
}

async fn process_trial(
    owner: &Database,
    monitor: &Database,
    url: &str,
    pod: Uuid,
    trial: Trial,
) -> anyhow::Result<Uuid> {
    println!("AUTOMATION_PROCESS_STEP {} START", trial.stage());
    let baseline = sessions(&monitor.pool, None).await?;
    ensure!(
        baseline.len() == 1,
        "Dedicated same-LOGIN monitor must be the only initial automation backend"
    );
    ensure!(
        baseline.values().all(|(_, _, ssl)| *ssl),
        "Independent automation LOGIN monitor did not negotiate PostgreSQL TLS"
    );
    let mut reservation = Some(std::net::TcpListener::bind("127.0.0.1:0")?);
    let address = reservation
        .as_ref()
        .context("Owned probe listener missing")?
        .local_addr()?;
    let mut startup_lock = Some(owner.pool.begin().await?);
    let mut child = None;
    let mut stdout = None;
    let mut stderr = None;
    let mut observed_id = None;
    let outcome = async {
        // The same two-second deadline includes actual lock acquisition, child
        // connection, observation and release ACK. The production three-second
        // lock_timeout is neither enlarged nor disabled.
        let lock_deadline = Instant::now() + LOCK_WINDOW;
        let tx = startup_lock
            .as_mut()
            .context("Owned startup transaction missing")?;
        let (blocker, session, current): (i32, String, String) = tokio::time::timeout_at(
            lock_deadline,
            sqlx::query_as("SELECT pg_backend_pid(),session_user::text,current_user::text")
                .fetch_one(&mut **tx),
        )
        .await
        .context("Owned startup identity query exceeded lock window")??;
        ensure!(
            session == "sandbox_owner" && current == session,
            "Startup blocker must use the exact independent migration LOGIN"
        );
        tokio::time::timeout_at(
            lock_deadline,
            sqlx::query("LOCK TABLE public._sqlx_migrations IN ACCESS EXCLUSIVE MODE")
                .execute(&mut **tx),
        )
        .await
        .context("Owned startup lock was not acquired within original window")??;
        ensure!(
            Instant::now() < lock_deadline,
            "Owned startup lock acquisition acknowledgment was late"
        );
        if trial != Trial::BindError {
            drop(reservation.take());
        }
        let mut command = Command::new(env!("CARGO_BIN_EXE_sandbox-automation"));
        command
            .env_clear()
            .env("RUST_LOG", "sandbox_platform=info,sandbox_automation=info")
            .env("SANDBOX_AUTOMATION_DATABASE_URL", url)
            .env("SANDBOX_PROCESS_POD_UID", pod.to_string())
            .args([
                "--db-max-connections",
                "4",
                "--health-listen",
                &address.to_string(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if trial == Trial::Check {
            command.arg("--check");
        }
        child = Some(
            command
                .spawn()
                .context("Cannot start actual automation binary")?,
        );
        let owned = child.as_mut().context("Owned automation binary missing")?;
        let pid = owned
            .id()
            .context("Actual binary process identity missing")?;
        stdout = Some(tokio::spawn(bounded_output(
            owned.stdout.take().context("Owned stdout missing")?,
        )));
        stderr = Some(tokio::spawn(bounded_output(
            owned.stderr.take().context("Owned stderr missing")?,
        )));
        let early = loop {
            ensure!(
                owned.try_wait()?.is_none(),
                "Actual binary exited before the intended postconnect boundary"
            );
            let rows =
                tokio::time::timeout_at(lock_deadline, sessions(&monitor.pool, Some(blocker)))
                    .await
                    .context(
                        "Actual connected startup blocker was not observed within original window",
                    )??;
            ensure!(
                Instant::now() < lock_deadline,
                "Startup backend observation acknowledgment was late"
            );
            let actual = child_backends(&rows, &baseline);
            if actual.values().any(|(_, blocked, _)| *blocked) {
                break actual;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        let identity = process_identity(&early, pod)?;
        observed_id = Some(identity);
        println!(
            "AUTOMATION_PROCESS_STEP {} CONNECTED_TLS_BLOCKED",
            trial.stage()
        );
        let tx = startup_lock
            .take()
            .context("Actual startup blocker missing")?;
        tokio::time::timeout_at(lock_deadline, tx.commit())
            .await
            .context("Owned startup lock COMMIT acknowledgment exceeded original window")??;
        ensure!(
            Instant::now() < lock_deadline,
            "Owned startup lock COMMIT acknowledgment was late"
        );
        if trial == Trial::Ready {
            let client = reqwest::Client::builder()
                .no_proxy()
                .pool_max_idle_per_host(0)
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_millis(250))
                .build()?;
            let deadline = Instant::now() + READY;
            loop {
                ensure!(
                    owned.try_wait()?.is_none(),
                    "Actual automation binary exited before readiness"
                );
                let ready = client
                    .get(format!("http://{address}/health/ready"))
                    .send()
                    .await
                    .is_ok_and(|response| response.status() == reqwest::StatusCode::NO_CONTENT);
                ensure!(
                    Instant::now() < deadline,
                    "Actual automation readiness returned after its original deadline"
                );
                if ready {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let actual = child_backends(&sessions(&monitor.pool, None).await?, &baseline);
            ensure!(
                early.keys().all(|backend| actual.contains_key(backend)),
                "Ready binary replaced its observed startup backend"
            );
            ensure!(
                process_identity(&actual, pod)? == identity,
                "Ready binary changed its process UUID"
            );
            // Only this owned test process receives a signal. No database PID,
            // container or external worker is terminated.
            kill(Pid::from_raw(i32::try_from(pid)?), Signal::SIGTERM)?;
        }
        let deadline = Instant::now() + EXIT;
        let status = tokio::time::timeout_at(deadline, owned.wait())
            .await
            .context("Actual automation binary did not exit within original deadline")??;
        ensure!(
            Instant::now() < deadline,
            "Actual automation exit acknowledgment was late"
        );
        ensure!(
            status.success() == (trial != Trial::BindError),
            "Actual automation binary did not preserve its intended business exit"
        );
        require_absent(&monitor.pool, &baseline).await?;
        println!("AUTOMATION_PROCESS_STEP {} BACKENDS_ABSENT", trial.stage());
        Ok::<_, anyhow::Error>(())
    }
    .await;
    // Reap every owned resource before propagating a business error. Error-path
    // forced child cleanup is test hygiene, never a successful drain verdict.
    let lock_cleanup = rollback_lock(&mut startup_lock).await;
    let child_cleanup = cleanup_child(&mut child, outcome.is_err()).await;
    let stdout = finish_reader(&mut stdout).await;
    let stderr = finish_reader(&mut stderr).await;
    outcome?;
    lock_cleanup?;
    child_cleanup?;
    let stdout = stdout?;
    let stderr = stderr?;
    let output = std::str::from_utf8(&stdout).context("Owned stdout is not UTF-8")?;
    ensure!(
        output.matches("database connection pool drained").count() == 1,
        "Actual connected wrapper did not finish its single database drain"
    );
    if trial == Trial::BindError {
        let error = std::str::from_utf8(&stderr).context("Owned stderr is not UTF-8")?;
        ensure!(
            error.contains(&format!(
                "os error {}",
                nix::errno::Errno::EADDRINUSE as i32
            )),
            "Actual failure did not reach the intended occupied health-listener bind"
        );
        ensure!(
            reservation
                .as_ref()
                .context("Owned listener released before bind verdict")?
                .local_addr()?
                == address,
            "Startup bind error must come from the still-held owned listener"
        );
    } else {
        ensure!(
            stderr.is_empty(),
            "Successful automation process unexpectedly returned an error"
        );
    }
    println!("AUTOMATION_PROCESS_STEP {} OUTPUT_JOINED", trial.stage());
    observed_id.context("Actual automation process UUID was not observed")
}

#[tokio::test]
#[ignore = "requires fresh formal1..37+39..44 loopback PostgreSQL/TLS, exact owner and automation LOGINs, and actual sandbox-automation binary; no cloud or Kubernetes certification"]
async fn automation_check_bind_error_and_same_pod_restarts_drain_actual_backends()
-> anyhow::Result<()> {
    let expected_worker = std::env::var("TEST_AUTOMATION_WORKER_BINARY")
        .context("Exact runner-hashed worker artifact is required")?;
    let expected_worker = Path::new(&expected_worker);
    ensure!(
        expected_worker.is_absolute()
            && expected_worker.symlink_metadata()?.is_file()
            && expected_worker.canonicalize()?
                == Path::new(env!("CARGO_BIN_EXE_sandbox-automation")).canonicalize()?,
        "Actual process must execute the exact worker artifact hashed by the runner"
    );
    let ca_value = std::env::var("TEST_AUTOMATION_TLS_ROOTCERT")
        .context("Absolute process test CA path is required")?;
    let ca = Path::new(&ca_value);
    ensure!(
        ca.is_absolute() && ca.symlink_metadata()?.is_file() && ca.metadata()?.len() > 0,
        "Process test CA must be an absolute regular nonempty file"
    );
    let url = protected_url("TEST_AUTOMATION_DATABASE_URL", "sandbox_automation", ca)?;
    let owner_url = protected_url("TEST_MIGRATION_DATABASE_URL", "sandbox_owner", ca)?;
    ensure!(
        url.host_str() == owner_url.host_str()
            && url.port_or_known_default() == owner_url.port_or_known_default()
            && url.path() == owner_url.path(),
        "Owner and automation LOGINs must target the same dedicated database"
    );
    let monitor = Database::connect(url.as_str(), 1).await?;
    let owner = match Database::connect(owner_url.as_str(), 1).await {
        Ok(owner) => owner,
        Err(error) => {
            monitor.pool.close().await;
            return Err(error);
        }
    };
    let outcome = async {
        monitor.verify_runtime_role().await?;
        let role: (String, String) = sqlx::query_as("SELECT session_user::text,current_user::text")
            .fetch_one(&monitor.pool)
            .await?;
        ensure!(
            role == ("sandbox_automation".into(), "sandbox_automation".into()),
            "Monitor must use the exact independent automation LOGIN"
        );
        let versions: Vec<i64> = sqlx::query_scalar(
            "SELECT version FROM _sqlx_migrations WHERE success ORDER BY version",
        )
        .fetch_all(&monitor.pool)
        .await?;
        let expected: Vec<i64> = (1..=37).chain([39, 40, 41, 42, 43, 44]).collect();
        ensure!(
            versions == expected,
            "Process test requires formal 1..37+39..44 and no invented migration38"
        );
        let pod = Uuid::new_v4();
        let mut identities = std::collections::BTreeSet::new();
        for trial in [Trial::Check, Trial::BindError, Trial::Ready, Trial::Ready] {
            ensure!(
                identities.insert(process_trial(&owner, &monitor, url.as_str(), pod, trial).await?),
                "Every real process must have a new UUID under the same configured Pod UID"
            );
        }
        ensure!(
            identities.len() == 4,
            "All four actual automation process identities must be distinct"
        );
        faults::verify(&owner, &monitor, url.as_str(), pod).await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    monitor.pool.close().await;
    owner.pool.close().await;
    outcome?;
    println!(
        "VERIFIED automation actual strict TLS startup + runtime fatal drain + natural original-intent handoff + claim/accept transient recovery + final SQL fence recovery / same-LOGIN physical backend absence"
    );
    Ok(())
}
