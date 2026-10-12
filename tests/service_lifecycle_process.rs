#![cfg(unix)]
#[allow(dead_code)]
mod support;

use std::{collections::BTreeSet, process::Stdio, time::Duration};

use anyhow::{Context, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use sandbox_platform::db::Database;
use serde_json::json;
use sqlx::PgPool;
use support::Fixture;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    time::Instant,
};
use uuid::Uuid;

const OBSERVE: Duration = Duration::from_secs(5);
type Backends = BTreeSet<(i32, DateTime<Utc>)>;

async fn sessions(monitor: &PgPool) -> anyhow::Result<Backends> {
    let deadline = Instant::now() + OBSERVE;
    let rows = tokio::time::timeout_at(deadline, async {
        let mut tx = monitor.begin().await?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await?;
        let rows: Vec<(i32, DateTime<Utc>)> = sqlx::query_as(
            "SELECT pid,backend_start FROM pg_stat_activity WHERE datname=current_database() AND usename=current_user AND backend_type='client backend' ORDER BY pid",
        ).fetch_all(&mut *tx).await?;
        tx.commit().await?;
        Ok::<_, anyhow::Error>(rows)
    })
    .await
    .context("Physical backend observation exceeded original bound")??;
    ensure!(
        Instant::now() < deadline,
        "Physical backend COMMIT acknowledgment completed too late"
    );
    Ok(rows.into_iter().collect())
}

async fn bounded_output(reader: impl AsyncRead + Unpin) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader.take(16_385).read_to_end(&mut output).await?;
    ensure!(
        output.len() <= 16_384,
        "Child test output exceeded fixed bound"
    );
    Ok(output)
}

async fn join_reader(
    task: &mut tokio::task::JoinHandle<anyhow::Result<Vec<u8>>>,
) -> anyhow::Result<Vec<u8>> {
    let deadline = Instant::now() + OBSERVE;
    match tokio::time::timeout_at(deadline, &mut *task).await {
        Ok(joined) => {
            ensure!(
                Instant::now() < deadline,
                "Child reader completed after original observation bound"
            );
            joined.context("Child output reader task failed")?
        }
        Err(_) => {
            task.abort();
            let _ = task.await;
            anyhow::bail!("Child output reader exceeded observation bound")
        }
    }
}

async fn observed_process_identity(
    monitor: &PgPool,
    actual: &Backends,
    expected_pod: Uuid,
) -> anyhow::Result<Uuid> {
    let deadline = Instant::now() + OBSERVE;
    let observations = async {
        let mut tx = monitor.begin().await?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await?;
        let rows: Vec<(i32, DateTime<Utc>, String)> = sqlx::query_as(
            "SELECT pid,backend_start,application_name FROM pg_stat_activity WHERE datname=current_database() AND usename=current_user AND backend_type='client backend' ORDER BY pid",
        ).fetch_all(&mut *tx).await?;
        tx.commit().await?;
        Ok::<_, anyhow::Error>(rows)
    };
    let rows = tokio::time::timeout_at(deadline, observations)
        .await
        .context("Process connection identity observation exceeded original bound")??;
    ensure!(
        Instant::now() < deadline,
        "Process identity COMMIT acknowledgment completed too late"
    );
    let mut count = 0;
    let mut identity = None;
    let mut full_label = None;
    for (pid, start, label) in rows {
        // The observed PID/backend_start set was established from the owned
        // child in an isolated database. Never select authority by this label.
        if !actual.contains(&(pid, start)) {
            continue;
        }
        count += 1;
        ensure!(
            label.is_ascii() && label.len() <= 63,
            "Actual PostgreSQL label is not a bounded ASCII name"
        );
        let fields: Vec<_> = label.split('.').collect();
        ensure!(
            fields.len() == 4 && fields[0] == "sbx1" && fields[1] == "api",
            "Actual child label did not use its fixed executable role"
        );
        let mut ids = Vec::new();
        for encoded in &fields[2..] {
            ensure!(
                encoded.len() == 22,
                "Process and Pod identifiers must preserve all 128 bits"
            );
            let bytes = URL_SAFE_NO_PAD
                .decode(encoded)
                .context("Actual child UUID encoding is invalid")?;
            ensure!(
                bytes.len() == 16 && URL_SAFE_NO_PAD.encode(&bytes) == *encoded,
                "Actual child UUID encoding must be canonical without truncation/padding"
            );
            let id = Uuid::from_slice(&bytes).context("Actual child UUID bytes invalid")?;
            ensure!(!id.is_nil(), "Actual child identity cannot be nil");
            ids.push(id);
        }
        ensure!(
            ids[1] == expected_pod,
            "Actual child label did not bind the exact configured Pod UID"
        );
        if let Some(known) = identity {
            ensure!(
                known == ids[0],
                "One process cannot label its connections with different process UUIDs"
            );
        }
        if let Some(known) = &full_label {
            ensure!(
                known == &label,
                "Every actual connection of one child must retain its full label"
            );
        }
        identity = Some(ids[0]);
        full_label = Some(label);
    }
    ensure!(
        count == actual.len() && count > 0,
        "Actual connection identities were not observed for every child backend"
    );
    identity.context("Actual child process UUID was not observed")
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcessCase {
    StartupError,
    ApiSigterm,
    BrowserSigterm,
    BrowserBusySigterm,
    BrowserCleanupErrorSigterm,
    BrowserBindError,
}

fn browser_files() -> anyhow::Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    let secret = directory.path().join("client-secret");
    let keys = directory.path().join("session-keys.json");
    let settings = directory.path().join("browser.json");
    std::fs::write(&secret, b"PUBLIC_BFF_PROCESS_FIXTURE_SECRET_0123456789")?;
    std::fs::write(
        &keys,
        json!({"active":"test","keys":[{"id":"test","key":URL_SAFE_NO_PAD.encode([47;32])}]})
            .to_string(),
    )?;
    std::fs::write(
        &settings,
        json!({
            "oidc": {
                "issuer":"https://identity.example.invalid/realms/lifecycle",
                "authorization_url":"https://identity.example.invalid/realms/lifecycle/authorize",
                "token_url":"https://identity.example.invalid/realms/lifecycle/token",
                "jwks_url":"https://identity.example.invalid/realms/lifecycle/jwks",
                "client_id":"sandbox-browser",
                "public_origin":"https://console.example.invalid",
                "scopes":["openid","sandbox:access"]
            },
            "client_secret_file":secret,
            "session_key_file":keys
        })
        .to_string(),
    )?;
    for path in [&secret, &keys, &settings] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        ensure!(
            std::fs::metadata(path)?.permissions().mode() & 0o777 == 0o600,
            "Actual browser fixture permissions must be private"
        );
    }
    Ok(directory)
}

async fn cleanup_waiting_on(
    monitor: &PgPool,
    blocker: i32,
) -> anyhow::Result<Option<(i32, DateTime<Utc>)>> {
    let mut tx = monitor.begin().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await?;
    let rows: Vec<(i32, DateTime<Utc>)> = sqlx::query_as(
        "SELECT pid,backend_start FROM pg_stat_activity WHERE datname=current_database() AND usename=current_user AND backend_type='client backend' AND state='active' AND wait_event_type='Lock' AND query='SELECT sandbox_browser_cleanup($1)' AND $1=ANY(pg_blocking_pids(pid)) ORDER BY pid",
    ).bind(blocker).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    ensure!(
        rows.len() <= 1,
        "One binary may have only one actual cleanup query"
    );
    Ok(rows.into_iter().next())
}

async fn process_case(
    fixture: &Fixture,
    monitor: &PgPool,
    url: &str,
    case: ProcessCase,
    pod_uid: Uuid,
) -> anyhow::Result<Option<Uuid>> {
    let startup_error = matches!(
        case,
        ProcessCase::StartupError | ProcessCase::BrowserBindError
    );
    let browser_enabled = !matches!(case, ProcessCase::StartupError | ProcessCase::ApiSigterm);
    let lock_cleanup_query = matches!(
        case,
        ProcessCase::BrowserBusySigterm | ProcessCase::BrowserCleanupErrorSigterm
    );

    let baseline = sessions(monitor).await?;
    ensure!(
        !baseline.is_empty(),
        "Independent actual app monitor session missing"
    );
    let mut reservation = Some(std::net::TcpListener::bind("127.0.0.1:0")?);
    let address = reservation
        .as_ref()
        .context("Owned listener missing")?
        .local_addr()?;
    let browser = if browser_enabled {
        Some(browser_files()?)
    } else {
        None
    };
    let mut cursor = tempfile::NamedTempFile::new()?;
    use std::io::Write;
    cursor.write_all(include_bytes!("fixtures/history/cursor-keys.json"))?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_sandboxd"));
    command
        .env_clear()
        .env("RUST_LOG", "sandbox_platform=info,sandboxd=info")
        .env("SANDBOX_DATABASE_URL", url)
        .env("SANDBOX_ALLOW_LOOPBACK_HTTP", "true")
        .env("SANDBOX_PROCESS_POD_UID", pod_uid.to_string())
        .env(
            "SANDBOX_OIDC_ISSUER",
            "https://identity.example.invalid/realms/lifecycle",
        )
        .env(
            "SANDBOX_OIDC_JWKS_URL",
            "https://identity.example.invalid/realms/lifecycle/jwks",
        )
        .args([
            "--role",
            "api",
            "--db-max-connections",
            "2",
            "--listen",
            &address.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if case != ProcessCase::StartupError {
        command.env("SANDBOX_CURSOR_SIGNING_KEY_FILE", cursor.path());
    }
    if let Some(browser) = &browser {
        command.env(
            "SANDBOX_BROWSER_CONFIG_FILE",
            browser.path().join("browser.json"),
        );
    }
    let mut cleanup_lock = if lock_cleanup_query {
        let mut tx = fixture.owner.begin().await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await?;
        sqlx::query("LOCK TABLE public.browser_login_challenges IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await?;
        Some((tx, pid))
    } else {
        None
    };
    if case != ProcessCase::BrowserBindError {
        drop(reservation.take());
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let rollback = async {
                let Some((tx, _)) = cleanup_lock.take() else {
                    return Ok::<_, anyhow::Error>(());
                };
                let deadline = Instant::now() + OBSERVE;
                tokio::time::timeout_at(deadline, tx.rollback())
                    .await
                    .context("Spawn-error owner lock ROLLBACK acknowledgment timed out")??;
                ensure!(
                    Instant::now() < deadline,
                    "Spawn-error owner lock ROLLBACK acknowledgment completed too late"
                );
                Ok(())
            }
            .await;
            if rollback.is_err() {
                tracing::warn!("Spawn-error owned lock cleanup did not complete");
            }
            return Err(error).context("Cannot start actual sandboxd binary");
        }
    };
    let pid = child
        .id()
        .context("Actual child process identity missing")?;
    let mut stdout = tokio::spawn(bounded_output(
        child.stdout.take().context("Child stdout missing")?,
    ));
    let mut stderr = tokio::spawn(bounded_output(
        child.stderr.take().context("Child stderr missing")?,
    ));
    let mut process_identity = None;
    let outcome = async {
        let mut actual = Backends::new();
        let mut blocked_backend = None;
        if !startup_error {
            let client = reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_millis(250))
                .build()?;
            let deadline = Instant::now() + OBSERVE;
            loop {
                ensure!(
                    child.try_wait()?.is_none(),
                    "Actual API exited before ready"
                );
                if client
                    .get(format!("http://{address}/health/ready"))
                    .send()
                    .await
                    .is_ok_and(|r| r.status() == reqwest::StatusCode::NO_CONTENT)
                {
                    ensure!(
                        Instant::now() < deadline,
                        "Actual API became ready after its original observation bound"
                    );
                    break;
                }
                ensure!(
                    Instant::now() < deadline,
                    "Actual API readiness was not reached"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            actual = sessions(monitor)
                .await?
                .difference(&baseline)
                .copied()
                .collect();
            ensure!(
                !actual.is_empty() && actual.len() <= 2,
                "Ready binary actual component backends missing or above its configured cap"
            );
            process_identity = Some(observed_process_identity(monitor, &actual, pod_uid).await?);
            if let Some((_, blocker)) = &cleanup_lock {
                let deadline = Instant::now() + OBSERVE;
                let blocked = loop {
                    let observed =
                        tokio::time::timeout_at(deadline, cleanup_waiting_on(monitor, *blocker))
                            .await
                            .context("Cleanup lock observation exceeded original bound")??;
                    ensure!(
                        Instant::now() < deadline,
                        "Cleanup lock observation completed too late"
                    );
                    if let Some(backend) = observed {
                        break backend;
                    }
                    ensure!(
                        child.try_wait()?.is_none(),
                        "API exited before actual cleanup lock wait"
                    );
                    tokio::time::sleep(Duration::from_millis(20)).await;
                };
                ensure!(
                    actual.contains(&blocked),
                    "Cleanup must belong to an actual child backend"
                );
                blocked_backend = Some(blocked);
                if case == ProcessCase::BrowserCleanupErrorSigterm {
                    let deadline = Instant::now() + OBSERVE;
                    loop {
                        let waiting = tokio::time::timeout_at(
                            deadline,
                            cleanup_waiting_on(monitor, *blocker),
                        )
                        .await
                        .context("Cleanup lock timeout was not observed")??;
                        ensure!(
                            Instant::now() < deadline,
                            "Cleanup error observation completed too late"
                        );
                        if waiting.is_none() {
                            break;
                        }
                        ensure!(
                            child.try_wait()?.is_none(),
                            "Cleanup SQL error terminated the live API"
                        );
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    ensure!(
                        child.try_wait()?.is_none(),
                        "Cleanup SQL error must keep the API running"
                    );
                    let response = client
                        .get(format!("http://{address}/health/ready"))
                        .send()
                        .await?;
                    ensure!(
                        response.status() == reqwest::StatusCode::NO_CONTENT,
                        "API readiness must survive cleanup SQL lock_timeout"
                    );
                }
            }
            // Only this owned test child receives SIGTERM; no database backend,
            // container, VM or external process is force terminated.
            kill(Pid::from_raw(i32::try_from(pid)?), Signal::SIGTERM)?;
            if case == ProcessCase::BrowserBusySigterm {
                tokio::time::sleep(Duration::from_millis(100)).await;
                ensure!(
                    child.try_wait()?.is_none(),
                    "API returned while cleanup SQL acknowledgment was pending"
                );
                let (_, blocker) = cleanup_lock
                    .as_ref()
                    .context("Actual cleanup lock missing")?;
                let deadline = Instant::now() + OBSERVE;
                let waiting =
                    tokio::time::timeout_at(deadline, cleanup_waiting_on(monitor, *blocker))
                        .await
                        .context("Post-SIGTERM cleanup observation timed out")??;
                ensure!(
                    Instant::now() < deadline,
                    "Post-SIGTERM observation completed too late"
                );
                ensure!(
                    waiting.is_some() && waiting == blocked_backend,
                    "SIGTERM must retain the same in-flight cleanup query and backend identity"
                );
            }
            if let Some((tx, _)) = cleanup_lock.take() {
                // The owner transaction's actual COMMIT acknowledgment releases
                // the known blocker before the binary is allowed to finish.
                let deadline = Instant::now() + OBSERVE;
                tokio::time::timeout_at(deadline, tx.commit())
                    .await
                    .context("Owned cleanup blocker COMMIT acknowledgment timed out")??;
                ensure!(
                    Instant::now() < deadline,
                    "Cleanup blocker COMMIT acknowledgment completed too late"
                );
            }
        }
        let exit_deadline = Instant::now() + OBSERVE;
        let status = tokio::time::timeout_at(exit_deadline, child.wait())
            .await
            .context("Actual sandboxd did not exit within test observation bound")??;
        ensure!(
            Instant::now() < exit_deadline,
            "Actual binary exit exceeded its original observation bound"
        );
        ensure!(
            status.success() != startup_error,
            "Actual binary exit did not preserve its business outcome"
        );
        let deadline = Instant::now() + OBSERVE;
        loop {
            let current = tokio::time::timeout_at(deadline, sessions(monitor))
                .await
                .context("Exited binary backend observation exceeded its original deadline")??;
            ensure!(
                Instant::now() < deadline,
                "Actual backend observation completed after its original deadline"
            );
            if current == baseline {
                ensure!(
                    actual.is_disjoint(&current),
                    "Actual binary backend survived completed shutdown"
                );
                break;
            }
            ensure!(
                Instant::now() < deadline,
                "Exited actual binary still has a component PostgreSQL backend"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let lock_cleanup = match cleanup_lock.take() {
        Some((tx, _)) => {
            let deadline = Instant::now() + OBSERVE;
            let rollback = tokio::time::timeout_at(deadline, tx.rollback()).await;
            match rollback {
                Ok(result) => result
                    .context("Owned cleanup lock rollback did not complete")
                    .and_then(|()| {
                        ensure!(
                            Instant::now() < deadline,
                            "Owned cleanup lock rollback completed too late"
                        );
                        Ok(())
                    }),
                Err(_) => Err(anyhow::anyhow!(
                    "Owned cleanup lock rollback acknowledgment timed out"
                )),
            }
        }
        None => Ok(()),
    };
    // Test failure remains a failure. Reap only this owned idle API child so a
    // failed assertion cannot leave a local server behind or certify drain.
    let cleanup = match tokio::time::timeout(OBSERVE, async {
        if outcome.is_err() && child.try_wait()?.is_none() {
            child.kill().await?;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!(
            "Owned test child cleanup exceeded observation bound"
        )),
    };
    // Reap both readers before propagating any business/cleanup/reader error.
    // A timeout retains the handle, aborts it and awaits its actual termination.
    let stdout = join_reader(&mut stdout).await;
    let stderr = join_reader(&mut stderr).await;
    outcome?;
    lock_cleanup?;
    cleanup?;
    let stdout = stdout?;
    let stderr = stderr?;
    let output = std::str::from_utf8(&stdout).context("Actual child stdout is not UTF-8")?;
    ensure!(
        output.matches("database connection pool drained").count() == 1,
        "Actual connected wrapper did not complete its single drain marker"
    );
    if startup_error {
        let error = std::str::from_utf8(&stderr).context("Actual child stderr is not UTF-8")?;
        if case == ProcessCase::StartupError {
            ensure!(
                error.contains("SANDBOX_CURSOR_SIGNING_KEY_FILE is required for the API role"),
                "Startup error did not reach the intended postconnect boundary"
            );
        } else {
            ensure!(
                error.contains(&format!(
                    "os error {}",
                    nix::errno::Errno::EADDRINUSE as i32
                )),
                "Browser startup failure must reach actual occupied-listener bind"
            );
            ensure!(
                reservation
                    .as_ref()
                    .context("Owned listener was released too soon")?
                    .local_addr()?
                    == address,
                "Only the held owned listener may induce startup bind error"
            );
        }
        ensure!(
            !output.contains("API listening")
                && !output.contains("browser session cleanup stopped"),
            "Startup failure must not start API or cleanup parents"
        );
    } else {
        ensure!(
            output.contains("shutdown requested") && output.contains("API listening"),
            "Actual SIGTERM signal and API parent exit were not reached"
        );
    }
    if browser_enabled && !startup_error {
        ensure!(
            output.matches("browser session cleanup stopped").count() == 1,
            "Actual BFF cleanup parent must finish exactly once"
        );
        let stopped = output
            .find("browser session cleanup stopped")
            .context("Cleanup parent completion marker missing")?;
        let drained = output
            .find("database connection pool drained")
            .context("Pool drain marker missing")?;
        ensure!(
            stopped < drained,
            "Cleanup parent must finish before physical pool drain marker"
        );
        let expected_errors = usize::from(case == ProcessCase::BrowserCleanupErrorSigterm);
        ensure!(
            output
                .matches("browser session cleanup unavailable")
                .count()
                == expected_errors,
            "Actual cleanup SQL outcome must preserve the intended warning/continuation behavior"
        );
    } else {
        ensure!(
            !output.contains("browser session cleanup stopped"),
            "Disabled or never-started cleanup must not report completion"
        );
    }
    Ok(process_identity)
}

#[tokio::test]
#[ignore = "requires fresh local PostgreSQL formal37 and actual sandboxd binary; not installed cloud/PKI/runtime or capacity certification"]
async fn sandboxd_startup_error_and_sigterm_finish_database_drain() -> anyhow::Result<()> {
    let _serial = support::serial().await;
    let fixture = Fixture::new(1).await?;
    let owner_role: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(&fixture.owner)
        .await?;
    ensure!(
        owner_role == "sandbox_owner",
        "Existing browser grants must be applied by the actual migration owner"
    );
    // Fixture::new applies normal formal 1..37. Use the same already-reviewed
    // production role script; no test function, extra authority or draft DDL.
    sqlx::raw_sql(include_str!("../scripts/sql/browser-role.sql"))
        .execute(&fixture.owner)
        .await?;
    let url = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL is required")?;
    let monitor = Database::connect(&url, 1).await?;
    let outcome = async {
        monitor.verify_runtime_role().await?;
        let role: String = sqlx::query_scalar("SELECT session_user::text")
            .fetch_one(&monitor.pool)
            .await?;
        ensure!(
            role == "sandbox_app",
            "Actual binary monitor must use component LOGIN"
        );
        // A fresh fixture Pod UID remains the same across owned process
        // restarts. Actual database labels must show new process UUIDs.
        let pod_uid = Uuid::new_v4();
        let mut process_ids = BTreeSet::new();
        for case in [
            ProcessCase::StartupError,
            ProcessCase::ApiSigterm,
            ProcessCase::BrowserSigterm,
            ProcessCase::BrowserBusySigterm,
            ProcessCase::BrowserCleanupErrorSigterm,
            ProcessCase::BrowserBindError,
        ] {
            let id = process_case(&fixture, &monitor.pool, &url, case, pod_uid).await?;
            match id {
                Some(id) => ensure!(
                    process_ids.insert(id),
                    "Same-Pod restart must create a new process UUID"
                ),
                None => ensure!(
                    matches!(
                        case,
                        ProcessCase::StartupError | ProcessCase::BrowserBindError
                    ),
                    "Every ready child must expose its actual physical connection labels"
                ),
            }
        }
        ensure!(
            process_ids.len() == 4,
            "All four ready process identities must be distinct under the same Pod UID"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    monitor.pool.close().await;
    fixture.database.pool.close().await;
    fixture.owner.close().await;
    outcome?;
    println!(
        "lifecycle actual BFF ready, in-flight SQL SIGTERM, SQL error continuation and owned bind failure / four process trials completed"
    );
    println!(
        "lifecycle actual sandboxd postconnect startup error and API SIGTERM / physical backend absence completed"
    );
    Ok(())
}
