//! Production O3 GateJournal integration acceptance: no private test library or pool access.
//! The ignored five-test filter requires the locked external SQLite 3.53.4.
use anyhow::{Context, ensure};
use chrono::Utc;
use sandbox_platform::nodeguard::{
    GuardError,
    journal::{GateJournal, StartKind},
    protocol::*,
};
use serde::{Deserialize, Serialize};
use sqlx::{Connection, SqliteConnection, sqlite::SqliteConnectOptions};
use std::{
    collections::HashSet,
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use uuid::Uuid;

fn node() -> NodeBinding {
    NodeBinding {
        cluster_epoch: Uuid::new_v4(),
        node_uid: Uuid::new_v4(),
        node_name: "node-1".into(),
        boot_id: Uuid::new_v4(),
        profile_sha256: "a".repeat(64),
    }
}
fn request(node: NodeBinding) -> RegisterLaunchRequest {
    let workspace_id = Uuid::new_v4();
    RegisterLaunchRequest {
        protocol: 1,
        permit_id: Uuid::new_v4(),
        node,
        expires_at: Utc::now() + chrono::Duration::minutes(5),
        launch: LaunchBinding {
            purpose: LaunchPurpose::Workload,
            tenant_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            instance_id: Uuid::new_v4(),
            workspace_id,
            generation: 1,
            launch_id: Uuid::new_v4(),
            pod_uid: Uuid::new_v4(),
            namespace: "test-project".into(),
            pod_name: format!("sbx-ws-{workspace_id}"),
            pvc_uid: Uuid::new_v4(),
            pv_uid: Uuid::new_v4(),
            pv_name: "pv-test".into(),
            csi_volume_handle: "d-test".into(),
        },
    }
}
fn close(r: &RegisterLaunchRequest) -> CloseRequest {
    CloseRequest {
        protocol: 1,
        challenge_id: Uuid::new_v4(),
        node: r.node.clone(),
        launch: r.launch.clone(),
        reason: CloseReason::Stop,
        challenge_expires_at: Utc::now() + chrono::Duration::minutes(1),
    }
}
fn observation() -> SandboxObservation {
    SandboxObservation {
        sandbox_id: "b".repeat(64),
        cgroup: CgroupIdentity {
            relative_path: "fixture".into(),
            device: 1,
            inode: 1,
        },
        registered_at: Utc::now(),
        processes: vec![ProcessIdentity {
            role: ProcessRole::Hypervisor,
            pid: 4,
            start_time_ticks: 5,
            executable_sha256: "c".repeat(64),
        }],
    }
}

const RELEASE_SQLITE_VERSION: &str = "3.53.4";
const CRASH_WRITER_TEST: &str = "sqlite_release_crash_writer";
const CRASH_FIXTURE_ENV: &str = "SANDBOX_SQLITE_CRASH_FIXTURE";
const CRASH_TOKEN_ENV: &str = "SANDBOX_SQLITE_CRASH_TOKEN";

async fn assert_runtime_contract(journal: &GateJournal) -> anyhow::Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "release acceptance requires Linux"
    );
    // All connection-local values come from the production journal's own
    // connection. The independent probes below never stand in for this check.
    let diagnostics = journal.storage_diagnostics().await?;
    ensure!(
        diagnostics.sqlite_version == RELEASE_SQLITE_VERSION,
        "SQLx must execute locked SQLite {RELEASE_SQLITE_VERSION}; linked {}",
        diagnostics.sqlite_version
    );
    let lock: serde_json::Value =
        serde_json::from_str(include_str!("../scripts/release/native-security.lock.json"))?;
    ensure!(
        lock["sqlite"]["version"].as_str() == Some(RELEASE_SQLITE_VERSION)
            && lock["sqlite"]["source_id"].as_str() == Some(diagnostics.sqlite_source_id.as_str()),
        "SQLx SQLite source identity differs from the native release lock"
    );
    ensure!(diagnostics.journal_mode == "wal", "journal must use WAL");
    ensure!(
        diagnostics.synchronous == 2
            && diagnostics.foreign_keys == 1
            && diagnostics.busy_timeout_millis == 5000,
        "unexpected production connection settings"
    );
    let options: HashSet<String> = diagnostics.compile_options.into_iter().collect();
    for required in [
        "DEFAULT_FOREIGN_KEYS",
        "ENABLE_API_ARMOR",
        "ENABLE_COLUMN_METADATA",
        "ENABLE_DBSTAT_VTAB",
        "ENABLE_FTS3",
        "ENABLE_FTS3_PARENTHESIS",
        "ENABLE_FTS5",
        "ENABLE_LOAD_EXTENSION",
        "ENABLE_MEMORY_MANAGEMENT",
        "ENABLE_RTREE",
        "ENABLE_STAT4",
        "ENABLE_UNLOCK_NOTIFY",
        "SOUNDEX",
        "THREADSAFE=1",
        "USE_URI",
    ] {
        ensure!(
            options.contains(required),
            "missing SQLite option: {required}"
        );
    }
    for omitted in ["OMIT_FOREIGN_KEY", "OMIT_WAL", "OMIT_JSON", "THREADSAFE=0"] {
        ensure!(
            !options.contains(omitted),
            "unsafe SQLite option: {omitted}"
        );
    }
    Ok(())
}

// Fixture setup represents the trusted host enrollment prerequisite. This is
// deliberately local SQL in an isolated temporary database, not a new public
// enrollment or arbitrary-SQL API on GateJournal.
async fn trusted_fixture_coverage(probe: &mut SqliteConnection) -> anyhow::Result<()> {
    let changed = sqlx::query("UPDATE guard_meta SET coverage_verified=1,revision=revision+1 WHERE singleton=1 AND quarantined=0")
        .execute(probe).await?.rows_affected();
    ensure!(
        changed == 1,
        "fixture node must be healthy before verified enrollment"
    );
    Ok(())
}

async fn database_probe(path: &Path) -> anyhow::Result<SqliteConnection> {
    Ok(SqliteConnection::connect_with(
        &SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(false)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5)),
    )
    .await?)
}

async fn checked_journal(path: &Path, node: NodeBinding) -> anyhow::Result<GateJournal> {
    let journal = GateJournal::open(path, node).await?;
    assert_runtime_contract(&journal).await?;
    let mut probe = database_probe(path).await?;
    let json: i64 = sqlx::query_scalar("SELECT json_extract('{\"proof\":1}', '$.proof')")
        .fetch_one(&mut probe)
        .await?;
    ensure!(json == 1, "journal JSON expressions must execute");
    probe.close().await?;
    Ok(journal)
}

fn assert_sqlite_error<T>(result: Result<T, GuardError>, primary_code: i32) -> anyhow::Result<()> {
    let Err(GuardError::Journal(sqlx::Error::Database(error))) = result else {
        anyhow::bail!("operation must fail with SQLite primary error {primary_code}");
    };
    let code = error
        .code()
        .context("SQLite error has no result code")?
        .parse::<i32>()?;
    ensure!(
        code & 0xff == primary_code,
        "unexpected SQLite result code {code}"
    );
    Ok(())
}

async fn ledger_state(probe: &mut SqliteConnection) -> anyhow::Result<(i64, i64, i64, i64)> {
    Ok(sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM guard_launches), \
         (SELECT COUNT(*) FROM guard_attempts), \
         (SELECT COALESCE(SUM(forwarded_starts),0) FROM guard_launches), \
         revision FROM guard_meta WHERE singleton=1",
    )
    .fetch_one(&mut *probe)
    .await?)
}

#[tokio::test]
async fn nodeguard_journal_regression_lifecycle_keeps_closed_uid_across_restart()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.sqlite3");
    let registration = request(node());
    let journal = GateJournal::open(&path, registration.node.clone()).await?;
    let diagnostics = journal.storage_diagnostics().await?;
    ensure!(
        diagnostics.journal_mode == "wal"
            && diagnostics.synchronous == 2
            && diagnostics.foreign_keys == 1
            && diagnostics.busy_timeout_millis == 5000,
        "production journal connection settings changed"
    );
    let mut probe = database_probe(&path).await?;
    trusted_fixture_coverage(&mut probe).await?;
    journal.register(&registration).await?;
    let permit = journal
        .begin_start(registration.launch.pod_uid, StartKind::Run)
        .await?;
    journal.settle(&permit, Some(&observation()), None).await?;
    ensure!(
        matches!(
            journal
                .begin_start(registration.launch.pod_uid, StartKind::Run)
                .await,
            Err(GuardError::Closed)
        ),
        "second RUN was admitted"
    );
    let closed = journal.close(&close(&registration)).await?;
    ensure!(
        closed.forwarded_starts == 1 && closed.state == ObservationState::WaitingRuntime,
        "closure changed the durable forwarding receipt"
    );
    journal.shutdown().await;
    let reopened = GateJournal::open(&path, registration.node.clone()).await?;
    trusted_fixture_coverage(&mut probe).await?;
    ensure!(
        matches!(
            reopened.register(&registration).await,
            Err(GuardError::Closed)
        ),
        "closed UID reopened"
    );
    ensure!(
        matches!(
            reopened.require_open(registration.launch.pod_uid).await,
            Err(GuardError::Closed)
        ),
        "closed UID remained usable"
    );
    ensure!(
        matches!(
            reopened
                .begin_start(registration.launch.pod_uid, StartKind::Start)
                .await,
            Err(GuardError::Closed)
        ),
        "clean restart replayed START"
    );
    let (state, forwarded): (String, i64) =
        sqlx::query_as("SELECT state,forwarded_starts FROM guard_launches WHERE pod_uid=$1")
            .bind(registration.launch.pod_uid.to_string())
            .fetch_one(&mut probe)
            .await?;
    ensure!(
        state == "CLOSED" && forwarded == 1,
        "clean restart lost the closed receipt"
    );
    reopened.shutdown().await;
    probe.close().await?;
    Ok(())
}

#[tokio::test]
async fn nodeguard_journal_regression_failed_open_rolls_back_and_drains() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.sqlite3");
    let registration = request(node());
    let journal = GateJournal::open(&path, registration.node.clone()).await?;
    let mut probe = database_probe(&path).await?;
    trusted_fixture_coverage(&mut probe).await?;
    journal.register(&registration).await?;
    journal.shutdown().await;
    sqlx::raw_sql("CREATE TRIGGER fail_enrollment BEFORE UPDATE OF node_json ON guard_meta BEGIN SELECT RAISE(ABORT,'PUBLIC_INTENTIONAL_ENROLLMENT_FAILURE'); END;")
        .execute(&mut probe).await?;
    let mut next = registration.node.clone();
    next.boot_id = Uuid::new_v4();
    assert_sqlite_error(GateJournal::open(&path, next).await, 19)?;
    // open() must have completed its worker rollback and connection drain when
    // the public error returns, not merely queued rollback from Drop.
    tokio::time::timeout(
        Duration::from_secs(2),
        sqlx::query("BEGIN IMMEDIATE").execute(&mut probe),
    )
    .await
    .context("failed enrollment retained a write lock")??;
    let (state, prior): (String,String) = sqlx::query_as("SELECT l.state,m.node_json FROM guard_launches l CROSS JOIN guard_meta m WHERE l.pod_uid=$1")
        .bind(registration.launch.pod_uid.to_string()).fetch_one(&mut probe).await?;
    ensure!(
        state == "OPEN" && serde_json::from_str::<NodeBinding>(&prior)? == registration.node,
        "failed enrollment partially persisted new-boot fencing"
    );
    sqlx::query("ROLLBACK").execute(&mut probe).await?;
    sqlx::query("DROP TRIGGER fail_enrollment")
        .execute(&mut probe)
        .await?;
    probe.close().await?;
    GateJournal::open(&path, registration.node)
        .await?
        .shutdown()
        .await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires the production Linux static SQLite 3.53.4 build"]
async fn sqlite_release_acceptance_runtime_contract() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.sqlite3");
    let journal = checked_journal(&path, node()).await?;
    let mut probe = database_probe(&path).await?;
    let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_one(&mut probe)
        .await?;
    ensure!(
        integrity == "ok",
        "fresh journal failed SQLite integrity check"
    );
    journal.shutdown().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires the production Linux static SQLite 3.53.4 build; holds two real writer locks"]
async fn sqlite_release_acceptance_writer_contention_fails_closed_and_recovers()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.sqlite3");
    let registration = request(node());
    let journal = checked_journal(&path, registration.node.clone()).await?;
    let mut probe = database_probe(&path).await?;
    trusted_fixture_coverage(&mut probe).await?;
    let mut competing_writer = SqliteConnection::connect_with(
        &SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(false)
            .foreign_keys(true)
            .busy_timeout(Duration::from_millis(250)),
    )
    .await?;

    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut competing_writer)
        .await?;
    let before = ledger_state(&mut probe).await?;
    let started = Instant::now();
    let rejected = tokio::time::timeout(Duration::from_secs(15), journal.register(&registration))
        .await
        .context("registration exceeded bounded busy wait")?;
    assert_sqlite_error(rejected, 5)?;
    ensure!(
        started.elapsed() >= Duration::from_secs(4),
        "busy handler did not wait"
    );
    ensure!(
        ledger_state(&mut probe).await? == before,
        "busy registration mutated ledger"
    );
    ensure!(
        matches!(
            journal.launch(registration.launch.pod_uid).await,
            Err(GuardError::Closed)
        ),
        "busy registration produced a launch"
    );
    sqlx::query("COMMIT").execute(&mut competing_writer).await?;
    journal.register(&registration).await?;

    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut competing_writer)
        .await?;
    let before = ledger_state(&mut probe).await?;
    let started = Instant::now();
    let rejected = tokio::time::timeout(
        Duration::from_secs(15),
        journal.begin_start(registration.launch.pod_uid, StartKind::Run),
    )
    .await
    .context("start exceeded bounded busy wait")?;
    assert_sqlite_error(rejected, 5)?;
    ensure!(
        started.elapsed() >= Duration::from_secs(4),
        "busy handler did not wait"
    );
    ensure!(
        ledger_state(&mut probe).await? == before,
        "busy start produced a permit"
    );
    sqlx::query("COMMIT").execute(&mut competing_writer).await?;
    let _permit = journal
        .begin_start(registration.launch.pod_uid, StartKind::Run)
        .await?;
    let (pod, kind): (String, String) =
        sqlx::query_as("SELECT pod_uid,kind FROM guard_attempts WHERE state='IN_FLIGHT'")
            .fetch_one(&mut probe)
            .await?;
    ensure!(
        pod == registration.launch.pod_uid.to_string() && kind == "RUN",
        "wrong released-lock permit"
    );
    let after = ledger_state(&mut probe).await?;
    ensure!(
        after.1 == before.1 + 1 && after.2 == before.2 + 1,
        "start was not durable"
    );
    competing_writer.close().await?;
    journal.shutdown().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires the production Linux static SQLite 3.53.4 build"]
async fn sqlite_release_acceptance_constraint_failure_rolls_back() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let registration = request(node());
    let path = directory.path().join("state.sqlite3");
    let journal = checked_journal(&path, registration.node.clone()).await?;
    let mut probe = database_probe(&path).await?;
    trusted_fixture_coverage(&mut probe).await?;
    // The final revision update fails a real schema CHECK after register/start
    // have already written their launch/attempt/counter inside the transaction.
    const REJECT_REVISION: &str = "CREATE TRIGGER release_reject_revision \
        BEFORE UPDATE OF revision ON guard_meta BEGIN \
        UPDATE guard_meta SET schema_version=2 WHERE singleton=1; END";
    sqlx::query(REJECT_REVISION).execute(&mut probe).await?;
    let before = ledger_state(&mut probe).await?;
    assert_sqlite_error(journal.register(&registration).await, 19)?;
    ensure!(
        ledger_state(&mut probe).await? == before,
        "failed register was partially committed"
    );
    sqlx::query("DROP TRIGGER release_reject_revision")
        .execute(&mut probe)
        .await?;
    journal.register(&registration).await?;

    sqlx::query(REJECT_REVISION).execute(&mut probe).await?;
    let before = ledger_state(&mut probe).await?;
    assert_sqlite_error(
        journal
            .begin_start(registration.launch.pod_uid, StartKind::Run)
            .await,
        19,
    )?;
    ensure!(
        ledger_state(&mut probe).await? == before,
        "failed start was partially committed"
    );
    sqlx::query("DROP TRIGGER release_reject_revision")
        .execute(&mut probe)
        .await?;
    let permit = journal
        .begin_start(registration.launch.pod_uid, StartKind::Run)
        .await?;
    journal.settle(&permit, Some(&observation()), None).await?;
    let violations = sqlx::query("PRAGMA foreign_key_check")
        .fetch_all(&mut probe)
        .await?;
    ensure!(
        violations.is_empty(),
        "rollback left dangling journal identities"
    );
    let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_one(&mut probe)
        .await?;
    ensure!(integrity == "ok", "constraint recovery damaged the journal");
    journal.shutdown().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires the production Linux static SQLite 3.53.4 build"]
async fn sqlite_release_acceptance_corrupt_database_refuses_open() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.sqlite3");
    let enrolled_node = node();
    let journal = checked_journal(&path, enrolled_node.clone()).await?;
    journal.shutdown().await;
    let damage = [0xa5_u8; 8192];
    let mut file = std::fs::File::create(&path)?;
    file.write_all(&damage)?;
    file.sync_all()?;
    drop(file);
    // NOTADB is a damaged header. No replacement empty journal may be accepted.
    assert_sqlite_error(GateJournal::open(&path, enrolled_node).await, 26)?;
    ensure!(
        std::fs::read(&path)? == damage,
        "damaged journal was silently replaced"
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum CrashPoint {
    Open,
    InFlightStart,
    UnknownStart,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CrashFixture {
    token: Uuid,
    registration: RegisterLaunchRequest,
    crash_point: CrashPoint,
}

struct ExitDropProbe(PathBuf);
impl Drop for ExitDropProbe {
    fn drop(&mut self) {
        let _ = std::fs::write(&self.0, b"destructor executed");
    }
}

#[tokio::test]
#[ignore = "child-only writer; requires the parent's UUID fixture environment"]
async fn sqlite_release_crash_writer() -> anyhow::Result<()> {
    let directory =
        PathBuf::from(std::env::var_os(CRASH_FIXTURE_ENV).context("missing parent fixture")?);
    let token = Uuid::parse_str(&std::env::var(CRASH_TOKEN_ENV).context("missing parent token")?)?;
    let temporary_root = std::env::temp_dir().canonicalize()?;
    ensure!(
        !token.is_nil()
            && directory.is_absolute()
            && directory.canonicalize()?.starts_with(temporary_root)
            && directory.file_name().and_then(|n| n.to_str()) == Some(token.to_string().as_str()),
        "writer fixture does not match parent temporary UUID directory"
    );
    let encoded = std::fs::read(directory.join("fixture.json"))?;
    ensure!(encoded.len() <= 16 * 1024, "writer fixture exceeds bound");
    let fixture: CrashFixture = serde_json::from_slice(&encoded)?;
    ensure!(
        fixture.token == token,
        "writer fixture token does not match parent"
    );
    let path = directory.join("state.sqlite3");
    ensure!(!path.exists(), "writer refuses an existing database");
    let _drop_probe = ExitDropProbe(directory.join("destructor-ran"));
    let journal = checked_journal(&path, fixture.registration.node.clone()).await?;
    let mut probe = database_probe(&path).await?;
    trusted_fixture_coverage(&mut probe).await?;
    journal.register(&fixture.registration).await?;
    if !matches!(fixture.crash_point, CrashPoint::Open) {
        let pod = fixture.registration.launch.pod_uid;
        let observed = observation();
        let run = journal.begin_start(pod, StartKind::Run).await?;
        journal.settle(&run, Some(&observed), None).await?;
        let create = journal.begin_start(pod, StartKind::Create).await?;
        journal
            .settle(&create, None, Some((&"c".repeat(64), &observed.sandbox_id)))
            .await?;
        let start = journal.begin_start(pod, StartKind::Start).await?;
        if matches!(fixture.crash_point, CrashPoint::UnknownStart) {
            journal.mark_unknown(&start).await?;
        }
    }
    ensure!(
        std::fs::metadata(directory.join("state.sqlite3-wal"))?.len() > 32,
        "missing committed WAL"
    );
    // Neither GateJournal shutdown nor SQLite/Tokio/Drop destructors run. The
    // parent must recover the exact FULL-committed WAL left by this process.
    std::process::exit(0);
}

#[tokio::test]
#[ignore = "requires production Linux SQLite 3.53.4; launches three abrupt-exit subprocesses"]
async fn sqlite_release_acceptance_abrupt_process_exit_recovers_durable_wal_without_start_replay()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    // Verify before spawning: development runs must fail, never report a skip.
    let probe = checked_journal(&directory.path().join("probe.sqlite3"), node()).await?;
    probe.shutdown().await;
    for crash_point in [
        CrashPoint::Open,
        CrashPoint::InFlightStart,
        CrashPoint::UnknownStart,
    ] {
        let token = Uuid::new_v4();
        let fixture_directory = directory.path().join(token.to_string());
        std::fs::create_dir(&fixture_directory)?;
        let fixture = CrashFixture {
            token,
            registration: request(node()),
            crash_point,
        };
        std::fs::write(
            fixture_directory.join("fixture.json"),
            serde_json::to_vec(&fixture)?,
        )?;
        let mut command = tokio::process::Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                CRASH_WRITER_TEST,
                "--ignored",
                "--test-threads=1",
            ])
            .env_clear()
            .env(CRASH_FIXTURE_ENV, &fixture_directory)
            .env(CRASH_TOKEN_ENV, token.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let child = command.spawn()?;
        let output = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
            .await
            .context("abrupt-exit writer exceeded 30 second bound")??;
        ensure!(
            output.stderr.len() <= 16 * 1024,
            "writer output exceeds bound"
        );
        ensure!(
            output.status.success(),
            "abrupt-exit writer failed: {}",
            output.status
        );
        ensure!(
            !fixture_directory.join("destructor-ran").exists(),
            "writer ran Drop destructors"
        );
        ensure!(
            std::fs::metadata(fixture_directory.join("state.sqlite3-wal"))?.len() > 32,
            "child did not leave WAL"
        );

        // Observe committed WAL without allowing GateJournal recovery to first
        // rewrite the evidence of the child process's crash point.
        let path = fixture_directory.join("state.sqlite3");
        let mut reader = SqliteConnection::connect_with(
            &SqliteConnectOptions::new()
                .filename(&path)
                .read_only(true)
                .create_if_missing(false),
        )
        .await?;
        let (durable_state, forwarded): (String, i64) =
            sqlx::query_as("SELECT state,forwarded_starts FROM guard_launches WHERE pod_uid=$1")
                .bind(fixture.registration.launch.pod_uid.to_string())
                .fetch_one(&mut reader)
                .await?;
        let starts: Vec<String> =
            sqlx::query_scalar("SELECT state FROM guard_attempts WHERE kind='START'")
                .fetch_all(&mut reader)
                .await?;
        match crash_point {
            CrashPoint::Open => ensure!(
                durable_state == "OPEN" && forwarded == 0 && starts.is_empty(),
                "OPEN WAL commit was lost"
            ),
            CrashPoint::InFlightStart => ensure!(
                durable_state == "OPEN" && forwarded == 1 && starts == ["IN_FLIGHT"],
                "in-flight START WAL commit was lost"
            ),
            CrashPoint::UnknownStart => ensure!(
                durable_state == "UNKNOWN" && forwarded == 1 && starts == ["UNKNOWN"],
                "unknown START WAL commit was lost"
            ),
        }
        reader.close().await?;

        let mut recovered_node = fixture.registration.node.clone();
        if matches!(crash_point, CrashPoint::Open) {
            // A registered launch from an earlier OS boot cannot be revived.
            recovered_node.boot_id = Uuid::new_v4();
        }
        let journal = checked_journal(&path, recovered_node.clone()).await?;
        let mut probe = database_probe(&path).await?;
        if matches!(crash_point, CrashPoint::Open) {
            trusted_fixture_coverage(&mut probe).await?;
        } else {
            let (quarantined, coverage): (i64, i64) = sqlx::query_as(
                "SELECT quarantined,coverage_verified FROM guard_meta WHERE singleton=1",
            )
            .fetch_one(&mut probe)
            .await?;
            ensure!(
                quarantined == 1 && coverage == 0,
                "recovery did not persist fencing"
            );
        }
        let mut registration = fixture.registration.clone();
        registration.node = recovered_node;
        ensure!(
            journal.register(&registration).await.is_err(),
            "crashed launch was reopened"
        );
        ensure!(
            matches!(
                journal
                    .begin_start(registration.launch.pod_uid, StartKind::Start)
                    .await,
                Err(GuardError::Closed)
            ),
            "crash recovery replayed START"
        );
        ensure!(
            matches!(
                journal.require_open(registration.launch.pod_uid).await,
                Err(GuardError::Closed)
            ),
            "crashed gate remained open"
        );
        let recovered_state: String =
            sqlx::query_scalar("SELECT state FROM guard_launches WHERE pod_uid=$1")
                .bind(registration.launch.pod_uid.to_string())
                .fetch_one(&mut probe)
                .await?;
        ensure!(
            recovered_state == "UNKNOWN",
            "recovery did not preserve unknown launch state"
        );
        let start_states: Vec<String> =
            sqlx::query_scalar("SELECT state FROM guard_attempts WHERE kind='START'")
                .fetch_all(&mut probe)
                .await?;
        if !matches!(crash_point, CrashPoint::Open) {
            ensure!(
                start_states == ["UNKNOWN"],
                "recovery duplicated or settled crashed START"
            );
            ensure!(
                journal.close(&close(&registration)).await?.state == ObservationState::UnknownStart,
                "closure fabricated success after crash"
            );
        } else {
            ensure!(
                start_states.is_empty(),
                "OPEN-only crash fabricated a START"
            );
        }
        journal.shutdown().await;
        // A subsequent clean restart must retain the recovered quarantine and
        // must still reject START, even after IN_FLIGHT was converted to UNKNOWN.
        if !matches!(crash_point, CrashPoint::Open) {
            let reopened = checked_journal(&path, registration.node.clone()).await?;
            let (quarantined, coverage): (i64, i64) = sqlx::query_as(
                "SELECT quarantined,coverage_verified FROM guard_meta WHERE singleton=1",
            )
            .fetch_one(&mut probe)
            .await?;
            ensure!(
                quarantined == 1 && coverage == 0,
                "quarantine disappeared on second restart"
            );
            ensure!(
                matches!(
                    reopened
                        .begin_start(registration.launch.pod_uid, StartKind::Start)
                        .await,
                    Err(GuardError::Closed)
                ),
                "second restart replayed START"
            );
            reopened.shutdown().await;
        }
    }
    Ok(())
}
