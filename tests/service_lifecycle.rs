//! Actual component LOGIN/normal migration/physical PostgreSQL pool drain.
//! No Kubernetes, cloud runtime, VM termination, or quota certification.
#[allow(dead_code)]
mod support;

use std::{env, fmt, time::Duration};

use anyhow::{Context, ensure};
use chrono::{DateTime, Utc};
use sandbox_platform::{
    db::Database,
    service_lifecycle::{run_pair, with_database_drain},
};
use sqlx::{PgPool, Postgres, pool::PoolConnection};
use support::Fixture;
use tokio::{sync::oneshot, time::Instant};
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

const ROLES: [(&str, &str); 8] = [
    ("TEST_DATABASE_URL", "sandbox_app"),
    ("TEST_WORKER_DATABASE_URL", "sandbox_worker"),
    ("TEST_GATEWAY_DATABASE_URL", "sandbox_gateway"),
    ("TEST_ADMISSION_DATABASE_URL", "sandbox_admission"),
    ("TEST_TERMINATION_DATABASE_URL", "sandbox_termination"),
    ("TEST_FENCING_DATABASE_URL", "sandbox_fencing"),
    ("TEST_VOLUME_DELETER_DATABASE_URL", "sandbox_volume_deleter"),
    ("TEST_BACKUP_DATABASE_URL", "sandbox_backup"),
];
const OBSERVER_LIMIT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
enum Case {
    Success,
    StartupError,
    PairFirstError,
    PairSiblingError,
}

#[derive(Debug, PartialEq)]
struct OriginalFailure {
    id: Uuid,
    origin: &'static str,
}
impl fmt::Display for OriginalFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fixed lifecycle test failure: {}", self.origin)
    }
}
impl std::error::Error for OriginalFailure {}

#[derive(Debug)]
struct Backend {
    pid: i32,
    started_at: DateTime<Utc>,
    application: String,
    role: String,
}

fn tagged_url(key: &str, role: &str, application: &str) -> anyhow::Result<String> {
    let raw = env::var(key).with_context(|| format!("{key} is required"))?;
    let mut parsed = Url::parse(&raw).map_err(|_| anyhow::anyhow!("Invalid component test URL"))?;
    let reference =
        Url::parse(&env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL is required")?)
            .map_err(|_| anyhow::anyhow!("Invalid reference test URL"))?;
    ensure!(
        matches!(parsed.scheme(), "postgres" | "postgresql")
            && parsed.username() == role
            && parsed.host_str() == reference.host_str()
            && parsed.port_or_known_default() == reference.port_or_known_default()
            && parsed.path() == reference.path()
            && parsed.path().ends_with("_test")
            && parsed.fragment().is_none()
            && parsed.query().is_none(),
        "Component test URL must use its exact LOGIN and the same disposable database"
    );
    ensure!(
        parsed
            .host_str()
            .and_then(|s| s.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
            .is_some_and(|host| host.is_loopback()),
        "Lifecycle integration requires a literal loopback PostgreSQL host"
    );
    parsed
        .query_pairs_mut()
        .append_pair("application_name", application);
    Ok(parsed.into())
}

async fn connect_role(key: &str, role: &str, application: &str) -> anyhow::Result<Database> {
    let database = Database::connect(&tagged_url(key, role, application)?, 1).await?;
    let result = async {
        database.verify_runtime_role().await?;
        let (session, current): (String, String) =
            sqlx::query_as("SELECT session_user::text,current_user::text")
                .fetch_one(&database.pool)
                .await?;
        ensure!(
            session == role && current == role,
            "Actual LOGIN differs from component role"
        );
        let ledger: (Vec<i64>, bool) = sqlx::query_as(
            "SELECT array_agg(version ORDER BY version),bool_and(success) FROM _sqlx_migrations",
        )
        .fetch_one(&database.pool)
        .await?;
        let expected: Vec<i64> = sqlx::migrate!("./migrations")
            .iter()
            .map(|migration| migration.version)
            .collect();
        ensure!(
            ledger == (expected, true),
            "Expected the complete checksum-verified embedded migration ledger"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if let Err(error) = result {
        database.pool.close().await;
        return Err(error);
    }
    Ok(database)
}

async fn backend(lease: &mut PoolConnection<Postgres>, role: &str) -> anyhow::Result<Backend> {
    let (pid, started_at, application): (i32, DateTime<Utc>, String) = sqlx::query_as(
        "SELECT pid,backend_start,application_name FROM pg_stat_activity WHERE pid=pg_backend_pid() AND usename=current_user AND datname=current_database()",
    )
    .fetch_one(&mut **lease)
    .await?;
    ensure!(
        pid > 0 && application.starts_with("lifecycle-service-"),
        "Actual service backend identity missing"
    );
    Ok(Backend {
        pid,
        started_at,
        application,
        role: role.into(),
    })
}

// A new read-only transaction per observation avoids a cached statistics snapshot.
// The observer uses the same actual LOGIN, never owner/pg_monitor/SET ROLE.
async fn visible(monitor: &PgPool, expected: &Backend) -> anyhow::Result<(bool, i64)> {
    let deadline = Instant::now() + OBSERVER_LIMIT;
    let result = tokio::time::timeout_at(deadline, async {
        let mut tx = monitor.begin().await?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND backend_start=$2 AND application_name=$3 AND usename=$4 AND datname=current_database()),(SELECT count(*) FROM pg_stat_activity WHERE application_name=$3 AND usename=$4 AND datname=current_database())",
        )
        .bind(expected.pid)
        .bind(expected.started_at)
        .bind(&expected.application)
        .bind(&expected.role)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok::<(bool, i64), anyhow::Error>(result)
    })
    .await
    .context("Backend visibility observer exceeded its fixed bound")??;
    // Tokio Timeout polls the inner future before the timer. Reject a ready
    // result observed after the deadline as well as a still-pending operation.
    ensure!(
        Instant::now() < deadline,
        "Backend visibility observer returned beyond its fixed bound"
    );
    Ok(result)
}

async fn require_absent(monitor: &PgPool, expected: &Backend) -> anyhow::Result<()> {
    let deadline = Instant::now() + OBSERVER_LIMIT;
    loop {
        let (exact, application_backends) =
            tokio::time::timeout_at(deadline, visible(monitor, expected))
                .await
                .context("Backend absence observer exceeded its fixed bound")??;
        ensure!(
            Instant::now() < deadline,
            "Backend absence observer returned beyond its fixed bound"
        );
        if !exact && application_backends == 0 {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn closed_clone(pool: &PgPool) -> anyhow::Result<()> {
    ensure!(
        matches!(pool.acquire().await, Err(sqlx::Error::PoolClosed)),
        "A service pool clone can acquire after completed shutdown"
    );
    Ok(())
}

async fn case_body(pool: &PgPool, monitor: &PgPool, role: &str, case: Case) -> anyhow::Result<()> {
    let mut lease = pool.acquire().await?;
    let identity = backend(&mut lease, role).await?;
    ensure!(
        visible(monitor, &identity).await? == (true, 1),
        "Independent same-role observer cannot see service backend"
    );
    let expected_pid = identity.pid;
    let pool_clone = pool.clone();
    let primary = Uuid::new_v4();
    let secondary = Uuid::new_v4();
    let (lease_tx, lease_rx) = oneshot::channel();
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let (join_tx, join_rx) = oneshot::channel();
    let paired = matches!(case, Case::PairFirstError | Case::PairSiblingError);
    let token = CancellationToken::new();
    let pair_token = token.clone();
    let business_pool = pool.clone();
    let business = async move {
        if paired {
            let (entered_tx, entered_rx) = oneshot::channel();
            let left = async move {
                entered_rx
                    .await
                    .context("Sibling did not enter its actual service future")?;
                match case {
                    Case::PairFirstError => Err(OriginalFailure {
                        id: primary,
                        origin: "first-parent",
                    }
                    .into()),
                    _ => Ok(()),
                }
            };
            let right = async move {
                let actual: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(&mut *lease)
                    .await?;
                ensure!(
                    actual == expected_pid,
                    "Sibling must own the recorded leased backend"
                );
                ensure!(
                    !business_pool.is_closed(),
                    "Business pool closed before paired service exit"
                );
                entered_tx
                    .send(())
                    .map_err(|_| anyhow::anyhow!("First parent disappeared"))?;
                pair_token.cancelled().await;
                cancel_tx
                    .send(())
                    .map_err(|_| anyhow::anyhow!("Pair cancellation observer disappeared"))?;
                join_rx.await.context("Sibling join gate disappeared")?;
                let after_cancel: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(&mut *lease)
                    .await?;
                ensure!(
                    after_cancel == actual,
                    "Cancellation must not drop the sibling's actual lease"
                );
                lease_tx
                    .send(lease)
                    .map_err(|_| anyhow::anyhow!("Lease observer disappeared"))?;
                // Both pair trials deliberately return a secondary error. The
                // first-error trial must preserve the first error; the first-OK
                // trial must propagate this exact secondary error after join.
                Err(OriginalFailure {
                    id: secondary,
                    origin: "joined-sibling",
                }
                .into())
            };
            run_pair(token, left, right).await
        } else {
            let actual: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *lease)
                .await?;
            ensure!(
                actual == expected_pid && !business_pool.is_closed(),
                "Service must hold its actual connection and pool clone"
            );
            lease_tx
                .send(lease)
                .map_err(|_| anyhow::anyhow!("Lease observer disappeared"))?;
            match case {
                Case::StartupError => Err(OriginalFailure {
                    id: primary,
                    origin: "startup",
                }
                .into()),
                _ => Ok(()),
            }
        }
    };
    let mut wrapped = Box::pin(with_database_drain(pool.clone(), business));
    if paired {
        tokio::select! {
            received = cancel_rx => received.context("Sibling was not actually cancelled")?,
            _ = &mut wrapped => anyhow::bail!("Pair returned before cancelled sibling joined"),
            _ = tokio::time::sleep(OBSERVER_LIMIT) => anyhow::bail!("Pair never cancelled sibling"),
        }
        ensure!(
            !pool.is_closed(),
            "Drain started before the cancelled sibling returned"
        );
        ensure!(
            visible(monitor, &identity).await? == (true, 1),
            "Sibling lease disappeared before join"
        );
        tokio::select! {
            _ = &mut wrapped => anyhow::bail!("Pair did not wait for its sibling's real return"),
            _ = tokio::time::sleep(Duration::from_millis(50)) => {},
        }
        join_tx
            .send(())
            .map_err(|_| anyhow::anyhow!("Sibling was dropped rather than joined"))?;
    }
    let held = tokio::select! {
        received = lease_rx => received.context("Business did not transfer its real lease")?,
        _ = &mut wrapped => anyhow::bail!("Service returned before borrowed backend was released"),
        _ = tokio::time::sleep(OBSERVER_LIMIT) => anyhow::bail!("Business did not settle"),
    };
    tokio::select! {
        _ = pool.close_event() => {},
        _ = &mut wrapped => anyhow::bail!("Shutdown returned before close began"),
        _ = tokio::time::sleep(OBSERVER_LIMIT) => anyhow::bail!("Shutdown never began pool close"),
    }
    ensure!(
        visible(monitor, &identity).await? == (true, 1),
        "Pool close must wait for the physically borrowed backend"
    );
    closed_clone(&pool_clone).await?;
    tokio::select! {
        _ = &mut wrapped => anyhow::bail!("Shutdown completed while an actual connection remained leased"),
        _ = tokio::time::sleep(Duration::from_millis(50)) => {},
    }
    // This returns the actual physical connection. No pg_terminate_backend or
    // privileged cancellation is used. The production helper must await close.
    drop(held);
    let outcome = tokio::time::timeout(OBSERVER_LIMIT, &mut wrapped)
        .await
        .context("Service did not finish after the leased backend was released")?;
    match case {
        Case::Success => outcome?,
        Case::StartupError | Case::PairFirstError | Case::PairSiblingError => {
            let expected = OriginalFailure {
                id: if matches!(case, Case::PairSiblingError) {
                    secondary
                } else {
                    primary
                },
                origin: match case {
                    Case::StartupError => "startup",
                    Case::PairFirstError => "first-parent",
                    _ => "joined-sibling",
                },
            };
            let error = outcome
                .err()
                .context("Expected the original business error")?;
            ensure!(
                error.downcast_ref::<OriginalFailure>() == Some(&expected),
                "Shutdown changed the original business error identity"
            );
        }
    }
    require_absent(monitor, &identity).await?;
    closed_clone(&pool_clone).await?;
    println!(
        "lifecycle actual role={role} case={case:?} backend_pid={} backend_start={} application={} close_pending=true final_backend_absent=true clone_pool_closed=true",
        identity.pid, identity.started_at, identity.application
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires fresh local PostgreSQL 17+, all eight exact TEST_* LOGIN URLs, and the normal checksum-verified embedded migration ledger; no cloud/runtime certification"]
async fn actual_component_shutdown_drains_real_pg_leases_and_joins_paired_parents()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let fixture = Fixture::new(1).await?;
    let mut trials = 0;
    let outcome = async {
        for script in [
            include_str!("../scripts/sql/worker-role.sql"),
            include_str!("../scripts/sql/gateway-role.sql"),
            include_str!("../scripts/sql/admission-role.sql"),
            include_str!("../scripts/sql/termination-role.sql"),
            include_str!("../scripts/sql/fencing-role.sql"),
            include_str!("../scripts/sql/volume-deleter-role.sql"),
            include_str!("../scripts/sql/backup-role.sql"),
        ] {
            sqlx::raw_sql(script).execute(&fixture.owner).await?;
        }
        for (key, role) in ROLES {
            let monitor = connect_role(
                key,
                role,
                &format!("lifecycle-monitor-{}", Uuid::new_v4().simple()),
            )
            .await?;
            let outcome = async {
                for case in [
                    Case::Success,
                    Case::StartupError,
                    Case::PairFirstError,
                    Case::PairSiblingError,
                ] {
                    let database = connect_role(
                        key,
                        role,
                        &format!("lifecycle-service-{}", Uuid::new_v4().simple()),
                    )
                    .await?;
                    let result =
                        Box::pin(case_body(&database.pool, &monitor.pool, role, case)).await;
                    // Even an assertion failure returns its owned lease and drains
                    // this test pool before propagating the original failure.
                    database.pool.close().await;
                    result?;
                    trials += 1;
                }
                Ok::<(), anyhow::Error>(())
            }
            .await;
            monitor.pool.close().await;
            outcome?;
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    fixture.database.pool.close().await;
    fixture.owner.close().await;
    outcome?;
    ensure!(trials == 32, "Lifecycle component matrix incomplete");
    println!(
        "lifecycle actual 8 authenticated normal-ledger roles / 32 physical drain trials completed"
    );
    Ok(())
}
