//! PRIVATE actual-role warm-path regression, not a planner/GUC product fix.
use super::*;
use crate::test_support_db::VerifiedFixtureConnections;
use chrono::{DateTime, Utc};

const PAIRS: usize = 6;
const OBSERVER_LIMIT: Duration = Duration::from_secs(5);
const ADMISSION_QUERY: &str = "SELECT sandbox_restore_raw_bound_admission($1,$2,$3)";
const BACKUP_QUERY: &str = "SELECT sandbox_restore_raw_bound_claim($1,$2,$3,$4,$5)";

#[derive(Clone, Copy)]
enum Reader {
    Admission,
    Backup,
}
impl Reader {
    fn login(self) -> &'static str {
        match self {
            Self::Admission => "sandbox_admission",
            Self::Backup => "sandbox_backup",
        }
    }
    fn query(self) -> &'static str {
        match self {
            Self::Admission => ADMISSION_QUERY,
            Self::Backup => BACKUP_QUERY,
        }
    }
}
#[derive(Clone, PartialEq, Eq)]
struct Backend {
    pid: i32,
    started: DateTime<Utc>,
    role: String,
}
async fn backend(database: &Database, login: &str) -> anyhow::Result<Backend> {
    let deadline = tokio::time::Instant::now() + OBSERVER_LIMIT;
    let value = tokio::time::timeout_at(deadline, async {
        let mut tx = database.pool.begin().await?;
        let value: (i32, DateTime<Utc>, String, String) = sqlx::query_as(
            "SELECT pg_backend_pid(),a.backend_start,session_user::text,current_user::text FROM pg_stat_activity a WHERE a.pid=pg_backend_pid() AND a.datname=current_database() AND a.usename=session_user",
        ).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        anyhow::Ok(value)
    }).await.context("hot backend identity original observation deadline")??;
    ensure!(
        tokio::time::Instant::now() < deadline && value.2 == login && value.3 == login,
        "actual fixed role backend identity includes final COMMIT acknowledgement"
    );
    Ok(Backend {
        pid: value.0,
        started: value.1,
        role: value.2,
    })
}
struct HotRole {
    reader: Reader,
    database: Database,
    monitor: Database,
    backend: Backend,
    original_plan_mode: String,
    collapse_settings: (String, String),
}
pub(in super::super) struct HotPools {
    roles: Vec<HotRole>,
}
impl HotPools {
    /// Both owned component connections authenticate and verify the formal
    /// ordered migration ledger BEFORE any draft DDL. No verifier fallback.
    pub(in super::super) async fn prepare(
        verified: &VerifiedFixtureConnections,
        admission_monitor: &Database,
        backup_monitor: &Database,
    ) -> anyhow::Result<Self> {
        let mut opened = Vec::<Database>::new();
        let result = Box::pin(async {
            let mut roles = Vec::new();
            for (reader, key, monitor) in [
                (
                    Reader::Admission,
                    "TEST_ADMISSION_DATABASE_URL",
                    admission_monitor,
                ),
                (Reader::Backup, "TEST_BACKUP_DATABASE_URL", backup_monitor),
            ] {
                let component = verified.runtime(key, reader.login(), 1).await?;
                let database = component.database_for(reader.login())?;
                opened.push(database.clone());
                // Existing normally verified role pool; this helper never owns
                // its lifecycle and must not close the later business caller.
                let monitor = monitor.clone();
                let observed = backend(&database, reader.login()).await?;
                ensure!(
                    backend(&monitor, reader.login()).await?.pid != observed.pid,
                    "independent same-role monitor cannot be the observed connection"
                );
                let original_settings: (String, String, String) = sqlx::query_as(
                    "SELECT current_setting('plan_cache_mode'),current_setting('join_collapse_limit'),current_setting('from_collapse_limit')",
                ).fetch_one(&database.pool).await?;
                roles.push(HotRole {
                    reader,
                    database,
                    monitor,
                    backend: observed,
                    original_plan_mode: original_settings.0,
                    collapse_settings: (original_settings.1, original_settings.2),
                });
            }
            anyhow::Ok(Self { roles })
        })
        .await;
        if result.is_err() {
            // These are the successfully returned owned pools. A failure inside
            // the pre-existing verifier is not claimed as globally drained.
            for database in opened {
                database.pool.close().await;
            }
        }
        result
    }
    pub(in super::super) async fn clear_after_draft(&self) -> anyhow::Result<()> {
        for role in &self.roles {
            clear(&[&role.database.pool]).await?;
            ensure!(
                backend(&role.database, role.reader.login()).await? == role.backend,
                "cache clearing retains the same actual verified backend"
            );
        }
        Ok(())
    }
    pub(in super::super) async fn finish(&self) -> anyhow::Result<()> {
        for role in &self.roles {
            role.database.pool.close().await;
        }
        let mut result = Ok(());
        for role in &self.roles {
            let absent = absence(&role.monitor, &role.backend).await;
            if result.is_ok() {
                result = absent;
            }
        }
        result
    }
}
async fn absence(monitor: &Database, expected: &Backend) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + OBSERVER_LIMIT;
    loop {
        let found = tokio::time::timeout_at(deadline, async {
            let mut tx = monitor.pool.begin().await?;
            let found: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND backend_start=$2 AND usename=$3 AND datname=current_database())")
                .bind(expected.pid).bind(expected.started).bind(&expected.role).fetch_one(&mut *tx).await?;
            tx.commit().await?;
            anyhow::Ok(found)
        }).await.context("hot same-role physical absence original deadline")??;
        ensure!(
            tokio::time::Instant::now() < deadline,
            "physical absence includes final fresh transaction acknowledgement"
        );
        if !found {
            return Ok(());
        }
        tokio::time::timeout_at(deadline, tokio::time::sleep(Duration::from_millis(25)))
            .await
            .context("hot physical backend absence did not arrive")?;
    }
}
async fn settings(role: &HotRole, expected: &str) -> anyhow::Result<()> {
    ensure!(
        role.database.pool.options().get_max_connections() == 1,
        "hot-path calls must use a dedicated max1 process pool"
    );
    let values: (String, String, String, String, String) = sqlx::query_as(
        "SELECT current_setting('plan_cache_mode'),current_setting('statement_timeout'),current_setting('lock_timeout'),current_setting('join_collapse_limit'),current_setting('from_collapse_limit')",
    ).fetch_one(&role.database.pool).await?;
    ensure!(
        values
            == (
                expected.into(),
                "10s".into(),
                "3s".into(),
                role.collapse_settings.0.clone(),
                role.collapse_settings.1.clone()
            ),
        "only local test plan policy changes; normal statement/lock budgets and original session join/from settings are restored"
    );
    ensure!(
        backend(&role.database, role.reader.login()).await? == role.backend,
        "every warm pair remains on the same PID/start/login backend"
    );
    Ok(())
}
async fn counts(role: &HotRole) -> anyhow::Result<(i64, i64)> {
    // Own-session prepared statements only. No pg_monitor/pg_read_all_stats or
    // other-role query visibility is requested; query text is never returned.
    let value = sqlx::query_as(
        "SELECT COALESCE(sum(generic_plans),0)::bigint,COALESCE(sum(custom_plans),0)::bigint FROM pg_prepared_statements WHERE statement=$1",
    ).bind(role.reader.query()).fetch_one(&role.database.pool).await?;
    Ok(value)
}
async fn pair(case: &SelectedCase<'_>, role: &HotRole, node_hint: &str) -> anyhow::Result<Value> {
    // Heartbeat belongs to the real existing worker and occurs BEFORE this
    // independent original attempt. None occurs between first/final reads.
    ensure!(
        case.source
            .f
            .backup
            .heartbeat(case.claim)
            .await
            .map_err(api_failure)?,
        "only the normal current worker renews before an independent warm attempt"
    );
    let attempt = RawBoundAttempt::start();
    let hint = Box::pin(locate_selected_parent(case, node_hint)).await?;
    let value = match role.reader {
        Reader::Admission => {
            let service = RestoreAdmissionService {
                database: role.database.clone(),
                ..case.service.clone()
            };
            let first = service
                .prepare_raw_bound_admission(&attempt, case.t, case.r, &hint)
                .await
                .map_err(|e| anyhow::anyhow!(e.message))?;
            let scope = first
                .admission_disk_scope(&attempt)
                .map_err(|e| anyhow::anyhow!(e.message))?;
            let value = serde_json::to_value(scope.facts())?;
            service
                .recheck_raw_bound_admission(&first)
                .await
                .map_err(|e| anyhow::anyhow!(e.message))?;
            scope.current().map_err(|e| anyhow::anyhow!(e.message))?;
            value
        }
        Reader::Backup => {
            let first = role
                .database
                .prepare_restore_bound_authority(
                    &attempt,
                    &case.source.f.backup,
                    case.claim,
                    case.r,
                    &hint,
                )
                .await
                .map_err(api_failure)?;
            let scope = first
                .backup_disk_scope(&attempt, &case.source.f.backup, case.claim)
                .map_err(|e| anyhow::anyhow!(e.message))?;
            let value = serde_json::to_value(scope.facts())?;
            role.database
                .recheck_restore_bound_authority(&case.source.f.backup, case.claim, &first)
                .await
                .map_err(api_failure)?;
            scope.current().map_err(|e| anyhow::anyhow!(e.message))?;
            value
        }
    };
    ensure!(
        value.is_object()
            && value["tenant_id"] == json!(case.t)
            && value["restore_id"] == json!(case.r),
        "actual strict14 decoder emits scoped comparison facts"
    );
    Ok(value)
}
pub(super) async fn run(case: &SelectedCase<'_>, node_hint: &str) -> anyhow::Result<()> {
    let requests_before = case
        .w
        .shared
        .lock()
        .map_err(|_| anyhow::anyhow!("workload state"))?
        .requests
        .len();
    let cloud_before = case.cloud.actions()?;
    for role in &case.hot.roles {
        let mut baseline = None;
        for mode in ["auto", "force_custom_plan", "force_generic_plan"] {
            sqlx::query("SELECT set_config('plan_cache_mode',$1,false)")
                .bind(mode)
                .execute(&role.database.pool)
                .await?;
            settings(role, mode).await?;
            let before = counts(role).await?;
            for _ in 0..PAIRS {
                let value = Box::pin(pair(case, role, node_hint)).await?;
                match &baseline {
                    Some(expected) => ensure!(
                        value == *expected,
                        "same complete source-storage scope across warm first/final pairs and test planner modes"
                    ),
                    None => baseline = Some(value),
                }
                settings(role, mode).await?;
            }
            let after = counts(role).await?;
            match mode {
                "force_custom_plan" => ensure!(
                    after.1 - before.1 >= (2 * PAIRS) as i64 && after.0 == before.0,
                    "actual role prepared reader executes forced custom at least twelve times"
                ),
                "force_generic_plan" => ensure!(
                    after.0 - before.0 >= (2 * PAIRS) as i64 && after.1 == before.1,
                    "actual role prepared reader executes forced generic at least twelve times"
                ),
                _ => ensure!(
                    (after.0 + after.1) - (before.0 + before.1) >= (2 * PAIRS) as i64,
                    "auto passes the five-execution warm threshold without asserting planner choice"
                ),
            }
            sqlx::query("SELECT set_config('plan_cache_mode',$1,false)")
                .bind(&role.original_plan_mode)
                .execute(&role.database.pool)
                .await?;
            settings(role, &role.original_plan_mode).await?;
        }
    }
    absent_companion(case).await?;
    ensure!(
        case.cloud.actions()? == cloud_before,
        "warm database scopes create no signed cloud facts"
    );
    {
        let state = case
            .w
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("workload state"))?;
        let added = &state.requests[requests_before..];
        ensure!(
            added.len() == 2 * 3 * PAIRS
                && added
                    .iter()
                    .all(|(method, path)| *method == Method::GET && path == case.pvc_path),
            "exact thirty-six real parent locator GETs, no PV/Node/cloud mutation or fabricated future record"
        );
    }
    eprintln!(
        "VERIFIED private raw-bound hot72: two authenticated fixed backends, auto/custom/generic six original-attempt pairs per role, exact strict14 first/final API checks, prepared-plan counters and unchanged10s/3s, no new signed facts or future records; not an OOM root-cause proof or product GUC fix"
    );
    Ok(())
}
