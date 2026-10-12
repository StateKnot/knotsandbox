//! Durable local start gate. A successful SQLite FULL-synchronous commit precedes
//! every forwarded mutating CRI call. No process can infer success from a timeout.
use super::{GuardError, protocol::*};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::{path::Path, time::Duration};
use uuid::Uuid;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS guard_meta(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema_version INTEGER NOT NULL CHECK(schema_version=1),
 node_json TEXT NOT NULL,quarantined INTEGER NOT NULL DEFAULT 0 CHECK(quarantined IN(0,1)),
 coverage_verified INTEGER NOT NULL DEFAULT 0 CHECK(coverage_verified IN(0,1)),revision INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS guard_launches(
 pod_uid TEXT PRIMARY KEY,boot_id TEXT NOT NULL,launch_json TEXT NOT NULL,permit_id TEXT NOT NULL,
 expires_at TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN('OPEN','CLOSED','UNKNOWN')),
 closed_at TEXT,termination_json TEXT,forwarded_starts INTEGER NOT NULL DEFAULT 0 CHECK(forwarded_starts BETWEEN 0 AND 1)
);
CREATE INDEX IF NOT EXISTS guard_launch_identity ON guard_launches(json_extract(launch_json,'$.launch_id'));
CREATE TABLE IF NOT EXISTS guard_attempts(
 id TEXT PRIMARY KEY,pod_uid TEXT NOT NULL REFERENCES guard_launches(pod_uid),
 kind TEXT NOT NULL CHECK(kind IN('RUN','CREATE','START')),
 state TEXT NOT NULL CHECK(state IN('IN_FLIGHT','SETTLED','UNKNOWN')),
 started_at TEXT NOT NULL,settled_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS guard_one_inflight ON guard_attempts(pod_uid) WHERE state='IN_FLIGHT';
CREATE TABLE IF NOT EXISTS guard_sandboxes(
 sandbox_id TEXT PRIMARY KEY,pod_uid TEXT NOT NULL REFERENCES guard_launches(pod_uid),
 observation_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS guard_containers(
 container_id TEXT PRIMARY KEY,pod_uid TEXT NOT NULL REFERENCES guard_launches(pod_uid),
 sandbox_id TEXT NOT NULL REFERENCES guard_sandboxes(sandbox_id)
);
"#;

#[derive(Clone)]
pub struct GateJournal {
    pool: SqlitePool,
    node: NodeBinding,
}

/// Fixed, read-only observations of the journal's actual pooled connection.
/// No database handle, path, arbitrary SQL, or mutation is exposed.
#[derive(Clone, Debug, Serialize)]
pub struct JournalStorageDiagnostics {
    pub sqlite_version: String,
    pub sqlite_source_id: String,
    pub journal_mode: String,
    pub synchronous: i64,
    pub foreign_keys: i64,
    pub busy_timeout_millis: i64,
    pub compile_options: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StartKind {
    Run,
    Create,
    Start,
}
impl StartKind {
    fn name(self) -> &'static str {
        match self {
            Self::Run => "RUN",
            Self::Create => "CREATE",
            Self::Start => "START",
        }
    }
}

#[derive(Debug)]
pub struct StartPermit {
    pub(crate) id: Uuid,
    pub(crate) pod_uid: Uuid,
    pub(crate) kind: StartKind,
}

#[derive(Clone, Debug)]
pub struct ClosedSnapshot {
    pub node: NodeBinding,
    pub launch: LaunchBinding,
    pub state: ObservationState,
    pub revision: i64,
    pub closed_at: DateTime<Utc>,
    pub forwarded_starts: u64,
    pub sandboxes: Vec<SandboxObservation>,
}

impl GateJournal {
    /// The daemon must hold an exclusive OS lock on the journal directory for
    /// its entire lifetime. Reopening after a crash fences every unresolved call.
    pub async fn open(path: &Path, node: NodeBinding) -> Result<Self, GuardError> {
        if !node.validate() {
            return Err(GuardError::Invalid);
        }
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .busy_timeout(Duration::from_secs(5));
        // Own the pool before the first asynchronous database operation, so
        // initialization/acquisition errors share the same explicit close.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_lazy_with(options);
        if let Err(error) = Self::initialize(&pool, &node).await {
            // Transaction rollback/connection shutdown run in the SQLite
            // worker. Drop alone only queues them; the daemon still owns its
            // exclusive directory lock until this actual drain completes.
            pool.close().await;
            return Err(error);
        }
        Ok(Self { pool, node })
    }

    async fn initialize(pool: &SqlitePool, node: &NodeBinding) -> Result<(), GuardError> {
        sqlx::raw_sql(SCHEMA).execute(pool).await?;
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        let initialized: Result<(), GuardError> = async {
        let prior: Option<String> =
            sqlx::query_scalar("SELECT node_json FROM guard_meta WHERE singleton=1")
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(prior) = prior {
            let previous: NodeBinding = serde_json::from_str(&prior)?;
            if previous.node_uid != node.node_uid
                || previous.node_name != node.node_name
                || previous.profile_sha256 != node.profile_sha256
                || previous.cluster_epoch != node.cluster_epoch
            {
                return Err(GuardError::IdentityMismatch);
            }
            let unresolved: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM guard_attempts WHERE state='IN_FLIGHT')",
            )
            .fetch_one(&mut *tx)
            .await?;
            if unresolved {
                sqlx::query("UPDATE guard_launches SET state='UNKNOWN' WHERE pod_uid IN (SELECT pod_uid FROM guard_attempts WHERE state='IN_FLIGHT')").execute(&mut *tx).await?;
                sqlx::query("UPDATE guard_attempts SET state='UNKNOWN' WHERE state='IN_FLIGHT'")
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("UPDATE guard_meta SET quarantined=1 WHERE singleton=1")
                    .execute(&mut *tx)
                    .await?;
            }
            // A new boot never revives previous permits. Closed tombstones stay
            // in the journal until the operator retires the whole node identity.
            if previous.boot_id != node.boot_id {
                sqlx::query("UPDATE guard_launches SET state='UNKNOWN' WHERE state='OPEN'")
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query("UPDATE guard_meta SET node_json=$1,coverage_verified=0,revision=revision+1 WHERE singleton=1").bind(serde_json::to_string(&node)?).execute(&mut *tx).await?;
        } else {
            sqlx::query(
                "INSERT INTO guard_meta(singleton,schema_version,node_json) VALUES(1,1,$1)",
            )
            .bind(serde_json::to_string(&node)?)
            .execute(&mut *tx)
            .await?;
        }
            Ok(())
        }
        .await;
        match initialized {
            Ok(()) => Ok(tx.commit().await?),
            Err(error) => {
                // Preserve the original enrollment/error reason. Even if the
                // explicit rollback fails, open() must close the entire pool
                // before its caller may relinquish daemon ownership.
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }

    pub async fn shutdown(self) {
        self.pool.close().await;
    }

    pub fn node(&self) -> &NodeBinding {
        &self.node
    }

    pub async fn storage_diagnostics(&self) -> Result<JournalStorageDiagnostics, GuardError> {
        let mut connection = self.pool.acquire().await?;
        Ok(JournalStorageDiagnostics {
            sqlite_version: sqlx::query_scalar("SELECT sqlite_version()")
                .fetch_one(&mut *connection)
                .await?,
            sqlite_source_id: sqlx::query_scalar("SELECT sqlite_source_id()")
                .fetch_one(&mut *connection)
                .await?,
            journal_mode: sqlx::query_scalar("PRAGMA journal_mode")
                .fetch_one(&mut *connection)
                .await?,
            synchronous: sqlx::query_scalar("PRAGMA synchronous")
                .fetch_one(&mut *connection)
                .await?,
            foreign_keys: sqlx::query_scalar("PRAGMA foreign_keys")
                .fetch_one(&mut *connection)
                .await?,
            busy_timeout_millis: sqlx::query_scalar("PRAGMA busy_timeout")
                .fetch_one(&mut *connection)
                .await?,
            compile_options: sqlx::query_scalar("PRAGMA compile_options")
                .fetch_all(&mut *connection)
                .await?,
        })
    }

    /// Called only after the daemon has verified its immutable host profile,
    /// kubelet endpoint and all existing CRI sandboxes against its own journal.
    /// No HTTP payload is allowed to call this method directly.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) async fn verify_coverage(&self) -> Result<(), GuardError> {
        let changed=sqlx::query("UPDATE guard_meta SET coverage_verified=1,revision=revision+1 WHERE singleton=1 AND quarantined=0").execute(&self.pool).await?.rows_affected();
        if changed != 1 {
            return Err(GuardError::Unknown);
        }
        Ok(())
    }

    pub async fn register(
        &self,
        request: &RegisterLaunchRequest,
    ) -> Result<RegisterLaunchResponse, GuardError> {
        self.check_node(request.protocol, &request.node)?;
        if !request.launch.validate() || request.permit_id.is_nil() {
            return Err(GuardError::Invalid);
        }
        if request.expires_at <= Utc::now() {
            return Err(GuardError::Expired);
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let healthy: bool = sqlx::query_scalar(
            "SELECT quarantined=0 AND coverage_verified=1 FROM guard_meta WHERE singleton=1",
        )
        .fetch_one(&mut *tx)
        .await?;
        if !healthy {
            return Err(GuardError::Closed);
        }
        // One immutable attempt may bind exactly one Pod UID, including after
        // Job-controller retries, CLOSED tombstones and guard restarts. This is
        // not a substitute for the cluster-wide consume-once admission ledger.
        let reused: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM guard_launches WHERE json_extract(launch_json,'$.launch_id')=$1 AND pod_uid<>$2)",
        ).bind(request.launch.launch_id.to_string()).bind(request.launch.pod_uid.to_string())
            .fetch_one(&mut *tx).await?;
        if reused {
            return Err(GuardError::IdentityMismatch);
        }
        let previous =
            sqlx::query("SELECT launch_json,boot_id,state FROM guard_launches WHERE pod_uid=$1")
                .bind(request.launch.pod_uid.to_string())
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(previous) = previous {
            let launch: LaunchBinding = serde_json::from_str(previous.get("launch_json"))?;
            if launch != request.launch
                || previous.get::<String, _>("boot_id") != self.node.boot_id.to_string()
            {
                return Err(GuardError::IdentityMismatch);
            }
            if previous.get::<String, _>("state") != "OPEN" {
                return Err(GuardError::Closed);
            }
            // Renewal may extend a still-open registration; it cannot reopen a
            // closed UID or change the identity of a sandbox already launched.
            sqlx::query("UPDATE guard_launches SET expires_at=MAX(expires_at,$2),permit_id=$3 WHERE pod_uid=$1").bind(request.launch.pod_uid.to_string()).bind(timestamp(request.expires_at)).bind(request.permit_id.to_string()).execute(&mut *tx).await?;
        } else {
            sqlx::query("INSERT INTO guard_launches(pod_uid,boot_id,launch_json,permit_id,expires_at,state) VALUES($1,$2,$3,$4,$5,'OPEN')")
                .bind(request.launch.pod_uid.to_string()).bind(self.node.boot_id.to_string()).bind(serde_json::to_string(&request.launch)?).bind(request.permit_id.to_string()).bind(timestamp(request.expires_at)).execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE guard_meta SET revision=revision+1 WHERE singleton=1")
            .execute(&mut *tx)
            .await?;
        let journal_revision =
            sqlx::query_scalar("SELECT revision FROM guard_meta WHERE singleton=1")
                .fetch_one(&mut *tx)
                .await?;
        let effective_expires: String =
            sqlx::query_scalar("SELECT expires_at FROM guard_launches WHERE pod_uid=$1")
                .bind(request.launch.pod_uid.to_string())
                .fetch_one(&mut *tx)
                .await?;
        let effective_expires_at = DateTime::parse_from_rfc3339(&effective_expires)
            .map_err(|_| GuardError::Invalid)?
            .with_timezone(&Utc);
        tx.commit().await?;
        Ok(RegisterLaunchResponse {
            protocol: PROTOCOL_VERSION,
            permit_id: request.permit_id,
            node: self.node.clone(),
            launch: request.launch.clone(),
            state: GateState::Open,
            effective_expires_at,
            journal_revision,
        })
    }

    pub async fn launch(&self, pod_uid: Uuid) -> Result<LaunchBinding, GuardError> {
        let value: Option<String> = sqlx::query_scalar(
            "SELECT launch_json FROM guard_launches WHERE pod_uid=$1 AND boot_id=$2",
        )
        .bind(pod_uid.to_string())
        .bind(self.node.boot_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        serde_json::from_str(&value.ok_or(GuardError::Closed)?).map_err(Into::into)
    }

    pub async fn pod_for_sandbox(&self, id: &str) -> Result<Uuid, GuardError> {
        opaque_id(id)?;
        let value: Option<String> =
            sqlx::query_scalar("SELECT pod_uid FROM guard_sandboxes WHERE sandbox_id=$1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
        Uuid::parse_str(&value.ok_or(GuardError::Closed)?).map_err(|_| GuardError::Invalid)
    }
    pub async fn pod_for_container(&self, id: &str) -> Result<Uuid, GuardError> {
        opaque_id(id)?;
        let value: Option<String> =
            sqlx::query_scalar("SELECT pod_uid FROM guard_containers WHERE container_id=$1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
        Uuid::parse_str(&value.ok_or(GuardError::Closed)?).map_err(|_| GuardError::Invalid)
    }

    pub async fn begin_start(
        &self,
        pod_uid: Uuid,
        kind: StartKind,
    ) -> Result<StartPermit, GuardError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let admitted:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM guard_launches l CROSS JOIN guard_meta m WHERE l.pod_uid=$1 AND l.boot_id=$2 AND l.state='OPEN' AND l.expires_at>$3 AND m.singleton=1 AND m.quarantined=0 AND m.coverage_verified=1)").bind(pod_uid.to_string()).bind(self.node.boot_id.to_string()).bind(timestamp(Utc::now())).fetch_one(&mut *tx).await?;
        if !admitted {
            return Err(GuardError::Closed);
        }
        let inflight: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM guard_attempts WHERE pod_uid=$1 AND state='IN_FLIGHT')",
        )
        .bind(pod_uid.to_string())
        .fetch_one(&mut *tx)
        .await?;
        if inflight {
            return Err(GuardError::InFlight);
        }
        let count: i64 =
            sqlx::query_scalar("SELECT forwarded_starts FROM guard_launches WHERE pod_uid=$1")
                .bind(pod_uid.to_string())
                .fetch_one(&mut *tx)
                .await?;
        if kind == StartKind::Run && count >= 1 {
            return Err(GuardError::Closed);
        }
        let backup: bool = sqlx::query_scalar("SELECT COALESCE(json_extract(launch_json,'$.purpose.kind'),'WORKLOAD')='BACKUP' FROM guard_launches WHERE pod_uid=$1")
            .bind(pod_uid.to_string()).fetch_one(&mut *tx).await?;
        if backup {
            let duplicate: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM guard_attempts WHERE pod_uid=$1 AND kind=$2)",
            )
            .bind(pod_uid.to_string())
            .bind(kind.name())
            .fetch_one(&mut *tx)
            .await?;
            if duplicate {
                return Err(GuardError::Closed);
            }
            let previous = match kind {
                StartKind::Run => None,
                StartKind::Create => Some("RUN"),
                StartKind::Start => Some("CREATE"),
            };
            if let Some(previous) = previous {
                let settled:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM guard_attempts WHERE pod_uid=$1 AND kind=$2 AND state='SETTLED')")
                    .bind(pod_uid.to_string()).bind(previous).fetch_one(&mut *tx).await?;
                if !settled {
                    return Err(GuardError::Closed);
                }
            }
        }
        let permit = StartPermit {
            id: Uuid::new_v4(),
            pod_uid,
            kind,
        };
        sqlx::query("INSERT INTO guard_attempts(id,pod_uid,kind,state,started_at) VALUES($1,$2,$3,'IN_FLIGHT',$4)").bind(permit.id.to_string()).bind(pod_uid.to_string()).bind(kind.name()).bind(timestamp(Utc::now())).execute(&mut *tx).await?;
        if kind == StartKind::Run {
            sqlx::query(
                "UPDATE guard_launches SET forwarded_starts=forwarded_starts+1 WHERE pod_uid=$1",
            )
            .bind(pod_uid.to_string())
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query("UPDATE guard_meta SET revision=revision+1 WHERE singleton=1")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?; // The caller may only forward after this FULL commit.
        Ok(permit)
    }

    /// Any error after forwarding is potentially a partial runtime start. A
    /// later successful stop RPC does not resolve this unknown generation.
    pub async fn mark_unknown(&self, permit: &StartPermit) -> Result<(), GuardError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let changed=sqlx::query("UPDATE guard_attempts SET state='UNKNOWN' WHERE id=$1 AND pod_uid=$2 AND kind=$3 AND state IN ('IN_FLIGHT','SETTLED','UNKNOWN')").bind(permit.id.to_string()).bind(permit.pod_uid.to_string()).bind(permit.kind.name()).execute(&mut *tx).await?.rows_affected();
        if changed != 1 {
            return Err(GuardError::IdentityMismatch);
        }
        sqlx::query("UPDATE guard_launches SET state='UNKNOWN' WHERE pod_uid=$1")
            .bind(permit.pod_uid.to_string())
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE guard_meta SET quarantined=1,coverage_verified=0,revision=revision+1 WHERE singleton=1").execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn settle(
        &self,
        permit: &StartPermit,
        sandbox: Option<&SandboxObservation>,
        container: Option<(&str, &str)>,
    ) -> Result<(), GuardError> {
        if (permit.kind == StartKind::Run) != sandbox.is_some()
            || (permit.kind == StartKind::Create) != container.is_some()
        {
            return Err(GuardError::Invalid);
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        if let Some(sandbox) = sandbox {
            opaque_id(&sandbox.sandbox_id)?;
            if sandbox.processes.is_empty() || sandbox.processes.len() > 64 {
                return Err(GuardError::Invalid);
            }
            sqlx::query(
                "INSERT INTO guard_sandboxes(sandbox_id,pod_uid,observation_json) VALUES($1,$2,$3)",
            )
            .bind(&sandbox.sandbox_id)
            .bind(permit.pod_uid.to_string())
            .bind(serde_json::to_string(sandbox)?)
            .execute(&mut *tx)
            .await?;
        }
        if let Some((id, sandbox_id)) = container {
            opaque_id(id)?;
            opaque_id(sandbox_id)?;
            let expected: Option<String> =
                sqlx::query_scalar("SELECT pod_uid FROM guard_sandboxes WHERE sandbox_id=$1")
                    .bind(sandbox_id)
                    .fetch_optional(&mut *tx)
                    .await?;
            if expected.as_deref() != Some(permit.pod_uid.to_string().as_str()) {
                return Err(GuardError::IdentityMismatch);
            }
            sqlx::query(
                "INSERT INTO guard_containers(container_id,pod_uid,sandbox_id) VALUES($1,$2,$3)",
            )
            .bind(id)
            .bind(permit.pod_uid.to_string())
            .bind(sandbox_id)
            .execute(&mut *tx)
            .await?;
        }
        let changed=sqlx::query("UPDATE guard_attempts SET state='SETTLED',settled_at=$4 WHERE id=$1 AND pod_uid=$2 AND kind=$3 AND state='IN_FLIGHT'").bind(permit.id.to_string()).bind(permit.pod_uid.to_string()).bind(permit.kind.name()).bind(timestamp(Utc::now())).execute(&mut *tx).await?.rows_affected();
        if changed != 1 {
            return Err(GuardError::IdentityMismatch);
        }
        sqlx::query("UPDATE guard_meta SET revision=revision+1 WHERE singleton=1")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Closing is irrevocable for this Pod UID, even if there has never been a
    /// registration. Late Run requests can therefore never open a closed UID.
    pub async fn close(&self, request: &CloseRequest) -> Result<ClosedSnapshot, GuardError> {
        self.check_node(request.protocol, &request.node)?;
        if !request.launch.validate() || request.challenge_id.is_nil() {
            return Err(GuardError::Invalid);
        }
        let now = Utc::now();
        if request.challenge_expires_at <= now
            || request.challenge_expires_at > now + chrono::Duration::minutes(5)
        {
            return Err(GuardError::Expired);
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let previous: Option<(String, String)> =
            sqlx::query_as("SELECT launch_json,boot_id FROM guard_launches WHERE pod_uid=$1")
                .bind(request.launch.pod_uid.to_string())
                .fetch_optional(&mut *tx)
                .await?;
        if let Some((value, boot)) = previous {
            if serde_json::from_str::<LaunchBinding>(&value)? != request.launch
                || boot != self.node.boot_id.to_string()
            {
                return Err(GuardError::IdentityMismatch);
            }
            sqlx::query("UPDATE guard_launches SET state=CASE WHEN state='UNKNOWN' THEN 'UNKNOWN' ELSE 'CLOSED' END,closed_at=COALESCE(closed_at,$2) WHERE pod_uid=$1").bind(request.launch.pod_uid.to_string()).bind(timestamp(now)).execute(&mut *tx).await?;
        } else {
            sqlx::query("INSERT INTO guard_launches(pod_uid,boot_id,launch_json,permit_id,expires_at,state,closed_at) VALUES($1,$2,$3,$4,$5,'UNKNOWN',$5)").bind(request.launch.pod_uid.to_string()).bind(self.node.boot_id.to_string()).bind(serde_json::to_string(&request.launch)?).bind(Uuid::nil().to_string()).bind(timestamp(now)).execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE guard_meta SET revision=revision+1 WHERE singleton=1")
            .execute(&mut *tx)
            .await?;
        let row=sqlx::query("SELECT l.state,l.forwarded_starts,l.closed_at,m.revision,m.quarantined,m.coverage_verified,EXISTS(SELECT 1 FROM guard_attempts a WHERE a.pod_uid=l.pod_uid AND a.state='IN_FLIGHT') AS inflight FROM guard_launches l CROSS JOIN guard_meta m WHERE l.pod_uid=$1 AND m.singleton=1").bind(request.launch.pod_uid.to_string()).fetch_one(&mut *tx).await?;
        let values: Vec<String> = sqlx::query_scalar(
            "SELECT observation_json FROM guard_sandboxes WHERE pod_uid=$1 ORDER BY sandbox_id",
        )
        .bind(request.launch.pod_uid.to_string())
        .fetch_all(&mut *tx)
        .await?;
        let sandboxes = values
            .iter()
            .map(|v| serde_json::from_str(v))
            .collect::<Result<Vec<_>, _>>()?;
        let state = if row.get::<String, _>("state") == "UNKNOWN"
            || row.get::<bool, _>("quarantined")
            || !row.get::<bool, _>("coverage_verified")
        {
            ObservationState::UnknownStart
        } else if row.get::<bool, _>("inflight") {
            ObservationState::WaitingInFlight
        } else {
            ObservationState::WaitingRuntime
        };
        let snapshot = ClosedSnapshot {
            node: self.node.clone(),
            launch: request.launch.clone(),
            state,
            revision: row.get("revision"),
            closed_at: DateTime::parse_from_rfc3339(row.get("closed_at"))
                .map_err(|_| GuardError::Invalid)?
                .with_timezone(&Utc),
            forwarded_starts: row.get::<i64, _>("forwarded_starts") as u64,
            sandboxes,
        };
        tx.commit().await?;
        Ok(snapshot)
    }

    fn check_node(&self, protocol: u32, node: &NodeBinding) -> Result<(), GuardError> {
        if protocol != PROTOCOL_VERSION || !node.validate() {
            return Err(GuardError::Invalid);
        }
        if node != &self.node {
            return Err(GuardError::IdentityMismatch);
        }
        Ok(())
    }
}
fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}
pub fn opaque_id(value: &str) -> Result<(), GuardError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(GuardError::Invalid);
    }
    Ok(())
}

impl GateJournal {
    pub async fn require_open(&self, pod_uid: Uuid) -> Result<(), GuardError> {
        let open:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM guard_launches l CROSS JOIN guard_meta m WHERE l.pod_uid=$1 AND l.boot_id=$2 AND l.state='OPEN' AND m.quarantined=0 AND m.coverage_verified=1)").bind(pod_uid.to_string()).bind(self.node.boot_id.to_string()).fetch_one(&self.pool).await?;
        if !open {
            return Err(GuardError::Closed);
        }
        Ok(())
    }
    /// Runtime ListPodSandbox may already have forgotten a still-live VMM.
    /// Startup recovery is driven by our durable ledger, never that list alone.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) async fn unterminated_observations(
        &self,
    ) -> Result<Vec<SandboxObservation>, GuardError> {
        let rows: Vec<String> = sqlx::query_scalar("SELECT s.observation_json FROM guard_sandboxes s JOIN guard_launches l ON l.pod_uid=s.pod_uid WHERE l.boot_id=$1 AND l.termination_json IS NULL ORDER BY s.sandbox_id LIMIT 4097")
            .bind(self.node.boot_id.to_string()).fetch_all(&self.pool).await?;
        if rows.len() > 4096 {
            return Err(GuardError::Unknown);
        }
        rows.into_iter()
            .map(|v| serde_json::from_str(&v).map_err(Into::into))
            .collect()
    }
    pub async fn observation(&self, sandbox_id: &str) -> Result<SandboxObservation, GuardError> {
        opaque_id(sandbox_id)?;
        let value: Option<String> =
            sqlx::query_scalar("SELECT observation_json FROM guard_sandboxes WHERE sandbox_id=$1")
                .bind(sandbox_id)
                .fetch_optional(&self.pool)
                .await?;
        serde_json::from_str(&value.ok_or(GuardError::Unknown)?).map_err(Into::into)
    }
    /// Read-only identity projection; never authorizes Run, CONNECT or closure.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) async fn metric_observations(
        &self,
    ) -> Result<Vec<(LaunchBinding, SandboxObservation)>, GuardError> {
        let rows:Vec<(String,String)>=sqlx::query_as("SELECT l.launch_json,s.observation_json FROM guard_sandboxes s JOIN guard_launches l ON l.pod_uid=s.pod_uid WHERE l.boot_id=$1 AND l.termination_json IS NULL ORDER BY s.sandbox_id LIMIT 257")
            .bind(self.node.boot_id.to_string()).fetch_all(&self.pool).await?;
        if rows.len() > 256 {
            return Err(GuardError::Unknown);
        }
        let mut result = Vec::new();
        for (launch, observation) in rows {
            let launch: LaunchBinding = serde_json::from_str(&launch)?;
            let observation: SandboxObservation = serde_json::from_str(&observation)?;
            if !launch.validate() {
                return Err(GuardError::Invalid);
            }
            if matches!(launch.purpose, LaunchPurpose::Workload) {
                result.push((launch, observation));
            }
        }
        Ok(result)
    }
}

impl GateJournal {
    #[cfg(any(target_os = "linux", test))]
    pub(crate) async fn saved_termination(
        &self,
        pod: Uuid,
    ) -> Result<Option<LocalTerminationEvidence>, GuardError> {
        let value:Option<String>=sqlx::query_scalar("SELECT termination_json FROM guard_launches WHERE pod_uid=$1 AND boot_id=$2 AND state='CLOSED'").bind(pod.to_string()).bind(self.node.boot_id.to_string()).fetch_optional(&self.pool).await?.flatten();
        value
            .map(|v| serde_json::from_str(&v))
            .transpose()
            .map_err(Into::into)
    }
    #[cfg(any(target_os = "linux", test))]
    pub(crate) async fn save_termination(
        &self,
        pod: Uuid,
        evidence: &LocalTerminationEvidence,
    ) -> Result<(), GuardError> {
        if evidence.forwarded_starts != evidence.observed_sandboxes.len() as u64 {
            return Err(GuardError::Unknown);
        }
        let encoded = serde_json::to_string(evidence)?;
        if encoded.len() > MAX_CONTROL_BODY - 4096 {
            return Err(GuardError::Invalid);
        }
        let changed=sqlx::query("UPDATE guard_launches SET termination_json=$3 WHERE pod_uid=$1 AND boot_id=$2 AND state='CLOSED' AND termination_json IS NULL AND forwarded_starts=$4 AND NOT EXISTS(SELECT 1 FROM guard_attempts WHERE pod_uid=$1 AND state<>'SETTLED')")
            .bind(pod.to_string()).bind(self.node.boot_id.to_string()).bind(encoded).bind(evidence.forwarded_starts as i64).execute(&self.pool).await?.rows_affected();
        if changed != 1 && self.saved_termination(pod).await?.is_none() {
            return Err(GuardError::Unknown);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn failed_open_rolls_back_prior_boot_fencing_and_drains_its_connection()
    -> anyhow::Result<()> {
        use sqlx::Connection;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("state.sqlite3");
        let r = request(node());
        let journal = GateJournal::open(&path, r.node.clone()).await?;
        journal.verify_coverage().await?;
        journal.register(&r).await?;
        journal.shutdown().await;
        let mut external = sqlx::SqliteConnection::connect_with(
            &SqliteConnectOptions::new()
                .filename(&path)
                .busy_timeout(Duration::from_millis(50)),
        )
        .await?;
        sqlx::raw_sql("CREATE TRIGGER fail_enrollment BEFORE UPDATE OF node_json ON guard_meta BEGIN SELECT RAISE(ABORT,'PUBLIC_INTENTIONAL_ENROLLMENT_FAILURE'); END;")
            .execute(&mut external).await?;
        let mut next = r.node.clone();
        next.boot_id = Uuid::new_v4();
        // The boot-change UPDATE has run before the later trigger fails. An
        // error must finish its rollback and worker drain before returning.
        assert!(GateJournal::open(&path, next).await.is_err());
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut external)
            .await?;
        let (state, prior): (String, String) = sqlx::query_as(
            "SELECT l.state,m.node_json FROM guard_launches l CROSS JOIN guard_meta m WHERE l.pod_uid=$1",
        )
        .bind(r.launch.pod_uid.to_string())
        .fetch_one(&mut external)
        .await?;
        assert_eq!(
            state, "OPEN",
            "The unsuccessful enrollment must roll back earlier writes"
        );
        assert_eq!(serde_json::from_str::<NodeBinding>(&prior)?, r.node);
        sqlx::query("ROLLBACK").execute(&mut external).await?;
        sqlx::query("DROP TRIGGER fail_enrollment")
            .execute(&mut external)
            .await?;
        external.close().await?;
        GateJournal::open(&path, r.node).await?.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn metrics_project_only_registered_current_boot_workloads_and_never_close_the_gate()
    -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let r = request(node());
        let j = GateJournal::open(&dir.path().join("state.sqlite3"), r.node.clone()).await?;
        j.verify_coverage().await?;
        j.register(&r).await?;
        assert!(j.metric_observations().await?.is_empty());
        let permit = j.begin_start(r.launch.pod_uid, StartKind::Run).await?;
        let obs = observation();
        j.settle(&permit, Some(&obs), None).await?;
        assert_eq!(
            j.metric_observations().await?,
            vec![(r.launch.clone(), obs.clone())]
        );
        j.require_open(r.launch.pod_uid).await?;
        j.close(&close(&r)).await?;
        // A closed start gate is not proof that the observed VMM has exited.
        assert_eq!(
            j.metric_observations().await?,
            vec![(r.launch.clone(), obs)]
        );
        sqlx::query("UPDATE guard_launches SET termination_json='{}' WHERE pod_uid=$1")
            .bind(r.launch.pod_uid.to_string())
            .execute(&j.pool)
            .await?;
        assert!(j.metric_observations().await?.is_empty());
        Ok(())
    }
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
                purpose: crate::nodeguard::protocol::LaunchPurpose::Workload,
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
    #[tokio::test]
    async fn backup_has_one_ordered_run_create_start_and_no_repeated_data_command()
    -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut r = request(node());
        let launch = r.launch.launch_id;
        r.launch.purpose = LaunchPurpose::Backup {
            backup_id: Uuid::new_v4(),
            attempt_id: launch,
            job_uid: Uuid::new_v4(),
            stage: BackupStage::Capture,
            image_ref: format!("registry.example.test/backup@sha256:{}", "a".repeat(64)),
            source_pvc_uid: Uuid::new_v4(),
        };
        r.launch.namespace = "sandbox-system".into();
        r.launch.pod_name = format!("{}-abc12", backup_job_name(launch, BackupStage::Capture));
        let j = GateJournal::open(&dir.path().join("state.sqlite3"), r.node.clone()).await?;
        j.verify_coverage().await?;
        j.register(&r).await?;
        assert!(
            j.begin_start(r.launch.pod_uid, StartKind::Create)
                .await
                .is_err()
        );
        let run = j.begin_start(r.launch.pod_uid, StartKind::Run).await?;
        let observed = observation();
        j.settle(&run, Some(&observed), None).await?;
        assert!(
            j.begin_start(r.launch.pod_uid, StartKind::Start)
                .await
                .is_err()
        );
        let create = j.begin_start(r.launch.pod_uid, StartKind::Create).await?;
        j.settle(&create, None, Some((&"c".repeat(64), &observed.sandbox_id)))
            .await?;
        assert!(
            j.begin_start(r.launch.pod_uid, StartKind::Create)
                .await
                .is_err()
        );
        let start = j.begin_start(r.launch.pod_uid, StartKind::Start).await?;
        j.settle(&start, None, None).await?;
        assert!(
            j.begin_start(r.launch.pod_uid, StartKind::Start)
                .await
                .is_err()
        );
        Ok(())
    }
    #[tokio::test]
    async fn one_launch_never_rebinds_to_job_controller_replacement_pod() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let r = request(node());
        let path = dir.path().join("state.sqlite3");
        let j = GateJournal::open(&path, r.node.clone()).await?;
        j.verify_coverage().await?;
        j.register(&r).await?;
        let mut replacement = r.clone();
        replacement.launch.pod_uid = Uuid::new_v4();
        replacement.permit_id = Uuid::new_v4();
        assert!(matches!(
            j.register(&replacement).await,
            Err(GuardError::IdentityMismatch)
        ));
        j.close(&close(&r)).await?;
        j.shutdown().await;
        let j = GateJournal::open(&path, r.node.clone()).await?;
        j.verify_coverage().await?;
        assert!(matches!(
            j.register(&replacement).await,
            Err(GuardError::IdentityMismatch)
        ));
        Ok(())
    }
    #[tokio::test]
    async fn full_commit_closes_all_late_starts_without_revoking_the_inflight_receipt()
    -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let r = request(node());
        let j = GateJournal::open(&dir.path().join("state.sqlite3"), r.node.clone()).await?;
        assert!(matches!(j.register(&r).await, Err(GuardError::Closed)));
        j.verify_coverage().await?;
        let ack = j.register(&r).await?;
        assert!(ack.journal_revision > 0);
        let mode: i64 = sqlx::query_scalar("PRAGMA synchronous")
            .fetch_one(&j.pool)
            .await?;
        assert_eq!(mode, 2);
        let permit = j.begin_start(r.launch.pod_uid, StartKind::Run).await?;
        assert!(matches!(
            j.begin_start(r.launch.pod_uid, StartKind::Run).await,
            Err(GuardError::InFlight)
        ));
        let closed = j.close(&close(&r)).await?;
        assert_eq!(closed.state, ObservationState::WaitingInFlight);
        assert!(matches!(
            j.begin_start(r.launch.pod_uid, StartKind::Create).await,
            Err(GuardError::Closed)
        ));
        assert!(matches!(j.register(&r).await, Err(GuardError::Closed)));
        j.settle(&permit, Some(&observation()), None).await?;
        let closed = j.close(&close(&r)).await?;
        assert_eq!(closed.state, ObservationState::WaitingRuntime);
        assert_eq!(closed.forwarded_starts, 1);
        assert_eq!(closed.sandboxes.len(), 1);
        Ok(())
    }
    #[tokio::test]
    async fn settled_run_cannot_create_second_vm_and_expired_start_permit_does_not_block_exec()
    -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let r = request(node());
        let j = GateJournal::open(&dir.path().join("state.sqlite3"), r.node.clone()).await?;
        j.verify_coverage().await?;
        j.register(&r).await?;
        let permit = j.begin_start(r.launch.pod_uid, StartKind::Run).await?;
        j.settle(&permit, Some(&observation()), None).await?;
        assert!(matches!(
            j.begin_start(r.launch.pod_uid, StartKind::Run).await,
            Err(GuardError::Closed)
        ));
        sqlx::query("UPDATE guard_launches SET expires_at=$2 WHERE pod_uid=$1")
            .bind(r.launch.pod_uid.to_string())
            .bind(timestamp(Utc::now() - chrono::Duration::seconds(1)))
            .execute(&j.pool)
            .await?;
        j.require_open(r.launch.pod_uid).await?;
        assert!(matches!(
            j.begin_start(r.launch.pod_uid, StartKind::Create).await,
            Err(GuardError::Closed)
        ));
        j.close(&close(&r)).await?;
        assert!(j.require_open(r.launch.pod_uid).await.is_err());
        Ok(())
    }
    #[tokio::test]
    async fn recovery_covers_journal_only_vms_and_durable_death_cache_never_reopens_gate()
    -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("state.sqlite3");
        let r = request(node());
        let j = GateJournal::open(&path, r.node.clone()).await?;
        j.verify_coverage().await?;
        j.register(&r).await?;
        let permit = j.begin_start(r.launch.pod_uid, StartKind::Run).await?;
        let obs = observation();
        j.settle(&permit, Some(&obs), None).await?;
        j.clone().shutdown().await;
        let j = GateJournal::open(&path, r.node.clone()).await?;
        assert_eq!(j.unterminated_observations().await?, vec![obs]);
        j.verify_coverage().await?;
        let snapshot = j.close(&close(&r)).await?;
        let evidence = LocalTerminationEvidence {
            journal_revision: snapshot.revision,
            observed_sandboxes: snapshot.sandboxes,
            forwarded_starts: 1,
            closed_at: snapshot.closed_at,
            processes_exited_at: Utc::now(),
            pod_mounts_absent_at: Utc::now(),
        };
        j.save_termination(r.launch.pod_uid, &evidence).await?;
        j.clone().shutdown().await;
        let j = GateJournal::open(&path, r.node.clone()).await?;
        assert!(j.unterminated_observations().await?.is_empty());
        assert_eq!(
            j.saved_termination(r.launch.pod_uid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("durable cache missing"))?
                .observed_sandboxes,
            evidence.observed_sandboxes
        );
        assert!(j.register(&r).await.is_err());
        assert!(
            j.begin_start(r.launch.pod_uid, StartKind::Run)
                .await
                .is_err()
        );
        let another = request(r.node.clone());
        assert!(j.saved_termination(another.launch.pod_uid).await?.is_none());
        Ok(())
    }
    #[tokio::test]
    async fn extension_ack_returns_durable_max_expiry_and_cannot_reopen_closed_uid()
    -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let r = request(node());
        let j = GateJournal::open(&dir.path().join("state.sqlite3"), r.node.clone()).await?;
        j.verify_coverage().await?;
        let ack = j.register(&r).await?;
        assert_eq!(ack.effective_expires_at, r.expires_at);
        let mut extension = r.clone();
        extension.permit_id = Uuid::new_v4();
        extension.expires_at += chrono::Duration::minutes(5);
        let extended = j.register(&extension).await?;
        assert_eq!(extended.permit_id, extension.permit_id);
        assert_eq!(extended.effective_expires_at, extension.expires_at);
        let replay = j.register(&r).await?;
        assert_eq!(replay.effective_expires_at, extension.expires_at);
        assert!(replay.journal_revision > extended.journal_revision);
        j.close(&close(&r)).await?;
        extension.expires_at += chrono::Duration::minutes(5);
        assert!(matches!(
            j.register(&extension).await,
            Err(GuardError::Closed)
        ));
        Ok(())
    }
    #[tokio::test]
    async fn restart_never_replays_a_durable_unknown_start() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("state.sqlite3");
        let r = request(node());
        let j = GateJournal::open(&path, r.node.clone()).await?;
        j.verify_coverage().await?;
        j.register(&r).await?;
        let _unsettled = j.begin_start(r.launch.pod_uid, StartKind::Run).await?;
        j.pool.close().await;
        let reopened = GateJournal::open(&path, r.node.clone()).await?;
        assert!(matches!(
            reopened.verify_coverage().await,
            Err(GuardError::Unknown)
        ));
        assert_eq!(
            reopened.close(&close(&r)).await?.state,
            ObservationState::UnknownStart
        );
        assert!(matches!(
            reopened.register(&r).await,
            Err(GuardError::Closed)
        ));
        assert!(matches!(
            reopened.begin_start(r.launch.pod_uid, StartKind::Run).await,
            Err(GuardError::Closed)
        ));
        Ok(())
    }
    #[tokio::test]
    async fn cold_or_changed_boot_and_missing_registration_cannot_fabricate_no_start()
    -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("state.sqlite3");
        let r = request(node());
        let j = GateJournal::open(&path, r.node.clone()).await?;
        j.verify_coverage().await?;
        assert_eq!(
            j.close(&close(&r)).await?.state,
            ObservationState::UnknownStart
        );
        assert!(j.register(&r).await.is_err());
        let live = request(r.node.clone());
        j.register(&live).await?;
        let never_started = j.close(&close(&live)).await?;
        assert_eq!(never_started.state, ObservationState::WaitingRuntime);
        assert_eq!(never_started.forwarded_starts, 0);
        assert!(never_started.sandboxes.is_empty());
        j.pool.close().await;
        let mut new_node = r.node.clone();
        new_node.boot_id = Uuid::new_v4();
        let next = GateJournal::open(&path, new_node).await?;
        assert!(matches!(
            next.register(&r).await,
            Err(GuardError::IdentityMismatch)
        ));
        Ok(())
    }
    #[tokio::test]
    async fn close_and_many_start_racers_have_only_one_durable_forwarding_permit()
    -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let r = request(node());
        let j = GateJournal::open(&dir.path().join("state.sqlite3"), r.node.clone()).await?;
        j.verify_coverage().await?;
        j.register(&r).await?;
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..24 {
            let j = j.clone();
            let id = r.launch.pod_uid;
            tasks.spawn(async move { j.begin_start(id, StartKind::Run).await.is_ok() });
        }
        let mut wins = 0;
        while let Some(result) = tasks.join_next().await {
            wins += usize::from(result?);
        }
        assert_eq!(wins, 1);
        let closed = j.close(&close(&r)).await?;
        assert_eq!(closed.forwarded_starts, 1);
        assert_eq!(closed.state, ObservationState::WaitingInFlight);
        Ok(())
    }
}
