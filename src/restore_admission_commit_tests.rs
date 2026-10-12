//! Real loopback PostgreSQL acknowledgements, never recorded. This private
//! fixture holds COMMIT frames or its explicit new handoff ROLLBACK mode;
//! production startup/TLS and all original COMMIT modes are unchanged.
use super::super::super::{RestoreRecord, admission::RestoreAdmissionService, ledger::JobPlan};
use crate::{
    admission::AdmissionRequest, db::Database, termination_ledger::tests::FixtureRuntime,
    test_support_db::api_failure,
};
use anyhow::{Context, ensure};
use chrono::{DateTime, Utc};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub(in crate::restore::tests) struct CommitProxy {
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    pub(in crate::restore::tests) stop: CancellationToken,
    pub(in crate::restore::tests) completed: Arc<AtomicUsize>,
    pub(in crate::restore::tests) first: Arc<Notify>,
    pub(in crate::restore::tests) final_commit: Arc<Notify>,
    pub(in crate::restore::tests) first_ack: Arc<Notify>,
    pub(in crate::restore::tests) final_ack: Arc<Notify>,
    pub(in crate::restore::tests) rollback_completed: Arc<AtomicUsize>,
    pub(in crate::restore::tests) rollback_arrived: Arc<Notify>,
    pub(in crate::restore::tests) rollback_ack: Arc<Notify>,
    pub(in crate::restore::tests) rollback_forwarded: Arc<std::sync::atomic::AtomicBool>,
}
impl Drop for CommitProxy {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
#[derive(Clone, Copy)]
enum AckMode {
    Admission,
    Owner { held_commit: usize },
    BoundAdmission { held_commit: usize },
    BoundBackup { held_commit: usize },
    HandoffBackupRollback,
}
impl CommitProxy {
    async fn connect() -> anyhow::Result<(Self, Database)> {
        Self::connect_mode(AckMode::Admission).await
    }
    pub(in crate::restore::tests) async fn connect_owner(
        held_commit: usize,
    ) -> anyhow::Result<(Self, Database)> {
        ensure!(
            matches!(held_commit, 1 | 2),
            "only exact first/final owner COMMIT faults"
        );
        Self::connect_mode(AckMode::Owner { held_commit }).await
    }
    pub(in crate::restore::tests) async fn connect_bound_admission(
        held_commit: usize,
    ) -> anyhow::Result<(Self, Database)> {
        ensure!(
            matches!(held_commit, 1 | 2),
            "exact bound admission COMMIT ordinal"
        );
        Self::connect_mode(AckMode::BoundAdmission { held_commit }).await
    }
    pub(in crate::restore::tests) async fn connect_bound_backup(
        held_commit: usize,
    ) -> anyhow::Result<(Self, Database)> {
        ensure!(
            matches!(held_commit, 1 | 2),
            "exact bound backup COMMIT ordinal"
        );
        Self::connect_mode(AckMode::BoundBackup { held_commit }).await
    }
    pub(in crate::restore::tests) async fn connect_handoff_backup_rollback()
    -> anyhow::Result<(Self, Database)> {
        Self::connect_mode(AckMode::HandoffBackupRollback).await
    }
    async fn connect_mode(mode: AckMode) -> anyhow::Result<(Self, Database)> {
        let (environment, expected_login) = match mode {
            AckMode::Admission => ("TEST_ADMISSION_DATABASE_URL", "sandbox_admission"),
            AckMode::Owner { .. } => ("TEST_MIGRATION_DATABASE_URL", "sandbox_owner"),
            AckMode::BoundAdmission { .. } => ("TEST_ADMISSION_DATABASE_URL", "sandbox_admission"),
            AckMode::BoundBackup { .. } | AckMode::HandoffBackupRollback => {
                ("TEST_BACKUP_DATABASE_URL", "sandbox_backup")
            }
        };
        let mut url = url::Url::parse(&std::env::var(environment)?)?;
        ensure!(
            matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"))
                && url.username() == expected_login,
            "private acknowledgement fixture requires the exact isolated loopback login"
        );
        let target = url::Url::parse(&std::env::var("TEST_DATABASE_URL")?)?;
        ensure!(
            url.host_str() == target.host_str()
                && url.port_or_known_default() == target.port_or_known_default()
                && url.path() == target.path(),
            "proxy must use the same fresh disposable database"
        );
        let upstream = (
            url.host_str().context("loopback host")?.to_owned(),
            url.port().unwrap_or(5432),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let stop = CancellationToken::new();
        let completed = Arc::new(AtomicUsize::new(0));
        let first = Arc::new(Notify::new());
        let final_commit = Arc::new(Notify::new());
        let first_ack = Arc::new(Notify::new());
        let final_ack = Arc::new(Notify::new());
        let rollback_completed = Arc::new(AtomicUsize::new(0));
        let rollback_arrived = Arc::new(Notify::new());
        let rollback_ack = Arc::new(Notify::new());
        let rollback_forwarded = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (rollback_count, rollback_seen, rollback_release, rollback_sent) = (
            rollback_completed.clone(),
            rollback_arrived.clone(),
            rollback_ack.clone(),
            rollback_forwarded.clone(),
        );
        let (count, initial, committed, initial_ack, committed_ack, shutdown) = (
            completed.clone(),
            first.clone(),
            final_commit.clone(),
            first_ack.clone(),
            final_ack.clone(),
            stop.clone(),
        );
        let task = tokio::spawn(async move {
            let forward = async {
                let (client, _) = listener.accept().await?;
                let backend = TcpStream::connect(upstream).await?;
                client.set_nodelay(true)?;
                backend.set_nodelay(true)?;
                let (mut client_read, mut client_write) = client.into_split();
                let (mut backend_read, mut backend_write) = backend.into_split();
                tokio::try_join!(
                    async {
                        tokio::io::copy(&mut client_read, &mut backend_write).await?;
                        backend_write.shutdown().await
                    },
                    async {
                        let mut targeted_rollback = false;
                        loop {
                            let mut tag = [0u8; 1];
                            match backend_read.read_exact(&mut tag).await {
                                Ok(_) => {}
                                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                                    return Ok(());
                                }
                                Err(e) => return Err(e),
                            }
                            let mut encoded = [0u8; 4];
                            backend_read.read_exact(&mut encoded).await?;
                            let size = u32::from_be_bytes(encoded);
                            if !(4..=16 * 1024 * 1024).contains(&size) {
                                return Err(std::io::Error::other(
                                    "invalid PostgreSQL response frame",
                                ));
                            }
                            let mut payload =
                                vec![0; usize::try_from(size - 4).map_err(std::io::Error::other)?];
                            backend_read.read_exact(&mut payload).await?;
                            if tag[0] == b'C' && payload == b"COMMIT\0" {
                                let ordinal = count.fetch_add(1, Ordering::SeqCst) + 1;
                                if ordinal > 2 {
                                    return Err(std::io::Error::other(
                                        "unexpected authority transaction",
                                    ));
                                }
                                let held = match mode {
                                    AckMode::Admission => true,
                                    AckMode::HandoffBackupRollback => false,
                                    AckMode::Owner { held_commit }
                                    | AckMode::BoundAdmission { held_commit }
                                    | AckMode::BoundBackup { held_commit } => {
                                        ordinal == held_commit
                                    }
                                };
                                if held && ordinal == 1 {
                                    initial.notify_one();
                                    initial_ack.notified().await;
                                } else if held && ordinal == 2 {
                                    committed.notify_one();
                                    committed_ack.notified().await;
                                }
                            }
                            // Only this explicit new mode observes actual ROLLBACK.
                            // Holding its CommandComplete also withholds the next
                            // ReadyForQuery consumed by sqlx rollback().await.
                            if matches!(mode, AckMode::HandoffBackupRollback)
                                && tag[0] == b'C'
                                && payload == b"ROLLBACK\0"
                            {
                                let ordinal = rollback_count.fetch_add(1, Ordering::SeqCst) + 1;
                                if ordinal == 1 {
                                    rollback_seen.notify_one();
                                    rollback_release.notified().await;
                                    targeted_rollback = true;
                                }
                            }
                            if targeted_rollback && tag[0] == b'Z' && payload != b"I" {
                                return Err(std::io::Error::other(
                                    "top-level rollback ReadyForQuery was not idle",
                                ));
                            }
                            client_write.write_all(&tag).await?;
                            client_write.write_all(&encoded).await?;
                            client_write.write_all(&payload).await?;
                            if targeted_rollback && tag[0] == b'Z' {
                                rollback_sent.store(true, Ordering::SeqCst);
                                targeted_rollback = false;
                            }
                        }
                    }
                )?;
                Ok(())
            };
            // Normal finish closes its pool before shutdown. The dedicated Bound
            // lost-ACK fixture also cancels after backend COMMIT, before ACK.
            // Cancellation drops the actual socket halves; finish joins them.
            tokio::select! { result = forward => result, _ = shutdown.cancelled() => Ok(()) }
        });
        url.set_host(Some("127.0.0.1"))
            .map_err(|_| anyhow::anyhow!("proxy host"))?;
        url.set_port(Some(port))
            .map_err(|_| anyhow::anyhow!("proxy port"))?;
        let parameters: Vec<(String, String)> = url
            .query_pairs()
            .filter(|(key, _)| key != "sslmode")
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        url.set_query(None);
        url.query_pairs_mut()
            .extend_pairs(parameters)
            .append_pair("sslmode", "disable");
        // This exact isolated loopback fixture forwards real SCRAM. Production
        // database validation still requires verified remote TLS and role checks.
        let mut proxy = Self {
            task: Some(task),
            stop,
            completed,
            first,
            final_commit,
            first_ack,
            final_ack,
            rollback_completed,
            rollback_arrived,
            rollback_ack,
            rollback_forwarded,
        };
        let database = match Database::connect(url.as_str(), 1).await {
            Ok(database) => database,
            Err(error) => {
                proxy.stop.cancel();
                if let Some(mut task) = proxy.task.take() {
                    match tokio::time::timeout(Duration::from_secs(3), &mut task).await {
                        Ok(_) => {}
                        Err(_) => {
                            task.abort();
                            let _ = task.await;
                        }
                    }
                }
                return Err(error.context("bounded private proxy connection failed"));
            }
        };
        Ok((proxy, database))
    }
    async fn finish(
        &mut self,
        database: &Database,
        base: &FixtureRuntime,
        pid: i32,
    ) -> anyhow::Result<()> {
        self.finish_owner(database, &base.f.owner, pid).await
    }
    pub(in crate::restore::tests) async fn finish_handoff(
        &mut self,
        database: &Database,
        owner: &sqlx::PgPool,
        pid: Option<i32>,
    ) -> anyhow::Result<()> {
        if let Some(pid) = pid {
            return self.finish_owner(database, owner, pid).await;
        }
        // Startup observation failed after a real pool was created. Still
        // settle it and the owned proxy; never assert an unidentified PID gone.
        if !self.stop.is_cancelled() {
            self.rollback_ack.notify_one();
        }
        database.pool.close().await;
        self.stop.cancel();
        if let Some(mut task) = self.task.take() {
            match tokio::time::timeout(Duration::from_secs(3), &mut task).await {
                Ok(result) => result??,
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    anyhow::bail!("unidentified handoff proxy failed to join after pool close");
                }
            }
        }
        anyhow::bail!("handoff backend identity was never established; no absence certificate")
    }
    pub(in crate::restore::tests) async fn finish_owner(
        &mut self,
        database: &Database,
        owner: &sqlx::PgPool,
        pid: i32,
    ) -> anyhow::Result<()> {
        self.first_ack.notify_one();
        self.final_ack.notify_one();
        if !self.stop.is_cancelled() {
            self.rollback_ack.notify_one();
        }
        database.pool.close().await;
        self.stop.cancel();
        if let Some(mut task) = self.task.take() {
            match tokio::time::timeout(Duration::from_secs(3), &mut task).await {
                Ok(result) => result??,
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    anyhow::bail!("owned acknowledgement proxy failed to finish after pool close");
                }
            }
        }
        let mut gone = false;
        for _ in 0..30 {
            gone = sqlx::query_scalar(
                "SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)",
            )
            .bind(pid)
            .fetch_one(owner)
            .await?;
            if gone {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        ensure!(gone, "joined proxy must release the real backend process");
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
enum Authority {
    Lease,
    SourceGrant,
}
struct Saved {
    lease: DateTime<Utc>,
    grants: Vec<(Uuid, Option<DateTime<Utc>>)>,
}
async fn shorten(
    base: &FixtureRuntime,
    record: &RestoreRecord,
    kind: Authority,
) -> anyhow::Result<Saved> {
    let mut tx = base.f.owner_transaction().await?;
    let lease =
        sqlx::query_scalar("SELECT lease_until FROM operations WHERE tenant_id=$1 AND id=$2")
            .bind(record.tenant_id)
            .bind(record.operation_id)
            .fetch_one(&mut *tx)
            .await?;
    let grants = sqlx::query_as("SELECT g.id,g.expires_at FROM grants g JOIN operations o ON o.tenant_id=g.tenant_id AND o.actor_principal_id=g.principal_id WHERE o.tenant_id=$1 AND o.id=$2 AND g.project_id=$3 AND g.action IN('backups:restore','*') AND g.enabled AND g.revoked_at IS NULL")
        .bind(record.tenant_id).bind(record.operation_id).bind(record.source_project_id).fetch_all(&mut *tx).await?;
    match kind {
        Authority::Lease => {
            sqlx::query("UPDATE operations SET lease_until=clock_timestamp()+interval '2 seconds' WHERE tenant_id=$1 AND id=$2")
                .bind(record.tenant_id).bind(record.operation_id).execute(&mut *tx).await?;
        }
        Authority::SourceGrant => {
            ensure!(
                !grants.is_empty(),
                "source restore grant must exist before expiry fixture"
            );
            for (id, _) in &grants {
                sqlx::query("UPDATE grants SET expires_at=clock_timestamp()+interval '2 seconds' WHERE tenant_id=$1 AND id=$2")
                    .bind(record.tenant_id).bind(id).execute(&mut *tx).await?;
            }
        }
    }
    tx.commit().await?;
    Ok(Saved { lease, grants })
}
async fn restore(
    base: &FixtureRuntime,
    record: &RestoreRecord,
    saved: Saved,
) -> anyhow::Result<()> {
    let mut tx = base.f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET lease_until=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(record.tenant_id)
        .bind(record.operation_id)
        .bind(saved.lease)
        .execute(&mut *tx)
        .await?;
    for (id, expiry) in saved.grants {
        sqlx::query("UPDATE grants SET expires_at=$3 WHERE tenant_id=$1 AND id=$2")
            .bind(record.tenant_id)
            .bind(id)
            .bind(expiry)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub(in crate::restore::tests) async fn final_ack(
    service: &RestoreAdmissionService,
    review: &AdmissionRequest,
    plan: &JobPlan,
    base: &FixtureRuntime,
    grant: bool,
) -> anyhow::Result<()> {
    final_ack_record(service, review, &plan.record, base, grant, false).await
}

async fn final_ack_record(
    service: &RestoreAdmissionService,
    review: &AdmissionRequest,
    record: &RestoreRecord,
    base: &FixtureRuntime,
    grant: bool,
    shorten_before_io: bool,
) -> anyhow::Result<()> {
    let kind = if grant {
        Authority::SourceGrant
    } else {
        Authority::Lease
    };
    let (mut proxy, database) = CommitProxy::connect().await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&database.pool)
        .await?;
    let delayed = RestoreAdmissionService {
        database: database.clone(),
        ..service.clone()
    };
    // Raw pins the project authz version. Shortening a grant after its first
    // reader would correctly fail pin equality before final COMMIT. Its ACK
    // case therefore installs the finite grant before the validator begins.
    let mut saved = if shorten_before_io {
        Some(shorten(base, record, kind).await?)
    } else {
        None
    };
    let (copy, request) = (delayed.clone(), review.clone());
    let started = Instant::now();
    let mut decision = Some(tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(4), Box::pin(copy.decide(&request))).await
    }));
    let result = async {
        tokio::time::timeout(Duration::from_secs(2), proxy.first.notified()).await?;
        ensure!(proxy.completed.load(Ordering::SeqCst)==1, "initial authority committed exactly once");
        // Existing Job/lease cases shorten after the first backend COMMIT;
        // Raw's finite-grant case was shortened before its pinned first read.
        if saved.is_none() {
            saved = Some(shorten(base, record, kind).await?);
        }
        proxy.first_ack.notify_one();
        tokio::time::timeout(Duration::from_secs(2), proxy.final_commit.notified()).await?;
        let released: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND granted AND locktype IN('relation','transactionid'))")
            .bind(pid).fetch_one(&base.f.owner).await?;
        ensure!(released, "backend final COMMIT must release its transaction locks before held ACK");
        tokio::time::sleep(Duration::from_secs(3)).await;
        proxy.final_ack.notify_one();
        let answer = decision.take().context("owned decision")?.await??;
        ensure!(started.elapsed()<Duration::from_secs(4), "fixture remains within production decision budget");
        ensure!(answer.err().is_some_and(|e|e.code==403), "final ACK crossing real {kind:?} must deny, never dependency timeout");
        ensure!(proxy.completed.load(Ordering::SeqCst)==2, "exactly two real authority COMMITs");
        anyhow::Ok(())
    }.await;
    proxy.first_ack.notify_one();
    proxy.final_ack.notify_one();
    if let Some(mut task) = decision.take()
        && tokio::time::timeout(Duration::from_secs(5), &mut task)
            .await
            .is_err()
    {
        task.abort();
        let _ = task.await;
    }
    let cleanup = proxy.finish(&database, base, pid).await;
    let restored = if let Some(saved) = saved {
        restore(base, record, saved).await
    } else {
        Ok(())
    };
    result?;
    cleanup?;
    restored?;
    eprintln!(
        "VERIFIED actual backend final COMMIT/lock release, held ACK crosses short {kind:?}, 403 inside unchanged 4s decision; proxy owner joined and backend PID absent"
    );
    Ok(())
}

// Real admission-role horizon reads prove alternatives and exact project scope;
// these temporary grants belong only to the isolated test database fixture.
pub(super) async fn alternatives(
    service: &RestoreAdmissionService,
    plan: &JobPlan,
    base: &FixtureRuntime,
) -> anyhow::Result<()> {
    let tenant = plan.record.tenant_id;
    let mut tx = base.f.owner_transaction().await?;
    let actor: Uuid = sqlx::query_scalar(
        "SELECT actor_principal_id FROM operations WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant)
    .bind(plan.record.operation_id)
    .fetch_one(&mut *tx)
    .await?;
    let (grant, expiry):(Uuid,Option<DateTime<Utc>>)=sqlx::query_as("SELECT id,expires_at FROM grants WHERE tenant_id=$1 AND principal_id=$2 AND project_id=$3 AND action='backups:restore' AND enabled AND revoked_at IS NULL")
        .bind(tenant).bind(actor).bind(plan.record.source_project_id).fetch_one(&mut *tx).await?;
    let no_wildcard:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM grants WHERE tenant_id=$1 AND principal_id=$2 AND project_id IN($3,$4) AND action='*')")
        .bind(tenant).bind(actor).bind(plan.record.source_project_id).bind(plan.record.target_project_id).fetch_one(&mut *tx).await?;
    ensure!(
        no_wildcard,
        "fixture must start without project wildcard alternatives"
    );
    let source_wildcard = Uuid::new_v4();
    let target_wildcard = Uuid::new_v4();
    sqlx::query("UPDATE grants SET expires_at=clock_timestamp()+interval '2 seconds' WHERE tenant_id=$1 AND id=$2")
        .bind(tenant).bind(grant).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO grants(id,tenant_id,principal_id,project_id,action,expires_at) VALUES($1,$2,$3,$4,'*',clock_timestamp()+interval '10 minutes')")
        .bind(source_wildcard).bind(tenant).bind(actor).bind(plan.record.source_project_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let result=async {
        for permanent in [false,true] {
            if permanent {
                let mut tx=base.f.owner_transaction().await?;
                sqlx::query("UPDATE grants SET expires_at=NULL WHERE tenant_id=$1 AND id=$2")
                    .bind(tenant).bind(source_wildcard).execute(&mut *tx).await?;
                tx.commit().await?;
            }
            let mut tx=service.database.begin(tenant).await.map_err(api_failure)?;
            let budget:Option<i64>=sqlx::query_scalar("SELECT sandbox_restore_admission_horizon($1,$2)")
                .bind(tenant).bind(plan.record.id).fetch_one(&mut *tx).await?;
            ensure!(budget.is_some_and(|v|v>5_000_000),"longer/permanent alternative must outlive short exact grant");
            tx.commit().await?;
        }
        let mut tx=base.f.owner_transaction().await?;
        sqlx::query("DELETE FROM grants WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(source_wildcard).execute(&mut *tx).await?;
        sqlx::query("UPDATE grants SET expires_at=clock_timestamp()+interval '2 seconds' WHERE tenant_id=$1 AND id=$2")
            .bind(tenant).bind(grant).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO grants(id,tenant_id,principal_id,project_id,action) VALUES($1,$2,$3,$4,'*')")
            .bind(target_wildcard).bind(tenant).bind(actor).bind(plan.record.target_project_id).execute(&mut *tx).await?;
        tx.commit().await?;
        let mut tx=service.database.begin(tenant).await.map_err(api_failure)?;
        let budget:Option<i64>=sqlx::query_scalar("SELECT sandbox_restore_admission_horizon($1,$2)")
            .bind(tenant).bind(plan.record.id).fetch_one(&mut *tx).await?;
        ensure!(budget.is_some_and(|v|v>0&&v<=2_000_000),"target-project wildcard cannot replace source restore authority");
        tx.commit().await?;
        let mut tx=base.f.owner_transaction().await?;
        sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(grant).execute(&mut *tx).await?;
        tx.commit().await?;
        let mut tx=service.database.begin(tenant).await.map_err(api_failure)?;
        let budget:Option<i64>=sqlx::query_scalar("SELECT sandbox_restore_admission_horizon($1,$2)")
            .bind(tenant).bind(plan.record.id).fetch_one(&mut *tx).await?;
        ensure!(budget.is_none(),"tenant and target grants cannot replace missing exact-source project grant");
        tx.commit().await?;
        anyhow::Ok(())
    }.await;
    let mut tx = base.f.owner_transaction().await?;
    sqlx::query("DELETE FROM grants WHERE tenant_id=$1 AND id IN($2,$3)")
        .bind(tenant)
        .bind(source_wildcard)
        .bind(target_wildcard)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE grants SET enabled=true,expires_at=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(tenant)
        .bind(grant)
        .bind(expiry)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    result?;
    eprintln!(
        "VERIFIED real admission-role horizon: longer finite/permanent wildcard alternative, exact source/target scope and required tenant AND project grants"
    );
    Ok(())
}

pub(super) async fn initial_ack(
    service: &RestoreAdmissionService,
    review: &AdmissionRequest,
    plan: &JobPlan,
    base: &FixtureRuntime,
) -> anyhow::Result<()> {
    initial_ack_record(service, review, &plan.record, base).await
}

/// Raw parent admission has no Job context or Job authority. It exercises the
/// exact same owned SCRAM/COMMIT proxy and finite-lease fixture using only the
/// real normally accepted restore's recorded IDs.
pub(in crate::restore::tests) async fn raw_ack(
    service: &RestoreAdmissionService,
    review: &AdmissionRequest,
    record: &RestoreRecord,
    base: &FixtureRuntime,
    final_ack: bool,
) -> anyhow::Result<()> {
    if final_ack {
        final_ack_record(service, review, record, base, false, false).await
    } else {
        initial_ack_record(service, review, record, base).await
    }
}

/// Finite source permission is installed before Raw's first authority read so
/// its pinned authz version remains equal; only the final held ACK crosses it.
pub(in crate::restore::tests) async fn raw_final_grant_ack(
    service: &RestoreAdmissionService,
    review: &AdmissionRequest,
    record: &RestoreRecord,
    base: &FixtureRuntime,
) -> anyhow::Result<()> {
    final_ack_record(service, review, record, base, true, true).await
}

async fn initial_ack_record(
    service: &RestoreAdmissionService,
    review: &AdmissionRequest,
    record: &RestoreRecord,
    base: &FixtureRuntime,
) -> anyhow::Result<()> {
    let (mut proxy, database) = CommitProxy::connect().await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&database.pool)
        .await?;
    let saved = shorten(base, record, Authority::Lease).await?;
    let delayed = RestoreAdmissionService {
        database: database.clone(),
        ..service.clone()
    };
    let (copy, request) = (delayed.clone(), review.clone());
    let started = Instant::now();
    let mut decision = Some(tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(4), Box::pin(copy.decide(&request))).await
    }));
    let result=async {
        tokio::time::timeout(Duration::from_secs(2),proxy.first.notified()).await?;
        let released:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND granted AND locktype IN('relation','transactionid'))")
            .bind(pid).fetch_one(&base.f.owner).await?;
        ensure!(released,"first authority COMMIT must finish on backend before held ACK");
        tokio::time::sleep(Duration::from_secs(3)).await;
        proxy.first_ack.notify_one();
        let answer=decision.take().context("owned initial authority decision")?.await??;
        ensure!(started.elapsed()<Duration::from_secs(4),"initial authority case preserves 4s budget");
        ensure!(answer.err().is_some_and(|e|e.code==403),"first ACK crossing lease must deny before remote observation or final admission");
        ensure!(proxy.completed.load(Ordering::SeqCst)==1,"expired first authority cannot start another admission transaction");
        anyhow::Ok(())
    }.await;
    proxy.first_ack.notify_one();
    proxy.final_ack.notify_one();
    if let Some(mut task) = decision.take()
        && tokio::time::timeout(Duration::from_secs(5), &mut task)
            .await
            .is_err()
    {
        task.abort();
        let _ = task.await;
    }
    let cleanup = proxy.finish(&database, base, pid).await;
    let restored = restore(base, record, saved).await;
    result?;
    cleanup?;
    restored?;
    eprintln!(
        "VERIFIED first-I/O monotonic authority includes first real COMMIT ACK wait; expired lease denies with one transaction, joined proxy and absent backend PID"
    );
    Ok(())
}

/// Historical cleanup has no revocable grant horizon, but its new observation
/// is bounded. This test budget is deliberately outside the unchanged 10s
/// validator contract and does not change the production listener's 4s timeout.
pub(in crate::restore::tests) async fn historical_final_ack(
    service: &RestoreAdmissionService,
    review: &AdmissionRequest,
    base: &FixtureRuntime,
) -> anyhow::Result<()> {
    let (mut proxy, database) = CommitProxy::connect().await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&database.pool)
        .await?;
    let delayed = RestoreAdmissionService {
        database: database.clone(),
        ..service.clone()
    };
    let request = review.clone();
    let started = Instant::now();
    let mut decision = Some(tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(14), Box::pin(delayed.decide(&request))).await
    }));
    let result = async {
        tokio::time::timeout(Duration::from_secs(2), proxy.first.notified()).await?;
        proxy.first_ack.notify_one();
        tokio::time::timeout(Duration::from_secs(2), proxy.final_commit.notified()).await?;
        let released: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND granted AND locktype IN('relation','transactionid'))")
            .bind(pid).fetch_one(&base.f.owner).await?;
        ensure!(released,"historical backend final COMMIT must release transaction locks before held ACK");
        tokio::time::sleep(Duration::from_secs(11)).await;
        proxy.final_ack.notify_one();
        let answer = decision.take().context("owned historical decision")?.await??;
        ensure!(started.elapsed() < Duration::from_secs(14), "bounded observation must return within fixture outer budget");
        ensure!(answer.err().is_some_and(|e|e.code==403),"historical final ACK crossing 10s must reject, never timeout or permit");
        ensure!(proxy.completed.load(Ordering::SeqCst)==2,"historical decision has exactly two actual authority transactions");
        anyhow::Ok(())
    }.await;
    proxy.first_ack.notify_one();
    proxy.final_ack.notify_one();
    if let Some(mut task) = decision.take()
        && tokio::time::timeout(Duration::from_secs(5), &mut task)
            .await
            .is_err()
    {
        task.abort();
        let _ = task.await;
    }
    let cleanup = proxy.finish(&database, base, pid).await;
    result?;
    cleanup?;
    eprintln!(
        "VERIFIED historical final COMMIT actually released backend locks; held ACK crosses total10s and returns403 inside14s fixture, real proxy owner joined and backend PID absent"
    );
    Ok(())
}
