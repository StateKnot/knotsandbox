//! PRIVATE real grant-management contraction and real ROLLBACK response faults.
//! HTTP cloud/Kubernetes are stand-ins; no writer/host/media fact is published.
use super::*;
use crate::{
    grants::{ProjectGrant, UpdateGrant},
    restore::raw_bound_collector::{BackupRawBoundTemplateAttempt, handoff_scope_tests},
    restore::tests::admission::commit::CommitProxy,
};
use std::sync::atomic::Ordering;

use tracing::instrument::WithSubscriber;
use tracing_subscriber::prelude::*;

// The request-local listener stores only one allowed static cause and a count.
// SQL/provider/debug/body fields are deliberately never recorded or formatted.
#[derive(Clone, Default)]
struct RefusalEvents {
    warnings: Arc<std::sync::atomic::AtomicUsize>,
    vendor: Arc<std::sync::atomic::AtomicUsize>,
}
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for RefusalEvents {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct Cause<'a>(&'a RefusalEvents);
        impl tracing::field::Visit for Cause<'_> {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "refusal_code" {
                    self.0.warnings.fetch_add(1, Ordering::SeqCst);
                    if value == "RESTORE_RAW_VENDOR_CERTIFICATION_REQUIRED" {
                        self.0.vendor.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
            fn record_debug(
                &mut self,
                _field: &tracing::field::Field,
                _value: &dyn std::fmt::Debug,
            ) {
            }
        }
        if *event.metadata().level() == tracing::Level::WARN {
            event.record(&mut Cause(self));
        }
    }
}

const FAULT_REQUEST_ID: Uuid = Uuid::from_u128(0x3456789a_bcde_4123_9123_123456789abc);

#[derive(Clone, Copy, Debug)]
enum RollbackFault {
    Delay,
    Lost,
}
struct GrantScope {
    original: ProjectGrant,
}
impl GrantScope {
    async fn load(case: &SelectedCase<'_>) -> anyhow::Result<Self> {
        let mut tx = Box::pin(case.source.f.base.f.owner_transaction()).await?;
        let candidates: Vec<ProjectGrant> = sqlx::query_as(
            "SELECT g.* FROM grants g JOIN operations o ON o.tenant_id=g.tenant_id AND o.actor_principal_id=g.principal_id JOIN restores r ON r.tenant_id=o.tenant_id AND r.operation_id=o.id WHERE r.tenant_id=$1 AND r.id=$2 AND g.project_id=r.source_project_id AND g.action IN('backups:restore','*') AND g.enabled AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>clock_timestamp()) ORDER BY g.id",
        ).bind(case.t).bind(case.r).fetch_all(&mut *tx).await?;
        Box::pin(tx.commit()).await?;
        ensure!(
            candidates.len() == 1 && candidates[0].action == "backups:restore",
            "one exact required source-project grant; no alternative/wildcard masks narrowing"
        );
        let original = candidates
            .into_iter()
            .next()
            .context("exact source grant")?;
        ensure!(
            original.expires_at.is_some(),
            "normal source grant already finite before contraction"
        );
        Ok(Self { original })
    }
    async fn tighten(
        &self,
        case: &SelectedCase<'_>,
        seconds: i32,
    ) -> anyhow::Result<chrono::DateTime<Utc>> {
        ensure!(
            matches!(seconds, 4 | 7),
            "only reviewed finite seven/four-second grant horizons"
        );
        let manager = &case.source.f.base.f.actor;
        let database = &case.source.f.base.f.database;
        eprintln!("PRIVATE handoff formal grant read entered");
        let current = Box::pin(database.get_project_grant(
            manager,
            self.original.project_id,
            self.original.id,
        ))
        .await
        .map_err(api_failure)?;
        eprintln!("PRIVATE handoff formal grant read settled");
        let mut tx = Box::pin(case.source.f.base.f.owner_transaction()).await?;
        let (expiry,lease): (chrono::DateTime<Utc>,chrono::DateTime<Utc>) = sqlx::query_as(
            "SELECT clock_timestamp()+make_interval(secs=>$5::double precision),lease_until FROM operations WHERE tenant_id=$1 AND id=$2 AND lease_owner=$3 AND lease_token=$4 AND status='RUNNING' AND lease_until>clock_timestamp()",
        ).bind(case.t).bind(case.claim.operation_id).bind(case.source.f.backup.worker_id()).bind(case.claim.lease_token).bind(seconds).fetch_one(&mut *tx).await?;
        Box::pin(tx.commit()).await?;
        ensure!(
            current.enabled
                && current.revoked_at.is_none()
                && current.principal_id == self.original.principal_id
                && current.action == self.original.action
                && current.expires_at.is_some_and(|old| expiry < old)
                && expiry <= lease,
            "real request only tightens exact grant TTL below existing grant/lease without claim or pin drift"
        );
        let mut actor = manager.clone();
        actor.request_id = Uuid::new_v4();
        eprintln!("PRIVATE handoff formal grant update entered");
        let changed = Box::pin(database.update_project_grant(
            &actor,
            self.original.project_id,
            self.original.id,
            &UpdateGrant {
                enabled: true,
                expires_at: Some(expiry),
            },
            &Uuid::new_v4().to_string(),
            current.version,
        ))
        .await
        .map_err(api_failure)?;
        eprintln!("PRIVATE handoff formal grant update settled");
        ensure!(
            changed.status == 200
                && changed.body.resource.expires_at == Some(expiry)
                && changed.body.resource.version == current.version + 1,
            "real manager guard/IfMatch/key commit advances grant version and exact finite expiry"
        );
        Ok(expiry)
    }
    async fn is_live(
        &self,
        case: &SelectedCase<'_>,
        expiry: chrono::DateTime<Utc>,
    ) -> anyhow::Result<bool> {
        let mut tx = Box::pin(case.source.f.base.f.owner_transaction()).await?;
        let live:bool=sqlx::query_scalar("SELECT expires_at>clock_timestamp() FROM grants WHERE tenant_id=$1 AND id=$2 AND expires_at=$3 AND enabled AND revoked_at IS NULL")
            .bind(case.t).bind(self.original.id).bind(expiry).fetch_one(&mut *tx).await?;
        Box::pin(tx.commit()).await?;
        Ok(live)
    }
    async fn restore(&self, case: &SelectedCase<'_>) -> anyhow::Result<()> {
        let manager = &case.source.f.base.f.actor;
        let db = &case.source.f.base.f.database;
        let current =
            Box::pin(db.get_project_grant(manager, self.original.project_id, self.original.id))
                .await
                .map_err(api_failure)?;
        let mut actor = manager.clone();
        actor.request_id = Uuid::new_v4();
        let result = Box::pin(db.update_project_grant(
            &actor,
            self.original.project_id,
            self.original.id,
            &UpdateGrant {
                enabled: true,
                expires_at: self.original.expires_at,
            },
            &Uuid::new_v4().to_string(),
            current.version,
        ))
        .await
        .map_err(api_failure)?;
        ensure!(
            result.status == 200
                && result.body.resource.version == current.version + 1
                && result.body.resource.expires_at == self.original.expires_at
                && result.body.resource.id == self.original.id
                && result.body.resource.principal_id == self.original.principal_id,
            "fixture restores expiry through real management guard, never resets version/trigger or identity"
        );
        Ok(())
    }
}
struct Resume(Arc<ReadPause>);
impl Drop for Resume {
    fn drop(&mut self) {
        self.0.resume.notify_one();
    }
}
fn caller(case: &SelectedCase<'_>, cloud: &DiskCloud) -> anyhow::Result<BackupRawBoundCollector> {
    BackupRawBoundCollector::for_loopback_test(
        case.w.runtime.clone(),
        cloud.config()?,
        cloud.server.url.clone(),
    )
    .map_err(api_failure)
}
async fn normal_claim(case: &SelectedCase<'_>) -> anyhow::Result<()> {
    ensure!(
        Box::pin(case.source.f.backup.heartbeat(case.claim))
            .await
            .map_err(api_failure)?,
        "only current normal worker renews before a separate original attempt"
    );
    Ok(())
}
async fn first_grant_contraction(
    case: &SelectedCase<'_>,
    cloud: &DiskCloud,
    grant: &GrantScope,
    pause: &Arc<ReadPause>,
    node_path: &str,
) -> anyhow::Result<chrono::DateTime<Utc>> {
    eprintln!("PRIVATE handoff first-grant mutation entered");
    let _resume = Resume(pause.clone());
    tokio::time::timeout(Duration::from_secs(3), pause.arrived.notified())
        .await
        .context("actual first Node GET after collector first SQL")?;
    eprintln!("PRIVATE handoff first Node pause observed");
    ensure!(
        case.w.reads(node_path)? == 1
            && cloud
                .shared
                .lock()
                .map_err(|_| anyhow::anyhow!("cloud count"))?
                .actions
                .is_empty(),
        "real first Node barrier before signed disk reads"
    );
    Box::pin(grant.tighten(case, 7)).await
}
// Keep future construction on a synchronous test-only stack boundary.
// The actual owned observation and original actor/claim remain unchanged.
#[inline(never)]
fn boxed_observe<'a, 'fixture: 'a>(
    collector: &'a BackupRawBoundCollector,
    case: &'a SelectedCase<'fixture>,
) -> std::pin::Pin<
    Box<
        impl std::future::Future<Output = Result<BackupRawBoundTemplateAttempt, crate::error::ApiError>>
        + 'a,
    >,
> {
    Box::pin(collector.observe_pending_restore(
        &case.source.f.backup.database,
        &case.source.f.backup,
        case.claim,
        case.r,
    ))
}
#[inline(never)]
fn boxed_handoff<'a, 'fixture: 'a>(
    case: &'a SelectedCase<'fixture>,
    grant: &'a GrantScope,
    observed: BackupRawBoundTemplateAttempt,
    first_expiry: chrono::DateTime<Utc>,
) -> std::pin::Pin<Box<impl std::future::Future<Output = anyhow::Result<()>> + 'a>> {
    Box::pin(narrowed_handoff(case, grant, observed, first_expiry))
}
async fn narrowed_collect(
    case: &SelectedCase<'_>,
    cloud: &DiskCloud,
    scope: &RawBoundDiskScope,
    grant: &GrantScope,
) -> anyhow::Result<()> {
    let (observed, first_expiry) = {
        eprintln!("PRIVATE handoff contraction phase entered");
        Box::pin(normal_claim(case)).await?;
        case.configure(0, Fault::None)?;
        cloud.reset(0)?;
        let node_path = format!("/api/v1/nodes/{}", scope.facts().node.node_name);
        let pause = Arc::new(ReadPause {
            path: node_path.clone(),
            hit: 1,
            arrived: tokio::sync::Notify::new(),
            resume: tokio::sync::Notify::new(),
        });
        case.w
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("strict first Node barrier"))?
            .read_pause = Some(pause.clone());
        let collector = caller(case, cloud)?;
        eprintln!("PRIVATE handoff first-read grant join entered");
        let (observed, mutation) = tokio::join!(
            boxed_observe(&collector, case),
            Box::pin(first_grant_contraction(
                case, cloud, grant, &pause, &node_path
            ))
        );
        case.w
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("strict barrier clear"))?
            .read_pause = None;
        eprintln!("PRIVATE handoff first-read grant join settled");
        let first_expiry = mutation?;
        let observed = observed.map_err(api_failure)?;
        cloud.exact_actions(2)?;
        reads(case, scope, 2, 3)?;
        Box::pin(unchanged(case)).await?;
        let clocks = handoff_scope_tests::horizons(&observed, &case.source.f.backup, case.claim)?;
        ensure!(
            clocks
                .first
                .checked_duration_since(clocks.final_read)
                .is_some_and(|d| d >= Duration::from_secs(1))
                && clocks.held == clocks.final_read
                && Box::pin(grant.is_live(case, first_expiry)).await?,
            "real manager grant contraction makes final/held strictly shorter than actual first by >=1s while still live"
        );
        (observed, first_expiry)
    };
    boxed_handoff(case, grant, observed, first_expiry).await
}

async fn narrowed_handoff(
    case: &SelectedCase<'_>,
    grant: &GrantScope,
    observed: BackupRawBoundTemplateAttempt,
    first_expiry: chrono::DateTime<Utc>,
) -> anyhow::Result<()> {
    eprintln!("PRIVATE handoff collector final scope checked");
    let second_expiry = Box::pin(grant.tighten(case, 4)).await?;
    eprintln!("PRIVATE handoff second real grant mutation committed");
    ensure!(
        second_expiry < first_expiry,
        "second formal source TTL is strictly smaller than first mutation"
    );
    eprintln!("PRIVATE handoff strict same-TX phase entered");
    let observed = Box::pin(handoff_scope_tests::same_tx_strictly_narrower(
        observed,
        &case.source.f.backup,
        case.claim,
    ))
    .await?;
    eprintln!("PRIVATE handoff strict same-TX phase settled");
    let refusal =
        Box::pin(observed.refuse_unverified_publication(&case.source.f.backup, case.claim))
            .await
            .err()
            .context("narrowed acknowledged vendor refusal")?;
    ensure!(
        refusal.status == StatusCode::FORBIDDEN
            && refusal.code == "RESTORE_RAW_VENDOR_CERTIFICATION_REQUIRED",
        "actual strict same-TX reaches vendor boundary only after acknowledged current rollback"
    );
    Box::pin(
        crate::restore::raw_bound_collector::handoff_tests::no_open_transactions(
            &case.source.f.backup,
        ),
    )
    .await?;
    Box::pin(unchanged(case)).await?;
    eprintln!(
        "VERIFIED private handoff real manager grant7 then grant4: unchanged strict14/claim, collector final<first and sameTX<held each at least1s, actual normal-role rollback ACK/new-min postcheck; no writer or host permit"
    );
    Ok(())
}
async fn narrowed(
    case: &SelectedCase<'_>,
    cloud: &DiskCloud,
    scope: &RawBoundDiskScope,
    grant: &GrantScope,
) -> anyhow::Result<()> {
    eprintln!("PRIVATE handoff narrowed phases entered");
    Box::pin(narrowed_collect(case, cloud, scope, grant)).await
}

struct ReleaseRollback<'a> {
    proxy: &'a CommitProxy,
    mode: RollbackFault,
}
impl Drop for ReleaseRollback<'_> {
    fn drop(&mut self) {
        match self.mode {
            RollbackFault::Delay => self.proxy.rollback_ack.notify_one(),
            RollbackFault::Lost => self.proxy.stop.cancel(),
        }
    }
}
async fn physically_rolled_back(
    case: &SelectedCase<'_>,
    pid: i32,
    start: chrono::DateTime<Utc>,
) -> anyhow::Result<()> {
    let end = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let clear:bool=tokio::time::timeout_at(end,sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND backend_start=$2 AND usename=session_user AND state='idle' AND xact_start IS NULL) AND NOT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND granted AND locktype IN('relation','transactionid'))")
            .bind(pid).bind(start).fetch_one(&case.source.f.backup.database.pool)).await.context("actual rollback own-role idle observer original deadline")??;
        ensure!(
            tokio::time::Instant::now() < end,
            "physical rollback observer ACK arrived within its own unchanged2s"
        );
        if clear {
            return Ok(());
        }
        tokio::time::timeout_at(end, tokio::time::sleep(Duration::from_millis(25)))
            .await
            .context("physical rollback idle stats never reached")?;
    }
}
async fn response_fault(
    case: &SelectedCase<'_>,
    cloud: &DiskCloud,
    scope: &RawBoundDiskScope,
    grant: &GrantScope,
    mode: RollbackFault,
) -> anyhow::Result<()> {
    eprintln!("PRIVATE handoff rollback fault phase entered");
    Box::pin(normal_claim(case)).await?;
    case.configure(0, Fault::None)?;
    cloud.reset(0)?;
    let observed = {
        let collector = caller(case, cloud)?;
        boxed_observe(&collector, case).await.map_err(api_failure)?
    };
    cloud.exact_actions(2)?;
    reads(case, scope, 2, 3)?;
    Box::pin(unchanged(case)).await?;
    let expiry = Box::pin(grant.tighten(
        case,
        match mode {
            RollbackFault::Delay => 4,
            RollbackFault::Lost => 7,
        },
    ))
    .await?;
    let (mut proxy, database) = Box::pin(CommitProxy::connect_handoff_backup_rollback()).await?;
    eprintln!("PRIVATE handoff rollback proxy connected");
    let mut backend_pid = None;
    let refusal_events = RefusalEvents::default();
    let outcome=Box::pin(async {
        let engine = crate::engine::OperationEngine::new(
        database.clone(),
        case.source.f.backup.worker_id().to_owned(),
    )?;
    let (pid,start,login):(i32,chrono::DateTime<Utc>,String)=tokio::time::timeout(Duration::from_secs(5),sqlx::query_as("SELECT pg_backend_pid(),backend_start,session_user::text FROM pg_stat_activity WHERE pid=pg_backend_pid()")
        .fetch_one(&database.pool)).await.context("handoff normal LOGIN/backend identity observation deadline")??;
        backend_pid=Some(pid);
    ensure!(
        login == "sandbox_backup"
            && proxy.completed.load(Ordering::SeqCst) == 0
            && proxy.rollback_completed.load(Ordering::SeqCst) == 0,
        "fresh normal same-role handoff proxy before any COMMIT/ROLLBACK"
    );
        let (call,injected)=tokio::join!(Box::pin(async {
            let result=tokio::time::timeout(Duration::from_secs(12),crate::error::REQUEST_ID.scope(FAULT_REQUEST_ID,Box::pin(observed.refuse_unverified_publication(&engine,case.claim))).with_subscriber(tracing_subscriber::registry().with(refusal_events.clone()))).await.context("handoff fault watchdog, not a production deadline extension")?;
            ensure!(proxy.rollback_completed.load(Ordering::SeqCst)==1 && !proxy.rollback_forwarded.load(Ordering::SeqCst),"actual caller settled while targeted ROLLBACK/ReadyForQuery response had not been forwarded");
            result.err().context("handoff response unknown must never return writer success")
        }),Box::pin(async {
            let _release=ReleaseRollback {proxy:&proxy,mode};
            tokio::time::timeout(Duration::from_secs(3),proxy.rollback_arrived.notified()).await.context("actual ROLLBACK CommandComplete target not reached")?;
            ensure!(proxy.rollback_completed.load(Ordering::SeqCst)==1 && proxy.completed.load(Ordering::SeqCst)==0
                && !proxy.rollback_forwarded.load(Ordering::SeqCst),"ROLLBACK-only fault, never mislabeled inherited COMMIT hook");
            Box::pin(physically_rolled_back(case,pid,start)).await?;
            match mode {
                RollbackFault::Delay=>{
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    ensure!(!Box::pin(grant.is_live(case,expiry)).await?,"held real rollback response crosses the actually managed finite grant horizon");
                }
                RollbackFault::Lost=>{
                    ensure!(Box::pin(grant.is_live(case,expiry)).await?,"lost real rollback response occurs while shortened source grant is still live");
                    proxy.stop.cancel();
                }
            }
            Ok::<(),anyhow::Error>(())
        }));
        injected?;let refusal=call?;
        ensure!(refusal_events.warnings.load(Ordering::SeqCst)==1 && refusal_events.vendor.load(Ordering::SeqCst)==1,
            "targeted actual rollback has the original fixed vendor cause, not a prepublication pin/decoder/dependency failure");
        ensure!(refusal.status==StatusCode::SERVICE_UNAVAILABLE && refusal.code=="RESTORE_RAW_HANDOFF_UNCONFIRMED"
            && refusal.detail=="Raw restore transaction acknowledgement unavailable; no publication or host permit is authorized" && !refusal.retryable && refusal.request_id==FAULT_REQUEST_ID,
            "only fixed nonretryable unconfirmed handoff; vendor403 cannot mask rollback/clock unknown");
        Box::pin(crate::restore::raw_bound_collector::handoff_tests::no_open_transactions(&case.source.f.backup)).await?;
        Box::pin(unchanged(case)).await?;
        Ok::<(),anyhow::Error>(())
    }).await;
    // Await pool drain and owned forwarding FD/task join before propagating
    // business error. A failed cleanup is not an acknowledged drain.
    let cleanup =
        Box::pin(proxy.finish_handoff(&database, &case.source.f.base.f.owner, backend_pid)).await;
    if cleanup.is_err() {
        eprintln!("PRIVATE handoff fault proxy cleanup unconfirmed");
    }
    outcome?;
    cleanup?;
    Box::pin(unchanged(case)).await?;
    eprintln!(
        "VERIFIED private handoff {mode:?} real ROLLBACK/ReadyForQuery fault: own-role backend idle/lockrelease, exact503nonretryable, pool closed and owned proxy joined/PID absent, whole source/target/holdquota unchanged; not media or host proof"
    );
    Ok(())
}
pub(super) async fn run(
    case: &SelectedCase<'_>,
    cloud: &DiskCloud,
    scope: &RawBoundDiskScope,
) -> anyhow::Result<()> {
    eprintln!("PRIVATE handoff fault suite entered");
    let grant = Box::pin(GrantScope::load(case)).await?;
    eprintln!("PRIVATE handoff exact source grant loaded");
    let contraction = Box::pin(narrowed(case, cloud, scope, &grant)).await;
    let restored = Box::pin(grant.restore(case)).await;
    if restored.is_err() {
        eprintln!("PRIVATE handoff grant restoration unconfirmed");
    }
    contraction?;
    restored?;
    for mode in [RollbackFault::Delay, RollbackFault::Lost] {
        let outcome = Box::pin(response_fault(case, cloud, scope, &grant, mode)).await;
        let restored = Box::pin(grant.restore(case)).await;
        if restored.is_err() {
            eprintln!("PRIVATE handoff grant restoration unconfirmed");
        }
        outcome?;
        restored?;
        Box::pin(confirmed_fresh(case, cloud, scope)).await?;
    }
    Box::pin(unchanged(case)).await?;
    Ok(())
}

async fn confirmed_fresh(
    case: &SelectedCase<'_>,
    cloud: &DiskCloud,
    scope: &RawBoundDiskScope,
) -> anyhow::Result<()> {
    Box::pin(normal_claim(case)).await?;
    case.configure(0, Fault::None)?;
    cloud.reset(0)?;
    let collector = caller(case, cloud)?;
    let observed = boxed_observe(&collector, case).await.map_err(api_failure)?;
    cloud.exact_actions(2)?;
    reads(case, scope, 2, 3)?;
    let refusal =
        Box::pin(observed.refuse_unverified_publication(&case.source.f.backup, case.claim))
            .await
            .err()
            .context("fresh acknowledged attempt still refuses absent vendor")?;
    ensure!(
        refusal.status == StatusCode::FORBIDDEN
            && refusal.code == "RESTORE_RAW_VENDOR_CERTIFICATION_REQUIRED",
        "fresh restored real authority/claim attempt returns original confirmed vendor403; no old scope reused"
    );
    Box::pin(
        crate::restore::raw_bound_collector::handoff_tests::no_open_transactions(
            &case.source.f.backup,
        ),
    )
    .await?;
    Box::pin(unchanged(case)).await?;
    eprintln!(
        "VERIFIED private handoff fresh acknowledged original-attempt vendor403 after unknown response; no old timer/scope reuse"
    );
    Ok(())
}
