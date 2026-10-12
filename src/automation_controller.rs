//! A replica may wake whenever it wants. PostgreSQL owns due times, claims,
//! immutable run requests and operation links; wakeups confer no authority.
use super::{
    ledger::{self, lock_resources, now},
    *,
};
use crate::{
    automation_authority::AutomationAcceptanceFence,
    db::{Actor, Database},
    domain::InstanceAction,
    error::ApiError,
    model::{CreateExecution, RenewRequest, StartRequest},
};
use chrono::Duration;
use sqlx::{Postgres, Row, Transaction};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone)]
pub struct AutomationController {
    database: Database,
    worker: String,
    default_ttl: i64,
    max_ttl: i64,
    scheduling_ready: Arc<AtomicBool>,
}
#[derive(sqlx::FromRow)]
pub struct AutomationClaim {
    pub(crate) tenant_id: Uuid,
    pub(crate) automation_id: Uuid,
    pub(crate) lease_token: i64,
}
pub(super) struct PreparedRun {
    actor: Actor,
    instance_id: Uuid,
    workspace_id: Uuid,
    kind: String,
    request: Value,
    expected: i64,
    fence: AutomationAcceptanceFence,
}
impl AutomationController {
    pub fn new(
        database: Database,
        worker: String,
        default_ttl: i64,
        max_ttl: i64,
    ) -> Result<Self, ApiError> {
        if worker.is_empty() || worker.len() > 128 || !(60..=max_ttl).contains(&default_ttl) {
            return Err(ApiError::invalid("Invalid automation worker configuration"));
        }
        Ok(Self {
            database,
            worker,
            default_ttl,
            max_ttl,
            scheduling_ready: Arc::new(AtomicBool::new(false)),
        })
    }
    pub async fn check_schema(&self) -> anyhow::Result<()> {
        self.database.verify_runtime_role().await?;
        ledger::require_formal_schema(&self.database).await?;
        let role: String = sqlx::query_scalar("SELECT session_user::text")
            .fetch_one(&self.database.pool)
            .await?;
        anyhow::ensure!(
            role == "sandbox_automation",
            "automation worker requires its dedicated login"
        );
        // One fixed privilege matrix is shared by startup and readiness. Each
        // permission is checked separately: PostgreSQL comma lists mean OR.
        let usable: bool = sqlx::query_scalar(REQUIRED_RUNTIME_PRIVILEGES)
            .fetch_one(&self.database.pool)
            .await?;
        anyhow::ensure!(
            usable,
            "automation worker required privileges are incomplete"
        );
        let private_exposed:bool=sqlx::query_scalar("SELECT has_table_privilege(current_user,'automation_claims','SELECT') OR has_table_privilege(current_user,'automation_claims','UPDATE') OR has_column_privilege(current_user,'automation_runs','lease_token','SELECT') OR has_column_privilege(current_user,'automation_runs','lease_token','UPDATE') OR has_column_privilege(current_user,'automation_runs','dispatch_attempt_id','UPDATE')")
            .fetch_one(&self.database.pool).await?;
        anyhow::ensure!(
            !private_exposed,
            "automation worker cannot enumerate or forge private claims"
        );
        Ok(())
    }
    pub(super) fn is_ready(&self) -> bool {
        self.scheduling_ready.load(Ordering::Acquire)
    }
    fn fatal(&self, error: &ApiError) -> bool {
        crate::service_lifecycle::fatal_database_failure(&self.database.pool, error)
            || error.code == "AUTOMATION_REQUEST_CHANGED"
            || (error.status.is_server_error()
                && !(error.retryable
                    && matches!(error.code, "DEPENDENCY_UNAVAILABLE" | "PLATFORM_SAFE_MODE")))
    }
    pub async fn run(
        self: Arc<Self>,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> anyhow::Result<()> {
        self.check_schema()
            .await
            .map_err(|_| anyhow::anyhow!("automation worker runtime verification failed"))?;
        let result = self.run_loop(shutdown).await;
        self.scheduling_ready.store(false, Ordering::Release);
        result
    }
    async fn run_loop(&self, shutdown: tokio_util::sync::CancellationToken) -> anyhow::Result<()> {
        loop {
            let claimed = tokio::select! {biased;()=shutdown.cancelled()=>return Ok(()),claimed=self.claim()=>claimed};
            let (result, idle) = match claimed {
                Ok(Some(claim)) => {
                    // One accepted request at a time per replica. A signal
                    // prevents the next I/O; the current DB transaction gets
                    // its normal bounded completion/rollback budget.
                    (self.run_claim_inner(&claim, Some(&shutdown)).await, false)
                }
                Ok(None) => (Ok(()), true),
                Err(error) => (Err(error), false),
            };
            let delay = match result.map_err(normalize_guard_error) {
                Ok(()) => {
                    self.scheduling_ready.store(true, Ordering::Release);
                    if idle {
                        std::time::Duration::from_millis(500)
                    } else {
                        std::time::Duration::ZERO
                    }
                }
                Err(error) if self.fatal(&error) => {
                    self.scheduling_ready.store(false, Ordering::Release);
                    shutdown.cancel();
                    tracing::error!(
                        code = error.code,
                        "automation runtime stopped after fatal error"
                    );
                    // Never expose a database error's detail or a stored request.
                    anyhow::bail!(
                        "automation runtime stopped after fatal error ({})",
                        error.code
                    );
                }
                Err(error) if error.retryable => {
                    self.scheduling_ready.store(false, Ordering::Release);
                    tracing::warn!(
                        code = error.code,
                        "automation dependency unavailable; durable history retained"
                    );
                    std::time::Duration::from_secs(2)
                }
                Err(error) => {
                    // A current-policy/business rejection is not a process
                    // failure; prepare/acceptance retains its existing outcome.
                    self.scheduling_ready.store(true, Ordering::Release);
                    tracing::warn!(
                        code = error.code,
                        "automation reconciliation rejected by current policy"
                    );
                    std::time::Duration::ZERO
                }
            };
            tokio::select! {biased;()=shutdown.cancelled()=>return Ok(()),()=tokio::time::sleep(delay)=>{}}
        }
    }
    pub async fn claim(&self) -> Result<Option<AutomationClaim>, ApiError> {
        Ok(sqlx::query_as("SELECT * FROM sandbox_claim_automation($1)")
            .bind(&self.worker)
            .fetch_optional(&self.database.pool)
            .await?)
    }
    pub async fn run_claim(&self, claim: &AutomationClaim) -> Result<(), ApiError> {
        self.run_claim_inner(claim, None)
            .await
            .map_err(normalize_guard_error)
    }
    async fn run_claim_inner(
        &self,
        claim: &AutomationClaim,
        shutdown: Option<&tokio_util::sync::CancellationToken>,
    ) -> Result<(), ApiError> {
        if shutdown.is_some_and(|s| s.is_cancelled()) {
            return Ok(());
        }
        let prepared = self.prepare(claim).await?;
        let mut transient_acceptance_error = None;
        if let Some(prepared) = prepared {
            if shutdown.is_some_and(|s| s.is_cancelled()) {
                // Keep the committed request, attempt, resource and key. A new
                // coordinator resumes the same intent after lease expiry.
                return Ok(());
            }
            let result = self.accept(&prepared).await.map_err(normalize_guard_error);
            if let Err(error) = result {
                if self.fatal(&error) {
                    // An infrastructure/invariant failure is not proof that this
                    // intent failed. Leave the committed intent and lease intact
                    // for a fresh worker; do not consume another run budget.
                    return Err(error);
                }
                // Acquiring resource locks here waits for an earlier acceptance
                // transaction to commit/rollback. Never replace its key or ID.
                self.record_acceptance_error(claim, prepared.fence.run_id, &error)
                    .await?;
                if error.retryable {
                    transient_acceptance_error = Some(error);
                }
            }
        }
        let mut tx = self.database.begin(claim.tenant_id).await?;
        sqlx::query("SELECT sandbox_finish_automation_claim($1,$2,$3,$4)")
            .bind(claim.tenant_id)
            .bind(claim.automation_id)
            .bind(&self.worker)
            .bind(claim.lease_token)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        if let Some(error) = transient_acceptance_error {
            // Finish only after durable error reconciliation, then let the loop
            // advertise degraded readiness and use its existing bounded backoff.
            return Err(error);
        }
        Ok(())
    }
    async fn claim_live(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        claim: &AutomationClaim,
    ) -> Result<bool, ApiError> {
        Ok(
            sqlx::query_scalar("SELECT sandbox_check_automation_claim($1,$2,$3,$4)")
                .bind(claim.tenant_id)
                .bind(claim.automation_id)
                .bind(&self.worker)
                .bind(claim.lease_token)
                .fetch_one(&mut **tx)
                .await?,
        )
    }
    #[cfg(test)]
    pub(crate) async fn prepare_for_acceptance_test(
        &self,
        claim: &AutomationClaim,
    ) -> Result<bool, ApiError> {
        Ok(self.prepare(claim).await?.is_some())
    }

    pub(super) async fn prepare(
        &self,
        claim: &AutomationClaim,
    ) -> Result<Option<PreparedRun>, ApiError> {
        let mut tx = self.database.begin(claim.tenant_id).await?;
        let initial = ledger::load(&mut tx, claim.tenant_id, claim.automation_id).await?;
        lock_resources(&mut tx, claim.tenant_id, initial.instance_id).await?;
        sqlx::query("SELECT id FROM automations WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
            .bind(claim.tenant_id)
            .bind(claim.automation_id)
            .fetch_one(&mut *tx)
            .await?;
        let a = ledger::load(&mut tx, claim.tenant_id, claim.automation_id).await?;
        sqlx::query("SELECT d.id FROM automation_delegations d JOIN automations a ON a.tenant_id=d.tenant_id AND a.delegation_id=d.id WHERE a.tenant_id=$1 AND a.id=$2 FOR UPDATE OF d").bind(claim.tenant_id).bind(a.id).fetch_one(&mut *tx).await?;
        if !self.claim_live(&mut tx, claim).await? {
            tx.commit().await?;
            return Ok(None);
        }
        let db_now = now(&mut tx).await?;
        // Facts are read without locking operations. Their closure is guarded
        // by existing execution/backup/lifecycle constraints and append-only
        // cleanup receipts. No run lock waits for an operation lock.
        let existing=sqlx::query("SELECT id,status,operation_id,deadline,automation_version,cluster_epoch FROM automation_runs WHERE tenant_id=$1 AND automation_id=$2 AND status IN('PENDING','CLAIMED','DISPATCHING','SUBMITTED','OUTCOME_UNKNOWN')")
            .bind(claim.tenant_id).bind(a.id).fetch_optional(&mut *tx).await?;
        let newly_prepared = existing.is_none();
        let run = if let Some(row) = existing {
            let run: Uuid = row.try_get("id")?;
            if let Some(operation) = row.try_get::<Option<Uuid>, _>("operation_id")? {
                let closed:Option<String>=sqlx::query_scalar("SELECT o.status FROM operations o WHERE o.tenant_id=$1 AND o.id=$2 AND o.status IN('SUCCEEDED','FAILED','CANCELLED') AND CASE o.kind WHEN 'EXECUTE' THEN EXISTS(SELECT 1 FROM executions e WHERE e.tenant_id=o.tenant_id AND e.operation_id=o.id AND NOT e.slot_held AND e.status IN('SUCCEEDED','FAILED','CANCELLED','TIMED_OUT')) WHEN 'BACKUP' THEN EXISTS(SELECT 1 FROM backups b JOIN workspace_hold_releases h ON h.tenant_id=b.tenant_id AND h.hold_id=b.hold_id WHERE b.tenant_id=o.tenant_id AND b.operation_id=o.id) ELSE EXISTS(SELECT 1 FROM instances i JOIN workspaces w ON w.tenant_id=i.tenant_id AND w.id=i.workspace_id WHERE i.tenant_id=o.tenant_id AND i.id=o.instance_id AND i.active_operation_id IS DISTINCT FROM o.id AND w.active_operation_id IS DISTINCT FROM o.id) END")
                    .bind(claim.tenant_id).bind(operation).fetch_optional(&mut *tx).await?;
                if let Some(status) = closed {
                    sqlx::query("UPDATE automation_runs SET status=$3,completed_at=clock_timestamp(),failure_code=CASE WHEN $3='FAILED' THEN 'OPERATION_FAILED' ELSE NULL END WHERE tenant_id=$1 AND id=$2 AND status='SUBMITTED'")
                        .bind(claim.tenant_id).bind(run).bind(if status=="SUCCEEDED"{"SUCCEEDED"}else{"FAILED"}).execute(&mut *tx).await?;
                    ledger::event(
                        &mut tx,
                        &Actor {
                            authorization: None,
                            tenant_id: claim.tenant_id,
                            principal_id: a.creator_principal_id,
                            request_id: run,
                        },
                        a.project_id,
                        run,
                        "automations:run",
                        &status,
                    )
                    .await?;
                    self.exhaust_if_finished(&mut tx, &a).await?;
                }
                tx.commit().await?;
                return Ok(None);
            }
            let live_authority = ledger::authorized(&mut tx, claim.tenant_id, a.id).await?;
            if a.status != "ACTIVE"
                || row.try_get::<i64, _>("automation_version")? != a.version
                || db_now >= row.try_get::<DateTime<Utc>, _>("deadline")?
                || !live_authority
            {
                let code = if ledger::stream_live(&mut tx, claim.tenant_id, a.id).await? {
                    "AUTHORITY_OR_DEADLINE_CHANGED"
                } else {
                    "EVENT_STREAM_CHANGED"
                };
                sqlx::query("UPDATE automation_runs SET status='CANCELLED',failure_code=$3,completed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND operation_id IS NULL")
                    .bind(claim.tenant_id).bind(run).bind(code).execute(&mut *tx).await?;
                self.run_event(&mut tx, &a, run, "CANCELLED").await?;
                if a.status == "ACTIVE" && !live_authority {
                    sqlx::query("UPDATE automations SET status=$3,version=version+1 WHERE tenant_id=$1 AND id=$2")
                        .bind(claim.tenant_id).bind(a.id).bind(if db_now>=a.delegation_expires_at{"EXPIRED"}else{"PAUSED"}).execute(&mut *tx).await?;
                    self.policy_event(
                        &mut tx,
                        &a,
                        if db_now >= a.delegation_expires_at {
                            "EXPIRED"
                        } else {
                            "PAUSED"
                        },
                        run,
                    )
                    .await?;
                } else {
                    self.exhaust_if_finished(&mut tx, &a).await?;
                }
                tx.commit().await?;
                return Ok(None);
            }
            let (current_epoch, safe_mode): (Uuid, bool) = sqlx::query_as(
                "SELECT cluster_epoch,safe_mode FROM platform_configuration WHERE singleton",
            )
            .fetch_one(&mut *tx)
            .await?;
            if current_epoch != row.try_get::<Uuid, _>("cluster_epoch")? {
                sqlx::query("UPDATE automation_runs SET status='CANCELLED',failure_code='CONTROL_EPOCH_CHANGED',completed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND operation_id IS NULL")
                    .bind(claim.tenant_id).bind(run).execute(&mut *tx).await?;
                self.run_event(&mut tx, &a, run, "CANCELLED").await?;
                self.exhaust_if_finished(&mut tx, &a).await?;
                tx.commit().await?;
                return Ok(None);
            }
            if safe_mode {
                tx.commit().await?;
                return Ok(None);
            }
            run
        } else {
            if db_now >= a.delegation_expires_at && matches!(a.status.as_str(), "ACTIVE" | "PAUSED")
            {
                sqlx::query("UPDATE automations SET status='EXPIRED',version=version+1 WHERE tenant_id=$1 AND id=$2").bind(claim.tenant_id).bind(a.id).execute(&mut *tx).await?;
                self.policy_event(&mut tx, &a, "EXPIRED", Uuid::new_v4())
                    .await?;
                tx.commit().await?;
                return Ok(None);
            }
            if a.status != "ACTIVE" {
                tx.commit().await?;
                return Ok(None);
            }
            if a.emitted_runs >= a.run_budget {
                self.exhaust_if_finished(&mut tx, &a).await?;
                tx.commit().await?;
                return Ok(None);
            }
            if !ledger::authorized(&mut tx, claim.tenant_id, a.id).await? {
                // Authority restoration requires an explicit current-policy
                // resume. A revoked issuer mapping must not silently recover.
                sqlx::query("UPDATE automations SET status='PAUSED',version=version+1 WHERE tenant_id=$1 AND id=$2").bind(claim.tenant_id).bind(a.id).execute(&mut *tx).await?;
                self.policy_event(&mut tx, &a, "PAUSED", Uuid::new_v4())
                    .await?;
                tx.commit().await?;
                return Ok(None);
            }
            let policy=sqlx::query("SELECT action,event_sequence,last_emitted_at FROM automations WHERE tenant_id=$1 AND id=$2").bind(claim.tenant_id).bind(a.id).fetch_one(&mut *tx).await?;
            let action: AutomationAction = serde_json::from_value(policy.try_get("action")?)
                .map_err(|_| stored_error("Stored automation action is invalid"))?;
            let mut source = None;
            let mut source_sequence = None;
            let mut skipped = None;
            let mut failure = None;
            let (due, deadline, next_due) = if a.trigger_kind == "EVENT" {
                let mut seq: i64 = policy.try_get("event_sequence")?;
                let batch=sqlx::query("SELECT e.id,p.sequence,e.occurred_at,e.event_type,e.aggregate_id,EXISTS(SELECT 1 FROM automation_runs r WHERE r.tenant_id=e.tenant_id AND(r.id=e.request_id OR r.operation_id=e.operation_id)) AS automated FROM event_stream_positions p JOIN domain_events e ON e.tenant_id=p.tenant_id AND e.id=p.event_id WHERE p.tenant_id=$1 AND p.project_id=$2 AND p.sequence>$3 ORDER BY p.sequence LIMIT 256")
                    .bind(claim.tenant_id).bind(a.project_id).bind(seq).fetch_all(&mut *tx).await?;
                let mut event = None;
                for row in batch {
                    seq = row.try_get("sequence")?;
                    if !row.try_get::<bool, _>("automated")?
                        && Some(row.try_get::<String, _>("event_type")?.as_str())
                            == a.event_type.as_deref()
                        && Some(row.try_get::<Uuid, _>("aggregate_id")?) == a.event_aggregate_id
                    {
                        event = Some(row);
                        break;
                    }
                }
                sqlx::query(
                    "UPDATE automations SET event_sequence=$3 WHERE tenant_id=$1 AND id=$2",
                )
                .bind(claim.tenant_id)
                .bind(a.id)
                .bind(seq)
                .execute(&mut *tx)
                .await?;
                let Some(event) = event else {
                    tx.commit().await?;
                    return Ok(None);
                };
                source = Some(event.try_get::<Uuid, _>("id")?);
                source_sequence = Some(seq);
                let occurred: DateTime<Utc> = event.try_get("occurred_at")?;
                let deadline = (occurred + Duration::seconds(i64::from(a.grace_seconds)))
                    .min(a.delegation_expires_at);
                if db_now >= deadline {
                    failure = Some("EVENT_EXPIRED");
                }
                if policy
                    .try_get::<Option<DateTime<Utc>>, _>("last_emitted_at")?
                    .is_some_and(|last| {
                        db_now < last + Duration::seconds(i64::from(a.minimum_interval_seconds))
                    })
                {
                    failure = Some("EVENT_RATE_LIMITED");
                }
                sqlx::query(
                    "UPDATE automations SET event_sequence=$3 WHERE tenant_id=$1 AND id=$2",
                )
                .bind(claim.tenant_id)
                .bind(a.id)
                .bind(seq)
                .execute(&mut *tx)
                .await?;
                (None, deadline, None)
            } else {
                let Some(due) = a.next_due_at else {
                    tx.commit().await?;
                    return Ok(None);
                };
                let cron = a
                    .cron_expression
                    .as_deref()
                    .map(rules::UtcCron::parse)
                    .transpose()
                    .map_err(|_| stored_error("Stored UTC cron is invalid"))?;
                match rules::decide_due(
                    cron.as_ref(),
                    due,
                    db_now,
                    a.delegation_expires_at,
                    a.grace_seconds as u32,
                )
                .map_err(|_| stored_error("Stored automation schedule is invalid"))?
                {
                    rules::DueDecision::NotDue => {
                        tx.commit().await?;
                        return Ok(None);
                    }
                    rules::DueDecision::Expired => {
                        tx.commit().await?;
                        return Ok(None);
                    }
                    rules::DueDecision::Ready {
                        scheduled_for,
                        deadline,
                        next_due,
                    } => (Some(scheduled_for), deadline, next_due),
                    rules::DueDecision::Skipped {
                        from,
                        through,
                        next_due,
                    } => {
                        skipped = Some(through);
                        failure = Some("SCHEDULE_EXPIRED");
                        (
                            Some(from),
                            from + Duration::seconds(i64::from(a.grace_seconds)),
                            next_due,
                        )
                    }
                }
            };
            let run = Uuid::new_v4();
            let produced = if matches!(
                action,
                AutomationAction::Execute { .. } | AutomationAction::Backup { .. }
            ) {
                Uuid::new_v4()
            } else {
                a.instance_id
            };
            let (original, operation_request) = action.requests(db_now, produced)?;
            let(version,generation):(i64,i64)=sqlx::query_as("SELECT CASE WHEN $3='BACKUP' THEN w.spec_version ELSE i.spec_version END,i.runtime_generation FROM instances i JOIN workspaces w ON w.tenant_id=i.tenant_id AND w.id=i.workspace_id WHERE i.tenant_id=$1 AND i.id=$2")
                .bind(claim.tenant_id).bind(a.instance_id).bind(action.kind()).fetch_one(&mut *tx).await?;
            let epoch = crate::db::runnable_epoch(&mut tx).await?;
            let digest = hex::encode(crate::request::request_digest(&original, Some(version))?);
            sqlx::query("INSERT INTO automation_runs(id,tenant_id,project_id,automation_id,automation_version,delegation_id,creator_principal_id,instance_id,workspace_id,scheduled_for,source_event_id,source_event_sequence,skipped_through,operation_kind,original_request,operation_request,expected_resource_version,expected_generation,cluster_epoch,produced_resource_id,management_key,request_sha256,status,failure_code,deadline,created_at,updated_at,completed_at) SELECT $1,a.tenant_id,a.project_id,a.id,a.version,a.delegation_id,a.creator_principal_id,a.instance_id,a.workspace_id,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'automation-run:'||$1::text,$15,$16,$17,$18,$19,$19,CASE WHEN $16='SKIPPED' THEN $19 ELSE NULL END FROM automations a WHERE a.tenant_id=$2 AND a.id=$3")
                .bind(run).bind(claim.tenant_id).bind(a.id).bind(due).bind(source).bind(source_sequence).bind(skipped).bind(action.kind()).bind(original).bind(operation_request).bind(version).bind(generation).bind(epoch).bind(produced).bind(digest).bind(if failure.is_some(){"SKIPPED"}else{"PENDING"}).bind(failure).bind(deadline).bind(db_now).execute(&mut *tx).await?;
            sqlx::query("UPDATE automations SET next_due_at=$3,emitted_runs=emitted_runs+1,last_emitted_at=$4 WHERE tenant_id=$1 AND id=$2")
                .bind(claim.tenant_id).bind(a.id).bind(next_due).bind(db_now).execute(&mut *tx).await?;
            // Pending intent is committed before calling the real acceptor.
            if failure.is_some() {
                ledger::event(
                    &mut tx,
                    &Actor {
                        authorization: None,
                        tenant_id: claim.tenant_id,
                        principal_id: a.creator_principal_id,
                        request_id: run,
                    },
                    a.project_id,
                    run,
                    "automations:run",
                    "SKIPPED",
                )
                .await?;
                self.exhaust_if_finished(&mut tx, &a).await?;
                tx.commit().await?;
                return Ok(None);
            }
            run
        };
        let binding = sqlx::query("SELECT * FROM sandbox_bind_automation_run_claim($1,$2,$3,$4)")
            .bind(claim.tenant_id)
            .bind(run)
            .bind(&self.worker)
            .bind(claim.lease_token)
            .fetch_one(&mut *tx)
            .await?;
        let row=sqlx::query("SELECT original_request,operation_kind,expected_resource_version,management_key,request_sha256 FROM automation_runs WHERE tenant_id=$1 AND id=$2").bind(claim.tenant_id).bind(run).fetch_one(&mut *tx).await?;
        let prepared = PreparedRun {
            actor: Actor {
                authorization: None,
                tenant_id: claim.tenant_id,
                principal_id: a.creator_principal_id,
                request_id: run,
            },
            instance_id: a.instance_id,
            workspace_id: a.workspace_id,
            kind: row.try_get("operation_kind")?,
            request: row.try_get("original_request")?,
            expected: row.try_get("expected_resource_version")?,
            fence: AutomationAcceptanceFence {
                run_id: run,
                lease_owner: self.worker.clone(),
                lease_token: claim.lease_token,
                dispatch_attempt_id: binding.try_get("dispatch_attempt_id")?,
                produced_resource_id: binding.try_get("produced_resource_id")?,
                management_key: row.try_get("management_key")?,
                request_sha256: row.try_get("request_sha256")?,
            },
        };
        if newly_prepared {
            ledger::event(
                &mut tx,
                &prepared.actor,
                a.project_id,
                run,
                "automations:run",
                "PREPARED",
            )
            .await?;
        }
        let deadline: DateTime<Utc> =
            sqlx::query_scalar("SELECT deadline FROM automation_runs WHERE tenant_id=$1 AND id=$2")
                .bind(claim.tenant_id)
                .bind(run)
                .fetch_one(&mut *tx)
                .await?;
        if !self.claim_live(&mut tx, claim).await?
            || !ledger::authorized(&mut tx, claim.tenant_id, a.id).await?
            || now(&mut tx).await? >= deadline
        {
            return Err(ApiError::conflict(
                "AUTOMATION_FENCE_CHANGED",
                "Automation authority changed before preparing the durable request",
            ));
        }
        tx.commit().await?;
        Ok(Some(prepared))
    }
    pub(super) async fn accept(&self, p: &PreparedRun) -> Result<(), ApiError> {
        let key = &p.fence.management_key;
        match p.kind.as_str() {
            "EXECUTE" => {
                let r: CreateExecution = decode(&p.request)?;
                self.database
                    .create_execution_with_automation(
                        &p.actor,
                        p.instance_id,
                        &r,
                        key,
                        p.expected,
                        &p.fence,
                    )
                    .await?;
            }
            "BACKUP" => {
                let r: crate::backup_ledger::CreateBackup = decode(&p.request)?;
                self.database
                    .create_backup_with_automation(
                        &p.actor,
                        p.workspace_id,
                        &r,
                        key,
                        p.expected,
                        &p.fence,
                    )
                    .await?;
            }
            "RENEW" => {
                let r: RenewRequest = decode(&p.request)?;
                self.database
                    .renew_instance_with_automation(
                        &p.actor,
                        p.instance_id,
                        &r,
                        key,
                        p.expected,
                        self.max_ttl,
                        &p.fence,
                    )
                    .await?;
            }
            "START" | "STOP" | "RESTART" | "DELETE" => {
                let r: StartRequest = decode(&p.request)?;
                let action = match p.kind.as_str() {
                    "START" => InstanceAction::Start,
                    "STOP" => InstanceAction::Stop,
                    "RESTART" => InstanceAction::Restart,
                    _ => InstanceAction::Delete,
                };
                self.database
                    .lifecycle_action_with_automation(
                        &p.actor,
                        p.instance_id,
                        action,
                        &r,
                        key,
                        p.expected,
                        self.default_ttl,
                        self.max_ttl,
                        &p.fence,
                    )
                    .await?;
            }
            _ => return Err(stored_error("Stored automation operation is invalid")),
        }
        Ok(())
    }
    async fn record_acceptance_error(
        &self,
        claim: &AutomationClaim,
        run: Uuid,
        error: &ApiError,
    ) -> Result<(), ApiError> {
        let mut tx = self.database.begin(claim.tenant_id).await?;
        let a = ledger::load(&mut tx, claim.tenant_id, claim.automation_id).await?;
        lock_resources(&mut tx, claim.tenant_id, a.instance_id).await?;
        if !self.claim_live(&mut tx, claim).await? {
            tx.commit().await?;
            return Ok(());
        }
        sqlx::query("SELECT id FROM automations WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
            .bind(claim.tenant_id)
            .bind(a.id)
            .fetch_one(&mut *tx)
            .await?;
        // A committed operation link outranks a lost local ACK. Do not change
        // that run or resend an EXECUTE merely because the caller saw an error.
        let status = if error.retryable {
            "OUTCOME_UNKNOWN"
        } else {
            "FAILED"
        };
        let changed=sqlx::query("UPDATE automation_runs SET status=$3,failure_code=$4,completed_at=CASE WHEN $3='FAILED' THEN clock_timestamp() ELSE NULL END WHERE tenant_id=$1 AND id=$2 AND operation_id IS NULL AND status='DISPATCHING'")
            .bind(claim.tenant_id).bind(run).bind(status).bind(error.code).execute(&mut *tx).await?.rows_affected();
        if changed == 1 {
            ledger::event(
                &mut tx,
                &Actor {
                    authorization: None,
                    tenant_id: claim.tenant_id,
                    principal_id: a.creator_principal_id,
                    request_id: run,
                },
                a.project_id,
                run,
                "automations:run",
                status,
            )
            .await?;
            self.exhaust_if_finished(&mut tx, &a).await?;
        }
        tx.commit().await?;
        Ok(())
    }
    async fn exhaust_if_finished(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        a: &Automation,
    ) -> Result<(), ApiError> {
        let changed=sqlx::query("UPDATE automations a SET status='EXHAUSTED',version=version+1 WHERE a.tenant_id=$1 AND a.id=$2 AND a.status='ACTIVE' AND(a.emitted_runs>=a.run_budget OR(a.trigger_kind<>'EVENT' AND a.next_due_at IS NULL)) AND NOT EXISTS(SELECT 1 FROM automation_runs r WHERE r.tenant_id=a.tenant_id AND r.automation_id=a.id AND r.status IN('PENDING','CLAIMED','DISPATCHING','SUBMITTED','OUTCOME_UNKNOWN'))")
            .bind(a.tenant_id).bind(a.id).execute(&mut **tx).await?.rows_affected();
        if changed == 1 {
            self.policy_event(tx, a, "EXHAUSTED", Uuid::new_v4())
                .await?;
        }
        Ok(())
    }
    async fn run_event(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        a: &Automation,
        run: Uuid,
        status: &str,
    ) -> Result<(), ApiError> {
        ledger::event(
            tx,
            &Actor {
                authorization: None,
                tenant_id: a.tenant_id,
                principal_id: a.creator_principal_id,
                request_id: run,
            },
            a.project_id,
            run,
            "automations:run",
            status,
        )
        .await
    }
    async fn policy_event(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        a: &Automation,
        status: &str,
        request: Uuid,
    ) -> Result<(), ApiError> {
        ledger::event(
            tx,
            &Actor {
                authorization: None,
                tenant_id: a.tenant_id,
                principal_id: a.creator_principal_id,
                request_id: request,
            },
            a.project_id,
            a.id,
            "automations:change",
            status,
        )
        .await
    }
}
fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, ApiError> {
    serde_json::from_value(value.clone())
        .map_err(|_| stored_error("Stored management request is invalid"))
}

fn normalize_guard_error(mut error: ApiError) -> ApiError {
    // These two SQLSTATEs are this module's live lease/authority/version guards.
    // Keep the global SQL-to-HTTP mapping unchanged for every other caller.
    if matches!(error.sqlstate.as_deref(), Some("P4090" | "P4120")) {
        error.status = axum::http::StatusCode::CONFLICT;
        error.code = "AUTOMATION_FENCE_CHANGED";
        error.detail =
            "Automation authority or resource version changed; reconcile the original intent"
                .to_owned();
        error.retryable = true;
    }
    error
}

fn stored_error(detail: &'static str) -> ApiError {
    let mut error = ApiError::new(
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_ERROR",
        detail,
    );
    error.retryable = false;
    error
}

// Only static, reviewed identifiers. This query reads privilege metadata and the
// existing configuration; it neither claims work nor reads private queue tokens.
const REQUIRED_RUNTIME_PRIVILEGES: &str = r#"
SELECT current_user='sandbox_automation'
 AND EXISTS(SELECT 1 FROM public.platform_configuration WHERE singleton)
 AND has_schema_privilege(current_user,'public','USAGE')
 AND (SELECT bool_and(has_function_privilege(current_user,required,'EXECUTE'))
      FROM unnest(ARRAY['public.sandbox_current_tenant_id()','public.sandbox_resolve_identity(text,text)','public.sandbox_principal_enabled(uuid)','public.sandbox_instance_certification(uuid,uuid)','public.sandbox_never_authorized_stop_candidate(uuid,uuid)','public.sandbox_workspace_cold_backup_ready(uuid,uuid)','public.sandbox_claim_automation(text)','public.sandbox_check_automation_claim(uuid,uuid,text,bigint)','public.sandbox_finish_automation_claim(uuid,uuid,text,bigint)','public.sandbox_bind_automation_run_claim(uuid,uuid,text,bigint)','public.sandbox_automation_authorized(uuid,uuid)','public.sandbox_automation_required_actions(text,boolean)','public.sandbox_workspace_writers_closed(uuid,uuid)']::text[]) AS required)
 AND (SELECT bool_and(has_table_privilege(current_user,required.table_name,permission))
      FROM (VALUES
        ('public.tenants',ARRAY['SELECT']::text[]),
        ('public.projects',ARRAY['SELECT']::text[]),
        ('public.grants',ARRAY['SELECT']::text[]),
        ('public.platform_configuration',ARRAY['SELECT']::text[]),
        ('public.template_versions',ARRAY['SELECT']::text[]),
        ('public.security_policy_versions',ARRAY['SELECT']::text[]),
        ('public.quota_accounts',ARRAY['SELECT']::text[]),
        ('public.launch_permits',ARRAY['SELECT']::text[]),
        ('public.local_termination_proofs',ARRAY['SELECT']::text[]),
        ('public.termination_cleanup_receipts',ARRAY['SELECT']::text[]),
        ('public.backup_profiles',ARRAY['SELECT']::text[]),
        ('public.workspace_holds',ARRAY['SELECT','INSERT']::text[]),
        ('public.workspace_hold_releases',ARRAY['SELECT']::text[]),
        ('public.event_stream_positions',ARRAY['SELECT']::text[]),
        ('public.event_stream_heads',ARRAY['SELECT']::text[]),
        ('public.domain_events',ARRAY['SELECT','INSERT']::text[]),
        ('public.file_transfers',ARRAY['SELECT']::text[]),
        ('public.instances',ARRAY['SELECT','INSERT','UPDATE']::text[]),
        ('public.workspaces',ARRAY['SELECT','INSERT','UPDATE']::text[]),
        ('public.operations',ARRAY['SELECT','INSERT','UPDATE']::text[]),
        ('public.executions',ARRAY['SELECT','INSERT','UPDATE']::text[]),
        ('public.idempotency_keys',ARRAY['SELECT','INSERT','UPDATE']::text[]),
        ('public.quota_reservations',ARRAY['SELECT','INSERT','UPDATE']::text[]),
        ('public.external_resources',ARRAY['SELECT','INSERT','UPDATE']::text[]),
        ('public.backups',ARRAY['SELECT','INSERT']::text[]),
        ('public.backup_attempts',ARRAY['SELECT','INSERT']::text[]),
        ('public.backup_resource_intents',ARRAY['SELECT','INSERT']::text[]),
        ('public.audit_events',ARRAY['SELECT','INSERT']::text[]),
        ('public.automations',ARRAY['SELECT']::text[]),
        ('public.automation_runs',ARRAY['INSERT']::text[])
      ) AS required(table_name,permissions)
      CROSS JOIN LATERAL unnest(required.permissions) AS permission)
 AND (SELECT bool_and(has_column_privilege(current_user,required.table_name,column_name,permission))
      FROM (VALUES
        ('public._sqlx_migrations',ARRAY['version','success','checksum']::text[],ARRAY['SELECT']::text[]),
        ('public.quota_accounts',ARRAY['pending','allocated','version','updated_at']::text[],ARRAY['UPDATE']::text[]),
        ('public.automations',ARRAY['next_due_at','event_sequence','status','version','emitted_runs','last_emitted_at','updated_at']::text[],ARRAY['UPDATE']::text[]),
        ('public.automation_delegations',ARRAY['id','tenant_id','project_id','expires_at','revoked_at']::text[],ARRAY['SELECT']::text[]),
        ('public.automation_delegations',ARRAY['id']::text[],ARRAY['UPDATE']::text[]),
        ('public.automation_runs',ARRAY['id','tenant_id','project_id','automation_id','automation_version','version','delegation_id','creator_principal_id','instance_id','workspace_id','scheduled_for','source_event_id','source_event_sequence','skipped_through','operation_kind','original_request','operation_request','expected_resource_version','expected_generation','cluster_epoch','produced_resource_id','management_key','request_sha256','status','operation_id','failure_code','deadline','created_at','updated_at','completed_at']::text[],ARRAY['SELECT']::text[]),
        ('public.automation_runs',ARRAY['status','failure_code','completed_at','updated_at']::text[],ARRAY['UPDATE']::text[])
      ) AS required(table_name,columns,permissions)
      CROSS JOIN LATERAL unnest(required.columns) AS column_name
      CROSS JOIN LATERAL unnest(required.permissions) AS permission)
"#;
