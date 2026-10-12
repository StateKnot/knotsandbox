//! The real cold-backup reconciler. Leases fence ledger progress; admission and
//! the host journal independently fence delayed Kubernetes/CRI side effects.
use crate::{
    backup_job::BackupJobRuntime,
    backup_ledger::JobPlan,
    backup_object::BackupVaultVerifier,
    backup_runtime::BackupRuntime,
    db::Database,
    engine::{Claim, OperationEngine},
    error::ApiError,
    nodeguard::protocol::BackupStage,
    runtime::KubernetesRuntime,
    termination_client::{NodeguardClient, NodeguardCredentials, TerminationObservation},
    termination_ledger::RuntimeNode,
};
use chrono::Utc;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
#[derive(Clone)]
pub struct BackupController {
    pub engine: OperationEngine,
    storage: BackupRuntime,
    jobs: BackupJobRuntime,
    credentials: NodeguardCredentials,
    vault: Arc<BackupVaultVerifier>,
    concurrency: usize,
    vault_slot: Arc<tokio::sync::Semaphore>,
    mutation_slots: Arc<tokio::sync::Semaphore>,
}
fn blocked(code: &'static str) -> ApiError {
    ApiError::conflict(
        code,
        "Backup progress requires exact current resources and trusted isolated-task evidence",
    )
}
impl BackupController {
    pub fn new(
        database: Database,
        runtime: KubernetesRuntime,
        credentials: NodeguardCredentials,
        vault: Arc<BackupVaultVerifier>,
        worker_id: String,
        concurrency: usize,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            (1..=8).contains(&concurrency),
            "Backup concurrency must be 1..=8"
        );
        Ok(Self {
            engine: OperationEngine::new(database, worker_id)?,
            storage: BackupRuntime::new(runtime.clone()),
            jobs: BackupJobRuntime::new(runtime),
            credentials,
            vault,
            concurrency,
            vault_slot: Arc::new(tokio::sync::Semaphore::new(1)),
            mutation_slots: Arc::new(tokio::sync::Semaphore::new(concurrency)),
        })
    }
    pub async fn run(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        self.engine.database.verify_runtime_role().await?;
        let role: String = sqlx::query_scalar("SELECT current_user")
            .fetch_one(&self.engine.database.pool)
            .await?;
        anyhow::ensure!(
            role == "sandbox_backup",
            "Backup controller requires dedicated sandbox_backup database identity"
        );
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {biased;
                _=shutdown.cancelled()=>break,
                Some(done)=tasks.join_next(),if !tasks.is_empty()=>{if done.is_err(){tracing::error!("Backup stage task failed")}},
                _=tokio::time::sleep(Duration::from_millis(500)),if tasks.len()<self.concurrency+1=>{
                    match self.engine.claim_backup().await{
                        Ok(Some(claim))=>{let worker=self.clone();let stop=shutdown.clone();tasks.spawn(async move{worker.run_claim(claim,stop).await;});},
                        Ok(None)=>{},Err(e)=>{tracing::warn!(code=e.code,"Backup queue unavailable");tokio::select!{_=shutdown.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(2))=>{}}}
                    }
                }
            }
        }
        if tokio::time::timeout(Duration::from_secs(30), async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        Ok(())
    }
    async fn run_claim(&self, claim: Claim, shutdown: CancellationToken) {
        let result = {
            let heartbeat = async {
                loop {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    if !self.engine.heartbeat(&claim).await? {
                        return Err(blocked("WORKER_LEASE_LOST"));
                    }
                }
            };
            tokio::select! {r=self.reconcile(&claim)=>r,r=heartbeat=>r,_=shutdown.cancelled()=>Err(blocked("BACKUP_SHUTDOWN")),_=tokio::time::sleep(Duration::from_secs(3610))=>Err(blocked("BACKUP_STAGE_TIMEOUT"))}
        };
        if let Err(e) = result
            && e.code != "WORKER_LEASE_LOST"
        {
            tracing::warn!(operation_id=%claim.operation_id,code=e.code,"Backup stage deferred; holds retained");
            let _ = self.engine.wait(&claim, "BACKUP_BLOCKED", e.code, 30).await;
        }
    }
    pub async fn reconcile(&self, claim: &Claim) -> Result<(), ApiError> {
        let db = &self.engine.database;
        let record = db.backup_record(&self.engine, claim).await?;
        let mutation_slot = self
            .mutation_slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| blocked("BACKUP_SHUTDOWN"))?;
        if matches!(
            record.status.as_str(),
            "QUEUED" | "SNAPSHOT_PENDING" | "SNAPSHOT_READY" | "CLONE_PENDING"
        ) {
            let plan = match db.prepare_backup_storage(&self.engine, claim).await {
                Ok(plan) => plan,
                Err(error) => {
                    if error.code == "BACKUP_BLOCKED"
                        && db.cancel_quiescent_backup(&self.engine, claim).await?
                    {
                        return Ok(());
                    }
                    return Err(error);
                }
            };
            if matches!(plan.backup.status.as_str(), "QUEUED" | "SNAPSHOT_PENDING") {
                let observation = tokio::time::timeout(
                    Duration::from_secs(20),
                    self.storage.reconcile_snapshot(
                        &plan.source,
                        &plan.known_snapshot,
                        &plan.cloud.deployment,
                    ),
                )
                .await
                .map_err(|_| blocked("BACKUP_CSI_TIMEOUT"))?
                .map_err(|_| blocked("BACKUP_SNAPSHOT_IDENTITY"))?;
                db.record_backup_snapshot(&self.engine, claim, &observation)
                    .await?;
                return self
                    .engine
                    .wait(
                        claim,
                        "BACKUP_SNAPSHOT",
                        "Waiting for exact snapshot readiness",
                        2,
                    )
                    .await;
            }
            self.jobs
                .verify_clone_storage(&plan.block.storage_class, &plan.cloud)
                .await
                .map_err(|_| blocked("BACKUP_STORAGE_CLASS_DRIFT"))?;
            let snapshot = plan
                .snapshot
                .as_ref()
                .ok_or_else(|| blocked("BACKUP_SNAPSHOT_RECEIPT_MISSING"))?;
            let observation = tokio::time::timeout(
                Duration::from_secs(20),
                self.storage.reconcile_clone(
                    &plan.source,
                    snapshot,
                    &plan.block,
                    &plan.known_clone,
                ),
            )
            .await
            .map_err(|_| blocked("BACKUP_CSI_TIMEOUT"))?
            .map_err(|_| blocked("BACKUP_CLONE_IDENTITY"))?;
            db.record_backup_clone(&self.engine, claim, &observation)
                .await?;
            return self
                .engine
                .wait(
                    claim,
                    "BACKUP_CLONE",
                    "Waiting for isolated capture admission",
                    2,
                )
                .await;
        }
        let mut plan = match db.prepare_backup_job(&self.engine, claim).await {
            Ok(p) => p,
            Err(e) => {
                if e.code == "BACKUP_BLOCKED"
                    && db.cancel_quiescent_backup(&self.engine, claim).await?
                {
                    return Ok(());
                }
                if matches!(
                    record.status.as_str(),
                    "CAPTURE_PENDING" | "CAPTURE_RUNNING" | "SEAL_PENDING" | "SEAL_RUNNING"
                ) {
                    db.close_backup_attempt(&self.engine, claim, None).await?;
                }
                return Err(e);
            }
        };
        if plan.backup.status.ends_with("CLOSING") {
            return self.close(claim, &plan, mutation_slot).await;
        }
        if plan.deadline <= Utc::now() {
            db.close_backup_attempt(&self.engine, claim, None).await?;
            return self
                .engine
                .wait(
                    claim,
                    "BACKUP_CLOSING",
                    "Task deadline requires trusted VM termination",
                    1,
                )
                .await;
        }
        self.jobs
            .verify_network(&plan.cloud)
            .await
            .map_err(|_| blocked("BACKUP_NETWORK_DRIFT"))?;
        self.jobs
            .verify_profile_secrets(&plan.cloud)
            .await
            .map_err(|_| blocked("BACKUP_SECRET_DRIFT"))?;
        if plan.context.stage == BackupStage::Seal && plan.backup.status == "SEAL_PENDING" {
            let report = db.prepare_capture_config(&self.engine, claim).await?;
            let uid = self
                .jobs
                .ensure_capture_config(&report.object, report.known_uid)
                .await
                .map_err(|_| blocked("BACKUP_CAPTURE_HANDOFF_DRIFT"))?;
            db.record_capture_config(&self.engine, claim, uid).await?;
        }
        let (config, job) = self
            .jobs
            .ensure_job(&plan.context, plan.known_config, plan.known_job)
            .await
            .map_err(|_| blocked("BACKUP_JOB_DRIFT"))?;
        db.record_backup_job_objects(&self.engine, claim, plan.context.attempt_id, config, job)
            .await?;
        plan.known_config = Some(config);
        plan.known_job = Some(job);
        let observation = self
            .jobs
            .start_and_observe(&plan.context, job, plan.known_pod)
            .await
            .map_err(|_| blocked("BACKUP_POD_DRIFT"))?;
        let Some(pod) = observation.pod else {
            return self
                .engine
                .wait(
                    claim,
                    "BACKUP_POD_PENDING",
                    "Waiting for the one-shot Job Pod",
                    2,
                )
                .await;
        };
        db.record_backup_pod(&self.engine, claim, plan.context.attempt_id, job, &pod)
            .await?;
        plan.known_pod = Some(pod.uid);
        if let Some(exit) = &pod.exit {
            // Reports guide the next data step only. Even an exit status of zero
            // must pass host closure before handoff, hold/quota release or AVAILABLE.
            if db
                .close_backup_attempt(&self.engine, claim, Some(exit))
                .await
                .is_err()
            {
                db.close_backup_attempt(&self.engine, claim, None).await?;
            }
            return self
                .engine
                .wait(
                    claim,
                    "BACKUP_CLOSING",
                    "Guest result observed; waiting for trusted VM closure",
                    1,
                )
                .await;
        }
        if pod.node_name.is_none() {
            return self
                .engine
                .wait(
                    claim,
                    "BACKUP_SCHEDULING",
                    "Waiting for a certified Kata node",
                    2,
                )
                .await;
        }
        if plan.context.stage == BackupStage::Capture {
            let storage = db.prepare_backup_storage(&self.engine, claim).await?;
            let snapshot = storage
                .snapshot
                .as_ref()
                .ok_or_else(|| blocked("BACKUP_SNAPSHOT_RECEIPT_MISSING"))?;
            let observation = self
                .storage
                .reconcile_clone(
                    &storage.source,
                    snapshot,
                    &storage.block,
                    &storage.known_clone,
                )
                .await
                .map_err(|_| blocked("BACKUP_CLONE_IDENTITY"))?;
            db.record_backup_clone(&self.engine, claim, &observation)
                .await?;
            if observation.bound.is_none() {
                return self
                    .engine
                    .wait(
                        claim,
                        "BACKUP_VOLUME_BINDING",
                        "Waiting for the exact Block clone",
                        2,
                    )
                    .await;
            }
        }
        let volume = db
            .backup_bound_volume(claim.tenant_id, plan.context.attempt_id)
            .await?;
        let observed = self
            .jobs
            .observe_launch(&plan, &pod.name, volume.as_ref())
            .await
            .map_err(|_| blocked("BACKUP_LAUNCH_OBSERVATION"))?;
        let permit = db
            .prepare_backup_launch(&self.engine, claim, &observed)
            .await?;
        let client = self.client(&permit.node)?;
        let receipt = client
            .register(&permit.request)
            .await
            .map_err(|_| blocked("BACKUP_HOST_REGISTRATION_UNKNOWN"))?;
        db.record_backup_registration(&self.engine, claim, &receipt)
            .await?;
        self.engine
            .wait(
                claim,
                "BACKUP_RUNNING",
                "Isolated backup task is running",
                5,
            )
            .await
    }
    async fn close(
        &self,
        claim: &Claim,
        plan: &JobPlan,
        mutation_slot: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<(), ApiError> {
        let db = &self.engine.database;
        if plan.context.stage == BackupStage::Capture
            && db.finish_failed_capture(&self.engine, claim).await?
        {
            return Ok(());
        }
        if db
            .backup_completion_expired_or_failed(&self.engine, claim)
            .await?
            && db.cancel_quiescent_backup(&self.engine, claim).await?
        {
            return Ok(());
        }
        if plan.context.stage == BackupStage::Seal
            && let Ok(expected) = db.backup_vault_expectation(&self.engine, claim).await
        {
            // Both writers are closed; release the mutation slot while the
            // independently bounded read-only inventory scan runs.
            drop(mutation_slot);
            let Ok(_slot) = self.vault_slot.try_acquire() else {
                return self
                    .engine
                    .wait(
                        claim,
                        "BACKUP_VAULT_QUEUED",
                        "Waiting for bounded independent vault verification",
                        5,
                    )
                    .await;
            };
            let remaining = (plan.backup.deadline - Utc::now())
                .to_std()
                .map_err(|_| blocked("BACKUP_COMPLETION_EXPIRED"))?;
            let verified = tokio::time::timeout(
                remaining.min(Duration::from_secs(3600)),
                self.vault.verify(&expected),
            )
            .await
            .map_err(|_| blocked("BACKUP_VAULT_UNVERIFIED"))?
            .map_err(|_| blocked("BACKUP_VAULT_UNVERIFIED"))?;
            return db.complete_backup(&self.engine, claim, &verified).await;
        }
        let challenge = db.prepare_backup_close(&self.engine, claim).await?;
        self.jobs
            .request_close(plan, &challenge.permit.request.launch)
            .await
            .map_err(|_| blocked("BACKUP_POD_STOP_UNKNOWN"))?;
        let client = self.client(&challenge.permit.node)?;
        match client
            .close(&challenge.request)
            .await
            .map_err(|_| blocked("BACKUP_HOST_TERMINATION_UNKNOWN"))?
        {
            TerminationObservation::Pending(_) => {
                self.engine
                    .wait(
                        claim,
                        "BACKUP_WAITING_TERMINATION",
                        "Host closure or mount absence is unproven",
                        5,
                    )
                    .await
            }
            TerminationObservation::Verified(proof) => {
                let proof_id = db
                    .record_backup_termination(&self.engine, claim, &proof)
                    .await?;
                let cleanup = self
                    .jobs
                    .finish_cleanup(plan, &proof)
                    .await
                    .map_err(|_| blocked("BACKUP_CLEANUP_UNVERIFIED"))?;
                if let Some(cleanup) = cleanup {
                    db.record_backup_cleanup(&self.engine, claim, proof_id, &cleanup)
                        .await?;
                }
                self.engine
                    .wait(
                        claim,
                        "BACKUP_TRUSTED_CLEANUP",
                        "Reconciling Pod absence and exact volume detach",
                        2,
                    )
                    .await
            }
        }
    }
    fn client(&self, node: &RuntimeNode) -> Result<NodeguardClient, ApiError> {
        let address = SocketAddr::new(
            node.private_ip
                .parse()
                .map_err(|_| blocked("BACKUP_NODE_ADDRESS_INVALID"))?,
            node.guard_port,
        );
        NodeguardClient::new(node.node.clone(), address, &self.credentials)
            .map_err(|_| blocked("BACKUP_NODE_CHANNEL_INVALID"))
    }
}
