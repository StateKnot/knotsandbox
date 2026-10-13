//! Durable, bounded Kubernetes reconciliation. Remote calls never hold a database
//! transaction. Admission independently fences delayed creates against the ledger.
//! No Pod observation is accepted as proof of VM termination.

use std::{collections::BTreeMap, time::Duration};

use chrono::{DateTime, Utc};
use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Pod};
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};
use tokio::{sync::watch, task::JoinSet, time::Instant};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    db::{Actor, Database},
    engine::{Claim, OperationEngine},
    error::ApiError,
    runtime::{KubernetesRuntime, RuntimeError},
    runtime_manifest::{
        RuntimeManifestConfig, RuntimeManifestContext, build_manifests, container_name,
    },
    service_lifecycle::fatal_database_failure,
    worker_observation::{ObservedPhase, observe},
};

#[path = "worker_dispatch.rs"]
mod dispatch;

#[derive(Clone)]
pub struct Worker {
    pub engine: OperationEngine,
    runtime: KubernetesRuntime,
    manifests: RuntimeManifestConfig,
    certification_id: String,
    concurrency: usize,
}

#[derive(sqlx::FromRow)]
struct Snapshot {
    tenant_id: Uuid,
    project_id: Uuid,
    instance_id: Uuid,
    workspace_id: Uuid,
    generation: i64,
    launch_id: Uuid,
    cluster_epoch: Uuid,
    namespace: String,
    storage_class: String,
    image_ref: String,
    image_digest: String,
    template_approved: bool,
    policy_approved: bool,
    policy_rules: Value,
    cpu_millis: i64,
    memory_mib: i64,
    size_gib: i64,
    kind: String,
    restart_generation: Option<i64>,
    actor_principal_id: Uuid,
    request_id: Uuid,
    active_operation_id: Option<Uuid>,
    workspace_operation_id: Option<Uuid>,
    workspace_status: String,
    desired_state: String,
    stop_accepted_at: Option<DateTime<Utc>>,
    compute_lease_expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
    current_epoch: Uuid,
    safe_mode: bool,
    pod_uid: Option<Uuid>,
    #[sqlx(skip)]
    restore_snapshot: Option<String>,
}

impl Snapshot {
    fn compute(&self) -> bool {
        matches!(self.kind.as_str(), "CREATE" | "START")
            || (self.kind == "RESTART" && self.restart_generation == Some(self.generation))
    }
    fn context(&self) -> RuntimeManifestContext {
        RuntimeManifestContext {
            tenant_id: self.tenant_id,
            project_id: self.project_id,
            instance_id: self.instance_id,
            workspace_id: self.workspace_id,
            launch_id: self.launch_id,
            cluster_epoch: self.cluster_epoch,
            generation: self.generation,
            namespace: self.namespace.clone(),
            storage_class: self.storage_class.clone(),
            workspace_snapshot: self.restore_snapshot.clone(),
            image_ref: self.image_ref.clone(),
            image_digest: self.image_digest.clone(),
            // Revocation must never prevent stopping an already accepted workload.
            template_approved: self.template_approved || !self.compute(),
            security_policy_approved: self.policy_approved || !self.compute(),
            security_policy_rules: self.policy_rules.clone(),
            cpu_millis: self.cpu_millis,
            memory_mib: self.memory_mib,
            workspace_size_gib: self.size_gib,
        }
    }
}

impl Worker {
    pub fn new(
        database: Database,
        runtime: KubernetesRuntime,
        worker_id: String,
        certification_id: String,
        concurrency: usize,
        dns_namespace: String,
        dns_labels: BTreeMap<String, String>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            (1..=32).contains(&concurrency),
            "Worker concurrency must be 1..=32"
        );
        anyhow::ensure!(
            !certification_id.is_empty()
                && certification_id.len() <= 128
                && !certification_id.chars().any(char::is_control),
            "A deployment certification reference is required"
        );
        Ok(Self {
            engine: OperationEngine::new(database, worker_id)?,
            runtime,
            certification_id,
            concurrency,
            manifests: RuntimeManifestConfig {
                runtime_class_name: "kata-qemu".into(),
                dns_namespace,
                dns_labels,
                ephemeral_storage_mib: 1024,
                tmp_size_mib: 256,
            },
        })
    }

    /// Run until cancelled, then drain bounded in-flight stages. Work abandoned
    /// by a process crash is reclaimed after its database lease expires.
    pub async fn run(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        self.engine.database.verify_runtime_role().await?;
        let authorized: bool = sqlx::query_scalar("SELECT has_function_privilege(current_user,'public.sandbox_claim_operation(text)','EXECUTE') AND has_function_privilege(current_user,'public.sandbox_due_instances(integer)','EXECUTE') AND has_function_privilege(current_user,'public.sandbox_maintain_diagnoses(integer)','EXECUTE') AND has_table_privilege(current_user,'public.diagnoses','SELECT')")
            .fetch_one(&self.engine.database.pool).await?;
        anyhow::ensure!(
            authorized,
            "Worker database identity lacks dedicated claim/timer grants"
        );
        tracing::info!("worker queue grants verified; lifecycle timer supervised");
        let timers = self.clone();
        let timer_shutdown = shutdown.clone();
        let mut timer_task = tokio::spawn(async move { timers.run_timers(timer_shutdown).await });
        let mut timer_joined = false;
        let (wake, mut wakeups) = watch::channel(());
        let hint_pool = self.engine.database.pool.clone();
        let hint_shutdown = shutdown.clone();
        let mut hint_task = tokio::spawn(dispatch::listen(hint_pool, wake, hint_shutdown));
        let mut hint_joined = false;
        let mut recovery = tokio::time::interval(Duration::from_millis(500));
        recovery.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut scan_requested = true; // Recover work committed before LISTEN.
        let mut claim_not_before = Instant::now();
        let mut jobs = JoinSet::new();
        let mut result = loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => break Ok(()),
                result = &mut timer_task => {
                    timer_joined = true;
                    break Err(match result {
                        Ok(Err(error)) => anyhow::anyhow!("worker timer stopped after fatal error ({})", error.code),
                        _ => anyhow::anyhow!("worker timer task terminated unexpectedly"),
                    });
                },
                _ = &mut hint_task => {
                    hint_joined = true;
                    break Err(anyhow::anyhow!("worker dispatch hint task terminated unexpectedly"));
                },
                Some(result) = jobs.join_next(), if !jobs.is_empty() => {
                    scan_requested = true; // Fill a released slot without resetting the poll clock.
                    match result {
                        Ok(Err(error)) if fatal_database_failure(&self.engine.database.pool, &error) => {
                            break Err(anyhow::anyhow!("worker stage stopped after fatal error ({})", error.code));
                        },
                        Ok(Err(error)) => tracing::warn!(code=error.code, "worker retry persistence deferred; durable operation retained"),
                        Ok(Ok(())) => {},
                        Err(_) => break Err(anyhow::anyhow!("worker stage task terminated unexpectedly")),
                    }
                },
                _ = tokio::time::sleep_until(claim_not_before), if scan_requested && jobs.len() < self.concurrency => {
                    let claimed = tokio::select! {
                        biased;
                        _=shutdown.cancelled()=>break Ok(()),
                        result=self.engine.claim()=>result,
                    };
                    match claimed {
                        Ok(Some(claim)) => {
                            // One claim per select turn: fill up to concurrency
                            // while supervision and cancellation retain priority.
                            let worker = self.clone();
                            jobs.spawn(async move { worker.run_claim(claim).await });
                        },
                        Ok(None) => {
                            scan_requested = false;
                            // Hints are untrusted: bound repeated empty scans.
                            // New hints never postpone this fixed deadline.
                            claim_not_before = Instant::now() + Duration::from_millis(50);
                        },
                        Err(error) if fatal_database_failure(&self.engine.database.pool, &error) => {
                            break Err(anyhow::anyhow!("worker claim stopped after fatal error ({})", error.code));
                        },
                        Err(error) => {
                            tracing::warn!(code=error.code, "operation claim unavailable; durable intent retained");
                            scan_requested = false;
                            // Hints, capacity and poll ticks cannot bypass retry
                            // backoff, nor does backoff suspend job supervision.
                            claim_not_before = Instant::now() + Duration::from_secs(2);
                        },
                    }
                },
                _ = recovery.tick() => scan_requested = true,
                changed = wakeups.changed() => {
                    if changed.is_err() {
                        break Err(anyhow::anyhow!("worker dispatch hint channel closed unexpectedly"));
                    }
                    scan_requested = true;
                },
            }
        };
        shutdown.cancel();
        // The hint task owns no work. Release listener ownership before draining
        // stages; only the outer awaited pool close proves physical DB shutdown.
        if !hint_joined {
            match tokio::time::timeout(Duration::from_secs(5), &mut hint_task).await {
                Ok(Err(_)) if result.is_ok() => {
                    result = Err(anyhow::anyhow!("worker dispatch hint task failed"));
                }
                Err(_) => {
                    hint_task.abort();
                    let _ = hint_task.await;
                    if result.is_ok() {
                        result = Err(anyhow::anyhow!(
                            "worker dispatch hint shutdown exceeded grace period"
                        ));
                    }
                }
                _ => {}
            }
        }
        // Each stage already has a hard wall-clock bound; shutdown never waits
        // for VM termination, a stuck API stream or the entire TTL scan batch.
        if tokio::time::timeout(Duration::from_secs(30), async {
            while let Some(stage) = jobs.join_next().await {
                if result.is_ok() {
                    match stage {
                        Ok(Err(error))
                            if fatal_database_failure(&self.engine.database.pool, &error) =>
                        {
                            result = Err(anyhow::anyhow!(
                                "worker stage stopped after fatal error ({})",
                                error.code
                            ));
                        }
                        Err(_) => {
                            result =
                                Err(anyhow::anyhow!("worker stage task terminated unexpectedly"))
                        }
                        _ => {}
                    }
                }
            }
        })
        .await
        .is_err()
        {
            jobs.abort_all();
            while jobs.join_next().await.is_some() {}
        }
        // A completed JoinHandle must not be polled twice. It was consumed by
        // the supervision branch; unfinished timers still get awaited shutdown.
        if !timer_joined {
            match tokio::time::timeout(Duration::from_secs(5), &mut timer_task).await {
                Ok(Ok(Err(error))) if result.is_ok() => {
                    result = Err(anyhow::anyhow!(
                        "worker timer stopped after fatal error ({})",
                        error.code
                    ));
                }
                Ok(Err(_)) if result.is_ok() => {
                    result = Err(anyhow::anyhow!("worker timer task terminated unexpectedly"));
                }
                Err(_) => {
                    timer_task.abort();
                    let _ = timer_task.await;
                    tracing::warn!("timer shutdown exceeded grace period");
                }
                _ => {}
            }
        }
        result
    }

    async fn run_timers(&self, shutdown: CancellationToken) -> Result<(), ApiError> {
        loop {
            tokio::select! { _=shutdown.cancelled()=>return Ok(()), _=tokio::time::sleep(Duration::from_secs(5))=>{} }
            let scan = async {
                if let Err(error) = self.engine.database.maintain_diagnoses().await {
                    if fatal_database_failure(&self.engine.database.pool, &error) {
                        return Err(error);
                    }
                    tracing::warn!(code = error.code, "diagnosis maintenance deferred");
                }
                for (tenant, instance) in self.engine.database.due_instances().await? {
                    if shutdown.is_cancelled() {
                        break;
                    }
                    if let Err(error) = self
                        .engine
                        .database
                        .try_accept_due_stop(tenant, instance)
                        .await
                    {
                        if fatal_database_failure(&self.engine.database.pool, &error) {
                            return Err(error);
                        }
                        tracing::warn!(code = error.code, "compute timer reconciliation deferred");
                    }
                }
                Ok::<(), ApiError>(())
            };
            tokio::select! {
                _=shutdown.cancelled()=>return Ok(()),
                result=scan=> {
                    if let Err(error)=result {
                        if fatal_database_failure(&self.engine.database.pool, &error) {
                            return Err(error);
                        }
                        tracing::warn!(code=error.code,"compute timer scan unavailable; durable timers retained");
                    }
                }
            }
        }
    }

    async fn run_claim(&self, claim: Claim) -> Result<(), ApiError> {
        // Drop the in-flight stage (and any transaction it owns) before persisting
        // its retry. Otherwise timeout handling could wait on its own row lock.
        let result = {
            let keep_alive = async {
                loop {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    if !self.engine.heartbeat(&claim).await? {
                        return Err(blocked("WORKER_LEASE_LOST"));
                    }
                }
            };
            tokio::select! {
                result = self.reconcile(&claim) => result,
                _ = tokio::time::sleep(Duration::from_secs(25)) => Err(blocked("RUNTIME_REQUEST_TIMEOUT")),
                result = keep_alive => result,
            }
        };
        if let Err(error) = result {
            if fatal_database_failure(&self.engine.database.pool, &error) {
                return Err(error);
            }
            self.defer_error(&claim, error).await?;
        }
        Ok(())
    }

    async fn defer_error(&self, claim: &Claim, error: ApiError) -> Result<(), ApiError> {
        if error.code == "WORKER_LEASE_LOST" {
            return Ok(());
        }
        tracing::warn!(operation_id=%claim.operation_id,code=error.code,"worker reconciliation deferred");
        let attempts: Result<i32, ApiError> = async {
            let mut tx = self.engine.database.begin(claim.tenant_id).await?;
            let n =
                sqlx::query_scalar("SELECT attempts FROM operations WHERE tenant_id=$1 AND id=$2")
                    .bind(claim.tenant_id)
                    .bind(claim.operation_id)
                    .fetch_one(&mut *tx)
                    .await?;
            tx.commit().await?;
            Ok(n)
        }
        .await;
        let retry = 2_i64.pow(attempts?.clamp(1, 8) as u32).min(300);
        self.engine
            .wait(claim, "RECONCILE_BLOCKED", error.code, retry)
            .await
    }

    /// One durable stage, exposed to integration tests and recovery tooling.
    /// Callers must hold the lease; this function checks it before and after I/O.
    pub async fn reconcile(&self, claim: &Claim) -> Result<(), ApiError> {
        observe(
            Some(claim),
            ObservedPhase::ReconcileAttempt,
            self.reconcile_stage(claim),
        )
        .await
    }

    async fn reconcile_stage(&self, claim: &Claim) -> Result<(), ApiError> {
        // Execution dispatch has its own durable at-most-one-attempt gate. The
        // generic worker must never send or replay a guest command.
        let mut tx = self.engine.database.begin(claim.tenant_id).await?;
        self.engine.assert_claim(&mut tx, claim).await?;
        let kind: String =
            sqlx::query_scalar("SELECT kind FROM operations WHERE tenant_id=$1 AND id=$2")
                .bind(claim.tenant_id)
                .bind(claim.operation_id)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        if kind == "DIAGNOSE" {
            return self
                .engine
                .database
                .reconcile_diagnosis(&self.engine, claim)
                .await;
        }
        if kind == "EXECUTE" {
            return self
                .engine
                .wait(
                    claim,
                    "WAITING_GATEWAY",
                    "EXECUTION_DISPATCHER_REQUIRED",
                    30,
                )
                .await;
        }
        let (tx, snapshot) = self.lock_snapshot(claim).await?;
        tx.commit().await?;
        let manifests = build_manifests(&snapshot.context(), &self.manifests)
            .map_err(|e| runtime_error(e.into()))?;
        if !snapshot.compute() {
            return self.stop_stage(claim, &snapshot, &manifests.pod).await;
        }
        observe(Some(claim), ObservedPhase::RuntimeClassVerify, async {
            self.runtime
                .verify_runtime_class()
                .await
                .map_err(runtime_error)
        })
        .await?;
        observe(Some(claim), ObservedPhase::NamespaceVerify, async {
            self.runtime
                .verify_namespace(&snapshot.context(), &self.certification_id)
                .await
                .map_err(runtime_error)
        })
        .await?;
        let resources = self.resources(claim, &snapshot).await?;
        let known_policy = resources.get("CILIUM_POLICY").map(String::as_str);
        let policy = observe(Some(claim), ObservedPhase::NetworkPolicyEnsure, async {
            self.runtime
                .ensure_network_policy(&manifests.network_policy, known_policy)
                .await
                .map_err(runtime_error)
        })
        .await?;
        if known_policy.is_none() {
            self.record_resource(claim, &snapshot, "CILIUM_POLICY", uid(&policy.metadata)?)
                .await?;
            return self
                .engine
                .wait(claim, "POLICY_RECORDED", "POLICY_OBJECT_CREATED", 1)
                .await;
        }
        self.check_current(claim, &snapshot).await?;
        let known_pvc = resources.get("PVC").map(String::as_str);
        let pvc = observe(Some(claim), ObservedPhase::WorkspaceEnsure, async {
            self.runtime
                .ensure_workspace(&manifests.pvc, known_pvc)
                .await
                .map_err(runtime_error)
        })
        .await?;
        if known_pvc.is_none() {
            self.record_resource(claim, &snapshot, "PVC", uid(&pvc.metadata)?)
                .await?;
            return self
                .engine
                .wait(claim, "VOLUME_RECORDED", "PVC_OBJECT_CREATED", 1)
                .await;
        }
        self.check_current(claim, &snapshot).await?;
        let known_pod = resources.get("POD").map(String::as_str);
        if snapshot.pod_uid.map(|v| v.to_string()).as_deref() != known_pod {
            return Err(blocked("POD_LEDGER_MISMATCH"));
        }
        let pod = observe(Some(claim), ObservedPhase::PodEnsure, async {
            self.runtime
                .ensure_pod(&manifests, known_pod)
                .await
                .map_err(runtime_error)
        })
        .await?;
        if known_pod.is_none() {
            self.record_resource(claim, &snapshot, "POD", uid(&pod.metadata)?)
                .await?;
            return self
                .engine
                .wait(claim, "POD_RECORDED", "POD_OBJECT_CREATED", 1)
                .await;
        }
        self.check_current(claim, &snapshot).await?;
        if !ready(&pod, &pvc, snapshot.launch_id) {
            return self
                .engine
                .wait(claim, "WAITING_READY", "CURRENT_LAUNCH_NOT_READY", 5)
                .await;
        }
        observe(
            Some(claim),
            ObservedPhase::TrustedReadyCommit,
            self.mark_ready(claim, &snapshot, uid(&pod.metadata)?),
        )
        .await
    }

    async fn lock_snapshot<'a>(
        &'a self,
        claim: &Claim,
    ) -> Result<(Transaction<'a, Postgres>, Snapshot), ApiError> {
        let mut tx = self.engine.database.begin(claim.tenant_id).await?;
        let (instance, workspace): (Uuid, Uuid) = sqlx::query_as(
            "SELECT instance_id,workspace_id FROM operations WHERE tenant_id=$1 AND id=$2",
        )
        .bind(claim.tenant_id)
        .bind(claim.operation_id)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query("SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
            .bind(claim.tenant_id)
            .bind(workspace)
            .fetch_one(&mut *tx)
            .await?;
        sqlx::query("SELECT id FROM instances WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
            .bind(claim.tenant_id)
            .bind(instance)
            .fetch_one(&mut *tx)
            .await?;
        self.engine.assert_claim(&mut tx, claim).await?;
        let mut s:Snapshot=sqlx::query_as("SELECT i.tenant_id,i.project_id,i.id AS instance_id,i.workspace_id,i.runtime_generation AS generation,i.launch_id,i.cluster_epoch,i.namespace,w.storage_class,t.image_ref,t.image_digest,t.status='APPROVED' AS template_approved,p.status='APPROVED' AS policy_approved,p.rules AS policy_rules,i.cpu_millis,i.memory_mib,w.size_gib,o.kind,o.restart_generation,o.actor_principal_id,o.request_id,i.active_operation_id,w.active_operation_id AS workspace_operation_id,w.status AS workspace_status,i.desired_state,i.stop_accepted_at,i.compute_lease_expires_at,clock_timestamp() AS now,c.cluster_epoch AS current_epoch,c.safe_mode,i.pod_uid FROM instances i JOIN workspaces w ON w.id=i.workspace_id AND w.tenant_id=i.tenant_id JOIN operations o ON o.id=$2 AND o.tenant_id=i.tenant_id JOIN template_versions t ON t.id=i.template_version_id AND t.tenant_id=i.tenant_id JOIN security_policy_versions p ON p.id=i.security_policy_version_id AND p.tenant_id=i.tenant_id CROSS JOIN platform_configuration c WHERE i.tenant_id=$1 AND i.id=$3 AND c.singleton")
            .bind(claim.tenant_id).bind(claim.operation_id).bind(instance).fetch_one(&mut *tx).await?;
        let mut restore_context = s.context();
        crate::workspace_restore::apply(&mut tx, &mut restore_context).await?;
        s.restore_snapshot = restore_context.workspace_snapshot;
        if s.active_operation_id != Some(claim.operation_id)
            || s.workspace_operation_id
                .is_some_and(|id| id != claim.operation_id)
        {
            return Err(blocked("ACTIVE_OPERATION_MISMATCH"));
        }
        if s.cluster_epoch != s.current_epoch {
            return Err(blocked("CLUSTER_EPOCH_MISMATCH"));
        }
        if s.compute() {
            if s.safe_mode {
                return Err(blocked("SAFE_MODE"));
            }
            if s.desired_state != "RUNNING" || s.stop_accepted_at.is_some() {
                return Err(blocked("COMPUTE_NO_LONGER_DESIRED"));
            }
            if s.now >= s.compute_lease_expires_at {
                return Err(blocked("COMPUTE_LEASE_EXPIRED"));
            }
            if !matches!(
                s.workspace_status.as_str(),
                "PENDING" | "AVAILABLE" | "IN_USE"
            ) {
                return Err(blocked("WORKSPACE_UNAVAILABLE"));
            }
            if !s.template_approved || !s.policy_approved {
                return Err(blocked("APPROVAL_REVOKED"));
            }
            let actor = Actor {
                tenant_id: s.tenant_id,
                principal_id: s.actor_principal_id,
                request_id: s.request_id,
                authorization: None,
            };
            Database::authorize(
                &mut tx,
                &actor,
                s.project_id,
                match s.kind.as_str() {
                    "CREATE" => "instances:create",
                    "RESTART" => "instances:restart",
                    _ => "instances:start",
                },
            )
            .await?;
            if s.kind == "RESTART" {
                Database::authorize(&mut tx, &actor, s.project_id, "instances:hard_stop").await?;
            }
        } else if !matches!(s.kind.as_str(), "STOP" | "DELETE" | "RESTART") {
            return Err(blocked("UNSUPPORTED_OPERATION"));
        }
        if s.workspace_operation_id.is_none() {
            sqlx::query("UPDATE workspaces SET active_operation_id=$3,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND active_operation_id IS NULL")
                .bind(s.tenant_id).bind(s.workspace_id).bind(claim.operation_id).execute(&mut *tx).await?;
        }
        // Safety cleanup retains the authority of an already accepted stop; a
        // caller revocation or safe mode cannot strand an untrusted VM forever.
        Ok((tx, s))
    }

    async fn check_current(&self, claim: &Claim, previous: &Snapshot) -> Result<(), ApiError> {
        let (tx, current) = self.lock_snapshot(claim).await?;
        same_launch(previous, &current)?;
        tx.commit().await?;
        Ok(())
    }

    async fn resources(
        &self,
        claim: &Claim,
        s: &Snapshot,
    ) -> Result<BTreeMap<String, String>, ApiError> {
        let mut tx = self.engine.database.begin(claim.tenant_id).await?;
        self.engine.assert_claim(&mut tx, claim).await?;
        let rows:Vec<(String,String,i64,Uuid,Option<Uuid>,String)>=sqlx::query_as("SELECT kind,provider_id,generation,owner_id,workspace_id,status FROM external_resources WHERE tenant_id=$1 AND instance_id=$2 AND provider='kubernetes' AND ((kind='POD' AND generation=$3) OR kind IN ('PVC','CILIUM_POLICY'))")
            .bind(claim.tenant_id).bind(s.instance_id).bind(s.generation).fetch_all(&mut *tx).await?;
        let mut result = BTreeMap::new();
        for (kind, uid, generation, owner, workspace, status) in rows {
            if status == "DELETED"
                || workspace != Some(s.workspace_id)
                || generation != if kind == "POD" { s.generation } else { 1 }
                || owner
                    != if kind == "PVC" {
                        s.workspace_id
                    } else {
                        s.instance_id
                    }
                || result.insert(kind, uid).is_some()
            {
                return Err(blocked("RESOURCE_LEDGER_MISMATCH"));
            }
        }
        tx.commit().await?;
        Ok(result)
    }

    async fn record_resource(
        &self,
        claim: &Claim,
        previous: &Snapshot,
        kind: &str,
        uid: &str,
    ) -> Result<(), ApiError> {
        let (mut tx, s) = self.lock_snapshot(claim).await?;
        same_launch(previous, &s)?;
        let generation = if kind == "POD" { s.generation } else { 1 };
        let owner = if kind == "PVC" {
            s.workspace_id
        } else {
            s.instance_id
        };
        // Fixed names let a new lease recover a create that completed before the
        // old worker could record its UID. The admission gate binds that object.
        sqlx::query("INSERT INTO external_resources(tenant_id,project_id,operation_id,instance_id,workspace_id,provider,kind,provider_id,generation,owner_id,status,observed_at) VALUES($1,$2,$3,$4,$5,'kubernetes',$6,$7,$8,$9,'ACTIVE',clock_timestamp())")
            .bind(s.tenant_id).bind(s.project_id).bind(claim.operation_id).bind(s.instance_id).bind(s.workspace_id).bind(kind).bind(uid).bind(generation).bind(owner).execute(&mut *tx).await?;
        if kind == "POD" {
            let pod_uid = Uuid::parse_str(uid).map_err(|_| blocked("INVALID_POD_UID"))?;
            sqlx::query("UPDATE instances SET pod_uid=$3,observed_state='STARTING',observed_at=clock_timestamp(),ready_generation=NULL,ready_launch_id=NULL,ready_pod_uid=NULL,ready_cluster_epoch=NULL,ready_observed_at=NULL WHERE tenant_id=$1 AND id=$2")
                .bind(s.tenant_id).bind(s.instance_id).bind(pod_uid).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn mark_ready(
        &self,
        claim: &Claim,
        previous: &Snapshot,
        uid: &str,
    ) -> Result<(), ApiError> {
        let pod_uid = Uuid::parse_str(uid).map_err(|_| blocked("INVALID_POD_UID"))?;
        let (mut tx, s) = self.lock_snapshot(claim).await?;
        same_launch(previous, &s)?;
        if s.pod_uid != Some(pod_uid) {
            return Err(blocked("POD_LEDGER_MISMATCH"));
        }
        let registered: bool =
            sqlx::query_scalar("SELECT sandbox_launch_registered($1,$2,$3,$4,$5,$6)")
                .bind(s.tenant_id)
                .bind(s.instance_id)
                .bind(s.generation)
                .bind(s.launch_id)
                .bind(pod_uid)
                .bind(s.cluster_epoch)
                .fetch_one(&mut *tx)
                .await?;
        if !registered {
            return Err(blocked("TRUSTED_LAUNCH_REGISTRATION_REQUIRED"));
        }
        // Stable lock ordering agrees with API quota reservations. Allocating is
        // only accounting movement; no capacity is released during reconciliation.
        let reservations:Vec<(Uuid,Uuid,i64)>=sqlx::query_as("SELECT r.id,r.quota_account_id,r.amount FROM quota_reservations r WHERE r.tenant_id=$1 AND r.resource_id IN ($2,$3) AND r.status='PENDING' ORDER BY r.quota_account_id,r.id")
            .bind(s.tenant_id).bind(s.instance_id).bind(s.workspace_id).fetch_all(&mut *tx).await?;
        for (_, account, _) in &reservations {
            sqlx::query("SELECT id FROM quota_accounts WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
                .bind(s.tenant_id)
                .bind(account)
                .fetch_one(&mut *tx)
                .await?;
        }
        for (reservation, account, amount) in reservations {
            sqlx::query("UPDATE quota_accounts SET pending=pending-$3,allocated=allocated+$3,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(s.tenant_id).bind(account).bind(amount).execute(&mut *tx).await?;
            sqlx::query("UPDATE quota_reservations SET status='ALLOCATED',updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND status='PENDING'").bind(s.tenant_id).bind(reservation).execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE instances SET observed_state='RUNNING',observed_at=clock_timestamp(),active_operation_id=NULL,idle_since=CASE WHEN slot_held THEN NULL ELSE clock_timestamp() END,ready_generation=runtime_generation,ready_launch_id=launch_id,ready_pod_uid=pod_uid,ready_cluster_epoch=cluster_epoch,ready_observed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
            .bind(s.tenant_id).bind(s.instance_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE workspaces SET status='IN_USE',active_operation_id=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(s.tenant_id).bind(s.workspace_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE operations SET status='SUCCEEDED',stage='COMPLETED',wait_reason=NULL,error=NULL,lease_owner=NULL,lease_until=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
            .bind(s.tenant_id).bind(claim.operation_id).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details) VALUES($1,$2,$3,$4,$5,$6,'runtime:ready','SUCCEEDED',$7)")
            .bind(s.tenant_id).bind(s.project_id).bind(s.actor_principal_id).bind(s.request_id).bind(claim.operation_id).bind(s.instance_id).bind(json!({"generation":s.generation,"launch_id":s.launch_id,"pod_uid":pod_uid,"cluster_epoch":s.cluster_epoch})).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload) VALUES($1,$2,$3,$4,'instance.ready',$5,$6,$7)")
            .bind(s.tenant_id).bind(s.project_id).bind(s.instance_id).bind(s.generation).bind(claim.operation_id).bind(s.request_id).bind(json!({"pod_uid":pod_uid,"launch_id":s.launch_id,"cluster_epoch":s.cluster_epoch})).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn stop_stage(&self, claim: &Claim, s: &Snapshot, pod: &Pod) -> Result<(), ApiError> {
        let resources = self.resources(claim, s).await?;
        let known = resources.get("POD").cloned();
        if s.pod_uid.map(|v| v.to_string()) != known {
            return Err(blocked("POD_LEDGER_MISMATCH"));
        }
        let known = match known {
            Some(uid) => Some(uid),
            None => match self
                .runtime
                .find_stop_target(pod)
                .await
                .map_err(runtime_error)?
            {
                Some(found) => {
                    let uid = uid(&found.metadata)?.to_owned();
                    self.record_resource(claim, s, "POD", &uid).await?;
                    Some(uid)
                }
                None => None,
            },
        };
        let present = if let Some(ref known) = known {
            self.check_current(claim, s).await?;
            self.runtime
                .request_stop(pod, known)
                .await
                .map_err(runtime_error)?
                .is_some()
        } else {
            false
        };
        let (mut tx, current) = self.lock_snapshot(claim).await?;
        same_launch(s, &current)?;
        sqlx::query("UPDATE instances SET observed_state=CASE WHEN desired_state='DELETED' THEN 'DELETING' ELSE 'STOPPING' END,observed_at=clock_timestamp(),ready_generation=NULL,ready_launch_id=NULL,ready_pod_uid=NULL,ready_cluster_epoch=NULL,ready_observed_at=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
            .bind(s.tenant_id).bind(s.instance_id).execute(&mut *tx).await?;
        if present {
            sqlx::query("UPDATE external_resources SET status='DELETING',delete_requested_at=COALESCE(delete_requested_at,clock_timestamp()),observed_at=clock_timestamp() WHERE tenant_id=$1 AND instance_id=$2 AND provider='kubernetes' AND kind='POD' AND generation=$3 AND status<>'DELETED'").bind(s.tenant_id).bind(s.instance_id).bind(s.generation).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        self.engine
            .wait(
                claim,
                "WAITING_TERMINATION",
                if present {
                    "TRUSTED_VM_TERMINATION_PROOF_REQUIRED"
                } else {
                    "POD_ABSENCE_IS_NOT_TERMINATION_PROOF"
                },
                30,
            )
            .await
    }
}

fn same_launch(before: &Snapshot, after: &Snapshot) -> Result<(), ApiError> {
    if before.restore_snapshot != after.restore_snapshot {
        return Err(blocked("RESTORE_PROVENANCE_CHANGED"));
    }
    if (
        before.instance_id,
        before.workspace_id,
        before.generation,
        before.launch_id,
        before.cluster_epoch,
    ) != (
        after.instance_id,
        after.workspace_id,
        after.generation,
        after.launch_id,
        after.cluster_epoch,
    ) {
        return Err(blocked("RUNTIME_IDENTITY_CHANGED"));
    }
    Ok(())
}
fn blocked(code: &'static str) -> ApiError {
    ApiError::conflict(
        code,
        "Reconciliation requires a fresh authorized and consistent runtime identity",
    )
}
fn runtime_error(error: RuntimeError) -> ApiError {
    let code = match error {
        RuntimeError::Kubernetes(_) => "KUBERNETES_UNAVAILABLE",
        RuntimeError::InvalidRuntimeClass => "INVALID_RUNTIME_CLASS",
        RuntimeError::UncertifiedNamespace => "DEPLOYMENT_CERTIFICATION_REQUIRED",
        RuntimeError::Manifest(_) => "RUNTIME_RESOURCE_DRIFT",
        RuntimeError::MissingIdentity => "RUNTIME_IDENTITY_MISSING",
        RuntimeError::InsecureConfiguration => "INSECURE_RUNTIME_CONFIGURATION",
    };
    blocked(code)
}
fn uid(
    meta: &k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta,
) -> Result<&str, ApiError> {
    meta.uid
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| blocked("RUNTIME_IDENTITY_MISSING"))
}
fn ready(pod: &Pod, pvc: &PersistentVolumeClaim, launch: Uuid) -> bool {
    pod.metadata.deletion_timestamp.is_none()
        && pvc.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Bound")
        && pod.status.as_ref().is_some_and(|s| {
            s.phase.as_deref() == Some("Running")
                && s.conditions
                    .as_ref()
                    .is_some_and(|c| c.iter().any(|c| c.type_ == "Ready" && c.status == "True"))
                && s.container_statuses.as_ref().is_some_and(|c| {
                    c.len() == 1
                        && c[0].name == container_name(launch)
                        && c[0].ready
                        && c[0].state.as_ref().is_some_and(|s| s.running.is_some())
                })
        })
}
