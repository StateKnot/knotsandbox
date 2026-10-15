//! Trusted lifecycle controller. Start registration and stop reconciliation are
//! independent, bounded loops; neither holds a database transaction over I/O.
use crate::{
    db::Database,
    engine::{Claim, OperationEngine},
    error::ApiError,
    nodeguard::protocol::ObservationState,
    runtime::KubernetesRuntime,
    runtime_manifest::RuntimeManifestConfig,
    termination_client::{NodeguardClient, NodeguardCredentials, TerminationObservation},
    termination_ledger::{RuntimeNode, TerminationCandidate},
    termination_runtime::TerminationRuntime,
};
use std::{net::SocketAddr, time::Duration};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub struct TerminationControllerConfig {
    pub concurrency: usize,
    pub certification_id: String,
    pub manifests: RuntimeManifestConfig,
}
#[derive(Clone)]
pub struct TerminationController {
    pub engine: OperationEngine,
    runtime: TerminationRuntime,
    credentials: NodeguardCredentials,
    concurrency: usize,
    never_gc: crate::never_authorized_gc::NeverAuthorizedGc,
}
impl TerminationController {
    pub fn new(
        database: Database,
        runtime: KubernetesRuntime,
        credentials: NodeguardCredentials,
        worker_id: String,
        config: TerminationControllerConfig,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            (1..=16).contains(&config.concurrency),
            "Termination concurrency must be 1..16"
        );
        anyhow::ensure!(
            !config.certification_id.is_empty()
                && config.certification_id.len() <= 128
                && !config.certification_id.chars().any(char::is_control),
            "Deployment certification reference is required"
        );
        Ok(Self {
            engine: OperationEngine::new(database.clone(), worker_id)?,
            never_gc: crate::never_authorized_gc::NeverAuthorizedGc {
                database: database.clone(),
                client: runtime.client_clone(),
                manifests: config.manifests.clone(),
            },
            runtime: TerminationRuntime::new(runtime, config.manifests, config.certification_id),
            credentials,
            concurrency: config.concurrency,
        })
    }

    pub async fn run(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        self.engine.database.verify_runtime_role().await?;
        let authorized:bool=sqlx::query_scalar("SELECT current_user='sandbox_termination' AND has_function_privilege(current_user,'public.sandbox_claim_termination(text)','EXECUTE') AND has_function_privilege(current_user,'public.sandbox_launch_registration_candidates(integer)','EXECUTE') AND has_function_privilege(current_user,'public.sandbox_close_never_authorized(uuid,uuid,text,bigint)','EXECUTE') AND has_table_privilege(current_user,'public.never_authorized_pod_observations','INSERT')")
            .fetch_one(&self.engine.database.pool).await?;
        anyhow::ensure!(
            authorized,
            "Termination controller requires its dedicated database identity"
        );
        let registration = self.clone();
        let signal = shutdown.clone();
        let mut registration_task =
            tokio::spawn(async move { registration.register_launches(signal).await });
        let collector = self.never_gc.clone();
        let signal = shutdown.clone();
        let mut gc_task = tokio::spawn(async move {
            let mut continuation = None;
            loop {
                tokio::select! { _=signal.cancelled()=>break,result=collector.page(continuation.as_deref())=> {
                    match result { Ok(next)=>continuation=next,Err(_)=>{continuation=None;tracing::warn!(reason="NEVER_AUTHORIZED_INVENTORY_UNAVAILABLE","closed launch inventory requires retry");} }
                }}
                let delay = if continuation.is_some() {
                    Duration::from_secs(1)
                } else {
                    Duration::from_secs(30)
                };
                tokio::select! {_=signal.cancelled()=>break,_=tokio::time::sleep(delay)=>{}}
            }
        });
        let mut jobs = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _=shutdown.cancelled()=>break,
                Some(result)=jobs.join_next(),if !jobs.is_empty()=>{if result.is_err(){tracing::error!("termination stage task failed");}},
                _=tokio::time::sleep(Duration::from_millis(500)),if jobs.len()<self.concurrency=>{
                    match self.engine.claim_termination().await {
                        Ok(Some(claim))=>{let controller=self.clone();jobs.spawn(async move{controller.run_claim(claim).await;});},
                        Ok(None)=>{},
                        Err(error)=>{tracing::warn!(code=error.code,"termination queue unavailable");tokio::select!{_=shutdown.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(2))=>{}}}
                    }
                }
            }
        }
        if tokio::time::timeout(Duration::from_secs(30), async {
            while jobs.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            jobs.abort_all();
            while jobs.join_next().await.is_some() {}
        }
        if tokio::time::timeout(Duration::from_secs(5), &mut registration_task)
            .await
            .is_err()
        {
            registration_task.abort();
            let _ = registration_task.await;
        }
        if tokio::time::timeout(Duration::from_secs(5), &mut gc_task)
            .await
            .is_err()
        {
            gc_task.abort();
            let _ = gc_task.await;
        }
        Ok(())
    }

    async fn register_launches(&self, shutdown: CancellationToken) {
        loop {
            tokio::select! {_=shutdown.cancelled()=>return,_=tokio::time::sleep(Duration::from_secs(2))=>{}}
            let scan = async {
                let candidates = self
                    .engine
                    .database
                    .launch_registration_candidates(self.concurrency as i32)
                    .await?;
                let mut registrations = JoinSet::new();
                for candidate in candidates {
                    let controller = self.clone();
                    registrations.spawn(async move{
                        let operation_id=candidate.operation_id;
                        let result=tokio::time::timeout(Duration::from_secs(25),controller.register_launch(candidate)).await;
                        match result {
                            Ok(Ok(()))=>{},
                            Ok(Err(error))=>tracing::warn!(%operation_id,code=error.code,"launch registration deferred"),
                            Err(_)=>tracing::warn!(%operation_id,"launch registration timed out; no completion inferred"),
                        }
                    });
                }
                while let Some(result) = registrations.join_next().await {
                    if result.is_err() {
                        tracing::error!("launch registration task failed");
                    }
                }
                Ok::<(), ApiError>(())
            };
            tokio::select! {_=shutdown.cancelled()=>return,result=scan=>{if let Err(error)=result{tracing::warn!(code=error.code,"launch registration inventory unavailable");}}}
        }
    }

    pub async fn register_launch(&self, candidate: TerminationCandidate) -> Result<(), ApiError> {
        let db = &self.engine.database;
        let target = db
            .load_termination_target(candidate.tenant_id, candidate.operation_id)
            .await?;
        let known = target
            .known_resources
            .as_ref()
            .ok_or_else(|| blocked("LAUNCH_RESOURCES_NOT_RECORDED"))?;
        let observed = self
            .runtime
            .observe_launch(&target.context, known)
            .await
            .map_err(|_| blocked("LAUNCH_RUNTIME_NOT_VERIFIED"))?;
        let node = db.registered_runtime_node(&observed.node).await?;
        let client = self.client(&node)?;
        client
            .verify_node()
            .await
            .map_err(|_| blocked("NODE_IDENTITY_NOT_VERIFIED"))?;
        let permit = db
            .prepare_launch_authorization(
                candidate.tenant_id,
                candidate.operation_id,
                &observed.node,
                &observed.launch,
            )
            .await?;
        let ack = client
            .register(&permit.request)
            .await
            .map_err(|_| blocked("NODE_REGISTRATION_NOT_CONFIRMED"))?;
        db.record_launch_authorization(&permit, &ack, &observed.resources)
            .await
    }

    async fn run_claim(&self, claim: Claim) {
        let result = {
            let heartbeat = async {
                loop {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    if !self.engine.heartbeat(&claim).await.unwrap_or(false) {
                        return Err(blocked("WORKER_LEASE_LOST"));
                    }
                }
            };
            tokio::select! {result=self.reconcile(&claim)=>result,result=heartbeat=>result,
            _=tokio::time::sleep(Duration::from_secs(25))=>Err(blocked("TERMINATION_OBSERVATION_TIMEOUT"))}
        };
        if let Err(error) = result {
            if error.code == "WORKER_LEASE_LOST" {
                return;
            }
            tracing::warn!(operation_id=%claim.operation_id,code=error.code,"termination deferred without releasing resources");
            let _ = self
                .engine
                .wait(&claim, "TERMINATION_BLOCKED", error.code, 10)
                .await;
        }
    }

    pub async fn reconcile(&self, claim: &Claim) -> Result<(), ApiError> {
        let db = &self.engine.database;
        if db
            .complete_never_authorized_deletion(&self.engine, claim)
            .await?
        {
            return Ok(());
        }
        let target = db
            .load_termination_target(claim.tenant_id, claim.operation_id)
            .await?;
        if target.kind == "DELETE" && target.observed_state == "STOPPED" {
            return db
                .complete_stopped_instance_deletion(&self.engine, claim)
                .await;
        }
        let challenge = db
            .prepare_termination_challenge(&self.engine, claim)
            .await?;
        let client = self.client(&challenge.permit.node)?;
        // Normal deletion may help even when the host is unreachable. It cannot
        // release the protective finalizer or produce termination evidence.
        self.runtime
            .request_stop(&challenge.request.node, &challenge.request.launch)
            .await
            .map_err(|_| blocked("POD_STOP_REQUEST_NOT_CONFIRMED"))?;
        match client
            .close(&challenge.request)
            .await
            .map_err(|_| blocked("HOST_TERMINATION_NOT_VERIFIED"))?
        {
            TerminationObservation::Pending(state) => {
                let (stage, reason, retry) = match state {
                    ObservationState::UnknownStart => (
                        "WAITING_NODE_FENCE",
                        "UNKNOWN_HOST_START_REQUIRES_FENCING",
                        30,
                    ),
                    ObservationState::WaitingInFlight => {
                        ("WAITING_TERMINATION", "HOST_START_STILL_IN_FLIGHT", 5)
                    }
                    ObservationState::WaitingRuntime => {
                        ("WAITING_TERMINATION", "HOST_RUNTIME_NOT_SETTLED", 5)
                    }
                    ObservationState::WaitingProcessExit => {
                        ("WAITING_TERMINATION", "HOST_PROCESSES_STILL_PRESENT", 5)
                    }
                    ObservationState::WaitingUnmount => {
                        ("WAITING_TERMINATION", "WORKSPACE_MOUNT_STILL_PRESENT", 5)
                    }
                    ObservationState::Terminated => {
                        return Err(blocked("INVALID_TERMINATION_OBSERVATION"));
                    }
                };
                self.engine.wait(claim, stage, reason, retry).await
            }
            TerminationObservation::Verified(proof) => {
                let proof_id = db
                    .record_local_termination(&self.engine, claim, &proof)
                    .await?;
                match self
                    .runtime
                    .cleanup(&proof)
                    .await
                    .map_err(|_| blocked("TERMINATION_CLEANUP_NOT_VERIFIED"))?
                {
                    Some(cleanup) => {
                        db.complete_termination(&self.engine, claim, proof_id, &cleanup)
                            .await?;
                        Ok(())
                    }
                    None => {
                        self.engine
                            .wait(
                                claim,
                                "WAITING_TERMINATION_CLEANUP",
                                "OLD_POD_OR_VOLUME_ATTACHMENT_PRESENT",
                                5,
                            )
                            .await
                    }
                }
            }
        }
    }

    fn client(&self, node: &RuntimeNode) -> Result<NodeguardClient, ApiError> {
        // Disabled nodes cannot receive new launch permits, but an existing
        // launch must still be safely stopped using its immutable identity.
        let ip = node
            .private_ip
            .parse()
            .map_err(|_| blocked("NODE_INVENTORY_INVALID"))?;
        NodeguardClient::new(
            node.node.clone(),
            SocketAddr::new(ip, node.guard_port),
            &self.credentials,
        )
        .map_err(|_| blocked("NODE_CONNECTION_CONFIGURATION_INVALID"))
    }
}
fn blocked(code: &'static str) -> ApiError {
    ApiError::conflict(
        code,
        "Lifecycle reconciliation is waiting for trusted runtime evidence",
    )
}
