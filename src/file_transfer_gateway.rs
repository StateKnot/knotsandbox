//! Dedicated file queue using the gateway database/RAM identity, with separately
//! configured bounded concurrency. Every dispatch stays at most once.
use super::{
    ledger::{blocked, load},
    protocol::FileDirection,
    transport::execute_file_once,
};
use crate::{
    db::Database,
    engine::{Claim, OperationEngine},
    error::ApiError,
    file_store::{FILE_PART_BYTES, OssFileWriter},
    gateway_runtime::{GatewayRuntime, KnownRuntimeResources},
    runtime::KubernetesRuntime,
    runtime_manifest::{RuntimeManifestConfig, RuntimeManifestContext},
};
use sqlx::Row;
use std::{collections::BTreeMap, time::Duration};
use tokio::{sync::mpsc, task::JoinSet};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
#[derive(Clone)]
pub struct FileGateway {
    pub engine: OperationEngine,
    runtime: KubernetesRuntime,
    verifier: GatewayRuntime,
    writer: OssFileWriter,
    concurrency: usize,
}
struct Snapshot {
    id: Uuid,
    attempt: Option<Uuid>,
    deadline: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
    status: String,
    context: RuntimeManifestContext,
    pod: Uuid,
}
impl FileGateway {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        database: Database,
        runtime: KubernetesRuntime,
        writer: OssFileWriter,
        gateway_id: String,
        certification_id: String,
        concurrency: usize,
        manifests: RuntimeManifestConfig,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            (1..=16).contains(&concurrency),
            "File gateway concurrency must be 1..=16"
        );
        anyhow::ensure!(
            !certification_id.is_empty()
                && certification_id.len() <= 128
                && !certification_id.chars().any(char::is_control),
            "Deployment certification required"
        );
        Ok(Self {
            engine: OperationEngine::new(database, gateway_id)?,
            verifier: GatewayRuntime::new(runtime.clone(), manifests, certification_id),
            runtime,
            writer,
            concurrency,
        })
    }
    pub async fn run(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        self.engine.database.verify_runtime_role().await?;
        let migrated: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=36 AND success)",
        )
        .fetch_one(&self.engine.database.pool)
        .await?;
        anyhow::ensure!(migrated, "File gateway requires completed migration 0036");
        let valid:bool=sqlx::query_scalar("SELECT current_user='sandbox_gateway' AND has_function_privilege(current_user,'public.sandbox_claim_file_transfer(text)','EXECUTE') AND NOT has_function_privilege(current_user,'public.sandbox_claim_operation(text)','EXECUTE')").fetch_one(&self.engine.database.pool).await?;
        anyhow::ensure!(valid, "File gateway requires dedicated database identity");
        self.writer.check_credentials().await?;
        self.runtime.verify_runtime_class().await?;
        let mut jobs = JoinSet::new();
        loop {
            tokio::select! {biased;_=shutdown.cancelled()=>break,Some(result)=jobs.join_next(),if !jobs.is_empty()=>{if result.is_err(){tracing::error!("file gateway task abandoned; durable attempt will not replay");}},_=tokio::time::sleep(Duration::from_millis(250)),if jobs.len()<self.concurrency=>{match self.engine.database.claim_file_transfer(self.engine.worker_id()).await{Ok(Some(claim))=>{let gateway=self.clone();let stop=shutdown.clone();jobs.spawn(async move{gateway.run_claim(claim,stop).await;});},Ok(None)=>{},Err(error)=>{tracing::warn!(code=error.code,"file queue unavailable");tokio::select!{_=shutdown.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(2))=>{}}}}}}
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
        Ok(())
    }
    pub async fn run_claim(&self, claim: Claim, shutdown: CancellationToken) {
        let result = {
            let heartbeat = async {
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    if !self.engine.heartbeat(&claim).await.unwrap_or(false) {
                        return Err(blocked("WORKER_LEASE_LOST"));
                    }
                    self.live_authority(&claim).await?;
                }
            };
            tokio::select! {result=self.reconcile(&claim)=>result,result=heartbeat=>result,_=shutdown.cancelled()=>Err(blocked("GATEWAY_SHUTDOWN"))}
        };
        if let Err(error) = result {
            tracing::warn!(operation_id=%claim.operation_id,code=error.code,"file operation requires recovery");
            if let Err(error) = self.recover(&claim).await {
                tracing::error!(operation_id=%claim.operation_id,code=error.code,"file recovery deferred; dispatch remains single attempt");
            }
        }
    }
    pub async fn reconcile(&self, claim: &Claim) -> Result<(), ApiError> {
        let s = self.snapshot(claim).await?;
        if s.attempt.is_some() {
            return self.recover(claim).await;
        }
        if s.now >= s.deadline {
            self.engine
                .database
                .stop_file_transfer_for_safety(claim.tenant_id, s.id, "TIMEOUT")
                .await?;
            return Ok(());
        }
        if s.status == "WAITING_UPLOAD" {
            return self
                .engine
                .wait(claim, "WAITING_UPLOAD", "FILE_CONTENT_NOT_COMMITTED", 5)
                .await;
        }
        self.live_authority(claim).await?;
        self.writer
            .check_credentials()
            .await
            .map_err(|_| blocked("FILE_STORE_UNAVAILABLE"))?;
        let known = self.resources(claim, &s).await?;
        let observed = tokio::time::timeout(
            Duration::from_secs(20),
            self.verifier.verify(&s.context, &known),
        )
        .await
        .map_err(|_| blocked("RUNTIME_VERIFICATION_TIMEOUT"))?
        .map_err(|_| blocked("RUNTIME_VERIFICATION_FAILED"))?;
        let prepared = self
            .engine
            .database
            .begin_file_transfer_dispatch(&self.engine, claim, s.id, observed.identity)
            .await?;
        if prepared.namespace != observed.namespace || prepared.pod_name != observed.pod_name {
            return Err(blocked("RUNTIME_IDENTITY_CHANGED"));
        }
        let (tx, rx) = mpsc::channel(8);
        let dispatch = execute_file_once(self.runtime.client_clone(), &prepared, &self.writer, tx);
        let persist = self.persist(
            claim,
            s.id,
            prepared.request.dispatch_attempt_id,
            prepared.request.direction,
            rx,
        );
        let (completed, ()) = tokio::try_join!(
            async { dispatch.await.map_err(|_| blocked("FILE_TRANSPORT_LOST")) },
            persist
        )?;
        self.engine
            .database
            .complete_file_transfer_process(
                &self.engine,
                claim,
                s.id,
                prepared.request.dispatch_attempt_id,
                &completed,
            )
            .await
    }
    async fn recover(&self, claim: &Claim) -> Result<(), ApiError> {
        let mut tx = self.engine.database.begin(claim.tenant_id).await?;
        let id: Uuid = sqlx::query_scalar(
            "SELECT id FROM file_transfers WHERE tenant_id=$1 AND operation_id=$2",
        )
        .bind(claim.tenant_id)
        .bind(claim.operation_id)
        .fetch_one(&mut *tx)
        .await?;
        let r = load(&mut tx, claim.tenant_id, id, false).await?;
        tx.commit().await?;
        if let Some(attempt) = r.dispatch_attempt_id {
            self.engine
                .database
                .mark_file_transfer_unknown(claim.tenant_id, id, attempt)
                .await?;
            self.engine
                .database
                .stop_file_transfer_for_safety(claim.tenant_id, id, "TRANSPORT_LOST")
                .await?;
        } else if chrono::Utc::now() >= r.deadline {
            self.engine
                .database
                .stop_file_transfer_for_safety(claim.tenant_id, id, "TIMEOUT")
                .await?;
        } else {
            self.engine
                .wait(
                    claim,
                    "FILE_RECONCILE_BLOCKED",
                    "FILE_PREREQUISITE_UNAVAILABLE",
                    5,
                )
                .await?;
        }
        Ok(())
    }
    async fn persist(
        &self,
        claim: &Claim,
        id: Uuid,
        attempt: Uuid,
        direction: FileDirection,
        mut rx: mpsc::Receiver<Vec<u8>>,
    ) -> Result<(), ApiError> {
        let mut buffer = Vec::with_capacity(FILE_PART_BYTES);
        let mut index = 0;
        while let Some(bytes) = rx.recv().await {
            if direction != FileDirection::Download {
                return Err(blocked("UNEXPECTED_FILE_OUTPUT"));
            }
            let mut offset = 0;
            while offset < bytes.len() {
                let n = (FILE_PART_BYTES - buffer.len()).min(bytes.len() - offset);
                buffer.extend_from_slice(&bytes[offset..offset + n]);
                offset += n;
                if buffer.len() == FILE_PART_BYTES {
                    self.flush_part(
                        claim,
                        id,
                        attempt,
                        index,
                        std::mem::replace(&mut buffer, Vec::with_capacity(FILE_PART_BYTES)),
                    )
                    .await?;
                    index += 1;
                }
            }
        }
        if !buffer.is_empty() {
            self.flush_part(claim, id, attempt, index, buffer).await?;
        }
        Ok(())
    }
    async fn flush_part(
        &self,
        claim: &Claim,
        id: Uuid,
        attempt: Uuid,
        index: u32,
        bytes: Vec<u8>,
    ) -> Result<(), ApiError> {
        let intent = self
            .engine
            .database
            .begin_download_file_part(&self.engine, claim, id, attempt, index, &bytes)
            .await?;
        if chrono::Utc::now() >= intent.write_until {
            return Err(blocked("FILE_PART_WRITE_AUTHORITY_EXPIRED"));
        }
        let receipt = match self.writer.put_part(intent.receipt.identity, bytes).await {
            Ok(receipt) => receipt,
            Err(_) => {
                let _ = self
                    .engine
                    .database
                    .mark_file_part_put_unknown(&intent)
                    .await;
                return Err(blocked("FILE_PART_PUT_OUTCOME_UNKNOWN"));
            }
        };
        self.engine
            .database
            .publish_download_file_part(&self.engine, claim, id, attempt, &intent, &receipt)
            .await
    }
    async fn snapshot(&self, claim: &Claim) -> Result<Snapshot, ApiError> {
        let mut tx = self.engine.database.begin(claim.tenant_id).await?;
        self.engine.assert_claim(&mut tx, claim).await?;
        let r=sqlx::query("SELECT f.id,f.dispatch_attempt_id,f.deadline,f.status,i.tenant_id,i.project_id,i.id AS instance_id,i.workspace_id,i.runtime_generation,i.launch_id,i.cluster_epoch,i.namespace,i.pod_uid,i.cpu_millis,i.memory_mib,w.storage_class,w.size_gib,t.image_ref,t.image_digest,t.status='APPROVED' AS template_approved,p.status='APPROVED' AS policy_approved,p.rules,clock_timestamp() AS now FROM file_transfers f JOIN instances i ON i.tenant_id=f.tenant_id AND i.id=f.instance_id JOIN workspaces w ON w.tenant_id=i.tenant_id AND w.id=i.workspace_id JOIN template_versions t ON t.tenant_id=i.tenant_id AND t.id=i.template_version_id JOIN security_policy_versions p ON p.tenant_id=i.tenant_id AND p.id=i.security_policy_version_id WHERE f.tenant_id=$1 AND f.operation_id=$2").bind(claim.tenant_id).bind(claim.operation_id).fetch_one(&mut *tx).await?;
        let mut s = Snapshot {
            id: r.try_get("id")?,
            attempt: r.try_get("dispatch_attempt_id")?,
            deadline: r.try_get("deadline")?,
            now: r.try_get("now")?,
            status: r.try_get("status")?,
            pod: r.try_get("pod_uid")?,
            context: RuntimeManifestContext {
                tenant_id: r.try_get("tenant_id")?,
                project_id: r.try_get("project_id")?,
                instance_id: r.try_get("instance_id")?,
                workspace_id: r.try_get("workspace_id")?,
                generation: r.try_get("runtime_generation")?,
                launch_id: r.try_get("launch_id")?,
                cluster_epoch: r.try_get("cluster_epoch")?,
                namespace: r.try_get("namespace")?,
                storage_class: r.try_get("storage_class")?,
                workspace_snapshot: None,
                image_ref: r.try_get("image_ref")?,
                image_digest: r.try_get("image_digest")?,
                template_approved: r.try_get("template_approved")?,
                security_policy_approved: r.try_get("policy_approved")?,
                security_policy_rules: r.try_get("rules")?,
                cpu_millis: r.try_get("cpu_millis")?,
                memory_mib: r.try_get("memory_mib")?,
                workspace_size_gib: r.try_get("size_gib")?,
            },
        };
        crate::workspace_restore::apply(&mut tx, &mut s.context).await?;
        tx.commit().await?;
        Ok(s)
    }
    async fn resources(
        &self,
        claim: &Claim,
        s: &Snapshot,
    ) -> Result<KnownRuntimeResources, ApiError> {
        let mut tx = self.engine.database.begin(claim.tenant_id).await?;
        let rows:Vec<(String,String,String,i64,Uuid)>=sqlx::query_as("SELECT kind,provider_id,status,generation,owner_id FROM external_resources WHERE tenant_id=$1 AND instance_id=$2 AND workspace_id=$3 AND provider='kubernetes' AND((kind='POD' AND generation=$4)OR kind IN('PVC','CILIUM_POLICY'))").bind(claim.tenant_id).bind(s.context.instance_id).bind(s.context.workspace_id).bind(s.context.generation).fetch_all(&mut *tx).await?;
        let mut known = BTreeMap::new();
        for (kind, uid, status, generation, owner) in rows {
            if status != "ACTIVE"
                || uid.is_empty()
                || generation
                    != if kind == "POD" {
                        s.context.generation
                    } else {
                        1
                    }
                || owner
                    != if kind == "PVC" {
                        s.context.workspace_id
                    } else {
                        s.context.instance_id
                    }
                || known.insert(kind, uid).is_some()
            {
                return Err(blocked("RESOURCE_LEDGER_INVALID"));
            }
        }
        if known.get("POD") != Some(&s.pod.to_string()) {
            return Err(blocked("RESOURCE_LEDGER_INVALID"));
        }
        let result = KnownRuntimeResources {
            pod_uid: s.pod,
            pvc_uid: known
                .remove("PVC")
                .ok_or_else(|| blocked("RESOURCE_LEDGER_INVALID"))?,
            policy_uid: known
                .remove("CILIUM_POLICY")
                .ok_or_else(|| blocked("RESOURCE_LEDGER_INVALID"))?,
        };
        tx.commit().await?;
        Ok(result)
    }
    async fn live_authority(&self, claim: &Claim) -> Result<(), ApiError> {
        let mut tx = self.engine.database.begin(claim.tenant_id).await?;
        let row=sqlx::query("SELECT f.id,o.actor_principal_id,o.request_id FROM file_transfers f JOIN operations o ON o.tenant_id=f.tenant_id AND o.id=f.operation_id WHERE f.tenant_id=$1 AND f.operation_id=$2").bind(claim.tenant_id).bind(claim.operation_id).fetch_one(&mut *tx).await?;
        let r = load(&mut tx, claim.tenant_id, row.try_get("id")?, false).await?;
        let actor = crate::db::Actor {
            authorization: None,
            tenant_id: claim.tenant_id,
            principal_id: row.try_get("actor_principal_id")?,
            request_id: row.try_get("request_id")?,
        };
        Database::authorize_resource(&mut tx, &actor, r.project_id, r.action()).await?;
        Database::authorize_resource(&mut tx, &actor, r.project_id, "instances:hard_stop").await?;
        let instance =
            crate::db::load_instance(&mut tx, claim.tenant_id, r.instance_id, false).await?;
        let now = super::ledger::db_now(&mut tx).await?;
        let epoch = crate::db::runnable_epoch(&mut tx).await?;
        if now >= r.deadline
            || crate::execution::ready_identity(&mut tx, &instance, epoch, now).await?
                != r.identity()
        {
            return Err(blocked("FILE_DISPATCH_AUTHORITY_CHANGED"));
        }
        if r.direction == "UPLOAD" {
            super::ledger::assert_write_activity(&mut tx, &r).await?;
        }
        tx.commit().await?;
        Ok(())
    }
}
