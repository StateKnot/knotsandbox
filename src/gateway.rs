//! Durable execution dispatch. A persisted attempt is never sent again after a
//! crash; recovery requests a safety STOP and preserves the occupied slot.
use crate::{
    db::{Actor, Database},
    engine::{Claim, OperationEngine},
    error::ApiError,
    gateway_ledger::{NormalProcessCompletion, StoredOutputSegment},
    gateway_protocol::{GuestEvent, GuestTerminal},
    gateway_runtime::{GatewayRuntime, KnownRuntimeResources},
    gateway_transport::{ExecTransportError, execute_once},
    output_store::{OssOutputStore, SegmentPayload},
    runtime::KubernetesRuntime,
    runtime_manifest::{RuntimeManifestConfig, RuntimeManifestContext},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sqlx::Row;
use std::{collections::BTreeMap, time::Duration};
use tokio::{sync::mpsc, task::JoinSet};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Clone)]
pub struct Gateway {
    pub engine: OperationEngine,
    runtime: KubernetesRuntime,
    verifier: GatewayRuntime,
    output: OssOutputStore,
    concurrency: usize,
}

struct Snapshot {
    execution_id: Uuid,
    dispatch_attempt_id: Option<Uuid>,
    deadline: DateTime<Utc>,
    now: DateTime<Utc>,
    slot_held: bool,
    context: RuntimeManifestContext,
    pod_uid: Option<Uuid>,
}

/// Keys are derived from the manifest's common tenant/execution/attempt header.
/// Keep 4096 low-frequency segments bounded instead of retaining repeated paths.
#[derive(Serialize)]
struct ManifestSegment {
    sequence: i64,
    first_frame_sequence: i64,
    last_frame_sequence: i64,
    raw_bytes: i64,
    object_bytes: i64,
    #[serde(serialize_with = "digest_hex")]
    sha256: [u8; 32],
}
#[derive(Serialize)]
struct OutputManifest<'a> {
    schema_version: u8,
    tenant_id: Uuid,
    execution_id: Uuid,
    dispatch_attempt_id: Uuid,
    output_status: &'a str,
    segments: &'a [ManifestSegment],
}
fn digest_hex<S: serde::Serializer>(digest: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex::encode(digest))
}
impl TryFrom<StoredOutputSegment> for ManifestSegment {
    type Error = ApiError;
    fn try_from(receipt: StoredOutputSegment) -> Result<Self, Self::Error> {
        let mut digest = [0; 32];
        hex::decode_to_slice(receipt.sha256, &mut digest)
            .map_err(|_| blocked("OUTPUT_PERSISTENCE_FAILED"))?;
        Ok(Self {
            sequence: receipt.sequence,
            first_frame_sequence: receipt.first_frame_sequence,
            last_frame_sequence: receipt.last_frame_sequence,
            raw_bytes: receipt.raw_bytes,
            object_bytes: receipt.object_bytes,
            sha256: digest,
        })
    }
}

impl Gateway {
    pub fn new(
        database: Database,
        runtime: KubernetesRuntime,
        output: OssOutputStore,
        gateway_id: String,
        certification_id: String,
        concurrency: usize,
        manifests: RuntimeManifestConfig,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            (1..=32).contains(&concurrency),
            "Gateway concurrency must be 1..=32"
        );
        anyhow::ensure!(
            !certification_id.is_empty()
                && certification_id.len() <= 128
                && !certification_id.chars().any(char::is_control),
            "Deployment certification reference is required"
        );
        Ok(Self {
            engine: OperationEngine::new(database, gateway_id)?,
            verifier: GatewayRuntime::new(runtime.clone(), manifests, certification_id),
            runtime,
            output,
            concurrency,
        })
    }

    pub async fn run(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        self.engine.database.verify_runtime_role().await?;
        let valid:bool=sqlx::query_scalar("SELECT current_user='sandbox_gateway' AND has_function_privilege(current_user,'public.sandbox_claim_execution(text)','EXECUTE') AND NOT has_function_privilege(current_user,'public.sandbox_claim_operation(text)','EXECUTE')")
            .fetch_one(&self.engine.database.pool).await?;
        anyhow::ensure!(
            valid,
            "Gateway requires its dedicated database identity and queue grant"
        );
        self.output.check_credentials().await?;
        self.runtime.verify_runtime_class().await?;
        let mut jobs = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _=shutdown.cancelled()=>break,
                Some(result)=jobs.join_next(), if !jobs.is_empty()=>{ if result.is_err() { tracing::error!("gateway task failed; durable attempt will be recovered without replay"); } },
                _=tokio::time::sleep(Duration::from_millis(250)),if jobs.len()<self.concurrency=>{
                    match self.engine.claim_execution().await {
                        Ok(Some(claim))=>{let gateway=self.clone();let stop=shutdown.clone();jobs.spawn(async move {gateway.run_claim(claim,stop).await;});},
                        Ok(None)=>{},
                        Err(error)=>{tracing::warn!(code=error.code,"gateway claim unavailable");tokio::select!{_=shutdown.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(2))=>{}}},
                    }
                }
            }
        }
        // Active dispatches close their streams and durably request STOP on
        // shutdown. An unreachable DB leaves an attempt for the next claimant.
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

    /// Process one leased claim with heartbeat and durable failure recovery.
    pub async fn run_claim(&self, claim: Claim, shutdown: CancellationToken) {
        let result = {
            let keep_alive = async {
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    if !self.engine.heartbeat(&claim).await.unwrap_or(false) {
                        return Err(blocked("WORKER_LEASE_LOST"));
                    }
                    self.check_live_authority(&claim).await?;
                }
            };
            tokio::select! {
                result=self.reconcile(&claim)=>result,
                result=keep_alive=>result,
                _=shutdown.cancelled()=>Err(blocked("GATEWAY_SHUTDOWN")),
            }
        };
        if let Err(error) = result {
            tracing::warn!(operation_id=%claim.operation_id,code=error.code,"execution dispatch did not complete");
            if let Err(recovery) = self.recover_or_defer(&claim, error.code).await {
                tracing::error!(operation_id=%claim.operation_id,code=recovery.code,"execution recovery deferred; never replay the attempt");
            }
        }
    }

    /// One claimed operation. Used by the supervisor and recovery integration
    /// tests; the supervisor supplies heartbeat and shutdown while this runs.
    pub async fn reconcile(&self, claim: &Claim) -> Result<(), ApiError> {
        let snapshot = self.snapshot(claim).await?;
        if !snapshot.slot_held {
            return self
                .engine
                .wait(
                    claim,
                    "RECONCILE_BLOCKED",
                    "ACTIVITY_SLOT_ALREADY_RELEASED",
                    300,
                )
                .await;
        }
        if snapshot.dispatch_attempt_id.is_some() {
            // Even a DISPATCHING row that crashed before CONNECT cannot be
            // distinguished from a delivered request. No second exec is sent.
            self.engine
                .database
                .stop_execution_for_safety(claim.tenant_id, snapshot.execution_id, "TRANSPORT_LOST")
                .await?;
            self.mark_partial_output(claim.tenant_id, snapshot.execution_id)
                .await?;
            return Ok(());
        }
        if snapshot.now >= snapshot.deadline {
            self.engine
                .database
                .stop_execution_for_safety(claim.tenant_id, snapshot.execution_id, "TIMEOUT")
                .await?;
            return Ok(());
        }
        self.check_live_authority(claim).await?;
        self.output
            .check_credentials()
            .await
            .map_err(|_| blocked("OUTPUT_STORE_UNAVAILABLE"))?;
        let resources = self.resources(claim, &snapshot).await?;
        let observed = tokio::time::timeout(
            Duration::from_secs(20),
            self.verifier.verify(&snapshot.context, &resources),
        )
        .await
        .map_err(|_| blocked("RUNTIME_VERIFICATION_TIMEOUT"))?
        .map_err(|_| blocked("RUNTIME_VERIFICATION_FAILED"))?;
        let prepared = self
            .engine
            .database
            .begin_execution_dispatch(
                &self.engine,
                claim,
                snapshot.execution_id,
                observed.identity,
            )
            .await?;
        if observed.namespace != prepared.namespace || observed.pod_name != prepared.pod_name {
            return Err(blocked("RUNTIME_IDENTITY_CHANGED"));
        }
        let (tx, rx) = mpsc::channel(16); // <= 16 * 6144 retained raw bytes + metadata.
        let dispatch = async {
            execute_once(self.runtime.client_clone(), &prepared, tx)
                .await
                .map_err(|error| match error {
                    ExecTransportError::Deadline => blocked("EXECUTION_DEADLINE_EXPIRED"),
                    ExecTransportError::OutputClosed => blocked("OUTPUT_PERSISTENCE_FAILED"),
                    _ => blocked("EXEC_TRANSPORT_LOST"),
                })
        };
        let persistence = self.persist_outputs(
            claim,
            snapshot.execution_id,
            prepared.dispatch_attempt_id,
            rx,
        );
        let (completed, segments) = tokio::try_join!(dispatch, persistence)?;
        let GuestTerminal::Exited(report) = completed.guest_terminal else {
            return Err(blocked("EXEC_TRANSPORT_LOST"));
        };
        if completed.trusted_process_exit_code != 0
            || (!report.output_complete && !report.output_truncated)
        {
            return Err(blocked("OUTPUT_PERSISTENCE_FAILED"));
        }
        let output_status = if report.output_truncated {
            "TRUNCATED"
        } else {
            "COMPLETE"
        };
        let manifest = serde_json::to_vec(&OutputManifest {
            schema_version: 1,
            tenant_id: claim.tenant_id,
            execution_id: snapshot.execution_id,
            dispatch_attempt_id: prepared.dispatch_attempt_id,
            output_status,
            segments: &segments,
        })
        .map_err(|_| blocked("OUTPUT_PERSISTENCE_FAILED"))?;
        let reference = self
            .output
            .put_manifest(
                claim.tenant_id,
                snapshot.execution_id,
                prepared.dispatch_attempt_id,
                manifest,
            )
            .await
            .map_err(|_| blocked("OUTPUT_PERSISTENCE_FAILED"))?;
        self.engine
            .database
            .complete_execution_process(
                &self.engine,
                claim,
                snapshot.execution_id,
                prepared.dispatch_attempt_id,
                &NormalProcessCompletion {
                    trusted_process_exit_code: completed.trusted_process_exit_code,
                    guest_report: report,
                    output_status: output_status.into(),
                    manifest: Some(reference),
                },
            )
            .await
    }

    async fn snapshot(&self, claim: &Claim) -> Result<Snapshot, ApiError> {
        let mut tx = self.engine.database.begin(claim.tenant_id).await?;
        self.engine.assert_claim(&mut tx, claim).await?;
        let r=sqlx::query("SELECT e.id AS execution_id,e.dispatch_attempt_id,e.deadline,e.slot_held,i.tenant_id,i.project_id,i.id AS instance_id,i.workspace_id,i.runtime_generation,i.launch_id,i.cluster_epoch,i.namespace,i.pod_uid,i.cpu_millis,i.memory_mib,w.storage_class,w.size_gib,t.image_ref,t.image_digest,t.status='APPROVED' AS template_approved,p.status='APPROVED' AS policy_approved,p.rules,clock_timestamp() AS now FROM executions e JOIN instances i ON i.tenant_id=e.tenant_id AND i.id=e.instance_id JOIN workspaces w ON w.tenant_id=i.tenant_id AND w.id=i.workspace_id JOIN template_versions t ON t.tenant_id=i.tenant_id AND t.id=i.template_version_id JOIN security_policy_versions p ON p.tenant_id=i.tenant_id AND p.id=i.security_policy_version_id WHERE e.tenant_id=$1 AND e.operation_id=$2")
            .bind(claim.tenant_id).bind(claim.operation_id).fetch_one(&mut *tx).await?;
        let mut snapshot = Snapshot {
            execution_id: r.try_get("execution_id")?,
            dispatch_attempt_id: r.try_get("dispatch_attempt_id")?,
            deadline: r.try_get("deadline")?,
            now: r.try_get("now")?,
            slot_held: r.try_get("slot_held")?,
            pod_uid: r.try_get("pod_uid")?,
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
        crate::workspace_restore::apply(&mut tx, &mut snapshot.context).await?;
        tx.commit().await?;
        Ok(snapshot)
    }

    async fn resources(
        &self,
        claim: &Claim,
        snapshot: &Snapshot,
    ) -> Result<KnownRuntimeResources, ApiError> {
        let mut tx = self.engine.database.begin(claim.tenant_id).await?;
        let rows:Vec<(String,String,String,i64,Uuid)>=sqlx::query_as("SELECT kind,provider_id,status,generation,owner_id FROM external_resources WHERE tenant_id=$1 AND instance_id=$2 AND workspace_id=$3 AND provider='kubernetes' AND ((kind='POD' AND generation=$4) OR kind IN ('PVC','CILIUM_POLICY'))")
            .bind(claim.tenant_id).bind(snapshot.context.instance_id).bind(snapshot.context.workspace_id).bind(snapshot.context.generation).fetch_all(&mut *tx).await?;
        let mut known = BTreeMap::new();
        for (kind, uid, status, generation, owner) in rows {
            let expected_owner = if kind == "PVC" {
                snapshot.context.workspace_id
            } else {
                snapshot.context.instance_id
            };
            let expected_generation = if kind == "POD" {
                snapshot.context.generation
            } else {
                1
            };
            if status != "ACTIVE"
                || generation != expected_generation
                || owner != expected_owner
                || uid.is_empty()
                || known.insert(kind, uid).is_some()
            {
                return Err(blocked("RESOURCE_LEDGER_INVALID"));
            }
        }
        let pod = snapshot
            .pod_uid
            .ok_or_else(|| blocked("RESOURCE_LEDGER_INVALID"))?;
        if known.get("POD") != Some(&pod.to_string()) {
            return Err(blocked("RESOURCE_LEDGER_INVALID"));
        }
        let resources = KnownRuntimeResources {
            pod_uid: pod,
            pvc_uid: known
                .remove("PVC")
                .ok_or_else(|| blocked("RESOURCE_LEDGER_INVALID"))?,
            policy_uid: known
                .remove("CILIUM_POLICY")
                .ok_or_else(|| blocked("RESOURCE_LEDGER_INVALID"))?,
        };
        tx.commit().await?;
        Ok(resources)
    }

    async fn check_live_authority(&self, claim: &Claim) -> Result<(), ApiError> {
        let mut tx = self.engine.database.begin(claim.tenant_id).await?;
        let r=sqlx::query("SELECT o.actor_principal_id,o.request_id,e.project_id,COALESCE(NOT c.safe_mode AND c.cluster_epoch=e.cluster_epoch AND i.cluster_epoch=e.cluster_epoch AND i.runtime_generation=e.runtime_generation AND i.launch_id=e.launch_id AND i.pod_uid=e.pod_uid AND i.desired_state='RUNNING' AND i.active_operation_id IS NULL AND i.stop_accepted_at IS NULL AND i.compute_lease_expires_at>clock_timestamp() AND e.deadline>clock_timestamp() AND e.slot_held AND i.slot_held AND i.activity_id=e.id AND e.cancel_requested_at IS NULL AND e.status IN ('QUEUED','DISPATCHING','RUNNING') AND t.status='APPROVED' AND p.status='APPROVED',false) AS valid FROM executions e JOIN operations o ON o.tenant_id=e.tenant_id AND o.id=e.operation_id JOIN instances i ON i.tenant_id=e.tenant_id AND i.id=e.instance_id JOIN template_versions t ON t.tenant_id=i.tenant_id AND t.id=i.template_version_id JOIN security_policy_versions p ON p.tenant_id=i.tenant_id AND p.id=i.security_policy_version_id CROSS JOIN platform_configuration c WHERE e.tenant_id=$1 AND e.operation_id=$2 AND c.singleton")
            .bind(claim.tenant_id).bind(claim.operation_id).fetch_one(&mut *tx).await?;
        if !r.try_get::<bool, _>("valid")? {
            return Err(blocked("EXECUTION_AUTHORITY_CHANGED"));
        }
        let actor = Actor {
            authorization: None,
            tenant_id: claim.tenant_id,
            principal_id: r.try_get("actor_principal_id")?,
            request_id: r.try_get("request_id")?,
        };
        for action in ["executions:create", "instances:hard_stop"] {
            Database::authorize(&mut tx, &actor, r.try_get("project_id")?, action).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn recover_or_defer(&self, claim: &Claim, code: &str) -> Result<(), ApiError> {
        // Recovery may run after losing its lease. It does not dispatch or
        // advance a worker stage: the accepted safety contract allows STOP.
        let mut tx = self.engine.database.begin(claim.tenant_id).await?;
        let (execution,attempt,due):(Uuid,Option<Uuid>,bool)=sqlx::query_as("SELECT id,dispatch_attempt_id,deadline<=clock_timestamp() FROM executions WHERE tenant_id=$1 AND operation_id=$2")
            .bind(claim.tenant_id).bind(claim.operation_id).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        if attempt.is_some() || due {
            let reason = if due {
                "TIMEOUT"
            } else if code == "OUTPUT_PERSISTENCE_FAILED" {
                "OUTPUT_FAILURE"
            } else {
                "TRANSPORT_LOST"
            };
            self.engine
                .database
                .stop_execution_for_safety(claim.tenant_id, execution, reason)
                .await?;
            self.mark_partial_output(claim.tenant_id, execution).await?;
            Ok(())
        } else {
            self.engine.wait(claim, "WAITING_DISPATCH", code, 10).await
        }
    }

    async fn mark_partial_output(&self, tenant: Uuid, execution: Uuid) -> Result<(), ApiError> {
        let mut tx = self.engine.database.begin(tenant).await?;
        sqlx::query("UPDATE executions SET output_status=CASE WHEN EXISTS(SELECT 1 FROM execution_output_segments s WHERE s.tenant_id=$1 AND s.execution_id=$2) THEN 'PARTIAL' ELSE 'LOST' END WHERE tenant_id=$1 AND id=$2 AND slot_held AND status IN ('OUTCOME_UNKNOWN','TIMED_OUT','CANCELLED') AND output_status='PENDING'")
            .bind(tenant).bind(execution).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn persist_outputs(
        &self,
        claim: &Claim,
        execution: Uuid,
        attempt: Uuid,
        mut rx: mpsc::Receiver<GuestEvent>,
    ) -> Result<Vec<ManifestSegment>, ApiError> {
        let mut segments = Vec::new();
        let mut buffer = Vec::with_capacity(262144);
        let mut raw = 0_i64;
        let mut first = None;
        let mut last = 0_i64;
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            let (event, flush) =
                tokio::select! {event=rx.recv()=>(event,false),_=tick.tick()=>(None,true)};
            let ending = event.is_none() && !flush;
            if let Some(GuestEvent::Output {
                sequence,
                stream,
                offset,
                bytes,
            }) = event
                && !bytes.is_empty()
            {
                let mut line=serde_json::to_vec(&json!({"sequence":sequence,"stream":stream,"offset":offset,"data":STANDARD.encode(&bytes)})).map_err(|_|blocked("OUTPUT_PERSISTENCE_FAILED"))?;
                line.push(b'\n');
                if buffer.len() + line.len() > 262144 || raw + bytes.len() as i64 > 262144 {
                    self.flush_segment(
                        claim,
                        execution,
                        attempt,
                        &mut segments,
                        &mut buffer,
                        &mut raw,
                        &mut first,
                        last,
                    )
                    .await?;
                }
                first.get_or_insert(sequence as i64);
                last = sequence as i64;
                raw += bytes.len() as i64;
                buffer.extend(line);
            }
            if (flush || ending) && !buffer.is_empty() {
                self.flush_segment(
                    claim,
                    execution,
                    attempt,
                    &mut segments,
                    &mut buffer,
                    &mut raw,
                    &mut first,
                    last,
                )
                .await?;
            }
            if ending {
                return Ok(segments);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn flush_segment(
        &self,
        claim: &Claim,
        execution: Uuid,
        attempt: Uuid,
        segments: &mut Vec<ManifestSegment>,
        buffer: &mut Vec<u8>,
        raw: &mut i64,
        first: &mut Option<i64>,
        last: i64,
    ) -> Result<(), ApiError> {
        if segments.len() >= 4096 {
            return Err(blocked("OUTPUT_PERSISTENCE_FAILED"));
        }
        let receipt = self
            .output
            .put_segment(SegmentPayload {
                tenant_id: claim.tenant_id,
                execution_id: execution,
                dispatch_attempt_id: attempt,
                sequence: segments.len() as i64,
                first_frame_sequence: first
                    .take()
                    .ok_or_else(|| blocked("OUTPUT_PERSISTENCE_FAILED"))?,
                last_frame_sequence: last,
                raw_bytes: *raw,
                ndjson: std::mem::take(buffer),
            })
            .await
            .map_err(|_| blocked("OUTPUT_PERSISTENCE_FAILED"))?;
        self.engine
            .database
            .record_execution_output_segment(&self.engine, claim, &receipt)
            .await?;
        segments.push(receipt.try_into()?);
        *raw = 0;
        Ok(())
    }
}

fn blocked(code: &'static str) -> ApiError {
    ApiError::conflict(
        code,
        "Execution requires recovery or a fresh authorized dispatch; an existing attempt is never replayed",
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn maximum_low_frequency_manifest_is_bounded() -> anyhow::Result<()> {
        use super::*;
        let segments: Vec<_> = (0..4096)
            .map(|sequence| ManifestSegment {
                sequence,
                first_frame_sequence: 4097,
                last_frame_sequence: 4097,
                raw_bytes: 262144,
                object_bytes: 524288,
                sha256: [255; 32],
            })
            .collect();
        let manifest = OutputManifest {
            schema_version: 1,
            tenant_id: Uuid::new_v4(),
            execution_id: Uuid::new_v4(),
            dispatch_attempt_id: Uuid::new_v4(),
            output_status: "TRUNCATED",
            segments: &segments,
        };
        let encoded = serde_json::to_vec(&manifest)?;
        assert!(encoded.len() < 1024 * 1024);
        // Compact live receipt vector plus serialized manifest capacity, one
        // 256 KiB segment and the bounded 16*6144-byte producer queue.
        let accounted = segments.capacity() * std::mem::size_of::<ManifestSegment>()
            + encoded.capacity()
            + 262144
            + 16 * 6144;
        assert!(accounted < 2 * 1024 * 1024);
        Ok(())
    }
}
