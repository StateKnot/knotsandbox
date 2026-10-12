//! Resumable destruction of an explicitly authorized, immutable workspace disk.
//! Network requests never hold a SQL transaction. A fixed disk may be retried
//! only after a new exact observation; disk absence alone cannot create intent.
use crate::{
    cloud_fencing::{
        AlibabaCloudVolumeDeletion, CloudDiskAbsence, CloudDiskAttachmentState,
        CloudDiskDeleteOutcome, CloudDiskIdentity, CloudDiskLookup, CloudDiskObservation,
        CloudDiskPreserveOutcome, CloudDiskState, CloudError, CloudErrorCode,
        CloudVolumeDeletionConfig,
    },
    db::{Actor, Database},
    engine::{Claim, OperationEngine},
    error::ApiError,
    volume_deletion_runtime::{
        VerifiedVolumeCleanup, VerifiedVolumePresent, VolumeDeletionRuntime, VolumeTarget,
        WorkspaceStorageProfile,
    },
};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeDeletionConfig {
    pub cloud: CloudVolumeDeletionConfig,
    pub storage: WorkspaceStorageProfile,
    pub concurrency: usize,
}
#[derive(sqlx::FromRow)]
struct State {
    tenant_id: Uuid,
    project_id: Uuid,
    workspace_id: Uuid,
    cluster_epoch: Uuid,
    namespace: String,
    pvc_name: String,
    storage_class: String,
    size_gib: i64,
    permit_id: Option<Uuid>,
    #[sqlx(default)]
    restore_id: Option<Uuid>,
    pvc_uid: Uuid,
    pv_uid: Uuid,
    pv_name: String,
    handle: String,
    account_id: String,
    region: String,
    actor_principal_id: Uuid,
    request_id: Uuid,
    spec_version: i64,
    cloud_identity: Option<Value>,
    has_absence: bool,
}
impl State {
    fn target(&self) -> Result<VolumeTarget, ApiError> {
        Ok(VolumeTarget {
            tenant_id: self.tenant_id,
            project_id: self.project_id,
            workspace_id: self.workspace_id,
            cluster_epoch: self.cluster_epoch,
            namespace: self.namespace.clone(),
            pvc_name: self.pvc_name.clone(),
            storage_class: self.storage_class.clone(),
            size_gib: self
                .size_gib
                .try_into()
                .map_err(|_| blocked("WORKSPACE_IDENTITY_INVALID"))?,
            pvc_uid: self.pvc_uid,
            pv_uid: self.pv_uid,
            pv_name: self.pv_name.clone(),
            handle: self.handle.clone(),
            account_id: self.account_id.clone(),
            region: self.region.clone(),
        })
    }
    fn identity(&self) -> Result<Option<CloudDiskIdentity>, ApiError> {
        self.cloud_identity
            .clone()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| blocked("DISK_IDENTITY_LEDGER_INVALID"))
    }
    fn actor(&self) -> Actor {
        Actor {
            authorization: None,
            tenant_id: self.tenant_id,
            principal_id: self.actor_principal_id,
            request_id: self.request_id,
        }
    }
}
fn blocked(code: &'static str) -> ApiError {
    ApiError::conflict(
        code,
        "Workspace destruction is waiting for verified authorization and storage evidence",
    )
}
async fn locked<'a>(
    db: &'a Database,
    engine: &OperationEngine,
    claim: &Claim,
    authorize: bool,
) -> Result<(Transaction<'a, Postgres>, State), ApiError> {
    let mut tx = db.begin(claim.tenant_id).await?;
    let ws:Option<Uuid>=sqlx::query_scalar("SELECT workspace_id FROM operations WHERE tenant_id=$1 AND id=$2 AND kind='DELETE_WORKSPACE'").bind(claim.tenant_id).bind(claim.operation_id).fetch_optional(&mut *tx).await?;
    let ws = ws.ok_or_else(|| blocked("WORKSPACE_DELETE_OPERATION_CHANGED"))?;
    sqlx::query("SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(claim.tenant_id)
        .bind(ws)
        .fetch_one(&mut *tx)
        .await?;
    engine.assert_claim(&mut tx, claim).await?;
    let mut state:Option<State>=sqlx::query_as("SELECT w.tenant_id,w.project_id,w.id AS workspace_id,d.cluster_epoch,w.namespace,w.pvc_name,w.storage_class,w.size_gib,p.id AS permit_id,p.pvc_uid,p.pv_uid,p.pv_name,p.csi_volume_handle AS handle,n.cloud_account_id AS account_id,n.region,o.actor_principal_id,o.request_id,w.spec_version,b.cloud_identity,EXISTS(SELECT 1 FROM workspace_disk_absences a WHERE a.tenant_id=w.tenant_id AND a.operation_id=o.id) AS has_absence FROM workspaces w JOIN workspace_delete_intents d ON d.tenant_id=w.tenant_id AND d.workspace_id=w.id JOIN operations o ON o.tenant_id=d.tenant_id AND o.id=d.operation_id JOIN instances i ON i.tenant_id=w.tenant_id AND i.workspace_id=w.id JOIN local_termination_proofs proof ON proof.tenant_id=i.tenant_id AND proof.id=i.last_termination_proof_id JOIN launch_permits p ON p.tenant_id=proof.tenant_id AND p.id=proof.permit_id JOIN runtime_nodes n ON n.id=p.runtime_node_id CROSS JOIN platform_configuration cfg LEFT JOIN workspace_delete_bindings b ON b.tenant_id=w.tenant_id AND b.operation_id=o.id WHERE w.tenant_id=$1 AND w.id=$2 AND o.id=$3 AND w.active_operation_id=o.id AND w.status='DELETING' AND cfg.singleton AND cfg.cluster_epoch=d.cluster_epoch AND (w.retention_until IS NULL OR w.retention_until<=clock_timestamp()) AND w.csi_volume_id=p.csi_volume_handle")
        .bind(claim.tenant_id).bind(ws).bind(claim.operation_id).fetch_optional(&mut *tx).await?;
    if state.is_none() {
        let reader: bool=sqlx::query_scalar("SELECT to_regprocedure('public.sandbox_restored_workspace_delete_binding(uuid,uuid)') IS NOT NULL").fetch_one(&mut *tx).await?;
        if reader {
            state =
                sqlx::query_as("SELECT * FROM sandbox_restored_workspace_delete_binding($1,$2)")
                    .bind(claim.tenant_id)
                    .bind(claim.operation_id)
                    .fetch_optional(&mut *tx)
                    .await?;
        }
    }
    let state = state.ok_or_else(|| blocked("WORKSPACE_DELETE_BINDING_CHANGED"))?;
    if state.permit_id.is_some() == state.restore_id.is_some() {
        return Err(blocked("WORKSPACE_DELETE_PROVENANCE_INVALID"));
    }
    let closed: bool = sqlx::query_scalar("SELECT sandbox_workspace_writers_closed($1,$2)")
        .bind(claim.tenant_id)
        .bind(ws)
        .fetch_one(&mut *tx)
        .await?;
    if !closed {
        return Err(blocked("WORKSPACE_WRITER_OR_HOLD_REMAINS"));
    }
    if authorize {
        Database::authorize_resource(
            &mut tx,
            &state.actor(),
            state.project_id,
            "workspaces:delete",
        )
        .await?;
    }
    Ok((tx, state))
}
fn identical<T: serde::Serialize>(a: &T, b: &T) -> bool {
    serde_json::to_value(a).ok() == serde_json::to_value(b).ok()
}
fn fresh(observed: DateTime<Utc>) -> bool {
    let now = Utc::now();
    observed <= now + Duration::seconds(2) && observed >= now - Duration::seconds(30)
}

impl Database {
    async fn volume_delete_state(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<State, ApiError> {
        let (tx, s) = locked(self, engine, claim, false).await?;
        tx.commit().await?;
        Ok(s)
    }
    async fn bind_workspace_disk(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        kube: &VerifiedVolumePresent,
        cloud: &CloudDiskObservation,
    ) -> Result<(), ApiError> {
        let identity = cloud
            .identity()
            .map_err(|_| blocked("DISK_IDENTITY_INCOMPLETE"))?;
        if !identical(&kube.binding, &identity.binding) || !fresh(cloud.evidence().received_at()) {
            return Err(blocked("DISK_IDENTITY_MISMATCH"));
        }
        let (mut tx, s) = locked(self, engine, claim, true).await?;
        if identity.binding.disk_id != s.handle
            || identity.binding.pv_name != s.pv_name
            || identity.binding.pvc_name != s.pvc_name
            || identity.binding.namespace != s.namespace
            || identity.binding.account_id != s.account_id
            || identity.binding.region != s.region
        {
            return Err(blocked("DISK_IDENTITY_MISMATCH"));
        }
        if let Some(previous) = s.identity()? {
            if !identical(&previous, &identity) {
                return Err(blocked("DISK_IDENTITY_CHANGED"));
            }
        } else {
            let statement = if s.restore_id.is_some() {
                "INSERT INTO workspace_delete_bindings(operation_id,tenant_id,workspace_id,permit_id,pvc_uid,pv_uid,pv_name,csi_volume_handle,cloud_identity,first_present_evidence,restore_id) VALUES($1,$2,$3,NULL,$5,$6,$7,$8,$9,$10,$4)"
            } else {
                "INSERT INTO workspace_delete_bindings(operation_id,tenant_id,workspace_id,permit_id,pvc_uid,pv_uid,pv_name,csi_volume_handle,cloud_identity,first_present_evidence) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"
            };
            sqlx::query(statement)
                .bind(claim.operation_id)
                .bind(claim.tenant_id)
                .bind(s.workspace_id)
                .bind(s.restore_id.or(s.permit_id))
                .bind(s.pvc_uid)
                .bind(s.pv_uid)
                .bind(&s.pv_name)
                .bind(&s.handle)
                .bind(json!(identity))
                .bind(json!(cloud))
                .execute(&mut *tx)
                .await?;
        }
        engine.assert_claim(&mut tx, claim).await?;
        if !fresh(cloud.evidence().received_at()) {
            return Err(blocked("DISK_OBSERVATION_STALE"));
        }
        tx.commit().await?;
        Ok(())
    }
    async fn begin_workspace_disk_delete(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        observed: &CloudDiskObservation,
    ) -> Result<Uuid, ApiError> {
        let current = observed
            .identity()
            .map_err(|_| blocked("DISK_IDENTITY_INCOMPLETE"))?;
        if !fresh(observed.evidence().received_at())
            || observed.state() != CloudDiskState::Available
            || observed.attachment_state() == CloudDiskAttachmentState::Present
            || observed.delete_auto_snapshot()
        {
            return Err(blocked("DISK_DELETE_PREFLIGHT_NOT_READY"));
        }
        let (mut tx, s) = locked(self, engine, claim, true).await?;
        let identity = s
            .identity()?
            .ok_or_else(|| blocked("DISK_IDENTITY_NOT_RECORDED"))?;
        if !identical(&identity, &current) || s.has_absence {
            return Err(blocked("DISK_DELETE_IDENTITY_CHANGED"));
        }
        let attempt = Uuid::new_v4();
        sqlx::query("INSERT INTO workspace_delete_attempts(id,tenant_id,operation_id,lease_token,preflight_evidence) VALUES($1,$2,$3,$4,$5)").bind(attempt).bind(claim.tenant_id).bind(claim.operation_id).bind(claim.lease_token).bind(json!(observed)).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details) VALUES($1,$2,$3,$4,$5,$6,'workspaces:delete:dispatch','ACCEPTED',$7)")
            .bind(s.tenant_id).bind(s.project_id).bind(s.actor_principal_id).bind(s.request_id).bind(claim.operation_id).bind(s.workspace_id).bind(json!({"attempt_id":attempt,"original_disk_id":s.handle})).execute(&mut *tx).await?;
        sqlx::query("UPDATE operations SET stage='DISK_DELETE_DISPATCHING',updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(claim.tenant_id).bind(claim.operation_id).execute(&mut *tx).await?;
        engine.assert_claim(&mut tx, claim).await?;
        if !fresh(observed.evidence().received_at()) {
            return Err(blocked("DISK_OBSERVATION_STALE"));
        }
        tx.commit().await?;
        Ok(attempt)
    }
    async fn begin_workspace_snapshot_preservation(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        observed: &CloudDiskObservation,
    ) -> Result<Uuid, ApiError> {
        let current = observed
            .identity()
            .map_err(|_| blocked("DISK_IDENTITY_INCOMPLETE"))?;
        if !fresh(observed.evidence().received_at())
            || observed.state() != CloudDiskState::Available
            || observed.attachment_state() == CloudDiskAttachmentState::Present
            || !observed.delete_auto_snapshot()
        {
            return Err(blocked("SNAPSHOT_PRESERVATION_PREFLIGHT_NOT_READY"));
        }
        let (mut tx, s) = locked(self, engine, claim, true).await?;
        let identity = s
            .identity()?
            .ok_or_else(|| blocked("DISK_IDENTITY_NOT_RECORDED"))?;
        if !identical(&identity, &current) || s.has_absence {
            return Err(blocked("DISK_DELETE_IDENTITY_CHANGED"));
        }
        let attempt = Uuid::new_v4();
        sqlx::query("INSERT INTO workspace_snapshot_preserve_attempts(id,tenant_id,operation_id,lease_token,preflight_evidence) VALUES($1,$2,$3,$4,$5)")
            .bind(attempt).bind(claim.tenant_id).bind(claim.operation_id).bind(claim.lease_token).bind(json!(observed)).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details) VALUES($1,$2,$3,$4,$5,$6,'workspaces:delete:preserve_snapshots','ACCEPTED',$7)")
            .bind(s.tenant_id).bind(s.project_id).bind(s.actor_principal_id).bind(s.request_id).bind(claim.operation_id).bind(s.workspace_id).bind(json!({"attempt_id":attempt,"original_disk_id":s.handle,"delete_auto_snapshot":false})).execute(&mut *tx).await?;
        sqlx::query("UPDATE operations SET stage='SNAPSHOT_PRESERVATION_DISPATCHING',updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
            .bind(claim.tenant_id).bind(claim.operation_id).execute(&mut *tx).await?;
        engine.assert_claim(&mut tx, claim).await?;
        if !fresh(observed.evidence().received_at()) {
            return Err(blocked("DISK_OBSERVATION_STALE"));
        }
        tx.commit().await?;
        Ok(attempt)
    }
    async fn record_workspace_disk_absence(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        absence: &CloudDiskAbsence,
    ) -> Result<(), ApiError> {
        if !fresh(absence.evidence().received_at())
            || absence.evidence().action() != "DescribeDisks"
        {
            return Err(blocked("DISK_ABSENCE_NOT_FRESH"));
        }
        let (mut tx, s) = locked(self, engine, claim, false).await?;
        let identity = s
            .identity()?
            .ok_or_else(|| blocked("DISK_IDENTITY_NOT_RECORDED"))?;
        if !identical(&identity.binding, absence.binding()) {
            return Err(blocked("DISK_IDENTITY_MISMATCH"));
        }
        let attempt:Option<Uuid>=sqlx::query_scalar("SELECT id FROM workspace_delete_attempts WHERE tenant_id=$1 AND operation_id=$2 AND dispatched_at<=$3 ORDER BY dispatched_at DESC,id LIMIT 1")
            .bind(claim.tenant_id).bind(claim.operation_id).bind(absence.evidence().sent_at()).fetch_optional(&mut *tx).await?;
        let attempt = attempt.ok_or_else(|| blocked("DISK_ABSENT_WITHOUT_DELETE_INTENT"))?;
        sqlx::query("INSERT INTO workspace_disk_absences(operation_id,tenant_id,attempt_id,evidence,observed_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(operation_id) DO NOTHING")
            .bind(claim.operation_id).bind(claim.tenant_id).bind(attempt).bind(json!(absence)).bind(absence.evidence().received_at()).execute(&mut *tx).await?;
        sqlx::query("UPDATE operations SET stage='WAITING_VOLUME_OBJECT_CLEANUP',updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(claim.tenant_id).bind(claim.operation_id).execute(&mut *tx).await?;
        engine.assert_claim(&mut tx, claim).await?;
        if !fresh(absence.evidence().received_at()) {
            return Err(blocked("DISK_OBSERVATION_STALE"));
        }
        tx.commit().await?;
        Ok(())
    }
    async fn finish_workspace_delete(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        cleanup: &VerifiedVolumeCleanup,
    ) -> Result<(), ApiError> {
        let (mut tx, s) = locked(self, engine, claim, false).await?;
        let (pvc_at, pv_at) = cleanup.observations();
        if !s.has_absence
            || cleanup.identities() != (s.pvc_uid, s.pv_uid)
            || !fresh(pvc_at)
            || !fresh(pv_at)
        {
            return Err(blocked("WORKSPACE_CLEANUP_EVIDENCE_MISMATCH"));
        }
        let observed:DateTime<Utc>=sqlx::query_scalar("SELECT observed_at FROM workspace_disk_absences WHERE tenant_id=$1 AND operation_id=$2").bind(claim.tenant_id).bind(claim.operation_id).fetch_one(&mut *tx).await?;
        if pvc_at < observed - Duration::seconds(2) || pv_at < observed - Duration::seconds(2) {
            return Err(blocked("WORKSPACE_CLEANUP_PRECEDES_CLOUD_PROOF"));
        }
        sqlx::query("SELECT id FROM quota_accounts WHERE tenant_id=$1 AND (project_id=$2 OR project_id IS NULL) ORDER BY id FOR UPDATE").bind(s.tenant_id).bind(s.project_id).fetch_all(&mut *tx).await?;
        let rows:Vec<(Uuid,Uuid,i64,String)>=sqlx::query_as("SELECT r.id,r.quota_account_id,r.amount,r.status FROM quota_reservations r JOIN quota_accounts q ON q.tenant_id=r.tenant_id AND q.id=r.quota_account_id WHERE r.tenant_id=$1 AND r.resource_id=$2 AND q.dimension='WORKSPACE_GIB' AND r.status IN('PENDING','ALLOCATED') ORDER BY r.quota_account_id,r.id FOR UPDATE OF r")
            .bind(s.tenant_id).bind(s.workspace_id).fetch_all(&mut *tx).await?;
        if rows.len() != 2 || rows.iter().any(|r| r.2 != s.size_gib) {
            return Err(blocked("WORKSPACE_QUOTA_LEDGER_MISMATCH"));
        }
        sqlx::query("INSERT INTO workspace_delete_cleanups(operation_id,tenant_id,pvc_uid,pv_uid,pvc_absent_at,pv_absent_at) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(claim.operation_id).bind(claim.tenant_id).bind(s.pvc_uid).bind(s.pv_uid).bind(pvc_at).bind(pv_at).execute(&mut *tx).await?;
        for (reservation, account, amount, status) in rows {
            sqlx::query("UPDATE quota_accounts SET pending=pending-CASE WHEN $4='PENDING' THEN $3 ELSE 0 END,allocated=allocated-CASE WHEN $4='ALLOCATED' THEN $3 ELSE 0 END,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(s.tenant_id).bind(account).bind(amount).bind(status).execute(&mut *tx).await?;
            sqlx::query("UPDATE quota_reservations SET status='RELEASED',released_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(s.tenant_id).bind(reservation).execute(&mut *tx).await?;
        }
        sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload) VALUES($1,$2,$3,$4,'workspace.deleted',$5,$6,$7)").bind(s.tenant_id).bind(s.project_id).bind(s.workspace_id).bind(s.spec_version+1).bind(claim.operation_id).bind(s.request_id).bind(json!({"storage_destroyed":true})).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details) VALUES($1,$2,$3,$4,$5,$6,'workspaces:delete','SUCCEEDED',$7)").bind(s.tenant_id).bind(s.project_id).bind(s.actor_principal_id).bind(s.request_id).bind(claim.operation_id).bind(s.workspace_id).bind(json!({"original_disk_id":s.handle,"pvc_uid":s.pvc_uid,"pv_uid":s.pv_uid})).execute(&mut *tx).await?;
        engine.assert_claim(&mut tx, claim).await?;
        if !fresh(pvc_at) || !fresh(pv_at) {
            return Err(blocked("WORKSPACE_CLEANUP_EVIDENCE_STALE"));
        }
        let epoch: bool = sqlx::query_scalar(
            "SELECT cluster_epoch=$1 FROM platform_configuration WHERE singleton",
        )
        .bind(s.cluster_epoch)
        .fetch_one(&mut *tx)
        .await?;
        if !epoch {
            return Err(blocked("CLUSTER_EPOCH_CHANGED"));
        }
        sqlx::query("UPDATE workspaces SET status='DELETED',deleted_at=clock_timestamp(),active_operation_id=NULL,spec_version=spec_version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(s.tenant_id).bind(s.workspace_id).execute(&mut *tx).await?;
        let changed=sqlx::query("UPDATE external_resources SET status='DELETED',deleted_at=clock_timestamp(),observed_at=clock_timestamp() WHERE tenant_id=$1 AND workspace_id=$2 AND owner_id=$2 AND kind='PVC' AND provider='kubernetes' AND provider_id=$3 AND generation=1")
            .bind(s.tenant_id).bind(s.workspace_id).bind(s.pvc_uid.to_string()).execute(&mut *tx).await?;
        if changed.rows_affected() != 1 {
            return Err(blocked("WORKSPACE_PVC_LEDGER_MISMATCH"));
        }
        sqlx::query("UPDATE operations SET status='SUCCEEDED',stage='COMPLETED',error=NULL,wait_reason=NULL,lease_owner=NULL,lease_until=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(claim.tenant_id).bind(claim.operation_id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct VolumeDeletionController {
    pub engine: OperationEngine,
    runtime: VolumeDeletionRuntime,
    cloud: AlibabaCloudVolumeDeletion,
    concurrency: usize,
}
impl VolumeDeletionController {
    pub fn new(
        engine: OperationEngine,
        runtime: VolumeDeletionRuntime,
        cloud: AlibabaCloudVolumeDeletion,
        concurrency: usize,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            (1..=8).contains(&concurrency),
            "Volume deletion concurrency must be 1..8"
        );
        Ok(Self {
            engine,
            runtime,
            cloud,
            concurrency,
        })
    }
    pub async fn reconcile(&self, claim: &Claim) -> Result<(), ApiError> {
        let db = &self.engine.database;
        let mut state = db.volume_delete_state(&self.engine, claim).await?;
        let target = state.target()?;
        if !state.has_absence {
            if state.identity()?.is_none() {
                let kube = self
                    .runtime
                    .observe(&target)
                    .await
                    .map_err(|_| blocked("WORKSPACE_RUNTIME_NOT_VERIFIED"))?;
                let CloudDiskLookup::Present(present) = self
                    .cloud
                    .observe_disk(&kube.binding)
                    .await
                    .map_err(|_| blocked("WORKSPACE_CLOUD_UNAVAILABLE"))?
                else {
                    return Err(blocked("DISK_ABSENT_WITHOUT_DELETE_INTENT"));
                };
                db.bind_workspace_disk(&self.engine, claim, &kube, &present)
                    .await?;
                state = db.volume_delete_state(&self.engine, claim).await?;
            }
            let identity = state
                .identity()?
                .ok_or_else(|| blocked("DISK_IDENTITY_NOT_RECORDED"))?;
            match self
                .cloud
                .observe_disk(&identity.binding)
                .await
                .map_err(|_| blocked("WORKSPACE_CLOUD_UNAVAILABLE"))?
            {
                CloudDiskLookup::Absent(absence) => {
                    db.record_workspace_disk_absence(&self.engine, claim, &absence)
                        .await?
                }
                CloudDiskLookup::Present(present) => {
                    let kube = self
                        .runtime
                        .observe(&target)
                        .await
                        .map_err(|_| blocked("WORKSPACE_RUNTIME_NOT_VERIFIED"))?;
                    if !identical(&kube.binding, &identity.binding) {
                        return Err(blocked("WORKSPACE_RUNTIME_IDENTITY_CHANGED"));
                    }
                    if present.delete_auto_snapshot() {
                        let attempt = db
                            .begin_workspace_snapshot_preservation(&self.engine, claim, &present)
                            .await?;
                        let result = self
                            .cloud
                            .preserve_automatic_snapshots(&identity, attempt)
                            .await;
                        if db
                            .record_workspace_snapshot_preservation_result(
                                &self.engine,
                                claim,
                                attempt,
                                &result,
                            )
                            .await?
                        {
                            return Ok(());
                        }
                        self.engine
                            .wait(
                                claim,
                                "WAITING_SNAPSHOT_PRESERVATION",
                                "SNAPSHOT_PRESERVATION_CONFIRMATION_REQUIRED",
                                5,
                            )
                            .await?;
                        return Ok(());
                    }
                    let attempt = db
                        .begin_workspace_disk_delete(&self.engine, claim, &present)
                        .await?;
                    // Even a preflight error after this durable dispatch stays
                    // uncertain. Recovery always queries first, never blind-replays.
                    let result = self.cloud.delete_disk(&identity, attempt).await;
                    if db
                        .record_workspace_delete_result(&self.engine, claim, attempt, &result)
                        .await?
                    {
                        return Ok(());
                    }
                    self.engine
                        .wait(
                            claim,
                            "WAITING_CLOUD_DISK_ABSENCE",
                            "DISK_DELETE_CONFIRMATION_REQUIRED",
                            5,
                        )
                        .await?;
                    return Ok(());
                }
            }
        }
        match self
            .runtime
            .cleanup(&target)
            .await
            .map_err(|_| blocked("WORKSPACE_OBJECT_CLEANUP_BLOCKED"))?
        {
            Some(cleanup) => {
                db.finish_workspace_delete(&self.engine, claim, &cleanup)
                    .await
            }
            None => {
                self.engine
                    .wait(
                        claim,
                        "WAITING_VOLUME_OBJECT_CLEANUP",
                        "PVC_OR_PV_STILL_PRESENT",
                        5,
                    )
                    .await
            }
        }
    }
    pub async fn run(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        self.engine.database.verify_runtime_role().await?;
        let allowed:bool=sqlx::query_scalar("SELECT current_user='sandbox_volume_deleter' AND has_function_privilege(current_user,'public.sandbox_claim_volume_deletion(text)','EXECUTE')").fetch_one(&self.engine.database.pool).await?;
        anyhow::ensure!(
            allowed,
            "Volume deletion requires its dedicated database role"
        );
        let mut jobs = tokio::task::JoinSet::new();
        loop {
            tokio::select! {biased;
                _=shutdown.cancelled()=>break,
                Some(result)=jobs.join_next(),if !jobs.is_empty()=>{if result.is_err(){tracing::error!("volume deletion task failed");}},
                _=tokio::time::sleep(std::time::Duration::from_millis(500)),if jobs.len()<self.concurrency=>{
                    match self.engine.claim_volume_deletion().await {Ok(Some(claim))=>{let c=self.clone();jobs.spawn(async move {
                        let heartbeat=async {loop {tokio::time::sleep(std::time::Duration::from_secs(10)).await;if !c.engine.heartbeat(&claim).await.unwrap_or(false){return Err(blocked("WORKER_LEASE_LOST"));}}};
                        let result=tokio::select!{r=c.reconcile(&claim)=>r,r=heartbeat=>r,_=tokio::time::sleep(std::time::Duration::from_secs(120))=>Err(blocked("WORKSPACE_RECONCILIATION_TIMEOUT"))};
                        if let Err(e)=result {tracing::warn!(operation_id=%claim.operation_id,code=e.code,"workspace destruction deferred; quota retained");let _=c.engine.wait(&claim,"WORKSPACE_DELETE_BLOCKED",e.code,30).await;}
                    });},Ok(None)=>{},Err(e)=>tracing::warn!(code=e.code,"workspace deletion queue unavailable")}
                }
            }
        }
        if tokio::time::timeout(std::time::Duration::from_secs(30), async {
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
}

fn requires_operator(code: CloudErrorCode) -> bool {
    matches!(
        code,
        CloudErrorCode::AccessDenied
            | CloudErrorCode::CredentialIdentityMismatch
            | CloudErrorCode::IdentityMismatch
            | CloudErrorCode::Configuration
            | CloudErrorCode::UnknownInstance
            | CloudErrorCode::ProviderRejected
    )
}

impl Database {
    async fn record_workspace_delete_result(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        attempt: Uuid,
        result: &Result<CloudDiskDeleteOutcome, CloudError>,
    ) -> Result<bool, ApiError> {
        let (outcome, evidence, manual) = match result {
            Ok(CloudDiskDeleteOutcome::Accepted(v)) => ("ACCEPTED", json!(v), false),
            Ok(CloudDiskDeleteOutcome::AlreadyAbsent(v)) => ("ALREADY_ABSENT", json!(v), false),
            Ok(CloudDiskDeleteOutcome::OutcomeUnknown(v)) => ("OUTCOME_UNKNOWN", json!(v), false),
            Err(e) => (
                "REJECTED",
                json!({"code":e.code,"evidence":e.evidence}),
                requires_operator(e.code),
            ),
        };
        self.record_workspace_mutation_result(
            engine,
            claim,
            attempt,
            (outcome, evidence, manual),
            false,
        )
        .await
    }
    async fn record_workspace_snapshot_preservation_result(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        attempt: Uuid,
        result: &Result<CloudDiskPreserveOutcome, CloudError>,
    ) -> Result<bool, ApiError> {
        let (outcome, evidence, manual) = match result {
            Ok(CloudDiskPreserveOutcome::Accepted(v)) => ("ACCEPTED", json!(v), false),
            Ok(CloudDiskPreserveOutcome::AlreadyPreserved(v)) => {
                ("ALREADY_PRESERVED", json!(v), false)
            }
            Ok(CloudDiskPreserveOutcome::AlreadyAbsent(v)) => ("ALREADY_ABSENT", json!(v), false),
            Ok(CloudDiskPreserveOutcome::OutcomeUnknown(v)) => ("OUTCOME_UNKNOWN", json!(v), false),
            Err(e) => (
                "REJECTED",
                json!({"code":e.code,"evidence":e.evidence}),
                requires_operator(e.code),
            ),
        };
        self.record_workspace_mutation_result(
            engine,
            claim,
            attempt,
            (outcome, evidence, manual),
            true,
        )
        .await
    }
    async fn record_workspace_mutation_result(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        attempt: Uuid,
        result: (&str, Value, bool),
        preservation: bool,
    ) -> Result<bool, ApiError> {
        let (outcome, evidence, manual) = result;
        let (mut tx, _) = locked(self, engine, claim, false).await?;
        let statement = if preservation {
            "INSERT INTO workspace_snapshot_preserve_results(attempt_id,tenant_id,operation_id,outcome,evidence) VALUES($1,$2,$3,$4,$5)"
        } else {
            "INSERT INTO workspace_delete_results(attempt_id,tenant_id,operation_id,outcome,evidence) VALUES($1,$2,$3,$4,$5)"
        };
        sqlx::query(statement)
            .bind(attempt)
            .bind(claim.tenant_id)
            .bind(claim.operation_id)
            .bind(outcome)
            .bind(evidence)
            .execute(&mut *tx)
            .await?;
        engine.assert_claim(&mut tx, claim).await?;
        if manual {
            sqlx::query("UPDATE operations SET status='WAITING',stage='WAITING_OPERATOR_REVIEW',wait_reason='DISK_DELETE_AUTHORITY_OR_IDENTITY_REVIEW',error='{\"code\":\"OPERATION_FAILED\",\"retryable\":false}'::jsonb,next_attempt_at='infinity',lease_owner=NULL,lease_until=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(claim.tenant_id).bind(claim.operation_id).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(manual)
    }
}

#[cfg(test)]
#[path = "volume_deletion_tests.rs"]
mod tests;
