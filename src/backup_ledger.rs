//! Cold-backup acceptance and durable reconciliation. No guest report can free a
//! workspace hold or manufacture VM termination / independent-vault evidence.
use crate::{
    backup_runtime::{BackupSource, CloneObservation, SnapshotObservation},
    db::{
        Actor, Database, Idempotency, insert_operation, load_operation, reserve_quota,
        runnable_epoch,
    },
    engine::{Claim, OperationEngine},
    error::ApiError,
    model::Operation,
    request::request_digest,
};
use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateBackup {
    pub profile_id: Uuid,
    /// Includes the time needed to publish the immutable objects. Minimum 31 days.
    pub retention_days: u32,
}
#[derive(Clone, Debug, Deserialize, Serialize, sqlx::FromRow)]
pub struct Backup {
    pub id: Uuid,
    pub project_id: Uuid,
    pub workspace_id: Uuid,
    pub instance_id: Uuid,
    pub operation_id: Uuid,
    pub status: String,
    pub version: i64,
    pub consistency: String,
    pub size_gib: i64,
    pub retention_until: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupAccepted {
    pub resource: Backup,
    pub operation: Operation,
    pub workspace_version: i64,
    pub idempotency_expires_at: DateTime<Utc>,
}
pub struct BackupMutationResult {
    pub status: u16,
    pub body: BackupAccepted,
}
#[derive(Clone, sqlx::FromRow)]
pub(crate) struct BackupRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub workspace_id: Uuid,
    pub instance_id: Uuid,
    pub operation_id: Uuid,
    pub profile_id: Uuid,
    pub hold_id: Uuid,
    pub source: Value,
    pub source_generation: i64,
    pub capture_attempt_id: Uuid,
    pub seal_attempt_id: Uuid,
    pub cluster_epoch: Uuid,
    pub status: String,
    pub version: i64,
    pub deadline: DateTime<Utc>,
    pub retention_until: DateTime<Utc>,
}
impl BackupRecord {
    pub fn source(&self) -> Result<BackupSource, ApiError> {
        serde_json::from_value(self.source.clone())
            .map_err(|_| internal("Backup source ledger is invalid"))
    }
}
fn internal(why: &'static str) -> ApiError {
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "BACKUP_LEDGER_INVALID",
        why,
    )
}
fn blocked(why: &'static str) -> ApiError {
    ApiError::conflict("BACKUP_BLOCKED", why)
}
fn verify_profile_key_names(
    profile: &sqlx::postgres::PgRow,
    cloud: &crate::backup_job::BackupCloudSettings,
) -> Result<(), ApiError> {
    for (column, name) in [
        ("password_secret", &cloud.secret_bindings.password.name),
        (
            "signing_private_secret",
            &cloud.secret_bindings.signing_private.name,
        ),
        (
            "signing_public_secret",
            &cloud.secret_bindings.signing_public.name,
        ),
    ] {
        if profile.try_get::<String, _>(column)? != *name {
            return Err(blocked(
                "Backup key identities differ from the approved mounts",
            ));
        }
    }
    Ok(())
}
impl Database {
    pub async fn get_backup(&self, actor: &Actor, id: Uuid) -> Result<Backup, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let value: Backup = sqlx::query_as("SELECT * FROM backups WHERE tenant_id=$1 AND id=$2")
            .bind(actor.tenant_id)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(ApiError::not_found)?;
        Self::authorize_resource(&mut tx, actor, value.project_id, "backups:read").await?;
        tx.commit().await?;
        Ok(value)
    }
    pub async fn create_backup(
        &self,
        actor: &Actor,
        workspace: Uuid,
        request: &CreateBackup,
        key: &str,
        expected: i64,
    ) -> Result<BackupMutationResult, ApiError> {
        self.create_backup_inner(actor, workspace, request, key, expected, None)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn create_backup_with_automation(
        &self,
        actor: &Actor,
        workspace: Uuid,
        request: &CreateBackup,
        key: &str,
        expected: i64,
        fence: &crate::automation_authority::AutomationAcceptanceFence,
    ) -> Result<BackupMutationResult, ApiError> {
        self.create_backup_inner(actor, workspace, request, key, expected, Some(fence))
            .await
    }

    async fn create_backup_inner(
        &self,
        actor: &Actor,
        workspace: Uuid,
        request: &CreateBackup,
        key: &str,
        expected: i64,
        fence: Option<&crate::automation_authority::AutomationAcceptanceFence>,
    ) -> Result<BackupMutationResult, ApiError> {
        if let Some(fence) = fence {
            fence.check_request(request, key, expected)?;
        }
        let mut tx = self.begin(actor.tenant_id).await?;
        if let Some(fence) = fence {
            fence.bind(&mut tx).await?;
        }
        let project: Uuid =
            sqlx::query_scalar("SELECT project_id FROM workspaces WHERE tenant_id=$1 AND id=$2")
                .bind(actor.tenant_id)
                .bind(workspace)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(ApiError::not_found)?;
        Self::authorize_resource(&mut tx, actor, project, "backups:create").await?;
        if request.profile_id.is_nil() || !(31..=3650).contains(&request.retention_days) {
            return Err(ApiError::invalid(
                "A reviewed profile UUID and retention_days 31..3650 are required",
            ));
        }
        let digest = request_digest(request, Some(expected))?;
        let idem = Idempotency::new(actor, workspace, "backups:create", key, &digest);
        if let Some((status, value)) = idem.replay_json(&mut tx).await? {
            Self::authorize_resource(&mut tx, actor, project, "backups:create").await?;
            let body = serde_json::from_value(value)
                .map_err(|_| internal("Invalid backup idempotency receipt"))?;
            tx.commit().await?;
            return Ok(BackupMutationResult { status, body });
        }
        let w = sqlx::query("SELECT * FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
            .bind(actor.tenant_id)
            .bind(workspace)
            .fetch_one(&mut *tx)
            .await?;
        let instance = sqlx::query(
            "SELECT * FROM instances WHERE tenant_id=$1 AND workspace_id=$2 FOR UPDATE",
        )
        .bind(actor.tenant_id)
        .bind(workspace)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
        Self::authorize_resource(&mut tx, actor, project, "backups:create").await?;
        if w.try_get::<i64, _>("spec_version")? != expected {
            return Err(ApiError::new(
                StatusCode::PRECONDITION_FAILED,
                "VERSION_MISMATCH",
                "The workspace has changed",
            ));
        }
        if w.try_get::<String, _>("status")? != "AVAILABLE"
            || w.try_get::<Option<Uuid>, _>("active_operation_id")?
                .is_some()
            || w.try_get::<Option<DateTime<Utc>>, _>("delete_requested_at")?
                .is_some()
        {
            return Err(blocked("Cold backup requires an available workspace"));
        }
        let ready: bool = sqlx::query_scalar("SELECT sandbox_workspace_cold_backup_ready($1,$2)")
            .bind(actor.tenant_id)
            .bind(workspace)
            .fetch_one(&mut *tx)
            .await?;
        let held: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM workspace_holds h WHERE h.tenant_id=$1 AND h.workspace_id=$2 AND h.kind IN('BACKUP','RESTORE') AND NOT EXISTS(SELECT 1 FROM workspace_hold_releases r WHERE r.tenant_id=h.tenant_id AND r.hold_id=h.id))")
            .bind(actor.tenant_id).bind(workspace).fetch_one(&mut *tx).await?;
        if !ready || held {
            return Err(blocked(
                "STOPPED and trusted termination/cleanup for every historical writer are required",
            ));
        }
        let epoch = runnable_epoch(&mut tx).await?;
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let deadline = now + Duration::hours(6);
        let profile = sqlx::query("SELECT * FROM backup_profiles WHERE id=$1 AND enabled AND cluster_epoch=$2 AND certified_until>=$3")
            .bind(request.profile_id).bind(epoch).bind(deadline).fetch_optional(&mut *tx).await?.ok_or_else(|| blocked("A current certified backup profile is required"))?;
        let cloud: crate::backup_job::BackupCloudSettings =
            serde_json::from_value(profile.try_get("settings")?)
                .map_err(|_| blocked("Approved backup cloud configuration is invalid"))?;
        cloud
            .validate()
            .map_err(|_| blocked("Approved backup cloud configuration is invalid"))?;
        verify_profile_key_names(&profile, &cloud)?;
        if request.retention_days > u32::from(cloud.vault_retention_days) {
            return Err(blocked(
                "Requested retention exceeds the approved locked vault retention",
            ));
        }
        let instance_id: Uuid = instance.try_get("id")?;
        let generation: i64 = instance.try_get("runtime_generation")?;
        let permit = sqlx::query("SELECT p.* FROM launch_permits p JOIN local_termination_proofs proof ON proof.tenant_id=p.tenant_id AND proof.permit_id=p.id JOIN termination_cleanup_receipts c ON c.tenant_id=proof.tenant_id AND c.proof_id=proof.id WHERE p.tenant_id=$1 AND p.instance_id=$2 AND p.generation=$3 AND p.launch_id=$4 AND p.pod_uid=$5 AND p.cluster_epoch=$6 AND proof.id=$7")
            .bind(actor.tenant_id).bind(instance_id).bind(generation).bind(instance.try_get::<Uuid,_>("launch_id")?)
            .bind(instance.try_get::<Option<Uuid>,_>("pod_uid")?).bind(epoch).bind(instance.try_get::<Option<Uuid>,_>("last_termination_proof_id")?)
            .fetch_optional(&mut *tx).await?.ok_or_else(|| blocked("Source volume identity lacks a trusted closed launch"))?;
        let id = fence.map_or_else(Uuid::new_v4, |f| f.produced_resource_id);
        let operation = Uuid::new_v4();
        let hold = Uuid::new_v4();
        let capture = Uuid::new_v4();
        let seal = Uuid::new_v4();
        let size: i64 = w.try_get("size_gib")?;
        let source = BackupSource {
            tenant_id: actor.tenant_id,
            project_id: project,
            workspace_id: workspace,
            backup_id: id,
            cluster_epoch: epoch,
            namespace: w.try_get("namespace")?,
            pvc_name: w.try_get("pvc_name")?,
            pvc_uid: permit.try_get("pvc_uid")?,
            pv_name: permit.try_get("pv_name")?,
            pv_uid: permit.try_get("pv_uid")?,
            cloud_disk: permit.try_get("csi_volume_handle")?,
            storage_class: w.try_get("storage_class")?,
            snapshot_class: profile.try_get("snapshot_class")?,
            size_bytes: u64::try_from(size)
                .ok()
                .and_then(|v| v.checked_mul(1024_u64.pow(3)))
                .ok_or_else(|| internal("Invalid volume size"))?,
        };
        source
            .validate()
            .map_err(|_| blocked("Source volume is outside the certified backup profile"))?;
        insert_operation(&mut tx,actor,operation,project,instance_id,workspace,"BACKUP",&json!({"backup_id":id,"profile_id":request.profile_id,"consistency":"STOPPED_CONSISTENT","retention_days":request.retention_days}),deadline).await?;
        sqlx::query("INSERT INTO workspace_holds(id,tenant_id,project_id,workspace_id,kind,reference_id,source_generation,source_pvc_uid,reason) VALUES($1,$2,$3,$4,'BACKUP',$5,$6,$7,'Cold backup source and unresolved isolated attempts')")
            .bind(hold).bind(actor.tenant_id).bind(project).bind(workspace).bind(id).bind(generation).bind(source.pvc_uid).execute(&mut *tx).await?;
        let resource: Backup = sqlx::query_as("INSERT INTO backups(id,tenant_id,project_id,workspace_id,instance_id,operation_id,profile_id,hold_id,source_permit_id,source_generation,cluster_epoch,source,capture_attempt_id,seal_attempt_id,size_gib,retention_until,deadline,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$18) RETURNING *")
            .bind(id).bind(actor.tenant_id).bind(project).bind(workspace).bind(instance_id).bind(operation).bind(request.profile_id).bind(hold).bind(permit.try_get::<Uuid,_>("id")?).bind(generation).bind(epoch).bind(json!(source)).bind(capture).bind(seal).bind(size).bind(now+Duration::days(i64::from(request.retention_days))).bind(deadline).bind(now).fetch_one(&mut *tx).await?;
        for (attempt, stage) in [(capture, "CAPTURE"), (seal, "SEAL")] {
            sqlx::query(
                "INSERT INTO backup_attempts(id,tenant_id,backup_id,stage) VALUES($1,$2,$3,$4)",
            )
            .bind(attempt)
            .bind(actor.tenant_id)
            .bind(id)
            .bind(stage)
            .execute(&mut *tx)
            .await?;
        }
        let snapshot = serde_json::to_value(
            source
                .snapshot()
                .map_err(|_| internal("Snapshot intent invalid"))?,
        )
        .map_err(|_| internal("Snapshot encoding failed"))?;
        resource_intent(
            &mut tx,
            actor.tenant_id,
            id,
            None,
            "SOURCE_SNAPSHOT",
            &source.namespace,
            &source.snapshot_name(),
            Some(&snapshot),
        )
        .await?;
        reserve_quota(
            &mut tx,
            actor,
            project,
            operation,
            id,
            capture,
            &[
                ("BACKUP_GIB", size),
                ("BACKUP_TEMP_GIB", size),
                ("CPU_MILLIS", 2000),
                ("MEMORY_MIB", 2048),
            ],
        )
        .await?;
        sqlx::query("UPDATE workspaces SET spec_version=spec_version+1,updated_at=$3 WHERE tenant_id=$1 AND id=$2").bind(actor.tenant_id).bind(workspace).bind(now).execute(&mut *tx).await?;
        // Producer inserts the operation before its backup FK exists; refresh routing after intent.
        sqlx::query(
            "UPDATE operations SET next_attempt_at=next_attempt_at WHERE tenant_id=$1 AND id=$2",
        )
        .bind(actor.tenant_id)
        .bind(operation)
        .execute(&mut *tx)
        .await?;
        let operation = load_operation(&mut tx, actor.tenant_id, operation).await?;
        let body = BackupAccepted {
            resource,
            operation,
            workspace_version: expected + 1,
            idempotency_expires_at: now + Duration::days(7),
        };
        idem.persist_json(
            &mut tx,
            project,
            body.operation.id,
            id,
            &json!(&body),
            202,
            now,
            body.idempotency_expires_at,
        )
        .await?;
        sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details) VALUES($1,$2,$3,$4,$5,$6,'backups:create','ACCEPTED',$7)")
            .bind(actor.tenant_id).bind(project).bind(actor.principal_id).bind(actor.request_id).bind(body.operation.id).bind(id).bind(json!({"workspace_id":workspace,"consistency":"STOPPED_CONSISTENT","source_generation":generation})).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload) VALUES($1,$2,$3,1,'backup.accepted',$4,$5,$6)")
            .bind(actor.tenant_id).bind(project).bind(id).bind(body.operation.id).bind(actor.request_id).bind(json!({"status":"QUEUED","workspace_id":workspace})).execute(&mut *tx).await?;
        Self::authorize_resource(&mut tx, actor, project, "backups:create").await?;
        tx.commit().await?;
        Ok(BackupMutationResult { status: 202, body })
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn resource_intent(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    backup: Uuid,
    attempt: Option<Uuid>,
    kind: &str,
    namespace: &str,
    name: &str,
    object: Option<&Value>,
) -> Result<Uuid, ApiError> {
    let existing=sqlx::query("SELECT id,attempt_id,expected_object FROM backup_resource_intents WHERE tenant_id=$1 AND backup_id=$2 AND kind=$3 AND namespace=$4 AND name=$5")
        .bind(tenant).bind(backup).bind(kind).bind(namespace).bind(name).fetch_optional(&mut **tx).await?;
    if let Some(row) = existing {
        if row.try_get::<Option<Uuid>, _>("attempt_id")? != attempt
            || row.try_get::<Option<Value>, _>("expected_object")?.as_ref() != object
        {
            return Err(blocked("Existing backup resource intent changed"));
        }
        return row.try_get("id").map_err(Into::into);
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO backup_resource_intents(id,tenant_id,backup_id,attempt_id,kind,namespace,name,expected_object) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(id).bind(tenant).bind(backup).bind(attempt).bind(kind).bind(namespace).bind(name).bind(object).execute(&mut **tx).await?;
    Ok(id)
}

pub(crate) async fn lock_backup(
    tx: &mut Transaction<'_, Postgres>,
    engine: &OperationEngine,
    claim: &Claim,
) -> Result<BackupRecord, ApiError> {
    let b: BackupRecord =
        sqlx::query_as("SELECT * FROM backups WHERE tenant_id=$1 AND operation_id=$2")
            .bind(claim.tenant_id)
            .bind(claim.operation_id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(ApiError::not_found)?;
    sqlx::query("SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(b.tenant_id)
        .bind(b.workspace_id)
        .fetch_one(&mut **tx)
        .await?;
    sqlx::query("SELECT id FROM instances WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(b.tenant_id)
        .bind(b.instance_id)
        .fetch_one(&mut **tx)
        .await?;
    let b = sqlx::query_as("SELECT * FROM backups WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(b.tenant_id)
        .bind(b.id)
        .fetch_one(&mut **tx)
        .await?;
    engine.assert_claim(tx, claim).await?;
    Ok(b)
}
pub(crate) async fn authorize_backup(
    tx: &mut Transaction<'_, Postgres>,
    b: &BackupRecord,
) -> Result<(), ApiError> {
    let active: bool = sqlx::query_scalar("SELECT sandbox_backup_authorized($1,$2,true)")
        .bind(b.tenant_id)
        .bind(b.id)
        .fetch_one(&mut **tx)
        .await?;
    if !active {
        return Err(blocked(
            "Backup authority, source closure, deadline or certification is no longer current",
        ));
    }
    Ok(())
}
pub(crate) async fn binding(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    backup: Uuid,
    kind: &str,
) -> Result<Option<Uuid>, ApiError> {
    Ok(sqlx::query_scalar("SELECT b.uid FROM backup_resource_intents r JOIN backup_resource_bindings b ON b.tenant_id=r.tenant_id AND b.intent_id=r.id WHERE r.tenant_id=$1 AND r.backup_id=$2 AND r.kind=$3")
        .bind(tenant).bind(backup).bind(kind).fetch_optional(&mut **tx).await?)
}
pub(crate) async fn bind_resource(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    backup: Uuid,
    intent: Uuid,
    uid: Uuid,
) -> Result<(), ApiError> {
    if uid.is_nil() {
        return Err(internal("Empty remote UID"));
    }
    let old: Option<Uuid> = sqlx::query_scalar(
        "SELECT uid FROM backup_resource_bindings WHERE tenant_id=$1 AND intent_id=$2",
    )
    .bind(tenant)
    .bind(intent)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(old) = old {
        if old != uid {
            return Err(blocked("Recorded Kubernetes UID was replaced"));
        }
        return Ok(());
    }
    sqlx::query("INSERT INTO backup_resource_bindings(intent_id,tenant_id,backup_id,uid) VALUES($1,$2,$3,$4)").bind(intent).bind(tenant).bind(backup).bind(uid).execute(&mut **tx).await?;
    Ok(())
}
pub(crate) async fn advance(
    tx: &mut Transaction<'_, Postgres>,
    b: &BackupRecord,
    status: &str,
) -> Result<(), ApiError> {
    if b.status == status {
        return Ok(());
    }
    sqlx::query("UPDATE backups SET status=$3,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(b.tenant_id).bind(b.id).bind(status).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload) SELECT $1,$2,$3,$4,'backup.progress',$5,request_id,$6 FROM operations WHERE tenant_id=$1 AND id=$5")
        .bind(b.tenant_id).bind(b.project_id).bind(b.id).bind(b.version+1).bind(b.operation_id).bind(json!({"status":status})).execute(&mut **tx).await?;
    Ok(())
}
impl Database {
    pub(crate) async fn record_backup_snapshot(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        observation: &SnapshotObservation,
    ) -> Result<(), ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let b = lock_backup(&mut tx, engine, claim).await?;
        authorize_backup(&mut tx, &b).await?;
        if !matches!(
            b.status.as_str(),
            "QUEUED" | "SNAPSHOT_PENDING" | "SNAPSHOT_READY"
        ) {
            return Err(blocked("Snapshot observation arrived after its stage"));
        }
        let source = b.source()?;
        let intent:Uuid=sqlx::query_scalar("SELECT id FROM backup_resource_intents WHERE tenant_id=$1 AND backup_id=$2 AND kind='SOURCE_SNAPSHOT'").bind(b.tenant_id).bind(b.id).fetch_one(&mut *tx).await?;
        bind_resource(&mut tx, b.tenant_id, b.id, intent, observation.snapshot_uid).await?;
        if let Some(ready) = &observation.ready {
            // PostgreSQL timestamps are microsecond precision. Use the same
            // canonical precision as the runtime CSI observer on every replay.
            let data_timestamp =
                DateTime::<Utc>::from_timestamp_micros(ready.created_at.timestamp_micros())
                    .ok_or_else(|| internal("Snapshot time invalid"))?;
            let content = resource_intent(
                &mut tx,
                b.tenant_id,
                b.id,
                None,
                "SOURCE_CONTENT",
                "",
                &ready.content_name,
                None,
            )
            .await?;
            bind_resource(&mut tx, b.tenant_id, b.id, content, ready.content_uid).await?;
            let old:Option<(Uuid,Uuid,String,DateTime<Utc>,i64)>=sqlx::query_as("SELECT snapshot_uid,content_uid,cloud_snapshot,data_timestamp,size_bytes FROM backup_snapshot_receipts WHERE tenant_id=$1 AND backup_id=$2")
                .bind(b.tenant_id).bind(b.id).fetch_optional(&mut *tx).await?;
            let size = i64::try_from(ready.restore_size)
                .map_err(|_| internal("Snapshot size overflow"))?;
            if let Some(old) = old {
                if old
                    != (
                        ready.snapshot_uid,
                        ready.content_uid,
                        ready.cloud_snapshot.clone(),
                        data_timestamp,
                        size,
                    )
                {
                    return Err(blocked("Snapshot receipt changed"));
                }
            } else {
                if ready.snapshot_uid != observation.snapshot_uid
                    || ready.restore_size != source.size_bytes
                {
                    return Err(blocked("Snapshot receipt identity mismatch"));
                }
                sqlx::query("INSERT INTO backup_snapshot_receipts(backup_id,tenant_id,snapshot_uid,content_uid,content_name,cloud_snapshot,data_timestamp,size_bytes) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
                    .bind(b.id).bind(b.tenant_id).bind(ready.snapshot_uid).bind(ready.content_uid).bind(&ready.content_name).bind(&ready.cloud_snapshot).bind(data_timestamp).bind(size).execute(&mut *tx).await?;
            }
            advance(&mut tx, &b, "SNAPSHOT_READY").await?;
        } else {
            advance(&mut tx, &b, "SNAPSHOT_PENDING").await?;
        }
        tx.commit().await?;
        Ok(())
    }
    pub(crate) async fn record_backup_clone(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        observation: &CloneObservation,
    ) -> Result<(), ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let b = lock_backup(&mut tx, engine, claim).await?;
        authorize_backup(&mut tx, &b).await?;
        if !matches!(
            b.status.as_str(),
            "CLONE_PENDING" | "CAPTURE_PENDING" | "CAPTURE_RUNNING"
        ) {
            return Err(blocked("Clone observation arrived after its stage"));
        }
        for (kind, uid) in [
            ("CLONE_CONTENT", observation.delegated_content_uid),
            ("CLONE_SNAPSHOT", observation.delegated_snapshot_uid),
            ("CLONE_PVC", observation.pvc_uid),
        ] {
            let intent:Uuid=sqlx::query_scalar("SELECT id FROM backup_resource_intents WHERE tenant_id=$1 AND backup_id=$2 AND kind=$3").bind(b.tenant_id).bind(b.id).bind(kind).fetch_one(&mut *tx).await?;
            bind_resource(&mut tx, b.tenant_id, b.id, intent, uid).await?;
        }
        if let Some(volume) = &observation.bound {
            let source = b.source()?;
            if volume.pvc_uid != observation.pvc_uid
                || volume.pvc_uid == source.pvc_uid
                || volume.pv_uid == source.pv_uid
                || volume.cloud_disk == source.cloud_disk
                || volume.size_bytes != source.size_bytes
            {
                return Err(blocked("Clone is not an independent exact block volume"));
            }
            let intent = resource_intent(
                &mut tx,
                b.tenant_id,
                b.id,
                Some(b.capture_attempt_id),
                "CLONE_PV",
                "",
                &volume.pv_name,
                None,
            )
            .await?;
            bind_resource(&mut tx, b.tenant_id, b.id, intent, volume.pv_uid).await?;
            let old:Option<Value>=sqlx::query_scalar("SELECT jsonb_build_object('pvc_uid',pvc_uid,'pv_uid',pv_uid,'pv_name',pv_name,'cloud_disk',cloud_disk,'size_bytes',size_bytes) FROM backup_clone_receipts WHERE tenant_id=$1 AND attempt_id=$2").bind(b.tenant_id).bind(b.capture_attempt_id).fetch_optional(&mut *tx).await?;
            if let Some(old) = old {
                if old != json!(volume) {
                    return Err(blocked("Clone receipt changed"));
                }
            } else {
                sqlx::query("INSERT INTO backup_clone_receipts(attempt_id,tenant_id,backup_id,pvc_uid,pv_uid,pv_name,cloud_disk,size_bytes) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
                .bind(b.capture_attempt_id).bind(b.tenant_id).bind(b.id).bind(volume.pvc_uid).bind(volume.pv_uid).bind(&volume.pv_name).bind(&volume.cloud_disk).bind(i64::try_from(volume.size_bytes).map_err(|_|internal("Clone size overflow"))?).execute(&mut *tx).await?;
            }
        }
        // WFFC needs the guarded Job Pod to schedule before its Block volume binds.
        // Nodeguard registration still requires the exact bound PVC/PV receipt.
        if b.status == "CLONE_PENDING" {
            advance(&mut tx, &b, "CAPTURE_PENDING").await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

pub(crate) struct StoragePlan {
    pub cloud: crate::backup_job::BackupCloudSettings,
    pub backup: BackupRecord,
    pub source: BackupSource,
    pub snapshot: Option<crate::backup_runtime::SnapshotReady>,
    pub known_snapshot: crate::backup_runtime::SnapshotKnown,
    pub block: crate::backup_manifest::BackupBlockContext,
    pub known_clone: crate::backup_runtime::CloneKnown,
}
impl Database {
    pub(crate) async fn prepare_backup_storage(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<StoragePlan, ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let mut b = lock_backup(&mut tx, engine, claim).await?;
        authorize_backup(&mut tx, &b).await?;
        let source = b.source()?;
        let settings: Value =
            sqlx::query_scalar("SELECT settings FROM backup_profiles WHERE id=$1")
                .bind(b.profile_id)
                .fetch_one(&mut *tx)
                .await?;
        let cloud =
            serde_json::from_value(settings).map_err(|_| internal("Backup profile invalid"))?;
        let class: String =
            sqlx::query_scalar("SELECT clone_storage_class FROM backup_profiles WHERE id=$1")
                .bind(b.profile_id)
                .fetch_one(&mut *tx)
                .await?;
        let block = crate::backup_manifest::BackupBlockContext {
            backup_id: b.id,
            attempt_id: b.capture_attempt_id,
            storage_class: class,
            size_bytes: source.size_bytes,
            snapshot_name: Some(source.snapshot_name()),
        };
        let row = sqlx::query(
            "SELECT * FROM backup_snapshot_receipts WHERE tenant_id=$1 AND backup_id=$2",
        )
        .bind(b.tenant_id)
        .bind(b.id)
        .fetch_optional(&mut *tx)
        .await?;
        let snapshot = row
            .map(
                |r| -> Result<crate::backup_runtime::SnapshotReady, ApiError> {
                    Ok(crate::backup_runtime::SnapshotReady {
                        snapshot_uid: r.try_get("snapshot_uid")?,
                        content_uid: r.try_get("content_uid")?,
                        content_name: r.try_get("content_name")?,
                        cloud_snapshot: r.try_get("cloud_snapshot")?,
                        created_at: r.try_get("data_timestamp")?,
                        restore_size: u64::try_from(r.try_get::<i64, _>("size_bytes")?)
                            .map_err(|_| internal("Stored snapshot size invalid"))?,
                    })
                },
            )
            .transpose()?;
        if b.status == "SNAPSHOT_READY" {
            let ready = snapshot
                .as_ref()
                .ok_or_else(|| internal("Snapshot receipt missing"))?;
            let content = serde_json::to_value(
                crate::backup_runtime::clone_content(&source, ready)
                    .map_err(|_| internal("Static clone content invalid"))?,
            )
            .map_err(|_| internal("Clone encoding failed"))?;
            let copy = serde_json::to_value(
                crate::backup_runtime::clone_snapshot(&source)
                    .map_err(|_| internal("Static snapshot invalid"))?,
            )
            .map_err(|_| internal("Clone encoding failed"))?;
            let pvc = crate::backup_runtime::scoped_block_pvc(&source, &block)
                .map_err(|_| internal("Block intent invalid"))?;
            for (kind, ns, name, v) in [
                ("CLONE_CONTENT", "", source.snapshot_name(), content),
                (
                    "CLONE_SNAPSHOT",
                    crate::backup_manifest::NAMESPACE,
                    source.snapshot_name(),
                    copy,
                ),
                (
                    "CLONE_PVC",
                    crate::backup_manifest::NAMESPACE,
                    crate::backup_manifest::block_pvc_name(b.capture_attempt_id),
                    pvc,
                ),
            ] {
                resource_intent(
                    &mut tx,
                    b.tenant_id,
                    b.id,
                    Some(b.capture_attempt_id),
                    kind,
                    ns,
                    &name,
                    Some(&v),
                )
                .await?;
            }
            advance(&mut tx, &b, "CLONE_PENDING").await?;
            b.status = "CLONE_PENDING".into();
            b.version += 1;
        }
        let known_snapshot = crate::backup_runtime::SnapshotKnown {
            snapshot_uid: binding(&mut tx, b.tenant_id, b.id, "SOURCE_SNAPSHOT").await?,
            content_uid: binding(&mut tx, b.tenant_id, b.id, "SOURCE_CONTENT").await?,
        };
        let known_clone = crate::backup_runtime::CloneKnown {
            delegated_content_uid: binding(&mut tx, b.tenant_id, b.id, "CLONE_CONTENT").await?,
            delegated_snapshot_uid: binding(&mut tx, b.tenant_id, b.id, "CLONE_SNAPSHOT").await?,
            pvc_uid: binding(&mut tx, b.tenant_id, b.id, "CLONE_PVC").await?,
            pv_uid: binding(&mut tx, b.tenant_id, b.id, "CLONE_PV").await?,
        };
        tx.commit().await?;
        Ok(StoragePlan {
            cloud,
            backup: b,
            source,
            snapshot,
            known_snapshot,
            block,
            known_clone,
        })
    }
}
#[cfg(test)]
#[path = "backup_ledger_tests.rs"]
pub(crate) mod tests;

#[derive(Clone)]
pub(crate) struct JobPlan {
    pub clone_storage_class: String,
    pub backup: BackupRecord,
    pub context: crate::backup_manifest::BackupManifestContext,
    pub cloud: crate::backup_job::BackupCloudSettings,
    pub deadline: DateTime<Utc>,
    pub known_config: Option<Uuid>,
    pub known_job: Option<Uuid>,
    pub known_pod: Option<Uuid>,
}
pub(crate) async fn attempt_binding(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    attempt: Uuid,
    kind: &str,
) -> Result<Option<Uuid>, ApiError> {
    Ok(sqlx::query_scalar("SELECT rb.uid FROM backup_resource_intents r JOIN backup_resource_bindings rb ON rb.tenant_id=r.tenant_id AND rb.intent_id=r.id WHERE r.tenant_id=$1 AND r.attempt_id=$2 AND r.kind=$3")
  .bind(tenant).bind(attempt).bind(kind).fetch_optional(&mut **tx).await?)
}
impl Database {
    pub(crate) async fn prepare_backup_job(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<JobPlan, ApiError> {
        use crate::{
            backup_job::BackupCloudSettings,
            backup_manifest::{BackupManifestContext, block_pvc_name, build_backup_manifests},
            nodeguard::protocol::BackupStage,
        };
        let mut tx = self.begin(claim.tenant_id).await?;
        let b = lock_backup(&mut tx, engine, claim).await?;
        let stage = match b.status.as_str() {
            "CAPTURE_PENDING" | "CAPTURE_RUNNING" | "CAPTURE_CLOSING" => BackupStage::Capture,
            "SEAL_PENDING" | "SEAL_RUNNING" | "SEAL_CLOSING" => BackupStage::Seal,
            _ => return Err(blocked("Backup is not in a Job stage")),
        };
        let closing = b.status.ends_with("CLOSING");
        if !closing {
            authorize_backup(&mut tx, &b).await?;
        }
        let profile = sqlx::query("SELECT * FROM backup_profiles WHERE id=$1")
            .bind(b.profile_id)
            .fetch_one(&mut *tx)
            .await?;
        let cloud: BackupCloudSettings = serde_json::from_value(profile.try_get("settings")?)
            .map_err(|_| internal("Backup profile cloud settings invalid"))?;
        if closing {
            cloud.validate_historical()
        } else {
            cloud.validate()
        }
        .map_err(|_| internal("Backup cloud identity invalid"))?;
        verify_profile_key_names(&profile, &cloud)?;
        let attempt = if stage == BackupStage::Capture {
            b.capture_attempt_id
        } else {
            b.seal_attempt_id
        };
        let old: Option<(Value, DateTime<Utc>)> = sqlx::query_as(
            "SELECT context,deadline FROM backup_job_contexts WHERE tenant_id=$1 AND attempt_id=$2",
        )
        .bind(b.tenant_id)
        .bind(attempt)
        .fetch_optional(&mut *tx)
        .await?;
        let (context, deadline) = if let Some((old, deadline)) = old {
            (
                serde_json::from_value(old)
                    .map_err(|_| internal("Backup context encoding invalid"))?,
                deadline,
            )
        } else {
            if closing {
                return Err(blocked("Closing attempt has no persisted context"));
            }
            let source = b.source()?;
            let snapshot = sqlx::query(
                "SELECT * FROM backup_snapshot_receipts WHERE tenant_id=$1 AND backup_id=$2",
            )
            .bind(b.tenant_id)
            .bind(b.id)
            .fetch_one(&mut *tx)
            .await?;
            let clone = attempt_binding(&mut tx, b.tenant_id, b.capture_attempt_id, "CLONE_PVC")
                .await?
                .ok_or_else(|| blocked("Clone PVC UID required before Job intent"))?;
            let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(&mut *tx)
                .await?;
            let deadline = (now + Duration::seconds(7180)).min(b.deadline);
            let seconds = u32::try_from((deadline - now).num_seconds())
                .map_err(|_| blocked("Backup job deadline elapsed"))?;
            if seconds == 0 {
                return Err(blocked("Backup job deadline elapsed"));
            }
            let mut config = json!(cloud);
            let o = config
                .as_object_mut()
                .ok_or_else(|| internal("Cloud object invalid"))?;
            let image: String = profile.try_get("image")?;
            let digest = image
                .split_once('@')
                .map(|(_, d)| d)
                .ok_or_else(|| internal("Backup image digest invalid"))?;
            for (k, v) in [
                ("protocol", json!(1)),
                ("tenant_id", json!(b.tenant_id)),
                ("project_id", json!(b.project_id)),
                ("backup_id", json!(b.id)),
                ("source_instance_id", json!(b.instance_id)),
                ("source_generation", json!(b.source_generation)),
                ("source_pvc_uid", json!(source.pvc_uid)),
                (
                    "snapshot_content_uid",
                    json!(snapshot.try_get::<Uuid, _>("content_uid")?),
                ),
                ("clone_pvc_uid", json!(clone)),
                ("seal_attempt_id", json!(b.seal_attempt_id)),
                ("cluster_epoch", json!(b.cluster_epoch)),
                ("size_bytes", json!(source.size_bytes)),
                (
                    "data_timestamp",
                    json!(snapshot.try_get::<DateTime<Utc>, _>("data_timestamp")?),
                ),
                ("consistency", json!("STOPPED_CONSISTENT")),
                ("retention_until", json!(b.retention_until)),
                ("deadline", json!(deadline)),
                ("template_digest", json!(digest)),
                (
                    "runtime_certification_sha256",
                    json!(profile.try_get::<String, _>("certification_sha256")?),
                ),
            ] {
                o.insert(k.into(), v);
            }
            let context = BackupManifestContext {
                tenant_id: b.tenant_id,
                project_id: b.project_id,
                backup_id: b.id,
                attempt_id: attempt,
                cluster_epoch: b.cluster_epoch,
                stage,
                image,
                certification_sha256: profile.try_get("certification_sha256")?,
                deadline_seconds: seconds,
                config_json: config.to_string(),
                password_secret: profile.try_get("password_secret")?,
                signing_private_secret: profile.try_get("signing_private_secret")?,
                signing_public_secret: profile.try_get("signing_public_secret")?,
                block_pvc: if stage == BackupStage::Capture {
                    Some(block_pvc_name(attempt))
                } else {
                    None
                },
                expected_manifest_sha256: None,
            };
            let objects = build_backup_manifests(&context)
                .map_err(|_| internal("Approved backup manifest invalid"))?;
            if stage == BackupStage::Seal {
                let closed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM backup_termination_proofs p JOIN backup_cleanup_receipts c ON c.tenant_id=p.tenant_id AND c.proof_id=p.id WHERE p.tenant_id=$1 AND p.attempt_id=$2)").bind(b.tenant_id).bind(b.capture_attempt_id).fetch_one(&mut *tx).await?;
                if !closed {
                    return Err(blocked(
                        "Mutable repository may only be sealed after capture VM and Pod cleanup",
                    ));
                }
            }
            sqlx::query("INSERT INTO backup_job_contexts(attempt_id,tenant_id,backup_id,context,deadline) VALUES($1,$2,$3,$4,$5)").bind(attempt).bind(b.tenant_id).bind(b.id).bind(json!(context)).bind(deadline).execute(&mut *tx).await?;
            for (kind, name, v) in [
                (
                    "CONFIG",
                    crate::backup_manifest::config_name(attempt),
                    objects.config_map,
                ),
                (
                    "JOB",
                    crate::nodeguard::protocol::backup_job_name(attempt, stage),
                    objects.job,
                ),
            ] {
                resource_intent(
                    &mut tx,
                    b.tenant_id,
                    b.id,
                    Some(attempt),
                    kind,
                    crate::backup_manifest::NAMESPACE,
                    &name,
                    Some(&v),
                )
                .await?;
            }
            (context, deadline)
        };
        let known_config = attempt_binding(&mut tx, b.tenant_id, attempt, "CONFIG").await?;
        let known_job = attempt_binding(&mut tx, b.tenant_id, attempt, "JOB").await?;
        let known_pod = attempt_binding(&mut tx, b.tenant_id, attempt, "POD").await?;
        tx.commit().await?;
        Ok(JobPlan {
            clone_storage_class: profile.try_get("clone_storage_class")?,
            backup: b,
            context,
            cloud,
            deadline,
            known_config,
            known_job,
            known_pod,
        })
    }
    pub(crate) async fn record_backup_job_objects(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        attempt: Uuid,
        config: Uuid,
        job: Uuid,
    ) -> Result<(), ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let b = lock_backup(&mut tx, engine, claim).await?;
        authorize_backup(&mut tx, &b).await?;
        for (kind, uid) in [("CONFIG", config), ("JOB", job)] {
            let intent:Uuid=sqlx::query_scalar("SELECT id FROM backup_resource_intents WHERE tenant_id=$1 AND backup_id=$2 AND attempt_id=$3 AND kind=$4").bind(b.tenant_id).bind(b.id).bind(attempt).bind(kind).fetch_one(&mut *tx).await?;
            bind_resource(&mut tx, b.tenant_id, b.id, intent, uid).await?;
        }
        tx.commit().await?;
        Ok(())
    }
    pub(crate) async fn record_backup_pod(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        attempt: Uuid,
        job: Uuid,
        pod: &crate::backup_job::ObservedBackupPod,
    ) -> Result<(), ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let b = lock_backup(&mut tx, engine, claim).await?;
        authorize_backup(&mut tx, &b).await?;
        let admitted:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM backup_pod_admissions WHERE tenant_id=$1 AND backup_id=$2 AND attempt_id=$3 AND job_uid=$4)").bind(b.tenant_id).bind(b.id).bind(attempt).bind(job).fetch_one(&mut *tx).await?;
        if !admitted {
            return Err(blocked("Pod has no consumed durable admission"));
        }
        let intent = resource_intent(
            &mut tx,
            b.tenant_id,
            b.id,
            Some(attempt),
            "POD",
            crate::backup_manifest::NAMESPACE,
            &pod.name,
            None,
        )
        .await?;
        bind_resource(&mut tx, b.tenant_id, b.id, intent, pod.uid).await?;
        tx.commit().await?;
        Ok(())
    }
}

#[path = "backup_host_ledger.rs"]
mod host_ledger;

#[path = "backup_completion.rs"]
mod completion;

#[cfg(test)]
#[path = "backup_pipeline_tests.rs"]
pub(crate) mod pipeline_tests;

#[cfg(test)]
#[path = "backup_job_create_admission_tests.rs"]
mod job_create_admission_tests;
