//! Durable file intent, cloud object index and single-attempt guest dispatch.
//! Paths and bytes are tenant data; audit contains only identities and hashes.
use crate::{
    db::{
        Actor, Database, Idempotency, insert_operation, load_instance, load_operation,
        reserve_quota, runnable_epoch,
    },
    engine::{Claim, OperationEngine},
    error::ApiError,
    execution::{DispatchIdentity, check_version, lock_workspace, ready_identity},
    file_store::{FILE_PART_BYTES, FilePartIdentity, FilePartReceipt, OssFileReader},
    file_transfer::{
        CreateFileTransfer, FileTransfer, FileTransferAccepted, FileTransferMutationResult,
        path::RelativeFilePath,
        protocol::{FileDirection, FileRequest, PROTOCOL_VERSION, valid_sha},
    },
    model::Instance,
    request::request_digest,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(sqlx::FromRow)]
pub(crate) struct TransferRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub instance_id: Uuid,
    pub workspace_id: Uuid,
    pub operation_id: Uuid,
    pub runtime_generation: i64,
    pub launch_id: Uuid,
    pub pod_uid: Uuid,
    pub cluster_epoch: Uuid,
    pub content_id: Uuid,
    pub direction: String,
    pub path: String,
    pub status: String,
    pub version: i64,
    pub byte_limit: i64,
    pub expected_sha256: Option<String>,
    pub observed_bytes: Option<i64>,
    pub observed_sha256: Option<String>,
    pub replace: bool,
    pub slot_held: bool,
    pub process_status: String,
    pub content_status: String,
    pub storage_writer_status: String,
    pub timeout_policy: String,
    pub deadline: DateTime<Utc>,
    pub content_expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub dispatch_attempt_id: Option<Uuid>,
    pub dispatch_lease_token: Option<i64>,
    pub exec_admission_uid: Option<Uuid>,
}
impl TransferRow {
    pub(crate) fn identity(&self) -> DispatchIdentity {
        DispatchIdentity {
            runtime_generation: self.runtime_generation,
            launch_id: self.launch_id,
            pod_uid: self.pod_uid,
            cluster_epoch: self.cluster_epoch,
        }
    }
    pub(crate) fn direction(&self) -> Result<FileDirection, ApiError> {
        match self.direction.as_str() {
            "UPLOAD" => Ok(FileDirection::Upload),
            "DOWNLOAD" => Ok(FileDirection::Download),
            _ => Err(blocked("INVALID_FILE_INTENT")),
        }
    }
    pub(crate) fn action(&self) -> &'static str {
        if self.direction == "UPLOAD" {
            "files:write"
        } else {
            "files:read"
        }
    }
    pub(crate) fn public(&self) -> Result<FileTransfer, ApiError> {
        Ok(FileTransfer {
            id: self.id,
            tenant_id: self.tenant_id,
            project_id: self.project_id,
            instance_id: self.instance_id,
            workspace_id: self.workspace_id,
            operation_id: self.operation_id,
            runtime_generation: self.runtime_generation,
            direction: self.direction()?,
            path: RelativeFilePath::new(self.path.clone())
                .map_err(|_| blocked("INVALID_FILE_INTENT"))?,
            status: self.status.clone(),
            version: self.version,
            byte_limit: self.byte_limit as u64,
            expected_sha256: self.expected_sha256.clone(),
            observed_bytes: self.observed_bytes.map(|v| v as u64),
            observed_sha256: self.observed_sha256.clone(),
            replace: self.replace,
            slot_held: self.slot_held,
            process_status: self.process_status.clone(),
            content_status: self.content_status.clone(),
            storage_writer_status: self.storage_writer_status.clone(),
            timeout_policy: self.timeout_policy.clone(),
            deadline: self.deadline,
            content_expires_at: self.content_expires_at,
            created_at: self.created_at,
            completed_at: self.completed_at,
        })
    }
}
/// These identities are generated and committed before any OSS request.
#[derive(Clone)]
pub struct FilePartUploadIntent {
    pub receipt: FilePartReceipt,
    pub transfer_version: i64,
    pub write_until: DateTime<Utc>,
    pub put_attempt_id: Uuid,
    pub already_stored: bool,
}
/// Contains only fixed server-selected runtime and content bindings.
pub struct PreparedFileTransfer {
    pub request: FileRequest,
    pub namespace: String,
    pub pod_name: String,
    pub identity: DispatchIdentity,
    pub deadline: DateTime<Utc>,
    pub parts: Vec<FilePartReceipt>,
}
pub struct FileContentSnapshot {
    pub resource: FileTransfer,
    pub parts: Vec<FilePartReceipt>,
    pub content_id: Uuid,
}

impl Database {
    pub async fn get_file_transfer(
        &self,
        actor: &Actor,
        id: Uuid,
    ) -> Result<FileTransfer, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let r = load(&mut tx, actor.tenant_id, id, false).await?;
        Self::authorize_resource(&mut tx, actor, r.project_id, r.action()).await?;
        let result = r.public()?;
        tx.commit().await?;
        Ok(result)
    }
    pub async fn create_file_transfer(
        &self,
        actor: &Actor,
        instance_id: Uuid,
        request: &CreateFileTransfer,
        key: &str,
        expected: i64,
        max_bytes: u64,
    ) -> Result<FileTransferMutationResult, ApiError> {
        let spec = request.validate(max_bytes)?;
        let direction = match spec.direction {
            FileDirection::Upload => "UPLOAD",
            FileDirection::Download => "DOWNLOAD",
        };
        let action = if direction == "UPLOAD" {
            "files:write"
        } else {
            "files:read"
        };
        let mut tx = self.begin(actor.tenant_id).await?;
        let initial = load_instance(&mut tx, actor.tenant_id, instance_id, false).await?;
        Self::authorize_resource(&mut tx, actor, initial.project_id, action).await?;
        Self::authorize_resource(&mut tx, actor, initial.project_id, "instances:hard_stop").await?;
        let digest = request_digest(request, Some(expected))?;
        let idem = Idempotency::new(actor, instance_id, "files:create", key, &digest);
        if let Some((status, value)) = idem.replay_json(&mut tx).await? {
            let body = serde_json::from_value(value).map_err(|_| blocked("INVALID_RECEIPT"))?;
            tx.commit().await?;
            return Ok(FileTransferMutationResult { status, body });
        }
        lock_workspace(&mut tx, actor.tenant_id, initial.workspace_id).await?;
        let instance = load_instance(&mut tx, actor.tenant_id, instance_id, true).await?;
        Self::authorize_resource(&mut tx, actor, instance.project_id, action).await?;
        Self::authorize_resource(&mut tx, actor, instance.project_id, "instances:hard_stop")
            .await?;
        check_version(instance.spec_version, expected)?;
        let now = db_now(&mut tx).await?;
        let epoch = runnable_epoch(&mut tx).await?;
        let identity = ready_identity(&mut tx, &instance, epoch, now).await?;
        if direction == "UPLOAD" && instance.slot_held {
            return Err(blocked("INSTANCE_BUSY"));
        }
        let deadline = now + Duration::seconds(spec.timeout_seconds as i64);
        if deadline > instance.compute_lease_expires_at {
            return Err(blocked("FILE_TRANSFER_EXCEEDS_LEASE"));
        }
        let id = Uuid::new_v4();
        let operation = Uuid::new_v4();
        let content_id = Uuid::new_v4();
        let stored =
            json!({"transfer_id":id,"direction":direction,"on_timeout":"HARD_STOP_INSTANCE"});
        insert_operation(
            &mut tx,
            actor,
            operation,
            instance.project_id,
            instance.id,
            instance.workspace_id,
            "FILE_TRANSFER",
            &stored,
            deadline,
        )
        .await?;
        sqlx::query("INSERT INTO file_transfers(id,tenant_id,project_id,instance_id,workspace_id,operation_id,runtime_generation,launch_id,pod_uid,cluster_epoch,content_id,direction,path,status,byte_limit,expected_sha256,replace,slot_held,deadline,content_expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)")
   .bind(id).bind(actor.tenant_id).bind(instance.project_id).bind(instance.id).bind(instance.workspace_id).bind(operation).bind(identity.runtime_generation).bind(identity.launch_id).bind(identity.pod_uid).bind(identity.cluster_epoch).bind(content_id).bind(direction).bind(spec.path.as_str()).bind(if direction=="UPLOAD" {"WAITING_UPLOAD"}else{"QUEUED"}).bind(spec.byte_limit as i64).bind(spec.expected_sha256).bind(spec.replace).bind(direction=="UPLOAD").bind(deadline).bind(now+Duration::hours(24)).execute(&mut *tx).await?;
        // Positive quota receipts are required even for an empty file. This is the
        // declared upper bound; a smaller download never silently borrows more.
        reserve_quota(
            &mut tx,
            actor,
            instance.project_id,
            operation,
            instance.id,
            instance.workspace_id,
            &[
                ("FILE_TRANSFERS", 1),
                ("FILE_TRANSFER_BYTES", (spec.byte_limit as i64).max(1)),
            ],
        )
        .await?;
        if direction == "UPLOAD" {
            sqlx::query("UPDATE instances SET slot_held=true,activity_kind='FILE_WRITE',activity_id=$3,activity_generation=runtime_generation,idle_since=NULL,last_activity_at=$4,spec_version=spec_version+1,updated_at=$4 WHERE tenant_id=$1 AND id=$2").bind(actor.tenant_id).bind(instance.id).bind(id).bind(now).execute(&mut *tx).await?;
        } else {
            sqlx::query("UPDATE instances SET idle_since=NULL,last_activity_at=$3,spec_version=spec_version+1,updated_at=$3 WHERE tenant_id=$1 AND id=$2").bind(actor.tenant_id).bind(instance.id).bind(now).execute(&mut *tx).await?;
        }
        let row = load(&mut tx, actor.tenant_id, id, false).await?;
        let current = load_instance(&mut tx, actor.tenant_id, instance.id, false).await?;
        event(&mut tx,actor,&row,"files:create",json!({"direction":direction,"instance_id":instance.id,"byte_limit":spec.byte_limit,"on_timeout":"HARD_STOP_INSTANCE"})).await?;
        let body = FileTransferAccepted {
            resource: row.public()?,
            operation: load_operation(&mut tx, actor.tenant_id, operation).await?,
            instance_version: current.spec_version,
            idempotency_expires_at: now + Duration::days(7),
        };
        idem.persist_json(
            &mut tx,
            instance.project_id,
            operation,
            id,
            &serde_json::to_value(&body).map_err(|_| blocked("INVALID_RECEIPT"))?,
            202,
            now,
            body.idempotency_expires_at,
        )
        .await?;
        // Audit stream head locks can cross the lease/deadline. Revalidate before
        // committing any reservation or slot ownership after that wait.
        let commit_now = db_now(&mut tx).await?;
        let commit_epoch = runnable_epoch(&mut tx).await?;
        ready_identity(&mut tx, &current, commit_epoch, commit_now).await?;
        if commit_now >= deadline {
            return Err(blocked("FILE_TRANSFER_DEADLINE_EXPIRED"));
        }
        tx.commit().await?;
        Ok(FileTransferMutationResult { status: 202, body })
    }
    /// Durable part reservation comes before PUT. An ambiguous PUT remains indexed
    /// and charged, including when publication never reaches the database.
    #[allow(clippy::too_many_arguments)]
    pub async fn begin_file_part_upload(
        &self,
        actor: &Actor,
        id: Uuid,
        index: u32,
        length: u64,
        sha: &str,
        expected: i64,
    ) -> Result<FilePartUploadIntent, ApiError> {
        if length == 0 || length > FILE_PART_BYTES as u64 || index >= 100 || !valid_sha(sha) {
            return Err(ApiError::invalid(
                "A file part requires 1..=1 MiB and a lowercase SHA-256",
            ));
        }
        let (mut tx, r, instance) = lock_transfer(self, actor.tenant_id, id).await?;
        authorize_upload(&mut tx, actor, &r, &instance).await?;
        let identity = FilePartIdentity {
            tenant_id: actor.tenant_id,
            transfer_id: id,
            content_id: r.content_id,
            index,
        };
        let receipt = FilePartReceipt {
            identity,
            object_key: identity
                .object_key()
                .map_err(|_| blocked("INVALID_FILE_PART"))?,
            byte_length: length,
            sha256: sha.into(),
        };
        let previous = part(&mut tx, actor.tenant_id, id, index).await?;
        if let Some((p, state, until, attempt, put_state)) = previous {
            if p != receipt || state == "CLEANED" {
                return Err(blocked("FILE_PART_CONFLICT"));
            }
            if state != "STORED" || put_state != "ACKED" {
                return Err(blocked("FILE_PART_PUT_OUTCOME_UNKNOWN"));
            }
            let result = FilePartUploadIntent {
                receipt: p,
                transfer_version: r.version,
                write_until: until,
                put_attempt_id: attempt,
                already_stored: true,
            };
            tx.commit().await?;
            return Ok(result);
        }
        check_version(r.version, expected)?;
        let offset = index as u64 * FILE_PART_BYTES as u64;
        if offset >= r.byte_limit as u64
            || length != (r.byte_limit as u64 - offset).min(FILE_PART_BYTES as u64)
        {
            return Err(ApiError::invalid(
                "Part index and length must match the exact declared file size",
            ));
        }
        let write_until = db_now(&mut tx).await? + Duration::seconds(30);
        let put_attempt_id = Uuid::new_v4();
        sqlx::query("INSERT INTO file_transfer_parts(tenant_id,project_id,transfer_id,content_id,part_index,byte_length,sha256,object_key,write_until,put_attempt_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)").bind(actor.tenant_id).bind(r.project_id).bind(id).bind(r.content_id).bind(index as i32).bind(length as i64).bind(sha).bind(&receipt.object_key).bind(write_until).bind(put_attempt_id).execute(&mut *tx).await?;
        // Reserving parts is not an ETag-changing resource mutation; content indexes
        // carry their own immutable identity and can upload concurrently within cap.
        tx.commit().await?;
        Ok(FilePartUploadIntent {
            receipt,
            transfer_version: r.version,
            write_until,
            put_attempt_id,
            already_stored: false,
        })
    }
    pub async fn publish_file_part(
        &self,
        actor: &Actor,
        intent: &FilePartUploadIntent,
        receipt: &FilePartReceipt,
    ) -> Result<(), ApiError> {
        if receipt != &intent.receipt {
            return Err(blocked("FILE_PART_RECEIPT_MISMATCH"));
        }
        receipt
            .validate()
            .map_err(|_| blocked("INVALID_FILE_PART"))?;
        let (mut tx, r, instance) =
            lock_transfer(self, actor.tenant_id, receipt.identity.transfer_id).await?;
        authorize_upload(&mut tx, actor, &r, &instance).await?;
        let (p, status, until, attempt, put_state) =
            part(&mut tx, actor.tenant_id, r.id, receipt.identity.index)
                .await?
                .ok_or_else(|| blocked("FILE_PART_NOT_RESERVED"))?;
        if p != *receipt
            || until != intent.write_until
            || attempt != intent.put_attempt_id
            || status == "CLEANED"
            || put_state == "UNKNOWN"
        {
            return Err(blocked("FILE_PART_RECEIPT_MISMATCH"));
        }
        sqlx::query("UPDATE file_transfer_parts SET status='STORED',put_state='ACKED',stored_at=COALESCE(stored_at,clock_timestamp()) WHERE tenant_id=$1 AND transfer_id=$2 AND part_index=$3").bind(actor.tenant_id).bind(r.id).bind(receipt.identity.index as i32).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    /// All objects are independently read and hashed outside the transaction.
    /// The second authorization/version check precedes FROZEN publication.
    pub async fn commit_file_upload(
        &self,
        actor: &Actor,
        id: Uuid,
        expected: i64,
        key: &str,
        reader: &OssFileReader,
        verified_identity: &crate::auth::VerifiedIdentity,
    ) -> Result<FileTransferMutationResult, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let r = load(&mut tx, actor.tenant_id, id, false).await?;
        Self::authorize_resource(&mut tx, actor, r.project_id, "files:write").await?;
        Self::authorize_resource(&mut tx, actor, r.project_id, "instances:hard_stop").await?;
        let digest = request_digest(&json!({"commit":true}), Some(expected))?;
        let idem = Idempotency::new(actor, id, "files:commit", key, &digest);
        if let Some((status, v)) = idem.replay_json(&mut tx).await? {
            let body = serde_json::from_value(v).map_err(|_| blocked("INVALID_RECEIPT"))?;
            tx.commit().await?;
            return Ok(FileTransferMutationResult { status, body });
        }
        check_version(r.version, expected)?;
        if r.direction != "UPLOAD" || r.status != "WAITING_UPLOAD" || r.content_status != "STAGING"
        {
            return Err(blocked("FILE_CONTENT_CLOSED"));
        }
        let parts = stored_parts(&mut tx, &r).await?;
        validate_parts(&r, &parts, r.byte_limit as u64)?;
        tx.commit().await?;
        let mut hash = Sha256::new();
        let mut length = 0_u64;
        for p in &parts {
            let bytes = reader
                .read_part(p)
                .await
                .map_err(|_| blocked("FILE_CONTENT_VERIFICATION_FAILED"))?;
            length += bytes.len() as u64;
            hash.update(bytes);
        }
        let sha = hex::encode(hash.finalize());
        if length != r.byte_limit as u64 || r.expected_sha256.as_deref() != Some(sha.as_str()) {
            return Err(blocked("FILE_CONTENT_CHECKSUM_MISMATCH"));
        }
        let current_actor = self
            .resolve_actor(verified_identity, actor.tenant_id, actor.request_id)
            .await?;
        if current_actor.principal_id != actor.principal_id
            || chrono::Utc::now().timestamp() >= verified_identity.expires_at
        {
            return Err(ApiError::forbidden());
        }
        let (mut tx, current, instance) = lock_transfer(self, actor.tenant_id, id).await?;
        authorize_upload(&mut tx, actor, &current, &instance).await?;
        check_version(current.version, expected)?;
        let current_parts = stored_parts(&mut tx, &current).await?;
        if current_parts != parts {
            return Err(blocked("FILE_CONTENT_CHANGED"));
        }
        // Serialize the final receipt only after the external reads; never hold the
        // idempotency advisory lock across cloud I/O.
        if let Some((status, v)) = idem.replay_json(&mut tx).await? {
            let body = serde_json::from_value(v).map_err(|_| blocked("INVALID_RECEIPT"))?;
            tx.commit().await?;
            return Ok(FileTransferMutationResult { status, body });
        }
        sqlx::query("UPDATE file_transfers SET content_status='FROZEN',observed_bytes=$3,observed_sha256=$4,status='QUEUED' WHERE tenant_id=$1 AND id=$2").bind(actor.tenant_id).bind(id).bind(length as i64).bind(&sha).execute(&mut *tx).await?;
        sqlx::query("UPDATE operations SET next_attempt_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(actor.tenant_id).bind(current.operation_id).execute(&mut *tx).await?;
        let frozen = load(&mut tx, actor.tenant_id, id, false).await?;
        let now = db_now(&mut tx).await?;
        event(
            &mut tx,
            actor,
            &frozen,
            "files:content_frozen",
            json!({"byte_length":length,"sha256":sha}),
        )
        .await?;
        let body = FileTransferAccepted {
            resource: frozen.public()?,
            operation: load_operation(&mut tx, actor.tenant_id, current.operation_id).await?,
            instance_version: instance.spec_version,
            idempotency_expires_at: now + Duration::days(7),
        };
        idem.persist_json(
            &mut tx,
            current.project_id,
            current.operation_id,
            id,
            &serde_json::to_value(&body).map_err(|_| blocked("INVALID_RECEIPT"))?,
            202,
            now,
            body.idempotency_expires_at,
        )
        .await?;
        authorize_upload_frozen(&mut tx, actor, &frozen, &instance).await?;
        let identity_enabled:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sandbox_resolve_identity($1,$2,$5) x WHERE x.principal_id=$3 AND x.enabled) AND clock_timestamp()<to_timestamp($4::double precision)").bind(&verified_identity.issuer).bind(&verified_identity.subject).bind(actor.principal_id).bind(verified_identity.expires_at).bind(&verified_identity.client_id).fetch_one(&mut *tx).await?;
        if !identity_enabled {
            return Err(ApiError::forbidden());
        }
        tx.commit().await?;
        Ok(FileTransferMutationResult { status: 202, body })
    }
    pub async fn file_content_snapshot(
        &self,
        actor: &Actor,
        id: Uuid,
    ) -> Result<FileContentSnapshot, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let r = load(&mut tx, actor.tenant_id, id, false).await?;
        Self::authorize_resource(&mut tx, actor, r.project_id, "files:read").await?;
        if r.direction != "DOWNLOAD"
            || r.status != "SUCCEEDED"
            || r.content_status != "FROZEN"
            || r.content_expires_at <= db_now(&mut tx).await?
        {
            return Err(blocked("FILE_CONTENT_UNAVAILABLE"));
        }
        let parts = stored_parts(&mut tx, &r).await?;
        validate_parts(
            &r,
            &parts,
            r.observed_bytes
                .ok_or_else(|| blocked("INVALID_FILE_CONTENT"))? as u64,
        )?;
        let result = FileContentSnapshot {
            resource: r.public()?,
            parts,
            content_id: r.content_id,
        };
        tx.commit().await?;
        Ok(result)
    }
    pub async fn begin_file_transfer_dispatch(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        id: Uuid,
        observed: DispatchIdentity,
    ) -> Result<PreparedFileTransfer, ApiError> {
        let (mut tx, r, instance) = lock_transfer(self, claim.tenant_id, id).await?;
        if r.operation_id != claim.operation_id {
            return Err(blocked("WORKER_LEASE_LOST"));
        }
        engine.assert_claim(&mut tx, claim).await?;
        if r.dispatch_attempt_id.is_some() {
            return Err(blocked("DISPATCH_ALREADY_ATTEMPTED"));
        }
        if r.status != "QUEUED" || r.direction == "UPLOAD" && r.content_status != "FROZEN" {
            return Err(blocked("FILE_TRANSFER_NOT_DISPATCHABLE"));
        }
        let now = db_now(&mut tx).await?;
        let epoch = runnable_epoch(&mut tx).await?;
        if ready_identity(&mut tx, &instance, epoch, now).await? != r.identity()
            || r.identity() != observed
            || now >= r.deadline
        {
            return Err(blocked("FILE_TRANSFER_IDENTITY_OR_DEADLINE_CHANGED"));
        }
        if r.direction == "UPLOAD" {
            assert_write_activity(&mut tx, &r).await?;
        }
        let operation=sqlx::query("SELECT actor_principal_id,request_id,kind,request,cancel_requested FROM operations WHERE tenant_id=$1 AND id=$2").bind(claim.tenant_id).bind(claim.operation_id).fetch_one(&mut *tx).await?;
        let actor = Actor {
            authorization: None,
            tenant_id: claim.tenant_id,
            principal_id: operation.try_get("actor_principal_id")?,
            request_id: operation.try_get("request_id")?,
        };
        Self::authorize_resource(&mut tx, &actor, r.project_id, r.action()).await?;
        Self::authorize_resource(&mut tx, &actor, r.project_id, "instances:hard_stop").await?;
        let stored: Value = operation.try_get("request")?;
        if operation.try_get::<String, _>("kind")? != "FILE_TRANSFER"
            || operation.try_get::<bool, _>("cancel_requested")?
            || stored
                != json!({"transfer_id":id,"direction":r.direction,"on_timeout":"HARD_STOP_INSTANCE"})
        {
            return Err(blocked("INVALID_FILE_INTENT"));
        }
        let attempt = Uuid::new_v4();
        let request = FileRequest {
            protocol_version: PROTOCOL_VERSION,
            transfer_id: id,
            dispatch_attempt_id: attempt,
            direction: r.direction()?,
            path: RelativeFilePath::new(r.path.clone())
                .map_err(|_| blocked("INVALID_FILE_INTENT"))?,
            byte_limit: r.byte_limit as u64,
            expected_length: if r.direction == "UPLOAD" {
                Some(r.byte_limit as u64)
            } else {
                None
            },
            expected_sha256: r.expected_sha256.clone(),
            replace: r.replace,
        };
        request
            .validate(crate::file_transfer::protocol::FileBinding {
                transfer_id: id,
                dispatch_attempt_id: attempt,
            })
            .map_err(|_| blocked("INVALID_FILE_INTENT"))?;
        let parts = if r.direction == "UPLOAD" {
            let parts = stored_parts(&mut tx, &r).await?;
            validate_parts(&r, &parts, r.byte_limit as u64)?;
            parts
        } else {
            Vec::new()
        };
        sqlx::query("UPDATE file_transfers SET status='DISPATCHING',process_status='DISPATCHING',dispatch_attempt_id=$3,dispatch_attempted_at=$4,dispatch_lease_token=$5 WHERE tenant_id=$1 AND id=$2").bind(claim.tenant_id).bind(id).bind(attempt).bind(now).bind(claim.lease_token).execute(&mut *tx).await?;
        sqlx::query("UPDATE operations SET stage='DISPATCHING',updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(claim.tenant_id).bind(claim.operation_id).execute(&mut *tx).await?;
        event(
            &mut tx,
            &actor,
            &r,
            "files:dispatch",
            json!({"dispatch_attempt_id":attempt,"automatic_replay_allowed":false}),
        )
        .await?;
        let dispatched = load(&mut tx, claim.tenant_id, id, false).await?;
        assert_gateway(&mut tx, engine, claim, &dispatched, &instance, attempt).await?;
        let (namespace, pod_name): (String, String) =
            sqlx::query_as("SELECT namespace,pod_name FROM instances WHERE tenant_id=$1 AND id=$2")
                .bind(claim.tenant_id)
                .bind(instance.id)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(PreparedFileTransfer {
            request,
            namespace,
            pod_name,
            identity: r.identity(),
            deadline: r.deadline,
            parts,
        })
    }
    pub async fn mark_file_transfer_unknown(
        &self,
        tenant: Uuid,
        id: Uuid,
        attempt: Uuid,
    ) -> Result<(), ApiError> {
        let (mut tx, r, _) = lock_transfer(self, tenant, id).await?;
        if r.dispatch_attempt_id != Some(attempt) {
            return Err(blocked("DISPATCH_IDENTITY_MISMATCH"));
        }
        if matches!(r.status.as_str(), "DISPATCHING" | "RUNNING") {
            sqlx::query("UPDATE file_transfers SET status='OUTCOME_UNKNOWN',process_status='UNKNOWN',content_status=CASE WHEN direction='DOWNLOAD' THEN 'UNAVAILABLE' ELSE content_status END WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).execute(&mut *tx).await?;
            sqlx::query("UPDATE operations SET status='WAITING',stage='OUTCOME_UNKNOWN',wait_reason='FILE_DISPATCH_UNKNOWN_NO_REPLAY',next_attempt_at=clock_timestamp()+interval '5 minutes',lease_owner=NULL,lease_until=NULL,lease_token=lease_token+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND status IN('QUEUED','RUNNING','WAITING')").bind(tenant).bind(r.operation_id).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }
}
pub(crate) async fn load(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    id: Uuid,
    lock: bool,
) -> Result<TransferRow, ApiError> {
    let query = if lock {
        "SELECT f.*,CASE WHEN EXISTS(SELECT 1 FROM file_transfer_parts p WHERE p.tenant_id=f.tenant_id AND p.transfer_id=f.id AND(p.put_state='UNKNOWN' OR p.put_state='PUTTING' AND p.write_until<=clock_timestamp())) THEN 'OUTCOME_UNKNOWN' WHEN EXISTS(SELECT 1 FROM file_transfer_parts p WHERE p.tenant_id=f.tenant_id AND p.transfer_id=f.id AND p.put_state='PUTTING') THEN 'PENDING' ELSE 'ACKNOWLEDGED' END AS storage_writer_status FROM file_transfers f WHERE f.tenant_id=$1 AND f.id=$2 FOR UPDATE OF f"
    } else {
        "SELECT f.*,CASE WHEN EXISTS(SELECT 1 FROM file_transfer_parts p WHERE p.tenant_id=f.tenant_id AND p.transfer_id=f.id AND(p.put_state='UNKNOWN' OR p.put_state='PUTTING' AND p.write_until<=clock_timestamp())) THEN 'OUTCOME_UNKNOWN' WHEN EXISTS(SELECT 1 FROM file_transfer_parts p WHERE p.tenant_id=f.tenant_id AND p.transfer_id=f.id AND p.put_state='PUTTING') THEN 'PENDING' ELSE 'ACKNOWLEDGED' END AS storage_writer_status FROM file_transfers f WHERE f.tenant_id=$1 AND f.id=$2"
    };
    sqlx::query_as(query)
        .bind(tenant)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(ApiError::not_found)
}
pub(crate) async fn lock_transfer(
    db: &Database,
    tenant: Uuid,
    id: Uuid,
) -> Result<(Transaction<'_, Postgres>, TransferRow, Instance), ApiError> {
    let mut tx = db.begin(tenant).await?;
    let initial = load(&mut tx, tenant, id, false).await?;
    lock_workspace(&mut tx, tenant, initial.workspace_id).await?;
    let instance = load_instance(&mut tx, tenant, initial.instance_id, true).await?;
    let r = load(&mut tx, tenant, id, true).await?;
    Ok((tx, r, instance))
}
pub(crate) async fn db_now(tx: &mut Transaction<'_, Postgres>) -> Result<DateTime<Utc>, ApiError> {
    Ok(sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?)
}
pub(crate) fn blocked(code: &'static str) -> ApiError {
    ApiError::conflict(
        code,
        "File transfer cannot safely advance; inspect its current operation and resource",
    )
}
async fn authorize_upload(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    r: &TransferRow,
    i: &Instance,
) -> Result<(), ApiError> {
    if r.direction != "UPLOAD" || r.status != "WAITING_UPLOAD" || r.content_status != "STAGING" {
        return Err(blocked("FILE_CONTENT_CLOSED"));
    }
    authorize_upload_frozen(tx, actor, r, i).await
}
async fn authorize_upload_frozen(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    r: &TransferRow,
    i: &Instance,
) -> Result<(), ApiError> {
    Database::authorize_resource(tx, actor, r.project_id, "files:write").await?;
    Database::authorize_resource(tx, actor, r.project_id, "instances:hard_stop").await?;
    let now = db_now(tx).await?;
    let epoch = runnable_epoch(tx).await?;
    if now >= r.deadline
        || ready_identity(tx, i, epoch, now).await? != r.identity()
        || !r.slot_held
        || !i.slot_held
    {
        return Err(blocked("FILE_TRANSFER_IDENTITY_OR_DEADLINE_CHANGED"));
    }
    assert_write_activity(tx, r).await?;
    Ok(())
}
async fn part(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    id: Uuid,
    index: u32,
) -> Result<Option<(FilePartReceipt, String, DateTime<Utc>, Uuid, String)>, ApiError> {
    let row=sqlx::query("SELECT content_id,byte_length,sha256,object_key,status,write_until,put_attempt_id,put_state FROM file_transfer_parts WHERE tenant_id=$1 AND transfer_id=$2 AND part_index=$3").bind(tenant).bind(id).bind(index as i32).fetch_optional(&mut **tx).await?;
    row.map(|r| {
        Ok((
            FilePartReceipt {
                identity: FilePartIdentity {
                    tenant_id: tenant,
                    transfer_id: id,
                    content_id: r.try_get("content_id")?,
                    index,
                },
                object_key: r.try_get("object_key")?,
                byte_length: r.try_get::<i64, _>("byte_length")? as u64,
                sha256: r.try_get("sha256")?,
            },
            r.try_get("status")?,
            r.try_get("write_until")?,
            r.try_get("put_attempt_id")?,
            r.try_get("put_state")?,
        ))
    })
    .transpose()
}
pub(crate) async fn stored_parts(
    tx: &mut Transaction<'_, Postgres>,
    r: &TransferRow,
) -> Result<Vec<FilePartReceipt>, ApiError> {
    let rows=sqlx::query("SELECT part_index,byte_length,sha256,object_key FROM file_transfer_parts WHERE tenant_id=$1 AND transfer_id=$2 AND content_id=$3 AND status='STORED' ORDER BY part_index").bind(r.tenant_id).bind(r.id).bind(r.content_id).fetch_all(&mut **tx).await?;
    rows.into_iter()
        .map(|p| {
            Ok(FilePartReceipt {
                identity: FilePartIdentity {
                    tenant_id: r.tenant_id,
                    transfer_id: r.id,
                    content_id: r.content_id,
                    index: p.try_get::<i32, _>("part_index")? as u32,
                },
                object_key: p.try_get("object_key")?,
                byte_length: p.try_get::<i64, _>("byte_length")? as u64,
                sha256: p.try_get("sha256")?,
            })
        })
        .collect()
}
pub(crate) fn validate_parts(
    r: &TransferRow,
    parts: &[FilePartReceipt],
    length: u64,
) -> Result<(), ApiError> {
    let count = length.div_ceil(FILE_PART_BYTES as u64);
    if parts.len() as u64 != count || count > 100 || length > r.byte_limit as u64 {
        return Err(blocked("FILE_CONTENT_INCOMPLETE"));
    }
    for (index, p) in parts.iter().enumerate() {
        p.validate().map_err(|_| blocked("INVALID_FILE_PART"))?;
        if p.identity
            != (FilePartIdentity {
                tenant_id: r.tenant_id,
                transfer_id: r.id,
                content_id: r.content_id,
                index: index as u32,
            })
            || p.byte_length
                != (length - index as u64 * FILE_PART_BYTES as u64).min(FILE_PART_BYTES as u64)
        {
            return Err(blocked("FILE_CONTENT_INCOMPLETE"));
        }
    }
    Ok(())
}
pub(crate) async fn event(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    r: &TransferRow,
    action: &str,
    details: Value,
) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details) VALUES($1,$2,$3,$4,$5,$6,$7,'ACCEPTED',$8)").bind(actor.tenant_id).bind(r.project_id).bind(actor.principal_id).bind(actor.request_id).bind(r.operation_id).bind(r.id).bind(action).bind(&details).execute(&mut **tx).await?;
    // Callers may hold either the pre-transition or post-transition snapshot.
    // Publish the version of the current durable row, matching its public ETag.
    let version: i64 =
        sqlx::query_scalar("SELECT version FROM file_transfers WHERE tenant_id=$1 AND id=$2")
            .bind(actor.tenant_id)
            .bind(r.id)
            .fetch_one(&mut **tx)
            .await?;
    sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8)").bind(actor.tenant_id).bind(r.project_id).bind(r.id).bind(version).bind(action).bind(r.operation_id).bind(actor.request_id).bind(details).execute(&mut **tx).await?;
    Ok(())
}

pub(crate) async fn assert_write_activity(
    tx: &mut Transaction<'_, Postgres>,
    r: &TransferRow,
) -> Result<(), ApiError> {
    let valid:bool=sqlx::query_scalar("SELECT slot_held AND activity_id=$3 AND activity_kind='FILE_WRITE' AND activity_generation=$4 FROM instances WHERE tenant_id=$1 AND id=$2").bind(r.tenant_id).bind(r.instance_id).bind(r.id).bind(r.runtime_generation).fetch_one(&mut **tx).await?;
    if !valid {
        return Err(blocked("ACTIVITY_LEDGER_MISMATCH"));
    }
    Ok(())
}

impl Database {
    pub async fn claim_file_transfer(&self, worker_id: &str) -> Result<Option<Claim>, ApiError> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query_as(
            "SELECT tenant_id,operation_id,lease_token FROM sandbox_claim_file_transfer($1)",
        )
        .bind(worker_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result)
    }
    pub async fn begin_download_file_part(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        id: Uuid,
        attempt: Uuid,
        index: u32,
        bytes: &[u8],
    ) -> Result<FilePartUploadIntent, ApiError> {
        if bytes.is_empty() || bytes.len() > FILE_PART_BYTES || index >= 100 {
            return Err(blocked("INVALID_FILE_PART"));
        }
        let (mut tx, r, instance) = lock_transfer(self, claim.tenant_id, id).await?;
        assert_gateway(&mut tx, engine, claim, &r, &instance, attempt).await?;
        if r.direction != "DOWNLOAD" || r.content_status != "STAGING" {
            return Err(blocked("FILE_CONTENT_CLOSED"));
        }
        let previous:(i64,i64)=sqlx::query_as("SELECT count(*),COALESCE(sum(byte_length),0)::bigint FROM file_transfer_parts WHERE tenant_id=$1 AND transfer_id=$2").bind(claim.tenant_id).bind(id).fetch_one(&mut *tx).await?;
        if previous.0 != index as i64
            || previous.1 != index as i64 * FILE_PART_BYTES as i64
            || previous.1 + bytes.len() as i64 > r.byte_limit
        {
            return Err(blocked("FILE_PART_ORDER_OR_LIMIT"));
        }
        let identity = FilePartIdentity {
            tenant_id: claim.tenant_id,
            transfer_id: id,
            content_id: r.content_id,
            index,
        };
        let receipt = FilePartReceipt {
            identity,
            object_key: identity
                .object_key()
                .map_err(|_| blocked("INVALID_FILE_PART"))?,
            byte_length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        };
        let until = db_now(&mut tx).await? + Duration::seconds(30);
        let put_attempt_id = Uuid::new_v4();
        sqlx::query("INSERT INTO file_transfer_parts(tenant_id,project_id,transfer_id,content_id,part_index,byte_length,sha256,object_key,write_until,put_attempt_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)").bind(claim.tenant_id).bind(r.project_id).bind(id).bind(r.content_id).bind(index as i32).bind(bytes.len() as i64).bind(&receipt.sha256).bind(&receipt.object_key).bind(until).bind(put_attempt_id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(FilePartUploadIntent {
            receipt,
            transfer_version: r.version,
            write_until: until,
            put_attempt_id,
            already_stored: false,
        })
    }
    pub async fn publish_download_file_part(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        id: Uuid,
        attempt: Uuid,
        intent: &FilePartUploadIntent,
        receipt: &FilePartReceipt,
    ) -> Result<(), ApiError> {
        if receipt != &intent.receipt {
            return Err(blocked("FILE_PART_RECEIPT_MISMATCH"));
        }
        let (mut tx, r, instance) = lock_transfer(self, claim.tenant_id, id).await?;
        assert_gateway(&mut tx, engine, claim, &r, &instance, attempt).await?;
        let (p, status, _, put_attempt, put_state) =
            part(&mut tx, claim.tenant_id, id, receipt.identity.index)
                .await?
                .ok_or_else(|| blocked("FILE_PART_NOT_RESERVED"))?;
        if p != *receipt
            || status == "CLEANED"
            || put_attempt != intent.put_attempt_id
            || put_state != "PUTTING"
        {
            return Err(blocked("FILE_PART_RECEIPT_MISMATCH"));
        }
        sqlx::query("UPDATE file_transfer_parts SET status='STORED',put_state='ACKED',stored_at=clock_timestamp() WHERE tenant_id=$1 AND transfer_id=$2 AND part_index=$3").bind(claim.tenant_id).bind(id).bind(receipt.identity.index as i32).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn complete_file_transfer_process(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        id: Uuid,
        attempt: Uuid,
        result: &super::transport::CompletedFileProcess,
    ) -> Result<(), ApiError> {
        if result.trusted_exit_code != 0 {
            return Err(blocked("FILE_PROCESS_COMPLETION_UNCONFIRMED"));
        }
        let (mut tx, r, instance) = lock_transfer(self, claim.tenant_id, id).await?;
        assert_gateway(&mut tx, engine, claim, &r, &instance, attempt).await?;
        if r.exec_admission_uid.is_none() {
            return Err(blocked("FILE_PROCESS_NOT_ADMITTED"));
        }
        let claim_until: DateTime<Utc> =
            sqlx::query_scalar("SELECT lease_until FROM operations WHERE tenant_id=$1 AND id=$2")
                .bind(claim.tenant_id)
                .bind(claim.operation_id)
                .fetch_one(&mut *tx)
                .await?;
        let (status, length, sha, content) = match &result.terminal {
            super::transport::FileTerminal::Complete {
                byte_length,
                sha256,
            } => {
                if *byte_length > r.byte_limit as u64 || !valid_sha(sha256) {
                    return Err(blocked("FILE_CONTENT_CHECKSUM_MISMATCH"));
                }
                if r.direction == "UPLOAD" {
                    if *byte_length != r.byte_limit as u64
                        || r.expected_sha256.as_deref() != Some(sha256)
                    {
                        return Err(blocked("FILE_CONTENT_CHECKSUM_MISMATCH"));
                    }
                } else {
                    let parts = stored_parts(&mut tx, &r).await?;
                    validate_parts(&r, &parts, *byte_length)?;
                }
                (
                    "SUCCEEDED",
                    Some(*byte_length as i64),
                    Some(sha256.as_str()),
                    "FROZEN",
                )
            }
            super::transport::FileTerminal::Error(_) => (
                "FAILED",
                None,
                None,
                if r.direction == "DOWNLOAD" {
                    "UNAVAILABLE"
                } else {
                    r.content_status.as_str()
                },
            ),
        };
        sqlx::query("UPDATE file_transfers SET status=$3,slot_held=false,process_status='EXITED',process_exit_code=0,process_exited_at=clock_timestamp(),content_status=$4,observed_bytes=COALESCE(observed_bytes,$5),observed_sha256=COALESCE(observed_sha256,$6),completed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(claim.tenant_id).bind(id).bind(status).bind(content).bind(length).bind(sha).execute(&mut *tx).await?;
        release_dimension(&mut tx, &r, "FILE_TRANSFERS", 1).await?;
        if r.direction == "UPLOAD" {
            sqlx::query("UPDATE instances SET slot_held=false,activity_kind=NULL,activity_id=NULL,activity_generation=NULL,spec_version=spec_version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(claim.tenant_id).bind(r.instance_id).execute(&mut *tx).await?;
        }
        refresh_idle(&mut tx, r.tenant_id, r.instance_id).await?;
        sqlx::query("UPDATE operations SET status='SUCCEEDED',stage='FILE_PROCESS_COMPLETED',lease_owner=NULL,lease_until=NULL,wait_reason=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(claim.tenant_id).bind(claim.operation_id).execute(&mut *tx).await?;
        let actor = operation_actor(&mut tx, &r).await?;
        event(&mut tx,&actor,&r,"files:process_completed",json!({"status":status,"dispatch_attempt_id":attempt,"result_source":"GUEST_REPORTED","vm_termination_confirmed":false,"retained_bytes_released":false})).await?;
        // Completion invalidates operation status, so the last fence is the captured
        // lease token/owner and current epoch rather than assert_claim's RUNNING gate.
        let still:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM operations o CROSS JOIN platform_configuration c WHERE o.tenant_id=$1 AND o.id=$2 AND o.lease_token=$3 AND c.singleton AND c.cluster_epoch=$4) AND $5>clock_timestamp() AND $6>clock_timestamp()").bind(claim.tenant_id).bind(claim.operation_id).bind(claim.lease_token).bind(r.cluster_epoch).bind(r.deadline).bind(claim_until).fetch_one(&mut *tx).await?;
        if !still {
            return Err(blocked("FILE_COMPLETION_FENCED"));
        }
        tx.commit().await?;
        Ok(())
    }
    /// Both directions consent to whole-instance hard stop. Read transfers also
    /// suppress idle and are closed only by authenticated process/whole-VM proof.
    pub async fn stop_file_transfer_for_safety(
        &self,
        tenant: Uuid,
        id: Uuid,
        reason: &str,
    ) -> Result<Option<Uuid>, ApiError> {
        if !matches!(reason, "TIMEOUT" | "TRANSPORT_LOST" | "SECURITY") {
            return Err(ApiError::invalid("Invalid file safety-stop reason"));
        }
        let (mut tx, r, instance) = lock_transfer(self, tenant, id).await?;
        if matches!(r.process_status.as_str(), "EXITED" | "VM_TERMINATED") {
            tx.commit().await?;
            return Ok(None);
        }
        let now = db_now(&mut tx).await?;
        if reason == "TIMEOUT" && now < r.deadline {
            return Err(blocked("FILE_TRANSFER_NOT_DUE"));
        }
        let(current_generation,current_launch,current_pod,current_epoch):(i64,Uuid,Option<Uuid>,Option<Uuid>)=sqlx::query_as("SELECT runtime_generation,launch_id,pod_uid,cluster_epoch FROM instances WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(instance.id).fetch_one(&mut *tx).await?;
        if (
            current_generation,
            current_launch,
            current_pod,
            current_epoch,
        ) != (
            r.runtime_generation,
            r.launch_id,
            Some(r.pod_uid),
            Some(r.cluster_epoch),
        ) {
            return Err(blocked("FILE_TRANSFER_IDENTITY_CHANGED"));
        }
        let principal = sqlx::query_scalar(
            "SELECT safety_principal_id FROM platform_configuration WHERE singleton",
        )
        .fetch_one(&mut *tx)
        .await?;
        let actor = Actor {
            authorization: None,
            tenant_id: tenant,
            principal_id: principal,
            request_id: Uuid::new_v4(),
        };
        let stop = if let Some(id) = instance.active_operation_id {
            let valid:bool=sqlx::query_scalar("SELECT kind='STOP' AND status IN('QUEUED','RUNNING','WAITING') FROM operations WHERE tenant_id=$1 AND id=$2 FOR UPDATE").bind(tenant).bind(id).fetch_one(&mut *tx).await?;
            if !valid {
                return Err(blocked("OPERATION_RECONCILIATION_REQUIRED"));
            }
            id
        } else {
            let id = Uuid::new_v4();
            if instance.desired_state != "RUNNING" || instance.stop_accepted_at.is_some() {
                return Err(blocked("OPERATION_RECONCILIATION_REQUIRED"));
            }
            insert_operation(
                &mut tx,
                &actor,
                id,
                r.project_id,
                instance.id,
                instance.workspace_id,
                "STOP",
                &json!({"reason":"SECURITY","file_transfer_id":r.id,"hard_stop_instance":true}),
                now + Duration::minutes(30),
            )
            .await?;
            sqlx::query("UPDATE operations SET compute_lease_id=$3,stop_reason='SECURITY' WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).bind(instance.compute_lease_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE instances SET desired_state='STOPPED',active_operation_id=$3,stop_reason='SECURITY',stop_accepted_at=$4,idle_since=NULL,spec_version=spec_version+1,updated_at=$4 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(instance.id).bind(id).bind(now).execute(&mut *tx).await?;
            id
        };
        let updated=sqlx::query("UPDATE workspaces SET active_operation_id=$3,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND(active_operation_id IS NULL OR active_operation_id=$3)").bind(tenant).bind(instance.workspace_id).bind(stop).execute(&mut *tx).await?;
        if updated.rows_affected() != 1 {
            return Err(blocked("WORKSPACE_RECONCILIATION_REQUIRED"));
        }
        sqlx::query("UPDATE file_transfers SET status=CASE WHEN dispatch_attempt_id IS NOT NULL THEN 'OUTCOME_UNKNOWN' WHEN $3='TIMEOUT' THEN 'TIMED_OUT' ELSE 'CANCELLED' END,process_status=CASE WHEN dispatch_attempt_id IS NOT NULL THEN 'UNKNOWN' ELSE process_status END,content_status=CASE WHEN direction='DOWNLOAD' THEN 'UNAVAILABLE' ELSE content_status END,completed_at=CASE WHEN dispatch_attempt_id IS NULL THEN clock_timestamp() ELSE completed_at END WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).bind(reason).execute(&mut *tx).await?;
        sqlx::query("UPDATE operations SET status='CANCELLED',stage='CANCELLED_BY_FILE_HARD_STOP',cancel_requested=true,lease_owner=NULL,lease_until=NULL,lease_token=lease_token+1,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND status IN('QUEUED','RUNNING','WAITING')").bind(tenant).bind(r.operation_id).execute(&mut *tx).await?;
        event(
            &mut tx,
            &actor,
            &r,
            "files:safety_stop",
            json!({"reason":reason,"stop_operation_id":stop,"termination_confirmed":false}),
        )
        .await?;
        tx.commit().await?;
        Ok(Some(stop))
    }
}
pub(crate) async fn refresh_idle(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    instance: Uuid,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE instances SET idle_since=CASE WHEN NOT slot_held AND desired_state='RUNNING' AND stop_accepted_at IS NULL AND NOT EXISTS(SELECT 1 FROM file_transfers f WHERE f.tenant_id=$1 AND f.instance_id=$2 AND f.runtime_generation=instances.runtime_generation AND f.process_status NOT IN('EXITED','VM_TERMINATED')) THEN clock_timestamp() ELSE NULL END,last_activity_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(instance).execute(&mut **tx).await?;
    Ok(())
}
async fn operation_actor(
    tx: &mut Transaction<'_, Postgres>,
    r: &TransferRow,
) -> Result<Actor, ApiError> {
    let (principal_id, request_id): (Uuid, Uuid) = sqlx::query_as(
        "SELECT actor_principal_id,request_id FROM operations WHERE tenant_id=$1 AND id=$2",
    )
    .bind(r.tenant_id)
    .bind(r.operation_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(Actor {
        authorization: None,
        tenant_id: r.tenant_id,
        principal_id,
        request_id,
    })
}
pub(crate) async fn assert_gateway(
    tx: &mut Transaction<'_, Postgres>,
    engine: &OperationEngine,
    claim: &Claim,
    r: &TransferRow,
    instance: &Instance,
    attempt: Uuid,
) -> Result<(), ApiError> {
    if r.operation_id != claim.operation_id
        || r.dispatch_attempt_id != Some(attempt)
        || r.dispatch_lease_token != Some(claim.lease_token)
        || !matches!(r.status.as_str(), "DISPATCHING" | "RUNNING")
        || !matches!(r.process_status.as_str(), "DISPATCHING" | "RUNNING")
    {
        return Err(blocked("FILE_DISPATCH_FENCED"));
    }
    engine.assert_claim(tx, claim).await?;
    let now = db_now(tx).await?;
    let epoch = runnable_epoch(tx).await?;
    if now >= r.deadline || ready_identity(tx, instance, epoch, now).await? != r.identity() {
        return Err(blocked("FILE_DISPATCH_AUTHORITY_CHANGED"));
    }
    if r.direction == "UPLOAD" {
        assert_write_activity(tx, r).await?;
    }
    let actor = operation_actor(tx, r).await?;
    Database::authorize_resource(tx, &actor, r.project_id, r.action()).await?;
    Database::authorize_resource(tx, &actor, r.project_id, "instances:hard_stop").await?;
    Ok(())
}
pub(crate) async fn release_dimension(
    tx: &mut Transaction<'_, Postgres>,
    r: &TransferRow,
    dimension: &str,
    amount: i64,
) -> Result<(), ApiError> {
    let _:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM quota_accounts WHERE tenant_id=$1 AND(project_id=$2 OR project_id IS NULL) ORDER BY id FOR UPDATE").bind(r.tenant_id).bind(r.project_id).fetch_all(&mut **tx).await?;
    let rows:Vec<(Uuid,Uuid,i64,String)>=sqlx::query_as("SELECT r.id,r.quota_account_id,r.amount,r.status FROM quota_reservations r JOIN quota_accounts q ON q.tenant_id=r.tenant_id AND q.id=r.quota_account_id WHERE r.tenant_id=$1 AND r.operation_id=$2 AND r.resource_id=$3 AND q.dimension=$4 AND r.status IN('PENDING','ALLOCATED') ORDER BY r.quota_account_id,r.id FOR UPDATE OF r").bind(r.tenant_id).bind(r.operation_id).bind(r.instance_id).bind(dimension).fetch_all(&mut **tx).await?;
    if rows.len() != 2 || rows.iter().any(|r| r.2 != amount) {
        return Err(blocked("FILE_QUOTA_LEDGER_MISMATCH"));
    }
    for (id, account, n, status) in rows {
        sqlx::query("UPDATE quota_accounts SET pending=pending-CASE WHEN $4='PENDING' THEN $3 ELSE 0 END,allocated=allocated-CASE WHEN $4='ALLOCATED' THEN $3 ELSE 0 END,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(r.tenant_id).bind(account).bind(n).bind(status).execute(&mut **tx).await?;
        sqlx::query("UPDATE quota_reservations SET status='RELEASED',released_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(r.tenant_id).bind(id).execute(&mut **tx).await?;
    }
    Ok(())
}
impl Database {
    /// A failed/cancelled remote PUT cannot authorize resending the same part.
    /// This monotonic safety update needs the unguessable persisted attempt and
    /// remains possible after the initiating actor's grant is revoked.
    pub async fn mark_file_part_put_unknown(
        &self,
        intent: &FilePartUploadIntent,
    ) -> Result<(), ApiError> {
        let identity = intent.receipt.identity;
        let (mut tx, r, _) = lock_transfer(self, identity.tenant_id, identity.transfer_id).await?;
        if r.content_id != identity.content_id {
            return Err(blocked("FILE_PART_RECEIPT_MISMATCH"));
        }
        sqlx::query("UPDATE file_transfer_parts SET put_state='UNKNOWN' WHERE tenant_id=$1 AND transfer_id=$2 AND part_index=$3 AND put_attempt_id=$4 AND put_state='PUTTING'").bind(identity.tenant_id).bind(identity.transfer_id).bind(identity.index as i32).bind(intent.put_attempt_id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
}
