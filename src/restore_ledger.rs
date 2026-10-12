//! Atomic restore acceptance. This cannot publish a recovered workspace: only
//! trusted task closure and independently observed CSI delivery may do that.
use super::{
    CreateRestore, Restore, RestoreAccepted, RestoreMutationResult, RestoreRecord, policy,
};
use crate::{
    backup_job::BackupCloudSettings,
    db::{
        Actor, Database, Idempotency, insert_operation, load_operation, reserve_quota,
        runnable_epoch,
    },
    error::ApiError,
    request::request_digest,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub(crate) struct VerificationPlan {
    pub record: RestoreRecord,
    pub cloud: BackupCloudSettings,
    pub expectation: crate::backup_object::BackupVaultExpectation,
}
pub(crate) struct JobPlan {
    pub record: RestoreRecord,
    pub cloud: BackupCloudSettings,
    pub context: crate::backup_manifest::BackupManifestContext,
    pub storage_contract: super::storage_contract::RestoreStorageContract,
    pub known_job: Option<Uuid>,
    pub known_pod: Option<Uuid>,
}

impl Database {
    pub async fn get_restore(&self, actor: &Actor, id: Uuid) -> Result<Restore, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let r: Restore = sqlx::query_as("SELECT * FROM restores WHERE tenant_id=$1 AND id=$2")
            .bind(actor.tenant_id)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(ApiError::not_found)?;
        Self::authorize_resource(&mut tx, actor, r.target_project_id, "restores:read").await?;
        tx.commit().await?;
        Ok(r)
    }
    pub async fn create_restore(
        &self,
        actor: &Actor,
        backup: Uuid,
        request: &CreateRestore,
        key: &str,
        expected: i64,
    ) -> Result<RestoreMutationResult, ApiError> {
        request.validate()?;
        let mut tx = self.begin(actor.tenant_id).await?;
        let source_project: Uuid =
            sqlx::query_scalar("SELECT project_id FROM backups WHERE tenant_id=$1 AND id=$2")
                .bind(actor.tenant_id)
                .bind(backup)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(ApiError::not_found)?;
        authorize(&mut tx, actor, source_project, request.target_project_id).await?;
        let digest = request_digest(request, Some(expected))?;
        let idem = Idempotency::new(actor, backup, "backups:restore", key, &digest);
        if let Some((status, value)) = idem.replay_json(&mut tx).await? {
            authorize(&mut tx, actor, source_project, request.target_project_id).await?;
            let body = serde_json::from_value(value).map_err(|_| policy::invalid())?;
            tx.commit().await?;
            return Ok(RestoreMutationResult { status, body });
        }
        // Source data is immutable and is read under the source backup lock.
        // No target workspace exists yet, so this cannot invert lifecycle locks.
        let b = sqlx::query("SELECT * FROM sandbox_lock_restore_source($1,$2)")
            .bind(actor.tenant_id)
            .bind(backup)
            .fetch_one(&mut *tx)
            .await?;
        if b.try_get::<i64, _>("version")? != expected {
            return Err(ApiError::new(
                axum::http::StatusCode::PRECONDITION_FAILED,
                "VERSION_MISMATCH",
                "The backup has changed",
            ));
        }
        if b.try_get::<String, _>("status")? != "AVAILABLE" {
            return Err(policy::blocked(
                "Only an available independently verified backup may be restored",
            ));
        }
        let epoch = runnable_epoch(&mut tx).await?;
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let deadline = now + Duration::hours(6);
        if b.try_get::<DateTime<Utc>, _>("retention_until")? < deadline + Duration::minutes(5) {
            return Err(policy::blocked(
                "Source retention must cover the entire restore and cleanup window",
            ));
        }
        let v =
            sqlx::query("SELECT * FROM backup_vault_receipts WHERE tenant_id=$1 AND backup_id=$2")
                .bind(actor.tenant_id)
                .bind(backup)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(policy::invalid)?;
        let size: i64 = b.try_get("size_gib")?;
        let source = policy::Source::from_receipt(
            actor.tenant_id,
            source_project,
            backup,
            size,
            v.try_get("manifest_sha256")?,
            v.try_get("manifest")?,
        )?;
        let historical: Value =
            sqlx::query_scalar("SELECT settings FROM backup_profiles WHERE id=$1")
                .bind(b.try_get::<Uuid, _>("profile_id")?)
                .fetch_one(&mut *tx)
                .await?;
        let locked: Option<Value> =
            sqlx::query_scalar("SELECT sandbox_lock_restore_configuration($1,$2,$3,$4,$5)")
                .bind(actor.tenant_id)
                .bind(request.target_project_id)
                .bind(request.profile_id)
                .bind(epoch)
                .bind(deadline)
                .fetch_one(&mut *tx)
                .await?;
        let storage_value = locked.ok_or_else(|| {
            policy::blocked("The target project requires a current exact restore storage mapping")
        })?;
        let storage_contract =
            super::storage_contract::RestoreStorageContract::parse(&storage_value)
                .map_err(|_| policy::invalid())?;
        if storage_contract.profile_id != request.profile_id
            || storage_contract.cluster_epoch != epoch
        {
            return Err(policy::invalid());
        }
        let profile = sqlx::query("SELECT * FROM backup_profiles WHERE id=$1 AND enabled AND cluster_epoch=$2 AND certified_until>=$3 AND sandbox_restore_profile_current(id,$2,$3)")
            .bind(request.profile_id).bind(epoch).bind(deadline).fetch_optional(&mut *tx).await?
            .ok_or_else(|| policy::blocked("A current runtime profile with independent restore and CSI mode-conversion approval is required"))?;
        let historical: BackupCloudSettings =
            serde_json::from_value(historical).map_err(|_| policy::invalid())?;
        let cloud: BackupCloudSettings =
            serde_json::from_value(profile.try_get("settings")?).map_err(|_| policy::invalid())?;
        policy::compatible(&source, &historical, &cloud)?;
        storage_contract
            .validate_cloud(&cloud)
            .map_err(|_| policy::invalid())?;
        for (column, binding) in [
            ("password_secret", &cloud.secret_bindings.password),
            (
                "signing_public_secret",
                &cloud.secret_bindings.signing_public,
            ),
            (
                "signing_private_secret",
                &cloud.secret_bindings.signing_private,
            ),
        ] {
            if profile.try_get::<String, _>(column)? != binding.name {
                return Err(policy::blocked(
                    "Current Secret names differ from approved immutable bindings",
                ));
            }
        }
        let project = sqlx::query("SELECT runtime_namespace,storage_class FROM projects WHERE tenant_id=$1 AND id=$2 AND enabled")
            .bind(actor.tenant_id).bind(request.target_project_id).fetch_optional(&mut *tx).await?.ok_or_else(ApiError::not_found)?;
        let namespace: Option<String> = project.try_get("runtime_namespace")?;
        let storage: Option<String> = project.try_get("storage_class")?;
        let (Some(namespace), Some(storage)) = (namespace, storage) else {
            return Err(policy::blocked(
                "The target project runtime is not provisioned",
            ));
        };
        if storage != storage_contract.mapping.normal.name {
            return Err(policy::blocked(
                "The locked project storage class differs from its restore mapping",
            ));
        }
        let approved: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM template_versions WHERE tenant_id=$1 AND id=$2 AND status='APPROVED') AND EXISTS(SELECT 1 FROM security_policy_versions WHERE tenant_id=$1 AND id=$3 AND status='APPROVED' AND rules='{\"profile\":\"deny-all\",\"dns\":true}'::jsonb)")
            .bind(actor.tenant_id).bind(request.template_version_id).bind(request.security_profile_id).fetch_one(&mut *tx).await?;
        if !approved {
            return Err(ApiError::invalid(
                "Target template and the supported deny-all/DNS security profile must be currently approved",
            ));
        }
        let id = Uuid::new_v4();
        let workspace = Uuid::new_v4();
        let instance = Uuid::new_v4();
        let operation = Uuid::new_v4();
        let hold = Uuid::new_v4();
        let (cpu, memory) = request.flavor.resources();
        sqlx::query("INSERT INTO workspaces(id,tenant_id,project_id,size_gib,storage_class,namespace,pvc_name,active_operation_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(workspace).bind(actor.tenant_id).bind(request.target_project_id).bind(size).bind(&storage_contract.mapping.delivery.name).bind(&namespace).bind(format!("ws-{workspace}")).bind(operation).execute(&mut *tx).await?;
        // No workload VM is requested or launched by restore. Active intent and
        // RESTORE hold fence explicit start until the new workspace is delivered.
        sqlx::query("INSERT INTO instances(id,tenant_id,project_id,name,template_version_id,security_policy_version_id,workspace_id,cpu_millis,memory_mib,desired_state,observed_state,cluster_epoch,launch_id,namespace,pod_name,active_operation_id,compute_lease_id,compute_lease_started_at,compute_lease_expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'STOPPED','STOPPED',$10,$11,$12,$13,$14,$15,$16,$17)")
            .bind(instance).bind(actor.tenant_id).bind(request.target_project_id).bind(&request.name).bind(request.template_version_id).bind(request.security_profile_id).bind(workspace).bind(cpu).bind(memory).bind(epoch).bind(Uuid::new_v4()).bind(namespace).bind(format!("sbx-ws-{workspace}")).bind(operation).bind(Uuid::new_v4()).bind(now).bind(deadline).execute(&mut *tx).await?;
        insert_operation(&mut tx, actor, operation, request.target_project_id, instance, workspace, "RESTORE", &json!({"restore_id":id,"backup_id":backup,"source_project_id":source_project,"profile_id":request.profile_id,"desired_state":"STOPPED"}), deadline).await?;
        let born: bool = sqlx::query_scalar("SELECT sandbox_restore_birth_guard($1,$2,$3,$4)")
            .bind(actor.tenant_id)
            .bind(instance)
            .bind(workspace)
            .bind(epoch)
            .fetch_one(&mut *tx)
            .await?;
        if !born {
            return Err(policy::blocked(
                "A current independently reviewed ordinary launch guard contract is required for the new stopped target",
            ));
        }
        sqlx::query("INSERT INTO workspace_holds(id,tenant_id,project_id,workspace_id,kind,reference_id,source_generation,source_pvc_uid,reason) VALUES($1,$2,$3,$4,'RESTORE',$5,1,$6,'New target and unresolved isolated restore writer')")
            .bind(hold).bind(actor.tenant_id).bind(request.target_project_id).bind(workspace).bind(id).bind(source.identity.source_pvc_uid).execute(&mut *tx).await?;
        let resource: Restore = sqlx::query_as("INSERT INTO restores(id,tenant_id,backup_id,source_project_id,target_project_id,workspace_id,instance_id,operation_id,profile_id,hold_id,cluster_epoch,source_manifest_sha256,source_identity,storage_contract,size_gib,deadline,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$17) RETURNING *")
            .bind(id).bind(actor.tenant_id).bind(backup).bind(source_project).bind(request.target_project_id).bind(workspace).bind(instance).bind(operation).bind(request.profile_id).bind(hold).bind(epoch).bind(&source.manifest_sha256).bind(json!(source.identity)).bind(&storage_value).bind(size).bind(deadline).bind(now).fetch_one(&mut *tx).await?;
        reserve_quota(
            &mut tx,
            actor,
            request.target_project_id,
            operation,
            instance,
            workspace,
            &[
                ("INSTANCES", 1),
                ("WORKSPACE_GIB", size),
                // Raw disk + one cloud snapshot. Static CSI delegation shares that
                // snapshot handle; the delivered disk belongs to WORKSPACE_GIB.
                (
                    "BACKUP_TEMP_GIB",
                    size.checked_mul(2).ok_or_else(policy::invalid)?,
                ),
                ("CPU_MILLIS", 2000),
                ("MEMORY_MIB", 2048),
            ],
        )
        .await?;
        sqlx::query(
            "UPDATE operations SET next_attempt_at=next_attempt_at WHERE tenant_id=$1 AND id=$2",
        )
        .bind(actor.tenant_id)
        .bind(operation)
        .execute(&mut *tx)
        .await?;
        let body = RestoreAccepted {
            resource,
            operation: load_operation(&mut tx, actor.tenant_id, operation).await?,
            idempotency_expires_at: now + Duration::days(7),
        };
        idem.persist_json(
            &mut tx,
            request.target_project_id,
            operation,
            id,
            &json!(body),
            202,
            now,
            body.idempotency_expires_at,
        )
        .await?;
        sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details) VALUES($1,$2,$3,$4,$5,$6,'backups:restore','ACCEPTED',$7)")
            .bind(actor.tenant_id).bind(request.target_project_id).bind(actor.principal_id).bind(actor.request_id).bind(operation).bind(id).bind(json!({"backup_id":backup,"source_project_id":source_project,"workspace_id":workspace,"default_state":"STOPPED"})).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload) VALUES($1,$2,$3,1,'restore.accepted',$4,$5,$6)")
            .bind(actor.tenant_id).bind(request.target_project_id).bind(id).bind(operation).bind(actor.request_id).bind(json!({"status":"QUEUED","workspace_id":workspace})).execute(&mut *tx).await?;
        authorize(&mut tx, actor, source_project, request.target_project_id).await?;
        tx.commit().await?;
        Ok(RestoreMutationResult { status: 202, body })
    }
}

async fn authorize(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    source: Uuid,
    target: Uuid,
) -> Result<(), ApiError> {
    Database::authorize_resource(tx, actor, source, "backups:read").await?;
    Database::authorize_resource(tx, actor, source, "backups:restore").await?;
    Database::authorize_resource(tx, actor, target, "instances:create").await?;
    // The integration scope and the explicit source/target project grants must
    // both remain current. A global grant cannot override project revocation.
    let scoped: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM (VALUES($3::uuid,'backups:read'),($3::uuid,'backups:restore'),($4::uuid,'instances:create')) actions(project_id,action) WHERE NOT EXISTS(SELECT 1 FROM grants g WHERE g.tenant_id=$1 AND g.principal_id=$2 AND g.project_id IS NULL AND g.action IN(actions.action,'*') AND g.enabled AND g.revoked_at IS NULL AND(g.expires_at IS NULL OR g.expires_at>clock_timestamp())) OR NOT EXISTS(SELECT 1 FROM grants g WHERE g.tenant_id=$1 AND g.principal_id=$2 AND g.project_id=actions.project_id AND g.action IN(actions.action,'*') AND g.enabled AND g.revoked_at IS NULL AND(g.expires_at IS NULL OR g.expires_at>clock_timestamp())))")
        .bind(actor.tenant_id).bind(actor.principal_id).bind(source).bind(target).fetch_one(&mut **tx).await?;
    if !scoped {
        return Err(ApiError::not_found());
    }
    Ok(())
}

pub(crate) async fn lock_restore(
    tx: &mut Transaction<'_, Postgres>,
    engine: &crate::engine::OperationEngine,
    claim: &crate::engine::Claim,
) -> Result<RestoreRecord, ApiError> {
    let r: RestoreRecord =
        sqlx::query_as("SELECT * FROM restores WHERE tenant_id=$1 AND operation_id=$2")
            .bind(claim.tenant_id)
            .bind(claim.operation_id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(ApiError::not_found)?;
    sqlx::query("SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(r.tenant_id)
        .bind(r.workspace_id)
        .fetch_one(&mut **tx)
        .await?;
    let active:Option<Uuid>=sqlx::query_scalar("SELECT active_operation_id FROM instances WHERE tenant_id=$1 AND id=$2 AND workspace_id=$3 FOR UPDATE")
        .bind(r.tenant_id)
        .bind(r.instance_id)
        .bind(r.workspace_id)
        .fetch_one(&mut **tx)
        .await?;
    sqlx::query(
        "SELECT id FROM operations WHERE tenant_id=$1 AND(id=$2 OR id=$3) ORDER BY id FOR UPDATE",
    )
    .bind(r.tenant_id)
    .bind(r.operation_id)
    .bind(active)
    .fetch_all(&mut **tx)
    .await?;
    let r = sqlx::query_as("SELECT * FROM restores WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(r.tenant_id)
        .bind(r.id)
        .fetch_one(&mut **tx)
        .await?;
    engine.assert_claim(tx, claim).await?;
    Ok(r)
}
pub(crate) async fn current_source(
    tx: &mut Transaction<'_, Postgres>,
    r: &RestoreRecord,
) -> Result<policy::Source, ApiError> {
    let v = sqlx::query("SELECT * FROM backup_vault_receipts WHERE tenant_id=$1 AND backup_id=$2")
        .bind(r.tenant_id)
        .bind(r.backup_id)
        .fetch_one(&mut **tx)
        .await?;
    let source = policy::Source::from_receipt(
        r.tenant_id,
        r.source_project_id,
        r.backup_id,
        r.size_gib,
        v.try_get("manifest_sha256")?,
        v.try_get("manifest")?,
    )?;
    if source.manifest_sha256 != r.source_manifest_sha256
        || json!(source.identity) != r.source_identity
    {
        return Err(policy::invalid());
    }
    Ok(source)
}
pub(crate) async fn current_cloud(
    tx: &mut Transaction<'_, Postgres>,
    r: &RestoreRecord,
    source: &policy::Source,
) -> Result<BackupCloudSettings, ApiError> {
    let authorized: bool = sqlx::query_scalar("SELECT sandbox_restore_authorized($1,$2,true)")
        .bind(r.tenant_id)
        .bind(r.id)
        .fetch_one(&mut **tx)
        .await?;
    if !authorized {
        return Err(policy::blocked(
            "Restore authority, hold, source retention or certification is no longer current",
        ));
    }
    let old: Value = sqlx::query_scalar("SELECT bp.settings FROM backup_profiles bp JOIN backups b ON b.profile_id=bp.id WHERE b.tenant_id=$1 AND b.id=$2")
        .bind(r.tenant_id).bind(r.backup_id).fetch_one(&mut **tx).await?;
    let new: Value = sqlx::query_scalar("SELECT settings FROM backup_profiles WHERE id=$1")
        .bind(r.profile_id)
        .fetch_one(&mut **tx)
        .await?;
    let old: BackupCloudSettings = serde_json::from_value(old).map_err(|_| policy::invalid())?;
    let new: BackupCloudSettings = serde_json::from_value(new).map_err(|_| policy::invalid())?;
    policy::compatible(source, &old, &new)?;
    r.storage()?
        .validate_cloud(&new)
        .map_err(|_| policy::invalid())?;
    Ok(new)
}
pub(crate) async fn advance(
    tx: &mut Transaction<'_, Postgres>,
    r: &RestoreRecord,
    status: &str,
) -> Result<(), ApiError> {
    if r.status == status {
        return Ok(());
    }
    sqlx::query("UPDATE restores SET status=$3,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
        .bind(r.tenant_id).bind(r.id).bind(status).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload) SELECT $1,$2,$3,$4,'restore.progress',$5,request_id,$6 FROM operations WHERE tenant_id=$1 AND id=$5")
        .bind(r.tenant_id).bind(r.target_project_id).bind(r.id).bind(r.version + 1).bind(r.operation_id).bind(json!({"status":status})).execute(&mut **tx).await?;
    Ok(())
}
impl Database {
    /// Closure reads the already frozen task intent after authorization or
    /// profile revocation. It cannot mint a new context, Job or launch permit.
    pub(crate) async fn prepare_restore_cleanup_job(
        &self,
        engine: &crate::engine::OperationEngine,
        claim: &crate::engine::Claim,
    ) -> Result<JobPlan, ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let r = lock_restore(&mut tx, engine, claim).await?;
        if !matches!(
            r.status.as_str(),
            "RESTORE_CLOSING" | "SNAPSHOT_PENDING" | "DELIVERY_PENDING"
        ) {
            return Err(policy::blocked(
                "Only a permanently closed restore may read cleanup intent",
            ));
        }
        let raw: Value = sqlx::query_scalar(
            "SELECT context FROM restore_job_contexts WHERE tenant_id=$1 AND restore_id=$2",
        )
        .bind(r.tenant_id)
        .bind(r.id)
        .fetch_one(&mut *tx)
        .await?;
        let context = serde_json::from_value(raw).map_err(|_| policy::invalid())?;
        let profile = sqlx::query("SELECT settings FROM backup_profiles WHERE id=$1")
            .bind(r.profile_id)
            .fetch_one(&mut *tx)
            .await?;
        let cloud =
            serde_json::from_value(profile.try_get("settings")?).map_err(|_| policy::invalid())?;
        let known_job = resource_binding(&mut tx, r.tenant_id, r.id, "JOB").await?;
        let known_pod = resource_binding(&mut tx, r.tenant_id, r.id, "POD").await?;
        let plan = JobPlan {
            storage_contract: r.storage()?,
            record: r,
            cloud,
            context,
            known_job,
            known_pod,
        };
        tx.commit().await?;
        Ok(plan)
    }
    pub(crate) async fn prepare_restore_verification(
        &self,
        engine: &crate::engine::OperationEngine,
        claim: &crate::engine::Claim,
    ) -> Result<VerificationPlan, ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let r = lock_restore(&mut tx, engine, claim).await?;
        if !matches!(r.status.as_str(), "QUEUED" | "VERIFIED") {
            return Err(policy::blocked(
                "Vault verification arrived after restore dispatch",
            ));
        }
        let source = current_source(&mut tx, &r).await?;
        let cloud = current_cloud(&mut tx, &r, &source).await?;
        let expectation = source.expectation();
        tx.commit().await?;
        Ok(VerificationPlan {
            record: r,
            cloud,
            expectation,
        })
    }
    pub(crate) async fn record_restore_verification(
        &self,
        engine: &crate::engine::OperationEngine,
        claim: &crate::engine::Claim,
        proof: &crate::backup_object::VerifiedBackupVault,
    ) -> Result<(), ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let r = lock_restore(&mut tx, engine, claim).await?;
        if !matches!(r.status.as_str(), "QUEUED" | "VERIFIED") {
            return Err(policy::blocked(
                "Vault verification arrived after restore dispatch",
            ));
        }
        let source = current_source(&mut tx, &r).await?;
        let cloud = current_cloud(&mut tx, &r, &source).await?;
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        if proof.identity() != &source.identity
            || proof.manifest_sha256() != source.manifest_sha256
            || proof.snapshot_id() != source.snapshot_id
            || proof.disk_sha256() != source.disk_sha256
            || proof.signing_key_sha256() != cloud.signing_key_sha256
            || proof.vault_endpoint() != cloud.vault_endpoint
            || proof.verified_at() < now - Duration::minutes(5)
            || proof.verified_at() > now + Duration::seconds(2)
        {
            return Err(policy::blocked(
                "Fresh independent vault proof does not match this immutable restore source",
            ));
        }
        let old: Option<(Uuid, String, String, String)> = sqlx::query_as("SELECT backup_id,manifest_sha256,signing_key_sha256,vault_endpoint FROM restore_vault_receipts WHERE tenant_id=$1 AND restore_id=$2")
            .bind(r.tenant_id).bind(r.id).fetch_optional(&mut *tx).await?;
        if let Some(old) = old {
            if old
                != (
                    r.backup_id,
                    proof.manifest_sha256().to_owned(),
                    proof.signing_key_sha256().to_owned(),
                    proof.vault_endpoint().to_owned(),
                )
            {
                return Err(policy::invalid());
            }
        } else {
            sqlx::query("INSERT INTO restore_vault_receipts(restore_id,tenant_id,backup_id,manifest_sha256,signing_key_sha256,vault_endpoint,verified_at) VALUES($1,$2,$3,$4,$5,$6,$7)")
                .bind(r.id).bind(r.tenant_id).bind(r.backup_id).bind(proof.manifest_sha256()).bind(proof.signing_key_sha256()).bind(proof.vault_endpoint()).bind(proof.verified_at()).execute(&mut *tx).await?;
        }
        advance(&mut tx, &r, "VERIFIED").await?;
        tx.commit().await?;
        Ok(())
    }
    pub(crate) async fn prepare_restore_job(
        &self,
        engine: &crate::engine::OperationEngine,
        claim: &crate::engine::Claim,
    ) -> Result<JobPlan, ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let r = lock_restore(&mut tx, engine, claim).await?;
        if !matches!(
            r.status.as_str(),
            "VERIFIED" | "BLOCK_PENDING" | "RESTORE_PENDING" | "RESTORE_RUNNING"
        ) {
            return Err(policy::blocked(
                "Restore job preparation is outside its stage",
            ));
        }
        let source = current_source(&mut tx, &r).await?;
        let cloud = current_cloud(&mut tx, &r, &source).await?;
        let verified: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM restore_vault_receipts WHERE tenant_id=$1 AND restore_id=$2 AND manifest_sha256=$3)")
            .bind(r.tenant_id).bind(r.id).bind(&r.source_manifest_sha256).fetch_one(&mut *tx).await?;
        if !verified {
            return Err(policy::blocked(
                "Independent vault verification must precede target writes",
            ));
        }
        let profile =
            sqlx::query("SELECT image,certification_sha256 FROM backup_profiles WHERE id=$1")
                .bind(r.profile_id)
                .fetch_one(&mut *tx)
                .await?;
        let existing: Option<(Value, DateTime<Utc>)> = sqlx::query_as("SELECT context,deadline FROM restore_job_contexts WHERE tenant_id=$1 AND restore_id=$2")
            .bind(r.tenant_id).bind(r.id).fetch_optional(&mut *tx).await?;
        let context = if let Some((context, deadline)) = existing {
            if deadline <= Utc::now() {
                return Err(policy::blocked(
                    "The isolated restore deadline expired; trusted closure is required",
                ));
            }
            serde_json::from_value(context).map_err(|_| policy::invalid())?
        } else {
            let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(&mut *tx)
                .await?;
            let deadline = (now + Duration::hours(2)).min(r.deadline);
            let context = policy::job_context(
                &source,
                &cloud,
                r.id,
                r.cluster_epoch,
                profile.try_get("image")?,
                profile.try_get("certification_sha256")?,
                now,
                deadline,
            )?;
            sqlx::query("INSERT INTO restore_job_contexts(restore_id,tenant_id,context,deadline) VALUES($1,$2,$3,$4)")
                .bind(r.id).bind(r.tenant_id).bind(json!(context)).bind(deadline).execute(&mut *tx).await?;
            context
        };
        let known_job = resource_binding(&mut tx, r.tenant_id, r.id, "JOB").await?;
        let known_pod = resource_binding(&mut tx, r.tenant_id, r.id, "POD").await?;
        if matches!(r.status.as_str(), "RESTORE_PENDING" | "RESTORE_RUNNING") {
            if resource_binding(&mut tx, r.tenant_id, r.id, "BLOCK_PVC")
                .await?
                .is_none()
            {
                return Err(policy::blocked(
                    "A recorded new raw claim must precede isolated restore Job intent",
                ));
            }
            super::resources::job_intents(&mut tx, &r, &context).await?;
        }
        let plan = JobPlan {
            storage_contract: r.storage()?,
            record: r,
            cloud,
            context,
            known_job,
            known_pod,
        };
        tx.commit().await?;
        Ok(plan)
    }
}

pub(crate) async fn resource_binding(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    restore: Uuid,
    kind: &str,
) -> Result<Option<Uuid>, ApiError> {
    Ok(sqlx::query_scalar("SELECT b.uid FROM restore_resource_intents r JOIN restore_resource_bindings b ON b.tenant_id=r.tenant_id AND b.intent_id=r.id WHERE r.tenant_id=$1 AND r.restore_id=$2 AND r.kind=$3")
        .bind(tenant).bind(restore).bind(kind).fetch_optional(&mut **tx).await?)
}
