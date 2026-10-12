//! One durable host permit per restore. Safety closure remains available after
//! principal, profile or template revocation; neither guest exit nor Kube absence
//! can resolve an admitted writer without verified host termination.
use super::{
    RestoreRecord,
    host::{VerifiedRestoreCleanup, VerifiedRestoreLaunch},
    ledger::{advance, current_source, lock_restore, resource_binding},
    policy,
};
use crate::{
    db::Database,
    engine::{Claim, OperationEngine},
    error::ApiError,
    nodeguard::protocol::{
        BackupStage, CloseReason, CloseRequest, LaunchPurpose, NodeBinding, ObservationState,
        PROTOCOL_VERSION, RegisterLaunchRequest,
    },
    termination_client::{VerifiedLaunchRegistration, VerifiedLocalTermination},
    termination_ledger::{LaunchPermit, RuntimeNode, TerminationChallenge},
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(PartialEq, sqlx::FromRow)]
struct RecordedIo {
    exit_code: i32,
    bytes: Option<i64>,
    disk_sha256: Option<String>,
    finished_at: DateTime<Utc>,
}

async fn now(tx: &mut Transaction<'_, Postgres>) -> Result<DateTime<Utc>, ApiError> {
    Ok(sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?)
}
async fn current_epoch(
    tx: &mut Transaction<'_, Postgres>,
    r: &RestoreRecord,
) -> Result<(), ApiError> {
    let current: Uuid =
        sqlx::query_scalar("SELECT cluster_epoch FROM platform_configuration WHERE singleton")
            .fetch_one(&mut **tx)
            .await?;
    if current != r.cluster_epoch {
        return Err(policy::blocked(
            "Restore closure belongs to a previous cluster epoch",
        ));
    }
    Ok(())
}
async fn node(
    tx: &mut Transaction<'_, Postgres>,
    binding: &NodeBinding,
    require_enabled: bool,
) -> Result<RuntimeNode, ApiError> {
    let r = sqlx::query("SELECT *,host(private_ip) AS address FROM runtime_nodes WHERE cluster_epoch=$1 AND node_uid=$2 AND boot_id=$3")
        .bind(binding.cluster_epoch).bind(binding.node_uid).bind(binding.boot_id).fetch_optional(&mut **tx).await?.ok_or_else(|| policy::blocked("Restore node is not enrolled"))?;
    let actual = NodeBinding {
        cluster_epoch: r.try_get("cluster_epoch")?,
        node_uid: r.try_get("node_uid")?,
        node_name: r.try_get("node_name")?,
        boot_id: r.try_get("boot_id")?,
        profile_sha256: r.try_get("profile_sha256")?,
    };
    if actual != *binding || require_enabled && !r.try_get::<bool, _>("enabled")? {
        return Err(policy::blocked("Restore node enrollment changed"));
    }
    Ok(RuntimeNode {
        id: r.try_get("id")?,
        node: actual,
        private_ip: r.try_get("address")?,
        guard_port: u16::try_from(r.try_get::<i32, _>("guard_port")?)
            .map_err(|_| policy::invalid())?,
        cloud_account_id: r.try_get("cloud_account_id")?,
        region: r.try_get("region")?,
        cloud_instance_id: r.try_get("cloud_instance_id")?,
        enabled: r.try_get("enabled")?,
    })
}
async fn certified(
    tx: &mut Transaction<'_, Postgres>,
    node: Uuid,
    until: DateTime<Utc>,
) -> Result<(), ApiError> {
    let expiry: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT sandbox_node_certified_until($1)")
            .bind(node)
            .fetch_one(&mut **tx)
            .await?;
    if expiry.is_none_or(|v| v < until) {
        return Err(policy::blocked(
            "Node certification does not cover restore deadline",
        ));
    }
    Ok(())
}
async fn permit(
    tx: &mut Transaction<'_, Postgres>,
    r: &RestoreRecord,
) -> Result<Option<LaunchPermit>, ApiError> {
    let raw: Option<Value> = sqlx::query_scalar(
        "SELECT request FROM restore_launch_permits WHERE tenant_id=$1 AND restore_id=$2",
    )
    .bind(r.tenant_id)
    .bind(r.id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(raw) = raw else { return Ok(None) };
    let request: RegisterLaunchRequest =
        serde_json::from_value(raw).map_err(|_| policy::invalid())?;
    let n = node(tx, &request.node, false).await?;
    Ok(Some(LaunchPermit { request, node: n }))
}
async fn require_authority(
    tx: &mut Transaction<'_, Postgres>,
    r: &RestoreRecord,
) -> Result<(), ApiError> {
    let yes: bool = sqlx::query_scalar("SELECT sandbox_restore_authorized($1,$2,true)")
        .bind(r.tenant_id)
        .bind(r.id)
        .fetch_one(&mut **tx)
        .await?;
    if !yes {
        return Err(policy::blocked(
            "Current restore authority is required before launch",
        ));
    }
    Ok(())
}
async fn journal(
    tx: &mut Transaction<'_, Postgres>,
    node: Uuid,
    revision: i64,
) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO runtime_node_journal_highwater(runtime_node_id,max_revision) VALUES($1,$2) ON CONFLICT(runtime_node_id) DO NOTHING").bind(node).bind(revision).execute(&mut **tx).await?;
    let previous:i64=sqlx::query_scalar("SELECT max_revision FROM runtime_node_journal_highwater WHERE runtime_node_id=$1 FOR UPDATE").bind(node).fetch_one(&mut **tx).await?;
    if revision < previous {
        return Err(policy::blocked("Restore node journal regressed"));
    }
    sqlx::query("UPDATE runtime_node_journal_highwater SET max_revision=$2,observed_at=clock_timestamp() WHERE runtime_node_id=$1").bind(node).bind(revision).execute(&mut **tx).await?;
    Ok(())
}
impl Database {
    pub(crate) async fn prepare_restore_launch(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        observed: &VerifiedRestoreLaunch,
    ) -> Result<LaunchPermit, ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let r = lock_restore(&mut tx, engine, claim).await?;
        require_authority(&mut tx, &r).await?;
        if !matches!(r.status.as_str(), "RESTORE_PENDING" | "RESTORE_RUNNING") {
            return Err(policy::blocked(
                "Closing or undelivered restore cannot obtain a host permit",
            ));
        }
        let timestamp = now(&mut tx).await?;
        if observed.observed_at < timestamp - Duration::seconds(10)
            || observed.observed_at > timestamp + Duration::seconds(2)
        {
            return Err(policy::blocked("Restore Kubernetes observation expired"));
        }
        let (raw,deadline):(Value,DateTime<Utc>)=sqlx::query_as("SELECT context,deadline FROM restore_job_contexts WHERE tenant_id=$1 AND restore_id=$2 AND deadline>clock_timestamp()")
            .bind(r.tenant_id).bind(r.id).fetch_optional(&mut *tx).await?.ok_or_else(||policy::blocked("Restore task deadline elapsed"))?;
        let context: crate::backup_manifest::BackupManifestContext =
            serde_json::from_value(raw).map_err(|_| policy::invalid())?;
        let source = current_source(&mut tx, &r).await?;
        let job = resource_binding(&mut tx, r.tenant_id, r.id, "JOB")
            .await?
            .ok_or_else(policy::invalid)?;
        let pod = resource_binding(&mut tx, r.tenant_id, r.id, "POD")
            .await?
            .ok_or_else(policy::invalid)?;
        let launch = &observed.launch;
        let purpose = LaunchPurpose::Backup {
            backup_id: r.backup_id,
            attempt_id: r.id,
            job_uid: job,
            stage: BackupStage::Restore,
            image_ref: context.image,
            source_pvc_uid: source.identity.source_pvc_uid,
        };
        let admitted:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM restore_pod_admissions WHERE tenant_id=$1 AND restore_id=$2 AND job_uid=$3)").bind(r.tenant_id).bind(r.id).bind(job).fetch_one(&mut *tx).await?;
        let bound:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM restore_block_receipts WHERE tenant_id=$1 AND restore_id=$2 AND pvc_uid=$3 AND pv_uid=$4 AND pv_name=$5 AND cloud_disk=$6 AND size_bytes=$7)")
            .bind(r.tenant_id).bind(r.id).bind(launch.pvc_uid).bind(launch.pv_uid).bind(&launch.pv_name).bind(&launch.csi_volume_handle).bind(i64::try_from(source.identity.size_bytes).map_err(|_|policy::invalid())?).fetch_one(&mut *tx).await?;
        if !admitted
            || !bound
            || launch.purpose != purpose
            || launch.tenant_id != r.tenant_id
            || launch.project_id != r.target_project_id
            || launch.instance_id != r.instance_id
            || launch.workspace_id != r.workspace_id
            || launch.generation != 1
            || launch.launch_id != r.id
            || launch.pod_uid != pod
            || observed.node.cluster_epoch != r.cluster_epoch
            || !launch.validate()
            || !observed.node.validate()
        {
            return Err(policy::blocked(
                "Restore launch differs from immutable target, admission or block-device ledger",
            ));
        }
        let n = node(&mut tx, &observed.node, true).await?;
        certified(&mut tx, n.id, deadline).await?;
        if let Some(old) = permit(&mut tx, &r).await? {
            if old.node.id != n.id
                || old.request.launch != *launch
                || old.request.node != observed.node
                || old.request.expires_at != deadline
            {
                return Err(policy::blocked(
                    "Restore cannot change writer, node or extend its only host permit",
                ));
            }
            tx.commit().await?;
            return Ok(old);
        }
        let request = RegisterLaunchRequest {
            protocol: PROTOCOL_VERSION,
            permit_id: Uuid::new_v4(),
            node: n.node.clone(),
            launch: launch.clone(),
            expires_at: deadline,
        };
        sqlx::query("INSERT INTO restore_launch_permits(id,tenant_id,restore_id,runtime_node_id,operation_id,lease_token,request,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(request.permit_id).bind(r.tenant_id).bind(r.id).bind(n.id).bind(r.operation_id).bind(claim.lease_token).bind(json!(request)).bind(deadline).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(LaunchPermit { request, node: n })
    }
    pub(crate) async fn record_restore_registration(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        verified: &VerifiedLaunchRegistration,
    ) -> Result<(), ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let r = lock_restore(&mut tx, engine, claim).await?;
        require_authority(&mut tx, &r).await?;
        if !matches!(r.status.as_str(), "RESTORE_PENDING" | "RESTORE_RUNNING") {
            return Err(policy::blocked(
                "Restore registration arrived after permanent closing",
            ));
        }
        let p = permit(&mut tx, &r).await?.ok_or_else(policy::invalid)?;
        let v = verified.response();
        if v.permit_id != p.request.permit_id
            || v.node != p.request.node
            || v.launch != p.request.launch
            || v.effective_expires_at != p.request.expires_at
            || v.journal_revision <= 0
        {
            return Err(policy::blocked(
                "Restore host registration differs from durable permit",
            ));
        }
        certified(&mut tx, p.node.id, v.effective_expires_at).await?;
        journal(&mut tx, p.node.id, v.journal_revision).await?;
        let previous:Option<(i64,DateTime<Utc>)>=sqlx::query_as("SELECT journal_revision,effective_expires_at FROM restore_launch_receipts WHERE tenant_id=$1 AND permit_id=$2").bind(r.tenant_id).bind(v.permit_id).fetch_optional(&mut *tx).await?;
        if previous.is_some_and(|old| old != (v.journal_revision, v.effective_expires_at)) {
            return Err(policy::blocked("Restore registration receipt changed"));
        }
        sqlx::query("INSERT INTO restore_launch_receipts(permit_id,tenant_id,restore_id,journal_revision,effective_expires_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(permit_id) DO NOTHING").bind(v.permit_id).bind(r.tenant_id).bind(r.id).bind(v.journal_revision).bind(v.effective_expires_at).execute(&mut *tx).await?;
        advance(&mut tx, &r, "RESTORE_RUNNING").await?;
        tx.commit().await?;
        Ok(())
    }
    /// A task result is bounded data evidence. It never asserts host death.
    pub(crate) async fn close_restore_task(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        exit: Option<&crate::backup_job::BackupJobExit>,
    ) -> Result<(), ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let r = lock_restore(&mut tx, engine, claim).await?;
        current_epoch(&mut tx, &r).await?;
        if !matches!(
            r.status.as_str(),
            "BLOCK_PENDING" | "RESTORE_PENDING" | "RESTORE_RUNNING" | "RESTORE_CLOSING"
        ) {
            return Err(policy::blocked(
                "Restore is outside its isolated writer stage",
            ));
        }
        if let Some(exit) = exit {
            let timestamp = now(&mut tx).await?;
            if !(0..=255).contains(&exit.exit_code)
                || exit.finished_at > timestamp + Duration::seconds(2)
            {
                return Err(policy::blocked(
                    "Restore result completion time or exit code is invalid",
                ));
            }
            let context_start: DateTime<Utc> = sqlx::query_scalar(
                "SELECT created_at FROM restore_job_contexts WHERE tenant_id=$1 AND restore_id=$2",
            )
            .bind(r.tenant_id)
            .bind(r.id)
            .fetch_one(&mut *tx)
            .await?;
            if exit.finished_at < context_start - Duration::seconds(2) {
                return Err(policy::blocked("Restore result predates its isolated task"));
            }
            let (bytes, sha) = if exit.exit_code == 0 {
                let source = current_source(&mut tx, &r).await?;
                let report = exit.report.as_ref().ok_or_else(policy::invalid)?;
                if !report.as_object().is_some_and(|v| v.len() == 8)
                    || report["protocol"] != 1
                    || report["backup_id"] != json!(r.backup_id)
                    || report["bytes"] != json!(source.identity.size_bytes)
                    || report["sha256"] != source.disk_sha256
                    || report["filesystem_mounted"] != false
                    || report["application_recovery_tested"] != false
                    || report["cloud_restore_certified"] != false
                    || report["restored_at"]
                        .as_str()
                        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                        .is_none()
                {
                    return Err(policy::blocked(
                        "Restore result differs from independently signed full disk identity",
                    ));
                }
                (
                    Some(i64::try_from(source.identity.size_bytes).map_err(|_| policy::invalid())?),
                    Some(source.disk_sha256),
                )
            } else {
                (None, None)
            };
            let finished =
                DateTime::<Utc>::from_timestamp_micros(exit.finished_at.timestamp_micros())
                    .ok_or_else(policy::invalid)?;
            let old:Option<RecordedIo>=sqlx::query_as("SELECT exit_code,bytes,disk_sha256,finished_at FROM restore_io_reports WHERE tenant_id=$1 AND restore_id=$2").bind(r.tenant_id).bind(r.id).fetch_optional(&mut *tx).await?;
            let expected = RecordedIo {
                exit_code: exit.exit_code,
                bytes,
                disk_sha256: sha.clone(),
                finished_at: finished,
            };
            if old.is_some_and(|v| v != expected) {
                return Err(policy::blocked("Restore data report changed"));
            }
            sqlx::query("INSERT INTO restore_io_reports(restore_id,tenant_id,exit_code,bytes,disk_sha256,finished_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(restore_id) DO NOTHING").bind(r.id).bind(r.tenant_id).bind(exit.exit_code).bind(bytes).bind(sha).bind(finished).execute(&mut *tx).await?;
        }
        advance(&mut tx, &r, "RESTORE_CLOSING").await?;
        tx.commit().await?;
        Ok(())
    }
    pub(crate) async fn prepare_restore_close(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<TerminationChallenge, ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let r = lock_restore(&mut tx, engine, claim).await?;
        current_epoch(&mut tx, &r).await?;
        if r.status != "RESTORE_CLOSING" {
            return Err(policy::blocked(
                "Restore writer has not permanently entered closing",
            ));
        }
        let p = permit(&mut tx, &r).await?.ok_or_else(|| {
            policy::blocked("Missing restore permit remains unknown and retains accounting")
        })?;
        let timestamp = now(&mut tx).await?;
        let lease: DateTime<Utc> =
            sqlx::query_scalar("SELECT lease_until FROM operations WHERE tenant_id=$1 AND id=$2")
                .bind(r.tenant_id)
                .bind(r.operation_id)
                .fetch_one(&mut *tx)
                .await?;
        let expires = (timestamp + Duration::seconds(25)).min(lease);
        if expires <= timestamp + Duration::seconds(2) {
            return Err(policy::blocked(
                "Restore controller lease is too short for a fresh close challenge",
            ));
        }
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO restore_close_challenges(id,tenant_id,restore_id,permit_id,lease_token,issued_at,not_after) VALUES($1,$2,$3,$4,$5,$6,$7)").bind(id).bind(r.tenant_id).bind(r.id).bind(p.request.permit_id).bind(claim.lease_token).bind(timestamp).bind(expires).execute(&mut *tx).await?;
        let request = CloseRequest {
            protocol: PROTOCOL_VERSION,
            challenge_id: id,
            node: p.request.node.clone(),
            launch: p.request.launch.clone(),
            reason: CloseReason::Stop,
            challenge_expires_at: expires,
        };
        tx.commit().await?;
        Ok(TerminationChallenge { request, permit: p })
    }
    pub(crate) async fn record_restore_termination(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        verified: &VerifiedLocalTermination,
    ) -> Result<Uuid, ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let r = lock_restore(&mut tx, engine, claim).await?;
        current_epoch(&mut tx, &r).await?;
        let p = permit(&mut tx, &r).await?.ok_or_else(policy::invalid)?;
        let v = verified.response();
        let issued:DateTime<Utc>=sqlx::query_scalar("SELECT issued_at FROM restore_close_challenges WHERE tenant_id=$1 AND restore_id=$2 AND id=$3 AND permit_id=$4 AND lease_token=$5 AND not_after>clock_timestamp()")
            .bind(r.tenant_id).bind(r.id).bind(v.challenge_id).bind(p.request.permit_id).bind(claim.lease_token).fetch_optional(&mut *tx).await?.ok_or_else(||policy::blocked("Restore close challenge expired or belongs to another claim"))?;
        let evidence = v.evidence.as_ref().ok_or_else(policy::invalid)?;
        let timestamp = now(&mut tx).await?;
        if r.status != "RESTORE_CLOSING"
            || v.state != ObservationState::Terminated
            || v.node != p.request.node
            || v.launch != p.request.launch
            || v.observed_at < issued - Duration::seconds(2)
            || v.observed_at > timestamp + Duration::seconds(2)
        {
            return Err(policy::blocked(
                "Verified restore termination does not bind this closed writer",
            ));
        }
        journal(&mut tx, p.node.id, evidence.journal_revision).await?;
        let raw = json!(v);
        let bytes = serde_json::to_vec(&raw).map_err(|_| policy::invalid())?;
        if bytes.len() > 65536 {
            return Err(policy::blocked(
                "Restore termination evidence exceeds limit",
            ));
        }
        let digest = hex::encode(Sha256::digest(bytes));
        if let Some((id,old))=sqlx::query_as::<_,(Uuid,String)>("SELECT id,evidence_sha256 FROM restore_termination_proofs WHERE tenant_id=$1 AND permit_id=$2").bind(r.tenant_id).bind(p.request.permit_id).fetch_optional(&mut *tx).await?{
            if old!=digest{return Err(policy::blocked("Restore proof conflicts with its single append-only closure"));}tx.commit().await?;return Ok(id);
        }
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO restore_termination_proofs(id,tenant_id,restore_id,permit_id,challenge_id,runtime_node_id,evidence,journal_revision,evidence_sha256,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
            .bind(id).bind(r.tenant_id).bind(r.id).bind(p.request.permit_id).bind(v.challenge_id).bind(p.node.id).bind(raw).bind(evidence.journal_revision).bind(digest).bind(v.observed_at).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(id)
    }
    pub(crate) async fn record_restore_cleanup(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        proof: Uuid,
        cleanup: &VerifiedRestoreCleanup,
    ) -> Result<(), ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let r = lock_restore(&mut tx, engine, claim).await?;
        current_epoch(&mut tx, &r).await?;
        let p = permit(&mut tx, &r).await?.ok_or_else(policy::invalid)?;
        let timestamp = now(&mut tx).await?;
        let recorded:Option<DateTime<Utc>>=sqlx::query_scalar("SELECT recorded_at FROM restore_termination_proofs WHERE tenant_id=$1 AND restore_id=$2 AND id=$3 AND permit_id=$4 AND challenge_id=$5")
            .bind(r.tenant_id).bind(r.id).bind(proof).bind(p.request.permit_id).bind(cleanup.challenge_id).fetch_optional(&mut *tx).await?;
        if r.status != "RESTORE_CLOSING"
            || cleanup.node != p.request.node
            || cleanup.launch != p.request.launch
            || recorded.is_none_or(|v| {
                cleanup.pod_absent_at < v - Duration::seconds(2)
                    || cleanup.volume_checked_at < v - Duration::seconds(2)
            })
            || [cleanup.pod_absent_at, cleanup.volume_checked_at]
                .iter()
                .any(|v| {
                    *v < timestamp - Duration::seconds(30) || *v > timestamp + Duration::seconds(2)
                })
        {
            return Err(policy::blocked(
                "Restore cleanup lacks fresh exact verified host closure",
            ));
        }
        sqlx::query("INSERT INTO restore_cleanup_receipts(proof_id,tenant_id,restore_id,pod_uid,pvc_uid,pv_uid,cloud_disk,pod_absent_at,volume_checked_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(proof_id) DO NOTHING")
            .bind(proof).bind(r.tenant_id).bind(r.id).bind(cleanup.launch.pod_uid).bind(cleanup.launch.pvc_uid).bind(cleanup.launch.pv_uid).bind(&cleanup.launch.csi_volume_handle).bind(cleanup.pod_absent_at).bind(cleanup.volume_checked_at).execute(&mut *tx).await?;
        // A revoked/failing writer remains closed and retained. A later stage must
        // independently authorize snapshot creation or prove resource cleanup.
        tx.commit().await?;
        Ok(())
    }
}
