//! Append-only backup launch/close ledger; shared nodeguard evidence rules apply.
use super::*;
use crate::{
    backup_host::{VerifiedBackupCleanup, VerifiedBackupLaunch},
    backup_runtime::BoundBackupVolume,
    nodeguard::protocol::{
        BackupStage, CloseReason, CloseRequest, LaunchBinding, LaunchPurpose, NodeBinding,
        ObservationState, PROTOCOL_VERSION, RegisterLaunchRequest,
    },
    termination_client::{VerifiedLaunchRegistration, VerifiedLocalTermination},
    termination_ledger::{LaunchPermit, RuntimeNode, TerminationChallenge},
};
use sha2::{Digest, Sha256};

impl Database {
    pub(crate) async fn backup_bound_volume(
        &self,
        tenant: Uuid,
        attempt: Uuid,
    ) -> Result<Option<BoundBackupVolume>, ApiError> {
        let mut tx = self.begin(tenant).await?;
        let row =
            sqlx::query("SELECT * FROM backup_clone_receipts WHERE tenant_id=$1 AND attempt_id=$2")
                .bind(tenant)
                .bind(attempt)
                .fetch_optional(&mut *tx)
                .await?;
        let result = row
            .map(|r| -> Result<_, ApiError> {
                Ok(BoundBackupVolume {
                    pvc_uid: r.try_get("pvc_uid")?,
                    pv_uid: r.try_get("pv_uid")?,
                    pv_name: r.try_get("pv_name")?,
                    cloud_disk: r.try_get("cloud_disk")?,
                    size_bytes: u64::try_from(r.try_get::<i64, _>("size_bytes")?)
                        .map_err(|_| internal("Invalid clone size"))?,
                })
            })
            .transpose()?;
        tx.commit().await?;
        Ok(result)
    }
    pub(crate) async fn prepare_backup_launch(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        observed: &VerifiedBackupLaunch,
    ) -> Result<LaunchPermit, ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let b = lock_backup(&mut tx, engine, claim).await?;
        authorize_backup(&mut tx, &b).await?;
        let (attempt, stage) = active_attempt(&b)?;
        if b.status.ends_with("CLOSING") {
            return Err(blocked(
                "Closed backup attempt cannot receive another launch permit",
            ));
        }
        let now = now(&mut tx).await?;
        if observed.observed_at < now - Duration::seconds(10)
            || observed.observed_at > now + Duration::seconds(2)
        {
            return Err(blocked("Backup Kubernetes launch observation expired"));
        }
        let context:Value=sqlx::query_scalar("SELECT context FROM backup_job_contexts WHERE tenant_id=$1 AND attempt_id=$2 AND deadline>clock_timestamp()")
            .bind(b.tenant_id).bind(attempt).fetch_optional(&mut *tx).await?.ok_or_else(||blocked("Backup Job deadline elapsed"))?;
        let context: crate::backup_manifest::BackupManifestContext =
            serde_json::from_value(context).map_err(|_| internal("Backup Job context invalid"))?;
        let job = attempt_binding(&mut tx, b.tenant_id, attempt, "JOB")
            .await?
            .ok_or_else(|| blocked("Known Job required"))?;
        let pod = attempt_binding(&mut tx, b.tenant_id, attempt, "POD")
            .await?
            .ok_or_else(|| blocked("Known Pod required"))?;
        let launch = &observed.launch;
        let source = b.source()?;
        let purpose = LaunchPurpose::Backup {
            backup_id: b.id,
            attempt_id: attempt,
            job_uid: job,
            stage,
            image_ref: context.image,
            source_pvc_uid: source.pvc_uid,
        };
        if launch.purpose != purpose
            || launch.tenant_id != b.tenant_id
            || launch.project_id != b.project_id
            || launch.instance_id != b.instance_id
            || launch.workspace_id != b.workspace_id
            || launch.generation != b.source_generation
            || launch.launch_id != attempt
            || launch.pod_uid != pod
            || observed.node.cluster_epoch != b.cluster_epoch
            || !launch.validate()
            || !observed.node.validate()
        {
            return Err(blocked("Backup launch does not match immutable ledger"));
        }
        if stage == BackupStage::Capture {
            let exact:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM backup_clone_receipts WHERE tenant_id=$1 AND attempt_id=$2 AND pvc_uid=$3 AND pv_uid=$4 AND pv_name=$5 AND cloud_disk=$6 AND size_bytes=$7)")
                .bind(b.tenant_id).bind(attempt).bind(launch.pvc_uid).bind(launch.pv_uid).bind(&launch.pv_name).bind(&launch.csi_volume_handle).bind(i64::try_from(source.size_bytes).map_err(|_|internal("size overflow"))?).fetch_one(&mut *tx).await?;
            if !exact {
                return Err(blocked(
                    "Bound clone identity differs from persisted receipt",
                ));
            }
        }
        let expiry: DateTime<Utc> = sqlx::query_scalar(
            "SELECT deadline FROM backup_job_contexts WHERE tenant_id=$1 AND attempt_id=$2",
        )
        .bind(b.tenant_id)
        .bind(attempt)
        .fetch_one(&mut *tx)
        .await?;
        let n = node(&mut tx, &observed.node, true).await?;
        certified(&mut tx, n.id, expiry).await?;
        if let Some(existing) = permit_for(&mut tx, b.tenant_id, attempt).await? {
            if existing.node.id != n.id
                || existing.request.launch != *launch
                || existing.request.node != observed.node
                || existing.request.expires_at != expiry
            {
                return Err(blocked(
                    "Backup attempt cannot move Pod/node or extend automatically",
                ));
            }
            tx.commit().await?;
            return Ok(existing);
        }
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO backup_launch_permits(id,tenant_id,backup_id,attempt_id,runtime_node_id,launch,pod_uid,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(id).bind(b.tenant_id).bind(b.id).bind(attempt).bind(n.id).bind(json!(launch)).bind(pod).bind(expiry).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(LaunchPermit {
            request: RegisterLaunchRequest {
                protocol: PROTOCOL_VERSION,
                permit_id: id,
                node: n.node.clone(),
                launch: launch.clone(),
                expires_at: expiry,
            },
            node: n,
        })
    }
    pub(crate) async fn record_backup_registration(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        verified: &VerifiedLaunchRegistration,
    ) -> Result<(), ApiError> {
        let r = verified.response();
        let mut tx = self.begin(claim.tenant_id).await?;
        let b = lock_backup(&mut tx, engine, claim).await?;
        authorize_backup(&mut tx, &b).await?;
        let (attempt, stage) = active_attempt(&b)?;
        let p = permit_for(&mut tx, b.tenant_id, attempt)
            .await?
            .ok_or_else(|| blocked("Backup permit not found"))?;
        if p.request.permit_id != r.permit_id
            || p.request.node != r.node
            || p.request.launch != r.launch
            || r.effective_expires_at != p.request.expires_at
            || r.journal_revision <= 0
        {
            return Err(blocked(
                "Backup host registration differs from durable permit",
            ));
        }
        certified(&mut tx, p.node.id, r.effective_expires_at).await?;
        sqlx::query("INSERT INTO backup_launch_receipts(permit_id,tenant_id,journal_revision) VALUES($1,$2,$3) ON CONFLICT(permit_id) DO NOTHING").bind(r.permit_id).bind(b.tenant_id).bind(r.journal_revision).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO runtime_node_journal_highwater(runtime_node_id,max_revision) VALUES($1,$2) ON CONFLICT(runtime_node_id) DO UPDATE SET max_revision=GREATEST(runtime_node_journal_highwater.max_revision,EXCLUDED.max_revision),observed_at=clock_timestamp()")
            .bind(p.node.id).bind(r.journal_revision).execute(&mut *tx).await?;
        advance(
            &mut tx,
            &b,
            if stage == BackupStage::Capture {
                "CAPTURE_RUNNING"
            } else {
                "SEAL_RUNNING"
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    /// Revocation, timeout and output failure may close already accepted work.
    /// This safety transition does not depend on the original principal's grants.
    pub(crate) async fn close_backup_attempt(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        report: Option<&crate::backup_job::BackupJobExit>,
    ) -> Result<(), ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let b = lock_backup(&mut tx, engine, claim).await?;
        let (attempt, stage) = active_attempt(&b)?;
        if let Some(exit) = report {
            let finished =
                DateTime::<Utc>::from_timestamp_micros(exit.finished_at.timestamp_micros())
                    .ok_or_else(|| blocked("Invalid task completion time"))?;
            let old:Option<(i32,DateTime<Utc>)>=sqlx::query_as("SELECT exit_code,finished_at FROM backup_stage_results WHERE tenant_id=$1 AND attempt_id=$2")
                .bind(b.tenant_id).bind(attempt).fetch_optional(&mut *tx).await?;
            if old.is_some_and(|v| v != (exit.exit_code, finished)) {
                return Err(blocked("Task result changed"));
            }
            sqlx::query("INSERT INTO backup_stage_results(tenant_id,backup_id,attempt_id,exit_code,finished_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(attempt_id) DO NOTHING")
                .bind(b.tenant_id).bind(b.id).bind(attempt).bind(exit.exit_code).bind(finished).execute(&mut *tx).await?;
        }
        if stage == BackupStage::Capture
            && let Some(exit) = report
            && exit.exit_code == 0
        {
            let report = exit
                .report
                .clone()
                .ok_or_else(|| blocked("Capture exited without a valid result"))?;
            validate_capture_report(&report, b.source()?.size_bytes)?;
            let old: Option<Value> = sqlx::query_scalar(
                "SELECT report FROM backup_capture_reports WHERE tenant_id=$1 AND backup_id=$2",
            )
            .bind(b.tenant_id)
            .bind(b.id)
            .fetch_optional(&mut *tx)
            .await?;
            if old.as_ref().is_some_and(|v| v != &report) {
                return Err(blocked("Capture result changed"));
            }
            sqlx::query("INSERT INTO backup_capture_reports(backup_id,tenant_id,attempt_id,report) VALUES($1,$2,$3,$4) ON CONFLICT(backup_id) DO NOTHING").bind(b.id).bind(b.tenant_id).bind(attempt).bind(report).execute(&mut *tx).await?;
        }
        advance(
            &mut tx,
            &b,
            if stage == BackupStage::Capture {
                "CAPTURE_CLOSING"
            } else {
                "SEAL_CLOSING"
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    pub(crate) async fn prepare_backup_close(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<TerminationChallenge, ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let b = lock_backup(&mut tx, engine, claim).await?;
        let (attempt, _) = active_attempt(&b)?;
        if !b.status.ends_with("CLOSING") {
            return Err(blocked(
                "Backup attempt has not permanently entered closing",
            ));
        }
        let p = permit_for(&mut tx, b.tenant_id, attempt)
            .await?
            .ok_or_else(|| {
                blocked(
                    "Missing backup host permit remains UNKNOWN; no inferred never-started proof",
                )
            })?;
        current_epoch(&mut tx, b.cluster_epoch).await?;
        let now = now(&mut tx).await?;
        let lease: DateTime<Utc> =
            sqlx::query_scalar("SELECT lease_until FROM operations WHERE tenant_id=$1 AND id=$2")
                .bind(b.tenant_id)
                .bind(b.operation_id)
                .fetch_one(&mut *tx)
                .await?;
        let expiry = (now + Duration::seconds(25)).min(lease);
        if expiry <= now + Duration::seconds(2) {
            return Err(blocked("Backup worker lease too short"));
        }
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO backup_close_challenges(id,tenant_id,backup_id,permit_id,lease_token,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(id).bind(b.tenant_id).bind(b.id).bind(p.request.permit_id).bind(claim.lease_token).bind(now).bind(expiry).execute(&mut *tx).await?;
        let request = CloseRequest {
            protocol: PROTOCOL_VERSION,
            challenge_id: id,
            node: p.request.node.clone(),
            launch: p.request.launch.clone(),
            reason: CloseReason::Stop,
            challenge_expires_at: expiry,
        };
        tx.commit().await?;
        Ok(TerminationChallenge { request, permit: p })
    }
    pub(crate) async fn record_backup_termination(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        verified: &VerifiedLocalTermination,
    ) -> Result<Uuid, ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let b = lock_backup(&mut tx, engine, claim).await?;
        let (attempt, _) = active_attempt(&b)?;
        let r = verified.response();
        let p = permit_for(&mut tx, b.tenant_id, attempt)
            .await?
            .ok_or_else(|| blocked("Backup permit missing"))?;
        current_epoch(&mut tx, b.cluster_epoch).await?;
        let c=sqlx::query("SELECT * FROM backup_close_challenges WHERE tenant_id=$1 AND backup_id=$2 AND id=$3 AND permit_id=$4 AND lease_token=$5 AND expires_at>clock_timestamp()")
            .bind(b.tenant_id).bind(b.id).bind(r.challenge_id).bind(p.request.permit_id).bind(claim.lease_token).fetch_optional(&mut *tx).await?.ok_or_else(||blocked("Backup close challenge expired"))?;
        let evidence = r
            .evidence
            .as_ref()
            .ok_or_else(|| blocked("Host termination evidence absent"))?;
        if !b.status.ends_with("CLOSING")
            || r.state != ObservationState::Terminated
            || r.node != p.request.node
            || r.launch != p.request.launch
            || r.observed_at < c.try_get::<DateTime<Utc>, _>("created_at")? - Duration::seconds(2)
            || r.observed_at > now(&mut tx).await? + Duration::seconds(2)
        {
            return Err(blocked("Backup termination identity mismatch"));
        }
        sqlx::query("INSERT INTO runtime_node_journal_highwater(runtime_node_id,max_revision) VALUES($1,$2) ON CONFLICT(runtime_node_id) DO NOTHING").bind(p.node.id).bind(evidence.journal_revision).execute(&mut *tx).await?;
        let revision:i64=sqlx::query_scalar("SELECT max_revision FROM runtime_node_journal_highwater WHERE runtime_node_id=$1 FOR UPDATE").bind(p.node.id).fetch_one(&mut *tx).await?;
        if evidence.journal_revision < revision {
            return Err(blocked("Node journal regressed"));
        }
        sqlx::query("UPDATE runtime_node_journal_highwater SET max_revision=$2,observed_at=clock_timestamp() WHERE runtime_node_id=$1").bind(p.node.id).bind(evidence.journal_revision).execute(&mut *tx).await?;
        let value = json!(r);
        let bytes = serde_json::to_vec(&value).map_err(|_| internal("proof encoding"))?;
        if bytes.len() > 65536 {
            return Err(blocked("Backup host evidence exceeded bound"));
        }
        let digest = hex::encode(Sha256::digest(bytes));
        if let Some((id,old))=sqlx::query_as::<_,(Uuid,String)>("SELECT id,evidence_sha256 FROM backup_termination_proofs WHERE tenant_id=$1 AND challenge_id=$2").bind(b.tenant_id).bind(r.challenge_id).fetch_optional(&mut *tx).await?{
            if old!=digest{return Err(blocked("Backup proof conflict"))}tx.commit().await?;return Ok(id)
        }
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO backup_termination_proofs(id,tenant_id,backup_id,attempt_id,permit_id,challenge_id,runtime_node_id,journal_revision,evidence,evidence_sha256,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
            .bind(id).bind(b.tenant_id).bind(b.id).bind(attempt).bind(p.request.permit_id).bind(r.challenge_id).bind(p.node.id).bind(evidence.journal_revision).bind(value).bind(digest).bind(r.observed_at).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(id)
    }
    pub(crate) async fn record_backup_cleanup(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        proof: Uuid,
        cleanup: &VerifiedBackupCleanup,
    ) -> Result<(), ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let b = lock_backup(&mut tx, engine, claim).await?;
        let (attempt, stage) = active_attempt(&b)?;
        let p = permit_for(&mut tx, b.tenant_id, attempt)
            .await?
            .ok_or_else(|| blocked("Backup permit missing"))?;
        let now = now(&mut tx).await?;
        current_epoch(&mut tx, b.cluster_epoch).await?;
        let recorded:Option<DateTime<Utc>>=sqlx::query_scalar("SELECT recorded_at FROM backup_termination_proofs WHERE tenant_id=$1 AND backup_id=$2 AND id=$3 AND challenge_id=$4 AND attempt_id=$5 AND permit_id=$6")
            .bind(b.tenant_id).bind(b.id).bind(proof).bind(cleanup.challenge_id).bind(attempt).bind(p.request.permit_id).fetch_optional(&mut *tx).await?;
        if !b.status.ends_with("CLOSING")
            || cleanup.node != p.request.node
            || cleanup.launch != p.request.launch
            || recorded.is_none_or(|r| {
                cleanup.pod_absent_at < r - Duration::seconds(2)
                    || cleanup.volume_checked_at < r - Duration::seconds(2)
            })
            || [cleanup.pod_absent_at, cleanup.volume_checked_at]
                .iter()
                .any(|t| *t < now - Duration::seconds(30) || *t > now + Duration::seconds(2))
        {
            return Err(blocked("Backup cleanup lacks fresh matching proof"));
        }
        let job = match p.request.launch.purpose {
            LaunchPurpose::Backup { job_uid, .. } => job_uid,
            _ => return Err(blocked("Workload proof cannot close backup")),
        };
        sqlx::query("INSERT INTO backup_cleanup_receipts(proof_id,tenant_id,backup_id,pod_uid,job_uid,pod_absent_at,volume_checked_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(proof_id) DO NOTHING")
            .bind(proof).bind(b.tenant_id).bind(b.id).bind(cleanup.launch.pod_uid).bind(job).bind(cleanup.pod_absent_at).bind(cleanup.volume_checked_at).execute(&mut *tx).await?;
        if stage == BackupStage::Capture {
            let report:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM backup_capture_reports WHERE tenant_id=$1 AND backup_id=$2)").bind(b.tenant_id).bind(b.id).fetch_one(&mut *tx).await?;
            if report {
                advance(&mut tx, &b, "SEAL_PENDING").await?;
            }
            // Failed capture remains closed with its source hold and accounting.
            // Cancellation is a separate durable cleanup action, never inferred here.
        }
        tx.commit().await?;
        Ok(())
    }
}
fn active_attempt(b: &BackupRecord) -> Result<(Uuid, BackupStage), ApiError> {
    match b.status.as_str() {
        "CAPTURE_PENDING" | "CAPTURE_RUNNING" | "CAPTURE_CLOSING" => {
            Ok((b.capture_attempt_id, BackupStage::Capture))
        }
        "SEAL_PENDING" | "SEAL_RUNNING" | "SEAL_CLOSING" => {
            Ok((b.seal_attempt_id, BackupStage::Seal))
        }
        _ => Err(blocked("Backup is not in isolated task stage")),
    }
}
async fn now(tx: &mut Transaction<'_, Postgres>) -> Result<DateTime<Utc>, ApiError> {
    Ok(sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?)
}
async fn current_epoch(tx: &mut Transaction<'_, Postgres>, epoch: Uuid) -> Result<(), ApiError> {
    let current: Uuid =
        sqlx::query_scalar("SELECT cluster_epoch FROM platform_configuration WHERE singleton")
            .fetch_one(&mut **tx)
            .await?;
    if current != epoch {
        return Err(blocked("Backup belongs to previous cluster epoch"));
    }
    Ok(())
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
    if expiry.is_none_or(|e| e < until) {
        return Err(blocked(
            "Node certification does not cover backup launch deadline",
        ));
    }
    Ok(())
}
async fn node(
    tx: &mut Transaction<'_, Postgres>,
    expected: &NodeBinding,
    enabled: bool,
) -> Result<RuntimeNode, ApiError> {
    let r=sqlx::query("SELECT *,host(private_ip) AS address FROM runtime_nodes WHERE cluster_epoch=$1 AND node_uid=$2 AND boot_id=$3").bind(expected.cluster_epoch).bind(expected.node_uid).bind(expected.boot_id).fetch_optional(&mut **tx).await?.ok_or_else(||blocked("Backup node not enrolled"))?;
    let binding = NodeBinding {
        cluster_epoch: r.try_get("cluster_epoch")?,
        node_uid: r.try_get("node_uid")?,
        node_name: r.try_get("node_name")?,
        boot_id: r.try_get("boot_id")?,
        profile_sha256: r.try_get("profile_sha256")?,
    };
    if &binding != expected || enabled && !r.try_get::<bool, _>("enabled")? {
        return Err(blocked("Backup node enrollment changed"));
    }
    Ok(RuntimeNode {
        id: r.try_get("id")?,
        node: binding,
        private_ip: r.try_get("address")?,
        guard_port: u16::try_from(r.try_get::<i32, _>("guard_port")?)
            .map_err(|_| internal("guard port invalid"))?,
        cloud_account_id: r.try_get("cloud_account_id")?,
        region: r.try_get("region")?,
        cloud_instance_id: r.try_get("cloud_instance_id")?,
        enabled: r.try_get("enabled")?,
    })
}
async fn permit_for(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    attempt: Uuid,
) -> Result<Option<LaunchPermit>, ApiError> {
    let row=sqlx::query("SELECT p.*,n.cluster_epoch,n.node_uid,n.node_name,n.boot_id,n.profile_sha256 FROM backup_launch_permits p JOIN runtime_nodes n ON n.id=p.runtime_node_id WHERE p.tenant_id=$1 AND p.attempt_id=$2")
        .bind(tenant).bind(attempt).fetch_optional(&mut **tx).await?;
    let Some(r) = row else { return Ok(None) };
    let binding = NodeBinding {
        cluster_epoch: r.try_get("cluster_epoch")?,
        node_uid: r.try_get("node_uid")?,
        node_name: r.try_get("node_name")?,
        boot_id: r.try_get("boot_id")?,
        profile_sha256: r.try_get("profile_sha256")?,
    };
    let n = node(tx, &binding, false).await?;
    let launch: LaunchBinding = serde_json::from_value(r.try_get("launch")?)
        .map_err(|_| internal("Backup permit JSON invalid"))?;
    Ok(Some(LaunchPermit {
        request: RegisterLaunchRequest {
            protocol: PROTOCOL_VERSION,
            permit_id: r.try_get("id")?,
            node: binding,
            launch,
            expires_at: r.try_get("expires_at")?,
        },
        node: n,
    }))
}
fn validate_capture_report(v: &Value, size: u64) -> Result<(), ApiError> {
    let valid = v.as_object().is_some_and(|m| m.len() == 2)
        && v.get("snapshot_id")
            .and_then(Value::as_str)
            .is_some_and(crate::nodeguard::protocol::valid_sha256)
        && v.get("disk")
            .and_then(Value::as_object)
            .is_some_and(|m| m.len() == 2)
        && v.pointer("/disk/size_bytes").and_then(Value::as_u64) == Some(size)
        && v.pointer("/disk/sha256")
            .and_then(Value::as_str)
            .is_some_and(crate::nodeguard::protocol::valid_sha256);
    if !valid {
        return Err(blocked("Capture report identity/hash/size invalid"));
    }
    Ok(())
}
