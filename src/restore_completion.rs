//! Publication needs a bound, independent Filesystem volume plus observed
//! removal of the already-closed writer's control objects. Retained raw storage
//! remains allocated until a separate cloud GC proves physical absence.
use super::{
    ledger::{JobPlan, lock_restore, resource_binding},
    policy,
    snapshot_ledger::snapshot_plan,
};
use crate::{
    backup_admission::verify_job_object,
    backup_job::BackupJobRuntime,
    backup_manifest::{NAMESPACE, build_backup_manifests, config_name},
    db::Database,
    engine::{Claim, OperationEngine},
    error::ApiError,
    nodeguard::protocol::backup_job_name,
    runtime::RuntimeError,
    runtime_manifest::ManifestError,
};
use chrono::{DateTime, Duration, Utc};
use k8s_openapi::api::{
    batch::v1::Job,
    core::v1::{ConfigMap, Pod},
};
use kube::{
    Api,
    api::{DeleteParams, ListParams, Preconditions, PropagationPolicy},
};
use serde_json::Value;
use uuid::Uuid;

pub(crate) struct RestoreArtifactPlan {
    pub job: JobPlan,
    pub config_uid: Uuid,
    pub closed_pod_name: String,
}
pub(crate) struct VerifiedRestoreArtifacts {
    tenant_id: Uuid,
    restore_id: Uuid,
    job_uid: Uuid,
    config_uid: Uuid,
    observed_at: DateTime<Utc>,
}
fn require(ok: bool, why: &'static str) -> Result<(), RuntimeError> {
    if ok {
        Ok(())
    } else {
        Err(ManifestError::SpecificationDrift(why).into())
    }
}
fn encode(v: &impl serde::Serialize) -> Result<Value, RuntimeError> {
    serde_json::to_value(v).map_err(|_| RuntimeError::MissingIdentity)
}
/// The closed artifact plan permits only ordinary Foreground retry. This
/// does not relax live workload admission or unknown protection finalizers.
fn closed_control_view(mut value: Value) -> Result<Value, RuntimeError> {
    let deleting = value
        .pointer("/metadata/deletionTimestamp")
        .is_some_and(|v| !v.is_null());
    let finalizers = value.pointer("/metadata/finalizers");
    require(
        finalizers.is_none_or(|v| {
            v.as_array().is_some_and(|values| {
                values.is_empty()
                    || (deleting && values == &[Value::String("foregroundDeletion".into())])
            })
        }),
        "restore control has unexpected or duplicated finalizer",
    )?;
    require(
        value
            .pointer("/metadata/deletionGracePeriodSeconds")
            .is_none_or(|v| v.is_null() || (deleting && v.as_i64().is_some_and(|v| v >= 0))),
        "restore control has invalid deletion lifecycle",
    )?;
    if let Some(metadata) = value.get_mut("metadata").and_then(Value::as_object_mut) {
        for field in [
            "deletionTimestamp",
            "deletionGracePeriodSeconds",
            "finalizers",
        ] {
            metadata.remove(field);
        }
    }
    Ok(value)
}
fn deletion(uid: Uuid, rv: Option<String>) -> Result<DeleteParams, RuntimeError> {
    Ok(DeleteParams {
        propagation_policy: Some(PropagationPolicy::Foreground),
        preconditions: Some(Preconditions {
            uid: Some(uid.to_string()),
            resource_version: Some(rv.ok_or(RuntimeError::MissingIdentity)?),
        }),
        ..Default::default()
    })
}
impl BackupJobRuntime {
    async fn restore_pods_absent(
        &self,
        p: &RestoreArtifactPlan,
        job_uid: Uuid,
    ) -> Result<bool, RuntimeError> {
        let pods = Api::<Pod>::namespaced(self.runtime().client_clone(), NAMESPACE);
        if pods.get_opt(&p.closed_pod_name).await?.is_some() {
            return Ok(false);
        }
        let page = pods
            .list(
                &ListParams::default()
                    .labels(&format!("batch.kubernetes.io/controller-uid={job_uid}"))
                    .limit(2),
            )
            .await?;
        require(
            page.metadata.continue_.as_deref().is_none_or(str::is_empty),
            "restore cleanup pod inventory exceeded bound",
        )?;
        Ok(page.items.is_empty())
    }
    pub(crate) async fn finish_restore_artifacts(
        &self,
        p: &RestoreArtifactPlan,
    ) -> Result<Option<VerifiedRestoreArtifacts>, RuntimeError> {
        let job_uid = p.job.known_job.ok_or(RuntimeError::MissingIdentity)?;
        let job_name = backup_job_name(p.job.record.id, p.job.context.stage);
        let config_name = config_name(p.job.record.id);
        if !self.restore_pods_absent(p, job_uid).await? {
            return Ok(None);
        }
        let jobs = Api::<Job>::namespaced(self.runtime().client_clone(), NAMESPACE);
        if let Some(job) = jobs.get_opt(&job_name).await? {
            let value = closed_control_view(encode(&job)?)?;
            require(
                job.metadata.uid.as_deref() == Some(job_uid.to_string().as_str())
                    && job
                        .metadata
                        .owner_references
                        .as_ref()
                        .is_none_or(Vec::is_empty),
                "restore cleanup Job identity changed",
            )?;
            // Only the exact deleting Foreground lifecycle is normalized;
            // frozen workload, labels and owner identity remain verified.
            verify_job_object(&value, &p.job.context, job_uid).map_err(|_| {
                ManifestError::SpecificationDrift("restore cleanup Job specification changed")
            })?;
            if job.metadata.deletion_timestamp.is_none() {
                jobs.delete(
                    &job_name,
                    &deletion(job_uid, job.metadata.resource_version)?,
                )
                .await?;
            }
        }
        if jobs.get_opt(&job_name).await?.is_some() {
            return Ok(None);
        }
        if !self.restore_pods_absent(p, job_uid).await? {
            return Ok(None);
        }
        let configs = Api::<ConfigMap>::namespaced(self.runtime().client_clone(), NAMESPACE);
        if let Some(config) = configs.get_opt(&config_name).await? {
            let expected = build_backup_manifests(&p.job.context)?.config_map;
            let mut value = closed_control_view(encode(&config)?)?;
            if let Some(metadata) = value.get_mut("metadata").and_then(Value::as_object_mut) {
                for field in [
                    "uid",
                    "resourceVersion",
                    "creationTimestamp",
                    "generation",
                    "managedFields",
                    "selfLink",
                ] {
                    metadata.remove(field);
                }
            }
            require(
                config.metadata.uid.as_deref() == Some(p.config_uid.to_string().as_str())
                    && config
                        .metadata
                        .owner_references
                        .as_ref()
                        .is_none_or(Vec::is_empty)
                    && value == expected,
                "restore cleanup config identity or content changed",
            )?;
            if config.metadata.deletion_timestamp.is_none() {
                configs
                    .delete(
                        &config_name,
                        &deletion(p.config_uid, config.metadata.resource_version)?,
                    )
                    .await?;
            }
        }
        if configs.get_opt(&config_name).await?.is_some() {
            return Ok(None);
        }
        require(
            jobs.get_opt(&job_name).await?.is_none(),
            "restore Job reappeared after control-object cleanup",
        )?;
        if !self.restore_pods_absent(p, job_uid).await? {
            return Ok(None);
        }
        Ok(Some(VerifiedRestoreArtifacts {
            tenant_id: p.job.record.tenant_id,
            restore_id: p.job.record.id,
            job_uid,
            config_uid: p.config_uid,
            observed_at: Utc::now(),
        }))
    }
}
impl Database {
    pub(crate) async fn prepare_restore_artifacts(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<RestoreArtifactPlan, ApiError> {
        // Read the frozen Job even after principal/profile revocation. The next
        // transaction independently verifies its permanent host closure.
        let job = self.prepare_restore_cleanup_job(engine, claim).await?;
        let mut tx = self.begin(claim.tenant_id).await?;
        let r = lock_restore(&mut tx, engine, claim).await?;
        if !matches!(
            r.status.as_str(),
            "RESTORE_CLOSING" | "SNAPSHOT_PENDING" | "DELIVERY_PENDING"
        ) {
            return Err(policy::blocked(
                "Restore artifacts require a permanently closed writer",
            ));
        }
        let closure:Option<String>=sqlx::query_scalar("SELECT permit.request->'launch'->>'pod_name' FROM restore_launch_permits permit JOIN restore_termination_proofs proof ON proof.tenant_id=permit.tenant_id AND proof.permit_id=permit.id JOIN restore_cleanup_receipts cleanup ON cleanup.tenant_id=proof.tenant_id AND cleanup.proof_id=proof.id WHERE permit.tenant_id=$1 AND permit.restore_id=$2 AND cleanup.restore_id=permit.restore_id").bind(r.tenant_id).bind(r.id).fetch_optional(&mut *tx).await?;
        let config_uid = resource_binding(&mut tx, r.tenant_id, r.id, "CONFIG")
            .await?
            .ok_or_else(policy::invalid)?;
        let closed_pod_name = closure.ok_or_else(|| {
            policy::blocked(
                "Restore control cleanup requires exact trusted host and volume cleanup",
            )
        })?;
        if job.record.id != r.id
            || job.known_job != resource_binding(&mut tx, r.tenant_id, r.id, "JOB").await?
        {
            return Err(policy::invalid());
        }
        tx.commit().await?;
        Ok(RestoreArtifactPlan {
            job,
            config_uid,
            closed_pod_name,
        })
    }
    pub(crate) async fn publish_restore(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        proof: &VerifiedRestoreArtifacts,
    ) -> Result<(), ApiError> {
        let mut tx = self.begin(claim.tenant_id).await?;
        let r = lock_restore(&mut tx, engine, claim).await?;
        if r.status != "DELIVERY_PENDING" {
            return Err(policy::blocked(
                "Restore publication requires bound filesystem delivery",
            ));
        }
        snapshot_plan(&mut tx, &r).await?;
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        if proof.tenant_id != r.tenant_id
            || proof.restore_id != r.id
            || proof.observed_at < now - Duration::seconds(30)
            || proof.observed_at > now + Duration::seconds(2)
            || resource_binding(&mut tx, r.tenant_id, r.id, "JOB").await? != Some(proof.job_uid)
            || resource_binding(&mut tx, r.tenant_id, r.id, "CONFIG").await?
                != Some(proof.config_uid)
        {
            return Err(policy::blocked(
                "Restore publication lacks fresh exact control-object absence",
            ));
        }
        sqlx::query("INSERT INTO restore_artifact_cleanup_receipts(restore_id,tenant_id,job_uid,config_uid,observed_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(restore_id) DO NOTHING")
            .bind(r.id).bind(r.tenant_id).bind(proof.job_uid).bind(proof.config_uid).bind(proof.observed_at).execute(&mut *tx).await?;
        let done: bool = sqlx::query_scalar("SELECT sandbox_publish_restore($1,$2,$3)")
            .bind(r.tenant_id)
            .bind(r.id)
            .bind(claim.lease_token)
            .fetch_one(&mut *tx)
            .await?;
        if !done {
            return Err(policy::blocked(
                "Restore publication current authority or immutable delivery receipt changed",
            ));
        }
        tx.commit().await?;
        Ok(())
    }
}
