//! Private RESTORE admission. The caller must be an authenticated apiserver;
//! submitted labels select durable authority and never provide it.
use super::RestoreRecord;
use crate::{
    admission::{AdmissionRequest, Denial},
    backup_admission::{
        BackupAdmissionIdentities, BackupAdmissionPlan, BackupAuthority, validate_backup_resource,
        verify_job_object,
    },
    backup_job::{BackupCloudSettings, BackupJobRuntime},
    backup_manifest::{BackupManifestContext, NAMESPACE, block_pvc_name},
    backup_runtime::BoundBackupVolume,
    db::Database,
    nodeguard::protocol::BackupStage,
    runtime_manifest::validate_existing_pvc,
};
use k8s_openapi::api::{batch::v1::Job, core::v1::PersistentVolumeClaim};
use kube::Api;
use serde_json::{Value, json};
use sqlx::{FromRow, Postgres, Row, Transaction};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use uuid::Uuid;
#[path = "restore_control_admission.rs"]
mod control;
#[path = "restore_node_admission.rs"]
mod node;
#[path = "restore_raw_admission.rs"]
mod raw;
#[path = "restore_raw_bound_authority.rs"]
mod raw_bound;
pub(crate) use raw_bound::{
    RawBoundAttempt, RawBoundCollectionFacts, RawBoundDiskFacts, RawBoundDiskPurpose,
    RawBoundDiskScope, RawBoundPublicationAttempt, RawBoundRead, RawBoundRecordedDiskFacts,
};
#[path = "restore_raw_scheduling_admission.rs"]
mod raw_scheduling;
pub(crate) use raw_scheduling::RawBoundVendorFacts;
pub(super) use raw_scheduling::RawSchedulingRuntime;

type Decision<T> = Result<T, Denial>;
fn checked(ok: bool, message: &'static str) -> Decision<()> {
    if ok {
        Ok(())
    } else {
        Err(Denial { code: 403, message })
    }
}
#[track_caller]
fn dependency(_: impl std::fmt::Debug) -> Denial {
    tracing::error!(
        line = std::panic::Location::caller().line(),
        "Restore admission dependency failed"
    );
    Denial {
        code: 503,
        message: "Restore admission dependency unavailable",
    }
}
fn observation(error: crate::runtime::RuntimeError) -> Denial {
    match error {
        crate::runtime::RuntimeError::Kubernetes(_) => dependency(error),
        _ => Denial {
            code: 403,
            message: "Observed restore security or resource identity differs from durable authority",
        },
    }
}
fn selector(value: &Value, path: &str) -> Decision<Uuid> {
    value
        .pointer(path)
        .and_then(Value::as_str)
        .and_then(|v| Uuid::parse_str(v).ok())
        .filter(|v| !v.is_nil())
        .ok_or(Denial {
            code: 403,
            message: "Restore scope selector missing",
        })
}
struct Loaded {
    record: RestoreRecord,
    context: BackupManifestContext,
    cloud: BackupCloudSettings,
    storage_contract: super::storage_contract::RestoreStorageContract,
    bindings: BTreeMap<String, Uuid>,
    intents: BTreeMap<String, (String, Value)>,
    volume: Option<BoundBackupVolume>,
    pin: Value,
    valid_until: Instant,
}
#[derive(Clone)]
pub(super) struct RestoreAdmissionService {
    pub database: Database,
    pub runtime: BackupJobRuntime,
    pub identities: BackupAdmissionIdentities,
    pub scheduler: crate::admission::ControllerIdentity,
    pub control_gc: crate::admission::ControllerIdentity,
    pub raw_scheduling: Option<RawSchedulingRuntime>,
}
impl RestoreAdmissionService {
    async fn load(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant: Uuid,
        restore: Uuid,
    ) -> Decision<Loaded> {
        let reading = Instant::now();
        let row=sqlx::query("SELECT r.*,bp.settings AS cloud_settings,c.context,c.deadline AS job_deadline,(SELECT to_jsonb(raw) FROM restore_block_receipts raw WHERE raw.tenant_id=r.tenant_id AND raw.restore_id=r.id) AS raw FROM restores r JOIN backup_profiles bp ON bp.id=r.profile_id JOIN restore_job_contexts c ON c.tenant_id=r.tenant_id AND c.restore_id=r.id WHERE r.tenant_id=$1 AND r.id=$2")
            .bind(tenant).bind(restore).fetch_optional(&mut **tx).await.map_err(|e| dependency(e))?.ok_or(Denial{code:403,message:"Restore intent missing"})?;
        let record = RestoreRecord::from_row(&row).map_err(|e| dependency(e))?;
        let context_value: Value = row.try_get("context").map_err(|e| dependency(e))?;
        let settings: Value = row.try_get("cloud_settings").map_err(|e| dependency(e))?;
        let context: BackupManifestContext =
            serde_json::from_value(context_value.clone()).map_err(|e| dependency(e))?;
        let cloud = serde_json::from_value(settings.clone()).map_err(|e| dependency(e))?;
        let current: bool = sqlx::query_scalar("SELECT sandbox_restore_authorized($1,$2,true)")
            .bind(tenant)
            .bind(restore)
            .fetch_one(&mut **tx)
            .await
            .map_err(|e| dependency(e))?;
        checked(
            current
                && matches!(
                    record.status.as_str(),
                    "RESTORE_PENDING" | "RESTORE_RUNNING"
                )
                && context.stage == BackupStage::Restore
                && context.attempt_id == restore
                && context.backup_id == record.backup_id
                && context.tenant_id == tenant
                && context.project_id == record.source_project_id
                && context.cluster_epoch == record.cluster_epoch
                && context.expected_manifest_sha256.as_deref()
                    == Some(record.source_manifest_sha256.as_str()),
            "Current restore scope, claim or certification unavailable",
        )?;
        let mut intents = BTreeMap::new();
        let mut bindings = BTreeMap::new();
        for row in sqlx::query("SELECT i.kind,i.name,i.expected_object,b.uid FROM restore_resource_intents i LEFT JOIN restore_resource_bindings b ON b.tenant_id=i.tenant_id AND b.intent_id=i.id WHERE i.tenant_id=$1 AND i.restore_id=$2")
            .bind(tenant).bind(restore).fetch_all(&mut **tx).await.map_err(|e| dependency(e))? {
            let kind:String=row.try_get("kind").map_err(|e| dependency(e))?;
            if let Some(uid)=row.try_get::<Option<Uuid>,_>("uid").map_err(|e| dependency(e))? { bindings.insert(kind.clone(),uid); }
            if let Some(expected)=row.try_get::<Option<Value>,_>("expected_object").map_err(|e| dependency(e))? {
                intents.insert(kind,(row.try_get("name").map_err(|e| dependency(e))?,expected));
            }
        }
        let raw: Option<Value> = row.try_get("raw").map_err(|e| dependency(e))?;
        let volume = raw
            .as_ref()
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()
            .map_err(|e| dependency(e))?;
        let storage_contract = record.storage().map_err(|e| dependency(e))?;
        storage_contract
            .validate_cloud(&cloud)
            .map_err(|e| dependency(e))?;
        let pin = json!({"profile":record.profile_id,"epoch":record.cluster_epoch,"source":record.source_identity,"manifest":record.source_manifest_sha256,
            "context":context_value,"settings":settings,"storage_contract":record.storage_contract,"bindings":bindings,"intents":intents,"raw":raw});
        // The database horizon is separate from the immutable authority pin.
        // Starting before the first SQL read conservatively deducts every SQL
        // wait and the later COMMIT acknowledgement from the remaining budget.
        let budget: Option<i64> =
            sqlx::query_scalar("SELECT sandbox_restore_admission_horizon($1,$2)")
                .bind(tenant)
                .bind(restore)
                .fetch_one(&mut **tx)
                .await
                .map_err(dependency)?;
        let budget = budget
            .and_then(|value| u64::try_from(value).ok())
            .filter(|value| *value > 0);
        checked(
            budget.is_some(),
            "Restore admission authority already expired",
        )?;
        let valid_until = reading
            .checked_add(Duration::from_micros(budget.ok_or(Denial {
                code: 403,
                message: "Restore admission authority horizon missing",
            })?))
            .ok_or(Denial {
                code: 403,
                message: "Restore admission authority horizon invalid",
            })?;
        Ok(Loaded {
            record,
            context,
            cloud,
            storage_contract,
            bindings,
            intents,
            volume,
            pin,
            valid_until,
        })
    }
    async fn observe(&self, a: &Loaded, request: &AdmissionRequest) -> Decision<()> {
        self.runtime
            .verify_network(&a.cloud)
            .await
            .map_err(observation)?;
        self.runtime
            .verify_profile_secrets(&a.cloud)
            .await
            .map_err(observation)?;
        self.runtime
            .verify_restore_storage_class(
                &a.storage_contract,
                super::storage_contract::RestoreStoragePurpose::Raw,
            )
            .await
            .map_err(observation)?;
        let expected = a.intents.get("BLOCK_PVC").ok_or(Denial {
            code: 403,
            message: "Restore raw intent missing",
        })?;
        let known = a.bindings.get("BLOCK_PVC").ok_or(Denial {
            code: 403,
            message: "Restore raw claim identity missing",
        })?;
        let expected: PersistentVolumeClaim =
            serde_json::from_value(expected.1.clone()).map_err(|e| dependency(e))?;
        let pvcs = Api::<PersistentVolumeClaim>::namespaced(
            self.runtime.runtime().client_clone(),
            NAMESPACE,
        );
        let actual = pvcs
            .get(&block_pvc_name(a.record.id))
            .await
            .map_err(|e| dependency(e))?;
        validate_existing_pvc(&actual, &expected, Some(known.to_string().as_str())).map_err(
            |_| Denial {
                code: 403,
                message: "Restore raw claim differs from immutable intent",
            },
        )?;
        // WFFC may legitimately have no PV yet. Only the later host permit can
        // authorize writes, after a fixed raw receipt and enrolled node exist.
        if let Some(volume) = &a.volume {
            self.runtime
                .verify_block_binding(a.record.id, volume)
                .await
                .map_err(observation)?;
        }
        if request.resource.resource == "pods"
            || (request.resource.resource == "jobs" && request.operation == "UPDATE")
        {
            let job_uid = a.bindings.get("JOB").copied().ok_or(Denial {
                code: 403,
                message: "Restore Job identity missing",
            })?;
            let name =
                crate::nodeguard::protocol::backup_job_name(a.record.id, BackupStage::Restore);
            let job = Api::<Job>::namespaced(self.runtime.runtime().client_clone(), NAMESPACE)
                .get(&name)
                .await
                .map_err(|e| dependency(e))?;
            let job = serde_json::to_value(job).map_err(|e| dependency(e))?;
            verify_job_object(&job, &a.context, job_uid)?;
            if request.resource.resource == "pods" {
                checked(
                    job.pointer("/spec/suspend") == Some(&json!(false)),
                    "Suspended restore Job cannot create a Pod",
                )?;
            }
        }
        Ok(())
    }
    pub async fn decide(&self, request: &AdmissionRequest) -> Decision<()> {
        if request.resource.resource == "persistentvolumeclaims" && request.operation == "UPDATE" {
            // Optional private runtime cannot open a fallback storage route.
            // The fixed child also checks group/version/subresource/caller.
            return Box::pin(self.decide_raw_scheduling(request)).await;
        }
        if matches!(
            request.resource.resource.as_str(),
            "persistentvolumeclaims" | "persistentvolumes"
        ) {
            // Raw parent creation has no Job/Pod/host permit dependency. All
            // other selected storage mutations remain explicitly unsupported.
            return Box::pin(self.decide_raw_parent(request)).await;
        }
        if request.resource.resource == "pods"
            && matches!(request.sub_resource.as_str(), "binding" | "status")
        {
            // Keep the isolated node workflow off the common resource future's
            // stack frame; it performs several independent Kubernetes reads.
            return Box::pin(self.decide_node(request)).await;
        }
        if request.operation == "DELETE"
            || (request.operation == "UPDATE"
                && (request.resource.resource == "pods"
                    || request.sub_resource == "status"
                    || request.old_object.as_ref().is_some_and(|old| {
                        old.pointer("/metadata/deletionTimestamp")
                            .is_some_and(|v| !v.is_null())
                    })))
        {
            return Box::pin(self.decide_control(request)).await;
        }
        checked(
            request.namespace == NAMESPACE
                && request.sub_resource.is_empty()
                && !request.dry_run
                && matches!(request.operation.as_str(), "CREATE" | "UPDATE")
                && matches!(
                    request.resource.resource.as_str(),
                    "jobs" | "configmaps" | "pods"
                ),
            "Restore operation has no implemented admission path",
        )?;
        checked(
            self.identities.controller.username
                == "system:serviceaccount:sandbox-system:sandbox-backup-controller"
                && Uuid::parse_str(&self.identities.controller.uid).is_ok_and(|v| !v.is_nil())
                && self.identities.job_controller.valid()
                && match &self.identities.job_controller {
                    crate::admission::ControllerIdentity::ServiceAccount { username, uid } => {
                        username != &self.identities.controller.username
                            && uid != &self.identities.controller.uid
                    }
                    crate::admission::ControllerIdentity::ControlPlane { username } => {
                        username == "system:kube-controller-manager"
                    }
                },
            "Reviewed restore controller identities required",
        )?;
        let value = request.object.as_ref().ok_or(Denial {
            code: 403,
            message: "Restore resource body missing",
        })?;
        let tenant = selector(value, "/metadata/labels/sandbox.platform~1tenant-id")?;
        let restore = selector(
            value,
            "/metadata/labels/sandbox.platform~1backup-attempt-id",
        )?;
        let observed_at = Instant::now();
        let mut tx = self
            .database
            .begin(tenant)
            .await
            .map_err(|e| dependency(e))?;
        let loaded = self.load(&mut tx, tenant, restore).await?;
        tx.commit().await.map_err(|e| dependency(e))?;
        checked(
            Instant::now() < loaded.valid_until && observed_at.elapsed() <= Duration::from_secs(10),
            "Restore authority expired after initial COMMIT acknowledgement",
        )?;
        self.observe(&loaded, request).await?;
        let mut tx = self
            .database
            .begin(tenant)
            .await
            .map_err(|e| dependency(e))?;
        let locked: bool = sqlx::query_scalar("SELECT sandbox_lock_restore_admission($1,$2)")
            .bind(tenant)
            .bind(restore)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| dependency(e))?;
        checked(
            locked && observed_at.elapsed() <= Duration::from_secs(10),
            "Restore authority expired while waiting",
        )?;
        let current = self.load(&mut tx, tenant, restore).await?;
        checked(
            current.pin == loaded.pin,
            "Restore resource or authority changed during observation",
        )?;
        let kind = match request.resource.resource.as_str() {
            "jobs" => "JOB",
            "configmaps" => "CONFIG",
            _ => "POD",
        };
        if kind != "POD" {
            let (name, expected) = current.intents.get(kind).ok_or(Denial {
                code: 403,
                message: "Durable restore resource intent required",
            })?;
            let manifests = crate::backup_manifest::build_backup_manifests(&current.context)
                .map_err(|e| dependency(e))?;
            let controlled = if kind == "JOB" {
                manifests.job
            } else {
                manifests.config_map
            };
            checked(
                name == &request.name && expected == &controlled,
                "Restore request differs from durable manifest intent",
            )?;
            checked(
                request.operation != "CREATE" || !current.bindings.contains_key(kind),
                "Bound restore resource cannot be recreated",
            )?;
        }
        let authority = BackupAuthority {
            context: current.context,
            block: None,
            hold_active: true,
            intent_active: true,
            certification_current: true,
            network_verified: true,
            job_uid: current.bindings.get("JOB").copied(),
            pod_uid: current.bindings.get("POD").copied(),
            pvc_uid: current.bindings.get("BLOCK_PVC").copied(),
            start_allowed: true,
        };
        match validate_backup_resource(request, &authority, &self.identities)? {
            BackupAdmissionPlan::Allow => {}
            BackupAdmissionPlan::ConsumePodCreate {
                attempt_id,
                review_uid,
                job_uid,
            } => {
                checked(attempt_id == restore, "Restore attempt changed")?;
                let allowed: bool =
                    sqlx::query_scalar("SELECT sandbox_admit_restore_pod($1,$2,$3,$4)")
                        .bind(tenant)
                        .bind(restore)
                        .bind(review_uid)
                        .bind(job_uid)
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(|e| dependency(e))?;
                checked(allowed, "Restore Pod has no remaining one-shot admission")?;
            }
        }
        tx.commit().await.map_err(|e| dependency(e))?;
        checked(
            Instant::now() < loaded.valid_until
                && Instant::now() < current.valid_until
                && observed_at.elapsed() <= Duration::from_secs(10),
            "Restore authority expired after final COMMIT acknowledgement",
        )?;
        Ok(())
    }
}
