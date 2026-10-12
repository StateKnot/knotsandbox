//! Actual read-only normal-claim collector. The returned opaque observation is
//! an upstream vendor TEMPLATE observation, not certification or a host permit.
//! No publication/activation hook is installed by this private candidate.
use crate::{
    backup_job::BackupJobRuntime,
    backup_manifest::{NAMESPACE, block_pvc_name},
    cloud_fencing::{
        CloudError, CloudErrorCode,
        raw_disk::{
            BackupDiskProtocolObservation, BackupRawDiskProtocolClient, RawDiskCloudConfig,
            RawDiskReadBudget,
        },
    },
    db::Database,
    engine::{Claim, OperationEngine},
    error::ApiError,
    restore::{
        admission::{RawBoundAttempt, RawBoundCollectionFacts, RawBoundDiskScope, RawBoundRead},
        raw_volume::{
            RawPvNodeFacts, RawPvProjection, RawPvShapeExpected, project_raw_pv_live_template,
            validate_raw_pvc_live_template,
        },
        storage_contract::RestoreStoragePurpose,
        vendor_profile::{RestoreVendorReport, VendorReportError},
    },
};
use axum::http::StatusCode;
use k8s_openapi::api::{
    core::v1::{Node, PersistentVolume, PersistentVolumeClaim},
    storage::v1::CSINode,
};
use kube::{Api, api::GetParams, core::Request};
use serde_json::Value;
use std::{sync::Arc, time::Instant};
use uuid::Uuid;

pub(crate) struct BackupRawBoundCollector {
    runtime: BackupJobRuntime,
    identity: RawDiskCloudConfig,
    budget: RawDiskReadBudget,
    vendor_report: Option<Arc<RestoreVendorReport>>,
}
// Private fields, no Deserialize/Clone/From<Value>/DTO or permitted=true flag.
// This does not expose a writer aggregate constructor or turn an unverified
// vendor template into an ACS3 proof. `disk` came from the signed transport;
// `pv` came from actual GETs; `current` came from the normal final SQL reader.
pub(crate) struct BackupRawBoundTemplateObservation {
    disk: BackupDiskProtocolObservation,
    pv: RawPvProjection,
    current: RawBoundRead,
    original_scope: RawBoundDiskScope,
}
impl BackupRawBoundTemplateObservation {
    pub(crate) fn current(
        &self,
        attempt: &RawBoundAttempt,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<(), ApiError> {
        self.original_scope.current().map_err(denial)?;
        self.disk.current().map_err(cloud_error)?;
        self.current
            .backup_current(attempt, engine, claim)
            .map_err(denial)
    }
    // Read-only comparison accessors, not a permission or a generic proof DTO.
    pub(crate) fn projection(&self) -> &RawPvProjection {
        &self.pv
    }
}
/// Owned normal current-claim read attempt. It still certifies only an actual
/// Bound GET matching the unverified vendor template, never a write/host permit.
pub(crate) struct BackupRawBoundTemplateAttempt {
    attempt: RawBoundAttempt,
    first: RawBoundRead,
    observed: BackupRawBoundTemplateObservation,
    vendor_report: Option<Arc<RestoreVendorReport>>,
    // Clone of the SAME authenticated runtime client that read this attempt.
    csi_client: kube::Client,
}
impl BackupRawBoundTemplateAttempt {
    pub(crate) fn current(&self, engine: &OperationEngine, claim: &Claim) -> Result<(), ApiError> {
        self.first
            .backup_current(&self.attempt, engine, claim)
            .map_err(denial)?;
        self.observed.current(&self.attempt, engine, claim)
    }
    pub(crate) fn projection(&self) -> &RawPvProjection {
        self.observed.projection()
    }
    fn handoff_deadline(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<Instant, ApiError> {
        self.current(engine, claim)?;
        // Each scope derives from the same original attempt and decoded SQL.
        // The final scope may legitimately be shorter than the original cloud
        // scope. Preserve the latter; never reset it or require both to equal.
        let first = self
            .first
            .backup_disk_scope(&self.attempt, engine, claim)
            .map_err(denial)?;
        let final_scope = self
            .observed
            .current
            .backup_disk_scope(&self.attempt, engine, claim)
            .map_err(denial)?;
        Ok(self
            .attempt
            .deadline()
            .map_err(denial)?
            .min(self.observed.original_scope.deadline())
            .min(first.deadline())
            .min(final_scope.deadline()))
    }
    // Configuration is expected data only. The fresh final Scope is derived
    // after full14 same-TX validation, never from caller-supplied report fields.
    fn compare_vendor_report(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<(), ApiError> {
        if let Some(report) = &self.vendor_report {
            let final_scope = self
                .observed
                .current
                .backup_disk_scope(&self.attempt, engine, claim)
                .map_err(denial)?;
            report
                .compare_scope(&final_scope)
                .map_err(vendor_report_error)?;
        }
        Ok(())
    }
    /// Current normal-role development caller. A real vendor certification
    /// factory is absent, so this consumes the whole owned TEMPLATE attempt,
    /// validates its actual final14 in the same TX, and refuses publication.
    /// It cannot insert a child row, create a host permit or return success.
    pub(crate) async fn refuse_unverified_publication(
        self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<(), ApiError> {
        let deadline = self.handoff_deadline(engine, claim)?;
        let end = tokio::time::Instant::from_std(deadline);
        let mut tx = tokio::time::timeout_at(end, async {
            self.current(engine, claim)?;
            engine.database.begin(claim.tenant_id).await
        })
        .await
        .map_err(|_| blocked())??;
        // Hold the actual TX in this async scope. A5 borrows the final read,
        // not the TX, and has no timer of its own: this outer deadline bounds
        // BEGIN, lock waits, full14 SQL, business checks and rollback ACK.
        let checked = tokio::time::timeout_at(end, async {
            self.current(engine, claim)?;
            self.observed
                .current
                .validate_backup_transaction(&self.attempt, engine, claim, &mut tx)
                .await
                .map_err(denial)
        })
        .await;
        // Keep every acquired same-TX token through rollback ACK. Extract its
        // sealed finite deadline BEFORE live checks: even an already expired
        // token must never fall back to a longer held collector deadline.
        let (refusal, rollback_deadline, publication) = match checked {
            Ok(Ok(publication)) => match publication.deadline() {
                Ok(pre_deadline) => {
                    let narrowed = deadline.min(pre_deadline);
                    let valid = publication
                        .sql_publication_pin()
                        .map_err(denial)
                        .and_then(|_| self.current(engine, claim))
                        .and_then(|_| self.compare_vendor_report(engine, claim));
                    // Pure report comparison can fail or consume the remaining
                    // horizon. Recheck the held same-TX token and original
                    // ownership even on failure; retain this new minimum.
                    let after_comparison = publication
                        .sql_publication_pin()
                        .map_err(denial)
                        .and_then(|_| self.current(engine, claim));
                    let refusal = if Instant::now() >= narrowed {
                        blocked()
                    } else {
                        match after_comparison.and(valid) {
                            Ok(()) => vendor_unavailable(),
                            Err(error) => error,
                        }
                    };
                    (refusal, Some(narrowed), Some(publication))
                }
                // If a finite deadline cannot be extracted, do not initiate
                // rollback under a guessed later deadline. Drop is UNKNOWN.
                Err(error) => (denial(error), None, Some(publication)),
            },
            Ok(Err(error)) => (error, Some(deadline), None),
            Err(_) => (blocked(), Some(deadline), None),
        };
        let acknowledged =
            if let Some(rollback_deadline) = rollback_deadline.filter(|d| Instant::now() < *d) {
                let rollback_end = tokio::time::Instant::from_std(rollback_deadline);
                matches!(
                    tokio::time::timeout_at(rollback_end, tx.rollback()).await,
                    Ok(Ok(()))
                ) && Instant::now() < rollback_deadline
                    && self.current(engine, claim).is_ok()
                    && publication
                        .as_ref()
                        .is_none_or(|p| p.sql_publication_pin().is_ok())
            } else {
                // SQLx may enqueue a rollback on Drop. This is not an ACK and is
                // never reported as an actual completed transaction drain.
                drop(tx);
                false
            };
        if !acknowledged {
            // A business refusal does not certify transaction cleanup. Preserve
            // its request identity, keep the reason in a fixed-code diagnostic,
            // and make the unconfirmed handoff explicit to the caller.
            tracing::warn!(
                refusal_code = refusal.code,
                "raw restore template refusal rollback acknowledgement unavailable"
            );
            let mut unknown = ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "RESTORE_RAW_HANDOFF_UNCONFIRMED",
                "Raw restore transaction acknowledgement unavailable; no publication or host permit is authorized",
            );
            unknown.retryable = false;
            return Err(unknown.with_request_id(refusal.request_id));
        }
        Err(refusal)
    }
}
struct Round {
    pvc: Value,
    pv: Value,
    node: Value,
    csi: Value,
}
fn blocked() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "RESTORE_RAW_COLLECTION_BLOCKED",
        "Raw storage observation or original current authority differs; no host permit may be issued",
    )
}
fn vendor_unavailable() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "RESTORE_RAW_VENDOR_CERTIFICATION_REQUIRED",
        "Raw restore volume vendor certification unavailable",
    )
}
fn vendor_report_error(error: VendorReportError) -> ApiError {
    match error {
        VendorReportError::Unavailable => vendor_unavailable(),
        VendorReportError::Read => dependency(),
        VendorReportError::Shape | VendorReportError::Binding | VendorReportError::Expired => {
            ApiError::new(
                StatusCode::FORBIDDEN,
                "RESTORE_RAW_VENDOR_RUNTIME_BLOCKED",
                "Raw restore vendor report differs from current sealed authority; no publication or host permit is authorized",
            )
        }
    }
}
fn dependency() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "DEPENDENCY_UNAVAILABLE",
        "Raw storage observation dependency unavailable",
    )
}
fn denial(d: crate::admission::Denial) -> ApiError {
    if d.code == 403 {
        blocked()
    } else {
        dependency()
    }
}
fn cloud_error(e: CloudError) -> ApiError {
    match e.code {
        CloudErrorCode::IdentityMismatch
        | CloudErrorCode::CredentialIdentityMismatch
        | CloudErrorCode::Configuration
        | CloudErrorCode::ObservationStale
        | CloudErrorCode::MalformedResponse
        | CloudErrorCode::InvalidState => blocked(),
        _ => dependency(),
    }
}
fn check(
    first: &RawBoundRead,
    scope: &RawBoundDiskScope,
    attempt: &RawBoundAttempt,
    engine: &OperationEngine,
    claim: &Claim,
) -> Result<(), ApiError> {
    first
        .backup_current(attempt, engine, claim)
        .map_err(denial)?;
    scope.current().map_err(denial)
}
async fn get(client: &kube::Client, url: &str, name: &str) -> Result<Value, ApiError> {
    let request = Request::new(url)
        .get(name, &GetParams::default())
        .map_err(|_| dependency())?;
    match client.request::<Value>(request).await {
        Ok(value) => Ok(value),
        Err(kube::Error::Api(e)) if e.code == 404 => Err(blocked()),
        Err(_) => Err(dependency()),
    }
}
fn disk_locator(round: &Round, scope: &RawBoundDiskScope) -> Result<String, ApiError> {
    // The handle is an untrusted locator, never authority. It is intersected
    // with sealed source/clone exclusions and later verified by the signed API
    // and full PV projector. No source/serial/role may be supplied by this JSON.
    let f = scope.facts();
    let id = round
        .pv
        .pointer("/spec/csi/volumeHandle")
        .and_then(Value::as_str)
        .ok_or_else(blocked)?;
    if round.pv["apiVersion"] != "v1"
        || round.pv["kind"] != "PersistentVolume"
        || round.pv["metadata"]["name"] != f.pv_name
        || round.pvc["metadata"]["name"] != f.pvc_name
        || round.pvc["metadata"]["uid"] != f.pvc_uid.to_string()
        || id.len() > 128
        || !id
            .strip_prefix("d-")
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric()))
        || id == f.source_disk_id
        || id == f.clone_disk_id
        || scope
            .collection()
            .recorded
            .as_ref()
            .is_some_and(|r| r.disk_id != id)
    {
        return Err(blocked());
    }
    Ok(id.into())
}
fn project(
    round: &Round,
    scope: &RawBoundDiskScope,
    cloud: &BackupDiskProtocolObservation,
    known: Option<Uuid>,
) -> Result<RawPvProjection, ApiError> {
    scope.current().map_err(denial)?;
    if round.pvc["status"]["phase"] != "Bound" || round.pv["status"]["phase"] != "Bound" {
        return Err(blocked());
    }
    let f = scope.facts();
    let c: &RawBoundCollectionFacts = scope.collection();
    let n = RawPvNodeFacts {
        runtime_node_id: f.runtime_node_id,
        node_uid: f.node.node_uid,
        boot_id: f.node.boot_id,
        profile_id: c.storage.storage_contract.profile_id,
        cluster_epoch: f.cluster_epoch,
        topology_receipt_id: c.topology_receipt_id,
        node_name: f.node.node_name.clone(),
        cloud: c.cloud.clone(),
    };
    let disk = cloud.disk_facts().map_err(cloud_error)?;
    let e = RawPvShapeExpected {
        context: &c.storage,
        recorded_parent_uid: f.pvc_uid,
        selected_node: &n,
        disk_identity: &disk,
    };
    validate_raw_pvc_live_template(&round.pvc, &e).map_err(|_| blocked())?;
    let p = project_raw_pv_live_template(&round.pv, &e, known).map_err(|_| blocked())?;
    if [
        f.pvc_uid,
        f.source_pvc_uid,
        f.source_pv_uid,
        f.clone_pvc_uid,
        f.clone_pv_uid,
    ]
    .contains(&p.uid())
    {
        return Err(blocked());
    }
    if c.recorded
        .as_ref()
        .is_some_and(|r| r.pv_uid != p.uid() || r.pv_spec_sha256 != p.spec_sha256())
    {
        return Err(blocked());
    }
    scope.current().map_err(denial)?;
    cloud.current().map_err(cloud_error)?;
    Ok(p)
}
impl BackupRawBoundCollector {
    #[cfg(test)]
    pub(crate) fn for_loopback_test(
        runtime: BackupJobRuntime,
        identity: RawDiskCloudConfig,
        endpoint: url::Url,
    ) -> Result<Self, ApiError> {
        let mut collector = Self::new(runtime, identity)?;
        collector
            .budget
            .use_loopback_test_endpoint(endpoint)
            .map_err(cloud_error)?;
        Ok(collector)
    }
    /// Normal operation caller: starts the original attempt BEFORE locator GET,
    /// obtains current claim authority by the ordinary backup reader, then runs
    /// the actual collector. No submitted UID/source/receipt or seeded proof.
    pub(crate) async fn observe_pending_restore(
        &self,
        database: &Database,
        engine: &OperationEngine,
        claim: &Claim,
        restore: Uuid,
    ) -> Result<BackupRawBoundTemplateAttempt, ApiError> {
        let attempt = RawBoundAttempt::start();
        let deadline = attempt.deadline().map_err(denial)?;
        let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            attempt.current().map_err(denial)?;
            let client = self.runtime.runtime().client_clone();
            let pvcs = Api::<PersistentVolumeClaim>::namespaced(client.clone(), NAMESPACE);
            let locator = get(&client, pvcs.resource_url(), &block_pvc_name(restore)).await?;
            let hint = locator
                .pointer("/metadata/annotations/volume.kubernetes.io~1selected-node")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty() && v.len() <= 253)
                .ok_or_else(blocked)?;
            attempt.current().map_err(denial)?;
            let first = database
                .prepare_restore_bound_authority(&attempt, engine, claim, restore, hint)
                .await?;
            let observed = self
                .collect(database, engine, claim, &first, &attempt)
                .await?;
            attempt.current().map_err(denial)?;
            Ok::<_, ApiError>((first, observed))
        })
        .await
        .map_err(|_| blocked())??;
        let result = BackupRawBoundTemplateAttempt {
            attempt,
            first: result.0,
            observed: result.1,
            vendor_report: self.vendor_report.clone(),
            csi_client: self.runtime.runtime().client_clone(),
        };
        result.current(engine, claim)?;
        Ok(result)
    }

    pub(crate) fn new(
        runtime: BackupJobRuntime,
        identity: RawDiskCloudConfig,
    ) -> Result<Self, ApiError> {
        // Installation must supply this distinct read-only controller identity.
        // Job/owner/delete credentials are never fallback configurations.
        if identity.oidc_subject != "system:serviceaccount:sandbox-system:sandbox-backup-controller"
        {
            return Err(blocked());
        }
        let budget = BackupRawDiskProtocolClient::budget(&identity).map_err(cloud_error)?;
        Ok(Self {
            runtime,
            identity,
            budget,
            vendor_report: None,
        })
    }
    /// Optional installed expectations. Neither Some nor None is a live vendor
    /// Gate, and changing configuration never extends a current attempt.
    pub(crate) fn with_vendor_report(mut self, report: Option<Arc<RestoreVendorReport>>) -> Self {
        self.vendor_report = report;
        self
    }
    pub(crate) async fn collect(
        &self,
        database: &Database,
        engine: &OperationEngine,
        claim: &Claim,
        first: &RawBoundRead,
        attempt: &RawBoundAttempt,
    ) -> Result<BackupRawBoundTemplateObservation, ApiError> {
        let scope = first
            .backup_disk_scope(attempt, engine, claim)
            .map_err(denial)?;
        BackupRawDiskProtocolClient::validate_scope(&self.identity, &scope).map_err(cloud_error)?;
        let deadline = scope.deadline();
        let result = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.collect_inner(database, engine, claim, first, attempt, &scope),
        )
        .await
        .map_err(|_| blocked())??;
        let result = BackupRawBoundTemplateObservation {
            disk: result.0,
            pv: result.1,
            current: result.2,
            original_scope: scope,
        };
        result.current(attempt, engine, claim)?;
        Ok(result)
    }
    async fn round(
        &self,
        first: &RawBoundRead,
        scope: &RawBoundDiskScope,
        attempt: &RawBoundAttempt,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<Round, ApiError> {
        check(first, scope, attempt, engine, claim)?;
        let c = scope.collection();
        let f = scope.facts();
        self.runtime
            .verify_network(&c.cloud_settings)
            .await
            .map_err(|_| dependency())?;
        check(first, scope, attempt, engine, claim)?;
        self.runtime
            .verify_profile_secrets(&c.cloud_settings)
            .await
            .map_err(|_| dependency())?;
        for purpose in [
            RestoreStoragePurpose::Normal,
            RestoreStoragePurpose::Raw,
            RestoreStoragePurpose::Delivery,
        ] {
            check(first, scope, attempt, engine, claim)?;
            self.runtime
                .verify_restore_storage_class(&c.storage.storage_contract, purpose)
                .await
                .map_err(|_| dependency())?;
        }
        check(first, scope, attempt, engine, claim)?;
        self.runtime
            .verify_restore_snapshot_class(&c.storage.storage_contract)
            .await
            .map_err(|_| dependency())?;
        let client = self.runtime.runtime().client_clone();
        let pvcs = Api::<PersistentVolumeClaim>::namespaced(client.clone(), NAMESPACE);
        let pvc = get(&client, pvcs.resource_url(), &f.pvc_name).await?;
        check(first, scope, attempt, engine, claim)?;
        let pvs = Api::<PersistentVolume>::all(client.clone());
        let pv = get(&client, pvs.resource_url(), &f.pv_name).await?;
        check(first, scope, attempt, engine, claim)?;
        let nodes = Api::<Node>::all(client.clone());
        let node = get(&client, nodes.resource_url(), &f.node.node_name).await?;
        check(first, scope, attempt, engine, claim)?;
        let csis = Api::<CSINode>::all(client.clone());
        let csi = get(&client, csis.resource_url(), &f.node.node_name).await?;
        if csi["metadata"]["uid"] != c.csi_node_uid.to_string() {
            return Err(blocked());
        }
        first
            .validate_collection_node(attempt, &node, &csi)
            .map_err(denial)?;
        check(first, scope, attempt, engine, claim)?;
        Ok(Round { pvc, pv, node, csi })
    }
    async fn collect_inner(
        &self,
        database: &Database,
        engine: &OperationEngine,
        claim: &Claim,
        first: &RawBoundRead,
        attempt: &RawBoundAttempt,
        scope: &RawBoundDiskScope,
    ) -> Result<(BackupDiskProtocolObservation, RawPvProjection, RawBoundRead), ApiError> {
        let one = self.round(first, scope, attempt, engine, claim).await?;
        let id = disk_locator(&one, scope)?;
        // Both calls build a fresh narrow transport, reread projected OIDC,
        // AssumeRole, validate issuer/subject, GetCallerIdentity account/RoleID,
        // and sign exact-instance DescribeDisks. No cached first credentials.
        let first_cloud = BackupRawDiskProtocolClient::observe_scope(
            self.identity.clone(),
            scope,
            &id,
            &self.budget,
        )
        .await
        .map_err(cloud_error)?;
        check(first, scope, attempt, engine, claim)?;
        let one_projection = project(
            &one,
            scope,
            &first_cloud,
            scope.collection().recorded.as_ref().map(|r| r.pv_uid),
        )?;
        let two = self.round(first, scope, attempt, engine, claim).await?;
        let second_id = disk_locator(&two, scope)?;
        if id != second_id {
            return Err(blocked());
        }
        let second_cloud = BackupRawDiskProtocolClient::observe_scope(
            self.identity.clone(),
            scope,
            &second_id,
            &self.budget,
        )
        .await
        .map_err(cloud_error)?;
        first_cloud
            .same_identity(&second_cloud)
            .map_err(cloud_error)?;
        let two_projection = project(
            &two,
            scope,
            &second_cloud,
            scope.collection().recorded.as_ref().map(|r| r.pv_uid),
        )?;
        if one_projection != two_projection {
            return Err(blocked());
        }
        for (before, after) in [
            (&one.pvc, &two.pvc),
            (&one.pv, &two.pv),
            (&one.node, &two.node),
            (&one.csi, &two.csi),
        ] {
            first
                .compare_collection_objects(attempt, before, after)
                .map_err(denial)?;
        }
        check(first, scope, attempt, engine, claim)?;
        // This is the existing normal current-claim reader, with original start
        // and full14 equality. Returning its owned token preserves the shorter
        // final horizon across final COMMIT ACK and caller handoff.
        let current = database
            .finish_restore_bound_collection(engine, claim, first)
            .await?;
        check(first, scope, attempt, engine, claim)?;
        current
            .backup_current(attempt, engine, claim)
            .map_err(denial)?;
        second_cloud.current().map_err(cloud_error)?;
        Ok((second_cloud, two_projection, current))
    }
}

// This module is a child of the collector so the actual integration consumer
// can borrow the whole owned attempt without exposing proof parts/constructors.
// No factory, cloud certification, publication row or permit is synthesized.
#[cfg(test)]
pub(crate) mod handoff_tests {
    use super::*;
    use crate::restore::admission::RawBoundPublicationAttempt;
    use anyhow::{Context, ensure};

    pub(crate) async fn same_transaction(
        owned: BackupRawBoundTemplateAttempt,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> anyhow::Result<BackupRawBoundTemplateAttempt> {
        owned
            .current(engine, claim)
            .map_err(|_| anyhow::anyhow!("owned normal collector attempt current"))?;
        let mut deadline = owned
            .handoff_deadline(engine, claim)
            .map_err(|_| anyhow::anyhow!("original owned handoff deadline"))?;
        let end = tokio::time::Instant::from_std(deadline);
        let first_scope = owned
            .first
            .backup_disk_scope(&owned.attempt, engine, claim)
            .map_err(|_| anyhow::anyhow!("original first scope"))?;
        let final_scope = owned
            .observed
            .current
            .backup_disk_scope(&owned.attempt, engine, claim)
            .map_err(|_| anyhow::anyhow!("actual final scope"))?;
        ensure!(
            deadline <= owned.observed.original_scope.deadline()
                && deadline <= first_scope.deadline()
                && deadline <= final_scope.deadline()
                && deadline
                    <= owned
                        .attempt
                        .deadline()
                        .map_err(|_| anyhow::anyhow!("original attempt"))?,
            "actual handoff minimum retains every original/current finite horizon"
        );
        // This asserts the real normal result. It does not edit Instants or
        // claim that this particular fixture produces a STRICTLY shorter lease.
        let mut tx = tokio::time::timeout_at(end, engine.database.begin(claim.tenant_id))
            .await
            .context("same-TX handoff BEGIN stayed within original deadline")?
            .map_err(|_| anyhow::anyhow!("normal backup transaction"))?;
        let outcome = tokio::time::timeout_at(end, async {
            owned
                .current(engine, claim)
                .map_err(|_| anyhow::anyhow!("same-TX before SQL"))?;
            let before: (String, String, i32, i64) = sqlx::query_as(
                "SELECT session_user::text,current_user::text,pg_backend_pid(),txid_current()",
            )
            .fetch_one(&mut *tx)
            .await?;
            ensure!(
                before.0 == "sandbox_backup" && before.1 == "sandbox_backup",
                "actual ordinary backup LOGIN; no owner or EXEC/table privilege bypass"
            );
            let publication: RawBoundPublicationAttempt<'_> = owned
                .observed
                .current
                .validate_backup_transaction(&owned.attempt, engine, claim, &mut tx)
                .await
                .map_err(|e| anyhow::anyhow!(e.message))?;
            deadline = deadline.min(publication.deadline().map_err(|e|anyhow::anyhow!(e.message))?);
            // Save the actual new current horizon before the consuming shape
            // negative. No token edit/reset or fabricated stricter timestamp.
            let post = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            let pin = publication
                .sql_publication_pin()
                .map_err(|e| anyhow::anyhow!(e.message))?;
            ensure!(
                pin.as_object().is_some_and(|o| o.len() == 14)
                    && pin["resource_identities"]["BLOCK_PV"]["binding"].is_null()
                    && pin["block_receipt"].is_null()
                    && pin["disk_receipt"].is_null(),
                "actual full14 prepublication has exactly no future three children"
            );
            // Read the actual fixed SQL function again IN THIS SAME TX. This is
            // its real returned envelope, not an invented post-pin/horizon.
            let returned: Option<Value> =
                sqlx::query_scalar("SELECT sandbox_restore_raw_bound_claim($1,$2,$3,$4,$5)")
                    .bind(claim.tenant_id)
                    .bind(owned.observed.original_scope.facts().restore_id)
                    .bind(engine.worker_id())
                    .bind(claim.lease_token)
                    .bind(&owned.observed.original_scope.facts().node.node_name)
                    .fetch_one(&mut *tx)
                    .await?;
            let returned = returned.context("actual pre-record SQL still authorized")?;
            ensure!(
                returned["pin"] == *pin && returned.as_object().is_some_and(|o| o.len() == 2),
                "same real14 pin persists; a pre-record SQL envelope is not a publication receipt"
            );
            let expected_pin = pin.clone();
            let missing = publication
                .validate_publication_envelope(&returned, &expected_pin)
                .err()
                .context("actual unrecorded14 cannot become a post-publication token")?;
            ensure!(
                missing.code == 403
                    && missing.message
                        == "Raw bound publication requires all three strong child records",
                "exact missing-three-row shape refusal, not vendor or database certification"
            );
            let after: (String, String, i32, i64) = sqlx::query_as(
                "SELECT session_user::text,current_user::text,pg_backend_pid(),txid_current()",
            )
            .fetch_one(&mut *tx)
            .await?;
            ensure!(
                before == after,
                "full14 pre/post-negative stays in the caller's exact backend and transaction"
            );
            owned
                .current(engine, claim)
                .map_err(|_| anyhow::anyhow!("original scope after SQL"))?;
                ensure!(Instant::now()<deadline, "same-TX checks finish within current narrowed horizon");
                Ok::<(),anyhow::Error>(())
            }).await.context("same-TX narrowed current horizon expired")?;
            post?;
            ensure!(Instant::now()<deadline, "same-TX post-poll check retains actual current horizon");
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("same-TX handoff original deadline expired")
        .and_then(|r| r);
        let rollback = if Instant::now() < deadline {
            async {
                tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), tx.rollback())
                    .await
                    .context("same-TX rollback ACK deadline")??;
                ensure!(
                    Instant::now() < deadline,
                    "same-TX rollback ACK arrived before original deadline"
                );
                owned.current(engine, claim).map_err(|_| {
                    anyhow::anyhow!("same-TX rollback ACK retains original/current authority")
                })?;
                Ok::<(), anyhow::Error>(())
            }
            .await
        } else {
            drop(tx);
            Err(anyhow::anyhow!(
                "same-TX rollback acknowledgement not certified after deadline"
            ))
        };
        if rollback.is_err() {
            eprintln!("PRIVATE handoff transaction cleanup failed; not certified acknowledged");
        }
        outcome?;
        rollback?;
        Ok(owned)
    }
    pub(crate) async fn no_open_transactions(engine: &OperationEngine) -> anyhow::Result<()> {
        // Independent post-refusal factual observation on the actual same
        // backup LOGIN. This is not a label or authority substitute, and does
        // not turn an unknown rollback ACK into a successful publication.
        let end = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let (role,clear):(String,bool)=tokio::time::timeout_at(end,sqlx::query_as(
            "SELECT session_user::text, COALESCE(bool_and(pid=pg_backend_pid() OR xact_start IS NULL),true) FROM pg_stat_activity WHERE datname=current_database() AND usename=session_user",
        ).fetch_one(&engine.database.pool)).await.context("post-refusal own-role transaction observation deadline")??;
        ensure!(
            tokio::time::Instant::now() < end,
            "post-refusal observation ACK within its distinct five-second observer budget"
        );
        ensure!(
            role == "sandbox_backup" && clear,
            "actual normal-role caller leaves no open backup transaction in this dedicated database"
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "restore_raw_handoff_scope_tests.rs"]
pub(crate) mod handoff_scope_tests;

// Live observation still cannot mint a vendor certification or write permit.
#[path = "restore_csi_live.rs"]
mod csi_live;

// Synthetic HTTP observations are shared by ordinary units and the real normal
// claimant test caller; this utility cannot build a scope, Gate or permission.
#[cfg(test)]
#[path = "restore_csi_live_fixture.rs"]
pub(crate) mod csi_live_fixture;
