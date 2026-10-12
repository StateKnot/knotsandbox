//! Dedicated first/final raw-bound database observations. This read token is
//! neither a signed disk proof nor a disk/VM/absence permit. No admission route
//! or normal record writer is installed by this slice.
use super::{Decision, RestoreAdmissionService, checked, dependency, raw_scheduling};
use crate::nodeguard::protocol::NodeBinding;
use crate::{
    db::Database,
    engine::{Claim, OperationEngine},
    error::ApiError,
};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use std::time::{Duration, Instant};
use uuid::Uuid;
const TOTAL: Duration = Duration::from_secs(10);

/// Start before the first untrusted locator GET. Caller code cannot supply a
/// timestamp or deserialize a replacement timer into this attempt.
pub(crate) struct RawBoundAttempt {
    started: Instant,
}
impl RawBoundAttempt {
    pub(crate) fn start() -> Self {
        Self {
            started: Instant::now(),
        }
    }
    pub(crate) fn deadline(&self) -> Decision<Instant> {
        self.started
            .checked_add(TOTAL)
            .ok_or(crate::admission::Denial {
                code: 403,
                message: "Raw bound attempt deadline overflow",
            })
    }
    pub(crate) fn current(&self) -> Decision<()> {
        checked(
            Instant::now() < self.deadline()?,
            "Original raw bound attempt expired",
        )
    }
}
#[derive(PartialEq, Eq)]
struct ClaimIdentity {
    operation_id: Uuid,
    owner: String,
    token: i64,
}
struct Scope {
    tenant: Uuid,
    restore: Uuid,
    node_hint: String,
    claim: Option<ClaimIdentity>,
}
/// A non-constructible first-read token. Its original monotonic start and full
/// fourteen-key pin survive final reading and COMMIT acknowledgement. It never
/// authorizes a cloud call, records objects, certifies media or proves VM absence.
pub(crate) struct RawBoundRead {
    scope: Scope,
    started: Instant,
    pin: Value,
    base: raw_scheduling::RawBoundBase,
}
/// Ordinary comparison facts derived only from the complete first14pin. These
/// facts are not signed disk evidence, a publication receipt or a host permit.
#[derive(Serialize)]
pub(crate) struct RawBoundDiskFacts {
    pub(crate) tenant_id: Uuid,
    pub(crate) restore_id: Uuid,
    pub(crate) cluster_epoch: Uuid,
    pub(crate) namespace: String,
    pub(crate) pvc_name: String,
    pub(crate) pvc_uid: Uuid,
    pub(crate) pv_name: String,
    pub(crate) parent_intent_created_at: DateTime<Utc>,
    pub(crate) account_id: String,
    pub(crate) region: String,
    pub(crate) deployment: String,
    pub(crate) workspace_kms_key_id: String,
    pub(crate) size_gib: u32,
    pub(crate) zone_id: String,
    pub(crate) runtime_node_id: Uuid,
    pub(crate) node: NodeBinding,
    pub(crate) cloud_instance_id: String,
    pub(crate) source_pvc_uid: Uuid,
    pub(crate) source_pv_uid: Uuid,
    pub(crate) source_disk_id: String,
    pub(crate) clone_pvc_uid: Uuid,
    pub(crate) clone_pv_uid: Uuid,
    pub(crate) clone_disk_id: String,
}
/// Comparison facts from the same decoded strict14 pin. No Deserialize or
/// proof constructor; only a sealed scope can supply these to the collector.
pub(crate) struct RawBoundCollectionFacts {
    pub(crate) storage: crate::restore::manifest::RestoreStorageContext,
    pub(crate) cloud: crate::cloud_fencing::node_topology::NodeTopologyCloudBinding,
    pub(crate) cloud_settings: crate::backup_job::BackupCloudSettings,
    pub(crate) topology_receipt_id: Uuid,
    pub(crate) csi_node_uid: Uuid,
    pub(crate) recorded: Option<RawBoundRecordedDiskFacts>,
}
/// Optional immutable target identity from the same full14 pin, never a later
/// naked query or a caller-supplied target tuple.
pub(crate) struct RawBoundRecordedDiskFacts {
    pub(crate) pv_uid: Uuid,
    pub(crate) pv_spec_sha256: String,
    pub(crate) disk_id: String,
    pub(crate) serial_number: String,
    pub(crate) creation_time: DateTime<Utc>,
}
#[derive(PartialEq, Eq)]
pub(crate) enum RawBoundDiskPurpose {
    Admission,
    Backup,
}
/// This sealed finite read scope has no public constructor, Deserialize or
/// Clone. It contains database comparison facts only; the separate fresh
/// authenticated cloud observation must come from the dedicated signed client.
pub(crate) struct RawBoundDiskScope {
    facts: RawBoundDiskFacts,
    collection: RawBoundCollectionFacts,
    vendor: raw_scheduling::RawBoundVendorFacts,
    deadline: Instant,
    purpose: RawBoundDiskPurpose,
}
impl RawBoundDiskScope {
    pub(crate) fn facts(&self) -> &RawBoundDiskFacts {
        &self.facts
    }
    pub(crate) fn collection(&self) -> &RawBoundCollectionFacts {
        &self.collection
    }
    /// Only this sealed scope can provide report comparison facts. Reading them
    /// does not refresh the scope deadline or produce a vendor capability.
    pub(crate) fn vendor_facts(&self) -> Decision<&raw_scheduling::RawBoundVendorFacts> {
        self.current()?;
        Ok(&self.vendor)
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn purpose(&self) -> &RawBoundDiskPurpose {
        &self.purpose
    }
    pub(crate) fn current(&self) -> Decision<()> {
        checked(
            Instant::now() < self.deadline,
            "Raw bound disk scope expired before observation or acknowledgement",
        )
    }
}
impl RawBoundRead {
    fn same_attempt(&self, attempt: &RawBoundAttempt) -> Decision<()> {
        checked(
            self.started == attempt.started,
            "Raw bound disk scope cannot replace the original attempt",
        )?;
        current(self.started, None, &self.base)
    }
    fn disk_scope(&self, purpose: RawBoundDiskPurpose) -> Decision<RawBoundDiskScope> {
        let deadline = self
            .started
            .checked_add(TOTAL)
            .ok_or(crate::admission::Denial {
                code: 403,
                message: "Raw bound attempt deadline overflow",
            })?
            .min(self.base.valid_until());
        let scope = RawBoundDiskScope {
            facts: self.base.disk_facts()?,
            collection: self.base.collection_facts()?,
            vendor: self.base.vendor_facts()?,
            deadline,
            purpose,
        };
        scope.current()?;
        Ok(scope)
    }
    pub(crate) fn admission_disk_scope(
        &self,
        attempt: &RawBoundAttempt,
    ) -> Decision<RawBoundDiskScope> {
        self.same_attempt(attempt)?;
        checked(
            self.scope.claim.is_none(),
            "Admission cannot borrow backup raw bound disk scope",
        )?;
        self.disk_scope(RawBoundDiskPurpose::Admission)
    }
    pub(crate) fn backup_current(
        &self,
        attempt: &RawBoundAttempt,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Decision<()> {
        self.same_attempt(attempt)?;
        let identity = ClaimIdentity {
            operation_id: claim.operation_id,
            owner: engine.worker_id().into(),
            token: claim.lease_token,
        };
        checked(
            self.scope.tenant == claim.tenant_id
                && self.scope.claim.as_ref() == Some(&identity)
                && self
                    .base
                    .claim_matches(identity.operation_id, &identity.owner, identity.token),
            "Raw bound backup claim changed before disk observation or acknowledgement",
        )
    }
    /// Raw transport objects are validated against the held typed authority;
    /// these methods confer no permission and perform no database query.
    pub(crate) fn validate_collection_node(
        &self,
        attempt: &RawBoundAttempt,
        node: &Value,
        csi: &Value,
    ) -> Decision<()> {
        self.same_attempt(attempt)?;
        self.base.validate_collection_node(node, csi)?;
        self.same_attempt(attempt)
    }
    pub(crate) fn compare_collection_objects(
        &self,
        attempt: &RawBoundAttempt,
        before: &Value,
        after: &Value,
    ) -> Decision<()> {
        self.same_attempt(attempt)?;
        self.base.compare_collection_objects(before, after)?;
        self.same_attempt(attempt)
    }
    pub(crate) fn backup_disk_scope(
        &self,
        attempt: &RawBoundAttempt,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Decision<RawBoundDiskScope> {
        self.backup_current(attempt, engine, claim)?;
        self.disk_scope(RawBoundDiskPurpose::Backup)
    }
}
/// Same-TX prepublication check. The constructor is private and the query
/// reading Instant is captured internally. No caller timestamp or current
/// independent COMMIT can substitute for this held transaction observation.
pub(crate) struct RawBoundPublicationAttempt<'a> {
    first: &'a RawBoundRead,
    current: RawBoundRead,
    reading: Instant,
}
fn duplicate_scope(scope: &Scope) -> Scope {
    Scope {
        tenant: scope.tenant,
        restore: scope.restore,
        node_hint: scope.node_hint.clone(),
        claim: scope.claim.as_ref().map(|c| ClaimIdentity {
            operation_id: c.operation_id,
            owner: c.owner.clone(),
            token: c.token,
        }),
    }
}
fn publication_delta(pre: &Value, post: &Value) -> Decision<()> {
    let paths = [
        "/resource_identities/BLOCK_PV/binding",
        "/block_receipt",
        "/disk_receipt",
    ];
    checked(
        paths
            .iter()
            .all(|path| post.pointer(path).is_some_and(|v| v.is_object())),
        "Raw bound publication requires all three strong child records",
    )?;
    if paths
        .iter()
        .all(|path| pre.pointer(path).is_some_and(Value::is_null))
    {
        let mut permitted = pre.clone();
        for path in paths {
            let target = permitted
                .pointer_mut(path)
                .ok_or(crate::admission::Denial {
                    code: 403,
                    message: "Raw bound publication pre-pin child absent",
                })?;
            *target = post
                .pointer(path)
                .ok_or(crate::admission::Denial {
                    code: 403,
                    message: "Raw bound publication post-pin child absent",
                })?
                .clone();
        }
        checked(
            permitted == *post,
            "Raw bound publication changed non-child authority facts",
        )
    } else {
        checked(
            pre == post,
            "Raw bound replay changed immutable authority or child records",
        )
    }
}
fn publication_base(
    value: &Value,
    scope: &Scope,
    reading: Instant,
    first: &RawBoundRead,
    original_horizon: Instant,
) -> Decision<raw_scheduling::RawBoundBase> {
    checked(
        exact(value, &["pin", "valid_for_us"]),
        "Bound reader envelope ABI differs",
    )?;
    recorded_shape(&value["pin"])?;
    let mut base = raw_scheduling::decode_raw_bound_base(
        value,
        scope.tenant,
        scope.restore,
        &scope.node_hint,
        reading,
    )?;
    base.validate_post_record(
        &value["pin"]["block_receipt"],
        &value["pin"]["disk_receipt"],
    )?;
    let claim = scope.claim.as_ref().ok_or(crate::admission::Denial {
        code: 403,
        message: "Raw bound publication requires backup claim purpose",
    })?;
    checked(
        base.claim_matches(claim.operation_id, &claim.owner, claim.token),
        "Raw bound backup claim identity differs",
    )?;
    base.narrow_horizon(first.base.valid_until().min(original_horizon));
    current(first.started, Some(first), &base)?;
    Ok(base)
}
impl RawBoundRead {
    pub(crate) async fn validate_backup_transaction<'a>(
        &'a self,
        attempt: &RawBoundAttempt,
        engine: &OperationEngine,
        claim: &Claim,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Decision<RawBoundPublicationAttempt<'a>> {
        let reading = Instant::now();
        self.backup_current(attempt, engine, claim)?;
        let identity = self.scope.claim.as_ref().ok_or(crate::admission::Denial {
            code: 403,
            message: "Raw bound publication requires backup claim purpose",
        })?;
        let value: Option<Value> =
            sqlx::query_scalar("SELECT sandbox_restore_raw_bound_claim($1,$2,$3,$4,$5)")
                .bind(self.scope.tenant)
                .bind(self.scope.restore)
                .bind(&identity.owner)
                .bind(identity.token)
                .bind(&self.scope.node_hint)
                .fetch_one(&mut **tx)
                .await
                .map_err(dependency)?;
        let value = value.ok_or(crate::admission::Denial {
            code: 403,
            message: "Current raw bound authority unavailable",
        })?;
        let base = publication_base(&value, &self.scope, reading, self, self.base.valid_until())?;
        checked(
            value["pin"] == self.pin,
            "Raw bound authority pin changed during observation",
        )?;
        self.backup_current(attempt, engine, claim)?;
        let current = RawBoundRead {
            scope: duplicate_scope(&self.scope),
            started: self.started,
            pin: value["pin"].clone(),
            base,
        };
        Ok(RawBoundPublicationAttempt {
            first: self,
            current,
            reading,
        })
    }
}
impl RawBoundPublicationAttempt<'_> {
    /// Extract the sealed original/first/current deadline, even if expired.
    /// This is comparison data, NOT live authority. Keeping an expired finite
    /// bound lets the TX owner refuse an ACK without falling back to a later
    /// held deadline. Pin/post validators separately check current authority.
    pub(crate) fn deadline(&self) -> Decision<Instant> {
        Ok(self
            .first
            .started
            .checked_add(TOTAL)
            .ok_or(crate::admission::Denial {
                code: 403,
                message: "Raw bound attempt deadline overflow",
            })?
            .min(self.first.base.valid_until())
            .min(self.current.base.valid_until()))
    }
    pub(crate) fn sql_publication_pin(&self) -> Decision<&Value> {
        current(self.first.started, Some(self.first), &self.current.base)?;
        Ok(&self.current.pin)
    }
    pub(crate) fn validate_publication_envelope(
        self,
        returned2: &Value,
        expected_post14: &Value,
    ) -> Decision<RawBoundRead> {
        current(self.first.started, Some(self.first), &self.current.base)?;
        publication_delta(&self.current.pin, expected_post14)?;
        checked(
            returned2["pin"] == *expected_post14,
            "Raw bound publication returned pin differs",
        )?;
        // Conservatively start this returned finite horizon at our internally
        // captured PRE-query reading, not a caller reset after writing. First,
        // current and new finite horizons survive the caller's COMMIT ACK.
        let base = publication_base(
            returned2,
            &self.current.scope,
            self.reading,
            self.first,
            self.current.base.valid_until(),
        )?;
        let post = RawBoundRead {
            scope: duplicate_scope(&self.current.scope),
            started: self.first.started,
            pin: returned2["pin"].clone(),
            base,
        };
        current(self.first.started, Some(self.first), &post.base)?;
        Ok(post)
    }
}
fn exact(value: &Value, fields: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|o| o.len() == fields.len() && fields.iter().all(|k| o.contains_key(*k)))
}
fn visible(value: &Value, limit: usize) -> bool {
    value.as_str().is_some_and(|s| {
        !s.is_empty() && s.len() <= limit && s.bytes().all(|b| b.is_ascii_graphic())
    })
}
fn recorded_shape(pin: &Value) -> Decision<()> {
    let pv = &pin["resource_identities"]["BLOCK_PV"]["binding"];
    let raw = &pin["block_receipt"];
    let disk = &pin["disk_receipt"];
    if pv.is_null() && raw.is_null() && disk.is_null() {
        return Ok(());
    }
    checked(
        exact(
            pv,
            &["intent_id", "tenant_id", "restore_id", "uid", "observed_at"],
        ) && exact(
            raw,
            &[
                "restore_id",
                "tenant_id",
                "pvc_uid",
                "pv_uid",
                "pv_name",
                "cloud_disk",
                "size_bytes",
                "recorded_at",
            ],
        ) && exact(
            disk,
            &[
                "restore_id",
                "tenant_id",
                "node_topology_receipt_id",
                "pv_spec_sha256",
                "cloud_identity",
                "cloud_evidence",
                "recorded_at",
            ],
        ) && exact(
            &disk["cloud_identity"],
            &["binding", "serial_number", "creation_time"],
        ) && exact(
            &disk["cloud_identity"]["binding"],
            &[
                "account_id",
                "region",
                "disk_id",
                "zone_id",
                "deployment",
                "namespace",
                "pvc_name",
                "pv_name",
                "kms_key_id",
                "size_gib",
            ],
        ) && exact(
            &disk["cloud_evidence"],
            &["request_id", "response_sha256", "observed_at"],
        ) && visible(&disk["cloud_identity"]["serial_number"], 128)
            && visible(&disk["cloud_evidence"]["request_id"], 256)
            && disk["cloud_evidence"]["response_sha256"]
                .as_str()
                .is_some_and(crate::nodeguard::protocol::valid_sha256),
        "Bound authority requires complete immutable binding and signed-disk record shape",
    )
}
fn current(
    started: Instant,
    first: Option<&RawBoundRead>,
    base: &raw_scheduling::RawBoundBase,
) -> Decision<()> {
    let now = Instant::now();
    checked(
        now.duration_since(started) < TOTAL
            && now < base.valid_until()
            && first.is_none_or(|f| now < f.base.valid_until()),
        "Raw bound authority expired during read, observation or COMMIT acknowledgement",
    )
}
async fn read(
    database: &Database,
    scope: Scope,
    started: Instant,
    first: Option<&RawBoundRead>,
) -> Decision<RawBoundRead> {
    // This begins before tenant setup/pool acquisition/lock waits. Even the
    // final read uses the first original total deadline, never a reset timer.
    let reading = Instant::now();
    checked(
        started.elapsed() < TOTAL,
        "Raw bound authority expired during read, observation or COMMIT acknowledgement",
    )?;
    if let Some(f) = first {
        current(started, Some(f), &f.base)?;
    }
    let mut tx = database.begin(scope.tenant).await.map_err(dependency)?;
    let value: Option<Value> = if let Some(c) = &scope.claim {
        sqlx::query_scalar("SELECT sandbox_restore_raw_bound_claim($1,$2,$3,$4,$5)")
            .bind(scope.tenant)
            .bind(scope.restore)
            .bind(&c.owner)
            .bind(c.token)
            .bind(&scope.node_hint)
            .fetch_one(&mut *tx)
            .await
            .map_err(dependency)?
    } else {
        sqlx::query_scalar("SELECT sandbox_restore_raw_bound_admission($1,$2,$3)")
            .bind(scope.tenant)
            .bind(scope.restore)
            .bind(&scope.node_hint)
            .fetch_one(&mut *tx)
            .await
            .map_err(dependency)?
    };
    let value = value.ok_or(crate::admission::Denial {
        code: 403,
        message: "Current raw bound authority unavailable",
    })?;
    checked(
        exact(&value, &["pin", "valid_for_us"]),
        "Bound reader envelope ABI differs",
    )?;
    recorded_shape(&value["pin"])?;
    let mut base = raw_scheduling::decode_raw_bound_base(
        &value,
        scope.tenant,
        scope.restore,
        &scope.node_hint,
        reading,
    )?;
    base.validate_post_record(
        &value["pin"]["block_receipt"],
        &value["pin"]["disk_receipt"],
    )?;
    if let Some(c) = &scope.claim {
        checked(
            base.claim_matches(c.operation_id, &c.owner, c.token),
            "Raw bound backup claim identity differs",
        )?;
    }
    if let Some(f) = first {
        checked(
            f.pin == value["pin"],
            "Raw bound authority pin changed during observation",
        )?;
    }
    if let Some(f) = first {
        base.narrow_horizon(f.base.valid_until());
    }
    current(started, first, &base)?;
    tx.commit().await.map_err(dependency)?;
    current(started, first, &base)?;
    Ok(RawBoundRead {
        scope,
        started,
        pin: value["pin"].clone(),
        base,
    })
}
impl RestoreAdmissionService {
    pub(crate) async fn prepare_raw_bound_admission(
        &self,
        attempt: &RawBoundAttempt,
        tenant: Uuid,
        restore: Uuid,
        node_hint: &str,
    ) -> Decision<RawBoundRead> {
        let started = attempt.started;
        read(
            &self.database,
            Scope {
                tenant,
                restore,
                node_hint: node_hint.into(),
                claim: None,
            },
            started,
            None,
        )
        .await
    }
    pub(crate) async fn recheck_raw_bound_admission(&self, first: &RawBoundRead) -> Decision<()> {
        checked(
            first.scope.claim.is_none(),
            "Admission cannot borrow backup raw bound claim authority",
        )?;
        let scope = Scope {
            tenant: first.scope.tenant,
            restore: first.scope.restore,
            node_hint: first.scope.node_hint.clone(),
            claim: None,
        };
        read(&self.database, scope, first.started, Some(first))
            .await
            .map(|_| ())
    }
}
fn api(error: crate::admission::Denial) -> ApiError {
    ApiError::new(
        if error.code == 403 {
            StatusCode::FORBIDDEN
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        if error.code == 403 {
            "RESTORE_BLOCKED"
        } else {
            "DEPENDENCY_UNAVAILABLE"
        },
        error.message,
    )
}
impl Database {
    /// Caller comes from the actual backup worker/current normal Claim. No
    /// caller-supplied PVC/PV/receipt or fabricated selected-node UID is accepted.
    pub(crate) async fn prepare_restore_bound_authority(
        &self,
        attempt: &RawBoundAttempt,
        engine: &OperationEngine,
        claim: &Claim,
        restore: Uuid,
        node_hint: &str,
    ) -> Result<RawBoundRead, ApiError> {
        let started = attempt.started;
        let scope = Scope {
            tenant: claim.tenant_id,
            restore,
            node_hint: node_hint.into(),
            claim: Some(ClaimIdentity {
                operation_id: claim.operation_id,
                owner: engine.worker_id().into(),
                token: claim.lease_token,
            }),
        };
        read(self, scope, started, None).await.map_err(api)
    }
    pub(crate) async fn recheck_restore_bound_authority(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        first: &RawBoundRead,
    ) -> Result<(), ApiError> {
        self.finish_restore_bound_collection(engine, claim, first)
            .await
            .map(|_| ())
    }
    /// Keep the actual final-read token so its shorter finite horizon also
    /// bounds the collector's return and any later same-TX writer observation.
    pub(crate) async fn finish_restore_bound_collection(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        first: &RawBoundRead,
    ) -> Result<RawBoundRead, ApiError> {
        let identity = ClaimIdentity {
            operation_id: claim.operation_id,
            owner: engine.worker_id().into(),
            token: claim.lease_token,
        };
        checked(
            first.scope.tenant == claim.tenant_id && first.scope.claim.as_ref() == Some(&identity),
            "Raw bound backup claim changed before final reading",
        )
        .map_err(api)?;
        let scope = Scope {
            tenant: claim.tenant_id,
            restore: first.scope.restore,
            node_hint: first.scope.node_hint.clone(),
            claim: Some(identity),
        };
        read(self, scope, first.started, Some(first))
            .await
            .map_err(api)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn raw_bound_shape_rejects_every_partial_future_state() {
        for mask in 1_u8..7 {
            let pin = json!({"resource_identities":{"BLOCK_PV":{"binding":if mask & 1 == 0 {Value::Null} else {json!({})}}},
                "block_receipt":if mask & 2 == 0 {Value::Null} else {json!({})},
                "disk_receipt":if mask & 4 == 0 {Value::Null} else {json!({})}});
            assert!(recorded_shape(&pin).is_err());
        }
        assert!(recorded_shape(&json!({"resource_identities":{"BLOCK_PV":{"binding":null}},"block_receipt":null,"disk_receipt":null})).is_ok());
    }
}
