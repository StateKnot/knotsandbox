//! Authorized, bounded control-plane security evidence. A desired policy, an
//! object receipt or historical Ready record never proves runtime enforcement.
use crate::{
    auth::VerifiedIdentity,
    db::{Actor, Database},
    error::ApiError,
    instance_details::{
        LifecycleObservation, OBSERVATION_RECENT_SECONDS, ObservationFreshness, ObservationSource,
        TemplateDetails,
    },
    model::PublicOperationError,
};
use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

const POLICY_BYTES: i32 = 65536;

macro_rules! codes {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
        pub enum $name { $($variant),+ }
    };
}
codes!(PolicyDocumentStatus {
    Available,
    Unavailable
});
codes!(PolicyProfile { DenyAllWithDns });
codes!(ObjectEvidenceStatus {
    Recorded,
    Unavailable
});
codes!(LaunchEvidenceStatus {
    HistoricalRecorded,
    Unavailable
});
codes!(NodeAuthorizationStatus {
    CoversComputeLease,
    Unavailable,
    ExpiredOrInsufficient
});
codes!(UnknownStatus { Unknown });
codes!(UnknownReason {
    IndependentEnforcementEvidenceUnavailable,
    RuntimeIsolationCertificationUnavailable,
    ImageVerificationEvidenceUnavailable,
});
codes!(SecurityFinding {
    TemplateNotApproved,
    SecurityPolicyNotApproved,
    PolicyDocumentUnavailable,
    PolicyProfileUnsupported,
    HistoricalClusterEpoch,
    PlatformSafeMode,
    ComputeLeaseExpired,
    ComputeNoLongerDesired,
    WorkspaceUnavailable,
});
codes!(OperationEvidenceState {
    Available,
    None,
    Redacted,
    Unavailable
});
codes!(DenialHistoryStatus { NotCaptured });
codes!(RuntimeCertification { NotAsserted });

#[derive(Debug, Serialize, Deserialize)]
pub struct InstanceSecurity {
    pub instance_id: Uuid,
    pub project_id: Uuid,
    pub spec_version: i64,
    pub runtime_generation: i64,
    pub launch_id: Uuid,
    pub cluster_epoch: Uuid,
    pub as_of: DateTime<Utc>,
    pub desired: DesiredSecurity,
    pub observations: SecurityObservations,
    pub applied_policy: UnknownSecurityEvidence,
    pub runtime_isolation: UnknownSecurityEvidence,
    pub image_verification: UnknownSecurityEvidence,
    pub findings: Vec<SecurityFinding>,
    pub active_operation: ActiveOperationEvidence,
    pub denial_history: DenialHistory,
    pub runtime_certification: RuntimeCertification,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct DesiredSecurity {
    pub template: TemplateDetails,
    pub security_policy: DesiredPolicy,
    pub resources: DesiredResources,
    pub runtime_controls: DesiredRuntimeControls,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct DesiredPolicy {
    pub id: Uuid,
    pub name: String,
    pub version: i64,
    pub status: String,
    pub document_status: PolicyDocumentStatus,
    /// SHA-256 of the exact UTF-8 PostgreSQL JSONB text representation. It
    /// preserves decimal precision; it is not a signature or enforcement proof.
    pub rules_sha256: Option<String>,
    pub profile: Option<PolicyProfile>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct DesiredResources {
    pub cpu_millis: i64,
    pub memory_mib: i64,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct DesiredRuntimeControls {
    pub runtime_class: String,
    pub run_as_non_root: bool,
    pub user_id: i64,
    pub seccomp_profile: String,
    pub privileged: bool,
    pub allow_privilege_escalation: bool,
    pub read_only_root_filesystem: bool,
    pub host_network: bool,
    pub host_pid: bool,
    pub host_ipc: bool,
    pub service_account_token: bool,
    pub capabilities_drop: Vec<String>,
}
impl Default for DesiredRuntimeControls {
    fn default() -> Self {
        Self {
            runtime_class: "kata-qemu".into(),
            run_as_non_root: true,
            user_id: 1000,
            seccomp_profile: "RuntimeDefault".into(),
            privileged: false,
            allow_privilege_escalation: false,
            read_only_root_filesystem: true,
            host_network: false,
            host_pid: false,
            host_ipc: false,
            service_account_token: false,
            capabilities_drop: vec!["ALL".into()],
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityObservations {
    pub lifecycle: LifecycleObservation,
    pub policy_object: PolicyObjectEvidence,
    pub launch_validation: LaunchSecurityEvidence,
    pub node_authorization: NodeAuthorizationEvidence,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyObjectEvidence {
    pub status: ObjectEvidenceStatus,
    pub ledger_status: Option<String>,
    pub recorded_generation: Option<i64>,
    pub observed_at: Option<DateTime<Utc>>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct LaunchSecurityEvidence {
    pub status: LaunchEvidenceStatus,
    pub observed_at: Option<DateTime<Utc>>,
    pub generation: Option<i64>,
    pub matches_current_launch: bool,
    pub matches_current_cluster_epoch: bool,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeAuthorizationEvidence {
    pub status: NodeAuthorizationStatus,
    pub valid_until: Option<DateTime<Utc>>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct UnknownSecurityEvidence {
    pub status: UnknownStatus,
    pub reason: UnknownReason,
}
impl UnknownSecurityEvidence {
    fn new(reason: UnknownReason) -> Self {
        Self {
            status: UnknownStatus::Unknown,
            reason,
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ActiveOperationEvidence {
    pub state: OperationEvidenceState,
    pub resource: Option<SecurityOperation>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityOperation {
    pub id: Uuid,
    pub kind: String,
    pub status: String,
    pub error: Option<PublicOperationError>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct DenialHistory {
    pub status: DenialHistoryStatus,
}

// Keep Database::authorize's tenant/project/live-grant predicates. Candidate
// deadlines are aggregated before the outer volatile clock projection, so no
// token or grant can expire during a preceding identity/table wait unnoticed.
async fn current_authority(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    identity: &VerifiedIdentity,
    project: Uuid,
) -> Result<(bool, DateTime<Utc>), ApiError> {
    Database::authorize_identity(tx, actor, "instances:read").await?;
    let row = sqlx::query(r#"WITH live AS MATERIALIZED (
      SELECT sandbox_principal_enabled($2) AND EXISTS (
        SELECT 1 FROM sandbox_resolve_identity($4,$5,$6) WHERE principal_id=$2 AND enabled
      ) AS identity_live
    ), permitted AS MATERIALIZED (
      SELECT action,expires_at FROM grants g JOIN projects p ON p.tenant_id=g.tenant_id AND p.id=$3
      JOIN tenants t ON t.id=g.tenant_id
      WHERE g.tenant_id=$1 AND g.principal_id=$2
        AND (g.project_id=$3 OR g.project_id IS NULL) AND g.enabled AND g.revoked_at IS NULL
        AND p.enabled AND t.enabled
    ), evaluated AS MATERIALIZED (
      SELECT live.identity_live,
        COALESCE(bool_or(expires_at IS NULL) FILTER (WHERE action IN ('instances:read','*')),false) AS required_indefinite,
        max(expires_at) FILTER (WHERE action IN ('instances:read','*')) AS required_until,
        COALESCE(bool_or(expires_at IS NULL) FILTER (WHERE action IN ('operations:read','*')),false) AS optional_indefinite,
        max(expires_at) FILTER (WHERE action IN ('operations:read','*')) AS optional_until
      FROM live LEFT JOIN permitted ON true GROUP BY live.identity_live
    ) SELECT evaluated.*,clock_timestamp() AS as_of FROM evaluated"#)
        .bind(actor.tenant_id).bind(actor.principal_id).bind(project)
        .bind(&identity.issuer).bind(&identity.subject).bind(&identity.client_id).fetch_one(&mut **tx).await?;
    let now: DateTime<Utc> = row.try_get("as_of")?;
    if now.timestamp() >= identity.expires_at {
        return Err(crate::request::unauthenticated());
    }
    let required_until: Option<DateTime<Utc>> = row.try_get("required_until")?;
    if !row.try_get::<bool, _>("identity_live")?
        || !(row.try_get::<bool, _>("required_indefinite")?
            || required_until.is_some_and(|deadline| deadline > now))
    {
        return Err(ApiError::not_found());
    }
    let optional_until: Option<DateTime<Utc>> = row.try_get("optional_until")?;
    Ok((
        identity.permits("operations:read")
            && (row.try_get::<bool, _>("optional_indefinite")?
                || optional_until.is_some_and(|deadline| deadline > now)),
        now,
    ))
}

// Every piece of evidence comes from one PostgreSQL statement snapshot. The
// second read must have the same binding and records; concurrent replacement
// produces a retryable conflict, never a mixed-generation security report.
const SECURITY_SQL: &str = r#"SELECT s.*,to_jsonb(s)-'as_of'-'matches_launch' AS binding FROM (
 SELECT i.spec_version,i.runtime_generation,i.launch_id,i.cluster_epoch,i.cpu_millis,i.memory_mib,i.workspace_id,i.desired_state,i.compute_lease_expires_at,i.observed_at,i.active_operation_id,i.ready_observed_at,i.ready_generation,
 w.status AS workspace_status,t.id AS template_id,t.name AS template_name,t.version AS template_version,t.image_digest,t.runner_version,t.status AS template_status,
 p.id AS policy_id,p.name AS policy_name,p.version AS policy_version,p.status AS policy_status,
 CASE WHEN octet_length(p.rules::text)<=$3 THEN p.rules::text ELSE NULL END AS bounded_rules,
 p.rules='{"profile":"deny-all","dns":true}'::jsonb AS supports_profile,
 c.safe_mode,i.cluster_epoch=c.cluster_epoch AS matches_epoch,clock_timestamp() AS as_of,
 COALESCE(i.ready_generation=i.runtime_generation AND i.ready_launch_id=i.launch_id AND i.ready_pod_uid=i.pod_uid AND i.ready_cluster_epoch=i.cluster_epoch AND i.ready_observed_at>=i.compute_lease_started_at AND i.ready_observed_at<=clock_timestamp(),false) AS matches_launch,
 COALESCE((SELECT jsonb_agg(e.record ORDER BY e.observed_at DESC NULLS LAST,e.id DESC) FROM (
   SELECT id,observed_at,jsonb_build_object('ledger_status',status,'recorded_generation',generation,'observed_at',observed_at) AS record
   FROM external_resources WHERE tenant_id=i.tenant_id AND project_id=i.project_id AND instance_id=i.id AND workspace_id=i.workspace_id AND owner_id=i.workspace_id AND provider='kubernetes' AND kind='CILIUM_POLICY'
   ORDER BY observed_at DESC NULLS LAST,id DESC LIMIT 2) e),'[]'::jsonb) AS policy_records,
 (SELECT jsonb_build_object('assigned',assigned,'valid_until',valid_until) FROM sandbox_instance_certification(i.tenant_id,i.id)) AS certification,
 CASE WHEN $5 THEN (SELECT jsonb_build_object('id',o.id,'kind',o.kind,'status',o.status,'error',CASE WHEN o.error IS NULL THEN NULL WHEN octet_length(o.error::text)<=65536 THEN o.error ELSE '{"code":"OPERATION_FAILED"}'::jsonb END)
 FROM operations o WHERE o.tenant_id=i.tenant_id AND o.project_id=i.project_id AND o.instance_id=i.id AND o.id=i.active_operation_id) ELSE NULL END AS operation_record
 FROM instances i JOIN workspaces w ON(w.tenant_id,w.project_id,w.id)=(i.tenant_id,i.project_id,i.workspace_id)
 JOIN template_versions t ON(t.tenant_id,t.id)=(i.tenant_id,i.template_version_id)
 JOIN security_policy_versions p ON(p.tenant_id,p.id)=(i.tenant_id,i.security_policy_version_id)
 CROSS JOIN platform_configuration c WHERE i.tenant_id=$1 AND i.project_id=$4 AND i.id=$2 AND c.singleton
) s"#;
async fn security_row(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    id: Uuid,
    project: Uuid,
    operation: bool,
) -> Result<sqlx::postgres::PgRow, ApiError> {
    sqlx::query(SECURITY_SQL)
        .bind(actor.tenant_id)
        .bind(id)
        .bind(POLICY_BYTES)
        .bind(project)
        .bind(operation)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(ApiError::not_found)
}

impl Database {
    pub async fn get_instance_security(
        &self,
        actor: &Actor,
        identity: &VerifiedIdentity,
        id: Uuid,
    ) -> Result<InstanceSecurity, ApiError> {
        let mut tx = self.pool.begin().await?;
        // READ COMMITTED is deliberate: the final authority check must see
        // revocation/expiration after any preceding database wait.
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(actor.tenant_id.to_string())
            .execute(&mut *tx)
            .await?;
        let project: Uuid =
            sqlx::query_scalar("SELECT project_id FROM instances WHERE tenant_id=$1 AND id=$2")
                .bind(actor.tenant_id)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(ApiError::not_found)?;
        let (can_read_operation, _) = current_authority(&mut tx, actor, identity, project).await?;
        // Never fetch arbitrary capabilities, image references, host identities
        // or oversized policy documents. The principal cannot select receipts.
        let first = security_row(&mut tx, actor, id, project, can_read_operation).await?;
        let row = security_row(&mut tx, actor, id, project, can_read_operation).await?;
        // Mandatory authorization wins over conflicts, so a withdrawn grant
        // never reveals whether the instance changed during the read.
        let (operation_still_allowed, now) =
            current_authority(&mut tx, actor, identity, project).await?;
        let mut old_binding: Value = first.try_get("binding")?;
        let mut new_binding: Value = row.try_get("binding")?;
        if !operation_still_allowed {
            if let Some(binding) = old_binding.as_object_mut() {
                binding.remove("operation_record");
            }
            if let Some(binding) = new_binding.as_object_mut() {
                binding.remove("operation_record");
            }
        }
        if old_binding != new_binding {
            return Err(ApiError::conflict(
                "SECURITY_TARGET_CHANGED",
                "Security evidence changed during the read; retry GET",
            ));
        }
        let rules: Option<String> = row.try_get("bounded_rules")?;
        let profile = (rules.is_some() && row.try_get::<bool, _>("supports_profile")?)
            .then_some(PolicyProfile::DenyAllWithDns);
        let rules_sha256 = rules
            .as_ref()
            .map(|rules| hex::encode(Sha256::digest(rules.as_bytes())));
        let template_status: String = row.try_get("template_status")?;
        let policy_status: String = row.try_get("policy_status")?;
        let same_epoch: bool = row.try_get("matches_epoch")?;
        let matches_launch: bool = row.try_get("matches_launch")?;
        let mut findings = Vec::new();
        if template_status != "APPROVED" {
            findings.push(SecurityFinding::TemplateNotApproved);
        }
        if policy_status != "APPROVED" {
            findings.push(SecurityFinding::SecurityPolicyNotApproved);
        }
        if rules.is_none() {
            findings.push(SecurityFinding::PolicyDocumentUnavailable);
        } else if profile.is_none() {
            findings.push(SecurityFinding::PolicyProfileUnsupported);
        }
        if !same_epoch {
            findings.push(SecurityFinding::HistoricalClusterEpoch);
        }
        if row.try_get::<bool, _>("safe_mode")? {
            findings.push(SecurityFinding::PlatformSafeMode);
        }
        if row.try_get::<DateTime<Utc>, _>("compute_lease_expires_at")? <= now {
            findings.push(SecurityFinding::ComputeLeaseExpired);
        }
        if row.try_get::<String, _>("desired_state")? != "RUNNING" {
            findings.push(SecurityFinding::ComputeNoLongerDesired);
        }
        if !matches!(
            row.try_get::<String, _>("workspace_status")?.as_str(),
            "AVAILABLE" | "IN_USE"
        ) {
            findings.push(SecurityFinding::WorkspaceUnavailable);
        }
        let records: Value = row.try_get("policy_records")?;
        let records = records.as_array().ok_or_else(|| {
            ApiError::conflict(
                "SECURITY_EVIDENCE_INVALID",
                "Security evidence cannot be classified",
            )
        })?;
        let policy_object = if records.len() == 1 {
            #[derive(Deserialize)]
            struct Record {
                ledger_status: String,
                recorded_generation: i64,
                observed_at: Option<DateTime<Utc>>,
            }
            let record: Record = decode(records[0].clone())?;
            PolicyObjectEvidence {
                status: ObjectEvidenceStatus::Recorded,
                ledger_status: Some(record.ledger_status),
                recorded_generation: Some(record.recorded_generation),
                observed_at: record.observed_at,
            }
        } else {
            PolicyObjectEvidence {
                status: ObjectEvidenceStatus::Unavailable,
                ledger_status: None,
                recorded_generation: None,
                observed_at: None,
            }
        };
        #[derive(Deserialize)]
        struct Certification {
            assigned: bool,
            valid_until: Option<DateTime<Utc>>,
        }
        let cert: Option<Value> = row.try_get("certification")?;
        let cert: Option<Certification> = cert.map(decode).transpose()?;
        let (assigned, valid_until) = cert
            .map(|c| (c.assigned, c.valid_until))
            .unwrap_or((false, None));
        let lease: DateTime<Utc> = row.try_get("compute_lease_expires_at")?;
        let node_authorization = NodeAuthorizationEvidence {
            status: if !assigned || valid_until.is_none() {
                NodeAuthorizationStatus::Unavailable
            } else if same_epoch
                && lease > now
                && valid_until.is_some_and(|time| time >= lease && time > now)
            {
                NodeAuthorizationStatus::CoversComputeLease
            } else {
                NodeAuthorizationStatus::ExpiredOrInsufficient
            },
            valid_until,
        };
        let operation: Option<Uuid> = row.try_get("active_operation_id")?;
        let active_operation = if !can_read_operation || !operation_still_allowed {
            ActiveOperationEvidence {
                state: OperationEvidenceState::Redacted,
                resource: None,
            }
        } else if operation.is_none() {
            ActiveOperationEvidence {
                state: OperationEvidenceState::None,
                resource: None,
            }
        } else {
            let record: Option<Value> = row.try_get("operation_record")?;
            let resource = record.map(decode).transpose()?;
            ActiveOperationEvidence {
                state: if resource.is_some() {
                    OperationEvidenceState::Available
                } else {
                    OperationEvidenceState::Unavailable
                },
                resource,
            }
        };
        let result = InstanceSecurity {
            instance_id: id,
            project_id: project,
            spec_version: row.try_get("spec_version")?,
            runtime_generation: row.try_get("runtime_generation")?,
            launch_id: row.try_get("launch_id")?,
            cluster_epoch: row.try_get("cluster_epoch")?,
            as_of: now,
            desired: DesiredSecurity {
                template: TemplateDetails {
                    id: row.try_get("template_id")?,
                    name: row.try_get("template_name")?,
                    version: row.try_get("template_version")?,
                    image_digest: row.try_get("image_digest")?,
                    runner_version: row.try_get("runner_version")?,
                    status: template_status,
                },
                security_policy: DesiredPolicy {
                    id: row.try_get("policy_id")?,
                    name: row.try_get("policy_name")?,
                    version: row.try_get("policy_version")?,
                    status: policy_status,
                    document_status: if rules.is_some() {
                        PolicyDocumentStatus::Available
                    } else {
                        PolicyDocumentStatus::Unavailable
                    },
                    rules_sha256,
                    profile,
                },
                resources: DesiredResources {
                    cpu_millis: row.try_get("cpu_millis")?,
                    memory_mib: row.try_get("memory_mib")?,
                },
                runtime_controls: DesiredRuntimeControls::default(),
            },
            observations: SecurityObservations {
                lifecycle: lifecycle_observation(row.try_get("observed_at")?, now),
                policy_object,
                launch_validation: LaunchSecurityEvidence {
                    status: if matches_launch && same_epoch {
                        LaunchEvidenceStatus::HistoricalRecorded
                    } else {
                        LaunchEvidenceStatus::Unavailable
                    },
                    observed_at: row.try_get("ready_observed_at")?,
                    generation: row.try_get("ready_generation")?,
                    matches_current_launch: matches_launch,
                    matches_current_cluster_epoch: same_epoch,
                },
                node_authorization,
            },
            applied_policy: UnknownSecurityEvidence::new(
                UnknownReason::IndependentEnforcementEvidenceUnavailable,
            ),
            runtime_isolation: UnknownSecurityEvidence::new(
                UnknownReason::RuntimeIsolationCertificationUnavailable,
            ),
            image_verification: UnknownSecurityEvidence::new(
                UnknownReason::ImageVerificationEvidenceUnavailable,
            ),
            findings,
            active_operation,
            denial_history: DenialHistory {
                status: DenialHistoryStatus::NotCaptured,
            },
            runtime_certification: RuntimeCertification::NotAsserted,
        };
        tx.commit().await?;
        Ok(result)
    }
}

fn lifecycle_observation(
    observed_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> LifecycleObservation {
    let (freshness, age_seconds) = match observed_at {
        None => (ObservationFreshness::Missing, None),
        Some(time) if time > now => (ObservationFreshness::InvalidTimestamp, None),
        Some(time) if now - time > Duration::seconds(OBSERVATION_RECENT_SECONDS) => (
            ObservationFreshness::Historical,
            Some((now - time).num_seconds()),
        ),
        Some(time) => (
            ObservationFreshness::Recent,
            Some((now - time).num_seconds()),
        ),
    };
    LifecycleObservation {
        source: ObservationSource::LifecycleReconciler,
        observed_at,
        age_seconds,
        freshness,
        recent_threshold_seconds: OBSERVATION_RECENT_SECONDS,
    }
}

fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, ApiError> {
    serde_json::from_value(value).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Invalid security evidence classification",
        )
    })
}
