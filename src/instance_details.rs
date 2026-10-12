//! A consistent read of configuration and lifecycle evidence. Launch validation
//! is historical evidence; this view never invents continuous runtime health.
use crate::{
    db::{Actor, Database, load_instance},
    error::ApiError,
    model::Instance,
};
use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

pub const OBSERVATION_RECENT_SECONDS: i64 = 60;

#[derive(Debug, Serialize, Deserialize)]
pub struct InstanceDetails {
    pub instance: Instance,
    pub as_of: DateTime<Utc>,
    pub workspace: WorkspaceDetails,
    pub template: TemplateDetails,
    pub security_policy: SecurityPolicyDetails,
    pub compute_lease: ComputeLeaseDetails,
    pub lifecycle_observation: LifecycleObservation,
    pub launch_readiness: LaunchReadiness,
    pub runtime_health: RuntimeHealth,
    pub active_execution: ActiveExecutionView,
}
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct WorkspaceDetails {
    pub id: Uuid,
    pub size_gib: i64,
    pub status: String,
    pub retention_until: Option<DateTime<Utc>>,
    pub delete_requested_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct TemplateDetails {
    pub id: Uuid,
    pub name: String,
    pub version: i64,
    pub image_digest: String,
    pub runner_version: String,
    pub status: String,
}
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct SecurityPolicyDetails {
    pub id: Uuid,
    pub name: String,
    pub version: i64,
    pub status: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ComputeLeaseDetails {
    pub state: ComputeLeaseState,
    pub remaining_seconds: i64,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComputeLeaseState {
    Active,
    Expired,
    StopAccepted,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct LifecycleObservation {
    pub source: ObservationSource,
    pub observed_at: Option<DateTime<Utc>>,
    pub age_seconds: Option<i64>,
    pub freshness: ObservationFreshness,
    pub recent_threshold_seconds: i64,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationSource {
    LifecycleReconciler,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationFreshness {
    Missing,
    Recent,
    Historical,
    InvalidTimestamp,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct LaunchReadiness {
    pub source: ObservationSource,
    pub status: LaunchReadinessStatus,
    pub verified_at: Option<DateTime<Utc>>,
    pub verified_generation: Option<i64>,
    pub matches_current_launch: bool,
    pub matches_current_cluster_epoch: bool,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LaunchReadinessStatus {
    VerifiedCurrentLaunch,
    Unverified,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct RuntimeHealth {
    pub status: RuntimeHealthStatus,
    pub reason: RuntimeHealthReason,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeHealthStatus {
    Unknown,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeHealthReason {
    ContinuousObservationUnavailable,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ActiveExecutionView {
    pub state: ExecutionViewState,
    pub resource: Option<ActiveExecutionMetadata>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionViewState {
    Available,
    None,
    Redacted,
    Unknown,
}
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct ActiveExecutionMetadata {
    pub id: Uuid,
    pub operation_id: Uuid,
    pub runtime_generation: i64,
    pub status: String,
    pub termination_status: String,
    pub deadline: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl Database {
    pub async fn instance_details(
        &self,
        actor: &Actor,
        id: Uuid,
    ) -> Result<InstanceDetails, ApiError> {
        // All projected records and grants share one read-only snapshot. We do
        // not hold lifecycle write locks while rendering a dashboard response.
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(actor.tenant_id.to_string())
            .execute(&mut *tx)
            .await?;
        let instance = load_instance(&mut tx, actor.tenant_id, id, false).await?;
        Self::authorize_resource(&mut tx, actor, instance.project_id, "instances:read").await?;
        let as_of: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let workspace=sqlx::query_as::<_,WorkspaceDetails>("SELECT id,size_gib,status,retention_until,delete_requested_at,deleted_at,updated_at FROM workspaces WHERE tenant_id=$1 AND project_id=$2 AND id=$3")
            .bind(actor.tenant_id).bind(instance.project_id).bind(instance.workspace_id).fetch_one(&mut *tx).await?;
        let template=sqlx::query_as::<_,TemplateDetails>("SELECT id,name,version,image_digest,runner_version,status FROM template_versions WHERE tenant_id=$1 AND id=$2")
            .bind(actor.tenant_id).bind(instance.template_version_id).fetch_one(&mut *tx).await?;
        let security_policy=sqlx::query_as::<_,SecurityPolicyDetails>("SELECT id,name,version,status FROM security_policy_versions WHERE tenant_id=$1 AND id=$2")
            .bind(actor.tenant_id).bind(instance.security_policy_version_id).fetch_one(&mut *tx).await?;
        let evidence=sqlx::query("SELECT i.ready_observed_at,i.ready_generation,COALESCE(i.ready_generation=i.runtime_generation AND i.ready_launch_id=i.launch_id AND i.ready_pod_uid=i.pod_uid AND i.ready_cluster_epoch=i.cluster_epoch AND i.ready_observed_at>=i.compute_lease_started_at AND i.ready_observed_at<=$3,false) AS matches_launch,i.cluster_epoch=c.cluster_epoch AS matches_epoch,i.activity_kind,i.activity_id FROM instances i CROSS JOIN platform_configuration c WHERE i.tenant_id=$1 AND i.id=$2 AND c.singleton")
            .bind(actor.tenant_id).bind(id).bind(as_of).fetch_one(&mut *tx).await?;
        let matches_current_launch: bool = evidence.try_get("matches_launch")?;
        let matches_current_cluster_epoch: bool = evidence.try_get("matches_epoch")?;
        let launch_readiness = LaunchReadiness {
            source: ObservationSource::LifecycleReconciler,
            status: if matches_current_launch && matches_current_cluster_epoch {
                LaunchReadinessStatus::VerifiedCurrentLaunch
            } else {
                LaunchReadinessStatus::Unverified
            },
            verified_at: evidence.try_get("ready_observed_at")?,
            verified_generation: evidence.try_get("ready_generation")?,
            matches_current_launch,
            matches_current_cluster_epoch,
        };
        let active_execution = match Self::authorize(
            &mut tx,
            actor,
            instance.project_id,
            "executions:read",
        )
        .await
        {
            Err(error) if error.status == StatusCode::FORBIDDEN => ActiveExecutionView {
                state: ExecutionViewState::Redacted,
                resource: None,
            },
            Err(error) => return Err(error),
            Ok(()) => {
                let kind: Option<String> = evidence.try_get("activity_kind")?;
                let activity: Option<Uuid> = evidence.try_get("activity_id")?;
                if instance.slot_held && kind.as_deref() == Some("EXECUTION") {
                    let resource=sqlx::query_as::<_,ActiveExecutionMetadata>("SELECT id,operation_id,runtime_generation,status,termination_status,deadline,created_at FROM executions WHERE tenant_id=$1 AND project_id=$2 AND instance_id=$3 AND id=$4 AND slot_held")
                        .bind(actor.tenant_id).bind(instance.project_id).bind(id).bind(activity).fetch_optional(&mut *tx).await?;
                    ActiveExecutionView {
                        state: if resource.is_some() {
                            ExecutionViewState::Available
                        } else {
                            ExecutionViewState::Unknown
                        },
                        resource,
                    }
                } else {
                    ActiveExecutionView {
                        state: ExecutionViewState::None,
                        resource: None,
                    }
                }
            }
        };
        let lifecycle_observation = observation(instance.observed_at, as_of);
        let compute_lease = ComputeLeaseDetails {
            state: if instance.stop_accepted_at.is_some() {
                ComputeLeaseState::StopAccepted
            } else if instance.compute_lease_expires_at <= as_of {
                ComputeLeaseState::Expired
            } else {
                ComputeLeaseState::Active
            },
            remaining_seconds: (instance.compute_lease_expires_at - as_of)
                .num_seconds()
                .max(0),
        };
        let result = InstanceDetails {
            instance,
            as_of,
            workspace,
            template,
            security_policy,
            compute_lease,
            lifecycle_observation,
            launch_readiness,
            runtime_health: RuntimeHealth {
                status: RuntimeHealthStatus::Unknown,
                reason: RuntimeHealthReason::ContinuousObservationUnavailable,
            },
            active_execution,
        };
        tx.commit().await?;
        Ok(result)
    }
}
fn observation(observed_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> LifecycleObservation {
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
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observation_freshness_is_evidence_age_not_a_health_assertion() {
        let now = Utc::now();
        assert_eq!(
            observation(None, now).freshness,
            ObservationFreshness::Missing
        );
        assert_eq!(
            observation(Some(now + Duration::seconds(1)), now).freshness,
            ObservationFreshness::InvalidTimestamp
        );
        assert_eq!(
            observation(Some(now - Duration::seconds(60)), now).freshness,
            ObservationFreshness::Recent
        );
        assert_eq!(
            observation(Some(now - Duration::seconds(61)), now).freshness,
            ObservationFreshness::Historical
        );
    }
}
