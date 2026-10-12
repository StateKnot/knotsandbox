//! Implemented API contract and configured project limits. This is deliberately
//! not a runtime health, available capacity or isolation certification endpoint.
use crate::{
    db::{Actor, Database},
    error::ApiError,
    model::Flavor,
    runner,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Capabilities {
    pub api_version: String,
    pub build_version: String,
    pub project_id: Uuid,
    pub api_features: ApiFeatures,
    pub flavors: Vec<FlavorCapability>,
    pub limits: CapabilityLimits,
    /// Only present when this replica mounts checked normal automation routes.
    /// Describes fixed API semantics, never caller authority or runtime health.
    pub automation: Option<crate::automation::contract::AutomationCapabilities>,
    pub runtime_certification: RuntimeCertification,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiFeatures {
    pub instance_lifecycle: bool,
    pub instance_details: bool,
    pub instance_security: bool,
    pub project_grants: bool,
    pub service_client_registry: bool,
    pub execution_acceptance: bool,
    pub execution_metadata: bool,
    pub execution_hard_cancellation: bool,
    pub operation_history: bool,
    pub domain_event_history: bool,
    pub audit_history: bool,
    pub file_transfer: bool,
    pub terminal_sessions: bool,
    pub execution_output_download: bool,
    pub execution_output_streaming: bool,
    pub monitoring: bool,
    pub runtime_metrics: bool,
    /// Durable read-only report APIs; no guest health or caller authorization.
    pub control_plane_diagnoses: bool,
    pub health_diagnostics: bool,
    /// Set by the API replica only when its checked automation routes are mounted.
    pub scheduled_tasks: bool,
    /// Implemented event-trigger API, not worker health or runtime certification.
    pub event_automation: bool,
    /// Project anomaly inbox and acknowledgement; no external delivery claim.
    pub automation_notifications: bool,
    pub backup_restore: bool,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct FlavorCapability {
    pub name: Flavor,
    pub cpu_millis: i64,
    pub memory_mib: i64,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct CapabilityLimits {
    pub ttl_seconds: TtlLimits,
    pub workspace_gib: IntegerRange,
    pub history_page_size: IntegerRange,
    pub management_body_bytes: u64,
    pub execution_timeout_seconds: IntegerRange,
    pub execution_output_bytes_max: u64,
    pub active_execution_slots_per_instance: u8,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct IntegerRange {
    pub minimum: i64,
    pub maximum: i64,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct TtlLimits {
    pub minimum: i64,
    pub maximum: i64,
    pub configured_default: i64,
    pub explicit_value_required: bool,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeCertification {
    NotAsserted,
}

impl Database {
    pub async fn capabilities(
        &self,
        actor: &Actor,
        project: Uuid,
        default_ttl: i64,
        max_ttl: i64,
    ) -> Result<Capabilities, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        Self::authorize_resource(&mut tx, actor, project, "capabilities:read").await?;
        let project_max: i64 =
            sqlx::query_scalar("SELECT max_ttl_seconds FROM projects WHERE tenant_id=$1 AND id=$2")
                .bind(actor.tenant_id)
                .bind(project)
                .fetch_one(&mut *tx)
                .await?;
        let maximum = max_ttl.min(project_max);
        if default_ttl < 60 || maximum < 60 {
            return Err(ApiError::conflict(
                "PROJECT_CONFIGURATION_INVALID",
                "The configured compute lease limits are invalid",
            ));
        }
        let result = Capabilities {
            api_version: "v1".into(),
            build_version: env!("CARGO_PKG_VERSION").into(),
            project_id: project,
            api_features: ApiFeatures {
                instance_lifecycle: true,
                instance_details: true,
                instance_security: true,
                project_grants: true,
                service_client_registry: true,
                execution_acceptance: true,
                execution_metadata: true,
                execution_hard_cancellation: true,
                operation_history: true,
                domain_event_history: true,
                audit_history: true,
                file_transfer: false,
                terminal_sessions: false,
                execution_output_download: false,
                execution_output_streaming: false,
                monitoring: false,
                runtime_metrics: false,
                control_plane_diagnoses: true,
                health_diagnostics: false,
                scheduled_tasks: false,
                event_automation: false,
                automation_notifications: false,
                backup_restore: false,
            },
            flavors: [Flavor::Cpu1Mem2, Flavor::Cpu2Mem4, Flavor::Cpu4Mem8]
                .into_iter()
                .map(|name| {
                    let (cpu_millis, memory_mib) = name.resources();
                    FlavorCapability {
                        name,
                        cpu_millis,
                        memory_mib,
                    }
                })
                .collect(),
            limits: CapabilityLimits {
                ttl_seconds: TtlLimits {
                    minimum: 60,
                    maximum,
                    configured_default: default_ttl,
                    explicit_value_required: default_ttl > maximum,
                },
                workspace_gib: IntegerRange {
                    minimum: 20,
                    maximum: 1024,
                },
                history_page_size: IntegerRange {
                    minimum: 1,
                    maximum: 100,
                },
                management_body_bytes: 64 * 1024,
                execution_timeout_seconds: IntegerRange {
                    minimum: 1,
                    maximum: 3600,
                },
                execution_output_bytes_max: runner::MAX_OUTPUT_BYTES,
                active_execution_slots_per_instance: 1,
            },
            automation: None,
            runtime_certification: RuntimeCertification::NotAsserted,
        };
        tx.commit().await?;
        Ok(result)
    }
}
