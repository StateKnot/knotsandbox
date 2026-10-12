use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateInstance {
    pub project_id: Uuid,
    pub name: String,
    pub template_version_id: Uuid,
    pub security_profile_id: Uuid,
    pub flavor: Flavor,
    pub workspace: WorkspaceSpec,
    pub ttl_seconds: Option<i64>,
    pub client_reference: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Flavor {
    #[serde(rename = "cpu1-mem2")]
    Cpu1Mem2,
    #[serde(rename = "cpu2-mem4")]
    Cpu2Mem4,
    #[serde(rename = "cpu4-mem8")]
    Cpu4Mem8,
}

impl Flavor {
    pub fn resources(self) -> (i64, i64) {
        match self {
            Self::Cpu1Mem2 => (1000, 2048),
            Self::Cpu2Mem4 => (2000, 4096),
            Self::Cpu4Mem8 => (4000, 8192),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSpec {
    pub size_gib: i64,
}

impl CreateInstance {
    pub fn validate(&self, default_ttl: i64, max_ttl: i64) -> Result<i64, ApiError> {
        if self.name.is_empty()
            || self.name.len() > 63
            || !self
                .name
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            || self.name.starts_with('-')
            || self.name.ends_with('-')
        {
            return Err(ApiError::invalid(
                "name must be a DNS label of 1..63 lower-case characters",
            ));
        }
        if !(20..=1024).contains(&self.workspace.size_gib) {
            return Err(ApiError::invalid("workspace size must be 20..1024 GiB"));
        }
        if self
            .client_reference
            .as_ref()
            .is_some_and(|s| s.len() > 128 || s.chars().any(char::is_control))
        {
            return Err(ApiError::invalid("Invalid client_reference"));
        }
        let ttl = self.ttl_seconds.unwrap_or(default_ttl);
        if !(60..=max_ttl).contains(&ttl) {
            return Err(ApiError::invalid(
                "ttl_seconds is outside the configured range",
            ));
        }
        Ok(ttl)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenewRequest {
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartRequest {
    pub ttl_seconds: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyRequest {}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Instance {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    pub template_version_id: Uuid,
    pub security_policy_version_id: Uuid,
    pub workspace_id: Uuid,
    pub desired_state: String,
    pub observed_state: String,
    pub spec_version: i64,
    pub runtime_generation: i64,
    pub active_operation_id: Option<Uuid>,
    pub cpu_millis: i64,
    pub memory_mib: i64,
    pub compute_lease_id: Uuid,
    pub compute_lease_version: i64,
    pub compute_lease_started_at: DateTime<Utc>,
    pub compute_lease_expires_at: DateTime<Utc>,
    pub stop_reason: Option<String>,
    pub stop_accepted_at: Option<DateTime<Utc>>,
    pub observed_at: Option<DateTime<Utc>>,
    pub slot_held: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Operation {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub instance_id: Option<Uuid>,
    pub workspace_id: Option<Uuid>,
    pub kind: String,
    pub status: String,
    pub stage: String,
    pub attempts: i32,
    #[sqlx(json(nullable))]
    pub error: Option<PublicOperationError>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Only a fixed public classification crosses the API boundary. The same
/// decoder sanitizes current SQL rows and historical idempotency receipts.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PublicOperationError {
    pub code: PublicOperationErrorCode,
    pub retryable: bool,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublicOperationErrorCode {
    DependencyUnavailable,
    OutcomeUnknown,
    OperationFailed,
}

impl<'de> Deserialize<'de> for PublicOperationError {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let stored = serde_json::Value::deserialize(deserializer)?;
        let code = match stored.get("code").and_then(serde_json::Value::as_str) {
            Some("DEPENDENCY_UNAVAILABLE" | "KUBERNETES_UNAVAILABLE" | "IDENTITY_UNAVAILABLE") => {
                PublicOperationErrorCode::DependencyUnavailable
            }
            Some("OUTCOME_UNKNOWN" | "DISPATCH_RESULT_UNKNOWN_NO_REPLAY") => {
                PublicOperationErrorCode::OutcomeUnknown
            }
            _ => PublicOperationErrorCode::OperationFailed,
        };
        Ok(Self {
            code,
            retryable: code == PublicOperationErrorCode::DependencyUnavailable,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Accepted {
    pub resource: Instance,
    pub operation: Operation,
    pub idempotency_expires_at: DateTime<Utc>,
}

/// These values are deliberately public workload configuration. Secrets are not
/// accepted by this contract and must not be placed in argv or public_env.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateExecution {
    pub argv: Vec<String>,
    #[serde(deserialize_with = "crate::runner::deserialize_environment")]
    pub public_env: std::collections::BTreeMap<String, String>,
    pub cwd: String,
    pub timeout_seconds: u64,
    pub on_timeout: ExecutionTimeoutPolicy,
    pub output_limit_bytes: u64,
    pub client_reference: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ExecutionTimeoutPolicy {
    #[serde(rename = "HARD_STOP_INSTANCE")]
    HardStopInstance,
}

impl CreateExecution {
    pub fn runner_request(
        &self,
        execution_id: Uuid,
    ) -> Result<crate::runner::ExecRequest, ApiError> {
        if self
            .client_reference
            .as_ref()
            .is_some_and(|value| value.len() > 128 || value.chars().any(char::is_control))
        {
            return Err(ApiError::invalid("Invalid client_reference"));
        }
        let request = crate::runner::ExecRequest {
            execution_id,
            argv: self.argv.clone(),
            env: self.public_env.clone(),
            cwd: self.cwd.clone(),
            timeout_seconds: self.timeout_seconds,
            output_limit_bytes: self.output_limit_bytes,
        };
        request
            .validate(std::path::Path::new("/workspace"))
            .map_err(|_| ApiError::invalid("Command parameters violate the runner protocol"))?;
        if serde_json::to_vec(&request)
            .map_err(|_| ApiError::invalid("Cannot encode command"))?
            .len()
            > crate::runner::MAX_INPUT_BYTES
        {
            return Err(ApiError::invalid(
                "Encoded runner request exceeds 65536 bytes",
            ));
        }
        Ok(request)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelExecution {
    /// Cancellation terminates the entire instance. The workspace is retained.
    pub hard_stop_instance: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResultRef {
    /// Private object-store key, never a presigned URL or a runner-provided URL.
    pub object_key: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Execution {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub instance_id: Uuid,
    pub operation_id: Uuid,
    pub version: i64,
    pub runtime_generation: i64,
    pub status: String,
    pub slot_held: bool,
    pub dispatch_attempted_at: Option<DateTime<Utc>>,
    pub deadline: DateTime<Utc>,
    pub timeout_seconds: i32,
    pub termination_status: String,
    pub exit_code: Option<i32>,
    pub output_status: String,
    #[sqlx(skip)]
    pub result_ref: Option<ExecutionResultRef>,
    pub cancel_requested_at: Option<DateTime<Utc>>,
    pub cancel_operation_id: Option<Uuid>,
    pub client_reference: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptedExecution {
    pub resource: Execution,
    pub operation: Operation,
    pub instance_id: Uuid,
    pub instance_spec_version: i64,
    pub idempotency_expires_at: DateTime<Utc>,
}
