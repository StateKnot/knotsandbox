//! Durable bounded automations. Triggers only produce management intents;
//! completion requires the underlying operation and physical activity closure.
//! Normal startup requires the independent formal 0039 migration and role grants.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[path = "automation_api.rs"]
pub mod api;
#[path = "automation_cli.rs"]
pub mod cli;
#[path = "automation_contract.rs"]
pub mod contract;
#[path = "automation_controller.rs"]
pub mod controller;
#[path = "automation_ledger.rs"]
mod ledger;
#[cfg(test)]
#[path = "automation_notification_http_tests.rs"]
mod notification_http_tests;
#[cfg(test)]
#[path = "automation_notifications_tests.rs"]
mod notification_tests;
#[path = "automation_notifications.rs"]
pub mod notifications;
#[path = "automation_rules.rs"]
pub mod rules;
#[cfg(test)]
#[path = "automation_integration_tests.rs"]
mod tests;

/// Workload arguments are intentionally not Debug. They are never included in
/// public automation metadata, run history, audit events or tracing fields.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum AutomationAction {
    Start {
        ttl_seconds: Option<i64>,
    },
    Stop,
    Restart,
    Delete,
    Renew {
        ttl_seconds: i64,
    },
    Execute {
        request: crate::model::CreateExecution,
    },
    Backup {
        request: crate::backup_ledger::CreateBackup,
    },
}
impl AutomationAction {
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Start { .. } => "START",
            Self::Stop => "STOP",
            Self::Restart => "RESTART",
            Self::Delete => "DELETE",
            Self::Renew { .. } => "RENEW",
            Self::Execute { .. } => "EXECUTE",
            Self::Backup { .. } => "BACKUP",
        }
    }
    pub(crate) fn required_actions(&self, event_rule: bool) -> Vec<&'static str> {
        let mut result = match self {
            Self::Start { .. } => vec!["instances:start"],
            Self::Stop => vec!["instances:stop", "instances:hard_stop"],
            Self::Restart => vec!["instances:restart", "instances:hard_stop"],
            Self::Delete => vec!["instances:delete", "instances:hard_stop"],
            Self::Renew { .. } => vec!["instances:renew"],
            Self::Execute { .. } => vec!["executions:create", "instances:hard_stop"],
            Self::Backup { .. } => vec!["backups:create"],
        };
        if event_rule {
            result.push("events:read");
        }
        result.push("automations:write");
        result
    }
    pub(crate) fn validate(&self, max_ttl: i64) -> Result<(), crate::error::ApiError> {
        let invalid = crate::error::ApiError::invalid;
        match self {
            Self::Start {
                ttl_seconds: Some(ttl),
            }
            | Self::Renew { ttl_seconds: ttl }
                if !(60..=max_ttl).contains(ttl) =>
            {
                return Err(invalid("Automation TTL exceeds the configured limit"));
            }
            Self::Execute { request } => {
                request.runner_request(Uuid::new_v4())?;
            }
            Self::Backup { request }
                if request.profile_id.is_nil()
                    || !(31..=3650).contains(&request.retention_days) =>
            {
                return Err(invalid(
                    "Backup requires a reviewed profile and retention_days 31..3650",
                ));
            }
            _ => {}
        }
        Ok(())
    }
    pub(crate) fn requests(
        &self,
        now: DateTime<Utc>,
        resource: Uuid,
    ) -> Result<(Value, Value), crate::error::ApiError> {
        use crate::model::{RenewRequest, StartRequest};
        use serde_json::json;
        Ok(match self {
            Self::Start { ttl_seconds } => {
                let v = json!(StartRequest {
                    ttl_seconds: *ttl_seconds
                });
                (v.clone(), v)
            }
            Self::Stop | Self::Restart | Self::Delete => {
                let v = json!(StartRequest::default());
                (v.clone(), v)
            }
            Self::Renew { ttl_seconds } => {
                let v = json!(RenewRequest {
                    expires_at: now + chrono::Duration::seconds(*ttl_seconds)
                });
                (v.clone(), v)
            }
            Self::Execute { request } => (
                json!(request),
                json!({"protocol_version":1,"classification":"NON_SENSITIVE","on_timeout":request.on_timeout,"runner":request.runner_request(resource)?}),
            ),
            Self::Backup { request } => (
                json!(request),
                json!({"backup_id":resource,"profile_id":request.profile_id,"consistency":"STOPPED_CONSISTENT","retention_days":request.retention_days}),
            ),
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum AutomationTrigger {
    Once {
        at: DateTime<Utc>,
    },
    CronUtc {
        expression: String,
    },
    /// Exact tenant/project event type and aggregate; no predicate language,
    /// scripts, callback URLs or guest-supplied telemetry trust.
    Event {
        event_type: String,
        aggregate_id: Uuid,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAutomation {
    pub name: String,
    pub action: AutomationAction,
    pub trigger: AutomationTrigger,
    pub delegation_expires_at: DateTime<Utc>,
    pub run_budget: u32,
    pub minimum_interval_seconds: u32,
    pub grace_seconds: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Automation {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub instance_id: Uuid,
    pub workspace_id: Uuid,
    pub creator_principal_id: Uuid,
    pub name: String,
    pub action_kind: String,
    pub trigger_kind: String,
    pub scheduled_at: Option<DateTime<Utc>>,
    pub cron_expression: Option<String>,
    pub event_type: Option<String>,
    pub event_aggregate_id: Option<Uuid>,
    pub next_due_at: Option<DateTime<Utc>>,
    pub status: String,
    pub version: i64,
    pub run_budget: i32,
    pub emitted_runs: i32,
    pub minimum_interval_seconds: i32,
    pub grace_seconds: i32,
    pub delegation_expires_at: DateTime<Utc>,
    pub delegation_revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AutomationRun {
    pub version: i64,
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub automation_id: Uuid,
    pub automation_version: i64,
    pub scheduled_for: Option<DateTime<Utc>>,
    pub source_event_id: Option<Uuid>,
    pub source_event_sequence: Option<i64>,
    pub skipped_through: Option<DateTime<Utc>>,
    pub operation_kind: String,
    pub expected_resource_version: i64,
    pub expected_generation: i64,
    pub status: String,
    pub operation_id: Option<Uuid>,
    pub failure_code: Option<String>,
    pub deadline: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AutomationChange {
    Pause,
    Resume,
    Revoke,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct AutomationReceipt {
    pub resource: Automation,
    pub idempotency_expires_at: DateTime<Utc>,
}
pub struct AutomationMutationResult {
    pub status: u16,
    pub body: AutomationReceipt,
}

impl crate::history::HistoryRow for Automation {
    fn time(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn id(&self) -> Uuid {
        self.id
    }
}
impl crate::history::HistoryRow for AutomationRun {
    fn time(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn id(&self) -> Uuid {
        self.id
    }
}
