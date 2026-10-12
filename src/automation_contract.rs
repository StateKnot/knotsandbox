//! Fixed public automation contract and the corresponding creation constraints.
//! This describes implemented routes, never present caller authority, available
//! quota, worker health or runtime certification. Delegation still intersects
//! every current grant; these are absolute ceilings, not promised entitlements.
use super::CreateAutomation;
use crate::error::ApiError;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

const RUN_BUDGET_MIN: u32 = 1;
const RUN_BUDGET_MAX: u32 = 10_000;
const MINIMUM_INTERVAL_MIN: u32 = 60;
const MINIMUM_INTERVAL_MAX: u32 = 86_400;
pub(crate) const GRACE_MIN: u32 = 1;
pub(crate) const GRACE_MAX: u32 = 3_600;
const DELEGATION_EXCLUSIVE_MIN: i64 = 60;
const DELEGATION_MAX: i64 = 366 * 86_400;
pub(crate) const LIVE_POLICIES_PER_PROJECT: i64 = 100;
pub(crate) const LIVE_POLICIES_PER_TENANT: i64 = 1_000;
const NAME_BYTES_MAX: usize = 128;
pub(crate) const CRON_EXPRESSION_BYTES_MAX: usize = 128;
pub(crate) const EVENT_TYPE_BYTES_MAX: usize = 128;
pub(crate) const CRON_FIELD_COUNT: usize = 7;
pub(crate) const CRON_SECONDS_FIELD: &str = "0";
pub(crate) const CRON_YEAR_FIELD: &str = "*";

#[derive(Debug, Serialize, Deserialize)]
pub struct AutomationCapabilities {
    pub schema_version: u32,
    pub supported_actions: [String; 7],
    pub supported_triggers: [String; 3],
    pub clock: String,
    pub time_zone: String,
    pub cron: AutomationCronContract,
    pub missed_run_policy: String,
    pub skipped_runs_consume_budget: bool,
    pub known_automated_events_retrigger: bool,
    pub outcome_unknown_policy: String,
    pub limits: AutomationCapabilityLimits,
    pub assurance: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AutomationCronContract {
    pub field_count: usize,
    pub seconds_field: String,
    pub year_field: String,
    pub day_of_month_and_week: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AutomationCapabilityLimits {
    pub run_budget: AutomationIntegerRange,
    pub minimum_interval_seconds: AutomationIntegerRange,
    pub grace_seconds: AutomationIntegerRange,
    /// Fixed API ceiling only. Every current required grant can shorten this.
    pub delegation_lifetime_seconds: AutomationDelegationRange,
    /// ACTIVE and PAUSED rules with a live, non-revoked delegation count here.
    pub live_policies_per_project: i64,
    pub live_policies_per_tenant: i64,
    pub name_bytes_max: usize,
    pub cron_expression_bytes_max: usize,
    pub event_type_bytes_max: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AutomationIntegerRange {
    pub minimum: u32,
    pub maximum: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AutomationDelegationRange {
    pub exclusive_minimum: i64,
    pub maximum: i64,
}

/// Call only for enabled, schema-checked normal automation routes. Availability
/// stays with the router so a disabled replica publishes `automation: null`.
pub fn capabilities() -> AutomationCapabilities {
    AutomationCapabilities {
        schema_version: 1,
        supported_actions: [
            "START", "STOP", "RESTART", "DELETE", "RENEW", "EXECUTE", "BACKUP",
        ]
        .map(str::to_owned),
        supported_triggers: ["ONCE", "CRON_UTC", "EVENT"].map(str::to_owned),
        clock: "POSTGRESQL".into(),
        time_zone: "UTC".into(),
        cron: AutomationCronContract {
            field_count: CRON_FIELD_COUNT,
            seconds_field: CRON_SECONDS_FIELD.into(),
            year_field: CRON_YEAR_FIELD.into(),
            day_of_month_and_week: "INTERSECTION".into(),
        },
        missed_run_policy: "AT_MOST_ONE_WITHIN_GRACE_ELSE_SKIP_SPAN".into(),
        skipped_runs_consume_budget: true,
        known_automated_events_retrigger: false,
        outcome_unknown_policy: "RECONCILE_ORIGINAL_ONLY".into(),
        limits: AutomationCapabilityLimits {
            run_budget: AutomationIntegerRange {
                minimum: RUN_BUDGET_MIN,
                maximum: RUN_BUDGET_MAX,
            },
            minimum_interval_seconds: AutomationIntegerRange {
                minimum: MINIMUM_INTERVAL_MIN,
                maximum: MINIMUM_INTERVAL_MAX,
            },
            grace_seconds: AutomationIntegerRange {
                minimum: GRACE_MIN,
                maximum: GRACE_MAX,
            },
            delegation_lifetime_seconds: AutomationDelegationRange {
                exclusive_minimum: DELEGATION_EXCLUSIVE_MIN,
                maximum: DELEGATION_MAX,
            },
            live_policies_per_project: LIVE_POLICIES_PER_PROJECT,
            live_policies_per_tenant: LIVE_POLICIES_PER_TENANT,
            name_bytes_max: NAME_BYTES_MAX,
            cron_expression_bytes_max: CRON_EXPRESSION_BYTES_MAX,
            event_type_bytes_max: EVENT_TYPE_BYTES_MAX,
        },
        assurance: "API_CONTRACT_ONLY".into(),
    }
}

impl CreateAutomation {
    /// Fixed creation limits only; trigger, action, current identity/grants,
    /// resource versions and quota still require normal server acceptance.
    pub fn validate_fixed_parameters(&self) -> Result<(), ApiError> {
        if self.name.is_empty()
            || self.name.len() > NAME_BYTES_MAX
            || self.name.chars().any(char::is_control)
            || !(RUN_BUDGET_MIN..=RUN_BUDGET_MAX).contains(&self.run_budget)
            || !(MINIMUM_INTERVAL_MIN..=MINIMUM_INTERVAL_MAX)
                .contains(&self.minimum_interval_seconds)
            || !(GRACE_MIN..=GRACE_MAX).contains(&self.grace_seconds)
        {
            return Err(ApiError::invalid(
                "Invalid automation name, budget, interval or grace",
            ));
        }
        Ok(())
    }
}

pub(crate) fn delegation_lifetime_is_valid(expires_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    expires_at > now + Duration::seconds(DELEGATION_EXCLUSIVE_MIN)
        && expires_at <= now + Duration::seconds(DELEGATION_MAX)
}
