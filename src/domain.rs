//! Pure lifecycle rules. Callers must lock the instance row before obtaining `now`
//! from the database; these helpers do not provide transaction isolation.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use uuid::Uuid;

macro_rules! state_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
        pub enum $name { $($variant),+ }

        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $value),+ }
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
        impl FromStr for $name {
            type Err = DomainError;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($value => Ok(Self::$variant),)+
                    _ => Err(DomainError::InvalidState),
                }
            }
        }
    };
}

state_enum!(DesiredState {
    Running => "RUNNING", Stopped => "STOPPED", Deleted => "DELETED"
});
state_enum!(ObservedState {
    Pending => "PENDING", Starting => "STARTING", Running => "RUNNING",
    Stopping => "STOPPING", Stopped => "STOPPED", Deleting => "DELETING",
    Deleted => "DELETED", Error => "ERROR", Unknown => "UNKNOWN",
    Quarantined => "QUARANTINED"
});
state_enum!(OperationKind {
    Create => "CREATE", Start => "START", Stop => "STOP", Restart => "RESTART",
    Delete => "DELETE", Renew => "RENEW", Execute => "EXECUTE",
    DeleteWorkspace => "DELETE_WORKSPACE"
});
state_enum!(OperationStatus {
    Queued => "QUEUED", Running => "RUNNING", Waiting => "WAITING",
    Succeeded => "SUCCEEDED", Failed => "FAILED", Cancelled => "CANCELLED"
});
state_enum!(ExecutionStatus {
    Queued => "QUEUED", Dispatching => "DISPATCHING", Running => "RUNNING",
    Succeeded => "SUCCEEDED", Failed => "FAILED", TimedOut => "TIMED_OUT",
    Cancelled => "CANCELLED", OutcomeUnknown => "OUTCOME_UNKNOWN"
});
state_enum!(TerminationStatus {
    NotRequested => "NOT_REQUESTED", Pending => "PENDING",
    Confirmed => "CONFIRMED", Unknown => "UNKNOWN"
});
state_enum!(OutputStatus {
    Pending => "PENDING", Complete => "COMPLETE", Truncated => "TRUNCATED",
    Partial => "PARTIAL", Lost => "LOST"
});
state_enum!(ActivityKind {
    Execution => "EXECUTION", Terminal => "TERMINAL", FileWrite => "FILE_WRITE"
});
state_enum!(StopReason {
    UserRequested => "USER_REQUESTED", LeaseExpired => "LEASE_EXPIRED",
    Idle => "IDLE", ExecutionTimeout => "EXECUTION_TIMEOUT",
    ExecutionCancelled => "EXECUTION_CANCELLED", Security => "SECURITY",
    Maintenance => "MAINTENANCE"
});
state_enum!(WorkspaceStatus {
    Pending => "PENDING", Available => "AVAILABLE", InUse => "IN_USE",
    Deleting => "DELETING", Deleted => "DELETED", Error => "ERROR",
    Unknown => "UNKNOWN"
});
state_enum!(InstanceAction {
    Start => "START", Stop => "STOP", Restart => "RESTART", Delete => "DELETE",
    Renew => "RENEW", Execute => "EXECUTE", OpenSession => "OPEN_SESSION",
    WriteFile => "WRITE_FILE", OpenPort => "OPEN_PORT"
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainError {
    InvalidState,
    InvalidTtl,
    LeaseLimitExceeded,
    LeaseExpired,
    VersionMismatch,
    StopAlreadyAccepted,
    RenewalMustExtend,
    OperationConflict,
    ActivityConflict,
    InstanceNotRunning,
    InstanceNotStopped,
    ResourceDeleted,
    InvalidIdleTimeout,
    WorkspaceRetentionActive,
    WorkspaceDeleteNotAuthorized,
    WorkspaceBusy,
}

impl DomainError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidState => "INVALID_STATE",
            Self::InvalidTtl => "INVALID_TTL",
            Self::LeaseLimitExceeded => "LEASE_LIMIT_EXCEEDED",
            Self::LeaseExpired => "COMPUTE_LEASE_EXPIRED",
            Self::VersionMismatch => "VERSION_MISMATCH",
            Self::StopAlreadyAccepted => "STOP_ALREADY_ACCEPTED",
            Self::RenewalMustExtend => "RENEWAL_MUST_EXTEND",
            Self::OperationConflict => "OPERATION_CONFLICT",
            Self::ActivityConflict => "ACTIVITY_CONFLICT",
            Self::InstanceNotRunning => "INSTANCE_NOT_RUNNING",
            Self::InstanceNotStopped => "INSTANCE_NOT_STOPPED",
            Self::ResourceDeleted => "RESOURCE_DELETED",
            Self::InvalidIdleTimeout => "INVALID_IDLE_TIMEOUT",
            Self::WorkspaceRetentionActive => "WORKSPACE_RETENTION_ACTIVE",
            Self::WorkspaceDeleteNotAuthorized => "WORKSPACE_DELETE_NOT_AUTHORIZED",
            Self::WorkspaceBusy => "WORKSPACE_BUSY",
        }
    }
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for DomainError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputeLease {
    pub id: Uuid,
    pub version: i64,
    pub started_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

fn future_time(now: DateTime<Utc>, seconds: i64) -> Result<DateTime<Utc>, DomainError> {
    if seconds <= 0 {
        return Err(DomainError::InvalidTtl);
    }
    let duration = Duration::try_seconds(seconds).ok_or(DomainError::InvalidTtl)?;
    now.checked_add_signed(duration)
        .ok_or(DomainError::InvalidTtl)
}

impl ComputeLease {
    /// The lease begins when create/start is accepted, including startup wait.
    pub fn new(
        id: Uuid,
        now: DateTime<Utc>,
        ttl_seconds: i64,
        max_ttl_seconds: i64,
    ) -> Result<Self, DomainError> {
        if max_ttl_seconds <= 0 || ttl_seconds <= 0 {
            return Err(DomainError::InvalidTtl);
        }
        if ttl_seconds > max_ttl_seconds {
            return Err(DomainError::LeaseLimitExceeded);
        }
        Ok(Self {
            id,
            version: 1,
            started_at: now,
            expires_at: future_time(now, ttl_seconds)?,
        })
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }

    /// Returns the new lease without mutating the old one. The limit bounds the
    /// remaining lease from `now`; renewal does not change the original start.
    pub fn renew(
        &self,
        now: DateTime<Utc>,
        target_expires_at: DateTime<Utc>,
        expected_version: i64,
        max_ttl_seconds: i64,
        stop_accepted: bool,
    ) -> Result<Self, DomainError> {
        if expected_version != self.version {
            return Err(DomainError::VersionMismatch);
        }
        if stop_accepted {
            return Err(DomainError::StopAlreadyAccepted);
        }
        if self.is_expired(now) {
            return Err(DomainError::LeaseExpired);
        }
        if target_expires_at <= self.expires_at {
            return Err(DomainError::RenewalMustExtend);
        }
        if target_expires_at > future_time(now, max_ttl_seconds)? {
            return Err(DomainError::LeaseLimitExceeded);
        }
        Ok(Self {
            version: self
                .version
                .checked_add(1)
                .ok_or(DomainError::InvalidState)?,
            expires_at: target_expires_at,
            ..self.clone()
        })
    }

    pub fn validate_admission(
        &self,
        now: DateTime<Utc>,
        stop_accepted: bool,
    ) -> Result<(), DomainError> {
        if stop_accepted {
            Err(DomainError::StopAlreadyAccepted)
        } else if self.is_expired(now) {
            Err(DomainError::LeaseExpired)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleState {
    pub desired: DesiredState,
    pub observed: ObservedState,
    pub has_active_operation: bool,
    /// Includes uncertain remote activities. A disconnected stream is not idle.
    pub has_activity: bool,
    pub stop_accepted: bool,
}

impl LifecycleState {
    /// Permission checks and compute-lease admission are separate requirements.
    /// Stop/delete may interrupt an activity through the coordinated stop path.
    pub fn validate(self, action: InstanceAction) -> Result<(), DomainError> {
        if self.desired == DesiredState::Deleted || self.observed == ObservedState::Deleted {
            return Err(DomainError::ResourceDeleted);
        }
        // Renewal updates the same compute lease; it does not create a second
        // runtime operation and is valid while create/start is still pending.
        if self.has_active_operation && action != InstanceAction::Renew {
            return Err(DomainError::OperationConflict);
        }
        match action {
            InstanceAction::Start => {
                if self.observed != ObservedState::Stopped || self.desired != DesiredState::Stopped
                {
                    return Err(DomainError::InstanceNotStopped);
                }
                if self.has_activity {
                    return Err(DomainError::ActivityConflict);
                }
            }
            InstanceAction::Stop | InstanceAction::Delete => {}
            InstanceAction::Restart => {
                if self.stop_accepted {
                    return Err(DomainError::StopAlreadyAccepted);
                }
                if self.observed != ObservedState::Running || self.desired != DesiredState::Running
                {
                    return Err(DomainError::InstanceNotRunning);
                }
            }
            InstanceAction::Renew => {
                if self.stop_accepted || self.desired != DesiredState::Running {
                    return Err(DomainError::StopAlreadyAccepted);
                }
                if !matches!(
                    self.observed,
                    ObservedState::Pending | ObservedState::Starting | ObservedState::Running
                ) {
                    return Err(DomainError::InstanceNotRunning);
                }
            }
            InstanceAction::Execute
            | InstanceAction::OpenSession
            | InstanceAction::WriteFile
            | InstanceAction::OpenPort => {
                if self.stop_accepted {
                    return Err(DomainError::StopAlreadyAccepted);
                }
                if self.observed != ObservedState::Running || self.desired != DesiredState::Running
                {
                    return Err(DomainError::InstanceNotRunning);
                }
                if self.has_activity && action != InstanceAction::OpenPort {
                    return Err(DomainError::ActivityConflict);
                }
            }
        }
        Ok(())
    }

    /// An expiry/security coordinator may preempt create/start, but must cancel
    /// that operation and install the stop operation atomically under the row
    /// lock. This helper does not remove a runtime or release an activity slot.
    pub fn validate_safety_stop(
        self,
        active_kind: Option<OperationKind>,
    ) -> Result<(), DomainError> {
        if self.desired == DesiredState::Deleted || self.observed == ObservedState::Deleted {
            return Err(DomainError::ResourceDeleted);
        }
        if self.has_active_operation
            && !matches!(
                active_kind,
                Some(OperationKind::Create | OperationKind::Start)
            )
        {
            return Err(DomainError::OperationConflict);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdlePolicy {
    /// None disables idle stopping. Persistent port services require None.
    pub timeout_seconds: Option<i64>,
}

impl IdlePolicy {
    pub fn new(
        timeout_seconds: Option<i64>,
        persistent_port_service: bool,
    ) -> Result<Self, DomainError> {
        if timeout_seconds.is_some_and(|seconds| seconds <= 0)
            || (persistent_port_service && timeout_seconds.is_some())
        {
            return Err(DomainError::InvalidIdleTimeout);
        }
        Ok(Self { timeout_seconds })
    }

    /// Only the end of a confirmed platform activity starts this idle clock.
    /// Reads, SSE consumers, metrics, heartbeats and CPU load do not update it.
    pub fn eligible(
        self,
        now: DateTime<Utc>,
        idle_since: Option<DateTime<Utc>>,
        activity_held: bool,
        lease: &ComputeLease,
        stop_accepted: bool,
    ) -> bool {
        if activity_held || stop_accepted || lease.is_expired(now) {
            return false;
        }
        let (Some(seconds), Some(since)) = (self.timeout_seconds, idle_since) else {
            return false;
        };
        future_time(since, seconds).is_ok_and(|deadline| now >= deadline)
    }
}

/// Eligibility only: the caller must lock the workspace and recheck references
/// and authorization in the same transaction that accepts deletion.
pub fn validate_workspace_reclamation(
    now: DateTime<Utc>,
    retention_until: Option<DateTime<Utc>>,
    has_valid_delete_authorization: bool,
    has_active_reference: bool,
    status: WorkspaceStatus,
) -> Result<(), DomainError> {
    if !has_valid_delete_authorization {
        return Err(DomainError::WorkspaceDeleteNotAuthorized);
    }
    if has_active_reference || !matches!(status, WorkspaceStatus::Available) {
        return Err(DomainError::WorkspaceBusy);
    }
    match retention_until {
        Some(deadline) if now >= deadline => Ok(()),
        _ => Err(DomainError::WorkspaceRetentionActive),
    }
}

impl OperationStatus {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}

impl ExecutionStatus {
    pub const fn may_dispatch(self) -> bool {
        matches!(self, Self::Queued)
    }

    /// Unknown is an outcome, not evidence that the remote process has stopped.
    pub const fn can_release_activity(self, termination: TerminationStatus) -> bool {
        matches!(termination, TerminationStatus::Confirmed)
    }
}
