#![allow(clippy::unwrap_used, clippy::expect_used)]
use chrono::{DateTime, Duration, Utc};
use sandbox_platform::domain::{
    ActivityKind, ComputeLease, DesiredState, DomainError, ExecutionStatus, IdlePolicy,
    InstanceAction, LifecycleState, ObservedState, OperationKind, StopReason, TerminationStatus,
    WorkspaceStatus, validate_workspace_reclamation,
};
use uuid::Uuid;

fn now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-10-03T04:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}

fn lease() -> ComputeLease {
    ComputeLease::new(Uuid::new_v4(), now(), 300, 3600).unwrap()
}

fn running() -> LifecycleState {
    LifecycleState {
        desired: DesiredState::Running,
        observed: ObservedState::Running,
        has_active_operation: false,
        has_activity: false,
        stop_accepted: false,
    }
}

#[test]
fn exact_deadline_closes_admission_and_cannot_be_renewed() {
    let original = lease();
    assert!(!original.is_expired(original.expires_at - Duration::microseconds(1)));
    assert!(original.is_expired(original.expires_at));
    assert_eq!(
        original.validate_admission(original.expires_at, false),
        Err(DomainError::LeaseExpired)
    );
    assert_eq!(
        original.renew(
            original.expires_at,
            original.expires_at + Duration::seconds(1),
            1,
            3600,
            false
        ),
        Err(DomainError::LeaseExpired)
    );
}

#[test]
fn renewal_keeps_identity_and_start_and_requires_current_version() {
    let original = lease();
    let target = now() + Duration::seconds(600);
    let renewed = original.renew(now(), target, 1, 3600, false).unwrap();
    assert_eq!(renewed.id, original.id);
    assert_eq!(renewed.started_at, original.started_at);
    assert_eq!(renewed.version, 2);
    assert_eq!(renewed.expires_at, target);
    assert_eq!(original.version, 1);
    assert_eq!(
        renewed.renew(now(), target + Duration::seconds(1), 1, 3600, false),
        Err(DomainError::VersionMismatch)
    );
}

#[test]
fn accepted_stop_wins_even_before_the_original_deadline() {
    let original = lease();
    assert_eq!(
        original.renew(now(), now() + Duration::seconds(600), 1, 3600, true),
        Err(DomainError::StopAlreadyAccepted)
    );
    assert_eq!(
        original.validate_admission(now(), true),
        Err(DomainError::StopAlreadyAccepted)
    );
}

#[test]
fn lease_bounds_do_not_accept_zero_negative_or_overflowing_ttls() {
    for seconds in [0, -1, i64::MIN] {
        assert_eq!(
            ComputeLease::new(Uuid::new_v4(), now(), seconds, 3600),
            Err(DomainError::InvalidTtl)
        );
    }
    assert_eq!(
        ComputeLease::new(Uuid::new_v4(), now(), 3601, 3600),
        Err(DomainError::LeaseLimitExceeded)
    );
    assert_eq!(
        ComputeLease::new(Uuid::new_v4(), now(), i64::MAX, i64::MAX),
        Err(DomainError::InvalidTtl)
    );
    assert_eq!(
        lease().renew(now(), now() + Duration::seconds(3601), 1, 3600, false),
        Err(DomainError::LeaseLimitExceeded)
    );
    assert_eq!(
        lease().renew(now(), now() + Duration::seconds(300), 1, 3600, false),
        Err(DomainError::RenewalMustExtend)
    );
}

#[test]
fn a_lock_wait_must_use_the_time_after_acquiring_the_lock() {
    let original = lease();
    let before_wait = original.expires_at - Duration::seconds(1);
    let after_wait = original.expires_at + Duration::seconds(1);
    let target = original.expires_at + Duration::minutes(5);
    assert!(original.renew(before_wait, target, 1, 3600, false).is_ok());
    assert_eq!(
        original.renew(after_wait, target, 1, 3600, false),
        Err(DomainError::LeaseExpired)
    );
}

#[test]
fn startup_can_renew_but_cannot_accept_user_work() {
    let startup = LifecycleState {
        observed: ObservedState::Starting,
        has_active_operation: true,
        ..running()
    };
    assert_eq!(startup.validate(InstanceAction::Renew), Ok(()));
    assert_eq!(
        startup.validate(InstanceAction::Execute),
        Err(DomainError::OperationConflict)
    );
    assert_eq!(
        startup.validate_safety_stop(Some(OperationKind::Create)),
        Ok(())
    );
    assert_eq!(
        startup.validate_safety_stop(Some(OperationKind::Stop)),
        Err(DomainError::OperationConflict)
    );
}

#[test]
fn safety_stop_only_preempts_an_unfinished_create_or_start() {
    let pending = LifecycleState {
        observed: ObservedState::Pending,
        has_active_operation: true,
        ..running()
    };
    for kind in [OperationKind::Create, OperationKind::Start] {
        assert_eq!(pending.validate_safety_stop(Some(kind)), Ok(()));
    }
    for kind in [
        OperationKind::Restart,
        OperationKind::Stop,
        OperationKind::Delete,
    ] {
        assert_eq!(
            pending.validate_safety_stop(Some(kind)),
            Err(DomainError::OperationConflict)
        );
    }
    assert_eq!(
        pending.validate_safety_stop(None),
        Err(DomainError::OperationConflict)
    );
}

#[test]
fn renewal_limit_is_remaining_time_and_does_not_reset_the_start() {
    let original = lease();
    let later = original.expires_at - Duration::microseconds(1);
    let target = later + Duration::seconds(3600);
    let renewed = original.renew(later, target, 1, 3600, false).unwrap();
    assert_eq!(renewed.started_at, original.started_at);
    assert_eq!(renewed.expires_at, target);
    assert_eq!(
        original.renew(later, target + Duration::microseconds(1), 1, 3600, false),
        Err(DomainError::LeaseLimitExceeded)
    );
}

#[test]
fn active_or_unknown_remote_activity_blocks_a_second_activity() {
    let occupied = LifecycleState {
        has_activity: true,
        ..running()
    };
    for action in [
        InstanceAction::Execute,
        InstanceAction::OpenSession,
        InstanceAction::WriteFile,
    ] {
        assert_eq!(
            occupied.validate(action),
            Err(DomainError::ActivityConflict)
        );
    }
    assert_eq!(occupied.validate(InstanceAction::Stop), Ok(()));
    assert_eq!(occupied.validate(InstanceAction::Delete), Ok(()));
}

#[test]
fn only_a_confirmed_stopped_instance_can_start_a_new_lease() {
    let stopped = LifecycleState {
        desired: DesiredState::Stopped,
        observed: ObservedState::Stopped,
        stop_accepted: true,
        ..running()
    };
    assert_eq!(stopped.validate(InstanceAction::Start), Ok(()));
    assert_eq!(
        stopped.validate(InstanceAction::Renew),
        Err(DomainError::StopAlreadyAccepted)
    );
    let unknown = LifecycleState {
        observed: ObservedState::Unknown,
        ..stopped
    };
    assert_eq!(
        unknown.validate(InstanceAction::Start),
        Err(DomainError::InstanceNotStopped)
    );
    let occupied = LifecycleState {
        has_activity: true,
        ..stopped
    };
    assert_eq!(
        occupied.validate(InstanceAction::Start),
        Err(DomainError::ActivityConflict)
    );
}

#[test]
fn deleted_or_quarantined_instances_never_accept_commands() {
    let deleted = LifecycleState {
        desired: DesiredState::Deleted,
        ..running()
    };
    assert_eq!(
        deleted.validate(InstanceAction::Execute),
        Err(DomainError::ResourceDeleted)
    );
    assert_eq!(
        deleted.validate_safety_stop(None),
        Err(DomainError::ResourceDeleted)
    );
    let quarantined = LifecycleState {
        observed: ObservedState::Quarantined,
        ..running()
    };
    assert_eq!(
        quarantined.validate(InstanceAction::Execute),
        Err(DomainError::InstanceNotRunning)
    );
}

#[test]
fn idle_is_disabled_by_default_and_never_overrides_expiry_or_activity() {
    let original = lease();
    let idle = IdlePolicy::new(Some(60), false).unwrap();
    let elapsed = now() + Duration::seconds(60);
    assert!(!IdlePolicy::default().eligible(elapsed, Some(now()), false, &original, false));
    assert!(!idle.eligible(
        elapsed - Duration::microseconds(1),
        Some(now()),
        false,
        &original,
        false
    ));
    assert!(idle.eligible(elapsed, Some(now()), false, &original, false));
    assert!(!idle.eligible(elapsed, Some(now()), true, &original, false));
    assert!(!idle.eligible(elapsed, Some(now()), false, &original, true));
    assert!(!idle.eligible(original.expires_at, Some(now()), false, &original, false));
    assert!(!idle.eligible(elapsed, None, false, &original, false));
    assert_eq!(
        IdlePolicy::new(Some(60), true),
        Err(DomainError::InvalidIdleTimeout)
    );
}

#[test]
fn idle_clock_restarts_after_the_last_confirmed_activity_ends() {
    let original = lease();
    let idle = IdlePolicy::new(Some(60), false).unwrap();
    let ended_at = now() + Duration::seconds(50);
    assert!(!idle.eligible(
        now() + Duration::seconds(60),
        Some(ended_at),
        false,
        &original,
        false
    ));
    assert!(idle.eligible(
        ended_at + Duration::seconds(60),
        Some(ended_at),
        false,
        &original,
        false
    ));
    for invalid in [0, -1, i64::MIN] {
        assert_eq!(
            IdlePolicy::new(Some(invalid), false),
            Err(DomainError::InvalidIdleTimeout)
        );
    }
}

#[test]
fn expired_compute_lease_does_not_authorize_workspace_deletion() {
    let late = now() + Duration::days(1);
    assert_eq!(
        validate_workspace_reclamation(late, Some(now()), false, false, WorkspaceStatus::Available),
        Err(DomainError::WorkspaceDeleteNotAuthorized)
    );
    assert_eq!(
        validate_workspace_reclamation(late, None, true, false, WorkspaceStatus::Available),
        Err(DomainError::WorkspaceRetentionActive)
    );
    assert_eq!(
        validate_workspace_reclamation(late, Some(now()), true, true, WorkspaceStatus::Available),
        Err(DomainError::WorkspaceBusy)
    );
    assert_eq!(
        validate_workspace_reclamation(late, Some(now()), true, false, WorkspaceStatus::InUse),
        Err(DomainError::WorkspaceBusy)
    );
    assert_eq!(
        validate_workspace_reclamation(late, Some(now()), true, false, WorkspaceStatus::Available),
        Ok(())
    );
}

#[test]
fn uncertain_execution_is_never_redispatched_or_released_by_disconnect() {
    assert!(ExecutionStatus::Queued.may_dispatch());
    for status in [
        ExecutionStatus::Dispatching,
        ExecutionStatus::Running,
        ExecutionStatus::OutcomeUnknown,
    ] {
        assert!(!status.may_dispatch());
        assert!(!status.can_release_activity(TerminationStatus::Unknown));
        assert!(!status.can_release_activity(TerminationStatus::Pending));
    }
    assert!(ExecutionStatus::OutcomeUnknown.can_release_activity(TerminationStatus::Confirmed));
}

#[test]
fn state_wire_format_is_explicit_and_unknown_states_are_rejected() {
    assert_eq!(
        serde_json::to_string(&ExecutionStatus::OutcomeUnknown).unwrap(),
        "\"OUTCOME_UNKNOWN\""
    );
    assert_eq!(
        serde_json::to_string(&StopReason::LeaseExpired).unwrap(),
        "\"LEASE_EXPIRED\""
    );
    assert_eq!(
        "FILE_WRITE".parse::<ActivityKind>(),
        Ok(ActivityKind::FileWrite)
    );
    assert!("running".parse::<ObservedState>().is_err());
    assert!(serde_json::from_str::<DesiredState>("\"PAUSED\"").is_err());
}
