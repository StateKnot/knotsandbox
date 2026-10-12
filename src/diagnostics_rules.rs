use super::*;

impl Database {
    pub(super) async fn diagnosis_snapshot(
        &self,
        actor: &Actor,
        d: &Stored,
    ) -> Result<(DateTime<Utc>, DiagnosticReport), ApiError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(actor.tenant_id.to_string())
            .execute(&mut *tx)
            .await?;
        authorization(&mut tx, actor, d.project_id, "diagnoses:create").await?;
        let row=sqlx::query("SELECT i.runtime_generation,i.launch_id,i.cluster_epoch,c.cluster_epoch AS current_epoch,c.safe_mode,clock_timestamp() AS as_of,i.desired_state,i.observed_state,i.observed_at,i.compute_lease_expires_at,i.stop_accepted_at,i.active_operation_id,i.slot_held,i.activity_kind,i.activity_id,i.ready_observed_at,COALESCE(i.ready_generation=i.runtime_generation AND i.ready_launch_id=i.launch_id AND i.ready_pod_uid=i.pod_uid AND i.ready_cluster_epoch=i.cluster_epoch AND i.ready_observed_at>=i.compute_lease_started_at AND i.ready_observed_at<=clock_timestamp(),false) AS ready_matches,w.status AS workspace_state,t.status AS template_state,p.status AS policy_state FROM instances i JOIN workspaces w ON(w.tenant_id,w.project_id,w.id)=(i.tenant_id,i.project_id,i.workspace_id) JOIN template_versions t ON(t.tenant_id,t.id)=(i.tenant_id,i.template_version_id) JOIN security_policy_versions p ON(p.tenant_id,p.id)=(i.tenant_id,i.security_policy_version_id) CROSS JOIN platform_configuration c WHERE i.tenant_id=$1 AND i.project_id=$2 AND i.id=$3 AND c.singleton")
            .bind(d.tenant_id).bind(d.project_id).bind(d.instance_id).fetch_one(&mut *tx).await?;
        if row.try_get::<i64, _>("runtime_generation")? != d.requested_generation
            || row.try_get::<Uuid, _>("launch_id")? != d.requested_launch_id
            || row.try_get::<Uuid, _>("current_epoch")? != d.cluster_epoch
        {
            return Err(ApiError::conflict(
                "DIAGNOSIS_TARGET_CHANGED",
                "Instance launch or cluster epoch changed before observation",
            ));
        }
        let now: DateTime<Utc> = row.try_get("as_of")?;
        let running = row.try_get::<String, _>("desired_state")? == "RUNNING";
        let lease: DateTime<Utc> = row.try_get("compute_lease_expires_at")?;
        let observed: Option<DateTime<Utc>> = row.try_get("observed_at")?;
        let state: String = row.try_get("observed_state")?;
        let workspace: String = row.try_get("workspace_state")?;
        let same_epoch = row.try_get::<Uuid, _>("cluster_epoch")? == d.cluster_epoch;
        let mut checks = vec![
            check(
                "compute_lease",
                if running && lease <= now {
                    DiagnosticStatus::Critical
                } else {
                    DiagnosticStatus::Healthy
                },
                if running && lease <= now {
                    "COMPUTE_LEASE_EXPIRED_WHILE_RUNNING"
                } else {
                    "COMPUTE_LEASE_RECORDED"
                },
                EvidenceScope::Instance,
                vec![evidence(
                    EvidenceSource::ControlPlaneSnapshot,
                    Some(now),
                    Some(d.instance_id),
                    Some(row.try_get("desired_state")?),
                    Some(lease),
                )],
                "INSPECT_LIFECYCLE",
            ),
            lifecycle_check(observed, now, d.instance_id, state),
            check(
                "launch_epoch",
                if same_epoch {
                    DiagnosticStatus::Healthy
                } else {
                    DiagnosticStatus::Critical
                },
                if same_epoch {
                    "CURRENT_CLUSTER_EPOCH"
                } else {
                    "HISTORICAL_CLUSTER_EPOCH"
                },
                EvidenceScope::Instance,
                vec![evidence(
                    EvidenceSource::ControlPlaneSnapshot,
                    Some(now),
                    Some(d.instance_id),
                    None,
                    None,
                )],
                "INSPECT_RECOVERY_EPOCH",
            ),
            check(
                "launch_readiness",
                if running && same_epoch && row.try_get("ready_matches")? {
                    DiagnosticStatus::Healthy
                } else {
                    DiagnosticStatus::Unknown
                },
                if running && same_epoch && row.try_get("ready_matches")? {
                    "HISTORICAL_LAUNCH_VALIDATION_MATCHES"
                } else {
                    "CURRENT_LAUNCH_VALIDATION_UNAVAILABLE"
                },
                EvidenceScope::Instance,
                vec![evidence(
                    EvidenceSource::LaunchValidation,
                    row.try_get("ready_observed_at")?,
                    Some(d.instance_id),
                    None,
                    None,
                )],
                "INSPECT_LIFECYCLE",
            ),
            check(
                "workspace",
                if matches!(workspace.as_str(), "DELETING" | "DELETED") && running {
                    DiagnosticStatus::Critical
                } else if matches!(workspace.as_str(), "AVAILABLE" | "IN_USE") {
                    DiagnosticStatus::Healthy
                } else {
                    DiagnosticStatus::Unknown
                },
                if matches!(workspace.as_str(), "DELETING" | "DELETED") && running {
                    "RUNNING_WORKSPACE_CONFLICT"
                } else if workspace == "AVAILABLE" {
                    "WORKSPACE_LEDGER_AVAILABLE"
                } else if workspace == "IN_USE" {
                    "WORKSPACE_LEDGER_IN_USE"
                } else {
                    "WORKSPACE_READINESS_UNCONFIRMED"
                },
                EvidenceScope::Instance,
                vec![evidence(
                    EvidenceSource::ControlPlaneSnapshot,
                    Some(now),
                    Some(d.workspace_id),
                    Some(workspace),
                    None,
                )],
                "INSPECT_WORKSPACE",
            ),
        ];
        for (rule, column) in [
            ("template_approval", "template_state"),
            ("security_policy_approval", "policy_state"),
        ] {
            let state: String = row.try_get(column)?;
            checks.push(check(
                rule,
                if state == "APPROVED" {
                    DiagnosticStatus::Healthy
                } else {
                    DiagnosticStatus::Warning
                },
                if state == "APPROVED" {
                    "CONFIGURATION_APPROVED"
                } else {
                    "CONFIGURATION_NOT_APPROVED"
                },
                EvidenceScope::Instance,
                vec![evidence(
                    EvidenceSource::ControlPlaneSnapshot,
                    Some(now),
                    None,
                    Some(state),
                    None,
                )],
                "REVIEW_APPROVED_CONFIGURATION",
            ));
        }
        let (assigned, valid_until): (bool, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT assigned,valid_until FROM sandbox_instance_certification($1,$2)",
        )
        .bind(d.tenant_id)
        .bind(d.instance_id)
        .fetch_one(&mut *tx)
        .await?;
        let covered = valid_until.is_some_and(|until| until >= lease && until > now);
        checks.push(check(
            "node_certification",
            if running && assigned && !covered {
                DiagnosticStatus::Critical
            } else if assigned && covered {
                DiagnosticStatus::Healthy
            } else {
                DiagnosticStatus::Unknown
            },
            if running && assigned && !covered {
                "CURRENT_NODE_AUTHORITY_UNAVAILABLE"
            } else if assigned && covered {
                "CERTIFICATION_COVERS_COMPUTE_LEASE"
            } else {
                "NODE_ASSIGNMENT_UNCONFIRMED"
            },
            EvidenceScope::Instance,
            vec![evidence(
                EvidenceSource::NodeCertification,
                Some(now),
                Some(d.instance_id),
                None,
                valid_until,
            )],
            "REVIEW_NODE_CERTIFICATION",
        ));
        if row.try_get::<bool, _>("safe_mode")? {
            checks.push(check(
                "platform_mode",
                DiagnosticStatus::Warning,
                "PLATFORM_SAFE_MODE",
                EvidenceScope::Instance,
                vec![evidence(
                    EvidenceSource::ControlPlaneSnapshot,
                    Some(now),
                    None,
                    None,
                    None,
                )],
                "CONTACT_PLATFORM_OPERATOR",
            ));
        }
        if d.include_operations {
            if optional_scope(&mut tx, actor, d.project_id, "operations:read").await? {
                let active: Option<Uuid> = row.try_get("active_operation_id")?;
                let op=sqlx::query("SELECT id,status,deadline,lease_until,updated_at FROM operations WHERE tenant_id=$1 AND project_id=$2 AND instance_id=$3 AND id=$4").bind(d.tenant_id).bind(d.project_id).bind(d.instance_id).bind(active).fetch_optional(&mut *tx).await?;
                let (status, code, ev) = if let Some(op) = op {
                    let deadline: DateTime<Utc> = op.try_get("deadline")?;
                    let state: String = op.try_get("status")?;
                    let lease_until: Option<DateTime<Utc>> = op.try_get("lease_until")?;
                    let bad = deadline <= now
                        || (state == "RUNNING" && lease_until.is_none_or(|v| v <= now));
                    (
                        if bad {
                            DiagnosticStatus::Warning
                        } else {
                            DiagnosticStatus::Healthy
                        },
                        if deadline <= now {
                            "OPERATION_DEADLINE_EXCEEDED"
                        } else if bad {
                            "OPERATION_LEASE_EXPIRED"
                        } else {
                            "OPERATION_PROGRESS_RECORDED"
                        },
                        vec![evidence(
                            EvidenceSource::OperationLedger,
                            op.try_get("updated_at")?,
                            Some(op.try_get("id")?),
                            Some(state),
                            Some(deadline),
                        )],
                    )
                } else {
                    (
                        if active.is_none() {
                            DiagnosticStatus::Healthy
                        } else {
                            DiagnosticStatus::Unknown
                        },
                        if active.is_none() {
                            "NO_ACTIVE_LIFECYCLE_OPERATION"
                        } else {
                            "ACTIVE_OPERATION_EVIDENCE_MISSING"
                        },
                        vec![],
                    )
                };
                checks.push(check(
                    "active_operation",
                    status,
                    code,
                    EvidenceScope::Operations,
                    ev,
                    "INSPECT_OPERATION_HISTORY",
                ));
            } else {
                checks.push(redacted("active_operation", EvidenceScope::Operations));
            }
        }
        if d.include_executions {
            if optional_scope(&mut tx, actor, d.project_id, "executions:read").await? {
                let held = row.try_get::<bool, _>("slot_held")?
                    && row
                        .try_get::<Option<String>, _>("activity_kind")?
                        .as_deref()
                        == Some("EXECUTION");
                let active: Option<Uuid> = row.try_get("activity_id")?;
                let execution = if held {
                    sqlx::query("SELECT id,status,deadline,updated_at FROM executions WHERE tenant_id=$1 AND project_id=$2 AND instance_id=$3 AND id=$4 AND slot_held").bind(d.tenant_id).bind(d.project_id).bind(d.instance_id).bind(active).fetch_optional(&mut *tx).await?
                } else {
                    None
                };
                let (status, code, ev) = if let Some(e) = execution {
                    let state: String = e.try_get("status")?;
                    let deadline: DateTime<Utc> = e.try_get("deadline")?;
                    let (status, code) = execution_status(&state, deadline, now);
                    (
                        status,
                        code,
                        vec![evidence(
                            EvidenceSource::ExecutionLedger,
                            e.try_get("updated_at")?,
                            Some(e.try_get("id")?),
                            Some(state),
                            Some(deadline),
                        )],
                    )
                } else {
                    (
                        if held {
                            DiagnosticStatus::Unknown
                        } else {
                            DiagnosticStatus::Healthy
                        },
                        if held {
                            "EXECUTION_EVIDENCE_MISSING"
                        } else {
                            "NO_ACTIVE_EXECUTION"
                        },
                        vec![],
                    )
                };
                checks.push(check(
                    "active_execution",
                    status,
                    code,
                    EvidenceScope::Executions,
                    ev,
                    "INSPECT_EXECUTION_HISTORY",
                ));
            } else {
                checks.push(redacted("active_execution", EvidenceScope::Executions));
            }
        }
        checks.push(check(
            "continuous_runtime_health",
            DiagnosticStatus::Unknown,
            "CONTINUOUS_RUNTIME_HEALTH_NOT_ASSESSED",
            EvidenceScope::Instance,
            vec![],
            "INSPECT_RUNTIME_MONITORING",
        ));
        checks.push(check(
            "guest_network_storage",
            DiagnosticStatus::Unknown,
            "GUEST_DNS_OOM_AND_FILESYSTEM_NOT_ASSESSED",
            EvidenceScope::Instance,
            vec![],
            "COLLECT_AUTHORIZED_GUEST_EVIDENCE",
        ));
        tx.commit().await?;
        Ok((
            now,
            DiagnosticReport {
                overall: overall(&checks),
                checks,
            },
        ))
    }
}
fn execution_status(
    state: &str,
    deadline: DateTime<Utc>,
    now: DateTime<Utc>,
) -> (DiagnosticStatus, &'static str) {
    if state == "OUTCOME_UNKNOWN" {
        (
            DiagnosticStatus::Critical,
            "EXECUTION_OUTCOME_UNKNOWN_SLOT_HELD",
        )
    } else if deadline <= now {
        (
            DiagnosticStatus::Warning,
            "EXECUTION_DEADLINE_EXCEEDED_SLOT_HELD",
        )
    } else {
        (DiagnosticStatus::Healthy, "EXECUTION_SLOT_HELD")
    }
}
fn evidence(
    source: EvidenceSource,
    observed_at: Option<DateTime<Utc>>,
    resource_id: Option<Uuid>,
    state: Option<String>,
    deadline: Option<DateTime<Utc>>,
) -> DiagnosticEvidence {
    DiagnosticEvidence {
        source,
        observed_at,
        resource_id,
        state,
        deadline,
    }
}
fn check(
    rule: &str,
    status: DiagnosticStatus,
    code: &str,
    evidence_scope: EvidenceScope,
    evidence: Vec<DiagnosticEvidence>,
    recommendation: &str,
) -> DiagnosticCheck {
    DiagnosticCheck {
        rule: rule.into(),
        status,
        code: code.into(),
        evidence_scope,
        evidence,
        recommendation: recommendation.into(),
    }
}
fn redacted(rule: &str, scope: EvidenceScope) -> DiagnosticCheck {
    check(
        rule,
        DiagnosticStatus::Unknown,
        "EVIDENCE_REDACTED",
        scope,
        vec![],
        "REQUEST_EVIDENCE_READ_PERMISSION",
    )
}
pub(super) fn redact(report: &mut DiagnosticReport, operations: bool, executions: bool) {
    for c in &mut report.checks {
        if (c.evidence_scope == EvidenceScope::Operations && !operations)
            || (c.evidence_scope == EvidenceScope::Executions && !executions)
        {
            *c = redacted(&c.rule, c.evidence_scope);
        }
    }
    report.overall = overall(&report.checks);
}
fn overall(checks: &[DiagnosticCheck]) -> DiagnosticStatus {
    for status in [
        DiagnosticStatus::Critical,
        DiagnosticStatus::Warning,
        DiagnosticStatus::Unknown,
    ] {
        if checks.iter().any(|c| c.status == status) {
            return status;
        }
    }
    DiagnosticStatus::Healthy
}
fn lifecycle_check(
    observed: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    id: Uuid,
    state: String,
) -> DiagnosticCheck {
    let age = observed.map(|at| (now - at).num_seconds());
    let (status, code) = match age {
        None => (DiagnosticStatus::Unknown, "LIFECYCLE_OBSERVATION_MISSING"),
        Some(age) if age < 0 => (
            DiagnosticStatus::Unknown,
            "LIFECYCLE_OBSERVATION_CLOCK_INVALID",
        ),
        Some(age) if age > 60 => (
            DiagnosticStatus::Unknown,
            "LIFECYCLE_OBSERVATION_HISTORICAL",
        ),
        _ => (DiagnosticStatus::Healthy, "LIFECYCLE_OBSERVATION_RECENT"),
    };
    check(
        "lifecycle_observation",
        status,
        code,
        EvidenceScope::Instance,
        vec![evidence(
            EvidenceSource::LifecycleReconciler,
            observed,
            Some(id),
            Some(state),
            None,
        )],
        "INSPECT_LIFECYCLE",
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_stale_and_future_observations_never_assert_vm_death() {
        let now = Utc::now();
        for at in [
            None,
            Some(now - Duration::seconds(61)),
            Some(now + Duration::seconds(1)),
        ] {
            let c = lifecycle_check(at, now, Uuid::nil(), "UNKNOWN".into());
            assert_eq!(c.status, DiagnosticStatus::Unknown);
            assert!(!c.code.contains("DEAD"));
        }
    }
    #[test]
    fn durable_outcome_unknown_is_critical_even_before_execution_deadline() {
        let now = Utc::now();
        assert_eq!(
            execution_status("OUTCOME_UNKNOWN", now + Duration::seconds(60), now),
            (
                DiagnosticStatus::Critical,
                "EXECUTION_OUTCOME_UNKNOWN_SLOT_HELD"
            )
        );
    }
    #[test]
    fn redaction_removes_evidence_and_recomputes_summary() {
        let mut r = DiagnosticReport {
            overall: DiagnosticStatus::Critical,
            checks: vec![check(
                "active_execution",
                DiagnosticStatus::Critical,
                "EXECUTION_OUTCOME_UNKNOWN_SLOT_HELD",
                EvidenceScope::Executions,
                vec![evidence(
                    EvidenceSource::ExecutionLedger,
                    None,
                    Some(Uuid::new_v4()),
                    Some("UNKNOWN".into()),
                    None,
                )],
                "INSPECT_EXECUTION_HISTORY",
            )],
        };
        redact(&mut r, true, false);
        assert_eq!(r.overall, DiagnosticStatus::Unknown);
        assert!(r.checks[0].evidence.is_empty());
        assert_eq!(r.checks[0].code, "EVIDENCE_REDACTED");
    }
}
