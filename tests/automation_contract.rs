#![allow(clippy::expect_used, clippy::unwrap_used)]
use chrono::{DateTime, Duration, Utc};
use sandbox_platform::automation::{
    AutomationAction, AutomationTrigger, CreateAutomation, contract,
    rules::{DueDecision, UtcCron, decide_due},
};

fn t(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
}

fn request() -> CreateAutomation {
    CreateAutomation {
        name: "bounded automation".into(),
        action: AutomationAction::Stop,
        trigger: AutomationTrigger::Once {
            at: t("2026-10-11T01:00:00Z"),
        },
        delegation_expires_at: t("2026-10-11T02:00:00Z"),
        run_budget: 1,
        minimum_interval_seconds: 60,
        grace_seconds: 300,
    }
}

#[test]
fn advertised_ranges_are_the_public_creation_validation_surface() {
    let capability = contract::capabilities();
    let limits = &capability.limits;
    for (name, minimum, maximum) in [
        (
            "budget",
            limits.run_budget.minimum,
            limits.run_budget.maximum,
        ),
        (
            "interval",
            limits.minimum_interval_seconds.minimum,
            limits.minimum_interval_seconds.maximum,
        ),
        (
            "grace",
            limits.grace_seconds.minimum,
            limits.grace_seconds.maximum,
        ),
    ] {
        for (value, accepted) in [
            (minimum, true),
            (maximum, true),
            (minimum - 1, false),
            (maximum + 1, false),
        ] {
            let mut request = request();
            match name {
                "budget" => request.run_budget = value,
                "interval" => request.minimum_interval_seconds = value,
                "grace" => request.grace_seconds = value,
                _ => unreachable!(),
            }
            assert_eq!(
                request.validate_fixed_parameters().is_ok(),
                accepted,
                "{name} {value} must match its published creation range"
            );
        }
    }
    let mut request = request();
    request.name = "界".repeat(42) + "é";
    assert_eq!(request.name.len(), limits.name_bytes_max);
    assert!(request.validate_fixed_parameters().is_ok());
    request.name.push('界');
    assert!(request.validate_fixed_parameters().is_err());
    request.name = "control\ncharacter".into();
    assert!(request.validate_fixed_parameters().is_err());
}

#[test]
fn advertised_cron_grammar_and_grace_match_the_real_public_rules() {
    let capability = contract::capabilities();
    let canonical = "0 * * * * * *";
    let padded = format!(
        "{canonical}{}",
        " ".repeat(capability.limits.cron_expression_bytes_max - canonical.len())
    );
    assert!(UtcCron::parse(&padded).is_ok());
    assert!(UtcCron::parse(&(padded + " ")).is_err());
    let fields: Vec<_> = canonical.split_ascii_whitespace().collect();
    assert_eq!(fields.len(), capability.cron.field_count);
    assert_eq!(fields[0], capability.cron.seconds_field);
    assert_eq!(fields[fields.len() - 1], capability.cron.year_field);

    let due = t("2026-10-11T01:00:00Z");
    let expiry = due + Duration::days(1);
    for grace in [
        capability.limits.grace_seconds.minimum,
        capability.limits.grace_seconds.maximum,
    ] {
        assert!(matches!(
            decide_due(None, due, due, expiry, grace).unwrap(),
            DueDecision::Ready { .. }
        ));
        assert!(matches!(
            decide_due(
                None,
                due,
                due + Duration::seconds(i64::from(grace)),
                expiry,
                grace,
            )
            .unwrap(),
            DueDecision::Skipped { next_due: None, .. }
        ));
    }
    assert!(
        decide_due(
            None,
            due,
            due,
            expiry,
            capability.limits.grace_seconds.minimum - 1,
        )
        .is_err()
    );
    assert!(
        decide_due(
            None,
            due,
            due,
            expiry,
            capability.limits.grace_seconds.maximum + 1,
        )
        .is_err()
    );
}
