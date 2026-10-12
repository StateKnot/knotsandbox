#![allow(clippy::expect_used, clippy::unwrap_used)]
use chrono::{DateTime, Utc};
use sandbox_platform::automation::rules::{DueDecision, RuleError, UtcCron, decide_due};
fn t(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
}

#[test]
fn utc_grammar_is_explicit_bounded_and_never_enables_seconds_or_host_timezone() {
    for expression in [
        "* * * * *",
        "* * * * * * *",
        "0 * * * * * 2027",
        "@daily",
        "0 0 0 * * * UTC",
        "0 0/0 * * * * *",
    ] {
        assert!(UtcCron::parse(expression).is_err(), "{expression}");
    }
    let cron = UtcCron::parse(" 0  */15  *  * * * * ").unwrap();
    assert_eq!(cron.expression(), "0 */15 * * * * *");
    assert_eq!(
        cron.next_after(t("2026-10-08T00:00:00Z"), t("2026-11-08T00:00:00Z"))
            .unwrap(),
        t("2026-10-08T00:15:00Z")
    );
}

#[test]
fn utc_leap_days_month_end_and_day_intersection_follow_the_pinned_parser() {
    let leap = UtcCron::parse("0 0 0 29 Feb * *").unwrap();
    assert_eq!(
        leap.next_after(t("2026-10-08T00:00:00Z"), t("2029-01-01T00:00:00Z"))
            .unwrap(),
        t("2028-02-29T00:00:00Z")
    );
    let month_end = UtcCron::parse("0 0 0 31 * * *").unwrap();
    assert_eq!(
        month_end
            .next_after(t("2026-04-01T00:00:00Z"), t("2027-04-01T00:00:00Z"))
            .unwrap(),
        t("2026-05-31T00:00:00Z")
    );
    let intersection = UtcCron::parse("0 0 0 1,15 * Mon *").unwrap();
    assert_eq!(
        intersection
            .next_after(t("2026-10-08T00:00:00Z"), t("2027-10-08T00:00:00Z"))
            .unwrap(),
        t("2027-02-01T00:00:00Z")
    );
}

#[test]
fn outage_skips_to_one_future_occurrence_and_exact_deadline_is_expired() {
    let cron = UtcCron::parse("0 * * * * * *").unwrap();
    assert_eq!(
        decide_due(
            Some(&cron),
            t("2026-10-08T00:00:00Z"),
            t("2026-10-08T05:00:00Z"),
            t("2026-11-08T00:00:00Z"),
            300
        )
        .unwrap(),
        DueDecision::Skipped {
            from: t("2026-10-08T00:00:00Z"),
            through: t("2026-10-08T05:00:00Z"),
            next_due: Some(t("2026-10-08T05:01:00Z")),
        }
    );
    assert!(matches!(
        decide_due(
            None,
            t("2026-10-08T00:00:00Z"),
            t("2026-10-08T00:05:00Z"),
            t("2026-11-08T00:00:00Z"),
            300
        )
        .unwrap(),
        DueDecision::Skipped { next_due: None, .. }
    ));
    assert_eq!(
        decide_due(
            Some(&cron),
            t("2026-10-08T00:00:00Z"),
            t("2026-11-08T00:00:00Z"),
            t("2026-11-08T00:00:00Z"),
            300
        )
        .unwrap(),
        DueDecision::Expired
    );
    assert_eq!(
        cron.next_after(t("2026-10-08T00:00:00Z"), t("2026-10-08T00:00:30Z")),
        Err(RuleError::NoOccurrence)
    );
}
