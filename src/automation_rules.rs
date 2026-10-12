//! UTC-only recurrence and bounded missed-run decisions. The caller supplies
//! PostgreSQL clock time; this module neither sleeps nor starts any operation.
//! Grammar and iterator: https://docs.rs/cron/0.17.0/cron/struct.Schedule.html
use super::contract;
use chrono::{DateTime, Duration, Utc};
use cron::Schedule;
use std::str::FromStr;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RuleError {
    #[error("cron requires seven UTC fields, second 0, and wildcard year")]
    InvalidCron,
    #[error("automation time or grace limit is invalid")]
    InvalidTime,
    #[error("no occurrence exists within the explicit delegation lifetime")]
    NoOccurrence,
}

pub struct UtcCron {
    canonical: String,
    schedule: Schedule,
}
impl UtcCron {
    /// Seven fields: sec/min/hour/day-of-month/month/day-of-week/year.
    /// Seconds must be 0, years *, days use cron 0.17's documented AND
    /// semantics. No timezone input, local host timezone or DST conversion.
    pub fn parse(expression: &str) -> Result<Self, RuleError> {
        if expression.len() > contract::CRON_EXPRESSION_BYTES_MAX || !expression.is_ascii() {
            return Err(RuleError::InvalidCron);
        }
        let fields: Vec<_> = expression.split_ascii_whitespace().collect();
        if fields.len() != contract::CRON_FIELD_COUNT
            || fields[0] != contract::CRON_SECONDS_FIELD
            || fields[contract::CRON_FIELD_COUNT - 1] != contract::CRON_YEAR_FIELD
        {
            return Err(RuleError::InvalidCron);
        }
        let canonical = fields.join(" ");
        let schedule = Schedule::from_str(&canonical).map_err(|_| RuleError::InvalidCron)?;
        Ok(Self {
            canonical,
            schedule,
        })
    }
    pub fn expression(&self) -> &str {
        &self.canonical
    }
    pub fn next_after(
        &self,
        after: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, RuleError> {
        self.schedule
            .after(&after)
            .find(|t| *t > after)
            .filter(|t| *t < expires_at)
            .ok_or(RuleError::NoOccurrence)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DueDecision {
    NotDue,
    Ready {
        scheduled_for: DateTime<Utc>,
        deadline: DateTime<Utc>,
        next_due: Option<DateTime<Utc>>,
    },
    Skipped {
        from: DateTime<Utc>,
        through: DateTime<Utc>,
        next_due: Option<DateTime<Utc>>,
    },
    Expired,
}
/// A missed interval is one historical skipped span. It never starts a catch-up
/// loop or manufactures one execution per minute during an outage.
pub fn decide_due(
    cron: Option<&UtcCron>,
    due: DateTime<Utc>,
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    grace_seconds: u32,
) -> Result<DueDecision, RuleError> {
    if !(contract::GRACE_MIN..=contract::GRACE_MAX).contains(&grace_seconds) {
        return Err(RuleError::InvalidTime);
    }
    if now >= expires_at || due >= expires_at {
        return Ok(DueDecision::Expired);
    }
    if now < due {
        return Ok(DueDecision::NotDue);
    }
    let deadline = due
        .checked_add_signed(Duration::seconds(grace_seconds as i64))
        .ok_or(RuleError::InvalidTime)?
        .min(expires_at);
    let next_due = cron.and_then(|c| c.next_after(now, expires_at).ok());
    if now >= deadline {
        Ok(DueDecision::Skipped {
            from: due,
            through: now,
            next_due,
        })
    } else {
        Ok(DueDecision::Ready {
            scheduled_for: due,
            deadline,
            next_due,
        })
    }
}
