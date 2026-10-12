//! Installation-owner EXPECTATION registration in the closed restore module.
//! A persisted configuration row is never a live vendor Gate or volume permit.
use super::{storage_contract::RestoreStorageMapping, vendor_profile::RestoreVendorReport};
use crate::{backup_job::BackupCloudSettings, db::Database};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde_json::Value;
use sqlx::Row;
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RestoreReportRegistrationError {
    #[error("Restore report registration requires installation owner")]
    Owner,
    #[error("Restore report registration binding rejected")]
    Binding,
    #[error("Restore report registration database unavailable or acknowledgement unknown")]
    Unknown,
}
pub(crate) struct RestoreReportRegistrationReceipt {
    pub(crate) profile_id: Uuid,
    pub(crate) report_sha256: String,
    pub(crate) recorded_at: DateTime<Utc>,
    pub(crate) replayed: bool,
}
type Result<T> = std::result::Result<T, RestoreReportRegistrationError>;
pub(crate) async fn register_restore_report_expectations(
    database: &Database,
    report: &RestoreVendorReport,
    approval_reference: &str,
) -> Result<RestoreReportRegistrationReceipt> {
    // No caller Instant and no reset after metadata reads, lock waits or ACK.
    let started = Instant::now();
    let deadline = started + Duration::from_secs(10);
    if approval_reference.trim().is_empty()
        || approval_reference.chars().count() > 256
        || approval_reference.chars().any(char::is_control)
    {
        return Err(RestoreReportRegistrationError::Binding);
    }
    let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
        let view = report.registration_view().map_err(|_| RestoreReportRegistrationError::Binding)?;
        let mut tx = database.pool.begin().await.map_err(|_| RestoreReportRegistrationError::Unknown)?;
        let owner: bool = sqlx::query_scalar("SELECT count(*)=3 AND bool_and(pg_has_role(current_user,c.relowner,'USAGE')) FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relname=ANY(ARRAY['backup_profiles','restore_profile_certifications','platform_configuration'])")
            .fetch_one(&mut *tx).await.map_err(|_| RestoreReportRegistrationError::Unknown)?;
        if !owner { return Err(RestoreReportRegistrationError::Owner); }
        sqlx::query("SET LOCAL lock_timeout='5s'").execute(&mut *tx).await.map_err(|_| RestoreReportRegistrationError::Unknown)?;
        sqlx::query("SET LOCAL statement_timeout='10s'").execute(&mut *tx).await.map_err(|_| RestoreReportRegistrationError::Unknown)?;
        let (epoch, safe): (Uuid, bool) = sqlx::query_as("SELECT cluster_epoch,safe_mode FROM platform_configuration WHERE singleton FOR UPDATE")
            .fetch_one(&mut *tx).await.map_err(|_| RestoreReportRegistrationError::Unknown)?;
        if epoch != view.cluster_epoch || !safe { return Err(RestoreReportRegistrationError::Binding); }
        let profile = sqlx::query("SELECT cluster_epoch,enabled,certification_sha256,certified_until,settings FROM backup_profiles WHERE id=$1 FOR SHARE")
            .bind(view.profile_id).fetch_optional(&mut *tx).await.map_err(|_| RestoreReportRegistrationError::Unknown)?
            .ok_or(RestoreReportRegistrationError::Binding)?;
        let cloud_value: Value = profile.try_get("settings").map_err(|_| RestoreReportRegistrationError::Unknown)?;
        let cloud: BackupCloudSettings = serde_json::from_value(cloud_value.clone()).map_err(|_| RestoreReportRegistrationError::Binding)?;
        cloud.validate().map_err(|_| RestoreReportRegistrationError::Binding)?;
        let mappings: Vec<RestoreStorageMapping> = serde_json::from_value(view.storage_mappings.clone()).map_err(|_| RestoreReportRegistrationError::Binding)?;
        for mapping in mappings {
            mapping.validate().map_err(|_| RestoreReportRegistrationError::Binding)?;
            if mapping.account_id != cloud.account_id || mapping.region != cloud.region || mapping.deployment != cloud.deployment {
                return Err(RestoreReportRegistrationError::Binding);
            }
        }
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()").fetch_one(&mut *tx).await.map_err(|_| RestoreReportRegistrationError::Unknown)?;
        let until: DateTime<Utc> = profile.try_get("certified_until").map_err(|_| RestoreReportRegistrationError::Unknown)?;
        let binding = &view.report["bindings"];
        if profile.try_get::<Uuid,_>("cluster_epoch").map_err(|_| RestoreReportRegistrationError::Unknown)? != epoch
            || !profile.try_get::<bool,_>("enabled").map_err(|_| RestoreReportRegistrationError::Unknown)?
            || profile.try_get::<String,_>("certification_sha256").map_err(|_| RestoreReportRegistrationError::Unknown)? != view.backup_certification_sha256
            || until < view.expires_at || view.reviewed_at > now
            || view.expires_at <= now + ChronoDuration::hours(6)
            || view.expires_at > view.reviewed_at + ChronoDuration::days(30)
            || ["account_id","region","deployment"].into_iter().any(|key| binding[key] != cloud_value[key])
        { return Err(RestoreReportRegistrationError::Binding); }
        let bounded: bool = sqlx::query_scalar("SELECT octet_length($1::jsonb::text)<=131072")
            .bind(&view.report).fetch_one(&mut *tx).await.map_err(|_| RestoreReportRegistrationError::Unknown)?;
        if !bounded { return Err(RestoreReportRegistrationError::Binding); }
        if Instant::now() >= deadline { return Err(RestoreReportRegistrationError::Unknown); }
        let changed = sqlx::query("INSERT INTO restore_profile_certifications(profile_id,cluster_epoch,backup_certification_sha256,report_sha256,report,storage_mappings,approval_reference,reviewed_at,certified_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(profile_id) DO NOTHING")
            .bind(view.profile_id).bind(view.cluster_epoch).bind(view.backup_certification_sha256).bind(view.report_sha256).bind(&view.report).bind(&view.storage_mappings).bind(approval_reference).bind(view.reviewed_at).bind(view.expires_at)
            .execute(&mut *tx).await.map_err(|_| RestoreReportRegistrationError::Unknown)?;
        let row = sqlx::query("SELECT * FROM restore_profile_certifications WHERE profile_id=$1 FOR SHARE")
            .bind(view.profile_id).fetch_one(&mut *tx).await.map_err(|_| RestoreReportRegistrationError::Unknown)?;
        if row.try_get::<Uuid,_>("cluster_epoch").map_err(|_| RestoreReportRegistrationError::Unknown)? != view.cluster_epoch
            || row.try_get::<String,_>("backup_certification_sha256").map_err(|_| RestoreReportRegistrationError::Unknown)? != view.backup_certification_sha256
            || row.try_get::<String,_>("report_sha256").map_err(|_| RestoreReportRegistrationError::Unknown)? != view.report_sha256
            || row.try_get::<Value,_>("report").map_err(|_| RestoreReportRegistrationError::Unknown)? != view.report
            || row.try_get::<Value,_>("storage_mappings").map_err(|_| RestoreReportRegistrationError::Unknown)? != view.storage_mappings
            || row.try_get::<String,_>("approval_reference").map_err(|_| RestoreReportRegistrationError::Unknown)? != approval_reference
            || row.try_get::<DateTime<Utc>,_>("reviewed_at").map_err(|_| RestoreReportRegistrationError::Unknown)? != view.reviewed_at
            || row.try_get::<DateTime<Utc>,_>("certified_until").map_err(|_| RestoreReportRegistrationError::Unknown)? != view.expires_at
        { return Err(RestoreReportRegistrationError::Binding); }
        let receipt = RestoreReportRegistrationReceipt {
            profile_id: view.profile_id, report_sha256: view.report_sha256.into(),
            recorded_at: row.try_get("recorded_at").map_err(|_| RestoreReportRegistrationError::Unknown)?,
            replayed: changed.rows_affected() == 0,
        };
        if Instant::now() >= deadline || Utc::now() >= view.expires_at { return Err(RestoreReportRegistrationError::Unknown); }
        tx.commit().await.map_err(|_| RestoreReportRegistrationError::Unknown)?;
        if Instant::now() >= deadline || Utc::now() >= view.expires_at { return Err(RestoreReportRegistrationError::Unknown); }
        Ok(receipt)
    }).await.map_err(|_| RestoreReportRegistrationError::Unknown)??;
    // Tokio's ready-first polling is not proof the original budget remains.
    if Instant::now() >= deadline {
        return Err(RestoreReportRegistrationError::Unknown);
    }
    Ok(result)
}
