use super::*;
use crate::{
    bucket_retention::{BucketRetentionExpectation, VerifiedBucketRetention},
    db::Database,
};
use sqlx::{Postgres, Transaction};

#[derive(Serialize)]
pub struct ProfileOwnerReceipt {
    pub request_id: Uuid,
    pub profile_id: Uuid,
    pub action: &'static str,
    pub replayed: bool,
    pub current_enabled: bool,
}
impl ReviewedBackupProfile {
    pub fn validate_retention_expectation(
        &self,
        e: &BucketRetentionExpectation,
    ) -> anyhow::Result<()> {
        e.validate()?;
        ensure!(
            e.profile_id == self.artifact.profile_id
                && e.cluster_epoch == self.artifact.cluster_epoch
                && e.profile_settings_sha256
                    == digest(&serde_json::to_vec(&self.artifact.settings)?)
                && e.account_id == self.cloud.account_id
                && e.region == self.cloud.region
                && e.bucket == self.cloud.vault_bucket
                && e.kms_key_id == self.cloud.vault_kms_key_id
                && e.vault_retention_days == self.cloud.vault_retention_days
                && e.certified_until == self.artifact.certified_until,
            "retention verification target does not match the immutable profile"
        );
        Ok(())
    }
}
fn reference(id: Uuid, value: &str) -> anyhow::Result<()> {
    ensure!(
        !id.is_nil()
            && !value.trim().is_empty()
            && value.len() <= 256
            && !value.chars().any(char::is_control),
        "an exact request UUID and bounded approval reference are required"
    );
    Ok(())
}
async fn owner(db: &Database) -> anyhow::Result<Transaction<'_, Postgres>> {
    let mut tx = db.pool.begin().await?;
    sqlx::query("SET LOCAL lock_timeout='5s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='30s'")
        .execute(&mut *tx)
        .await?;
    let allowed:bool=sqlx::query_scalar("SELECT count(*)=3 AND bool_and(pg_has_role(current_user,c.relowner,'USAGE')) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY['backup_profiles','backup_profile_actions','platform_configuration'])").fetch_one(&mut *tx).await?;
    ensure!(
        allowed,
        "backup profile administration requires the installation owner"
    );
    // Serialize owner actions with recovery epoch changes, not tenant writers.
    sqlx::query("SELECT singleton FROM platform_configuration WHERE singleton FOR UPDATE")
        .fetch_one(&mut *tx)
        .await?;
    Ok(tx)
}
async fn replay(
    tx: &mut Transaction<'_, Postgres>,
    request: Uuid,
    hash: &str,
) -> anyhow::Result<bool> {
    let prior: Option<String> =
        sqlx::query_scalar("SELECT request_sha256 FROM backup_profile_actions WHERE id=$1")
            .bind(request)
            .fetch_optional(&mut **tx)
            .await?;
    if let Some(prior) = prior {
        ensure!(
            prior == hash,
            "owner request UUID was already used for another action"
        );
        Ok(true)
    } else {
        Ok(false)
    }
}
async fn exact(
    tx: &mut Transaction<'_, Postgres>,
    p: &ReviewedBackupProfile,
) -> anyhow::Result<()> {
    let a = &p.artifact;
    let same:Option<bool>=sqlx::query_scalar("SELECT cluster_epoch=$2 AND certification_sha256=$3 AND certified_until=$4 AND image=$5 AND snapshot_class=$6 AND clone_storage_class=$7 AND password_secret=$8 AND signing_private_secret=$9 AND signing_public_secret=$10 AND settings=$11 FROM backup_profiles WHERE id=$1 FOR UPDATE")
        .bind(a.profile_id).bind(a.cluster_epoch).bind(&a.certification_report_sha256).bind(a.certified_until).bind(&a.image).bind(&a.snapshot_class).bind(&a.clone_storage_class).bind(&a.password_secret).bind(&a.signing_private_secret).bind(&a.signing_public_secret).bind(&a.settings).fetch_optional(&mut **tx).await?;
    ensure!(
        same == Some(true),
        "registered profile differs; register a new immutable profile UUID"
    );
    Ok(())
}
async fn record(
    tx: &mut Transaction<'_, Postgres>,
    request: Uuid,
    profile: Uuid,
    action: &str,
    hash: &str,
    approval: &str,
    evidence: Value,
) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO backup_profile_actions(id,profile_id,action,request_sha256,approval_reference,database_actor,observed_cluster_epoch,evidence) SELECT $1,$2,$3,$4,$5,current_user,cluster_epoch,$6 FROM platform_configuration WHERE singleton")
        .bind(request).bind(profile).bind(action).bind(hash).bind(approval).bind(evidence).execute(&mut **tx).await?;
    Ok(())
}
async fn finish(
    mut tx: Transaction<'_, Postgres>,
    request_id: Uuid,
    profile_id: Uuid,
    action: &'static str,
    replayed: bool,
) -> anyhow::Result<ProfileOwnerReceipt> {
    let current_enabled = sqlx::query_scalar("SELECT enabled FROM backup_profiles WHERE id=$1")
        .bind(profile_id)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(ProfileOwnerReceipt {
        request_id,
        profile_id,
        action,
        replayed,
        current_enabled,
    })
}
pub async fn register_profile(
    db: &Database,
    p: &ReviewedBackupProfile,
    request: Uuid,
    approval: &str,
) -> anyhow::Result<ProfileOwnerReceipt> {
    reference(request, approval)?;
    let hash = digest(&serde_json::to_vec(
        &json!({"action":"REGISTER","profile_sha256":p.profile_sha256,"approval_reference":approval}),
    )?);
    let mut tx = owner(db).await?;
    if replay(&mut tx, request, &hash).await? {
        return finish(tx, request, p.artifact.profile_id, "REGISTER", true).await;
    }
    let a = &p.artifact;
    let valid:bool=sqlx::query_scalar("SELECT cluster_epoch=$1 AND clock_timestamp()<$2 FROM platform_configuration WHERE singleton").bind(a.cluster_epoch).bind(a.certified_until).fetch_one(&mut *tx).await?;
    ensure!(
        valid,
        "backup profile requires current epoch and unexpired review"
    );
    sqlx::query("INSERT INTO backup_profiles(id,cluster_epoch,enabled,certification_sha256,certified_until,image,snapshot_class,clone_storage_class,password_secret,signing_private_secret,signing_public_secret,settings) VALUES($1,$2,false,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(id) DO NOTHING")
        .bind(a.profile_id).bind(a.cluster_epoch).bind(&a.certification_report_sha256).bind(a.certified_until).bind(&a.image).bind(&a.snapshot_class).bind(&a.clone_storage_class).bind(&a.password_secret).bind(&a.signing_private_secret).bind(&a.signing_public_secret).bind(&a.settings).execute(&mut *tx).await?;
    exact(&mut tx, p).await?;
    record(
        &mut tx,
        request,
        a.profile_id,
        "REGISTER",
        &hash,
        approval,
        serde_json::to_value(p.static_receipt())?,
    )
    .await?;
    finish(tx, request, a.profile_id, "REGISTER", false).await
}
pub async fn activate_profile(
    db: &Database,
    p: &ReviewedBackupProfile,
    request: Uuid,
    approval: &str,
    kube: &VerifiedBackupKubernetes,
    vault: &VerifiedBucketRetention,
) -> anyhow::Result<ProfileOwnerReceipt> {
    reference(request, approval)?;
    p.validate_retention_expectation(&vault.receipt().expectation)?;
    let hash = digest(&serde_json::to_vec(
        &json!({"action":"ACTIVATE","profile_sha256":p.profile_sha256,"expectation":vault.receipt().expectation,"approval_reference":approval}),
    )?);
    let mut tx = owner(db).await?;
    if replay(&mut tx, request, &hash).await? {
        return finish(tx, request, p.artifact.profile_id, "ACTIVATE", true).await;
    }
    exact(&mut tx, p).await?;
    let (epoch,safe,now):(Uuid,bool,DateTime<Utc>)=sqlx::query_as("SELECT cluster_epoch,safe_mode,clock_timestamp() FROM platform_configuration WHERE singleton").fetch_one(&mut *tx).await?;
    ensure!(
        epoch == p.artifact.cluster_epoch
            && safe
            && p.artifact.certified_until > now + Duration::hours(6),
        "activation requires current epoch, safe mode and certification covering a complete backup deadline"
    );
    ensure!(
        kube.profile_sha256 == p.profile_sha256
            && kube.observed_at <= now + Duration::seconds(30)
            && kube.observed_at >= now - Duration::minutes(5),
        "live Kubernetes profile verification expired or differs"
    );
    vault.check_current(&vault.receipt().expectation)?;
    ensure!(
        vault.receipt().observed_at <= now + Duration::seconds(30)
            && vault.receipt().activation_not_after > now,
        "cloud retention proof does not cover database activation time"
    );
    sqlx::query("UPDATE backup_profiles SET enabled=true WHERE id=$1")
        .bind(p.artifact.profile_id)
        .execute(&mut *tx)
        .await?;
    record(&mut tx,request,p.artifact.profile_id,"ACTIVATE",&hash,approval,json!({"profile":p.static_receipt(),"kubernetes":kube.receipt(),"retention":vault.receipt()})).await?;
    // Recheck after any lock/trigger wait before returning a durable activation.
    let still_fresh: bool =
        sqlx::query_scalar("SELECT clock_timestamp()<$1 AND clock_timestamp()<$2")
            .bind(vault.receipt().activation_not_after)
            .bind(kube.observed_at + Duration::minutes(5))
            .fetch_one(&mut *tx)
            .await?;
    ensure!(
        still_fresh,
        "activation evidence expired while committing owner action"
    );
    finish(tx, request, p.artifact.profile_id, "ACTIVATE", false).await
}
pub async fn revoke_profile(
    db: &Database,
    profile: Uuid,
    request: Uuid,
    approval: &str,
) -> anyhow::Result<ProfileOwnerReceipt> {
    reference(request, approval)?;
    ensure!(!profile.is_nil(), "profile UUID required");
    let hash = digest(&serde_json::to_vec(
        &json!({"action":"REVOKE","profile_id":profile,"approval_reference":approval}),
    )?);
    let mut tx = owner(db).await?;
    if replay(&mut tx, request, &hash).await? {
        return finish(tx, request, profile, "REVOKE", true).await;
    }
    let changed = sqlx::query("UPDATE backup_profiles SET enabled=false WHERE id=$1")
        .bind(profile)
        .execute(&mut *tx)
        .await?;
    ensure!(
        changed.rows_affected() == 1,
        "backup profile does not exist"
    );
    record(
        &mut tx,
        request,
        profile,
        "REVOKE",
        &hash,
        approval,
        json!({"cleanup_still_required":true}),
    )
    .await?;
    finish(tx, request, profile, "REVOKE", false).await
}
