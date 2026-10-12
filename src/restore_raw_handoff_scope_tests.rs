//! PRIVATE test-only child of the collector. Every time below is obtained from
//! the complete actual owned attempt; none is an authorization constructor.
use super::*;
use anyhow::{Context, ensure};

pub(crate) struct HorizonFacts {
    pub(crate) first: Instant,
    pub(crate) final_read: Instant,
    pub(crate) held: Instant,
}
pub(crate) fn horizons(
    owned: &BackupRawBoundTemplateAttempt,
    engine: &OperationEngine,
    claim: &Claim,
) -> anyhow::Result<HorizonFacts> {
    owned
        .current(engine, claim)
        .map_err(|_| anyhow::anyhow!("real owned collector scope current"))?;
    Ok(HorizonFacts {
        first: owned
            .first
            .backup_disk_scope(&owned.attempt, engine, claim)
            .map_err(|_| anyhow::anyhow!("actual first scope"))?
            .deadline(),
        final_read: owned
            .observed
            .current
            .backup_disk_scope(&owned.attempt, engine, claim)
            .map_err(|_| anyhow::anyhow!("actual final scope"))?
            .deadline(),
        held: owned
            .handoff_deadline(engine, claim)
            .map_err(|_| anyhow::anyhow!("actual held minimum"))?,
    })
}

pub(crate) async fn same_tx_strictly_narrower(
    owned: BackupRawBoundTemplateAttempt,
    engine: &OperationEngine,
    claim: &Claim,
) -> anyhow::Result<BackupRawBoundTemplateAttempt> {
    let held = horizons(&owned, engine, claim)?.held;
    let mut deadline = held;
    let mut tx = tokio::time::timeout_at(
        tokio::time::Instant::from_std(held),
        engine.database.begin(claim.tenant_id),
    )
    .await
    .context("strict same-TX original BEGIN budget")?
    .map_err(|_| anyhow::anyhow!("strict same-TX normal backup BEGIN"))?;
    eprintln!("PRIVATE handoff strict14 same-TX read entered");
    let outcome = tokio::time::timeout_at(tokio::time::Instant::from_std(held), Box::pin(async {
        let before: (String, String, i32, i64) = sqlx::query_as(
            "SELECT session_user::text,current_user::text,pg_backend_pid(),txid_current()",
        ).fetch_one(&mut *tx).await?;
        ensure!(before.0 == "sandbox_backup" && before.1 == "sandbox_backup", "strict same-TX actual normal backup LOGIN");
        let publication = Box::pin(owned.observed.current.validate_backup_transaction(&owned.attempt, engine, claim, &mut tx))
            .await.map_err(|_| anyhow::anyhow!("strict same-TX actual final14 reader"))?;
        deadline = held.min(publication.deadline().map_err(|_| anyhow::anyhow!("strict same-TX sealed finite deadline"))?);
        ensure!(held.checked_duration_since(deadline).is_some_and(|difference| difference >= std::time::Duration::from_secs(1)),
            "actual same-TX SQL authority is genuinely shorter than the held collector; not a clock conversion micro-difference");
        let pin = publication.sql_publication_pin().map_err(|_| anyhow::anyhow!("strict same-TX current14"))?;
        let returned: Option<serde_json::Value> = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline),
            sqlx::query_scalar("SELECT sandbox_restore_raw_bound_claim($1,$2,$3,$4,$5)")
                .bind(claim.tenant_id).bind(owned.observed.original_scope.facts().restore_id)
                .bind(engine.worker_id()).bind(claim.lease_token)
                .bind(&owned.observed.original_scope.facts().node.node_name)
                .fetch_one(&mut *tx),
        ).await.context("strict same-TX fixed reader original/new min")??;
        let returned = returned.context("strict same-TX exact authority remains live")?;
        ensure!(returned.as_object().is_some_and(|v|v.len()==2) && returned["pin"] == *pin
            && pin.as_object().is_some_and(|v|v.len()==14)
            && pin["resource_identities"]["BLOCK_PV"]["binding"].is_null()
            && pin["block_receipt"].is_null() && pin["disk_receipt"].is_null(),
            "strict narrowed real14 has unchanged pin and no future child facts");
        let expected_pin = pin.clone();
        let missing = publication.validate_publication_envelope(&returned, &expected_pin)
            .err().context("strict pre-record real envelope must not become writer publication")?;
        ensure!(missing.code == 403 && missing.message == "Raw bound publication requires all three strong child records",
            "strict same-TX exact missing-three-child refusal, not unrelated dependency/pin error");
        // Retain another ACTUAL current same-TX read through rollback ACK after
        // the consuming negative, without creating/editing any scope or token.
        let publication = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline),
            owned.observed.current.validate_backup_transaction(&owned.attempt, engine, claim, &mut tx))
            .await.context("strict retained read stays inside newly smaller budget")?
            .map_err(|_|anyhow::anyhow!("strict same-TX retained actual final14"))?;
        deadline = deadline.min(publication.deadline().map_err(|_|anyhow::anyhow!("strict retained finite minimum"))?);
        ensure!(*publication.sql_publication_pin().map_err(|_|anyhow::anyhow!("strict retained current pin"))? == expected_pin,
            "strict negative and retained token preserve complete actual14 in the same TX");
        let after: (String, String, i32, i64) = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline),sqlx::query_as(
            "SELECT session_user::text,current_user::text,pg_backend_pid(),txid_current()",
        ).fetch_one(&mut *tx)).await.context("strict same-TX identity read stays inside newly smaller budget")??;
        ensure!(before == after && Instant::now() < deadline, "strict narrowed read remained in one actual backend/XID within the new minimum");
        Ok::<_, anyhow::Error>(publication)
    })).await.context("strict same-TX original held budget").and_then(|result|result);
    eprintln!("PRIVATE handoff strict14 same-TX read settled");
    let rollback = if Instant::now() < deadline {
        Box::pin(async {
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), tx.rollback())
                .await
                .context("strict new-min actual rollback ACK")??;
            ensure!(
                Instant::now() < deadline,
                "strict new-min rollback response arrived before deadline"
            );
            owned
                .current(engine, claim)
                .map_err(|_| anyhow::anyhow!("strict rollback retains original owned authority"))?;
            if let Ok(publication) = &outcome {
                publication.sql_publication_pin().map_err(|_| {
                    anyhow::anyhow!("strict rollback retains the newly smaller finite token")
                })?;
            }
            Ok::<(), anyhow::Error>(())
        })
        .await
    } else {
        drop(tx);
        Err(anyhow::anyhow!("strict new-min rollback ACK unconfirmed"))
    };
    if rollback.is_err() {
        eprintln!("PRIVATE strict handoff cleanup unconfirmed");
    }
    eprintln!("PRIVATE handoff strict14 same-TX rollback settled");
    outcome?;
    rollback?;
    Ok(owned)
}
