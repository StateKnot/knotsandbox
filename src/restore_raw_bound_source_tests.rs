//! Source-storage facts come from the normal completed backup chain, never
//! inserted by this child. These SQL read scopes are not signed cloud proofs.
use super::*;
use crate::restore::admission::{
    RawBoundDiskFacts, RawBoundDiskPurpose, RawBoundDiskScope, RawBoundRead,
};
use std::time::Instant;

async fn actual_source(case: &SelectedCase<'_>) -> anyhow::Result<Value> {
    let mut tx = case.source.f.base.f.owner_transaction().await?;
    let value: Value = sqlx::query_scalar("SELECT jsonb_build_object('source',b.source,'capture_attempt_id',b.capture_attempt_id,'clone_receipt',to_jsonb(c)) FROM backups b JOIN backup_clone_receipts c ON c.tenant_id=b.tenant_id AND c.backup_id=b.id AND c.attempt_id=b.capture_attempt_id WHERE b.tenant_id=$1 AND b.id=$2 AND b.status='AVAILABLE'")
        .bind(case.t).bind(case.source.plan.backup.id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    ensure!(
        value.as_object().is_some_and(|o| o.len() == 3)
            && value["source"].as_object().is_some_and(|o| o.len() == 14)
            && value["clone_receipt"]
                .as_object()
                .is_some_and(|o| o.len() == 9)
            && value["source"]["tenant_id"] == json!(case.t)
            && value["source"]["backup_id"] == json!(case.source.plan.backup.id)
            && value["capture_attempt_id"]
                .as_str()
                .is_some_and(|s| Uuid::parse_str(s).is_ok_and(|u| !u.is_nil()))
            && value["clone_receipt"]["attempt_id"] == value["capture_attempt_id"]
            && value["clone_receipt"]["backup_id"] == value["source"]["backup_id"]
            && value["clone_receipt"]["tenant_id"] == value["source"]["tenant_id"],
        "actual normal source14/capture/immutable clone9 are nonempty matched rows"
    );
    Ok(value)
}
pub(super) async fn actual_pin(case: &SelectedCase<'_>, pin: &Value) -> anyhow::Result<()> {
    let expected = actual_source(case).await?;
    ensure!(
        pin["source_storage"] == expected,
        "same authority CTE returns complete actual normal source and immutable capture clone, not caller exclusions"
    );
    ensure!(
        expected["source"]["pvc_uid"] == pin["record"]["source_identity"]["source_pvc_uid"]
            && expected["clone_receipt"]["pvc_uid"]
                == pin["record"]["source_identity"]["clone_pvc_uid"]
            && expected["source"]["cluster_epoch"]
                == pin["record"]["source_identity"]["cluster_epoch"],
        "historical source epoch/UIDs match cold verified identity rather than requiring new target epoch"
    );
    Ok(())
}
fn expected_scope(pin: &Value) -> anyhow::Result<Value> {
    let r = &pin["record"];
    let parent = &pin["resource_identities"]["BLOCK_PVC"];
    let node = &pin["node_identity"];
    let source = &pin["source_storage"]["source"];
    let clone = &pin["source_storage"]["clone_receipt"];
    let mapping = &r["storage_contract"]["mapping"];
    ensure!(
        parent["binding"]["uid"].is_string()
            && node.is_object()
            && source.is_object()
            && clone.is_object(),
        "facts comparison never treats missing rows as empty source facts"
    );
    Ok(json!({
        "tenant_id":r["tenant_id"],"restore_id":r["id"],"cluster_epoch":r["cluster_epoch"],
        "namespace":parent["intent"]["namespace"],"pvc_name":parent["intent"]["name"],"pvc_uid":parent["binding"]["uid"],
        "pv_name":pin["resource_identities"]["BLOCK_PV"]["intent"]["name"],
        "parent_intent_created_at":parent["intent"]["created_at"],
        "account_id":mapping["account_id"],"region":mapping["region"],"deployment":mapping["deployment"],
        "workspace_kms_key_id":mapping["workspace_kms_key_id"],"size_gib":r["size_gib"],
        "zone_id":pin["node_topology"]["zone_id"],"runtime_node_id":node["runtime_node_id"],
        "node":{"cluster_epoch":node["cluster_epoch"],"node_uid":node["node_uid"],"node_name":node["node_name"],
            "boot_id":node["boot_id"],"profile_sha256":node["profile_sha256"]},
        "cloud_instance_id":node["cloud_instance_id"],
        "source_pvc_uid":source["pvc_uid"],"source_pv_uid":source["pv_uid"],"source_disk_id":source["cloud_disk"],
        "clone_pvc_uid":clone["pvc_uid"],"clone_pv_uid":clone["pv_uid"],"clone_disk_id":clone["cloud_disk"]}))
}
fn serialized_facts(facts: &RawBoundDiskFacts) -> anyhow::Result<Value> {
    Ok(serde_json::to_value(facts)?)
}
fn scope(scope: &RawBoundDiskScope, pin: &Value) -> anyhow::Result<()> {
    scope.current().map_err(|e| anyhow::anyhow!(e.message))?;
    let mut actual = serialized_facts(scope.facts())?;
    let mut expected = expected_scope(pin)?;
    // PostgreSQL JSON uses +00:00 and chrono emits Z; equality is typed UTC
    // microseconds, not lexical timestamp spelling. All other facts are exact.
    let a = actual["parent_intent_created_at"]
        .as_str()
        .context("typed parent time")?
        .parse::<chrono::DateTime<chrono::Utc>>()?;
    let b = expected["parent_intent_created_at"]
        .as_str()
        .context("actual parent time")?
        .parse::<chrono::DateTime<chrono::Utc>>()?;
    ensure!(
        a == b,
        "scope parent time equals exact actual intent timestamp"
    );
    actual
        .as_object_mut()
        .context("serialized scope")?
        .remove("parent_intent_created_at");
    expected
        .as_object_mut()
        .context("expected scope")?
        .remove("parent_intent_created_at");
    ensure!(
        actual == expected && scope.deadline() > Instant::now(),
        "all sealed scope comparison facts derive from full14pin under original finite horizon"
    );
    Ok(())
}
fn denied(
    value: Result<RawBoundDiskScope, crate::admission::Denial>,
    message: &'static str,
) -> anyhow::Result<()> {
    let error = value
        .err()
        .context("targeted sealed scope misuse must deny")?;
    ensure!(
        error.code == 403 && error.message == message,
        "exact attempt/purpose/claim denial instead of unrelated expiry/dependency"
    );
    Ok(())
}
pub(super) async fn run(case: &SelectedCase<'_>, node_hint: &str) -> anyhow::Result<()> {
    let requests_before = case
        .w
        .shared
        .lock()
        .map_err(|_| anyhow::anyhow!("workload state"))?
        .requests
        .len();
    let cloud_before = case.cloud.actions()?;
    let pin = envelope(case, node_hint).await?["pin"].clone();
    let attempt = RawBoundAttempt::start();
    let hint = Box::pin(locate_selected_parent(case, node_hint)).await?;
    let first: RawBoundRead = case
        .service
        .prepare_raw_bound_admission(&attempt, case.t, case.r, &hint)
        .await
        .map_err(|e| anyhow::anyhow!(e.message))?;
    let admission = first
        .admission_disk_scope(&attempt)
        .map_err(|e| anyhow::anyhow!(e.message))?;
    ensure!(
        matches!(admission.purpose(), RawBoundDiskPurpose::Admission),
        "independent admission first read has admission-only scope"
    );
    scope(&admission, &pin)?;
    denied(
        first.admission_disk_scope(&RawBoundAttempt::start()),
        "Raw bound disk scope cannot replace the original attempt",
    )?;
    denied(
        first.backup_disk_scope(&attempt, &case.source.f.backup, case.claim),
        "Raw bound backup claim changed before disk observation or acknowledgement",
    )?;
    case.service
        .recheck_raw_bound_admission(&first)
        .await
        .map_err(|e| anyhow::anyhow!(e.message))?;
    let attempt = RawBoundAttempt::start();
    let hint = Box::pin(locate_selected_parent(case, node_hint)).await?;
    let first: RawBoundRead = case
        .source
        .f
        .backup
        .database
        .prepare_restore_bound_authority(&attempt, &case.source.f.backup, case.claim, case.r, &hint)
        .await
        .map_err(api_failure)
        .context("source14 actual backup first read")?;
    let backup = first
        .backup_disk_scope(&attempt, &case.source.f.backup, case.claim)
        .map_err(|e| anyhow::anyhow!(e.message))?;
    ensure!(
        matches!(backup.purpose(), RawBoundDiskPurpose::Backup),
        "normal current worker claim has distinct backup-only scope"
    );
    scope(&backup, &pin)?;
    first
        .backup_current(&attempt, &case.source.f.backup, case.claim)
        .map_err(|e| anyhow::anyhow!(e.message))?;
    denied(
        first.admission_disk_scope(&attempt),
        "Admission cannot borrow backup raw bound disk scope",
    )?;
    let mut changed = case.claim.clone();
    changed.lease_token += 1;
    denied(
        first.backup_disk_scope(&attempt, &case.source.f.backup, &changed),
        "Raw bound backup claim changed before disk observation or acknowledgement",
    )?;
    denied(
        first.backup_disk_scope(&RawBoundAttempt::start(), &case.source.f.backup, case.claim),
        "Raw bound disk scope cannot replace the original attempt",
    )?;
    case.source
        .f
        .backup
        .database
        .recheck_restore_bound_authority(&case.source.f.backup, case.claim, &first)
        .await
        .map_err(api_failure)
        .context("source14 actual backup final read")?;
    let before = actual_source(case).await?;
    let capture = Uuid::parse_str(
        before["capture_attempt_id"]
            .as_str()
            .context("actual capture UUID")?,
    )?;
    for query in [
        "UPDATE backup_clone_receipts SET cloud_disk=cloud_disk WHERE tenant_id=$1 AND attempt_id=$2",
        "DELETE FROM backup_clone_receipts WHERE tenant_id=$1 AND attempt_id=$2",
    ] {
        let mut tx = case.source.f.base.f.owner_transaction().await?;
        let error = sqlx::query(query)
            .bind(case.t)
            .bind(capture)
            .execute(&mut *tx)
            .await
            .err()
            .context("normal immutable source clone refuses owner mutation")?;
        ensure!(
            error.as_database_error().and_then(|e| e.code()).as_deref() == Some("23514"),
            "targeted append-only source clone denial, not permission or missing-row failure"
        );
        tx.rollback().await?;
        ensure!(
            actual_source(case).await? == before,
            "actual whole source14 and clone9 preserve original facts"
        );
    }
    absent_companion(case).await?;
    {
        let state = case
            .w
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("workload state"))?;
        ensure!(
            state.requests[requests_before..]
                == [
                    (Method::GET, case.pvc_path.to_owned()),
                    (Method::GET, case.pvc_path.to_owned())
                ],
            "scope extraction, denied reuse and source trials perform only two real parent locator GETs, no PV/cloud I/O"
        );
    }
    ensure!(
        case.cloud.actions()? == cloud_before,
        "reader scope facts never become a signed cloud observation"
    );
    eprintln!(
        "VERIFIED private raw-bound14 source: complete actual normal source14/capture/clone9 in same CTE, original-attempt admission/backup scope separation, exact immutable clone UPDATE+DELETE rejection; no signed cloud observation or three-row publication"
    );
    Ok(())
}
