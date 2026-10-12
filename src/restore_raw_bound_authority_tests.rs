//! PRIVATE exact SQL reader acceptance layered on the existing normal Pending
//! parent/Job/once-Pod/enrollment/owner-collector setup. No future record is seeded.
use super::*;
use crate::restore::admission::RawBoundAttempt;

#[path = "restore_raw_bound_commit_tests.rs"]
mod commit_faults;
#[path = "restore_raw_bound_hot_tests.rs"]
pub(super) mod hot;
#[path = "restore_raw_bound_source_tests.rs"]
mod source_storage;

#[path = "restore_raw_bound_collector_tests.rs"]
mod disk_collector;

async fn envelope(case: &SelectedCase<'_>, node_hint: &str) -> anyhow::Result<Value> {
    let mut tx = case
        .service
        .database
        .begin(case.t)
        .await
        .map_err(api_failure)?;
    let value: Option<Value> =
        sqlx::query_scalar("SELECT sandbox_restore_raw_bound_admission($1,$2,$3)")
            .bind(case.t)
            .bind(case.r)
            .bind(node_hint)
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    let value = value.context("actual bound reader positive envelope")?;
    ensure!(
        value.as_object().is_some_and(|o| o.len() == 2)
            && value["valid_for_us"]
                .as_i64()
                .is_some_and(|n| (1..=10_000_000).contains(&n))
            && value["pin"].as_object().is_some_and(|o| o.len() == 14)
            && value["pin"]["block_receipt"].is_null()
            && value["pin"]["disk_receipt"].is_null()
            && value["pin"]["resource_identities"]["BLOCK_PV"]["binding"].is_null()
            && value["pin"]["resource_identities"]["BLOCK_PVC"]["binding"]["uid"]
                == case.w.get(case.pvc_path)?["metadata"]["uid"]
            && value["pin"]["record"]["id"] == json!(case.r)
            && value["pin"]["operation_identity"]["id"] == json!(case.claim.operation_id)
            && value["pin"]["node_identity"]["node_name"] == json!(node_hint),
        "real 14pin source/claim/recorded parent/enrolled Node and exactly no future identities"
    );
    source_storage::actual_pin(case, &value["pin"]).await?;
    Ok(value)
}
async fn absent_companion(case: &SelectedCase<'_>) -> anyhow::Result<()> {
    let mut tx = case.source.f.base.f.owner_transaction().await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM restore_raw_disk_receipts WHERE tenant_id=$1 AND restore_id=$2",
    )
    .bind(case.t)
    .bind(case.r)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    ensure!(
        count == 0,
        "reader trials must not fabricate a signed-disk record"
    );
    let current = facts(&case.source.f.base.f.owner, case.t, case.r).await?;
    no_future(&current)?;
    ensure!(
        current == *case.baseline,
        "reader trials preserve actual whole source/target/bindings/holds/quota facts"
    );
    Ok(())
}
async fn acl(case: &SelectedCase<'_>) -> anyhow::Result<()> {
    for (database, queries) in [
        (
            &case.source.f.base.f.database,
            vec![
                "SELECT sandbox_restore_raw_bound_admission($1,$2,'missing-node')",
                "SELECT sandbox_restore_raw_bound_claim($1,$2,'missing-worker',1,'missing-node')",
            ],
        ),
        (
            &case.source.f.backup.database,
            vec!["SELECT sandbox_restore_raw_bound_admission($1,$2,'missing-node')"],
        ),
        (
            &case.service.database,
            vec!["SELECT sandbox_restore_raw_bound_claim($1,$2,'missing-worker',1,'missing-node')"],
        ),
    ] {
        for query in queries {
            let mut tx = database.begin(case.t).await.map_err(api_failure)?;
            let error = sqlx::query(query)
                .bind(case.t)
                .bind(case.r)
                .execute(&mut *tx)
                .await
                .err()
                .context("foreign reader EXEC must fail")?;
            ensure!(
                error.as_database_error().and_then(|e| e.code()).as_deref() == Some("42501"),
                "exact independent reader EXEC privileges"
            );
            tx.rollback().await?;
        }
    }
    for database in [
        &case.source.f.base.f.database,
        &case.source.f.backup.database,
        &case.service.database,
    ] {
        for query in [
            "SELECT * FROM restore_raw_disk_receipts",
            "SELECT sandbox_restore_raw_disk_payload_valid(NULL,NULL)",
            "SELECT sandbox_restore_raw_bound_envelope(NULL,NULL,NULL,NULL,NULL)",
        ] {
            let mut tx = database.begin(case.t).await.map_err(api_failure)?;
            let error = sqlx::query(query)
                .execute(&mut *tx)
                .await
                .err()
                .context("ordinary global/helper access must fail")?;
            ensure!(
                error.as_database_error().and_then(|e| e.code()).as_deref() == Some("42501"),
                "ordinary reader stays EXEC-only without companion/global/internal access"
            );
            tx.rollback().await?;
        }
    }
    Ok(())
}
async fn locate_selected_parent(
    case: &SelectedCase<'_>,
    expected_hint: &str,
) -> anyhow::Result<String> {
    let url = format!(
        "{}{}",
        case.w.server.url.as_str().trim_end_matches('/'),
        case.pvc_path
    );
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?
        .get(url)
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::OK,
        "actual locator parent GET reaches existing selected PVC"
    );
    let parent: Value = response.json().await?;
    let intent = case.baseline["intents"]
        .as_array()
        .context("normal intents")?
        .iter()
        .find(|i| i["kind"] == "BLOCK_PVC")
        .context("normal parent intent")?;
    let binding = case.baseline["bindings"]
        .as_array()
        .context("normal bindings")?
        .iter()
        .find(|b| b["intent_id"] == intent["id"])
        .context("normal recorded parent binding")?;
    ensure!(
        parent["metadata"]["uid"] == binding["uid"]
            && parent["status"]["phase"] == "Pending"
            && parent["metadata"]["annotations"][STABLE] == DRIVER
            && parent["metadata"]["annotations"][BETA] == DRIVER,
        "actual Pending locator GET matches normal recorded UID/provisioner pair, no future PV"
    );
    let hint = parent["metadata"]["annotations"][SELECTED]
        .as_str()
        .context("actual selected-node locator")?
        .to_owned();
    ensure!(
        hint == expected_hint,
        "actual selection matches the independently registered fixture Node"
    );
    Ok(hint)
}
async fn pair(case: &SelectedCase<'_>, node_hint: &str) -> anyhow::Result<()> {
    let attempt = RawBoundAttempt::start();
    let hint = Box::pin(locate_selected_parent(case, node_hint)).await?;
    let first = case
        .service
        .prepare_raw_bound_admission(&attempt, case.t, case.r, &hint)
        .await
        .map_err(|e| anyhow::anyhow!(e.message))
        .context("raw bound actual admission first decoder")?;
    case.service
        .recheck_raw_bound_admission(&first)
        .await
        .map_err(|e| anyhow::anyhow!(e.message))
        .context("raw bound actual admission final decoder")?;
    let attempt = RawBoundAttempt::start();
    let hint = Box::pin(locate_selected_parent(case, node_hint)).await?;
    let database = &case.source.f.backup.database;
    let first = database
        .prepare_restore_bound_authority(&attempt, &case.source.f.backup, case.claim, case.r, &hint)
        .await
        .map_err(api_failure)
        .context("raw bound actual backup first decoder")?;
    database
        .recheck_restore_bound_authority(&case.source.f.backup, case.claim, &first)
        .await
        .map_err(api_failure)
        .context("raw bound actual backup final decoder")?;
    Ok(())
}
async fn six_scopes(case: &SelectedCase<'_>, node_hint: &str) -> anyhow::Result<()> {
    let mut tx = case.source.f.base.f.owner_transaction().await?;
    let grants: Vec<Uuid> = sqlx::query_scalar("SELECT g.id FROM grants g JOIN operations o ON o.tenant_id=g.tenant_id AND o.actor_principal_id=g.principal_id JOIN restores r ON r.tenant_id=o.tenant_id AND r.operation_id=o.id WHERE r.tenant_id=$1 AND r.id=$2 AND g.enabled AND g.revoked_at IS NULL AND ((g.project_id IS NULL AND g.action IN('backups:read','backups:restore','instances:create')) OR(g.project_id=r.source_project_id AND g.action IN('backups:read','backups:restore')) OR(g.project_id=r.target_project_id AND g.action='instances:create')) ORDER BY g.id")
        .bind(case.t).bind(case.r).fetch_all(&mut *tx).await?;
    let alternative: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM grants g JOIN operations o ON o.tenant_id=g.tenant_id AND o.actor_principal_id=g.principal_id WHERE o.tenant_id=$1 AND o.id=$2 AND g.action='*' AND g.enabled AND g.revoked_at IS NULL AND(g.expires_at IS NULL OR g.expires_at>clock_timestamp()))")
        .bind(case.t).bind(case.claim.operation_id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    ensure!(
        grants.len() == 6 && !alternative,
        "six exact independent scope fixture, no alternative wildcard bypass"
    );
    for grant in grants {
        let mut tx = case.source.f.base.f.owner_transaction().await?;
        sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND id=$2 AND enabled")
            .bind(case.t)
            .bind(grant)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        let outcome = Box::pin(async {
            let error = case
                .service
                .prepare_raw_bound_admission(&RawBoundAttempt::start(), case.t, case.r, node_hint)
                .await
                .err()
                .context("each withdrawn scope denies independent admission reader")?;
            ensure!(
                error.code == 403 && error.message == "Current raw bound authority unavailable",
                "targeted SQL scope denial, not dependency failure"
            );
            let error = case
                .source
                .f
                .backup
                .database
                .prepare_restore_bound_authority(
                    &RawBoundAttempt::start(),
                    &case.source.f.backup,
                    case.claim,
                    case.r,
                    node_hint,
                )
                .await
                .err()
                .context("each withdrawn scope denies current claim reader")?;
            ensure!(
                error.status == StatusCode::FORBIDDEN
                    && error.detail == "Current raw bound authority unavailable",
                "backup reader same single-statement scope denial"
            );
            absent_companion(case).await
        })
        .await;
        let mut tx = case.source.f.base.f.owner_transaction().await?;
        sqlx::query("UPDATE grants SET enabled=true WHERE tenant_id=$1 AND id=$2 AND NOT enabled")
            .bind(case.t)
            .bind(grant)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        outcome?;
    }
    Ok(())
}
async fn final_pin(case: &SelectedCase<'_>, node_hint: &str) -> anyhow::Result<()> {
    let first = case
        .service
        .prepare_raw_bound_admission(&RawBoundAttempt::start(), case.t, case.r, node_hint)
        .await
        .map_err(|e| anyhow::anyhow!(e.message))?;
    let backup = case
        .source
        .f
        .backup
        .database
        .prepare_restore_bound_authority(
            &RawBoundAttempt::start(),
            &case.source.f.backup,
            case.claim,
            case.r,
            node_hint,
        )
        .await
        .map_err(api_failure)?;
    let mut tx = case.source.f.base.f.owner_transaction().await?;
    let principal: Uuid = sqlx::query_scalar(
        "SELECT actor_principal_id FROM operations WHERE tenant_id=$1 AND id=$2",
    )
    .bind(case.t)
    .bind(case.claim.operation_id)
    .fetch_one(&mut *tx)
    .await?;
    let changed =
        sqlx::query("UPDATE principals SET authz_version=authz_version+1 WHERE id=$1 AND enabled")
            .bind(principal)
            .execute(&mut *tx)
            .await?;
    ensure!(
        changed.rows_affected() == 1,
        "normal monotonic principal version change"
    );
    tx.commit().await?;
    let error = case
        .service
        .recheck_raw_bound_admission(&first)
        .await
        .err()
        .context(
            "same authorized principal with new version must invalidate in-flight first pin",
        )?;
    ensure!(
        error.code == 403 && error.message == "Raw bound authority pin changed during observation",
        "final pin equality actually detects version change"
    );
    let error = case
        .source
        .f
        .backup
        .database
        .recheck_restore_bound_authority(&case.source.f.backup, case.claim, &backup)
        .await
        .err()
        .context("backup final pin must detect same monotonic version change")?;
    ensure!(
        error.status == StatusCode::FORBIDDEN
            && error.detail == "Raw bound authority pin changed during observation",
        "backup final pin exact change category"
    );
    // No version rollback: new first/final reads legitimately observe new authority.
    Box::pin(pair(case, node_hint)).await?;
    Ok(())
}
pub(super) async fn run(case: &SelectedCase<'_>, node_hint: &str) -> anyhow::Result<()> {
    let entry = case.w.get(case.pvc_path)?;
    let entry_hints = json!({SELECTED:entry["metadata"]["annotations"][SELECTED],
        STABLE:entry["metadata"]["annotations"][STABLE],BETA:entry["metadata"]["annotations"][BETA]});
    ensure!(
        entry_hints == json!({SELECTED:node_hint,STABLE:DRIVER,BETA:DRIVER}),
        "normal selected/provisioned entry must remain available to later boundary trials"
    );
    ensure!(
        case.source
            .f
            .backup
            .heartbeat(case.claim)
            .await
            .map_err(api_failure)?,
        "current real claim before independent bound readers"
    );
    Box::pin(acl(case)).await?;
    // Reach selected+provisioned Pending through the real reviewed HTTP actors;
    // a supplied name remains only a locator for the database reader.
    case.configure(0, Fault::None)?;
    Box::pin(case.put(
        "select",
        case.changed(|v| selected(v, node_hint))?,
        StatusCode::OK,
    ))
    .await
    .context("raw bound precondition actual SELECT API")?;
    case.configure(0, Fault::None)?;
    Box::pin(case.put("provision", case.changed(provision)?, StatusCode::OK))
        .await
        .context("raw bound precondition actual PROVISIONER API")?;
    ensure!(
        case.w.get(case.pvc_path)?["metadata"]["annotations"][SELECTED] == json!(node_hint),
        "actual selected parent locates the registered Node"
    );
    let first = envelope(case, node_hint)
        .await
        .context("raw bound complete actual SQL envelope")?;
    ensure!(
        first["pin"]["record"]["status"] == "RESTORE_PENDING",
        "normal no-future selected setup, not an old Bound fixture"
    );
    Box::pin(pair(case, node_hint)).await?;
    Box::pin(source_storage::run(case, node_hint))
        .await
        .context("raw bound actual sealed source14 scope case")?;
    Box::pin(hot::run(case, node_hint))
        .await
        .context("raw bound same-backend strict14 warm planner regression")?;
    for (tenant, restore, node) in [
        (Uuid::new_v4(), case.r, node_hint),
        (case.t, Uuid::new_v4(), node_hint),
        (case.t, case.source.plan.backup.id, node_hint),
        (case.t, case.r, "not-registered-node"),
    ] {
        let error = case
            .service
            .prepare_raw_bound_admission(&RawBoundAttempt::start(), tenant, restore, node)
            .await
            .err()
            .context("foreign/missing current bound scope must deny")?;
        ensure!(
            error.code == 403 && error.message == "Current raw bound authority unavailable",
            "exact no-disclosure denial"
        );
    }
    for replacement in [false, true] {
        let mut claim = case.claim.clone();
        if replacement {
            claim.operation_id = Uuid::new_v4();
        } else {
            claim.lease_token += 1;
        }
        let error = case
            .source
            .f
            .backup
            .database
            .prepare_restore_bound_authority(
                &RawBoundAttempt::start(),
                &case.source.f.backup,
                &claim,
                case.r,
                node_hint,
            )
            .await
            .err()
            .context("wrong current claim must deny")?;
        ensure!(
            error.status == StatusCode::FORBIDDEN
                && error.detail
                    == if replacement {
                        "Raw bound backup claim identity differs"
                    } else {
                        "Current raw bound authority unavailable"
                    },
            "SQL token and typed operation identity independently fence claim"
        );
    }
    Box::pin(six_scopes(case, node_hint)).await?;
    Box::pin(disk_collector::run(case, node_hint)).await?;
    Box::pin(final_pin(case, node_hint)).await?;
    Box::pin(commit_faults::run(case, node_hint)).await?;
    absent_companion(case).await?;
    // The parent continues with SELECT no-op and RESET drift trials. Preserve
    // its actual selected/provisioned hints; clearing them would make the next
    // no-op refuse before it reaches the targeted Bound observation.
    let final_parent = case.w.get(case.pvc_path)?;
    ensure!(
        entry_hints
            == json!({SELECTED:final_parent["metadata"]["annotations"][SELECTED],
            STABLE:final_parent["metadata"]["annotations"][STABLE],BETA:final_parent["metadata"]["annotations"][BETA]}),
        "normal reviewed child updates preserve parent scheduling hints"
    );
    eprintln!(
        "VERIFIED private raw-bound SQL pre-record 14pin: real Pending parent/earlyPV intent, independent admission/current backup claim first+final COMMIT, six exact scope withdrawals, typed claim fence and monotonic authz pin drift; zero future PV binding/disk receipt/permit/proof; not CSI Bound record or cloud media"
    );
    Ok(())
}
