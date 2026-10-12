//! Real PostgreSQL constraints/roles. Test reports and class UIDs are disposable;
//! neither these fixtures nor a successful HTTP request certify a cloud restore.
use super::*;
use crate::{
    backup_job::BackupCloudSettings,
    db::{Actor, Database},
    restore::storage_contract::{
        RestoreStorageContract, RestoreStoragePurpose, expected_snapshot_class_spec,
        expected_storage_class_spec, snapshot_class_spec_sha256, storage_class_spec_sha256,
    },
    test_support_db::api_failure,
};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use std::collections::BTreeMap;

pub(super) fn digest(value: &Value) -> anyhow::Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}
pub(super) fn fixture(
    cloud: &BackupCloudSettings,
    profile: Uuid,
    epoch: Uuid,
    backup_cert: &str,
) -> anyhow::Result<(Value, Value, BTreeMap<String, Value>)> {
    let class = |name: &str| json!({"name":name,"uid":Uuid::new_v4(),"spec_sha256":"a".repeat(64)});
    let mut contract = RestoreStorageContract::parse(&json!({
        "protocol":1,"profile_id":profile,"cluster_epoch":epoch,
        "backup_certification_sha256":backup_cert,"report_sha256":"a".repeat(64),
        "mapping":{
            "normal":class("integration-storage"),"raw":class("integration-restore-raw"),
            "delivery":class("integration-restore-delivery"),"snapshot":class("integration-restore-snapshot"),
            "workspace_kms_key_id":"restore-compute-key","account_id":cloud.account_id,
            "region":cloud.region,"deployment":cloud.deployment,
            "topology":{"key":"topology.diskplugin.csi.alibabacloud.com/zone",
                "zone_ids":[format!("{}-a",cloud.region),format!("{}-b",cloud.region),format!("{}-c",cloud.region)]}
        }
    }))?;
    let mut objects = BTreeMap::new();
    for purpose in [
        RestoreStoragePurpose::Normal,
        RestoreStoragePurpose::Raw,
        RestoreStoragePurpose::Delivery,
    ] {
        let mut value = expected_storage_class_spec(&contract.mapping, purpose);
        let identity = match purpose {
            RestoreStoragePurpose::Normal => &contract.mapping.normal,
            RestoreStoragePurpose::Raw => &contract.mapping.raw,
            RestoreStoragePurpose::Delivery => &contract.mapping.delivery,
        };
        value["metadata"] = json!({"name":identity.name,"uid":identity.uid});
        let sha = storage_class_spec_sha256(&value, &contract.mapping, purpose)?;
        let identity = match purpose {
            RestoreStoragePurpose::Normal => &mut contract.mapping.normal,
            RestoreStoragePurpose::Raw => &mut contract.mapping.raw,
            RestoreStoragePurpose::Delivery => &mut contract.mapping.delivery,
        };
        identity.spec_sha256 = sha;
        objects.insert(
            format!("/apis/storage.k8s.io/v1/storageclasses/{}", identity.name),
            value,
        );
    }
    let mut value = expected_snapshot_class_spec(&contract.mapping);
    value["metadata"] =
        json!({"name":contract.mapping.snapshot.name,"uid":contract.mapping.snapshot.uid});
    contract.mapping.snapshot.spec_sha256 = snapshot_class_spec_sha256(&value, &contract.mapping)?;
    objects.insert(
        format!(
            "/apis/snapshot.storage.k8s.io/v1/volumesnapshotclasses/{}",
            contract.mapping.snapshot.name
        ),
        value,
    );
    contract.validate()?;
    let mappings = json!([contract.mapping]);
    let report = json!({"protocol":1,"environment":"DISPOSABLE_TEST_NOT_PRODUCTION_CERTIFICATION",
        "bindings":{"profile_id":profile,"cluster_epoch":epoch,"backup_certification_sha256":backup_cert,
            "storage_mappings":mappings,"workspace_kms_key_id":"restore-compute-key",
            "account_id":cloud.account_id,"region":cloud.region,"deployment":cloud.deployment,
            "versions_lock_sha256":hex::encode(Sha256::digest(include_bytes!("../deploy/cluster/versions.lock.json"))),
            "infrastructure_sha256":hex::encode(Sha256::digest(b"DISPOSABLE_TEST_NOT_PRODUCTION_TERRAFORM"))}});
    Ok((mappings, report, objects))
}

async fn trial(
    tx: &mut Transaction<'_, Postgres>,
    profile: Uuid,
    mappings: &Value,
    report: &Value,
    accepted: bool,
) -> anyhow::Result<()> {
    sqlx::query("SAVEPOINT storage_cert_trial")
        .execute(&mut **tx)
        .await?;
    let result=sqlx::query("INSERT INTO restore_profile_certifications(profile_id,cluster_epoch,backup_certification_sha256,report_sha256,report,storage_mappings,approval_reference,reviewed_at,certified_until) SELECT id,cluster_epoch,certification_sha256,$2,$3,$4,'DISPOSABLE_TEST_NOT_PRODUCTION',clock_timestamp(),certified_until FROM backup_profiles WHERE id=$1")
        .bind(profile).bind(digest(report)?).bind(report).bind(mappings).execute(&mut **tx).await;
    match (accepted, result) {
        (true, Ok(value)) => ensure!(
            value.rows_affected() == 1,
            "actual owner certification insert required"
        ),
        (false, Err(error)) => ensure!(
            error.as_database_error().and_then(|e| e.code()).as_deref() == Some("23514"),
            "certification must fail through its actual CHECK/trigger: {error}"
        ),
        (expected, actual) => {
            anyhow::bail!("certificate constraint expected accepted={expected}, got {actual:?}")
        }
    }
    sqlx::query("ROLLBACK TO SAVEPOINT storage_cert_trial")
        .execute(&mut **tx)
        .await?;
    sqlx::query("RELEASE SAVEPOINT storage_cert_trial")
        .execute(&mut **tx)
        .await?;
    Ok(())
}
pub(super) async fn certification_inputs(
    tx: &mut Transaction<'_, Postgres>,
    profile: Uuid,
    mappings: &Value,
    report: &Value,
) -> anyhow::Result<()> {
    trial(tx, profile, mappings, report, true).await?;
    let mut alias = mappings[0].clone();
    alias["normal"]["name"] = json!("integration-storage-alias");
    alias["normal"]["uid"] = json!(Uuid::new_v4());
    let aliases = json!([mappings[0], alias]);
    let mut alias_report = report.clone();
    alias_report["bindings"]["storage_mappings"] = aliases.clone();
    trial(tx, profile, &aliases, &alias_report, true).await?;
    for length in [256, 257] {
        let key = "k".repeat(length);
        let mut changed = mappings.clone();
        changed[0]["workspace_kms_key_id"] = json!(key);
        let mut changed_report = report.clone();
        changed_report["bindings"]["storage_mappings"] = changed.clone();
        changed_report["bindings"]["workspace_kms_key_id"] = json!(key);
        trial(tx, profile, &changed, &changed_report, length == 256)
            .await
            .with_context(|| format!("compute KMS length {length}"))?;
    }
    for case in 0..18 {
        let mut changed = mappings.clone();
        match case {
            0 => changed = Value::Null,
            1 => changed = json!([]),
            2 => changed = json!([mappings[0], mappings[0]]),
            3 => changed[0]["raw"]["uid"] = json!(Uuid::nil()),
            4 => changed[0]["delivery"]["name"] = changed[0]["raw"]["name"].clone(),
            5 => changed[0]["raw"]["spec_sha256"] = json!("missing"),
            6 => changed[0]["normal"] = Value::Null,
            7 => changed[0]["topology"]["zone_ids"] = json!(["cn-hangzhou-a"]),
            8 => {
                changed[0]["topology"]["zone_ids"] =
                    json!(["cn-hangzhou-a", "cn-hangzhou-a", "cn-hangzhou-b"])
            }
            9 => {
                changed[0]["topology"]["zone_ids"] =
                    json!(["cn-hangzhou-c", "cn-hangzhou-b", "cn-hangzhou-a"])
            }
            10 => changed[0]["topology"]["key"] = json!("topology.kubernetes.io/zone"),
            11 => changed[0]["unreviewed"] = json!(true),
            12 => changed[0]["raw"]["unreviewed"] = json!(true),
            13 => changed[0]["workspace_kms_key_id"] = json!(1),
            14 => changed[0]["deployment"] = json!(""),
            15 => changed[0]["account_id"] = json!(true),
            16 => changed = json!(vec![mappings[0].clone(); 33]),
            _ => changed[0]["topology"]["zone_ids"][0] = json!("cn-another-a"),
        }
        let mut changed_report = report.clone();
        changed_report["bindings"]["storage_mappings"] = changed.clone();
        trial(tx, profile, &changed, &changed_report, false)
            .await
            .with_context(|| format!("mapping case {case}"))?;
    }
    for case in 0..7 {
        let mut changed = report.clone();
        match case {
            0 => changed["protocol"] = json!(true),
            1 => changed["protocol"] = json!(1.0),
            2 => changed["bindings"]["storage_mappings"] = json!([]),
            3 => changed["bindings"]["profile_id"] = json!(Uuid::new_v4()),
            4 => changed["bindings"]["workspace_kms_key_id"] = json!("other-key"),
            5 => changed["bindings"]["deployment"] = json!("other-deployment"),
            _ => changed["bindings"]["unreviewed"] = json!(true),
        }
        trial(tx, profile, mappings, &changed, false)
            .await
            .with_context(|| format!("report case {case}"))?;
    }
    sqlx::query("SAVEPOINT expired_storage_certificate")
        .execute(&mut **tx)
        .await?;
    sqlx::query("INSERT INTO restore_profile_certifications(profile_id,cluster_epoch,backup_certification_sha256,report_sha256,report,storage_mappings,approval_reference,reviewed_at,certified_until) SELECT id,cluster_epoch,certification_sha256,$2,$3,$4,'DISPOSABLE_TEST_NOT_PRODUCTION_EXPIRED',clock_timestamp()-interval '2 days',clock_timestamp()-interval '1 day' FROM backup_profiles WHERE id=$1")
        .bind(profile).bind(digest(report)?).bind(report).bind(mappings).execute(&mut **tx).await?;
    let current: bool = sqlx::query_scalar("SELECT sandbox_restore_profile_current($1,(SELECT cluster_epoch FROM backup_profiles WHERE id=$1),clock_timestamp()+interval '6 hours')")
        .bind(profile).fetch_one(&mut **tx).await?;
    assert!(
        !current,
        "a legal historical certificate cannot authorize a fresh restore"
    );
    sqlx::query("ROLLBACK TO SAVEPOINT expired_storage_certificate")
        .execute(&mut **tx)
        .await?;
    sqlx::query("RELEASE SAVEPOINT expired_storage_certificate")
        .execute(&mut **tx)
        .await?;
    Ok(())
}
async fn owner_tx(owner: &PgPool, tenant: Uuid) -> anyhow::Result<Transaction<'_, Postgres>> {
    let mut tx = owner.begin().await?;
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}
async fn reject_update(
    owner: &PgPool,
    tenant: Uuid,
    query: &str,
    resource: Uuid,
    value: &Value,
) -> anyhow::Result<()> {
    let mut tx = owner_tx(owner, tenant).await?;
    let error = sqlx::query(query)
        .bind(tenant)
        .bind(resource)
        .bind(value)
        .execute(&mut *tx)
        .await
        .err()
        .context("immutable update unexpectedly accepted")?;
    ensure!(
        error.as_database_error().and_then(|e| e.code()).as_deref() == Some("23514"),
        "actual identity guard must reject update: {error}"
    );
    tx.rollback().await?;
    Ok(())
}
pub(super) async fn accepted(
    owner: &PgPool,
    databases: [&Database; 2],
    actor: &Actor,
    backup: Uuid,
    request: &CreateRestore,
    version: i64,
    accepted: &RestoreAccepted,
) -> anyhow::Result<()> {
    let app = databases[0];
    let restore = accepted.resource.id;
    let workspace = accepted.resource.workspace_id;
    let mut tx = owner_tx(owner, actor.tenant_id).await?;
    let (contract, workspace_class,normal,deadline):(Value,String,String,chrono::DateTime<Utc>)=sqlx::query_as("SELECT r.storage_contract,w.storage_class,p.storage_class,r.deadline FROM restores r JOIN workspaces w ON w.tenant_id=r.tenant_id AND w.id=r.workspace_id JOIN projects p ON p.tenant_id=r.tenant_id AND p.id=r.target_project_id WHERE r.tenant_id=$1 AND r.id=$2")
        .bind(actor.tenant_id).bind(restore).fetch_one(&mut *tx).await?;
    let typed = RestoreStorageContract::parse(&contract)?;
    assert_eq!(normal, typed.mapping.normal.name);
    assert_eq!(workspace_class, typed.mapping.delivery.name);
    assert_ne!(typed.mapping.raw.name, typed.mapping.delivery.name);
    let clone: String =
        sqlx::query_scalar("SELECT clone_storage_class FROM backup_profiles WHERE id=$1")
            .bind(request.profile_id)
            .fetch_one(&mut *tx)
            .await?;
    assert_ne!(
        clone, typed.mapping.raw.name,
        "restore raw purpose must not derive capture clone class"
    );
    tx.commit().await?;
    for case in 0..7 {
        let mut value = contract.clone();
        match case {
            0 => value["protocol"] = json!(true),
            1 => value["protocol"] = json!(1.0),
            2 => value["mapping"] = Value::Null,
            3 => value["unreviewed"] = json!(true),
            4 => value["report_sha256"] = json!("b".repeat(64)),
            5 => value["mapping"]["raw"]["uid"] = json!(Uuid::new_v4()),
            _ => value["mapping"]["normal"]["name"] = json!("unknown-normal"),
        }
        let mut tx = owner_tx(owner, actor.tenant_id).await?;
        let error=sqlx::query("INSERT INTO restores SELECT (jsonb_populate_record(NULL::restores,to_jsonb(r)||jsonb_build_object('storage_contract',$3::jsonb))).* FROM restores r WHERE tenant_id=$1 AND id=$2")
            .bind(actor.tenant_id).bind(restore).bind(&value).execute(&mut *tx).await.err().context("invalid contract INSERT unexpectedly accepted")?;
        ensure!(
            error.as_database_error().and_then(|e| e.code()).as_deref() == Some("23514"),
            "INSERT contract case {case} must fail before duplicate identity: {error}"
        );
        tx.rollback().await?;
    }
    let mut changed = contract.clone();
    changed["report_sha256"] = json!("b".repeat(64));
    reject_update(
        owner,
        actor.tenant_id,
        "UPDATE restores SET storage_contract=$3 WHERE tenant_id=$1 AND id=$2",
        restore,
        &changed,
    )
    .await?;
    let mut tx = owner_tx(owner, actor.tenant_id).await?;
    let error = sqlx::query(
        "UPDATE workspaces SET storage_class='unreviewed-delivery' WHERE tenant_id=$1 AND id=$2",
    )
    .bind(actor.tenant_id)
    .bind(workspace)
    .execute(&mut *tx)
    .await
    .err()
    .context("PENDING delivery purpose changed")?;
    ensure!(error.as_database_error().and_then(|e| e.code()).as_deref() == Some("23514"));
    tx.rollback().await?;
    for database in databases {
        let mut tx = database.begin(actor.tenant_id).await.map_err(api_failure)?;
        let error=sqlx::query("INSERT INTO restore_profile_certifications SELECT * FROM restore_profile_certifications WHERE profile_id=$1")
            .bind(request.profile_id).execute(&mut *tx).await.err().context("runtime role wrote certification")?;
        ensure!(error.as_database_error().and_then(|e| e.code()).as_deref() == Some("42501"));
        tx.rollback().await?;
    }
    let mut tx = app.begin(actor.tenant_id).await.map_err(api_failure)?;
    let selected: Option<Value> =
        sqlx::query_scalar("SELECT sandbox_lock_restore_configuration($1,$2,$3,$4,$5)")
            .bind(actor.tenant_id)
            .bind(request.target_project_id)
            .bind(request.profile_id)
            .bind(typed.cluster_epoch)
            .bind(deadline)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(selected.as_ref(), Some(&contract));
    for (epoch, horizon) in [
        (Uuid::new_v4(), deadline),
        (typed.cluster_epoch, Utc::now() + chrono::Duration::days(31)),
    ] {
        let absent: Option<Value> =
            sqlx::query_scalar("SELECT sandbox_lock_restore_configuration($1,$2,$3,$4,$5)")
                .bind(actor.tenant_id)
                .bind(request.target_project_id)
                .bind(request.profile_id)
                .bind(epoch)
                .bind(horizon)
                .fetch_one(&mut *tx)
                .await?;
        assert!(
            absent.is_none(),
            "wrong epoch or insufficient approval horizon cannot select a mapping"
        );
    }
    let foreign: Option<Value> =
        sqlx::query_scalar("SELECT sandbox_lock_restore_configuration($1,$2,$3,$4,$5)")
            .bind(Uuid::new_v4())
            .bind(request.target_project_id)
            .bind(request.profile_id)
            .bind(typed.cluster_epoch)
            .bind(deadline)
            .fetch_one(&mut *tx)
            .await?;
    assert!(foreign.is_none());
    tx.commit().await?;
    let mut tx = owner_tx(owner, actor.tenant_id).await?;
    sqlx::query("UPDATE projects SET storage_class='unknown-normal' WHERE tenant_id=$1 AND id=$2")
        .bind(actor.tenant_id)
        .bind(request.target_project_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let mut tx = databases[1]
        .begin(actor.tenant_id)
        .await
        .map_err(api_failure)?;
    let current: bool = sqlx::query_scalar("SELECT sandbox_restore_authorized($1,$2,false)")
        .bind(actor.tenant_id)
        .bind(restore)
        .fetch_one(&mut *tx)
        .await?;
    assert!(
        !current,
        "project normal drift must invalidate fresh storage authority"
    );
    tx.commit().await?;
    let replay = app
        .create_restore(actor, backup, request, "same-restore", version)
        .await
        .map_err(api_failure)?;
    assert_eq!(
        replay.body.resource.id, restore,
        "replay must not remap accepted purpose"
    );
    let error = app
        .create_restore(actor, backup, request, "unmapped-normal", version)
        .await
        .err()
        .context("unmapped normal was accepted")?;
    ensure!(
        error.code == "RESTORE_BLOCKED",
        "new accept must fail because mapping is absent"
    );
    let mut tx = owner_tx(owner, actor.tenant_id).await?;
    sqlx::query("UPDATE projects SET storage_class=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(actor.tenant_id)
        .bind(request.target_project_id)
        .bind(&typed.mapping.normal.name)
        .execute(&mut *tx)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM restores WHERE tenant_id=$1")
        .bind(actor.tenant_id)
        .fetch_one(&mut *tx)
        .await?;
    assert_eq!(
        count, 1,
        "blocked acceptance must not leak target/hold/quota"
    );
    tx.commit().await?;
    Ok(())
}

pub(super) async fn admission_role(
    database: &Database,
    actor: &Actor,
    contract: &RestoreStorageContract,
) -> anyhow::Result<()> {
    let mut tx = database.begin(actor.tenant_id).await.map_err(api_failure)?;
    let certified: bool =
        sqlx::query_scalar("SELECT sandbox_restore_storage_contract_certified($1,$2,$3)")
            .bind(contract.profile_id)
            .bind(contract.cluster_epoch)
            .bind(serde_json::to_value(contract)?)
            .fetch_one(&mut *tx)
            .await?;
    assert!(
        certified,
        "narrow admission matcher must work without certification SELECT permission"
    );
    tx.commit().await?;
    for query in [
        "SELECT * FROM restore_profile_certifications WHERE profile_id=$1",
        "INSERT INTO restore_profile_certifications SELECT * FROM restore_profile_certifications WHERE profile_id=$1",
    ] {
        let mut tx = database.begin(actor.tenant_id).await.map_err(api_failure)?;
        let error = sqlx::query(query)
            .bind(contract.profile_id)
            .execute(&mut *tx)
            .await
            .err()
            .context("admission accessed owner-only certification table")?;
        ensure!(error.as_database_error().and_then(|e| e.code()).as_deref() == Some("42501"));
        tx.rollback().await?;
    }
    Ok(())
}
pub(super) async fn published(
    owner: &PgPool,
    app: &Database,
    tenant: Uuid,
    restore: Uuid,
    workspace: Uuid,
) -> anyhow::Result<()> {
    let mut tx = owner_tx(owner, tenant).await?;
    let error = sqlx::query(
        "UPDATE workspaces SET storage_class='unreviewed-published' WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant)
    .bind(workspace)
    .execute(&mut *tx)
    .await
    .err()
    .context("AVAILABLE storage purpose changed")?;
    ensure!(error.as_database_error().and_then(|e| e.code()).as_deref() == Some("23514"));
    tx.rollback().await?;
    let mut tx = owner_tx(owner, tenant).await?;
    sqlx::query("UPDATE backup_profiles SET enabled=false WHERE id=(SELECT profile_id FROM restores WHERE tenant_id=$1 AND id=$2)")
        .bind(tenant).bind(restore).execute(&mut *tx).await?;
    tx.commit().await?;
    let mut tx = app.begin(tenant).await.map_err(api_failure)?;
    let binding: crate::workspace_restore::WorkspaceRestoreBinding =
        sqlx::query_as("SELECT * FROM sandbox_workspace_restore_binding($1,$2)")
            .bind(tenant)
            .bind(workspace)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(
        binding.restore_id, restore,
        "published provenance survives writer profile revocation"
    );
    assert_eq!(
        binding.delivery_storage_class,
        "integration-restore-delivery"
    );
    tx.commit().await?;
    Ok(())
}
