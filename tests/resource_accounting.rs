//! Real ordinary-role PostgreSQL transactions for the launch request and quota
//! history contract. No physical VM, readiness or capacity certification is made.
#[allow(dead_code)]
mod support;

use anyhow::{Context, ensure};
use sandbox_platform::{
    db::insert_operation,
    model::{Instance, RenewRequest},
};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};
use support::{Fixture, api_failure, require_pg_error};
use uuid::Uuid;

const LEDGERS: [&str; 3] = [
    "launch_resource_contracts",
    "quota_resource_receipts",
    "launch_quota_bindings",
];

async fn snapshot(fixture: &Fixture) -> anyhow::Result<Value> {
    let mut tx = fixture
        .database
        .begin(fixture.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    let result = sqlx::query_scalar(
        "SELECT jsonb_build_object( \
         'contracts',COALESCE((SELECT jsonb_agg(to_jsonb(c) ORDER BY c.id) FROM launch_resource_contracts c),'[]'::jsonb), \
         'receipts',COALESCE((SELECT jsonb_agg(to_jsonb(r) ORDER BY r.id) FROM quota_resource_receipts r),'[]'::jsonb), \
         'bindings',COALESCE((SELECT jsonb_agg(to_jsonb(b) ORDER BY b.reservation_id) FROM launch_quota_bindings b),'[]'::jsonb), \
         'reservations',COALESCE((SELECT jsonb_agg(to_jsonb(r) ORDER BY r.id) FROM quota_reservations r),'[]'::jsonb), \
         'accounts',COALESCE((SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id) FROM quota_accounts a),'[]'::jsonb))",
    )
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(result)
}

async fn launch_identity(fixture: &Fixture, instance_id: Uuid) -> anyhow::Result<(Uuid, Uuid)> {
    let mut tx = fixture
        .database
        .begin(fixture.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    let identity = sqlx::query_as(
        "SELECT launch_id,cluster_epoch FROM instances WHERE tenant_id=$1 AND id=$2",
    )
    .bind(fixture.actor.tenant_id)
    .bind(instance_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(identity)
}

#[tokio::test]
#[ignore = "Requires normally migrated disposable TLS PostgreSQL and exact runtime app credentials"]
async fn accepted_create_freezes_launch_request_and_scoped_pending_receipts_once()
-> anyhow::Result<()> {
    let _scope = support::serial().await;
    let fixture = Fixture::new(10).await?;
    let created = fixture
        .create("resource-create")
        .await
        .map_err(api_failure)?;
    let instance = &created.body.resource;
    let mut tx = fixture
        .database
        .begin(fixture.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    let contract: Value = sqlx::query_scalar(
        "SELECT to_jsonb(c) FROM launch_resource_contracts c WHERE instance_id=$1",
    )
    .bind(instance.id)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(contract["tenant_id"] == fixture.actor.tenant_id.to_string());
    ensure!(contract["project_id"] == instance.project_id.to_string());
    ensure!(contract["workspace_id"] == instance.workspace_id.to_string());
    ensure!(contract["generation"] == instance.runtime_generation);
    let (launch_id, cluster_epoch): (Uuid, Uuid) = sqlx::query_as(
        "SELECT launch_id,cluster_epoch FROM instances WHERE tenant_id=$1 AND id=$2",
    )
    .bind(fixture.actor.tenant_id)
    .bind(instance.id)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(contract["launch_id"] == launch_id.to_string());
    ensure!(contract["cluster_epoch"] == cluster_epoch.to_string());
    ensure!(contract["operation_id"] == created.body.operation.id.to_string());
    ensure!(contract["cpu_millis"] == 1000 && contract["memory_mib"] == 2048);
    ensure!(contract["source"] == "REQUESTED_COMPUTE_QUOTA");
    let (count, pending, scopes, captured, matching_versions): (i64, i64, i64, i64, i64) =
        sqlx::query_as(
            "SELECT count(*),count(*) FILTER(WHERE r.status='PENDING' AND r.previous_status IS NULL), \
             count(*) FILTER(WHERE (r.account_scope='TENANT' AND r.account_project_id IS NULL) \
                 OR(r.account_scope='PROJECT' AND r.account_project_id=$2)), \
             count(*) FILTER(WHERE r.history_start='CAPTURED'), \
             count(*) FILTER(WHERE r.account_version=q.version AND r.limit_value=q.limit_value \
                 AND r.pending_value=q.pending AND r.allocated_value=q.allocated) \
             FROM quota_resource_receipts r JOIN quota_accounts q \
                 ON(q.tenant_id,q.id)=(r.tenant_id,r.quota_account_id) \
             WHERE r.operation_id=$1",
        )
        .bind(created.body.operation.id)
        .bind(instance.project_id)
        .fetch_one(&mut *tx)
        .await?;
    ensure!((count, pending, scopes, captured, matching_versions) == (8, 8, 8, 8, 8));
    let dimensions: Vec<(String, String, String, i64, i64)> = sqlx::query_as(
        "SELECT purpose,dimension,unit,amount,count(*) FROM quota_resource_receipts \
         WHERE operation_id=$1 GROUP BY purpose,dimension,unit,amount ORDER BY dimension",
    )
    .bind(created.body.operation.id)
    .fetch_all(&mut *tx)
    .await?;
    ensure!(
        dimensions
            == vec![
                (
                    "ORDINARY_COMPUTE".into(),
                    "CPU_MILLIS".into(),
                    "MILLICORES".into(),
                    1000,
                    2
                ),
                (
                    "INSTANCE_LIFETIME".into(),
                    "INSTANCES".into(),
                    "COUNT".into(),
                    1,
                    2
                ),
                (
                    "ORDINARY_COMPUTE".into(),
                    "MEMORY_MIB".into(),
                    "MIB".into(),
                    2048,
                    2
                ),
                (
                    "WORKSPACE_STORAGE".into(),
                    "WORKSPACE_GIB".into(),
                    "GIB".into(),
                    20,
                    2
                ),
            ]
    );
    let bindings: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM launch_quota_bindings b \
         JOIN launch_resource_contracts c ON(c.tenant_id,c.id)=(b.tenant_id,b.contract_id) \
         JOIN quota_resource_receipts r ON(r.tenant_id,r.reservation_id)=(b.tenant_id,b.reservation_id) \
         WHERE c.instance_id=$1 AND r.purpose='ORDINARY_COMPUTE' AND r.status='PENDING' \
             AND r.operation_id=c.operation_id AND r.resource_id=c.instance_id",
    )
    .bind(instance.id)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(bindings == 4);
    tx.commit().await?;
    let before_replay = snapshot(&fixture).await?;
    let replay = fixture
        .create("resource-create")
        .await
        .map_err(api_failure)?;
    ensure!(serde_json::to_value(&replay.body)? == serde_json::to_value(&created.body)?);
    ensure!(snapshot(&fixture).await? == before_replay);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires normally migrated disposable TLS PostgreSQL and exact runtime app credentials"]
async fn renewal_keeps_original_launch_contract_and_does_not_manufacture_quota_history()
-> anyhow::Result<()> {
    let _scope = support::serial().await;
    let fixture = Fixture::new(10).await?;
    let created = fixture
        .create("resource-renew-create")
        .await
        .map_err(api_failure)?;
    let instance = &created.body.resource;
    let before = snapshot(&fixture).await?;
    let launch_before = launch_identity(&fixture, instance.id).await?;
    let request = RenewRequest {
        expires_at: instance.compute_lease_expires_at + chrono::Duration::seconds(300),
    };
    let renewed = fixture
        .database
        .renew_instance(
            &fixture.actor,
            instance.id,
            &request,
            "resource-renew",
            instance.spec_version,
            86400,
        )
        .await
        .map_err(api_failure)?;
    ensure!(renewed.body.resource.compute_lease_version == instance.compute_lease_version + 1);
    ensure!(launch_identity(&fixture, instance.id).await? == launch_before);
    ensure!(renewed.body.resource.runtime_generation == instance.runtime_generation);
    ensure!(snapshot(&fixture).await? == before);
    let replay = fixture
        .database
        .renew_instance(
            &fixture.actor,
            instance.id,
            &request,
            "resource-renew",
            instance.spec_version,
            86400,
        )
        .await
        .map_err(api_failure)?;
    ensure!(serde_json::to_value(replay.body)? == serde_json::to_value(renewed.body)?);
    ensure!(snapshot(&fixture).await? == before);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires normally migrated disposable TLS PostgreSQL and exact runtime app credentials"]
async fn runtime_can_only_read_its_tenant_ledgers_and_cannot_access_legacy_baseline()
-> anyhow::Result<()> {
    let _scope = support::serial().await;
    let a = Fixture::new(10).await?;
    let b = Fixture::new(10).await?;
    a.create("resource-rls-a").await.map_err(api_failure)?;
    b.create("resource-rls-b").await.map_err(api_failure)?;
    let forced: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace \
         AND relname=ANY($1) AND relrowsecurity AND relforcerowsecurity",
    )
    .bind(LEDGERS.to_vec())
    .fetch_one(&a.database.pool)
    .await?;
    ensure!(forced == 3);
    for (table, expected) in LEDGERS.into_iter().zip([1, 8, 4]) {
        // The identifier comes from the fixed source list above, never an API input.
        let no_context: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(&a.database.pool)
            .await?;
        ensure!(no_context == 0);
        let mut tx = a
            .database
            .begin(a.actor.tenant_id)
            .await
            .map_err(api_failure)?;
        let own: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(&mut *tx)
            .await?;
        let foreign: i64 =
            sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE tenant_id=$1"))
                .bind(b.actor.tenant_id)
                .fetch_one(&mut *tx)
                .await?;
        ensure!(own == expected && foreign == 0);
        tx.commit().await?;
        for mutation in [
            format!("INSERT INTO {table} SELECT * FROM {table} LIMIT 1"),
            format!("UPDATE {table} SET tenant_id=tenant_id"),
            format!("DELETE FROM {table}"),
            format!("TRUNCATE {table}"),
        ] {
            let mut tx = a
                .database
                .begin(a.actor.tenant_id)
                .await
                .map_err(api_failure)?;
            require_pg_error(sqlx::query(&mutation).execute(&mut *tx).await, "42501")?;
            tx.rollback().await?;
        }
    }
    let mut tx = a
        .database
        .begin(a.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    require_pg_error(
        sqlx::query("SELECT * FROM quota_resource_legacy_baseline")
            .fetch_all(&mut *tx)
            .await,
        "42501",
    )?;
    tx.rollback().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires normally migrated disposable TLS PostgreSQL and exact runtime app credentials"]
async fn reservation_origin_cannot_drift_and_terminal_states_cannot_regress() -> anyhow::Result<()>
{
    let _scope = support::serial().await;
    let fixture = Fixture::new(10).await?;
    fixture
        .create("resource-identity")
        .await
        .map_err(api_failure)?;
    let before = snapshot(&fixture).await?;
    let mut tx = fixture
        .database
        .begin(fixture.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    let reservation: Uuid = sqlx::query_scalar(
        "SELECT reservation_id FROM quota_resource_receipts WHERE purpose='ORDINARY_COMPUTE' ORDER BY reservation_id LIMIT 1",
    ).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    for assignment in [
        "amount=amount+1",
        "operation_id=gen_random_uuid()",
        "resource_id=gen_random_uuid()",
        "quota_account_id=gen_random_uuid()",
        "created_at=created_at-interval '1 second'",
        "released_at=clock_timestamp()",
    ] {
        let mut tx = fixture
            .database
            .begin(fixture.actor.tenant_id)
            .await
            .map_err(api_failure)?;
        let statement = format!("UPDATE quota_reservations SET {assignment} WHERE id=$1");
        require_pg_error(
            sqlx::query(&statement)
                .bind(reservation)
                .execute(&mut *tx)
                .await,
            "23514",
        )?;
        tx.rollback().await?;
        ensure!(snapshot(&fixture).await? == before);
    }
    // These deliberately malformed transactions never commit. Moving counters
    // here only reaches the regression guard; it is not a readiness/release proof.
    for (advance, regress) in [
        ("ALLOCATED", "PENDING"),
        ("RELEASED", "PENDING"),
        ("RELEASED", "ALLOCATED"),
    ] {
        let mut tx = fixture
            .database
            .begin(fixture.actor.tenant_id)
            .await
            .map_err(api_failure)?;
        sqlx::query("UPDATE quota_accounts q SET pending=q.pending-r.amount,allocated=q.allocated+CASE WHEN $2='ALLOCATED' THEN r.amount ELSE 0 END,version=q.version+1,updated_at=clock_timestamp() FROM quota_reservations r WHERE r.id=$1 AND q.id=r.quota_account_id AND q.tenant_id=r.tenant_id")
            .bind(reservation).bind(advance).execute(&mut *tx).await?;
        sqlx::query("UPDATE quota_reservations SET status=$2,released_at=CASE WHEN $2='RELEASED' THEN clock_timestamp() ELSE NULL END WHERE id=$1")
            .bind(reservation).bind(advance).execute(&mut *tx).await?;
        require_pg_error(
            sqlx::query("UPDATE quota_reservations SET status=$2,released_at=NULL WHERE id=$1")
                .bind(reservation)
                .bind(regress)
                .execute(&mut *tx)
                .await,
            "23514",
        )?;
        tx.rollback().await?;
        ensure!(snapshot(&fixture).await? == before);
    }
    Ok(())
}

/// A malformed ordinary-role CREATE transaction exercises the actual deferred
/// quota constraint. It uses real production tables/triggers, no owner writes,
/// disabled guard, synthetic proof or special session capability.
async fn malformed_create(
    fixture: &Fixture,
    tx: &mut Transaction<'_, Postgres>,
    source: &Instance,
    omit_project_memory: bool,
    conflicting_cpu: bool,
) -> anyhow::Result<Uuid> {
    let instance = Uuid::new_v4();
    let workspace = Uuid::new_v4();
    let operation = Uuid::new_v4();
    sqlx::query("INSERT INTO workspaces(id,tenant_id,project_id,size_gib,storage_class,namespace,pvc_name) SELECT $1,tenant_id,project_id,size_gib,storage_class,namespace,$2 FROM workspaces WHERE id=$3")
        .bind(workspace).bind(format!("ws-{workspace}")).bind(source.workspace_id).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO instances(id,tenant_id,project_id,name,template_version_id,security_policy_version_id,workspace_id,cpu_millis,memory_mib,desired_state,cluster_epoch,launch_id,namespace,pod_name,active_operation_id,compute_lease_id,compute_lease_started_at,compute_lease_expires_at) SELECT $1,tenant_id,project_id,'malformed-resource-create',template_version_id,security_policy_version_id,$2,cpu_millis,memory_mib,'RUNNING',cluster_epoch,$3,namespace,$4,$5,$6,clock_timestamp(),clock_timestamp()+interval '5 minutes' FROM instances WHERE id=$7")
        .bind(instance).bind(workspace).bind(Uuid::new_v4()).bind(format!("sbx-ws-{workspace}")).bind(operation).bind(Uuid::new_v4()).bind(source.id).execute(&mut **tx).await?;
    insert_operation(
        tx,
        &fixture.actor,
        operation,
        source.project_id,
        instance,
        workspace,
        "CREATE",
        &serde_json::to_value(&fixture.request)?,
        source.compute_lease_expires_at,
    )
    .await
    .map_err(api_failure)?;
    let accounts = sqlx::query("SELECT id,project_id,dimension FROM quota_accounts WHERE tenant_id=$1 AND (project_id=$2 OR project_id IS NULL) AND dimension IN('CPU_MILLIS','MEMORY_MIB') ORDER BY id FOR UPDATE")
        .bind(fixture.actor.tenant_id).bind(source.project_id).fetch_all(&mut **tx).await?;
    ensure!(accounts.len() == 4);
    for account in accounts {
        let id: Uuid = account.try_get("id")?;
        let project: Option<Uuid> = account.try_get("project_id")?;
        let dimension: String = account.try_get("dimension")?;
        if omit_project_memory && dimension == "MEMORY_MIB" && project.is_some() {
            continue;
        }
        let amount = if dimension == "CPU_MILLIS" {
            source.cpu_millis + i64::from(conflicting_cpu)
        } else {
            source.memory_mib
        };
        sqlx::query("UPDATE quota_accounts SET pending=pending+$2,version=version+1,updated_at=clock_timestamp() WHERE id=$1")
            .bind(id).bind(amount).execute(&mut **tx).await?;
        sqlx::query("INSERT INTO quota_reservations(tenant_id,project_id,quota_account_id,operation_id,resource_id,amount) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(fixture.actor.tenant_id).bind(source.project_id).bind(id).bind(operation).bind(instance).bind(amount).execute(&mut **tx).await?;
    }
    Ok(instance)
}

#[tokio::test]
#[ignore = "Requires normally migrated disposable TLS PostgreSQL and exact runtime app credentials"]
async fn incomplete_scope_or_conflicting_amount_rejects_commit_and_rolls_back_every_fact()
-> anyhow::Result<()> {
    let _scope = support::serial().await;
    let fixture = Fixture::new(10).await?;
    let original = fixture
        .create("resource-valid-base")
        .await
        .map_err(api_failure)?;
    let before = snapshot(&fixture).await?;
    let counts_before = (
        fixture.count("instances").await?,
        fixture.count("workspaces").await?,
        fixture.count("operations").await?,
    );
    for (omit_scope, conflict) in [(true, false), (false, true)] {
        let mut tx = fixture
            .database
            .begin(fixture.actor.tenant_id)
            .await
            .map_err(api_failure)?;
        let new_instance = malformed_create(
            &fixture,
            &mut tx,
            &original.body.resource,
            omit_scope,
            conflict,
        )
        .await?;
        let tentative: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM launch_resource_contracts WHERE instance_id=$1",
        )
        .bind(new_instance)
        .fetch_one(&mut *tx)
        .await?;
        ensure!(
            tentative == 1,
            "actual launch capture must occur before deferred validation"
        );
        require_pg_error(tx.commit().await, "23514")
            .context("malformed ordinary compute transaction must fail at COMMIT")?;
        ensure!(snapshot(&fixture).await? == before);
        ensure!(
            (
                fixture.count("instances").await?,
                fixture.count("workspaces").await?,
                fixture.count("operations").await?
            ) == counts_before,
            "deferred failure must roll back resources and originating operation"
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires normally migrated disposable TLS PostgreSQL and exact runtime app credentials"]
async fn compute_quota_cannot_be_released_without_original_launch_termination_proof()
-> anyhow::Result<()> {
    let _scope = support::serial().await;
    let fixture = Fixture::new(10).await?;
    fixture
        .create("resource-unproven-release")
        .await
        .map_err(api_failure)?;
    let before = snapshot(&fixture).await?;
    let mut tx = fixture
        .database
        .begin(fixture.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    let reservations: Vec<(Uuid, Uuid, i64)> = sqlx::query_as(
        "SELECT reservation_id,quota_account_id,amount FROM quota_resource_receipts \
         WHERE purpose='ORDINARY_COMPUTE' AND status='PENDING' ORDER BY quota_account_id",
    )
    .fetch_all(&mut *tx)
    .await?;
    ensure!(reservations.len() == 4);
    for (reservation, account, amount) in reservations {
        sqlx::query("UPDATE quota_accounts SET pending=pending-$2,version=version+1,updated_at=clock_timestamp() WHERE id=$1")
            .bind(account).bind(amount).execute(&mut *tx).await?;
        sqlx::query("UPDATE quota_reservations SET status='RELEASED',released_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1")
            .bind(reservation).execute(&mut *tx).await?;
    }
    let tentative_releases: i64 = sqlx::query_scalar("SELECT count(*) FROM quota_resource_receipts WHERE purpose='ORDINARY_COMPUTE' AND status='RELEASED'")
        .fetch_one(&mut *tx).await?;
    ensure!(tentative_releases == 4);
    require_pg_error(tx.commit().await, "23514")
        .context("balanced counters cannot stand in for original-launch trusted cleanup")?;
    ensure!(snapshot(&fixture).await? == before);
    Ok(())
}

async fn assert_unproven_release_rejected_after_context_change(
    context: &str,
) -> anyhow::Result<()> {
    let fixture = Fixture::new(10).await?;
    fixture
        .create("resource-unproven-release-context")
        .await
        .map_err(api_failure)?;
    let before = snapshot(&fixture).await?;
    let mut tx = fixture
        .database
        .begin(fixture.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    let login: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(&mut *tx)
        .await?;
    ensure!(
        login == "sandbox_app",
        "the authenticated ordinary app must write the release"
    );
    let pending: i64 =
        sqlx::query_scalar("SELECT count(*) FROM quota_reservations WHERE status='PENDING'")
            .fetch_one(&mut *tx)
            .await?;
    ensure!(pending == 8);
    let reservations: Vec<(Uuid, Uuid, i64)> = sqlx::query_as(
        "SELECT reservation_id,quota_account_id,amount FROM quota_resource_receipts \
         WHERE purpose='ORDINARY_COMPUTE' AND status='PENDING' ORDER BY quota_account_id",
    )
    .fetch_all(&mut *tx)
    .await?;
    ensure!(reservations.len() == 4);
    for (reservation, account, amount) in reservations {
        sqlx::query("UPDATE quota_accounts SET pending=pending-$2,version=version+1,updated_at=clock_timestamp() WHERE id=$1")
            .bind(account).bind(amount).execute(&mut *tx).await?;
        sqlx::query("UPDATE quota_reservations SET status='RELEASED',released_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1")
            .bind(reservation).execute(&mut *tx).await?;
    }
    let tentative: i64 = sqlx::query_scalar("SELECT count(*) FROM quota_resource_receipts WHERE purpose='ORDINARY_COMPUTE' AND status='RELEASED'")
        .fetch_one(&mut *tx).await?;
    ensure!(
        tentative == 4,
        "the actual release receipts must exist before changing context"
    );
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(context)
        .execute(&mut *tx)
        .await?;
    require_pg_error(tx.commit().await, "23514")
        .context("caller context cannot hide the original launch release proof obligation")?;
    ensure!(
        snapshot(&fixture).await? == before,
        "the rejected release must roll back all eight pending reservations and every accounting fact"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires normally migrated disposable TLS PostgreSQL and exact runtime app credentials"]
async fn changing_tenant_before_commit_cannot_bypass_compute_release_proof() -> anyhow::Result<()> {
    let _scope = support::serial().await;
    let other = Fixture::new(10).await?;
    assert_unproven_release_rejected_after_context_change(&other.actor.tenant_id.to_string()).await
}

#[tokio::test]
#[ignore = "Requires normally migrated disposable TLS PostgreSQL and exact runtime app credentials"]
async fn clearing_tenant_before_commit_cannot_bypass_compute_release_proof() -> anyhow::Result<()> {
    let _scope = support::serial().await;
    assert_unproven_release_rejected_after_context_change("").await
}

#[tokio::test]
#[ignore = "Requires normally migrated disposable TLS PostgreSQL and exact runtime app credentials"]
async fn deferred_launch_binding_uses_each_row_tenant_and_restores_caller_context()
-> anyhow::Result<()> {
    let _scope = support::serial().await;
    let a = Fixture::new(10).await?;
    let b = Fixture::new(10).await?;
    let original_a = a.create("resource-context-a").await.map_err(api_failure)?;
    let original_b = b.create("resource-context-b").await.map_err(api_failure)?;
    let mut tx = a
        .database
        .begin(a.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    let created_a = malformed_create(&a, &mut tx, &original_a.body.resource, false, false).await?;
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(b.actor.tenant_id.to_string())
        .execute(&mut *tx)
        .await?;
    let created_b = malformed_create(&b, &mut tx, &original_b.body.resource, false, false).await?;
    // Flush the actual deferred triggers while their restored GUC is observable.
    // The transaction then commits both exact four-scope launch bindings.
    sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *tx)
        .await?;
    let restored: String = sqlx::query_scalar("SELECT current_setting('app.tenant_id')")
        .fetch_one(&mut *tx)
        .await?;
    ensure!(restored == b.actor.tenant_id.to_string());
    tx.commit().await?;
    for (fixture, instance) in [(&a, created_a), (&b, created_b)] {
        let mut tx = fixture
            .database
            .begin(fixture.actor.tenant_id)
            .await
            .map_err(api_failure)?;
        let bindings: i64 = sqlx::query_scalar("SELECT count(*) FROM launch_quota_bindings b JOIN launch_resource_contracts c ON(c.tenant_id,c.id)=(b.tenant_id,b.contract_id) WHERE c.instance_id=$1")
            .bind(instance).fetch_one(&mut *tx).await?;
        ensure!(
            bindings == 4,
            "each tenant launch must retain its exact four compute scopes"
        );
        tx.commit().await?;
    }
    Ok(())
}
