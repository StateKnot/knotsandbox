mod support;

use std::sync::Arc;

use anyhow::{Context, ensure};
use axum::http::StatusCode;
use futures_util::future::join_all;
use sandbox_platform::{
    db::{Actor, Database},
    domain::InstanceAction,
    engine::OperationEngine,
    model::{RenewRequest, StartRequest},
};
use sqlx::Connection;
use support::{Fixture, api_failure, require_api_error, require_pg_error};
use tokio::sync::Barrier;
use uuid::Uuid;

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn forced_rls_isolates_rows_and_transaction_context_does_not_leak() -> anyhow::Result<()> {
    let _test_scope = support::serial().await;
    let a = Fixture::new(10).await?;
    let b = Fixture::new(10).await?;
    a.create("tenant-a").await.map_err(api_failure)?;
    let foreign = b.create("tenant-b").await.map_err(api_failure)?;

    let tables = vec![
        "tenants",
        "projects",
        "grants",
        "template_versions",
        "security_policy_versions",
        "workspaces",
        "instances",
        "operations",
        "executions",
        "idempotency_keys",
        "quota_accounts",
        "quota_reservations",
        "audit_events",
        "audit_events_default",
        "domain_events",
        "external_resources",
    ];
    let protected: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace AND relname=ANY($1) AND relrowsecurity AND relforcerowsecurity")
        .bind(&tables)
        .fetch_one(&a.owner)
        .await?;
    assert_eq!(protected, tables.len() as i64);
    let unsafe_owner = Database {
        pool: a.owner.clone(),
    };
    assert!(unsafe_owner.verify_runtime_role().await.is_err());

    let mut connection = a.database.pool.acquire().await?;
    let no_context: i64 = sqlx::query_scalar("SELECT count(*) FROM instances")
        .fetch_one(&mut *connection)
        .await?;
    assert_eq!(no_context, 0);
    let mut tx = connection.begin().await?;
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(a.actor.tenant_id.to_string())
        .execute(&mut *tx)
        .await?;
    let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM instances")
        .fetch_one(&mut *tx)
        .await?;
    let foreign_visible: i64 = sqlx::query_scalar("SELECT count(*) FROM instances WHERE id=$1")
        .bind(foreign.body.resource.id)
        .fetch_one(&mut *tx)
        .await?;
    assert_eq!(visible, 1);
    assert_eq!(foreign_visible, 0);
    tx.commit().await?;
    let after_commit: i64 = sqlx::query_scalar("SELECT count(*) FROM instances")
        .fetch_one(&mut *connection)
        .await?;
    assert_eq!(
        after_commit, 0,
        "SET LOCAL must not survive on the pooled connection"
    );

    let owner_visible: i64 = sqlx::query_scalar("SELECT count(*) FROM instances")
        .fetch_one(&a.owner)
        .await?;
    assert_eq!(
        owner_visible, 0,
        "FORCE RLS must constrain the non-superuser owner"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn composite_foreign_key_rejects_another_tenants_project() -> anyhow::Result<()> {
    let _test_scope = support::serial().await;
    let a = Fixture::new(10).await?;
    let b = Fixture::new(10).await?;
    let id = Uuid::new_v4();
    let mut tx = a
        .database
        .begin(a.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    let result = sqlx::query("INSERT INTO workspaces(id,tenant_id,project_id,size_gib,storage_class,namespace,pvc_name) VALUES($1,$2,$3,20,'integration-storage','integration-cross-tenant',$4)")
        .bind(id).bind(a.actor.tenant_id).bind(b.request.project_id).bind(format!("ws-{id}"))
        .execute(&mut *tx).await;
    require_pg_error(result, "23503")?;
    tx.rollback().await?;
    assert_eq!(a.count("workspaces").await?, 0);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn audit_is_append_only_for_runtime_and_schema_owner() -> anyhow::Result<()> {
    let _test_scope = support::serial().await;
    let fixture = Fixture::new(10).await?;
    fixture.create("audit-create").await.map_err(api_failure)?;
    let mut runtime = fixture
        .database
        .begin(fixture.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    require_pg_error(
        sqlx::query("UPDATE audit_events SET outcome='FAILED'")
            .execute(&mut *runtime)
            .await,
        "42501",
    )?;
    runtime.rollback().await?;
    let mut runtime = fixture
        .database
        .begin(fixture.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    require_pg_error(
        sqlx::query("TRUNCATE audit_events")
            .execute(&mut *runtime)
            .await,
        "42501",
    )?;
    runtime.rollback().await?;
    for statement in [
        "UPDATE audit_events SET outcome='FAILED'",
        "DELETE FROM audit_events",
    ] {
        let mut owner = fixture.owner_transaction().await?;
        require_pg_error(sqlx::query(statement).execute(&mut *owner).await, "23514")?;
        owner.rollback().await?;
    }
    assert_eq!(fixture.count("audit_events").await?, 1);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn create_commits_one_complete_resource_operation_audit_and_quota_receipt()
-> anyhow::Result<()> {
    let _test_scope = support::serial().await;
    let fixture = Fixture::new(10).await?;
    let accepted = fixture
        .create("complete-create")
        .await
        .map_err(api_failure)?;
    assert_eq!(accepted.status, 202);
    assert_eq!(accepted.body.resource.desired_state, "RUNNING");
    assert_eq!(accepted.body.resource.observed_state, "PENDING");
    assert_eq!(
        accepted.body.resource.active_operation_id,
        Some(accepted.body.operation.id)
    );
    assert_eq!(
        accepted.body.operation.instance_id,
        Some(accepted.body.resource.id)
    );
    assert_eq!(accepted.body.operation.status, "QUEUED");
    for table in [
        "instances",
        "workspaces",
        "operations",
        "idempotency_keys",
        "audit_events",
        "domain_events",
    ] {
        assert_eq!(
            fixture.count(table).await?,
            1,
            "Missing atomic create row in {table}"
        );
    }
    assert_eq!(fixture.count("quota_reservations").await?, 8);
    let mut tx = fixture.owner_transaction().await?;
    let accounts: Vec<(String, i64, i64)> = sqlx::query_as("SELECT dimension,pending,allocated FROM quota_accounts WHERE tenant_id=$1 ORDER BY dimension,project_id NULLS FIRST")
        .bind(fixture.actor.tenant_id).fetch_all(&mut *tx).await?;
    assert_eq!(accounts.len(), 8);
    for (dimension, pending, allocated) in accounts {
        let expected = match dimension.as_str() {
            "INSTANCES" => 1,
            "CPU_MILLIS" => 1000,
            "MEMORY_MIB" => 2048,
            "WORKSPACE_GIB" => 20,
            _ => anyhow::bail!("Unexpected dimension"),
        };
        assert_eq!(pending, expected);
        assert_eq!(allocated, 0);
    }
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn concurrent_identical_idempotency_keys_replay_the_same_receipt() -> anyhow::Result<()> {
    let _test_scope = support::serial().await;
    let fixture = Fixture::new(100).await?;
    let barrier = Arc::new(Barrier::new(32));
    let attempts = (0..32).map(|_| {
        let database = fixture.database.clone();
        let mut actor = fixture.actor.clone();
        actor.request_id = Uuid::new_v4();
        let request = fixture.request.clone();
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            database
                .create_instance(&actor, &request, "same-key", 300, 86400)
                .await
        }
    });
    let mut receipt = None;
    for result in join_all(attempts).await {
        let accepted = result.map_err(api_failure)?;
        let current = serde_json::to_value(accepted.body)?;
        match &receipt {
            Some(expected) => assert_eq!(expected, &current),
            None => receipt = Some(current),
        }
    }
    for table in [
        "instances",
        "workspaces",
        "operations",
        "idempotency_keys",
        "audit_events",
        "domain_events",
    ] {
        assert_eq!(
            fixture.count(table).await?,
            1,
            "Concurrent replay duplicated {table}"
        );
    }
    assert_eq!(fixture.count("quota_reservations").await?, 8);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn reusing_an_idempotency_key_with_another_body_is_a_conflict() -> anyhow::Result<()> {
    let _test_scope = support::serial().await;
    let fixture = Fixture::new(10).await?;
    let original = fixture.create("body-conflict").await.map_err(api_failure)?;
    let mut changed = fixture.request.clone();
    changed.name = "different-instance".to_owned();
    let error = require_api_error(
        fixture
            .database
            .create_instance(&fixture.actor, &changed, "body-conflict", 300, 86400)
            .await,
    )?;
    assert_eq!(error.status, StatusCode::CONFLICT);
    assert_eq!(error.code, "IDEMPOTENCY_CONFLICT");
    assert_eq!(fixture.count("instances").await?, 1);
    let replay = fixture.create("body-conflict").await.map_err(api_failure)?;
    assert_eq!(replay.body.operation.id, original.body.operation.id);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn concurrent_distinct_requests_cannot_oversell_quota() -> anyhow::Result<()> {
    let _test_scope = support::serial().await;
    let fixture = Fixture::new(1).await?;
    let barrier = Arc::new(Barrier::new(16));
    let attempts = (0..16).map(|index| {
        let database = fixture.database.clone();
        let mut actor = fixture.actor.clone();
        actor.request_id = Uuid::new_v4();
        let mut request = fixture.request.clone();
        request.name = format!("quota-{index}");
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            database
                .create_instance(&actor, &request, &format!("quota-key-{index}"), 300, 86400)
                .await
        }
    });
    let mut accepted = 0;
    let mut rejected = 0;
    for result in join_all(attempts).await {
        match result {
            Ok(_) => accepted += 1,
            Err(error) => {
                ensure!(
                    error.status == StatusCode::CONFLICT && error.code == "QUOTA_EXCEEDED",
                    "Unexpected concurrent result: {}",
                    error.code
                );
                rejected += 1;
            }
        }
    }
    assert_eq!((accepted, rejected), (1, 15));
    for table in [
        "instances",
        "workspaces",
        "operations",
        "idempotency_keys",
        "audit_events",
        "domain_events",
    ] {
        assert_eq!(
            fixture.count(table).await?,
            1,
            "Rejected create leaked into {table}"
        );
    }
    assert_eq!(fixture.count("quota_reservations").await?, 8);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn late_quota_failure_rolls_back_resources_and_earlier_reservations() -> anyhow::Result<()> {
    let _test_scope = support::serial().await;
    let fixture = Fixture::new(10).await?;
    let mut tx = fixture.owner_transaction().await?;
    sqlx::query("UPDATE quota_accounts SET limit_value=19 WHERE tenant_id=$1 AND project_id IS NULL AND dimension='WORKSPACE_GIB'")
        .bind(fixture.actor.tenant_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let error = require_api_error(fixture.create("late-failure").await)?;
    assert_eq!(error.code, "QUOTA_EXCEEDED");
    fixture.assert_empty_mutation().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn revoked_grant_cannot_read_an_old_idempotent_receipt() -> anyhow::Result<()> {
    let _test_scope = support::serial().await;
    let fixture = Fixture::new(10).await?;
    fixture
        .create("before-revocation")
        .await
        .map_err(api_failure)?;
    let mut tx = fixture.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false,revoked_at=clock_timestamp() WHERE tenant_id=$1 AND principal_id=$2 AND action='instances:create'")
        .bind(fixture.actor.tenant_id).bind(fixture.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let error = require_api_error(fixture.create("before-revocation").await)?;
    assert_eq!(error.status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "PERMISSION_DENIED");
    assert_eq!(fixture.count("idempotency_keys").await?, 1);
    assert_eq!(fixture.count("audit_events").await?, 1);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn disabled_principal_cannot_reuse_a_previously_resolved_actor() -> anyhow::Result<()> {
    let _test_scope = support::serial().await;
    let fixture = Fixture::new(10).await?;
    fixture
        .create("principal-enabled")
        .await
        .map_err(api_failure)?;
    sqlx::query("UPDATE principals SET enabled=false WHERE id=$1")
        .bind(fixture.actor.principal_id)
        .execute(&fixture.owner)
        .await?;
    let error = require_api_error(fixture.create("principal-enabled").await)?;
    assert_eq!(error.status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "PERMISSION_DENIED");
    assert_eq!(fixture.count("instances").await?, 1);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn inaccessible_instances_and_operations_are_indistinguishable_from_missing_resources()
-> anyhow::Result<()> {
    let _test_scope = support::serial().await;
    let a = Fixture::new(10).await?;
    let b = Fixture::new(10).await?;
    let accessible = a.create("visible-resource").await.map_err(api_failure)?;
    let foreign = b.create("foreign-resource").await.map_err(api_failure)?;

    // Principal A can choose a tenant header, but cannot acquire B's grants.
    let forged_tenant = Actor {
        authorization: None,
        tenant_id: b.actor.tenant_id,
        principal_id: a.actor.principal_id,
        request_id: Uuid::new_v4(),
    };
    assert_resource_hidden(
        &a.database,
        &forged_tenant,
        foreign.body.resource.id,
        foreign.body.operation.id,
    )
    .await?;
    assert_resource_hidden(
        &a.database,
        &a.actor,
        foreign.body.resource.id,
        foreign.body.operation.id,
    )
    .await?;

    // A second project belongs to A's tenant, but only principal B can access it.
    let private_project = Uuid::new_v4();
    let mut tx = a.owner_transaction().await?;
    sqlx::query("INSERT INTO projects(id,tenant_id,name,max_ttl_seconds,runtime_namespace,storage_class) VALUES($1,$2,'Private project',86400,$3,'integration-storage')")
        .bind(private_project).bind(a.actor.tenant_id).bind(format!("private-{}", private_project.simple())).execute(&mut *tx).await?;
    for action in ["instances:create", "instances:read", "operations:read"] {
        sqlx::query(
            "INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4)",
        )
        .bind(a.actor.tenant_id)
        .bind(private_project)
        .bind(b.actor.principal_id)
        .bind(action)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("INSERT INTO quota_accounts(tenant_id,project_id,dimension,limit_value) SELECT tenant_id,$3,dimension,limit_value FROM quota_accounts WHERE tenant_id=$1 AND project_id=$2")
        .bind(a.actor.tenant_id).bind(a.request.project_id).bind(private_project).execute(&mut *tx).await?;
    tx.commit().await?;
    let private_actor = Actor {
        authorization: None,
        tenant_id: a.actor.tenant_id,
        principal_id: b.actor.principal_id,
        request_id: Uuid::new_v4(),
    };
    let mut private_request = a.request.clone();
    private_request.project_id = private_project;
    let private = a
        .database
        .create_instance(
            &private_actor,
            &private_request,
            "private-resource",
            300,
            86400,
        )
        .await
        .map_err(api_failure)?;
    assert_resource_hidden(
        &a.database,
        &a.actor,
        private.body.resource.id,
        private.body.operation.id,
    )
    .await?;

    let visible_instance = a
        .database
        .get_instance(&a.actor, accessible.body.resource.id)
        .await
        .map_err(api_failure)?;
    let visible_operation = a
        .database
        .get_operation(&a.actor, accessible.body.operation.id)
        .await
        .map_err(api_failure)?;
    assert_eq!(visible_instance.id, accessible.body.resource.id);
    assert_eq!(visible_operation.id, accessible.body.operation.id);
    Ok(())
}

async fn assert_resource_hidden(
    database: &Database,
    actor: &Actor,
    instance: Uuid,
    operation: Uuid,
) -> anyhow::Result<()> {
    for id in [instance, Uuid::new_v4()] {
        let error = database
            .get_instance(actor, id)
            .await
            .err()
            .context("Instance lookup unexpectedly disclosed a resource")?;
        assert_eq!(error.status, StatusCode::NOT_FOUND);
        assert_eq!(error.code, "RESOURCE_NOT_FOUND");
    }
    for id in [operation, Uuid::new_v4()] {
        let error = database
            .get_operation(actor, id)
            .await
            .err()
            .context("Operation lookup unexpectedly disclosed a resource")?;
        assert_eq!(error.status, StatusCode::NOT_FOUND);
        assert_eq!(error.code, "RESOURCE_NOT_FOUND");
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn pending_create_renewal_preserves_the_operation_and_replays_old_if_match()
-> anyhow::Result<()> {
    let _test_scope = support::serial().await;
    let fixture = Fixture::new(10).await?;
    let created = fixture.create("renew-create").await.map_err(api_failure)?;
    let before = &created.body.resource;
    let request = RenewRequest {
        expires_at: before.compute_lease_expires_at + chrono::Duration::seconds(300),
    };
    let renewed = fixture
        .database
        .renew_instance(
            &fixture.actor,
            before.id,
            &request,
            "renew-key",
            before.spec_version,
            86400,
        )
        .await
        .map_err(api_failure)?;
    assert_eq!(renewed.status, 200);
    assert_eq!(
        renewed.body.resource.active_operation_id,
        Some(created.body.operation.id)
    );
    assert_eq!(
        renewed.body.resource.compute_lease_id,
        before.compute_lease_id
    );
    assert_eq!(
        renewed.body.resource.compute_lease_version,
        before.compute_lease_version + 1
    );
    assert_eq!(renewed.body.resource.spec_version, before.spec_version + 1);
    assert_eq!(
        renewed.body.resource.compute_lease_expires_at,
        request.expires_at
    );
    assert_eq!(renewed.body.operation.status, "SUCCEEDED");
    let replay = fixture
        .database
        .renew_instance(
            &fixture.actor,
            before.id,
            &request,
            "renew-key",
            before.spec_version,
            86400,
        )
        .await
        .map_err(api_failure)?;
    assert_eq!(
        serde_json::to_value(replay.body)?,
        serde_json::to_value(renewed.body)?
    );
    assert_eq!(fixture.count("operations").await?, 2);
    assert_eq!(fixture.count("quota_reservations").await?, 8);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn concurrent_renewals_require_one_current_version() -> anyhow::Result<()> {
    let _test_scope = support::serial().await;
    let fixture = Fixture::new(10).await?;
    let created = fixture.create("renew-race").await.map_err(api_failure)?;
    let barrier = Arc::new(Barrier::new(2));
    let attempts = (1..=2).map(|index| {
        let database = fixture.database.clone();
        let actor = fixture.actor.clone();
        let before = created.body.resource.clone();
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            database
                .renew_instance(
                    &actor,
                    before.id,
                    &RenewRequest {
                        expires_at: before.compute_lease_expires_at
                            + chrono::Duration::seconds(index * 300),
                    },
                    &format!("renew-{index}"),
                    before.spec_version,
                    86400,
                )
                .await
        }
    });
    let mut accepted = 0;
    let mut rejected = 0;
    for result in join_all(attempts).await {
        match result {
            Ok(_) => accepted += 1,
            Err(error) => {
                ensure!(
                    error.status == StatusCode::PRECONDITION_FAILED
                        && error.code == "VERSION_MISMATCH",
                    "Unexpected renewal result: {}",
                    error.code
                );
                rejected += 1;
            }
        }
    }
    assert_eq!((accepted, rejected), (1, 1));
    assert_eq!(fixture.count("operations").await?, 2);
    assert_eq!(fixture.count("audit_events").await?, 2);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn accepted_stop_fences_create_without_releasing_activity_or_quota() -> anyhow::Result<()> {
    let _test_scope = support::serial().await;
    let fixture = Fixture::new(10).await?;
    let created = fixture.create("stop-create").await.map_err(api_failure)?;
    let before = &created.body.resource;
    let mut tx = fixture.owner_transaction().await?;
    // Exercise conservative handling of legacy terminal occupancy during a
    // pending create. Formal file slots require a real transfer receipt and
    // are covered by the file pipeline's trusted termination integration test.
    sqlx::query("UPDATE instances SET slot_held=true,activity_kind='TERMINAL',activity_id=$3,activity_generation=runtime_generation WHERE tenant_id=$1 AND id=$2")
        .bind(fixture.actor.tenant_id).bind(before.id).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    tx.commit().await?;
    let stopped = fixture
        .database
        .lifecycle_action(
            &fixture.actor,
            before.id,
            InstanceAction::Stop,
            &StartRequest::default(),
            "stop-key",
            before.spec_version,
            300,
            86400,
        )
        .await
        .map_err(api_failure)?;
    assert_eq!(stopped.body.resource.desired_state, "STOPPED");
    assert_eq!(stopped.body.resource.observed_state, "PENDING");
    assert!(
        stopped.body.resource.slot_held,
        "Accepted stop is not evidence of remote termination"
    );
    assert_eq!(
        stopped.body.resource.active_operation_id,
        Some(stopped.body.operation.id)
    );
    let mut tx = fixture.owner_transaction().await?;
    let old: (String, i64, bool) = sqlx::query_as(
        "SELECT status,lease_token,cancel_requested FROM operations WHERE tenant_id=$1 AND id=$2",
    )
    .bind(fixture.actor.tenant_id)
    .bind(created.body.operation.id)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(old, ("CANCELLED".to_owned(), 1, true));
    let released: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM quota_reservations WHERE tenant_id=$1 AND status='RELEASED'",
    )
    .bind(fixture.actor.tenant_id)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(released, 0);
    tx.commit().await?;
    let renewal = RenewRequest {
        expires_at: before.compute_lease_expires_at + chrono::Duration::seconds(300),
    };
    let error = require_api_error(
        fixture
            .database
            .renew_instance(
                &fixture.actor,
                before.id,
                &renewal,
                "after-stop",
                stopped.body.resource.spec_version,
                86400,
            )
            .await,
    )?;
    assert_eq!(error.code, "STOP_ALREADY_ACCEPTED");
    assert_eq!(fixture.count("operations").await?, 2);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn start_requires_available_storage_and_released_compute_then_reserves_only_compute()
-> anyhow::Result<()> {
    let _test_scope = support::serial().await;
    let fixture = Fixture::new(10).await?;
    let created = fixture.create("start-create").await.map_err(api_failure)?;
    let before = &created.body.resource;
    fixture.seed_observed_state(before.id, "STOPPED").await?;
    let mut tx = fixture.owner_transaction().await?;
    sqlx::query("UPDATE workspaces SET status='UNKNOWN' WHERE tenant_id=$1 AND id=$2")
        .bind(fixture.actor.tenant_id)
        .bind(before.workspace_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let error = require_api_error(
        fixture
            .database
            .lifecycle_action(
                &fixture.actor,
                before.id,
                InstanceAction::Start,
                &StartRequest::default(),
                "start-key",
                before.spec_version,
                300,
                86400,
            )
            .await,
    )?;
    assert_eq!(error.code, "WORKSPACE_BUSY");
    let mut tx = fixture.owner_transaction().await?;
    sqlx::query("UPDATE workspaces SET status='AVAILABLE' WHERE tenant_id=$1 AND id=$2")
        .bind(fixture.actor.tenant_id)
        .bind(before.workspace_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let error = require_api_error(
        fixture
            .database
            .lifecycle_action(
                &fixture.actor,
                before.id,
                InstanceAction::Start,
                &StartRequest::default(),
                "start-key",
                before.spec_version,
                300,
                86400,
            )
            .await,
    )?;
    assert_eq!(error.code, "COMPUTE_QUOTA_RECONCILIATION_REQUIRED");
    fixture.release_fixture_compute(before.id).await?;
    let started = fixture
        .database
        .lifecycle_action(
            &fixture.actor,
            before.id,
            InstanceAction::Start,
            &StartRequest::default(),
            "start-key",
            before.spec_version,
            300,
            86400,
        )
        .await
        .map_err(api_failure)?;
    assert_eq!(
        started.body.resource.runtime_generation,
        before.runtime_generation + 1
    );
    assert_ne!(
        started.body.resource.compute_lease_id,
        before.compute_lease_id
    );
    assert_eq!(started.body.operation.kind, "START");
    let mut tx = fixture.owner_transaction().await?;
    let reserved: Vec<(String, i64)> = sqlx::query_as("SELECT q.dimension,r.amount FROM quota_reservations r JOIN quota_accounts q ON q.tenant_id=r.tenant_id AND q.id=r.quota_account_id WHERE r.tenant_id=$1 AND r.operation_id=$2 ORDER BY q.dimension")
        .bind(fixture.actor.tenant_id).bind(started.body.operation.id).fetch_all(&mut *tx).await?;
    assert_eq!(
        reserved,
        vec![
            ("CPU_MILLIS".to_owned(), 1000),
            ("CPU_MILLIS".to_owned(), 1000),
            ("MEMORY_MIB".to_owned(), 2048),
            ("MEMORY_MIB".to_owned(), 2048)
        ]
    );
    let instances_pending: Vec<i64> = sqlx::query_scalar(
        "SELECT pending FROM quota_accounts WHERE tenant_id=$1 AND dimension='INSTANCES'",
    )
    .bind(fixture.actor.tenant_id)
    .fetch_all(&mut *tx)
    .await?;
    assert_eq!(instances_pending, vec![1, 1]);
    tx.commit().await?;
    assert_eq!(
        fixture.count("idempotency_keys").await?,
        2,
        "Rejected start attempts must not leave receipts"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn restart_acceptance_preserves_the_lease_and_current_generation() -> anyhow::Result<()> {
    let _test_scope = support::serial().await;
    let fixture = Fixture::new(10).await?;
    let created = fixture
        .create("restart-create")
        .await
        .map_err(api_failure)?;
    let before = &created.body.resource;
    fixture.seed_observed_state(before.id, "RUNNING").await?;
    let restarted = fixture
        .database
        .lifecycle_action(
            &fixture.actor,
            before.id,
            InstanceAction::Restart,
            &StartRequest::default(),
            "restart-key",
            before.spec_version,
            300,
            86400,
        )
        .await
        .map_err(api_failure)?;
    assert_eq!(
        restarted.body.resource.compute_lease_id,
        before.compute_lease_id
    );
    assert_eq!(
        restarted.body.resource.compute_lease_expires_at,
        before.compute_lease_expires_at
    );
    assert_eq!(
        restarted.body.resource.runtime_generation,
        before.runtime_generation
    );
    assert_eq!(
        restarted.body.resource.active_operation_id,
        Some(restarted.body.operation.id)
    );
    assert_eq!(fixture.count("quota_reservations").await?, 8);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn safe_mode_blocks_compute_admission_but_permits_safety_stop() -> anyhow::Result<()> {
    let _test_scope = support::serial().await;
    let active = Fixture::new(10).await?;
    let stopped = Fixture::new(10).await?;
    let running_receipt = active.create("safe-active").await.map_err(api_failure)?;
    let stopped_receipt = stopped.create("safe-stopped").await.map_err(api_failure)?;
    stopped
        .seed_observed_state(stopped_receipt.body.resource.id, "STOPPED")
        .await?;
    stopped
        .release_fixture_compute(stopped_receipt.body.resource.id)
        .await?;
    sqlx::query("UPDATE platform_configuration SET safe_mode=true WHERE singleton")
        .execute(&active.owner)
        .await?;

    // Always restore the global switch before propagating an assertion failure.
    let outcome: anyhow::Result<()> = async {
        let before = &running_receipt.body.resource;
        let renewal = RenewRequest {
            expires_at: before.compute_lease_expires_at + chrono::Duration::seconds(300),
        };
        let error = require_api_error(
            active
                .database
                .renew_instance(
                    &active.actor,
                    before.id,
                    &renewal,
                    "safe-renew",
                    before.spec_version,
                    86400,
                )
                .await,
        )?;
        ensure!(
            error.code == "PLATFORM_SAFE_MODE",
            "Unexpected safe-mode renew result: {}",
            error.code
        );
        let before_stopped = &stopped_receipt.body.resource;
        let error = require_api_error(
            stopped
                .database
                .lifecycle_action(
                    &stopped.actor,
                    before_stopped.id,
                    InstanceAction::Start,
                    &StartRequest::default(),
                    "safe-start",
                    before_stopped.spec_version,
                    300,
                    86400,
                )
                .await,
        )?;
        ensure!(
            error.code == "PLATFORM_SAFE_MODE",
            "Unexpected safe-mode start result: {}",
            error.code
        );
        let stop = active
            .database
            .lifecycle_action(
                &active.actor,
                before.id,
                InstanceAction::Stop,
                &StartRequest::default(),
                "safe-stop",
                before.spec_version,
                300,
                86400,
            )
            .await
            .map_err(api_failure)?;
        ensure!(
            stop.body.resource.desired_state == "STOPPED",
            "Safe mode must allow safety stop"
        );
        Ok(())
    }
    .await;
    sqlx::query("UPDATE platform_configuration SET safe_mode=false WHERE singleton")
        .execute(&active.owner)
        .await?;
    outcome
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn database_constraints_reject_null_activity_generation_and_binding_changes()
-> anyhow::Result<()> {
    let _test_scope = support::serial().await;
    let fixture = Fixture::new(10).await?;
    let created = fixture
        .create("invariants-create")
        .await
        .map_err(api_failure)?;
    let before = &created.body.resource;
    let mut tx = fixture
        .database
        .begin(fixture.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    require_pg_error(sqlx::query("UPDATE instances SET slot_held=true,activity_kind='TERMINAL',activity_id=$2,activity_generation=NULL WHERE id=$1")
        .bind(before.id).bind(Uuid::new_v4()).execute(&mut *tx).await, "23514")?;
    tx.rollback().await?;
    for table in ["instances", "workspaces"] {
        let mut tx = fixture
            .database
            .begin(fixture.actor.tenant_id)
            .await
            .map_err(api_failure)?;
        require_pg_error(
            sqlx::query(&format!(
                "UPDATE {table} SET namespace='different-namespace'"
            ))
            .execute(&mut *tx)
            .await,
            "23514",
        )?;
        tx.rollback().await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn same_project_workspace_rebinding_is_rejected_by_identity_trigger() -> anyhow::Result<()> {
    let _test_scope = support::serial().await;
    let fixture = Fixture::new(10).await?;
    let created = fixture
        .create("workspace-binding-create")
        .await
        .map_err(api_failure)?;
    let original = &created.body.resource;
    let replacement = Uuid::new_v4();
    let mut owner_tx = fixture.owner_transaction().await?;
    // A valid, unused workspace in the same project and namespace satisfies both
    // composite foreign keys; change pod_name too to satisfy its binding CHECK.
    let inserted = sqlx::query("INSERT INTO workspaces(id,tenant_id,project_id,size_gib,storage_class,namespace,pvc_name) SELECT $1,tenant_id,project_id,size_gib,storage_class,namespace,'ws-' || $1::text FROM workspaces WHERE id=$2")
        .bind(replacement)
        .bind(original.workspace_id)
        .execute(&mut *owner_tx)
        .await?;
    assert_eq!(inserted.rows_affected(), 1);
    owner_tx.commit().await?;

    let mut tx = fixture
        .database
        .begin(fixture.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    let result = sqlx::query(
        "UPDATE instances SET workspace_id=$2,pod_name='sbx-ws-' || $2::text WHERE id=$1",
    )
    .bind(original.id)
    .bind(replacement)
    .execute(&mut *tx)
    .await;
    match result {
        Ok(_) => anyhow::bail!("Same-project workspace rebinding unexpectedly succeeded"),
        Err(error) => {
            let database_error = error
                .as_database_error()
                .context("Expected PostgreSQL identity trigger error")?;
            assert_eq!(database_error.code().as_deref(), Some("23514"));
            assert_eq!(
                database_error.message(),
                "instance workspace and Kubernetes name are immutable"
            );
        }
    }
    tx.rollback().await?;
    let mut tx = fixture
        .database
        .begin(fixture.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    let binding: Uuid = sqlx::query_scalar("SELECT workspace_id FROM instances WHERE id=$1")
        .bind(original.id)
        .fetch_one(&mut *tx)
        .await?;
    assert_eq!(binding, original.workspace_id);
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn queue_claims_are_exclusive_and_expired_workers_cannot_progress() -> anyhow::Result<()> {
    let _test_scope = support::serial().await;
    let a = Fixture::new(10).await?;
    let b = Fixture::new(10).await?;
    let first = a.create("queue-a").await.map_err(api_failure)?;
    let second = b.create("queue-b").await.map_err(api_failure)?;
    for (fixture, operation) in [
        (&a, first.body.operation.id),
        (&b, second.body.operation.id),
    ] {
        let mut tx = fixture.owner_transaction().await?;
        // Put this case's work before retained fixtures without changing other tenants.
        sqlx::query("UPDATE operations SET next_attempt_at='1900-01-01 00:00:00+00'::timestamptz WHERE id=$1")
            .bind(operation)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    let denied = sqlx::query("SELECT * FROM operation_dispatch")
        .fetch_all(&a.database.pool)
        .await;
    require_pg_error(denied, "42501")?;
    let denied = sqlx::query("SELECT * FROM sandbox_claim_operation('forbidden-api-worker')")
        .fetch_all(&a.database.pool)
        .await;
    require_pg_error(denied, "42501")?;

    let worker_a = OperationEngine::new(
        Database {
            pool: a.owner.clone(),
        },
        "integration-worker-a".to_owned(),
    )?;
    let worker_b = OperationEngine::new(
        Database {
            pool: b.owner.clone(),
        },
        "integration-worker-b".to_owned(),
    )?;
    let (claim_a, claim_b) = tokio::join!(worker_a.claim(), worker_b.claim());
    let claim_a = claim_a
        .map_err(api_failure)?
        .context("Worker A did not receive a claim")?;
    let claim_b = claim_b
        .map_err(api_failure)?
        .context("Worker B did not receive a claim")?;
    let mut actual = vec![claim_a.operation_id, claim_b.operation_id];
    let mut expected = vec![first.body.operation.id, second.body.operation.id];
    actual.sort();
    expected.sort();
    assert_eq!(
        actual, expected,
        "Two workers must not claim the same operation"
    );
    assert_eq!((claim_a.lease_token, claim_b.lease_token), (1, 1));
    assert!(worker_a.heartbeat(&claim_a).await.map_err(api_failure)?);
    assert!(
        !worker_b.heartbeat(&claim_a).await.map_err(api_failure)?,
        "A different worker cannot renew another lease"
    );

    let mut tx = a.owner.begin().await?;
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(claim_a.tenant_id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE operations SET lease_until='1900-01-01 00:00:00+00'::timestamptz WHERE id=$1",
    )
    .bind(claim_a.operation_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    assert!(
        !worker_a.heartbeat(&claim_a).await.map_err(api_failure)?,
        "An expired worker cannot revive its own lease"
    );
    let replacement = worker_b
        .claim()
        .await
        .map_err(api_failure)?
        .context("Expired operation was not reclaimable")?;
    assert_eq!(replacement.operation_id, claim_a.operation_id);
    assert_eq!(replacement.lease_token, claim_a.lease_token + 1);
    let error = worker_a
        .wait(
            &claim_a,
            "STALE_WORKER",
            "must not overwrite replacement",
            1,
        )
        .await
        .err()
        .context("Stale worker unexpectedly progressed the operation")?;
    assert_eq!(error.code, "WORKER_LEASE_LOST");
    worker_b
        .wait(&replacement, "DEPENDENCY_WAIT", "integration retry", 1)
        .await
        .map_err(api_failure)?;

    let mut tx = a.owner.begin().await?;
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(replacement.tenant_id.to_string())
        .execute(&mut *tx)
        .await?;
    let state: (String, String, Option<String>) =
        sqlx::query_as("SELECT status,stage,lease_owner FROM operations WHERE id=$1")
            .bind(replacement.operation_id)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(
        state,
        ("WAITING".to_owned(), "DEPENDENCY_WAIT".to_owned(), None)
    );
    tx.commit().await?;
    let context: Option<String> =
        sqlx::query_scalar("SELECT current_setting('app.tenant_id',true)")
            .fetch_one(&a.owner)
            .await?;
    assert!(
        context.is_none_or(|value| value.is_empty()),
        "Claim must restore the caller's tenant context"
    );
    Ok(())
}
