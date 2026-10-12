//! Real PostgreSQL tests. Run after the database integration suite has migrated
//! and initialized the disposable database. These cases never change the global
//! safe-mode flag or cluster epoch.
#![allow(clippy::unwrap_used)]

use anyhow::{Context, ensure};
use sandbox_platform::{
    admin::{AdminError, BootstrapSpec, apply_bootstrap, parse_spec},
    db::Database,
};
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};
use url::Url;
use uuid::Uuid;

fn spec() -> BootstrapSpec {
    let tenant = Uuid::new_v4();
    let project = Uuid::new_v4();
    let principal = Uuid::new_v4();
    let value = json!({
        "tenant":{"id":tenant,"name":"Bootstrap integration"},
        "project":{"id":project,"name":"Agents","runtime_namespace":format!("bootstrap-{}",project.simple()),"storage_class":"sandbox-test-storage","max_ttl_seconds":3600},
        "initial_principal":{"id":principal,"issuer":"https://bootstrap.example.test/realms/sandbox","subject":principal.to_string(),"kind":"SERVICE","client_id":"bootstrap-client","display_name":"Bootstrap client","project_actions":["instances:create","instances:read","operations:read"]},
        "approved_template":{"id":Uuid::new_v4(),"name":"bootstrap-python","version":1,"image_ref":"registry.example.test/sandbox/python","image_digest":format!("sha256:{}","a".repeat(64)),"runner_version":"1.0.0"},
        "security_policy":{"id":Uuid::new_v4(),"name":"deny-all","version":1,"rules":{"profile":"deny-all","dns":true}},
        "quotas":{"tenant":{"instances":10,"cpu_millis":10000,"memory_mib":20480,"workspace_gib":200,"executions":10},"project":{"instances":2,"cpu_millis":2000,"memory_mib":4096,"workspace_gib":40,"executions":2}}
    });
    parse_spec(value.to_string().as_bytes(), false).unwrap()
}

#[tokio::test]
#[ignore = "Requires prepared disposable PostgreSQL and separate owner/runtime logins"]
async fn optional_backup_quotas_can_be_added_without_rewriting_existing_limits()
-> anyhow::Result<()> {
    let (owner, _) = connections().await?;
    let original = spec();
    apply_bootstrap(&owner, &original, None, false).await?;
    let mut extended = original.clone();
    extended.quotas.tenant.backup_gib = Some(200);
    extended.quotas.project.backup_gib = Some(40);
    extended.quotas.tenant.backup_temp_gib = Some(80);
    extended.quotas.project.backup_temp_gib = Some(40);
    let first = apply_bootstrap(&owner, &extended, None, false).await?;
    assert!(first.changed);
    assert!(
        !apply_bootstrap(&owner, &extended, None, false)
            .await?
            .changed
    );
    assert!(
        !apply_bootstrap(&owner, &original, None, false)
            .await?
            .changed
    );
    let mut tx = tenant_tx(&owner, original.tenant.id).await?;
    let quotas:Vec<(String,Option<Uuid>,i64)>=sqlx::query_as("SELECT dimension,project_id,limit_value FROM quota_accounts WHERE tenant_id=$1 AND dimension IN('BACKUP_GIB','BACKUP_TEMP_GIB') ORDER BY dimension,project_id NULLS FIRST").bind(original.tenant.id).fetch_all(&mut *tx).await?;
    assert_eq!(
        quotas,
        vec![
            ("BACKUP_GIB".into(), None, 200),
            ("BACKUP_GIB".into(), Some(original.project.id), 40),
            ("BACKUP_TEMP_GIB".into(), None, 80),
            ("BACKUP_TEMP_GIB".into(), Some(original.project.id), 40)
        ]
    );
    tx.commit().await?;
    extended.quotas.project.backup_gib = Some(41);
    assert!(matches!(
        apply_bootstrap(&owner, &extended, None, false).await,
        Err(AdminError::Conflict("quota limits"))
    ));
    Ok(())
}

async fn connections() -> anyhow::Result<(Database, Database)> {
    let owner_url = std::env::var("TEST_MIGRATION_DATABASE_URL")
        .context("TEST_MIGRATION_DATABASE_URL must target the prepared disposable database")?;
    let runtime_url = std::env::var("TEST_DATABASE_URL")
        .context("TEST_DATABASE_URL must use the restricted runtime login")?;
    let owner_target = Url::parse(&owner_url)?;
    let runtime_target = Url::parse(&runtime_url)?;
    ensure!(
        owner_target.host_str() == runtime_target.host_str()
            && owner_target.port_or_known_default() == runtime_target.port_or_known_default()
            && owner_target.path() == runtime_target.path()
            && owner_target.username() != runtime_target.username(),
        "Bootstrap tests require separate roles for the same disposable database"
    );
    let owner = Database::connect(&owner_url, 2).await?;
    let runtime = Database::connect(&runtime_url, 2).await?;
    runtime.verify_runtime_role().await?;
    Ok((owner, runtime))
}

async fn tenant_tx(database: &Database, tenant: Uuid) -> anyhow::Result<Transaction<'_, Postgres>> {
    let mut tx = database.pool.begin().await?;
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

#[tokio::test]
#[ignore = "Requires prepared disposable PostgreSQL and separate owner/runtime logins"]
async fn explicit_feature_permissions_bootstrap_without_wildcard_or_tenant_grants()
-> anyhow::Result<()> {
    let (owner, _) = connections().await?;
    let mut configured = spec();
    configured.initial_principal.project_actions = vec![
        "files:read".into(),
        "files:write".into(),
        "automations:read".into(),
        "automations:write".into(),
        "backups:create".into(),
        "backups:read".into(),
    ];
    configured.validate(false)?;
    for action in ["backups:restore", "restores:read"] {
        let mut unpublished = configured.clone();
        unpublished
            .initial_principal
            .project_actions
            .push(action.into());
        assert!(
            matches!(
                unpublished.validate(false),
                Err(AdminError::Invalid(
                    "project_actions must explicitly list unique supported permissions, or only *"
                ))
            ),
            "unpublished restore action {action} must remain unavailable to bootstrap"
        );
    }
    apply_bootstrap(&owner, &configured, None, false).await?;
    let mut tx = tenant_tx(&owner, configured.tenant.id).await?;
    let grants: Vec<(Option<Uuid>, String)> = sqlx::query_as(
        "SELECT project_id,action FROM grants WHERE tenant_id=$1 AND principal_id=$2 ORDER BY action"
    ).bind(configured.tenant.id).bind(configured.initial_principal.id)
        .fetch_all(&mut *tx).await?;
    assert_eq!(
        grants,
        vec![
            (Some(configured.project.id), "automations:read".into()),
            (Some(configured.project.id), "automations:write".into()),
            (Some(configured.project.id), "backups:create".into()),
            (Some(configured.project.id), "backups:read".into()),
            (Some(configured.project.id), "files:read".into()),
            (Some(configured.project.id), "files:write".into())
        ]
    );
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires the prepared PostgreSQL 17+ integration database and both TEST_*DATABASE_URL credentials"]
async fn bootstrap_is_atomic_repeatable_preserves_limits_and_rejects_identity_rebinding()
-> anyhow::Result<()> {
    let (owner, runtime) = connections().await?;
    let configured: (Uuid, bool) = sqlx::query_as(
        "SELECT cluster_epoch,safe_mode FROM platform_configuration WHERE singleton",
    )
    .fetch_one(&owner.pool)
    .await
    .context("Run the database integration suite before bootstrap tests")?;
    let original = spec();
    let first = apply_bootstrap(&owner, &original, Some(configured.0), false).await?;
    assert!(first.changed);
    assert_eq!((first.cluster_epoch, first.safe_mode), configured);

    // Existing allocation counters survive an exact bootstrap retry.
    let mut tx = tenant_tx(&owner, original.tenant.id).await?;
    sqlx::query(
        "UPDATE quota_accounts SET allocated=1 WHERE tenant_id=$1 AND dimension='INSTANCES'",
    )
    .bind(original.tenant.id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let replay = apply_bootstrap(&owner, &original, None, false).await?;
    assert!(!replay.changed);
    assert_ne!(replay.request_id, first.request_id);
    assert_eq!(replay.spec_sha256, first.spec_sha256);
    assert_eq!((replay.cluster_epoch, replay.safe_mode), configured);
    let mut tx = tenant_tx(&owner, original.tenant.id).await?;
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT count(*),sum(allocated)::bigint FROM quota_accounts WHERE tenant_id=$1",
    )
    .bind(original.tenant.id)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(counts, (10, 2));
    let audits: Vec<(Option<Uuid>, Value)> = sqlx::query_as("SELECT actor_principal_id,details FROM audit_events WHERE tenant_id=$1 AND action='platform:bootstrap'")
        .bind(original.tenant.id).fetch_all(&mut *tx).await?;
    assert_eq!(audits.len(), 2);
    for (actor, details) in audits {
        assert!(actor.is_none());
        assert_eq!(details["authorization_source"], "database_table_owner");
        assert!(details["database_role"].as_str().is_some());
        assert_eq!(details["spec_sha256"], first.spec_sha256);
    }
    tx.commit().await?;

    // A colliding external identity cannot be reassigned to a new principal;
    // tenant/project/principal rows inserted earlier in the transaction roll back.
    let mut rebind = spec();
    rebind.initial_principal.issuer = original.initial_principal.issuer.clone();
    rebind.initial_principal.subject = original.initial_principal.subject.clone();
    assert!(matches!(
        apply_bootstrap(&owner, &rebind, None, false).await,
        Err(AdminError::Conflict("identity binding"))
    ));
    let mut tx = tenant_tx(&owner, rebind.tenant.id).await?;
    let absent: (bool, bool, bool) = sqlx::query_as("SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1), EXISTS(SELECT 1 FROM projects WHERE id=$2), EXISTS(SELECT 1 FROM principals WHERE id=$3)")
        .bind(rebind.tenant.id).bind(rebind.project.id).bind(rebind.initial_principal.id).fetch_one(&mut *tx).await?;
    assert_eq!(absent, (false, false, false));
    tx.commit().await?;

    let mut grant_change = original.clone();
    grant_change
        .initial_principal
        .project_actions
        .push("instances:delete".into());
    assert!(matches!(
        apply_bootstrap(&owner, &grant_change, None, false).await,
        Err(AdminError::Conflict("principal grants"))
    ));

    // Fail late, after inserting an approved template, to prove rollback also
    // covers privileged catalog writes and does not leave a success audit.
    let mut quota_change = original.clone();
    quota_change.approved_template.id = Uuid::new_v4();
    quota_change.approved_template.name = "must-roll-back".into();
    quota_change.quotas.project.instances = 3;
    assert!(matches!(
        apply_bootstrap(&owner, &quota_change, None, false).await,
        Err(AdminError::Conflict("quota limits"))
    ));
    let mut tx = tenant_tx(&owner, original.tenant.id).await?;
    let template_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM template_versions WHERE id=$1)")
            .bind(quota_change.approved_template.id)
            .fetch_one(&mut *tx)
            .await?;
    assert!(!template_exists);
    let audit_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE tenant_id=$1")
            .bind(original.tenant.id)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(audit_count, 2);
    let grant_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM grants WHERE tenant_id=$1 AND principal_id=$2")
            .bind(original.tenant.id)
            .bind(original.initial_principal.id)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(grant_count, 3);
    sqlx::query("UPDATE principals SET enabled=false WHERE id=$1")
        .bind(original.initial_principal.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    assert!(matches!(
        apply_bootstrap(&owner, &original, None, false).await,
        Err(AdminError::Conflict("principal"))
    ));
    assert!(matches!(
        apply_bootstrap(&runtime, &original, None, false).await,
        Err(AdminError::OwnerRequired)
    ));
    assert!(matches!(
        apply_bootstrap(&owner, &spec(), Some(Uuid::new_v4()), false).await,
        Err(AdminError::Conflict("cluster epoch"))
    ));
    let still_configured: (Uuid, bool) = sqlx::query_as(
        "SELECT cluster_epoch,safe_mode FROM platform_configuration WHERE singleton",
    )
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(still_configured, configured);
    owner.pool.close().await;
    runtime.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires the prepared PostgreSQL integration database and both TEST_*DATABASE_URL credentials"]
async fn bootstrap_tenant_identity_permissions_are_explicit_repeatable_and_do_not_reenable_membership()
-> anyhow::Result<()> {
    let (owner, runtime) = connections().await?;
    let mut request = spec();
    assert!(request.initial_principal.tenant_actions.is_empty());
    request.initial_principal.tenant_actions = vec![
        "service_clients:read".into(),
        "service_clients:write".into(),
        "tenant_audit:read".into(),
    ];
    assert!(
        apply_bootstrap(&owner, &request, None, false)
            .await?
            .changed
    );
    assert!(
        !apply_bootstrap(&owner, &request, None, false)
            .await?
            .changed
    );
    let mut tx = tenant_tx(&owner, request.tenant.id).await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM grants WHERE tenant_id=$1 AND principal_id=$2 AND project_id IS NULL",
    )
    .bind(request.tenant.id)
    .bind(request.initial_principal.id)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(count, 3);
    sqlx::query(
        "UPDATE tenant_principals SET enabled=false WHERE tenant_id=$1 AND principal_id=$2",
    )
    .bind(request.tenant.id)
    .bind(request.initial_principal.id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    assert!(matches!(
        apply_bootstrap(&owner, &request, None, false).await,
        Err(AdminError::Conflict("tenant principal membership"))
    ));
    request.initial_principal.tenant_actions = vec!["*".into()];
    assert!(request.validate(false).is_err());
    owner.pool.close().await;
    runtime.pool.close().await;
    Ok(())
}
