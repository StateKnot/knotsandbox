//! Project authority is delegated through the real management API/functions;
//! owner setup only provides the manager and tenant integration identity.
use crate::{
    db::{Actor, Database},
    grants::{CreateGrant, ProjectGrant},
    test_support_db::api_failure,
};
use anyhow::Context;
use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;
pub(super) struct Delegated {
    pub actor: Actor,
    pub source_restore: ProjectGrant,
}
pub(super) async fn create(
    database: &Database,
    owner: &PgPool,
    manager: &Actor,
    source: Uuid,
    target: Uuid,
) -> anyhow::Result<Delegated> {
    let principal = Uuid::new_v4();
    let mut tx = owner.begin().await?;
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(manager.tenant_id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO principals(id,kind,display_name) VALUES($1,'SERVICE','Delegated restore caller')").bind(principal).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO tenant_principals(tenant_id,principal_id,display_name) VALUES($1,$2,'Delegated restore caller')").bind(manager.tenant_id).bind(principal).execute(&mut *tx).await?;
    for action in [
        "backups:read",
        "backups:restore",
        "instances:create",
        "restores:read",
    ] {
        sqlx::query(
            "INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,NULL,$2,$3)",
        )
        .bind(manager.tenant_id)
        .bind(principal)
        .bind(action)
        .execute(&mut *tx)
        .await?;
    }
    for project in [source, target] {
        for action in ["grants:read", "grants:write"] {
            sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action,expires_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING").bind(manager.tenant_id).bind(project).bind(manager.principal_id).bind(action).bind(Utc::now()+Duration::hours(2)).execute(&mut *tx).await?;
        }
    }
    tx.commit().await?;
    for expiry in [None, Some(Utc::now() + Duration::hours(3))] {
        assert!(
            database
                .create_project_grant(
                    manager,
                    source,
                    &CreateGrant {
                        principal_id: principal,
                        action: "backups:restore".into(),
                        expires_at: expiry
                    },
                    &Uuid::new_v4().to_string()
                )
                .await
                .is_err(),
            "delegation cannot exceed the current manager expiry"
        );
    }
    let mut source_restore = None;
    for (project, action) in [
        (source, "backups:read"),
        (source, "backups:restore"),
        (target, "instances:create"),
        (target, "restores:read"),
    ] {
        let expiry = if action == "backups:restore" {
            Utc::now() + Duration::seconds(1)
        } else {
            Utc::now() + Duration::hours(1)
        };
        let grant = database
            .create_project_grant(
                manager,
                project,
                &CreateGrant {
                    principal_id: principal,
                    action: action.into(),
                    expires_at: Some(expiry),
                },
                &format!("restore-delegate-{action}"),
            )
            .await
            .map_err(api_failure)?
            .body
            .resource;
        if action == "backups:restore" {
            source_restore = Some(grant);
        }
    }
    Ok(Delegated {
        actor: Actor {
            authorization: None,
            tenant_id: manager.tenant_id,
            principal_id: principal,
            request_id: Uuid::new_v4(),
        },
        source_restore: source_restore.context("real source restore grant")?,
    })
}
