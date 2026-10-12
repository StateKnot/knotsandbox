//! Real PostgreSQL authorization at the public lifecycle boundary.
#[allow(dead_code)]
mod support;
use axum::http::StatusCode;
use sandbox_platform::{domain::InstanceAction, model::StartRequest};
use support::{Fixture, api_failure};

async fn grant(f: &Fixture, action: &str, enabled: bool) -> anyhow::Result<()> {
    let mut tx = f.owner_transaction().await?;
    sqlx::query(
        "UPDATE grants SET enabled=$3 WHERE tenant_id=$1 AND principal_id=$2 AND action=$4",
    )
    .bind(f.actor.tenant_id)
    .bind(f.actor.principal_id)
    .bind(enabled)
    .bind(action)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL runtime and migration roles"]
async fn whole_vm_actions_require_both_scopes_and_revocation_blocks_replay() -> anyhow::Result<()> {
    let _serial = support::serial().await;
    for (action, permission) in [
        (InstanceAction::Stop, "instances:stop"),
        (InstanceAction::Delete, "instances:delete"),
        (InstanceAction::Restart, "instances:restart"),
    ] {
        let f = Fixture::new(5).await?;
        let created = f
            .create("lifecycle-auth-create")
            .await
            .map_err(api_failure)?;
        let instance = created.body.resource;
        f.seed_observed_state(instance.id, "RUNNING").await?;
        // Even an empty managed activity slot can contain background guest work.
        assert!(!instance.slot_held);
        grant(&f, "instances:hard_stop", false).await?;
        let denied = f
            .database
            .lifecycle_action(
                &f.actor,
                instance.id,
                action,
                &StartRequest::default(),
                "lifecycle-action",
                instance.spec_version,
                300,
                86400,
            )
            .await;
        assert!(matches!(denied,Err(error) if error.status==StatusCode::NOT_FOUND));
        assert_eq!(
            f.count("operations").await?,
            1,
            "denial must not reserve an operation"
        );
        grant(&f, "instances:hard_stop", true).await?;
        grant(&f, permission, false).await?;
        let denied = f
            .database
            .lifecycle_action(
                &f.actor,
                instance.id,
                action,
                &StartRequest::default(),
                "lifecycle-action",
                instance.spec_version,
                300,
                86400,
            )
            .await;
        assert!(matches!(denied,Err(error) if error.status==StatusCode::NOT_FOUND));
        grant(&f, permission, true).await?;
        let accepted = f
            .database
            .lifecycle_action(
                &f.actor,
                instance.id,
                action,
                &StartRequest::default(),
                "lifecycle-action",
                instance.spec_version,
                300,
                86400,
            )
            .await
            .map_err(api_failure)?;
        let replay = f
            .database
            .lifecycle_action(
                &f.actor,
                instance.id,
                action,
                &StartRequest::default(),
                "lifecycle-action",
                instance.spec_version,
                300,
                86400,
            )
            .await
            .map_err(api_failure)?;
        assert_eq!(accepted.body.operation.id, replay.body.operation.id);
        for revoked in ["instances:hard_stop", permission] {
            grant(&f, revoked, false).await?;
            let denied = f
                .database
                .lifecycle_action(
                    &f.actor,
                    instance.id,
                    action,
                    &StartRequest::default(),
                    "lifecycle-action",
                    instance.spec_version,
                    300,
                    86400,
                )
                .await;
            assert!(matches!(denied,Err(error) if error.status==StatusCode::NOT_FOUND));
            grant(&f, revoked, true).await?;
        }
        assert_eq!(
            f.count("operations").await?,
            2,
            "authorization denial must not repeat a side effect"
        );
    }
    Ok(())
}
