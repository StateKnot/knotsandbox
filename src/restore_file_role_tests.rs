//! Actual product acceptance creates the metadata row; dedicated backup
//! credentials can read its own tenant but cannot read payloads or mutate it.
use crate::{
    db::Database, termination_ledger::tests::FixtureRuntime, test_support_db::api_failure,
};
use serde_json::json;
use uuid::Uuid;
pub(super) async fn run(
    base: &FixtureRuntime,
    backup: &Database,
    instance: Uuid,
    project: Uuid,
) -> anyhow::Result<()> {
    let f = &base.f;
    let mut tx = f.owner_transaction().await?;
    for scope in [None, Some(project)] {
        for action in ["files:read", "instances:hard_stop"] {
            sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
                .bind(f.actor.tenant_id).bind(scope).bind(f.actor.principal_id).bind(action).execute(&mut *tx).await?;
        }
        for dimension in ["FILE_TRANSFERS", "FILE_TRANSFER_BYTES"] {
            sqlx::query("INSERT INTO quota_accounts(tenant_id,project_id,dimension,limit_value) VALUES($1,$2,$3,100) ON CONFLICT DO NOTHING")
                .bind(f.actor.tenant_id).bind(scope).bind(dimension).execute(&mut *tx).await?;
        }
    }
    tx.commit().await?;
    let current = f
        .database
        .get_instance(&f.actor, instance)
        .await
        .map_err(api_failure)?;
    let request = serde_json::from_value(
        json!({"direction":"DOWNLOAD","path":"verification.txt","max_bytes":1,"timeout_seconds":30}),
    )?;
    let accepted = f
        .database
        .create_file_transfer(
            &f.actor,
            instance,
            &request,
            "restore-real-metadata-permissions",
            current.spec_version,
            1,
        )
        .await
        .map_err(api_failure)?;
    let id = accepted.body.resource.id;
    for (tenant, count) in [(f.actor.tenant_id, 1_i64), (Uuid::new_v4(), 0)] {
        let mut tx = backup.begin(tenant).await.map_err(api_failure)?;
        let actual: i64 = sqlx::query_scalar("SELECT count(*) FROM file_transfers WHERE id=$1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(actual, count);
        tx.commit().await?;
    }
    for statement in [
        "SELECT * FROM file_transfer_parts WHERE transfer_id=$1",
        "UPDATE file_transfers SET status=status WHERE id=$1",
        "UPDATE instances SET desired_state=desired_state WHERE id=$1",
    ] {
        let mut tx = backup.begin(f.actor.tenant_id).await.map_err(api_failure)?;
        let result = sqlx::query(statement)
            .bind(if statement.contains("instances") {
                instance
            } else {
                id
            })
            .execute(&mut *tx)
            .await;
        assert!(
            matches!(result,Err(sqlx::Error::Database(ref e)) if e.code().as_deref()==Some("42501")),
            "dedicated backup must receive actual insufficient privilege"
        );
        tx.rollback().await?;
    }
    eprintln!(
        "VERIFIED actual file acceptance on restored RUNNING workspace, backup own-tenant metadata SELECT, foreign-tenant RLS invisibility, parts/file UPDATE/instance UPDATE permission denial"
    );
    Ok(())
}
