#[allow(dead_code)]
mod support;

use anyhow::{Context, ensure};
use support::{Fixture, api_failure};
use uuid::Uuid;

#[tokio::test]
#[ignore = "Requires real PostgreSQL and both TEST_*DATABASE_URL credentials"]
async fn operations_reject_a_workspace_not_bound_to_their_instance() -> anyhow::Result<()> {
    let _test_scope = support::serial().await;
    let fixture = Fixture::new(10).await?;
    let first = fixture.create("binding-first").await.map_err(api_failure)?;
    let second = fixture
        .create("binding-second")
        .await
        .map_err(api_failure)?;
    let mut tx = fixture
        .database
        .begin(fixture.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    let result = sqlx::query("INSERT INTO operations(id,tenant_id,project_id,instance_id,workspace_id,kind,request,actor_principal_id,request_id,deadline) VALUES($1,$2,$3,$4,$5,'RENEW','{}'::jsonb,$6,$7,clock_timestamp()+interval '5 minutes')")
        .bind(Uuid::new_v4())
        .bind(fixture.actor.tenant_id)
        .bind(fixture.request.project_id)
        .bind(first.body.resource.id)
        .bind(second.body.resource.workspace_id)
        .bind(fixture.actor.principal_id)
        .bind(Uuid::new_v4())
        .execute(&mut *tx)
        .await;
    // The original foreign keys are deferred. Force them before rolling the
    // transaction back, without leaving a corrupt operation in the shared DB.
    let result = match result {
        Ok(_) => {
            sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
                .execute(&mut *tx)
                .await
        }
        Err(error) => Err(error),
    };
    tx.rollback().await?;
    let error = result.err().context(
        "Database accepted an operation for instance A bound to instance B's workspace in the same project",
    )?;
    let code = error
        .as_database_error()
        .and_then(|error| error.code())
        .context("Expected a database binding constraint error")?;
    ensure!(
        matches!(code.as_ref(), "23503" | "23514"),
        "Expected a binding FK/check violation; got SQLSTATE {code}"
    );
    Ok(())
}
