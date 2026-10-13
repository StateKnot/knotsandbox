//! Real TLS PostgreSQL regression for cancellation inside BEGIN's round trip.
//! No driver hooks, altered transaction depth, privileged runtime or retry.
use crate::test_support_db::{Fixture, serial};
use anyhow::{anyhow, ensure};
use sqlx::{Connection, PgConnection};
use std::time::Duration;
use tokio::time::Instant;
use uuid::Uuid;

fn database_error(_: sqlx::Error) -> anyhow::Error {
    // Never emit connection URLs, credentials or PostgreSQL query text.
    anyhow!("DB_BEGIN_CANCEL_DATABASE_OPERATION_FAILED")
}

async fn entered_begin(observer: &mut PgConnection, pid: i32) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let entered: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 \
             AND usename=current_user AND state='active' AND xact_start IS NOT NULL \
             AND wait_event_type='Timeout' AND wait_event='PgSleep')",
        )
        .bind(pid)
        .fetch_one(&mut *observer)
        .await
        .map_err(database_error)?;
        if entered {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "DB_BEGIN_CANCEL_SERVER_WINDOW_NOT_OBSERVED"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
#[ignore = "Requires the disposable TLS PostgreSQL fixture and separate ordinary runtime/owner logins"]
async fn cancelled_begin_returns_runtime_tls_connection_idle_and_autocommit_safe()
-> anyhow::Result<()> {
    let _serial = serial().await;
    let url = std::env::var("TEST_DATABASE_URL")
        .map_err(|_| anyhow!("DB_BEGIN_CANCEL_TLS_FIXTURE_REQUIRED"))?;
    let parsed =
        url::Url::parse(&url).map_err(|_| anyhow!("DB_BEGIN_CANCEL_TLS_FIXTURE_REQUIRED"))?;
    ensure!(
        parsed
            .query_pairs()
            .any(|(key, value)| key == "sslmode" && value == "verify-full"),
        "DB_BEGIN_CANCEL_VERIFY_FULL_REQUIRED"
    );
    let verified = Fixture::prepare_verified_connections().await?;
    let fixture = Fixture::new_with_verified_connections(1, &verified).await?;
    let target = verified
        .runtime("TEST_DATABASE_URL", "sandbox_app", 1)
        .await?
        .database();
    let observer = verified
        .runtime("TEST_DATABASE_URL", "sandbox_app", 1)
        .await?
        .database();
    let result = async {
        let mut connection = target.pool.acquire().await.map_err(database_error)?;
        let (pid, secured): (i32, bool) = sqlx::query_as(
            "SELECT pg_backend_pid(), session_user='sandbox_app' AND \
             EXISTS(SELECT 1 FROM pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl)",
        ).fetch_one(&mut *connection).await.map_err(database_error)?;
        ensure!(secured, "DB_BEGIN_CANCEL_RUNTIME_TLS_REQUIRED");
        drop(connection);
        let mut observation = observer.pool.acquire().await.map_err(database_error)?;
        let (observer_pid, observer_secured): (i32, bool) = sqlx::query_as(
            "SELECT pg_backend_pid(), session_user='sandbox_app' AND \
             EXISTS(SELECT 1 FROM pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl)",
        ).fetch_one(&mut *observation).await.map_err(database_error)?;
        ensure!(observer_secured && observer_pid != pid, "DB_BEGIN_CANCEL_INDEPENDENT_RUNTIME_TLS_OBSERVER_REQUIRED");

        // The upstream regression uses this real simple-query round trip: the
        // server executes BEGIN before the sleep, while the driver awaits Ready.
        let mut opening = Box::pin(target.pool.begin_with("BEGIN; SELECT pg_sleep(2);"));
        tokio::select! {
            result = &mut opening => {
                let transaction = result.map_err(database_error)?;
                transaction.rollback().await.map_err(database_error)?;
                return Err(anyhow!("DB_BEGIN_CANCEL_FINISHED_BEFORE_SERVER_OBSERVATION"));
            }
            result = entered_begin(&mut observation, pid) => result?,
        }
        eprintln!("DB_BEGIN_CANCEL_SERVER_TRANSACTION_OBSERVED");
        drop(opening); // Cancel the actual future; ordinary pool Drop owns cleanup.

        let mut reused = target.pool.acquire().await.map_err(database_error)?;
        let reused_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *reused).await.map_err(database_error)?;
        ensure!(reused_pid == pid, "DB_BEGIN_CANCEL_SAME_PHYSICAL_CONNECTION_REQUIRED");
        let (state, no_transaction): (String, bool) = sqlx::query_as(
            "SELECT state,xact_start IS NULL FROM pg_stat_activity WHERE pid=$1 AND usename=current_user",
        ).bind(pid).fetch_one(&mut *observation).await.map_err(database_error)?;

        let audit_id = Uuid::new_v4();
        let nonce = Uuid::new_v4();
        let lock = i64::from_be_bytes(nonce.as_bytes()[..8].try_into()
            .map_err(|_| anyhow!("DB_BEGIN_CANCEL_LOCK_ID_INVALID"))?);
        // A single ordinary statement must autocommit its existing-table write
        // and release its xact lock. Do not BEGIN/COMMIT/ROLLBACK the reused pool.
        sqlx::query(
            "WITH context AS MATERIALIZED(SELECT set_config('app.tenant_id',$1,true), \
             pg_advisory_xact_lock($2)) \
             INSERT INTO audit_events(id,tenant_id,actor_principal_id,request_id,action,outcome) \
             SELECT $3,$4,$5,$6,'db:cancel_begin_probe','SUCCEEDED' FROM context",
        ).bind(fixture.actor.tenant_id.to_string()).bind(lock).bind(audit_id)
            .bind(fixture.actor.tenant_id).bind(fixture.actor.principal_id).bind(Uuid::new_v4())
            .execute(&mut *reused).await.map_err(database_error)?;
        drop(reused);
        let mut observed = observation.begin().await.map_err(database_error)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(fixture.actor.tenant_id.to_string())
            .execute(&mut *observed)
            .await
            .map_err(database_error)?;
        let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND id=$2")
            .bind(fixture.actor.tenant_id).bind(audit_id).fetch_one(&mut *observed).await.map_err(database_error)?;
        let unlocked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
            .bind(lock).fetch_one(&mut *observed).await.map_err(database_error)?;
        observed.rollback().await.map_err(database_error)?;
        // Collect independent write/lock facts before the first RED assertion.
        ensure!((0..=1).contains(&visible), "DB_BEGIN_CANCEL_AUTOCOMMIT_WITNESS_NOT_UNIQUE");
        eprintln!("DB_BEGIN_CANCEL_FACTS server_idle={} no_transaction={} followup_visible={} advisory_lock_released={}",
            state == "idle", no_transaction, visible, unlocked);
        ensure!(state == "idle" && no_transaction, "DB_BEGIN_CANCEL_RETURNED_CONNECTION_NOT_IDLE");
        ensure!(visible == 1, "DB_BEGIN_CANCEL_FOLLOWUP_WRITE_NOT_AUTOCOMMITTED");
        ensure!(unlocked, "DB_BEGIN_CANCEL_FOLLOWUP_TRANSACTION_LOCK_LEAKED");
        eprintln!("DB_BEGIN_CANCEL_RUNTIME_TLS_POOL_CLEAN_VERIFIED");
        Ok(())
    }.await;
    target.pool.close().await;
    observer.pool.close().await;
    fixture.database.pool.close().await;
    fixture.owner.close().await;
    result
}
