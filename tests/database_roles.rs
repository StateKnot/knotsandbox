#[allow(dead_code)]
mod support;

use anyhow::{Context, ensure};
use sandbox_platform::db::Database;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use support::Fixture;
use url::Url;

const COMPONENTS: [&str; 8] = [
    "sandbox_app",
    "sandbox_worker",
    "sandbox_gateway",
    "sandbox_admission",
    "sandbox_termination",
    "sandbox_fencing",
    "sandbox_volume_deleter",
    "sandbox_backup",
];

#[tokio::test]
#[ignore = "requires explicit local disposable PostgreSQL and sandbox_dev_admin credentials"]
async fn runtime_rejects_noinherit_set_role_memberships_and_hidden_admin_login()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let target = Url::parse(
        &std::env::var("TEST_MIGRATION_DATABASE_URL")
            .context("TEST_MIGRATION_DATABASE_URL is required")?,
    )?;
    let host = match target.host_str() {
        Some("127.0.0.1") => "127.0.0.1",
        Some("[::1]") => "::1",
        _ => anyhow::bail!("Role integration requires a literal loopback PostgreSQL host"),
    };
    let name = target.path().strip_prefix('/').unwrap_or("");
    ensure!(
        matches!(target.scheme(), "postgres" | "postgresql")
            && target.username() == "sandbox_owner"
            && name.ends_with("_test")
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && target.query().is_none()
            && target.fragment().is_none(),
        "Role integration requires the generated local owner URL and a *_test database"
    );
    let password = std::env::var("SANDBOX_POSTGRES_ADMIN_PASSWORD")
        .context("SANDBOX_POSTGRES_ADMIN_PASSWORD is required")?;
    ensure!(!password.is_empty(), "Local admin password is empty");
    let fixture = Fixture::new(1).await?;
    for script in [
        include_str!("../scripts/sql/worker-role.sql"),
        include_str!("../scripts/sql/gateway-role.sql"),
        include_str!("../scripts/sql/admission-role.sql"),
        include_str!("../scripts/sql/termination-role.sql"),
        include_str!("../scripts/sql/fencing-role.sql"),
        include_str!("../scripts/sql/volume-deleter-role.sql"),
        include_str!("../scripts/sql/backup-role.sql"),
    ] {
        sqlx::raw_sql(script).execute(&fixture.owner).await?;
    }
    // Exactly one physical connection is intentional. The public Database method
    // sees the same uncommitted GRANT and session identity as the test setup.
    // No membership ever commits; connection loss also rolls it back.
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .min_connections(1)
        .max_lifetime(None)
        .idle_timeout(None)
        .connect_with(
            PgConnectOptions::new()
                .host(host)
                .port(target.port().unwrap_or(5432))
                .username("sandbox_dev_admin")
                .password(&password)
                .database(name)
                .ssl_mode(PgSslMode::Disable),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Cannot connect to the dedicated local role test database"))?;
    let database = Database { pool: pool.clone() };
    sqlx::query("BEGIN").execute(&pool).await?;
    let outcome = async {
        for role in COMPONENTS {
            // The interpolated identifiers are fixed compile-time constants.
            sqlx::query(&format!("SET SESSION AUTHORIZATION {role}")).execute(&pool).await?;
            database.verify_runtime_role().await.with_context(|| format!("baseline runtime role {role}"))?;
            sqlx::query("RESET SESSION AUTHORIZATION").execute(&pool).await?;
        }
        for (index, member) in COMPONENTS.iter().enumerate() {
            for granted in &COMPONENTS[index+1..] {
                sqlx::query(&format!("GRANT {granted} TO {member} WITH INHERIT FALSE")).execute(&pool).await?;
                // SET defaults true, but state it separately for a visible contract.
                sqlx::query(&format!("GRANT {granted} TO {member} WITH SET TRUE")).execute(&pool).await?;
                let flags:(bool,bool,bool)=sqlx::query_as("SELECT pg_has_role($1,$2,'MEMBER'),pg_has_role($1,$2,'USAGE'),pg_has_role($1,$2,'SET')")
                    .bind(member).bind(granted).fetch_one(&pool).await?;
                ensure!(flags==(true,false,true), "Expected MEMBER without INHERIT but with SET ROLE");
                for role in [*member,*granted] {
                    sqlx::query(&format!("SET SESSION AUTHORIZATION {role}")).execute(&pool).await?;
                    ensure!(database.verify_runtime_role().await.is_err(), "Cross-component membership accepted: {member} -> {granted} as {role}");
                    sqlx::query("RESET SESSION AUTHORIZATION").execute(&pool).await?;
                }
                sqlx::query(&format!("REVOKE {granted} FROM {member}")).execute(&pool).await?;
            }
        }
        sqlx::query("SET ROLE sandbox_app").execute(&pool).await?;
        ensure!(database.verify_runtime_role().await.is_err(), "SET ROLE must not hide the privileged session login");
        sqlx::query("RESET ROLE").execute(&pool).await?;
        Ok::<(),anyhow::Error>(())
    }.await;
    let cleanup = sqlx::query("ROLLBACK").execute(&pool).await;
    pool.close().await;
    match (outcome, cleanup) {
        (result, Ok(_)) => result,
        (Ok(()), Err(error)) => Err(error).context("Role-test transaction rollback failed"),
        (Err(error), Err(cleanup)) => {
            Err(error).context(format!("Role-test rollback also failed: {cleanup}"))
        }
    }
}
