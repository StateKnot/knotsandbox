//! Test-only historical database preparation, never a production migration mode.
//! Runs the real SQLx migrator against an empty, explicitly owned TLS fixture.
use std::{borrow::Cow, env, path::Path};

use anyhow::ensure;
use sqlx::{migrate::Migrator, postgres::PgPoolOptions};
use url::Url;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let raw = env::var("TEST_MIGRATION_DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("TEST_MIGRATION_DATABASE_URL is required"))?;
    let url = Url::parse(&raw).map_err(|_| anyhow::anyhow!("Invalid fixture database URL"))?;
    let database = url.path().strip_prefix('/').unwrap_or_default();
    let query: Vec<_> = url.query_pairs().collect();
    ensure!(
        matches!(url.scheme(), "postgres" | "postgresql")
            && url.host_str() == Some("127.0.0.1")
            && url.port().is_some()
            && url.username() == "sandbox_owner"
            && url.password().is_some_and(|password| !password.is_empty())
            && database.ends_with("_test")
            && database
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            && url.fragment().is_none()
            && query.len() == 2
            && query
                .iter()
                .filter(|(key, value)| key == "sslmode" && value == "verify-full")
                .count()
                == 1
            && query
                .iter()
                .filter(|(key, value)| key == "sslrootcert"
                    && Path::new(value.as_ref()).is_absolute()
                    && Path::new(value.as_ref()).is_file())
                .count()
                == 1,
        "Only literal loopback, verify-full, sandbox_owner and an explicit *_test fixture are allowed"
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&raw)
        .await
        .map_err(|_| anyhow::anyhow!("Cannot connect to the isolated TLS upgrade fixture"))?;
    let identity: (String, String, bool, bool) = sqlx::query_as(
        "SELECT session_user::text,current_user::text,r.rolsuper OR r.rolbypassrls OR r.rolcreatedb OR r.rolcreaterole,s.ssl FROM pg_roles r JOIN pg_stat_ssl s ON s.pid=pg_backend_pid() WHERE r.rolname=session_user",
    ).fetch_one(&pool).await?;
    ensure!(
        identity == ("sandbox_owner".into(), "sandbox_owner".into(), false, true),
        "Exact unprivileged authenticated sandbox_owner and actual TLS are required"
    );
    let relations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'",
    ).fetch_one(&pool).await?;
    ensure!(
        relations == 0,
        "Historical preparation requires a fresh empty public schema"
    );
    let all = sqlx::migrate!("./migrations");
    let historical = Migrator {
        migrations: Cow::Owned(
            all.iter()
                .filter(|migration| migration.version <= 44)
                .cloned()
                .collect(),
        ),
        ..Migrator::DEFAULT
    };
    historical.run(&pool).await?;
    pool.close().await;
    println!("RESOURCE_ACCOUNTING_V44_SQLX_PREFIX_PREPARED");
    Ok(())
}
