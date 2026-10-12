use std::{borrow::Cow, env, time::Duration};

use anyhow::{Context, ensure};
use sandbox_platform::{db::Database, engine::OperationEngine};
use sqlx::{
    PgPool,
    migrate::Migrator,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use url::Url;
use uuid::Uuid;

struct LocalTarget {
    host: String,
    port: u16,
    owner_password: String,
}

impl LocalTarget {
    fn parse(raw: &str) -> anyhow::Result<Self> {
        let url = Url::parse(raw).context("Invalid TEST_MIGRATION_DATABASE_URL")?;
        let host = match url.host_str() {
            Some("127.0.0.1") => "127.0.0.1",
            Some("[::1]") => "::1",
            _ => anyhow::bail!("Migration upgrade tests require a literal loopback database host"),
        };
        let parent = url.path().strip_prefix('/').unwrap_or("");
        ensure!(
            matches!(url.scheme(), "postgres" | "postgresql")
                && parent.ends_with("_test")
                && parent
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && url.username() == "sandbox_owner"
                && url.query().is_none()
                && url.fragment().is_none(),
            "Upgrade tests require sandbox_owner and a plain local *_test parent URL"
        );
        let owner_password = url
            .password()
            .context("Owner password is required")?
            .to_owned();
        ensure!(
            !owner_password.is_empty() && !owner_password.contains('%'),
            "Use the generated local owner password without URL escapes"
        );
        Ok(Self {
            host: host.to_owned(),
            port: url.port().unwrap_or(5432),
            owner_password,
        })
    }

    fn options(&self, user: &str, password: &str, database: &str) -> PgConnectOptions {
        // Reconstruct only the checked local target. No inherited URL query,
        // socket path, service definition, or environment-selected database.
        PgConnectOptions::new()
            .host(&self.host)
            .port(self.port)
            .username(user)
            .password(password)
            .database(database)
            .ssl_mode(PgSslMode::Disable)
            .application_name("sandbox-migration-integration")
    }
}

fn required(name: &str) -> anyhow::Result<String> {
    let value = env::var(name)
        .with_context(|| format!("{name} is required; load the local development environment"))?;
    ensure!(!value.is_empty(), "{name} must not be empty");
    Ok(value)
}

async fn connect(options: PgConnectOptions) -> anyhow::Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET statement_timeout='30s'")
                    .execute(&mut *connection)
                    .await?;
                sqlx::query("SET lock_timeout='5s'")
                    .execute(&mut *connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(options)
        .await
        .map_err(|_| {
            anyhow::anyhow!("Cannot connect to the isolated local migration test database")
        })
}

#[tokio::test]
#[ignore = "Requires local TEST_MIGRATION_DATABASE_URL and SANDBOX_POSTGRES_ADMIN_PASSWORD"]
async fn upgrade_from_v2_backfills_durable_work_and_preserves_forced_rls() -> anyhow::Result<()> {
    let target = LocalTarget::parse(&required("TEST_MIGRATION_DATABASE_URL")?)?;
    let admin_password = required("SANDBOX_POSTGRES_ADMIN_PASSWORD")?;
    let admin = connect(target.options("sandbox_dev_admin", &admin_password, "postgres")).await?;
    // The sole interpolated SQL identifier is generated here, never taken from
    // environment/input or discovered by enumerating the user's databases.
    let name = format!("sandbox_migration_{}", Uuid::new_v4().simple());
    let created = sqlx::query(&format!("CREATE DATABASE \"{name}\" OWNER sandbox_owner"))
        .execute(&admin)
        .await;
    if let Err(error) = created {
        admin.close().await;
        return Err(error).context("Could not create the dedicated migration test database");
    }
    let outcome = async {
        sqlx::query(&format!("REVOKE ALL ON DATABASE \"{name}\" FROM PUBLIC"))
            .execute(&admin)
            .await?;
        let owner = connect(target.options("sandbox_owner", &target.owner_password, &name)).await?;
        let result = exercise_upgrade(&owner).await;
        owner.close().await;
        result
    }
    .await;
    // Cleanup runs after every returned test error, after all owner connections
    // close. Never DROP a preexisting database or terminate unrelated sessions.
    let cleanup = sqlx::query(&format!("DROP DATABASE \"{name}\""))
        .execute(&admin)
        .await;
    admin.close().await;
    match (outcome, cleanup) {
        (Ok(()), Ok(_)) => Ok(()),
        (Err(error), Ok(_)) => Err(error),
        (Ok(()), Err(error)) => {
            Err(error).with_context(|| format!("Cleanup failed for temporary database {name}"))
        }
        (Err(error), Err(cleanup)) => Err(error).context(format!(
            "Cleanup also failed for temporary database {name}: {cleanup}"
        )),
    }
}

struct HistoricalData {
    tenant: Uuid,
    project: Uuid,
    epoch: Uuid,
    running: Uuid,
    queued: Uuid,
    completed_operation: Uuid,
    queued_operation: Uuid,
}

async fn exercise_upgrade(owner: &PgPool) -> anyhow::Result<()> {
    let all = sqlx::migrate!("./migrations");
    let old = Migrator {
        migrations: Cow::Owned(all.iter().filter(|m| m.version <= 2).cloned().collect()),
        ..Migrator::DEFAULT
    };
    ensure!(old.iter().map(|m| m.version).collect::<Vec<_>>() == [1, 2]);
    old.run(owner)
        .await
        .context("Cannot install historical schema v2")?;
    let fixture = seed_historical_data(owner).await?;
    let before = rls_snapshot(owner).await?;
    ensure!(
        before.len() == 16
            && before
                .iter()
                .all(|(_, enabled, forced)| *enabled && *forced),
        "Historical tenant tables must already use FORCE RLS"
    );
    let no_routing_tables: bool = sqlx::query_scalar("SELECT to_regclass('public.operation_dispatch') IS NULL AND to_regclass('public.instance_timers') IS NULL")
        .fetch_one(owner).await?;
    ensure!(
        no_routing_tables,
        "Historical state unexpectedly contains later routing indexes"
    );

    let before_dispatch_fix = Migrator {
        migrations: Cow::Owned(all.iter().filter(|m| m.version <= 17).cloned().collect()),
        ..Migrator::DEFAULT
    };
    before_dispatch_fix
        .run(owner)
        .await
        .context("Cannot upgrade to pre-fix registration queue")?;
    // Reproduce the real old trigger omission, without corrupting queue rows or
    // bypassing RLS. Only the operation's newly added clock changes here.
    let mut tx = owner.begin().await?;
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(fixture.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let expected_due:chrono::DateTime<chrono::Utc>=sqlx::query_scalar("UPDATE operations SET launch_registration_next_attempt_at=clock_timestamp()-interval '1 day' WHERE tenant_id=$1 AND id=$2 RETURNING launch_registration_next_attempt_at")
        .bind(fixture.tenant).bind(fixture.queued_operation).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    let old_due: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "SELECT launch_registration_eligible_at FROM operation_dispatch WHERE operation_id=$1",
    )
    .bind(fixture.queued_operation)
    .fetch_one(owner)
    .await?;
    ensure!(
        old_due != expected_due,
        "v17 should reproduce the historical clock mismatch"
    );
    let trigger_fix = Migrator {
        migrations: Cow::Owned(all.iter().filter(|m| m.version <= 18).cloned().collect()),
        ..Migrator::DEFAULT
    };
    trigger_fix
        .run(owner)
        .await
        .context("Cannot install immutable v18 trigger migration")?;
    let visible_tenants: i64 = sqlx::query_scalar("SELECT count(*) FROM tenants")
        .fetch_one(owner)
        .await?;
    ensure!(
        visible_tenants == 0,
        "owner without tenant context must remain subject to FORCE RLS"
    );
    let before_repair: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "SELECT launch_registration_eligible_at FROM operation_dispatch WHERE operation_id=$1",
    )
    .bind(fixture.queued_operation)
    .fetch_one(owner)
    .await?;
    ensure!(
        before_repair == old_due,
        "v18 cannot enumerate the FORCE-RLS tenant catalog for backfill"
    );
    all.run(owner)
        .await
        .context("Cannot upgrade historical schema to current migrations")?;
    let repaired: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "SELECT launch_registration_eligible_at FROM operation_dispatch WHERE operation_id=$1",
    )
    .bind(fixture.queued_operation)
    .fetch_one(owner)
    .await?;
    ensure!(
        repaired == expected_due,
        "routing-index tenant discovery must repair the legacy clock"
    );
    ensure!(
        rls_snapshot(owner).await? == before,
        "Upgrade changed ENABLE/FORCE RLS on existing tenant tables"
    );
    let mut event_tx = owner.begin().await?;
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(fixture.tenant.to_string())
        .execute(&mut *event_tx)
        .await?;
    let head: i64 = sqlx::query_scalar(
        "SELECT last_sequence FROM event_stream_heads WHERE tenant_id=$1 AND project_id=$2",
    )
    .bind(fixture.tenant)
    .bind(fixture.project)
    .fetch_one(&mut *event_tx)
    .await?;
    ensure!(
        head == 2,
        "Event stream backfill missed FORCE-RLS historical events"
    );
    let historical:Vec<(i64,Uuid)>=sqlx::query_as("SELECT p.sequence,e.aggregate_id FROM event_stream_positions p JOIN domain_events e ON e.id=p.event_id WHERE p.tenant_id=$1 AND p.project_id=$2 ORDER BY p.sequence")
        .bind(fixture.tenant).bind(fixture.project).fetch_all(&mut *event_tx).await?;
    ensure!(
        historical == [(1, fixture.running), (2, fixture.queued)],
        "Historical committed events were reordered or omitted"
    );
    event_tx.commit().await?;
    let configuration: (Uuid, bool) = sqlx::query_as(
        "SELECT cluster_epoch,safe_mode FROM platform_configuration WHERE singleton",
    )
    .fetch_one(owner)
    .await?;
    ensure!(
        configuration == (fixture.epoch, true),
        "Upgrade changed installation epoch or safe mode"
    );
    let dispatch: Vec<Uuid> =
        sqlx::query_scalar("SELECT operation_id FROM operation_dispatch ORDER BY operation_id")
            .fetch_all(owner)
            .await?;
    ensure!(
        dispatch == [fixture.queued_operation],
        "Upgrade did not recover exactly the old queued operation"
    );
    let timers: Vec<Uuid> =
        sqlx::query_scalar("SELECT instance_id FROM instance_timers ORDER BY instance_id")
            .fetch_all(owner)
            .await?;
    let mut expected_timers = vec![fixture.running, fixture.queued];
    expected_timers.sort();
    ensure!(
        timers == expected_timers,
        "Upgrade missed an instance, including a running instance whose create had completed"
    );

    // Replay the full migrator before consuming any recovered work. Its ledger,
    // queue and timers must be unchanged; SQLx validates historical checksums.
    let ledger: Vec<(i64, Vec<u8>, bool)> =
        sqlx::query_as("SELECT version,checksum,success FROM _sqlx_migrations ORDER BY version")
            .fetch_all(owner)
            .await?;
    ensure!(ledger.len() == all.iter().count() && ledger.iter().all(|(_, _, success)| *success));
    all.run(owner)
        .await
        .context("Re-running current migrations failed")?;
    let replayed: Vec<(i64, Vec<u8>, bool)> =
        sqlx::query_as("SELECT version,checksum,success FROM _sqlx_migrations ORDER BY version")
            .fetch_all(owner)
            .await?;
    ensure!(ledger == replayed, "Migration replay rewrote the ledger");
    let indexes: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM operation_dispatch),(SELECT count(*) FROM instance_timers)",
    )
    .fetch_one(owner)
    .await?;
    ensure!(
        indexes == (1, 2),
        "Migration replay duplicated recovery work"
    );

    let database = Database {
        pool: owner.clone(),
    };
    let engine = OperationEngine::new(database.clone(), "migration-upgrade-test".to_owned())?;
    let claimed = engine
        .claim()
        .await
        .map_err(api_error)?
        .context("Historical queued work was not claimable")?;
    ensure!(
        claimed.tenant_id == fixture.tenant
            && claimed.operation_id == fixture.queued_operation
            && claimed.lease_token == 1
    );
    ensure!(
        engine.claim().await.map_err(api_error)?.is_none(),
        "Completed or already leased historical work was claimed"
    );
    let due = database.due_instances().await.map_err(api_error)?;
    ensure!(
        due.len() == 2
            && due.contains(&(fixture.tenant, fixture.running))
            && due.contains(&(fixture.tenant, fixture.queued))
    );

    let hidden: i64 = sqlx::query_scalar("SELECT count(*) FROM instances")
        .fetch_one(owner)
        .await?;
    ensure!(
        hidden == 0,
        "Migration or worker claim leaked tenant context into the owner pool"
    );
    let mut tx = database.begin(Uuid::new_v4()).await.map_err(api_error)?;
    let foreign: i64 = sqlx::query_scalar("SELECT count(*) FROM instances")
        .fetch_one(&mut *tx)
        .await?;
    ensure!(
        foreign == 0,
        "FORCE RLS allowed a different tenant to read historical data"
    );
    tx.commit().await?;
    let mut tx = database.begin(fixture.tenant).await.map_err(api_error)?;
    let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM instances")
        .fetch_one(&mut *tx)
        .await?;
    ensure!(
        visible == 2,
        "Historical instance rows were lost during migration"
    );
    let completed: String = sqlx::query_scalar("SELECT status FROM operations WHERE id=$1")
        .bind(fixture.completed_operation)
        .fetch_one(&mut *tx)
        .await?;
    ensure!(
        completed == "SUCCEEDED",
        "Completed historical create was changed by migration or claim"
    );
    tx.commit().await?;
    Ok(())
}

fn api_error(error: sandbox_platform::error::ApiError) -> anyhow::Error {
    anyhow::anyhow!("{}: {}", error.code, error.detail)
}

async fn rls_snapshot(owner: &PgPool) -> anyhow::Result<Vec<(String, bool, bool)>> {
    Ok(sqlx::query_as("SELECT relname::text,relrowsecurity,relforcerowsecurity FROM pg_class WHERE relnamespace='public'::regnamespace AND relname=ANY(ARRAY['tenants','projects','grants','template_versions','security_policy_versions','workspaces','instances','operations','executions','idempotency_keys','quota_accounts','quota_reservations','audit_events','audit_events_default','domain_events','external_resources']) ORDER BY relname")
        .fetch_all(owner).await?)
}

async fn seed_historical_data(owner: &PgPool) -> anyhow::Result<HistoricalData> {
    let fixture = HistoricalData {
        tenant: Uuid::new_v4(),
        project: Uuid::new_v4(),
        epoch: Uuid::new_v4(),
        running: Uuid::new_v4(),
        queued: Uuid::new_v4(),
        completed_operation: Uuid::new_v4(),
        queued_operation: Uuid::new_v4(),
    };
    let project = fixture.project;
    let principal = Uuid::new_v4();
    let template = Uuid::new_v4();
    let policy = Uuid::new_v4();
    let namespace = format!("migration-{}", project.simple());
    let mut tx = owner.begin().await?;
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(fixture.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO platform_configuration(singleton,cluster_epoch,safe_mode) VALUES(true,$1,true)").bind(fixture.epoch).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO tenants(id,name) VALUES($1,'Historical migration tenant')")
        .bind(fixture.tenant)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO principals(id,kind,display_name) VALUES($1,'SERVICE','Historical migration service')").bind(principal).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO projects(id,tenant_id,name,max_ttl_seconds,runtime_namespace,storage_class) VALUES($1,$2,'Historical migration project',3600,$3,'migration-storage')")
        .bind(project).bind(fixture.tenant).bind(&namespace).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO template_versions(id,tenant_id,name,version,image_ref,image_digest,runner_version,status) VALUES($1,$2,'historical',1,'registry.example.test/historical',$3,'historical','APPROVED')")
        .bind(template).bind(fixture.tenant).bind(format!("sha256:{}", "a".repeat(64))).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO security_policy_versions(id,tenant_id,name,version,status,rules) VALUES($1,$2,'historical',1,'APPROVED','{}'::jsonb)")
        .bind(policy).bind(fixture.tenant).execute(&mut *tx).await?;
    for (instance, operation, completed) in [
        (fixture.running, fixture.completed_operation, true),
        (fixture.queued, fixture.queued_operation, false),
    ] {
        let workspace = Uuid::new_v4();
        sqlx::query("INSERT INTO workspaces(id,tenant_id,project_id,size_gib,storage_class,namespace,pvc_name,status) VALUES($1,$2,$3,20,'migration-storage',$4,$5,$6)")
            .bind(workspace).bind(fixture.tenant).bind(project).bind(&namespace).bind(format!("ws-{workspace}")).bind(if completed { "IN_USE" } else { "PENDING" }).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO instances(id,tenant_id,project_id,name,template_version_id,security_policy_version_id,workspace_id,cpu_millis,memory_mib,desired_state,observed_state,cluster_epoch,launch_id,namespace,pod_name,active_operation_id,compute_lease_id,compute_lease_started_at,compute_lease_expires_at) VALUES($1,$2,$3,'historical-instance',$4,$5,$6,1000,2048,'RUNNING',$7,$8,$9,$10,$11,$12,$13,'1970-01-01T00:00:00Z','1970-01-01T00:01:00Z')")
            .bind(instance).bind(fixture.tenant).bind(project).bind(template).bind(policy).bind(workspace).bind(if completed { "RUNNING" } else { "PENDING" }).bind(fixture.epoch).bind(Uuid::new_v4()).bind(&namespace).bind(format!("sbx-ws-{workspace}")).bind(if completed { None } else { Some(operation) }).bind(Uuid::new_v4()).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO operations(id,tenant_id,project_id,instance_id,workspace_id,kind,request,actor_principal_id,request_id,deadline,status,completed_at) VALUES($1,$2,$3,$4,$5,'CREATE','{}'::jsonb,$6,$7,'1970-01-01T00:01:00Z',$8,CASE WHEN $9 THEN clock_timestamp() ELSE NULL END)")
            .bind(operation).bind(fixture.tenant).bind(project).bind(instance).bind(workspace).bind(principal).bind(Uuid::new_v4()).bind(if completed { "SUCCEEDED" } else { "QUEUED" }).bind(completed).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload,occurred_at) VALUES($1,$2,$3,1,'historical.created',$4,$5,'{}',CASE WHEN $6 THEN '2000-01-01T00:00:00Z'::timestamptz ELSE '2000-01-01T00:00:01Z'::timestamptz END)")
            .bind(fixture.tenant).bind(project).bind(instance).bind(operation).bind(Uuid::new_v4()).bind(completed).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(fixture)
}

#[test]
fn destructive_upgrade_test_refuses_nonlocal_or_nontest_targets() {
    for target in [
        "postgres://sandbox_owner:test-only@database.example.test/sandbox_test",
        "postgres://sandbox_owner:test-only@localhost/sandbox_test",
        "postgres://sandbox_owner:test-only@127.0.0.1/sandbox_dev",
        "postgres://sandbox_owner:test-only@127.0.0.1/sandbox_test?host=elsewhere",
        "postgres://other_role:test-only@127.0.0.1/sandbox_test",
    ] {
        assert!(LocalTarget::parse(target).is_err());
    }
    assert!(
        LocalTarget::parse("postgres://sandbox_owner:test-only@127.0.0.1:55432/sandbox_test")
            .is_ok()
    );
    assert!(
        LocalTarget::parse("postgres://sandbox_owner:test-only@[::1]:55432/sandbox_test").is_ok()
    );
}
