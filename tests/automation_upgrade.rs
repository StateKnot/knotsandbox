//! A frozen schema/ACL contract upgrade, not a claim about a released old binary.
//! The runner supplies one freshly created TLS database. This suite never uses
//! an administrator, creates/drops a database, clears data, or bypasses RLS.
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    env,
    path::Path,
    str::FromStr,
    time::Duration,
};

use anyhow::{Context, ensure};
use axum::http::StatusCode;
use sandbox_platform::{
    db::{Actor, Database},
    history::{CursorSigner, HistoryQuery},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{
    Connection, PgPool, Postgres, Transaction,
    migrate::{MigrateError, Migrator},
    postgres::{PgConnectOptions, PgPoolOptions},
};
use url::Url;
use uuid::Uuid;

const VERIFIED: &str = "AUTO_UPGRADE_V41_CURRENT_FACTS_OLD_MIGRATOR_REFUSAL_VERIFIED";
const STATE_VERIFIED: &str =
    "AUTO_UPGRADE_NONEMPTY_HISTORY_SCHEMA42_ACK_CURRENT_REPLAY_REVOKE_VERIFIED";
const PROGRESSION_VERIFIED: &str =
    "AUTO_UPGRADE_UNKNOWN_FAILED_DISTINCT_SOURCES_ACK_REPLAY_ISOLATION_VERIFIED";

#[path = "automation_upgrade/ack.rs"]
mod ack;
#[path = "automation_upgrade/history.rs"]
mod history;

fn checked_url(raw: &str, role: &str) -> anyhow::Result<Url> {
    let url = Url::parse(raw).context("Invalid upgrade database URL")?;
    let database = url.path().strip_prefix('/').unwrap_or_default();
    let query: Vec<_> = url.query_pairs().collect();
    ensure!(
        matches!(url.scheme(), "postgres" | "postgresql")
            && matches!(url.host_str(), Some("127.0.0.1" | "[::1]"))
            && url.username() == role
            && url.password().is_some_and(|p| !p.is_empty())
            && database.ends_with("_test")
            && database
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && url.fragment().is_none()
            && query.len() == 2
            && query
                .iter()
                .filter(|(k, v)| k == "sslmode" && v == "verify-full")
                .count()
                == 1
            && query
                .iter()
                .filter(|(k, v)| k == "sslrootcert" && Path::new(v.as_ref()).is_absolute())
                .count()
                == 1,
        "Upgrade tests require exact unprivileged roles, literal loopback *_test URLs and verified TLS; URL routing overrides are forbidden"
    );
    Ok(url)
}

fn checked_pair(owner: &str, app: &str) -> anyhow::Result<()> {
    checked_runtime_target(owner, app, "sandbox_app")
}

fn checked_runtime_target(owner: &str, runtime: &str, role: &str) -> anyhow::Result<()> {
    let owner = checked_url(owner, "sandbox_owner")?;
    let app = checked_url(runtime, role)?;
    ensure!(
        owner.host_str() == app.host_str()
            && owner.port_or_known_default() == app.port_or_known_default()
            && owner.path() == app.path()
            && owner
                .query_pairs()
                .find(|(k, _)| k == "sslrootcert")
                .map(|(_, v)| v)
                == app
                    .query_pairs()
                    .find(|(k, _)| k == "sslrootcert")
                    .map(|(_, v)| v),
        "Historical owner and runtime must use the same disposable TLS database and trust root"
    );
    Ok(())
}

async fn connect(raw: &str, role: &str) -> anyhow::Result<PgPool> {
    checked_url(raw, role)?;
    let pool = if role != "sandbox_owner" {
        // Real runtime connection settings: 10s statements, 3s locks and 15s
        // idle transactions. Migration maintenance limits never reach a writer.
        Database::connect(raw, 2).await?.pool
    } else {
        PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(5))
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::query("SET statement_timeout='60s'")
                        .execute(&mut *connection)
                        .await?;
                    sqlx::query("SET lock_timeout='5s'")
                        .execute(&mut *connection)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(PgConnectOptions::from_str(raw)?)
            .await
            .map_err(|_| anyhow::anyhow!("Cannot connect to the isolated upgrade TLS database"))?
    };
    let identity: (String, String, bool, bool) = sqlx::query_as(
        "SELECT session_user::text,current_user::text,r.rolsuper OR r.rolbypassrls OR r.rolcreatedb OR r.rolcreaterole,s.ssl FROM pg_roles r JOIN pg_stat_ssl s ON s.pid=pg_backend_pid() WHERE r.rolname=session_user"
    ).fetch_one(&pool).await?;
    ensure!(
        identity == (role.to_owned(), role.to_owned(), false, true),
        "Exact authenticated nonprivileged TLS login required"
    );
    Ok(pool)
}

async fn tenant_tx(pool: &PgPool, tenant: Uuid) -> anyhow::Result<Transaction<'_, Postgres>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

struct Scope {
    tenant: Uuid,
    project: Uuid,
    sibling: Uuid,
    principal: Uuid,
    instance: Uuid,
    workspace: Uuid,
    launch: Uuid,
    pod: Uuid,
    epoch: Uuid,
}

impl Scope {
    fn actor(&self) -> Actor {
        Actor {
            tenant_id: self.tenant,
            principal_id: self.principal,
            request_id: Uuid::new_v4(),
            authorization: None,
        }
    }
}

async fn seed_scope(owner: &PgPool, epoch: Uuid) -> anyhow::Result<Scope> {
    let scope = Scope {
        tenant: Uuid::new_v4(),
        project: Uuid::new_v4(),
        sibling: Uuid::new_v4(),
        principal: Uuid::new_v4(),
        instance: Uuid::new_v4(),
        workspace: Uuid::new_v4(),
        launch: Uuid::new_v4(),
        pod: Uuid::new_v4(),
        epoch,
    };
    let template = Uuid::new_v4();
    let policy = Uuid::new_v4();
    let namespace = format!("upgrade-{}", scope.project.simple());
    let mut tx = tenant_tx(owner, scope.tenant).await?;
    sqlx::query("INSERT INTO tenants(id,name) VALUES($1,'Historical automation tenant')")
        .bind(scope.tenant)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO principals(id,kind,display_name) VALUES($1,'SERVICE','Historical automation service')").bind(scope.principal).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO principal_identities(principal_id,issuer,subject,service_client_id,service_binding_generation) VALUES($1,'https://issuer.example.test',$2,'historical-client',1)").bind(scope.principal).bind(scope.principal.to_string()).execute(&mut *tx).await?;
    for project in [scope.project, scope.sibling] {
        sqlx::query("INSERT INTO projects(id,tenant_id,name,max_ttl_seconds,runtime_namespace,storage_class) VALUES($1,$2,$4,86400,$3,'upgrade-storage')").bind(project).bind(scope.tenant).bind(format!("upgrade-{}", project.simple())).bind(format!("Historical automation project {project}")).execute(&mut *tx).await?;
        for action in ["automations:read", "automations:write", "instances:renew"] {
            sqlx::query(
                "INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4)",
            )
            .bind(scope.tenant)
            .bind(project)
            .bind(scope.principal)
            .bind(action)
            .execute(&mut *tx)
            .await?;
        }
    }
    sqlx::query("INSERT INTO template_versions(id,tenant_id,name,version,image_ref,image_digest,runner_version,status) VALUES($1,$2,'historical',1,'registry.example.test/historical',$3,'historical','APPROVED')").bind(template).bind(scope.tenant).bind(format!("sha256:{}", "a".repeat(64))).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO security_policy_versions(id,tenant_id,name,version,status,rules) VALUES($1,$2,'historical',1,'APPROVED','{}')").bind(policy).bind(scope.tenant).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO workspaces(id,tenant_id,project_id,size_gib,storage_class,namespace,pvc_name,status) VALUES($1,$2,$3,20,'upgrade-storage',$4,$5,'PENDING')").bind(scope.workspace).bind(scope.tenant).bind(scope.project).bind(&namespace).bind(format!("ws-{}", scope.workspace)).execute(&mut *tx).await?;
    // Queued intent only: this is no cloud/guest/VM execution receipt.
    sqlx::query("INSERT INTO instances(id,tenant_id,project_id,name,template_version_id,security_policy_version_id,workspace_id,cpu_millis,memory_mib,desired_state,observed_state,cluster_epoch,launch_id,pod_uid,namespace,pod_name,compute_lease_id,compute_lease_started_at,compute_lease_expires_at) VALUES($1,$2,$3,'historical-instance',$4,$5,$6,1000,2048,'RUNNING','PENDING',$7,$8,$9,$10,$11,$12,clock_timestamp()-interval '3 hours',clock_timestamp()+interval '1 hour')")
        .bind(scope.instance).bind(scope.tenant).bind(scope.project).bind(template).bind(policy).bind(scope.workspace).bind(epoch).bind(scope.launch).bind(scope.pod).bind(&namespace).bind(format!("sbx-ws-{}", scope.workspace)).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    let operation = Uuid::new_v4();
    sqlx::query("INSERT INTO operations(id,tenant_id,project_id,instance_id,workspace_id,kind,request,actor_principal_id,request_id,deadline,status) VALUES($1,$2,$3,$4,$5,'FILE_TRANSFER','{}',$6,$7,clock_timestamp()+interval '1 hour','QUEUED')")
        .bind(operation).bind(scope.tenant).bind(scope.project).bind(scope.instance).bind(scope.workspace).bind(scope.principal).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO file_transfers(id,tenant_id,project_id,instance_id,workspace_id,operation_id,runtime_generation,launch_id,pod_uid,cluster_epoch,content_id,direction,path,status,byte_limit,slot_held,deadline,content_expires_at) VALUES($1,$2,$3,$4,$5,$6,1,$7,$8,$9,$10,'DOWNLOAD','historical.txt','QUEUED',1024,false,clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours')")
        .bind(Uuid::new_v4()).bind(scope.tenant).bind(scope.project).bind(scope.instance).bind(scope.workspace).bind(operation).bind(scope.launch).bind(scope.pod).bind(epoch).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(scope)
}

// Insert only legal intents, then follow the actual immutable run transition
// graph. No disabled trigger, changed RLS, or fabricated acceptance operation.
async fn seed_run(
    owner: &PgPool,
    scope: &Scope,
    status: &str,
    historical_event: bool,
) -> anyhow::Result<Uuid> {
    ensure!(matches!(status, "FAILED" | "OUTCOME_UNKNOWN"));
    let delegation = Uuid::new_v4();
    let automation = Uuid::new_v4();
    let run = Uuid::new_v4();
    let mut tx = tenant_tx(owner, scope.tenant).await?;
    sqlx::query("INSERT INTO automation_delegations(id,tenant_id,project_id,principal_id,identity_issuer,identity_subject,instance_id,workspace_id,allowed_actions,created_at,expires_at,identity_client_id,identity_binding_generation) VALUES($1,$2,$3,$4,'https://issuer.example.test',$5,$6,$7,ARRAY['instances:renew','automations:write'],clock_timestamp()-interval '3 hours',clock_timestamp()+interval '1 day','historical-client',1)")
        .bind(delegation).bind(scope.tenant).bind(scope.project).bind(scope.principal).bind(scope.principal.to_string()).bind(scope.instance).bind(scope.workspace).execute(&mut *tx).await?;
    sqlx::query(r#"INSERT INTO automations(id,tenant_id,project_id,delegation_id,instance_id,workspace_id,creator_principal_id,name,action_kind,action,trigger_kind,scheduled_at,next_due_at,run_budget,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,'Historical renewal','RENEW','{"kind":"RENEW","ttl_seconds":3600}','ONCE',clock_timestamp()-interval '2 hours',clock_timestamp()-interval '2 hours',1,clock_timestamp()-interval '3 hours',clock_timestamp()-interval '3 hours')"#)
        .bind(automation).bind(scope.tenant).bind(scope.project).bind(delegation).bind(scope.instance).bind(scope.workspace).bind(scope.principal).execute(&mut *tx).await?;
    sqlx::query(r#"INSERT INTO automation_runs(id,tenant_id,project_id,automation_id,automation_version,delegation_id,creator_principal_id,instance_id,workspace_id,scheduled_for,operation_kind,original_request,operation_request,expected_resource_version,expected_generation,cluster_epoch,produced_resource_id,management_key,request_sha256,deadline,created_at,updated_at) VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,clock_timestamp()-interval '2 hours','RENEW','{"kind":"RENEW","ttl_seconds":3600}','{"expires_at":"2026-10-12T00:00:00Z"}',1,1,$9,$10,$11,$12,clock_timestamp()+interval '1 hour',clock_timestamp()-interval '2 hours',clock_timestamp()-interval '2 hours')"#)
        .bind(run).bind(scope.tenant).bind(scope.project).bind(automation).bind(delegation).bind(scope.principal).bind(scope.instance).bind(scope.workspace).bind(scope.epoch).bind(Uuid::new_v4()).bind(format!("automation-run:{run}")).bind("a".repeat(64)).execute(&mut *tx).await?;
    sqlx::query("UPDATE automation_runs SET status='CLAIMED' WHERE tenant_id=$1 AND id=$2")
        .bind(scope.tenant)
        .bind(run)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE automation_runs SET status='DISPATCHING',dispatch_attempt_id=$3,dispatch_started_at=clock_timestamp(),lease_owner='historical-writer',lease_token=1,lease_until=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1 AND id=$2").bind(scope.tenant).bind(run).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    sqlx::query("UPDATE automation_runs SET status=$3,failure_code='DEPENDENCY_UNAVAILABLE',completed_at=CASE WHEN $3='FAILED' THEN clock_timestamp() ELSE NULL END WHERE tenant_id=$1 AND id=$2").bind(scope.tenant).bind(run).bind(status).execute(&mut *tx).await?;
    sqlx::query("UPDATE automations SET emitted_runs=1,last_emitted_at=clock_timestamp(),next_due_at=NULL,status=CASE WHEN $3='FAILED' THEN 'EXHAUSTED' ELSE 'ACTIVE' END,version=CASE WHEN $3='FAILED' THEN version+1 ELSE version END WHERE tenant_id=$1 AND id=$2").bind(scope.tenant).bind(automation).bind(status).execute(&mut *tx).await?;
    if historical_event {
        write_event(&mut tx, scope, run, 4, run, json!({"status":status})).await?;
        sqlx::query(r#"INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,resource_id,action,outcome,details) VALUES($1,$2,$3,$4,$4,'automations:run',$5,'{"historical":"private-payload-must-remain"}')"#)
            .bind(scope.tenant).bind(scope.project).bind(scope.principal).bind(run).bind(if status == "FAILED" { "FAILED" } else { "UNKNOWN" }).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(run)
}

async fn write_event(
    tx: &mut Transaction<'_, Postgres>,
    scope: &Scope,
    run: Uuid,
    version: i64,
    request: Uuid,
    payload: Value,
) -> Result<Uuid, sqlx::Error> {
    let event = Uuid::new_v4();
    sqlx::query("INSERT INTO domain_events(id,tenant_id,project_id,aggregate_id,aggregate_version,event_type,request_id,payload) VALUES($1,$2,$3,$4,$5,'automations:run.changed',$6,$7)")
        .bind(event).bind(scope.tenant).bind(scope.project).bind(run).bind(version).bind(request).bind(payload).execute(&mut **tx).await?;
    Ok(event)
}

type Snapshot = BTreeMap<String, Value>;

fn snapshot_matches(expected: &Snapshot, actual: Snapshot) -> bool {
    if expected == &actual {
        return true;
    }
    // Only this closed set of categories reaches diagnostics: never tenant
    // identifiers, row payloads, policy definitions or arbitrary snapshot keys.
    let mut categories = BTreeSet::new();
    for key in expected.keys().chain(actual.keys()) {
        if expected.get(key) == actual.get(key) {
            continue;
        }
        categories.insert(match key.as_str() {
            "existing_rls_policies" => "RLS_POLICIES",
            "existing_trigger_contracts" => "TRIGGER_CONTRACTS",
            "existing_function_security" => "FUNCTION_SECURITY",
            "platform_configuration" => "PLATFORM_CONFIGURATION",
            _ => match key.rsplit(':').next() {
                Some("quota_accounts" | "quota_reservations") => "QUOTA_FACTS",
                Some("workspace_holds" | "workspace_hold_releases") => "HOLD_FACTS",
                Some("management_receipts" | "idempotency_keys") => "ACCEPTANCE_RECEIPTS",
                Some(
                    "domain_events"
                    | "audit_events"
                    | "event_stream_heads"
                    | "event_stream_positions",
                ) => "EVENT_FACTS",
                Some(
                    "automation_delegations"
                    | "automations"
                    | "automation_runs"
                    | "automation_claims",
                ) => "AUTOMATION_FACTS",
                _ => "OTHER_HISTORICAL_FACTS",
            },
        });
    }
    eprintln!(
        "UPGRADE_SNAPSHOT_DIFFERENCE_CATEGORIES={}",
        categories.into_iter().collect::<Vec<_>>().join(",")
    );
    false
}

async fn snapshot(owner: &PgPool, scopes: &[Scope]) -> anyhow::Result<Snapshot> {
    let mut facts = Snapshot::new();
    for scope in scopes {
        let mut tx = tenant_tx(owner, scope.tenant).await?;
        // Identifiers below are compile-time literals, never environment data.
        for table in [
            "tenants",
            "projects",
            "grants",
            "tenant_principals",
            "template_versions",
            "security_policy_versions",
            "workspaces",
            "instances",
            "operations",
            "executions",
            "idempotency_keys",
            "quota_accounts",
            "quota_reservations",
            "workspace_holds",
            "workspace_hold_releases",
            "management_receipts",
            "launch_permits",
            "backups",
            "backup_attempts",
            "backup_resource_intents",
            "file_transfers",
            "file_cleanup_schedule",
            "automation_delegations",
            "automations",
            "automation_runs",
            "automation_claims",
            "domain_events",
            "audit_events",
            "event_stream_heads",
            "event_stream_positions",
            "instance_timers",
            "operation_dispatch",
        ] {
            let tenant_column = if table == "tenants" {
                "id"
            } else {
                "tenant_id"
            };
            let sql = format!(
                "SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM public.{table} r WHERE {tenant_column}=$1"
            );
            let value: Value = sqlx::query_scalar(&sql)
                .bind(scope.tenant)
                .fetch_one(&mut *tx)
                .await?;
            facts.insert(format!("{}:{table}", scope.tenant), value);
        }
        for (table, column) in [
            ("principals", "id"),
            ("principal_identities", "principal_id"),
        ] {
            let sql = format!(
                "SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM public.{table} r WHERE {column}=$1"
            );
            let value: Value = sqlx::query_scalar(&sql)
                .bind(scope.principal)
                .fetch_one(&mut *tx)
                .await?;
            facts.insert(format!("{}:{table}", scope.tenant), value);
        }
        tx.commit().await?;
    }
    // Only 0047's additive installation identity is excluded; its non-nil value
    // and stability are checked separately before/after grants and replay.
    let config: Value = sqlx::query_scalar(
        "SELECT jsonb_agg(to_jsonb(c)-'installation_id' ORDER BY singleton) FROM platform_configuration c",
    )
    .fetch_one(owner)
    .await?;
    facts.insert("platform_configuration".to_owned(), config);
    // Exclude only additive 0042/0045/0046/0047 relations. Every historical relation's
    // RLS flags and complete policy rows remain in the exact comparison.
    let rls: Value = sqlx::query_scalar("SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.relname),'[]'::jsonb) FROM (SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity,(SELECT jsonb_agg(to_jsonb(p) ORDER BY p.polname) FROM pg_policy p WHERE p.polrelid=c.oid) AS policies FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relkind IN('r','p') AND c.relname NOT IN('automation_notifications','launch_resource_contracts','quota_resource_receipts','launch_quota_bindings','quota_resource_legacy_baseline','launch_pod_resource_observations','launch_registration_legacy_baseline','node_image_reader_grants','node_image_reader_audit')) r").fetch_one(owner).await?;
    facts.insert("existing_rls_policies".to_owned(), rls);
    // A trigger name alone is not its identity: append_only already protects
    // older tables. Match each new 0045/0046/0047 trigger by its exact relation and name.
    let triggers: Value = sqlx::query_scalar(r#"
        SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.relation,r.tgname),'[]'::jsonb)
        FROM (SELECT t.tgrelid::regclass::text AS relation,t.tgname,t.tgenabled,t.tgtype,
            t.tgdeferrable,t.tginitdeferred,t.tgfoid::regprocedure::text AS function
          FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
          WHERE NOT t.tgisinternal AND c.relnamespace='public'::regnamespace
            AND t.tgname NOT IN('immutable_automation_notification','automation_notification_no_delete','domain_event_stream_automation_notification_capture','worker_dispatch_hint')
            AND (c.relname,t.tgname) NOT IN (
              ('launch_resource_contracts','append_only'),
              ('quota_resource_receipts','append_only'),
              ('launch_quota_bindings','append_only'),
              ('quota_resource_legacy_baseline','append_only'),
              ('quota_resource_legacy_baseline','baseline_closed'),
              ('quota_reservations','quota_resource_identity_guard'),
              ('quota_accounts','quota_account_resource_identity_guard'),
              ('quota_reservations','quota_resource_capture'),
              ('instances','launch_resource_capture'),
              ('launch_resource_contracts','launch_resource_quota_complete'),
              ('quota_reservations','quota_resource_launch_binding'),
              ('quota_reservations','compute_quota_release_proof'),
              ('launch_pod_resource_observations','append_only'),
              ('launch_pod_resource_observations','launch_resource_observation_ack'),
              ('launch_registration_legacy_baseline','append_only'),
              ('launch_registration_legacy_baseline','baseline_closed'),
              ('launch_permit_receipts','launch_registration_resource_complete'),
              ('launch_permit_extension_receipts','launch_extension_resource_complete'),
              ('node_image_reader_audit','append_only'),
              ('node_image_reader_grants','immutable_node_image_reader'),
              ('node_image_reader_grants','audit_node_image_reader'),
              ('principals','node_image_reader_principal_change'),
              ('principal_identities','node_image_reader_identity_change'),
              ('platform_configuration','node_image_reader_scope_change'))) r
    "#).fetch_one(owner).await?;
    facts.insert("existing_trigger_contracts".to_owned(), triggers);
    // 0048 adds only this exact node-image binding function; no historical
    // relation, column or trigger is excluded for that migration.
    let functions: Value = sqlx::query_scalar(r#"
        SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.function),'[]'::jsonb)
        FROM (SELECT oid::regprocedure::text AS function,prosecdef,proconfig FROM pg_proc f
          WHERE pronamespace='public'::regnamespace
            AND proname NOT IN('sandbox_file_activity_match','sandbox_guard_automation_notification','sandbox_capture_automation_notification','sandbox_lock_automation_notification_head','sandbox_notify_worker_dispatch')
            AND NOT (prokind='f' AND pronargs=0 AND proname IN('sandbox_guard_quota_resource_identity','sandbox_capture_quota_resource','sandbox_capture_launch_resource','sandbox_bind_launch_quota','sandbox_guard_compute_quota_release'))
            AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY[
              'public.sandbox_guard_launch_resource_registration()',
              'public.sandbox_guard_launch_resource_observation()',
              'public.sandbox_lock_registration_boundary(uuid)',
              'public.sandbox_record_launch_resource_observation(uuid,uuid,text,text,uuid,text,text,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,timestamptz)',
              'public.sandbox_guard_node_image_reader()',
              'public.sandbox_audit_node_image_reader()',
              'public.sandbox_invalidate_node_image_reader()',
              'public.sandbox_grant_node_image_reader(uuid,uuid,uuid,text,text,text,timestamptz,text)',
              'public.sandbox_revoke_node_image_reader(uuid,uuid,uuid,text)',
              'public.sandbox_node_image_access(text,text,text,bigint)',
              'public.sandbox_node_image_binding(text,text,text,bigint,uuid)'
            ]::text[]) added(signature) WHERE f.oid=to_regprocedure(added.signature))) r
    "#).fetch_one(owner).await?;
    facts.insert("existing_function_security".to_owned(), functions);
    Ok(facts)
}

async fn assert_resource_accounting_upgrade(
    owner: &PgPool,
    scopes: &[Scope],
) -> anyhow::Result<()> {
    let guarded_tables: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace
          AND relname IN('launch_resource_contracts','quota_resource_receipts',
            'launch_quota_bindings','quota_resource_legacy_baseline')
          AND relkind='r' AND relrowsecurity AND relforcerowsecurity
    "#,
    )
    .fetch_one(owner)
    .await?;
    ensure!(
        guarded_tables == 4,
        "Migration 45 requires all four new accounting tables with FORCE RLS"
    );
    let mut total_baseline = 0;
    for scope in scopes {
        let mut tx = tenant_tx(owner, scope.tenant).await?;
        let facts: (i64, i64, i64, i64, bool) = sqlx::query_as(
            r#"
            SELECT (SELECT count(*) FROM quota_resource_legacy_baseline WHERE tenant_id=$1),
              (SELECT count(*) FROM launch_resource_contracts WHERE tenant_id=$1),
              (SELECT count(*) FROM quota_resource_receipts WHERE tenant_id=$1),
              (SELECT count(*) FROM launch_quota_bindings WHERE tenant_id=$1),
              (SELECT array_agg(reservation_id ORDER BY reservation_id)
                FROM quota_resource_legacy_baseline WHERE tenant_id=$1)
                IS NOT DISTINCT FROM (SELECT array_agg(id ORDER BY id)
                  FROM quota_reservations WHERE tenant_id=$1)
        "#,
        )
        .bind(scope.tenant)
        .fetch_one(&mut *tx)
        .await?;
        ensure!(
            facts == (8, 0, 0, 0, true),
            "Migration 45 must freeze the exact historical reservation IDs without fabricating launch contracts, quota bindings or receipt history"
        );
        total_baseline += facts.0;
        tx.commit().await?;
    }
    ensure!(
        total_baseline == 16,
        "Both historical tenants require a complete 16-reservation legacy baseline"
    );
    Ok(())
}

async fn assert_pod_observation_upgrade(owner: &PgPool, scopes: &[Scope]) -> anyhow::Result<()> {
    let guarded_tables: i64 = sqlx::query_scalar(r#"
        SELECT count(*) FROM pg_class c WHERE c.relnamespace='public'::regnamespace
          AND c.relname IN('launch_pod_resource_observations','launch_registration_legacy_baseline')
          AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity
          AND (SELECT count(*) FROM pg_policy p WHERE p.polrelid=c.oid)=1
          AND EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid
            AND p.polname='tenant_isolation' AND p.polcmd='*' AND p.polpermissive
            AND p.polroles=ARRAY[0::oid]
            AND replace(replace(pg_get_expr(p.polqual,p.polrelid),'public.',''),' ','')='(tenant_id=sandbox_current_tenant_id())'
            AND replace(replace(pg_get_expr(p.polwithcheck,p.polrelid),'public.',''),' ','')='(tenant_id=sandbox_current_tenant_id())')
    "#).fetch_one(owner).await?;
    ensure!(
        guarded_tables == 2,
        "Migration 46 requires both reviewed FORCE RLS observation tables and exact tenant policies"
    );
    let exact_triggers: i64 = sqlx::query_scalar(r#"
        SELECT count(*) FROM (VALUES
          ('launch_pod_resource_observations','append_only','sandbox_prevent_audit_mutation()',27,false),
          ('launch_pod_resource_observations','launch_resource_observation_ack','sandbox_guard_launch_resource_observation()',5,true),
          ('launch_registration_legacy_baseline','append_only','sandbox_prevent_audit_mutation()',27,false),
          ('launch_registration_legacy_baseline','baseline_closed','sandbox_prevent_audit_mutation()',7,false),
          ('launch_permit_receipts','launch_registration_resource_complete','sandbox_guard_launch_resource_registration()',5,true),
          ('launch_permit_extension_receipts','launch_extension_resource_complete','sandbox_guard_launch_resource_registration()',5,true)
        ) expected(relation,name,function,kind,deferred)
        JOIN pg_trigger t ON t.tgrelid=to_regclass('public.'||expected.relation)
          AND t.tgname=expected.name AND t.tgfoid=to_regprocedure('public.'||expected.function)
          AND t.tgtype=expected.kind AND t.tgenabled='O' AND NOT t.tgisinternal
          AND t.tgdeferrable=expected.deferred AND t.tginitdeferred=expected.deferred
          AND t.tgnargs=0 AND t.tgqual IS NULL AND cardinality(t.tgattr::smallint[])=0
    "#).fetch_one(owner).await?;
    ensure!(
        exact_triggers == 6,
        "Migration 46 requires the six exact append-only and atomic-registration triggers"
    );
    let migration = include_str!("../migrations/0046_launch_pod_resource_observations.sql");
    for (signature, result) in [
        ("sandbox_guard_launch_resource_registration()", "trigger"),
        ("sandbox_guard_launch_resource_observation()", "trigger"),
        ("sandbox_lock_registration_boundary(uuid)", "boolean"),
        (
            "sandbox_record_launch_resource_observation(uuid,uuid,text,text,uuid,text,text,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,timestamptz)",
            "uuid",
        ),
    ] {
        let name = signature
            .split_once('(')
            .context("fixed observation signature")?
            .0;
        let body = migration
            .split_once(&format!("CREATE FUNCTION {name}("))
            .context("reviewed observation declaration")?
            .1
            .split("$observation$")
            .nth(1)
            .context("reviewed observation body")?;
        let guarded: bool=sqlx::query_scalar(r#"
            SELECT f.prosrc=$2 AND f.prosecdef AND f.proconfig=ARRAY['search_path=pg_catalog']::text[]
              AND f.proowner=current_user::regrole AND f.prorettype=to_regtype($3)
              AND f.prokind='f' AND f.provolatile='v' AND f.proparallel='u'
              AND NOT f.proretset AND NOT f.proisstrict AND NOT f.proleakproof
              AND (SELECT lanname='plpgsql' FROM pg_language WHERE oid=f.prolang)
              AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(f.proacl,acldefault('f',f.proowner))) a
                  WHERE a.grantee=0 AND a.privilege_type='EXECUTE')
            FROM pg_proc f WHERE f.oid=to_regprocedure('public.'||$1)
        "#).bind(signature).bind(body).bind(result).fetch_one(owner).await?;
        ensure!(
            guarded,
            "Migration 46 function must match its reviewed exact signature, body and security: {name}"
        );
    }
    for scope in scopes {
        let mut tx = tenant_tx(owner, scope.tenant).await?;
        let rows:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM launch_pod_resource_observations),(SELECT count(*) FROM launch_registration_legacy_baseline)")
            .fetch_one(&mut *tx).await?;
        ensure!(
            rows == (0, 0),
            "Migration 46 must not invent Pod observations or registration ACKs for these historical unregistered launches"
        );
        tx.commit().await?;
    }
    Ok(())
}

async fn assert_operator_authorization_upgrade(
    owner: &PgPool,
    app: &PgPool,
    read_granted: bool,
) -> anyhow::Result<Uuid> {
    let installation: Uuid =
        sqlx::query_scalar("SELECT installation_id FROM platform_configuration WHERE singleton")
            .fetch_one(owner)
            .await?;
    ensure!(
        !installation.is_nil(),
        "Migration 47 must establish a non-nil installation identity"
    );
    let empty: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS(SELECT 1 FROM node_image_reader_grants) AND NOT EXISTS(SELECT 1 FROM node_image_reader_audit)",
    )
    .fetch_one(owner)
    .await?;
    ensure!(
        empty,
        "Migration/role installation must not preauthorize historical service identities"
    );
    for table in ["node_image_reader_grants", "node_image_reader_audit"] {
        let private: bool = sqlx::query_scalar(
            "SELECT NOT has_table_privilege(current_user,$1,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND NOT has_any_column_privilege(current_user,$1,'SELECT,INSERT,UPDATE,REFERENCES')",
        )
        .bind(format!("public.{table}"))
        .fetch_one(app)
        .await?;
        ensure!(
            private,
            "Ordinary app must have no private operator table/column grants"
        );
        let error = sqlx::query(&format!("SELECT id FROM public.{table} LIMIT 1"))
            .fetch_optional(app)
            .await
            .err()
            .context("Ordinary app unexpectedly read a private operator table")?;
        ensure!(
            error
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref()
                == Some("42501"),
            "Private operator tables must reject the actual ordinary app with insufficient_privilege"
        );
    }
    let narrow: bool = sqlx::query_scalar(r#"
        SELECT bool_and(p.oid IS NOT NULL
            AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
                WHERE a.grantee=0 AND a.privilege_type='EXECUTE')
            AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname IN
                ('sandbox_app','sandbox_worker','sandbox_gateway','sandbox_admission','sandbox_termination',
                 'sandbox_fencing','sandbox_volume_deleter','sandbox_backup','sandbox_automation',
                 'sandbox_browser','sandbox_restore','sandbox_restore_admission','sandbox_restore_gc','sandbox_restore_gc_admission')
                AND has_function_privilege(r.oid,p.oid,'EXECUTE') IS DISTINCT FROM
                    (r.rolname='sandbox_app' AND expected.reader AND $1)))
        FROM (VALUES
            ('public.sandbox_guard_node_image_reader()',false),
            ('public.sandbox_audit_node_image_reader()',false),
            ('public.sandbox_invalidate_node_image_reader()',false),
            ('public.sandbox_grant_node_image_reader(uuid,uuid,uuid,text,text,text,timestamptz,text)',false),
            ('public.sandbox_revoke_node_image_reader(uuid,uuid,uuid,text)',false),
            ('public.sandbox_node_image_access(text,text,text,bigint)',true),
            ('public.sandbox_node_image_binding(text,text,text,bigint,uuid)',true)
        ) expected(signature,reader)
        LEFT JOIN pg_proc p ON p.oid=to_regprocedure(expected.signature)
    "#)
    .bind(read_granted)
    .fetch_one(owner)
    .await?;
    ensure!(
        narrow,
        "Migrations 47/48 must close PUBLIC/runtime management execution and grant only the explicit app readers"
    );
    Ok(installation)
}

async fn ledger(owner: &PgPool) -> anyhow::Result<Vec<(i64, Value)>> {
    Ok(
        sqlx::query_as("SELECT version,to_jsonb(m) FROM _sqlx_migrations m ORDER BY version")
            .fetch_all(owner)
            .await?,
    )
}

async fn all_roles(owner: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql(include_str!("../scripts/sql/roles.sql"))
        .execute(owner)
        .await?;
    sqlx::raw_sql(include_str!("../scripts/sql/browser-role.sql"))
        .execute(owner)
        .await?;
    for (role, sql) in [
        (
            "sandbox_worker",
            include_str!("../scripts/sql/worker-role.sql"),
        ),
        (
            "sandbox_gateway",
            include_str!("../scripts/sql/gateway-role.sql"),
        ),
        (
            "sandbox_admission",
            include_str!("../scripts/sql/admission-role.sql"),
        ),
        (
            "sandbox_termination",
            include_str!("../scripts/sql/termination-role.sql"),
        ),
        (
            "sandbox_fencing",
            include_str!("../scripts/sql/fencing-role.sql"),
        ),
        (
            "sandbox_volume_deleter",
            include_str!("../scripts/sql/volume-deleter-role.sql"),
        ),
        (
            "sandbox_backup",
            include_str!("../scripts/sql/backup-role.sql"),
        ),
    ] {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)")
                .bind(role)
                .fetch_one(owner)
                .await?;
        if exists {
            sqlx::raw_sql(sql).execute(owner).await?;
        }
    }
    sqlx::raw_sql(include_str!("../scripts/sql/automation-role.sql"))
        .execute(owner)
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires fresh empty owned *_test PostgreSQL 17+ TLS database and exact provisioned runtime logins"]
async fn upgrade_from_v41_preserves_historical_automation_and_rejects_invalid_source_events()
-> anyhow::Result<()> {
    let owner_url =
        env::var("TEST_MIGRATION_DATABASE_URL").context("TEST_MIGRATION_DATABASE_URL required")?;
    let app_url = env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let coordinator_url = env::var("TEST_AUTOMATION_DATABASE_URL")
        .context("TEST_AUTOMATION_DATABASE_URL required")?;
    checked_pair(&owner_url, &app_url)?;
    checked_runtime_target(&owner_url, &coordinator_url, "sandbox_automation")?;
    let owner = connect(&owner_url, "sandbox_owner").await?;
    let fresh: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind IN('r','p','v','m','S'))").fetch_one(&owner).await?;
    ensure!(
        fresh,
        "Upgrade suite refuses any preexisting schema; runner must supply a new owned empty database"
    );
    let version: String = sqlx::query_scalar("SHOW server_version_num")
        .fetch_one(&owner)
        .await?;
    ensure!(version.parse::<u32>()? >= 170000);
    let all = sqlx::migrate!("./migrations");
    let old = Migrator {
        migrations: Cow::Owned(all.iter().filter(|m| m.version <= 41).cloned().collect()),
        ..Migrator::DEFAULT
    };
    let mut historical_versions: Vec<_> = (1..=37).collect();
    historical_versions.extend([39, 40, 41]);
    ensure!(old.iter().map(|m| m.version).collect::<Vec<_>>() == historical_versions);
    old.run(&owner)
        .await
        .context("Cannot install frozen schema 41 contract")?;
    sqlx::raw_sql(include_str!("fixtures/upgrade/v41-roles.sql"))
        .execute(&owner)
        .await?;
    sqlx::raw_sql(include_str!("fixtures/upgrade/v41-automation-role.sql"))
        .execute(&owner)
        .await?;
    let app = connect(&app_url, "sandbox_app").await?;
    let coordinator = connect(&coordinator_url, "sandbox_automation").await?;
    let epoch = Uuid::new_v4();
    sqlx::query("INSERT INTO platform_configuration(singleton,cluster_epoch,safe_mode) VALUES(true,$1,true)").bind(epoch).execute(&owner).await?;
    let scopes = [
        seed_scope(&owner, epoch).await?,
        seed_scope(&owner, epoch).await?,
    ];
    for scope in &scopes {
        seed_run(&owner, scope, "FAILED", true).await?;
        seed_run(&owner, scope, "OUTCOME_UNKNOWN", true).await?;
    }
    history::seed_nonempty_history(&owner, &scopes).await?;
    history::assert_nonempty_history(&owner, &scopes).await?;
    let before = snapshot(&owner, &scopes).await?;
    let before_ledger = ledger(&owner).await?;
    ensure!(before_ledger.iter().map(|(v, _)| *v).collect::<Vec<_>>() == historical_versions);
    let absent: bool =
        sqlx::query_scalar("SELECT to_regclass('public.automation_notifications') IS NULL")
            .fetch_one(&owner)
            .await?;
    ensure!(
        absent,
        "Historical schema unexpectedly contains the new notification table"
    );
    let expanded = Migrator {
        migrations: Cow::Owned(all.iter().filter(|m| m.version <= 42).cloned().collect()),
        ..Migrator::DEFAULT
    };
    expanded
        .run(&owner)
        .await
        .context("Cannot expand schema 41 to schema 42")?;
    ensure!(
        snapshot_matches(&before, snapshot(&owner, &scopes).await?),
        "Upgrade altered historical facts, source epochs, timers, file intents or configuration"
    );
    let expanded_ledger = ledger(&owner).await?;
    ensure!(
        expanded_ledger[..before_ledger.len()] == before_ledger,
        "Upgrade rewrote old migration records or checksums"
    );
    ensure!(
        expanded_ledger.iter().map(|(v, _)| *v).collect::<Vec<_>>()
            == expanded.iter().map(|m| m.version).collect::<Vec<_>>()
    );
    for scope in &scopes {
        let mut tx = tenant_tx(&owner, scope.tenant).await?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM automation_notifications")
            .fetch_one(&mut *tx)
            .await?;
        ensure!(
            count == 0,
            "Migration must not replay or backfill historical exceptions"
        );
        tx.commit().await?;
    }
    let legacy_no_acl: bool = sqlx::query_scalar("SELECT NOT has_table_privilege('sandbox_app','automation_notifications','SELECT,INSERT,UPDATE,DELETE,TRUNCATE') AND NOT has_function_privilege('sandbox_app','sandbox_capture_automation_notification()','EXECUTE') AND NOT has_table_privilege('sandbox_automation','automation_notifications','SELECT,INSERT,UPDATE,DELETE,TRUNCATE') AND NOT has_function_privilege('sandbox_automation','sandbox_capture_automation_notification()','EXECUTE')").fetch_one(&owner).await?;
    ensure!(
        legacy_no_acl,
        "DDL must not grant legacy logins direct notification privileges"
    );
    // Existing writer ACLs remain unchanged: an ordinary source-event INSERT
    // derives the anomaly despite having no privileges on the new table.
    let legacy_run = seed_run(&owner, &scopes[0], "FAILED", false).await?;
    let mut tx = tenant_tx(&app, scopes[0].tenant).await?;
    let legacy_event = write_event(
        &mut tx,
        &scopes[0],
        legacy_run,
        4,
        legacy_run,
        json!({"status":"FAILED"}),
    )
    .await?;
    tx.commit().await?;
    let legacy_coordinator_run = seed_run(&owner, &scopes[1], "FAILED", false).await?;
    let mut tx = tenant_tx(&coordinator, scopes[1].tenant).await?;
    let legacy_coordinator_event = write_event(
        &mut tx,
        &scopes[1],
        legacy_coordinator_run,
        4,
        legacy_coordinator_run,
        json!({"status":"FAILED"}),
    )
    .await?;
    tx.commit().await?;
    // Schema 42's owner seeds legal committed historical ACK facts. This is
    // stored-state migration coverage, not an old binary or current startup
    // proof. Current runtime validation happens only after migration 43.
    let historical_ack = ack::seed_schema42_ack(&owner, &scopes[0], legacy_event).await?;
    let before_current_roles = snapshot(&owner, &scopes).await?;
    let notices_at42 = notification_snapshot(&owner, &scopes).await?;
    let ledger_at42 = ledger(&owner).await?;
    ensure!(ledger_at42 == expanded_ledger);
    all.run(&owner)
        .await
        .context("Cannot upgrade committed schema 42 state to current migrations")?;
    let deferred_security: bool = sqlx::query_scalar("SELECT prosecdef AND proconfig=ARRAY['search_path=pg_catalog']::text[] FROM pg_proc WHERE oid='sandbox_file_activity_match()'::regprocedure").fetch_one(&owner).await?;
    ensure!(
        deferred_security,
        "Current deferred activity validation must use its fixed-path restricted definer"
    );
    // New 0044 metadata is checked separately from byte-for-byte preservation
    // of existing schema 42 facts and function/trigger security contracts.
    let dispatch_hint_security: bool = sqlx::query_scalar(r#"
        SELECT f.prosecdef AND f.proconfig=ARRAY['search_path=pg_catalog']::text[]
          AND f.proowner=current_user::regrole
          AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(f.proacl,acldefault('f',f.proowner))) a
              WHERE a.grantee=0 AND a.privilege_type='EXECUTE')
          AND EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid='public.operation_dispatch'::regclass
              AND t.tgname='worker_dispatch_hint' AND t.tgfoid=f.oid AND t.tgenabled='O'
              AND t.tgtype=21 AND NOT t.tgdeferrable AND NOT t.tginitdeferred
              AND t.tgnargs=0 AND t.tgqual IS NULL)
          AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname IN
              ('sandbox_app','sandbox_worker','sandbox_gateway','sandbox_admission','sandbox_termination',
               'sandbox_fencing','sandbox_volume_deleter','sandbox_backup','sandbox_automation','sandbox_browser')
              AND has_function_privilege(r.oid,f.oid,'EXECUTE'))
        FROM pg_proc f WHERE f.oid='public.sandbox_notify_worker_dispatch()'::regprocedure
    "#).fetch_one(&owner).await?;
    ensure!(
        dispatch_hint_security,
        "Migration 44 dispatch hint must have an exact owner-only fixed-path trigger contract"
    );
    assert_resource_accounting_upgrade(&owner, &scopes).await?;
    assert_pod_observation_upgrade(&owner, &scopes).await?;
    let installation = assert_operator_authorization_upgrade(&owner, &app, false).await?;
    ensure!(
        snapshot_matches(&before_current_roles, snapshot(&owner, &scopes).await?)
            && notification_snapshot(&owner, &scopes).await? == notices_at42,
        "Current migrations changed historical quota, holds, receipts, ACK, source events or authority"
    );
    history::assert_nonempty_history(&owner, &scopes).await?;
    let upgraded_ledger = ledger(&owner).await?;
    ensure!(
        upgraded_ledger[..ledger_at42.len()] == ledger_at42,
        "Current migrations rewrote the complete schema 42 migration ledger"
    );
    ensure!(
        upgraded_ledger.iter().map(|(v, _)| *v).collect::<Vec<_>>()
            == all.iter().map(|m| m.version).collect::<Vec<_>>()
    );
    all_roles(&owner).await?;
    ensure!(
        assert_operator_authorization_upgrade(&owner, &app, true).await? == installation,
        "Role installation must preserve the installation identity"
    );
    ensure!(
        snapshot_matches(&before_current_roles, snapshot(&owner, &scopes).await?)
            && notification_snapshot(&owner, &scopes).await? == notices_at42,
        "Current role installation changed committed historical or new facts"
    );
    let database = Database { pool: app.clone() };
    database.verify_runtime_role().await?;
    Database {
        pool: coordinator.clone(),
    }
    .verify_runtime_role()
    .await?;
    database.check_automation_notification_schema().await?;
    let first = database
        .get_automation_notification(&scopes[0].actor(), legacy_event)
        .await
        .map_err(api_error)?;
    ensure!(
        first.run_id == legacy_run
            && first.source_status == "FAILED"
            && first.source_run_version == 4
            && first.version == 2
            && first.acknowledged_by == Some(scopes[0].principal)
    );
    let coordinator_source = database
        .get_automation_notification(&scopes[1].actor(), legacy_coordinator_event)
        .await
        .map_err(api_error)?;
    ensure!(
        coordinator_source.run_id == legacy_coordinator_run
            && coordinator_source.source_status == "FAILED"
            && coordinator_source.source_run_version == 4
    );
    let signer = CursorSigner::from_json(include_str!("fixtures/history/cursor-keys.json"))?;
    let mut unknowns = Vec::new();
    for scope in &scopes {
        let run = seed_run(&owner, scope, "OUTCOME_UNKNOWN", false).await?;
        let mut tx = tenant_tx(&app, scope.tenant).await?;
        let event = write_event(
            &mut tx,
            scope,
            run,
            4,
            run,
            json!({"status":"OUTCOME_UNKNOWN"}),
        )
        .await?;
        tx.commit().await?;
        let mut tx = tenant_tx(&app, scope.tenant).await?;
        sqlx::query(
            "UPDATE automation_runs SET status='OUTCOME_UNKNOWN' WHERE tenant_id=$1 AND id=$2",
        )
        .bind(scope.tenant)
        .bind(run)
        .execute(&mut *tx)
        .await?;
        write_event(
            &mut tx,
            scope,
            run,
            5,
            run,
            json!({"status":"OUTCOME_UNKNOWN"}),
        )
        .await?;
        tx.commit().await?;
        let source = database
            .get_automation_notification(&scope.actor(), event)
            .await
            .map_err(api_error)?;
        ensure!(
            source.source_run_version == 4,
            "Later source versions must retain the first unknown exception fact"
        );
        let mut tx = tenant_tx(&owner, scope.tenant).await?;
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM automation_notifications WHERE run_id=$1")
                .bind(run)
                .fetch_one(&mut *tx)
                .await?;
        ensure!(count == 1);
        tx.commit().await?;
        let query = HistoryQuery {
            project_id: scope.project,
            instance_id: Some(scope.instance),
            limit: Some(100),
            cursor: None,
        };
        let page = database
            .list_automation_notifications(&scope.actor(), &query, &signer)
            .await
            .map_err(api_error)?;
        ensure!(page.items.len() == 2);
        ensure!(page.items.iter().all(|n| n.tenant_id == scope.tenant
            && n.project_id == scope.project
            && n.instance_id == scope.instance));
        let sibling = HistoryQuery {
            project_id: scope.sibling,
            ..query
        };
        ensure!(
            database
                .list_automation_notifications(&scope.actor(), &sibling, &signer)
                .await
                .map_err(api_error)?
                .items
                .is_empty(),
            "Notifications leaked to a sibling project"
        );
        unknowns.push((run, event));
    }
    let foreign = database
        .get_automation_notification(&scopes[1].actor(), legacy_event)
        .await
        .err()
        .context("Cross-tenant notification read unexpectedly succeeded")?;
    ensure!(foreign.status == StatusCode::NOT_FOUND);
    // Old events without status stay valid and must not become exceptions.
    let old_format_run = seed_run(&owner, &scopes[0], "OUTCOME_UNKNOWN", false).await?;
    let mut tx = tenant_tx(&app, scopes[0].tenant).await?;
    let old_format_event = write_event(
        &mut tx,
        &scopes[0],
        old_format_run,
        4,
        old_format_run,
        json!({}),
    )
    .await?;
    tx.commit().await?;
    let mut tx = tenant_tx(&owner, scopes[0].tenant).await?;
    let old_format_facts: (bool, bool) = sqlx::query_as("SELECT EXISTS(SELECT 1 FROM domain_events WHERE id=$1),NOT EXISTS(SELECT 1 FROM automation_notifications WHERE run_id=$2)").bind(old_format_event).bind(old_format_run).fetch_one(&mut *tx).await?;
    ensure!(
        old_format_facts == (true, true),
        "Old payload without status must commit its event without creating a notification"
    );
    tx.commit().await?;
    ack::verify_post_upgrade_ack(&database, &owner, &scopes, &historical_ack, unknowns[0].1)
        .await?;
    history::assert_nonempty_history(&owner, &scopes).await?;
    let stable = snapshot(&owner, &scopes).await?;
    let notification_before = notification_snapshot(&owner, &scopes).await?;
    for invalid in ["version", "status", "request"] {
        let scope = &scopes[0];
        let run = unknowns[0].0;
        let mut tx = tenant_tx(&app, scope.tenant).await?;
        sqlx::query(
            "UPDATE automation_runs SET status='OUTCOME_UNKNOWN' WHERE tenant_id=$1 AND id=$2",
        )
        .bind(scope.tenant)
        .bind(run)
        .execute(&mut *tx)
        .await?;
        let result = write_event(
            &mut tx,
            scope,
            run,
            if invalid == "version" { 99 } else { 6 },
            if invalid == "request" {
                Uuid::new_v4()
            } else {
                run
            },
            json!({"status":if invalid == "status" { "FAILED" } else { "OUTCOME_UNKNOWN" }}),
        )
        .await;
        let error = result
            .err()
            .context("Invalid notification source unexpectedly committed")?;
        ensure!(
            error.as_database_error().and_then(|e| e.code()).as_deref() == Some("23514"),
            "Expected exact source-match constraint error"
        );
        tx.rollback().await?;
        ensure!(
            snapshot_matches(&stable, snapshot(&owner, &scopes).await?)
                && notification_snapshot(&owner, &scopes).await? == notification_before,
            "Rejected source left run, event, stream sequence, audit, routing or notification side effects"
        );
    }
    verify_deferred_activity(&app, &scopes).await?;
    ensure!(
        snapshot_matches(&stable, snapshot(&owner, &scopes).await?)
            && notification_snapshot(&owner, &scopes).await? == notification_before
    );
    // Resolving an unknown outcome is a real coordinator source transition.
    // Run this after the invalid-source rollback cases, which require UNKNOWN.
    ack::verify_dual_status_progression(
        &database,
        &owner,
        &coordinator,
        &scopes,
        unknowns[0].0,
        unknowns[0].1,
    )
    .await?;
    history::assert_nonempty_history(&owner, &scopes).await?;
    let stable = snapshot(&owner, &scopes).await?;
    let notification_before = notification_snapshot(&owner, &scopes).await?;
    all.run(&owner).await?;
    all_roles(&owner).await?;
    ensure!(
        assert_operator_authorization_upgrade(&owner, &app, true).await? == installation,
        "Migration/role replay must preserve installation identity and must not preauthorize readers"
    );
    ensure!(
        ledger(&owner).await? == upgraded_ledger,
        "Migration/role replay rewrote its immutable ledger"
    );
    ensure!(
        snapshot_matches(&stable, snapshot(&owner, &scopes).await?)
            && notification_snapshot(&owner, &scopes).await? == notification_before,
        "Migration/role replay altered historical or new facts"
    );
    // SQLx may retain its connection-level migration lock on this early error.
    // A dedicated physical connection models the old migration process exiting
    // and cannot leave that lock in the reusable owner pool.
    let mut old_connection =
        sqlx::PgConnection::connect_with(&PgConnectOptions::from_str(&owner_url)?).await?;
    let refusal = old
        .run(&mut old_connection)
        .await
        .err()
        .context("Old migrator must refuse newer installed versions")?;
    sqlx::Connection::close(old_connection).await?;
    ensure!(
        matches!(
            refusal,
            MigrateError::VersionMissing(42) | MigrateError::VersionMissing(43)
        ),
        "Expected newer-version refusal, not a connection or migration error"
    );
    ensure!(
        ledger(&owner).await? == upgraded_ledger
            && snapshot_matches(&stable, snapshot(&owner, &scopes).await?)
            && notification_snapshot(&owner, &scopes).await? == notification_before,
        "Old migration refusal must leave all committed facts unchanged"
    );
    assert_resource_accounting_upgrade(&owner, &scopes).await?;
    let hidden: i64 = sqlx::query_scalar("SELECT count(*) FROM automation_notifications")
        .fetch_one(&app)
        .await?;
    ensure!(
        hidden == 0,
        "Tenant context leaked into a pooled runtime connection"
    );
    app.close().await;
    coordinator.close().await;
    owner.close().await;
    println!("{PROGRESSION_VERIFIED}");
    println!("{STATE_VERIFIED}");
    println!("{VERIFIED}");
    Ok(())
}

async fn notification_snapshot(owner: &PgPool, scopes: &[Scope]) -> anyhow::Result<Vec<Value>> {
    let mut rows = Vec::new();
    for scope in scopes {
        let mut tx = tenant_tx(owner, scope.tenant).await?;
        rows.extend(
            sqlx::query_scalar::<_, Value>(
                "SELECT to_jsonb(n) FROM automation_notifications n ORDER BY id",
            )
            .fetch_all(&mut *tx)
            .await?,
        );
        tx.commit().await?;
    }
    Ok(rows)
}

async fn verify_deferred_activity(app: &PgPool, scopes: &[Scope]) -> anyhow::Result<()> {
    // Commit with a changed caller context. The definer must validate the
    // original row scope and restore the actual commit context afterwards.
    let mut tx = tenant_tx(app, scopes[0].tenant).await?;
    let changed = sqlx::query("UPDATE instances SET updated_at=updated_at WHERE id=$1")
        .bind(scopes[0].instance)
        .execute(&mut *tx)
        .await?;
    ensure!(changed.rows_affected() == 1);
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(scopes[1].tenant.to_string())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    // Separately inspect restoration inside an open transaction, before SET
    // LOCAL would reset automatically at commit. The negative case below still
    // validates its original deferred normal-COMMIT failure path.
    let mut tx = tenant_tx(app, scopes[0].tenant).await?;
    let changed = sqlx::query("UPDATE instances SET updated_at=updated_at WHERE id=$1")
        .bind(scopes[0].instance)
        .execute(&mut *tx)
        .await?;
    ensure!(changed.rows_affected() == 1);
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(scopes[1].tenant.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET CONSTRAINTS instance_file_activity_match IMMEDIATE")
        .execute(&mut *tx)
        .await?;
    let restored: String = sqlx::query_scalar("SELECT current_setting('app.tenant_id')")
        .fetch_one(&mut *tx)
        .await?;
    ensure!(
        restored == scopes[1].tenant.to_string(),
        "Deferred activity validation must restore the caller's previous context within the transaction"
    );
    tx.commit().await?;
    // This invalid activity must fail at the normal deferred COMMIT, even
    // after the caller switches to another valid tenant; no early trigger flush.
    let mut tx = tenant_tx(app, scopes[0].tenant).await?;
    let changed = sqlx::query("UPDATE instances SET slot_held=true,activity_kind='FILE_WRITE',activity_id=$2,activity_generation=runtime_generation,idle_since=NULL WHERE id=$1").bind(scopes[0].instance).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    ensure!(changed.rows_affected() == 1);
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(scopes[1].tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let error =
        tx.commit().await.err().context(
            "Deferred orphan activity must fail at COMMIT despite changed caller tenant",
        )?;
    ensure!(error.as_database_error().and_then(|e| e.code()).as_deref() == Some("23514"));
    Ok(())
}

fn api_error(error: sandbox_platform::error::ApiError) -> anyhow::Error {
    anyhow::anyhow!("{}: {}", error.code, error.detail)
}

#[test]
fn upgrade_target_requires_literal_loopback_owned_disposable_verified_tls() {
    for raw in [
        "postgres://sandbox_owner:test@localhost/sandbox_test?sslmode=verify-full&sslrootcert=/tmp/ca.pem",
        "postgres://sandbox_owner:test@database.example.test/sandbox_test?sslmode=verify-full&sslrootcert=/tmp/ca.pem",
        "postgres://sandbox_owner:test@127.0.0.1/sandbox_prod?sslmode=verify-full&sslrootcert=/tmp/ca.pem",
        "postgres://sandbox_owner:test@127.0.0.1/sandbox_test?sslmode=disable&sslrootcert=/tmp/ca.pem",
        "postgres://sandbox_owner:test@127.0.0.1/sandbox_test?sslmode=verify-full&sslrootcert=relative.pem",
        "postgres://sandbox_owner:test@127.0.0.1/sandbox_test?sslmode=verify-full&sslrootcert=/tmp/ca.pem&host=other",
        "postgres://sandbox_app:test@127.0.0.1/sandbox_test?sslmode=verify-full&sslrootcert=/tmp/ca.pem",
    ] {
        assert!(checked_url(raw, "sandbox_owner").is_err());
    }
    for host in ["127.0.0.1", "[::1]"] {
        assert!(checked_url(&format!("postgres://sandbox_owner:test@{host}:55432/sandbox_test?sslmode=verify-full&sslrootcert=/tmp/ca.pem"), "sandbox_owner").is_ok());
    }
}

#[test]
fn upgrade_owner_and_runtime_must_match_database_port_and_ca() {
    let owner = "postgres://sandbox_owner:owner@127.0.0.1:55432/upgrade_test?sslmode=verify-full&sslrootcert=/tmp/ca.pem";
    let app = "postgres://sandbox_app:app@127.0.0.1:55432/upgrade_test?sslrootcert=/tmp/ca.pem&sslmode=verify-full";
    assert!(checked_pair(owner, app).is_ok());
    for changed in [
        app.replace("upgrade_test", "other_test"),
        app.replace("55432", "55433"),
        app.replace("/tmp/ca.pem", "/tmp/other.pem"),
    ] {
        assert!(checked_pair(owner, &changed).is_err());
    }
}

#[test]
fn frozen_writer_acl_fixtures_match_recorded_historical_commit() {
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "fixtures/upgrade/v41-roles.sql"
        ))),
        "44a569ccd0e32957458544d4cbd448455cde0598fbe86c355ec21336bbeba3b0"
    );
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "fixtures/upgrade/v41-automation-role.sql"
        ))),
        "8b248bbb0d745b2b1360087d01271df143636a6c5d3e5aaf6f095d690d13d119"
    );
}
