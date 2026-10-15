//! Fail before listening/claiming if the installed accounting guards differ
//! from the reviewed migration, including same-name function replacements.
use sqlx::{PgPool, Row};

const MIGRATION: &str = include_str!("../migrations/0045_launch_resource_accounting.sql");
const TABLES: [&str; 4] = [
    "launch_resource_contracts",
    "quota_resource_receipts",
    "launch_quota_bindings",
    "quota_resource_legacy_baseline",
];
const FUNCTIONS: [(&str, bool, bool); 6] = [
    ("sandbox_guard_quota_resource_identity", false, true),
    ("sandbox_capture_quota_resource", true, true),
    ("sandbox_capture_launch_resource", true, true),
    ("sandbox_bind_launch_quota", true, true),
    ("sandbox_guard_compute_quota_release", true, true),
    // This older shared trigger always raises. Its historical PUBLIC execute
    // grant does not confer mutation authority, but replacing its body would.
    ("sandbox_prevent_audit_mutation", false, false),
];

fn expected_body(name: &str) -> anyhow::Result<&'static str> {
    let declaration = format!("CREATE FUNCTION {name}()");
    let (migration, delimiter) = if name == "sandbox_prevent_audit_mutation" {
        (include_str!("../migrations/0001_core.sql"), "$$")
    } else {
        (MIGRATION, "$resource$")
    };
    let function = migration
        .split_once(&declaration)
        .ok_or_else(|| anyhow::anyhow!("resource accounting function declaration missing"))?
        .1;
    function
        .split(delimiter)
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("resource accounting function body missing"))
}

pub(crate) async fn verify(pool: &PgPool) -> anyhow::Result<()> {
    let shapes: serde_json::Value =
        serde_json::from_str(include_str!("resource_accounting_schema_contract.json"))?;
    for table in TABLES {
        verify_table_structure(pool, table, &shapes[table]).await?;
        let valid: bool = sqlx::query_scalar(r#"
          SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='public' AND c.relname=$1 AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relispartition
            AND c.relrowsecurity AND c.relforcerowsecurity
            AND c.relowner=(SELECT relowner FROM pg_class WHERE oid='public.quota_reservations'::regclass)
            AND (SELECT count(*) FROM pg_policy p WHERE p.polrelid=c.oid)=1
            AND EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid
              AND p.polname='tenant_isolation' AND p.polcmd='*' AND p.polpermissive
              AND p.polroles=ARRAY[0::oid]
              AND replace(replace(pg_get_expr(p.polqual,p.polrelid),'public.',''),' ','')='(tenant_id=sandbox_current_tenant_id())'
              AND replace(replace(pg_get_expr(p.polwithcheck,p.polrelid),'public.',''),' ','')='(tenant_id=sandbox_current_tenant_id())'))
        "#).bind(table).fetch_one(pool).await?;
        anyhow::ensure!(
            valid,
            "Resource accounting table/RLS guard differs: {table}"
        );
        let unsafe_access: bool = sqlx::query_scalar(r#"
          SELECT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname IN
            ('sandbox_app','sandbox_worker','sandbox_gateway','sandbox_admission','sandbox_termination',
             'sandbox_fencing','sandbox_volume_deleter','sandbox_backup','sandbox_automation',
             'sandbox_browser','sandbox_restore','sandbox_restore_admission','sandbox_restore_gc','sandbox_restore_gc_admission')
            AND (has_table_privilege(r.oid,('public.'||$1)::regclass,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
              OR has_any_column_privilege(r.oid,('public.'||$1)::regclass,'INSERT,UPDATE,REFERENCES')
              OR ($1='quota_resource_legacy_baseline' AND (has_table_privilege(r.oid,('public.'||$1)::regclass,'SELECT') OR has_any_column_privilege(r.oid,('public.'||$1)::regclass,'SELECT')))))
        "#).bind(table).fetch_one(pool).await?;
        anyhow::ensure!(
            !unsafe_access,
            "Resource accounting runtime write/baseline grants are unsafe: {table}"
        );
        verify_trigger(
            pool,
            table,
            "append_only",
            "sandbox_prevent_audit_mutation",
            27,
            false,
            &[],
        )
        .await?;
    }
    let readable: bool = sqlx::query_scalar("SELECT has_table_privilege('sandbox_app','public.launch_resource_contracts','SELECT') AND has_table_privilege('sandbox_app','public.quota_resource_receipts','SELECT') AND has_table_privilege('sandbox_app','public.launch_quota_bindings','SELECT')")
        .fetch_one(pool).await?;
    anyhow::ensure!(readable, "Resource accounting API read grants are missing");
    for (name, definer, closed) in FUNCTIONS {
        let row = sqlx::query(r#"
          SELECT p.prosrc,p.prosecdef,p.proconfig,(SELECT lanname='plpgsql' FROM pg_language WHERE oid=p.prolang) AS correct_language,(p.provolatile='v' AND p.proparallel='u' AND NOT p.proisstrict AND NOT p.proleakproof AND NOT p.proretset) AS function_shape,p.prorettype='trigger'::regtype AS trigger_result,
            p.proowner=(SELECT relowner FROM pg_class WHERE oid='public.quota_reservations'::regclass) AS correct_owner,
            NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
              WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_closed,
            NOT EXISTS(SELECT 1 FROM pg_roles runtime WHERE runtime.rolname IN
              ('sandbox_app','sandbox_worker','sandbox_gateway','sandbox_admission','sandbox_termination',
               'sandbox_fencing','sandbox_volume_deleter','sandbox_backup','sandbox_automation',
               'sandbox_browser','sandbox_restore','sandbox_restore_admission','sandbox_restore_gc','sandbox_restore_gc_admission')
              AND has_function_privilege(runtime.oid,p.oid,'EXECUTE')) AS runtime_closed
          FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
          WHERE n.nspname='public' AND p.proname=$1 AND p.pronargs=0 AND p.prokind='f'
        "#).bind(name).fetch_optional(pool).await?
            .ok_or_else(|| anyhow::anyhow!("Resource accounting function missing: {name}"))?;
        anyhow::ensure!(
            row.try_get::<String, _>("prosrc")? == expected_body(name)?
                && row.try_get::<bool, _>("prosecdef")? == definer
                && row.try_get::<Option<Vec<String>>, _>("proconfig")?
                    == Some(vec!["search_path=pg_catalog".into()])
                && row.try_get::<bool, _>("correct_language")?
                && row.try_get::<bool, _>("function_shape")?
                && row.try_get::<bool, _>("trigger_result")?
                && row.try_get::<bool, _>("correct_owner")?
                && (!closed
                    || (row.try_get::<bool, _>("public_closed")?
                        && row.try_get::<bool, _>("runtime_closed")?)),
            "Resource accounting function guard differs: {name}"
        );
    }
    verify_trigger(
        pool,
        "quota_resource_legacy_baseline",
        "baseline_closed",
        "sandbox_prevent_audit_mutation",
        7,
        false,
        &[],
    )
    .await?;
    verify_trigger(
        pool,
        "quota_reservations",
        "quota_resource_identity_guard",
        "sandbox_guard_quota_resource_identity",
        31,
        false,
        &[],
    )
    .await?;
    verify_trigger(
        pool,
        "quota_accounts",
        "quota_account_resource_identity_guard",
        "sandbox_guard_quota_resource_identity",
        27,
        false,
        &[],
    )
    .await?;
    verify_trigger(
        pool,
        "quota_reservations",
        "quota_resource_capture",
        "sandbox_capture_quota_resource",
        21,
        false,
        &["status"],
    )
    .await?;
    verify_trigger(
        pool,
        "instances",
        "launch_resource_capture",
        "sandbox_capture_launch_resource",
        21,
        false,
        &["cluster_epoch", "launch_id", "runtime_generation"],
    )
    .await?;
    verify_trigger(
        pool,
        "launch_resource_contracts",
        "launch_resource_quota_complete",
        "sandbox_bind_launch_quota",
        5,
        true,
        &[],
    )
    .await?;
    verify_trigger(
        pool,
        "quota_reservations",
        "quota_resource_launch_binding",
        "sandbox_bind_launch_quota",
        5,
        true,
        &[],
    )
    .await?;
    verify_trigger(
        pool,
        "quota_reservations",
        "compute_quota_release_proof",
        "sandbox_guard_compute_quota_release",
        17,
        true,
        &["status"],
    )
    .await?;
    Ok(())
}

async fn verify_trigger(
    pool: &PgPool,
    table: &str,
    name: &str,
    function: &str,
    kind: i16,
    deferred: bool,
    columns: &[&str],
) -> anyhow::Result<()> {
    let row = sqlx::query(r#"
      SELECT t.tgtype,t.tgenabled::text AS enabled,t.tgdeferrable,t.tginitdeferred,
        t.tgqual IS NULL AND t.tgnargs=0 AND NOT t.tgisinternal AS plain_trigger,
        p.proname::text AS function,n.nspname::text AS function_schema,
        ARRAY(SELECT a.attname::text FROM unnest(t.tgattr::smallint[]) num
          JOIN pg_attribute a ON a.attrelid=t.tgrelid AND a.attnum=num ORDER BY a.attname) AS columns
      FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace n ON n.oid=p.pronamespace
      WHERE t.tgrelid=('public.'||$1)::regclass AND t.tgname=$2
    "#).bind(table).bind(name).fetch_optional(pool).await?
        .ok_or_else(|| anyhow::anyhow!("Resource accounting trigger missing: {table}.{name}"))?;
    anyhow::ensure!(
        row.try_get::<i16, _>("tgtype")? == kind
            && row.try_get::<String, _>("enabled")? == "O"
            && row.try_get::<bool, _>("tgdeferrable")? == deferred
            && row.try_get::<bool, _>("tginitdeferred")? == deferred
            && row.try_get::<bool, _>("plain_trigger")?
            && row.try_get::<String, _>("function")? == function
            && row.try_get::<String, _>("function_schema")? == "public"
            && row.try_get::<Vec<String>, _>("columns")? == columns,
        "Resource accounting trigger guard differs: {table}.{name}"
    );
    Ok(())
}

// The checked-in structural contract comes from the normally applied reviewed
// migration on the locked PostgreSQL 17 server. It contains names and structure,
// never OIDs, storage identities, row data or timestamps. PostgreSQL-major
// upgrades must review expression deparsing before changing this contract.
const SCHEMA_SHAPE_SQL: &str = r#"
SELECT jsonb_build_object(
  'columns',COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'name',a.attname,'type',format_type(a.atttypid,a.atttypmod),
      'not_null',a.attnotnull,'identity',a.attidentity::text,'generated',a.attgenerated::text,
      'default',pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attnum)
    FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum)
    WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),'[]'::jsonb),
  'constraints',COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'name',k.conname,'kind',k.contype::text,'deferrable',k.condeferrable,
      'initially_deferred',k.condeferred,'validated',k.convalidated,
      'local',k.conislocal,'inherited_count',k.coninhcount,'no_inherit',k.connoinherit,
      'columns',ARRAY(SELECT a.attname::text FROM unnest(k.conkey) WITH ORDINALITY key(attnum,position)
          JOIN pg_attribute a ON a.attrelid=k.conrelid AND a.attnum=key.attnum ORDER BY key.position),
      'referenced_table',(SELECT n.nspname||'.'||r.relname FROM pg_class r JOIN pg_namespace n ON n.oid=r.relnamespace WHERE r.oid=k.confrelid),
      'referenced_columns',ARRAY(SELECT a.attname::text FROM unnest(k.confkey) WITH ORDINALITY key(attnum,position)
          JOIN pg_attribute a ON a.attrelid=k.confrelid AND a.attnum=key.attnum ORDER BY key.position),
      'update_action',k.confupdtype::text,'delete_action',k.confdeltype::text,
      'match',k.confmatchtype::text,'expression',pg_get_expr(k.conbin,k.conrelid)) ORDER BY k.conname)
    FROM pg_constraint k WHERE k.conrelid=c.oid),'[]'::jsonb),
  'indexes',COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'name',ic.relname,'access_method',am.amname,'unique',i.indisunique,
      'primary',i.indisprimary,'valid',i.indisvalid,'ready',i.indisready,
      'immediate',i.indimmediate,'nulls_not_distinct',i.indnullsnotdistinct,
      'key_count',i.indnkeyatts,'attribute_count',i.indnatts,
      'predicate',pg_get_expr(i.indpred,i.indrelid),'expressions',pg_get_expr(i.indexprs,i.indrelid),
      'keys',COALESCE((SELECT jsonb_agg(jsonb_build_object(
          'column',a.attname,'options',i.indoption[(key.position-1)::integer],
          'operator_class',(SELECT n.nspname||'.'||o.opcname FROM pg_opclass o JOIN pg_namespace n ON n.oid=o.opcnamespace WHERE o.oid=i.indclass[(key.position-1)::integer]),
          'collation',(SELECT n.nspname||'.'||o.collname FROM pg_collation o JOIN pg_namespace n ON n.oid=o.collnamespace WHERE o.oid=i.indcollation[(key.position-1)::integer])) ORDER BY key.position)
        FROM unnest(i.indkey::smallint[]) WITH ORDINALITY key(attnum,position)
        LEFT JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=key.attnum),'[]'::jsonb)) ORDER BY ic.relname)
    FROM pg_index i JOIN pg_class ic ON ic.oid=i.indexrelid JOIN pg_am am ON am.oid=ic.relam
    WHERE i.indrelid=c.oid),'[]'::jsonb))
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relname=$1 AND c.relkind='r'
"#;

async fn verify_table_structure(
    pool: &PgPool,
    table: &str,
    expected: &serde_json::Value,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        expected.is_object(),
        "Resource accounting structural contract missing: {table}"
    );
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL search_path=pg_catalog")
        .execute(&mut *tx)
        .await?;
    let actual: serde_json::Value = sqlx::query_scalar(SCHEMA_SHAPE_SQL)
        .bind(table)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Resource accounting table missing: {table}"))?;
    anyhow::ensure!(
        actual == *expected,
        "Resource accounting table structure differs: {table}"
    );
    tx.commit().await?;
    Ok(())
}
