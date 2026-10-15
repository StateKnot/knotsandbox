//! The trusted observation boundary is checked before any component listens or
//! claims work, and by the independent schema preflight command.
use sqlx::{PgPool, Row};

use crate::resource_accounting_schema::{verify_table_structure, verify_trigger};

const MIGRATION: &str = include_str!("../migrations/0046_launch_pod_resource_observations.sql");
pub(crate) const RECORD_SIGNATURE: &str = "sandbox_record_launch_resource_observation(uuid,uuid,text,text,uuid,text,text,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,timestamptz)";
const RUNTIME_ROLES: &str = "'sandbox_app','sandbox_worker','sandbox_gateway','sandbox_admission','sandbox_termination','sandbox_fencing','sandbox_volume_deleter','sandbox_backup','sandbox_automation','sandbox_browser','sandbox_restore','sandbox_restore_admission','sandbox_restore_gc','sandbox_restore_gc_admission'";

pub(crate) async fn verify(pool: &PgPool) -> anyhow::Result<()> {
    let shapes: serde_json::Value = serde_json::from_str(include_str!(
        "launch_resource_observation_schema_contract.json"
    ))?;
    for table in [
        "launch_pod_resource_observations",
        "launch_registration_legacy_baseline",
        // The composite identity FK targets are themselves part of this
        // contract, including their reviewed unique constraints.
        "launch_permits",
        "runtime_nodes",
    ] {
        verify_table_structure(pool, table, &shapes[table]).await?;
    }
    for table in [
        "launch_pod_resource_observations",
        "launch_registration_legacy_baseline",
    ] {
        let valid: bool = sqlx::query_scalar(r#"
            SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relname=$1 AND c.relkind='r' AND c.relpersistence='p'
              AND NOT c.relispartition AND c.relrowsecurity AND c.relforcerowsecurity
              AND c.relowner=(SELECT relowner FROM pg_class WHERE oid='public.quota_reservations'::regclass)
              AND (SELECT count(*) FROM pg_policy p WHERE p.polrelid=c.oid)=1
              AND EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant_isolation'
                AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
                AND replace(replace(pg_get_expr(p.polqual,p.polrelid),'public.',''),' ','')='(tenant_id=sandbox_current_tenant_id())'
                AND replace(replace(pg_get_expr(p.polwithcheck,p.polrelid),'public.',''),' ','')='(tenant_id=sandbox_current_tenant_id())'))
        "#).bind(table).fetch_one(pool).await?;
        anyhow::ensure!(valid, "Trusted resource observation RLS differs: {table}");
        let unsafe_access: bool = sqlx::query_scalar(&format!(r#"
            SELECT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname IN ({RUNTIME_ROLES})
              AND (has_table_privilege(r.oid,('public.'||$1)::regclass,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                OR has_any_column_privilege(r.oid,('public.'||$1)::regclass,'INSERT,UPDATE,REFERENCES')
                OR (($1='launch_registration_legacy_baseline' OR r.rolname<>'sandbox_app') AND
                    (has_table_privilege(r.oid,('public.'||$1)::regclass,'SELECT')
                        OR has_any_column_privilege(r.oid,('public.'||$1)::regclass,'SELECT')))))
        "#)).bind(table).fetch_one(pool).await?;
        anyhow::ensure!(
            !unsafe_access,
            "Trusted resource observation grants are unsafe: {table}"
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
    let readable: bool = sqlx::query_scalar("SELECT has_table_privilege('sandbox_app','public.launch_pod_resource_observations','SELECT')")
        .fetch_one(pool).await?;
    anyhow::ensure!(
        readable,
        "Trusted resource observation API read grant missing"
    );
    for (signature, result_type) in [
        ("sandbox_guard_launch_resource_registration()", "trigger"),
        ("sandbox_guard_launch_resource_observation()", "trigger"),
        ("sandbox_lock_registration_boundary(uuid)", "boolean"),
        (RECORD_SIGNATURE, "uuid"),
    ] {
        let returns_trigger = result_type == "trigger";
        let name = signature
            .split_once('(')
            .ok_or_else(|| anyhow::anyhow!("Invalid fixed observation function signature"))?
            .0;
        let expected = MIGRATION
            .split_once(&format!("CREATE FUNCTION {name}("))
            .ok_or_else(|| anyhow::anyhow!("Missing reviewed observation function"))?
            .1
            .split("$observation$")
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("Missing reviewed observation function body"))?;
        let row = sqlx::query(&format!(r#"
            SELECT p.prosrc,p.prosecdef,p.proconfig,
                p.prorettype=to_regtype($3) AS correct_result,
                (SELECT lanname='plpgsql' FROM pg_language WHERE oid=p.prolang) AS correct_language,
                p.provolatile='v' AND p.proparallel='u' AND NOT p.proisstrict AND NOT p.proleakproof
                    AND NOT p.proretset AND p.prokind='f' AS correct_shape,
                p.proowner=(SELECT relowner FROM pg_class WHERE oid='public.quota_reservations'::regclass) AS correct_owner,
                NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
                    WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_closed,
                NOT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname IN ({RUNTIME_ROLES})
                    AND has_function_privilege(r.oid,p.oid,'EXECUTE')
                        IS DISTINCT FROM (r.rolname='sandbox_termination' AND NOT $2)) AS runtime_grants
            FROM pg_proc p WHERE p.oid=to_regprocedure('public.'||$1)
        "#)).bind(signature).bind(returns_trigger).bind(result_type).fetch_optional(pool).await?
            .ok_or_else(|| anyhow::anyhow!("Trusted resource observation function missing: {name}"))?;
        anyhow::ensure!(
            row.try_get::<String, _>("prosrc")? == expected
                && row.try_get::<bool, _>("prosecdef")?
                && row.try_get::<Option<Vec<String>>, _>("proconfig")?
                    == Some(vec!["search_path=pg_catalog".into()])
                && row.try_get::<bool, _>("correct_result")?
                && row.try_get::<bool, _>("correct_language")?
                && row.try_get::<bool, _>("correct_shape")?
                && row.try_get::<bool, _>("correct_owner")?
                && row.try_get::<bool, _>("public_closed")?
                && row.try_get::<bool, _>("runtime_grants")?,
            "Trusted resource observation function differs: {name}"
        );
    }
    for (table, name, function, kind, deferred) in [
        (
            "launch_registration_legacy_baseline",
            "baseline_closed",
            "sandbox_prevent_audit_mutation",
            7,
            false,
        ),
        (
            "launch_permit_receipts",
            "launch_registration_resource_complete",
            "sandbox_guard_launch_resource_registration",
            5,
            true,
        ),
        (
            "launch_permit_extension_receipts",
            "launch_extension_resource_complete",
            "sandbox_guard_launch_resource_registration",
            5,
            true,
        ),
        (
            "launch_pod_resource_observations",
            "launch_resource_observation_ack",
            "sandbox_guard_launch_resource_observation",
            5,
            true,
        ),
    ] {
        verify_trigger(pool, table, name, function, kind, deferred, &[]).await?;
    }
    Ok(())
}
