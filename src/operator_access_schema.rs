//! Startup and maintenance preflight for the installation authority contract.
use sqlx::{PgPool, Row};

use crate::resource_accounting_schema::{verify_table_structure, verify_trigger};

const MIGRATION: &str = include_str!("../migrations/0047_installation_operator_authorization.sql");
const NODE_MIGRATION: &str = include_str!("../migrations/0014_trusted_termination.sql");
const BINDING_MIGRATION: &str = include_str!("../migrations/0048_operator_node_image_binding.sql");
const RUNTIME_ROLES: &str = "'sandbox_app','sandbox_worker','sandbox_gateway','sandbox_admission','sandbox_termination','sandbox_fencing','sandbox_volume_deleter','sandbox_backup','sandbox_automation','sandbox_browser','sandbox_restore','sandbox_restore_admission','sandbox_restore_gc','sandbox_restore_gc_admission'";

pub(crate) async fn verify(pool: &PgPool) -> anyhow::Result<()> {
    let shapes: serde_json::Value =
        serde_json::from_str(include_str!("operator_access_schema_contract.json"))?;
    for table in [
        "platform_configuration",
        "node_image_reader_grants",
        "node_image_reader_audit",
    ] {
        verify_table_structure(pool, table, &shapes[table]).await?;
    }
    let scope_closed: bool = sqlx::query_scalar(&format!(r#"
      SELECT c.relowner=(SELECT relowner FROM pg_class WHERE oid='public._sqlx_migrations'::regclass)
       AND c.relpersistence='p' AND NOT c.relispartition AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
       AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a
         WHERE a.grantee<>c.relowner AND a.privilege_type<>'SELECT')
       AND NOT EXISTS(SELECT 1 FROM pg_attribute att CROSS JOIN LATERAL aclexplode(att.attacl) a
         WHERE att.attrelid=c.oid AND a.grantee<>c.relowner AND a.privilege_type<>'SELECT')
       AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname IN({RUNTIME_ROLES})
         AND (has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
           OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES')))
      FROM pg_class c WHERE c.oid='public.platform_configuration'::regclass
    "#)).fetch_one(pool).await?;
    anyhow::ensure!(
        scope_closed,
        "Installation scope owner or write privileges differ"
    );
    for table in ["node_image_reader_grants", "node_image_reader_audit"] {
        let closed: bool = sqlx::query_scalar(&format!(r#"
          SELECT NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND c.relpersistence='p' AND NOT c.relispartition
           AND c.relowner=(SELECT relowner FROM pg_class WHERE oid='public._sqlx_migrations'::regclass)
           AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee<>c.relowner)
           AND NOT EXISTS(SELECT 1 FROM pg_attribute att CROSS JOIN LATERAL aclexplode(att.attacl) a
             WHERE att.attrelid=c.oid AND a.grantee<>c.relowner)
           AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname IN({RUNTIME_ROLES})
             AND (has_table_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
               OR has_any_column_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
          FROM pg_class c WHERE c.oid=('public.'||$1)::regclass
        "#)).bind(table).fetch_one(pool).await?;
        anyhow::ensure!(
            closed,
            "Installation authority table owner or grants differ: {table}"
        );
    }
    for (signature, language, definer, result, names) in [
        (
            "sandbox_guard_node_image_reader()",
            "plpgsql",
            false,
            "trigger",
            vec![],
        ),
        (
            "sandbox_audit_node_image_reader()",
            "plpgsql",
            true,
            "trigger",
            vec![],
        ),
        (
            "sandbox_invalidate_node_image_reader()",
            "plpgsql",
            true,
            "trigger",
            vec![],
        ),
        (
            "sandbox_grant_node_image_reader(uuid,uuid,uuid,text,text,text,timestamptz,text)",
            "plpgsql",
            true,
            "uuid",
            vec![
                "requested_grant_id",
                "requested_installation",
                "requested_epoch",
                "requested_issuer",
                "requested_subject",
                "requested_client",
                "requested_expiry",
                "requested_change_reason",
            ],
        ),
        (
            "sandbox_revoke_node_image_reader(uuid,uuid,uuid,text)",
            "plpgsql",
            true,
            "void",
            vec![
                "requested_grant_id",
                "requested_installation",
                "requested_epoch",
                "requested_change_reason",
            ],
        ),
        (
            "sandbox_node_image_access(text,text,text,bigint)",
            "sql",
            true,
            "TABLE(installation_id uuid, cluster_epoch uuid, grant_id uuid, expires_at timestamp with time zone)",
            vec![
                "issuer",
                "subject",
                "client",
                "token_exp",
                "installation_id",
                "cluster_epoch",
                "grant_id",
                "expires_at",
            ],
        ),
        (
            "sandbox_preserve_runtime_node()",
            "plpgsql",
            false,
            "trigger",
            vec![],
        ),
        (
            "sandbox_node_image_binding(text,text,text,bigint,uuid)",
            "sql",
            true,
            "TABLE(installation_id uuid, cluster_epoch uuid, grant_id uuid, grant_expires_at timestamp with time zone, runtime_node_id uuid, node_uid uuid, host_boot_id uuid, profile_sha256 text, certified_until timestamp with time zone)",
            vec![
                "issuer",
                "subject",
                "client",
                "token_exp",
                "requested_node",
                "installation_id",
                "cluster_epoch",
                "grant_id",
                "grant_expires_at",
                "runtime_node_id",
                "node_uid",
                "host_boot_id",
                "profile_sha256",
                "certified_until",
            ],
        ),
    ] {
        let name = signature
            .split('(')
            .next()
            .ok_or_else(|| anyhow::anyhow!("Invalid authority signature"))?;
        let reader = matches!(
            name,
            "sandbox_node_image_access" | "sandbox_node_image_binding"
        );
        let migration = match name {
            "sandbox_node_image_binding" => BINDING_MIGRATION,
            "sandbox_preserve_runtime_node" => NODE_MIGRATION,
            _ => MIGRATION,
        };
        let body = migration
            .split_once(&format!("CREATE FUNCTION {name}("))
            .and_then(|(_, tail)| tail.split("$$").nth(1))
            .ok_or_else(|| anyhow::anyhow!("Missing reviewed authority function"))?;
        let row = sqlx::query(&format!(r#"
          SELECT p.prosrc,p.prosecdef,p.proconfig,COALESCE(p.proargnames,ARRAY[]::text[]) AS names,
           pg_get_function_result(p.oid) AS result,(SELECT lanname FROM pg_language WHERE oid=p.prolang) AS language,
           p.provolatile='v' AND p.proparallel='u' AND NOT p.proisstrict AND NOT p.proleakproof
             AND p.proretset=$2 AND p.prokind='f' AS correct_shape,
           p.proowner=(SELECT relowner FROM pg_class WHERE oid='public._sqlx_migrations'::regclass) AS correct_owner,
           NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
             WHERE a.grantee<>p.proowner AND NOT($2 AND a.grantee=(SELECT oid FROM pg_roles WHERE rolname='sandbox_app') AND NOT a.is_grantable)) AS closed_acl,
           NOT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname IN({RUNTIME_ROLES})
             AND has_function_privilege(r.oid,p.oid,'EXECUTE') IS DISTINCT FROM (r.rolname='sandbox_app' AND $2)) AS runtime_grants
          FROM pg_proc p WHERE p.oid=to_regprocedure('public.'||$1)
        "#)).bind(signature).bind(reader).fetch_optional(pool).await?
            .ok_or_else(|| anyhow::anyhow!("Installation authority function missing: {name}"))?;
        anyhow::ensure!(
            row.try_get::<String, _>("prosrc")? == body
                && row.try_get::<bool, _>("prosecdef")? == definer
                && row.try_get::<Option<Vec<String>>, _>("proconfig")?
                    == Some(vec!["search_path=pg_catalog".into()])
                && row.try_get::<Vec<String>, _>("names")? == names
                && row.try_get::<String, _>("result")? == result
                && row.try_get::<String, _>("language")? == language
                && [
                    "correct_shape",
                    "correct_owner",
                    "closed_acl",
                    "runtime_grants"
                ]
                .iter()
                .all(|key| row.try_get::<bool, _>(*key).unwrap_or(false)),
            "Installation authority function differs: {name}"
        );
    }
    for (table, name, function, kind) in [
        (
            "node_image_reader_audit",
            "append_only",
            "sandbox_prevent_audit_mutation",
            27,
        ),
        (
            "node_image_reader_grants",
            "immutable_node_image_reader",
            "sandbox_guard_node_image_reader",
            27,
        ),
        (
            "node_image_reader_grants",
            "audit_node_image_reader",
            "sandbox_audit_node_image_reader",
            21,
        ),
        (
            "principals",
            "node_image_reader_principal_change",
            "sandbox_invalidate_node_image_reader",
            17,
        ),
        (
            "principal_identities",
            "node_image_reader_identity_change",
            "sandbox_invalidate_node_image_reader",
            17,
        ),
        (
            "platform_configuration",
            "node_image_reader_scope_change",
            "sandbox_invalidate_node_image_reader",
            17,
        ),
    ] {
        verify_trigger(pool, table, name, function, kind, false, &[]).await?;
    }
    let enrollment_shape: serde_json::Value =
        serde_json::from_str(include_str!("node_image_enrollment_schema_contract.json"))?;
    verify_table_structure(pool, "runtime_node_enrollments", &enrollment_shape).await?;
    for table in ["runtime_nodes", "runtime_node_enrollments"] {
        let closed: bool = sqlx::query_scalar(&format!(r#"
          SELECT c.relowner=(SELECT relowner FROM pg_class WHERE oid='public._sqlx_migrations'::regclass)
           AND c.relpersistence='p' AND NOT c.relispartition AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
           AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a
             WHERE a.grantee<>c.relowner AND (a.privilege_type<>'SELECT' OR $1='runtime_node_enrollments'))
           AND NOT EXISTS(SELECT 1 FROM pg_attribute att CROSS JOIN LATERAL aclexplode(att.attacl) a
             WHERE att.attrelid=c.oid AND a.grantee<>c.relowner AND (a.privilege_type<>'SELECT' OR $1='runtime_node_enrollments'))
           AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname IN({RUNTIME_ROLES})
             AND (has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
               OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES')
               OR ($1='runtime_node_enrollments' AND (has_table_privilege(r.oid,c.oid,'SELECT') OR has_any_column_privilege(r.oid,c.oid,'SELECT')))))
          FROM pg_class c WHERE c.oid=('public.'||$1)::regclass
        "#)).bind(table).fetch_one(pool).await?;
        anyhow::ensure!(
            closed,
            "Node image binding source owner or write privileges differ: {table}"
        );
    }
    verify_trigger(
        pool,
        "runtime_node_enrollments",
        "runtime_node_enrollments_append_only",
        "sandbox_prevent_audit_mutation",
        27,
        false,
        &[],
    )
    .await?;
    verify_trigger(
        pool,
        "runtime_nodes",
        "runtime_node_identity_immutable",
        "sandbox_preserve_runtime_node",
        19,
        false,
        &[],
    )
    .await?;
    verify_trigger(
        pool,
        "runtime_nodes",
        "runtime_node_no_delete",
        "sandbox_prevent_audit_mutation",
        11,
        false,
        &[],
    )
    .await?;
    Ok(())
}
