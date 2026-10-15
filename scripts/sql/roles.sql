-- Run after migrations, as the schema/database owner:
--   psql "$MIGRATION_DATABASE_URL" -v ON_ERROR_STOP=1 -f scripts/sql/roles.sql
-- The administrator must provision sandbox_app separately as a LOGIN role with
-- NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE, not a member of the owner role.
-- This script does not create accounts, set passwords, or grant elevated roles.
BEGIN;
DO $$
DECLARE unsafe boolean;
BEGIN
    SELECT r.rolsuper OR r.rolbypassrls OR r.rolcreatedb OR r.rolcreaterole
           OR pg_has_role('sandbox_app', current_user, 'MEMBER')
    INTO unsafe FROM pg_roles r WHERE r.rolname = 'sandbox_app';
    IF unsafe IS NULL THEN
        RAISE EXCEPTION 'provision the sandbox_app runtime login before applying grants';
    END IF;
    IF unsafe THEN
        RAISE EXCEPTION 'sandbox_app must not be privileged or a member of the migration owner';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'public' AND tableowner = 'sandbox_app') THEN
        RAISE EXCEPTION 'sandbox_app must not own application tables';
    END IF;
END;
$$;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM sandbox_app;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM sandbox_app;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM sandbox_app;
GRANT USAGE ON SCHEMA public TO sandbox_app;
GRANT SELECT(version,success,checksum) ON _sqlx_migrations TO sandbox_app;
GRANT EXECUTE ON FUNCTION sandbox_current_tenant_id(),sandbox_instance_certification(uuid,uuid) TO sandbox_app;
GRANT EXECUTE ON FUNCTION sandbox_resolve_identity(text, text),sandbox_resolve_identity(text,text,text) TO sandbox_app;
GRANT EXECUTE ON FUNCTION sandbox_principal_enabled(uuid) TO sandbox_app;

GRANT SELECT ON tenants, projects, grants, template_versions, security_policy_versions TO sandbox_app;
GRANT SELECT ON platform_configuration,execution_output_segments TO sandbox_app;
GRANT SELECT(id,node_uid,boot_id) ON runtime_nodes TO sandbox_app;
GRANT SELECT(tenant_id,project_id,instance_id,generation,launch_id,cluster_epoch,runtime_node_id) ON launch_permits TO sandbox_app;
GRANT SELECT ON event_stream_heads,event_stream_positions TO sandbox_app;
GRANT SELECT ON tenant_principals,management_receipts TO sandbox_app;
GRANT INSERT ON management_receipts TO sandbox_app;
GRANT EXECUTE ON FUNCTION sandbox_lock_identity_tenant(uuid),
    sandbox_check_grant_delegation(uuid,uuid,text,timestamptz,boolean),
    sandbox_mutate_project_grant(uuid,uuid,text,uuid,uuid,text,timestamptz,boolean,bigint) TO sandbox_app;
GRANT SELECT, INSERT, UPDATE ON instances, workspaces, operations, executions,
    idempotency_keys, quota_reservations, external_resources TO sandbox_app;
GRANT SELECT ON quota_accounts TO sandbox_app;
GRANT UPDATE (pending, allocated, version, updated_at) ON quota_accounts TO sandbox_app;
GRANT SELECT, INSERT ON audit_events, domain_events TO sandbox_app;
-- Outbox payload remains immutable; only the acknowledged publication time moves.
GRANT UPDATE (published_at) ON domain_events TO sandbox_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
-- New migrations must deliberately grant their new tables; no blanket access to
-- future credentials, principal directories, or security configuration tables.
GRANT EXECUTE ON FUNCTION sandbox_workspace_writers_closed(uuid,uuid) TO sandbox_app;
GRANT SELECT,INSERT ON workspace_delete_intents TO sandbox_app;
-- Migration 0036 file-transfer component grants.
GRANT SELECT,INSERT,UPDATE ON file_transfers,file_transfer_parts TO sandbox_app;
COMMIT;

GRANT EXECUTE ON FUNCTION sandbox_authorize_service_clients(uuid,text), sandbox_read_service_clients(uuid,uuid,timestamptz,timestamptz,uuid,integer), sandbox_mutate_service_client(uuid,text,uuid,text,text,text,text,boolean,bigint) TO sandbox_app;

GRANT EXECUTE ON FUNCTION sandbox_never_authorized_stop_candidate(uuid,uuid) TO sandbox_app;

GRANT SELECT,INSERT ON diagnoses TO sandbox_app;
GRANT EXECUTE ON FUNCTION sandbox_expire_tenant_diagnoses(uuid,integer) TO sandbox_app;

-- Immutable launch accounting: runtime components cannot author ledger facts.
GRANT SELECT ON launch_resource_contracts,quota_resource_receipts,launch_quota_bindings TO sandbox_app;
GRANT SELECT ON launch_pod_resource_observations TO sandbox_app;

-- Fixed installation read authority only. Management and audit remain owner-only.
GRANT EXECUTE ON FUNCTION sandbox_node_image_access(text,text,text,bigint) TO sandbox_app;
GRANT EXECUTE ON FUNCTION sandbox_node_image_binding(text,text,text,bigint,uuid) TO sandbox_app;
