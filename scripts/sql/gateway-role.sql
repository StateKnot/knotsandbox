-- Migration owner applies this after a DBA provisions the dedicated LOGIN.
BEGIN;
DO $$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='sandbox_gateway' AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole) THEN
        RAISE EXCEPTION 'provision an unprivileged sandbox_gateway login first';
    END IF;
    IF pg_has_role('sandbox_gateway',current_user,'MEMBER') OR pg_has_role('sandbox_gateway','sandbox_app','MEMBER') OR pg_has_role('sandbox_gateway','sandbox_worker','MEMBER') OR pg_has_role('sandbox_gateway','sandbox_admission','MEMBER') THEN
        RAISE EXCEPTION 'gateway must not inherit owner/app/worker/admission roles';
    END IF;
END;
$$;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM sandbox_gateway;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM sandbox_gateway;
GRANT USAGE ON SCHEMA public TO sandbox_gateway;
GRANT SELECT(version,success,checksum) ON _sqlx_migrations TO sandbox_gateway;
GRANT EXECUTE ON FUNCTION sandbox_current_tenant_id(),sandbox_principal_enabled(uuid),sandbox_claim_execution(text) TO sandbox_gateway;
GRANT SELECT ON tenants,projects,grants,template_versions,security_policy_versions,platform_configuration,external_resources TO sandbox_gateway;
GRANT SELECT,UPDATE ON instances,workspaces,operations,executions,quota_reservations TO sandbox_gateway;
GRANT INSERT ON operations TO sandbox_gateway;
GRANT SELECT ON quota_accounts TO sandbox_gateway;
GRANT UPDATE(pending,allocated,version,updated_at) ON quota_accounts TO sandbox_gateway;
GRANT SELECT,INSERT ON execution_output_segments,audit_events,domain_events TO sandbox_gateway;
-- Migration 0036 file-transfer component grants.
GRANT SELECT,UPDATE ON file_transfers,file_transfer_parts TO sandbox_gateway;
GRANT INSERT ON file_transfer_parts TO sandbox_gateway;
GRANT EXECUTE ON FUNCTION sandbox_claim_file_transfer(text) TO sandbox_gateway;
COMMIT;
