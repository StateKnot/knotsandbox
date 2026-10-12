-- Run as the migration owner after a DBA provisions the sandbox_worker LOGIN.
-- It must not be a member of sandbox_owner or sandbox_app.
BEGIN;
DO $$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='sandbox_worker' AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole) THEN
        RAISE EXCEPTION 'provision an unprivileged sandbox_worker login first';
    END IF;
    IF pg_has_role('sandbox_worker',current_user,'MEMBER') THEN
        RAISE EXCEPTION 'sandbox_worker must not inherit migration owner';
    END IF;
END;
$$;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM sandbox_worker;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM sandbox_worker;
GRANT USAGE ON SCHEMA public TO sandbox_worker;
GRANT SELECT(version,success,checksum) ON _sqlx_migrations TO sandbox_worker;
GRANT EXECUTE ON FUNCTION sandbox_current_tenant_id(),sandbox_principal_enabled(uuid),sandbox_claim_operation(text) TO sandbox_worker;
GRANT EXECUTE ON FUNCTION sandbox_due_instances(integer) TO sandbox_worker;
GRANT SELECT ON tenants,projects,grants,template_versions,security_policy_versions,platform_configuration TO sandbox_worker;
GRANT SELECT,UPDATE ON instances,workspaces,operations,executions,quota_reservations TO sandbox_worker;
GRANT INSERT ON operations TO sandbox_worker;
GRANT SELECT,INSERT,UPDATE ON external_resources TO sandbox_worker;
GRANT SELECT ON quota_accounts TO sandbox_worker;
GRANT UPDATE(pending,allocated,version,updated_at) ON quota_accounts TO sandbox_worker;
GRANT SELECT,INSERT ON audit_events,domain_events TO sandbox_worker;
GRANT UPDATE(published_at) ON domain_events TO sandbox_worker;
GRANT EXECUTE ON FUNCTION sandbox_launch_registered(uuid,uuid,bigint,uuid,uuid,uuid) TO sandbox_worker;
-- Migration 0036 file-transfer component grants.
GRANT SELECT ON file_transfers,file_transfer_parts,file_part_cleanup_receipts TO sandbox_worker;
GRANT UPDATE(content_status,version,updated_at) ON file_transfers TO sandbox_worker;
GRANT UPDATE(status,cleaned_at) ON file_transfer_parts TO sandbox_worker;
GRANT INSERT ON file_part_cleanup_receipts TO sandbox_worker;
GRANT EXECUTE ON FUNCTION sandbox_file_cleanup_candidates(integer) TO sandbox_worker;
COMMIT;

GRANT SELECT ON diagnoses TO sandbox_worker;
GRANT UPDATE(status,snapshot_at,completed_at,report,failure_code) ON diagnoses TO sandbox_worker;
GRANT EXECUTE ON FUNCTION sandbox_maintain_diagnoses(integer),sandbox_instance_certification(uuid,uuid) TO sandbox_worker;
