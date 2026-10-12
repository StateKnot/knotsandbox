-- Run as migration owner after a DBA creates the dedicated LOGIN.
BEGIN;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='sandbox_admission' AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole) THEN
        RAISE EXCEPTION 'provision an unprivileged sandbox_admission login first';
    END IF;
    IF pg_has_role('sandbox_admission',current_user,'MEMBER') OR pg_has_role('sandbox_admission','sandbox_app','MEMBER') OR pg_has_role('sandbox_admission','sandbox_worker','MEMBER') THEN
        RAISE EXCEPTION 'sandbox_admission must not inherit owner/app/worker';
    END IF;
END;
$$;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM sandbox_admission;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM sandbox_admission;
GRANT USAGE ON SCHEMA public TO sandbox_admission;
GRANT SELECT(version,success,checksum) ON _sqlx_migrations TO sandbox_admission;
GRANT EXECUTE ON FUNCTION sandbox_current_tenant_id(),sandbox_principal_enabled(uuid),sandbox_admit_execution_connect(uuid,uuid,uuid,uuid) TO sandbox_admission;
GRANT SELECT ON tenants,projects,grants,template_versions,security_policy_versions,platform_configuration,instances,workspaces,operations,executions,external_resources TO sandbox_admission;
GRANT SELECT ON launch_permits,termination_challenges TO sandbox_admission;
GRANT SELECT(id,tenant_id,project_id,challenge_id,permit_id,instance_id,workspace_id,generation,launch_id,pod_uid,cluster_epoch,runtime_node_id,recorded_at,observed_at) ON local_termination_proofs TO sandbox_admission;
GRANT SELECT(id,cluster_epoch,node_name) ON runtime_nodes TO sandbox_admission;
GRANT EXECUTE ON FUNCTION sandbox_workspace_cleanup_authorized(uuid,uuid,text,text,uuid,text,uuid,text,boolean) TO sandbox_admission;
GRANT EXECUTE ON FUNCTION sandbox_never_authorized_pod(uuid,uuid,uuid) TO sandbox_admission;
GRANT EXECUTE ON FUNCTION sandbox_guarded_node_binding(uuid,uuid,uuid,text,uuid,text) TO sandbox_admission;
-- Migration 0036 file-transfer component grants.
GRANT SELECT ON file_transfers TO sandbox_admission;
GRANT EXECUTE ON FUNCTION sandbox_check_file_connect(uuid,uuid,uuid,uuid,boolean) TO sandbox_admission;
COMMIT;
