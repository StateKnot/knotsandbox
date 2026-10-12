-- DBA provisions this independent unprivileged LOGIN; credentials stay external.
BEGIN;
DO $$ DECLARE other_role text; BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='sandbox_volume_deleter' AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole) THEN
  RAISE EXCEPTION 'provision an unprivileged sandbox_volume_deleter login first';END IF;
 IF pg_has_role('sandbox_volume_deleter',current_user,'MEMBER') THEN RAISE EXCEPTION 'volume deleter must not inherit migration owner';END IF;
 FOREACH other_role IN ARRAY ARRAY['sandbox_app','sandbox_worker','sandbox_gateway','sandbox_admission','sandbox_termination','sandbox_fencing','sandbox_backup'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=other_role) AND
    (pg_has_role('sandbox_volume_deleter',other_role,'MEMBER') OR pg_has_role(other_role,'sandbox_volume_deleter','MEMBER')) THEN
   RAISE EXCEPTION 'volume deleter and runtime roles must not share membership';END IF;
 END LOOP;
END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM sandbox_volume_deleter;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM sandbox_volume_deleter;
GRANT USAGE ON SCHEMA public TO sandbox_volume_deleter;
GRANT SELECT(version,success,checksum) ON _sqlx_migrations TO sandbox_volume_deleter;
GRANT EXECUTE ON FUNCTION sandbox_current_tenant_id(),sandbox_principal_enabled(uuid),sandbox_workspace_writers_closed(uuid,uuid),sandbox_claim_volume_deletion(text) TO sandbox_volume_deleter;
GRANT SELECT ON tenants,projects,grants,platform_configuration,instances,launch_permits,local_termination_proofs,termination_cleanup_receipts,runtime_nodes,executions,workspace_holds,workspace_hold_releases,workspace_delete_intents TO sandbox_volume_deleter;
GRANT SELECT,UPDATE ON workspaces,operations,quota_reservations,external_resources TO sandbox_volume_deleter;
GRANT SELECT ON quota_accounts TO sandbox_volume_deleter;
GRANT UPDATE(pending,allocated,version,updated_at) ON quota_accounts TO sandbox_volume_deleter;
GRANT SELECT,INSERT ON workspace_delete_bindings,workspace_delete_attempts,workspace_delete_results,workspace_snapshot_preserve_attempts,workspace_snapshot_preserve_results,workspace_disk_absences,workspace_delete_cleanups,audit_events,domain_events TO sandbox_volume_deleter;
COMMIT;
