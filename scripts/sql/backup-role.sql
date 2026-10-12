-- Owner-applied object grants; provision the independent LOGIN outside migrations.
BEGIN;
DO $$ DECLARE peer text;BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='sandbox_backup' AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole) THEN
  RAISE EXCEPTION 'provision an unprivileged sandbox_backup login first';END IF;
 IF pg_has_role('sandbox_backup',current_user,'MEMBER') THEN RAISE EXCEPTION 'backup controller must not inherit migration owner';END IF;
 FOREACH peer IN ARRAY ARRAY['sandbox_app','sandbox_worker','sandbox_gateway','sandbox_admission','sandbox_termination','sandbox_fencing','sandbox_volume_deleter'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=peer) AND(pg_has_role('sandbox_backup',peer,'MEMBER') OR pg_has_role(peer,'sandbox_backup','MEMBER')) THEN
   RAISE EXCEPTION 'backup controller and runtime roles must not share membership';END IF;
 END LOOP;
END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM sandbox_backup;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM sandbox_backup;
GRANT USAGE ON SCHEMA public TO sandbox_backup;
GRANT SELECT(version,success,checksum) ON _sqlx_migrations TO sandbox_backup;
GRANT EXECUTE ON FUNCTION sandbox_current_tenant_id(),sandbox_principal_enabled(uuid),sandbox_claim_backup(text),sandbox_workspace_cold_backup_ready(uuid,uuid),sandbox_backup_authorized(uuid,uuid,boolean),sandbox_node_certified_until(uuid) TO sandbox_backup;
GRANT SELECT ON tenants,projects,grants,platform_configuration,instances,workspaces,executions,launch_permits,local_termination_proofs,termination_cleanup_receipts,runtime_nodes,backup_profiles,workspace_holds,workspace_hold_releases,quota_accounts TO sandbox_backup;
GRANT UPDATE(id) ON instances,workspaces TO sandbox_backup;
-- The controller can advance its durable operation, never the compute instance.
GRANT SELECT,UPDATE ON operations,backups,quota_reservations TO sandbox_backup;
GRANT UPDATE(pending,allocated,version,updated_at) ON quota_accounts TO sandbox_backup;
GRANT SELECT,INSERT ON backup_attempts,backup_resource_intents,backup_resource_bindings,backup_snapshot_receipts,backup_clone_receipts,backup_job_contexts,backup_launch_permits,backup_launch_receipts,backup_close_challenges,backup_termination_proofs,backup_cleanup_receipts,backup_capture_reports,backup_vault_receipts,backup_stage_results,workspace_hold_releases,audit_events,domain_events TO sandbox_backup;
GRANT SELECT ON backup_pod_admissions TO sandbox_backup;
GRANT SELECT,INSERT,UPDATE ON runtime_node_journal_highwater TO sandbox_backup;
-- Apply after roles.sql; product API may accept/query, not forge completion.
GRANT SELECT,INSERT ON backups,backup_attempts,backup_resource_intents TO sandbox_app;
GRANT SELECT ON backup_profiles,launch_permits,local_termination_proofs,termination_cleanup_receipts,workspace_hold_releases TO sandbox_app;
GRANT SELECT,INSERT ON workspace_holds TO sandbox_app;
GRANT EXECUTE ON FUNCTION sandbox_workspace_cold_backup_ready(uuid,uuid) TO sandbox_app;
-- Admission has read authority and a single narrowly scoped consume-once gate.
GRANT SELECT ON backups,backup_profiles,backup_attempts,backup_resource_intents,backup_resource_bindings,backup_snapshot_receipts,backup_clone_receipts,backup_job_contexts,backup_pod_admissions,backup_launch_permits,backup_termination_proofs,backup_cleanup_receipts,workspace_holds,workspace_hold_releases TO sandbox_admission;
GRANT EXECUTE ON FUNCTION sandbox_backup_authorized(uuid,uuid,boolean),sandbox_admit_backup_pod(uuid,uuid,uuid,uuid) TO sandbox_admission;
GRANT EXECUTE ON FUNCTION sandbox_backup_node_binding(uuid,uuid,uuid,text,uuid,text),sandbox_backup_node_observation(uuid,uuid,uuid,text,uuid,text) TO sandbox_admission;
COMMIT;
