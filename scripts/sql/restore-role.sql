-- Owner-applied after 0038 and backup-role.sql. Restore keeps the existing
-- dedicated backup controller identity; ordinary workers cannot claim it.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='sandbox_backup' AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole)
  OR pg_has_role('sandbox_backup',current_user,'MEMBER') THEN
  RAISE EXCEPTION 'an independent unprivileged backup login is required';END IF;
END $$;
GRANT SELECT,INSERT ON restores TO sandbox_app;
GRANT EXECUTE ON FUNCTION sandbox_restored_workspace_delete_binding(uuid,uuid) TO sandbox_volume_deleter;
GRANT EXECUTE ON FUNCTION sandbox_restored_never_started(uuid,uuid,uuid) TO sandbox_termination;
GRANT EXECUTE ON FUNCTION sandbox_restore_birth_guard(uuid,uuid,uuid,uuid) TO sandbox_app;
GRANT EXECUTE ON FUNCTION sandbox_lock_restored_runtime(uuid,uuid,uuid) TO sandbox_admission;
GRANT EXECUTE ON FUNCTION sandbox_workspace_restore_binding(uuid,uuid) TO sandbox_app,sandbox_worker,sandbox_admission,sandbox_termination,sandbox_gateway,sandbox_volume_deleter;
-- Read-only immutable first-START identity; these roles cannot forge restore receipts.
GRANT SELECT ON restore_delivery_receipts TO sandbox_app,sandbox_worker,sandbox_termination,sandbox_gateway,sandbox_volume_deleter;
GRANT SELECT ON restores TO sandbox_worker,sandbox_termination,sandbox_gateway,sandbox_volume_deleter;
GRANT SELECT ON backup_vault_receipts TO sandbox_app;
GRANT EXECUTE ON FUNCTION sandbox_lock_restore_source(uuid,uuid) TO sandbox_app;
GRANT EXECUTE ON FUNCTION sandbox_lock_restore_configuration(uuid,uuid,uuid,uuid,timestamptz) TO sandbox_app;
GRANT EXECUTE ON FUNCTION sandbox_restore_profile_current(uuid,uuid,timestamptz) TO sandbox_app,sandbox_backup,sandbox_admission;
GRANT EXECUTE ON FUNCTION sandbox_restore_storage_contract_certified(uuid,uuid,jsonb) TO sandbox_app,sandbox_backup,sandbox_admission;
-- Pure shape checks confer no authority; INSERT/UPDATE constraints run as the caller.
GRANT EXECUTE ON FUNCTION sandbox_restore_storage_contract_valid(jsonb),sandbox_restore_storage_mapping_valid(jsonb) TO sandbox_app,sandbox_backup;
GRANT SELECT,UPDATE ON restores TO sandbox_backup;
-- 0036's deferred instance/file slot-consistency trigger runs after the
-- narrow definer returns, so the publishing login must inspect held file rows.
-- File payload/parts and file mutation privileges stay outside this role.
GRANT SELECT ON file_transfers TO sandbox_backup;
GRANT SELECT ON backup_vault_receipts,restore_pod_admissions TO sandbox_backup;
GRANT SELECT,INSERT ON restore_vault_receipts,restore_resource_intents,restore_resource_bindings,
 restore_block_receipts,restore_job_contexts,restore_launch_permits,restore_launch_receipts,
 restore_close_challenges,restore_termination_proofs,restore_cleanup_receipts,
 restore_io_reports,restore_snapshot_receipts,restore_delivery_receipts,restore_artifact_cleanup_receipts TO sandbox_backup;
GRANT EXECUTE ON FUNCTION sandbox_restore_authorized(uuid,uuid,boolean),sandbox_publish_restore(uuid,uuid,bigint) TO sandbox_backup;
GRANT SELECT ON restores,restore_vault_receipts,restore_resource_intents,restore_resource_bindings,
 restore_block_receipts,restore_job_contexts,restore_pod_admissions,restore_launch_permits,
 restore_launch_receipts,restore_close_challenges,restore_termination_proofs,
 restore_cleanup_receipts,restore_io_reports,restore_snapshot_receipts,restore_delivery_receipts TO sandbox_admission;
GRANT EXECUTE ON FUNCTION sandbox_restore_authorized(uuid,uuid,boolean) TO sandbox_admission;
GRANT EXECUTE ON FUNCTION sandbox_admit_restore_pod(uuid,uuid,uuid,uuid) TO sandbox_admission;
GRANT EXECUTE ON FUNCTION sandbox_lock_restore_admission(uuid,uuid) TO sandbox_admission;
GRANT EXECUTE ON FUNCTION sandbox_restore_admission_horizon(uuid,uuid) TO sandbox_admission;
GRANT EXECUTE ON FUNCTION sandbox_lock_restore_observation(uuid,uuid) TO sandbox_admission;
GRANT EXECUTE ON FUNCTION sandbox_restore_node_binding(uuid,uuid,uuid,text,uuid,text),sandbox_restore_node_observation(uuid,uuid,uuid,text,uuid,text) TO sandbox_admission;
GRANT EXECUTE ON FUNCTION sandbox_restore_control_cleanup(uuid,uuid,text,text,uuid),sandbox_restore_job_status(uuid,uuid,text,uuid) TO sandbox_admission;
COMMIT;
