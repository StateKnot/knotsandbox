-- Owner-applied automation grants after normal migration 0039 and roles.sql.
-- LOGIN/password provisioning belongs to the DBA. This script creates neither.
-- API grants are independent of the coordinator's installation/health.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='sandbox_app' AND rolcanlogin
     AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole) THEN
  RAISE EXCEPTION 'provision an unprivileged sandbox_app login first';
 END IF;
 IF pg_catalog.pg_has_role('sandbox_app',current_user,'MEMBER') THEN
  RAISE EXCEPTION 'automation API must not inherit migration owner';
 END IF;
END $$;
GRANT SELECT,INSERT,UPDATE ON automation_delegations,automations TO sandbox_app;
GRANT SELECT(id,tenant_id,project_id,automation_id,automation_version,version,scheduled_for,source_event_id,source_event_sequence,skipped_through,operation_kind,expected_resource_version,expected_generation,status,operation_id,failure_code,deadline,created_at,updated_at,completed_at) ON automation_runs TO sandbox_app;
GRANT UPDATE(status,failure_code,completed_at,updated_at) ON automation_runs TO sandbox_app;
GRANT EXECUTE ON FUNCTION sandbox_automation_authorized(uuid,uuid),sandbox_automation_required_actions(text,boolean) TO sandbox_app;
GRANT EXECUTE ON FUNCTION sandbox_check_automation_delegation(uuid,uuid,text[],timestamptz) TO sandbox_app;

-- The coordinator identity is optional while installing the API. If it exists,
-- invalid privilege or membership fails the whole grant transaction.
DO $$ DECLARE peer text; BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='sandbox_automation') THEN
  RETURN;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='sandbox_automation' AND rolcanlogin
     AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole) THEN
  RAISE EXCEPTION 'automation coordinator login must be unprivileged';
 END IF;
 IF pg_catalog.pg_has_role('sandbox_automation',current_user,'MEMBER')
    OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.relnamespace='public'::regnamespace
              AND pg_catalog.pg_has_role('sandbox_automation',c.relowner,'MEMBER')) THEN
  RAISE EXCEPTION 'automation coordinator must not inherit any application owner';
 END IF;
 FOREACH peer IN ARRAY ARRAY['sandbox_app','sandbox_worker','sandbox_gateway','sandbox_admission',
   'sandbox_termination','sandbox_fencing','sandbox_volume_deleter','sandbox_backup'] LOOP
  IF EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=peer)
     AND(pg_catalog.pg_has_role('sandbox_automation',peer,'MEMBER')
         OR pg_catalog.pg_has_role(peer,'sandbox_automation','MEMBER')) THEN
   RAISE EXCEPTION 'automation coordinator and runtime roles must not share membership';
  END IF;
 END LOOP;
 EXECUTE $automation_grants$
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM sandbox_automation;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM sandbox_automation;
GRANT USAGE ON SCHEMA public TO sandbox_automation;
GRANT SELECT(version,success,checksum) ON _sqlx_migrations TO sandbox_automation;
GRANT EXECUTE ON FUNCTION sandbox_current_tenant_id(),sandbox_resolve_identity(text,text),sandbox_principal_enabled(uuid),sandbox_instance_certification(uuid,uuid),sandbox_never_authorized_stop_candidate(uuid,uuid),sandbox_workspace_cold_backup_ready(uuid,uuid) TO sandbox_automation;
GRANT EXECUTE ON FUNCTION sandbox_claim_automation(text),sandbox_check_automation_claim(uuid,uuid,text,bigint),sandbox_finish_automation_claim(uuid,uuid,text,bigint),sandbox_bind_automation_run_claim(uuid,uuid,text,bigint),sandbox_automation_authorized(uuid,uuid),sandbox_automation_required_actions(text,boolean) TO sandbox_automation;
GRANT SELECT ON tenants,projects,grants,platform_configuration,template_versions,security_policy_versions,quota_accounts,launch_permits,local_termination_proofs,termination_cleanup_receipts,backup_profiles,workspace_holds,workspace_hold_releases,event_stream_positions,event_stream_heads,domain_events,file_transfers TO sandbox_automation;
GRANT EXECUTE ON FUNCTION sandbox_workspace_writers_closed(uuid,uuid) TO sandbox_automation;
GRANT SELECT,INSERT,UPDATE ON instances,workspaces,operations,executions,idempotency_keys,quota_reservations,external_resources TO sandbox_automation;
GRANT UPDATE(pending,allocated,version,updated_at) ON quota_accounts TO sandbox_automation;
GRANT SELECT,INSERT ON backups,backup_attempts,backup_resource_intents,workspace_holds,audit_events,domain_events TO sandbox_automation;
GRANT SELECT ON automations TO sandbox_automation;
GRANT UPDATE(next_due_at,event_sequence,status,version,emitted_runs,last_emitted_at,updated_at) ON automations TO sandbox_automation;
GRANT SELECT(id,tenant_id,project_id,expires_at,revoked_at) ON automation_delegations TO sandbox_automation;
-- UPDATE id solely permits resource-ordered row locking of delegation authority.
GRANT UPDATE(id) ON automation_delegations TO sandbox_automation;
GRANT SELECT(id,tenant_id,project_id,automation_id,automation_version,version,delegation_id,creator_principal_id,instance_id,workspace_id,scheduled_for,source_event_id,source_event_sequence,skipped_through,operation_kind,original_request,operation_request,expected_resource_version,expected_generation,cluster_epoch,produced_resource_id,management_key,request_sha256,status,operation_id,failure_code,deadline,created_at,updated_at,completed_at) ON automation_runs TO sandbox_automation;
GRANT INSERT ON automation_runs TO sandbox_automation;
GRANT UPDATE(status,failure_code,completed_at,updated_at) ON automation_runs TO sandbox_automation;
$automation_grants$;
END $$;
COMMIT;
