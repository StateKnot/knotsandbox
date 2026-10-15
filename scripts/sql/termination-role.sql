-- Dedicated trusted controller login, provisioned by the DBA; never a member
-- of the owner/API/worker/gateway/admission roles. Run as migration owner.
BEGIN;
DO $$
DECLARE other_role text;
BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='sandbox_termination' AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole) THEN
        RAISE EXCEPTION 'provision an unprivileged sandbox_termination login first';END IF;
    IF pg_has_role('sandbox_termination',current_user,'MEMBER') THEN
        RAISE EXCEPTION 'termination controller must not inherit migration owner';END IF;
    FOREACH other_role IN ARRAY ARRAY['sandbox_app','sandbox_worker','sandbox_gateway','sandbox_admission','sandbox_fencing'] LOOP
        IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=other_role) THEN
            IF pg_has_role('sandbox_termination',other_role,'MEMBER') OR pg_has_role(other_role,'sandbox_termination','MEMBER') THEN
                RAISE EXCEPTION 'termination controller and other runtime roles must not share membership';
            END IF;
        END IF;
    END LOOP;
END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM sandbox_termination;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM sandbox_termination;
GRANT USAGE ON SCHEMA public TO sandbox_termination;
GRANT SELECT(version,success,checksum) ON _sqlx_migrations TO sandbox_termination;
GRANT EXECUTE ON FUNCTION sandbox_current_tenant_id(),sandbox_principal_enabled(uuid),sandbox_claim_termination(text),sandbox_launch_registration_candidates(integer),sandbox_node_certified_until(uuid) TO sandbox_termination;
GRANT SELECT ON tenants,projects,grants,template_versions,security_policy_versions,platform_configuration,runtime_nodes TO sandbox_termination;
GRANT SELECT,INSERT ON launch_permits,launch_permit_receipts,launch_permit_extensions,launch_permit_extension_receipts,termination_challenges,local_termination_proofs,termination_cleanup_receipts TO sandbox_termination;
GRANT SELECT,UPDATE ON instances,workspaces,operations,executions,quota_reservations,external_resources TO sandbox_termination;
GRANT INSERT ON quota_reservations TO sandbox_termination;
GRANT SELECT,INSERT,UPDATE ON runtime_node_journal_highwater TO sandbox_termination;
GRANT SELECT ON quota_accounts TO sandbox_termination;
GRANT UPDATE(pending,allocated,version,updated_at) ON quota_accounts TO sandbox_termination;
GRANT SELECT,INSERT ON audit_events,domain_events TO sandbox_termination;
GRANT SELECT ON launch_guard_contracts,launch_guard_contract_revocations,launch_authority_births,never_authorized_closures TO sandbox_termination;
GRANT SELECT,INSERT ON never_authorized_pod_observations TO sandbox_termination;
GRANT EXECUTE ON FUNCTION sandbox_close_never_authorized(uuid,uuid,text,bigint),sandbox_never_authorized(uuid,uuid,uuid,bigint,uuid,uuid,uuid) TO sandbox_termination;
-- Migration 0036 file-transfer component grants.
GRANT SELECT,UPDATE ON file_transfers TO sandbox_termination;
GRANT EXECUTE ON FUNCTION sandbox_lock_registration_boundary(uuid) TO sandbox_termination;
GRANT EXECUTE ON FUNCTION sandbox_record_launch_resource_observation(uuid,uuid,text,text,uuid,text,text,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,timestamptz) TO sandbox_termination;
COMMIT;
