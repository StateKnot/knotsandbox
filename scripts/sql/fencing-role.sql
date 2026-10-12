-- No tenant caller may create a node incident. This login only consumes
-- installation-owner tombstones and does not receive quota or proof privileges.
BEGIN;
DO $$
DECLARE other_role text;
BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='sandbox_fencing' AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole) THEN
        RAISE EXCEPTION 'provision an unprivileged sandbox_fencing login first';END IF;
    IF pg_has_role('sandbox_fencing',current_user,'MEMBER') THEN RAISE EXCEPTION 'fencing cannot inherit owner';END IF;
    FOREACH other_role IN ARRAY ARRAY['sandbox_app','sandbox_worker','sandbox_gateway','sandbox_admission','sandbox_termination'] LOOP
        IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=other_role) AND
          (pg_has_role('sandbox_fencing',other_role,'MEMBER') OR pg_has_role(other_role,'sandbox_fencing','MEMBER')) THEN
            RAISE EXCEPTION 'fencing role must not share other runtime identities';END IF;
    END LOOP;
END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM sandbox_fencing;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM sandbox_fencing;
GRANT USAGE ON SCHEMA public TO sandbox_fencing;
GRANT SELECT(version,success,checksum) ON _sqlx_migrations TO sandbox_fencing;
GRANT SELECT ON runtime_nodes,platform_configuration,node_fence_incidents,node_fence_targets TO sandbox_fencing;
GRANT UPDATE(state,attempt_id,dispatched_at,stopped_observed_at,breach_at,lease_owner,lease_token,lease_until,next_attempt_at) ON node_fence_incidents TO sandbox_fencing;
GRANT INSERT ON node_fence_events TO sandbox_fencing;
GRANT EXECUTE ON FUNCTION sandbox_freeze_node_launch(uuid,uuid,text,bigint) TO sandbox_fencing;
COMMIT;
