-- Owner-applied only after private 0038 plus its GC companion. Production
-- startup still rejects a private draft without the normal SQLx migration.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='sandbox_restore_gc' AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole)
  OR pg_has_role('sandbox_restore_gc',current_user,'MEMBER') THEN
  RAISE EXCEPTION 'an independent unprivileged restore GC login is required';END IF;
END $$;
GRANT USAGE ON SCHEMA public TO sandbox_restore_gc;
GRANT EXECUTE ON FUNCTION sandbox_current_tenant_id() TO sandbox_restore_gc;
GRANT SELECT ON _sqlx_migrations TO sandbox_restore_gc;
GRANT SELECT ON restore_gc_reviews,restore_gc_runs,restore_gc_dispatches,restore_gc_results,
 restore_gc_cloud_absences,restore_gc_kube_absences,restore_gc_settlements TO sandbox_restore_gc;
GRANT SELECT ON restore_resource_intents,restore_resource_bindings TO sandbox_restore_gc;
GRANT INSERT ON restore_gc_dispatches,restore_gc_results,restore_gc_cloud_absences,restore_gc_kube_absences TO sandbox_restore_gc;
-- Reviews and queue creation are owner-only; this login cannot broaden a
-- policy, change the source/target identities or manipulate quota directly.
GRANT EXECUTE ON FUNCTION sandbox_restore_gc_candidates(integer),sandbox_claim_restore_gc(uuid,uuid,text,integer),
 sandbox_wait_restore_gc(uuid,uuid,text,bigint,text,integer),sandbox_finish_restore_gc(uuid,uuid,text,bigint),sandbox_assert_restore_gc_claim(uuid,uuid,text,bigint) TO sandbox_restore_gc;
COMMIT;
