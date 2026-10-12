-- Private GC admission readers only: no ability to manufacture absence evidence.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='sandbox_admission' AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole)
  OR pg_has_role('sandbox_admission',current_user,'MEMBER') THEN
  RAISE EXCEPTION 'an independent unprivileged admission login is required';END IF;
END $$;
GRANT EXECUTE ON FUNCTION sandbox_resolve_restore_gc_resource(text,text,text,text,uuid),
 sandbox_restore_gc_metadata(uuid,uuid,text,text,uuid) TO sandbox_admission;
COMMIT;
