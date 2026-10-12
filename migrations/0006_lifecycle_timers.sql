INSERT INTO principals(id,kind,display_name) VALUES('00000000-0000-4000-8000-000000000001','SYSTEM','Platform lifecycle safety controller');
ALTER TABLE platform_configuration ADD COLUMN safety_principal_id uuid NOT NULL
    DEFAULT '00000000-0000-4000-8000-000000000001' REFERENCES principals(id);

-- A system actor can never authenticate through a human/machine OAuth binding.
CREATE OR REPLACE FUNCTION sandbox_resolve_identity(identity_issuer text,identity_subject text)
RETURNS TABLE(principal_id uuid,kind text,enabled boolean,authz_version bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
    SELECT p.id,p.kind,p.enabled,p.authz_version
    FROM public.principal_identities i JOIN public.principals p ON p.id=i.principal_id
    WHERE i.issuer=identity_issuer AND i.subject=identity_subject AND i.enabled
      AND p.kind IN ('USER','SERVICE')
$$;

CREATE TABLE instance_timers (
    instance_id uuid PRIMARY KEY REFERENCES instances(id),
    tenant_id uuid NOT NULL,
    due_at timestamptz NOT NULL
);
CREATE INDEX instance_timers_due ON instance_timers(due_at,instance_id);
REVOKE ALL ON instance_timers FROM PUBLIC;

CREATE FUNCTION sandbox_update_instance_timer() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE idle_deadline timestamptz;
BEGIN
    IF NEW.desired_state='RUNNING' AND NEW.stop_accepted_at IS NULL THEN
        idle_deadline := CASE WHEN NOT NEW.slot_held AND NEW.idle_since IS NOT NULL AND NEW.idle_timeout_seconds IS NOT NULL
            THEN NEW.idle_since+make_interval(secs=>NEW.idle_timeout_seconds::double precision) ELSE NULL END;
        INSERT INTO public.instance_timers(instance_id,tenant_id,due_at)
        VALUES(NEW.id,NEW.tenant_id,LEAST(NEW.compute_lease_expires_at,idle_deadline))
        ON CONFLICT(instance_id) DO UPDATE SET due_at=EXCLUDED.due_at;
    ELSE
        DELETE FROM public.instance_timers WHERE instance_id=NEW.id;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER instance_timer_sync AFTER INSERT OR UPDATE OF desired_state,stop_accepted_at,compute_lease_expires_at,idle_since,idle_timeout_seconds,slot_held ON instances
FOR EACH ROW EXECUTE FUNCTION sandbox_update_instance_timer();
REVOKE ALL ON FUNCTION sandbox_update_instance_timer() FROM PUBLIC;

CREATE FUNCTION sandbox_due_instances(batch_size integer)
RETURNS TABLE(tenant_id uuid,instance_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
    SELECT t.tenant_id,t.instance_id FROM public.instance_timers t
    WHERE t.due_at<=clock_timestamp() ORDER BY t.due_at,t.instance_id
    LIMIT LEAST(GREATEST(batch_size,1),100)
$$;
REVOKE ALL ON FUNCTION sandbox_due_instances(integer) FROM PUBLIC;

-- The migration owner enumerates tenants under an exclusive DDL lock, then
-- backfills each tenant with the ordinary local context. FORCE is restored in
-- this migration transaction before any other session can observe the change.
-- Runtime roles are non-owners and remain subject to RLS throughout.
ALTER TABLE tenants NO FORCE ROW LEVEL SECURITY;
DO $$
DECLARE tenant uuid;
BEGIN
    FOR tenant IN SELECT id FROM tenants LOOP
        PERFORM set_config('app.tenant_id',tenant::text,true);
        UPDATE instances SET compute_lease_expires_at=compute_lease_expires_at
        WHERE tenant_id=tenant AND desired_state='RUNNING' AND stop_accepted_at IS NULL;
    END LOOP;
    PERFORM set_config('app.tenant_id','',true);
END;
$$;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
