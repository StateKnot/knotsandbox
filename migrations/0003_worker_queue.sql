-- A routing index contains no payload, identity claims, or workload output.
-- Only the definer-owned trigger and the narrowly exposed claim function access it.
CREATE TABLE operation_dispatch (
    operation_id uuid PRIMARY KEY REFERENCES operations(id),
    tenant_id uuid NOT NULL,
    eligible_at timestamptz NOT NULL
);
CREATE INDEX operation_dispatch_due ON operation_dispatch(eligible_at,operation_id);
REVOKE ALL ON operation_dispatch FROM PUBLIC;

CREATE FUNCTION sandbox_update_dispatch() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    IF NEW.status IN ('QUEUED','RUNNING','WAITING') THEN
        INSERT INTO public.operation_dispatch(operation_id,tenant_id,eligible_at)
        VALUES(NEW.id,NEW.tenant_id,GREATEST(NEW.next_attempt_at,COALESCE(NEW.lease_until,NEW.next_attempt_at)))
        ON CONFLICT(operation_id) DO UPDATE SET eligible_at=EXCLUDED.eligible_at;
    ELSE
        DELETE FROM public.operation_dispatch WHERE operation_id=NEW.id;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER operation_dispatch_sync AFTER INSERT OR UPDATE OF status,lease_until,next_attempt_at ON operations
FOR EACH ROW EXECUTE FUNCTION sandbox_update_dispatch();
REVOKE ALL ON FUNCTION sandbox_update_dispatch() FROM PUBLIC;

-- Claim changes the tenant context only inside the caller's transaction. The
-- application executes this in a short transaction and then uses explicit scope.
CREATE FUNCTION sandbox_claim_operation(worker_id text)
RETURNS TABLE(tenant_id uuid,operation_id uuid,lease_token bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;
DECLARE found_id uuid;
DECLARE previous_tenant text := current_setting('app.tenant_id',true);
BEGIN
    IF worker_id IS NULL OR char_length(worker_id) NOT BETWEEN 1 AND 128 THEN
        RAISE EXCEPTION 'invalid worker identity' USING ERRCODE='22023';
    END IF;
    -- Do not lock routing rows before operations: API paths lock the operation
    -- before the routing trigger. SKIP LOCKED avoids lock-order inversion.
    FOR candidate IN SELECT d.operation_id,d.tenant_id FROM public.operation_dispatch d
        WHERE d.eligible_at<=clock_timestamp() ORDER BY d.eligible_at,d.operation_id LIMIT 64 LOOP
        PERFORM set_config('app.tenant_id',candidate.tenant_id::text,true);
        SELECT o.id INTO found_id FROM public.operations o
        WHERE o.tenant_id=candidate.tenant_id AND o.id=candidate.operation_id
          AND o.status IN ('QUEUED','RUNNING','WAITING')
          AND o.next_attempt_at<=clock_timestamp()
          AND (o.lease_until IS NULL OR o.lease_until<=clock_timestamp())
        FOR UPDATE SKIP LOCKED;
        IF found_id IS NOT NULL THEN
            RETURN QUERY UPDATE public.operations o
                SET status='RUNNING',lease_owner=worker_id,lease_token=o.lease_token+1,
                    lease_until=clock_timestamp()+interval '30 seconds',attempts=o.attempts+1,
                    updated_at=clock_timestamp()
                WHERE o.id=found_id AND o.tenant_id=candidate.tenant_id
                RETURNING o.tenant_id,o.id,o.lease_token;
            PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
            RETURN;
        END IF;
    END LOOP;
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
END;
$$;
REVOKE ALL ON FUNCTION sandbox_claim_operation(text) FROM PUBLIC;
