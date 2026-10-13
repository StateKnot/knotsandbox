-- Empty notifications accelerate scanning only. They convey no tenant data,
-- operation identity, payload or authority. The durable routed claim function
-- remains the sole source of work, including due times and expired leases.
CREATE FUNCTION sandbox_notify_worker_dispatch() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    IF NEW.queue_role='WORKER' AND NEW.eligible_at<=clock_timestamp() THEN
        IF TG_OP='INSERT' THEN
            PERFORM pg_notify('sandbox_worker_dispatch','');
        ELSIF OLD.queue_role IS DISTINCT FROM NEW.queue_role
              OR NEW.eligible_at<OLD.eligible_at THEN
            PERFORM pg_notify('sandbox_worker_dispatch','');
        END IF;
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION sandbox_notify_worker_dispatch() FROM PUBLIC;
CREATE TRIGGER worker_dispatch_hint
AFTER INSERT OR UPDATE OF eligible_at,queue_role ON operation_dispatch
FOR EACH ROW EXECUTE FUNCTION sandbox_notify_worker_dispatch();
-- Existing rows need no rewrite: startup and periodic scans recover them.
