-- Retry eligibility is scheduling metadata only. due_at remains the actual
-- TTL/idle deadline, synchronized by the existing instance trigger.
ALTER TABLE instance_timers
    ADD COLUMN last_selected_at timestamptz,
    ADD COLUMN next_scan_at timestamptz NOT NULL DEFAULT '-infinity';
CREATE INDEX instance_timers_fair_scan
    ON instance_timers(last_selected_at NULLS FIRST,due_at,instance_id);

-- Atomic selection prevents replicas from repeatedly choosing the same oldest
-- batch. Recently attempted blocked rows move behind every unattempted/older
-- eligible row, so retries cannot monopolize the bounded batch. Selection is
-- not VM fencing: accept_due_stop still rechecks under workspace/instance locks.
CREATE OR REPLACE FUNCTION sandbox_due_instances(batch_size integer)
RETURNS TABLE(tenant_id uuid,instance_id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
    WITH moment AS MATERIALIZED (SELECT clock_timestamp() AS at),
    candidates AS MATERIALIZED (
        SELECT t.instance_id FROM public.instance_timers t
        WHERE t.due_at<=(SELECT m.at FROM moment m)
          AND t.next_scan_at<=(SELECT m.at FROM moment m)
        ORDER BY t.last_selected_at NULLS FIRST,t.due_at,t.instance_id
        LIMIT LEAST(GREATEST(batch_size,1),100)
        FOR UPDATE SKIP LOCKED
    ), selected AS (
        UPDATE public.instance_timers t
        SET last_selected_at=(SELECT m.at FROM moment m),
            next_scan_at=(SELECT m.at+interval '5 seconds' FROM moment m)
        FROM candidates c WHERE t.instance_id=c.instance_id
        RETURNING t.tenant_id,t.instance_id
    ) SELECT s.tenant_id,s.instance_id FROM selected s
$$;
REVOKE ALL ON FUNCTION sandbox_due_instances(integer) FROM PUBLIC;
