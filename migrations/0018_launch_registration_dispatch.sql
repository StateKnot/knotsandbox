-- Registration retry scheduling was added after the original queue trigger.
-- Keep both dispatch clocks synchronized, including a RESTART's phase switch.
DROP TRIGGER operation_dispatch_sync ON operations;
CREATE TRIGGER operation_dispatch_sync
AFTER INSERT OR UPDATE OF status,lease_until,next_attempt_at,
    launch_registration_next_attempt_at,restart_generation,kind ON operations
FOR EACH ROW EXECUTE FUNCTION sandbox_update_dispatch();

-- Repair active legacy rows with their existing due time; do not reset retries
-- or resurrect terminal operations. FORCE RLS remains active during migration.
DO $$
DECLARE tenant record;previous_tenant text:=current_setting('app.tenant_id',true);
BEGIN
    FOR tenant IN SELECT id FROM public.tenants LOOP
        PERFORM set_config('app.tenant_id',tenant.id::text,true);
        UPDATE public.operations o SET launch_registration_next_attempt_at=o.launch_registration_next_attempt_at
        WHERE o.tenant_id=tenant.id AND (o.status IN('QUEUED','RUNNING','WAITING')
            OR EXISTS(SELECT 1 FROM public.operation_dispatch d WHERE d.operation_id=o.id AND d.tenant_id=o.tenant_id));
    END LOOP;
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
END $$;
