-- The tenant catalog itself uses FORCE RLS, so an owner without a tenant GUC
-- cannot enumerate it. The non-tenant-facing routing index already contains
-- every routed tenant and is the authoritative discovery source for this repair.
DO $$
DECLARE candidate record;previous_tenant text:=current_setting('app.tenant_id',true);
BEGIN
    FOR candidate IN SELECT DISTINCT tenant_id FROM public.operation_dispatch LOOP
        PERFORM set_config('app.tenant_id',candidate.tenant_id::text,true);
        UPDATE public.operations o
        SET launch_registration_next_attempt_at=o.launch_registration_next_attempt_at
        WHERE o.tenant_id=candidate.tenant_id
          AND EXISTS(SELECT 1 FROM public.operation_dispatch d
              WHERE d.tenant_id=o.tenant_id AND d.operation_id=o.id);
    END LOOP;
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
END $$;
