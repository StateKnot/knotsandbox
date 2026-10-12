-- Deferred checks run after a restricted SECURITY DEFINER operation returns.
-- Validate each trigger row under its own immutable tenant, rather than the
-- caller's restored context. Runtime logins receive no additional table ACLs;
-- FORCE ROW LEVEL SECURITY and the original activity invariant remain intact.
CREATE OR REPLACE FUNCTION sandbox_file_activity_match() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
    tenant uuid;
    instance uuid;
    runtime public.instances%ROWTYPE;
    active public.file_transfers%ROWTYPE;
    previous_tenant text:=current_setting('app.tenant_id',true);
BEGIN
    IF TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME NOT IN('instances','file_transfers')
       OR TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP NOT IN('INSERT','UPDATE') THEN
        RAISE EXCEPTION 'invalid file activity constraint target' USING ERRCODE='42501';
    END IF;
    tenant:=NEW.tenant_id;
    IF TG_TABLE_NAME='instances' THEN instance:=NEW.id;ELSE instance:=NEW.instance_id;END IF;
    IF tenant IS NULL OR instance IS NULL THEN
        RAISE EXCEPTION 'file activity requires exact row scope' USING ERRCODE='23514';
    END IF;
    PERFORM set_config('app.tenant_id',tenant::text,true);
    SELECT * INTO runtime FROM public.instances i WHERE i.tenant_id=tenant AND i.id=instance;
    SELECT * INTO active FROM public.file_transfers f WHERE f.tenant_id=tenant AND f.instance_id=instance AND f.slot_held;
    IF FOUND AND NOT COALESCE(runtime.slot_held AND runtime.activity_kind='FILE_WRITE' AND runtime.activity_id=active.id AND runtime.activity_generation=active.runtime_generation AND(runtime.runtime_generation,runtime.launch_id,runtime.pod_uid,runtime.cluster_epoch)=(active.runtime_generation,active.launch_id,active.pod_uid,active.cluster_epoch),false) THEN
        RAISE EXCEPTION 'file writer slot requires exact activity identity' USING ERRCODE='23514';
    END IF;
    IF runtime.slot_held AND runtime.activity_kind='FILE_WRITE' AND NOT EXISTS(SELECT 1 FROM public.file_transfers f WHERE f.tenant_id=tenant AND f.id=runtime.activity_id AND f.instance_id=instance AND f.slot_held) THEN
        RAISE EXCEPTION 'file activity requires held file slot' USING ERRCODE='23514';
    END IF;
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
    RETURN NEW;
EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
    RAISE;
END $$;
REVOKE ALL ON FUNCTION sandbox_file_activity_match() FROM PUBLIC;
