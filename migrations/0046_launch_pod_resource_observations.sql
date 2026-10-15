-- Upgrade is a maintenance cutover: drain old registration writers first. A
-- previously issued permit is not historical evidence. Only committed ACKs
-- visible while these locks are held enter the permanent closed baseline.
LOCK TABLE public.launch_permits, public.launch_permit_extensions,
    public.launch_permit_receipts, public.launch_permit_extension_receipts
    IN ACCESS EXCLUSIVE MODE;

ALTER TABLE public.launch_permits ADD CONSTRAINT launch_permit_resource_identity
    UNIQUE(tenant_id,project_id,instance_id,workspace_id,generation,launch_id,
        cluster_epoch,pod_uid,runtime_node_id,id);
ALTER TABLE public.runtime_nodes ADD CONSTRAINT runtime_node_resource_identity
    UNIQUE(id,cluster_epoch,node_uid,boot_id);

CREATE TABLE launch_registration_legacy_baseline (
    registration_kind text NOT NULL CHECK(registration_kind IN ('BASE','EXTENSION')),
    registration_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    instance_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    generation bigint NOT NULL CHECK(generation>0),
    launch_id uuid NOT NULL,
    cluster_epoch uuid NOT NULL,
    pod_uid uuid NOT NULL,
    runtime_node_id uuid NOT NULL,
    node_uid uuid NOT NULL,
    node_boot_id uuid NOT NULL,
    base_permit_id uuid NOT NULL,
    journal_revision bigint NOT NULL CHECK(journal_revision>0),
    effective_expires_at timestamptz NOT NULL,
    registered_at timestamptz NOT NULL,
    captured_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(registration_kind,registration_id),
    FOREIGN KEY(tenant_id,project_id,instance_id,workspace_id,generation,launch_id,
        cluster_epoch,pod_uid,runtime_node_id,base_permit_id)
        REFERENCES public.launch_permits(tenant_id,project_id,instance_id,workspace_id,
            generation,launch_id,cluster_epoch,pod_uid,runtime_node_id,id),
    FOREIGN KEY(runtime_node_id,cluster_epoch,node_uid,node_boot_id)
        REFERENCES public.runtime_nodes(id,cluster_epoch,node_uid,boot_id)
);
ALTER TABLE public.launch_permit_receipts NO FORCE ROW LEVEL SECURITY;
ALTER TABLE public.launch_permit_extension_receipts NO FORCE ROW LEVEL SECURITY;
ALTER TABLE public.launch_permits NO FORCE ROW LEVEL SECURITY;
ALTER TABLE public.launch_permit_extensions NO FORCE ROW LEVEL SECURITY;
INSERT INTO public.launch_registration_legacy_baseline
    (registration_kind,registration_id,tenant_id,project_id,instance_id,workspace_id,
     generation,launch_id,cluster_epoch,pod_uid,runtime_node_id,node_uid,node_boot_id,
     base_permit_id,journal_revision,effective_expires_at,registered_at)
    SELECT 'BASE',r.permit_id,p.tenant_id,p.project_id,p.instance_id,p.workspace_id,
        p.generation,p.launch_id,p.cluster_epoch,p.pod_uid,p.runtime_node_id,n.node_uid,
        n.boot_id,p.id,r.journal_revision,p.expires_at,r.registered_at
    FROM public.launch_permit_receipts r JOIN public.launch_permits p
        ON(p.tenant_id,p.id)=(r.tenant_id,r.permit_id)
    JOIN public.runtime_nodes n ON(n.id,n.cluster_epoch)=(p.runtime_node_id,p.cluster_epoch);
INSERT INTO public.launch_registration_legacy_baseline
    (registration_kind,registration_id,tenant_id,project_id,instance_id,workspace_id,
     generation,launch_id,cluster_epoch,pod_uid,runtime_node_id,node_uid,node_boot_id,
     base_permit_id,journal_revision,effective_expires_at,registered_at)
    SELECT 'EXTENSION',r.extension_id,p.tenant_id,p.project_id,p.instance_id,p.workspace_id,
        p.generation,p.launch_id,p.cluster_epoch,p.pod_uid,p.runtime_node_id,n.node_uid,
        n.boot_id,p.id,r.journal_revision,r.effective_expires_at,r.registered_at
    FROM public.launch_permit_extension_receipts r JOIN public.launch_permit_extensions e
        ON(e.tenant_id,e.id)=(r.tenant_id,r.extension_id)
    JOIN public.launch_permits p ON(p.tenant_id,p.id)=(e.tenant_id,e.base_permit_id)
    JOIN public.runtime_nodes n ON(n.id,n.cluster_epoch)=(p.runtime_node_id,p.cluster_epoch);
DO $observation$
BEGIN
    IF (SELECT count(*) FROM public.launch_registration_legacy_baseline WHERE registration_kind='BASE')
            <> (SELECT count(*) FROM public.launch_permit_receipts)
        OR (SELECT count(*) FROM public.launch_registration_legacy_baseline WHERE registration_kind='EXTENSION')
            <> (SELECT count(*) FROM public.launch_permit_extension_receipts) THEN
        RAISE EXCEPTION 'historical registration identity mismatch; maintenance repair is required' USING ERRCODE='23514';
    END IF;
END
$observation$;
ALTER TABLE public.launch_permit_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE public.launch_permit_extension_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE public.launch_permits FORCE ROW LEVEL SECURITY;
ALTER TABLE public.launch_permit_extensions FORCE ROW LEVEL SECURITY;

CREATE TABLE launch_pod_resource_observations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    instance_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    generation bigint NOT NULL CHECK(generation>0),
    launch_id uuid NOT NULL,
    cluster_epoch uuid NOT NULL,
    base_permit_id uuid NOT NULL,
    registration_id uuid NOT NULL,
    registration_kind text NOT NULL CHECK(registration_kind IN ('BASE','EXTENSION')),
    runtime_node_id uuid NOT NULL,
    node_uid uuid NOT NULL,
    node_boot_id uuid NOT NULL,
    pod_uid uuid NOT NULL,
    pod_resource_version text NOT NULL CHECK(octet_length(pod_resource_version) BETWEEN 1 AND 256 AND pod_resource_version~'^[!-~]+$'),
    class_uid uuid NOT NULL,
    class_resource_version text NOT NULL CHECK(octet_length(class_resource_version) BETWEEN 1 AND 256 AND class_resource_version~'^[!-~]+$'),
    class_config_sha256 text NOT NULL CHECK(class_config_sha256~'^[0-9a-f]{64}$'),
    class_overhead_cpu_millis bigint NOT NULL CHECK(class_overhead_cpu_millis>=0),
    class_overhead_memory_bytes bigint NOT NULL CHECK(class_overhead_memory_bytes>=0),
    workload_request_cpu_millis bigint NOT NULL CHECK(workload_request_cpu_millis>0),
    workload_request_memory_bytes bigint NOT NULL CHECK(workload_request_memory_bytes>0),
    workload_request_ephemeral_bytes bigint NOT NULL CHECK(workload_request_ephemeral_bytes>0),
    workload_limit_cpu_millis bigint NOT NULL CHECK(workload_limit_cpu_millis>0),
    workload_limit_memory_bytes bigint NOT NULL CHECK(workload_limit_memory_bytes>0),
    workload_limit_ephemeral_bytes bigint NOT NULL CHECK(workload_limit_ephemeral_bytes>0),
    pod_overhead_cpu_millis bigint NOT NULL CHECK(pod_overhead_cpu_millis>=0),
    pod_overhead_memory_bytes bigint NOT NULL CHECK(pod_overhead_memory_bytes>=0),
    effective_request_cpu_millis bigint NOT NULL CHECK(effective_request_cpu_millis>0),
    effective_request_memory_bytes bigint NOT NULL CHECK(effective_request_memory_bytes>0),
    effective_request_ephemeral_bytes bigint NOT NULL CHECK(effective_request_ephemeral_bytes>0),
    effective_limit_cpu_millis bigint NOT NULL CHECK(effective_limit_cpu_millis>0),
    effective_limit_memory_bytes bigint NOT NULL CHECK(effective_limit_memory_bytes>0),
    effective_limit_ephemeral_bytes bigint NOT NULL CHECK(effective_limit_ephemeral_bytes>0),
    source text NOT NULL DEFAULT 'KUBERNETES_API_READBACK' CHECK(source='KUBERNETES_API_READBACK'),
    observed_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK(class_uid<>'00000000-0000-0000-0000-000000000000'::uuid),
    CHECK(observed_at<=recorded_at+interval '2 seconds'),
    CHECK((class_overhead_cpu_millis,class_overhead_memory_bytes)=(pod_overhead_cpu_millis,pod_overhead_memory_bytes)),
    CHECK((workload_request_cpu_millis,workload_request_memory_bytes,workload_request_ephemeral_bytes)
        =(workload_limit_cpu_millis,workload_limit_memory_bytes,workload_limit_ephemeral_bytes)),
    CHECK((workload_request_cpu_millis,workload_request_memory_bytes) IN ((1000,2147483648),(2000,4294967296),(4000,8589934592))),
    CHECK(workload_request_ephemeral_bytes BETWEEN 134217728 AND 34359738368
        AND workload_request_ephemeral_bytes%1048576=0),
    CHECK(effective_request_cpu_millis::numeric=workload_request_cpu_millis::numeric+pod_overhead_cpu_millis::numeric
        AND effective_limit_cpu_millis::numeric=workload_limit_cpu_millis::numeric+pod_overhead_cpu_millis::numeric
        AND effective_request_memory_bytes::numeric=workload_request_memory_bytes::numeric+pod_overhead_memory_bytes::numeric
        AND effective_limit_memory_bytes::numeric=workload_limit_memory_bytes::numeric+pod_overhead_memory_bytes::numeric
        AND effective_request_ephemeral_bytes=workload_request_ephemeral_bytes
        AND effective_limit_ephemeral_bytes=workload_limit_ephemeral_bytes),
    UNIQUE(tenant_id,id),
    UNIQUE(tenant_id,base_permit_id),
    UNIQUE(tenant_id,instance_id,generation,launch_id,cluster_epoch),
    FOREIGN KEY(tenant_id,project_id,instance_id,workspace_id,generation,launch_id,
        cluster_epoch,pod_uid,runtime_node_id,base_permit_id)
        REFERENCES public.launch_permits(tenant_id,project_id,instance_id,workspace_id,
            generation,launch_id,cluster_epoch,pod_uid,runtime_node_id,id),
    FOREIGN KEY(runtime_node_id,cluster_epoch,node_uid,node_boot_id)
        REFERENCES public.runtime_nodes(id,cluster_epoch,node_uid,boot_id)
);
CREATE INDEX launch_pod_resource_observations_read
    ON public.launch_pod_resource_observations(tenant_id,project_id,instance_id,launch_id,cluster_epoch,id);

DO $observation$
DECLARE tab text;
BEGIN
    FOREACH tab IN ARRAY ARRAY['launch_pod_resource_observations','launch_registration_legacy_baseline'] LOOP
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);
        EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
        EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.sandbox_current_tenant_id()) WITH CHECK(tenant_id=public.sandbox_current_tenant_id())',tab);
        EXECUTE format('CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.sandbox_prevent_audit_mutation()',tab);
        EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',tab);
    END LOOP;
END
$observation$;
CREATE TRIGGER baseline_closed BEFORE INSERT ON public.launch_registration_legacy_baseline
    FOR EACH ROW EXECUTE FUNCTION public.sandbox_prevent_audit_mutation();

-- Row-locking SELECT itself requires UPDATE privilege. Keep inventory and
-- installation configuration immutable to runtime roles by exposing only this
-- tenant-scoped lock/read gate, never granting UPDATE to obtain a SHARE lock.
CREATE FUNCTION sandbox_lock_registration_boundary(node_id uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $observation$
DECLARE configuration public.platform_configuration;allowed boolean;
BEGIN
    IF NOT EXISTS(SELECT 1 FROM public.launch_permits p
        WHERE p.tenant_id=public.sandbox_current_tenant_id() AND p.runtime_node_id=node_id) THEN
        RETURN false;
    END IF;
    SELECT * INTO configuration FROM public.platform_configuration WHERE singleton FOR SHARE;
    SELECT n.enabled AND n.cluster_epoch=configuration.cluster_epoch AND NOT configuration.safe_mode
        AND NOT EXISTS(SELECT 1 FROM public.node_fence_incidents f
            WHERE(f.cloud_account_id,f.region,f.cloud_instance_id)=(n.cloud_account_id,n.region,n.cloud_instance_id))
        INTO allowed FROM public.runtime_nodes n WHERE n.id=node_id FOR SHARE;
    RETURN COALESCE(allowed,false);
END
$observation$;

-- A receipt cannot commit alone. Absence of an observation, the age of a permit,
-- timestamps and caller-set GUCs never classify a new ACK as historical.
CREATE FUNCTION sandbox_guard_launch_resource_registration() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $observation$
DECLARE base_id uuid;registration uuid;kind text;previous_tenant text:=current_setting('app.tenant_id',true);
BEGIN
    PERFORM set_config('app.tenant_id',NEW.tenant_id::text,true);
    IF TG_TABLE_NAME='launch_permit_receipts' THEN
        base_id:=NEW.permit_id;registration:=NEW.permit_id;kind:='BASE';
    ELSE
        SELECT e.base_permit_id INTO base_id FROM public.launch_permit_extensions e
            WHERE e.tenant_id=NEW.tenant_id AND e.id=NEW.extension_id;
        registration:=NEW.extension_id;kind:='EXTENSION';
    END IF;
    IF base_id IS NULL OR NOT (
        EXISTS(SELECT 1 FROM public.launch_registration_legacy_baseline b
            WHERE b.tenant_id=NEW.tenant_id AND b.registration_kind=kind
                AND b.registration_id=registration AND b.base_permit_id=base_id)
        OR EXISTS(SELECT 1 FROM public.launch_pod_resource_observations o
            WHERE o.tenant_id=NEW.tenant_id AND o.base_permit_id=base_id)) THEN
        RAISE EXCEPTION 'new registration ACK requires an atomic trusted Pod resource observation' USING ERRCODE='23514';
    END IF;
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
    RETURN NEW;
EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
    RAISE;
END
$observation$;
CREATE CONSTRAINT TRIGGER launch_registration_resource_complete AFTER INSERT ON public.launch_permit_receipts
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.sandbox_guard_launch_resource_registration();
CREATE CONSTRAINT TRIGGER launch_extension_resource_complete AFTER INSERT ON public.launch_permit_extension_receipts
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.sandbox_guard_launch_resource_registration();

CREATE FUNCTION sandbox_guard_launch_resource_observation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $observation$
DECLARE acknowledged boolean;previous_tenant text:=current_setting('app.tenant_id',true);
BEGIN
    PERFORM set_config('app.tenant_id',NEW.tenant_id::text,true);
    IF NEW.registration_kind='BASE' THEN
        SELECT NEW.registration_id=NEW.base_permit_id AND EXISTS(
            SELECT 1 FROM public.launch_permit_receipts r WHERE r.tenant_id=NEW.tenant_id
                AND r.permit_id=NEW.registration_id) INTO acknowledged;
    ELSE
        SELECT EXISTS(SELECT 1 FROM public.launch_permit_extension_receipts r
            JOIN public.launch_permit_extensions e ON(e.tenant_id,e.id)=(r.tenant_id,r.extension_id)
            WHERE r.tenant_id=NEW.tenant_id AND r.extension_id=NEW.registration_id
                AND e.base_permit_id=NEW.base_permit_id) INTO acknowledged;
    END IF;
    IF acknowledged IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'trusted Pod resource observation requires its atomic registration ACK' USING ERRCODE='23514';
    END IF;
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
    RETURN NEW;
EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
    RAISE;
END
$observation$;
CREATE CONSTRAINT TRIGGER launch_resource_observation_ack AFTER INSERT ON public.launch_pod_resource_observations
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.sandbox_guard_launch_resource_observation();

-- This narrow entry point belongs only to the authenticated termination
-- controller. Its Rust caller supplies a non-deserializable verified capability;
-- the API role and every other component have neither EXECUTE nor table writes.
CREATE FUNCTION sandbox_record_launch_resource_observation(
    base uuid,registration uuid,kind text,pod_rv text,class_id uuid,class_rv text,class_hash text,
    class_cpu bigint,class_memory bigint,request_cpu bigint,request_memory bigint,request_ephemeral bigint,
    limit_cpu bigint,limit_memory bigint,limit_ephemeral bigint,overhead_cpu bigint,overhead_memory bigint,
    effective_request_cpu bigint,effective_request_memory bigint,effective_request_ephemeral bigint,
    effective_limit_cpu bigint,effective_limit_memory bigint,effective_limit_ephemeral bigint,observed timestamptz)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $observation$
DECLARE p public.launch_permits;n public.runtime_nodes;existing public.launch_pod_resource_observations;result uuid;
BEGIN
    IF observed IS NULL OR observed<clock_timestamp()-interval '30 seconds'
        OR observed>clock_timestamp()+interval '2 seconds'
        OR pod_rv IS NULL OR octet_length(pod_rv) NOT BETWEEN 1 AND 256 OR pod_rv!~'^[!-~]+$'
        OR class_rv IS NULL OR octet_length(class_rv) NOT BETWEEN 1 AND 256 OR class_rv!~'^[!-~]+$' THEN
        RAISE EXCEPTION 'resource observation must be a fresh bounded API readback' USING ERRCODE='23514';
    END IF;
    SELECT * INTO p FROM public.launch_permits WHERE tenant_id=public.sandbox_current_tenant_id() AND id=base;
    IF p.id IS NULL OR NOT ((kind='BASE' AND registration=base)
        OR (kind='EXTENSION' AND EXISTS(SELECT 1 FROM public.launch_permit_extensions e
            WHERE e.tenant_id=p.tenant_id AND e.id=registration AND e.base_permit_id=base))) THEN
        RAISE EXCEPTION 'resource observation registration identity mismatch' USING ERRCODE='23514';
    END IF;
    SELECT * INTO n FROM public.runtime_nodes WHERE id=p.runtime_node_id AND cluster_epoch=p.cluster_epoch;
    IF n.id IS NULL THEN RAISE EXCEPTION 'resource observation node identity mismatch' USING ERRCODE='23514'; END IF;
    SELECT * INTO existing FROM public.launch_pod_resource_observations
        WHERE tenant_id=p.tenant_id AND base_permit_id=base;
    IF existing.id IS NOT NULL THEN
        -- RV and timestamps describe the first read. A later metadata-only
        -- change does not overwrite history or create a resource conflict.
        IF (existing.class_uid,existing.class_config_sha256,
            existing.class_overhead_cpu_millis,existing.class_overhead_memory_bytes,
            existing.workload_request_cpu_millis,existing.workload_request_memory_bytes,existing.workload_request_ephemeral_bytes,
            existing.workload_limit_cpu_millis,existing.workload_limit_memory_bytes,existing.workload_limit_ephemeral_bytes,
            existing.pod_overhead_cpu_millis,existing.pod_overhead_memory_bytes,
            existing.effective_request_cpu_millis,existing.effective_request_memory_bytes,existing.effective_request_ephemeral_bytes,
            existing.effective_limit_cpu_millis,existing.effective_limit_memory_bytes,existing.effective_limit_ephemeral_bytes)
            IS DISTINCT FROM (class_id,class_hash,class_cpu,class_memory,request_cpu,request_memory,request_ephemeral,
                limit_cpu,limit_memory,limit_ephemeral,overhead_cpu,overhead_memory,effective_request_cpu,
                effective_request_memory,effective_request_ephemeral,effective_limit_cpu,effective_limit_memory,effective_limit_ephemeral) THEN
            RAISE EXCEPTION 'immutable launch Pod resource observation conflict' USING ERRCODE='23514';
        END IF;
        RETURN existing.id;
    END IF;
    IF EXISTS(SELECT 1 FROM public.launch_registration_legacy_baseline b
        WHERE b.tenant_id=p.tenant_id AND b.registration_kind=kind
            AND b.registration_id=registration AND b.base_permit_id=base) THEN
        -- Replaying an already committed historical ACK does not turn today's
        -- Pod into the resource facts of that old registration. A genuinely
        -- new extension may capture its own fresh observation below.
        RETURN NULL;
    END IF;
    INSERT INTO public.launch_pod_resource_observations(tenant_id,project_id,instance_id,workspace_id,
        generation,launch_id,cluster_epoch,base_permit_id,registration_id,registration_kind,runtime_node_id,
        node_uid,node_boot_id,pod_uid,pod_resource_version,class_uid,class_resource_version,class_config_sha256,
        class_overhead_cpu_millis,class_overhead_memory_bytes,
        workload_request_cpu_millis,workload_request_memory_bytes,workload_request_ephemeral_bytes,
        workload_limit_cpu_millis,workload_limit_memory_bytes,workload_limit_ephemeral_bytes,
        pod_overhead_cpu_millis,pod_overhead_memory_bytes,
        effective_request_cpu_millis,effective_request_memory_bytes,effective_request_ephemeral_bytes,
        effective_limit_cpu_millis,effective_limit_memory_bytes,effective_limit_ephemeral_bytes,observed_at)
    VALUES(p.tenant_id,p.project_id,p.instance_id,p.workspace_id,p.generation,p.launch_id,p.cluster_epoch,
        p.id,registration,kind,n.id,n.node_uid,n.boot_id,p.pod_uid,pod_rv,class_id,class_rv,class_hash,
        class_cpu,class_memory,request_cpu,request_memory,request_ephemeral,limit_cpu,limit_memory,limit_ephemeral,
        overhead_cpu,overhead_memory,effective_request_cpu,effective_request_memory,effective_request_ephemeral,
        effective_limit_cpu,effective_limit_memory,effective_limit_ephemeral,observed) RETURNING id INTO result;
    RETURN result;
END
$observation$;
REVOKE ALL ON FUNCTION public.sandbox_guard_launch_resource_registration(),
    public.sandbox_guard_launch_resource_observation(),
    public.sandbox_lock_registration_boundary(uuid),
    public.sandbox_record_launch_resource_observation(uuid,uuid,text,text,uuid,text,text,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,timestamptz) FROM PUBLIC;
