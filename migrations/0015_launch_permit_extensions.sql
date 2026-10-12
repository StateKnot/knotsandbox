-- Renewing a STARTING compute lease must extend its unopened host admission
-- permit durably. Base launch identity and termination evidence never change.
CREATE TABLE launch_permit_extensions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    base_permit_id uuid NOT NULL,
    compute_lease_id uuid NOT NULL,
    compute_lease_version bigint NOT NULL CHECK(compute_lease_version>0),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(tenant_id,id),
    UNIQUE(tenant_id,base_permit_id,compute_lease_version),
    FOREIGN KEY(tenant_id,base_permit_id) REFERENCES launch_permits(tenant_id,id),
    CHECK(expires_at>created_at)
);
CREATE TABLE launch_permit_extension_receipts (
    extension_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    journal_revision bigint NOT NULL CHECK(journal_revision>0),
    effective_expires_at timestamptz NOT NULL,
    registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY(tenant_id,extension_id) REFERENCES launch_permit_extensions(tenant_id,id)
);
DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['launch_permit_extensions','launch_permit_extension_receipts'] LOOP
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',table_name);
        EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',table_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.sandbox_current_tenant_id()) WITH CHECK(tenant_id=public.sandbox_current_tenant_id())',table_name);
        EXECUTE format('CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.sandbox_prevent_audit_mutation()',table_name);
        EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',table_name);
    END LOOP;
END $$;
CREATE OR REPLACE FUNCTION sandbox_launch_registration_candidates(batch_size integer)
RETURNS TABLE(tenant_id uuid,operation_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;previous_tenant text:=current_setting('app.tenant_id',true);accepted integer:=0;selected_id uuid;
BEGIN
    IF batch_size IS NULL OR batch_size<1 OR batch_size>100 THEN RAISE EXCEPTION 'invalid candidate bound' USING ERRCODE='22023';END IF;
    FOR candidate IN SELECT d.tenant_id,d.operation_id FROM public.operation_dispatch d
      WHERE d.queue_role='WORKER' AND d.launch_registration_eligible_at<=clock_timestamp()
      ORDER BY d.launch_registration_eligible_at,d.operation_id LIMIT 1000 LOOP
        PERFORM set_config('app.tenant_id',candidate.tenant_id::text,true);
        SELECT o.id INTO selected_id FROM public.operations o WHERE o.tenant_id=candidate.tenant_id AND o.id=candidate.operation_id
          AND o.status IN('QUEUED','RUNNING','WAITING') AND o.launch_registration_next_attempt_at<=clock_timestamp()
          FOR UPDATE SKIP LOCKED;
        IF selected_id IS NULL THEN CONTINUE;END IF;
        UPDATE public.operations SET launch_registration_next_attempt_at=clock_timestamp()+interval '5 seconds'
          WHERE id=selected_id AND public.operations.tenant_id=candidate.tenant_id;
        IF EXISTS(SELECT 1 FROM public.operations o JOIN public.instances i ON i.tenant_id=o.tenant_id AND i.id=o.instance_id
          WHERE o.tenant_id=candidate.tenant_id AND o.id=candidate.operation_id
            AND (o.kind IN('CREATE','START') OR (o.kind='RESTART' AND o.restart_generation=i.runtime_generation))
            AND i.active_operation_id=o.id AND i.pod_uid IS NOT NULL AND i.desired_state='RUNNING' AND i.stop_accepted_at IS NULL
            AND NOT EXISTS(SELECT 1 FROM public.launch_permits lp
                WHERE lp.tenant_id=i.tenant_id AND lp.instance_id=i.id AND lp.generation=i.runtime_generation AND lp.launch_id=i.launch_id
                  AND ((lp.expires_at>=i.compute_lease_expires_at AND EXISTS(SELECT 1 FROM public.launch_permit_receipts r WHERE r.tenant_id=lp.tenant_id AND r.permit_id=lp.id))
                    OR EXISTS(SELECT 1 FROM public.launch_permit_extensions e JOIN public.launch_permit_extension_receipts r ON r.tenant_id=e.tenant_id AND r.extension_id=e.id
                      WHERE e.tenant_id=lp.tenant_id AND e.base_permit_id=lp.id AND e.compute_lease_id=i.compute_lease_id AND e.compute_lease_version>=i.compute_lease_version AND e.expires_at>=i.compute_lease_expires_at)))) THEN
            tenant_id:=candidate.tenant_id;operation_id:=candidate.operation_id;RETURN NEXT;accepted:=accepted+1;
            EXIT WHEN accepted>=batch_size;
        END IF;
    END LOOP;
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
END $$;
CREATE OR REPLACE FUNCTION sandbox_launch_registered(requested_tenant uuid,instance uuid,generation bigint,launch uuid,pod uuid,epoch uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
    SELECT COALESCE($1=public.sandbox_current_tenant_id() AND EXISTS(
      SELECT 1 FROM public.launch_permits p JOIN public.runtime_nodes n ON n.id=p.runtime_node_id
      WHERE p.tenant_id=$1 AND p.instance_id=$2 AND p.generation=$3 AND p.launch_id=$4
        AND p.pod_uid=$5 AND p.cluster_epoch=$6 AND n.cluster_epoch=$6 AND n.enabled
        AND (EXISTS(SELECT 1 FROM public.launch_permit_receipts r WHERE r.tenant_id=p.tenant_id AND r.permit_id=p.id)
          OR EXISTS(SELECT 1 FROM public.launch_permit_extensions e JOIN public.launch_permit_extension_receipts r ON r.tenant_id=e.tenant_id AND r.extension_id=e.id
             WHERE e.tenant_id=p.tenant_id AND e.base_permit_id=p.id))),false);
$$;
REVOKE ALL ON FUNCTION sandbox_launch_registered(uuid,uuid,bigint,uuid,uuid,uuid),sandbox_launch_registration_candidates(integer) FROM PUBLIC;
