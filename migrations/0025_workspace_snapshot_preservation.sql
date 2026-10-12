-- CreateDisk defaults DeleteAutoSnapshot=true. Preserve existing automatic
-- snapshots before physical deletion; this intent is never deletion evidence.
CREATE TABLE workspace_snapshot_preserve_attempts (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,operation_id uuid NOT NULL,
 lease_token bigint NOT NULL CHECK(lease_token>0),
 preflight_evidence jsonb NOT NULL CHECK(jsonb_typeof(preflight_evidence)='object' AND octet_length(preflight_evidence::text)<=65536),
 dispatched_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,operation_id,id),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES workspace_delete_bindings(tenant_id,operation_id)
);
CREATE TABLE workspace_snapshot_preserve_results (
 attempt_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,operation_id uuid NOT NULL,
 outcome text NOT NULL CHECK(outcome IN('ACCEPTED','ALREADY_PRESERVED','ALREADY_ABSENT','OUTCOME_UNKNOWN','REJECTED')),
 evidence jsonb NOT NULL CHECK(jsonb_typeof(evidence)='object' AND octet_length(evidence::text)<=65536),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,operation_id,attempt_id) REFERENCES workspace_snapshot_preserve_attempts(tenant_id,operation_id,id)
);
DO $$ DECLARE name text; BEGIN
 FOREACH name IN ARRAY ARRAY['workspace_snapshot_preserve_attempts','workspace_snapshot_preserve_results'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.sandbox_current_tenant_id()) WITH CHECK(tenant_id=public.sandbox_current_tenant_id())',name);
  EXECUTE format('CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.sandbox_prevent_audit_mutation()',name);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',name);
 END LOOP;
END $$;
