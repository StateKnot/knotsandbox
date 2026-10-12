-- Operator-owned inventory. A reboot/profile/instance change is a new record;
-- existing launches remain bound to the old trusted identity until reconciled.
CREATE TABLE runtime_nodes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_epoch uuid NOT NULL,
    node_uid uuid NOT NULL,
    node_name text NOT NULL CHECK(char_length(node_name) BETWEEN 1 AND 253),
    cloud_provider text NOT NULL CHECK(cloud_provider='alicloud'),
    cloud_account_id text NOT NULL CHECK(char_length(cloud_account_id) BETWEEN 1 AND 128),
    region text NOT NULL CHECK(char_length(region) BETWEEN 1 AND 128),
    cloud_instance_id text NOT NULL CHECK(char_length(cloud_instance_id) BETWEEN 1 AND 128),
    private_ip inet NOT NULL,
    guard_port integer NOT NULL DEFAULT 9444 CHECK(guard_port BETWEEN 1 AND 65535),
    profile_sha256 text NOT NULL CHECK(profile_sha256~'^[0-9a-f]{64}$'),
    boot_id uuid NOT NULL,
    enabled boolean NOT NULL DEFAULT false,
    registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(cluster_epoch,node_uid,boot_id),
    CHECK(masklen(private_ip)=CASE family(private_ip) WHEN 4 THEN 32 ELSE 128 END)
);
CREATE UNIQUE INDEX runtime_node_one_active_uid ON runtime_nodes(cluster_epoch,node_uid) WHERE enabled;
CREATE UNIQUE INDEX runtime_node_one_active_instance ON runtime_nodes(cloud_account_id,region,cloud_instance_id) WHERE enabled;
CREATE FUNCTION sandbox_preserve_runtime_node() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF (to_jsonb(NEW)-'enabled') IS DISTINCT FROM (to_jsonb(OLD)-'enabled') THEN
        RAISE EXCEPTION 'trusted node identity is immutable' USING ERRCODE='23514';END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER runtime_node_identity_immutable BEFORE UPDATE ON runtime_nodes
FOR EACH ROW EXECUTE FUNCTION sandbox_preserve_runtime_node();
CREATE TRIGGER runtime_node_no_delete BEFORE DELETE ON runtime_nodes
FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_audit_mutation();

CREATE TABLE launch_permits (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    instance_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    runtime_node_id uuid NOT NULL REFERENCES runtime_nodes(id),
    cluster_epoch uuid NOT NULL,
    generation bigint NOT NULL CHECK(generation>0),
    launch_id uuid NOT NULL,
    pod_uid uuid NOT NULL,
    namespace text NOT NULL,
    pod_name text NOT NULL,
    pvc_uid uuid NOT NULL,
    pv_uid uuid NOT NULL,
    pv_name text NOT NULL,
    csi_volume_handle text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    FOREIGN KEY(tenant_id,project_id,instance_id,operation_id) REFERENCES operations(tenant_id,project_id,instance_id,id),
    FOREIGN KEY(tenant_id,project_id,workspace_id) REFERENCES workspaces(tenant_id,project_id,id),
    UNIQUE(tenant_id,instance_id,generation,launch_id),
    UNIQUE(tenant_id,id),
    UNIQUE(tenant_id,project_id,id),
    CHECK(expires_at>created_at),
    CHECK(pod_name='sbx-ws-'||workspace_id::text)
);
CREATE TABLE launch_permit_receipts (
    permit_id uuid PRIMARY KEY REFERENCES launch_permits(id),
    tenant_id uuid NOT NULL,
    journal_revision bigint NOT NULL CHECK(journal_revision>0),
    registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY(tenant_id,permit_id) REFERENCES launch_permits(tenant_id,id)
);

-- Every lease owner uses a new bounded challenge. Historical challenges and
-- local proofs remain append-only; they are never replayed into a newer launch.
CREATE TABLE termination_challenges (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    permit_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    lease_token bigint NOT NULL CHECK(lease_token>0),
    reason text NOT NULL CHECK(reason IN('STOP','RESTART','DELETE')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    FOREIGN KEY(tenant_id,project_id,permit_id) REFERENCES launch_permits(tenant_id,project_id,id),
    FOREIGN KEY(tenant_id,project_id,operation_id) REFERENCES operations(tenant_id,project_id,id),
    UNIQUE(tenant_id,id),
    CHECK(expires_at>created_at AND expires_at<=created_at+interval '30 seconds')
);
CREATE TABLE local_termination_proofs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    challenge_id uuid NOT NULL UNIQUE,
    permit_id uuid NOT NULL,
    instance_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    generation bigint NOT NULL CHECK(generation>0),
    launch_id uuid NOT NULL,
    pod_uid uuid NOT NULL,
    cluster_epoch uuid NOT NULL,
    runtime_node_id uuid NOT NULL REFERENCES runtime_nodes(id),
    journal_revision bigint NOT NULL CHECK(journal_revision>0),
    evidence jsonb NOT NULL CHECK(jsonb_typeof(evidence)='object' AND octet_length(evidence::text)<=65536),
    evidence_sha256 text NOT NULL CHECK(evidence_sha256~'^[0-9a-f]{64}$'),
    observed_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY(tenant_id,challenge_id) REFERENCES termination_challenges(tenant_id,id),
    FOREIGN KEY(tenant_id,project_id,permit_id) REFERENCES launch_permits(tenant_id,project_id,id),
    FOREIGN KEY(tenant_id,project_id,instance_id) REFERENCES instances(tenant_id,project_id,id),
    FOREIGN KEY(tenant_id,project_id,workspace_id) REFERENCES workspaces(tenant_id,project_id,id),
    UNIQUE(tenant_id,id),
    UNIQUE(tenant_id,id,instance_id,generation,launch_id,pod_uid,cluster_epoch)
);
CREATE TABLE termination_cleanup_receipts (
    proof_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    old_pod_uid uuid NOT NULL,
    pod_resource_version text,
    pod_absent_at timestamptz NOT NULL,
    volume_checked_at timestamptz NOT NULL,
    completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completion text NOT NULL CHECK(completion IN('STOPPED','RESTART_QUEUED','RESTART_BLOCKED','AWAITING_VOLUME_DELETION')),
    FOREIGN KEY(tenant_id,proof_id) REFERENCES local_termination_proofs(tenant_id,id)
);
DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['launch_permits','launch_permit_receipts','termination_challenges','local_termination_proofs','termination_cleanup_receipts'] LOOP
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',table_name);
        EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',table_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.sandbox_current_tenant_id()) WITH CHECK(tenant_id=public.sandbox_current_tenant_id())',table_name);
        EXECUTE format('CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.sandbox_prevent_audit_mutation()',table_name);
        EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',table_name);
    END LOOP;
END $$;
REVOKE ALL ON runtime_nodes FROM PUBLIC;
REVOKE ALL ON FUNCTION sandbox_preserve_runtime_node() FROM PUBLIC;

ALTER TABLE instances ADD COLUMN last_termination_proof_id uuid,
    ADD CONSTRAINT instance_termination_proof_scope FOREIGN KEY(tenant_id,last_termination_proof_id) REFERENCES local_termination_proofs(tenant_id,id);
ALTER TABLE executions ADD COLUMN termination_proof_id uuid,
    ADD CONSTRAINT execution_termination_proof_identity FOREIGN KEY(tenant_id,termination_proof_id,instance_id,runtime_generation,launch_id,pod_uid,cluster_epoch)
        REFERENCES local_termination_proofs(tenant_id,id,instance_id,generation,launch_id,pod_uid,cluster_epoch);
ALTER TABLE operations ADD COLUMN restart_generation bigint CHECK(restart_generation>0);

-- Privileged proof creation is distinct from ordinary observed state writes.
CREATE FUNCTION sandbox_guard_termination_reference() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE changed boolean;selected_proof uuid;
BEGIN
    IF pg_has_role(current_user,(SELECT relowner FROM pg_class WHERE oid=TG_RELID),'MEMBER') THEN RETURN NEW;END IF;
    IF TG_TABLE_NAME='executions' THEN
        changed:=NEW.termination_proof_id IS DISTINCT FROM OLD.termination_proof_id
          OR (NEW.termination_status='CONFIRMED' AND OLD.termination_status<>'CONFIRMED');
        IF OLD.termination_proof_id IS NOT NULL AND NEW.termination_proof_id IS DISTINCT FROM OLD.termination_proof_id THEN
            RAISE EXCEPTION 'termination proof is immutable' USING ERRCODE='23514';END IF;
        selected_proof:=NEW.termination_proof_id;
    ELSE
        changed:=NEW.last_termination_proof_id IS DISTINCT FROM OLD.last_termination_proof_id;
        selected_proof:=NEW.last_termination_proof_id;
    END IF;
    IF NOT changed THEN RETURN NEW;END IF;
    IF current_user<>'sandbox_termination' THEN
        RAISE EXCEPTION 'only termination controller may consume termination evidence' USING ERRCODE='42501';END IF;
    IF selected_proof IS NULL THEN RAISE EXCEPTION 'termination proof required' USING ERRCODE='42501';END IF;
    IF NOT EXISTS(SELECT 1 FROM public.termination_cleanup_receipts c WHERE c.tenant_id=NEW.tenant_id AND c.proof_id=selected_proof) THEN
        RAISE EXCEPTION 'termination requires completed trusted cleanup' USING ERRCODE='42501';END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER execution_termination_reference_guard BEFORE UPDATE ON executions FOR EACH ROW EXECUTE FUNCTION sandbox_guard_termination_reference();
CREATE TRIGGER instance_termination_reference_guard BEFORE UPDATE ON instances FOR EACH ROW EXECUTE FUNCTION sandbox_guard_termination_reference();
REVOKE ALL ON FUNCTION sandbox_guard_termination_reference() FROM PUBLIC;

CREATE FUNCTION sandbox_guard_runtime_release() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE selected_proof uuid;expected_instance uuid;expected_generation bigint;expected_launch uuid;expected_pod uuid;expected_epoch uuid;
BEGIN
    IF pg_has_role(current_user,(SELECT relowner FROM pg_class WHERE oid=TG_RELID),'MEMBER') THEN RETURN NEW;END IF;
    IF TG_TABLE_NAME='instances' THEN
        IF NOT ((OLD.slot_held AND NOT NEW.slot_held) OR (NEW.observed_state='STOPPED' AND OLD.observed_state<>'STOPPED')) THEN RETURN NEW;END IF;
        -- A completed platform runner may free its activity slot without claiming
        -- whole-VM termination. The independent gateway evidence guard still applies.
        IF OLD.slot_held AND NOT NEW.slot_held AND NEW.observed_state<>'STOPPED'
           AND OLD.activity_kind='EXECUTION' AND EXISTS(SELECT 1 FROM public.executions e
             WHERE e.tenant_id=OLD.tenant_id AND e.id=OLD.activity_id AND e.instance_id=OLD.id
               AND e.runtime_generation=OLD.runtime_generation AND e.launch_id=OLD.launch_id
               AND NOT e.slot_held AND e.activity_completion_kind='EXEC_PROCESS_EXITED'
               AND e.exec_process_exit_code=0 AND e.termination_status='NOT_REQUESTED') THEN RETURN NEW;END IF;
        selected_proof:=NEW.last_termination_proof_id;expected_instance:=OLD.id;expected_generation:=OLD.runtime_generation;
        expected_launch:=OLD.launch_id;expected_pod:=OLD.pod_uid;expected_epoch:=OLD.cluster_epoch;
    ELSE
        IF NEW.status<>'AVAILABLE' OR OLD.status='AVAILABLE' THEN RETURN NEW;END IF;
        SELECT i.last_termination_proof_id,i.id,i.runtime_generation,i.launch_id,i.pod_uid,i.cluster_epoch
          INTO selected_proof,expected_instance,expected_generation,expected_launch,expected_pod,expected_epoch
          FROM public.instances i WHERE i.tenant_id=NEW.tenant_id AND i.workspace_id=NEW.id
          ORDER BY i.created_at DESC LIMIT 1;
    END IF;
    IF current_user<>'sandbox_termination' THEN RAISE EXCEPTION 'only termination controller may release runtime resources' USING ERRCODE='42501';END IF;
    IF selected_proof IS NULL THEN RAISE EXCEPTION 'termination proof required' USING ERRCODE='42501';END IF;
    IF NOT EXISTS(
       SELECT 1 FROM public.local_termination_proofs p JOIN public.termination_cleanup_receipts c ON c.tenant_id=p.tenant_id AND c.proof_id=p.id
       WHERE p.tenant_id=NEW.tenant_id AND p.id=selected_proof AND p.instance_id=expected_instance
         AND p.generation=expected_generation AND p.launch_id=expected_launch AND p.pod_uid=expected_pod AND p.cluster_epoch=expected_epoch) THEN
        RAISE EXCEPTION 'runtime release requires exact trusted termination and cleanup' USING ERRCODE='42501';END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER instance_runtime_release_guard BEFORE UPDATE ON instances FOR EACH ROW EXECUTE FUNCTION sandbox_guard_runtime_release();
CREATE TRIGGER workspace_runtime_release_guard BEFORE UPDATE ON workspaces FOR EACH ROW EXECUTE FUNCTION sandbox_guard_runtime_release();
REVOKE ALL ON FUNCTION sandbox_guard_runtime_release() FROM PUBLIC;

ALTER TABLE operations ADD COLUMN launch_registration_next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp();
ALTER TABLE operation_dispatch ADD COLUMN launch_registration_eligible_at timestamptz NOT NULL DEFAULT clock_timestamp();
CREATE INDEX operation_dispatch_launch_due ON operation_dispatch(queue_role,launch_registration_eligible_at,operation_id);
ALTER TABLE operation_dispatch DROP CONSTRAINT operation_dispatch_queue_role_check;
ALTER TABLE operation_dispatch ADD CONSTRAINT operation_dispatch_queue_role_check CHECK(queue_role IN('WORKER','GATEWAY','TERMINATION'));
CREATE OR REPLACE FUNCTION sandbox_update_dispatch() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE target_queue text;
BEGIN
    target_queue:=CASE WHEN NEW.kind='EXECUTE' THEN 'GATEWAY'
        WHEN NEW.kind IN('STOP','DELETE') OR (NEW.kind='RESTART' AND NEW.restart_generation IS NULL) THEN 'TERMINATION'
        ELSE 'WORKER' END;
    IF NEW.status IN('QUEUED','RUNNING','WAITING') THEN
        INSERT INTO public.operation_dispatch(operation_id,tenant_id,eligible_at,queue_role,launch_registration_eligible_at)
        VALUES(NEW.id,NEW.tenant_id,GREATEST(NEW.next_attempt_at,COALESCE(NEW.lease_until,NEW.next_attempt_at)),target_queue,NEW.launch_registration_next_attempt_at)
        ON CONFLICT(operation_id) DO UPDATE SET eligible_at=EXCLUDED.eligible_at,queue_role=EXCLUDED.queue_role,launch_registration_eligible_at=EXCLUDED.launch_registration_eligible_at;
    ELSE DELETE FROM public.operation_dispatch WHERE operation_id=NEW.id;
    END IF;
    RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION sandbox_claim_routed_operation(worker_id text,requested_role text)
RETURNS TABLE(tenant_id uuid,operation_id uuid,lease_token bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;found_id uuid;previous_tenant text:=current_setting('app.tenant_id',true);
BEGIN
    IF worker_id IS NULL OR char_length(worker_id) NOT BETWEEN 1 AND 128 OR requested_role IS NULL OR requested_role NOT IN('WORKER','GATEWAY','TERMINATION') THEN
        RAISE EXCEPTION 'invalid worker identity or queue role' USING ERRCODE='22023';END IF;
    FOR candidate IN SELECT d.operation_id,d.tenant_id FROM public.operation_dispatch d
      WHERE d.queue_role=requested_role AND d.eligible_at<=clock_timestamp() ORDER BY d.eligible_at,d.operation_id LIMIT 64 LOOP
        PERFORM set_config('app.tenant_id',candidate.tenant_id::text,true);
        SELECT o.id INTO found_id FROM public.operations o
        WHERE o.tenant_id=candidate.tenant_id AND o.id=candidate.operation_id
          AND CASE requested_role WHEN 'GATEWAY' THEN o.kind='EXECUTE'
              WHEN 'TERMINATION' THEN o.kind IN('STOP','DELETE') OR (o.kind='RESTART' AND o.restart_generation IS NULL)
              ELSE o.kind NOT IN('EXECUTE','STOP','DELETE') AND (o.kind<>'RESTART' OR o.restart_generation IS NOT NULL) END
          AND o.status IN('QUEUED','RUNNING','WAITING') AND o.next_attempt_at<=clock_timestamp()
          AND (o.lease_until IS NULL OR o.lease_until<=clock_timestamp()) FOR UPDATE SKIP LOCKED;
        IF found_id IS NOT NULL THEN
            RETURN QUERY UPDATE public.operations o SET status='RUNNING',lease_owner=worker_id,lease_token=o.lease_token+1,
              lease_until=clock_timestamp()+interval '30 seconds',attempts=o.attempts+1,updated_at=clock_timestamp()
            WHERE o.id=found_id AND o.tenant_id=candidate.tenant_id RETURNING o.tenant_id,o.id,o.lease_token;
            PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);RETURN;
        END IF;
    END LOOP;
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
END $$;
CREATE FUNCTION sandbox_claim_termination(worker_id text)
RETURNS TABLE(tenant_id uuid,operation_id uuid,lease_token bigint)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
    SELECT * FROM public.sandbox_claim_routed_operation(worker_id,'TERMINATION');
$$;
-- Cross-tenant discovery returns only bounded hints. Full reads always use the
-- tenant-scoped transaction and repeat all state/identity/authorization checks.
CREATE FUNCTION sandbox_launch_registration_candidates(batch_size integer)
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
            AND NOT EXISTS(SELECT 1 FROM public.launch_permits lp JOIN public.launch_permit_receipts r ON r.permit_id=lp.id AND r.tenant_id=lp.tenant_id
                WHERE lp.tenant_id=i.tenant_id AND lp.instance_id=i.id AND lp.generation=i.runtime_generation AND lp.launch_id=i.launch_id)) THEN
            tenant_id:=candidate.tenant_id;operation_id:=candidate.operation_id;RETURN NEXT;accepted:=accepted+1;
            EXIT WHEN accepted>=batch_size;
        END IF;
    END LOOP;
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
END $$;
DO $$
DECLARE row record;previous_tenant text:=current_setting('app.tenant_id',true);
BEGIN
    FOR row IN SELECT tenant_id,operation_id FROM operation_dispatch LOOP
        PERFORM set_config('app.tenant_id',row.tenant_id::text,true);
        UPDATE operations SET next_attempt_at=next_attempt_at WHERE tenant_id=row.tenant_id AND id=row.operation_id;
    END LOOP;
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
END $$;
REVOKE ALL ON FUNCTION sandbox_claim_termination(text),sandbox_launch_registration_candidates(integer) FROM PUBLIC;

CREATE TABLE runtime_node_journal_highwater (
    runtime_node_id uuid PRIMARY KEY REFERENCES runtime_nodes(id),
    max_revision bigint NOT NULL CHECK(max_revision>0),
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION sandbox_preserve_journal_highwater() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' OR NEW.runtime_node_id<>OLD.runtime_node_id OR NEW.max_revision<OLD.max_revision THEN
        RAISE EXCEPTION 'node journal watermarks cannot regress' USING ERRCODE='23514';END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER node_journal_monotonic BEFORE UPDATE OR DELETE ON runtime_node_journal_highwater
FOR EACH ROW EXECUTE FUNCTION sandbox_preserve_journal_highwater();
REVOKE ALL ON runtime_node_journal_highwater FROM PUBLIC;
REVOKE ALL ON FUNCTION sandbox_preserve_journal_highwater() FROM PUBLIC;
CREATE FUNCTION sandbox_launch_registered(requested_tenant uuid,instance uuid,generation bigint,launch uuid,pod uuid,epoch uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
    SELECT COALESCE($1=public.sandbox_current_tenant_id() AND EXISTS(
      SELECT 1 FROM public.launch_permits p JOIN public.launch_permit_receipts r ON r.tenant_id=p.tenant_id AND r.permit_id=p.id
      JOIN public.runtime_nodes n ON n.id=p.runtime_node_id
      WHERE p.tenant_id=$1 AND p.instance_id=$2 AND p.generation=$3 AND p.launch_id=$4
        AND p.pod_uid=$5 AND p.cluster_epoch=$6 AND n.cluster_epoch=$6 AND n.enabled),false);
$$;
REVOKE ALL ON FUNCTION sandbox_launch_registered(uuid,uuid,bigint,uuid,uuid,uuid) FROM PUBLIC;
