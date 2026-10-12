-- A platform exec process can end while unrelated guest descendants remain.
-- Keep that evidence distinct from trusted whole-VM termination/fencing.
ALTER TABLE executions
    ADD COLUMN dispatch_lease_token bigint CHECK(dispatch_lease_token>0),
    ADD COLUMN exec_admission_uid uuid,
    ADD COLUMN exec_admitted_at timestamptz,
    ADD CONSTRAINT exec_admission_complete CHECK((exec_admission_uid IS NULL)=(exec_admitted_at IS NULL)),
    ADD COLUMN exec_process_attempt_id uuid,
    ADD COLUMN exec_process_exited_at timestamptz,
    ADD COLUMN exec_process_exit_code integer,
    ADD COLUMN activity_completion_kind text CHECK(activity_completion_kind IN ('EXEC_PROCESS_EXITED','VM_TERMINATED')),
    ADD COLUMN result_source text CHECK(result_source='GUEST_REPORTED'),
    ADD CONSTRAINT exec_process_evidence_complete CHECK (
      (exec_process_attempt_id IS NULL AND exec_process_exited_at IS NULL AND exec_process_exit_code IS NULL)
      OR (exec_process_attempt_id IS NOT NULL AND exec_process_attempt_id=dispatch_attempt_id
          AND dispatch_attempt_id IS NOT NULL AND exec_process_exited_at IS NOT NULL
          AND exec_process_exit_code IS NOT NULL AND exec_process_exit_code BETWEEN 0 AND 255)
    ),
    ADD CONSTRAINT execution_attempt_scope UNIQUE(tenant_id,project_id,id,dispatch_attempt_id);

-- The initial schema used an unnamed CHECK. Locate exactly that original
-- invariant rather than relying on an installation-dependent generated name.
DO $$
DECLARE constraint_name text;
DECLARE matches integer;
BEGIN
    SELECT min(conname::text),count(*) INTO constraint_name,matches FROM pg_constraint
    WHERE conrelid='public.executions'::regclass AND contype='c'
      AND pg_get_constraintdef(oid) LIKE '%slot_held%termination_status%CONFIRMED%';
    IF matches<>1 THEN RAISE EXCEPTION 'original execution slot invariant missing or ambiguous'; END IF;
    EXECUTE format('ALTER TABLE public.executions DROP CONSTRAINT %I',constraint_name);
END;
$$;
ALTER TABLE executions ADD CONSTRAINT execution_slot_release_evidence CHECK (
    slot_held OR termination_status='CONFIRMED'
    OR (activity_completion_kind='EXEC_PROCESS_EXITED' AND activity_completion_kind IS NOT NULL
        AND exec_process_attempt_id IS NOT NULL AND exec_process_exited_at IS NOT NULL
        AND exec_admission_uid IS NOT NULL AND exec_admitted_at IS NOT NULL
        AND exec_process_exit_code=0 AND exec_process_exit_code IS NOT NULL
        AND termination_status='NOT_REQUESTED' AND status IN ('SUCCEEDED','FAILED')
        AND result_source='GUEST_REPORTED' AND result_source IS NOT NULL)
);

CREATE FUNCTION sandbox_preserve_exec_process_evidence() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.exec_process_attempt_id IS NOT NULL OR NEW.activity_completion_kind IS NOT NULL
           OR NEW.exec_admission_uid IS NOT NULL OR NEW.dispatch_lease_token IS NOT NULL THEN
            RAISE EXCEPTION 'new execution cannot fabricate dispatch or completion evidence' USING ERRCODE='23514';
        END IF;
    ELSE
        IF OLD.dispatch_attempt_id IS NOT NULL AND NEW.dispatch_lease_token IS DISTINCT FROM OLD.dispatch_lease_token THEN
            RAISE EXCEPTION 'dispatch worker token is immutable' USING ERRCODE='23514';
        END IF;
        IF OLD.dispatch_attempt_id IS NULL AND NEW.dispatch_attempt_id IS NOT NULL AND NEW.dispatch_lease_token IS NULL THEN
            RAISE EXCEPTION 'new dispatch must bind its worker token' USING ERRCODE='23514';
        END IF;
        IF NEW.dispatch_attempt_id IS NULL AND NEW.dispatch_lease_token IS NOT NULL THEN
            RAISE EXCEPTION 'worker token requires a dispatch attempt' USING ERRCODE='23514';
        END IF;
        IF OLD.exec_admission_uid IS NOT NULL AND (NEW.exec_admission_uid,NEW.exec_admitted_at)
             IS DISTINCT FROM (OLD.exec_admission_uid,OLD.exec_admitted_at) THEN
            RAISE EXCEPTION 'exec admission receipt is immutable' USING ERRCODE='23514';
        END IF;
        IF (NEW.exec_admission_uid,NEW.exec_admitted_at) IS DISTINCT FROM (OLD.exec_admission_uid,OLD.exec_admitted_at)
          AND (NEW.dispatch_attempt_id IS NULL OR NEW.dispatch_lease_token IS NULL
            OR NEW.exec_admission_uid='00000000-0000-0000-0000-000000000000'
            OR NOT pg_has_role(current_user,(SELECT relowner FROM pg_class WHERE oid=TG_RELID),'MEMBER')) THEN
            RAISE EXCEPTION 'only the narrow definer gate may consume exec admission' USING ERRCODE='42501';
        END IF;
        IF OLD.exec_process_attempt_id IS NOT NULL AND
           (NEW.exec_process_attempt_id,NEW.exec_process_exited_at,NEW.exec_process_exit_code)
             IS DISTINCT FROM (OLD.exec_process_attempt_id,OLD.exec_process_exited_at,OLD.exec_process_exit_code) THEN
            RAISE EXCEPTION 'trusted process completion evidence is immutable' USING ERRCODE='23514';
        END IF;
        IF (NEW.exec_process_attempt_id,NEW.exec_process_exited_at,NEW.exec_process_exit_code)
             IS DISTINCT FROM (OLD.exec_process_attempt_id,OLD.exec_process_exited_at,OLD.exec_process_exit_code)
           AND (NEW.exec_admission_uid IS NULL OR (current_user<>'sandbox_gateway'
             AND NOT pg_has_role(current_user,(SELECT relowner FROM pg_class WHERE oid=TG_RELID),'MEMBER'))) THEN
            RAISE EXCEPTION 'only gateway may record trusted exec status after admission' USING ERRCODE='42501';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER exec_process_evidence_guard BEFORE INSERT OR UPDATE ON executions
FOR EACH ROW EXECUTE FUNCTION sandbox_preserve_exec_process_evidence();
REVOKE ALL ON FUNCTION sandbox_preserve_exec_process_evidence() FROM PUBLIC;

-- Rows are published only after the exact immutable object PUT has succeeded.
-- The output remains in OSS; this table is its tenant-scoped durable index.
CREATE TABLE execution_output_segments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    execution_id uuid NOT NULL,
    dispatch_attempt_id uuid NOT NULL,
    sequence bigint NOT NULL CHECK(sequence BETWEEN 0 AND 4097),
    first_frame_sequence bigint NOT NULL CHECK(first_frame_sequence BETWEEN 0 AND 4097),
    last_frame_sequence bigint NOT NULL CHECK(last_frame_sequence BETWEEN first_frame_sequence AND 4097),
    raw_bytes bigint NOT NULL CHECK(raw_bytes BETWEEN 0 AND 262144),
    object_bytes bigint NOT NULL CHECK(object_bytes BETWEEN 1 AND 524288),
    sha256 text NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),
    object_key text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY(tenant_id,project_id,execution_id,dispatch_attempt_id)
        REFERENCES executions(tenant_id,project_id,id,dispatch_attempt_id),
    UNIQUE(tenant_id,execution_id,dispatch_attempt_id,sequence),
    CHECK(object_key='tenants/'||tenant_id::text||'/executions/'||execution_id::text||
        '/attempts/'||dispatch_attempt_id::text||'/segments/'||sequence::text||'-'||sha256||'.ndjson')
);
ALTER TABLE execution_output_segments ENABLE ROW LEVEL SECURITY;
ALTER TABLE execution_output_segments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON execution_output_segments
USING(tenant_id=sandbox_current_tenant_id()) WITH CHECK(tenant_id=sandbox_current_tenant_id());
CREATE TRIGGER output_segment_append_only BEFORE UPDATE OR DELETE ON execution_output_segments
FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_audit_mutation();
REVOKE ALL ON execution_output_segments FROM PUBLIC;

-- Route execution claims without allowing a gateway to starve behind arbitrary
-- lifecycle rows, or a lifecycle worker to steal a live execution connection.
ALTER TABLE operation_dispatch ADD COLUMN queue_role text NOT NULL DEFAULT 'WORKER'
    CHECK(queue_role IN ('WORKER','GATEWAY'));
DO $$
DECLARE routed record;
DECLARE previous_tenant text := current_setting('app.tenant_id',true);
BEGIN
    FOR routed IN SELECT operation_id,tenant_id FROM operation_dispatch LOOP
        PERFORM set_config('app.tenant_id',routed.tenant_id::text,true);
        UPDATE operation_dispatch d SET queue_role=CASE WHEN o.kind='EXECUTE' THEN 'GATEWAY' ELSE 'WORKER' END
        FROM operations o WHERE d.operation_id=routed.operation_id AND o.id=d.operation_id AND o.tenant_id=routed.tenant_id;
    END LOOP;
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
END;
$$;
CREATE INDEX operation_dispatch_role_due ON operation_dispatch(queue_role,eligible_at,operation_id);
CREATE OR REPLACE FUNCTION sandbox_update_dispatch() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    IF NEW.status IN ('QUEUED','RUNNING','WAITING') THEN
        INSERT INTO public.operation_dispatch(operation_id,tenant_id,eligible_at,queue_role)
        VALUES(NEW.id,NEW.tenant_id,GREATEST(NEW.next_attempt_at,COALESCE(NEW.lease_until,NEW.next_attempt_at)),CASE WHEN NEW.kind='EXECUTE' THEN 'GATEWAY' ELSE 'WORKER' END)
        ON CONFLICT(operation_id) DO UPDATE SET eligible_at=EXCLUDED.eligible_at,queue_role=EXCLUDED.queue_role;
    ELSE DELETE FROM public.operation_dispatch WHERE operation_id=NEW.id;
    END IF;
    RETURN NEW;
END;
$$;
CREATE FUNCTION sandbox_claim_routed_operation(worker_id text, requested_role text)
RETURNS TABLE(tenant_id uuid,operation_id uuid,lease_token bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;
DECLARE found_id uuid;
DECLARE previous_tenant text:=current_setting('app.tenant_id',true);
BEGIN
    IF worker_id IS NULL OR char_length(worker_id) NOT BETWEEN 1 AND 128 OR requested_role IS NULL OR requested_role NOT IN ('WORKER','GATEWAY') THEN
        RAISE EXCEPTION 'invalid worker identity or queue role' USING ERRCODE='22023';
    END IF;
    FOR candidate IN SELECT d.operation_id,d.tenant_id FROM public.operation_dispatch d
      WHERE d.queue_role=requested_role AND d.eligible_at<=clock_timestamp()
      ORDER BY d.eligible_at,d.operation_id LIMIT 64 LOOP
        PERFORM set_config('app.tenant_id',candidate.tenant_id::text,true);
        SELECT o.id INTO found_id FROM public.operations o
        WHERE o.tenant_id=candidate.tenant_id AND o.id=candidate.operation_id
          AND ((requested_role='GATEWAY' AND o.kind='EXECUTE') OR (requested_role='WORKER' AND o.kind<>'EXECUTE'))
          AND o.status IN ('QUEUED','RUNNING','WAITING') AND o.next_attempt_at<=clock_timestamp()
          AND (o.lease_until IS NULL OR o.lease_until<=clock_timestamp()) FOR UPDATE SKIP LOCKED;
        IF found_id IS NOT NULL THEN
            RETURN QUERY UPDATE public.operations o SET status='RUNNING',lease_owner=worker_id,
              lease_token=o.lease_token+1,lease_until=clock_timestamp()+interval '30 seconds',
              attempts=o.attempts+1,updated_at=clock_timestamp()
            WHERE o.id=found_id AND o.tenant_id=candidate.tenant_id RETURNING o.tenant_id,o.id,o.lease_token;
            PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true); RETURN;
        END IF;
    END LOOP;
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
END;
$$;
CREATE OR REPLACE FUNCTION sandbox_claim_operation(worker_id text)
RETURNS TABLE(tenant_id uuid,operation_id uuid,lease_token bigint)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
    SELECT * FROM public.sandbox_claim_routed_operation(worker_id,'WORKER');
$$;
CREATE FUNCTION sandbox_claim_execution(worker_id text)
RETURNS TABLE(tenant_id uuid,operation_id uuid,lease_token bigint)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
    SELECT * FROM public.sandbox_claim_routed_operation(worker_id,'GATEWAY');
$$;
REVOKE ALL ON FUNCTION sandbox_update_dispatch(),sandbox_claim_routed_operation(text,text),sandbox_claim_operation(text),sandbox_claim_execution(text) FROM PUBLIC;

-- Integrate after executions.exec_admission_uid/exec_admitted_at are added.
-- The dedicated admission role receives EXECUTE in admission-role.sql only.
-- No caller-supplied SQL, credential, username or grant is accepted by this gate.
CREATE FUNCTION sandbox_admit_execution_connect(
    requested_tenant uuid, requested_execution uuid, requested_attempt uuid,
    requested_review_uid uuid
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
    previous_tenant text := current_setting('app.tenant_id',true);
    instance_id uuid;
    workspace_id uuid;
    runtime public.instances%ROWTYPE;
    workspace public.workspaces%ROWTYPE;
    execution public.executions%ROWTYPE;
    operation public.operations%ROWTYPE;
    configuration public.platform_configuration%ROWTYPE;
    observed_now timestamptz;
    admitted boolean := false;
    authorized boolean;
BEGIN
    IF requested_tenant IS NULL OR requested_execution IS NULL
       OR requested_attempt IS NULL OR requested_review_uid IS NULL
       OR requested_tenant='00000000-0000-0000-0000-000000000000'
       OR requested_execution='00000000-0000-0000-0000-000000000000'
       OR requested_attempt='00000000-0000-0000-0000-000000000000'
       OR requested_review_uid='00000000-0000-0000-0000-000000000000' THEN
        RETURN false;
    END IF;
    PERFORM set_config('app.tenant_id',requested_tenant::text,true);
    <<validate_connect>>
    BEGIN
        SELECT e.instance_id,i.workspace_id INTO instance_id,workspace_id
        FROM public.executions e JOIN public.instances i
          ON (i.tenant_id,i.project_id,i.id)=(e.tenant_id,e.project_id,e.instance_id)
        WHERE e.tenant_id=requested_tenant AND e.id=requested_execution;
        IF NOT FOUND THEN EXIT validate_connect; END IF;
        -- Match every product/dispatcher path: workspace -> instance -> execution
        -- -> operation. No remote Kubernetes call is made while holding these.
        SELECT w.* INTO workspace FROM public.workspaces w
        WHERE w.tenant_id=requested_tenant AND w.id=workspace_id FOR UPDATE;
        IF NOT FOUND THEN EXIT validate_connect; END IF;
        SELECT i.* INTO runtime FROM public.instances i
        WHERE i.tenant_id=requested_tenant AND i.id=instance_id FOR UPDATE;
        IF NOT FOUND THEN EXIT validate_connect; END IF;
        SELECT e.* INTO execution FROM public.executions e
        WHERE e.tenant_id=requested_tenant AND e.id=requested_execution FOR UPDATE;
        IF NOT FOUND THEN EXIT validate_connect; END IF;
        SELECT o.* INTO operation FROM public.operations o
        WHERE o.tenant_id=requested_tenant AND o.id=execution.operation_id FOR UPDATE;
        IF NOT FOUND THEN EXIT validate_connect; END IF;
        SELECT c.* INTO configuration FROM public.platform_configuration c WHERE c.singleton;
        IF NOT FOUND THEN EXIT validate_connect; END IF;
        observed_now := clock_timestamp();
        IF NOT COALESCE(
            NOT configuration.safe_mode
            AND runtime.desired_state='RUNNING' AND runtime.observed_state='RUNNING'
            AND runtime.active_operation_id IS NULL AND runtime.stop_accepted_at IS NULL
            AND runtime.compute_lease_expires_at>observed_now
            AND runtime.cluster_epoch=configuration.cluster_epoch
            AND runtime.slot_held AND runtime.activity_kind='EXECUTION'
            AND runtime.activity_id=requested_execution
            AND runtime.activity_generation=runtime.runtime_generation
            AND runtime.ready_generation=runtime.runtime_generation
            AND runtime.ready_launch_id=runtime.launch_id
            AND runtime.ready_pod_uid=runtime.pod_uid
            AND runtime.ready_cluster_epoch=runtime.cluster_epoch
            AND runtime.ready_observed_at>=runtime.compute_lease_started_at
            AND runtime.ready_observed_at<=observed_now
            AND runtime.namespace IS NOT NULL
            AND runtime.pod_name='sbx-ws-'||runtime.workspace_id::text
            AND workspace.status='IN_USE' AND workspace.active_operation_id IS NULL
            AND workspace.delete_requested_at IS NULL
            AND workspace.namespace=runtime.namespace
            AND execution.instance_id=runtime.id AND execution.project_id=runtime.project_id
            AND execution.runtime_generation=runtime.runtime_generation
            AND execution.launch_id=runtime.launch_id AND execution.pod_uid=runtime.pod_uid
            AND execution.cluster_epoch=runtime.cluster_epoch
            AND execution.dispatch_attempt_id=requested_attempt
            AND execution.dispatch_attempted_at IS NOT NULL
            AND execution.status IN ('DISPATCHING','RUNNING')
            AND execution.slot_held AND execution.termination_status='NOT_REQUESTED'
            AND execution.cancel_requested_at IS NULL AND execution.deadline>observed_now
            AND operation.kind='EXECUTE' AND operation.status='RUNNING'
            AND execution.dispatch_lease_token=operation.lease_token
            AND operation.lease_owner IS NOT NULL AND operation.lease_until>observed_now
            AND NOT operation.cancel_requested AND operation.deadline>observed_now
            AND operation.instance_id=runtime.id AND operation.workspace_id=workspace.id
            AND operation.request->>'on_timeout'='HARD_STOP_INSTANCE'
            AND operation.request->>'classification'='NON_SENSITIVE'
            AND operation.request->'runner'->>'execution_id'=requested_execution::text
            AND (execution.exec_admission_uid IS NULL OR execution.exec_admission_uid=requested_review_uid),
            false) THEN EXIT validate_connect; END IF;
        SELECT public.sandbox_principal_enabled(operation.actor_principal_id)
            AND EXISTS (SELECT 1 FROM public.projects p JOIN public.tenants t ON t.id=p.tenant_id
                WHERE p.tenant_id=requested_tenant AND p.id=runtime.project_id
                  AND p.enabled AND t.enabled AND p.runtime_namespace=runtime.namespace)
            AND EXISTS (SELECT 1 FROM public.template_versions t WHERE t.tenant_id=requested_tenant
                AND t.id=runtime.template_version_id AND t.status='APPROVED')
            AND EXISTS (SELECT 1 FROM public.security_policy_versions p WHERE p.tenant_id=requested_tenant
                AND p.id=runtime.security_policy_version_id AND p.status='APPROVED')
            AND NOT EXISTS (
                SELECT 1 FROM (VALUES ('executions:create'),('instances:hard_stop')) AS required(action)
                WHERE NOT EXISTS (SELECT 1 FROM public.grants g
                    WHERE g.tenant_id=requested_tenant AND g.principal_id=operation.actor_principal_id
                      AND (g.project_id=runtime.project_id OR g.project_id IS NULL)
                      AND (g.action=required.action OR g.action='*') AND g.enabled
                      AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>observed_now))
            ) INTO authorized;
        IF authorized IS DISTINCT FROM true THEN EXIT validate_connect; END IF;
        IF execution.exec_admission_uid IS NULL THEN
            UPDATE public.executions e SET exec_admission_uid=requested_review_uid,
                exec_admitted_at=observed_now
            WHERE e.tenant_id=requested_tenant AND e.id=requested_execution;
        END IF;
        admitted := true;
    END validate_connect;
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
    RETURN admitted;
EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
    RAISE;
END;
$$;
REVOKE ALL ON FUNCTION sandbox_admit_execution_connect(uuid,uuid,uuid,uuid) FROM PUBLIC;
