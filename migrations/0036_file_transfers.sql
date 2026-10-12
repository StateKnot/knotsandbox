-- Fixed single-file transfers; cloud staging, process completion and VM death
-- are separate receipts. No process/guest observation releases retained bytes.
ALTER TABLE operations DROP CONSTRAINT operations_kind_check;
ALTER TABLE operations ADD CONSTRAINT operations_kind_check CHECK(kind IN('CREATE','START','STOP','RESTART','DELETE','RENEW','EXECUTE','DELETE_WORKSPACE','BACKUP','DIAGNOSE','FILE_TRANSFER'));
ALTER TABLE quota_accounts DROP CONSTRAINT quota_accounts_dimension_check;
ALTER TABLE quota_accounts ADD CONSTRAINT quota_accounts_dimension_check CHECK(dimension IN('INSTANCES','CPU_MILLIS','MEMORY_MIB','WORKSPACE_GIB','EXECUTIONS','BACKUP_GIB','BACKUP_TEMP_GIB','FILE_TRANSFERS','FILE_TRANSFER_BYTES'));
CREATE TABLE file_transfers (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,project_id uuid NOT NULL,instance_id uuid NOT NULL,workspace_id uuid NOT NULL,operation_id uuid NOT NULL UNIQUE,
 runtime_generation bigint NOT NULL CHECK(runtime_generation>0),launch_id uuid NOT NULL,pod_uid uuid NOT NULL,cluster_epoch uuid NOT NULL,content_id uuid NOT NULL,
 direction text NOT NULL CHECK(direction IN('UPLOAD','DOWNLOAD')),path text NOT NULL CHECK(octet_length(path) BETWEEN 1 AND 4096),
 status text NOT NULL CHECK(status IN('WAITING_UPLOAD','QUEUED','DISPATCHING','RUNNING','SUCCEEDED','FAILED','CANCELLED','TIMED_OUT','OUTCOME_UNKNOWN')),
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),byte_limit bigint NOT NULL CHECK(byte_limit BETWEEN 0 AND 104857600),expected_sha256 text CHECK(expected_sha256~'^[0-9a-f]{64}$'),
 observed_bytes bigint CHECK(observed_bytes BETWEEN 0 AND 104857600),observed_sha256 text CHECK(observed_sha256~'^[0-9a-f]{64}$'),replace boolean NOT NULL DEFAULT false,
 slot_held boolean NOT NULL,process_status text NOT NULL DEFAULT 'NOT_STARTED' CHECK(process_status IN('NOT_STARTED','DISPATCHING','RUNNING','EXITED','UNKNOWN','VM_TERMINATED')),
 content_status text NOT NULL DEFAULT 'STAGING' CHECK(content_status IN('STAGING','FROZEN','UNAVAILABLE','CLEANING','CLEANED')),
 timeout_policy text NOT NULL DEFAULT 'HARD_STOP_INSTANCE' CHECK(timeout_policy='HARD_STOP_INSTANCE'),deadline timestamptz NOT NULL,content_expires_at timestamptz NOT NULL,
 dispatch_attempt_id uuid,dispatch_attempted_at timestamptz,dispatch_lease_token bigint CHECK(dispatch_lease_token>0),exec_admission_uid uuid,exec_admitted_at timestamptz,
 process_exit_code integer CHECK(process_exit_code BETWEEN 0 AND 255),process_exited_at timestamptz,termination_proof_id uuid,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),completed_at timestamptz,
 FOREIGN KEY(tenant_id,project_id,instance_id) REFERENCES instances(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,workspace_id) REFERENCES workspaces(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,instance_id,operation_id) REFERENCES operations(tenant_id,project_id,instance_id,id),
 FOREIGN KEY(tenant_id,termination_proof_id) REFERENCES local_termination_proofs(tenant_id,id),
 UNIQUE(tenant_id,id),UNIQUE(tenant_id,project_id,id),UNIQUE(tenant_id,id,content_id),UNIQUE(tenant_id,id,dispatch_attempt_id),
 CHECK((direction='UPLOAD' AND expected_sha256 IS NOT NULL) OR(direction='DOWNLOAD' AND expected_sha256 IS NULL AND NOT replace AND NOT slot_held)),
 CHECK((dispatch_attempt_id IS NULL)=(dispatch_attempted_at IS NULL)),CHECK((dispatch_attempt_id IS NULL)=(dispatch_lease_token IS NULL)),
 CHECK((exec_admission_uid IS NULL)=(exec_admitted_at IS NULL)),CHECK((process_exit_code IS NULL)=(process_exited_at IS NULL)),
 CHECK(status NOT IN('DISPATCHING','RUNNING','SUCCEEDED','OUTCOME_UNKNOWN') OR dispatch_attempt_id IS NOT NULL),
 CHECK(status NOT IN('SUCCEEDED','FAILED','CANCELLED','TIMED_OUT') OR completed_at IS NOT NULL),
 CHECK(content_status<>'FROZEN' OR(observed_bytes IS NOT NULL AND observed_sha256 IS NOT NULL)),
 CHECK(NOT slot_held OR direction='UPLOAD'),CHECK(direction<>'UPLOAD' OR slot_held OR process_status IN('EXITED','VM_TERMINATED')),
 CHECK(process_status<>'EXITED' OR(process_exit_code=0 AND process_exit_code IS NOT NULL AND exec_admission_uid IS NOT NULL)),
 CHECK(process_status<>'VM_TERMINATED' OR termination_proof_id IS NOT NULL),
 CHECK(content_expires_at>=created_at AND content_expires_at<=created_at+interval '24 hours')
);
CREATE UNIQUE INDEX file_one_writer ON file_transfers(tenant_id,instance_id) WHERE slot_held;
CREATE INDEX file_transfer_history ON file_transfers(tenant_id,instance_id,created_at DESC,id);
CREATE TABLE file_transfer_parts (
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,transfer_id uuid NOT NULL,content_id uuid NOT NULL,part_index integer NOT NULL CHECK(part_index BETWEEN 0 AND 99),
 byte_length bigint NOT NULL CHECK(byte_length BETWEEN 1 AND 1048576),sha256 text NOT NULL CHECK(sha256~'^[0-9a-f]{64}$'),object_key text NOT NULL,
 write_until timestamptz NOT NULL,put_attempt_id uuid NOT NULL,put_state text NOT NULL DEFAULT 'PUTTING' CHECK(put_state IN('PUTTING','ACKED','UNKNOWN')), status text NOT NULL DEFAULT 'RESERVED' CHECK(status IN('RESERVED','STORED','CLEANED')),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),stored_at timestamptz,cleaned_at timestamptz,
 PRIMARY KEY(tenant_id,transfer_id,part_index),FOREIGN KEY(tenant_id,project_id,transfer_id) REFERENCES file_transfers(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,transfer_id,content_id) REFERENCES file_transfers(tenant_id,id,content_id),
 CHECK(object_key='tenants/'||tenant_id::text||'/file-transfers/'||transfer_id::text||'/content/'||content_id::text||'/parts/'||part_index::text),
 CHECK((status='CLEANED')=(cleaned_at IS NOT NULL)),CHECK(status<>'STORED' OR(stored_at IS NOT NULL AND put_state='ACKED'))
);
CREATE TABLE file_part_cleanup_receipts (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),tenant_id uuid NOT NULL,project_id uuid NOT NULL,transfer_id uuid NOT NULL,part_index integer NOT NULL,
 confirmed_absent_at timestamptz NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,transfer_id,part_index) REFERENCES file_transfer_parts(tenant_id,transfer_id,part_index),
 FOREIGN KEY(tenant_id,project_id,transfer_id) REFERENCES file_transfers(tenant_id,project_id,id),UNIQUE(tenant_id,transfer_id,part_index)
);
DO $$ DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['file_transfers','file_transfer_parts','file_part_cleanup_receipts'] LOOP
 EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
 EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.sandbox_current_tenant_id()) WITH CHECK(tenant_id=public.sandbox_current_tenant_id())',tab);
 EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',tab);END LOOP;
END $$;
CREATE TRIGGER file_no_delete BEFORE DELETE ON file_transfers FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_audit_mutation();
CREATE TRIGGER file_parts_no_delete BEFORE DELETE ON file_transfer_parts FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_audit_mutation();
CREATE TRIGGER file_cleanup_append_only BEFORE UPDATE OR DELETE ON file_part_cleanup_receipts FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_audit_mutation();
CREATE FUNCTION sandbox_guard_file_transfer() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE owner_member boolean:=pg_has_role(current_user,(SELECT relowner FROM pg_class WHERE oid=TG_RELID),'MEMBER');
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.dispatch_attempt_id IS NOT NULL OR NEW.exec_admission_uid IS NOT NULL OR NEW.process_exit_code IS NOT NULL OR NEW.termination_proof_id IS NOT NULL OR NEW.process_status<>'NOT_STARTED' THEN RAISE EXCEPTION 'new file transfer cannot fabricate evidence' USING ERRCODE='23514';END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['status','version','observed_bytes','observed_sha256','slot_held','process_status','content_status','dispatch_attempt_id','dispatch_attempted_at','dispatch_lease_token','exec_admission_uid','exec_admitted_at','process_exit_code','process_exited_at','termination_proof_id','updated_at','completed_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['status','version','observed_bytes','observed_sha256','slot_held','process_status','content_status','dispatch_attempt_id','dispatch_attempted_at','dispatch_lease_token','exec_admission_uid','exec_admitted_at','process_exit_code','process_exited_at','termination_proof_id','updated_at','completed_at']) THEN RAISE EXCEPTION 'file transfer intent immutable' USING ERRCODE='23514';END IF;
  IF OLD.dispatch_attempt_id IS NOT NULL AND (NEW.dispatch_attempt_id,NEW.dispatch_attempted_at,NEW.dispatch_lease_token) IS DISTINCT FROM(OLD.dispatch_attempt_id,OLD.dispatch_attempted_at,OLD.dispatch_lease_token) THEN RAISE EXCEPTION 'file dispatch immutable' USING ERRCODE='23514';END IF;
  IF OLD.dispatch_attempt_id IS NULL AND NEW.dispatch_attempt_id IS NOT NULL AND(OLD.status<>'QUEUED' OR NEW.status<>'DISPATCHING' OR NEW.process_status<>'DISPATCHING') THEN RAISE EXCEPTION 'file dispatch requires queued intent' USING ERRCODE='23514';END IF;
  IF OLD.status='OUTCOME_UNKNOWN' AND NEW.status<>'OUTCOME_UNKNOWN' THEN RAISE EXCEPTION 'unknown file outcome cannot resolve' USING ERRCODE='23514';END IF;
  IF OLD.process_status IN('EXITED','VM_TERMINATED') AND NEW.process_status<>OLD.process_status THEN RAISE EXCEPTION 'file closure cannot regress' USING ERRCODE='23514';END IF;
  IF OLD.exec_admission_uid IS NOT NULL AND(NEW.exec_admission_uid,NEW.exec_admitted_at) IS DISTINCT FROM(OLD.exec_admission_uid,OLD.exec_admitted_at) THEN RAISE EXCEPTION 'file admission immutable' USING ERRCODE='23514';END IF;
  IF (NEW.exec_admission_uid,NEW.exec_admitted_at) IS DISTINCT FROM(OLD.exec_admission_uid,OLD.exec_admitted_at) AND NOT owner_member THEN RAISE EXCEPTION 'file admission requires definer gate' USING ERRCODE='42501';END IF;
  IF OLD.process_exit_code IS NOT NULL AND(NEW.process_exit_code,NEW.process_exited_at) IS DISTINCT FROM(OLD.process_exit_code,OLD.process_exited_at) THEN RAISE EXCEPTION 'file process receipt immutable' USING ERRCODE='23514';END IF;
  IF (NEW.process_exit_code,NEW.process_exited_at) IS DISTINCT FROM(OLD.process_exit_code,OLD.process_exited_at) AND NOT owner_member AND current_user<>'sandbox_gateway' THEN RAISE EXCEPTION 'file process requires gateway' USING ERRCODE='42501';END IF;
  IF NEW.termination_proof_id IS DISTINCT FROM OLD.termination_proof_id THEN
   IF NOT owner_member AND current_user<>'sandbox_termination' THEN RAISE EXCEPTION 'file VM closure requires termination role' USING ERRCODE='42501';END IF;
   IF NOT EXISTS(SELECT 1 FROM public.local_termination_proofs p JOIN public.termination_cleanup_receipts c ON c.tenant_id=p.tenant_id AND c.proof_id=p.id WHERE p.tenant_id=NEW.tenant_id AND p.id=NEW.termination_proof_id AND(p.instance_id,p.generation,p.launch_id,p.pod_uid,p.cluster_epoch)=(NEW.instance_id,NEW.runtime_generation,NEW.launch_id,NEW.pod_uid,NEW.cluster_epoch)) THEN RAISE EXCEPTION 'file VM closure requires exact cleanup proof' USING ERRCODE='42501';END IF;
  END IF;
  IF OLD.observed_sha256 IS NOT NULL AND(NEW.observed_sha256,NEW.observed_bytes) IS DISTINCT FROM(OLD.observed_sha256,OLD.observed_bytes) THEN RAISE EXCEPTION 'frozen content immutable' USING ERRCODE='23514';END IF;
  IF OLD.content_status='CLEANED' AND NEW.content_status<>'CLEANED' THEN RAISE EXCEPTION 'cleaned content cannot revive' USING ERRCODE='23514';END IF;
  NEW.version:=OLD.version+1;NEW.updated_at:=clock_timestamp();
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER file_evidence_guard BEFORE INSERT OR UPDATE ON file_transfers FOR EACH ROW EXECUTE FUNCTION sandbox_guard_file_transfer();
CREATE FUNCTION sandbox_guard_file_part() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF (NEW.tenant_id,NEW.project_id,NEW.transfer_id,NEW.content_id,NEW.part_index,NEW.byte_length,NEW.sha256,NEW.object_key,NEW.put_attempt_id,NEW.write_until) IS DISTINCT FROM(OLD.tenant_id,OLD.project_id,OLD.transfer_id,OLD.content_id,OLD.part_index,OLD.byte_length,OLD.sha256,OLD.object_key,OLD.put_attempt_id,OLD.write_until) OR OLD.status='CLEANED' AND NEW.status<>'CLEANED' OR OLD.status='STORED' AND NEW.status='RESERVED' OR OLD.put_state IN('ACKED','UNKNOWN') AND NEW.put_state<>OLD.put_state THEN RAISE EXCEPTION 'file part identity immutable' USING ERRCODE='23514';END IF;
 IF NEW.status='CLEANED' AND OLD.status<>'CLEANED' AND NOT EXISTS(SELECT 1 FROM public.file_part_cleanup_receipts r WHERE r.tenant_id=NEW.tenant_id AND r.transfer_id=NEW.transfer_id AND r.part_index=NEW.part_index) THEN RAISE EXCEPTION 'file part cleanup requires receipt' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER file_part_identity_guard BEFORE UPDATE ON file_transfer_parts FOR EACH ROW EXECUTE FUNCTION sandbox_guard_file_part();
REVOKE ALL ON FUNCTION sandbox_guard_file_transfer(),sandbox_guard_file_part() FROM PUBLIC;

CREATE OR REPLACE FUNCTION sandbox_mutate_project_grant(actor uuid,project uuid,mutation text,grant_id uuid,target_principal uuid,delegated_action text,requested_expiry timestamptz,will_enable boolean,expected_version bigint)
RETURNS public.grants LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=public.sandbox_current_tenant_id();result public.grants;
BEGIN
    PERFORM public.sandbox_lock_identity_tenant(tenant);
    IF delegated_action IS NULL OR delegated_action NOT IN('instances:create','instances:read','instances:start','instances:stop','instances:restart','instances:renew','instances:delete','instances:hard_stop','workspaces:read','workspaces:delete','operations:read','events:read','audit:read','capabilities:read','executions:create','executions:read','executions:cancel','executions:output:read','grants:read','grants:write','backups:create','backups:read','diagnoses:create','diagnoses:read','files:read','files:write') THEN
        RAISE EXCEPTION 'unsupported grant action' USING ERRCODE='P4000';END IF;
    IF mutation NOT IN('CREATE','UPDATE','REVOKE') THEN RAISE EXCEPTION 'unknown grant mutation' USING ERRCODE='P4000';END IF;
    IF mutation<>'CREATE' THEN
        SELECT g.* INTO result FROM public.grants g WHERE g.tenant_id=tenant AND g.project_id=project AND g.id=grant_id FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION 'grant not found' USING ERRCODE='P4040';END IF;
        IF expected_version IS DISTINCT FROM result.version THEN RAISE EXCEPTION 'grant version mismatch' USING ERRCODE='P4120';END IF;
        IF (target_principal,delegated_action) IS DISTINCT FROM(result.principal_id,result.action) THEN
            RAISE EXCEPTION 'grant identity is immutable' USING ERRCODE='P4000';END IF;
    END IF;
    IF will_enable AND mutation<>'REVOKE' AND requested_expiry IS NOT NULL AND requested_expiry<=clock_timestamp() THEN
        RAISE EXCEPTION 'grant expiry must be in the future' USING ERRCODE='P4000';END IF;
    PERFORM public.sandbox_check_grant_delegation(actor,project,delegated_action,requested_expiry,will_enable AND mutation<>'REVOKE');
    IF NOT EXISTS(SELECT 1 FROM public.tenant_principals tp JOIN public.principals p ON p.id=tp.principal_id
        WHERE tp.tenant_id=tenant AND tp.principal_id=target_principal AND p.kind<>'SYSTEM') THEN
        RAISE EXCEPTION 'grant target not found' USING ERRCODE='P4040';END IF;
    IF mutation='CREATE' THEN
        IF EXISTS(SELECT 1 FROM public.grants g WHERE g.tenant_id=tenant AND g.project_id=project AND g.principal_id=target_principal AND g.action=delegated_action) THEN
            RAISE EXCEPTION 'grant already exists' USING ERRCODE='P4090';END IF;
        INSERT INTO public.grants(id,tenant_id,project_id,principal_id,action,enabled,expires_at)
        VALUES(grant_id,tenant,project,target_principal,delegated_action,will_enable,requested_expiry) RETURNING * INTO result;
    ELSE
        UPDATE public.grants SET enabled=will_enable AND mutation<>'REVOKE',expires_at=CASE WHEN mutation='REVOKE' THEN result.expires_at ELSE requested_expiry END,
            revoked_at=CASE WHEN mutation='REVOKE' THEN clock_timestamp() WHEN will_enable THEN NULL ELSE revoked_at END
        WHERE tenant_id=tenant AND id=grant_id RETURNING * INTO result;
    END IF;
    RETURN result;
END $$;

ALTER TABLE operation_dispatch DROP CONSTRAINT operation_dispatch_queue_role_check;
ALTER TABLE operation_dispatch ADD CONSTRAINT operation_dispatch_queue_role_check CHECK(queue_role IN('WORKER','GATEWAY','TERMINATION','VOLUME','BACKUP','FILE_TRANSFER'));
CREATE OR REPLACE FUNCTION sandbox_update_dispatch() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE target_queue text;
BEGIN
    target_queue:=CASE WHEN NEW.kind='FILE_TRANSFER' THEN 'FILE_TRANSFER' WHEN NEW.kind='BACKUP' THEN 'BACKUP' WHEN NEW.kind='DELETE_WORKSPACE' THEN 'VOLUME' WHEN NEW.kind='EXECUTE' THEN 'GATEWAY'
        WHEN NEW.kind IN('STOP','DELETE') OR (NEW.kind='RESTART' AND NEW.restart_generation IS NULL) THEN 'TERMINATION'
        ELSE 'WORKER' END;
    IF NEW.status IN('QUEUED','RUNNING','WAITING') THEN
        INSERT INTO public.operation_dispatch(operation_id,tenant_id,eligible_at,queue_role,launch_registration_eligible_at,workspace_delete_epoch,backup_epoch)
        VALUES(NEW.id,NEW.tenant_id,GREATEST(NEW.next_attempt_at,COALESCE(NEW.lease_until,NEW.next_attempt_at)),target_queue,NEW.launch_registration_next_attempt_at,(SELECT d.cluster_epoch FROM public.workspace_delete_intents d WHERE d.tenant_id=NEW.tenant_id AND d.operation_id=NEW.id),(SELECT b.cluster_epoch FROM public.backups b WHERE b.tenant_id=NEW.tenant_id AND b.operation_id=NEW.id))
        ON CONFLICT(operation_id) DO UPDATE SET eligible_at=EXCLUDED.eligible_at,queue_role=EXCLUDED.queue_role,launch_registration_eligible_at=EXCLUDED.launch_registration_eligible_at,workspace_delete_epoch=EXCLUDED.workspace_delete_epoch,backup_epoch=EXCLUDED.backup_epoch;
    ELSE DELETE FROM public.operation_dispatch WHERE operation_id=NEW.id;
    END IF;
    RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION sandbox_claim_routed_operation(worker_id text,requested_role text)
RETURNS TABLE(tenant_id uuid,operation_id uuid,lease_token bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;found_id uuid;previous_tenant text:=current_setting('app.tenant_id',true);
BEGIN
    IF worker_id IS NULL OR char_length(worker_id) NOT BETWEEN 1 AND 128 OR requested_role IS NULL OR requested_role NOT IN('WORKER','GATEWAY','TERMINATION','VOLUME','BACKUP','FILE_TRANSFER') THEN
        RAISE EXCEPTION 'invalid worker identity or queue role' USING ERRCODE='22023';END IF;
    FOR candidate IN SELECT d.operation_id,d.tenant_id FROM public.operation_dispatch d
      WHERE d.queue_role=requested_role AND (requested_role<>'VOLUME' OR d.workspace_delete_epoch=(SELECT cluster_epoch FROM public.platform_configuration WHERE singleton)) AND(requested_role<>'BACKUP' OR d.backup_epoch=(SELECT cluster_epoch FROM public.platform_configuration WHERE singleton)) AND d.eligible_at<=clock_timestamp() ORDER BY d.eligible_at,d.operation_id LIMIT 64 LOOP
        PERFORM set_config('app.tenant_id',candidate.tenant_id::text,true);
        SELECT o.id INTO found_id FROM public.operations o
        WHERE o.tenant_id=candidate.tenant_id AND o.id=candidate.operation_id
          AND CASE requested_role WHEN 'FILE_TRANSFER' THEN o.kind='FILE_TRANSFER' WHEN 'BACKUP' THEN o.kind='BACKUP' WHEN 'VOLUME' THEN o.kind='DELETE_WORKSPACE' WHEN 'GATEWAY' THEN o.kind='EXECUTE'
              WHEN 'TERMINATION' THEN o.kind IN('STOP','DELETE') OR (o.kind='RESTART' AND o.restart_generation IS NULL)
              ELSE o.kind NOT IN('EXECUTE','STOP','DELETE','DELETE_WORKSPACE','BACKUP','FILE_TRANSFER') AND (o.kind<>'RESTART' OR o.restart_generation IS NOT NULL) END
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

CREATE FUNCTION sandbox_claim_file_transfer(worker_id text) RETURNS TABLE(tenant_id uuid,operation_id uuid,lease_token bigint) LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$ SELECT * FROM public.sandbox_claim_routed_operation(worker_id,'FILE_TRANSFER'); $$;
REVOKE ALL ON FUNCTION sandbox_claim_file_transfer(text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION sandbox_check_file_connect(
    requested_tenant uuid, requested_transfer uuid, requested_attempt uuid,
    requested_review_uid uuid, consume boolean
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
    previous_tenant text := current_setting('app.tenant_id',true);
    instance_id uuid;
    workspace_id uuid;
    runtime public.instances%ROWTYPE;
    workspace public.workspaces%ROWTYPE;
    transfer public.file_transfers%ROWTYPE;
    operation public.operations%ROWTYPE;
    configuration public.platform_configuration%ROWTYPE;
    observed_now timestamptz;
    admitted boolean := false;
    authorized boolean;
BEGIN
    IF requested_tenant IS NULL OR requested_transfer IS NULL
       OR requested_attempt IS NULL OR requested_review_uid IS NULL
       OR requested_tenant='00000000-0000-0000-0000-000000000000'
       OR requested_transfer='00000000-0000-0000-0000-000000000000'
       OR requested_attempt='00000000-0000-0000-0000-000000000000'
       OR requested_review_uid='00000000-0000-0000-0000-000000000000' THEN
        RETURN false;
    END IF;
    PERFORM set_config('app.tenant_id',requested_tenant::text,true);
    <<validate_connect>>
    BEGIN
        SELECT e.instance_id,i.workspace_id INTO instance_id,workspace_id
        FROM public.file_transfers e JOIN public.instances i
          ON (i.tenant_id,i.project_id,i.id)=(e.tenant_id,e.project_id,e.instance_id)
        WHERE e.tenant_id=requested_tenant AND e.id=requested_transfer;
        IF NOT FOUND THEN EXIT validate_connect; END IF;
        -- Match every product/dispatcher path: workspace -> instance -> transfer
        -- -> operation. No remote Kubernetes call is made while holding these.
        SELECT w.* INTO workspace FROM public.workspaces w
        WHERE w.tenant_id=requested_tenant AND w.id=workspace_id FOR UPDATE;
        IF NOT FOUND THEN EXIT validate_connect; END IF;
        SELECT i.* INTO runtime FROM public.instances i
        WHERE i.tenant_id=requested_tenant AND i.id=instance_id FOR UPDATE;
        IF NOT FOUND THEN EXIT validate_connect; END IF;
        SELECT e.* INTO transfer FROM public.file_transfers e
        WHERE e.tenant_id=requested_tenant AND e.id=requested_transfer FOR UPDATE;
        IF NOT FOUND THEN EXIT validate_connect; END IF;
        SELECT o.* INTO operation FROM public.operations o
        WHERE o.tenant_id=requested_tenant AND o.id=transfer.operation_id FOR UPDATE;
        IF NOT FOUND THEN EXIT validate_connect; END IF;
        SELECT c.* INTO configuration FROM public.platform_configuration c WHERE c.singleton;
        IF NOT FOUND THEN EXIT validate_connect; END IF;
        observed_now := clock_timestamp();
        IF NOT COALESCE(
            NOT configuration.safe_mode
            AND runtime.desired_state='RUNNING' AND runtime.observed_state='RUNNING'
            AND runtime.active_operation_id IS NULL AND runtime.stop_accepted_at IS NULL
            AND runtime.compute_lease_expires_at>observed_now
            AND EXISTS(SELECT 1 FROM public.sandbox_instance_certification(requested_tenant,runtime.id) certification
                WHERE certification.assigned AND certification.valid_until>=runtime.compute_lease_expires_at)
            AND runtime.cluster_epoch=configuration.cluster_epoch
            AND (transfer.direction='DOWNLOAD' OR (runtime.slot_held AND runtime.activity_kind='FILE_WRITE' AND runtime.activity_id=requested_transfer AND runtime.activity_generation=runtime.runtime_generation))
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
            AND transfer.instance_id=runtime.id AND transfer.project_id=runtime.project_id
            AND transfer.runtime_generation=runtime.runtime_generation
            AND transfer.launch_id=runtime.launch_id AND transfer.pod_uid=runtime.pod_uid
            AND transfer.cluster_epoch=runtime.cluster_epoch
            AND transfer.dispatch_attempt_id=requested_attempt
            AND transfer.dispatch_attempted_at IS NOT NULL
            AND transfer.status IN ('DISPATCHING','RUNNING')
            AND (transfer.direction='DOWNLOAD' OR transfer.slot_held) AND transfer.process_status IN('DISPATCHING','RUNNING') AND transfer.deadline>observed_now AND (transfer.direction='DOWNLOAD' OR transfer.content_status='FROZEN')
            AND operation.kind='FILE_TRANSFER' AND operation.status='RUNNING'
            AND transfer.dispatch_lease_token=operation.lease_token
            AND operation.lease_owner IS NOT NULL AND operation.lease_until>observed_now
            AND NOT operation.cancel_requested AND operation.deadline>observed_now
            AND operation.instance_id=runtime.id AND operation.workspace_id=workspace.id
            AND operation.request->>'on_timeout'='HARD_STOP_INSTANCE'
            AND operation.request->>'transfer_id'=requested_transfer::text
            AND operation.request->>'direction'=transfer.direction
            AND (transfer.exec_admission_uid IS NULL OR transfer.exec_admission_uid=requested_review_uid),
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
                SELECT 1 FROM (VALUES (CASE WHEN transfer.direction='UPLOAD' THEN 'files:write' ELSE 'files:read' END),('instances:hard_stop')) AS required(action)
                WHERE NOT EXISTS (SELECT 1 FROM public.grants g
                    WHERE g.tenant_id=requested_tenant AND g.principal_id=operation.actor_principal_id
                      AND (g.project_id=runtime.project_id OR g.project_id IS NULL)
                      AND (g.action=required.action OR g.action='*') AND g.enabled
                      AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>observed_now))
            ) INTO authorized;
        IF authorized IS DISTINCT FROM true THEN EXIT validate_connect; END IF;
        IF consume AND transfer.exec_admission_uid IS NULL THEN
            UPDATE public.file_transfers e SET exec_admission_uid=requested_review_uid,
                exec_admitted_at=observed_now
            WHERE e.tenant_id=requested_tenant AND e.id=requested_transfer;
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
REVOKE ALL ON FUNCTION sandbox_check_file_connect(uuid,uuid,uuid,uuid,boolean) FROM PUBLIC;

CREATE OR REPLACE FUNCTION sandbox_guard_runtime_release() RETURNS trigger
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
        IF OLD.slot_held AND NOT NEW.slot_held AND NEW.observed_state<>'STOPPED' AND OLD.activity_kind='FILE_WRITE' AND EXISTS(SELECT 1 FROM public.file_transfers f WHERE f.tenant_id=OLD.tenant_id AND f.id=OLD.activity_id AND f.instance_id=OLD.id AND(f.runtime_generation,f.launch_id,f.pod_uid,f.cluster_epoch)=(OLD.runtime_generation,OLD.launch_id,OLD.pod_uid,OLD.cluster_epoch) AND NOT f.slot_held AND f.process_status='EXITED' AND f.process_exit_code=0 AND f.exec_admission_uid IS NOT NULL) THEN RETURN NEW;END IF;
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
-- Every platform activity update respects concurrent download observations.
CREATE FUNCTION sandbox_file_idle_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.idle_since IS NOT NULL AND EXISTS(SELECT 1 FROM public.file_transfers f WHERE f.tenant_id=NEW.tenant_id AND f.instance_id=NEW.id AND f.runtime_generation=NEW.runtime_generation AND f.process_status NOT IN('EXITED','VM_TERMINATED')) THEN NEW.idle_since:=NULL;END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER instance_file_idle_guard BEFORE UPDATE ON instances FOR EACH ROW EXECUTE FUNCTION sandbox_file_idle_guard();
CREATE FUNCTION sandbox_file_activity_match() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE tenant uuid;instance uuid;runtime public.instances%ROWTYPE;active public.file_transfers%ROWTYPE;
BEGIN
 IF TG_TABLE_NAME='instances' THEN tenant:=NEW.tenant_id;instance:=NEW.id;ELSE tenant:=NEW.tenant_id;instance:=NEW.instance_id;END IF;
 SELECT * INTO runtime FROM public.instances i WHERE i.tenant_id=tenant AND i.id=instance;
 SELECT * INTO active FROM public.file_transfers f WHERE f.tenant_id=tenant AND f.instance_id=instance AND f.slot_held;
 IF FOUND AND NOT COALESCE(runtime.slot_held AND runtime.activity_kind='FILE_WRITE' AND runtime.activity_id=active.id AND runtime.activity_generation=active.runtime_generation AND(runtime.runtime_generation,runtime.launch_id,runtime.pod_uid,runtime.cluster_epoch)=(active.runtime_generation,active.launch_id,active.pod_uid,active.cluster_epoch),false) THEN RAISE EXCEPTION 'file writer slot requires exact activity identity' USING ERRCODE='23514';END IF;
 IF runtime.slot_held AND runtime.activity_kind='FILE_WRITE' AND NOT EXISTS(SELECT 1 FROM public.file_transfers f WHERE f.tenant_id=tenant AND f.id=runtime.activity_id AND f.instance_id=instance AND f.slot_held) THEN RAISE EXCEPTION 'file activity requires held file slot' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER instance_file_activity_match AFTER INSERT OR UPDATE ON instances DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sandbox_file_activity_match();
CREATE CONSTRAINT TRIGGER transfer_file_activity_match AFTER INSERT OR UPDATE ON file_transfers DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sandbox_file_activity_match();
-- Minimal global scheduler reveals only expired object cleanup identities.
CREATE TABLE file_cleanup_schedule(transfer_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,eligible_at timestamptz NOT NULL,FOREIGN KEY(tenant_id,transfer_id) REFERENCES file_transfers(tenant_id,id));
REVOKE ALL ON file_cleanup_schedule FROM PUBLIC;
CREATE FUNCTION sandbox_update_file_cleanup() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.content_status<>'CLEANED' THEN INSERT INTO public.file_cleanup_schedule(transfer_id,tenant_id,eligible_at) VALUES(NEW.id,NEW.tenant_id,NEW.content_expires_at) ON CONFLICT(transfer_id) DO NOTHING;
 ELSE DELETE FROM public.file_cleanup_schedule WHERE transfer_id=NEW.id;END IF;RETURN NEW;
END $$;
CREATE TRIGGER file_cleanup_sync AFTER INSERT OR UPDATE ON file_transfers FOR EACH ROW EXECUTE FUNCTION sandbox_update_file_cleanup();
CREATE FUNCTION sandbox_file_cleanup_candidates(requested_limit integer) RETURNS TABLE(tenant_id uuid,transfer_id uuid) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 RETURN QUERY WITH due AS(SELECT s.transfer_id FROM public.file_cleanup_schedule s WHERE s.eligible_at<=clock_timestamp() ORDER BY s.eligible_at,s.transfer_id LIMIT LEAST(GREATEST(requested_limit,1),100) FOR UPDATE SKIP LOCKED)
 UPDATE public.file_cleanup_schedule s SET eligible_at=clock_timestamp()+interval '5 minutes' FROM due WHERE s.transfer_id=due.transfer_id RETURNING s.tenant_id,s.transfer_id;
END $$;
CREATE FUNCTION sandbox_guard_file_quota_release() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE dimension text;file public.file_transfers%ROWTYPE;
BEGIN
 IF NEW.status<>'RELEASED' OR OLD.status='RELEASED' THEN RETURN NEW;END IF;
 SELECT q.dimension INTO dimension FROM public.quota_accounts q WHERE q.tenant_id=NEW.tenant_id AND q.id=NEW.quota_account_id;
 IF dimension NOT IN('FILE_TRANSFERS','FILE_TRANSFER_BYTES') THEN RETURN NEW;END IF;
 SELECT * INTO file FROM public.file_transfers f WHERE f.tenant_id=NEW.tenant_id AND f.operation_id=NEW.operation_id AND f.instance_id=NEW.resource_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'file quota requires exact transfer' USING ERRCODE='23514';END IF;
 IF dimension='FILE_TRANSFERS' AND file.process_status NOT IN('EXITED','VM_TERMINATED') THEN RAISE EXCEPTION 'file count quota requires trusted process/VM closure' USING ERRCODE='23514';END IF;
 IF dimension='FILE_TRANSFER_BYTES' AND(file.content_status<>'CLEANED' OR EXISTS(SELECT 1 FROM public.file_transfer_parts p WHERE p.tenant_id=file.tenant_id AND p.transfer_id=file.id AND(p.status<>'CLEANED' OR p.put_state<>'ACKED'))) THEN RAISE EXCEPTION 'file byte quota requires no ambiguous writers and complete object cleanup' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER file_quota_release_guard BEFORE UPDATE ON quota_reservations FOR EACH ROW EXECUTE FUNCTION sandbox_guard_file_quota_release();
REVOKE ALL ON FUNCTION sandbox_file_idle_guard(),sandbox_file_activity_match(),sandbox_update_file_cleanup(),sandbox_file_cleanup_candidates(integer),sandbox_guard_file_quota_release() FROM PUBLIC;
