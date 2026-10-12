-- No backfill: historical generations without this enforced protocol cannot
-- infer non-execution from missing permit rows or Kubernetes object absence.
CREATE TABLE launch_guard_contracts (
 id uuid PRIMARY KEY,cluster_epoch uuid NOT NULL,protocol text NOT NULL CHECK(protocol='NODEGUARD_REQUIRED_V1'),
 certification_report_sha256 text NOT NULL CHECK(certification_report_sha256~'^[0-9a-f]{64}$'),
 runtime_node_ids uuid[] NOT NULL CHECK(cardinality(runtime_node_ids)>0),
 approval_reference text NOT NULL CHECK(char_length(approval_reference) BETWEEN 1 AND 256),
 valid_until timestamptz NOT NULL,activated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 database_role text NOT NULL DEFAULT current_user,CHECK(valid_until>activated_at)
);
CREATE TABLE launch_guard_contract_revocations (
 contract_id uuid PRIMARY KEY REFERENCES launch_guard_contracts(id),
 approval_reference text NOT NULL CHECK(char_length(approval_reference) BETWEEN 1 AND 256),
 revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),database_role text NOT NULL DEFAULT current_user
);
CREATE TABLE launch_authority_births (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),tenant_id uuid NOT NULL,project_id uuid NOT NULL,
 instance_id uuid NOT NULL,workspace_id uuid NOT NULL,generation bigint NOT NULL CHECK(generation>0),
 launch_id uuid NOT NULL,cluster_epoch uuid NOT NULL,contract_id uuid NOT NULL REFERENCES launch_guard_contracts(id),
 namespace text NOT NULL,pod_name text NOT NULL,born_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,id),UNIQUE(tenant_id,project_id,id,instance_id,workspace_id,generation,launch_id,cluster_epoch),UNIQUE(tenant_id,instance_id,generation,launch_id,cluster_epoch),
 FOREIGN KEY(tenant_id,project_id,instance_id,workspace_id) REFERENCES instances(tenant_id,project_id,id,workspace_id)
);
CREATE TABLE never_authorized_closures (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),tenant_id uuid NOT NULL,project_id uuid NOT NULL,
 birth_id uuid NOT NULL,instance_id uuid NOT NULL,workspace_id uuid NOT NULL,operation_id uuid NOT NULL,
 generation bigint NOT NULL,launch_id uuid NOT NULL,cluster_epoch uuid NOT NULL,
 closed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,id),UNIQUE(tenant_id,birth_id),UNIQUE(tenant_id,instance_id,generation,launch_id,cluster_epoch),
 FOREIGN KEY(tenant_id,project_id,birth_id,instance_id,workspace_id,generation,launch_id,cluster_epoch) REFERENCES launch_authority_births(tenant_id,project_id,id,instance_id,workspace_id,generation,launch_id,cluster_epoch),
 FOREIGN KEY(tenant_id,project_id,instance_id,operation_id) REFERENCES operations(tenant_id,project_id,instance_id,id)
);
CREATE TABLE never_authorized_pod_observations (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),tenant_id uuid NOT NULL,closure_id uuid NOT NULL,
 pod_uid uuid NOT NULL,resource_version text NOT NULL CHECK(char_length(resource_version) BETWEEN 1 AND 256),
 observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,closure_id,pod_uid),
 FOREIGN KEY(tenant_id,closure_id) REFERENCES never_authorized_closures(tenant_id,id)
);
DO $$ DECLARE name text; BEGIN
 FOREACH name IN ARRAY ARRAY['launch_guard_contracts','launch_guard_contract_revocations','launch_authority_births','never_authorized_closures','never_authorized_pod_observations'] LOOP
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',name);
  EXECUTE format('CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.sandbox_prevent_audit_mutation()',name);
  IF name NOT IN('launch_guard_contracts','launch_guard_contract_revocations') THEN
   EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',name);
   EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',name);
   EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.sandbox_current_tenant_id()) WITH CHECK(tenant_id=public.sandbox_current_tenant_id())',name);
  END IF;
 END LOOP;
END $$;
ALTER TABLE instances ADD COLUMN never_authorized_closure_id uuid,
 ADD CONSTRAINT instance_never_authorized_closure FOREIGN KEY(tenant_id,never_authorized_closure_id) REFERENCES never_authorized_closures(tenant_id,id);

CREATE FUNCTION sandbox_record_launch_birth() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE contract uuid;BEGIN
 IF TG_OP='UPDATE' AND (NEW.runtime_generation,NEW.launch_id,NEW.cluster_epoch)=(OLD.runtime_generation,OLD.launch_id,OLD.cluster_epoch) THEN RETURN NEW;END IF;
 IF TG_OP='INSERT' AND NEW.runtime_generation<>1 THEN RETURN NEW;END IF;
 IF TG_OP='UPDATE' AND NOT EXISTS(SELECT 1 FROM public.launch_authority_births b
     WHERE b.tenant_id=OLD.tenant_id AND b.instance_id=OLD.id AND b.generation=OLD.runtime_generation AND b.launch_id=OLD.launch_id AND b.cluster_epoch=OLD.cluster_epoch)
   AND NOT EXISTS(SELECT 1 FROM public.local_termination_proofs p JOIN public.termination_cleanup_receipts c ON c.tenant_id=p.tenant_id AND c.proof_id=p.id
     WHERE p.tenant_id=OLD.tenant_id AND p.id=OLD.last_termination_proof_id AND p.instance_id=OLD.id AND p.workspace_id=OLD.workspace_id
       AND p.generation=OLD.runtime_generation AND p.launch_id=OLD.launch_id AND p.pod_uid=OLD.pod_uid AND p.cluster_epoch=OLD.cluster_epoch) THEN RETURN NEW;END IF;

 SELECT c.id INTO contract FROM public.launch_guard_contracts c
 WHERE c.cluster_epoch=NEW.cluster_epoch AND c.valid_until>clock_timestamp()
  AND c.cluster_epoch=(SELECT cluster_epoch FROM public.platform_configuration WHERE singleton)
  AND NOT EXISTS(SELECT 1 FROM public.launch_guard_contract_revocations r WHERE r.contract_id=c.id)
 ORDER BY c.activated_at DESC,c.id DESC LIMIT 1;
 IF contract IS NOT NULL THEN
  INSERT INTO public.launch_authority_births(tenant_id,project_id,instance_id,workspace_id,generation,launch_id,cluster_epoch,contract_id,namespace,pod_name)
   VALUES(NEW.tenant_id,NEW.project_id,NEW.id,NEW.workspace_id,NEW.runtime_generation,NEW.launch_id,NEW.cluster_epoch,contract,NEW.namespace,NEW.pod_name);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER launch_authority_birth AFTER INSERT OR UPDATE OF runtime_generation,launch_id,cluster_epoch ON instances
 FOR EACH ROW EXECUTE FUNCTION sandbox_record_launch_birth();
REVOKE ALL ON FUNCTION sandbox_record_launch_birth() FROM PUBLIC;

-- Alphabetically first BEFORE INSERT trigger: workspace -> instance -> node.
CREATE FUNCTION sandbox_gate_launch_authority() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE i public.instances;born boolean;BEGIN
 PERFORM id FROM public.workspaces WHERE tenant_id=NEW.tenant_id AND id=NEW.workspace_id FOR UPDATE;
 SELECT * INTO i FROM public.instances WHERE tenant_id=NEW.tenant_id AND id=NEW.instance_id FOR UPDATE;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM public.never_authorized_closures c WHERE c.tenant_id=NEW.tenant_id AND c.instance_id=NEW.instance_id
   AND c.generation=NEW.generation AND c.launch_id=NEW.launch_id AND c.cluster_epoch=NEW.cluster_epoch) THEN
  RAISE EXCEPTION 'launch authority permanently closed' USING ERRCODE='23514';END IF;
 SELECT EXISTS(SELECT 1 FROM public.launch_authority_births b WHERE b.tenant_id=NEW.tenant_id AND b.instance_id=NEW.instance_id
   AND b.generation=NEW.generation AND b.launch_id=NEW.launch_id AND b.cluster_epoch=NEW.cluster_epoch) INTO born;
 IF born AND ((i.project_id,i.workspace_id,i.runtime_generation,i.launch_id,i.cluster_epoch,i.pod_uid)
     IS DISTINCT FROM (NEW.project_id,NEW.workspace_id,NEW.generation,NEW.launch_id,NEW.cluster_epoch,NEW.pod_uid)
   OR i.desired_state<>'RUNNING' OR i.stop_accepted_at IS NOT NULL OR i.active_operation_id IS DISTINCT FROM NEW.operation_id
   OR NOT EXISTS(SELECT 1 FROM public.launch_guard_contracts c WHERE c.cluster_epoch=NEW.cluster_epoch
      AND NEW.runtime_node_id=ANY(c.runtime_node_ids) AND c.valid_until>clock_timestamp()
      AND NOT EXISTS(SELECT 1 FROM public.launch_guard_contract_revocations r WHERE r.contract_id=c.id))) THEN
  RAISE EXCEPTION 'launch authority no longer valid for current guard contract' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER aa_launch_authority_gate BEFORE INSERT ON launch_permits
 FOR EACH ROW EXECUTE FUNCTION sandbox_gate_launch_authority();
REVOKE ALL ON FUNCTION sandbox_gate_launch_authority() FROM PUBLIC;

CREATE FUNCTION sandbox_close_never_authorized(requested_tenant uuid,operation uuid,worker text,token bigint) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE i public.instances;o public.operations;b public.launch_authority_births;closed uuid;ws uuid;inst uuid;BEGIN
 IF requested_tenant IS DISTINCT FROM public.sandbox_current_tenant_id() OR worker IS NULL OR char_length(worker) NOT BETWEEN 1 AND 128 OR token IS NULL OR token<=0 THEN
  RAISE EXCEPTION 'invalid closure claim' USING ERRCODE='P4090';END IF;
 SELECT workspace_id,instance_id INTO ws,inst FROM public.operations WHERE tenant_id=requested_tenant AND id=operation;
 PERFORM id FROM public.workspaces WHERE tenant_id=requested_tenant AND id=ws FOR UPDATE;
 SELECT * INTO i FROM public.instances WHERE tenant_id=requested_tenant AND id=inst AND workspace_id=ws FOR UPDATE;
 PERFORM id FROM public.executions WHERE tenant_id=requested_tenant AND instance_id=inst AND slot_held ORDER BY id FOR UPDATE;
 SELECT * INTO o FROM public.operations WHERE tenant_id=requested_tenant AND id=operation FOR UPDATE;
 IF o.kind IS DISTINCT FROM 'DELETE' OR o.status IS DISTINCT FROM 'RUNNING' OR o.lease_owner IS DISTINCT FROM worker OR o.lease_token IS DISTINCT FROM token OR NOT COALESCE(o.lease_until>clock_timestamp(),false)
  OR i.active_operation_id IS DISTINCT FROM o.id OR i.desired_state IS DISTINCT FROM 'DELETED' OR i.slot_held
  OR i.cluster_epoch IS DISTINCT FROM(SELECT cluster_epoch FROM public.platform_configuration WHERE singleton)
  OR EXISTS(SELECT 1 FROM public.executions e WHERE e.tenant_id=i.tenant_id AND e.instance_id=i.id AND (e.slot_held OR e.dispatch_attempt_id IS NOT NULL AND e.runtime_generation=i.runtime_generation)) THEN
  RAISE EXCEPTION 'closure requires current DELETE with no guest activity' USING ERRCODE='P4090';END IF;
 SELECT * INTO b FROM public.launch_authority_births WHERE tenant_id=i.tenant_id AND instance_id=i.id
  AND workspace_id=i.workspace_id AND project_id=i.project_id AND generation=i.runtime_generation AND launch_id=i.launch_id AND cluster_epoch=i.cluster_epoch;
 IF b.id IS NULL THEN RETURN NULL;END IF;
 IF EXISTS(SELECT 1 FROM public.launch_permits p WHERE p.tenant_id=i.tenant_id AND p.instance_id=i.id AND p.generation=i.runtime_generation AND p.launch_id=i.launch_id AND p.cluster_epoch=i.cluster_epoch) THEN RETURN NULL;END IF;
 IF EXISTS(SELECT 1 FROM public.launch_permits p WHERE p.tenant_id=i.tenant_id AND p.instance_id=i.id
   AND NOT EXISTS(SELECT 1 FROM public.local_termination_proofs proof JOIN public.termination_cleanup_receipts cleanup ON cleanup.tenant_id=proof.tenant_id AND cleanup.proof_id=proof.id
     WHERE proof.tenant_id=p.tenant_id AND proof.permit_id=p.id AND proof.instance_id=p.instance_id AND proof.workspace_id=p.workspace_id
       AND proof.generation=p.generation AND proof.launch_id=p.launch_id AND proof.pod_uid=p.pod_uid AND proof.cluster_epoch=p.cluster_epoch)) THEN RETURN NULL;END IF;

 INSERT INTO public.never_authorized_closures(tenant_id,project_id,birth_id,instance_id,workspace_id,operation_id,generation,launch_id,cluster_epoch)
 VALUES(i.tenant_id,i.project_id,b.id,i.id,i.workspace_id,o.id,i.runtime_generation,i.launch_id,i.cluster_epoch) ON CONFLICT(tenant_id,birth_id) DO NOTHING;
 SELECT id INTO closed FROM public.never_authorized_closures WHERE tenant_id=i.tenant_id AND birth_id=b.id AND operation_id=o.id;
 RETURN closed;
END $$;
REVOKE ALL ON FUNCTION sandbox_close_never_authorized(uuid,uuid,text,bigint) FROM PUBLIC;

CREATE FUNCTION sandbox_never_authorized(tenant uuid,instance uuid,workspace uuid,generation bigint,launch uuid,epoch uuid,closure uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT COALESCE($1=public.sandbox_current_tenant_id() AND EXISTS(SELECT 1 FROM public.never_authorized_closures c
 JOIN public.launch_authority_births b ON b.tenant_id=c.tenant_id AND b.id=c.birth_id
 JOIN public.launch_guard_contracts g ON g.id=b.contract_id
 WHERE c.tenant_id=$1 AND c.instance_id=$2 AND c.workspace_id=$3 AND c.generation=$4 AND c.launch_id=$5 AND c.cluster_epoch=$6 AND c.id=$7
  AND (b.instance_id,b.workspace_id,b.generation,b.launch_id,b.cluster_epoch)=(c.instance_id,c.workspace_id,c.generation,c.launch_id,c.cluster_epoch)
  AND g.cluster_epoch=c.cluster_epoch AND b.born_at>=g.activated_at AND b.born_at<g.valid_until
  AND c.cluster_epoch=(SELECT cluster_epoch FROM public.platform_configuration WHERE singleton)
  AND NOT EXISTS(SELECT 1 FROM public.launch_permits p WHERE p.tenant_id=c.tenant_id AND p.instance_id=c.instance_id AND
     ((p.generation=c.generation AND p.launch_id=c.launch_id AND p.cluster_epoch=c.cluster_epoch) OR NOT EXISTS(
       SELECT 1 FROM public.local_termination_proofs proof JOIN public.termination_cleanup_receipts cleanup ON cleanup.tenant_id=proof.tenant_id AND cleanup.proof_id=proof.id
       WHERE proof.tenant_id=p.tenant_id AND proof.permit_id=p.id AND proof.instance_id=p.instance_id AND proof.workspace_id=p.workspace_id
         AND proof.generation=p.generation AND proof.launch_id=p.launch_id AND proof.pod_uid=p.pod_uid AND proof.cluster_epoch=p.cluster_epoch)))),false);
$$;
REVOKE ALL ON FUNCTION sandbox_never_authorized(uuid,uuid,uuid,bigint,uuid,uuid,uuid) FROM PUBLIC;

-- A compute DELETE may alternatively carry an immutable, permanently fenced
-- proof that this exact launch never received execution authority.
CREATE OR REPLACE FUNCTION sandbox_guard_instance_deletion() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF pg_has_role(current_user,(SELECT relowner FROM pg_class WHERE oid=TG_RELID),'MEMBER') THEN RETURN NEW;END IF;
 IF OLD.observed_state='DELETED' AND
   (NEW.observed_state<>'DELETED' OR NEW.desired_state<>'DELETED' OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at) THEN
   RAISE EXCEPTION 'deleted instance cannot be revived' USING ERRCODE='42501';END IF;
 IF NEW.observed_state<>'DELETED' OR OLD.observed_state='DELETED' THEN RETURN NEW;END IF;
 IF current_user<>'sandbox_termination' OR NEW.desired_state<>'DELETED' OR NEW.slot_held
    OR NEW.active_operation_id IS NOT NULL OR NEW.deleted_at IS NULL THEN
   RAISE EXCEPTION 'instance deletion requires trusted termination controller' USING ERRCODE='42501';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.operations o CROSS JOIN public.platform_configuration cfg
   WHERE o.tenant_id=OLD.tenant_id AND o.id=OLD.active_operation_id AND o.instance_id=OLD.id
     AND o.workspace_id=OLD.workspace_id AND o.kind='DELETE' AND o.status='RUNNING'
     AND o.lease_owner IS NOT NULL AND o.lease_until>clock_timestamp()
     AND cfg.singleton AND cfg.cluster_epoch=OLD.cluster_epoch) THEN
   RAISE EXCEPTION 'instance deletion requires current claimed DELETE' USING ERRCODE='42501';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.local_termination_proofs p
     JOIN public.termination_cleanup_receipts c ON c.tenant_id=p.tenant_id AND c.proof_id=p.id
   WHERE p.tenant_id=OLD.tenant_id AND p.id=NEW.last_termination_proof_id AND p.instance_id=OLD.id
     AND p.workspace_id=OLD.workspace_id AND p.generation=OLD.runtime_generation
     AND p.launch_id=OLD.launch_id AND p.pod_uid=OLD.pod_uid AND p.cluster_epoch=OLD.cluster_epoch
     AND c.old_pod_uid=p.pod_uid) AND NOT public.sandbox_never_authorized(OLD.tenant_id,OLD.id,OLD.workspace_id,OLD.runtime_generation,OLD.launch_id,OLD.cluster_epoch,NEW.never_authorized_closure_id) THEN
   RAISE EXCEPTION 'instance deletion requires exact immutable termination and cleanup' USING ERRCODE='42501';END IF;
 IF EXISTS(SELECT 1 FROM public.executions e WHERE e.tenant_id=OLD.tenant_id AND e.instance_id=OLD.id AND e.slot_held)
   OR EXISTS(SELECT 1 FROM public.quota_reservations r JOIN public.quota_accounts q
       ON q.tenant_id=r.tenant_id AND q.id=r.quota_account_id
     WHERE r.tenant_id=OLD.tenant_id AND r.resource_id=OLD.id AND r.status IN('PENDING','ALLOCATED')
       AND q.dimension IN('CPU_MILLIS','MEMORY_MIB','INSTANCES','EXECUTIONS')) THEN
   RAISE EXCEPTION 'instance deletion cannot retain active activity or compute reservations' USING ERRCODE='42501';END IF;
 RETURN NEW;
END $$;

CREATE FUNCTION sandbox_guard_never_closure_reference() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF OLD.never_authorized_closure_id IS NOT NULL AND NEW.never_authorized_closure_id IS DISTINCT FROM OLD.never_authorized_closure_id THEN
  RAISE EXCEPTION 'never-authorized closure reference is permanent' USING ERRCODE='23514';END IF;
 IF NEW.never_authorized_closure_id IS DISTINCT FROM OLD.never_authorized_closure_id AND
  (NEW.observed_state<>'DELETED' OR NOT public.sandbox_never_authorized(NEW.tenant_id,NEW.id,NEW.workspace_id,NEW.runtime_generation,NEW.launch_id,NEW.cluster_epoch,NEW.never_authorized_closure_id)) THEN
  RAISE EXCEPTION 'exact never-authorized closure required' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER never_closure_reference_guard BEFORE UPDATE OF never_authorized_closure_id ON instances FOR EACH ROW EXECUTE FUNCTION sandbox_guard_never_closure_reference();
REVOKE ALL ON FUNCTION sandbox_guard_never_closure_reference() FROM PUBLIC;

CREATE FUNCTION sandbox_never_authorized_pod(tenant uuid,instance uuid,pod uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT COALESCE($1=public.sandbox_current_tenant_id() AND EXISTS(
  SELECT 1 FROM public.instances i JOIN public.never_authorized_pod_observations p
    ON p.tenant_id=i.tenant_id AND p.closure_id=i.never_authorized_closure_id
  WHERE i.tenant_id=$1 AND i.id=$2 AND p.pod_uid=$3 AND i.desired_state='DELETED' AND i.observed_state='DELETED'
    AND public.sandbox_never_authorized(i.tenant_id,i.id,i.workspace_id,i.runtime_generation,i.launch_id,i.cluster_epoch,i.never_authorized_closure_id)),false);
$$;
REVOKE ALL ON FUNCTION sandbox_never_authorized_pod(uuid,uuid,uuid) FROM PUBLIC;
