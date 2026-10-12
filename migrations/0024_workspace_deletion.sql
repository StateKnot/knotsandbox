-- Explicit data destruction is separate from compute DELETE. No implicit TTL
-- garbage collector is added here; NULL retention means no automatic expiry.
ALTER TABLE workspaces ADD COLUMN spec_version bigint NOT NULL DEFAULT 1 CHECK(spec_version>0);
CREATE TABLE workspace_holds (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),tenant_id uuid NOT NULL,project_id uuid NOT NULL,workspace_id uuid NOT NULL,
 kind text NOT NULL CHECK(kind IN('LEGAL','BACKUP','RESTORE')),reference_id uuid NOT NULL,
 source_generation bigint CHECK(source_generation>0),source_pvc_uid uuid,
 reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 256),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,id),UNIQUE(tenant_id,workspace_id,kind,reference_id),
 FOREIGN KEY(tenant_id,project_id,workspace_id) REFERENCES workspaces(tenant_id,project_id,id),
 CHECK(kind='LEGAL' OR (source_generation IS NOT NULL AND source_pvc_uid IS NOT NULL))
);
CREATE TABLE workspace_hold_releases (
 hold_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 256),
 released_at timestamptz NOT NULL DEFAULT clock_timestamp(),FOREIGN KEY(tenant_id,hold_id) REFERENCES workspace_holds(tenant_id,id)
);
CREATE TABLE workspace_delete_intents (
 operation_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,project_id uuid NOT NULL,workspace_id uuid NOT NULL,
 cluster_epoch uuid NOT NULL,confirmed_workspace_id uuid NOT NULL,accepted_version bigint NOT NULL CHECK(accepted_version>0),
 accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,operation_id),UNIQUE(tenant_id,workspace_id),
 FOREIGN KEY(tenant_id,project_id,workspace_id,operation_id) REFERENCES operations(tenant_id,project_id,workspace_id,id),
 CHECK(confirmed_workspace_id=workspace_id)
);
-- Immutable identities originate from the existing launch/PVC/PV ledger plus
-- trusted deployment configuration and an authenticated cloud observation.
CREATE TABLE workspace_delete_bindings (
 operation_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,workspace_id uuid NOT NULL,
 permit_id uuid NOT NULL,pvc_uid uuid NOT NULL,pv_uid uuid NOT NULL,pv_name text NOT NULL,
 csi_volume_handle text NOT NULL,cloud_identity jsonb NOT NULL CHECK(jsonb_typeof(cloud_identity)='object' AND octet_length(cloud_identity::text)<=16384),
 first_present_evidence jsonb NOT NULL CHECK(jsonb_typeof(first_present_evidence)='object' AND octet_length(first_present_evidence::text)<=65536),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,operation_id),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES workspace_delete_intents(tenant_id,operation_id),
 FOREIGN KEY(tenant_id,permit_id) REFERENCES launch_permits(tenant_id,id),
 FOREIGN KEY(tenant_id,workspace_id) REFERENCES workspaces(tenant_id,id)
);
CREATE TABLE workspace_delete_attempts (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,operation_id uuid NOT NULL,lease_token bigint NOT NULL CHECK(lease_token>0),
 preflight_evidence jsonb NOT NULL CHECK(jsonb_typeof(preflight_evidence)='object' AND octet_length(preflight_evidence::text)<=65536),
 dispatched_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,id),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES workspace_delete_bindings(tenant_id,operation_id)
);
CREATE TABLE workspace_delete_results (
 attempt_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,operation_id uuid NOT NULL,
 outcome text NOT NULL CHECK(outcome IN('ACCEPTED','ALREADY_ABSENT','OUTCOME_UNKNOWN','REJECTED')),
 evidence jsonb NOT NULL CHECK(jsonb_typeof(evidence)='object' AND octet_length(evidence::text)<=65536),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,attempt_id) REFERENCES workspace_delete_attempts(tenant_id,id)
);
CREATE TABLE workspace_disk_absences (
 operation_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,attempt_id uuid NOT NULL,
 evidence jsonb NOT NULL CHECK(jsonb_typeof(evidence)='object' AND octet_length(evidence::text)<=65536),
 observed_at timestamptz NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,operation_id),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES workspace_delete_bindings(tenant_id,operation_id),
 FOREIGN KEY(tenant_id,attempt_id) REFERENCES workspace_delete_attempts(tenant_id,id)
);
CREATE TABLE workspace_delete_cleanups (
 operation_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,pvc_uid uuid NOT NULL,pv_uid uuid NOT NULL,
 pvc_absent_at timestamptz NOT NULL,pv_absent_at timestamptz NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES workspace_disk_absences(tenant_id,operation_id)
);
DO $$ DECLARE name text; BEGIN
 FOREACH name IN ARRAY ARRAY['workspace_holds','workspace_hold_releases','workspace_delete_intents','workspace_delete_bindings','workspace_delete_attempts','workspace_delete_results','workspace_disk_absences','workspace_delete_cleanups'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.sandbox_current_tenant_id()) WITH CHECK(tenant_id=public.sandbox_current_tenant_id())',name);
  EXECUTE format('CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.sandbox_prevent_audit_mutation()',name);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',name);
 END LOOP;
END $$;

CREATE FUNCTION sandbox_serialize_workspace_hold() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE workspace uuid;state text;BEGIN
 IF TG_TABLE_NAME='workspace_holds' THEN workspace:=NEW.workspace_id;
 ELSE SELECT h.workspace_id INTO workspace FROM public.workspace_holds h WHERE h.tenant_id=NEW.tenant_id AND h.id=NEW.hold_id;END IF;
 SELECT w.status INTO state FROM public.workspaces w WHERE w.tenant_id=NEW.tenant_id AND w.id=workspace FOR UPDATE;
 IF state IS NULL OR (TG_TABLE_NAME='workspace_holds' AND state IN('DELETING','DELETED')) THEN
  RAISE EXCEPTION 'workspace deletion has already linearized or workspace is missing' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER workspace_hold_serialize BEFORE INSERT ON workspace_holds FOR EACH ROW EXECUTE FUNCTION sandbox_serialize_workspace_hold();
CREATE TRIGGER workspace_hold_release_serialize BEFORE INSERT ON workspace_hold_releases FOR EACH ROW EXECUTE FUNCTION sandbox_serialize_workspace_hold();
REVOKE ALL ON FUNCTION sandbox_serialize_workspace_hold() FROM PUBLIC;

-- Narrow read gate used by API, controller and cleanup admission under FORCE RLS.
CREATE FUNCTION sandbox_workspace_writers_closed(requested_tenant uuid,workspace uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT COALESCE(requested_tenant=public.sandbox_current_tenant_id() AND
  EXISTS(SELECT 1 FROM public.instances i WHERE i.tenant_id=requested_tenant AND i.workspace_id=workspace AND i.observed_state='DELETED')
  AND NOT EXISTS(SELECT 1 FROM public.instances i WHERE i.tenant_id=requested_tenant AND i.workspace_id=workspace AND (i.observed_state<>'DELETED' OR i.slot_held OR i.active_operation_id IS NOT NULL))
  AND NOT EXISTS(SELECT 1 FROM public.instances i WHERE i.tenant_id=requested_tenant AND i.workspace_id=workspace AND (i.cluster_epoch<>(SELECT cluster_epoch FROM public.platform_configuration WHERE singleton) OR NOT EXISTS(SELECT 1 FROM public.local_termination_proofs proof JOIN public.termination_cleanup_receipts c ON c.tenant_id=proof.tenant_id AND c.proof_id=proof.id WHERE proof.tenant_id=i.tenant_id AND proof.id=i.last_termination_proof_id AND proof.instance_id=i.id AND proof.workspace_id=i.workspace_id AND proof.generation=i.runtime_generation AND proof.launch_id=i.launch_id AND proof.pod_uid=i.pod_uid AND proof.cluster_epoch=i.cluster_epoch)))
  AND NOT EXISTS(SELECT 1 FROM public.executions e JOIN public.instances i ON i.tenant_id=e.tenant_id AND i.id=e.instance_id WHERE i.tenant_id=requested_tenant AND i.workspace_id=workspace AND e.slot_held)
  AND NOT EXISTS(SELECT 1 FROM public.launch_permits p WHERE p.tenant_id=requested_tenant AND p.workspace_id=workspace
    AND NOT EXISTS(SELECT 1 FROM public.local_termination_proofs proof JOIN public.termination_cleanup_receipts c ON c.tenant_id=proof.tenant_id AND c.proof_id=proof.id
       WHERE proof.tenant_id=p.tenant_id AND proof.permit_id=p.id AND proof.instance_id=p.instance_id AND proof.workspace_id=p.workspace_id
        AND proof.generation=p.generation AND proof.launch_id=p.launch_id AND proof.pod_uid=p.pod_uid AND proof.cluster_epoch=p.cluster_epoch AND c.old_pod_uid=p.pod_uid))
  AND NOT EXISTS(SELECT 1 FROM public.workspace_holds h WHERE h.tenant_id=requested_tenant AND h.workspace_id=workspace
    AND NOT EXISTS(SELECT 1 FROM public.workspace_hold_releases r WHERE r.tenant_id=h.tenant_id AND r.hold_id=h.id)),false);
$$;
REVOKE ALL ON FUNCTION sandbox_workspace_writers_closed(uuid,uuid) FROM PUBLIC;
ALTER TABLE workspace_delete_intents ADD CONSTRAINT workspace_delete_intent_identity UNIQUE(tenant_id,workspace_id,operation_id);
ALTER TABLE launch_permits ADD CONSTRAINT launch_permit_workspace_identity UNIQUE(tenant_id,workspace_id,id);
ALTER TABLE workspace_delete_bindings ADD CONSTRAINT workspace_delete_binding_intent_scope
 FOREIGN KEY(tenant_id,workspace_id,operation_id) REFERENCES workspace_delete_intents(tenant_id,workspace_id,operation_id),
 ADD CONSTRAINT workspace_delete_binding_permit_scope FOREIGN KEY(tenant_id,workspace_id,permit_id) REFERENCES launch_permits(tenant_id,workspace_id,id),
 ADD CONSTRAINT workspace_delete_binding_cleanup_identity UNIQUE(tenant_id,operation_id,pvc_uid,pv_uid);
ALTER TABLE workspace_delete_attempts ADD CONSTRAINT workspace_delete_attempt_identity UNIQUE(tenant_id,operation_id,id);
ALTER TABLE workspace_delete_results ADD CONSTRAINT workspace_delete_result_attempt_scope FOREIGN KEY(tenant_id,operation_id,attempt_id) REFERENCES workspace_delete_attempts(tenant_id,operation_id,id);
ALTER TABLE workspace_disk_absences ADD CONSTRAINT workspace_disk_absence_attempt_scope
 FOREIGN KEY(tenant_id,operation_id,attempt_id) REFERENCES workspace_delete_attempts(tenant_id,operation_id,id);
ALTER TABLE workspace_delete_cleanups ADD CONSTRAINT workspace_delete_cleanup_binding
 FOREIGN KEY(tenant_id,operation_id,pvc_uid,pv_uid) REFERENCES workspace_delete_bindings(tenant_id,operation_id,pvc_uid,pv_uid);

CREATE FUNCTION sandbox_guard_workspace_deletion() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE intent uuid;BEGIN
 -- A tombstone is permanent even when a lease, client grant or controller expires.
 IF OLD.delete_requested_at IS NOT NULL AND
   (NEW.delete_requested_at IS DISTINCT FROM OLD.delete_requested_at OR NEW.delete_authorization_ref IS DISTINCT FROM OLD.delete_authorization_ref
    OR NEW.retention_until IS DISTINCT FROM OLD.retention_until OR NEW.size_gib<>OLD.size_gib
    OR NEW.status NOT IN('DELETING','DELETED') OR (OLD.status='DELETED' AND NEW.status<>'DELETED')) THEN
   RAISE EXCEPTION 'workspace deletion tombstone is immutable' USING ERRCODE='23514';END IF;
 IF pg_has_role(current_user,(SELECT relowner FROM pg_class WHERE oid=TG_RELID),'MEMBER') THEN RETURN NEW;END IF;
 IF NEW.status='DELETING' AND OLD.status<>'DELETING' THEN
   IF OLD.status<>'AVAILABLE' OR NEW.active_operation_id IS NULL OR NEW.delete_requested_at IS NULL
      OR NEW.delete_authorization_ref IS DISTINCT FROM NEW.active_operation_id::text
      OR NEW.spec_version<>OLD.spec_version+1 OR (NEW.retention_until IS NOT NULL AND NEW.retention_until>clock_timestamp())
      OR NOT public.sandbox_workspace_writers_closed(NEW.tenant_id,NEW.id)
      OR NOT EXISTS(SELECT 1 FROM public.workspace_delete_intents d JOIN public.operations o ON o.tenant_id=d.tenant_id AND o.id=d.operation_id
        JOIN public.platform_configuration cfg ON cfg.singleton AND cfg.cluster_epoch=d.cluster_epoch
        WHERE d.tenant_id=NEW.tenant_id AND d.workspace_id=NEW.id AND d.operation_id=NEW.active_operation_id AND o.kind='DELETE_WORKSPACE' AND o.status='QUEUED') THEN
    RAISE EXCEPTION 'workspace deletion requires explicit authorized intent and closed writers' USING ERRCODE='42501';END IF;
 END IF;
 IF NEW.status='DELETED' AND OLD.status<>'DELETED' THEN
   IF current_user<>'sandbox_volume_deleter' OR OLD.status<>'DELETING' OR NEW.active_operation_id IS NOT NULL OR NEW.deleted_at IS NULL THEN
    RAISE EXCEPTION 'only volume controller may complete workspace destruction' USING ERRCODE='42501';END IF;
   IF NOT EXISTS(SELECT 1 FROM public.workspace_delete_cleanups c JOIN public.workspace_delete_intents d ON d.tenant_id=c.tenant_id AND d.operation_id=c.operation_id
      JOIN public.operations o ON o.tenant_id=d.tenant_id AND o.id=d.operation_id JOIN public.platform_configuration cfg ON cfg.singleton AND cfg.cluster_epoch=d.cluster_epoch
      WHERE d.tenant_id=OLD.tenant_id AND d.workspace_id=OLD.id AND d.operation_id=OLD.active_operation_id
       AND o.status='RUNNING' AND o.lease_until>clock_timestamp()) THEN
    RAISE EXCEPTION 'workspace destruction requires cloud and UID cleanup receipts' USING ERRCODE='42501';END IF;
   IF EXISTS(SELECT 1 FROM public.quota_reservations r JOIN public.quota_accounts q ON q.tenant_id=r.tenant_id AND q.id=r.quota_account_id
     WHERE r.tenant_id=OLD.tenant_id AND r.resource_id=OLD.id AND q.dimension='WORKSPACE_GIB' AND r.status<>'RELEASED') THEN
    RAISE EXCEPTION 'workspace destruction has unreconciled storage reservation' USING ERRCODE='42501';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER workspace_deletion_guard BEFORE UPDATE ON workspaces FOR EACH ROW EXECUTE FUNCTION sandbox_guard_workspace_deletion();
REVOKE ALL ON FUNCTION sandbox_guard_workspace_deletion() FROM PUBLIC;

ALTER TABLE operation_dispatch ADD COLUMN workspace_delete_epoch uuid;
ALTER TABLE operation_dispatch DROP CONSTRAINT operation_dispatch_queue_role_check;
ALTER TABLE operation_dispatch ADD CONSTRAINT operation_dispatch_queue_role_check CHECK(queue_role IN('WORKER','GATEWAY','TERMINATION','VOLUME'));
CREATE OR REPLACE FUNCTION sandbox_update_dispatch() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE target_queue text;
BEGIN
    target_queue:=CASE WHEN NEW.kind='DELETE_WORKSPACE' THEN 'VOLUME' WHEN NEW.kind='EXECUTE' THEN 'GATEWAY'
        WHEN NEW.kind IN('STOP','DELETE') OR (NEW.kind='RESTART' AND NEW.restart_generation IS NULL) THEN 'TERMINATION'
        ELSE 'WORKER' END;
    IF NEW.status IN('QUEUED','RUNNING','WAITING') THEN
        INSERT INTO public.operation_dispatch(operation_id,tenant_id,eligible_at,queue_role,launch_registration_eligible_at,workspace_delete_epoch)
        VALUES(NEW.id,NEW.tenant_id,GREATEST(NEW.next_attempt_at,COALESCE(NEW.lease_until,NEW.next_attempt_at)),target_queue,NEW.launch_registration_next_attempt_at,(SELECT d.cluster_epoch FROM public.workspace_delete_intents d WHERE d.tenant_id=NEW.tenant_id AND d.operation_id=NEW.id))
        ON CONFLICT(operation_id) DO UPDATE SET eligible_at=EXCLUDED.eligible_at,queue_role=EXCLUDED.queue_role,launch_registration_eligible_at=EXCLUDED.launch_registration_eligible_at,workspace_delete_epoch=EXCLUDED.workspace_delete_epoch;
    ELSE DELETE FROM public.operation_dispatch WHERE operation_id=NEW.id;
    END IF;
    RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION sandbox_claim_routed_operation(worker_id text,requested_role text)
RETURNS TABLE(tenant_id uuid,operation_id uuid,lease_token bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;found_id uuid;previous_tenant text:=current_setting('app.tenant_id',true);
BEGIN
    IF worker_id IS NULL OR char_length(worker_id) NOT BETWEEN 1 AND 128 OR requested_role IS NULL OR requested_role NOT IN('WORKER','GATEWAY','TERMINATION','VOLUME') THEN
        RAISE EXCEPTION 'invalid worker identity or queue role' USING ERRCODE='22023';END IF;
    FOR candidate IN SELECT d.operation_id,d.tenant_id FROM public.operation_dispatch d
      WHERE d.queue_role=requested_role AND (requested_role<>'VOLUME' OR d.workspace_delete_epoch=(SELECT cluster_epoch FROM public.platform_configuration WHERE singleton)) AND d.eligible_at<=clock_timestamp() ORDER BY d.eligible_at,d.operation_id LIMIT 64 LOOP
        PERFORM set_config('app.tenant_id',candidate.tenant_id::text,true);
        SELECT o.id INTO found_id FROM public.operations o
        WHERE o.tenant_id=candidate.tenant_id AND o.id=candidate.operation_id
          AND CASE requested_role WHEN 'VOLUME' THEN o.kind='DELETE_WORKSPACE' WHEN 'GATEWAY' THEN o.kind='EXECUTE'
              WHEN 'TERMINATION' THEN o.kind IN('STOP','DELETE') OR (o.kind='RESTART' AND o.restart_generation IS NULL)
              ELSE o.kind NOT IN('EXECUTE','STOP','DELETE','DELETE_WORKSPACE') AND (o.kind<>'RESTART' OR o.restart_generation IS NOT NULL) END
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
CREATE FUNCTION sandbox_claim_volume_deletion(worker_id text)
RETURNS TABLE(tenant_id uuid,operation_id uuid,lease_token bigint)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT * FROM public.sandbox_claim_routed_operation(worker_id,'VOLUME');
$$;
REVOKE ALL ON FUNCTION sandbox_claim_volume_deletion(text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION sandbox_mutate_project_grant(actor uuid,project uuid,mutation text,grant_id uuid,target_principal uuid,delegated_action text,requested_expiry timestamptz,will_enable boolean,expected_version bigint)
RETURNS public.grants LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=public.sandbox_current_tenant_id();result public.grants;
BEGIN
    PERFORM public.sandbox_lock_identity_tenant(tenant);
    IF delegated_action IS NULL OR delegated_action NOT IN('instances:create','instances:read','instances:start','instances:stop','instances:restart','instances:renew','instances:delete','instances:hard_stop','workspaces:read','workspaces:delete','operations:read','events:read','audit:read','capabilities:read','executions:create','executions:read','executions:cancel','executions:output:read','grants:read','grants:write') THEN
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
CREATE FUNCTION sandbox_workspace_cleanup_authorized(requested_tenant uuid,project uuid,namespace text,pvc_name text,pvc_uid uuid,pv_name text,pv_uid uuid,handle text,require_lease boolean) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT COALESCE($1=public.sandbox_current_tenant_id() AND $9 IS NOT NULL AND EXISTS(
   SELECT 1 FROM public.workspace_delete_bindings b JOIN public.workspace_disk_absences a ON a.tenant_id=b.tenant_id AND a.operation_id=b.operation_id
   JOIN public.workspace_delete_intents d ON d.tenant_id=b.tenant_id AND d.operation_id=b.operation_id
   JOIN public.workspaces w ON w.tenant_id=b.tenant_id AND w.id=b.workspace_id
   JOIN public.operations o ON o.tenant_id=d.tenant_id AND o.id=d.operation_id
   JOIN public.platform_configuration cfg ON cfg.singleton AND cfg.cluster_epoch=d.cluster_epoch
   WHERE w.tenant_id=$1 AND w.project_id=$2 AND w.namespace=$3 AND w.pvc_name=$4 AND b.pvc_uid=$5 AND b.pv_name=$6
     AND ($7 IS NULL OR b.pv_uid=$7) AND ($8 IS NULL OR b.csi_volume_handle=$8)
     AND w.status='DELETING' AND w.active_operation_id=d.operation_id AND o.kind='DELETE_WORKSPACE' AND o.status IN('QUEUED','RUNNING','WAITING')
     AND (NOT $9 OR (o.status='RUNNING' AND o.lease_owner IS NOT NULL AND o.lease_until>clock_timestamp()))
     AND public.sandbox_workspace_writers_closed(w.tenant_id,w.id)),false);
$$;
REVOKE ALL ON FUNCTION sandbox_workspace_cleanup_authorized(uuid,uuid,text,text,uuid,text,uuid,text,boolean) FROM PUBLIC;
