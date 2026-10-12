-- Read-only diagnostic tasks share the ordinary durable worker queue, never
-- the instance's lifecycle/activity slot or its compute/storage reservations.
ALTER TABLE operations DROP CONSTRAINT operations_kind_check;
ALTER TABLE operations ADD CONSTRAINT operations_kind_check CHECK(kind IN('CREATE','START','STOP','RESTART','DELETE','RENEW','EXECUTE','DELETE_WORKSPACE','BACKUP','DIAGNOSE'));

CREATE TABLE diagnoses (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,project_id uuid NOT NULL,
 instance_id uuid NOT NULL,workspace_id uuid NOT NULL,operation_id uuid NOT NULL,
 actor_principal_id uuid NOT NULL REFERENCES principals(id),
 requested_generation bigint NOT NULL CHECK(requested_generation>0),requested_launch_id uuid NOT NULL,cluster_epoch uuid NOT NULL,
 ruleset_version text NOT NULL CHECK(ruleset_version='control-plane/v1'),
 include_operations boolean NOT NULL,include_executions boolean NOT NULL,
 status text NOT NULL DEFAULT 'PENDING' CHECK(status IN('PENDING','COMPLETE','FAILED','EXPIRED')),
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 created_at timestamptz NOT NULL,deadline timestamptz NOT NULL,retention_until timestamptz NOT NULL,
 snapshot_at timestamptz,completed_at timestamptz,report jsonb,
 failure_code text CHECK(failure_code IN('AUTHORITY_REVOKED','TARGET_CHANGED','DEADLINE_EXCEEDED','OBSERVATION_FAILED')),
 CHECK(deadline=created_at+interval '120 seconds' AND retention_until=created_at+interval '30 days'),
 CHECK(report IS NULL OR(jsonb_typeof(report)='object' AND octet_length(report::text)<=131072)),
 CHECK((status='PENDING' AND completed_at IS NULL AND report IS NULL AND snapshot_at IS NULL AND failure_code IS NULL)
    OR(status='COMPLETE' AND completed_at IS NOT NULL AND snapshot_at IS NOT NULL AND report IS NOT NULL AND failure_code IS NULL)
    OR(status='FAILED' AND completed_at IS NOT NULL AND report IS NULL AND snapshot_at IS NULL AND failure_code IS NOT NULL)
    OR(status='EXPIRED' AND completed_at IS NOT NULL AND report IS NULL)),
 CHECK(snapshot_at IS NULL OR(created_at<=snapshot_at AND snapshot_at<=completed_at)),
 UNIQUE(tenant_id,id),UNIQUE(tenant_id,operation_id),
 FOREIGN KEY(tenant_id,project_id,instance_id,workspace_id) REFERENCES instances(tenant_id,project_id,id,workspace_id),
 FOREIGN KEY(tenant_id,project_id,instance_id,operation_id) REFERENCES operations(tenant_id,project_id,instance_id,id)
);
CREATE UNIQUE INDEX diagnoses_one_pending ON diagnoses(tenant_id,instance_id) WHERE status='PENDING';
CREATE INDEX diagnoses_tenant_window ON diagnoses(tenant_id,created_at DESC);
ALTER TABLE diagnoses ENABLE ROW LEVEL SECURITY;
ALTER TABLE diagnoses FORCE ROW LEVEL SECURITY;
CREATE POLICY diagnoses_tenant ON diagnoses USING(tenant_id=sandbox_current_tenant_id()) WITH CHECK(tenant_id=sandbox_current_tenant_id());

-- Payload-free maintenance discovery, avoiding a FORCE-RLS bypass or a scan of
-- unrelated tenant data. Only the definer trigger/functions can read this index.
CREATE TABLE diagnosis_maintenance (
 diagnosis_id uuid PRIMARY KEY REFERENCES diagnoses(id),tenant_id uuid NOT NULL,due_at timestamptz NOT NULL,available_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX diagnosis_maintenance_due ON diagnosis_maintenance(available_at,due_at,diagnosis_id);
REVOKE ALL ON diagnoses,diagnosis_maintenance FROM PUBLIC;
CREATE FUNCTION sandbox_diagnosis_maintenance_sync() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.status='EXPIRED' THEN DELETE FROM public.diagnosis_maintenance WHERE diagnosis_id=NEW.id;
 ELSE INSERT INTO public.diagnosis_maintenance(diagnosis_id,tenant_id,due_at)
 VALUES(NEW.id,NEW.tenant_id,CASE WHEN NEW.status='PENDING' THEN NEW.deadline ELSE NEW.retention_until END)
 ON CONFLICT(diagnosis_id) DO UPDATE SET due_at=EXCLUDED.due_at,available_at=clock_timestamp();END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER diagnosis_maintenance_sync AFTER INSERT OR UPDATE ON diagnoses FOR EACH ROW EXECUTE FUNCTION sandbox_diagnosis_maintenance_sync();

CREATE FUNCTION sandbox_diagnosis_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'diagnosis identity is retained' USING ERRCODE='23514';END IF;
 IF (NEW.id,NEW.tenant_id,NEW.project_id,NEW.instance_id,NEW.workspace_id,NEW.operation_id,NEW.actor_principal_id,NEW.requested_generation,NEW.requested_launch_id,NEW.cluster_epoch,NEW.ruleset_version,NEW.include_operations,NEW.include_executions,NEW.created_at,NEW.deadline,NEW.retention_until)
 IS DISTINCT FROM (OLD.id,OLD.tenant_id,OLD.project_id,OLD.instance_id,OLD.workspace_id,OLD.operation_id,OLD.actor_principal_id,OLD.requested_generation,OLD.requested_launch_id,OLD.cluster_epoch,OLD.ruleset_version,OLD.include_operations,OLD.include_executions,OLD.created_at,OLD.deadline,OLD.retention_until) THEN
 RAISE EXCEPTION 'diagnosis identity is immutable' USING ERRCODE='23514';END IF;
 IF OLD.status<>'PENDING' AND (NEW.status<>'EXPIRED' OR clock_timestamp()<OLD.retention_until OR NEW.report IS NOT NULL
      OR NEW.completed_at IS DISTINCT FROM OLD.completed_at OR NEW.snapshot_at IS DISTINCT FROM OLD.snapshot_at
      OR NEW.failure_code IS DISTINCT FROM OLD.failure_code) THEN
 RAISE EXCEPTION 'completed diagnosis is immutable until payload retention expiry' USING ERRCODE='23514';END IF;
 IF OLD.status='EXPIRED' THEN RAISE EXCEPTION 'expired diagnosis cannot be revived' USING ERRCODE='23514';END IF;
 NEW.version:=OLD.version+1;RETURN NEW;
END $$;
CREATE TRIGGER diagnosis_immutable BEFORE UPDATE OR DELETE ON diagnoses FOR EACH ROW EXECUTE FUNCTION sandbox_diagnosis_immutable();

CREATE FUNCTION sandbox_diagnosis_operation_match() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE d public.diagnoses%ROWTYPE;o public.operations%ROWTYPE;previous_tenant text:=current_setting('app.tenant_id',true);
BEGIN
 IF TG_TABLE_NAME='operations' THEN
   IF NEW.kind<>'DIAGNOSE' THEN RETURN NEW;END IF;
   PERFORM set_config('app.tenant_id',NEW.tenant_id::text,true);
   SELECT * INTO d FROM public.diagnoses WHERE tenant_id=NEW.tenant_id AND operation_id=NEW.id;
 ELSE PERFORM set_config('app.tenant_id',NEW.tenant_id::text,true);SELECT * INTO d FROM public.diagnoses WHERE tenant_id=NEW.tenant_id AND id=NEW.id;END IF;
 IF d.id IS NULL THEN RAISE EXCEPTION 'diagnosis operation lacks report identity' USING ERRCODE='23514';END IF;
 SELECT * INTO o FROM public.operations WHERE tenant_id=d.tenant_id AND id=d.operation_id;
 IF o.id IS NULL OR o.kind<>'DIAGNOSE' OR o.actor_principal_id<>d.actor_principal_id OR o.workspace_id<>d.workspace_id OR o.deadline<>d.deadline
  OR(d.status='PENDING' AND o.status NOT IN('QUEUED','RUNNING','WAITING'))
  OR(d.status='COMPLETE' AND o.status<>'SUCCEEDED') OR(d.status='FAILED' AND o.status<>'FAILED')
  OR(d.status='EXPIRED' AND o.status NOT IN('SUCCEEDED','FAILED')) THEN
 RAISE EXCEPTION 'diagnosis and operation must commit together' USING ERRCODE='23514';END IF;
 PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER diagnosis_operation_match AFTER INSERT OR UPDATE ON diagnoses DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sandbox_diagnosis_operation_match();
CREATE CONSTRAINT TRIGGER operation_diagnosis_match AFTER INSERT OR UPDATE ON operations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sandbox_diagnosis_operation_match();

-- Internal exact-target expiry follows the same operation -> diagnosis lock order
-- as publication. SKIP LOCKED never waits behind a still running publisher.
CREATE FUNCTION sandbox_expire_diagnosis(requested_tenant uuid,diagnosis uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE d public.diagnoses%ROWTYPE;op uuid;request uuid;
BEGIN
 IF requested_tenant IS DISTINCT FROM public.sandbox_current_tenant_id() THEN RAISE EXCEPTION 'invalid diagnosis expiry scope' USING ERRCODE='22023';END IF;
 SELECT operation_id INTO op FROM public.diagnoses WHERE tenant_id=requested_tenant AND id=diagnosis;
 IF op IS NULL THEN RETURN false;END IF;
 SELECT request_id INTO request FROM public.operations WHERE tenant_id=requested_tenant AND id=op FOR UPDATE SKIP LOCKED;
 IF NOT FOUND THEN RETURN false;END IF;
 SELECT * INTO d FROM public.diagnoses WHERE tenant_id=requested_tenant AND id=diagnosis FOR UPDATE;
 IF d.status='PENDING' AND d.deadline<=clock_timestamp() THEN
  UPDATE public.diagnoses SET status='FAILED',failure_code='DEADLINE_EXCEEDED',completed_at=clock_timestamp() WHERE tenant_id=requested_tenant AND id=d.id;
  UPDATE public.operations SET status='FAILED',stage='DIAGNOSIS_EXPIRED',error='{"code":"OPERATION_FAILED","retryable":false}'::jsonb,
   wait_reason=NULL,lease_owner=NULL,lease_until=NULL,lease_token=lease_token+1,completed_at=clock_timestamp(),updated_at=clock_timestamp()
   WHERE tenant_id=requested_tenant AND id=d.operation_id;
  INSERT INTO public.audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details)
  VALUES(d.tenant_id,d.project_id,d.actor_principal_id,request,d.operation_id,d.id,'diagnoses:complete','FAILED','{"reason":"DEADLINE_EXCEEDED"}'::jsonb);
  INSERT INTO public.domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload)
  VALUES(d.tenant_id,d.project_id,d.id,d.version+1,'diagnoses.failed',d.operation_id,request,'{"failure_code":"DEADLINE_EXCEEDED"}'::jsonb);
  RETURN true;
 ELSIF d.status IN('COMPLETE','FAILED') AND d.retention_until<=clock_timestamp() THEN
  UPDATE public.diagnoses SET status='EXPIRED',report=NULL WHERE tenant_id=requested_tenant AND id=d.id;
  RETURN true;
 END IF;
 RETURN false;
END $$;
-- Safe for the API to expire its own overdue tasks before quota admission; the
-- selected tenant cannot be changed and no deadline can be shortened.
CREATE FUNCTION sandbox_expire_tenant_diagnoses(requested_tenant uuid,batch integer) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;changed integer:=0;
BEGIN
 IF requested_tenant IS NULL OR requested_tenant IS DISTINCT FROM public.sandbox_current_tenant_id() OR batch NOT BETWEEN 1 AND 128 THEN
 RAISE EXCEPTION 'invalid diagnosis expiry scope' USING ERRCODE='22023';END IF;
 FOR candidate IN SELECT id FROM public.diagnoses
 WHERE tenant_id=requested_tenant AND status='PENDING' AND deadline<=clock_timestamp() ORDER BY deadline,id LIMIT batch LOOP
  IF public.sandbox_expire_diagnosis(requested_tenant,candidate.id) THEN changed:=changed+1;END IF;
 END LOOP;
 RETURN changed;
END $$;
CREATE FUNCTION sandbox_maintain_diagnoses(batch integer) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;changed integer:=0;previous_tenant text:=current_setting('app.tenant_id',true);
BEGIN
 IF batch NOT BETWEEN 1 AND 128 THEN RAISE EXCEPTION 'invalid diagnosis maintenance batch' USING ERRCODE='22023';END IF;
 FOR candidate IN SELECT tenant_id,diagnosis_id FROM public.diagnosis_maintenance WHERE due_at<=clock_timestamp() AND available_at<=clock_timestamp() ORDER BY available_at,due_at,diagnosis_id LIMIT batch LOOP
  PERFORM set_config('app.tenant_id',candidate.tenant_id::text,true);
  IF public.sandbox_expire_diagnosis(candidate.tenant_id,candidate.diagnosis_id) THEN changed:=changed+1;
  ELSE
   -- Rotate contended targets out of the next bounded batch. A delayed task
   -- must not permanently hide unrelated tenants' overdue tasks.
   UPDATE public.diagnosis_maintenance SET available_at=clock_timestamp()+interval '5 seconds' WHERE diagnosis_id=candidate.diagnosis_id;
  END IF;
 END LOOP;
 PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);RETURN changed;
END $$;
CREATE INDEX diagnoses_pending_expiry ON diagnoses(tenant_id,deadline,id) WHERE status='PENDING';
REVOKE ALL ON FUNCTION sandbox_diagnosis_maintenance_sync(),sandbox_diagnosis_immutable(),sandbox_diagnosis_operation_match(),sandbox_expire_diagnosis(uuid,uuid),sandbox_expire_tenant_diagnoses(uuid,integer),sandbox_maintain_diagnoses(integer) FROM PUBLIC;
