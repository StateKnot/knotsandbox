-- Cold backups are independent object copies, never a cloud snapshot success flag.
-- Profiles are operator-owned trust inputs. Runtime identities cannot approve them.
CREATE TABLE backup_profiles (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),cluster_epoch uuid NOT NULL,enabled boolean NOT NULL DEFAULT false,
 certification_sha256 text NOT NULL CHECK(certification_sha256~'^[0-9a-f]{64}$'),
 certified_until timestamptz NOT NULL,image text NOT NULL CHECK(image~'^[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}$'),
 snapshot_class text NOT NULL,clone_storage_class text NOT NULL,
 password_secret text NOT NULL,signing_private_secret text NOT NULL,signing_public_secret text NOT NULL,
 settings jsonb NOT NULL CHECK(jsonb_typeof(settings)='object' AND octet_length(settings::text)<=65536),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),CHECK(certified_until>created_at),
 CHECK(password_secret<>signing_private_secret AND password_secret<>signing_public_secret AND signing_private_secret<>signing_public_secret)
);
CREATE FUNCTION sandbox_preserve_backup_profile() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN IF (to_jsonb(NEW)-'enabled') IS DISTINCT FROM(to_jsonb(OLD)-'enabled') THEN
 RAISE EXCEPTION 'backup profile is immutable; register a new reviewed version' USING ERRCODE='23514';END IF;RETURN NEW;END $$;
CREATE TRIGGER backup_profile_immutable BEFORE UPDATE ON backup_profiles FOR EACH ROW EXECUTE FUNCTION sandbox_preserve_backup_profile();
CREATE TRIGGER backup_profile_no_delete BEFORE DELETE ON backup_profiles FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_audit_mutation();
REVOKE ALL ON backup_profiles FROM PUBLIC;
REVOKE ALL ON FUNCTION sandbox_preserve_backup_profile() FROM PUBLIC;

ALTER TABLE operations DROP CONSTRAINT operations_kind_check;
ALTER TABLE operations ADD CONSTRAINT operations_kind_check CHECK(kind IN('CREATE','START','STOP','RESTART','DELETE','RENEW','EXECUTE','DELETE_WORKSPACE','BACKUP'));
ALTER TABLE quota_accounts DROP CONSTRAINT quota_accounts_dimension_check;
ALTER TABLE quota_accounts ADD CONSTRAINT quota_accounts_dimension_check CHECK(dimension IN('INSTANCES','CPU_MILLIS','MEMORY_MIB','WORKSPACE_GIB','EXECUTIONS','BACKUP_GIB','BACKUP_TEMP_GIB'));
CREATE TABLE backups (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,project_id uuid NOT NULL,workspace_id uuid NOT NULL,instance_id uuid NOT NULL,
 operation_id uuid NOT NULL UNIQUE,profile_id uuid NOT NULL REFERENCES backup_profiles(id),hold_id uuid NOT NULL,
 source_permit_id uuid NOT NULL,source_generation bigint NOT NULL CHECK(source_generation>0),
 cluster_epoch uuid NOT NULL,source jsonb NOT NULL CHECK(jsonb_typeof(source)='object' AND octet_length(source::text)<=16384),
 capture_attempt_id uuid NOT NULL UNIQUE,seal_attempt_id uuid NOT NULL UNIQUE,
 size_gib bigint NOT NULL CHECK(size_gib BETWEEN 1 AND 16384),
 status text NOT NULL DEFAULT 'QUEUED' CHECK(status IN('QUEUED','SNAPSHOT_PENDING','SNAPSHOT_READY','CLONE_PENDING','CAPTURE_PENDING','CAPTURE_RUNNING','CAPTURE_CLOSING','SEAL_PENDING','SEAL_RUNNING','SEAL_CLOSING','AVAILABLE','CANCELLED')),
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),consistency text NOT NULL DEFAULT 'STOPPED_CONSISTENT' CHECK(consistency='STOPPED_CONSISTENT'),
 retention_until timestamptz NOT NULL,deadline timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,project_id,workspace_id) REFERENCES workspaces(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,instance_id) REFERENCES instances(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,workspace_id,operation_id) REFERENCES operations(tenant_id,project_id,workspace_id,id),
 FOREIGN KEY(tenant_id,hold_id) REFERENCES workspace_holds(tenant_id,id),
 FOREIGN KEY(tenant_id,workspace_id,source_permit_id) REFERENCES launch_permits(tenant_id,workspace_id,id),
 UNIQUE(tenant_id,id),UNIQUE(tenant_id,project_id,id),UNIQUE(tenant_id,id,workspace_id),
 CHECK(deadline>created_at AND deadline<=created_at+interval '6 hours'),CHECK(retention_until>=deadline+interval '30 days 5 minutes'),
 CHECK(capture_attempt_id<>seal_attempt_id)
);
CREATE INDEX backups_project_list ON backups(tenant_id,project_id,created_at DESC,id DESC);
CREATE TABLE backup_attempts (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,backup_id uuid NOT NULL,stage text NOT NULL CHECK(stage IN('CAPTURE','SEAL')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,id),UNIQUE(tenant_id,backup_id,stage),UNIQUE(tenant_id,backup_id,id),
 FOREIGN KEY(tenant_id,backup_id) REFERENCES backups(tenant_id,id)
);
-- Intents precede remote mutation. Their UIDs can only be assigned once.
CREATE TABLE backup_resource_intents (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,backup_id uuid NOT NULL,attempt_id uuid,
 kind text NOT NULL CHECK(kind IN('SOURCE_SNAPSHOT','SOURCE_CONTENT','CLONE_CONTENT','CLONE_SNAPSHOT','CLONE_PVC','CLONE_PV','CONFIG','JOB','POD','CAPTURE_REPORT')),
 namespace text NOT NULL,name text NOT NULL,expected_object jsonb,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,id),UNIQUE(tenant_id,backup_id,id),
 FOREIGN KEY(tenant_id,backup_id) REFERENCES backups(tenant_id,id),
 FOREIGN KEY(tenant_id,backup_id,attempt_id) REFERENCES backup_attempts(tenant_id,backup_id,id),
 CHECK(expected_object IS NULL OR(jsonb_typeof(expected_object)='object' AND octet_length(expected_object::text)<=131072)),
 UNIQUE(tenant_id,backup_id,kind,namespace,name)
);
CREATE TABLE backup_resource_bindings (
 intent_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,backup_id uuid NOT NULL,uid uuid NOT NULL,
 observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,intent_id),UNIQUE(uid),
 FOREIGN KEY(tenant_id,backup_id,intent_id) REFERENCES backup_resource_intents(tenant_id,backup_id,id)
);
CREATE TABLE backup_snapshot_receipts (
 backup_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,snapshot_uid uuid NOT NULL,content_uid uuid NOT NULL,content_name text NOT NULL,
 cloud_snapshot text NOT NULL CHECK(cloud_snapshot~'^s-[a-zA-Z0-9]+$'),data_timestamp timestamptz NOT NULL,size_bytes bigint NOT NULL CHECK(size_bytes>0 AND size_bytes%512=0),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,backup_id),FOREIGN KEY(tenant_id,backup_id) REFERENCES backups(tenant_id,id)
);
CREATE TABLE backup_clone_receipts (
 attempt_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,backup_id uuid NOT NULL,
 pvc_uid uuid NOT NULL,pv_uid uuid NOT NULL,pv_name text NOT NULL,cloud_disk text NOT NULL CHECK(cloud_disk~'^d-[a-zA-Z0-9]+$'),size_bytes bigint NOT NULL CHECK(size_bytes>0 AND size_bytes%512=0),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,attempt_id),
 FOREIGN KEY(tenant_id,backup_id,attempt_id) REFERENCES backup_attempts(tenant_id,backup_id,id)
);
CREATE TABLE backup_job_contexts (
 attempt_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,backup_id uuid NOT NULL,context jsonb NOT NULL CHECK(jsonb_typeof(context)='object' AND octet_length(context::text)<=131072),
 deadline timestamptz NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,attempt_id),
 FOREIGN KEY(tenant_id,backup_id,attempt_id) REFERENCES backup_attempts(tenant_id,backup_id,id),CHECK(deadline>recorded_at AND deadline<=recorded_at+interval '2 hours')
);
-- One apiserver review wins permanently. It cannot authorize a replacement Pod.
CREATE TABLE backup_pod_admissions (
 attempt_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,backup_id uuid NOT NULL,review_uid uuid NOT NULL UNIQUE,job_uid uuid NOT NULL,
 admitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,attempt_id),
 FOREIGN KEY(tenant_id,backup_id,attempt_id) REFERENCES backup_attempts(tenant_id,backup_id,id)
);
CREATE TABLE backup_launch_permits (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,backup_id uuid NOT NULL,attempt_id uuid NOT NULL UNIQUE,
 runtime_node_id uuid NOT NULL REFERENCES runtime_nodes(id),launch jsonb NOT NULL CHECK(jsonb_typeof(launch)='object' AND octet_length(launch::text)<=16384),
 pod_uid uuid NOT NULL UNIQUE,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL,
 UNIQUE(tenant_id,id),UNIQUE(tenant_id,backup_id,id),FOREIGN KEY(tenant_id,backup_id,attempt_id) REFERENCES backup_attempts(tenant_id,backup_id,id),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '2 hours')
);
CREATE TABLE backup_launch_receipts (
 permit_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,journal_revision bigint NOT NULL CHECK(journal_revision>0),registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,permit_id) REFERENCES backup_launch_permits(tenant_id,id)
);
CREATE TABLE backup_close_challenges (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,backup_id uuid NOT NULL,permit_id uuid NOT NULL,lease_token bigint NOT NULL CHECK(lease_token>0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL,
 UNIQUE(tenant_id,id),FOREIGN KEY(tenant_id,backup_id,permit_id) REFERENCES backup_launch_permits(tenant_id,backup_id,id),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '30 seconds')
);
CREATE TABLE backup_termination_proofs (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,backup_id uuid NOT NULL,attempt_id uuid NOT NULL UNIQUE,permit_id uuid NOT NULL,
 challenge_id uuid NOT NULL UNIQUE,runtime_node_id uuid NOT NULL REFERENCES runtime_nodes(id),journal_revision bigint NOT NULL CHECK(journal_revision>0),
 evidence jsonb NOT NULL CHECK(jsonb_typeof(evidence)='object' AND octet_length(evidence::text)<=65536),evidence_sha256 text NOT NULL CHECK(evidence_sha256~'^[0-9a-f]{64}$'),
 observed_at timestamptz NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,id),UNIQUE(tenant_id,backup_id,id),
 FOREIGN KEY(tenant_id,backup_id,attempt_id) REFERENCES backup_attempts(tenant_id,backup_id,id),
 FOREIGN KEY(tenant_id,backup_id,permit_id) REFERENCES backup_launch_permits(tenant_id,backup_id,id),
 FOREIGN KEY(tenant_id,challenge_id) REFERENCES backup_close_challenges(tenant_id,id)
);
CREATE TABLE backup_cleanup_receipts (
 proof_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,backup_id uuid NOT NULL,pod_uid uuid NOT NULL,job_uid uuid NOT NULL,
 pod_absent_at timestamptz NOT NULL,volume_checked_at timestamptz NOT NULL,completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,backup_id,proof_id) REFERENCES backup_termination_proofs(tenant_id,backup_id,id)
);
CREATE TABLE backup_capture_reports (
 backup_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,attempt_id uuid NOT NULL,report jsonb NOT NULL CHECK(jsonb_typeof(report)='object' AND octet_length(report::text)<=4096),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),FOREIGN KEY(tenant_id,backup_id,attempt_id) REFERENCES backup_attempts(tenant_id,backup_id,id)
);
CREATE TABLE backup_vault_receipts (
 backup_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,manifest_sha256 text NOT NULL CHECK(manifest_sha256~'^[0-9a-f]{64}$'),
 manifest jsonb NOT NULL CHECK(jsonb_typeof(manifest)='object' AND octet_length(manifest::text)<=65536),verified_at timestamptz NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),FOREIGN KEY(tenant_id,backup_id) REFERENCES backups(tenant_id,id)
);
DO $$ DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['backups','backup_attempts','backup_resource_intents','backup_resource_bindings','backup_snapshot_receipts','backup_clone_receipts','backup_job_contexts','backup_pod_admissions','backup_launch_permits','backup_launch_receipts','backup_close_challenges','backup_termination_proofs','backup_cleanup_receipts','backup_capture_reports','backup_vault_receipts'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
  EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.sandbox_current_tenant_id()) WITH CHECK(tenant_id=public.sandbox_current_tenant_id())',tab);
  IF tab<>'backups' THEN EXECUTE format('CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.sandbox_prevent_audit_mutation()',tab);END IF;
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',tab);
 END LOOP;
END $$;
CREATE TRIGGER backup_no_delete BEFORE DELETE ON backups FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_audit_mutation();

CREATE FUNCTION sandbox_workspace_cold_backup_ready(requested_tenant uuid,workspace uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT COALESCE(requested_tenant=public.sandbox_current_tenant_id() AND
  EXISTS(SELECT 1 FROM public.instances i WHERE i.tenant_id=requested_tenant AND i.workspace_id=workspace AND i.observed_state='STOPPED')
  AND NOT EXISTS(SELECT 1 FROM public.instances i WHERE i.tenant_id=requested_tenant AND i.workspace_id=workspace AND (i.observed_state<>'STOPPED' OR i.desired_state<>'STOPPED' OR i.slot_held OR i.active_operation_id IS NOT NULL))
  AND NOT EXISTS(SELECT 1 FROM public.instances i WHERE i.tenant_id=requested_tenant AND i.workspace_id=workspace AND (i.cluster_epoch<>(SELECT cluster_epoch FROM public.platform_configuration WHERE singleton) OR NOT EXISTS(SELECT 1 FROM public.local_termination_proofs proof JOIN public.termination_cleanup_receipts c ON c.tenant_id=proof.tenant_id AND c.proof_id=proof.id WHERE proof.tenant_id=i.tenant_id AND proof.id=i.last_termination_proof_id AND proof.instance_id=i.id AND proof.workspace_id=i.workspace_id AND proof.generation=i.runtime_generation AND proof.launch_id=i.launch_id AND proof.pod_uid=i.pod_uid AND proof.cluster_epoch=i.cluster_epoch)))
  AND NOT EXISTS(SELECT 1 FROM public.executions e JOIN public.instances i ON i.tenant_id=e.tenant_id AND i.id=e.instance_id WHERE i.tenant_id=requested_tenant AND i.workspace_id=workspace AND e.slot_held)
  AND NOT EXISTS(SELECT 1 FROM public.launch_permits p WHERE p.tenant_id=requested_tenant AND p.workspace_id=workspace
    AND NOT EXISTS(SELECT 1 FROM public.local_termination_proofs proof JOIN public.termination_cleanup_receipts c ON c.tenant_id=proof.tenant_id AND c.proof_id=proof.id
       WHERE proof.tenant_id=p.tenant_id AND proof.permit_id=p.id AND proof.instance_id=p.instance_id AND proof.workspace_id=p.workspace_id
        AND proof.generation=p.generation AND proof.launch_id=p.launch_id AND proof.pod_uid=p.pod_uid AND proof.cluster_epoch=p.cluster_epoch AND c.old_pod_uid=p.pod_uid))
,false);
$$;
REVOKE ALL ON FUNCTION sandbox_workspace_cold_backup_ready(uuid,uuid) FROM PUBLIC;
CREATE FUNCTION sandbox_guard_cold_backup() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE w public.workspaces;p public.launch_permits;BEGIN
 SELECT * INTO w FROM public.workspaces WHERE tenant_id=NEW.tenant_id AND id=NEW.workspace_id FOR UPDATE;
 IF TG_OP='INSERT' THEN
  SELECT * INTO p FROM public.launch_permits WHERE tenant_id=NEW.tenant_id AND id=NEW.source_permit_id;
  IF w.status<>'AVAILABLE' OR w.active_operation_id IS NOT NULL OR w.delete_requested_at IS NOT NULL
    OR NOT public.sandbox_workspace_cold_backup_ready(NEW.tenant_id,NEW.workspace_id)
    OR EXISTS(SELECT 1 FROM public.workspace_holds h WHERE h.tenant_id=NEW.tenant_id AND h.workspace_id=NEW.workspace_id AND h.kind IN('BACKUP','RESTORE') AND h.id<>NEW.hold_id AND NOT EXISTS(SELECT 1 FROM public.workspace_hold_releases r WHERE r.tenant_id=h.tenant_id AND r.hold_id=h.id))
    OR p.instance_id IS DISTINCT FROM NEW.instance_id OR p.generation IS DISTINCT FROM NEW.source_generation OR p.cluster_epoch IS DISTINCT FROM NEW.cluster_epoch
    OR NEW.source->>'tenant_id' IS DISTINCT FROM NEW.tenant_id::text OR NEW.source->>'project_id' IS DISTINCT FROM NEW.project_id::text OR NEW.source->>'backup_id' IS DISTINCT FROM NEW.id::text OR NEW.source->>'workspace_id' IS DISTINCT FROM NEW.workspace_id::text OR NEW.source->>'cluster_epoch' IS DISTINCT FROM NEW.cluster_epoch::text
    OR NEW.source->>'pvc_uid' IS DISTINCT FROM p.pvc_uid::text OR NEW.source->>'pv_uid' IS DISTINCT FROM p.pv_uid::text
    OR NEW.source->>'cloud_disk' IS DISTINCT FROM p.csi_volume_handle OR NEW.source->>'pv_name' IS DISTINCT FROM p.pv_name
    OR NEW.source->>'namespace' IS DISTINCT FROM p.namespace OR NEW.source->>'pvc_name' IS DISTINCT FROM w.pvc_name
    OR NEW.size_gib<>w.size_gib OR (NEW.source->>'size_bytes')::bigint<>w.size_gib*1073741824
    OR NOT EXISTS(SELECT 1 FROM public.instances i WHERE i.tenant_id=NEW.tenant_id AND i.id=NEW.instance_id AND i.runtime_generation=p.generation AND i.launch_id=p.launch_id AND i.pod_uid=p.pod_uid)
    OR NOT EXISTS(SELECT 1 FROM public.workspace_holds h WHERE h.tenant_id=NEW.tenant_id AND h.id=NEW.hold_id AND h.workspace_id=NEW.workspace_id AND h.kind='BACKUP' AND h.reference_id=NEW.id AND h.source_generation=NEW.source_generation AND h.source_pvc_uid=p.pvc_uid)
    OR NOT EXISTS(SELECT 1 FROM public.backup_profiles bp JOIN public.platform_configuration cfg ON cfg.singleton AND cfg.cluster_epoch=bp.cluster_epoch
         WHERE bp.id=NEW.profile_id AND bp.enabled AND bp.cluster_epoch=NEW.cluster_epoch AND bp.certified_until>=NEW.deadline AND NOT cfg.safe_mode) THEN
   RAISE EXCEPTION 'cold backup requires exact closed source and current reviewed profile' USING ERRCODE='23514';END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['status','version','updated_at']) IS DISTINCT FROM(to_jsonb(OLD)-ARRAY['status','version','updated_at'])
    OR NEW.version<>OLD.version+1 OR OLD.status IN('AVAILABLE','CANCELLED') THEN
   RAISE EXCEPTION 'backup identity/history is immutable' USING ERRCODE='23514';END IF;
  IF current_user<>'sandbox_backup' AND NOT pg_has_role(current_user,(SELECT relowner FROM pg_class WHERE oid=TG_RELID),'MEMBER') THEN
   RAISE EXCEPTION 'only backup controller may advance backup' USING ERRCODE='42501';END IF;
  IF NEW.status='AVAILABLE' AND (NOT EXISTS(SELECT 1 FROM public.backup_vault_receipts v WHERE v.tenant_id=NEW.tenant_id AND v.backup_id=NEW.id)
    OR (SELECT count(*) FROM public.backup_attempts a JOIN public.backup_termination_proofs p ON p.tenant_id=a.tenant_id AND p.attempt_id=a.id
      JOIN public.backup_cleanup_receipts c ON c.tenant_id=p.tenant_id AND c.proof_id=p.id
      WHERE a.tenant_id=NEW.tenant_id AND a.backup_id=NEW.id AND a.stage IN('CAPTURE','SEAL'))<>2) THEN
   RAISE EXCEPTION 'available backup requires independently verified vault and both closed attempts' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;END $$;
CREATE TRIGGER cold_backup_guard BEFORE INSERT OR UPDATE ON backups FOR EACH ROW EXECUTE FUNCTION sandbox_guard_cold_backup();
REVOKE ALL ON FUNCTION sandbox_guard_cold_backup() FROM PUBLIC;

CREATE FUNCTION sandbox_guard_backup_writer() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.desired_state='RUNNING' AND(OLD.desired_state<>'RUNNING' OR (NEW.runtime_generation,NEW.launch_id) IS DISTINCT FROM(OLD.runtime_generation,OLD.launch_id)) THEN
  PERFORM 1 FROM public.workspaces WHERE tenant_id=NEW.tenant_id AND id=NEW.workspace_id FOR UPDATE;
  IF EXISTS(SELECT 1 FROM public.workspace_holds h WHERE h.tenant_id=NEW.tenant_id AND h.workspace_id=NEW.workspace_id AND h.kind IN('BACKUP','RESTORE')
      AND NOT EXISTS(SELECT 1 FROM public.workspace_hold_releases r WHERE r.tenant_id=h.tenant_id AND r.hold_id=h.id)) THEN
   RAISE EXCEPTION 'workspace has an active cold backup or restore hold' USING ERRCODE='P4090';END IF;
 END IF;RETURN NEW;END $$;
CREATE TRIGGER instance_backup_writer_guard BEFORE UPDATE ON instances FOR EACH ROW EXECUTE FUNCTION sandbox_guard_backup_writer();
REVOKE ALL ON FUNCTION sandbox_guard_backup_writer() FROM PUBLIC;

CREATE FUNCTION sandbox_guard_backup_hold_release() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE h public.workspace_holds;b public.backups;BEGIN
 SELECT * INTO h FROM public.workspace_holds WHERE tenant_id=NEW.tenant_id AND id=NEW.hold_id;
 IF h.kind<>'BACKUP' THEN RETURN NEW;END IF;
 SELECT * INTO b FROM public.backups WHERE tenant_id=NEW.tenant_id AND id=h.reference_id;
 IF b.id IS NULL OR b.hold_id<>h.id OR b.status NOT IN('AVAILABLE','CANCELLED') OR
  EXISTS(SELECT 1 FROM public.backup_launch_permits p WHERE p.tenant_id=b.tenant_id AND p.backup_id=b.id AND NOT EXISTS(
    SELECT 1 FROM public.backup_termination_proofs proof JOIN public.backup_cleanup_receipts c ON c.tenant_id=proof.tenant_id AND c.proof_id=proof.id
     WHERE proof.tenant_id=p.tenant_id AND proof.permit_id=p.id)) OR
  EXISTS(SELECT 1 FROM public.backup_pod_admissions a WHERE a.tenant_id=b.tenant_id AND a.backup_id=b.id AND NOT EXISTS(
    SELECT 1 FROM public.backup_termination_proofs proof JOIN public.backup_cleanup_receipts c ON c.tenant_id=proof.tenant_id AND c.proof_id=proof.id
     WHERE proof.tenant_id=a.tenant_id AND proof.attempt_id=a.attempt_id)) THEN
  RAISE EXCEPTION 'unknown backup activity cannot release workspace hold' USING ERRCODE='23514';END IF;
 RETURN NEW;END $$;
CREATE TRIGGER backup_hold_release_guard BEFORE INSERT ON workspace_hold_releases FOR EACH ROW EXECUTE FUNCTION sandbox_guard_backup_hold_release();
REVOKE ALL ON FUNCTION sandbox_guard_backup_hold_release() FROM PUBLIC;

ALTER TABLE operation_dispatch ADD COLUMN backup_epoch uuid;
ALTER TABLE operation_dispatch DROP CONSTRAINT operation_dispatch_queue_role_check;
ALTER TABLE operation_dispatch ADD CONSTRAINT operation_dispatch_queue_role_check CHECK(queue_role IN('WORKER','GATEWAY','TERMINATION','VOLUME','BACKUP'));
CREATE OR REPLACE FUNCTION sandbox_update_dispatch() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE target_queue text;
BEGIN
    target_queue:=CASE WHEN NEW.kind='BACKUP' THEN 'BACKUP' WHEN NEW.kind='DELETE_WORKSPACE' THEN 'VOLUME' WHEN NEW.kind='EXECUTE' THEN 'GATEWAY'
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
    IF worker_id IS NULL OR char_length(worker_id) NOT BETWEEN 1 AND 128 OR requested_role IS NULL OR requested_role NOT IN('WORKER','GATEWAY','TERMINATION','VOLUME','BACKUP') THEN
        RAISE EXCEPTION 'invalid worker identity or queue role' USING ERRCODE='22023';END IF;
    FOR candidate IN SELECT d.operation_id,d.tenant_id FROM public.operation_dispatch d
      WHERE d.queue_role=requested_role AND (requested_role<>'VOLUME' OR d.workspace_delete_epoch=(SELECT cluster_epoch FROM public.platform_configuration WHERE singleton)) AND(requested_role<>'BACKUP' OR d.backup_epoch=(SELECT cluster_epoch FROM public.platform_configuration WHERE singleton)) AND d.eligible_at<=clock_timestamp() ORDER BY d.eligible_at,d.operation_id LIMIT 64 LOOP
        PERFORM set_config('app.tenant_id',candidate.tenant_id::text,true);
        SELECT o.id INTO found_id FROM public.operations o
        WHERE o.tenant_id=candidate.tenant_id AND o.id=candidate.operation_id
          AND CASE requested_role WHEN 'BACKUP' THEN o.kind='BACKUP' WHEN 'VOLUME' THEN o.kind='DELETE_WORKSPACE' WHEN 'GATEWAY' THEN o.kind='EXECUTE'
              WHEN 'TERMINATION' THEN o.kind IN('STOP','DELETE') OR (o.kind='RESTART' AND o.restart_generation IS NULL)
              ELSE o.kind NOT IN('EXECUTE','STOP','DELETE','DELETE_WORKSPACE','BACKUP') AND (o.kind<>'RESTART' OR o.restart_generation IS NOT NULL) END
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
CREATE FUNCTION sandbox_claim_backup(worker_id text)
RETURNS TABLE(tenant_id uuid,operation_id uuid,lease_token bigint)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT * FROM public.sandbox_claim_routed_operation(worker_id,'BACKUP');
$$;
REVOKE ALL ON FUNCTION sandbox_claim_backup(text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION sandbox_mutate_project_grant(actor uuid,project uuid,mutation text,grant_id uuid,target_principal uuid,delegated_action text,requested_expiry timestamptz,will_enable boolean,expected_version bigint)
RETURNS public.grants LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=public.sandbox_current_tenant_id();result public.grants;
BEGIN
    PERFORM public.sandbox_lock_identity_tenant(tenant);
    IF delegated_action IS NULL OR delegated_action NOT IN('instances:create','instances:read','instances:start','instances:stop','instances:restart','instances:renew','instances:delete','instances:hard_stop','workspaces:read','workspaces:delete','operations:read','events:read','audit:read','capabilities:read','executions:create','executions:read','executions:cancel','executions:output:read','grants:read','grants:write','backups:create','backups:read') THEN
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
-- Rechecked at admission. Resource labels select an intent; they never grant it.
CREATE FUNCTION sandbox_backup_authorized(requested_tenant uuid,backup uuid,require_lease boolean) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT COALESCE($1=public.sandbox_current_tenant_id() AND EXISTS(
  SELECT 1 FROM public.backups b JOIN public.operations o ON o.tenant_id=b.tenant_id AND o.id=b.operation_id
   JOIN public.backup_profiles bp ON bp.id=b.profile_id JOIN public.platform_configuration cfg ON cfg.singleton
   JOIN public.tenants t ON t.id=b.tenant_id JOIN public.projects p ON p.tenant_id=b.tenant_id AND p.id=b.project_id
  WHERE b.tenant_id=$1 AND b.id=$2 AND b.status NOT IN('AVAILABLE','CANCELLED','CAPTURE_CLOSING','SEAL_CLOSING')
   AND b.cluster_epoch=cfg.cluster_epoch AND bp.cluster_epoch=cfg.cluster_epoch AND NOT cfg.safe_mode
   AND t.enabled AND p.enabled AND bp.enabled AND bp.certified_until>=b.deadline AND b.deadline>clock_timestamp()
   AND o.kind='BACKUP' AND o.status IN('QUEUED','RUNNING','WAITING') AND NOT o.cancel_requested
   AND(NOT $3 OR(o.status='RUNNING' AND o.lease_owner IS NOT NULL AND o.lease_until>clock_timestamp()))
   AND public.sandbox_principal_enabled(o.actor_principal_id)
   AND EXISTS(SELECT 1 FROM public.grants g WHERE g.tenant_id=b.tenant_id AND g.principal_id=o.actor_principal_id AND g.project_id IS NULL AND g.action IN('backups:create','*') AND g.enabled AND g.revoked_at IS NULL AND(g.expires_at IS NULL OR g.expires_at>clock_timestamp()))
   AND EXISTS(SELECT 1 FROM public.grants g WHERE g.tenant_id=b.tenant_id AND g.principal_id=o.actor_principal_id AND g.project_id=b.project_id AND g.action IN('backups:create','*') AND g.enabled AND g.revoked_at IS NULL AND(g.expires_at IS NULL OR g.expires_at>clock_timestamp()))
   AND EXISTS(SELECT 1 FROM public.workspace_holds h WHERE h.tenant_id=b.tenant_id AND h.id=b.hold_id AND NOT EXISTS(SELECT 1 FROM public.workspace_hold_releases r WHERE r.tenant_id=h.tenant_id AND r.hold_id=h.id))
   AND public.sandbox_workspace_cold_backup_ready(b.tenant_id,b.workspace_id)),false);
$$;
REVOKE ALL ON FUNCTION sandbox_backup_authorized(uuid,uuid,boolean) FROM PUBLIC;
CREATE FUNCTION sandbox_admit_backup_pod(requested_tenant uuid,attempt uuid,review uuid,job uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE b public.backups;a public.backup_attempts;previous text:=current_setting('app.tenant_id',true);accepted boolean:=false;BEGIN
 IF requested_tenant IS NULL OR attempt IS NULL OR review IS NULL OR job IS NULL OR requested_tenant='00000000-0000-0000-0000-000000000000' OR attempt='00000000-0000-0000-0000-000000000000' OR review='00000000-0000-0000-0000-000000000000' OR job='00000000-0000-0000-0000-000000000000' THEN RETURN false;END IF;
 PERFORM set_config('app.tenant_id',requested_tenant::text,true);
 SELECT * INTO a FROM public.backup_attempts WHERE tenant_id=requested_tenant AND id=attempt;
 IF a.id IS NULL THEN PERFORM set_config('app.tenant_id',COALESCE(previous,''),true);RETURN false;END IF;
 SELECT * INTO b FROM public.backups WHERE tenant_id=requested_tenant AND id=a.backup_id;
 PERFORM 1 FROM public.workspaces WHERE tenant_id=requested_tenant AND id=b.workspace_id FOR UPDATE;
 PERFORM 1 FROM public.instances WHERE tenant_id=requested_tenant AND id=b.instance_id FOR UPDATE;
 SELECT * INTO b FROM public.backups WHERE tenant_id=requested_tenant AND id=a.backup_id FOR UPDATE;
 PERFORM 1 FROM public.operations WHERE tenant_id=requested_tenant AND id=b.operation_id FOR UPDATE;
 IF public.sandbox_backup_authorized(requested_tenant,b.id,false)
  AND((a.stage='CAPTURE' AND b.status IN('CAPTURE_PENDING','CAPTURE_RUNNING')) OR(a.stage='SEAL' AND b.status IN('SEAL_PENDING','SEAL_RUNNING')))
  AND EXISTS(SELECT 1 FROM public.backup_job_contexts c WHERE c.tenant_id=requested_tenant AND c.attempt_id=a.id AND c.deadline>clock_timestamp())
  AND EXISTS(SELECT 1 FROM public.backup_resource_intents r JOIN public.backup_resource_bindings rb ON rb.tenant_id=r.tenant_id AND rb.intent_id=r.id WHERE r.tenant_id=requested_tenant AND r.attempt_id=a.id AND r.kind='JOB' AND rb.uid=job) THEN
  INSERT INTO public.backup_pod_admissions(attempt_id,tenant_id,backup_id,review_uid,job_uid) VALUES(a.id,requested_tenant,b.id,review,job) ON CONFLICT(attempt_id) DO NOTHING;
  SELECT p.review_uid=review AND p.job_uid=job INTO accepted FROM public.backup_pod_admissions p WHERE p.tenant_id=requested_tenant AND p.attempt_id=a.id;
 END IF;
 PERFORM set_config('app.tenant_id',COALESCE(previous,''),true);RETURN COALESCE(accepted,false);
END $$;
REVOKE ALL ON FUNCTION sandbox_admit_backup_pod(uuid,uuid,uuid,uuid) FROM PUBLIC;

ALTER TABLE backup_launch_permits ADD CONSTRAINT backup_permit_attempt_scope UNIQUE(tenant_id,backup_id,attempt_id,id);
ALTER TABLE backup_close_challenges ADD CONSTRAINT backup_challenge_permit_scope UNIQUE(tenant_id,backup_id,permit_id,id);
ALTER TABLE backup_termination_proofs ADD CONSTRAINT backup_proof_attempt_permit FOREIGN KEY(tenant_id,backup_id,attempt_id,permit_id) REFERENCES backup_launch_permits(tenant_id,backup_id,attempt_id,id),
 ADD CONSTRAINT backup_proof_challenge_permit FOREIGN KEY(tenant_id,backup_id,permit_id,challenge_id) REFERENCES backup_close_challenges(tenant_id,backup_id,permit_id,id);
