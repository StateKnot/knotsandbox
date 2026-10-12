-- Private companion to 0038_restores.sql. Merge only when every GC acceptance
-- gate passes. This file is DDL, not a SQLx migration or production certificate.
CREATE TABLE restore_gc_reviews (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,restore_id uuid NOT NULL,source_backup_id uuid NOT NULL,cluster_epoch uuid NOT NULL,
 raw_identity jsonb NOT NULL CHECK(jsonb_typeof(raw_identity)='object' AND octet_length(raw_identity::text)<=16384),
 snapshot_identity jsonb NOT NULL CHECK(jsonb_typeof(snapshot_identity)='object' AND octet_length(snapshot_identity::text)<=16384),
 target_identity jsonb NOT NULL CHECK(jsonb_typeof(target_identity)='object' AND octet_length(target_identity::text)<=16384),
 force_created_disk boolean NOT NULL DEFAULT false,retain_until timestamptz NOT NULL,valid_until timestamptz NOT NULL,
 reviewed_by uuid NOT NULL REFERENCES principals(id),approval_reference text NOT NULL CHECK(length(approval_reference) BETWEEN 1 AND 512),
 report_sha256 text NOT NULL CHECK(report_sha256~'^[0-9a-f]{64}$'),reviewed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 supersedes uuid UNIQUE REFERENCES restore_gc_reviews(id),UNIQUE(tenant_id,restore_id,id),CHECK(supersedes IS NULL OR supersedes<>id),
 FOREIGN KEY(tenant_id,restore_id) REFERENCES restores(tenant_id,id),FOREIGN KEY(tenant_id,source_backup_id) REFERENCES backups(tenant_id,id),
 CHECK(valid_until>retain_until AND valid_until>reviewed_at)
);
CREATE UNIQUE INDEX restore_gc_initial_review ON restore_gc_reviews(tenant_id,restore_id) WHERE supersedes IS NULL;
CREATE TABLE restore_gc_runs (
 restore_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,review_id uuid NOT NULL,status text NOT NULL DEFAULT 'QUEUED' CHECK(status IN('QUEUED','RUNNING','WAITING','SUCCEEDED')),
 lease_owner text,lease_token bigint NOT NULL DEFAULT 0 CHECK(lease_token>=0),lease_until timestamptz,next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 attempts integer NOT NULL DEFAULT 0,wait_reason text,completed_at timestamptz,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,restore_id),FOREIGN KEY(tenant_id,restore_id,review_id) REFERENCES restore_gc_reviews(tenant_id,restore_id,id),
 CHECK((lease_owner IS NULL)=(lease_until IS NULL)),CHECK((status='SUCCEEDED')=(completed_at IS NOT NULL))
);
CREATE TABLE restore_gc_dispatches (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,restore_id uuid NOT NULL,review_id uuid NOT NULL,lease_token bigint NOT NULL,
 kind text NOT NULL CHECK(kind IN('PRESERVE_RAW_SNAPSHOTS','DELETE_RAW_DISK','DELETE_SNAPSHOT')),identity jsonb NOT NULL,force_created_disk boolean NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,restore_id,id),
 FOREIGN KEY(tenant_id,restore_id,review_id) REFERENCES restore_gc_reviews(tenant_id,restore_id,id),
 CHECK(jsonb_typeof(identity)='object' AND octet_length(identity::text)<=16384),
 CHECK(kind='DELETE_SNAPSHOT' OR NOT force_created_disk)
);
CREATE TABLE restore_gc_results (
 dispatch_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,restore_id uuid NOT NULL,outcome text NOT NULL CHECK(outcome IN('ACCEPTED','UNKNOWN','REJECTED')),
 evidence jsonb NOT NULL CHECK(jsonb_typeof(evidence)='object' AND octet_length(evidence::text)<=65536),recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,restore_id,dispatch_id) REFERENCES restore_gc_dispatches(tenant_id,restore_id,id)
);
CREATE TABLE restore_gc_cloud_absences (
 tenant_id uuid NOT NULL,restore_id uuid NOT NULL,kind text NOT NULL CHECK(kind IN('RAW_DISK','SNAPSHOT')),resource_id text NOT NULL,
 dispatch_id uuid NOT NULL,evidence jsonb NOT NULL CHECK(jsonb_typeof(evidence)='object' AND octet_length(evidence::text)<=65536),
 observed_at timestamptz NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,restore_id,kind),
 FOREIGN KEY(tenant_id,restore_id,dispatch_id) REFERENCES restore_gc_dispatches(tenant_id,restore_id,id)
);
CREATE TABLE restore_gc_kube_absences (
 tenant_id uuid NOT NULL,restore_id uuid NOT NULL,intent_id uuid NOT NULL,uid uuid NOT NULL,observed_at timestamptz NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,restore_id,intent_id),
 FOREIGN KEY(tenant_id,restore_id,intent_id) REFERENCES restore_resource_intents(tenant_id,restore_id,id)
);
CREATE TABLE restore_gc_settlements (
 restore_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,review_id uuid NOT NULL,released_gib bigint NOT NULL CHECK(released_gib>0),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,restore_id),
 FOREIGN KEY(tenant_id,restore_id,review_id) REFERENCES restore_gc_reviews(tenant_id,restore_id,id)
);
-- A private cross-tenant scheduler index contains only IDs and eligibility,
-- like operation_dispatch. No runtime login receives table SELECT privileges.
CREATE TABLE restore_gc_queue (
 restore_id uuid PRIMARY KEY REFERENCES restore_gc_runs(restore_id),tenant_id uuid NOT NULL,
 eligible_at timestamptz NOT NULL,valid_until timestamptz NOT NULL,has_dispatch boolean NOT NULL DEFAULT false
);
REVOKE ALL ON restore_gc_queue FROM PUBLIC;
DO $$ DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['restore_gc_reviews','restore_gc_runs','restore_gc_dispatches','restore_gc_results','restore_gc_cloud_absences','restore_gc_kube_absences','restore_gc_settlements'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
  EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.sandbox_current_tenant_id()) WITH CHECK(tenant_id=public.sandbox_current_tenant_id())',tab);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',tab);
  IF tab<>'restore_gc_runs' THEN EXECUTE format('CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.sandbox_prevent_audit_mutation()',tab);END IF;
 END LOOP;
END $$;

CREATE FUNCTION sandbox_restore_gc_writers_closed(tenant uuid,restore uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT COALESCE($1=public.sandbox_current_tenant_id() AND EXISTS(
  SELECT 1 FROM public.restores r JOIN public.backup_vault_receipts v ON v.tenant_id=r.tenant_id AND v.backup_id=r.backup_id JOIN public.restore_block_receipts raw ON raw.tenant_id=r.tenant_id AND raw.restore_id=r.id
  JOIN public.restore_snapshot_receipts s ON s.tenant_id=r.tenant_id AND s.restore_id=r.id
  JOIN public.restore_delivery_receipts d ON d.tenant_id=r.tenant_id AND d.restore_id=r.id
  JOIN public.restore_io_reports io ON io.tenant_id=r.tenant_id AND io.restore_id=r.id
  WHERE r.tenant_id=$1 AND r.id=$2 AND r.status='AVAILABLE'
  AND r.cluster_epoch=(SELECT cluster_epoch FROM public.platform_configuration WHERE singleton)
  AND io.exit_code=0 AND io.bytes=raw.size_bytes AND io.disk_sha256=v.manifest->'manifest'->'disk'->>'sha256' AND v.manifest_sha256=r.source_manifest_sha256
  AND s.cloud_snapshot=d.cloud_snapshot AND raw.cloud_disk<>d.cloud_disk AND raw.size_bytes=d.size_bytes
  AND EXISTS(SELECT 1 FROM public.restore_artifact_cleanup_receipts c WHERE c.tenant_id=r.tenant_id AND c.restore_id=r.id)
  AND EXISTS(SELECT 1 FROM public.restore_launch_permits p WHERE p.tenant_id=r.tenant_id AND p.restore_id=r.id)
  AND NOT EXISTS(SELECT 1 FROM public.restore_launch_permits p WHERE p.tenant_id=r.tenant_id AND p.restore_id=r.id AND NOT EXISTS(
   SELECT 1 FROM public.restore_termination_proofs proof JOIN public.restore_cleanup_receipts clean ON clean.tenant_id=proof.tenant_id AND clean.proof_id=proof.id
   WHERE proof.tenant_id=p.tenant_id AND proof.permit_id=p.id AND proof.restore_id=p.restore_id
   AND clean.pvc_uid=raw.pvc_uid AND clean.pv_uid=raw.pv_uid AND clean.cloud_disk=raw.cloud_disk AND clean.pod_uid=(p.request->'launch'->>'pod_uid')::uuid))
 ),false);
$$;
REVOKE ALL ON FUNCTION sandbox_restore_gc_writers_closed(uuid,uuid) FROM PUBLIC;
-- Every writer/settlement entry, including a direct definer invocation, uses
-- the ordinary W -> I -> operation lock order. No network I/O holds these locks.
CREATE FUNCTION sandbox_lock_restore_gc(tenant uuid,restore uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r public.restores;active uuid;
BEGIN
 IF tenant IS DISTINCT FROM public.sandbox_current_tenant_id() THEN RETURN false;END IF;
 SELECT * INTO r FROM public.restores WHERE tenant_id=tenant AND id=restore;
 IF NOT FOUND THEN RETURN false;END IF;
 PERFORM 1 FROM public.workspaces w WHERE w.tenant_id=tenant AND w.id=r.workspace_id FOR UPDATE;
 IF NOT FOUND THEN RETURN false;END IF;
 SELECT i.active_operation_id INTO active FROM public.instances i WHERE i.tenant_id=tenant AND i.id=r.instance_id AND i.workspace_id=r.workspace_id FOR UPDATE;
 IF NOT FOUND THEN RETURN false;END IF;
 PERFORM 1 FROM public.operations o WHERE o.tenant_id=tenant AND (o.id=r.operation_id OR o.id=active) ORDER BY o.id FOR UPDATE;
 SELECT * INTO r FROM public.restores WHERE tenant_id=tenant AND id=restore FOR UPDATE;
 PERFORM 1 FROM public.restore_gc_runs run WHERE run.tenant_id=tenant AND run.restore_id=restore FOR UPDATE;
 PERFORM b.intent_id FROM public.restore_resource_bindings b WHERE b.tenant_id=tenant AND b.restore_id=restore ORDER BY b.intent_id FOR UPDATE;
 RETURN public.sandbox_restore_gc_writers_closed(tenant,restore);
END $$;
REVOKE ALL ON FUNCTION sandbox_lock_restore_gc(uuid,uuid) FROM PUBLIC;
CREATE FUNCTION sandbox_assert_restore_gc_claim(tenant uuid,restore uuid,worker text,lease bigint) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT public.sandbox_lock_restore_gc(tenant,restore) THEN RETURN false;END IF;
 RETURN EXISTS(SELECT 1 FROM public.restore_gc_runs run JOIN public.restore_gc_reviews review
  ON review.tenant_id=run.tenant_id AND review.restore_id=run.restore_id AND review.id=run.review_id
  WHERE run.tenant_id=tenant AND run.restore_id=restore AND run.status='RUNNING' AND run.lease_owner=worker
  AND run.lease_token=lease AND run.lease_until>clock_timestamp() AND review.retain_until<=clock_timestamp());
END $$;
REVOKE ALL ON FUNCTION sandbox_assert_restore_gc_claim(uuid,uuid,text,bigint) FROM PUBLIC;
CREATE FUNCTION sandbox_guard_restore_gc_review() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT public.sandbox_lock_restore_gc(NEW.tenant_id,NEW.restore_id) OR NOT EXISTS(
  SELECT 1 FROM public.restores r JOIN public.backups b ON b.tenant_id=r.tenant_id AND b.id=r.backup_id
  JOIN public.backup_snapshot_receipts source_snapshot ON source_snapshot.tenant_id=b.tenant_id AND source_snapshot.backup_id=b.id
  JOIN public.restore_block_receipts raw ON raw.tenant_id=r.tenant_id AND raw.restore_id=r.id
  JOIN public.restore_snapshot_receipts s ON s.tenant_id=r.tenant_id AND s.restore_id=r.id
  JOIN public.restore_delivery_receipts d ON d.tenant_id=r.tenant_id AND d.restore_id=r.id
  JOIN public.workspaces w ON w.tenant_id=r.tenant_id AND w.id=r.workspace_id
  WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.restore_id AND r.backup_id=NEW.source_backup_id AND r.cluster_epoch=NEW.cluster_epoch
  AND NEW.raw_identity->'binding'->>'disk_id'=raw.cloud_disk AND NEW.raw_identity->'binding'->>'pv_name'=raw.pv_name
  AND NEW.raw_identity->'binding'->>'namespace'='sandbox-system' AND NEW.raw_identity->'binding'->>'pvc_name'='sbx-bvol-'||r.id::text
  AND NEW.target_identity->'binding'->>'disk_id'=d.cloud_disk AND NEW.target_identity->'binding'->>'pv_name'=d.pv_name
  AND NEW.target_identity->'binding'->>'namespace'=d.namespace AND NEW.target_identity->'binding'->>'pvc_name'=w.pvc_name
  AND NEW.raw_identity->'binding'->>'account_id'=r.source_identity->>'account_id' AND NEW.target_identity->'binding'->>'account_id'=r.source_identity->>'account_id'
  AND NEW.raw_identity->'binding'->>'region'=r.source_identity->>'region' AND NEW.target_identity->'binding'->>'region'=r.source_identity->>'region'
  AND (NEW.raw_identity->'binding'->>'size_gib')::bigint=raw.size_bytes/1073741824 AND (NEW.target_identity->'binding'->>'size_gib')::bigint=d.size_bytes/1073741824
  AND NEW.snapshot_identity->'binding'->'scope'->>'restore_id'=r.id::text AND NEW.snapshot_identity->'binding'->'scope'->>'raw_disk_id'=raw.cloud_disk
  AND NEW.snapshot_identity->'binding'->'scope'->>'snapshot_id'=s.cloud_snapshot AND NEW.snapshot_identity->'binding'->'scope'->>'target_disk_id'=d.cloud_disk
  AND NEW.snapshot_identity->'binding'->>'account_id'=r.source_identity->>'account_id' AND NEW.snapshot_identity->'binding'->>'region'=r.source_identity->>'region'
  AND NEW.snapshot_identity->'binding'->>'kms_key_id'=NEW.raw_identity->'binding'->>'kms_key_id' AND NEW.snapshot_identity->'binding'->>'kms_key_id'=NEW.target_identity->'binding'->>'kms_key_id'
  AND (NEW.snapshot_identity->'binding'->>'size_gib')::bigint=s.size_bytes/1073741824 AND s.cloud_snapshot<>source_snapshot.cloud_snapshot
  AND raw.cloud_disk<>d.cloud_disk AND w.restore_snapshot_name=d.snapshot_name
  AND NEW.valid_until>clock_timestamp()
 ) THEN RAISE EXCEPTION 'GC review requires closed restore and immutable non-source raw/snapshot/target identities' USING ERRCODE='23514';END IF;
 IF NEW.supersedes IS NULL THEN
  IF EXISTS(SELECT 1 FROM public.restore_gc_runs run WHERE run.tenant_id=NEW.tenant_id AND run.restore_id=NEW.restore_id) THEN
   RAISE EXCEPTION 'GC already has an immutable review chain' USING ERRCODE='23514';END IF;
 ELSIF NOT EXISTS(SELECT 1 FROM public.restore_gc_runs run JOIN public.restore_gc_reviews old
  ON old.tenant_id=run.tenant_id AND old.restore_id=run.restore_id AND old.id=run.review_id
  WHERE run.tenant_id=NEW.tenant_id AND run.restore_id=NEW.restore_id AND old.id=NEW.supersedes AND run.status<>'SUCCEEDED'
  AND(run.lease_until IS NULL OR run.lease_until<=clock_timestamp())
  AND(old.source_backup_id,old.cluster_epoch,old.raw_identity,old.snapshot_identity,old.target_identity)=
     (NEW.source_backup_id,NEW.cluster_epoch,NEW.raw_identity,NEW.snapshot_identity,NEW.target_identity)) THEN
  RAISE EXCEPTION 'renewal cannot change identities, fork a review or replace a live lease' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER restore_gc_review_guard BEFORE INSERT ON restore_gc_reviews FOR EACH ROW EXECUTE FUNCTION sandbox_guard_restore_gc_review();
REVOKE ALL ON FUNCTION sandbox_guard_restore_gc_review() FROM PUBLIC;
CREATE FUNCTION sandbox_restore_gc_review_run() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 INSERT INTO public.restore_gc_runs(restore_id,tenant_id,review_id) VALUES(NEW.restore_id,NEW.tenant_id,NEW.id)
 ON CONFLICT(restore_id) DO UPDATE SET review_id=EXCLUDED.review_id,status='QUEUED',lease_owner=NULL,lease_until=NULL,
  next_attempt_at=clock_timestamp(),wait_reason=NULL WHERE restore_gc_runs.review_id=NEW.supersedes;
 RETURN NEW;
END $$;
CREATE TRIGGER restore_gc_review_run AFTER INSERT ON restore_gc_reviews FOR EACH ROW EXECUTE FUNCTION sandbox_restore_gc_review_run();
REVOKE ALL ON FUNCTION sandbox_restore_gc_review_run() FROM PUBLIC;
CREATE FUNCTION sandbox_guard_restore_gc_run() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'GC claim history is immutable' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' AND (NEW.restore_id<>OLD.restore_id OR NEW.tenant_id<>OLD.tenant_id
  OR NEW.created_at<>OLD.created_at OR NEW.lease_token<OLD.lease_token OR (OLD.status='SUCCEEDED' AND NEW IS DISTINCT FROM OLD)) THEN
  RAISE EXCEPTION 'GC claim provenance is immutable' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' AND NEW.review_id<>OLD.review_id AND NOT EXISTS(SELECT 1 FROM public.restore_gc_reviews review
  WHERE review.tenant_id=NEW.tenant_id AND review.restore_id=NEW.restore_id AND review.id=NEW.review_id AND review.supersedes=OLD.review_id
  AND(OLD.lease_until IS NULL OR OLD.lease_until<=clock_timestamp()) AND OLD.status<>'SUCCEEDED' AND NEW.lease_owner IS NULL) THEN
  RAISE EXCEPTION 'GC review change requires immutable approved successor and no live lease' USING ERRCODE='23514';END IF;
 IF (NEW.status='RUNNING')<>(NEW.lease_owner IS NOT NULL AND NEW.lease_until>clock_timestamp())
 OR (NEW.status='SUCCEEDED' AND NOT EXISTS(SELECT 1 FROM public.restore_gc_settlements s WHERE s.tenant_id=NEW.tenant_id AND s.restore_id=NEW.restore_id AND s.review_id=NEW.review_id)) THEN
  RAISE EXCEPTION 'GC claim status lacks lease or settlement' USING ERRCODE='23514';END IF;
 IF NEW.status='SUCCEEDED' AND(TG_OP<>'UPDATE' OR OLD.status<>'RUNNING' OR OLD.lease_until<=clock_timestamp()
  OR NOT public.sandbox_restore_gc_writers_closed(NEW.tenant_id,NEW.restore_id)) THEN
  RAISE EXCEPTION 'GC completion requires a live previously running claim and current closed writer' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER restore_gc_run_guard BEFORE INSERT OR UPDATE OR DELETE ON restore_gc_runs FOR EACH ROW EXECUTE FUNCTION sandbox_guard_restore_gc_run();
REVOKE ALL ON FUNCTION sandbox_guard_restore_gc_run() FROM PUBLIC;
CREATE FUNCTION sandbox_update_restore_gc_queue() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE review public.restore_gc_reviews;
BEGIN
 IF NEW.status='SUCCEEDED' THEN DELETE FROM public.restore_gc_queue WHERE restore_id=NEW.restore_id;RETURN NEW;END IF;
 SELECT * INTO review FROM public.restore_gc_reviews WHERE tenant_id=NEW.tenant_id AND restore_id=NEW.restore_id AND id=NEW.review_id;
 INSERT INTO public.restore_gc_queue(restore_id,tenant_id,eligible_at,valid_until,has_dispatch)
 VALUES(NEW.restore_id,NEW.tenant_id,GREATEST(NEW.next_attempt_at,COALESCE(NEW.lease_until,NEW.next_attempt_at),review.retain_until),review.valid_until,
 EXISTS(SELECT 1 FROM public.restore_gc_dispatches d WHERE d.tenant_id=NEW.tenant_id AND d.restore_id=NEW.restore_id))
 ON CONFLICT(restore_id) DO UPDATE SET eligible_at=EXCLUDED.eligible_at,valid_until=EXCLUDED.valid_until,has_dispatch=EXCLUDED.has_dispatch;
 RETURN NEW;
END $$;
CREATE TRIGGER restore_gc_queue AFTER INSERT OR UPDATE ON restore_gc_runs FOR EACH ROW EXECUTE FUNCTION sandbox_update_restore_gc_queue();
REVOKE ALL ON FUNCTION sandbox_update_restore_gc_queue() FROM PUBLIC;
CREATE FUNCTION sandbox_guard_restore_gc_evidence() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE run public.restore_gc_runs;review public.restore_gc_reviews;dispatch public.restore_gc_dispatches;
BEGIN
 IF NOT public.sandbox_lock_restore_gc(NEW.tenant_id,NEW.restore_id) THEN
  RAISE EXCEPTION 'GC scope or isolated writer changed while waiting' USING ERRCODE='23514';END IF;
 SELECT * INTO run FROM public.restore_gc_runs WHERE tenant_id=NEW.tenant_id AND restore_id=NEW.restore_id FOR UPDATE;
 SELECT * INTO review FROM public.restore_gc_reviews WHERE tenant_id=NEW.tenant_id AND restore_id=NEW.restore_id AND id=run.review_id;
 IF NOT FOUND OR run.status<>'RUNNING' OR run.lease_until<=clock_timestamp() OR review.retain_until>clock_timestamp()
 OR NOT public.sandbox_restore_gc_writers_closed(NEW.tenant_id,NEW.restore_id) THEN
  RAISE EXCEPTION 'GC evidence requires current scoped claim and closed isolated writer' USING ERRCODE='23514';END IF;
 IF TG_TABLE_NAME='restore_gc_dispatches' THEN
  IF NEW.review_id<>review.id OR NEW.lease_token<>run.lease_token OR review.valid_until<=clock_timestamp()
   OR NEW.identity<>(CASE WHEN NEW.kind='DELETE_SNAPSHOT' THEN review.snapshot_identity ELSE review.raw_identity END)
   OR (NEW.force_created_disk AND (NEW.kind<>'DELETE_SNAPSHOT' OR NOT review.force_created_disk)) THEN
   RAISE EXCEPTION 'GC dispatch differs from reviewed immutable identity' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='restore_gc_results' THEN
  SELECT * INTO dispatch FROM public.restore_gc_dispatches WHERE tenant_id=NEW.tenant_id AND restore_id=NEW.restore_id AND id=NEW.dispatch_id;
  IF NOT FOUND OR dispatch.review_id<>review.id OR dispatch.lease_token<>run.lease_token
   OR dispatch.identity<>(CASE WHEN dispatch.kind='DELETE_SNAPSHOT' THEN review.snapshot_identity ELSE review.raw_identity END)
   OR(dispatch.force_created_disk AND(dispatch.kind<>'DELETE_SNAPSHOT' OR NOT review.force_created_disk))
   OR NEW.recorded_at<dispatch.created_at OR NEW.recorded_at>clock_timestamp()+interval '2 seconds' THEN
   RAISE EXCEPTION 'GC outcome requires this live claim and its immutable dispatched source' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='restore_gc_cloud_absences' THEN
  SELECT * INTO dispatch FROM public.restore_gc_dispatches WHERE tenant_id=NEW.tenant_id AND restore_id=NEW.restore_id AND id=NEW.dispatch_id;
  IF NOT FOUND OR NEW.observed_at<dispatch.created_at OR NEW.observed_at>clock_timestamp()+interval '2 seconds'
   OR NEW.observed_at<clock_timestamp()-interval '30 seconds'
   OR NEW.kind<>(CASE WHEN dispatch.kind='DELETE_RAW_DISK' THEN 'RAW_DISK' WHEN dispatch.kind='DELETE_SNAPSHOT' THEN 'SNAPSHOT' ELSE '' END)
   OR NEW.resource_id<>(CASE WHEN NEW.kind='RAW_DISK' THEN review.raw_identity->'binding'->>'disk_id' ELSE review.snapshot_identity->'binding'->'scope'->>'snapshot_id' END) THEN
   RAISE EXCEPTION 'GC absence requires matching dispatched physical resource and fresh exact query' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='restore_gc_kube_absences' THEN
  IF NOT EXISTS(SELECT 1 FROM public.restore_resource_intents i JOIN public.restore_resource_bindings b ON b.tenant_id=i.tenant_id AND b.intent_id=i.id
   WHERE i.tenant_id=NEW.tenant_id AND i.restore_id=NEW.restore_id AND i.id=NEW.intent_id AND b.uid=NEW.uid
   AND i.kind IN('BLOCK_PVC','BLOCK_PV','RESTORED_SNAPSHOT','RESTORED_CONTENT','DELIVERY_SNAPSHOT','DELIVERY_CONTENT'))
   OR (SELECT count(*) FROM public.restore_gc_cloud_absences a WHERE a.tenant_id=NEW.tenant_id AND a.restore_id=NEW.restore_id)<>2
   OR NEW.observed_at>clock_timestamp()+interval '2 seconds' OR NEW.observed_at<clock_timestamp()-interval '30 seconds' THEN
   RAISE EXCEPTION 'GC metadata absence requires both physical absences and exact immutable Kube UID' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER restore_gc_dispatch_guard BEFORE INSERT ON restore_gc_dispatches FOR EACH ROW EXECUTE FUNCTION sandbox_guard_restore_gc_evidence();
CREATE TRIGGER restore_gc_result_guard BEFORE INSERT ON restore_gc_results FOR EACH ROW EXECUTE FUNCTION sandbox_guard_restore_gc_evidence();
CREATE TRIGGER restore_gc_absence_guard BEFORE INSERT ON restore_gc_cloud_absences FOR EACH ROW EXECUTE FUNCTION sandbox_guard_restore_gc_evidence();
CREATE TRIGGER restore_gc_kube_guard BEFORE INSERT ON restore_gc_kube_absences FOR EACH ROW EXECUTE FUNCTION sandbox_guard_restore_gc_evidence();
REVOKE ALL ON FUNCTION sandbox_guard_restore_gc_evidence() FROM PUBLIC;

CREATE FUNCTION sandbox_restore_gc_candidates(maximum integer) RETURNS TABLE(tenant_id uuid,restore_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT q.tenant_id,q.restore_id FROM public.restore_gc_queue q WHERE maximum BETWEEN 1 AND 64 AND q.eligible_at<=clock_timestamp()
 AND(q.valid_until>clock_timestamp() OR q.has_dispatch)
 ORDER BY q.eligible_at,q.restore_id LIMIT LEAST(GREATEST(maximum,0),64);
$$;
REVOKE ALL ON FUNCTION sandbox_restore_gc_candidates(integer) FROM PUBLIC;
CREATE FUNCTION sandbox_claim_restore_gc(tenant uuid,restore uuid,worker text,seconds integer) RETURNS SETOF restore_gc_runs
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF worker IS NULL OR length(worker) NOT BETWEEN 1 AND 128 OR seconds NOT BETWEEN 10 AND 300
  OR NOT public.sandbox_lock_restore_gc(tenant,restore) THEN RETURN;END IF;
 RETURN QUERY UPDATE public.restore_gc_runs run SET status='RUNNING',lease_owner=worker,lease_token=run.lease_token+1,
  lease_until=clock_timestamp()+make_interval(secs=>seconds),attempts=run.attempts+1,wait_reason=NULL
  FROM public.restore_gc_reviews review WHERE run.tenant_id=tenant AND run.restore_id=restore AND run.review_id=review.id
  AND review.tenant_id=run.tenant_id AND review.restore_id=run.restore_id AND review.retain_until<=clock_timestamp()
  AND(review.valid_until>clock_timestamp() OR EXISTS(SELECT 1 FROM public.restore_gc_dispatches d WHERE d.tenant_id=run.tenant_id AND d.restore_id=run.restore_id))
  AND run.status<>'SUCCEEDED' AND run.next_attempt_at<=clock_timestamp() AND(run.lease_until IS NULL OR run.lease_until<=clock_timestamp()) RETURNING run.*;
END $$;
REVOKE ALL ON FUNCTION sandbox_claim_restore_gc(uuid,uuid,text,integer) FROM PUBLIC;
CREATE FUNCTION sandbox_wait_restore_gc(tenant uuid,restore uuid,worker text,lease bigint,reason text,seconds integer) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF reason IS NULL OR length(reason) NOT BETWEEN 1 AND 256 OR seconds NOT BETWEEN 1 AND 3600
 OR NOT public.sandbox_lock_restore_gc(tenant,restore) THEN RETURN false;END IF;
 UPDATE public.restore_gc_runs SET status='WAITING',lease_owner=NULL,lease_until=NULL,wait_reason=reason,
  next_attempt_at=clock_timestamp()+make_interval(secs=>seconds)
  WHERE tenant_id=tenant AND restore_id=restore AND status='RUNNING' AND lease_owner=worker AND lease_token=lease AND lease_until>clock_timestamp();
 RETURN FOUND;
END $$;
REVOKE ALL ON FUNCTION sandbox_wait_restore_gc(uuid,uuid,text,bigint,text,integer) FROM PUBLIC;
CREATE FUNCTION sandbox_finish_restore_gc(tenant uuid,restore uuid,worker text,lease bigint) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE run public.restore_gc_runs;review public.restore_gc_reviews;r public.restores;reservation record;size_gib bigint;matches integer:=0;
BEGIN
 IF NOT public.sandbox_lock_restore_gc(tenant,restore) THEN RETURN false;END IF;
 SELECT * INTO run FROM public.restore_gc_runs WHERE tenant_id=tenant AND restore_id=restore FOR UPDATE;
 IF NOT FOUND THEN RETURN false;END IF;
 IF run.status='SUCCEEDED' THEN RETURN EXISTS(SELECT 1 FROM public.restore_gc_settlements s WHERE s.tenant_id=tenant AND s.restore_id=restore AND s.review_id=run.review_id);END IF;
 IF run.status<>'RUNNING' OR run.lease_owner<>worker OR run.lease_token<>lease OR run.lease_until<=clock_timestamp()
 OR NOT public.sandbox_restore_gc_writers_closed(tenant,restore) THEN RETURN false;END IF;
 SELECT * INTO r FROM public.restores WHERE tenant_id=tenant AND id=restore;
 SELECT * INTO review FROM public.restore_gc_reviews WHERE tenant_id=tenant AND restore_id=restore AND id=run.review_id;
 IF (SELECT count(*) FROM public.restore_gc_cloud_absences a WHERE a.tenant_id=tenant AND a.restore_id=restore)<>2
 OR EXISTS(SELECT 1 FROM public.restore_resource_intents i JOIN public.restore_resource_bindings b ON b.tenant_id=i.tenant_id AND b.intent_id=i.id
  WHERE i.tenant_id=tenant AND i.restore_id=restore AND i.kind IN('BLOCK_PVC','BLOCK_PV','RESTORED_SNAPSHOT','RESTORED_CONTENT','DELIVERY_SNAPSHOT','DELIVERY_CONTENT')
  AND NOT EXISTS(SELECT 1 FROM public.restore_gc_kube_absences a WHERE a.tenant_id=i.tenant_id AND a.restore_id=i.restore_id AND a.intent_id=i.id AND a.uid=b.uid))
 OR (SELECT count(*) FROM public.restore_gc_kube_absences a WHERE a.tenant_id=tenant AND a.restore_id=restore)<>6 THEN RETURN false;END IF;
 size_gib:=(r.source_identity->>'size_bytes')::bigint/1073741824;
 PERFORM id FROM public.quota_accounts WHERE tenant_id=tenant AND(project_id=r.target_project_id OR project_id IS NULL) ORDER BY id FOR UPDATE;
 FOR reservation IN SELECT q.* FROM public.quota_reservations q JOIN public.quota_accounts a ON a.tenant_id=q.tenant_id AND a.id=q.quota_account_id
  WHERE q.tenant_id=tenant AND q.operation_id=r.operation_id AND a.dimension='BACKUP_TEMP_GIB' ORDER BY q.quota_account_id,q.id FOR UPDATE OF q LOOP
  IF reservation.status<>'ALLOCATED' OR reservation.amount<>size_gib*2 OR reservation.resource_id<>r.instance_id THEN RAISE EXCEPTION 'GC temporary quota ledger mismatch' USING ERRCODE='23514';END IF;
  matches:=matches+1;
  UPDATE public.quota_accounts SET allocated=allocated-reservation.amount,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=tenant AND id=reservation.quota_account_id;
  UPDATE public.quota_reservations SET status='RELEASED',released_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=tenant AND id=reservation.id;
 END LOOP;
 IF matches<>2 THEN RAISE EXCEPTION 'GC requires both exact temporary reservations' USING ERRCODE='23514';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.restore_gc_runs current WHERE current.tenant_id=tenant AND current.restore_id=restore AND current.lease_owner=worker AND current.lease_token=lease AND current.lease_until>clock_timestamp())
  OR NOT public.sandbox_restore_gc_writers_closed(tenant,restore) THEN RAISE EXCEPTION 'GC lease or epoch expired before settlement' USING ERRCODE='23514';END IF;
 INSERT INTO public.restore_gc_settlements(restore_id,tenant_id,review_id,released_gib) VALUES(restore,tenant,review.id,size_gib*2);
 INSERT INTO public.audit_events(tenant_id,project_id,actor_principal_id,request_id,resource_id,action,outcome,details)
  VALUES(tenant,r.target_project_id,review.reviewed_by,review.id,r.id,'restores:gc','SUCCEEDED',jsonb_build_object('review_id',review.id,'temporary_gib_released',size_gib*2,'source_backup_preserved',r.backup_id));
 INSERT INTO public.domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload)
  VALUES(tenant,r.target_project_id,r.id,r.version+1,'restore.temporary_storage_reclaimed',r.operation_id,review.id,jsonb_build_object('review_id',review.id,'temporary_gib_released',size_gib*2,'source_backup_preserved',r.backup_id));
 -- Event sequencing may wait after the earlier quota check. A stale claim
 -- rolls back quota, settlement and both audit/event inserts atomically.
 IF NOT public.sandbox_assert_restore_gc_claim(tenant,restore,worker,lease) THEN
  RAISE EXCEPTION 'GC claim, epoch or writer changed during event publication' USING ERRCODE='23514';END IF;
 UPDATE public.restore_gc_runs SET status='SUCCEEDED',completed_at=clock_timestamp(),lease_owner=NULL,lease_until=NULL,wait_reason=NULL WHERE tenant_id=tenant AND restore_id=restore;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION sandbox_finish_restore_gc(uuid,uuid,text,bigint) FROM PUBLIC;
