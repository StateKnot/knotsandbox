-- Private companion only. No ordered migration or production webhook is enabled.
-- Generated CSI objects may have no tenant labels. This immutable routing index
-- carries IDs/scope only, like operation_dispatch; no runtime has table access.
-- RLS evidence remains in the tenant tables and is rechecked by the locked reader.
CREATE TABLE restore_gc_resource_routes (
 uid uuid PRIMARY KEY REFERENCES restore_resource_bindings(uid),
 tenant_id uuid NOT NULL,restore_id uuid NOT NULL,intent_id uuid NOT NULL,
 kind text NOT NULL CHECK(kind IN('BLOCK_PVC','BLOCK_PV','RESTORED_SNAPSHOT','RESTORED_CONTENT','DELIVERY_SNAPSHOT','DELIVERY_CONTENT')),
 namespace text NOT NULL,name text NOT NULL,
 FOREIGN KEY(tenant_id,intent_id) REFERENCES restore_resource_bindings(tenant_id,intent_id),
 FOREIGN KEY(tenant_id,restore_id,intent_id) REFERENCES restore_resource_intents(tenant_id,restore_id,id)
);
REVOKE ALL ON restore_gc_resource_routes FROM PUBLIC;
CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON restore_gc_resource_routes FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_audit_mutation();
CREATE FUNCTION sandbox_route_restore_gc_resource() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.tenant_id IS DISTINCT FROM public.sandbox_current_tenant_id() THEN
  RAISE EXCEPTION 'resource routing requires its binding tenant' USING ERRCODE='23514';END IF;
 INSERT INTO public.restore_gc_resource_routes(uid,tenant_id,restore_id,intent_id,kind,namespace,name)
 SELECT NEW.uid,i.tenant_id,i.restore_id,i.id,i.kind,i.namespace,i.name FROM public.restore_resource_intents i
 WHERE i.tenant_id=NEW.tenant_id AND i.restore_id=NEW.restore_id AND i.id=NEW.intent_id
 AND i.kind IN('BLOCK_PVC','BLOCK_PV','RESTORED_SNAPSHOT','RESTORED_CONTENT','DELIVERY_SNAPSHOT','DELIVERY_CONTENT');
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION sandbox_route_restore_gc_resource() FROM PUBLIC;
CREATE TRIGGER restore_gc_resource_route AFTER INSERT ON restore_resource_bindings FOR EACH ROW EXECUTE FUNCTION sandbox_route_restore_gc_resource();
-- Upgrade/backfill only IDs already present in the private GC queue. Forced RLS
-- is kept on all tenant evidence; the owner saves/restores the transaction scope.
DO $$ DECLARE route record;prior text:=current_setting('app.tenant_id',true);BEGIN
 FOR route IN SELECT tenant_id,restore_id FROM public.restore_gc_queue LOOP
  PERFORM set_config('app.tenant_id',route.tenant_id::text,true);
  INSERT INTO public.restore_gc_resource_routes(uid,tenant_id,restore_id,intent_id,kind,namespace,name)
  SELECT b.uid,i.tenant_id,i.restore_id,i.id,i.kind,i.namespace,i.name
  FROM public.restore_resource_intents i JOIN public.restore_resource_bindings b
  ON b.tenant_id=i.tenant_id AND b.restore_id=i.restore_id AND b.intent_id=i.id
  WHERE i.tenant_id=route.tenant_id AND i.restore_id=route.restore_id
  AND i.kind IN('BLOCK_PVC','BLOCK_PV','RESTORED_SNAPSHOT','RESTORED_CONTENT','DELIVERY_SNAPSHOT','DELIVERY_CONTENT');
 END LOOP;
 PERFORM set_config('app.tenant_id',COALESCE(prior,''),true);
END $$;
CREATE FUNCTION sandbox_resolve_restore_gc_resource(requested_group text,plural text,namespace text,name text,uid uuid)
RETURNS TABLE(tenant_id uuid,restore_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT i.tenant_id,i.restore_id FROM public.restore_gc_resource_routes i
 WHERE i.uid=$5 AND i.namespace=$3 AND i.name=$4 AND (
  ($1='' AND $2='persistentvolumeclaims' AND i.kind='BLOCK_PVC') OR
  ($1='' AND $2='persistentvolumes' AND i.kind='BLOCK_PV') OR
  ($1='snapshot.storage.k8s.io' AND $2='volumesnapshots' AND i.kind IN('RESTORED_SNAPSHOT','DELIVERY_SNAPSHOT')) OR
  ($1='snapshot.storage.k8s.io' AND $2='volumesnapshotcontents' AND i.kind IN('RESTORED_CONTENT','DELIVERY_CONTENT')))
 LIMIT 2;
$$;
REVOKE ALL ON FUNCTION sandbox_resolve_restore_gc_resource(text,text,text,text,uuid) FROM PUBLIC;
CREATE FUNCTION sandbox_restore_gc_metadata(tenant uuid,restore uuid,namespace text,name text,uid uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE result jsonb;run public.restore_gc_runs;review public.restore_gc_reviews;
BEGIN
 IF tenant IS DISTINCT FROM public.sandbox_current_tenant_id() OR NOT public.sandbox_lock_restore_gc(tenant,restore) THEN RETURN NULL;END IF;
 SELECT * INTO run FROM public.restore_gc_runs WHERE tenant_id=tenant AND restore_id=restore;
 IF NOT FOUND OR run.status<>'RUNNING' OR run.lease_owner IS NULL OR run.lease_until<=clock_timestamp() THEN RETURN NULL;END IF;
 SELECT * INTO review FROM public.restore_gc_reviews WHERE tenant_id=tenant AND restore_id=restore AND id=run.review_id;
 IF NOT FOUND OR review.retain_until>clock_timestamp() OR review.valid_until<=clock_timestamp() THEN RETURN NULL;END IF;
 -- Acknowledgements cannot authorize metadata deletion. Both independent
 -- absence records must refer to their exact immutable dispatched resources.
 IF (SELECT count(*) FROM public.restore_gc_cloud_absences a JOIN public.restore_gc_dispatches dispatch
   ON dispatch.tenant_id=a.tenant_id AND dispatch.restore_id=a.restore_id AND dispatch.id=a.dispatch_id
   WHERE a.tenant_id=tenant AND a.restore_id=restore AND (
    (a.kind='RAW_DISK' AND dispatch.kind='DELETE_RAW_DISK' AND a.resource_id=review.raw_identity->'binding'->>'disk_id' AND dispatch.identity=review.raw_identity) OR
    (a.kind='SNAPSHOT' AND dispatch.kind='DELETE_SNAPSHOT' AND a.resource_id=review.snapshot_identity->'binding'->'scope'->>'snapshot_id' AND dispatch.identity=review.snapshot_identity)))<>2 THEN RETURN NULL;END IF;
 SELECT jsonb_build_object('tenant_id',r.tenant_id,'restore_id',r.id,'kind',i.kind,'namespace',i.namespace,'name',i.name,'uid',b.uid,
  'epoch',r.cluster_epoch,'review_id',review.id,'lease_token',run.lease_token,'lease_owner',run.lease_owner,
  'raw',to_jsonb(raw),'snapshot',to_jsonb(s),'delivery',to_jsonb(d),'expected',i.expected_object,
  'raw_claim',(SELECT claim.expected_object FROM public.restore_resource_intents claim WHERE claim.tenant_id=r.tenant_id AND claim.restore_id=r.id AND claim.kind='BLOCK_PVC'))
 INTO result FROM public.restores r
 JOIN public.restore_resource_intents i ON i.tenant_id=r.tenant_id AND i.restore_id=r.id
 JOIN public.restore_resource_bindings b ON b.tenant_id=i.tenant_id AND b.intent_id=i.id AND b.restore_id=r.id
 JOIN public.restore_block_receipts raw ON raw.tenant_id=r.tenant_id AND raw.restore_id=r.id
 JOIN public.restore_snapshot_receipts s ON s.tenant_id=r.tenant_id AND s.restore_id=r.id
 JOIN public.restore_delivery_receipts d ON d.tenant_id=r.tenant_id AND d.restore_id=r.id
 JOIN public.backup_snapshot_receipts source ON source.tenant_id=r.tenant_id AND source.backup_id=r.backup_id
 WHERE r.tenant_id=tenant AND r.id=restore AND i.namespace=sandbox_restore_gc_metadata.namespace AND i.name=sandbox_restore_gc_metadata.name AND b.uid=sandbox_restore_gc_metadata.uid
 AND i.kind IN('BLOCK_PVC','BLOCK_PV','RESTORED_SNAPSHOT','RESTORED_CONTENT','DELIVERY_SNAPSHOT','DELIVERY_CONTENT')
 AND r.cluster_epoch=review.cluster_epoch AND r.backup_id=review.source_backup_id
 AND r.cluster_epoch=(SELECT cluster_epoch FROM public.platform_configuration WHERE singleton)
 AND raw.cloud_disk<>d.cloud_disk AND s.cloud_snapshot=d.cloud_snapshot AND s.cloud_snapshot<>source.cloud_snapshot
 AND b.uid NOT IN(d.pvc_uid,d.pv_uid,source.snapshot_uid,source.content_uid)
 AND review.raw_identity->'binding'->>'disk_id'=raw.cloud_disk
 AND review.snapshot_identity->'binding'->'scope'->>'snapshot_id'=s.cloud_snapshot
 AND review.target_identity->'binding'->>'disk_id'=d.cloud_disk;
 -- The lock helper may have waited. Its durable writer predicate and the
 -- final clock check must remain inside this definer, including direct calls.
 IF result IS NULL OR run.lease_until<=clock_timestamp() OR review.valid_until<=clock_timestamp()
  OR NOT public.sandbox_restore_gc_writers_closed(tenant,restore) THEN RETURN NULL;END IF;
 -- Budget is separate from the immutable pin. The receiver conservatively
 -- deducts SQL/COMMIT ACK wait using a reader-before-I/O monotonic Instant.
 RETURN jsonb_build_object('pin',result,'valid_for_us',
  floor(extract(epoch FROM(LEAST(run.lease_until,review.valid_until)-clock_timestamp()))*1000000)::bigint);
END $$;
REVOKE ALL ON FUNCTION sandbox_restore_gc_metadata(uuid,uuid,text,text,uuid) FROM PUBLIC;
