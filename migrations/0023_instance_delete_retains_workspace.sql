-- Instance DELETE destroys compute only. Workspace destruction is a separate
-- authorization and evidence protocol; neither storage nor its quota is released.
ALTER TABLE termination_cleanup_receipts DROP CONSTRAINT termination_cleanup_receipts_completion_check;
ALTER TABLE termination_cleanup_receipts ADD CONSTRAINT termination_cleanup_receipts_completion_check
 CHECK(completion IN('STOPPED','RESTART_QUEUED','RESTART_BLOCKED','AWAITING_VOLUME_DELETION','INSTANCE_DELETED'));

CREATE FUNCTION sandbox_guard_instance_deletion() RETURNS trigger
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
     AND c.old_pod_uid=p.pod_uid) THEN
   RAISE EXCEPTION 'instance deletion requires exact immutable termination and cleanup' USING ERRCODE='42501';END IF;
 IF EXISTS(SELECT 1 FROM public.executions e WHERE e.tenant_id=OLD.tenant_id AND e.instance_id=OLD.id AND e.slot_held)
   OR EXISTS(SELECT 1 FROM public.quota_reservations r JOIN public.quota_accounts q
       ON q.tenant_id=r.tenant_id AND q.id=r.quota_account_id
     WHERE r.tenant_id=OLD.tenant_id AND r.resource_id=OLD.id AND r.status IN('PENDING','ALLOCATED')
       AND q.dimension IN('CPU_MILLIS','MEMORY_MIB','INSTANCES','EXECUTIONS')) THEN
   RAISE EXCEPTION 'instance deletion cannot retain active activity or compute reservations' USING ERRCODE='42501';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER instance_deletion_guard BEFORE UPDATE ON instances
 FOR EACH ROW EXECUTE FUNCTION sandbox_guard_instance_deletion();
REVOKE ALL ON FUNCTION sandbox_guard_instance_deletion() FROM PUBLIC;
