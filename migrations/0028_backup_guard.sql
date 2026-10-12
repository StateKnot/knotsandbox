-- Fix PL/pgSQL variable/alias ambiguity discovered by actual UPDATE integration test.
CREATE OR REPLACE FUNCTION sandbox_guard_cold_backup() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
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
    OR (SELECT count(DISTINCT a.stage) FROM public.backup_attempts a JOIN public.backup_termination_proofs proof ON proof.tenant_id=a.tenant_id AND proof.attempt_id=a.id
      JOIN public.backup_cleanup_receipts c ON c.tenant_id=proof.tenant_id AND c.proof_id=proof.id
      WHERE a.tenant_id=NEW.tenant_id AND a.backup_id=NEW.id AND a.stage IN('CAPTURE','SEAL'))<>2) THEN
   RAISE EXCEPTION 'available backup requires independently verified vault and both closed attempts' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;END $$;

-- Each retry obtains a fresh bounded host challenge; proofs stay append-only.
ALTER TABLE backup_termination_proofs DROP CONSTRAINT backup_termination_proofs_attempt_id_key;
CREATE INDEX backup_proofs_attempt ON backup_termination_proofs(tenant_id,attempt_id,recorded_at DESC);
