-- PRIVATE DRAFT; not a formal migration or production activation.
-- Historical isolated writer identity is not a current create/start grant.
-- Ordinary target NEVER_AUTHORIZED closures do not describe this restore VM.
CREATE FUNCTION sandbox_restore_control_cleanup(tenant uuid,restore uuid,kind text,name text,uid uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE recorded public.restores;active uuid;result jsonb;
BEGIN
 IF tenant IS DISTINCT FROM public.sandbox_current_tenant_id()
  OR restore IS NULL OR uid IS NULL OR uid='00000000-0000-0000-0000-000000000000'
  OR kind NOT IN('JOB','CONFIG','POD') OR name IS NULL THEN RETURN NULL;END IF;
 SELECT * INTO recorded FROM public.restores WHERE tenant_id=tenant AND id=restore;
 IF NOT FOUND THEN RETURN NULL;END IF;
 PERFORM 1 FROM public.workspaces w WHERE w.tenant_id=tenant AND w.id=recorded.workspace_id FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL;END IF;
 SELECT i.active_operation_id INTO active FROM public.instances i
  WHERE i.tenant_id=tenant AND i.id=recorded.instance_id AND i.workspace_id=recorded.workspace_id FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL;END IF;
 PERFORM 1 FROM public.operations o WHERE o.tenant_id=tenant AND(o.id=recorded.operation_id OR o.id=active) ORDER BY o.id FOR UPDATE;
 SELECT * INTO recorded FROM public.restores WHERE tenant_id=tenant AND id=restore FOR UPDATE;
 PERFORM b.intent_id FROM public.restore_resource_bindings b
  WHERE b.tenant_id=tenant AND b.restore_id=restore ORDER BY b.intent_id FOR SHARE;
 -- One read point pins complete durable identity. No grant/profile/lease or
 -- successful I/O/delivery requirement is imported into this historical path.
 WITH controls AS MATERIALIZED (
  SELECT i.kind,i.namespace,i.name,i.expected_object,b.uid
  FROM public.restore_resource_intents i JOIN public.restore_resource_bindings b
   ON b.tenant_id=i.tenant_id AND b.restore_id=i.restore_id AND b.intent_id=i.id
  WHERE i.tenant_id=tenant AND i.restore_id=restore AND i.kind IN('JOB','CONFIG','POD')
 ), authority AS (
  SELECT r.id,r.tenant_id,r.status,r.cluster_epoch,r.backup_id,r.source_manifest_sha256,
   r.source_identity,r.source_identity->>'source_pvc_uid' AS source_pvc_uid,c.context,p.id AS permit_id,p.request,
   job.uid AS job_uid,pod.uid AS pod_uid,pod.name AS pod_name,
   proof.id AS proof_id,proof.evidence_sha256,proof.observed_at AS closed_at,
   cleanup.proof_id AS cleaned_proof_id,cleanup.pod_uid AS cleaned_pod_uid,
   cleanup.pvc_uid AS cleaned_pvc_uid,cleanup.pv_uid AS cleaned_pv_uid,cleanup.cloud_disk AS cleaned_disk,
   cleanup.pod_absent_at,cleanup.volume_checked_at
  FROM public.restores r
  JOIN public.operations o ON o.tenant_id=r.tenant_id AND o.id=r.operation_id
  JOIN public.restore_job_contexts c ON c.tenant_id=r.tenant_id AND c.restore_id=r.id
  JOIN public.restore_launch_permits p ON p.tenant_id=r.tenant_id AND p.restore_id=r.id AND p.operation_id=r.operation_id
  JOIN public.restore_block_receipts raw ON raw.tenant_id=r.tenant_id AND raw.restore_id=r.id
  JOIN public.restore_pod_admissions admitted ON admitted.tenant_id=r.tenant_id AND admitted.restore_id=r.id
  JOIN public.runtime_nodes node ON node.id=p.runtime_node_id AND node.cluster_epoch=r.cluster_epoch
  JOIN controls job ON job.kind='JOB' AND job.uid=admitted.job_uid AND job.namespace='sandbox-system'
  JOIN controls config ON config.kind='CONFIG' AND config.namespace='sandbox-system'
  JOIN controls pod ON pod.kind='POD' AND pod.namespace='sandbox-system'
  JOIN controls selected ON selected.kind=sandbox_restore_control_cleanup.kind
   AND selected.name=sandbox_restore_control_cleanup.name AND selected.uid=sandbox_restore_control_cleanup.uid
  LEFT JOIN public.restore_termination_proofs proof ON proof.tenant_id=p.tenant_id AND proof.restore_id=p.restore_id
   AND proof.permit_id=p.id AND proof.runtime_node_id=p.runtime_node_id
   AND proof.evidence->>'state'='TERMINATED' AND proof.evidence->>'challenge_id'=proof.challenge_id::text
   AND proof.evidence->'launch'=p.request->'launch' AND proof.evidence->'node'=p.request->'node'
   AND proof.evidence->'evidence'->>'journal_revision'=proof.journal_revision::text
  LEFT JOIN public.restore_cleanup_receipts cleanup ON cleanup.tenant_id=proof.tenant_id AND cleanup.restore_id=proof.restore_id
   AND cleanup.proof_id=proof.id AND cleanup.pod_uid=pod.uid
   AND cleanup.pvc_uid=raw.pvc_uid AND cleanup.pv_uid=raw.pv_uid AND cleanup.cloud_disk=raw.cloud_disk
  WHERE r.tenant_id=tenant AND r.id=restore AND o.kind='RESTORE'
   AND o.instance_id=r.instance_id AND o.workspace_id=r.workspace_id AND o.project_id=r.target_project_id
   AND r.status IN('RESTORE_CLOSING','SNAPSHOT_PENDING','DELIVERY_PENDING','AVAILABLE','CANCELLED')
   AND EXISTS(SELECT 1 FROM public.platform_configuration cfg WHERE cfg.singleton AND cfg.cluster_epoch=r.cluster_epoch)
   AND c.context->>'stage'='RESTORE' AND c.context->>'attempt_id'=r.id::text
   AND c.context->>'tenant_id'=r.tenant_id::text AND c.context->>'project_id'=r.source_project_id::text
   AND c.context->>'backup_id'=r.backup_id::text AND c.context->>'cluster_epoch'=r.cluster_epoch::text
   AND c.context->>'expected_manifest_sha256'=r.source_manifest_sha256
   AND p.request->'launch'->'purpose'->>'kind'='BACKUP' AND p.request->'launch'->'purpose'->>'stage'='RESTORE'
   AND p.request->'launch'->'purpose'->>'attempt_id'=r.id::text AND p.request->'launch'->'purpose'->>'backup_id'=r.backup_id::text
   AND p.request->'launch'->'purpose'->>'job_uid'=job.uid::text
   AND p.request->'launch'->'purpose'->>'image_ref'=c.context->>'image'
   AND p.request->'launch'->'purpose'->>'source_pvc_uid'=r.source_identity->>'source_pvc_uid'
   AND p.request->>'permit_id'=p.id::text
   AND p.request->'launch'->>'pod_uid'=pod.uid::text AND p.request->'launch'->>'pod_name'=pod.name
   AND p.request->'launch'->>'namespace'=pod.namespace AND p.request->'launch'->>'launch_id'=r.id::text
   AND p.request->'launch'->>'generation'='1' AND p.request->'launch'->>'tenant_id'=r.tenant_id::text
   AND p.request->'launch'->>'project_id'=r.target_project_id::text AND p.request->'launch'->>'workspace_id'=r.workspace_id::text
   AND p.request->'launch'->>'instance_id'=r.instance_id::text AND p.request->'launch'->>'pvc_uid'=raw.pvc_uid::text
   AND p.request->'launch'->>'pv_name'=raw.pv_name
   AND p.request->'launch'->>'pv_uid'=raw.pv_uid::text AND p.request->'launch'->>'csi_volume_handle'=raw.cloud_disk
   AND p.request->'node'->>'cluster_epoch'=r.cluster_epoch::text AND p.request->'node'->>'node_uid'=node.node_uid::text
   AND p.request->'node'->>'node_name'=node.node_name AND p.request->'node'->>'boot_id'=node.boot_id::text
   AND p.request->'node'->>'profile_sha256'=node.profile_sha256
   -- Terminal lineage cannot acquire a new close intent. It is eligible only
   -- for already independently closed, exact leftover control objects.
   AND(r.status IN('RESTORE_CLOSING','SNAPSHOT_PENDING','DELIVERY_PENDING') OR(proof.id IS NOT NULL AND cleanup.proof_id IS NOT NULL))
 ) SELECT jsonb_build_object('restore_id',a.id,'tenant_id',a.tenant_id,'status',a.status,'cluster_epoch',a.cluster_epoch,
   'source_identity',a.source_identity,'source_pvc_uid',a.source_pvc_uid,'source_manifest_sha256',a.source_manifest_sha256,
   'context',a.context,'permit_id',a.permit_id,'permit',a.request,'job_uid',a.job_uid,
   'bindings',(SELECT jsonb_object_agg(controls.kind,jsonb_build_object('namespace',controls.namespace,'name',controls.name,'uid',controls.uid,'expected',controls.expected_object)) FROM controls),
   'proof',CASE WHEN a.proof_id IS NOT NULL THEN jsonb_build_object('id',a.proof_id,'digest',a.evidence_sha256,'closed_at',a.closed_at) END,
   'cleanup',CASE WHEN a.cleaned_proof_id IS NOT NULL THEN jsonb_build_object('proof_id',a.cleaned_proof_id,'pod_uid',a.cleaned_pod_uid,
     'pvc_uid',a.cleaned_pvc_uid,'pv_uid',a.cleaned_pv_uid,'cloud_disk',a.cleaned_disk,
     'pod_absent_at',a.pod_absent_at,'volume_checked_at',a.volume_checked_at) END)
 INTO result FROM authority a;
 IF NOT FOUND OR result IS NULL OR octet_length(result::text)>1048576 THEN RETURN NULL;END IF;
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION sandbox_restore_control_cleanup(uuid,uuid,text,text,uuid) FROM PUBLIC;

-- Status is independently authorized by immutable Job identity. It cannot
-- start a writer, remove protection, delete controls or settle accounting.
CREATE FUNCTION sandbox_restore_job_status(tenant uuid,restore uuid,name text,uid uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE recorded public.restores;active uuid;result jsonb;
BEGIN
 IF tenant IS DISTINCT FROM public.sandbox_current_tenant_id() OR restore IS NULL OR name IS NULL
  OR uid IS NULL OR uid='00000000-0000-0000-0000-000000000000' THEN RETURN NULL;END IF;
 SELECT * INTO recorded FROM public.restores WHERE tenant_id=tenant AND id=restore;
 IF NOT FOUND THEN RETURN NULL;END IF;
 PERFORM 1 FROM public.workspaces w WHERE w.tenant_id=tenant AND w.id=recorded.workspace_id FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL;END IF;
 SELECT i.active_operation_id INTO active FROM public.instances i
  WHERE i.tenant_id=tenant AND i.id=recorded.instance_id AND i.workspace_id=recorded.workspace_id FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL;END IF;
 PERFORM 1 FROM public.operations o WHERE o.tenant_id=tenant AND(o.id=recorded.operation_id OR o.id=active) ORDER BY o.id FOR UPDATE;
 SELECT * INTO recorded FROM public.restores WHERE tenant_id=tenant AND id=restore FOR UPDATE;
 PERFORM b.intent_id FROM public.restore_resource_bindings b JOIN public.restore_resource_intents i
  ON i.tenant_id=b.tenant_id AND i.id=b.intent_id AND i.restore_id=b.restore_id
  WHERE b.tenant_id=tenant AND b.restore_id=restore AND i.kind='JOB' FOR SHARE OF b;
 SELECT jsonb_build_object('restore_id',r.id,'tenant_id',r.tenant_id,'cluster_epoch',r.cluster_epoch,
   'source_manifest_sha256',r.source_manifest_sha256,'source_identity',r.source_identity,'context',c.context,
   'operation_id',r.operation_id,'workspace_id',r.workspace_id,'instance_id',r.instance_id,
   'source_project_id',r.source_project_id,'target_project_id',r.target_project_id,
   'job',jsonb_build_object('namespace',i.namespace,'name',i.name,'uid',b.uid,'expected',i.expected_object)) INTO result
 FROM public.restores r
 JOIN public.operations o ON o.tenant_id=r.tenant_id AND o.id=r.operation_id
 JOIN public.workspaces w ON w.tenant_id=r.tenant_id AND w.id=r.workspace_id AND w.project_id=r.target_project_id
 JOIN public.instances instance ON instance.tenant_id=r.tenant_id AND instance.id=r.instance_id
  AND instance.workspace_id=r.workspace_id AND instance.project_id=r.target_project_id
 JOIN public.restore_job_contexts c ON c.tenant_id=r.tenant_id AND c.restore_id=r.id
 JOIN public.restore_resource_intents i ON i.tenant_id=r.tenant_id AND i.restore_id=r.id AND i.kind='JOB'
 JOIN public.restore_resource_bindings b ON b.tenant_id=i.tenant_id AND b.restore_id=i.restore_id AND b.intent_id=i.id
 WHERE r.tenant_id=tenant AND r.id=restore AND i.name=sandbox_restore_job_status.name AND b.uid=sandbox_restore_job_status.uid
  AND i.namespace='sandbox-system' AND i.expected_object IS NOT NULL
  AND o.kind='RESTORE' AND o.instance_id=r.instance_id AND o.workspace_id=r.workspace_id AND o.project_id=r.target_project_id
  AND r.status IN('RESTORE_PENDING','RESTORE_RUNNING','RESTORE_CLOSING','SNAPSHOT_PENDING','DELIVERY_PENDING','AVAILABLE','CANCELLED')
  AND EXISTS(SELECT 1 FROM public.platform_configuration cfg WHERE cfg.singleton AND cfg.cluster_epoch=r.cluster_epoch)
  AND c.context->>'stage'='RESTORE' AND c.context->>'attempt_id'=r.id::text AND c.context->>'tenant_id'=r.tenant_id::text
  AND c.context->>'project_id'=r.source_project_id::text AND c.context->>'backup_id'=r.backup_id::text
  AND c.context->>'cluster_epoch'=r.cluster_epoch::text AND c.context->>'expected_manifest_sha256'=r.source_manifest_sha256;
 IF NOT FOUND OR result IS NULL OR octet_length(result::text)>1048576 THEN RETURN NULL;END IF;
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION sandbox_restore_job_status(uuid,uuid,text,uuid) FROM PUBLIC;
