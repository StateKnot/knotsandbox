-- A previously accepted safety STOP must not make a never-started CREATE
-- undeletable. This candidate check grants no execution/termination proof.
-- The API calls it only while holding workspace -> instance locks.
CREATE FUNCTION sandbox_never_authorized_stop_candidate(tenant uuid,instance uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT COALESCE($1=public.sandbox_current_tenant_id() AND EXISTS(
  SELECT 1 FROM public.instances i
  JOIN public.operations o ON o.tenant_id=i.tenant_id AND o.id=i.active_operation_id
    AND o.instance_id=i.id AND o.workspace_id=i.workspace_id
  JOIN public.launch_authority_births b ON b.tenant_id=i.tenant_id AND b.instance_id=i.id
    AND b.project_id=i.project_id AND b.workspace_id=i.workspace_id
    AND b.generation=i.runtime_generation AND b.launch_id=i.launch_id AND b.cluster_epoch=i.cluster_epoch
  JOIN public.launch_guard_contracts g ON g.id=b.contract_id AND g.cluster_epoch=b.cluster_epoch
  CROSS JOIN public.platform_configuration cfg
  WHERE i.tenant_id=$1 AND i.id=$2 AND i.desired_state='STOPPED' AND i.observed_state<>'DELETED'
    AND NOT i.slot_held AND o.kind='STOP' AND o.status IN('QUEUED','RUNNING','WAITING')
    AND cfg.singleton AND cfg.cluster_epoch=i.cluster_epoch AND b.born_at>=g.activated_at AND b.born_at<g.valid_until
    AND NOT EXISTS(SELECT 1 FROM public.launch_permits p WHERE p.tenant_id=i.tenant_id AND p.instance_id=i.id
      AND p.generation=i.runtime_generation AND p.launch_id=i.launch_id AND p.cluster_epoch=i.cluster_epoch)
    AND NOT EXISTS(SELECT 1 FROM public.executions e WHERE e.tenant_id=i.tenant_id AND e.instance_id=i.id
      AND (e.slot_held OR e.dispatch_attempt_id IS NOT NULL AND e.runtime_generation=i.runtime_generation))
 ),false);
$$;
REVOKE ALL ON FUNCTION sandbox_never_authorized_stop_candidate(uuid,uuid) FROM PUBLIC;
