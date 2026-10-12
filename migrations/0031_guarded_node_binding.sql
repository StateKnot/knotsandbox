-- A scheduling label is not proof of the host CRI contract. This predicate is
-- called with a fresh authenticated Node GET and exact current workload scope.
CREATE FUNCTION sandbox_guarded_node_binding(tenant uuid,instance uuid,node_uid uuid,node_name text,boot uuid,profile text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT COALESCE($1=public.sandbox_current_tenant_id() AND EXISTS(
  SELECT 1 FROM public.instances i CROSS JOIN public.platform_configuration cfg
  JOIN public.runtime_nodes n ON n.cluster_epoch=cfg.cluster_epoch
  WHERE i.tenant_id=$1 AND i.id=$2 AND cfg.singleton AND NOT cfg.safe_mode
    AND i.cluster_epoch=cfg.cluster_epoch AND i.desired_state='RUNNING' AND i.stop_accepted_at IS NULL
    AND i.compute_lease_expires_at>clock_timestamp()
    AND n.node_uid=$3 AND n.node_name=$4 AND n.boot_id=$5 AND n.profile_sha256=$6 AND n.enabled
    AND public.sandbox_node_certified_until(n.id)>=i.compute_lease_expires_at
    AND (NOT EXISTS(SELECT 1 FROM public.launch_authority_births b WHERE b.tenant_id=i.tenant_id AND b.instance_id=i.id
       AND b.generation=i.runtime_generation AND b.launch_id=i.launch_id AND b.cluster_epoch=i.cluster_epoch)
      OR EXISTS(SELECT 1 FROM public.launch_guard_contracts c WHERE c.cluster_epoch=i.cluster_epoch AND n.id=ANY(c.runtime_node_ids)
         AND c.valid_until>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM public.launch_guard_contract_revocations r WHERE r.contract_id=c.id)))
    AND NOT EXISTS(SELECT 1 FROM public.never_authorized_closures c WHERE c.tenant_id=i.tenant_id AND c.instance_id=i.id
      AND c.generation=i.runtime_generation AND c.launch_id=i.launch_id AND c.cluster_epoch=i.cluster_epoch)
 ),false);
$$;
REVOKE ALL ON FUNCTION sandbox_guarded_node_binding(uuid,uuid,uuid,text,uuid,text) FROM PUBLIC;
