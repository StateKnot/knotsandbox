-- Backup scheduling uses its own stopped-source intent, never the ordinary
-- workload's RUNNING lifecycle. Exact host enrollment and expiry still apply.
CREATE FUNCTION sandbox_backup_node_binding(tenant uuid,attempt uuid,node_uid uuid,node_name text,boot uuid,profile text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT COALESCE($1=public.sandbox_current_tenant_id() AND EXISTS(
  SELECT 1 FROM public.backup_attempts a JOIN public.backups b ON b.tenant_id=a.tenant_id AND b.id=a.backup_id
   JOIN public.backup_job_contexts c ON c.tenant_id=a.tenant_id AND c.attempt_id=a.id
   JOIN public.backup_pod_admissions admitted ON admitted.tenant_id=a.tenant_id AND admitted.attempt_id=a.id
   CROSS JOIN public.platform_configuration cfg JOIN public.runtime_nodes n ON n.cluster_epoch=cfg.cluster_epoch
  WHERE a.tenant_id=$1 AND a.id=$2 AND cfg.singleton AND b.cluster_epoch=cfg.cluster_epoch
   AND public.sandbox_backup_authorized($1,b.id,false) AND c.deadline>clock_timestamp()
   AND ((a.stage='CAPTURE' AND b.status IN('CAPTURE_PENDING','CAPTURE_RUNNING')) OR(a.stage='SEAL' AND b.status IN('SEAL_PENDING','SEAL_RUNNING')))
   AND n.node_uid=$3 AND n.node_name=$4 AND n.boot_id=$5 AND n.profile_sha256=$6 AND n.enabled
   AND public.sandbox_node_certified_until(n.id)>=c.deadline
 ),false);
$$;
REVOKE ALL ON FUNCTION sandbox_backup_node_binding(uuid,uuid,uuid,text,uuid,text) FROM PUBLIC;
-- Existing assigned-node status may continue after TTL/certification expiry to
-- finish graceful shutdown. It cannot authorize Run/Create/Start or new binding.
CREATE FUNCTION sandbox_backup_node_observation(tenant uuid,attempt uuid,node_uid uuid,node_name text,boot uuid,profile text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT COALESCE(public.sandbox_backup_node_binding($1,$2,$3,$4,$5,$6) OR
 ($1=public.sandbox_current_tenant_id() AND EXISTS(
  SELECT 1 FROM public.backup_launch_permits p JOIN public.backups b ON b.tenant_id=p.tenant_id AND b.id=p.backup_id
   JOIN public.runtime_nodes n ON n.id=p.runtime_node_id CROSS JOIN public.platform_configuration cfg
  WHERE p.tenant_id=$1 AND p.attempt_id=$2 AND cfg.singleton AND b.cluster_epoch=cfg.cluster_epoch
   AND n.cluster_epoch=cfg.cluster_epoch AND n.node_uid=$3 AND n.node_name=$4 AND n.boot_id=$5 AND n.profile_sha256=$6
   AND b.status IN('CAPTURE_PENDING','CAPTURE_RUNNING','CAPTURE_CLOSING','SEAL_PENDING','SEAL_RUNNING','SEAL_CLOSING')
 )),false);
$$;
REVOKE ALL ON FUNCTION sandbox_backup_node_observation(uuid,uuid,uuid,text,uuid,text) FROM PUBLIC;
