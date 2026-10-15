-- No new inventory table and no runtime write permission. Observation opt-in is
-- telemetry availability, not a grant: the existing installation read grant is
-- still the only product authority, independently checked for every query.
CREATE FUNCTION sandbox_node_image_binding(issuer text,subject text,client text,token_exp bigint,requested_node uuid)
RETURNS TABLE(installation_id uuid,cluster_epoch uuid,grant_id uuid,grant_expires_at timestamptz,
 runtime_node_id uuid,node_uid uuid,host_boot_id uuid,profile_sha256 text,certified_until timestamptz)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 WITH access AS MATERIALIZED (
  SELECT * FROM public.sandbox_node_image_access($1,$2,$3,$4)
 ), target AS MATERIALIZED (
  SELECT n.id,n.cluster_epoch,n.node_uid,n.boot_id,n.profile_sha256,
    max(e.certification_expires_at) AS certified_until
  FROM public.runtime_nodes n JOIN public.runtime_node_enrollments e ON e.runtime_node_id=n.id AND e.cluster_epoch=n.cluster_epoch
  WHERE n.id=$5 AND n.enabled AND e.certification_reviewed_at<=clock_timestamp()+interval '2 seconds'
    AND e.certification_expires_at>clock_timestamp()
  GROUP BY n.id
 )
 SELECT a.installation_id,a.cluster_epoch,a.grant_id,a.expires_at,
   n.id,n.node_uid,n.boot_id,n.profile_sha256,n.certified_until
 FROM access a LEFT JOIN target n ON n.cluster_epoch=a.cluster_epoch AND n.certified_until>clock_timestamp()
 WHERE a.expires_at>clock_timestamp() AND $4>extract(epoch FROM clock_timestamp())
$$;
REVOKE ALL ON FUNCTION sandbox_node_image_binding(text,text,text,bigint,uuid) FROM PUBLIC;
