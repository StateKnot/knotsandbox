-- PRIVATE DRAFT ONLY. Apply after private base 0038 and node topology companion.
-- Never a formal migration, listener activation or media/VM/absence permit.
-- These two readers are only the SQL half of strict SELECT/PROVISIONER/RESET
-- admission; the consuming path still needs actual PVC/Job/Pod/Node/CSI/cloud
-- reads, exact caller/diff checks, final pin equality and original ACK budget.

-- Fixed RESTORE context parser. It grants no authority or source read itself.
CREATE FUNCTION sandbox_restore_raw_scheduling_config(context_json jsonb) RETURNS jsonb
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $$
DECLARE config_json jsonb;field_name text;
BEGIN
 IF context_json IS NULL OR jsonb_typeof(context_json) IS DISTINCT FROM 'object'
  OR NOT(context_json ?& ARRAY['tenant_id','project_id','backup_id','attempt_id','cluster_epoch','stage','image','certification_sha256','deadline_seconds','config_json','password_secret','signing_private_secret','signing_public_secret','block_pvc','expected_manifest_sha256'])
  OR(SELECT count(*) FROM jsonb_object_keys(context_json) AS keys(key_name))<>15 THEN RETURN NULL;END IF;
 FOREACH field_name IN ARRAY ARRAY['tenant_id','project_id','backup_id','attempt_id','cluster_epoch','stage','image','certification_sha256','config_json','password_secret','signing_private_secret','signing_public_secret','block_pvc','expected_manifest_sha256'] LOOP
  IF jsonb_typeof(context_json->field_name) IS DISTINCT FROM 'string' THEN RETURN NULL;END IF;
 END LOOP;
 IF jsonb_typeof(context_json->'deadline_seconds') IS DISTINCT FROM 'number'
  OR(context_json->'deadline_seconds')::text !~ '^[1-9][0-9]{0,3}$'
  OR octet_length(context_json->>'config_json')>65536 THEN RETURN NULL;END IF;
 IF(context_json->>'deadline_seconds')::integer NOT BETWEEN 1 AND 7200 THEN RETURN NULL;END IF;
 BEGIN config_json:=(context_json->>'config_json')::jsonb;
 EXCEPTION WHEN invalid_text_representation THEN RETURN NULL;END;
 IF jsonb_typeof(config_json) IS DISTINCT FROM 'object'
  OR jsonb_typeof(config_json->'deadline') IS DISTINCT FROM 'string'
  OR public.sandbox_restore_topology_timestamp_valid(config_json->>'deadline') IS NOT TRUE THEN RETURN NULL;END IF;
 RETURN config_json;
END $$;
REVOKE ALL ON FUNCTION sandbox_restore_raw_scheduling_config(jsonb) FROM PUBLIC;

-- Private common implementation, not an externally selectable policy/action.
CREATE FUNCTION sandbox_restore_raw_scheduling_envelope(requested_tenant uuid,requested_restore uuid,requested_node_name text,require_node boolean)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE located public.restores;active uuid;result jsonb;
BEGIN
 IF requested_tenant IS NULL OR requested_restore IS NULL OR require_node IS NULL
  OR requested_tenant='00000000-0000-0000-0000-000000000000'
  OR requested_restore='00000000-0000-0000-0000-000000000000'
  OR requested_tenant IS DISTINCT FROM public.sandbox_current_tenant_id() THEN RETURN NULL;END IF;
 IF require_node THEN
  IF requested_node_name IS NULL OR char_length(requested_node_name) NOT BETWEEN 1 AND 253
   OR EXISTS(SELECT 1 FROM regexp_split_to_table(requested_node_name,'[.]') AS labels(label)
    WHERE char_length(label) NOT BETWEEN 1 AND 63 OR label !~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$') THEN RETURN NULL;END IF;
 ELSIF requested_node_name IS NOT NULL THEN RETURN NULL;END IF;
 SELECT r.* INTO located FROM public.restores AS r WHERE r.tenant_id=requested_tenant AND r.id=requested_restore;
 IF NOT FOUND THEN RETURN NULL;END IF;
 PERFORM w.id FROM public.workspaces AS w WHERE w.tenant_id=requested_tenant AND w.id=located.workspace_id FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL;END IF;
 SELECT i.active_operation_id INTO active FROM public.instances AS i
  WHERE i.tenant_id=requested_tenant AND i.id=located.instance_id AND i.workspace_id=located.workspace_id FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL;END IF;
 PERFORM o.id FROM public.operations AS o WHERE o.tenant_id=requested_tenant
  AND(o.id=located.operation_id OR o.id=active) ORDER BY o.id FOR UPDATE;
 SELECT r.* INTO located FROM public.restores AS r WHERE r.tenant_id=requested_tenant AND r.id=requested_restore FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL;END IF;
 -- The restore fence serializes additions to the otherwise immutable resource set.
 PERFORM i.id FROM public.restore_resource_intents AS i
  WHERE i.tenant_id=requested_tenant AND i.restore_id=requested_restore ORDER BY i.id FOR SHARE;
 PERFORM b.intent_id FROM public.restore_resource_bindings AS b
  WHERE b.tenant_id=requested_tenant AND b.restore_id=requested_restore ORDER BY b.intent_id FOR SHARE;
 IF require_node THEN
  -- node_name is a locator only and is not unique in this inventory. Never
  -- pick an arbitrary row by LIMIT1; lock all matching current candidates.
  PERFORM n.id FROM public.runtime_nodes AS n WHERE n.cluster_epoch=located.cluster_epoch
   AND n.node_name=requested_node_name AND n.enabled ORDER BY n.id FOR SHARE;
  IF NOT FOUND THEN RETURN NULL;END IF;
 END IF;
 WITH moment AS MATERIALIZED(SELECT clock_timestamp() AS now_at),
 base AS MATERIALIZED(
  SELECT r,o,bp,cert,backup,c,admitted,pvc,pvc_binding,pv,config,config_binding,job,job_binding,pod,pod_binding,
   r.tenant_id,o.actor_principal_id,r.source_project_id,r.target_project_id,moment.now_at,
   jsonb_build_object('record',to_jsonb(r),'cloud_settings',bp.settings,'target_namespace',target.runtime_namespace,
    'vault',jsonb_build_object('verified',to_jsonb(verified),'source',to_jsonb(source_vault)),
    'operation_identity',jsonb_build_object('id',o.id,'tenant_id',o.tenant_id,'project_id',o.project_id,
     'instance_id',o.instance_id,'workspace_id',o.workspace_id,'kind',o.kind,'actor_principal_id',o.actor_principal_id,
     'request_id',o.request_id,'lease_owner',o.lease_owner,'lease_token',o.lease_token),
    'authz_identity',jsonb_build_object('tenant_version',tenant.authz_version,'principal_version',principal.authz_version,
     'source_project_version',source.authz_version,'target_project_version',target.authz_version,
     'instance_spec_version',instance.spec_version,'template_id',template.id,'template_version',template.version,
     'security_id',security.id,'security_version',security.version),
    'job_context',to_jsonb(c),'pod_admission',to_jsonb(admitted),
    'resource_identities',jsonb_build_object(
     'BLOCK_PVC',jsonb_build_object('intent',to_jsonb(pvc),'binding',to_jsonb(pvc_binding)),
     'BLOCK_PV',jsonb_build_object('intent',to_jsonb(pv),'binding',NULL),
     'CONFIG',jsonb_build_object('intent',to_jsonb(config),'binding',to_jsonb(config_binding)),
     'JOB',jsonb_build_object('intent',to_jsonb(job),'binding',to_jsonb(job_binding)),
     'POD',jsonb_build_object('intent',to_jsonb(pod),'binding',to_jsonb(pod_binding)))) AS base_pin,
   LEAST(r.deadline,c.deadline,o.deadline,o.lease_until,bp.certified_until,cert.certified_until,
    backup.retention_until-interval '5 minutes') AS resource_until
  FROM public.restores AS r CROSS JOIN moment
  JOIN public.backups AS backup ON backup.tenant_id=r.tenant_id AND backup.id=r.backup_id AND backup.project_id=r.source_project_id
  JOIN public.backup_profiles AS bp ON bp.id=r.profile_id
  JOIN public.restore_profile_certifications AS cert ON cert.profile_id=r.profile_id AND cert.cluster_epoch=r.cluster_epoch
  JOIN public.operations AS o ON o.tenant_id=r.tenant_id AND o.id=r.operation_id AND o.project_id=r.target_project_id
   AND o.instance_id=r.instance_id AND o.workspace_id=r.workspace_id AND o.kind='RESTORE'
  JOIN public.tenants AS tenant ON tenant.id=r.tenant_id
  JOIN public.principals AS principal ON principal.id=o.actor_principal_id
  JOIN public.projects AS source ON source.tenant_id=r.tenant_id AND source.id=r.source_project_id
  JOIN public.projects AS target ON target.tenant_id=r.tenant_id AND target.id=r.target_project_id
  JOIN public.instances AS instance ON instance.tenant_id=r.tenant_id AND instance.id=r.instance_id
   AND instance.project_id=r.target_project_id AND instance.workspace_id=r.workspace_id
  JOIN public.workspaces AS workspace ON workspace.tenant_id=r.tenant_id AND workspace.id=r.workspace_id AND workspace.project_id=r.target_project_id
  JOIN public.template_versions AS template ON template.tenant_id=instance.tenant_id AND template.id=instance.template_version_id AND template.status='APPROVED'
  JOIN public.security_policy_versions AS security ON security.tenant_id=instance.tenant_id AND security.id=instance.security_policy_version_id AND security.status='APPROVED'
  JOIN public.restore_vault_receipts AS verified ON verified.tenant_id=r.tenant_id AND verified.restore_id=r.id AND verified.backup_id=r.backup_id
   AND verified.manifest_sha256=r.source_manifest_sha256
  JOIN public.backup_vault_receipts AS source_vault ON source_vault.tenant_id=r.tenant_id AND source_vault.backup_id=r.backup_id
   AND source_vault.manifest_sha256=r.source_manifest_sha256 AND source_vault.manifest->'manifest'->'backup'=r.source_identity
   AND source_vault.manifest->>'signing_key_sha256'=verified.signing_key_sha256 AND source_vault.manifest->>'vault_endpoint'=verified.vault_endpoint
  JOIN public.restore_job_contexts AS c ON c.tenant_id=r.tenant_id AND c.restore_id=r.id
  JOIN LATERAL(SELECT public.sandbox_restore_raw_scheduling_config(c.context) AS config_json) AS parsed ON parsed.config_json IS NOT NULL
  JOIN public.restore_resource_intents AS pvc ON pvc.tenant_id=r.tenant_id AND pvc.restore_id=r.id AND pvc.kind='BLOCK_PVC'
  JOIN public.restore_resource_bindings AS pvc_binding ON pvc_binding.tenant_id=pvc.tenant_id AND pvc_binding.restore_id=pvc.restore_id AND pvc_binding.intent_id=pvc.id
  JOIN public.restore_resource_intents AS pv ON pv.tenant_id=r.tenant_id AND pv.restore_id=r.id AND pv.kind='BLOCK_PV'
  JOIN public.restore_resource_intents AS config ON config.tenant_id=r.tenant_id AND config.restore_id=r.id AND config.kind='CONFIG'
  JOIN public.restore_resource_bindings AS config_binding ON config_binding.tenant_id=config.tenant_id AND config_binding.restore_id=config.restore_id AND config_binding.intent_id=config.id
  JOIN public.restore_resource_intents AS job ON job.tenant_id=r.tenant_id AND job.restore_id=r.id AND job.kind='JOB'
  JOIN public.restore_resource_bindings AS job_binding ON job_binding.tenant_id=job.tenant_id AND job_binding.restore_id=job.restore_id AND job_binding.intent_id=job.id
  JOIN public.restore_resource_intents AS pod ON pod.tenant_id=r.tenant_id AND pod.restore_id=r.id AND pod.kind='POD'
  JOIN public.restore_resource_bindings AS pod_binding ON pod_binding.tenant_id=pod.tenant_id AND pod_binding.restore_id=pod.restore_id AND pod_binding.intent_id=pod.id
  JOIN public.restore_pod_admissions AS admitted ON admitted.tenant_id=r.tenant_id AND admitted.restore_id=r.id AND admitted.job_uid=job_binding.uid
  WHERE r.tenant_id=requested_tenant AND r.id=requested_restore AND r.status='RESTORE_PENDING'
   AND public.sandbox_restore_authorized(requested_tenant,requested_restore,true) IS TRUE
   AND o.status='RUNNING' AND o.lease_owner IS NOT NULL AND char_length(o.lease_owner) BETWEEN 1 AND 128 AND o.lease_token>0
   AND r.deadline IS NOT NULL AND c.deadline IS NOT NULL AND o.deadline IS NOT NULL AND o.lease_until IS NOT NULL
   AND bp.certified_until IS NOT NULL AND cert.certified_until IS NOT NULL AND backup.retention_until IS NOT NULL
   AND isfinite(r.deadline) AND isfinite(c.deadline) AND isfinite(o.deadline) AND isfinite(o.lease_until)
   AND isfinite(bp.certified_until) AND isfinite(cert.certified_until) AND isfinite(backup.retention_until)
   AND r.deadline>moment.now_at AND c.deadline>moment.now_at AND o.deadline>moment.now_at AND o.lease_until>moment.now_at
   AND c.deadline<=r.deadline AND bp.certified_until>=r.deadline AND cert.certified_until>=r.deadline
   AND backup.retention_until>=r.deadline+interval '5 minutes'
   AND tenant.enabled AND principal.enabled AND source.enabled AND target.enabled
   AND tenant.authz_version>0 AND principal.authz_version>0 AND source.authz_version>0 AND target.authz_version>0
   AND instance.spec_version>0 AND template.version>0 AND security.version>0
   AND target.runtime_namespace=workspace.namespace AND instance.namespace=workspace.namespace AND target.runtime_namespace<>'sandbox-system'
   AND pvc_binding.uid<>'00000000-0000-0000-0000-000000000000'
   AND config_binding.uid<>'00000000-0000-0000-0000-000000000000' AND job_binding.uid<>'00000000-0000-0000-0000-000000000000'
   AND pod_binding.uid<>'00000000-0000-0000-0000-000000000000' AND admitted.review_uid<>'00000000-0000-0000-0000-000000000000'
   AND pvc_binding.uid::text IS DISTINCT FROM r.source_identity->>'source_pvc_uid'
   AND pvc_binding.uid::text IS DISTINCT FROM r.source_identity->>'clone_pvc_uid'
   AND pvc.namespace='sandbox-system' AND pvc.name='sbx-bvol-'||r.id::text
   AND pvc.expected_object=jsonb_build_object('apiVersion','v1','kind','PersistentVolumeClaim',
    'metadata',jsonb_build_object('name',pvc.name,'namespace','sandbox-system',
     'labels',jsonb_build_object('sandbox.platform/backup-id',r.backup_id::text,'sandbox.platform/restore-id',r.id::text,
      'sandbox.platform/tenant-id',r.tenant_id::text,'sandbox.platform/project-id',r.target_project_id::text,
      'sandbox.platform/cluster-epoch',r.cluster_epoch::text,'app.kubernetes.io/managed-by','sandbox-backup')),
    'spec',jsonb_build_object('volumeMode','Block','accessModes',jsonb_build_array('ReadWriteOnce'),
     'storageClassName',r.storage_contract->'mapping'->'raw'->>'name',
     'resources',jsonb_build_object('requests',jsonb_build_object('storage',
      CASE WHEN r.size_gib%1024=0 THEN(r.size_gib/1024)::text||'Ti' ELSE r.size_gib::text||'Gi' END))))
   AND pv.namespace='' AND pv.name='disk-'||pvc_binding.uid::text AND pv.expected_object IS NULL
   AND config.namespace='sandbox-system' AND config.name='sbx-bcfg-'||r.id::text AND config.expected_object IS NOT NULL
   AND config.expected_object->'apiVersion'=to_jsonb('v1'::text) AND config.expected_object->'kind'=to_jsonb('ConfigMap'::text)
   AND config.expected_object->'metadata'->'name'=to_jsonb(config.name) AND config.expected_object->'metadata'->'namespace'=to_jsonb(config.namespace)
   AND config.expected_object->'immutable'='true'::jsonb AND config.expected_object->'data'->'job.json'=c.context->'config_json'
   AND job.namespace='sandbox-system' AND job.name='sbx-bkp-'||r.id::text||'-restore' AND job.expected_object IS NOT NULL
   AND job.expected_object->'apiVersion'=to_jsonb('batch/v1'::text) AND job.expected_object->'kind'=to_jsonb('Job'::text)
   AND job.expected_object->'metadata'->'name'=to_jsonb(job.name) AND job.expected_object->'metadata'->'namespace'=to_jsonb(job.namespace)
   AND job.expected_object->'spec'->'suspend'='true'::jsonb
   AND pod.namespace='sandbox-system' AND char_length(pod.name) BETWEEN 1 AND 63 AND pod.name~'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$' AND pod.expected_object IS NULL
   AND c.context->'tenant_id'=to_jsonb(r.tenant_id::text) AND c.context->'project_id'=to_jsonb(r.source_project_id::text)
   AND c.context->'backup_id'=to_jsonb(r.backup_id::text) AND c.context->'attempt_id'=to_jsonb(r.id::text)
   AND c.context->'cluster_epoch'=to_jsonb(r.cluster_epoch::text) AND c.context->'stage'=to_jsonb('RESTORE'::text)
   AND c.context->'image'=to_jsonb(bp.image) AND c.context->'certification_sha256'=to_jsonb(bp.certification_sha256)
   AND c.context->'block_pvc'=to_jsonb(pvc.name) AND c.context->'expected_manifest_sha256'=to_jsonb(r.source_manifest_sha256)
   AND c.context->'password_secret'=to_jsonb(bp.password_secret) AND c.context->'signing_private_secret'=to_jsonb(bp.signing_private_secret)
   AND c.context->'signing_public_secret'=to_jsonb(bp.signing_public_secret)
   AND(parsed.config_json-ARRAY['issuer','oidc_provider_arn','roles','runtime_certification_sha256','deadline'])=r.source_identity
   AND parsed.config_json->'issuer'=bp.settings->'issuer' AND parsed.config_json->'oidc_provider_arn'=bp.settings->'oidc_provider_arn'
   AND parsed.config_json->'roles'=bp.settings->'roles' AND parsed.config_json->'runtime_certification_sha256'=to_jsonb(bp.certification_sha256)
   AND CASE WHEN public.sandbox_restore_topology_timestamp_valid(parsed.config_json->>'deadline') IS TRUE
    THEN(parsed.config_json->>'deadline')::timestamptz=c.deadline ELSE false END
   AND NOT EXISTS(SELECT 1 FROM public.restore_resource_intents AS extra WHERE extra.tenant_id=r.tenant_id AND extra.restore_id=r.id AND extra.kind NOT IN('BLOCK_PVC','BLOCK_PV','CONFIG','JOB','POD'))
   AND NOT EXISTS(SELECT 1 FROM public.restore_resource_bindings AS bound WHERE bound.tenant_id=r.tenant_id AND bound.restore_id=r.id AND bound.intent_id=pv.id)
   AND NOT EXISTS(SELECT 1 FROM public.restore_block_receipts AS raw WHERE raw.tenant_id=r.tenant_id AND raw.restore_id=r.id)
   AND NOT EXISTS(SELECT 1 FROM public.restore_launch_permits AS permit WHERE permit.tenant_id=r.tenant_id AND permit.restore_id=r.id)
   AND NOT EXISTS(SELECT 1 FROM public.restore_launch_receipts AS receipt WHERE receipt.tenant_id=r.tenant_id AND receipt.restore_id=r.id)
   AND NOT EXISTS(SELECT 1 FROM public.restore_close_challenges AS challenge WHERE challenge.tenant_id=r.tenant_id AND challenge.restore_id=r.id)
   AND NOT EXISTS(SELECT 1 FROM public.restore_termination_proofs AS proof WHERE proof.tenant_id=r.tenant_id AND proof.restore_id=r.id)
   AND NOT EXISTS(SELECT 1 FROM public.restore_cleanup_receipts AS cleanup WHERE cleanup.tenant_id=r.tenant_id AND cleanup.restore_id=r.id)
   AND NOT EXISTS(SELECT 1 FROM public.restore_io_reports AS io WHERE io.tenant_id=r.tenant_id AND io.restore_id=r.id)
   AND NOT EXISTS(SELECT 1 FROM public.restore_snapshot_receipts AS snapshot WHERE snapshot.tenant_id=r.tenant_id AND snapshot.restore_id=r.id)
   AND NOT EXISTS(SELECT 1 FROM public.restore_delivery_receipts AS delivery WHERE delivery.tenant_id=r.tenant_id AND delivery.restore_id=r.id)
   AND NOT EXISTS(SELECT 1 FROM public.restore_artifact_cleanup_receipts AS artifact WHERE artifact.tenant_id=r.tenant_id AND artifact.restore_id=r.id)
 ), authority AS MATERIALIZED(
  SELECT base.tenant_id,base.actor_principal_id,base.source_project_id,base.target_project_id,base.now_at,
   base.base_pin||jsonb_build_object('node_identity',selected.node_identity,'node_topology',selected.node_topology) AS pin,
   LEAST(base.resource_until,CASE WHEN require_node THEN selected.topology_until ELSE base.resource_until END,
    CASE WHEN require_node THEN selected.enrollment_until ELSE base.resource_until END) AS resource_until
  FROM base LEFT JOIN LATERAL(
   SELECT jsonb_build_object('runtime_node_id',n.id,'cluster_epoch',n.cluster_epoch,'node_uid',n.node_uid,'node_name',n.node_name,
     'boot_id',n.boot_id,'profile_sha256',n.profile_sha256,'cloud_account_id',n.cloud_account_id,'region',n.region,
     'cloud_instance_id',n.cloud_instance_id,'private_ip',host(n.private_ip)) AS node_identity,
    to_jsonb(topology) AS node_topology,topology.certified_until AS topology_until,e.certification_expires_at AS enrollment_until
   FROM public.runtime_nodes AS n
   JOIN public.restore_node_topology_receipts AS topology ON topology.runtime_node_id=n.id
   JOIN public.runtime_node_enrollments AS e ON e.id=topology.enrollment_id AND e.runtime_node_id=n.id AND e.cluster_epoch=n.cluster_epoch
   WHERE require_node IS TRUE AND n.enabled AND n.cluster_epoch=(base.r).cluster_epoch AND n.node_name=requested_node_name
    AND(SELECT count(*) FROM public.runtime_nodes AS candidates WHERE candidates.enabled AND candidates.cluster_epoch=n.cluster_epoch AND candidates.node_name=requested_node_name)=1
    AND n.cloud_provider='alicloud' AND n.node_uid<>'00000000-0000-0000-0000-000000000000' AND n.boot_id<>'00000000-0000-0000-0000-000000000000'
    AND topology.restore_profile_id=(base.r).profile_id AND topology.restore_report_sha256=(base.cert).report_sha256
    AND topology.restore_report_sha256=(base.r).storage_contract->>'report_sha256'
    AND topology.terraform_output_sha256=e.terraform_output_sha256
    AND topology.infrastructure_sha256=(base.cert).report->'bindings'->>'infrastructure_sha256'
    AND topology.reviewed_at=(base.cert).reviewed_at
    AND topology.certified_until=LEAST((base.bp).certified_until,(base.cert).certified_until,e.certification_expires_at,(base.cert).reviewed_at+interval '30 days')
    AND public.sandbox_restore_node_topology_payload_valid(to_jsonb(topology)-'recorded_at') IS TRUE
    AND isfinite(topology.recorded_at) AND isfinite(topology.observed_at) AND isfinite(topology.reviewed_at) AND isfinite(topology.certified_until)
    AND isfinite(e.certification_reviewed_at) AND isfinite(e.certification_expires_at) AND isfinite(e.registered_at)
    AND topology.recorded_at<=base.now_at+interval '2 seconds'
    AND topology.observed_at BETWEEN topology.recorded_at-interval '10 seconds' AND topology.recorded_at+interval '2 seconds'
    AND topology.observed_at>=e.registered_at AND topology.observed_at>=n.registered_at
    AND topology.reviewed_at<=base.now_at+interval '2 seconds' AND e.certification_reviewed_at<=base.now_at+interval '2 seconds'
    AND topology.certified_until>base.now_at AND topology.certified_until>=(base.c).deadline
    AND e.certification_expires_at>base.now_at AND e.certification_expires_at>=(base.c).deadline
    AND topology.describe_instance->'account_id'=to_jsonb(n.cloud_account_id) AND topology.describe_instance->'region'=to_jsonb(n.region)
    AND topology.describe_instance->'instance_id'=to_jsonb(n.cloud_instance_id) AND topology.describe_instance->'private_ip'=to_jsonb(host(n.private_ip))
    AND topology.describe_instance->'account_id'=(base.bp).settings->'account_id'
    AND topology.describe_instance->'region'=(base.bp).settings->'region' AND topology.describe_instance->'deployment'=(base.bp).settings->'deployment'
    AND topology.describe_instance->'account_id'=(base.r).storage_contract->'mapping'->'account_id'
    AND topology.describe_instance->'region'=(base.r).storage_contract->'mapping'->'region'
    AND topology.describe_instance->'deployment'=(base.r).storage_contract->'mapping'->'deployment'
    AND(base.r).storage_contract->'mapping'->'topology'->'zone_ids' @> jsonb_build_array(topology.zone_id)
    AND jsonb_typeof(e.receipt)='object' AND jsonb_typeof(e.receipt->'node')='object'
    AND e.receipt ?& ARRAY['protocol','enrollment_id','runtime_node_id','node','cloud_account_id','region','cloud_instance_id','private_ip','guard_port','certification_id','certification_report_sha256','artifact_sha256','terraform_output_sha256','registered_at','changed','enabled']
    AND(SELECT count(*) FROM jsonb_object_keys(e.receipt) AS keys(key_name))=16
    AND(SELECT count(*) FROM jsonb_object_keys(e.receipt->'node') AS keys(key_name))=5
    AND jsonb_typeof(e.receipt->'protocol')='number' AND(e.receipt->'protocol')::text='1'
    AND jsonb_typeof(e.receipt->'guard_port')='number' AND(e.receipt->'guard_port')::text=n.guard_port::text
    AND jsonb_typeof(e.receipt->'changed')='boolean' AND e.receipt->'enabled'='true'::jsonb
    AND jsonb_typeof(e.receipt->'certification_id')='string' AND char_length(e.receipt->>'certification_id') BETWEEN 1 AND 128
    AND e.receipt->>'certification_id'~'^[A-Za-z0-9_.-]+$'
    AND e.receipt->'enrollment_id'=to_jsonb(e.id::text) AND e.receipt->'runtime_node_id'=to_jsonb(n.id::text)
    AND e.receipt->'cloud_account_id'=to_jsonb(n.cloud_account_id) AND e.receipt->'region'=to_jsonb(n.region)
    AND e.receipt->'cloud_instance_id'=to_jsonb(n.cloud_instance_id) AND e.receipt->'private_ip'=to_jsonb(host(n.private_ip))
    AND e.receipt->'certification_report_sha256'=to_jsonb(e.certification_report_sha256) AND e.receipt->'artifact_sha256'=to_jsonb(e.artifact_sha256)
    AND CASE WHEN public.sandbox_restore_topology_timestamp_valid(e.receipt->>'registered_at') IS TRUE
     THEN(e.receipt->>'registered_at')::timestamptz=e.registered_at ELSE false END
    AND e.receipt->'node'=jsonb_build_object('cluster_epoch',n.cluster_epoch::text,'node_uid',n.node_uid::text,'node_name',n.node_name,'boot_id',n.boot_id::text,'profile_sha256',n.profile_sha256)
    AND e.receipt->'terraform_output_sha256'=to_jsonb(e.terraform_output_sha256)
   ORDER BY topology.recorded_at DESC,topology.id DESC LIMIT 1
  ) AS selected ON true
  WHERE(require_node IS FALSE OR selected.node_topology IS NOT NULL)
 ), required AS(
  SELECT authority.tenant_id,authority.actor_principal_id,authority.now_at,actions.project_id,actions.action
  FROM authority CROSS JOIN LATERAL(VALUES(authority.source_project_id,'backups:read'),
   (authority.source_project_id,'backups:restore'),(authority.target_project_id,'instances:create')) AS actions(project_id,action)
 ), horizons AS(
  SELECT required.project_id,required.action,scopes.project_id AS grant_project,
   MAX(COALESCE(grant_row.expires_at,'infinity'::timestamptz)) FILTER(WHERE grant_row.id IS NOT NULL) AS valid_until
  FROM required CROSS JOIN LATERAL(VALUES(NULL::uuid),(required.project_id)) AS scopes(project_id)
  LEFT JOIN public.grants AS grant_row ON grant_row.tenant_id=required.tenant_id AND grant_row.principal_id=required.actor_principal_id
   AND grant_row.project_id IS NOT DISTINCT FROM scopes.project_id AND grant_row.action IN(required.action,'*')
   AND grant_row.enabled AND grant_row.revoked_at IS NULL AND(grant_row.expires_at IS NULL OR grant_row.expires_at>required.now_at)
  GROUP BY required.project_id,required.action,scopes.project_id
 ), budget AS(
  SELECT MIN(valid_until) AS grant_until,count(valid_until) AS matched FROM horizons
 ), ready AS MATERIALIZED(
  SELECT authority.pin,LEAST(authority.resource_until,budget.grant_until) AS authority_until
  FROM authority CROSS JOIN budget WHERE budget.matched=6 AND budget.grant_until IS NOT NULL AND authority.resource_until IS NOT NULL
 ), remaining AS(
  SELECT ready.pin,LEAST(10000000::bigint,floor(extract(epoch FROM(ready.authority_until-clock_timestamp()))*1000000)::bigint) AS valid_for_us FROM ready
 ) SELECT jsonb_build_object('pin',remaining.pin,'valid_for_us',remaining.valid_for_us) INTO result
  FROM remaining WHERE remaining.valid_for_us>0;
 IF NOT FOUND OR result IS NULL OR octet_length(result::text)>2097152 THEN RETURN NULL;END IF;
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION sandbox_restore_raw_scheduling_envelope(uuid,uuid,text,boolean) FROM PUBLIC;

CREATE FUNCTION sandbox_restore_raw_scheduling_admission(requested_tenant uuid,requested_restore uuid,requested_node_name text)
RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT public.sandbox_restore_raw_scheduling_envelope($1,$2,$3,true);
$$;
CREATE FUNCTION sandbox_restore_raw_reschedule_admission(requested_tenant uuid,requested_restore uuid)
RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT public.sandbox_restore_raw_scheduling_envelope($1,$2,NULL::text,false);
$$;
REVOKE ALL ON FUNCTION sandbox_restore_raw_scheduling_admission(uuid,uuid,text),sandbox_restore_raw_reschedule_admission(uuid,uuid) FROM PUBLIC;
DO $$
DECLARE ordinary_role text;
BEGIN
 FOREACH ordinary_role IN ARRAY ARRAY['sandbox_app','sandbox_worker','sandbox_admission','sandbox_gateway','sandbox_termination','sandbox_fencing','sandbox_volume_deleter','sandbox_backup','sandbox_restore_gc'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles AS r WHERE r.rolname=ordinary_role) THEN
   EXECUTE format('REVOKE ALL ON FUNCTION public.sandbox_restore_raw_scheduling_config(jsonb),public.sandbox_restore_raw_scheduling_envelope(uuid,uuid,text,boolean),public.sandbox_restore_raw_scheduling_admission(uuid,uuid,text),public.sandbox_restore_raw_reschedule_admission(uuid,uuid) FROM %I',ordinary_role);
  END IF;
 END LOOP;
END $$;
GRANT EXECUTE ON FUNCTION sandbox_restore_raw_scheduling_admission(uuid,uuid,text),sandbox_restore_raw_reschedule_admission(uuid,uuid) TO sandbox_admission;
