-- PRIVATE DRAFT; not a formal migration or production activation.
-- Initial raw PVC creation needs no future Job, PV, Pod or VM permit. The
-- complete current authority and its finite horizon share one read statement.
CREATE FUNCTION sandbox_restore_raw_parent_admission(requested_tenant uuid,requested_restore uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE located public.restores;active uuid;result jsonb;
BEGIN
 IF requested_tenant IS NULL OR requested_restore IS NULL
  OR requested_tenant='00000000-0000-0000-0000-000000000000'
  OR requested_restore='00000000-0000-0000-0000-000000000000'
  OR requested_tenant IS DISTINCT FROM public.sandbox_current_tenant_id() THEN RETURN NULL;END IF;
 SELECT * INTO located FROM public.restores r WHERE r.tenant_id=requested_tenant AND r.id=requested_restore;
 IF NOT FOUND THEN RETURN NULL;END IF;
 -- Keep the same resource lock order as the controller's record path. An
 -- absent binding cannot be locked, so the parent restore fence serializes it.
 PERFORM w.id FROM public.workspaces w WHERE w.tenant_id=requested_tenant AND w.id=located.workspace_id FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL;END IF;
 SELECT i.active_operation_id INTO active FROM public.instances i
  WHERE i.tenant_id=requested_tenant AND i.id=located.instance_id AND i.workspace_id=located.workspace_id FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL;END IF;
 PERFORM o.id FROM public.operations o WHERE o.tenant_id=requested_tenant
  AND(o.id=located.operation_id OR o.id=active) ORDER BY o.id FOR UPDATE;
 SELECT * INTO located FROM public.restores r WHERE r.tenant_id=requested_tenant AND r.id=requested_restore FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL;END IF;
 PERFORM intent.id FROM public.restore_resource_intents intent
  WHERE intent.tenant_id=requested_tenant AND intent.restore_id=requested_restore AND intent.kind IN('BLOCK_PVC','BLOCK_PV') ORDER BY intent.id FOR SHARE;
 PERFORM binding.intent_id FROM public.restore_resource_bindings binding
  WHERE binding.tenant_id=requested_tenant AND binding.restore_id=requested_restore ORDER BY binding.intent_id FOR SHARE;
 WITH authority AS MATERIALIZED (
  SELECT r.tenant_id,o.actor_principal_id,r.source_project_id,r.target_project_id,
   jsonb_build_object('record',to_jsonb(r),'cloud_settings',bp.settings,
    'target_namespace',target.runtime_namespace,
    'vault',jsonb_build_object('verified',to_jsonb(verified),'source',to_jsonb(source_vault)),
    'intent',to_jsonb(intent),
    'operation_identity',jsonb_build_object('id',o.id,'tenant_id',o.tenant_id,'project_id',o.project_id,
     'instance_id',o.instance_id,'workspace_id',o.workspace_id,'kind',o.kind,
     'actor_principal_id',o.actor_principal_id,'request_id',o.request_id,'lease_owner',o.lease_owner,'lease_token',o.lease_token),
    'authz_identity',jsonb_build_object('tenant_version',tenant.authz_version,'principal_version',principal.authz_version,
     'source_project_version',source.authz_version,'target_project_version',target.authz_version,'instance_spec_version',instance.spec_version,
     'template_id',template.id,'template_version',template.version,'security_id',security.id,'security_version',security.version)) AS pin,
   LEAST(r.deadline,o.deadline,o.lease_until,bp.certified_until,cert.certified_until,
    backup.retention_until-interval '5 minutes') AS resource_until
  FROM public.restores r
  JOIN public.backups backup ON backup.tenant_id=r.tenant_id AND backup.id=r.backup_id AND backup.project_id=r.source_project_id
  JOIN public.backup_profiles bp ON bp.id=r.profile_id
  JOIN public.restore_profile_certifications cert ON cert.profile_id=r.profile_id AND cert.cluster_epoch=r.cluster_epoch
  JOIN public.operations o ON o.tenant_id=r.tenant_id AND o.id=r.operation_id
   AND o.project_id=r.target_project_id AND o.instance_id=r.instance_id AND o.workspace_id=r.workspace_id AND o.kind='RESTORE'
  JOIN public.tenants tenant ON tenant.id=r.tenant_id
  JOIN public.principals principal ON principal.id=o.actor_principal_id
  JOIN public.projects source ON source.tenant_id=r.tenant_id AND source.id=r.source_project_id
  JOIN public.projects target ON target.tenant_id=r.tenant_id AND target.id=r.target_project_id
  JOIN public.instances instance ON instance.tenant_id=r.tenant_id AND instance.id=r.instance_id
   AND instance.project_id=r.target_project_id AND instance.workspace_id=r.workspace_id
  JOIN public.workspaces workspace ON workspace.tenant_id=r.tenant_id AND workspace.id=r.workspace_id AND workspace.project_id=r.target_project_id
  JOIN public.template_versions template ON template.tenant_id=instance.tenant_id AND template.id=instance.template_version_id AND template.status='APPROVED'
  JOIN public.security_policy_versions security ON security.tenant_id=instance.tenant_id AND security.id=instance.security_policy_version_id AND security.status='APPROVED'
  JOIN public.restore_vault_receipts verified ON verified.tenant_id=r.tenant_id AND verified.restore_id=r.id AND verified.backup_id=r.backup_id
   AND verified.manifest_sha256=r.source_manifest_sha256
  JOIN public.backup_vault_receipts source_vault ON source_vault.tenant_id=r.tenant_id AND source_vault.backup_id=r.backup_id
   AND source_vault.manifest_sha256=r.source_manifest_sha256
   AND source_vault.manifest->'manifest'->'backup'=r.source_identity
   AND source_vault.manifest->>'signing_key_sha256'=verified.signing_key_sha256
   AND source_vault.manifest->>'vault_endpoint'=verified.vault_endpoint
  JOIN public.restore_resource_intents intent ON intent.tenant_id=r.tenant_id AND intent.restore_id=r.id AND intent.kind='BLOCK_PVC'
  WHERE r.tenant_id=requested_tenant AND r.id=requested_restore AND r.status='BLOCK_PENDING'
   AND public.sandbox_restore_authorized(requested_tenant,requested_restore,true) IS TRUE
   AND o.status='RUNNING' AND o.lease_owner IS NOT NULL AND char_length(o.lease_owner) BETWEEN 1 AND 128 AND o.lease_token>0
   AND o.lease_until IS NOT NULL AND o.deadline IS NOT NULL AND r.deadline IS NOT NULL
   AND tenant.enabled AND principal.enabled AND source.enabled AND target.enabled
   AND tenant.authz_version>0 AND principal.authz_version>0 AND source.authz_version>0 AND target.authz_version>0
   AND instance.spec_version>0 AND template.version>0 AND security.version>0
   AND target.runtime_namespace=workspace.namespace AND instance.namespace=workspace.namespace
   AND target.runtime_namespace<>'sandbox-system'
   AND intent.namespace='sandbox-system' AND intent.name='sbx-bvol-'||r.id::text
   AND intent.expected_object=jsonb_build_object('apiVersion','v1','kind','PersistentVolumeClaim',
    'metadata',jsonb_build_object('name','sbx-bvol-'||r.id::text,'namespace','sandbox-system',
     'labels',jsonb_build_object('sandbox.platform/backup-id',r.backup_id::text,'sandbox.platform/restore-id',r.id::text,
      'sandbox.platform/tenant-id',r.tenant_id::text,'sandbox.platform/project-id',r.target_project_id::text,
      'sandbox.platform/cluster-epoch',r.cluster_epoch::text,'app.kubernetes.io/managed-by','sandbox-backup')),
    'spec',jsonb_build_object('volumeMode','Block','accessModes',jsonb_build_array('ReadWriteOnce'),
     'storageClassName',r.storage_contract->'mapping'->'raw'->>'name',
     'resources',jsonb_build_object('requests',jsonb_build_object('storage',
      CASE WHEN r.size_gib%1024=0 THEN(r.size_gib/1024)::text||'Ti' ELSE r.size_gib::text||'Gi' END))))
   AND NOT EXISTS(SELECT 1 FROM public.restore_resource_bindings binding WHERE binding.tenant_id=r.tenant_id AND binding.restore_id=r.id AND binding.intent_id=intent.id)
   AND NOT EXISTS(SELECT 1 FROM public.restore_resource_intents pv WHERE pv.tenant_id=r.tenant_id AND pv.restore_id=r.id AND pv.kind='BLOCK_PV')
   AND NOT EXISTS(SELECT 1 FROM public.restore_block_receipts raw WHERE raw.tenant_id=r.tenant_id AND raw.restore_id=r.id)
   AND NOT EXISTS(SELECT 1 FROM public.restore_launch_permits permit WHERE permit.tenant_id=r.tenant_id AND permit.restore_id=r.id)
 ), required AS (
  SELECT authority.tenant_id,authority.actor_principal_id,actions.project_id,actions.action
  FROM authority CROSS JOIN LATERAL(VALUES(authority.source_project_id,'backups:read'),
   (authority.source_project_id,'backups:restore'),(authority.target_project_id,'instances:create')) AS actions(project_id,action)
 ), horizons AS (
  SELECT required.project_id,required.action,scopes.project_id AS grant_project,
   MAX(COALESCE(grant_row.expires_at,'infinity'::timestamptz)) FILTER(WHERE grant_row.id IS NOT NULL) AS valid_until
  FROM required CROSS JOIN LATERAL(VALUES(NULL::uuid),(required.project_id)) AS scopes(project_id)
  LEFT JOIN public.grants grant_row ON grant_row.tenant_id=required.tenant_id AND grant_row.principal_id=required.actor_principal_id
   AND grant_row.project_id IS NOT DISTINCT FROM scopes.project_id AND grant_row.action IN(required.action,'*')
   AND grant_row.enabled AND grant_row.revoked_at IS NULL AND(grant_row.expires_at IS NULL OR grant_row.expires_at>clock_timestamp())
  GROUP BY required.project_id,required.action,scopes.project_id
 ), budget AS (
  SELECT MIN(valid_until) AS grant_until,count(valid_until) AS matched FROM horizons
 ), ready AS MATERIALIZED (
  SELECT authority.pin,LEAST(authority.resource_until,budget.grant_until) AS authority_until
  FROM authority CROSS JOIN budget WHERE budget.matched=6 AND budget.grant_until IS NOT NULL AND authority.resource_until IS NOT NULL
 ), remaining AS (
  SELECT ready.pin,LEAST(10000000::bigint,floor(extract(epoch FROM(ready.authority_until-clock_timestamp()))*1000000)::bigint) AS valid_for_us FROM ready
 ) SELECT jsonb_build_object('pin',remaining.pin,'valid_for_us',remaining.valid_for_us) INTO result
  FROM remaining WHERE remaining.valid_for_us>0;
 IF NOT FOUND OR result IS NULL OR octet_length(result::text)>2097152 THEN RETURN NULL;END IF;
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION sandbox_restore_raw_parent_admission(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sandbox_restore_raw_parent_admission(uuid,uuid) TO sandbox_admission;
