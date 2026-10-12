-- OWNER-only, reviewed operator recovery. No remote request is made here.
-- Required psql variables: tenant_id, operation_id, operator_id, binding_sha256,
-- incident_reference. The operator must be an enabled USER with current
-- workspaces:delete permission. Never modify append-only receipts/tombstones.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL lock_timeout='3s';
SET LOCAL statement_timeout='10s';
SELECT set_config('app.tenant_id', :'tenant_id', true),
       set_config('sandbox.resume_operation', :'operation_id', true),
       set_config('sandbox.resume_operator', :'operator_id', true),
       set_config('sandbox.resume_binding', :'binding_sha256', true),
       set_config('sandbox.resume_reference', :'incident_reference', true);
DO $$
DECLARE tenant uuid:=public.sandbox_current_tenant_id();
 operation uuid:=current_setting('sandbox.resume_operation')::uuid;
 actor uuid:=current_setting('sandbox.resume_operator')::uuid;
 binding_digest text:=current_setting('sandbox.resume_binding');
 reference text:=current_setting('sandbox.resume_reference');
 workspace uuid;project uuid;version bigint;request uuid:=gen_random_uuid();
BEGIN
 IF NOT pg_has_role(current_user,(SELECT relowner FROM pg_class WHERE oid='public.workspace_delete_intents'::regclass),'MEMBER')
    OR binding_digest !~ '^[0-9a-f]{64}$' OR char_length(reference) NOT BETWEEN 1 AND 256 THEN
  RAISE EXCEPTION 'owner role, exact binding digest and approved incident reference required';END IF;
 SELECT w.id,w.project_id,w.spec_version INTO workspace,project,version FROM public.workspaces w
 JOIN public.workspace_delete_intents d ON d.tenant_id=w.tenant_id AND d.workspace_id=w.id
 WHERE w.tenant_id=tenant AND d.operation_id=operation AND w.active_operation_id=operation AND w.status='DELETING'
 FOR UPDATE OF w;
 IF workspace IS NULL THEN RAISE EXCEPTION 'current deleting workspace missing';END IF;
 PERFORM 1 FROM public.operations o JOIN public.workspace_delete_intents d ON d.tenant_id=o.tenant_id AND d.operation_id=o.id
 JOIN public.platform_configuration cfg ON cfg.singleton AND cfg.cluster_epoch=d.cluster_epoch
 JOIN public.workspace_delete_bindings b ON b.tenant_id=o.tenant_id AND b.operation_id=o.id
 WHERE o.tenant_id=tenant AND o.id=operation AND o.kind='DELETE_WORKSPACE' AND o.status='WAITING'
  AND o.stage='WAITING_OPERATOR_REVIEW' AND (o.lease_until IS NULL OR o.lease_until<=clock_timestamp())
  AND encode(sha256(convert_to(b.cloud_identity::text,'UTF8')),'hex')=binding_digest FOR UPDATE OF o;
 IF NOT FOUND OR NOT public.sandbox_workspace_writers_closed(tenant,workspace) THEN
  RAISE EXCEPTION 'operation, epoch, evidence or binding changed; no resume';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.principals p JOIN public.tenant_principals tp ON tp.principal_id=p.id
  JOIN public.grants g ON g.tenant_id=tp.tenant_id AND g.principal_id=p.id
  JOIN public.tenants t ON t.id=g.tenant_id JOIN public.projects pr ON pr.tenant_id=t.id AND pr.id=g.project_id
  WHERE p.id=actor AND p.kind='USER' AND public.sandbox_principal_enabled(actor) AND tp.tenant_id=tenant AND tp.enabled
   AND t.enabled AND pr.enabled AND g.project_id=project AND g.action='workspaces:delete'
   AND g.enabled AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>clock_timestamp())) THEN
  RAISE EXCEPTION 'enabled authorized human operator required';END IF;
 INSERT INTO public.audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details)
 VALUES(tenant,project,actor,request,operation,workspace,'workspaces:delete:resume','ACCEPTED',
  jsonb_build_object('incident_reference',reference,'binding_sha256',binding_digest));
 UPDATE public.operations SET status='QUEUED',stage='RESUMING_AFTER_OPERATOR_REVIEW',wait_reason=NULL,error=NULL,
  next_attempt_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=tenant AND id=operation;
END $$;
COMMIT;
