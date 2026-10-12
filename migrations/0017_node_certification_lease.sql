-- Certification renewals append new immutable operator reviews for the same node.
ALTER TABLE runtime_node_enrollments DROP CONSTRAINT runtime_node_enrollments_runtime_node_id_key;
ALTER TABLE runtime_node_enrollments ADD COLUMN certification_reviewed_at timestamptz;
ALTER TABLE runtime_node_enrollments DISABLE TRIGGER runtime_node_enrollments_append_only;
UPDATE runtime_node_enrollments SET certification_reviewed_at=registered_at;
ALTER TABLE runtime_node_enrollments ENABLE TRIGGER runtime_node_enrollments_append_only;
ALTER TABLE runtime_node_enrollments ALTER COLUMN certification_reviewed_at SET NOT NULL;
ALTER TABLE runtime_node_enrollments ADD CONSTRAINT certification_review_precedes_expiry CHECK(certification_reviewed_at<certification_expires_at);
CREATE UNIQUE INDEX runtime_node_report_once ON runtime_node_enrollments(runtime_node_id,certification_report_sha256);
CREATE INDEX runtime_node_certification_expiry ON runtime_node_enrollments(runtime_node_id,certification_expires_at DESC);

-- Returns only an expiry to the trusted registration controller, not operator
-- report contents. It deliberately does not participate in termination proof.
CREATE FUNCTION sandbox_node_certified_until(node_id uuid) RETURNS timestamptz
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
    SELECT max(e.certification_expires_at)
    FROM public.runtime_node_enrollments e JOIN public.runtime_nodes n ON n.id=e.runtime_node_id
    WHERE e.runtime_node_id=$1 AND e.cluster_epoch=n.cluster_epoch
      AND e.certification_reviewed_at<=clock_timestamp()+interval '2 seconds'
      AND e.certification_expires_at>clock_timestamp();
$$;
-- Product callers see only their current instance's assignment and expiry.
-- A missing permit is distinct from an assigned but expired/disabled node.
CREATE FUNCTION sandbox_instance_certification(requested_tenant uuid,instance_id uuid)
RETURNS TABLE(assigned boolean,valid_until timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
    SELECT count(p.id)>0,max(CASE WHEN n.enabled AND n.cluster_epoch=c.cluster_epoch
        THEN public.sandbox_node_certified_until(n.id) END)
    FROM public.instances i JOIN public.platform_configuration c ON c.singleton
    LEFT JOIN public.launch_permits p ON (p.tenant_id,p.project_id,p.instance_id,p.workspace_id,p.generation,p.launch_id,p.pod_uid,p.cluster_epoch)
        =(i.tenant_id,i.project_id,i.id,i.workspace_id,i.runtime_generation,i.launch_id,i.pod_uid,i.cluster_epoch)
    LEFT JOIN public.runtime_nodes n ON n.id=p.runtime_node_id AND n.cluster_epoch=p.cluster_epoch
    WHERE i.tenant_id=$1 AND i.id=$2 AND $1=public.sandbox_current_tenant_id()
    HAVING count(i.id)>0;
$$;
CREATE OR REPLACE FUNCTION sandbox_launch_registered(requested_tenant uuid,instance uuid,generation bigint,launch uuid,pod uuid,epoch uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
    SELECT COALESCE($1=public.sandbox_current_tenant_id() AND EXISTS(
      SELECT 1 FROM public.launch_permits p JOIN public.runtime_nodes n ON n.id=p.runtime_node_id
      JOIN public.instances i ON (i.tenant_id,i.id,i.runtime_generation,i.launch_id,i.pod_uid,i.cluster_epoch)
        =(p.tenant_id,p.instance_id,p.generation,p.launch_id,p.pod_uid,p.cluster_epoch)
      WHERE p.tenant_id=$1 AND p.instance_id=$2 AND p.generation=$3 AND p.launch_id=$4
        AND p.pod_uid=$5 AND p.cluster_epoch=$6 AND n.cluster_epoch=$6 AND n.enabled
        AND public.sandbox_node_certified_until(n.id)>=i.compute_lease_expires_at
        AND (EXISTS(SELECT 1 FROM public.launch_permit_receipts r WHERE r.tenant_id=p.tenant_id AND r.permit_id=p.id AND p.expires_at>=i.compute_lease_expires_at)
          OR EXISTS(SELECT 1 FROM public.launch_permit_extensions e JOIN public.launch_permit_extension_receipts r ON r.tenant_id=e.tenant_id AND r.extension_id=e.id
             WHERE e.tenant_id=p.tenant_id AND e.base_permit_id=p.id AND e.expires_at>=i.compute_lease_expires_at))),false);
$$;
REVOKE ALL ON FUNCTION sandbox_node_certified_until(uuid),sandbox_instance_certification(uuid,uuid),sandbox_launch_registered(uuid,uuid,bigint,uuid,uuid,uuid) FROM PUBLIC;

-- Existing Ready rows must not bypass certification after an upgrade.
CREATE OR REPLACE FUNCTION sandbox_admit_execution_connect(
    requested_tenant uuid, requested_execution uuid, requested_attempt uuid,
    requested_review_uid uuid
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
    previous_tenant text := current_setting('app.tenant_id',true);
    instance_id uuid;
    workspace_id uuid;
    runtime public.instances%ROWTYPE;
    workspace public.workspaces%ROWTYPE;
    execution public.executions%ROWTYPE;
    operation public.operations%ROWTYPE;
    configuration public.platform_configuration%ROWTYPE;
    observed_now timestamptz;
    admitted boolean := false;
    authorized boolean;
BEGIN
    IF requested_tenant IS NULL OR requested_execution IS NULL
       OR requested_attempt IS NULL OR requested_review_uid IS NULL
       OR requested_tenant='00000000-0000-0000-0000-000000000000'
       OR requested_execution='00000000-0000-0000-0000-000000000000'
       OR requested_attempt='00000000-0000-0000-0000-000000000000'
       OR requested_review_uid='00000000-0000-0000-0000-000000000000' THEN
        RETURN false;
    END IF;
    PERFORM set_config('app.tenant_id',requested_tenant::text,true);
    <<validate_connect>>
    BEGIN
        SELECT e.instance_id,i.workspace_id INTO instance_id,workspace_id
        FROM public.executions e JOIN public.instances i
          ON (i.tenant_id,i.project_id,i.id)=(e.tenant_id,e.project_id,e.instance_id)
        WHERE e.tenant_id=requested_tenant AND e.id=requested_execution;
        IF NOT FOUND THEN EXIT validate_connect; END IF;
        -- Match every product/dispatcher path: workspace -> instance -> execution
        -- -> operation. No remote Kubernetes call is made while holding these.
        SELECT w.* INTO workspace FROM public.workspaces w
        WHERE w.tenant_id=requested_tenant AND w.id=workspace_id FOR UPDATE;
        IF NOT FOUND THEN EXIT validate_connect; END IF;
        SELECT i.* INTO runtime FROM public.instances i
        WHERE i.tenant_id=requested_tenant AND i.id=instance_id FOR UPDATE;
        IF NOT FOUND THEN EXIT validate_connect; END IF;
        SELECT e.* INTO execution FROM public.executions e
        WHERE e.tenant_id=requested_tenant AND e.id=requested_execution FOR UPDATE;
        IF NOT FOUND THEN EXIT validate_connect; END IF;
        SELECT o.* INTO operation FROM public.operations o
        WHERE o.tenant_id=requested_tenant AND o.id=execution.operation_id FOR UPDATE;
        IF NOT FOUND THEN EXIT validate_connect; END IF;
        SELECT c.* INTO configuration FROM public.platform_configuration c WHERE c.singleton;
        IF NOT FOUND THEN EXIT validate_connect; END IF;
        observed_now := clock_timestamp();
        IF NOT COALESCE(
            NOT configuration.safe_mode
            AND runtime.desired_state='RUNNING' AND runtime.observed_state='RUNNING'
            AND runtime.active_operation_id IS NULL AND runtime.stop_accepted_at IS NULL
            AND runtime.compute_lease_expires_at>observed_now
            AND EXISTS(SELECT 1 FROM public.sandbox_instance_certification(requested_tenant,runtime.id) certification
                WHERE certification.assigned AND certification.valid_until>=runtime.compute_lease_expires_at)
            AND runtime.cluster_epoch=configuration.cluster_epoch
            AND runtime.slot_held AND runtime.activity_kind='EXECUTION'
            AND runtime.activity_id=requested_execution
            AND runtime.activity_generation=runtime.runtime_generation
            AND runtime.ready_generation=runtime.runtime_generation
            AND runtime.ready_launch_id=runtime.launch_id
            AND runtime.ready_pod_uid=runtime.pod_uid
            AND runtime.ready_cluster_epoch=runtime.cluster_epoch
            AND runtime.ready_observed_at>=runtime.compute_lease_started_at
            AND runtime.ready_observed_at<=observed_now
            AND runtime.namespace IS NOT NULL
            AND runtime.pod_name='sbx-ws-'||runtime.workspace_id::text
            AND workspace.status='IN_USE' AND workspace.active_operation_id IS NULL
            AND workspace.delete_requested_at IS NULL
            AND workspace.namespace=runtime.namespace
            AND execution.instance_id=runtime.id AND execution.project_id=runtime.project_id
            AND execution.runtime_generation=runtime.runtime_generation
            AND execution.launch_id=runtime.launch_id AND execution.pod_uid=runtime.pod_uid
            AND execution.cluster_epoch=runtime.cluster_epoch
            AND execution.dispatch_attempt_id=requested_attempt
            AND execution.dispatch_attempted_at IS NOT NULL
            AND execution.status IN ('DISPATCHING','RUNNING')
            AND execution.slot_held AND execution.termination_status='NOT_REQUESTED'
            AND execution.cancel_requested_at IS NULL AND execution.deadline>observed_now
            AND operation.kind='EXECUTE' AND operation.status='RUNNING'
            AND execution.dispatch_lease_token=operation.lease_token
            AND operation.lease_owner IS NOT NULL AND operation.lease_until>observed_now
            AND NOT operation.cancel_requested AND operation.deadline>observed_now
            AND operation.instance_id=runtime.id AND operation.workspace_id=workspace.id
            AND operation.request->>'on_timeout'='HARD_STOP_INSTANCE'
            AND operation.request->>'classification'='NON_SENSITIVE'
            AND operation.request->'runner'->>'execution_id'=requested_execution::text
            AND (execution.exec_admission_uid IS NULL OR execution.exec_admission_uid=requested_review_uid),
            false) THEN EXIT validate_connect; END IF;
        SELECT public.sandbox_principal_enabled(operation.actor_principal_id)
            AND EXISTS (SELECT 1 FROM public.projects p JOIN public.tenants t ON t.id=p.tenant_id
                WHERE p.tenant_id=requested_tenant AND p.id=runtime.project_id
                  AND p.enabled AND t.enabled AND p.runtime_namespace=runtime.namespace)
            AND EXISTS (SELECT 1 FROM public.template_versions t WHERE t.tenant_id=requested_tenant
                AND t.id=runtime.template_version_id AND t.status='APPROVED')
            AND EXISTS (SELECT 1 FROM public.security_policy_versions p WHERE p.tenant_id=requested_tenant
                AND p.id=runtime.security_policy_version_id AND p.status='APPROVED')
            AND NOT EXISTS (
                SELECT 1 FROM (VALUES ('executions:create'),('instances:hard_stop')) AS required(action)
                WHERE NOT EXISTS (SELECT 1 FROM public.grants g
                    WHERE g.tenant_id=requested_tenant AND g.principal_id=operation.actor_principal_id
                      AND (g.project_id=runtime.project_id OR g.project_id IS NULL)
                      AND (g.action=required.action OR g.action='*') AND g.enabled
                      AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>observed_now))
            ) INTO authorized;
        IF authorized IS DISTINCT FROM true THEN EXIT validate_connect; END IF;
        IF execution.exec_admission_uid IS NULL THEN
            UPDATE public.executions e SET exec_admission_uid=requested_review_uid,
                exec_admitted_at=observed_now
            WHERE e.tenant_id=requested_tenant AND e.id=requested_execution;
        END IF;
        admitted := true;
    END validate_connect;
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
    RETURN admitted;
EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
    RAISE;
END;
$$;
REVOKE ALL ON FUNCTION sandbox_admit_execution_connect(uuid,uuid,uuid,uuid) FROM PUBLIC;
