-- Reject NULL/empty claims explicitly; SQL UNKNOWN must never grant a lease.
CREATE OR REPLACE FUNCTION sandbox_freeze_node_launch(incident uuid,permit uuid,worker text,token bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE f public.node_fence_incidents%ROWTYPE;t public.node_fence_targets%ROWTYPE;
    p public.launch_permits%ROWTYPE;i public.instances%ROWTYPE;old_op public.operations%ROWTYPE;
    stop_id uuid;system_actor uuid;current_epoch uuid;now_at timestamptz;previous_tenant text:=current_setting('app.tenant_id',true);
BEGIN
    IF incident IS NULL OR permit IS NULL OR worker IS NULL OR token IS NULL
       OR incident='00000000-0000-0000-0000-000000000000' OR permit='00000000-0000-0000-0000-000000000000'
       OR length(worker)<1 OR length(worker)>128 OR worker~'[[:cntrl:]]' OR token<1 THEN
        RAISE EXCEPTION 'invalid fencing claim' USING ERRCODE='22023';END IF;
    SELECT * INTO f FROM public.node_fence_incidents WHERE id=incident FOR UPDATE;
    IF NOT FOUND OR NOT COALESCE(f.state='FREEZING' AND f.lease_owner=worker AND f.lease_token=token AND f.lease_until>clock_timestamp(),false) THEN
        RAISE EXCEPTION 'fencing lease lost' USING ERRCODE='40001';END IF;
    SELECT * INTO t FROM public.node_fence_targets WHERE incident_id=incident AND permit_id=permit;
    IF NOT FOUND THEN RAISE EXCEPTION 'permit not in incident' USING ERRCODE='23514';END IF;
    IF t.state<>'PENDING' THEN RETURN false;END IF;
    PERFORM set_config('app.tenant_id',t.tenant_id::text,true);
    SELECT * INTO p FROM public.launch_permits WHERE tenant_id=t.tenant_id AND id=permit;
    IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM public.runtime_nodes n WHERE n.id=p.runtime_node_id AND (n.cloud_account_id,n.region,n.cloud_instance_id)=(f.cloud_account_id,f.region,f.cloud_instance_id)) THEN RAISE EXCEPTION 'incident identity mismatch' USING ERRCODE='23514';END IF;
    PERFORM id FROM public.workspaces WHERE tenant_id=p.tenant_id AND id=p.workspace_id FOR UPDATE;
    SELECT * INTO i FROM public.instances WHERE tenant_id=p.tenant_id AND id=p.instance_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'missing fenced instance' USING ERRCODE='23514';END IF;
    SELECT cluster_epoch,safety_principal_id INTO current_epoch,system_actor FROM public.platform_configuration WHERE singleton FOR SHARE;
    now_at:=clock_timestamp();
    IF f.lease_until<=now_at OR current_epoch<>f.cluster_epoch THEN RAISE EXCEPTION 'fencing lease or epoch changed while locking resources' USING ERRCODE='40001';END IF;
    IF (i.runtime_generation,i.launch_id,i.pod_uid,i.cluster_epoch) IS DISTINCT FROM (p.generation,p.launch_id,p.pod_uid,p.cluster_epoch)
       OR (i.observed_state='STOPPED' AND i.desired_state='STOPPED' AND i.active_operation_id IS NULL) THEN
        UPDATE public.node_fence_targets SET state='HISTORICAL',frozen_at=now_at WHERE incident_id=incident AND permit_id=permit;
        INSERT INTO public.node_fence_events(incident_id,kind,lease_token,evidence) VALUES(incident,'HISTORICAL_LAUNCH',token,jsonb_build_object('permit_id',permit));
    ELSE
        PERFORM id FROM public.executions WHERE tenant_id=p.tenant_id AND instance_id=i.id AND slot_held ORDER BY id FOR UPDATE;
        PERFORM id FROM public.operations WHERE tenant_id=p.tenant_id AND (id=i.active_operation_id OR id IN(SELECT operation_id FROM public.executions WHERE tenant_id=p.tenant_id AND instance_id=i.id AND slot_held)) ORDER BY id FOR UPDATE;
        now_at:=clock_timestamp();
        IF f.lease_until<=now_at THEN RAISE EXCEPTION 'fencing lease expired while locking activity' USING ERRCODE='40001';END IF;
        IF i.active_operation_id IS NOT NULL THEN
            SELECT * INTO old_op FROM public.operations WHERE tenant_id=p.tenant_id AND id=i.active_operation_id;
            IF old_op.kind IN('STOP','DELETE') AND old_op.status IN('QUEUED','RUNNING','WAITING') THEN stop_id:=old_op.id;
            ELSIF old_op.kind IN('CREATE','START','RESTART') AND old_op.status IN('QUEUED','RUNNING','WAITING') THEN
                UPDATE public.operations SET status='CANCELLED',stage='SUPERSEDED_BY_NODE_FENCE',cancel_requested=true,lease_owner=NULL,lease_until=NULL,lease_token=lease_token+1,completed_at=now_at,updated_at=now_at WHERE tenant_id=p.tenant_id AND id=old_op.id;
            ELSE RAISE EXCEPTION 'incompatible fenced operation' USING ERRCODE='23514';END IF;
        END IF;
        IF stop_id IS NULL THEN
            stop_id:=gen_random_uuid();
            INSERT INTO public.operations(id,tenant_id,project_id,instance_id,workspace_id,kind,request,actor_principal_id,request_id,deadline,stop_reason,compute_lease_id)
            VALUES(stop_id,p.tenant_id,p.project_id,i.id,p.workspace_id,'STOP',jsonb_build_object('reason','NODE_FENCE','incident_id',incident),system_actor,incident,now_at+interval '30 minutes','SECURITY',i.compute_lease_id);
        END IF;
        UPDATE public.instances SET desired_state='STOPPED',stop_reason='SECURITY',stop_accepted_at=COALESCE(stop_accepted_at,now_at),active_operation_id=stop_id,spec_version=spec_version+1,idle_since=NULL,updated_at=now_at WHERE tenant_id=p.tenant_id AND id=i.id;
        UPDATE public.workspaces SET active_operation_id=stop_id,updated_at=now_at WHERE tenant_id=p.tenant_id AND id=p.workspace_id AND (active_operation_id IS NULL OR active_operation_id=i.active_operation_id);
        IF NOT FOUND THEN RAISE EXCEPTION 'workspace operation conflict' USING ERRCODE='23514';END IF;
        UPDATE public.executions SET cancel_requested_at=COALESCE(cancel_requested_at,now_at),cancel_operation_id=stop_id,termination_status='PENDING',status=CASE WHEN dispatch_attempt_id IS NOT NULL AND status IN('DISPATCHING','RUNNING') THEN 'OUTCOME_UNKNOWN' WHEN status='QUEUED' THEN 'CANCELLED' ELSE status END,completed_at=CASE WHEN status='QUEUED' THEN now_at ELSE completed_at END WHERE tenant_id=p.tenant_id AND instance_id=i.id AND slot_held;
        UPDATE public.operations SET cancel_requested=true,lease_owner=NULL,lease_until=NULL,lease_token=lease_token+1,status='WAITING',stage='WAITING_NODE_FENCE',wait_reason='NODE_FENCE_TERMINATION_UNCONFIRMED',next_attempt_at=now_at+interval '5 minutes',updated_at=now_at WHERE tenant_id=p.tenant_id AND id IN(SELECT operation_id FROM public.executions WHERE tenant_id=p.tenant_id AND instance_id=i.id AND slot_held) AND status IN('QUEUED','RUNNING','WAITING');
        UPDATE public.node_fence_targets SET state='FROZEN',stop_operation_id=stop_id,frozen_at=now_at WHERE incident_id=incident AND permit_id=permit;
        INSERT INTO public.audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details) VALUES(p.tenant_id,p.project_id,system_actor,incident,stop_id,i.id,'instances:node_fence','ACCEPTED',jsonb_build_object('incident_id',incident,'permit_id',permit,'termination_confirmed',false));
        INSERT INTO public.domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload) VALUES(p.tenant_id,p.project_id,i.id,i.spec_version+1,'instances.node_fence.accepted',stop_id,incident,jsonb_build_object('incident_id',incident,'termination_confirmed',false));
        INSERT INTO public.node_fence_events(incident_id,kind,lease_token,evidence) VALUES(incident,'LAUNCH_FROZEN',token,jsonb_build_object('permit_id',permit,'tenant_id',p.tenant_id,'operation_id',stop_id));
    END IF;
    -- Event stream sequencing/FK checks can wait after resource locks too.
    IF f.lease_until<=clock_timestamp() THEN RAISE EXCEPTION 'fencing lease expired before completing freeze' USING ERRCODE='40001';END IF;
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
    RETURN true;
END $$;
REVOKE ALL ON FUNCTION sandbox_freeze_node_launch(uuid,uuid,text,bigint) FROM PUBLIC;
