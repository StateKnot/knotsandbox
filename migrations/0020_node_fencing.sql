-- Installation-level incidents. Only an installation owner may request one;
-- fencing is a SYSTEM node operation, never a tenant hard_stop escalation.
CREATE TABLE node_fence_incidents (
    id uuid PRIMARY KEY,
    runtime_node_id uuid NOT NULL UNIQUE REFERENCES runtime_nodes(id),
    cluster_epoch uuid NOT NULL,
    cloud_account_id text NOT NULL, region text NOT NULL, cloud_instance_id text NOT NULL,
    request jsonb NOT NULL CHECK(jsonb_typeof(request)='object' AND octet_length(request::text)<=16384),
    request_sha256 text NOT NULL CHECK(request_sha256~'^[0-9a-f]{64}$'),
    requested_by text NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    state text NOT NULL DEFAULT 'FREEZING' CHECK(state IN('FREEZING','READY_TO_STOP','DISPATCHING','OBSERVING','STOPPED_OBSERVED','BREACH')),
    attempt_id uuid UNIQUE, dispatched_at timestamptz,
    stopped_observed_at timestamptz, breach_at timestamptz,
    lease_owner text, lease_token bigint NOT NULL DEFAULT 0 CHECK(lease_token>=0), lease_until timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(cloud_account_id,region,cloud_instance_id),
    CHECK((attempt_id IS NULL)=(dispatched_at IS NULL)),
    CHECK((lease_owner IS NULL)=(lease_until IS NULL)),
    CHECK(state NOT IN('DISPATCHING','OBSERVING','STOPPED_OBSERVED','BREACH') OR attempt_id IS NOT NULL),
    CHECK((state='BREACH')=(breach_at IS NOT NULL)),
    CHECK(state<>'STOPPED_OBSERVED' OR stopped_observed_at IS NOT NULL)
);
CREATE INDEX node_fence_due ON node_fence_incidents(next_attempt_at,id) WHERE state<>'BREACH';
CREATE TABLE runtime_launch_index (
    permit_id uuid PRIMARY KEY REFERENCES launch_permits(id),
    runtime_node_id uuid NOT NULL REFERENCES runtime_nodes(id),
    tenant_id uuid NOT NULL
);
CREATE INDEX runtime_launch_by_node ON runtime_launch_index(runtime_node_id,tenant_id,permit_id);
CREATE TABLE node_fence_targets (
    incident_id uuid NOT NULL REFERENCES node_fence_incidents(id),
    permit_id uuid NOT NULL REFERENCES launch_permits(id),
    tenant_id uuid NOT NULL,
    state text NOT NULL DEFAULT 'PENDING' CHECK(state IN('PENDING','FROZEN','HISTORICAL')),
    stop_operation_id uuid, frozen_at timestamptz,
    PRIMARY KEY(incident_id,permit_id),
    FOREIGN KEY(tenant_id,permit_id) REFERENCES launch_permits(tenant_id,id),
    CHECK((state='PENDING')=(frozen_at IS NULL))
);
CREATE TABLE node_fence_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id uuid NOT NULL REFERENCES node_fence_incidents(id),
    kind text NOT NULL CHECK(kind IN('REQUESTED','LAUNCH_FROZEN','HISTORICAL_LAUNCH','DISPATCHING','STOP_RESULT','OBSERVATION','ERROR','BREACH')),
    attempt_id uuid,
    lease_token bigint NOT NULL,
    evidence jsonb NOT NULL CHECK(jsonb_typeof(evidence)='object' AND octet_length(evidence::text)<=65536),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER node_fence_events_append_only BEFORE UPDATE OR DELETE ON node_fence_events
FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_audit_mutation();
CREATE FUNCTION sandbox_preserve_node_fence() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'node tombstones are permanent' USING ERRCODE='23514';END IF;
    IF (to_jsonb(NEW)-ARRAY['state','attempt_id','dispatched_at','stopped_observed_at','breach_at','lease_owner','lease_token','lease_until','next_attempt_at'])
       IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','attempt_id','dispatched_at','stopped_observed_at','breach_at','lease_owner','lease_token','lease_until','next_attempt_at'])
       OR (OLD.attempt_id IS NOT NULL AND (NEW.attempt_id,NEW.dispatched_at) IS DISTINCT FROM (OLD.attempt_id,OLD.dispatched_at))
       OR (OLD.stopped_observed_at IS NOT NULL AND NEW.stopped_observed_at IS DISTINCT FROM OLD.stopped_observed_at)
       OR (OLD.breach_at IS NOT NULL AND NEW.breach_at IS DISTINCT FROM OLD.breach_at)
       OR NEW.lease_token<OLD.lease_token OR (OLD.state='BREACH' AND NEW.state<>'BREACH') THEN
        RAISE EXCEPTION 'node fence identity/evidence cannot regress' USING ERRCODE='23514';END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER node_fence_immutable BEFORE UPDATE OR DELETE ON node_fence_incidents
FOR EACH ROW EXECUTE FUNCTION sandbox_preserve_node_fence();
CREATE FUNCTION sandbox_reject_fenced_node() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    -- Serialize enrollment against an incident for the same immutable cloud
    -- identity, including a new boot/node ID inserted after the active row retires.
    IF TG_OP='INSERT' OR NEW.enabled THEN
        PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array(NEW.cloud_account_id,NEW.region,NEW.cloud_instance_id)::text,24020));
    END IF;
    IF (TG_OP='INSERT' OR NEW.enabled) AND EXISTS(SELECT 1 FROM public.node_fence_incidents f
        WHERE (f.cloud_account_id,f.region,f.cloud_instance_id)=(NEW.cloud_account_id,NEW.region,NEW.cloud_instance_id)) THEN
        RAISE EXCEPTION 'fenced cloud instance cannot be enrolled or enabled' USING ERRCODE='23514';END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER runtime_node_cloud_tombstone BEFORE INSERT OR UPDATE ON runtime_nodes
FOR EACH ROW EXECUTE FUNCTION sandbox_reject_fenced_node();
CREATE FUNCTION sandbox_gate_launch_on_node() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE node_id uuid;allowed boolean;
BEGIN
    IF TG_TABLE_NAME='launch_permits' THEN node_id:=NEW.runtime_node_id;
    ELSE SELECT p.runtime_node_id INTO node_id FROM public.launch_permits p WHERE p.tenant_id=NEW.tenant_id AND p.id=NEW.base_permit_id;END IF;
    -- SHARE conflicts with the incident's disable transaction. That transaction
    -- never locks tenant resources, preserving workspace -> instance lock order.
    SELECT n.enabled AND NOT EXISTS(SELECT 1 FROM public.node_fence_incidents f WHERE (f.cloud_account_id,f.region,f.cloud_instance_id)=(n.cloud_account_id,n.region,n.cloud_instance_id))
      INTO allowed FROM public.runtime_nodes n WHERE n.id=node_id FOR SHARE;
    IF allowed IS DISTINCT FROM true THEN RAISE EXCEPTION 'node no longer accepts launches or extensions' USING ERRCODE='23514';END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER launch_permit_node_gate BEFORE INSERT ON launch_permits FOR EACH ROW EXECUTE FUNCTION sandbox_gate_launch_on_node();
CREATE TRIGGER launch_extension_node_gate BEFORE INSERT ON launch_permit_extensions FOR EACH ROW EXECUTE FUNCTION sandbox_gate_launch_on_node();
CREATE FUNCTION sandbox_index_launch() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    INSERT INTO public.runtime_launch_index(permit_id,runtime_node_id,tenant_id) VALUES(NEW.id,NEW.runtime_node_id,NEW.tenant_id);
    RETURN NEW;
END $$;
CREATE TRIGGER launch_permit_node_index AFTER INSERT ON launch_permits FOR EACH ROW EXECUTE FUNCTION sandbox_index_launch();
-- Owner backfill under an exclusive DDL lock; normal runtime RLS remains enabled.
ALTER TABLE launch_permits NO FORCE ROW LEVEL SECURITY;
INSERT INTO runtime_launch_index(permit_id,runtime_node_id,tenant_id) SELECT id,runtime_node_id,tenant_id FROM launch_permits;
ALTER TABLE launch_permits FORCE ROW LEVEL SECURITY;
REVOKE ALL ON node_fence_incidents,node_fence_targets,node_fence_events,runtime_launch_index FROM PUBLIC;
REVOKE ALL ON FUNCTION sandbox_preserve_node_fence(),sandbox_reject_fenced_node(),sandbox_gate_launch_on_node(),sandbox_index_launch() FROM PUBLIC;

-- The only cross-tenant mutation exposed to the dedicated fencing login. The
-- durable owner-created incident and its exact permit set are mandatory.
CREATE FUNCTION sandbox_freeze_node_launch(incident uuid,permit uuid,worker text,token bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE f public.node_fence_incidents%ROWTYPE;t public.node_fence_targets%ROWTYPE;
    p public.launch_permits%ROWTYPE;i public.instances%ROWTYPE;old_op public.operations%ROWTYPE;
    stop_id uuid;system_actor uuid;current_epoch uuid;now_at timestamptz;previous_tenant text:=current_setting('app.tenant_id',true);
BEGIN
    SELECT * INTO f FROM public.node_fence_incidents WHERE id=incident FOR UPDATE;
    IF NOT FOUND OR f.state<>'FREEZING' OR f.lease_owner IS DISTINCT FROM worker OR f.lease_token<>token OR f.lease_until<=clock_timestamp() THEN
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
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
    RETURN true;
END $$;
REVOKE ALL ON FUNCTION sandbox_freeze_node_launch(uuid,uuid,text,bigint) FROM PUBLIC;
