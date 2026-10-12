-- Independent formal automation component. Version 0038 was never published
-- and must remain unused; a future restore component receives a new version.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public._sqlx_migrations WHERE version=38) THEN
  RAISE EXCEPTION 'unpublished migration 0038 cannot precede formal automation';
 END IF;
END $$;
-- Durable UTC automation authority. No tokens, callback URLs or host scripts.
CREATE TABLE automation_delegations (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL, project_id uuid NOT NULL,
 principal_id uuid NOT NULL REFERENCES principals(id), identity_issuer text NOT NULL,
 identity_subject text NOT NULL, instance_id uuid NOT NULL, workspace_id uuid NOT NULL,
 allowed_actions text[] NOT NULL CHECK(cardinality(allowed_actions) BETWEEN 1 AND 8),
 expires_at timestamptz NOT NULL, revoked_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,project_id) REFERENCES projects(tenant_id,id),
 FOREIGN KEY(tenant_id,project_id,instance_id) REFERENCES instances(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,workspace_id) REFERENCES workspaces(tenant_id,project_id,id),
 UNIQUE(tenant_id,project_id,id),
 CHECK(octet_length(identity_issuer) BETWEEN 1 AND 2048),
 CHECK(octet_length(identity_subject) BETWEEN 1 AND 512),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '366 days'),
 CHECK(allowed_actions<@ARRAY['automations:write','instances:start','instances:stop','instances:restart','instances:delete','instances:renew','instances:hard_stop','executions:create','backups:create','events:read']::text[])
);
CREATE TABLE automations (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL, project_id uuid NOT NULL,
 delegation_id uuid NOT NULL, instance_id uuid NOT NULL, workspace_id uuid NOT NULL,
 creator_principal_id uuid NOT NULL REFERENCES principals(id), name text NOT NULL,
 action_kind text NOT NULL CHECK(action_kind IN('START','STOP','RESTART','DELETE','RENEW','EXECUTE','BACKUP')),
 action jsonb NOT NULL CHECK(jsonb_typeof(action)='object' AND octet_length(action::text)<=65536),
 trigger_kind text NOT NULL CHECK(trigger_kind IN('ONCE','CRON_UTC','EVENT')),
 scheduled_at timestamptz, cron_expression text, event_type text, event_aggregate_id uuid,
 next_due_at timestamptz, event_sequence bigint NOT NULL DEFAULT 0 CHECK(event_sequence>=0),
 event_stream_epoch uuid,
 status text NOT NULL DEFAULT 'ACTIVE' CHECK(status IN('ACTIVE','PAUSED','REVOKED','EXHAUSTED','EXPIRED')),
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 run_budget integer NOT NULL DEFAULT 100 CHECK(run_budget BETWEEN 1 AND 10000),
 emitted_runs integer NOT NULL DEFAULT 0 CHECK(emitted_runs BETWEEN 0 AND run_budget),
 minimum_interval_seconds integer NOT NULL DEFAULT 60 CHECK(minimum_interval_seconds BETWEEN 60 AND 86400),
 grace_seconds integer NOT NULL DEFAULT 300 CHECK(grace_seconds BETWEEN 1 AND 3600),
 last_emitted_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,project_id,delegation_id) REFERENCES automation_delegations(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,instance_id) REFERENCES instances(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,workspace_id) REFERENCES workspaces(tenant_id,project_id,id),
 UNIQUE(tenant_id,project_id,id), UNIQUE(tenant_id,id),
 UNIQUE(tenant_id,delegation_id),
 CHECK(char_length(name) BETWEEN 1 AND 128),
 CHECK((trigger_kind='ONCE' AND scheduled_at IS NOT NULL AND cron_expression IS NULL AND event_type IS NULL AND event_aggregate_id IS NULL)
    OR(trigger_kind='CRON_UTC' AND scheduled_at IS NULL AND cron_expression IS NOT NULL AND event_type IS NULL AND event_aggregate_id IS NULL)
    OR(trigger_kind='EVENT' AND scheduled_at IS NULL AND cron_expression IS NULL AND event_type IS NOT NULL AND event_aggregate_id IS NOT NULL AND next_due_at IS NULL)),
 CHECK((trigger_kind='EVENT')=(event_stream_epoch IS NOT NULL)),
 CHECK(cron_expression IS NULL OR octet_length(cron_expression) BETWEEN 7 AND 128),
 CHECK(event_type IS NULL OR octet_length(event_type) BETWEEN 1 AND 128)
);
ALTER TABLE domain_events ADD CONSTRAINT domain_events_scoped_identity UNIQUE(tenant_id,project_id,id);
CREATE TABLE automation_runs (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL, project_id uuid NOT NULL, automation_id uuid NOT NULL,
 automation_version bigint NOT NULL CHECK(automation_version>0), delegation_id uuid NOT NULL,
 creator_principal_id uuid NOT NULL REFERENCES principals(id),
 instance_id uuid NOT NULL, workspace_id uuid NOT NULL,
 scheduled_for timestamptz, source_event_id uuid, source_event_sequence bigint,
 skipped_through timestamptz,
 operation_kind text NOT NULL CHECK(operation_kind IN('START','STOP','RESTART','DELETE','RENEW','EXECUTE','BACKUP')),
 original_request jsonb NOT NULL CHECK(jsonb_typeof(original_request)='object' AND octet_length(original_request::text)<=65536),
 operation_request jsonb NOT NULL CHECK(jsonb_typeof(operation_request)='object' AND octet_length(operation_request::text)<=65536),
 expected_resource_version bigint NOT NULL CHECK(expected_resource_version>0),
 expected_generation bigint NOT NULL CHECK(expected_generation>=0), cluster_epoch uuid NOT NULL,
 produced_resource_id uuid NOT NULL,
 management_key text NOT NULL,
 request_sha256 text NOT NULL CHECK(request_sha256~'^[0-9a-f]{64}$'),
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 status text NOT NULL DEFAULT 'PENDING' CHECK(status IN('PENDING','CLAIMED','DISPATCHING','SUBMITTED','SUCCEEDED','FAILED','SKIPPED','CANCELLED','OUTCOME_UNKNOWN')),
 lease_owner text, lease_token bigint NOT NULL DEFAULT 0 CHECK(lease_token>=0), lease_until timestamptz,
 dispatch_attempt_id uuid, dispatch_started_at timestamptz,
 operation_id uuid, accepted_at timestamptz, failure_code text,
 deadline timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), updated_at timestamptz NOT NULL DEFAULT clock_timestamp(), completed_at timestamptz,
 FOREIGN KEY(tenant_id,project_id,automation_id) REFERENCES automations(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,delegation_id) REFERENCES automation_delegations(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,instance_id) REFERENCES instances(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,workspace_id) REFERENCES workspaces(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,source_event_id) REFERENCES domain_events(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,instance_id,operation_id) REFERENCES operations(tenant_id,project_id,instance_id,id),
 UNIQUE(tenant_id,project_id,id), UNIQUE(tenant_id,id), UNIQUE(tenant_id,operation_id),
 CHECK((scheduled_for IS NULL)<>(source_event_id IS NULL)),
 CHECK((source_event_id IS NULL)=(source_event_sequence IS NULL)),
 CHECK(source_event_sequence IS NULL OR source_event_sequence>0),
 CHECK(management_key='automation-run:'||id::text),
 CHECK((lease_owner IS NULL)=(lease_until IS NULL)),
 CHECK(lease_owner IS NULL OR char_length(lease_owner) BETWEEN 1 AND 128),
 CHECK((dispatch_attempt_id IS NULL)=(dispatch_started_at IS NULL)),
 CHECK((operation_id IS NULL)=(accepted_at IS NULL)),
 CHECK(status NOT IN('DISPATCHING','SUBMITTED','OUTCOME_UNKNOWN') OR dispatch_attempt_id IS NOT NULL),
 CHECK(status<>'SUBMITTED' OR operation_id IS NOT NULL),
 CHECK(status NOT IN('SUCCEEDED','FAILED','SKIPPED','CANCELLED') OR completed_at IS NOT NULL),
 CHECK(deadline>created_at OR status='SKIPPED'),
 CHECK(skipped_through IS NULL OR(status='SKIPPED' AND skipped_through>=scheduled_for))
);
CREATE UNIQUE INDEX automation_unique_scheduled_run ON automation_runs(tenant_id,automation_id,scheduled_for) WHERE scheduled_for IS NOT NULL;
CREATE UNIQUE INDEX automation_unique_event_run ON automation_runs(tenant_id,automation_id,source_event_id) WHERE source_event_id IS NOT NULL;
CREATE UNIQUE INDEX automation_one_unclosed_run ON automation_runs(tenant_id,automation_id) WHERE status IN('PENDING','CLAIMED','DISPATCHING','SUBMITTED','OUTCOME_UNKNOWN');
CREATE INDEX automation_run_history ON automation_runs(tenant_id,automation_id,created_at DESC,id DESC);
CREATE INDEX automation_history ON automations(tenant_id,project_id,created_at DESC,id DESC);
CREATE INDEX automation_active_limits ON automations(tenant_id,project_id) WHERE status IN('ACTIVE','PAUSED');
-- Global queue contains only routing IDs and leases. Runtime table access is
-- revoked; the eventual definer claims only IDs, then commits before tenant I/O.
CREATE TABLE automation_claims (
 automation_id uuid PRIMARY KEY, tenant_id uuid NOT NULL, eligible_at timestamptz NOT NULL,
 claim_cluster_epoch uuid,
 lease_owner text, lease_token bigint NOT NULL DEFAULT 0 CHECK(lease_token>=0), lease_until timestamptz,
 FOREIGN KEY(tenant_id,automation_id) REFERENCES automations(tenant_id,id),
 CHECK((lease_owner IS NULL)=(lease_until IS NULL)),
 CHECK(lease_owner IS NULL OR char_length(lease_owner) BETWEEN 1 AND 128)
);
REVOKE ALL ON automation_claims FROM PUBLIC;
CREATE INDEX automation_claims_due ON automation_claims(eligible_at,automation_id) INCLUDE(lease_until);
DO $$ DECLARE tab text; BEGIN
 FOREACH tab IN ARRAY ARRAY['automation_delegations','automations','automation_runs'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
  EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.sandbox_current_tenant_id()) WITH CHECK(tenant_id=public.sandbox_current_tenant_id())',tab);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',tab);
 END LOOP;
END $$;
CREATE TRIGGER automation_delegation_no_delete BEFORE DELETE ON automation_delegations FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_audit_mutation();
CREATE TRIGGER automation_no_delete BEFORE DELETE ON automations FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_audit_mutation();
CREATE TRIGGER automation_run_no_delete BEFORE DELETE ON automation_runs FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_audit_mutation();

-- Delegations are a bounded, immutable intersection with current authority.
-- They never elevate a SYSTEM principal or store an access/refresh token.
CREATE FUNCTION sandbox_automation_required_actions(kind text,event_rule boolean) RETURNS text[]
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT CASE kind
 WHEN 'START' THEN ARRAY['instances:start']
 WHEN 'STOP' THEN ARRAY['instances:stop','instances:hard_stop']
 WHEN 'RESTART' THEN ARRAY['instances:restart','instances:hard_stop']
 WHEN 'DELETE' THEN ARRAY['instances:delete','instances:hard_stop']
 WHEN 'RENEW' THEN ARRAY['instances:renew']
 WHEN 'EXECUTE' THEN ARRAY['executions:create','instances:hard_stop']
 WHEN 'BACKUP' THEN ARRAY['backups:create'] ELSE ARRAY['INVALID'] END
 ||ARRAY['automations:write']||CASE WHEN event_rule THEN ARRAY['events:read'] ELSE ARRAY[]::text[] END
$$;
REVOKE ALL ON FUNCTION sandbox_automation_required_actions(text,boolean) FROM PUBLIC;

CREATE FUNCTION sandbox_check_automation_delegation(actor uuid,project uuid,actions text[],expiry timestamptz) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=public.sandbox_current_tenant_id();required text;unbounded boolean;latest timestamptz;matches bigint;
BEGIN
 IF NOT public.sandbox_principal_enabled(actor) OR NOT EXISTS(SELECT 1 FROM public.principals p WHERE p.id=actor AND p.kind IN('USER','SERVICE')) THEN
  RAISE EXCEPTION 'creator unavailable' USING ERRCODE='P4030';END IF;
 FOREACH required IN ARRAY actions LOOP
  SELECT count(*),coalesce(bool_or(g.expires_at IS NULL),false),max(g.expires_at) INTO matches,unbounded,latest
  FROM public.grants g WHERE g.tenant_id=tenant AND g.principal_id=actor AND(g.project_id=project OR g.project_id IS NULL)
   AND(g.action=required OR g.action='*') AND g.enabled AND g.revoked_at IS NULL AND(g.expires_at IS NULL OR g.expires_at>clock_timestamp());
  IF matches=0 OR(NOT unbounded AND expiry>latest) THEN RAISE EXCEPTION 'delegation exceeds current expiry authority' USING ERRCODE='P4030';END IF;
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION sandbox_check_automation_delegation(uuid,uuid,text[],timestamptz) FROM PUBLIC;

CREATE FUNCTION sandbox_automation_authorized(requested_tenant uuid,automation uuid) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT requested_tenant=public.sandbox_current_tenant_id() AND EXISTS(
  SELECT 1 FROM public.automations a
  JOIN public.automation_delegations d ON(d.tenant_id,d.project_id,d.id)=(a.tenant_id,a.project_id,a.delegation_id)
  JOIN public.projects p ON(p.tenant_id,p.id)=(a.tenant_id,a.project_id)
  JOIN public.tenants t ON t.id=a.tenant_id
  WHERE a.tenant_id=requested_tenant AND a.id=automation AND p.enabled AND t.enabled
   AND a.status='ACTIVE' AND d.revoked_at IS NULL AND d.expires_at>clock_timestamp()
   AND(a.trigger_kind<>'EVENT' OR EXISTS(SELECT 1 FROM public.event_stream_heads h WHERE(h.tenant_id,h.project_id,h.epoch)=(a.tenant_id,a.project_id,a.event_stream_epoch)))
   AND(d.principal_id,d.instance_id,d.workspace_id)=(a.creator_principal_id,a.instance_id,a.workspace_id)
   AND public.sandbox_principal_enabled(d.principal_id)
   AND EXISTS(SELECT 1 FROM public.sandbox_resolve_identity(d.identity_issuer,d.identity_subject) i
       WHERE i.principal_id=d.principal_id AND i.enabled AND i.kind IN('USER','SERVICE'))
   AND NOT EXISTS(SELECT 1 FROM unnest(public.sandbox_automation_required_actions(a.action_kind,a.trigger_kind='EVENT')) required(action)
       WHERE NOT required.action=ANY(d.allowed_actions) OR NOT EXISTS(
        SELECT 1 FROM public.grants g WHERE g.tenant_id=a.tenant_id AND g.principal_id=d.principal_id
         AND(g.project_id=a.project_id OR g.project_id IS NULL) AND(g.action=required.action OR g.action='*')
         AND g.enabled AND g.revoked_at IS NULL AND(g.expires_at IS NULL OR g.expires_at>clock_timestamp())))
 )
$$;
REVOKE ALL ON FUNCTION sandbox_automation_authorized(uuid,uuid) FROM PUBLIC;

CREATE FUNCTION sandbox_guard_automation_delegation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF (to_jsonb(NEW)-'revoked_at') IS DISTINCT FROM (to_jsonb(OLD)-'revoked_at')
 OR(OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at)
 OR(OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL AND NEW.revoked_at>clock_timestamp()) THEN
  RAISE EXCEPTION 'automation delegation is immutable except irreversible revocation' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER immutable_automation_delegation BEFORE UPDATE ON automation_delegations
FOR EACH ROW EXECUTE FUNCTION sandbox_guard_automation_delegation();

CREATE FUNCTION sandbox_guard_automation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NOT EXISTS(SELECT 1 FROM public.automation_delegations d WHERE d.tenant_id=NEW.tenant_id AND d.project_id=NEW.project_id AND d.id=NEW.delegation_id
     AND(d.principal_id,d.instance_id,d.workspace_id)=(NEW.creator_principal_id,NEW.instance_id,NEW.workspace_id)
     AND public.sandbox_automation_required_actions(NEW.action_kind,NEW.trigger_kind='EVENT')<@d.allowed_actions)
   OR NOT EXISTS(SELECT 1 FROM public.instances i WHERE i.tenant_id=NEW.tenant_id AND i.id=NEW.instance_id AND i.workspace_id=NEW.workspace_id)
   OR NEW.emitted_runs<>0 OR NEW.event_sequence<>0 OR NEW.version<>1 OR NEW.status<>'ACTIVE' THEN
   RAISE EXCEPTION 'automation authority scope mismatch' USING ERRCODE='23514';
  END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['next_due_at','event_sequence','status','version','emitted_runs','last_emitted_at','updated_at'])
      IS DISTINCT FROM(to_jsonb(OLD)-ARRAY['next_due_at','event_sequence','status','version','emitted_runs','last_emitted_at','updated_at'])
   OR NEW.emitted_runs<OLD.emitted_runs OR NEW.emitted_runs>OLD.emitted_runs+1 OR NEW.event_sequence<OLD.event_sequence
   OR(OLD.status IN('REVOKED','EXHAUSTED','EXPIRED') AND NEW.status IS DISTINCT FROM OLD.status)
   OR(NEW.status<>OLD.status AND NEW.version<>OLD.version+1)
   OR(NEW.status=OLD.status AND NEW.version<>OLD.version) THEN
   RAISE EXCEPTION 'automation policy and budget are immutable' USING ERRCODE='23514';
  END IF;
  NEW.updated_at:=clock_timestamp();
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER immutable_automation BEFORE INSERT OR UPDATE ON automations
FOR EACH ROW EXECUTE FUNCTION sandbox_guard_automation();

CREATE FUNCTION sandbox_guard_automation_run() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NOT EXISTS(SELECT 1 FROM public.automations a WHERE(a.tenant_id,a.project_id,a.id)=(NEW.tenant_id,NEW.project_id,NEW.automation_id)
   AND(a.version,a.delegation_id,a.creator_principal_id,a.instance_id,a.workspace_id,a.action_kind)=
      (NEW.automation_version,NEW.delegation_id,NEW.creator_principal_id,NEW.instance_id,NEW.workspace_id,NEW.operation_kind))
   OR NEW.operation_id IS NOT NULL OR NEW.dispatch_attempt_id IS NOT NULL OR NEW.lease_token<>0
   OR NEW.status NOT IN('PENDING','SKIPPED') OR NEW.version<>1 THEN
   RAISE EXCEPTION 'automation run scope mismatch' USING ERRCODE='23514';
  END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['version','status','lease_owner','lease_token','lease_until','dispatch_attempt_id','dispatch_started_at','operation_id','accepted_at','failure_code','updated_at','completed_at'])
   IS DISTINCT FROM(to_jsonb(OLD)-ARRAY['version','status','lease_owner','lease_token','lease_until','dispatch_attempt_id','dispatch_started_at','operation_id','accepted_at','failure_code','updated_at','completed_at'])
   OR NEW.lease_token<OLD.lease_token
   OR(OLD.dispatch_attempt_id IS NOT NULL AND(NEW.dispatch_attempt_id,NEW.dispatch_started_at) IS DISTINCT FROM(OLD.dispatch_attempt_id,OLD.dispatch_started_at))
   OR(OLD.operation_id IS NOT NULL AND(NEW.operation_id,NEW.accepted_at) IS DISTINCT FROM(OLD.operation_id,OLD.accepted_at))
   OR(OLD.status IN('SUCCEEDED','FAILED','SKIPPED','CANCELLED') AND NEW IS DISTINCT FROM OLD)
   OR NOT(NEW.status=OLD.status OR
      (OLD.status='PENDING' AND NEW.status IN('CLAIMED','CANCELLED','SKIPPED')) OR
      (OLD.status='CLAIMED' AND NEW.status IN('DISPATCHING','CANCELLED','SKIPPED')) OR
      (OLD.status='DISPATCHING' AND NEW.status IN('SUBMITTED','OUTCOME_UNKNOWN','CANCELLED','SKIPPED','FAILED')) OR
      (OLD.status='OUTCOME_UNKNOWN' AND NEW.status IN('DISPATCHING','SUBMITTED','CANCELLED','SKIPPED','FAILED')) OR
      (OLD.status='SUBMITTED' AND NEW.status IN('SUCCEEDED','FAILED'))) THEN
   RAISE EXCEPTION 'automation run is immutable or transition invalid' USING ERRCODE='23514';
  END IF;
  NEW.version:=OLD.version+1;NEW.updated_at:=clock_timestamp();
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER immutable_automation_run BEFORE INSERT OR UPDATE ON automation_runs
FOR EACH ROW EXECUTE FUNCTION sandbox_guard_automation_run();

-- Routing queue updates are definer-only. Claims commit before any resource
-- lock. No login can enumerate or UPDATE lease tokens through the table.
CREATE FUNCTION sandbox_sync_automation_queue() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a public.automations; due timestamptz; expiry timestamptz;
BEGIN
 IF TG_TABLE_NAME='automations' THEN a:=NEW;
 ELSE SELECT * INTO a FROM public.automations WHERE tenant_id=NEW.tenant_id AND id=NEW.automation_id; END IF;
 SELECT min(least(coalesce(r.lease_until,clock_timestamp()),clock_timestamp()+interval '30 seconds')) INTO due
 FROM public.automation_runs r WHERE r.tenant_id=a.tenant_id AND r.automation_id=a.id
  AND r.status IN('PENDING','CLAIMED','DISPATCHING','SUBMITTED','OUTCOME_UNKNOWN');
 IF due IS NULL AND a.status='ACTIVE' THEN
  due:=CASE WHEN a.trigger_kind='EVENT' THEN clock_timestamp()+interval '5 seconds' ELSE a.next_due_at END;
 END IF;
 IF a.status IN('ACTIVE','PAUSED') THEN
  SELECT d.expires_at INTO expiry FROM public.automation_delegations d WHERE d.tenant_id=a.tenant_id AND d.id=a.delegation_id;
  due:=least(coalesce(due,expiry),expiry);
 END IF;
 IF due IS NULL THEN DELETE FROM public.automation_claims WHERE automation_id=a.id;
 ELSE INSERT INTO public.automation_claims(automation_id,tenant_id,eligible_at) VALUES(a.id,a.tenant_id,due)
 ON CONFLICT(automation_id) DO UPDATE SET eligible_at=excluded.eligible_at; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION sandbox_sync_automation_queue() FROM PUBLIC;
CREATE TRIGGER automation_queue AFTER INSERT OR UPDATE ON automations FOR EACH ROW EXECUTE FUNCTION sandbox_sync_automation_queue();
CREATE TRIGGER automation_run_queue AFTER INSERT OR UPDATE ON automation_runs FOR EACH ROW EXECUTE FUNCTION sandbox_sync_automation_queue();

CREATE FUNCTION sandbox_claim_automation(worker text) RETURNS TABLE(tenant_id uuid,automation_id uuid,lease_token bigint,lease_until timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE q public.automation_claims; now_at timestamptz:=clock_timestamp();
BEGIN
 IF worker IS NULL OR char_length(worker) NOT BETWEEN 1 AND 128 THEN RAISE EXCEPTION 'invalid worker' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.platform_configuration c WHERE c.singleton AND NOT c.safe_mode) THEN RETURN; END IF;
 SELECT * INTO q FROM public.automation_claims c WHERE c.eligible_at<=now_at AND(c.lease_until IS NULL OR c.lease_until<=now_at)
 ORDER BY c.eligible_at,c.automation_id FOR UPDATE SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN; END IF;
 UPDATE public.automation_claims c SET lease_owner=worker,lease_token=c.lease_token+1,lease_until=now_at+interval '30 seconds',
 claim_cluster_epoch=(SELECT p.cluster_epoch FROM public.platform_configuration p WHERE p.singleton)
 WHERE c.automation_id=q.automation_id RETURNING * INTO q;
 RETURN QUERY SELECT q.tenant_id,q.automation_id,q.lease_token,q.lease_until;
END $$;
REVOKE ALL ON FUNCTION sandbox_claim_automation(text) FROM PUBLIC;

CREATE FUNCTION sandbox_check_automation_claim(requested_tenant uuid,automation uuid,worker text,token bigint) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT requested_tenant=public.sandbox_current_tenant_id() AND EXISTS(SELECT 1 FROM public.automation_claims c
 WHERE(c.tenant_id,c.automation_id,c.lease_owner,c.lease_token)=(requested_tenant,automation,worker,token) AND c.lease_until>clock_timestamp()
 AND EXISTS(SELECT 1 FROM public.platform_configuration p WHERE p.singleton AND NOT p.safe_mode AND p.cluster_epoch=c.claim_cluster_epoch))
$$;
REVOKE ALL ON FUNCTION sandbox_check_automation_claim(uuid,uuid,text,bigint) FROM PUBLIC;

CREATE FUNCTION sandbox_finish_automation_claim(requested_tenant uuid,automation uuid,worker text,token bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF requested_tenant IS DISTINCT FROM public.sandbox_current_tenant_id() THEN RETURN false; END IF;
 UPDATE public.automation_claims c SET lease_owner=NULL,lease_until=NULL,eligible_at=greatest(c.eligible_at,clock_timestamp()+interval '5 seconds')
 WHERE(c.tenant_id,c.automation_id,c.lease_owner,c.lease_token)=(requested_tenant,automation,worker,token) AND c.lease_until>clock_timestamp();
 RETURN FOUND;
END $$;
REVOKE ALL ON FUNCTION sandbox_finish_automation_claim(uuid,uuid,text,bigint) FROM PUBLIC;

CREATE FUNCTION sandbox_bind_automation_run_claim(requested_tenant uuid,run uuid,worker text,token bigint)
RETURNS TABLE(dispatch_attempt_id uuid,produced_resource_id uuid,lease_until timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r public.automation_runs; a public.automations; until_at timestamptz;
BEGIN
 IF requested_tenant IS DISTINCT FROM public.sandbox_current_tenant_id() THEN RAISE EXCEPTION 'tenant mismatch' USING ERRCODE='P4040'; END IF;
 SELECT * INTO r FROM public.automation_runs x WHERE x.tenant_id=requested_tenant AND x.id=run;
 IF NOT FOUND THEN RAISE EXCEPTION 'run missing' USING ERRCODE='P4040'; END IF;
 PERFORM 1 FROM public.workspaces w WHERE w.tenant_id=requested_tenant AND w.id=r.workspace_id FOR UPDATE;
 PERFORM 1 FROM public.instances i WHERE i.tenant_id=requested_tenant AND i.id=r.instance_id FOR UPDATE;
 SELECT * INTO a FROM public.automations x WHERE x.tenant_id=requested_tenant AND x.id=r.automation_id FOR UPDATE;
 PERFORM 1 FROM public.automation_delegations d WHERE d.tenant_id=requested_tenant AND d.id=r.delegation_id FOR UPDATE;
 SELECT * INTO r FROM public.automation_runs x WHERE x.tenant_id=requested_tenant AND x.id=run FOR UPDATE;
 IF NOT public.sandbox_check_automation_claim(requested_tenant,r.automation_id,worker,token)
 OR NOT public.sandbox_automation_authorized(requested_tenant,r.automation_id)
 OR r.automation_version<>a.version OR r.deadline<=clock_timestamp() OR r.operation_id IS NOT NULL
 OR r.status NOT IN('PENDING','CLAIMED','DISPATCHING','OUTCOME_UNKNOWN') THEN
  RAISE EXCEPTION 'run claim authority changed' USING ERRCODE='P4090';
 END IF;
 SELECT c.lease_until INTO until_at FROM public.automation_claims c WHERE c.automation_id=r.automation_id;
 IF r.status='PENDING' THEN UPDATE public.automation_runs SET status='CLAIMED' WHERE tenant_id=requested_tenant AND id=run; END IF;
 UPDATE public.automation_runs x SET status='DISPATCHING',lease_owner=worker,lease_token=token,lease_until=until_at,
 dispatch_attempt_id=coalesce(x.dispatch_attempt_id,gen_random_uuid()),dispatch_started_at=coalesce(x.dispatch_started_at,clock_timestamp())
 WHERE x.tenant_id=requested_tenant AND x.id=run RETURNING * INTO r;
 RETURN QUERY SELECT r.dispatch_attempt_id,r.produced_resource_id,r.lease_until;
END $$;
REVOKE ALL ON FUNCTION sandbox_bind_automation_run_claim(uuid,uuid,text,bigint) FROM PUBLIC;

-- Existing acceptors already hold workspace -> instance -> optional old
-- operation. Only then take automation authority -> run. Pause/revoke/prepare
-- take those same resource locks first; the queue claim never takes them.
CREATE FUNCTION sandbox_gate_automation_operation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r public.automation_runs; a public.automations; actual_version bigint; generation bigint;
BEGIN
 IF session_user<>'sandbox_automation' THEN
  IF EXISTS(SELECT 1 FROM public.automation_runs x WHERE x.tenant_id=NEW.tenant_id AND x.id=NEW.request_id) THEN
   RAISE EXCEPTION 'automation request IDs require dedicated acceptance' USING ERRCODE='P4030';
  END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO r FROM public.automation_runs x WHERE x.tenant_id=NEW.tenant_id AND x.id=NEW.request_id;
 IF NOT FOUND OR NEW.tenant_id IS DISTINCT FROM public.sandbox_current_tenant_id() THEN
  RAISE EXCEPTION 'automation run missing' USING ERRCODE='P4030';
 END IF;
 SELECT * INTO a FROM public.automations x WHERE x.tenant_id=r.tenant_id AND x.id=r.automation_id FOR UPDATE;
 PERFORM 1 FROM public.automation_delegations d WHERE d.tenant_id=r.tenant_id AND d.id=r.delegation_id FOR UPDATE;
 SELECT * INTO r FROM public.automation_runs x WHERE x.tenant_id=r.tenant_id AND x.id=r.id FOR UPDATE;
 IF (NEW.project_id,NEW.instance_id,NEW.workspace_id,NEW.actor_principal_id,NEW.kind,NEW.request)
 IS DISTINCT FROM(r.project_id,r.instance_id,r.workspace_id,r.creator_principal_id,r.operation_kind,r.operation_request)
 OR r.operation_id IS NOT NULL OR r.status<>'DISPATCHING'
 OR r.automation_version<>a.version OR r.deadline<=clock_timestamp()
 OR r.lease_until<=clock_timestamp() OR r.lease_until IS NULL
 OR r.id::text IS DISTINCT FROM nullif(current_setting('app.automation_run_id',true),'')
 OR r.lease_owner IS DISTINCT FROM nullif(current_setting('app.automation_owner',true),'')
 OR r.lease_token::text IS DISTINCT FROM nullif(current_setting('app.automation_token',true),'')
 OR r.dispatch_attempt_id::text IS DISTINCT FROM nullif(current_setting('app.automation_attempt',true),'')
 OR r.produced_resource_id::text IS DISTINCT FROM nullif(current_setting('app.automation_resource',true),'')
 OR r.management_key IS DISTINCT FROM nullif(current_setting('app.automation_key',true),'')
 OR r.request_sha256 IS DISTINCT FROM nullif(current_setting('app.automation_digest',true),'')
 OR NOT public.sandbox_check_automation_claim(r.tenant_id,r.automation_id,r.lease_owner,r.lease_token)
 OR NOT public.sandbox_automation_authorized(r.tenant_id,r.automation_id)
 OR NOT EXISTS(SELECT 1 FROM public.platform_configuration c WHERE c.singleton AND NOT c.safe_mode AND c.cluster_epoch=r.cluster_epoch) THEN
  RAISE EXCEPTION 'automation acceptance fence changed' USING ERRCODE='P4090';
 END IF;
 SELECT i.runtime_generation,CASE WHEN r.operation_kind='BACKUP' THEN w.spec_version ELSE i.spec_version END INTO generation,actual_version
 FROM public.instances i JOIN public.workspaces w ON w.tenant_id=i.tenant_id AND w.id=i.workspace_id
 WHERE i.tenant_id=r.tenant_id AND i.id=r.instance_id;
 IF(generation,actual_version) IS DISTINCT FROM(r.expected_generation,r.expected_resource_version) THEN
  RAISE EXCEPTION 'automation resource changed' USING ERRCODE='P4120';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION sandbox_gate_automation_operation() FROM PUBLIC;
CREATE TRIGGER automation_acceptance_gate BEFORE INSERT ON operations FOR EACH ROW EXECUTE FUNCTION sandbox_gate_automation_operation();

CREATE FUNCTION sandbox_link_automation_operation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF session_user='sandbox_automation' THEN
  UPDATE public.automation_runs SET status='SUBMITTED',operation_id=NEW.id,accepted_at=clock_timestamp()
  WHERE tenant_id=NEW.tenant_id AND id=NEW.request_id AND status='DISPATCHING' AND operation_id IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'automation operation link failed' USING ERRCODE='P4090'; END IF;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION sandbox_link_automation_operation() FROM PUBLIC;
CREATE TRIGGER automation_operation_link AFTER INSERT ON operations FOR EACH ROW EXECUTE FUNCTION sandbox_link_automation_operation();

CREATE FUNCTION sandbox_final_automation_operation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r public.automation_runs;
BEGIN
 IF session_user<>'sandbox_automation' THEN RETURN NEW; END IF;
 SELECT * INTO r FROM public.automation_runs x WHERE x.tenant_id=NEW.tenant_id AND x.id=NEW.request_id;
 IF r.operation_id IS DISTINCT FROM NEW.id OR r.status<>'SUBMITTED' OR r.deadline<=clock_timestamp()
 OR r.lease_until<=clock_timestamp() OR r.lease_until IS NULL
 OR NOT public.sandbox_check_automation_claim(r.tenant_id,r.automation_id,r.lease_owner,r.lease_token)
 OR NOT public.sandbox_automation_authorized(r.tenant_id,r.automation_id)
 OR NOT EXISTS(SELECT 1 FROM public.platform_configuration c WHERE c.singleton AND NOT c.safe_mode AND c.cluster_epoch=r.cluster_epoch) THEN
  RAISE EXCEPTION 'automation authority expired before commit' USING ERRCODE='P4090';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION sandbox_final_automation_operation() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER automation_final_acceptance AFTER INSERT ON operations DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION sandbox_final_automation_operation();

-- Preserve formal 0036 delegation semantics; only the implemented action set expands.
CREATE OR REPLACE FUNCTION sandbox_mutate_project_grant(actor uuid,project uuid,mutation text,grant_id uuid,target_principal uuid,delegated_action text,requested_expiry timestamptz,will_enable boolean,expected_version bigint)
RETURNS public.grants LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=public.sandbox_current_tenant_id();result public.grants;
BEGIN
    PERFORM public.sandbox_lock_identity_tenant(tenant);
    IF delegated_action IS NULL OR delegated_action NOT IN('instances:create','instances:read','instances:start','instances:stop','instances:restart','instances:renew','instances:delete','instances:hard_stop','workspaces:read','workspaces:delete','operations:read','events:read','audit:read','capabilities:read','executions:create','executions:read','executions:cancel','executions:output:read','grants:read','grants:write','backups:create','backups:read','diagnoses:create','diagnoses:read','files:read','files:write','automations:read','automations:write') THEN
        RAISE EXCEPTION 'unsupported grant action' USING ERRCODE='P4000';END IF;
    IF mutation NOT IN('CREATE','UPDATE','REVOKE') THEN RAISE EXCEPTION 'unknown grant mutation' USING ERRCODE='P4000';END IF;
    IF mutation<>'CREATE' THEN
        SELECT g.* INTO result FROM public.grants g WHERE g.tenant_id=tenant AND g.project_id=project AND g.id=grant_id FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION 'grant not found' USING ERRCODE='P4040';END IF;
        IF expected_version IS DISTINCT FROM result.version THEN RAISE EXCEPTION 'grant version mismatch' USING ERRCODE='P4120';END IF;
        IF (target_principal,delegated_action) IS DISTINCT FROM(result.principal_id,result.action) THEN
            RAISE EXCEPTION 'grant identity is immutable' USING ERRCODE='P4000';END IF;
    END IF;
    IF will_enable AND mutation<>'REVOKE' AND requested_expiry IS NOT NULL AND requested_expiry<=clock_timestamp() THEN
        RAISE EXCEPTION 'grant expiry must be in the future' USING ERRCODE='P4000';END IF;
    PERFORM public.sandbox_check_grant_delegation(actor,project,delegated_action,requested_expiry,will_enable AND mutation<>'REVOKE');
    IF NOT EXISTS(SELECT 1 FROM public.tenant_principals tp JOIN public.principals p ON p.id=tp.principal_id
        WHERE tp.tenant_id=tenant AND tp.principal_id=target_principal AND p.kind<>'SYSTEM') THEN
        RAISE EXCEPTION 'grant target not found' USING ERRCODE='P4040';END IF;
    IF mutation='CREATE' THEN
        IF EXISTS(SELECT 1 FROM public.grants g WHERE g.tenant_id=tenant AND g.project_id=project AND g.principal_id=target_principal AND g.action=delegated_action) THEN
            RAISE EXCEPTION 'grant already exists' USING ERRCODE='P4090';END IF;
        INSERT INTO public.grants(id,tenant_id,project_id,principal_id,action,enabled,expires_at)
        VALUES(grant_id,tenant,project,target_principal,delegated_action,will_enable,requested_expiry) RETURNING * INTO result;
    ELSE
        UPDATE public.grants SET enabled=will_enable AND mutation<>'REVOKE',expires_at=CASE WHEN mutation='REVOKE' THEN result.expires_at ELSE requested_expiry END,
            revoked_at=CASE WHEN mutation='REVOKE' THEN clock_timestamp() WHEN will_enable THEN NULL ELSE revoked_at END
        WHERE tenant_id=tenant AND id=grant_id RETURNING * INTO result;
    END IF;
    RETURN result;
END $$;
