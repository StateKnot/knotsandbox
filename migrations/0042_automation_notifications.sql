-- Project-scoped historical automation exceptions. Delivery is by the normal
-- authenticated read API; acknowledgement never changes a run or its effects.
CREATE TABLE automation_notifications (
 id uuid PRIMARY KEY,
 tenant_id uuid NOT NULL, project_id uuid NOT NULL, instance_id uuid NOT NULL,
 automation_id uuid NOT NULL, run_id uuid NOT NULL, source_event_id uuid NOT NULL,
 source_run_version bigint NOT NULL CHECK(source_run_version>0),
 source_status text NOT NULL CHECK(source_status IN('FAILED','OUTCOME_UNKNOWN')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 acknowledged_at timestamptz, acknowledged_by uuid REFERENCES principals(id),
 version bigint NOT NULL DEFAULT 1 CHECK(version IN(1,2)),
 FOREIGN KEY(tenant_id,project_id) REFERENCES projects(tenant_id,id),
 FOREIGN KEY(tenant_id,project_id,instance_id) REFERENCES instances(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,automation_id) REFERENCES automations(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,run_id) REFERENCES automation_runs(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,source_event_id) REFERENCES domain_events(tenant_id,project_id,id),
 UNIQUE(tenant_id,id), UNIQUE(tenant_id,run_id,source_status),
 CHECK(id=source_event_id),
 CHECK((acknowledged_at IS NULL)=(acknowledged_by IS NULL)),
 CHECK((version=1)=(acknowledged_at IS NULL))
);
ALTER TABLE automation_notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE automation_notifications FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON automation_notifications
 USING(tenant_id=public.sandbox_current_tenant_id())
 WITH CHECK(tenant_id=public.sandbox_current_tenant_id());
REVOKE ALL ON automation_notifications FROM PUBLIC;
CREATE INDEX automation_notification_history
 ON automation_notifications(tenant_id,project_id,created_at DESC,id DESC);
CREATE INDEX automation_notification_instance_history
 ON automation_notifications(tenant_id,project_id,instance_id,created_at DESC,id DESC);

CREATE FUNCTION sandbox_guard_automation_notification() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF (to_jsonb(NEW)-ARRAY['acknowledged_at','acknowledged_by','version'])
  IS DISTINCT FROM(to_jsonb(OLD)-ARRAY['acknowledged_at','acknowledged_by','version'])
  OR OLD.version<>1 OR OLD.acknowledged_at IS NOT NULL
  OR NEW.version<>2 OR NEW.acknowledged_at IS NULL OR NEW.acknowledged_by IS NULL
  OR NEW.acknowledged_at<OLD.created_at OR NEW.acknowledged_at>clock_timestamp()
  OR NOT public.sandbox_principal_enabled(NEW.acknowledged_by) THEN
  RAISE EXCEPTION 'notification source is immutable and acknowledgement is one-way' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER immutable_automation_notification BEFORE UPDATE ON automation_notifications
 FOR EACH ROW EXECUTE FUNCTION sandbox_guard_automation_notification();
CREATE TRIGGER automation_notification_no_delete BEFORE DELETE ON automation_notifications
 FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_audit_mutation();

-- This trigger derives only real exception facts in the caller's tenant. It
-- does not trust event payload arguments, manufacture run outcomes or replay
-- old events. Legacy writers need no direct privileges on the new table.
CREATE FUNCTION sandbox_capture_automation_notification() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE source public.automation_runs;
BEGIN
 IF NEW.event_type IS DISTINCT FROM 'automations:run.changed'
  OR NOT COALESCE(NEW.payload->>'status' IN('FAILED','OUTCOME_UNKNOWN'),false) THEN RETURN NEW; END IF;
 SELECT * INTO source FROM public.automation_runs r
 WHERE r.tenant_id=NEW.tenant_id AND r.project_id=NEW.project_id
  AND r.id=NEW.aggregate_id AND r.version=NEW.aggregate_version
  AND r.status=NEW.payload->>'status' AND NEW.request_id=r.id;
 IF NOT FOUND OR NEW.tenant_id IS DISTINCT FROM public.sandbox_current_tenant_id() THEN
  RAISE EXCEPTION 'notification event does not match its persisted run' USING ERRCODE='23514';
 END IF;
 INSERT INTO public.automation_notifications(
  id,tenant_id,project_id,instance_id,automation_id,run_id,source_event_id,source_run_version,source_status)
 VALUES(NEW.id,source.tenant_id,source.project_id,source.instance_id,source.automation_id,
  source.id,NEW.id,source.version,source.status)
 ON CONFLICT(tenant_id,run_id,source_status) DO NOTHING;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION sandbox_capture_automation_notification() FROM PUBLIC;
-- PostgreSQL orders same-kind triggers by name: the existing stream allocator
-- must take the project head lock before this trigger takes notification keys.
CREATE TRIGGER domain_event_stream_automation_notification_capture AFTER INSERT ON domain_events
 FOR EACH ROW EXECUTE FUNCTION sandbox_capture_automation_notification();

-- The API receives no UPDATE privilege on event stream state. This narrow lock
-- preserves the producer's head -> notification order without changing state.
CREATE FUNCTION sandbox_lock_automation_notification_head(tenant uuid,project uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF tenant IS DISTINCT FROM public.sandbox_current_tenant_id() THEN
  RAISE EXCEPTION 'notification head tenant mismatch' USING ERRCODE='P4030';
 END IF;
 PERFORM 1 FROM public.event_stream_heads h
  WHERE h.tenant_id=tenant AND h.project_id=project FOR UPDATE;
 IF NOT FOUND THEN
  RAISE EXCEPTION 'notification event stream head missing' USING ERRCODE='23514';
 END IF;
END $$;
REVOKE ALL ON FUNCTION sandbox_lock_automation_notification_head(uuid,uuid) FROM PUBLIC;
