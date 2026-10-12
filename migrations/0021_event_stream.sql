-- A stream position is allocated in the event's own transaction. The project
-- head row remains locked until COMMIT, so a reader cannot pass an uncommitted
-- lower position. PostgreSQL sequences and event timestamps do not provide this.
LOCK TABLE projects, domain_events IN ACCESS EXCLUSIVE MODE;

CREATE TABLE event_stream_heads (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    epoch uuid NOT NULL DEFAULT gen_random_uuid(),
    last_sequence bigint NOT NULL DEFAULT 0 CHECK(last_sequence >= 0),
    PRIMARY KEY(tenant_id,project_id),
    FOREIGN KEY(tenant_id,project_id) REFERENCES projects(tenant_id,id)
);
CREATE TABLE event_stream_positions (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    sequence bigint NOT NULL CHECK(sequence > 0),
    event_id uuid NOT NULL UNIQUE REFERENCES domain_events(id),
    PRIMARY KEY(tenant_id,project_id,sequence),
    FOREIGN KEY(tenant_id,project_id) REFERENCES event_stream_heads(tenant_id,project_id)
);

-- The owner temporarily bypasses FORCE RLS while holding both source tables
-- exclusively. All changes, including re-enabling FORCE, commit atomically.
-- Enumerating tenants through a forced-RLS owner query would silently miss data.
ALTER TABLE projects NO FORCE ROW LEVEL SECURITY;
ALTER TABLE domain_events NO FORCE ROW LEVEL SECURITY;
INSERT INTO event_stream_heads(tenant_id,project_id)
    SELECT tenant_id,id FROM projects;
INSERT INTO event_stream_positions(tenant_id,project_id,sequence,event_id)
    SELECT tenant_id,project_id,
           row_number() OVER(PARTITION BY tenant_id,project_id ORDER BY occurred_at,id),id
    FROM domain_events;
UPDATE event_stream_heads h SET last_sequence=p.last_sequence
FROM (SELECT tenant_id,project_id,max(sequence) AS last_sequence
      FROM event_stream_positions GROUP BY tenant_id,project_id) p
WHERE h.tenant_id=p.tenant_id AND h.project_id=p.project_id;
ALTER TABLE domain_events FORCE ROW LEVEL SECURITY;
ALTER TABLE projects FORCE ROW LEVEL SECURITY;

ALTER TABLE event_stream_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_stream_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON event_stream_heads
    USING(tenant_id=sandbox_current_tenant_id())
    WITH CHECK(tenant_id=sandbox_current_tenant_id());
ALTER TABLE event_stream_positions ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_stream_positions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON event_stream_positions
    USING(tenant_id=sandbox_current_tenant_id())
    WITH CHECK(tenant_id=sandbox_current_tenant_id());

CREATE FUNCTION sandbox_initialize_event_stream() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    INSERT INTO public.event_stream_heads(tenant_id,project_id) VALUES(NEW.tenant_id,NEW.id);
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION sandbox_initialize_event_stream() FROM PUBLIC;
CREATE TRIGGER project_event_stream AFTER INSERT ON projects
    FOR EACH ROW EXECUTE FUNCTION sandbox_initialize_event_stream();

CREATE FUNCTION sandbox_sequence_event() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE position bigint;
BEGIN
    UPDATE public.event_stream_heads SET last_sequence=last_sequence+1
    WHERE tenant_id=NEW.tenant_id AND project_id=NEW.project_id
    RETURNING last_sequence INTO position;
    IF position IS NULL THEN
        RAISE EXCEPTION 'event stream head missing' USING ERRCODE='23514';
    END IF;
    INSERT INTO public.event_stream_positions(tenant_id,project_id,sequence,event_id)
        VALUES(NEW.tenant_id,NEW.project_id,position,NEW.id);
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION sandbox_sequence_event() FROM PUBLIC;
CREATE TRIGGER domain_event_stream AFTER INSERT ON domain_events
    FOR EACH ROW EXECUTE FUNCTION sandbox_sequence_event();

CREATE FUNCTION sandbox_preserve_event_position() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'event stream positions are append only' USING ERRCODE='23514';
END;
$$;
REVOKE ALL ON FUNCTION sandbox_preserve_event_position() FROM PUBLIC;
CREATE TRIGGER event_position_immutable BEFORE UPDATE OR DELETE ON event_stream_positions
    FOR EACH ROW EXECUTE FUNCTION sandbox_preserve_event_position();

REVOKE ALL ON event_stream_heads,event_stream_positions FROM PUBLIC;
