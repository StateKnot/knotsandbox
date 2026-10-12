-- Tenant-local identity status must never mutate the global principal directory.
CREATE TABLE tenant_principals (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    principal_id uuid NOT NULL REFERENCES principals(id),
    display_name text NOT NULL CHECK(char_length(display_name) BETWEEN 1 AND 128),
    enabled boolean NOT NULL DEFAULT true,
    version bigint NOT NULL DEFAULT 1 CHECK(version>0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(tenant_id,principal_id),
    UNIQUE(tenant_id,id)
);
-- Only the migration owner temporarily bypasses FORCE to enumerate tenants.
-- Transactional DDL keeps runtime RLS enabled throughout the migration.
ALTER TABLE grants NO FORCE ROW LEVEL SECURITY;
INSERT INTO tenant_principals(tenant_id,principal_id,display_name)
SELECT DISTINCT g.tenant_id,g.principal_id,p.display_name
FROM grants g JOIN principals p ON p.id=g.principal_id WHERE p.kind<>'SYSTEM';
ALTER TABLE grants FORCE ROW LEVEL SECURITY;
ALTER TABLE tenant_principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_principals FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_principals
USING(tenant_id=sandbox_current_tenant_id()) WITH CHECK(tenant_id=sandbox_current_tenant_id());

CREATE FUNCTION sandbox_update_tenant_principal_version() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF (NEW.id,NEW.tenant_id,NEW.principal_id,NEW.created_at) IS DISTINCT FROM
       (OLD.id,OLD.tenant_id,OLD.principal_id,OLD.created_at) THEN
        RAISE EXCEPTION 'tenant principal identity is immutable' USING ERRCODE='23514';
    END IF;
    NEW.version:=OLD.version+1;NEW.updated_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER tenant_principal_version BEFORE UPDATE ON tenant_principals
FOR EACH ROW EXECUTE FUNCTION sandbox_update_tenant_principal_version();

-- Owner/bootstrap grant insertion registers legacy principals locally. The API
-- receives no generic grant INSERT permission; its narrow function checks that
-- a target registration already exists before it inserts a grant.
CREATE FUNCTION sandbox_register_grant_principal() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    INSERT INTO public.tenant_principals(tenant_id,principal_id,display_name)
    SELECT NEW.tenant_id,p.id,p.display_name FROM public.principals p
    WHERE p.id=NEW.principal_id AND p.kind<>'SYSTEM'
    ON CONFLICT(tenant_id,principal_id) DO NOTHING;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION sandbox_register_grant_principal() FROM PUBLIC;
CREATE TRIGGER register_grant_principal AFTER INSERT ON grants
FOR EACH ROW EXECUTE FUNCTION sandbox_register_grant_principal();

CREATE OR REPLACE FUNCTION sandbox_principal_enabled(principal uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
    SELECT COALESCE((SELECT p.enabled AND public.sandbox_current_tenant_id() IS NOT NULL
        AND (p.kind='SYSTEM' OR EXISTS(SELECT 1 FROM public.tenant_principals tp
            WHERE tp.tenant_id=public.sandbox_current_tenant_id() AND tp.principal_id=p.id AND tp.enabled))
        FROM public.principals p WHERE p.id=principal),false)
$$;
REVOKE ALL ON FUNCTION sandbox_principal_enabled(uuid) FROM PUBLIC;

ALTER TABLE grants DROP CONSTRAINT grants_action_check;
ALTER TABLE grants ADD CONSTRAINT grants_action_check CHECK(action='*' OR action~'^[a-z][a-z0-9_]*(:[a-z][a-z0-9_]*)+$');
ALTER TABLE grants ADD COLUMN version bigint NOT NULL DEFAULT 1 CHECK(version>0);
ALTER TABLE grants ADD COLUMN updated_at timestamptz NOT NULL DEFAULT clock_timestamp();
CREATE FUNCTION sandbox_update_grant_version() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF (NEW.id,NEW.tenant_id,NEW.project_id,NEW.principal_id,NEW.action,NEW.created_at) IS DISTINCT FROM
       (OLD.id,OLD.tenant_id,OLD.project_id,OLD.principal_id,OLD.action,OLD.created_at) THEN
        RAISE EXCEPTION 'grant scope and action are immutable' USING ERRCODE='23514';
    END IF;
    NEW.version:=OLD.version+1;NEW.updated_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER grant_version BEFORE UPDATE ON grants
FOR EACH ROW EXECUTE FUNCTION sandbox_update_grant_version();
CREATE INDEX grants_project_history ON grants(tenant_id,project_id,created_at DESC,id DESC);

CREATE TABLE management_receipts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    project_id uuid,
    principal_id uuid NOT NULL REFERENCES principals(id),
    action text NOT NULL,
    target_id uuid NOT NULL,
    key_hash text NOT NULL CHECK(key_hash~'^[0-9a-f]{64}$'),
    request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),
    resource_id uuid NOT NULL,
    response_status smallint NOT NULL CHECK(response_status IN(200,201)),
    response_body jsonb NOT NULL CHECK(jsonb_typeof(response_body)='object' AND octet_length(response_body::text)<=65536),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    tombstone_until timestamptz NOT NULL,
    FOREIGN KEY(tenant_id,project_id) REFERENCES projects(tenant_id,id),
    UNIQUE(tenant_id,principal_id,action,target_id,key_hash),
    CHECK(expires_at>=created_at+interval '7 days'),
    CHECK(tombstone_until>=expires_at+interval '90 days')
);
ALTER TABLE management_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE management_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON management_receipts USING(tenant_id=sandbox_current_tenant_id()) WITH CHECK(tenant_id=sandbox_current_tenant_id());
CREATE INDEX management_receipts_cleanup ON management_receipts(tombstone_until);
CREATE TRIGGER immutable_scope BEFORE UPDATE ON management_receipts FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_scope_change();

CREATE FUNCTION sandbox_lock_identity_tenant(requested_tenant uuid) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF requested_tenant IS NULL OR requested_tenant IS DISTINCT FROM public.sandbox_current_tenant_id() THEN
        RAISE EXCEPTION 'identity tenant context mismatch' USING ERRCODE='P4040';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('sandbox-identity:'||requested_tenant::text,0));
END $$;
REVOKE ALL ON FUNCTION sandbox_lock_identity_tenant(uuid) FROM PUBLIC;

-- Authority is the intersection of management permission and the delegated
-- action, including the maximum expiry of each currently effective grant set.
CREATE FUNCTION sandbox_check_grant_delegation(actor uuid,project uuid,delegated_action text,requested_expiry timestamptz,will_enable boolean) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=public.sandbox_current_tenant_id();observed_now timestamptz:=clock_timestamp();
        required_action text;matches bigint;unbounded boolean;latest timestamptz;ceiling timestamptz;
BEGIN
    IF tenant IS NULL OR NOT public.sandbox_principal_enabled(actor)
       OR NOT EXISTS(SELECT 1 FROM public.principals p WHERE p.id=actor AND p.kind<>'SYSTEM')
       OR NOT EXISTS(SELECT 1 FROM public.projects p JOIN public.tenants t ON t.id=p.tenant_id WHERE p.tenant_id=tenant AND p.id=project AND p.enabled AND t.enabled) THEN
        RAISE EXCEPTION 'grant project is not available' USING ERRCODE='P4040';
    END IF;
    FOREACH required_action IN ARRAY ARRAY['grants:write',delegated_action] LOOP
        SELECT count(*),COALESCE(bool_or(g.expires_at IS NULL),false),max(g.expires_at)
        INTO matches,unbounded,latest FROM public.grants g
        WHERE g.tenant_id=tenant AND g.principal_id=actor AND (g.project_id=project OR g.project_id IS NULL)
          AND (g.action=required_action OR g.action='*') AND g.enabled AND g.revoked_at IS NULL
          AND (g.expires_at IS NULL OR g.expires_at>observed_now);
        IF matches=0 THEN RAISE EXCEPTION 'delegation is not authorized' USING ERRCODE='P4030';END IF;
        IF NOT unbounded AND (ceiling IS NULL OR latest<ceiling) THEN ceiling:=latest;END IF;
    END LOOP;
    IF will_enable AND ceiling IS NOT NULL AND (requested_expiry IS NULL OR requested_expiry>ceiling) THEN
        RAISE EXCEPTION 'delegation exceeds current authority expiry' USING ERRCODE='P4030';
    END IF;
END $$;
REVOKE ALL ON FUNCTION sandbox_check_grant_delegation(uuid,uuid,text,timestamptz,boolean) FROM PUBLIC;

CREATE FUNCTION sandbox_mutate_project_grant(actor uuid,project uuid,mutation text,grant_id uuid,target_principal uuid,delegated_action text,requested_expiry timestamptz,will_enable boolean,expected_version bigint)
RETURNS public.grants LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=public.sandbox_current_tenant_id();result public.grants;
BEGIN
    PERFORM public.sandbox_lock_identity_tenant(tenant);
    IF delegated_action IS NULL OR delegated_action NOT IN('instances:create','instances:read','instances:start','instances:stop','instances:restart','instances:renew','instances:delete','instances:hard_stop','operations:read','events:read','audit:read','capabilities:read','executions:create','executions:read','executions:cancel','executions:output:read','grants:read','grants:write') THEN
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
REVOKE ALL ON FUNCTION sandbox_mutate_project_grant(uuid,uuid,text,uuid,uuid,text,timestamptz,boolean,bigint) FROM PUBLIC;
REVOKE ALL ON tenant_principals,management_receipts FROM PUBLIC;
