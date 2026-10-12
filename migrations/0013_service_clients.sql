-- Tenant-local OIDC service registrations. No IdP credential or token is stored.
ALTER TABLE principal_identities ADD CONSTRAINT identity_id_principal UNIQUE(id,principal_id);
ALTER TABLE tenant_principals ADD COLUMN service_identity_id uuid;
ALTER TABLE tenant_principals ADD CONSTRAINT tenant_service_identity
    FOREIGN KEY(service_identity_id,principal_id) REFERENCES principal_identities(id,principal_id);
CREATE INDEX tenant_service_clients_page ON tenant_principals(tenant_id,created_at DESC,id DESC) WHERE service_identity_id IS NOT NULL;
CREATE OR REPLACE FUNCTION sandbox_update_tenant_principal_version() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF (NEW.id,NEW.tenant_id,NEW.principal_id,NEW.created_at) IS DISTINCT FROM
       (OLD.id,OLD.tenant_id,OLD.principal_id,OLD.created_at)
       OR (OLD.service_identity_id IS NOT NULL AND NEW.service_identity_id IS DISTINCT FROM OLD.service_identity_id) THEN
        RAISE EXCEPTION 'tenant principal identity is immutable' USING ERRCODE='23514';
    END IF;
    NEW.version:=OLD.version+1;NEW.updated_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TYPE sandbox_service_client AS (id uuid,tenant_id uuid,principal_id uuid,issuer text,subject text,display_name text,enabled boolean,identity_enabled boolean,version bigint,created_at timestamptz,updated_at timestamptz);

CREATE FUNCTION sandbox_authorize_service_clients(actor uuid,required_action text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=public.sandbox_current_tenant_id();
BEGIN
    IF tenant IS NULL OR required_action IS NULL OR required_action NOT IN('service_clients:read','service_clients:write')
       OR NOT public.sandbox_principal_enabled(actor)
       OR NOT EXISTS(SELECT 1 FROM public.principals p WHERE p.id=actor AND p.kind<>'SYSTEM')
       OR NOT EXISTS(SELECT 1 FROM public.tenants t WHERE t.id=tenant AND t.enabled)
       OR NOT EXISTS(SELECT 1 FROM public.grants g WHERE g.tenant_id=tenant AND g.principal_id=actor
            AND g.project_id IS NULL AND g.action IN(required_action,'*') AND g.enabled AND g.revoked_at IS NULL
            AND (g.expires_at IS NULL OR g.expires_at>clock_timestamp())) THEN
        RAISE EXCEPTION 'service client scope not available' USING ERRCODE='P4040';
    END IF;
END $$;

-- Restoration can reactivate old grants. It must not exceed the restorer's
-- management/action/scope/expiry authority, even though no grant row changes.
CREATE FUNCTION sandbox_check_service_client_enable(actor uuid,target uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=public.sandbox_current_tenant_id();target_grant record;required_action text;
        count_grants bigint;unbounded boolean;latest timestamptz;ceiling timestamptz;observed_now timestamptz:=clock_timestamp();
BEGIN
    PERFORM public.sandbox_authorize_service_clients(actor,'service_clients:write');
    FOR target_grant IN SELECT g.project_id,g.action,g.expires_at FROM public.grants g
      WHERE g.tenant_id=tenant AND g.principal_id=target AND g.enabled AND g.revoked_at IS NULL
        AND (g.expires_at IS NULL OR g.expires_at>observed_now) LOOP
        ceiling:=NULL;
        FOREACH required_action IN ARRAY ARRAY['service_clients:write','grants:write',target_grant.action] LOOP
            SELECT count(*),COALESCE(bool_or(g.expires_at IS NULL),false),max(g.expires_at)
            INTO count_grants,unbounded,latest FROM public.grants g
            WHERE g.tenant_id=tenant AND g.principal_id=actor AND g.enabled AND g.revoked_at IS NULL
              AND (g.expires_at IS NULL OR g.expires_at>observed_now)
              AND (g.action=required_action OR g.action='*')
              AND (g.project_id IS NULL OR (required_action<>'service_clients:write' AND g.project_id=target_grant.project_id));
            IF count_grants=0 THEN RAISE EXCEPTION 'restore exceeds authority' USING ERRCODE='P4030';END IF;
            IF NOT unbounded AND (ceiling IS NULL OR latest<ceiling) THEN ceiling:=latest;END IF;
        END LOOP;
        IF ceiling IS NOT NULL AND (target_grant.expires_at IS NULL OR target_grant.expires_at>ceiling) THEN
            RAISE EXCEPTION 'restore exceeds authority expiry' USING ERRCODE='P4030';END IF;
    END LOOP;
END $$;

CREATE FUNCTION sandbox_read_service_clients(actor uuid,client_id uuid,cutoff timestamptz,after_time timestamptz,after_id uuid,page_limit integer)
RETURNS SETOF public.sandbox_service_client LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    PERFORM public.sandbox_authorize_service_clients(actor,'service_clients:read');
    IF page_limit IS NULL OR page_limit<1 OR page_limit>101 THEN RAISE EXCEPTION 'invalid page limit' USING ERRCODE='P4000';END IF;
    RETURN QUERY SELECT tp.id,tp.tenant_id,tp.principal_id,i.issuer,i.subject,tp.display_name,tp.enabled,(i.enabled AND p.enabled),tp.version,tp.created_at,tp.updated_at
      FROM public.tenant_principals tp JOIN public.principal_identities i ON i.id=tp.service_identity_id
      JOIN public.principals p ON p.id=tp.principal_id
      WHERE tp.tenant_id=public.sandbox_current_tenant_id() AND p.kind='SERVICE'
        AND (client_id IS NULL OR tp.id=client_id) AND tp.created_at<=cutoff
        AND (after_time IS NULL OR (tp.created_at,tp.id)<(after_time,after_id))
      ORDER BY tp.created_at DESC,tp.id DESC LIMIT page_limit;
END $$;

CREATE FUNCTION sandbox_mutate_service_client(actor uuid,mutation text,client_id uuid,identity_issuer text,identity_subject text,local_name text,will_enable boolean,expected_version bigint)
RETURNS public.sandbox_service_client LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=public.sandbox_current_tenant_id();registered public.tenant_principals;
        identity public.principal_identities;principal public.principals;result public.sandbox_service_client;
BEGIN
    PERFORM public.sandbox_lock_identity_tenant(tenant);
    PERFORM public.sandbox_authorize_service_clients(actor,'service_clients:write');
    IF mutation NOT IN('CREATE','UPDATE') OR mutation IS NULL OR local_name IS NULL
       OR char_length(local_name) NOT BETWEEN 1 AND 128 OR local_name~'[[:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid service client request' USING ERRCODE='P4000';END IF;
    IF mutation='CREATE' THEN
        IF identity_issuer IS NULL OR char_length(identity_issuer) NOT BETWEEN 1 AND 2048 OR identity_issuer~'[[:cntrl:]]'
           OR identity_subject IS NULL OR char_length(identity_subject) NOT BETWEEN 1 AND 512 OR identity_subject~'[[:cntrl:]]'
           OR will_enable IS DISTINCT FROM true THEN RAISE EXCEPTION 'invalid service identity' USING ERRCODE='P4000';END IF;
        -- Stable identity serialization across tenants, always after own tenant lock.
        PERFORM pg_advisory_xact_lock(hashtextextended('sandbox-oidc:'||length(identity_issuer)::text||':'||identity_issuer||identity_subject,0));
        SELECT i.* INTO identity FROM public.principal_identities i WHERE i.issuer=identity_issuer AND i.subject=identity_subject;
        IF FOUND THEN
            SELECT p.* INTO principal FROM public.principals p WHERE p.id=identity.principal_id;
            IF NOT identity.enabled OR NOT principal.enabled OR principal.kind<>'SERVICE' THEN
                RAISE EXCEPTION 'service identity unavailable' USING ERRCODE='P4040';END IF;
        ELSE
            INSERT INTO public.principals(kind,display_name) VALUES('SERVICE','Registered service') RETURNING * INTO principal;
            INSERT INTO public.principal_identities(principal_id,issuer,subject) VALUES(principal.id,identity_issuer,identity_subject) RETURNING * INTO identity;
        END IF;
        SELECT tp.* INTO registered FROM public.tenant_principals tp WHERE tp.tenant_id=tenant AND tp.principal_id=principal.id;
        IF FOUND THEN
            IF registered.service_identity_id IS NOT NULL THEN RAISE EXCEPTION 'service client exists' USING ERRCODE='P4090';END IF;
            IF NOT registered.enabled THEN RAISE EXCEPTION 'service identity unavailable' USING ERRCODE='P4040';END IF;
            UPDATE public.tenant_principals SET service_identity_id=identity.id,display_name=local_name WHERE id=registered.id RETURNING * INTO registered;
        ELSE
            INSERT INTO public.tenant_principals(id,tenant_id,principal_id,service_identity_id,display_name)
              VALUES(client_id,tenant,principal.id,identity.id,local_name) RETURNING * INTO registered;
        END IF;
    ELSE
        SELECT tp.* INTO registered FROM public.tenant_principals tp WHERE tp.tenant_id=tenant AND tp.id=client_id AND tp.service_identity_id IS NOT NULL FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION 'service client not found' USING ERRCODE='P4040';END IF;
        IF expected_version IS DISTINCT FROM registered.version THEN RAISE EXCEPTION 'service client version mismatch' USING ERRCODE='P4120';END IF;
        SELECT i.* INTO identity FROM public.principal_identities i WHERE i.id=registered.service_identity_id;
        SELECT p.* INTO principal FROM public.principals p WHERE p.id=registered.principal_id;
        IF identity_issuer IS NOT NULL OR identity_subject IS NOT NULL OR will_enable IS NULL OR principal.kind<>'SERVICE' THEN
            RAISE EXCEPTION 'service identity is immutable' USING ERRCODE='P4000';END IF;
        IF will_enable AND NOT registered.enabled THEN
            IF NOT identity.enabled OR NOT principal.enabled THEN RAISE EXCEPTION 'service identity unavailable' USING ERRCODE='P4040';END IF;
            PERFORM public.sandbox_check_service_client_enable(actor,registered.principal_id);
        END IF;
        UPDATE public.tenant_principals SET enabled=will_enable,display_name=local_name WHERE tenant_id=tenant AND id=client_id RETURNING * INTO registered;
    END IF;
    SELECT registered.id,registered.tenant_id,registered.principal_id,identity.issuer,identity.subject,registered.display_name,registered.enabled,(identity.enabled AND principal.enabled),registered.version,registered.created_at,registered.updated_at INTO result;
    RETURN result;
END $$;
REVOKE ALL ON FUNCTION sandbox_authorize_service_clients(uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION sandbox_check_service_client_enable(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION sandbox_read_service_clients(uuid,uuid,timestamptz,timestamptz,uuid,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION sandbox_mutate_service_client(uuid,text,uuid,text,text,text,boolean,bigint) FROM PUBLIC;
