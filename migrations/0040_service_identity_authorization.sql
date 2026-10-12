-- Exact OAuth SERVICE client binding. Existing SERVICE identities have no safe
-- inferred client identifier: fail closed until the owner explicitly binds the
-- reviewed IdP client using sandbox-admin bind-service-identity. USER subjects
-- remain independent of the login client and never acquire a service binding.
-- Matches Rust str::trim and char::is_control, independently of database locale.
-- OAuth identifiers retain their exact bytes; whitespace is never normalized.
CREATE FUNCTION sandbox_valid_oauth_client_id(client text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT octet_length(client) BETWEEN 1 AND 256
   AND btrim(client,U&'\0009\000a\000b\000c\000d\0020\0085\00a0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200a\2028\2029\202f\205f\3000')<>''
   AND client !~ U&'[\0001-\001f\007f-\009f]'
$$;
REVOKE ALL ON FUNCTION sandbox_valid_oauth_client_id(text) FROM PUBLIC;

ALTER TABLE principal_identities ADD COLUMN service_client_id text
 CHECK(service_client_id IS NULL OR sandbox_valid_oauth_client_id(service_client_id));
ALTER TABLE principal_identities ADD COLUMN service_binding_generation bigint NOT NULL DEFAULT 0 CHECK(service_binding_generation>=0);
ALTER TYPE sandbox_service_client ADD ATTRIBUTE client_id text;

CREATE FUNCTION sandbox_check_identity_client_binding() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE principal_kind text;
BEGIN
 SELECT kind INTO principal_kind FROM public.principals WHERE id=NEW.principal_id;
 IF (principal_kind<>'SERVICE' AND (NEW.service_client_id IS NOT NULL OR NEW.service_binding_generation<>0))
 OR (NEW.service_client_id IS NULL AND NEW.service_binding_generation<>0)
 OR (NEW.service_client_id IS NOT NULL AND NEW.service_binding_generation=0) THEN
  RAISE EXCEPTION 'invalid identity client binding shape' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER identity_client_binding_shape BEFORE INSERT OR UPDATE ON principal_identities
 FOR EACH ROW EXECUTE FUNCTION sandbox_check_identity_client_binding();
REVOKE ALL ON FUNCTION sandbox_check_identity_client_binding() FROM PUBLIC;


CREATE FUNCTION sandbox_resolve_identity(identity_issuer text,identity_subject text,token_client_id text)
RETURNS TABLE(principal_id uuid,kind text,enabled boolean,authz_version bigint,binding_generation bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT p.id,p.kind,p.enabled AND i.enabled AND
   CASE p.kind WHEN 'USER' THEN i.service_client_id IS NULL
    WHEN 'SERVICE' THEN i.service_client_id IS NOT NULL AND i.service_client_id=token_client_id
    ELSE false END,p.authz_version,i.service_binding_generation
 FROM public.principal_identities i JOIN public.principals p ON p.id=i.principal_id
 WHERE i.issuer=identity_issuer AND i.subject=identity_subject
$$;
REVOKE ALL ON FUNCTION sandbox_resolve_identity(text,text,text) FROM PUBLIC;

CREATE TABLE service_identity_binding_audit(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),principal_id uuid NOT NULL REFERENCES principals(id),
 changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),database_role text NOT NULL,
 previous_client_id text,new_client_id text NOT NULL,
 reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 256 AND reason !~ '[[:cntrl:]]')
);
REVOKE ALL ON service_identity_binding_audit FROM PUBLIC;

-- Only the migration/table owner receives EXECUTE (not sandbox_app). Exact CAS
-- serializes global binding/rotation; the monotonic generation irreversibly
-- invalidates old delegations even if an operator later binds the old client again.
CREATE FUNCTION sandbox_bind_service_identity(identity_issuer text,identity_subject text,
 expected_client text,new_client text,change_reason text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE identity public.principal_identities;principal public.principals;
BEGIN
 IF public.sandbox_valid_oauth_client_id(new_client) IS DISTINCT FROM true
    OR (expected_client IS NOT NULL AND NOT public.sandbox_valid_oauth_client_id(expected_client))
    OR change_reason IS NULL OR char_length(change_reason) NOT BETWEEN 1 AND 256 OR change_reason~'[[:cntrl:]]' THEN
  RAISE EXCEPTION 'invalid client binding request' USING ERRCODE='P4000';END IF;
 SELECT i.* INTO identity FROM public.principal_identities i
  WHERE i.issuer=identity_issuer AND i.subject=identity_subject FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'service identity unavailable' USING ERRCODE='P4040';END IF;
 SELECT p.* INTO principal FROM public.principals p WHERE p.id=identity.principal_id FOR UPDATE;
 IF principal.kind<>'SERVICE' OR NOT principal.enabled OR NOT identity.enabled THEN
  RAISE EXCEPTION 'service identity unavailable' USING ERRCODE='P4040';END IF;
 IF identity.service_client_id IS DISTINCT FROM expected_client THEN
  RAISE EXCEPTION 'service client binding changed' USING ERRCODE='P4120';END IF;
 IF expected_client IS NOT DISTINCT FROM new_client THEN RETURN principal.id;END IF;
 UPDATE public.principal_identities SET service_client_id=new_client,service_binding_generation=service_binding_generation+1 WHERE id=identity.id;
 INSERT INTO public.service_identity_binding_audit(principal_id,database_role,previous_client_id,new_client_id,reason)
 VALUES(principal.id,session_user,expected_client,new_client,change_reason);
 RETURN principal.id;
END $$;
REVOKE ALL ON FUNCTION sandbox_bind_service_identity(text,text,text,text,text) FROM PUBLIC;

-- Reject the old tenant mutation entry point, including an accidentally retained
-- runtime grant. It cannot register an identity without a reviewed client_id.
CREATE OR REPLACE FUNCTION sandbox_mutate_service_client(actor uuid,mutation text,client_id uuid,identity_issuer text,identity_subject text,local_name text,will_enable boolean,expected_version bigint)
RETURNS public.sandbox_service_client LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'client binding required' USING ERRCODE='P4000';END $$;

CREATE OR REPLACE FUNCTION sandbox_read_service_clients(actor uuid,client_id uuid,cutoff timestamptz,after_time timestamptz,after_id uuid,page_limit integer)
RETURNS SETOF public.sandbox_service_client LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    PERFORM public.sandbox_authorize_service_clients(actor,'service_clients:read');
    IF page_limit IS NULL OR page_limit<1 OR page_limit>101 THEN RAISE EXCEPTION 'invalid page limit' USING ERRCODE='P4000';END IF;
    RETURN QUERY SELECT tp.id,tp.tenant_id,tp.principal_id,i.issuer,i.subject,tp.display_name,tp.enabled,(i.enabled AND p.enabled),tp.version,tp.created_at,tp.updated_at,i.service_client_id
      FROM public.tenant_principals tp JOIN public.principal_identities i ON i.id=tp.service_identity_id
      JOIN public.principals p ON p.id=tp.principal_id
      WHERE tp.tenant_id=public.sandbox_current_tenant_id() AND p.kind='SERVICE'
        AND (client_id IS NULL OR tp.id=client_id) AND tp.created_at<=cutoff
        AND (after_time IS NULL OR (tp.created_at,tp.id)<(after_time,after_id))
      ORDER BY tp.created_at DESC,tp.id DESC LIMIT page_limit;
END $$;


CREATE FUNCTION sandbox_mutate_service_client(actor uuid,mutation text,client_id uuid,identity_issuer text,identity_subject text,identity_client text,local_name text,will_enable boolean,expected_version bigint)
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
           OR public.sandbox_valid_oauth_client_id(identity_client) IS DISTINCT FROM true
           OR will_enable IS DISTINCT FROM true THEN RAISE EXCEPTION 'invalid service identity' USING ERRCODE='P4000';END IF;
        -- Stable identity serialization across tenants, always after own tenant lock.
        PERFORM pg_advisory_xact_lock(hashtextextended('sandbox-oidc:'||length(identity_issuer)::text||':'||identity_issuer||identity_subject,0));
        SELECT i.* INTO identity FROM public.principal_identities i WHERE i.issuer=identity_issuer AND i.subject=identity_subject;
        IF FOUND THEN
            SELECT p.* INTO principal FROM public.principals p WHERE p.id=identity.principal_id;
            IF NOT identity.enabled OR NOT principal.enabled OR principal.kind<>'SERVICE' OR identity.service_client_id IS DISTINCT FROM identity_client THEN
                RAISE EXCEPTION 'service identity unavailable' USING ERRCODE='P4040';END IF;
        ELSE
            INSERT INTO public.principals(kind,display_name) VALUES('SERVICE','Registered service') RETURNING * INTO principal;
            INSERT INTO public.principal_identities(principal_id,issuer,subject,service_client_id,service_binding_generation) VALUES(principal.id,identity_issuer,identity_subject,identity_client,1) RETURNING * INTO identity;
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
        IF identity_issuer IS NOT NULL OR identity_subject IS NOT NULL OR identity_client IS NOT NULL OR will_enable IS NULL OR principal.kind<>'SERVICE' THEN
            RAISE EXCEPTION 'service identity is immutable' USING ERRCODE='P4000';END IF;
        IF will_enable AND NOT registered.enabled THEN
            IF NOT identity.enabled OR NOT principal.enabled THEN RAISE EXCEPTION 'service identity unavailable' USING ERRCODE='P4040';END IF;
            PERFORM public.sandbox_check_service_client_enable(actor,registered.principal_id);
        END IF;
        UPDATE public.tenant_principals SET enabled=will_enable,display_name=local_name WHERE tenant_id=tenant AND id=client_id RETURNING * INTO registered;
    END IF;
    SELECT registered.id,registered.tenant_id,registered.principal_id,identity.issuer,identity.subject,registered.display_name,registered.enabled,(identity.enabled AND principal.enabled),registered.version,registered.created_at,registered.updated_at,identity.service_client_id INTO result;
    RETURN result;
END $$;

REVOKE ALL ON FUNCTION sandbox_mutate_service_client(uuid,text,uuid,text,text,text,text,boolean,bigint) FROM PUBLIC;

ALTER TABLE automation_delegations ADD COLUMN identity_client_id text;
ALTER TABLE automation_delegations ADD COLUMN identity_binding_generation bigint NOT NULL DEFAULT 0 CHECK(identity_binding_generation>=0);
CREATE OR REPLACE FUNCTION sandbox_automation_authorized(requested_tenant uuid,automation uuid) RETURNS boolean
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
   AND EXISTS(SELECT 1 FROM public.sandbox_resolve_identity(d.identity_issuer,d.identity_subject,d.identity_client_id) i
       WHERE i.principal_id=d.principal_id AND i.enabled AND i.kind IN('USER','SERVICE') AND i.binding_generation=d.identity_binding_generation)
   AND NOT EXISTS(SELECT 1 FROM unnest(public.sandbox_automation_required_actions(a.action_kind,a.trigger_kind='EVENT')) required(action)
       WHERE NOT required.action=ANY(d.allowed_actions) OR NOT EXISTS(
        SELECT 1 FROM public.grants g WHERE g.tenant_id=a.tenant_id AND g.principal_id=d.principal_id
         AND(g.project_id=a.project_id OR g.project_id IS NULL) AND(g.action=required.action OR g.action='*')
         AND g.enabled AND g.revoked_at IS NULL AND(g.expires_at IS NULL OR g.expires_at>clock_timestamp())))
 )
$$;
REVOKE ALL ON FUNCTION sandbox_automation_authorized(uuid,uuid) FROM PUBLIC;

