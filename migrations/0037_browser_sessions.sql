-- Browser credentials stay server-side; cookie hashes are narrow capabilities.
CREATE TABLE browser_login_challenges (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL, cluster_epoch uuid NOT NULL,
 state_hash text NOT NULL UNIQUE CHECK(state_hash ~ '^[0-9a-f]{64}$'),
 binding_hash text NOT NULL CHECK(binding_hash ~ '^[0-9a-f]{64}$'),
 payload bytea CHECK(octet_length(payload) BETWEEN 31 AND 65598),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '5 minutes',
 consumed_at timestamptz,
 CHECK((consumed_at IS NULL)=(payload IS NOT NULL))
);
CREATE INDEX browser_login_cleanup ON browser_login_challenges(expires_at);
CREATE TABLE browser_session_routes (
 cookie_hash text PRIMARY KEY CHECK(cookie_hash ~ '^[0-9a-f]{64}$'),
 tenant_id uuid NOT NULL REFERENCES tenants(id), id uuid NOT NULL UNIQUE,
 expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '30 minutes',scrubbed_at timestamptz
);
CREATE TABLE browser_sessions (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id),
 principal_id uuid NOT NULL REFERENCES principals(id), cluster_epoch uuid NOT NULL,
 issuer text NOT NULL, subject text NOT NULL,
 csrf_hash text NOT NULL CHECK(csrf_hash ~ '^[0-9a-f]{64}$'),
 payload bytea CHECK(octet_length(payload) BETWEEN 31 AND 65598),
 status text NOT NULL CHECK(status IN('ACTIVE','REFRESHING','REVOKED')),
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 access_expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 absolute_expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '8 hours',
 idle_expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '30 minutes',
 refresh_started_at timestamptz, revoked_at timestamptz,
 UNIQUE(tenant_id,id),
 CHECK((status='REVOKED')=(payload IS NULL)),
 CHECK((status='REFRESHING')=(refresh_started_at IS NOT NULL)),
 CHECK((status='REVOKED')=(revoked_at IS NOT NULL))
);
ALTER TABLE browser_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE browser_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON browser_sessions USING(tenant_id=public.sandbox_current_tenant_id()) WITH CHECK(tenant_id=public.sandbox_current_tenant_id());
CREATE INDEX browser_sessions_principal ON browser_sessions(tenant_id,principal_id,status);
CREATE INDEX browser_sessions_expiry ON browser_sessions(absolute_expires_at);
CREATE INDEX browser_routes_cleanup ON browser_session_routes(expires_at) WHERE scrubbed_at IS NULL;

CREATE FUNCTION sandbox_browser_member(t uuid,p uuid,i text,s text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM public.principals pr JOIN public.principal_identities pi ON pi.principal_id=pr.id
 JOIN public.tenant_principals tp ON tp.principal_id=pr.id AND tp.tenant_id=t JOIN public.tenants te ON te.id=t
 WHERE pr.id=p AND pr.kind='USER' AND pr.enabled AND pi.enabled AND pi.issuer=i AND pi.subject=s AND tp.enabled AND te.enabled
 AND t=public.sandbox_current_tenant_id())
$$;
CREATE FUNCTION sandbox_browser_login_create(record_id uuid,t uuid,epoch uuid,state text,binding text,encrypted bytea) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM 1 FROM public.platform_configuration WHERE singleton AND cluster_epoch=epoch FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 DELETE FROM public.browser_login_challenges WHERE expires_at<clock_timestamp();
 IF (SELECT count(*) FROM public.browser_login_challenges)>=5000 THEN RETURN false; END IF;
 INSERT INTO public.browser_login_challenges(id,tenant_id,cluster_epoch,state_hash,binding_hash,payload)
 VALUES(record_id,t,epoch,state,binding,encrypted);RETURN true;
END $$;
CREATE FUNCTION sandbox_browser_cleanup(request_id uuid) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r public.browser_session_routes;b public.browser_sessions;changed bigint:=0;
BEGIN
 DELETE FROM public.browser_login_challenges WHERE expires_at<clock_timestamp();
 FOR r IN SELECT * FROM public.browser_session_routes WHERE expires_at<clock_timestamp()
 AND (scrubbed_at IS NULL OR expires_at<clock_timestamp()-interval '30 days') ORDER BY expires_at,id LIMIT 100 FOR UPDATE SKIP LOCKED LOOP
 PERFORM set_config('app.tenant_id',r.tenant_id::text,true);
 SELECT * INTO b FROM public.browser_sessions WHERE browser_sessions.id=r.id FOR UPDATE;
 IF b.status<>'REVOKED' THEN
  UPDATE public.browser_sessions SET status='REVOKED',payload=NULL,refresh_started_at=NULL,revoked_at=clock_timestamp(),version=version+1 WHERE browser_sessions.id=r.id;
  INSERT INTO public.audit_events(tenant_id,actor_principal_id,request_id,resource_id,action,outcome) VALUES(b.tenant_id,b.principal_id,request_id,b.id,'browser_sessions:expire','SUCCEEDED');
 END IF;
 IF r.expires_at<clock_timestamp()-interval '30 days' THEN
  DELETE FROM public.browser_sessions WHERE browser_sessions.id=r.id;
  DELETE FROM public.browser_session_routes WHERE cookie_hash=r.cookie_hash;
 ELSE UPDATE public.browser_session_routes SET scrubbed_at=clock_timestamp() WHERE cookie_hash=r.cookie_hash;END IF;
 changed:=changed+1;
 END LOOP;RETURN changed;
END $$;
CREATE FUNCTION sandbox_browser_login_consume(state text,binding text)
RETURNS TABLE(id uuid,tenant_id uuid,cluster_epoch uuid,payload bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c public.browser_login_challenges;
BEGIN
 SELECT * INTO c FROM public.browser_login_challenges l WHERE l.state_hash=state AND l.binding_hash=binding
 AND l.consumed_at IS NULL AND l.expires_at>clock_timestamp()
 AND l.cluster_epoch=(SELECT p.cluster_epoch FROM public.platform_configuration p WHERE p.singleton) FOR UPDATE;
 IF NOT FOUND THEN RETURN;END IF;
 UPDATE public.browser_login_challenges SET consumed_at=clock_timestamp(),payload=NULL WHERE browser_login_challenges.id=c.id;
 RETURN QUERY SELECT c.id,c.tenant_id,c.cluster_epoch,c.payload;
END $$;
CREATE FUNCTION sandbox_browser_session_create(challenge uuid,record_id uuid,cookie text,csrf text,i text,s text,access_expiry timestamptz,encrypted bytea,request_id uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c public.browser_login_challenges;p uuid;
BEGIN
 SELECT * INTO c FROM public.browser_login_challenges l WHERE l.id=challenge AND l.consumed_at IS NOT NULL
 AND l.expires_at>clock_timestamp() AND l.cluster_epoch=(SELECT pc.cluster_epoch FROM public.platform_configuration pc WHERE pc.singleton) FOR UPDATE;
 IF NOT FOUND THEN RETURN false;END IF;
 PERFORM set_config('app.tenant_id',c.tenant_id::text,true);
 PERFORM public.sandbox_lock_identity_tenant(c.tenant_id);
 SELECT r.principal_id INTO p FROM public.sandbox_resolve_identity(i,s) r WHERE r.enabled AND r.kind='USER';
 IF p IS NULL OR NOT public.sandbox_browser_member(c.tenant_id,p,i,s) OR access_expiry<=clock_timestamp() OR access_expiry>clock_timestamp()+interval '5 minutes' THEN RETURN false;END IF;
 -- One consumed login cannot produce a second session after any ambiguous reply.
 DELETE FROM public.browser_login_challenges WHERE browser_login_challenges.id=c.id;
 PERFORM 1 FROM public.principals WHERE principals.id=p FOR UPDATE;
 IF NOT public.sandbox_browser_member(c.tenant_id,p,i,s)
 OR c.cluster_epoch<>(SELECT pc.cluster_epoch FROM public.platform_configuration pc WHERE pc.singleton)
 OR c.expires_at<=clock_timestamp() OR access_expiry<=clock_timestamp() THEN RETURN false;END IF;
 IF (SELECT count(*) FROM public.browser_sessions b WHERE b.tenant_id=c.tenant_id AND b.principal_id=p
 AND b.status<>'REVOKED' AND b.absolute_expires_at>clock_timestamp() AND b.idle_expires_at>clock_timestamp())>=20 THEN RETURN false;END IF;
 INSERT INTO public.browser_sessions(id,tenant_id,principal_id,cluster_epoch,issuer,subject,csrf_hash,payload,status,access_expires_at)
 VALUES(record_id,c.tenant_id,p,c.cluster_epoch,i,s,csrf,encrypted,'ACTIVE',access_expiry);
 INSERT INTO public.browser_session_routes(cookie_hash,tenant_id,id) VALUES(cookie,c.tenant_id,record_id);
 INSERT INTO public.audit_events(tenant_id,actor_principal_id,request_id,resource_id,action,outcome) VALUES(c.tenant_id,p,request_id,record_id,'browser_sessions:login','SUCCEEDED');
 IF NOT public.sandbox_browser_member(c.tenant_id,p,i,s)
 OR c.cluster_epoch<>(SELECT pc.cluster_epoch FROM public.platform_configuration pc WHERE pc.singleton)
 OR c.expires_at<=clock_timestamp() OR access_expiry<=clock_timestamp() THEN
 RAISE EXCEPTION 'browser identity changed before commit' USING ERRCODE='42501';END IF;
 RETURN true;
END $$;
CREATE FUNCTION sandbox_browser_session_read(cookie text,touch boolean)
RETURNS SETOF public.browser_sessions LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r public.browser_session_routes;b public.browser_sessions;
BEGIN
 SELECT * INTO r FROM public.browser_session_routes WHERE cookie_hash=cookie FOR UPDATE;
 IF NOT FOUND THEN RETURN;END IF;
 PERFORM set_config('app.tenant_id',r.tenant_id::text,true);
 SELECT * INTO b FROM public.browser_sessions WHERE browser_sessions.id=r.id FOR UPDATE;
 IF NOT FOUND OR b.status='REVOKED' THEN RETURN;END IF;
 IF b.cluster_epoch<>(SELECT p.cluster_epoch FROM public.platform_configuration p WHERE p.singleton)
 OR b.absolute_expires_at<=clock_timestamp() OR b.idle_expires_at<=clock_timestamp()
 OR NOT public.sandbox_browser_member(b.tenant_id,b.principal_id,b.issuer,b.subject)
 OR (b.status='REFRESHING' AND b.refresh_started_at<=clock_timestamp()-interval '15 seconds') THEN
 UPDATE public.browser_sessions SET status='REVOKED',payload=NULL,refresh_started_at=NULL,revoked_at=clock_timestamp(),version=version+1 WHERE browser_sessions.id=b.id;RETURN;
 END IF;
 IF touch THEN
 UPDATE public.browser_sessions SET idle_expires_at=LEAST(absolute_expires_at,clock_timestamp()+interval '30 minutes') WHERE browser_sessions.id=b.id RETURNING * INTO b;
 UPDATE public.browser_session_routes SET expires_at=b.idle_expires_at WHERE cookie_hash=cookie;
 END IF;
 RETURN NEXT b;
END $$;
CREATE FUNCTION sandbox_browser_refresh_begin(cookie text,expected bigint) RETURNS SETOF public.browser_sessions
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE b public.browser_sessions;
BEGIN
 SELECT * INTO b FROM public.sandbox_browser_session_read(cookie,false);
 IF NOT FOUND OR b.status<>'ACTIVE' OR b.version<>expected OR b.access_expires_at>clock_timestamp()+interval '30 seconds' THEN RETURN;END IF;
 UPDATE public.browser_sessions SET status='REFRESHING',refresh_started_at=clock_timestamp(),version=version+1
 WHERE browser_sessions.id=b.id RETURNING * INTO b;RETURN NEXT b;
END $$;
CREATE FUNCTION sandbox_browser_refresh_finish(cookie text,expected bigint,access_expiry timestamptz,encrypted bytea) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE b public.browser_sessions;
BEGIN
 SELECT * INTO b FROM public.sandbox_browser_session_read(cookie,false);
 IF NOT FOUND OR b.status<>'REFRESHING' OR b.version<>expected OR access_expiry<=clock_timestamp() OR access_expiry>clock_timestamp()+interval '5 minutes' THEN RETURN false;END IF;
 UPDATE public.browser_sessions SET status='ACTIVE',refresh_started_at=NULL,version=version+1,payload=encrypted,access_expires_at=access_expiry WHERE browser_sessions.id=b.id;RETURN true;
END $$;
CREATE FUNCTION sandbox_browser_session_revoke(cookie text,csrf text,expected bigint,request_id uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r public.browser_session_routes;b public.browser_sessions;
BEGIN
 SELECT * INTO r FROM public.browser_session_routes WHERE cookie_hash=cookie;
 IF NOT FOUND THEN RETURN false;END IF;
 PERFORM set_config('app.tenant_id',r.tenant_id::text,true);
 SELECT * INTO b FROM public.browser_sessions WHERE browser_sessions.id=r.id FOR UPDATE;
 -- CSRF capability permits logout even if the current identity/refresh is invalid.
 IF (csrf IS NOT NULL AND b.csrf_hash<>csrf) OR (expected IS NOT NULL AND b.version<>expected) THEN RETURN false;END IF;
 IF b.status='REVOKED' THEN RETURN true;END IF;
 UPDATE public.browser_sessions SET status='REVOKED',payload=NULL,refresh_started_at=NULL,revoked_at=clock_timestamp(),version=version+1 WHERE browser_sessions.id=b.id;
 INSERT INTO public.audit_events(tenant_id,actor_principal_id,request_id,resource_id,action,outcome) VALUES(b.tenant_id,b.principal_id,request_id,b.id,'browser_sessions:revoke','SUCCEEDED');RETURN true;
END $$;
REVOKE ALL ON browser_login_challenges,browser_session_routes,browser_sessions FROM PUBLIC;
REVOKE ALL ON FUNCTION sandbox_browser_cleanup(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION sandbox_browser_member(uuid,uuid,text,text),sandbox_browser_login_create(uuid,uuid,uuid,text,text,bytea),sandbox_browser_login_consume(text,text),sandbox_browser_session_create(uuid,uuid,text,text,text,text,timestamptz,bytea,uuid),sandbox_browser_session_read(text,boolean),sandbox_browser_refresh_begin(text,bigint),sandbox_browser_refresh_finish(text,bigint,timestamptz,bytea),sandbox_browser_session_revoke(text,text,bigint,uuid) FROM PUBLIC;
