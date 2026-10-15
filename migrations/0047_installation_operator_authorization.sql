-- Installation operator authority is independent of tenant membership/grants.
-- No automatic operator is created on upgrade; every grant requires an owner.
ALTER TABLE platform_configuration ADD COLUMN installation_id uuid NOT NULL DEFAULT gen_random_uuid()
 CHECK(installation_id<>'00000000-0000-0000-0000-000000000000'::uuid);

CREATE TABLE node_image_reader_grants (
 id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
 installation_id uuid NOT NULL,cluster_epoch uuid NOT NULL,
 identity_id uuid NOT NULL REFERENCES principal_identities(id),
 principal_id uuid NOT NULL REFERENCES principals(id),
 identity_issuer text NOT NULL,identity_subject text NOT NULL,identity_client_id text NOT NULL,
 binding_generation bigint NOT NULL CHECK(binding_generation>0),
 principal_authz_version bigint NOT NULL CHECK(principal_authz_version>0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL,
 reason text NOT NULL CHECK(octet_length(reason) BETWEEN 1 AND 256 AND reason !~ '[[:cntrl:]]'),
 revoked_at timestamptz,revocation_reason text,
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '24 hours'),
 CHECK((revoked_at IS NULL AND revocation_reason IS NULL) OR
       (revoked_at IS NOT NULL AND revocation_reason IS NOT NULL AND octet_length(revocation_reason) BETWEEN 1 AND 256 AND revocation_reason !~ '[[:cntrl:]]'))
);
CREATE UNIQUE INDEX node_image_reader_one_live ON node_image_reader_grants(installation_id,cluster_epoch,identity_id) WHERE revoked_at IS NULL;
CREATE TABLE node_image_reader_audit (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),grant_id uuid NOT NULL REFERENCES node_image_reader_grants(id),
 installation_id uuid NOT NULL,cluster_epoch uuid NOT NULL,
 action text NOT NULL CHECK(action IN('GRANTED','REVOKED')),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),database_role text NOT NULL,
 reason text NOT NULL CHECK(octet_length(reason) BETWEEN 1 AND 256 AND reason !~ '[[:cntrl:]]')
);
REVOKE ALL ON node_image_reader_grants,node_image_reader_audit FROM PUBLIC;
CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON node_image_reader_audit
 FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_audit_mutation();

CREATE FUNCTION sandbox_guard_node_image_reader() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'operator authority is retained' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' AND (
   (to_jsonb(NEW)-'revoked_at'-'revocation_reason') IS DISTINCT FROM (to_jsonb(OLD)-'revoked_at'-'revocation_reason')
   OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL) THEN
  RAISE EXCEPTION 'operator authority is immutable except permanent revocation' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER immutable_node_image_reader BEFORE UPDATE OR DELETE ON node_image_reader_grants
 FOR EACH ROW EXECUTE FUNCTION sandbox_guard_node_image_reader();
CREATE FUNCTION sandbox_audit_node_image_reader() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 INSERT INTO public.node_image_reader_audit(grant_id,installation_id,cluster_epoch,action,database_role,reason)
 VALUES(NEW.id,NEW.installation_id,NEW.cluster_epoch,CASE WHEN TG_OP='INSERT' THEN 'GRANTED' ELSE 'REVOKED' END,
 session_user,CASE WHEN TG_OP='INSERT' THEN NEW.reason ELSE NEW.revocation_reason END);
 RETURN NEW;
END $$;
CREATE TRIGGER audit_node_image_reader AFTER INSERT OR UPDATE ON node_image_reader_grants
 FOR EACH ROW EXECUTE FUNCTION sandbox_audit_node_image_reader();

-- Disable/re-enable and identity/client ABA must never revive an old grant.
-- These triggers do not confer any new tenant authority or change identity data.
CREATE FUNCTION sandbox_invalidate_node_image_reader() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_TABLE_NAME='platform_configuration' THEN
  IF (NEW.installation_id,NEW.cluster_epoch) IS DISTINCT FROM (OLD.installation_id,OLD.cluster_epoch) THEN
   UPDATE public.node_image_reader_grants SET revoked_at=clock_timestamp(),revocation_reason='Installation scope changed'
    WHERE (installation_id,cluster_epoch)=(OLD.installation_id,OLD.cluster_epoch) AND revoked_at IS NULL;
  END IF;
 ELSIF TG_TABLE_NAME='principals' THEN
  IF (NEW.enabled,NEW.kind,NEW.authz_version) IS DISTINCT FROM (OLD.enabled,OLD.kind,OLD.authz_version) THEN
   UPDATE public.node_image_reader_grants SET revoked_at=clock_timestamp(),revocation_reason='Principal authority changed'
    WHERE principal_id=NEW.id AND revoked_at IS NULL;
  END IF;
 ELSE
  IF (NEW.enabled,NEW.principal_id,NEW.issuer,NEW.subject,NEW.service_client_id,NEW.service_binding_generation)
    IS DISTINCT FROM (OLD.enabled,OLD.principal_id,OLD.issuer,OLD.subject,OLD.service_client_id,OLD.service_binding_generation) THEN
   UPDATE public.node_image_reader_grants SET revoked_at=clock_timestamp(),revocation_reason='Identity authority changed'
    WHERE identity_id=NEW.id AND revoked_at IS NULL;
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER node_image_reader_principal_change AFTER UPDATE ON principals
 FOR EACH ROW EXECUTE FUNCTION sandbox_invalidate_node_image_reader();
CREATE TRIGGER node_image_reader_identity_change AFTER UPDATE ON principal_identities
 FOR EACH ROW EXECUTE FUNCTION sandbox_invalidate_node_image_reader();
CREATE TRIGGER node_image_reader_scope_change AFTER UPDATE ON platform_configuration
 FOR EACH ROW EXECUTE FUNCTION sandbox_invalidate_node_image_reader();

CREATE FUNCTION sandbox_grant_node_image_reader(requested_grant_id uuid,requested_installation uuid,requested_epoch uuid,
 requested_issuer text,requested_subject text,requested_client text,requested_expiry timestamptz,requested_change_reason text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE config public.platform_configuration;identity public.principal_identities;principal public.principals;
 existing public.node_image_reader_grants;as_of timestamptz;
BEGIN
 SELECT * INTO config FROM public.platform_configuration WHERE singleton FOR SHARE;
 IF NOT FOUND OR (config.installation_id,config.cluster_epoch) IS DISTINCT FROM (requested_installation,requested_epoch) THEN
  RAISE EXCEPTION 'requested_installation scope changed' USING ERRCODE='P4120';END IF;
 -- Stable request serialization also protects exact-ID retries across identities.
 PERFORM pg_advisory_xact_lock(hashtextextended('sandbox-node-image-reader:'||requested_grant_id::text,0));
 SELECT * INTO identity FROM public.principal_identities i WHERE i.issuer=requested_issuer AND i.subject=requested_subject FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'operator identity unavailable' USING ERRCODE='P4040';END IF;
 SELECT * INTO principal FROM public.principals p WHERE p.id=identity.principal_id FOR UPDATE;
 IF principal.kind<>'SERVICE' OR NOT principal.enabled OR NOT identity.enabled
   OR identity.service_client_id IS DISTINCT FROM requested_client OR identity.service_binding_generation<=0 THEN
  RAISE EXCEPTION 'operator identity unavailable' USING ERRCODE='P4040';END IF;
 SELECT * INTO existing FROM public.node_image_reader_grants g WHERE g.id=requested_grant_id;
 IF FOUND THEN
  IF (existing.installation_id,existing.cluster_epoch,existing.identity_id,existing.principal_id,
      existing.identity_issuer,existing.identity_subject,existing.identity_client_id,existing.binding_generation,
      existing.principal_authz_version,existing.expires_at,existing.reason)
    IS DISTINCT FROM (requested_installation,requested_epoch,identity.id,principal.id,requested_issuer,requested_subject,requested_client,identity.service_binding_generation,
      principal.authz_version,requested_expiry,requested_change_reason) OR existing.revoked_at IS NOT NULL THEN
   RAISE EXCEPTION 'operator grant conflicts' USING ERRCODE='P4090';END IF;
  RETURN existing.id;
 END IF;
 as_of:=clock_timestamp();
 IF requested_grant_id IS NULL OR requested_grant_id='00000000-0000-0000-0000-000000000000'::uuid
   OR requested_expiry IS NULL OR NOT isfinite(requested_expiry) OR requested_expiry<=as_of OR requested_expiry>as_of+interval '24 hours'
   OR requested_change_reason IS NULL OR btrim(requested_change_reason)='' OR octet_length(requested_change_reason) NOT BETWEEN 1 AND 256
   OR requested_change_reason~'[[:cntrl:]]' THEN
  RAISE EXCEPTION 'invalid operator grant' USING ERRCODE='P4000';END IF;
 INSERT INTO public.node_image_reader_grants(id,installation_id,cluster_epoch,identity_id,principal_id,
   identity_issuer,identity_subject,identity_client_id,binding_generation,principal_authz_version,created_at,expires_at,reason)
 VALUES(requested_grant_id,requested_installation,requested_epoch,identity.id,principal.id,requested_issuer,requested_subject,requested_client,identity.service_binding_generation,principal.authz_version,as_of,requested_expiry,requested_change_reason);
 RETURN requested_grant_id;
END $$;

CREATE FUNCTION sandbox_revoke_node_image_reader(requested_grant_id uuid,requested_installation uuid,requested_epoch uuid,requested_change_reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE existing public.node_image_reader_grants;
BEGIN
 IF requested_change_reason IS NULL OR btrim(requested_change_reason)='' OR octet_length(requested_change_reason) NOT BETWEEN 1 AND 256 OR requested_change_reason~'[[:cntrl:]]' THEN
  RAISE EXCEPTION 'invalid operator revocation' USING ERRCODE='P4000';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('sandbox-node-image-reader:'||requested_grant_id::text,0));
 SELECT * INTO existing FROM public.node_image_reader_grants g WHERE g.id=requested_grant_id FOR UPDATE;
 IF NOT FOUND OR (existing.installation_id,existing.cluster_epoch) IS DISTINCT FROM (requested_installation,requested_epoch) THEN
  RAISE EXCEPTION 'operator grant unavailable' USING ERRCODE='P4040';END IF;
 IF existing.revoked_at IS NOT NULL THEN RETURN;END IF;
 UPDATE public.node_image_reader_grants SET revoked_at=clock_timestamp(),revocation_reason=requested_change_reason WHERE id=requested_grant_id;
END $$;

-- Fixed action/current singleton only: never accepts a tenant, installation,
-- principal UUID, free-form action, node selector or PromQL from the caller.
CREATE FUNCTION sandbox_node_image_access(issuer text,subject text,client text,token_exp bigint)
RETURNS TABLE(installation_id uuid,cluster_epoch uuid,grant_id uuid,expires_at timestamptz)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT c.installation_id,c.cluster_epoch,g.id,g.expires_at
 FROM public.platform_configuration c JOIN public.node_image_reader_grants g
   ON(g.installation_id,g.cluster_epoch)=(c.installation_id,c.cluster_epoch)
 JOIN public.principal_identities i ON i.id=g.identity_id
 JOIN public.principals p ON p.id=g.principal_id AND i.principal_id=p.id
 WHERE c.singleton AND i.issuer=$1 AND i.subject=$2 AND i.service_client_id=$3
  AND(i.issuer,i.subject,i.service_client_id,i.service_binding_generation)=(g.identity_issuer,g.identity_subject,g.identity_client_id,g.binding_generation)
  AND p.authz_version=g.principal_authz_version AND p.kind='SERVICE' AND p.enabled AND i.enabled
  AND g.revoked_at IS NULL AND g.expires_at>clock_timestamp()
  AND $4>extract(epoch FROM clock_timestamp())
$$;
REVOKE ALL ON FUNCTION sandbox_guard_node_image_reader(),sandbox_audit_node_image_reader(),sandbox_invalidate_node_image_reader(),
 sandbox_grant_node_image_reader(uuid,uuid,uuid,text,text,text,timestamptz,text),
 sandbox_revoke_node_image_reader(uuid,uuid,uuid,text),sandbox_node_image_access(text,text,text,bigint) FROM PUBLIC;
