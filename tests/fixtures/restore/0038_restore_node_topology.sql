-- PRIVATE CANDIDATE: companion after 0038_restores.sql; not a migration or
-- production capability. This owner installation fact grants no RESTORE/PV/VM
-- authority. Future exact tenant-scoped definer readers belong to another slice.

CREATE FUNCTION sandbox_restore_topology_timestamp_valid(timestamp_text text) RETURNS boolean
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $$
DECLARE parsed timestamptz;
BEGIN
 IF timestamp_text IS NULL OR char_length(timestamp_text) NOT BETWEEN 20 AND 35
  OR timestamp_text !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,6})?(Z|[+]00:00)$' THEN RETURN false;END IF;
 -- PostgreSQL's broader time input must not normalize hour 24 or a leap
 -- second into a different instant under the strict RFC3339 wire contract.
 IF substring(timestamp_text FROM 12 FOR 2)::integer NOT BETWEEN 0 AND 23
  OR substring(timestamp_text FROM 15 FOR 2)::integer NOT BETWEEN 0 AND 59
  OR substring(timestamp_text FROM 18 FOR 2)::integer NOT BETWEEN 0 AND 59 THEN RETURN false;END IF;
 BEGIN parsed:=timestamp_text::timestamptz;
 EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow THEN RETURN false;END;
 RETURN isfinite(parsed) IS TRUE;
END $$;
REVOKE ALL ON FUNCTION sandbox_restore_topology_timestamp_valid(text) FROM PUBLIC;

CREATE FUNCTION sandbox_restore_node_topology_payload_valid(receipt_json jsonb) RETURNS boolean
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $$
DECLARE field text;cloud_json jsonb;csi_json jsonb;address inet;
BEGIN
 IF receipt_json IS NULL OR jsonb_typeof(receipt_json) IS DISTINCT FROM 'object' THEN RETURN false;END IF;
 IF NOT(receipt_json ?& ARRAY['id','runtime_node_id','enrollment_id','restore_profile_id','restore_report_sha256','terraform_output_sha256','infrastructure_sha256','zone_id','describe_instance','csi_registration','observed_node_resource_version','observed_csi_node_resource_version','observed_at','reviewed_at','certified_until'])
  OR (SELECT count(*) FROM jsonb_object_keys(receipt_json) AS keys(key_name))<>15
  OR octet_length(receipt_json::text)>16384 THEN RETURN false;END IF;
 FOREACH field IN ARRAY ARRAY['id','runtime_node_id','enrollment_id','restore_profile_id'] LOOP
  IF jsonb_typeof(receipt_json->field) IS DISTINCT FROM 'string'
   OR receipt_json->>field !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
   OR receipt_json->>field='00000000-0000-0000-0000-000000000000' THEN RETURN false;END IF;
 END LOOP;
 FOREACH field IN ARRAY ARRAY['restore_report_sha256','terraform_output_sha256','infrastructure_sha256'] LOOP
  IF jsonb_typeof(receipt_json->field) IS DISTINCT FROM 'string' OR receipt_json->>field !~ '^[0-9a-f]{64}$' THEN RETURN false;END IF;
 END LOOP;
 FOREACH field IN ARRAY ARRAY['observed_node_resource_version','observed_csi_node_resource_version'] LOOP
  IF jsonb_typeof(receipt_json->field) IS DISTINCT FROM 'string' OR char_length(receipt_json->>field) NOT BETWEEN 1 AND 256
   OR receipt_json->>field !~ '^[!-~]+$' THEN RETURN false;END IF;
 END LOOP;
 FOREACH field IN ARRAY ARRAY['observed_at','reviewed_at','certified_until'] LOOP
  IF jsonb_typeof(receipt_json->field) IS DISTINCT FROM 'string'
   OR public.sandbox_restore_topology_timestamp_valid(receipt_json->>field) IS NOT TRUE THEN RETURN false;END IF;
 END LOOP;
 IF jsonb_typeof(receipt_json->'zone_id') IS DISTINCT FROM 'string' OR char_length(receipt_json->>'zone_id') NOT BETWEEN 1 AND 64
  OR receipt_json->>'zone_id' !~ '^cn-[a-z0-9-]+$' THEN RETURN false;END IF;
 cloud_json:=receipt_json->'describe_instance';csi_json:=receipt_json->'csi_registration';
 IF jsonb_typeof(cloud_json) IS DISTINCT FROM 'object' OR jsonb_typeof(csi_json) IS DISTINCT FROM 'object' THEN RETURN false;END IF;
 IF NOT(cloud_json ?& ARRAY['protocol','account_id','region','instance_id','zone_id','vpc_id','vswitch_id','private_ip','deployment','role','status','request_id','response_sha256','observed_at'])
  OR (SELECT count(*) FROM jsonb_object_keys(cloud_json) AS keys(key_name))<>14 OR octet_length(cloud_json::text)>8192
  OR jsonb_typeof(cloud_json->'protocol') IS DISTINCT FROM 'number' OR (cloud_json->'protocol')::text IS DISTINCT FROM '1' THEN RETURN false;END IF;
 FOREACH field IN ARRAY ARRAY['account_id','region','instance_id','zone_id','vpc_id','vswitch_id','private_ip','deployment','role','status','request_id','response_sha256','observed_at'] LOOP
  IF jsonb_typeof(cloud_json->field) IS DISTINCT FROM 'string' THEN RETURN false;END IF;
 END LOOP;
 IF cloud_json->>'account_id' !~ '^[0-9]{16}$'
  OR char_length(cloud_json->>'region') NOT BETWEEN 4 AND 32 OR cloud_json->>'region' !~ '^cn-[a-z0-9-]+$'
  OR char_length(cloud_json->>'instance_id') NOT BETWEEN 3 AND 128 OR cloud_json->>'instance_id' !~ '^i-[A-Za-z0-9]+$'
  OR char_length(cloud_json->>'vpc_id') NOT BETWEEN 5 AND 128 OR cloud_json->>'vpc_id' !~ '^vpc-[A-Za-z0-9]+$'
  OR char_length(cloud_json->>'vswitch_id') NOT BETWEEN 5 AND 128 OR cloud_json->>'vswitch_id' !~ '^vsw-[A-Za-z0-9]+$'
  OR cloud_json->>'deployment' !~ '^[a-z][a-z0-9-]{3,19}$'
  OR cloud_json->'role' IS DISTINCT FROM to_jsonb('kata'::text) OR cloud_json->'status' IS DISTINCT FROM to_jsonb('Running'::text)
  OR char_length(cloud_json->>'request_id') NOT BETWEEN 1 AND 256 OR cloud_json->>'request_id' !~ '^[!-~]+$'
  OR cloud_json->>'response_sha256' !~ '^[0-9a-f]{64}$'
  OR public.sandbox_restore_topology_timestamp_valid(cloud_json->>'observed_at') IS NOT TRUE
  OR cloud_json->'zone_id' IS DISTINCT FROM receipt_json->'zone_id'
  OR char_length(cloud_json->>'zone_id')<=char_length(cloud_json->>'region')+1
  OR cloud_json->>'zone_id' NOT LIKE ((cloud_json->>'region')||'-%') THEN RETURN false;END IF;
 IF cloud_json->>'private_ip' !~ '^[0-9]{1,3}([.][0-9]{1,3}){3}$' THEN RETURN false;END IF;
 BEGIN address:=(cloud_json->>'private_ip')::inet;
 EXCEPTION WHEN invalid_text_representation THEN RETURN false;END;
 IF family(address)<>4 OR host(address) IS DISTINCT FROM cloud_json->>'private_ip'
  OR NOT(address << inet '10.0.0.0/8' OR address << inet '172.16.0.0/12' OR address << inet '192.168.0.0/16') THEN RETURN false;END IF;
 IF NOT(csi_json ?& ARRAY['csi_node_uid','node_id','topology_keys'])
  OR (SELECT count(*) FROM jsonb_object_keys(csi_json) AS keys(key_name))<>3 OR octet_length(csi_json::text)>2048
  OR jsonb_typeof(csi_json->'csi_node_uid') IS DISTINCT FROM 'string'
  OR csi_json->>'csi_node_uid' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  OR csi_json->>'csi_node_uid'='00000000-0000-0000-0000-000000000000'
  OR csi_json->'node_id' IS DISTINCT FROM cloud_json->'instance_id'
  OR csi_json->'topology_keys' IS DISTINCT FROM jsonb_build_array('alibabacloud.com/ecs-instance-id','topology.diskplugin.csi.alibabacloud.com/zone','topology.kubernetes.io/region','topology.kubernetes.io/zone') THEN RETURN false;END IF;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION sandbox_restore_node_topology_payload_valid(jsonb) FROM PUBLIC;

CREATE TABLE restore_node_topology_receipts (
 id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'),
 runtime_node_id uuid NOT NULL REFERENCES runtime_nodes(id) CHECK(runtime_node_id<>'00000000-0000-0000-0000-000000000000'),
 enrollment_id uuid NOT NULL REFERENCES runtime_node_enrollments(id) CHECK(enrollment_id<>'00000000-0000-0000-0000-000000000000'),
 restore_profile_id uuid NOT NULL REFERENCES restore_profile_certifications(profile_id) CHECK(restore_profile_id<>'00000000-0000-0000-0000-000000000000'),
 restore_report_sha256 text NOT NULL CHECK(restore_report_sha256~'^[0-9a-f]{64}$'),
 terraform_output_sha256 text NOT NULL CHECK(terraform_output_sha256~'^[0-9a-f]{64}$'),
 infrastructure_sha256 text NOT NULL CHECK(infrastructure_sha256~'^[0-9a-f]{64}$'),
 zone_id text NOT NULL CHECK(char_length(zone_id) BETWEEN 1 AND 64 AND zone_id~'^cn-[a-z0-9-]+$'),
 describe_instance jsonb NOT NULL CHECK(jsonb_typeof(describe_instance)='object' AND octet_length(describe_instance::text)<=8192),
 csi_registration jsonb NOT NULL CHECK(jsonb_typeof(csi_registration)='object' AND octet_length(csi_registration::text)<=2048),
 observed_node_resource_version text NOT NULL CHECK(char_length(observed_node_resource_version) BETWEEN 1 AND 256 AND observed_node_resource_version~'^[!-~]+$'),
 observed_csi_node_resource_version text NOT NULL CHECK(char_length(observed_csi_node_resource_version) BETWEEN 1 AND 256 AND observed_csi_node_resource_version~'^[!-~]+$'),
 observed_at timestamptz NOT NULL CHECK(isfinite(observed_at)),
 reviewed_at timestamptz NOT NULL CHECK(isfinite(reviewed_at)),
 certified_until timestamptz NOT NULL CHECK(isfinite(certified_until)),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(recorded_at)),
 CHECK(certified_until>reviewed_at AND certified_until<=reviewed_at+interval '30 days')
);
CREATE UNIQUE INDEX restore_node_topology_identity_once ON restore_node_topology_receipts
 (runtime_node_id,enrollment_id,restore_profile_id,infrastructure_sha256,(csi_registration->>'csi_node_uid'));
REVOKE ALL ON restore_node_topology_receipts FROM PUBLIC;

CREATE FUNCTION sandbox_guard_restore_node_topology() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE cfg public.platform_configuration;bp public.backup_profiles;cert public.restore_profile_certifications;
 node_row public.runtime_nodes;enrollment_row public.runtime_node_enrollments;
 now_at timestamptz;cloud_at timestamptz;item jsonb;receipt jsonb;node_json jsonb;owner_ok boolean;
BEGIN
 SELECT count(*)=6 AND bool_and(pg_has_role(current_user,c.relowner,'USAGE')) INTO owner_ok
 FROM pg_class AS c WHERE c.relnamespace='public'::regnamespace
  AND c.relname=ANY(ARRAY['restore_node_topology_receipts','runtime_nodes','runtime_node_enrollments','platform_configuration','backup_profiles','restore_profile_certifications']);
 IF owner_ok IS NOT TRUE THEN RAISE EXCEPTION 'topology publication requires installation table owner' USING ERRCODE='42501';END IF;
 -- Same operator order as enrollment: configuration precedes the trusted node.
 -- No workspace/instance/operation lock or remote call belongs inside this guard.
 SELECT c.* INTO cfg FROM public.platform_configuration AS c WHERE c.singleton FOR SHARE;
 SELECT p.* INTO bp FROM public.backup_profiles AS p WHERE p.id=NEW.restore_profile_id FOR SHARE;
 SELECT c.* INTO cert FROM public.restore_profile_certifications AS c WHERE c.profile_id=NEW.restore_profile_id FOR SHARE;
 SELECT n.* INTO node_row FROM public.runtime_nodes AS n WHERE n.id=NEW.runtime_node_id FOR SHARE;
 SELECT e.* INTO enrollment_row FROM public.runtime_node_enrollments AS e WHERE e.id=NEW.enrollment_id FOR SHARE;
 now_at:=clock_timestamp();NEW.recorded_at:=now_at;
 -- to_jsonb(timestamptz) has UTC+00:00 under this fixed function timezone.
 IF public.sandbox_restore_node_topology_payload_valid(to_jsonb(NEW)-'recorded_at') IS NOT TRUE THEN
  RAISE EXCEPTION 'topology receipt requires exact strict JSON identity and observation shape' USING ERRCODE='23514';END IF;
 cloud_at:=(NEW.describe_instance->>'observed_at')::timestamptz;
 IF cfg.singleton IS DISTINCT FROM true OR cfg.safe_mode IS DISTINCT FROM false
  OR bp.id IS NULL OR cert.profile_id IS NULL OR node_row.id IS NULL OR enrollment_row.id IS NULL
  OR bp.enabled IS DISTINCT FROM true OR node_row.enabled IS DISTINCT FROM true
  OR node_row.cloud_provider IS DISTINCT FROM 'alicloud'
  OR node_row.cluster_epoch='00000000-0000-0000-0000-000000000000'
  OR node_row.node_uid='00000000-0000-0000-0000-000000000000' OR node_row.boot_id='00000000-0000-0000-0000-000000000000'
  OR char_length(node_row.node_name) NOT BETWEEN 1 AND 253
  OR EXISTS(SELECT 1 FROM regexp_split_to_table(node_row.node_name,'[.]') AS labels(label)
   WHERE char_length(label) NOT BETWEEN 1 AND 63 OR label !~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')
  OR cfg.cluster_epoch IS DISTINCT FROM node_row.cluster_epoch OR cfg.cluster_epoch IS DISTINCT FROM bp.cluster_epoch
  OR cfg.cluster_epoch IS DISTINCT FROM cert.cluster_epoch OR cfg.cluster_epoch IS DISTINCT FROM enrollment_row.cluster_epoch
  OR enrollment_row.runtime_node_id IS DISTINCT FROM node_row.id
  OR cert.backup_certification_sha256 IS DISTINCT FROM bp.certification_sha256
  OR NEW.restore_report_sha256 IS DISTINCT FROM cert.report_sha256
  OR NEW.terraform_output_sha256 IS DISTINCT FROM enrollment_row.terraform_output_sha256
  OR cert.report->'bindings'->'infrastructure_sha256' IS DISTINCT FROM to_jsonb(NEW.infrastructure_sha256)
  OR public.sandbox_restore_storage_mappings_valid(cert.storage_mappings) IS NOT TRUE
  OR NEW.reviewed_at IS DISTINCT FROM cert.reviewed_at
  OR NOT(isfinite(bp.certified_until) AND isfinite(cert.reviewed_at) AND isfinite(cert.certified_until)
   AND isfinite(enrollment_row.certification_reviewed_at) AND isfinite(enrollment_row.certification_expires_at)
   AND isfinite(node_row.registered_at) AND isfinite(enrollment_row.registered_at) AND isfinite(enrollment_row.observed_at) AND isfinite(cloud_at))
  OR cert.reviewed_at>now_at+interval '2 seconds' OR enrollment_row.certification_reviewed_at>now_at+interval '2 seconds'
  OR NEW.observed_at<now_at-interval '10 seconds' OR NEW.observed_at>now_at+interval '2 seconds'
  OR NEW.observed_at<node_row.registered_at OR NEW.observed_at<enrollment_row.registered_at
  OR cloud_at<NEW.observed_at-interval '10 seconds' OR cloud_at>NEW.observed_at OR cloud_at>now_at+interval '2 seconds'
  OR NEW.certified_until<=now_at OR NEW.certified_until>bp.certified_until OR NEW.certified_until>cert.certified_until
  OR NEW.certified_until>enrollment_row.certification_expires_at
  OR NEW.certified_until IS DISTINCT FROM least(bp.certified_until,cert.certified_until,enrollment_row.certification_expires_at,cert.reviewed_at+interval '30 days')
  OR NEW.describe_instance->'account_id' IS DISTINCT FROM to_jsonb(node_row.cloud_account_id)
  OR NEW.describe_instance->'region' IS DISTINCT FROM to_jsonb(node_row.region)
  OR NEW.describe_instance->'instance_id' IS DISTINCT FROM to_jsonb(node_row.cloud_instance_id)
  OR NEW.describe_instance->'private_ip' IS DISTINCT FROM to_jsonb(host(node_row.private_ip))
  OR NEW.describe_instance->'account_id' IS DISTINCT FROM bp.settings->'account_id'
  OR NEW.describe_instance->'region' IS DISTINCT FROM bp.settings->'region'
  OR NEW.describe_instance->'deployment' IS DISTINCT FROM bp.settings->'deployment'
  OR cert.report->'bindings'->'account_id' IS DISTINCT FROM NEW.describe_instance->'account_id'
  OR cert.report->'bindings'->'region' IS DISTINCT FROM NEW.describe_instance->'region'
  OR cert.report->'bindings'->'deployment' IS DISTINCT FROM NEW.describe_instance->'deployment' THEN
  RAISE EXCEPTION 'topology receipt does not match current exact certified node and infrastructure authority' USING ERRCODE='23514';END IF;
 FOR item IN SELECT mapping FROM jsonb_array_elements(cert.storage_mappings) AS mappings(mapping) LOOP
  IF item->'account_id' IS DISTINCT FROM NEW.describe_instance->'account_id'
   OR item->'region' IS DISTINCT FROM NEW.describe_instance->'region'
   OR item->'deployment' IS DISTINCT FROM NEW.describe_instance->'deployment'
   OR NOT(item->'topology'->'zone_ids' @> jsonb_build_array(NEW.zone_id)) THEN
   RAISE EXCEPTION 'topology zone and cloud identity are outside the certified restore mappings' USING ERRCODE='23514';END IF;
 END LOOP;
 receipt:=enrollment_row.receipt;node_json:=receipt->'node';
 IF jsonb_typeof(receipt) IS DISTINCT FROM 'object' OR jsonb_typeof(node_json) IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'topology publication requires exact audited enrollment receipt' USING ERRCODE='23514';END IF;
 IF NOT(receipt ?& ARRAY['protocol','enrollment_id','runtime_node_id','node','cloud_account_id','region','cloud_instance_id','private_ip','guard_port','certification_id','certification_report_sha256','artifact_sha256','terraform_output_sha256','registered_at','changed','enabled'])
  OR (SELECT count(*) FROM jsonb_object_keys(receipt) AS keys(key_name))<>16
  OR NOT(node_json ?& ARRAY['cluster_epoch','node_uid','node_name','boot_id','profile_sha256'])
  OR (SELECT count(*) FROM jsonb_object_keys(node_json) AS keys(key_name))<>5
  OR jsonb_typeof(receipt->'protocol') IS DISTINCT FROM 'number' OR (receipt->'protocol')::text IS DISTINCT FROM '1'
  OR jsonb_typeof(receipt->'guard_port') IS DISTINCT FROM 'number' OR (receipt->'guard_port')::text IS DISTINCT FROM node_row.guard_port::text
  OR jsonb_typeof(receipt->'changed') IS DISTINCT FROM 'boolean' OR receipt->'enabled' IS DISTINCT FROM 'true'::jsonb
  OR jsonb_typeof(receipt->'certification_id') IS DISTINCT FROM 'string'
  OR char_length(receipt->>'certification_id') NOT BETWEEN 1 AND 128 OR receipt->>'certification_id' !~ '^[A-Za-z0-9_.-]+$'
  OR receipt->'enrollment_id' IS DISTINCT FROM to_jsonb(enrollment_row.id::text)
  OR receipt->'runtime_node_id' IS DISTINCT FROM to_jsonb(node_row.id::text)
  OR node_json IS DISTINCT FROM jsonb_build_object('cluster_epoch',node_row.cluster_epoch::text,'node_uid',node_row.node_uid::text,'node_name',node_row.node_name,'boot_id',node_row.boot_id::text,'profile_sha256',node_row.profile_sha256)
  OR receipt->'cloud_account_id' IS DISTINCT FROM to_jsonb(node_row.cloud_account_id)
  OR receipt->'region' IS DISTINCT FROM to_jsonb(node_row.region)
  OR receipt->'cloud_instance_id' IS DISTINCT FROM to_jsonb(node_row.cloud_instance_id)
  OR receipt->'private_ip' IS DISTINCT FROM to_jsonb(host(node_row.private_ip))
  OR receipt->'certification_report_sha256' IS DISTINCT FROM to_jsonb(enrollment_row.certification_report_sha256)
  OR receipt->'artifact_sha256' IS DISTINCT FROM to_jsonb(enrollment_row.artifact_sha256)
  OR receipt->'terraform_output_sha256' IS DISTINCT FROM to_jsonb(enrollment_row.terraform_output_sha256)
  OR jsonb_typeof(receipt->'registered_at') IS DISTINCT FROM 'string'
  OR public.sandbox_restore_topology_timestamp_valid(receipt->>'registered_at') IS NOT TRUE THEN
  RAISE EXCEPTION 'topology publication requires exact audited enrollment receipt' USING ERRCODE='23514';END IF;
 IF (receipt->>'registered_at')::timestamptz IS DISTINCT FROM enrollment_row.registered_at THEN
  RAISE EXCEPTION 'topology enrollment registration time differs from immutable receipt' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION sandbox_guard_restore_node_topology() FROM PUBLIC;
CREATE TRIGGER restore_node_topology_insert_guard BEFORE INSERT ON restore_node_topology_receipts
 FOR EACH ROW EXECUTE FUNCTION sandbox_guard_restore_node_topology();
CREATE TRIGGER restore_node_topology_append_only BEFORE UPDATE OR DELETE ON restore_node_topology_receipts
 FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_audit_mutation();

-- The sealed collector is the only runtime call site. An invoker function
-- cannot elevate an ordinary role or bypass owner-only input provenance.
CREATE FUNCTION sandbox_record_restore_node_topology(requested_receipt jsonb) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE candidate public.restore_node_topology_receipts;existing public.restore_node_topology_receipts;owner_ok boolean;
BEGIN
 SELECT count(*)=6 AND bool_and(pg_has_role(current_user,c.relowner,'USAGE')) INTO owner_ok
 FROM pg_class AS c WHERE c.relnamespace='public'::regnamespace
  AND c.relname=ANY(ARRAY['restore_node_topology_receipts','runtime_nodes','runtime_node_enrollments','platform_configuration','backup_profiles','restore_profile_certifications']);
 IF owner_ok IS NOT TRUE THEN RAISE EXCEPTION 'topology publication requires installation table owner' USING ERRCODE='42501';END IF;
 IF public.sandbox_restore_node_topology_payload_valid(requested_receipt) IS NOT TRUE THEN
  RAISE EXCEPTION 'topology publication requires exact sealed observation shape' USING ERRCODE='23514';END IF;
 candidate:=jsonb_populate_record(NULL::public.restore_node_topology_receipts,requested_receipt);
 SELECT r.* INTO existing FROM public.restore_node_topology_receipts AS r WHERE r.id=candidate.id;
 IF FOUND THEN
  IF(to_jsonb(existing)-'recorded_at') IS DISTINCT FROM(to_jsonb(candidate)-'recorded_at') THEN
   RAISE EXCEPTION 'topology receipt identity cannot be remapped' USING ERRCODE='23514';END IF;
  -- Historical same-payload replay returns the original timestamp; it neither
  -- refreshes observations/certification nor grants fresh scheduling authority.
  RETURN to_jsonb(existing);
 END IF;
 BEGIN
  INSERT INTO public.restore_node_topology_receipts AS recorded
   (id,runtime_node_id,enrollment_id,restore_profile_id,restore_report_sha256,terraform_output_sha256,infrastructure_sha256,zone_id,describe_instance,csi_registration,observed_node_resource_version,observed_csi_node_resource_version,observed_at,reviewed_at,certified_until)
  VALUES(candidate.id,candidate.runtime_node_id,candidate.enrollment_id,candidate.restore_profile_id,candidate.restore_report_sha256,candidate.terraform_output_sha256,candidate.infrastructure_sha256,candidate.zone_id,candidate.describe_instance,candidate.csi_registration,candidate.observed_node_resource_version,candidate.observed_csi_node_resource_version,candidate.observed_at,candidate.reviewed_at,candidate.certified_until)
  RETURNING recorded.* INTO existing;
 EXCEPTION WHEN unique_violation THEN
  SELECT r.* INTO existing FROM public.restore_node_topology_receipts AS r WHERE r.id=candidate.id;
  IF NOT FOUND OR(to_jsonb(existing)-'recorded_at') IS DISTINCT FROM(to_jsonb(candidate)-'recorded_at') THEN
   RAISE EXCEPTION 'topology identity already has a different immutable receipt' USING ERRCODE='23514';END IF;
 END;
 RETURN to_jsonb(existing);
END $$;
REVOKE ALL ON FUNCTION sandbox_record_restore_node_topology(jsonb) FROM PUBLIC;

-- Existing ordinary component logins retain zero table/owner-writer access.
-- Some disposable schemas omit components; never create or modify role identity.
DO $$
DECLARE ordinary_role text;
BEGIN
 FOREACH ordinary_role IN ARRAY ARRAY['sandbox_app','sandbox_worker','sandbox_admission','sandbox_gateway','sandbox_termination','sandbox_fencing','sandbox_volume_deleter','sandbox_backup','sandbox_restore_gc'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles AS r WHERE r.rolname=ordinary_role) THEN
   EXECUTE format('REVOKE ALL ON TABLE public.restore_node_topology_receipts FROM %I',ordinary_role);
   EXECUTE format('REVOKE ALL ON FUNCTION public.sandbox_record_restore_node_topology(jsonb),public.sandbox_guard_restore_node_topology(),public.sandbox_restore_node_topology_payload_valid(jsonb),public.sandbox_restore_topology_timestamp_valid(text) FROM %I',ordinary_role);
  END IF;
 END LOOP;
END $$;
