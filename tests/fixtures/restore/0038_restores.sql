-- DRAFT: not an applied migration. Final dispatch/operation checks must retain
-- the preceding file-transfer and BFF migrations before this enters migrations/.
-- Restore approval is separate from the capture-direction backup approval.
-- Owner certification must include actual CSI Block->Filesystem and explicit
-- start of the new workspace; a raw-device unit test cannot authorize dispatch.
-- Shape is independent of grants/current approval. NULL is always invalid;
-- no user can obtain a new storage purpose by supplying a class name alone.
CREATE FUNCTION sandbox_restore_storage_mapping_valid(mapping_json jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE field text;identity jsonb;zones jsonb;BEGIN
 IF mapping_json IS NULL OR jsonb_typeof(mapping_json) IS DISTINCT FROM 'object' THEN RETURN false;END IF;
 IF NOT(mapping_json ?& ARRAY['normal','raw','delivery','snapshot','workspace_kms_key_id','account_id','region','deployment','topology'])
  OR (SELECT count(*) FROM jsonb_object_keys(mapping_json) AS keys(key_name))<>9 OR octet_length(mapping_json::text)>8192 THEN RETURN false;END IF;
 FOREACH field IN ARRAY ARRAY['normal','raw','delivery','snapshot'] LOOP
  identity:=mapping_json->field;
  IF jsonb_typeof(identity) IS DISTINCT FROM 'object' THEN RETURN false;END IF;
  IF NOT(identity ?& ARRAY['name','uid','spec_sha256']) OR (SELECT count(*) FROM jsonb_object_keys(identity) AS keys(key_name))<>3
   OR jsonb_typeof(identity->'name') IS DISTINCT FROM 'string' OR char_length(identity->>'name') NOT BETWEEN 1 AND 63
   OR identity->>'name' !~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'
   OR jsonb_typeof(identity->'uid') IS DISTINCT FROM 'string' OR identity->>'uid' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
   OR identity->>'uid'='00000000-0000-0000-0000-000000000000'
   OR jsonb_typeof(identity->'spec_sha256') IS DISTINCT FROM 'string' OR identity->>'spec_sha256' !~ '^[0-9a-f]{64}$' THEN RETURN false;END IF;
 END LOOP;
 IF mapping_json->'normal'->>'name'=mapping_json->'raw'->>'name' OR mapping_json->'normal'->>'name'=mapping_json->'delivery'->>'name' OR mapping_json->'raw'->>'name'=mapping_json->'delivery'->>'name'
  OR (SELECT count(DISTINCT mapping_json->kind->>'uid') FROM unnest(ARRAY['normal','raw','delivery','snapshot']) AS purposes(kind))<>4 THEN RETURN false;END IF;
 IF jsonb_typeof(mapping_json->'workspace_kms_key_id') IS DISTINCT FROM 'string' OR char_length(mapping_json->>'workspace_kms_key_id') NOT BETWEEN 1 AND 256 OR mapping_json->>'workspace_kms_key_id' !~ '^[A-Za-z0-9/_:-]+$'
  OR jsonb_typeof(mapping_json->'account_id') IS DISTINCT FROM 'string' OR mapping_json->>'account_id' !~ '^[0-9]{16}$'
  OR jsonb_typeof(mapping_json->'region') IS DISTINCT FROM 'string' OR char_length(mapping_json->>'region') NOT BETWEEN 4 AND 32 OR mapping_json->>'region' !~ '^cn-[a-z0-9-]+$'
  OR jsonb_typeof(mapping_json->'deployment') IS DISTINCT FROM 'string' OR mapping_json->>'deployment' !~ '^[a-z][a-z0-9-]{3,19}$' THEN RETURN false;END IF;
 IF jsonb_typeof(mapping_json->'topology') IS DISTINCT FROM 'object' THEN RETURN false;END IF;
 IF NOT(mapping_json->'topology' ?& ARRAY['key','zone_ids']) OR (SELECT count(*) FROM jsonb_object_keys(mapping_json->'topology') AS keys(key_name))<>2
  OR mapping_json->'topology'->'key' IS DISTINCT FROM to_jsonb('topology.diskplugin.csi.alibabacloud.com/zone'::text) THEN RETURN false;END IF;
 zones:=mapping_json->'topology'->'zone_ids';
 IF jsonb_typeof(zones) IS DISTINCT FROM 'array' THEN RETURN false;END IF;
 IF jsonb_array_length(zones)<>3 OR EXISTS(SELECT 1 FROM jsonb_array_elements(zones) AS z(zone) WHERE jsonb_typeof(zone) IS DISTINCT FROM 'string'
   OR char_length(zone#>>'{}')>64 OR char_length(zone#>>'{}')<=char_length(mapping_json->>'region')+1 OR zone#>>'{}' !~ '^cn-[a-z0-9-]+$' OR zone#>>'{}' NOT LIKE ((mapping_json->>'region')||'-%'))
  OR (SELECT count(DISTINCT zone#>>'{}') FROM jsonb_array_elements(zones) AS z(zone))<>3
  OR zones IS DISTINCT FROM (SELECT jsonb_agg(zone ORDER BY (zone#>>'{}') COLLATE "C") FROM jsonb_array_elements(zones) AS z(zone)) THEN RETURN false;END IF;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION sandbox_restore_storage_mapping_valid(jsonb) FROM PUBLIC;
CREATE FUNCTION sandbox_restore_storage_mappings_valid(mappings_json jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE item jsonb;kind text;identity jsonb;previous jsonb;seen jsonb:='[]';BEGIN
 IF mappings_json IS NULL OR jsonb_typeof(mappings_json) IS DISTINCT FROM 'array' THEN RETURN false;END IF;
 IF jsonb_array_length(mappings_json) NOT BETWEEN 1 AND 32 OR octet_length(mappings_json::text)>65536 THEN RETURN false;END IF;
 FOR item IN SELECT entry FROM jsonb_array_elements(mappings_json) AS m(entry) LOOP
  IF public.sandbox_restore_storage_mapping_valid(item) IS NOT TRUE THEN RETURN false;END IF;
  FOREACH kind IN ARRAY ARRAY['normal','raw','delivery','snapshot'] LOOP
   identity:=item->kind;
   FOR previous IN SELECT prior FROM jsonb_array_elements(seen) AS s(prior) LOOP
    IF(kind='normal' AND previous->>'purpose'='normal' AND previous->'identity'->>'name'=identity->>'name')
     OR((previous->'identity'->>'uid'=identity->>'uid' OR(kind<>'snapshot' AND previous->>'purpose'<>'snapshot' AND previous->'identity'->>'name'=identity->>'name')
       OR(kind='snapshot' AND previous->>'purpose'='snapshot' AND previous->'identity'->>'name'=identity->>'name'))
       AND(previous->>'purpose'<>kind OR previous->'identity' IS DISTINCT FROM identity)) THEN RETURN false;END IF;
   END LOOP;
   seen:=seen||jsonb_build_array(jsonb_build_object('purpose',kind,'identity',identity));
  END LOOP;
 END LOOP;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION sandbox_restore_storage_mappings_valid(jsonb) FROM PUBLIC;
CREATE FUNCTION sandbox_restore_storage_contract_valid(contract_json jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE field text;BEGIN
 IF contract_json IS NULL OR jsonb_typeof(contract_json) IS DISTINCT FROM 'object' THEN RETURN false;END IF;
 IF NOT(contract_json ?& ARRAY['protocol','profile_id','cluster_epoch','backup_certification_sha256','report_sha256','mapping'])
  OR (SELECT count(*) FROM jsonb_object_keys(contract_json) AS keys(key_name))<>6 OR octet_length(contract_json::text)>16384
  OR jsonb_typeof(contract_json->'protocol') IS DISTINCT FROM 'number' OR (contract_json->'protocol')::text IS DISTINCT FROM '1' THEN RETURN false;END IF;
 FOREACH field IN ARRAY ARRAY['profile_id','cluster_epoch'] LOOP
  IF jsonb_typeof(contract_json->field) IS DISTINCT FROM 'string' OR contract_json->>field !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
   OR contract_json->>field='00000000-0000-0000-0000-000000000000' THEN RETURN false;END IF;
 END LOOP;
 FOREACH field IN ARRAY ARRAY['backup_certification_sha256','report_sha256'] LOOP
  IF jsonb_typeof(contract_json->field) IS DISTINCT FROM 'string' OR contract_json->>field !~ '^[0-9a-f]{64}$' THEN RETURN false;END IF;
 END LOOP;
 RETURN public.sandbox_restore_storage_mapping_valid(contract_json->'mapping') IS TRUE;
END $$;
REVOKE ALL ON FUNCTION sandbox_restore_storage_contract_valid(jsonb) FROM PUBLIC;
CREATE TABLE restore_profile_certifications (
 profile_id uuid PRIMARY KEY REFERENCES backup_profiles(id),cluster_epoch uuid NOT NULL,
 backup_certification_sha256 text NOT NULL CHECK(backup_certification_sha256~'^[0-9a-f]{64}$'),
 report_sha256 text NOT NULL CHECK(report_sha256~'^[0-9a-f]{64}$'),report jsonb NOT NULL CHECK(jsonb_typeof(report)='object' AND octet_length(report::text)<=131072),
 storage_mappings jsonb NOT NULL CHECK(sandbox_restore_storage_mappings_valid(storage_mappings) IS TRUE),
 approval_reference text NOT NULL CHECK(char_length(approval_reference) BETWEEN 1 AND 256),
 reviewed_at timestamptz NOT NULL,certified_until timestamptz NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),CHECK(certified_until>reviewed_at AND certified_until<=reviewed_at+interval '30 days')
);
CREATE FUNCTION sandbox_guard_restore_certification() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE bp public.backup_profiles;binding jsonb;item jsonb;BEGIN
 SELECT * INTO bp FROM public.backup_profiles WHERE id=NEW.profile_id;
 binding:=NEW.report->'bindings';
 IF bp.id IS NULL OR NEW.cluster_epoch<>bp.cluster_epoch OR NEW.backup_certification_sha256<>bp.certification_sha256
  OR jsonb_typeof(NEW.report->'protocol') IS DISTINCT FROM 'number' OR (NEW.report->'protocol')::text IS DISTINCT FROM '1'
  OR jsonb_typeof(binding) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'restore certification requires exact profile and storage report binding' USING ERRCODE='23514';END IF;
 IF NOT(binding ?& ARRAY['profile_id','cluster_epoch','backup_certification_sha256','storage_mappings','account_id','region','deployment','workspace_kms_key_id','versions_lock_sha256','infrastructure_sha256'])
  OR (SELECT count(*) FROM jsonb_object_keys(binding))<>10
  OR binding->'profile_id' IS DISTINCT FROM to_jsonb(NEW.profile_id::text) OR binding->'cluster_epoch' IS DISTINCT FROM to_jsonb(NEW.cluster_epoch::text)
  OR binding->'backup_certification_sha256' IS DISTINCT FROM to_jsonb(NEW.backup_certification_sha256)
  OR binding->'storage_mappings' IS DISTINCT FROM NEW.storage_mappings
  OR binding->'account_id' IS DISTINCT FROM bp.settings->'account_id' OR binding->'region' IS DISTINCT FROM bp.settings->'region' OR binding->'deployment' IS DISTINCT FROM bp.settings->'deployment'
  OR jsonb_typeof(binding->'versions_lock_sha256') IS DISTINCT FROM 'string' OR binding->>'versions_lock_sha256' !~ '^[0-9a-f]{64}$'
  OR jsonb_typeof(binding->'infrastructure_sha256') IS DISTINCT FROM 'string' OR binding->>'infrastructure_sha256' !~ '^[0-9a-f]{64}$'
  OR public.sandbox_restore_storage_mappings_valid(NEW.storage_mappings) IS NOT TRUE THEN
  RAISE EXCEPTION 'restore certification requires exact profile and storage report binding' USING ERRCODE='23514';END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(NEW.storage_mappings) LOOP
  IF item->'account_id' IS DISTINCT FROM binding->'account_id' OR item->'region' IS DISTINCT FROM binding->'region' OR item->'deployment' IS DISTINCT FROM binding->'deployment'
   OR item->'workspace_kms_key_id' IS DISTINCT FROM binding->'workspace_kms_key_id' THEN
   RAISE EXCEPTION 'restore storage mapping belongs to another cloud deployment' USING ERRCODE='23514';END IF;
 END LOOP;
 RETURN NEW;
END $$;
CREATE TRIGGER restore_certification_binding_guard BEFORE INSERT ON restore_profile_certifications FOR EACH ROW EXECUTE FUNCTION sandbox_guard_restore_certification();
REVOKE ALL ON FUNCTION sandbox_guard_restore_certification() FROM PUBLIC;
CREATE TRIGGER restore_certification_append_only BEFORE UPDATE OR DELETE ON restore_profile_certifications FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_audit_mutation();
REVOKE ALL ON restore_profile_certifications FROM PUBLIC;
CREATE FUNCTION sandbox_restore_profile_current(profile uuid,epoch uuid,required_until timestamptz) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT COALESCE(EXISTS(SELECT 1 FROM public.restore_profile_certifications rc JOIN public.backup_profiles bp ON bp.id=rc.profile_id
  WHERE rc.profile_id=$1 AND rc.cluster_epoch=$2 AND bp.cluster_epoch=$2 AND bp.enabled AND rc.backup_certification_sha256=bp.certification_sha256
   AND rc.reviewed_at<=clock_timestamp() AND rc.certified_until>clock_timestamp() AND rc.certified_until>=$3 AND bp.certified_until>=rc.certified_until),false);
$$;
REVOKE ALL ON FUNCTION sandbox_restore_profile_current(uuid,uuid,timestamptz) FROM PUBLIC;
-- Permanent membership proves the historical tuple, never a current write grant.
CREATE FUNCTION sandbox_restore_storage_contract_certified(profile uuid,epoch uuid,contract jsonb) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT COALESCE(public.sandbox_restore_storage_contract_valid($3) IS TRUE AND EXISTS(
  SELECT 1 FROM public.restore_profile_certifications c WHERE c.profile_id=$1 AND c.cluster_epoch=$2
   AND $3->'profile_id'=to_jsonb(c.profile_id::text) AND $3->'cluster_epoch'=to_jsonb(c.cluster_epoch::text)
   AND $3->'backup_certification_sha256'=to_jsonb(c.backup_certification_sha256) AND $3->'report_sha256'=to_jsonb(c.report_sha256)
   AND EXISTS(SELECT 1 FROM jsonb_array_elements(c.storage_mappings) mapping WHERE mapping=$3->'mapping')),false);
$$;
REVOKE ALL ON FUNCTION sandbox_restore_storage_contract_certified(uuid,uuid,jsonb) FROM PUBLIC;
CREATE FUNCTION sandbox_lock_restore_configuration(requested_tenant uuid,target uuid,profile uuid,epoch uuid,required_until timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE storage text;cert public.restore_profile_certifications;mapping jsonb;matches bigint;BEGIN
 IF $1 IS DISTINCT FROM public.sandbox_current_tenant_id() OR $5 IS NULL THEN RETURN NULL;END IF;
 SELECT storage_class INTO storage FROM public.projects WHERE tenant_id=$1 AND id=$2 AND enabled FOR SHARE;
 IF NOT FOUND OR storage IS NULL THEN RETURN NULL;END IF;
 PERFORM 1 FROM public.backup_profiles WHERE id=$3 AND cluster_epoch=$4 AND enabled AND certified_until>=$5 FOR SHARE;
 IF NOT FOUND OR public.sandbox_restore_profile_current($3,$4,$5) IS NOT TRUE THEN RETURN NULL;END IF;
 SELECT * INTO cert FROM public.restore_profile_certifications WHERE profile_id=$3 AND cluster_epoch=$4;
 IF NOT FOUND THEN RETURN NULL;END IF;
 SELECT count(*) INTO matches FROM jsonb_array_elements(cert.storage_mappings) m WHERE m->'normal'->>'name'=storage;
 IF matches<>1 THEN RETURN NULL;END IF;
 SELECT m INTO mapping FROM jsonb_array_elements(cert.storage_mappings) m WHERE m->'normal'->>'name'=storage;
 RETURN jsonb_build_object('protocol',1,'profile_id',cert.profile_id::text,'cluster_epoch',cert.cluster_epoch::text,
  'backup_certification_sha256',cert.backup_certification_sha256,'report_sha256',cert.report_sha256,'mapping',mapping);
END $$;
REVOKE ALL ON FUNCTION sandbox_lock_restore_configuration(uuid,uuid,uuid,uuid,timestamptz) FROM PUBLIC;
ALTER TABLE operations DROP CONSTRAINT operations_kind_check;
ALTER TABLE operations ADD CONSTRAINT operations_kind_check CHECK(kind IN('CREATE','START','STOP','RESTART','DELETE','RENEW','EXECUTE','DELETE_WORKSPACE','BACKUP','DIAGNOSE','FILE_TRANSFER','RESTORE'));
CREATE TABLE restores (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,backup_id uuid NOT NULL,source_project_id uuid NOT NULL,
 target_project_id uuid NOT NULL,workspace_id uuid NOT NULL UNIQUE,instance_id uuid NOT NULL UNIQUE,
 operation_id uuid NOT NULL UNIQUE,profile_id uuid NOT NULL REFERENCES backup_profiles(id),hold_id uuid NOT NULL,
 cluster_epoch uuid NOT NULL,source_manifest_sha256 text NOT NULL CHECK(source_manifest_sha256~'^[0-9a-f]{64}$'),
 source_identity jsonb NOT NULL CHECK(jsonb_typeof(source_identity)='object' AND octet_length(source_identity::text)<=16384),
 storage_contract jsonb NOT NULL CHECK(sandbox_restore_storage_contract_valid(storage_contract) IS TRUE),
 size_gib bigint NOT NULL CHECK(size_gib BETWEEN 20 AND 1024),
 status text NOT NULL DEFAULT 'QUEUED' CHECK(status IN('QUEUED','VERIFIED','BLOCK_PENDING','RESTORE_PENDING','RESTORE_RUNNING','RESTORE_CLOSING','SNAPSHOT_PENDING','DELIVERY_PENDING','AVAILABLE','CANCELLED')),
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),deadline timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,id),UNIQUE(tenant_id,target_project_id,id),UNIQUE(tenant_id,id,workspace_id),
 FOREIGN KEY(tenant_id,source_project_id,backup_id) REFERENCES backups(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,target_project_id,workspace_id) REFERENCES workspaces(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,target_project_id,instance_id,workspace_id) REFERENCES instances(tenant_id,project_id,id,workspace_id),
 FOREIGN KEY(tenant_id,target_project_id,workspace_id,operation_id) REFERENCES operations(tenant_id,project_id,workspace_id,id),
 FOREIGN KEY(tenant_id,hold_id) REFERENCES workspace_holds(tenant_id,id),
 CHECK(deadline>created_at AND deadline<=created_at+interval '6 hours')
);
-- PostgreSQL row locks require UPDATE privilege. The API identity stays
-- read-only on historical backups; this narrow tenant-bound definer takes only
-- a source SHARE lock and cannot alter or repoint any backup evidence.
CREATE FUNCTION sandbox_lock_restore_source(requested_tenant uuid,backup uuid) RETURNS SETOF public.backups
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT b.* FROM public.backups b WHERE $1=public.sandbox_current_tenant_id() AND b.tenant_id=$1 AND b.id=$2 FOR SHARE;
$$;
REVOKE ALL ON FUNCTION sandbox_lock_restore_source(uuid,uuid) FROM PUBLIC;
CREATE INDEX restores_target_list ON restores(tenant_id,target_project_id,created_at DESC,id DESC);
-- This FK/reference survives completion and makes future backup GC explicitly
-- inspect restore references; a caller cannot repoint it to another backup.
CREATE INDEX restores_backup_references ON restores(tenant_id,backup_id,status);
CREATE TABLE restore_vault_receipts (
 restore_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,backup_id uuid NOT NULL,
 manifest_sha256 text NOT NULL CHECK(manifest_sha256~'^[0-9a-f]{64}$'),
 signing_key_sha256 text NOT NULL CHECK(signing_key_sha256~'^[0-9a-f]{64}$'),
 vault_endpoint text NOT NULL,verified_at timestamptz NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,restore_id),FOREIGN KEY(tenant_id,restore_id) REFERENCES restores(tenant_id,id),
 FOREIGN KEY(tenant_id,backup_id) REFERENCES backups(tenant_id,id)
);
CREATE TABLE restore_resource_intents (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,restore_id uuid NOT NULL,
 kind text NOT NULL CHECK(kind IN('BLOCK_PVC','BLOCK_PV','CONFIG','JOB','POD','RESTORED_SNAPSHOT','RESTORED_CONTENT','DELIVERY_CONTENT','DELIVERY_SNAPSHOT','WORKSPACE_PVC','WORKSPACE_PV')),
 namespace text NOT NULL,name text NOT NULL,expected_object jsonb,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,id),UNIQUE(tenant_id,restore_id,id),
 UNIQUE(tenant_id,restore_id,kind),UNIQUE(tenant_id,restore_id,kind,namespace,name),FOREIGN KEY(tenant_id,restore_id) REFERENCES restores(tenant_id,id),
 CHECK(expected_object IS NULL OR(jsonb_typeof(expected_object)='object' AND octet_length(expected_object::text)<=131072))
);
CREATE TABLE restore_resource_bindings (
 intent_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,restore_id uuid NOT NULL,uid uuid NOT NULL UNIQUE,
 observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,intent_id),
 FOREIGN KEY(tenant_id,restore_id,intent_id) REFERENCES restore_resource_intents(tenant_id,restore_id,id)
);
CREATE TABLE restore_block_receipts (
 restore_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,pvc_uid uuid NOT NULL,pv_uid uuid NOT NULL,pv_name text NOT NULL,
 cloud_disk text NOT NULL CHECK(cloud_disk~'^d-[a-zA-Z0-9]+$'),size_bytes bigint NOT NULL CHECK(size_bytes>0 AND size_bytes%512=0),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,restore_id),
 FOREIGN KEY(tenant_id,restore_id) REFERENCES restores(tenant_id,id)
);
CREATE TABLE restore_job_contexts (
 restore_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,context jsonb NOT NULL CHECK(jsonb_typeof(context)='object' AND octet_length(context::text)<=131072),
 deadline timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,restore_id),FOREIGN KEY(tenant_id,restore_id) REFERENCES restores(tenant_id,id)
);
CREATE TABLE restore_pod_admissions (
 restore_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,job_uid uuid NOT NULL,review_uid uuid NOT NULL UNIQUE,
 admitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,restore_id),
 FOREIGN KEY(tenant_id,restore_id) REFERENCES restores(tenant_id,id)
);
CREATE TABLE restore_launch_permits (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,restore_id uuid NOT NULL UNIQUE,runtime_node_id uuid NOT NULL REFERENCES runtime_nodes(id),
 operation_id uuid NOT NULL,lease_token bigint NOT NULL CHECK(lease_token>0),
 request jsonb NOT NULL CHECK(jsonb_typeof(request)='object' AND octet_length(request::text)<=65536),
 expires_at timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,id),UNIQUE(tenant_id,restore_id,id),FOREIGN KEY(tenant_id,restore_id) REFERENCES restores(tenant_id,id),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES operations(tenant_id,id)
);
CREATE TABLE restore_launch_receipts (
 permit_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,restore_id uuid NOT NULL,
 journal_revision bigint NOT NULL CHECK(journal_revision>0),effective_expires_at timestamptz NOT NULL,
 observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,permit_id),
 FOREIGN KEY(tenant_id,restore_id,permit_id) REFERENCES restore_launch_permits(tenant_id,restore_id,id)
);
CREATE TABLE restore_close_challenges (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,restore_id uuid NOT NULL,permit_id uuid NOT NULL,
 lease_token bigint NOT NULL CHECK(lease_token>0),issued_at timestamptz NOT NULL,not_after timestamptz NOT NULL,
 UNIQUE(tenant_id,id),UNIQUE(tenant_id,restore_id,id),
 FOREIGN KEY(tenant_id,restore_id,permit_id) REFERENCES restore_launch_permits(tenant_id,restore_id,id),
 CHECK(not_after>issued_at AND not_after<=issued_at+interval '30 seconds')
);
CREATE TABLE restore_termination_proofs (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,restore_id uuid NOT NULL,permit_id uuid NOT NULL UNIQUE,
 challenge_id uuid NOT NULL UNIQUE,runtime_node_id uuid NOT NULL REFERENCES runtime_nodes(id),
 evidence jsonb NOT NULL CHECK(jsonb_typeof(evidence)='object' AND octet_length(evidence::text)<=65536),
 journal_revision bigint NOT NULL CHECK(journal_revision>0),evidence_sha256 text NOT NULL CHECK(evidence_sha256~'^[0-9a-f]{64}$'),observed_at timestamptz NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,id),UNIQUE(tenant_id,restore_id,id),
 FOREIGN KEY(tenant_id,restore_id,permit_id) REFERENCES restore_launch_permits(tenant_id,restore_id,id),
 FOREIGN KEY(tenant_id,restore_id,challenge_id) REFERENCES restore_close_challenges(tenant_id,restore_id,id)
);
CREATE TABLE restore_cleanup_receipts (
 proof_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,restore_id uuid NOT NULL,pod_uid uuid NOT NULL,
 pvc_uid uuid NOT NULL,pv_uid uuid NOT NULL,cloud_disk text NOT NULL,
 pod_absent_at timestamptz NOT NULL,volume_checked_at timestamptz NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,restore_id),FOREIGN KEY(tenant_id,restore_id,proof_id) REFERENCES restore_termination_proofs(tenant_id,restore_id,id)
);
-- A bounded result from the certified data mover does not assert host death.
CREATE TABLE restore_io_reports (
 restore_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,exit_code integer NOT NULL,
 bytes bigint,disk_sha256 text,finished_at timestamptz NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,restore_id),FOREIGN KEY(tenant_id,restore_id) REFERENCES restores(tenant_id,id),
 CHECK(bytes IS NULL OR bytes>0),CHECK(disk_sha256 IS NULL OR disk_sha256~'^[0-9a-f]{64}$')
);
CREATE TABLE restore_snapshot_receipts (
 restore_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,snapshot_uid uuid NOT NULL,content_uid uuid NOT NULL,content_name text NOT NULL,
 cloud_snapshot text NOT NULL CHECK(cloud_snapshot~'^s-[a-zA-Z0-9]+$'),size_bytes bigint NOT NULL CHECK(size_bytes>0 AND size_bytes%512=0),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,restore_id),
 FOREIGN KEY(tenant_id,restore_id) REFERENCES restores(tenant_id,id)
);
CREATE TABLE restore_delivery_receipts (
 restore_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,workspace_id uuid NOT NULL,
 namespace text NOT NULL,snapshot_name text NOT NULL,snapshot_uid uuid NOT NULL,content_uid uuid NOT NULL,
 pvc_uid uuid NOT NULL,pv_uid uuid NOT NULL,pv_name text NOT NULL,cloud_disk text NOT NULL CHECK(cloud_disk~'^d-[a-zA-Z0-9]+$'),
 cloud_snapshot text NOT NULL CHECK(cloud_snapshot~'^s-[a-zA-Z0-9]+$'),size_bytes bigint NOT NULL CHECK(size_bytes>0 AND size_bytes%512=0),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,workspace_id),UNIQUE(tenant_id,workspace_id,snapshot_name),
 FOREIGN KEY(tenant_id,restore_id,workspace_id) REFERENCES restores(tenant_id,id,workspace_id)
);
CREATE TABLE restore_artifact_cleanup_receipts (
 restore_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,job_uid uuid NOT NULL,config_uid uuid NOT NULL,
 observed_at timestamptz NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,restore_id),FOREIGN KEY(tenant_id,restore_id) REFERENCES restores(tenant_id,id)
);
ALTER TABLE workspaces ADD COLUMN restore_snapshot_name text,
 ADD CONSTRAINT workspace_restore_snapshot_binding FOREIGN KEY(tenant_id,id,restore_snapshot_name)
 REFERENCES restore_delivery_receipts(tenant_id,workspace_id,snapshot_name);
DO $$ DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['restores','restore_vault_receipts','restore_resource_intents','restore_resource_bindings','restore_block_receipts','restore_job_contexts','restore_pod_admissions','restore_launch_permits','restore_launch_receipts','restore_close_challenges','restore_termination_proofs','restore_cleanup_receipts','restore_io_reports','restore_snapshot_receipts','restore_delivery_receipts','restore_artifact_cleanup_receipts'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
  EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.sandbox_current_tenant_id()) WITH CHECK(tenant_id=public.sandbox_current_tenant_id())',tab);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',tab);
  IF tab<>'restores' THEN EXECUTE format('CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.sandbox_prevent_audit_mutation()',tab);END IF;
 END LOOP;
END $$;
CREATE TRIGGER restore_no_delete BEFORE DELETE ON restores FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_audit_mutation();

-- New objects are created atomically under one request. The accepted source is
-- already independently verified; dispatch must verify it afresh before writes.
CREATE FUNCTION sandbox_guard_restore() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE b public.backups;w public.workspaces;i public.instances;h public.workspace_holds;bp public.backup_profiles;oldbp public.backup_profiles;v public.backup_vault_receipts;BEGIN
 IF TG_OP='INSERT' THEN
  SELECT * INTO b FROM public.backups WHERE tenant_id=NEW.tenant_id AND id=NEW.backup_id;
  SELECT * INTO v FROM public.backup_vault_receipts WHERE tenant_id=NEW.tenant_id AND backup_id=NEW.backup_id;
  SELECT * INTO w FROM public.workspaces WHERE tenant_id=NEW.tenant_id AND id=NEW.workspace_id FOR UPDATE;
  SELECT * INTO i FROM public.instances WHERE tenant_id=NEW.tenant_id AND id=NEW.instance_id FOR UPDATE;
  SELECT * INTO h FROM public.workspace_holds WHERE tenant_id=NEW.tenant_id AND id=NEW.hold_id;
  SELECT * INTO bp FROM public.backup_profiles WHERE id=NEW.profile_id;
  SELECT * INTO oldbp FROM public.backup_profiles WHERE id=b.profile_id;
  IF NEW.status<>'QUEUED' OR b.status<>'AVAILABLE' OR b.project_id<>NEW.source_project_id OR b.retention_until<NEW.deadline+interval '5 minutes'
   OR v.backup_id IS NULL OR v.manifest_sha256<>NEW.source_manifest_sha256 OR v.manifest->'manifest'->'backup' IS DISTINCT FROM NEW.source_identity
   OR w.status<>'PENDING' OR w.project_id<>NEW.target_project_id OR w.size_gib<>NEW.size_gib OR NEW.size_gib<>b.size_gib OR w.active_operation_id IS DISTINCT FROM NEW.operation_id
   OR i.workspace_id<>w.id OR i.project_id<>NEW.target_project_id OR i.desired_state<>'STOPPED' OR i.observed_state<>'STOPPED' OR i.pod_uid IS NOT NULL OR i.slot_held OR i.active_operation_id IS DISTINCT FROM NEW.operation_id
   OR h.workspace_id<>w.id OR h.kind<>'RESTORE' OR h.reference_id<>NEW.id
   OR NOT EXISTS(SELECT 1 FROM public.operations o WHERE o.tenant_id=NEW.tenant_id AND o.id=NEW.operation_id AND o.kind='RESTORE' AND o.instance_id=i.id AND o.workspace_id=w.id AND o.deadline=NEW.deadline)
   OR NOT EXISTS(SELECT 1 FROM public.template_versions t WHERE t.tenant_id=i.tenant_id AND t.id=i.template_version_id AND t.status='APPROVED')
   OR NOT EXISTS(SELECT 1 FROM public.security_policy_versions s WHERE s.tenant_id=i.tenant_id AND s.id=i.security_policy_version_id AND s.status='APPROVED')
   OR NOT bp.enabled OR bp.cluster_epoch<>NEW.cluster_epoch OR bp.certified_until<NEW.deadline OR NOT public.sandbox_restore_profile_current(NEW.profile_id,NEW.cluster_epoch,NEW.deadline)
   OR public.sandbox_restore_storage_contract_certified(NEW.profile_id,NEW.cluster_epoch,NEW.storage_contract) IS NOT TRUE
   OR w.storage_class IS DISTINCT FROM NEW.storage_contract->'mapping'->'delivery'->>'name'
   OR NOT EXISTS(SELECT 1 FROM public.projects target WHERE target.tenant_id=NEW.tenant_id AND target.id=NEW.target_project_id AND target.storage_class=NEW.storage_contract->'mapping'->'normal'->>'name')
   OR NOT EXISTS(SELECT 1 FROM public.platform_configuration c WHERE c.singleton AND c.cluster_epoch=NEW.cluster_epoch AND NOT c.safe_mode)
   OR bp.settings->'secret_bindings'->'password' IS DISTINCT FROM oldbp.settings->'secret_bindings'->'password'
   OR bp.settings->'secret_bindings'->'signing_public' IS DISTINCT FROM oldbp.settings->'secret_bindings'->'signing_public'
   OR EXISTS(SELECT 1 FROM unnest(ARRAY['key_ref','region','account_id','bucket','vault_bucket','kms_key_id','vault_kms_key_id','signing_key_sha256','vault_endpoint']) k WHERE bp.settings->k IS DISTINCT FROM oldbp.settings->k) THEN
   RAISE EXCEPTION 'restore requires immutable verified source, new held stopped target and current compatible profile' USING ERRCODE='23514';END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['status','version','updated_at']) IS DISTINCT FROM(to_jsonb(OLD)-ARRAY['status','version','updated_at']) OR NEW.version<>OLD.version+1 OR OLD.status IN('AVAILABLE','CANCELLED') THEN
   RAISE EXCEPTION 'restore identity/history is immutable' USING ERRCODE='23514';END IF;
  IF current_user<>'sandbox_backup' AND NOT pg_has_role(current_user,(SELECT relowner FROM pg_class WHERE oid=TG_RELID),'MEMBER') THEN
   RAISE EXCEPTION 'only backup controller may advance restore' USING ERRCODE='42501';END IF;
  IF NOT ((OLD.status='QUEUED' AND NEW.status IN('VERIFIED','CANCELLED')) OR(OLD.status='VERIFIED' AND NEW.status IN('BLOCK_PENDING','CANCELLED'))
   OR(OLD.status='BLOCK_PENDING' AND NEW.status IN('RESTORE_PENDING','RESTORE_CLOSING')) OR(OLD.status='RESTORE_PENDING' AND NEW.status IN('RESTORE_RUNNING','RESTORE_CLOSING'))
   OR(OLD.status='RESTORE_RUNNING' AND NEW.status='RESTORE_CLOSING') OR(OLD.status='RESTORE_CLOSING' AND NEW.status IN('SNAPSHOT_PENDING','CANCELLED'))
   OR(OLD.status='SNAPSHOT_PENDING' AND NEW.status='DELIVERY_PENDING') OR(OLD.status='DELIVERY_PENDING' AND NEW.status='AVAILABLE')) THEN
   RAISE EXCEPTION 'restore transition is not authoritative' USING ERRCODE='23514';END IF;
  IF NEW.status IN('SNAPSHOT_PENDING','AVAILABLE','CANCELLED') AND(
   EXISTS(SELECT 1 FROM public.restore_launch_permits p WHERE p.tenant_id=NEW.tenant_id AND p.restore_id=NEW.id AND NOT EXISTS(SELECT 1 FROM public.restore_termination_proofs proof JOIN public.restore_cleanup_receipts c ON c.tenant_id=proof.tenant_id AND c.proof_id=proof.id WHERE proof.tenant_id=p.tenant_id AND proof.permit_id=p.id))
   OR EXISTS(SELECT 1 FROM public.restore_pod_admissions a WHERE a.tenant_id=NEW.tenant_id AND a.restore_id=NEW.id AND NOT EXISTS(SELECT 1 FROM public.restore_termination_proofs p JOIN public.restore_cleanup_receipts c ON c.tenant_id=p.tenant_id AND c.proof_id=p.id WHERE p.tenant_id=a.tenant_id AND p.restore_id=a.restore_id))) THEN
   RAISE EXCEPTION 'unresolved restore task retains holds and accounting' USING ERRCODE='23514';END IF;
  IF NEW.status IN('SNAPSHOT_PENDING','DELIVERY_PENDING','AVAILABLE') AND NOT EXISTS(SELECT 1 FROM public.restore_termination_proofs proof JOIN public.restore_cleanup_receipts cleanup ON cleanup.tenant_id=proof.tenant_id AND cleanup.proof_id=proof.id WHERE proof.tenant_id=NEW.tenant_id AND proof.restore_id=NEW.id AND cleanup.restore_id=NEW.id) THEN
   RAISE EXCEPTION 'restore delivery requires an actual trusted isolated-writer closure' USING ERRCODE='23514';END IF;
  IF NEW.status='DELIVERY_PENDING' AND NOT EXISTS(SELECT 1 FROM public.restore_snapshot_receipts snapshot WHERE snapshot.tenant_id=NEW.tenant_id AND snapshot.restore_id=NEW.id AND snapshot.size_bytes=NEW.size_gib*1073741824) THEN
   RAISE EXCEPTION 'restore delivery requires an exact immutable raw snapshot receipt' USING ERRCODE='23514';END IF;
  IF NEW.status IN('SNAPSHOT_PENDING','DELIVERY_PENDING','AVAILABLE') AND NOT EXISTS(SELECT 1 FROM public.restore_io_reports io WHERE io.tenant_id=NEW.tenant_id AND io.restore_id=NEW.id AND io.exit_code=0 AND io.bytes=NEW.size_gib*1073741824 AND io.disk_sha256=(SELECT vault.manifest->'manifest'->'disk'->>'sha256' FROM public.backup_vault_receipts vault WHERE vault.tenant_id=NEW.tenant_id AND vault.backup_id=NEW.backup_id)) THEN
   RAISE EXCEPTION 'restored snapshot requires exact successful full-device readback' USING ERRCODE='23514';END IF;
  IF NEW.status='AVAILABLE' AND NOT EXISTS(SELECT 1 FROM public.restore_artifact_cleanup_receipts cleanup WHERE cleanup.tenant_id=NEW.tenant_id AND cleanup.restore_id=NEW.id AND cleanup.observed_at>=clock_timestamp()-interval '30 seconds' AND cleanup.observed_at<=clock_timestamp()+interval '2 seconds') THEN
   RAISE EXCEPTION 'available restore requires observed control-object removal' USING ERRCODE='23514';END IF;
  IF NEW.status='AVAILABLE' AND NOT EXISTS(SELECT 1 FROM public.restore_delivery_receipts d WHERE d.tenant_id=NEW.tenant_id AND d.restore_id=NEW.id AND d.workspace_id=NEW.workspace_id) THEN
   RAISE EXCEPTION 'available restore requires controlled filesystem delivery receipt' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;END $$;
CREATE TRIGGER restore_guard BEFORE INSERT OR UPDATE ON restores FOR EACH ROW EXECUTE FUNCTION sandbox_guard_restore();
REVOKE ALL ON FUNCTION sandbox_guard_restore() FROM PUBLIC;

CREATE FUNCTION sandbox_restore_authorized(requested_tenant uuid,restore uuid,require_lease boolean) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT COALESCE($1=public.sandbox_current_tenant_id() AND EXISTS(
  SELECT 1 FROM public.restores r JOIN public.backups b ON b.tenant_id=r.tenant_id AND b.id=r.backup_id JOIN public.operations o ON o.tenant_id=r.tenant_id AND o.id=r.operation_id
   JOIN public.backup_profiles bp ON bp.id=r.profile_id JOIN public.platform_configuration cfg ON cfg.singleton JOIN public.tenants t ON t.id=r.tenant_id
   JOIN public.projects source ON source.tenant_id=r.tenant_id AND source.id=r.source_project_id JOIN public.projects target ON target.tenant_id=r.tenant_id AND target.id=r.target_project_id
   JOIN public.instances i ON i.tenant_id=r.tenant_id AND i.id=r.instance_id JOIN public.workspaces w ON w.tenant_id=r.tenant_id AND w.id=r.workspace_id
  WHERE r.tenant_id=$1 AND r.id=$2 AND r.status NOT IN('AVAILABLE','CANCELLED') AND r.cluster_epoch=cfg.cluster_epoch AND bp.cluster_epoch=cfg.cluster_epoch AND NOT cfg.safe_mode
   AND t.enabled AND source.enabled AND target.enabled AND bp.enabled AND bp.certified_until>=r.deadline AND public.sandbox_restore_profile_current(r.profile_id,r.cluster_epoch,r.deadline)
   AND r.deadline>clock_timestamp() AND b.status='AVAILABLE' AND b.retention_until>=r.deadline+interval '5 minutes'
   AND o.kind='RESTORE' AND o.status IN('QUEUED','RUNNING','WAITING') AND NOT o.cancel_requested AND(NOT $3 OR(o.status='RUNNING' AND o.lease_owner IS NOT NULL AND o.lease_until>clock_timestamp()))
   AND public.sandbox_principal_enabled(o.actor_principal_id) AND i.desired_state='STOPPED' AND i.observed_state='STOPPED' AND i.pod_uid IS NULL AND NOT i.slot_held
   AND i.active_operation_id=r.operation_id AND w.active_operation_id=r.operation_id AND w.status='PENDING'
   AND public.sandbox_restore_storage_contract_certified(r.profile_id,r.cluster_epoch,r.storage_contract) IS TRUE
   AND target.storage_class=r.storage_contract->'mapping'->'normal'->>'name' AND w.storage_class=r.storage_contract->'mapping'->'delivery'->>'name'
   AND EXISTS(SELECT 1 FROM public.template_versions tv WHERE tv.tenant_id=i.tenant_id AND tv.id=i.template_version_id AND tv.status='APPROVED')
   AND EXISTS(SELECT 1 FROM public.security_policy_versions sp WHERE sp.tenant_id=i.tenant_id AND sp.id=i.security_policy_version_id AND sp.status='APPROVED')
   AND NOT EXISTS(SELECT 1 FROM(VALUES(r.source_project_id,'backups:read'),(r.source_project_id,'backups:restore'),(r.target_project_id,'instances:create')) actions(project_id,action)
     WHERE NOT EXISTS(SELECT 1 FROM public.grants g WHERE g.tenant_id=r.tenant_id AND g.principal_id=o.actor_principal_id AND g.project_id IS NULL AND g.action IN(actions.action,'*') AND g.enabled AND g.revoked_at IS NULL AND(g.expires_at IS NULL OR g.expires_at>clock_timestamp()))
       OR NOT EXISTS(SELECT 1 FROM public.grants g WHERE g.tenant_id=r.tenant_id AND g.principal_id=o.actor_principal_id AND g.project_id=actions.project_id AND g.action IN(actions.action,'*') AND g.enabled AND g.revoked_at IS NULL AND(g.expires_at IS NULL OR g.expires_at>clock_timestamp())))
   AND EXISTS(SELECT 1 FROM public.workspace_holds h WHERE h.tenant_id=r.tenant_id AND h.id=r.hold_id AND h.workspace_id=r.workspace_id AND h.kind='RESTORE' AND h.reference_id=r.id AND NOT EXISTS(SELECT 1 FROM public.workspace_hold_releases release WHERE release.tenant_id=h.tenant_id AND release.hold_id=h.id))),false);
$$;
REVOKE ALL ON FUNCTION sandbox_restore_authorized(uuid,uuid,boolean) FROM PUBLIC;

CREATE FUNCTION sandbox_admit_restore_pod(requested_tenant uuid,restore uuid,review uuid,job uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r public.restores;previous text:=current_setting('app.tenant_id',true);accepted boolean:=false;BEGIN
 IF requested_tenant IS NULL OR restore IS NULL OR review IS NULL OR job IS NULL OR requested_tenant='00000000-0000-0000-0000-000000000000' OR restore='00000000-0000-0000-0000-000000000000' OR review='00000000-0000-0000-0000-000000000000' OR job='00000000-0000-0000-0000-000000000000' THEN RETURN false;END IF;
 PERFORM set_config('app.tenant_id',requested_tenant::text,true);
 SELECT * INTO r FROM public.restores WHERE tenant_id=requested_tenant AND id=restore;
 IF r.id IS NULL THEN PERFORM set_config('app.tenant_id',COALESCE(previous,''),true);RETURN false;END IF;
 PERFORM 1 FROM public.workspaces WHERE tenant_id=requested_tenant AND id=r.workspace_id FOR UPDATE;
 PERFORM 1 FROM public.instances WHERE tenant_id=requested_tenant AND id=r.instance_id FOR UPDATE;
 PERFORM 1 FROM public.operations WHERE tenant_id=requested_tenant AND id=r.operation_id FOR UPDATE;
 SELECT * INTO r FROM public.restores WHERE tenant_id=requested_tenant AND id=restore FOR UPDATE;
 IF public.sandbox_restore_authorized(requested_tenant,r.id,true) AND r.status IN('RESTORE_PENDING','RESTORE_RUNNING')
  AND EXISTS(SELECT 1 FROM public.restore_vault_receipts v WHERE v.tenant_id=r.tenant_id AND v.restore_id=r.id AND v.manifest_sha256=r.source_manifest_sha256)
  AND EXISTS(SELECT 1 FROM public.restore_job_contexts c WHERE c.tenant_id=r.tenant_id AND c.restore_id=r.id AND c.deadline>clock_timestamp())
  AND EXISTS(SELECT 1 FROM public.restore_resource_intents i JOIN public.restore_resource_bindings b ON b.tenant_id=i.tenant_id AND b.intent_id=i.id WHERE i.tenant_id=r.tenant_id AND i.restore_id=r.id AND i.kind='JOB' AND b.uid=job) THEN
  INSERT INTO public.restore_pod_admissions(restore_id,tenant_id,job_uid,review_uid) VALUES(r.id,requested_tenant,job,review) ON CONFLICT(restore_id) DO NOTHING;
  SELECT a.job_uid=job AND a.review_uid=review INTO accepted FROM public.restore_pod_admissions a WHERE a.tenant_id=r.tenant_id AND a.restore_id=r.id;
 END IF;
 PERFORM set_config('app.tenant_id',COALESCE(previous,''),true);RETURN COALESCE(accepted,false);
END $$;
REVOKE ALL ON FUNCTION sandbox_admit_restore_pod(uuid,uuid,uuid,uuid) FROM PUBLIC;

-- Private RESTORE resource admission observes Kubernetes without holding SQL
-- locks, then takes the same W -> I -> operation -> restore order before the
-- final fresh authorization and immutable intent comparison.
CREATE FUNCTION sandbox_lock_restore_admission(requested_tenant uuid,restore uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r public.restores;active uuid;
BEGIN
 IF requested_tenant IS DISTINCT FROM public.sandbox_current_tenant_id() THEN RETURN false;END IF;
 SELECT * INTO r FROM public.restores WHERE tenant_id=requested_tenant AND id=restore;
 IF NOT FOUND THEN RETURN false;END IF;
 PERFORM 1 FROM public.workspaces WHERE tenant_id=requested_tenant AND id=r.workspace_id FOR UPDATE;
 IF NOT FOUND THEN RETURN false;END IF;
 SELECT active_operation_id INTO active FROM public.instances WHERE tenant_id=requested_tenant AND id=r.instance_id AND workspace_id=r.workspace_id FOR UPDATE;
 IF NOT FOUND THEN RETURN false;END IF;
 PERFORM 1 FROM public.operations WHERE tenant_id=requested_tenant AND(id=r.operation_id OR id=active) ORDER BY id FOR UPDATE;
 SELECT * INTO r FROM public.restores WHERE tenant_id=requested_tenant AND id=restore FOR UPDATE;
 PERFORM b.intent_id FROM public.restore_resource_bindings b WHERE b.tenant_id=requested_tenant AND b.restore_id=restore ORDER BY b.intent_id FOR SHARE;
 RETURN r.status IN('RESTORE_PENDING','RESTORE_RUNNING') AND public.sandbox_restore_authorized(requested_tenant,restore,true)
  AND EXISTS(SELECT 1 FROM public.restore_job_contexts c WHERE c.tenant_id=requested_tenant AND c.restore_id=restore AND c.deadline>clock_timestamp())
  AND EXISTS(SELECT 1 FROM public.restore_vault_receipts v WHERE v.tenant_id=r.tenant_id AND v.restore_id=r.id AND v.manifest_sha256=r.source_manifest_sha256);
END $$;
REVOKE ALL ON FUNCTION sandbox_lock_restore_admission(uuid,uuid) FROM PUBLIC;

-- Finite new-writer admission budget. The immutable intent/identity pin remains
-- separate; callers deduct all SQL and COMMIT acknowledgement time using an
-- Instant captured before their first SQL read. Existing historical status and
-- trusted closure do not acquire a new current grant/lease requirement.
CREATE FUNCTION sandbox_restore_admission_horizon(tenant uuid,restore uuid)
RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE horizon timestamptz;
BEGIN
 IF tenant IS DISTINCT FROM public.sandbox_current_tenant_id()
  OR NOT public.sandbox_lock_restore_admission(tenant,restore) THEN RETURN NULL;END IF;
 -- The complete STABLE authorization predicate, all six required grant scopes,
 -- and finite resource deadlines share this one statement's MVCC snapshot.
 -- A later SPI statement must not combine its Boolean with an older budget.
 WITH authority AS MATERIALIZED (
  SELECT r.tenant_id,o.actor_principal_id,r.source_project_id,r.target_project_id,
   LEAST(r.deadline,c.deadline,o.deadline,o.lease_until,bp.certified_until) AS resource_until
  FROM public.restores r
  JOIN public.restore_job_contexts c ON c.tenant_id=r.tenant_id AND c.restore_id=r.id
  JOIN public.operations o ON o.tenant_id=r.tenant_id AND o.id=r.operation_id
  JOIN public.backup_profiles bp ON bp.id=r.profile_id
  WHERE r.tenant_id=tenant AND r.id=restore
   AND public.sandbox_restore_authorized(tenant,restore,true)
 ), required AS (
  SELECT authority.tenant_id,authority.actor_principal_id,actions.project_id,actions.action
  FROM authority CROSS JOIN LATERAL(VALUES(authority.source_project_id,'backups:read'),
   (authority.source_project_id,'backups:restore'),(authority.target_project_id,'instances:create')) actions(project_id,action)
 ), horizons AS (
  SELECT required.project_id,required.action,scopes.project_id AS grant_project,
   MAX(COALESCE(g.expires_at,'infinity'::timestamptz)) FILTER(WHERE g.id IS NOT NULL) AS valid_until
  FROM required CROSS JOIN LATERAL(VALUES(NULL::uuid),(required.project_id)) scopes(project_id)
  LEFT JOIN public.grants g ON g.tenant_id=required.tenant_id AND g.principal_id=required.actor_principal_id
   AND g.project_id IS NOT DISTINCT FROM scopes.project_id AND g.action IN(required.action,'*')
   AND g.enabled AND g.revoked_at IS NULL AND(g.expires_at IS NULL OR g.expires_at>clock_timestamp())
  GROUP BY required.project_id,required.action,scopes.project_id
 ), budget AS (
  SELECT MIN(valid_until) AS grant_until,count(valid_until) AS matched FROM horizons
 ) SELECT LEAST(authority.resource_until,budget.grant_until) INTO horizon
  FROM authority CROSS JOIN budget
  WHERE budget.matched=6 AND budget.grant_until IS NOT NULL AND authority.resource_until IS NOT NULL;
 IF NOT FOUND OR horizon IS NULL OR horizon<=clock_timestamp() THEN RETURN NULL;END IF;
 RETURN floor(extract(epoch FROM(horizon-clock_timestamp()))*1000000)::bigint;
END $$;
REVOKE ALL ON FUNCTION sandbox_restore_admission_horizon(uuid,uuid) FROM PUBLIC;

-- Existing status/closure observations outlive caller grants, profile/node
-- enablement and the launch deadline. They cannot admit a new Pod or writer.
CREATE FUNCTION sandbox_lock_restore_observation(requested_tenant uuid,restore uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r public.restores;active uuid;
BEGIN
 IF requested_tenant IS DISTINCT FROM public.sandbox_current_tenant_id() THEN RETURN false;END IF;
 SELECT * INTO r FROM public.restores WHERE tenant_id=requested_tenant AND id=restore;
 IF NOT FOUND THEN RETURN false;END IF;
 PERFORM 1 FROM public.workspaces WHERE tenant_id=requested_tenant AND id=r.workspace_id FOR UPDATE;
 IF NOT FOUND THEN RETURN false;END IF;
 SELECT active_operation_id INTO active FROM public.instances WHERE tenant_id=requested_tenant AND id=r.instance_id AND workspace_id=r.workspace_id FOR UPDATE;
 IF NOT FOUND THEN RETURN false;END IF;
 PERFORM 1 FROM public.operations WHERE tenant_id=requested_tenant AND(id=r.operation_id OR id=active) ORDER BY id FOR UPDATE;
 SELECT * INTO r FROM public.restores WHERE tenant_id=requested_tenant AND id=restore FOR UPDATE;
 PERFORM b.intent_id FROM public.restore_resource_bindings b WHERE b.tenant_id=requested_tenant AND b.restore_id=restore ORDER BY b.intent_id FOR SHARE;
 RETURN r.status IN('RESTORE_PENDING','RESTORE_RUNNING','RESTORE_CLOSING')
  AND EXISTS(SELECT 1 FROM public.platform_configuration cfg WHERE cfg.singleton AND cfg.cluster_epoch=r.cluster_epoch)
  AND EXISTS(SELECT 1 FROM public.restore_launch_permits p WHERE p.tenant_id=r.tenant_id AND p.restore_id=r.id);
END $$;
REVOKE ALL ON FUNCTION sandbox_lock_restore_observation(uuid,uuid) FROM PUBLIC;

-- RESTORE scheduling never borrows an ordinary RUNNING permit or a historical
-- backup attempt. The fresh node grant is scoped to this isolated current job.
CREATE FUNCTION sandbox_restore_node_binding(tenant uuid,restore uuid,node_uid uuid,node_name text,boot uuid,profile text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT public.sandbox_lock_restore_admission(tenant,restore) THEN RETURN false;END IF;
 -- Inventory revocation must not race a successful binding decision. A wait
 -- on this exact node row is followed by fresh authority/deadline checks.
 PERFORM n.id FROM public.runtime_nodes n JOIN public.restores r ON r.cluster_epoch=n.cluster_epoch
  WHERE r.tenant_id=tenant AND r.id=restore AND n.node_uid=sandbox_restore_node_binding.node_uid
   AND n.node_name=sandbox_restore_node_binding.node_name AND n.boot_id=boot AND n.profile_sha256=profile FOR SHARE OF n;
 IF NOT FOUND THEN RETURN false;END IF;
 RETURN EXISTS(SELECT 1 FROM public.restores r JOIN public.restore_job_contexts c ON c.tenant_id=r.tenant_id AND c.restore_id=r.id
  JOIN public.restore_pod_admissions admitted ON admitted.tenant_id=r.tenant_id AND admitted.restore_id=r.id
  JOIN public.restore_resource_intents i ON i.tenant_id=r.tenant_id AND i.restore_id=r.id AND i.kind='JOB'
  JOIN public.restore_resource_bindings b ON b.tenant_id=i.tenant_id AND b.intent_id=i.id AND b.uid=admitted.job_uid
  JOIN public.runtime_nodes n ON n.cluster_epoch=r.cluster_epoch
  WHERE r.tenant_id=tenant AND r.id=restore AND c.context->>'stage'='RESTORE' AND c.context->>'attempt_id'=r.id::text
   AND c.deadline>clock_timestamp() AND n.node_uid=sandbox_restore_node_binding.node_uid AND n.node_name=sandbox_restore_node_binding.node_name
   AND n.boot_id=boot AND n.profile_sha256=profile AND n.enabled AND public.sandbox_node_certified_until(n.id)>=c.deadline)
  AND public.sandbox_restore_authorized(tenant,restore,true);
END $$;
REVOKE ALL ON FUNCTION sandbox_restore_node_binding(uuid,uuid,uuid,text,uuid,text) FROM PUBLIC;
-- Historical observations only: a fixed isolated launch remains identifiable
-- after permission/profile expiry for trusted closure, never for a new start.
CREATE FUNCTION sandbox_restore_node_observation(tenant uuid,restore uuid,node_uid uuid,node_name text,boot uuid,profile text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT COALESCE($1=public.sandbox_current_tenant_id() AND EXISTS(
  SELECT 1 FROM public.restores r JOIN public.restore_launch_permits p ON p.tenant_id=r.tenant_id AND p.restore_id=r.id
   JOIN public.restore_block_receipts raw ON raw.tenant_id=r.tenant_id AND raw.restore_id=r.id
   JOIN public.restore_pod_admissions admitted ON admitted.tenant_id=r.tenant_id AND admitted.restore_id=r.id
   JOIN public.restore_resource_intents pod_intent ON pod_intent.tenant_id=r.tenant_id AND pod_intent.restore_id=r.id AND pod_intent.kind='POD'
   JOIN public.restore_resource_bindings pod ON pod.tenant_id=pod_intent.tenant_id AND pod.intent_id=pod_intent.id
   JOIN public.runtime_nodes n ON n.id=p.runtime_node_id CROSS JOIN public.platform_configuration cfg
  WHERE r.tenant_id=$1 AND r.id=$2 AND cfg.singleton AND r.cluster_epoch=cfg.cluster_epoch AND n.cluster_epoch=r.cluster_epoch
   AND r.status IN('RESTORE_PENDING','RESTORE_RUNNING','RESTORE_CLOSING')
   AND n.node_uid=$3 AND n.node_name=$4 AND n.boot_id=$5 AND n.profile_sha256=$6
   AND p.request->'launch'->'purpose'->>'kind'='BACKUP' AND p.request->'launch'->'purpose'->>'stage'='RESTORE'
   AND p.request->'launch'->'purpose'->>'attempt_id'=r.id::text AND p.request->'launch'->'purpose'->>'backup_id'=r.backup_id::text
   AND p.request->'launch'->'purpose'->>'job_uid'=admitted.job_uid::text
   AND p.request->'launch'->'purpose'->>'source_pvc_uid'=r.source_identity->>'source_pvc_uid'
   AND p.request->'launch'->>'pod_uid'=pod.uid::text AND p.request->'launch'->>'pod_name'=pod_intent.name
   AND p.request->'launch'->>'namespace'=pod_intent.namespace AND pod_intent.namespace='sandbox-system'
   AND p.request->'launch'->>'launch_id'=r.id::text AND p.request->'launch'->>'generation'='1'
   AND p.request->'launch'->>'tenant_id'=r.tenant_id::text AND p.request->'launch'->>'project_id'=r.target_project_id::text
   AND p.request->'launch'->>'workspace_id'=r.workspace_id::text AND p.request->'launch'->>'instance_id'=r.instance_id::text
   AND p.request->'launch'->>'pvc_uid'=raw.pvc_uid::text AND p.request->'launch'->>'pv_uid'=raw.pv_uid::text
   AND p.request->'launch'->>'csi_volume_handle'=raw.cloud_disk
   AND p.request->'node'->>'node_uid'=n.node_uid::text AND p.request->'node'->>'node_name'=n.node_name
   AND p.request->'node'->>'boot_id'=n.boot_id::text AND p.request->'node'->>'profile_sha256'=n.profile_sha256
   AND p.request->'node'->>'cluster_epoch'=r.cluster_epoch::text
 ),false);
$$;
REVOKE ALL ON FUNCTION sandbox_restore_node_observation(uuid,uuid,uuid,text,uuid,text) FROM PUBLIC;

CREATE FUNCTION sandbox_guard_restore_hold_release() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE h public.workspace_holds;r public.restores;BEGIN
 SELECT * INTO h FROM public.workspace_holds WHERE tenant_id=NEW.tenant_id AND id=NEW.hold_id;
 IF h.kind<>'RESTORE' THEN RETURN NEW;END IF;
 SELECT * INTO r FROM public.restores WHERE tenant_id=NEW.tenant_id AND id=h.reference_id;
 IF r.id IS NULL OR r.hold_id<>h.id OR r.status NOT IN('AVAILABLE','CANCELLED')
  OR EXISTS(SELECT 1 FROM public.restore_pod_admissions a WHERE a.tenant_id=r.tenant_id AND a.restore_id=r.id AND NOT EXISTS(SELECT 1 FROM public.restore_termination_proofs p JOIN public.restore_cleanup_receipts c ON c.tenant_id=p.tenant_id AND c.proof_id=p.id WHERE p.tenant_id=a.tenant_id AND p.restore_id=a.restore_id))
  OR EXISTS(SELECT 1 FROM public.restore_launch_permits p WHERE p.tenant_id=r.tenant_id AND p.restore_id=r.id AND NOT EXISTS(SELECT 1 FROM public.restore_termination_proofs proof JOIN public.restore_cleanup_receipts c ON c.tenant_id=proof.tenant_id AND c.proof_id=proof.id WHERE proof.tenant_id=p.tenant_id AND proof.permit_id=p.id)) THEN
  RAISE EXCEPTION 'restore hold requires all isolated writer closures and completed delivery or cancellation' USING ERRCODE='23514';END IF;
 RETURN NEW;END $$;
CREATE TRIGGER restore_hold_release_guard BEFORE INSERT ON workspace_hold_releases FOR EACH ROW EXECUTE FUNCTION sandbox_guard_restore_hold_release();
REVOKE ALL ON FUNCTION sandbox_guard_restore_hold_release() FROM PUBLIC;

-- Dispatch and delegated-action extensions must be composed with the final
-- 0036 file-transfer migration, not replace that migration's role separation.

CREATE OR REPLACE FUNCTION sandbox_update_dispatch() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE target_queue text;
BEGIN
    target_queue:=CASE WHEN NEW.kind='FILE_TRANSFER' THEN 'FILE_TRANSFER' WHEN NEW.kind IN('BACKUP','RESTORE') THEN 'BACKUP' WHEN NEW.kind='DELETE_WORKSPACE' THEN 'VOLUME' WHEN NEW.kind='EXECUTE' THEN 'GATEWAY'
        WHEN NEW.kind IN('STOP','DELETE') OR (NEW.kind='RESTART' AND NEW.restart_generation IS NULL) THEN 'TERMINATION'
        ELSE 'WORKER' END;
    IF NEW.status IN('QUEUED','RUNNING','WAITING') THEN
        INSERT INTO public.operation_dispatch(operation_id,tenant_id,eligible_at,queue_role,launch_registration_eligible_at,workspace_delete_epoch,backup_epoch)
        VALUES(NEW.id,NEW.tenant_id,GREATEST(NEW.next_attempt_at,COALESCE(NEW.lease_until,NEW.next_attempt_at)),target_queue,NEW.launch_registration_next_attempt_at,(SELECT d.cluster_epoch FROM public.workspace_delete_intents d WHERE d.tenant_id=NEW.tenant_id AND d.operation_id=NEW.id),COALESCE((SELECT b.cluster_epoch FROM public.backups b WHERE b.tenant_id=NEW.tenant_id AND b.operation_id=NEW.id),(SELECT r.cluster_epoch FROM public.restores r WHERE r.tenant_id=NEW.tenant_id AND r.operation_id=NEW.id)))
        ON CONFLICT(operation_id) DO UPDATE SET eligible_at=EXCLUDED.eligible_at,queue_role=EXCLUDED.queue_role,launch_registration_eligible_at=EXCLUDED.launch_registration_eligible_at,workspace_delete_epoch=EXCLUDED.workspace_delete_epoch,backup_epoch=EXCLUDED.backup_epoch;
    ELSE DELETE FROM public.operation_dispatch WHERE operation_id=NEW.id;
    END IF;
    RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION sandbox_claim_routed_operation(worker_id text,requested_role text)
RETURNS TABLE(tenant_id uuid,operation_id uuid,lease_token bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;found_id uuid;previous_tenant text:=current_setting('app.tenant_id',true);
BEGIN
    IF worker_id IS NULL OR char_length(worker_id) NOT BETWEEN 1 AND 128 OR requested_role IS NULL OR requested_role NOT IN('WORKER','GATEWAY','TERMINATION','VOLUME','BACKUP','FILE_TRANSFER') THEN
        RAISE EXCEPTION 'invalid worker identity or queue role' USING ERRCODE='22023';END IF;
    FOR candidate IN SELECT d.operation_id,d.tenant_id FROM public.operation_dispatch d
      WHERE d.queue_role=requested_role AND (requested_role<>'VOLUME' OR d.workspace_delete_epoch=(SELECT cluster_epoch FROM public.platform_configuration WHERE singleton)) AND(requested_role<>'BACKUP' OR d.backup_epoch=(SELECT cluster_epoch FROM public.platform_configuration WHERE singleton)) AND d.eligible_at<=clock_timestamp() ORDER BY d.eligible_at,d.operation_id LIMIT 64 LOOP
        PERFORM set_config('app.tenant_id',candidate.tenant_id::text,true);
        SELECT o.id INTO found_id FROM public.operations o
        WHERE o.tenant_id=candidate.tenant_id AND o.id=candidate.operation_id
          AND CASE requested_role WHEN 'FILE_TRANSFER' THEN o.kind='FILE_TRANSFER' WHEN 'BACKUP' THEN o.kind IN('BACKUP','RESTORE') WHEN 'VOLUME' THEN o.kind='DELETE_WORKSPACE' WHEN 'GATEWAY' THEN o.kind='EXECUTE'
              WHEN 'TERMINATION' THEN o.kind IN('STOP','DELETE') OR (o.kind='RESTART' AND o.restart_generation IS NULL)
              ELSE o.kind NOT IN('EXECUTE','STOP','DELETE','DELETE_WORKSPACE','BACKUP','FILE_TRANSFER','RESTORE') AND (o.kind<>'RESTART' OR o.restart_generation IS NOT NULL) END
          AND o.status IN('QUEUED','RUNNING','WAITING') AND o.next_attempt_at<=clock_timestamp()
          AND (o.lease_until IS NULL OR o.lease_until<=clock_timestamp()) FOR UPDATE SKIP LOCKED;
        IF found_id IS NOT NULL THEN
            RETURN QUERY UPDATE public.operations o SET status='RUNNING',lease_owner=worker_id,lease_token=o.lease_token+1,
              lease_until=clock_timestamp()+interval '30 seconds',attempts=o.attempts+1,updated_at=clock_timestamp()
            WHERE o.id=found_id AND o.tenant_id=candidate.tenant_id RETURNING o.tenant_id,o.id,o.lease_token;
            PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);RETURN;
        END IF;
    END LOOP;
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
END $$;


-- Dedicated backup login can publish only this stopped, held recovery target.
-- It receives no general UPDATE privileges on compute instances/workspaces.
CREATE FUNCTION sandbox_publish_restore(requested_tenant uuid,restore uuid,lease bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r public.restores;d public.restore_delivery_receipts;item record;w public.workspaces;i public.instances;hold_id uuid;
BEGIN
 IF requested_tenant IS DISTINCT FROM public.sandbox_current_tenant_id() OR lease IS NULL OR lease<=0 THEN RETURN false;END IF;
 SELECT * INTO r FROM public.restores WHERE tenant_id=requested_tenant AND id=restore;
 IF NOT FOUND THEN RETURN false;END IF;
 SELECT * INTO w FROM public.workspaces WHERE tenant_id=r.tenant_id AND id=r.workspace_id FOR UPDATE;
 SELECT * INTO i FROM public.instances WHERE tenant_id=r.tenant_id AND id=r.instance_id FOR UPDATE;
 SELECT * INTO r FROM public.restores WHERE tenant_id=requested_tenant AND id=restore FOR UPDATE;
 PERFORM 1 FROM public.operations WHERE tenant_id=r.tenant_id AND id=r.operation_id AND lease_token=lease AND status='RUNNING' AND lease_until>clock_timestamp() FOR UPDATE;
 IF NOT FOUND OR r.status<>'DELIVERY_PENDING' OR NOT public.sandbox_restore_authorized(r.tenant_id,r.id,true)
  OR w.status<>'PENDING' OR w.restore_snapshot_name IS NOT NULL OR w.cloud_volume_id IS NOT NULL OR w.csi_volume_id IS NOT NULL
  OR w.active_operation_id<>r.operation_id OR i.active_operation_id<>r.operation_id OR i.desired_state<>'STOPPED' OR i.observed_state<>'STOPPED' OR i.pod_uid IS NOT NULL OR i.slot_held THEN RETURN false;END IF;
 SELECT * INTO d FROM public.restore_delivery_receipts WHERE tenant_id=r.tenant_id AND restore_id=r.id AND workspace_id=r.workspace_id;
 IF NOT FOUND OR d.namespace<>w.namespace OR d.snapshot_name<>'sbx-rs-'||r.id::text OR d.size_bytes<>r.size_gib*1073741824
  OR NOT EXISTS(SELECT 1 FROM public.restore_snapshot_receipts snap WHERE snap.tenant_id=r.tenant_id AND snap.restore_id=r.id AND snap.cloud_snapshot=d.cloud_snapshot AND snap.size_bytes=d.size_bytes)
  OR EXISTS(SELECT 1 FROM public.restore_block_receipts raw WHERE raw.tenant_id=r.tenant_id AND raw.restore_id=r.id AND(raw.pvc_uid=d.pvc_uid OR raw.pv_uid=d.pv_uid OR raw.cloud_disk=d.cloud_disk))
  OR EXISTS(SELECT 1 FROM public.backups b WHERE b.tenant_id=r.tenant_id AND b.id=r.backup_id AND (b.source->>'cloud_disk'=d.cloud_disk OR (b.source->>'pv_uid')::uuid=d.pv_uid))
  OR EXISTS(SELECT 1 FROM public.backup_clone_receipts clone WHERE clone.tenant_id=r.tenant_id AND clone.backup_id=r.backup_id AND(clone.cloud_disk=d.cloud_disk OR clone.pv_uid=d.pv_uid))
  OR NOT EXISTS(SELECT 1 FROM public.restore_artifact_cleanup_receipts cleanup
   JOIN public.restore_resource_intents job ON job.tenant_id=cleanup.tenant_id AND job.restore_id=cleanup.restore_id AND job.kind='JOB'
   JOIN public.restore_resource_bindings jb ON jb.tenant_id=job.tenant_id AND jb.intent_id=job.id AND jb.uid=cleanup.job_uid
   JOIN public.restore_resource_intents config ON config.tenant_id=cleanup.tenant_id AND config.restore_id=cleanup.restore_id AND config.kind='CONFIG'
   JOIN public.restore_resource_bindings cb ON cb.tenant_id=config.tenant_id AND cb.intent_id=config.id AND cb.uid=cleanup.config_uid
   WHERE cleanup.tenant_id=r.tenant_id AND cleanup.restore_id=r.id AND cleanup.observed_at>=clock_timestamp()-interval '30 seconds' AND cleanup.observed_at<=clock_timestamp()+interval '2 seconds') THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM(VALUES('WORKSPACE_PVC',d.pvc_uid),('WORKSPACE_PV',d.pv_uid),('DELIVERY_SNAPSHOT',d.snapshot_uid),('DELIVERY_CONTENT',d.content_uid)) wanted(kind,uid)
  WHERE NOT EXISTS(SELECT 1 FROM public.restore_resource_intents intent JOIN public.restore_resource_bindings binding ON binding.tenant_id=intent.tenant_id AND binding.intent_id=intent.id WHERE intent.tenant_id=r.tenant_id AND intent.restore_id=r.id AND intent.kind=wanted.kind AND binding.uid=wanted.uid)) THEN RETURN false;END IF;
 IF (SELECT count(*) FROM public.quota_reservations qr JOIN public.quota_accounts qa ON qa.tenant_id=qr.tenant_id AND qa.id=qr.quota_account_id
  WHERE qr.tenant_id=r.tenant_id AND qr.operation_id=r.operation_id AND qr.status='PENDING'
   AND ((qa.dimension='INSTANCES' AND qr.amount=1) OR(qa.dimension='WORKSPACE_GIB' AND qr.amount=r.size_gib)
    OR(qa.dimension='BACKUP_TEMP_GIB' AND qr.amount=r.size_gib*2) OR(qa.dimension='CPU_MILLIS' AND qr.amount=2000) OR(qa.dimension='MEMORY_MIB' AND qr.amount=2048)))<>10 THEN RETURN false;END IF;
 FOR item IN SELECT qr.id,qr.quota_account_id,qr.amount,qa.dimension FROM public.quota_reservations qr JOIN public.quota_accounts qa ON qa.tenant_id=qr.tenant_id AND qa.id=qr.quota_account_id WHERE qr.tenant_id=r.tenant_id AND qr.operation_id=r.operation_id AND qr.status='PENDING' ORDER BY qr.quota_account_id,qr.id FOR UPDATE OF qr,qa LOOP
  IF item.dimension IN('CPU_MILLIS','MEMORY_MIB') THEN
   UPDATE public.quota_accounts SET pending=pending-item.amount,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=r.tenant_id AND id=item.quota_account_id;
   UPDATE public.quota_reservations SET status='RELEASED',released_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=r.tenant_id AND id=item.id;
  ELSE
   UPDATE public.quota_accounts SET pending=pending-item.amount,allocated=allocated+item.amount,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=r.tenant_id AND id=item.quota_account_id;
   UPDATE public.quota_reservations SET status='ALLOCATED',updated_at=clock_timestamp() WHERE tenant_id=r.tenant_id AND id=item.id;
  END IF;
 END LOOP;
 UPDATE public.restores SET status='AVAILABLE',version=version+1,updated_at=clock_timestamp() WHERE tenant_id=r.tenant_id AND id=r.id;
 UPDATE public.workspaces SET status='AVAILABLE',active_operation_id=NULL,cloud_volume_id=d.cloud_disk,csi_volume_id=d.cloud_disk,restore_snapshot_name=d.snapshot_name,spec_version=spec_version+1,updated_at=clock_timestamp() WHERE tenant_id=r.tenant_id AND id=r.workspace_id;
 UPDATE public.instances SET active_operation_id=NULL,spec_version=spec_version+1,updated_at=clock_timestamp() WHERE tenant_id=r.tenant_id AND id=r.instance_id;
 INSERT INTO public.external_resources(tenant_id,project_id,operation_id,instance_id,workspace_id,provider,kind,provider_id,generation,owner_id,status,observed_at) VALUES(r.tenant_id,r.target_project_id,r.operation_id,r.instance_id,r.workspace_id,'kubernetes','PVC',d.pvc_uid::text,1,r.workspace_id,'ACTIVE',clock_timestamp());
 INSERT INTO public.workspace_hold_releases(hold_id,tenant_id,reason) SELECT rr.hold_id,rr.tenant_id,'Independent filesystem delivered; writer/control objects absent; retained raw disk and snapshot remain accounted' FROM public.restores rr WHERE rr.tenant_id=r.tenant_id AND rr.id=r.id;
 UPDATE public.operations SET status='SUCCEEDED',stage='RESTORE_AVAILABLE_STOPPED',lease_owner=NULL,lease_until=NULL,wait_reason=NULL,error=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=r.tenant_id AND id=r.operation_id;
 INSERT INTO public.audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details)
 SELECT r.tenant_id,r.target_project_id,o.actor_principal_id,o.request_id,o.id,r.id,'backups:restore:publish','SUCCEEDED',jsonb_build_object('instance_state','STOPPED','retained_raw_disk_and_snapshot_accounted',true,'raw_storage_gib',r.size_gib*2,'source_backup_id',r.backup_id) FROM public.operations o WHERE o.tenant_id=r.tenant_id AND o.id=r.operation_id;
 INSERT INTO public.domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload)
 SELECT r.tenant_id,r.target_project_id,r.id,r.version+1,'restore.available',o.id,o.request_id,jsonb_build_object('instance_id',r.instance_id,'workspace_id',r.workspace_id,'state','STOPPED','retained_raw_storage_gib',r.size_gib*2) FROM public.operations o WHERE o.tenant_id=r.tenant_id AND o.id=r.operation_id;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION sandbox_publish_restore(uuid,uuid,bigint) FROM PUBLIC;

-- The first ordinary START has no prior ordinary launch permit. Its binding
-- must still use the private delivery receipt, never adopt a replaced same-name
-- PVC/PV/disk. API resourceVersion is deliberately not a durable identity.
CREATE FUNCTION sandbox_guard_restored_launch() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r public.restores;d public.restore_delivery_receipts;
BEGIN
 SELECT * INTO r FROM public.restores WHERE tenant_id=NEW.tenant_id AND workspace_id=NEW.workspace_id;
 IF NOT FOUND THEN RETURN NEW;END IF;
 SELECT * INTO d FROM public.restore_delivery_receipts WHERE tenant_id=r.tenant_id AND restore_id=r.id;
 IF r.status<>'AVAILABLE' OR d.restore_id IS NULL OR NEW.project_id<>r.target_project_id OR NEW.instance_id<>r.instance_id
  OR NEW.pvc_uid<>d.pvc_uid OR NEW.pv_uid<>d.pv_uid OR NEW.pv_name<>d.pv_name OR NEW.csi_volume_handle<>d.cloud_disk
  OR NEW.namespace<>d.namespace OR NEW.cluster_epoch<>r.cluster_epoch OR NEW.cluster_epoch<>(SELECT cluster_epoch FROM public.platform_configuration WHERE singleton)
  OR NOT EXISTS(SELECT 1 FROM public.workspaces w WHERE w.tenant_id=r.tenant_id AND w.id=r.workspace_id AND w.restore_snapshot_name=d.snapshot_name AND w.csi_volume_id=d.cloud_disk AND w.storage_class=r.storage_contract->'mapping'->'delivery'->>'name')
  OR NOT EXISTS(SELECT 1 FROM public.instances i JOIN public.template_versions tv ON tv.tenant_id=i.tenant_id AND tv.id=i.template_version_id JOIN public.security_policy_versions sp ON sp.tenant_id=i.tenant_id AND sp.id=i.security_policy_version_id WHERE i.tenant_id=r.tenant_id AND i.id=r.instance_id AND tv.status='APPROVED' AND sp.status='APPROVED') THEN
  RAISE EXCEPTION 'restored workspace launch requires current approval and exact immutable filesystem delivery identity' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER restored_launch_binding_guard BEFORE INSERT ON launch_permits FOR EACH ROW EXECUTE FUNCTION sandbox_guard_restored_launch();
REVOKE ALL ON FUNCTION sandbox_guard_restored_launch() FROM PUBLIC;
CREATE FUNCTION sandbox_guard_restore_datasource() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.storage_class IS DISTINCT FROM OLD.storage_class AND EXISTS(SELECT 1 FROM public.restores r WHERE r.tenant_id=NEW.tenant_id AND r.workspace_id=NEW.id) THEN
  RAISE EXCEPTION 'restored workspace storage purpose is immutable' USING ERRCODE='23514';END IF;
 IF OLD.restore_snapshot_name IS NOT NULL AND NEW.restore_snapshot_name IS DISTINCT FROM OLD.restore_snapshot_name THEN
  RAISE EXCEPTION 'restored workspace datasource lineage is immutable' USING ERRCODE='23514';END IF;
 IF NEW.restore_snapshot_name IS NOT NULL AND NOT EXISTS(SELECT 1 FROM public.restore_delivery_receipts d JOIN public.restores r ON r.tenant_id=d.tenant_id AND r.id=d.restore_id WHERE d.tenant_id=NEW.tenant_id AND d.workspace_id=NEW.id AND d.snapshot_name=NEW.restore_snapshot_name AND r.status='AVAILABLE' AND d.cloud_disk=NEW.csi_volume_id AND NEW.storage_class=r.storage_contract->'mapping'->'delivery'->>'name' AND public.sandbox_restore_storage_contract_certified(r.profile_id,r.cluster_epoch,r.storage_contract) IS TRUE) THEN
  RAISE EXCEPTION 'restored datasource requires independently delivered filesystem volume' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER restore_datasource_guard BEFORE UPDATE ON workspaces FOR EACH ROW EXECUTE FUNCTION sandbox_guard_restore_datasource();
REVOKE ALL ON FUNCTION sandbox_guard_restore_datasource() FROM PUBLIC;

-- Ordinary consumers can inspect only the immutable delivery/provenance tuple;
-- callers retain their normal runtime permissions, leases and live Kube checks.
CREATE FUNCTION sandbox_workspace_restore_binding(requested_tenant uuid,workspace uuid)
RETURNS TABLE(restore_id uuid,tenant_id uuid,project_id uuid,instance_id uuid,workspace_id uuid,cluster_epoch uuid,namespace text,snapshot_name text,pvc_uid uuid,pv_uid uuid,pv_name text,cloud_disk text,size_bytes bigint,delivery_storage_class text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r public.restores;w public.workspaces;d public.restore_delivery_receipts;
BEGIN
 IF requested_tenant IS DISTINCT FROM public.sandbox_current_tenant_id() THEN RAISE EXCEPTION 'restore provenance tenant mismatch' USING ERRCODE='42501';END IF;
 SELECT * INTO w FROM public.workspaces ws WHERE ws.tenant_id=requested_tenant AND ws.id=workspace;
 IF NOT FOUND THEN RAISE EXCEPTION 'restore provenance workspace missing' USING ERRCODE='42501';END IF;
 SELECT * INTO r FROM public.restores rr WHERE rr.tenant_id=requested_tenant AND rr.workspace_id=workspace;
 IF NOT FOUND THEN
  IF w.restore_snapshot_name IS NOT NULL THEN RAISE EXCEPTION 'restore provenance marked workspace missing immutable source' USING ERRCODE='42501';END IF;
  RETURN;
 END IF;
 SELECT * INTO d FROM public.restore_delivery_receipts delivery WHERE delivery.tenant_id=r.tenant_id AND delivery.restore_id=r.id AND delivery.workspace_id=r.workspace_id;
 IF r.status<>'AVAILABLE' OR d.restore_id IS NULL OR w.restore_snapshot_name IS DISTINCT FROM d.snapshot_name OR w.csi_volume_id IS DISTINCT FROM d.cloud_disk
  OR w.project_id<>r.target_project_id OR d.namespace<>w.namespace OR d.size_bytes<>w.size_gib*1073741824
  OR public.sandbox_restore_storage_contract_certified(r.profile_id,r.cluster_epoch,r.storage_contract) IS NOT TRUE
  OR w.storage_class IS DISTINCT FROM r.storage_contract->'mapping'->'delivery'->>'name'
  OR NOT EXISTS(SELECT 1 FROM public.restore_termination_proofs proof JOIN public.restore_cleanup_receipts cleanup ON cleanup.tenant_id=proof.tenant_id AND cleanup.proof_id=proof.id WHERE proof.tenant_id=r.tenant_id AND proof.restore_id=r.id)
  OR NOT EXISTS(SELECT 1 FROM public.restore_artifact_cleanup_receipts cleanup WHERE cleanup.tenant_id=r.tenant_id AND cleanup.restore_id=r.id)
  OR NOT EXISTS(SELECT 1 FROM public.external_resources resource WHERE resource.tenant_id=r.tenant_id AND resource.workspace_id=r.workspace_id AND resource.instance_id=r.instance_id AND resource.provider='kubernetes' AND resource.kind='PVC' AND resource.generation=1 AND resource.owner_id=r.workspace_id AND resource.provider_id=d.pvc_uid::text) THEN
  RAISE EXCEPTION 'restore provenance missing exact independently published filesystem identity' USING ERRCODE='42501';END IF;
 RETURN QUERY SELECT r.id,r.tenant_id,r.target_project_id,r.instance_id,r.workspace_id,r.cluster_epoch,d.namespace,d.snapshot_name,d.pvc_uid,d.pv_uid,d.pv_name,d.cloud_disk,d.size_bytes,r.storage_contract->'mapping'->'delivery'->>'name';
END $$;
REVOKE ALL ON FUNCTION sandbox_workspace_restore_binding(uuid,uuid) FROM PUBLIC;

-- Admission rechecks immutable provenance and ordinary compute authority under
-- the same workspace -> instance -> operation fence after live Kube reads.
-- This function only locks already scoped rows; it cannot mutate state.

CREATE FUNCTION sandbox_lock_restored_runtime(requested_tenant uuid,instance uuid,workspace uuid)
RETURNS TABLE(restore_id uuid,tenant_id uuid,project_id uuid,instance_id uuid,workspace_id uuid,cluster_epoch uuid,namespace text,snapshot_name text,pvc_uid uuid,pv_uid uuid,pv_name text,cloud_disk text,size_bytes bigint,delivery_storage_class text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE operation uuid;
BEGIN
 IF requested_tenant IS DISTINCT FROM public.sandbox_current_tenant_id() THEN RAISE EXCEPTION 'restore admission tenant mismatch' USING ERRCODE='42501';END IF;
 PERFORM 1 FROM public.workspaces w WHERE w.tenant_id=requested_tenant AND w.id=workspace FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'restore admission workspace missing' USING ERRCODE='42501';END IF;
 SELECT i.active_operation_id INTO operation FROM public.instances i WHERE i.tenant_id=requested_tenant AND i.id=instance AND i.workspace_id=workspace FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'restore admission instance mismatch' USING ERRCODE='42501';END IF;
 IF operation IS NOT NULL THEN PERFORM 1 FROM public.operations o WHERE o.tenant_id=requested_tenant AND o.id=operation FOR UPDATE;END IF;
 RETURN QUERY SELECT * FROM public.sandbox_workspace_restore_binding(requested_tenant,workspace);
END $$;
REVOKE ALL ON FUNCTION sandbox_lock_restored_runtime(uuid,uuid,uuid) FROM PUBLIC;

-- A STOPPED restore target is born under the ordinary enforced launch protocol,
-- so a never-started DELETE has permanent positive provenance, not a missing Pod.
CREATE FUNCTION sandbox_restore_birth_guard(requested_tenant uuid,instance uuid,workspace uuid,epoch uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT COALESCE($1=public.sandbox_current_tenant_id() AND EXISTS(
 SELECT 1 FROM public.instances i JOIN public.launch_authority_births b ON b.tenant_id=i.tenant_id AND b.instance_id=i.id AND b.workspace_id=i.workspace_id AND b.generation=i.runtime_generation AND b.launch_id=i.launch_id AND b.cluster_epoch=i.cluster_epoch
 JOIN public.launch_guard_contracts c ON c.id=b.contract_id
 WHERE i.tenant_id=$1 AND i.id=$2 AND i.workspace_id=$3 AND i.cluster_epoch=$4 AND i.runtime_generation=1
 AND i.desired_state='STOPPED' AND i.observed_state='STOPPED' AND i.pod_uid IS NULL AND NOT i.slot_held
 AND b.project_id=i.project_id AND b.namespace=i.namespace AND b.pod_name=i.pod_name
 AND c.cluster_epoch=$4 AND b.born_at>=c.activated_at AND b.born_at<c.valid_until AND c.valid_until>clock_timestamp()
 AND NOT EXISTS(SELECT 1 FROM public.launch_guard_contract_revocations r WHERE r.contract_id=c.id)
 AND NOT EXISTS(SELECT 1 FROM public.launch_permits p WHERE p.tenant_id=i.tenant_id AND p.instance_id=i.id)),false);
$$;
REVOKE ALL ON FUNCTION sandbox_restore_birth_guard(uuid,uuid,uuid,uuid) FROM PUBLIC;

-- Positive ordinary never-started closure for an independently delivered
-- restore. Any ordinary start/permit/runner history excludes this branch.
CREATE FUNCTION sandbox_restored_never_started(tenant uuid,instance uuid,workspace uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT COALESCE($1=public.sandbox_current_tenant_id() AND EXISTS(
 SELECT 1 FROM public.restores r JOIN public.instances i ON i.tenant_id=r.tenant_id AND i.id=r.instance_id AND i.workspace_id=r.workspace_id
 JOIN public.restore_delivery_receipts d ON d.tenant_id=r.tenant_id AND d.restore_id=r.id
 JOIN public.workspaces w ON w.tenant_id=r.tenant_id AND w.id=r.workspace_id
 JOIN public.never_authorized_closures c ON c.tenant_id=i.tenant_id AND c.instance_id=i.id AND c.workspace_id=i.workspace_id AND c.generation=i.runtime_generation AND c.launch_id=i.launch_id AND c.cluster_epoch=i.cluster_epoch
 WHERE r.tenant_id=$1 AND i.id=$2 AND w.id=$3 AND r.status='AVAILABLE' AND i.runtime_generation=1 AND i.pod_uid IS NULL
 AND i.desired_state='DELETED' AND NOT i.slot_held AND i.cluster_epoch=r.cluster_epoch
 AND r.cluster_epoch=(SELECT cluster_epoch FROM public.platform_configuration WHERE singleton)
 AND w.restore_snapshot_name=d.snapshot_name AND w.csi_volume_id=d.cloud_disk
 AND public.sandbox_never_authorized(i.tenant_id,i.id,i.workspace_id,i.runtime_generation,i.launch_id,i.cluster_epoch,c.id)
 AND NOT EXISTS(SELECT 1 FROM public.launch_permits p WHERE p.tenant_id=r.tenant_id AND p.workspace_id=r.workspace_id)
 AND NOT EXISTS(SELECT 1 FROM public.operations o WHERE o.tenant_id=r.tenant_id AND o.instance_id=r.instance_id AND o.kind IN('CREATE','START','RESTART'))
 AND NOT EXISTS(SELECT 1 FROM public.executions e WHERE e.tenant_id=r.tenant_id AND e.instance_id=r.instance_id)
 AND NOT EXISTS(SELECT 1 FROM public.file_transfers f WHERE f.tenant_id=r.tenant_id AND f.instance_id=r.instance_id)
 AND NOT EXISTS(SELECT 1 FROM public.restore_launch_permits p WHERE p.tenant_id=r.tenant_id AND p.restore_id=r.id AND NOT EXISTS(
 SELECT 1 FROM public.restore_termination_proofs proof JOIN public.restore_cleanup_receipts clean ON clean.tenant_id=proof.tenant_id AND clean.proof_id=proof.id WHERE proof.tenant_id=p.tenant_id AND proof.permit_id=p.id AND proof.restore_id=p.restore_id))
 AND EXISTS(SELECT 1 FROM public.restore_termination_proofs proof JOIN public.restore_cleanup_receipts clean ON clean.tenant_id=proof.tenant_id AND clean.proof_id=proof.id WHERE proof.tenant_id=r.tenant_id AND proof.restore_id=r.id)
 AND EXISTS(SELECT 1 FROM public.restore_artifact_cleanup_receipts clean WHERE clean.tenant_id=r.tenant_id AND clean.restore_id=r.id)),false);
$$;
REVOKE ALL ON FUNCTION sandbox_restored_never_started(uuid,uuid,uuid) FROM PUBLIC;

CREATE FUNCTION sandbox_workspace_ordinary_writers_closed(requested_tenant uuid,workspace uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT COALESCE(requested_tenant=public.sandbox_current_tenant_id() AND
  EXISTS(SELECT 1 FROM public.instances i WHERE i.tenant_id=requested_tenant AND i.workspace_id=workspace AND i.observed_state='DELETED')
  AND NOT EXISTS(SELECT 1 FROM public.instances i WHERE i.tenant_id=requested_tenant AND i.workspace_id=workspace AND (i.observed_state<>'DELETED' OR i.slot_held OR i.active_operation_id IS NOT NULL))
  AND NOT EXISTS(SELECT 1 FROM public.instances i WHERE i.tenant_id=requested_tenant AND i.workspace_id=workspace AND (i.cluster_epoch<>(SELECT cluster_epoch FROM public.platform_configuration WHERE singleton) OR NOT EXISTS(SELECT 1 FROM public.local_termination_proofs proof JOIN public.termination_cleanup_receipts c ON c.tenant_id=proof.tenant_id AND c.proof_id=proof.id WHERE proof.tenant_id=i.tenant_id AND proof.id=i.last_termination_proof_id AND proof.instance_id=i.id AND proof.workspace_id=i.workspace_id AND proof.generation=i.runtime_generation AND proof.launch_id=i.launch_id AND proof.pod_uid=i.pod_uid AND proof.cluster_epoch=i.cluster_epoch)))
  AND NOT EXISTS(SELECT 1 FROM public.executions e JOIN public.instances i ON i.tenant_id=e.tenant_id AND i.id=e.instance_id WHERE i.tenant_id=requested_tenant AND i.workspace_id=workspace AND e.slot_held)
  AND NOT EXISTS(SELECT 1 FROM public.launch_permits p WHERE p.tenant_id=requested_tenant AND p.workspace_id=workspace
    AND NOT EXISTS(SELECT 1 FROM public.local_termination_proofs proof JOIN public.termination_cleanup_receipts c ON c.tenant_id=proof.tenant_id AND c.proof_id=proof.id
       WHERE proof.tenant_id=p.tenant_id AND proof.permit_id=p.id AND proof.instance_id=p.instance_id AND proof.workspace_id=p.workspace_id
        AND proof.generation=p.generation AND proof.launch_id=p.launch_id AND proof.pod_uid=p.pod_uid AND proof.cluster_epoch=p.cluster_epoch AND c.old_pod_uid=p.pod_uid))
  AND NOT EXISTS(SELECT 1 FROM public.workspace_holds h WHERE h.tenant_id=requested_tenant AND h.workspace_id=workspace
    AND NOT EXISTS(SELECT 1 FROM public.workspace_hold_releases r WHERE r.tenant_id=h.tenant_id AND r.hold_id=h.id)),false);
$$;
REVOKE ALL ON FUNCTION sandbox_workspace_ordinary_writers_closed(uuid,uuid) FROM PUBLIC;
CREATE OR REPLACE FUNCTION sandbox_workspace_writers_closed(requested_tenant uuid,workspace uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT public.sandbox_workspace_ordinary_writers_closed($1,$2) OR COALESCE($1=public.sandbox_current_tenant_id() AND
 EXISTS(SELECT 1 FROM public.instances i WHERE i.tenant_id=$1 AND i.workspace_id=$2 AND i.observed_state='DELETED' AND i.desired_state='DELETED' AND i.active_operation_id IS NULL AND public.sandbox_restored_never_started($1,i.id,$2))
 AND NOT EXISTS(SELECT 1 FROM public.instances i WHERE i.tenant_id=$1 AND i.workspace_id=$2 AND (i.observed_state<>'DELETED' OR i.desired_state<>'DELETED' OR i.active_operation_id IS NOT NULL OR i.slot_held))
 AND NOT EXISTS(SELECT 1 FROM public.workspace_holds h WHERE h.tenant_id=$1 AND h.workspace_id=$2 AND NOT EXISTS(SELECT 1 FROM public.workspace_hold_releases r WHERE r.tenant_id=h.tenant_id AND r.hold_id=h.id)),false);
$$;

-- Workspace destruction accepts exactly one independently fixed provenance:
-- the existing ordinary permit/proof, or the delivered never-started restore.
ALTER TABLE restore_delivery_receipts ADD CONSTRAINT restore_delivery_delete_identity UNIQUE(tenant_id,workspace_id,restore_id);
ALTER TABLE workspace_delete_bindings ALTER COLUMN permit_id DROP NOT NULL,
 ADD COLUMN restore_id uuid,
 ADD CONSTRAINT workspace_delete_provenance_one CHECK(num_nonnulls(permit_id,restore_id)=1),
 ADD CONSTRAINT workspace_delete_restore_provenance FOREIGN KEY(tenant_id,workspace_id,restore_id) REFERENCES restore_delivery_receipts(tenant_id,workspace_id,restore_id);
CREATE FUNCTION sandbox_guard_restore_workspace_delete_binding() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.restore_id IS NOT NULL AND (NEW.permit_id IS NOT NULL OR NOT EXISTS(
 SELECT 1 FROM public.restores r JOIN public.restore_delivery_receipts d ON d.tenant_id=r.tenant_id AND d.restore_id=r.id
 JOIN public.workspaces w ON w.tenant_id=r.tenant_id AND w.id=r.workspace_id
 JOIN public.instances i ON i.tenant_id=r.tenant_id AND i.id=r.instance_id
 WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.restore_id AND r.workspace_id=NEW.workspace_id AND r.status='AVAILABLE'
 AND w.active_operation_id=NEW.operation_id AND w.status='DELETING' AND i.observed_state='DELETED'
 AND(d.pvc_uid,d.pv_uid,d.pv_name,d.cloud_disk)=(NEW.pvc_uid,NEW.pv_uid,NEW.pv_name,NEW.csi_volume_handle)
 AND public.sandbox_restored_never_started(r.tenant_id,i.id,w.id)
 AND public.sandbox_workspace_writers_closed(r.tenant_id,w.id))) THEN
 RAISE EXCEPTION 'restore workspace delete requires exact delivery and permanent no ordinary writer closure' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER restore_workspace_delete_binding BEFORE INSERT ON workspace_delete_bindings FOR EACH ROW EXECUTE FUNCTION sandbox_guard_restore_workspace_delete_binding();
REVOKE ALL ON FUNCTION sandbox_guard_restore_workspace_delete_binding() FROM PUBLIC;
CREATE FUNCTION sandbox_restored_workspace_delete_binding(requested_tenant uuid,operation uuid)
RETURNS TABLE(tenant_id uuid,project_id uuid,workspace_id uuid,cluster_epoch uuid,namespace text,pvc_name text,storage_class text,size_gib bigint,permit_id uuid,restore_id uuid,pvc_uid uuid,pv_uid uuid,pv_name text,handle text,account_id text,region text,actor_principal_id uuid,request_id uuid,spec_version bigint,cloud_identity jsonb,has_absence boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT w.tenant_id,w.project_id,w.id,intent.cluster_epoch,w.namespace,w.pvc_name,w.storage_class,w.size_gib,NULL::uuid,r.id,d.pvc_uid,d.pv_uid,d.pv_name,d.cloud_disk,r.source_identity->>'account_id',r.source_identity->>'region',o.actor_principal_id,o.request_id,w.spec_version,b.cloud_identity,
 EXISTS(SELECT 1 FROM public.workspace_disk_absences a WHERE a.tenant_id=w.tenant_id AND a.operation_id=o.id)
 FROM public.workspaces w JOIN public.workspace_delete_intents intent ON intent.tenant_id=w.tenant_id AND intent.workspace_id=w.id
 JOIN public.operations o ON o.tenant_id=intent.tenant_id AND o.id=intent.operation_id
 JOIN public.restores r ON r.tenant_id=w.tenant_id AND r.workspace_id=w.id
 JOIN public.restore_delivery_receipts d ON d.tenant_id=r.tenant_id AND d.restore_id=r.id
 JOIN public.instances i ON i.tenant_id=r.tenant_id AND i.id=r.instance_id
 CROSS JOIN public.platform_configuration cfg
 LEFT JOIN public.workspace_delete_bindings b ON b.tenant_id=w.tenant_id AND b.operation_id=o.id
 WHERE $1=public.sandbox_current_tenant_id() AND w.tenant_id=$1 AND o.id=$2 AND o.kind='DELETE_WORKSPACE'
 AND w.status='DELETING' AND w.active_operation_id=o.id AND i.observed_state='DELETED' AND cfg.singleton AND cfg.cluster_epoch=intent.cluster_epoch
 AND r.cluster_epoch=intent.cluster_epoch AND r.status='AVAILABLE' AND w.csi_volume_id=d.cloud_disk AND w.restore_snapshot_name=d.snapshot_name
 AND(w.retention_until IS NULL OR w.retention_until<=clock_timestamp())
 AND public.sandbox_restored_never_started(w.tenant_id,i.id,w.id) AND public.sandbox_workspace_writers_closed(w.tenant_id,w.id);
$$;
REVOKE ALL ON FUNCTION sandbox_restored_workspace_delete_binding(uuid,uuid) FROM PUBLIC;


-- Preserve mature delegation/tenant serialization; permit only two new actions.
CREATE OR REPLACE FUNCTION sandbox_mutate_project_grant(actor uuid,project uuid,mutation text,grant_id uuid,target_principal uuid,delegated_action text,requested_expiry timestamptz,will_enable boolean,expected_version bigint)
RETURNS public.grants LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=public.sandbox_current_tenant_id();result public.grants;
BEGIN
    PERFORM public.sandbox_lock_identity_tenant(tenant);
    IF delegated_action IS NULL OR delegated_action NOT IN('instances:create','instances:read','instances:start','instances:stop','instances:restart','instances:renew','instances:delete','instances:hard_stop','workspaces:read','workspaces:delete','operations:read','events:read','audit:read','capabilities:read','executions:create','executions:read','executions:cancel','executions:output:read','grants:read','grants:write','backups:create','backups:read','diagnoses:create','diagnoses:read','files:read','files:write','backups:restore','restores:read') THEN
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
