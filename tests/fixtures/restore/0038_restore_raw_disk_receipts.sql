-- PRIVATE DRAFT ONLY, after base 0038/node topology/raw scheduling fixtures.
-- No normal writer, production route, cloud proof constructor or role activation.
-- This parser validates shape only. A future writer MUST accept sealed signed
-- DescribeDisks observations and execute normal binding+both receipts atomically.
CREATE FUNCTION sandbox_restore_raw_disk_payload_valid(identity_json jsonb,evidence_json jsonb) RETURNS boolean
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $$
DECLARE binding_json jsonb;field_name text;size_text text;
BEGIN
 IF identity_json IS NULL OR jsonb_typeof(identity_json) IS DISTINCT FROM 'object'
  OR evidence_json IS NULL OR jsonb_typeof(evidence_json) IS DISTINCT FROM 'object' THEN RETURN false;END IF;
 IF NOT(identity_json ?& ARRAY['binding','serial_number','creation_time'])
  OR(SELECT count(*) FROM jsonb_object_keys(identity_json) AS k(key_name))<>3
  OR NOT(evidence_json ?& ARRAY['request_id','response_sha256','observed_at'])
  OR(SELECT count(*) FROM jsonb_object_keys(evidence_json) AS k(key_name))<>3
  OR octet_length(identity_json::text)>8192 OR octet_length(evidence_json::text)>2048 THEN RETURN false;END IF;
 binding_json:=identity_json->'binding';
 IF jsonb_typeof(binding_json) IS DISTINCT FROM 'object' THEN RETURN false;END IF;
 IF NOT(binding_json ?& ARRAY['account_id','region','disk_id','zone_id','deployment','namespace','pvc_name','pv_name','kms_key_id','size_gib'])
  OR(SELECT count(*) FROM jsonb_object_keys(binding_json) AS k(key_name))<>10 THEN RETURN false;END IF;
 FOREACH field_name IN ARRAY ARRAY['account_id','region','disk_id','zone_id','deployment','namespace','pvc_name','pv_name','kms_key_id'] LOOP
  IF jsonb_typeof(binding_json->field_name) IS DISTINCT FROM 'string' THEN RETURN false;END IF;
 END LOOP;
 IF binding_json->>'account_id' !~ '^[0-9]{16}$'
  OR char_length(binding_json->>'region') NOT BETWEEN 4 AND 32 OR binding_json->>'region' !~ '^cn-[a-z0-9-]+$'
  OR char_length(binding_json->>'disk_id') NOT BETWEEN 3 AND 128 OR binding_json->>'disk_id' !~ '^d-[A-Za-z0-9]+$'
  OR char_length(binding_json->>'zone_id') NOT BETWEEN 1 AND 64 OR binding_json->>'zone_id' !~ '^cn-[a-z0-9-]+$'
  OR char_length(binding_json->>'zone_id')<=char_length(binding_json->>'region')+1
  OR binding_json->>'zone_id' NOT LIKE((binding_json->>'region')||'-%')
  OR binding_json->>'deployment' !~ '^[a-z][a-z0-9-]{3,19}$'
  OR binding_json->'namespace' IS DISTINCT FROM to_jsonb('sandbox-system'::text)
  OR binding_json->>'pvc_name' !~ '^sbx-bvol-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  OR binding_json->>'pv_name' !~ '^disk-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  OR char_length(binding_json->>'kms_key_id') NOT BETWEEN 1 AND 256 OR binding_json->>'kms_key_id' !~ '^[A-Za-z0-9/_:-]+$'
  OR jsonb_typeof(binding_json->'size_gib') IS DISTINCT FROM 'number' THEN RETURN false;END IF;
 size_text:=(binding_json->'size_gib')::text;
 IF size_text !~ '^[1-9][0-9]{0,3}$' THEN RETURN false;END IF;
 IF size_text::integer NOT BETWEEN 20 AND 1024 THEN RETURN false;END IF;
 FOREACH field_name IN ARRAY ARRAY['serial_number','creation_time'] LOOP
  IF jsonb_typeof(identity_json->field_name) IS DISTINCT FROM 'string' THEN RETURN false;END IF;
 END LOOP;
 FOREACH field_name IN ARRAY ARRAY['request_id','response_sha256','observed_at'] LOOP
  IF jsonb_typeof(evidence_json->field_name) IS DISTINCT FROM 'string' THEN RETURN false;END IF;
 END LOOP;
 IF char_length(identity_json->>'serial_number') NOT BETWEEN 1 AND 128 OR identity_json->>'serial_number' !~ '^[!-~]+$'
  OR char_length(evidence_json->>'request_id') NOT BETWEEN 1 AND 256 OR evidence_json->>'request_id' !~ '^[!-~]+$'
  OR evidence_json->>'response_sha256' !~ '^[0-9a-f]{64}$'
  OR public.sandbox_restore_topology_timestamp_valid(identity_json->>'creation_time') IS NOT TRUE
  OR public.sandbox_restore_topology_timestamp_valid(evidence_json->>'observed_at') IS NOT TRUE THEN RETURN false;END IF;
 RETURN(identity_json->>'creation_time')::timestamptz<=(evidence_json->>'observed_at')::timestamptz;
END $$;
REVOKE ALL ON FUNCTION sandbox_restore_raw_disk_payload_valid(jsonb,jsonb) FROM PUBLIC;

CREATE TABLE restore_raw_disk_receipts (
 restore_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,
 node_topology_receipt_id uuid NOT NULL REFERENCES restore_node_topology_receipts(id),
 pv_spec_sha256 text NOT NULL CHECK(pv_spec_sha256~'^[0-9a-f]{64}$'),
 cloud_identity jsonb NOT NULL,cloud_evidence jsonb NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(tenant_id,restore_id),
 FOREIGN KEY(tenant_id,restore_id) REFERENCES restore_block_receipts(tenant_id,restore_id),
 CHECK(restore_id<>'00000000-0000-0000-0000-000000000000' AND tenant_id<>'00000000-0000-0000-0000-000000000000'),
 CHECK(node_topology_receipt_id<>'00000000-0000-0000-0000-000000000000'),
 CHECK(isfinite(recorded_at)),
 CHECK(public.sandbox_restore_raw_disk_payload_valid(cloud_identity,cloud_evidence) IS TRUE)
);
ALTER TABLE restore_raw_disk_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE restore_raw_disk_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON restore_raw_disk_receipts
 USING(tenant_id=public.sandbox_current_tenant_id()) WITH CHECK(tenant_id=public.sandbox_current_tenant_id());
CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON restore_raw_disk_receipts
 FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_audit_mutation();
REVOKE ALL ON TABLE restore_raw_disk_receipts FROM PUBLIC;

-- Owner-only append point has no publication function yet. It cannot certify
-- signatures: new sealed signed-disk normal writer remains a required next slice.
CREATE FUNCTION sandbox_guard_restore_raw_disk() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE restore_row public.restores;raw_row public.restore_block_receipts;topology_row public.restore_node_topology_receipts;
 pvc_binding public.restore_resource_bindings;pv_binding public.restore_resource_bindings;
 pv_intent public.restore_resource_intents;binding_json jsonb;now_at timestamptz;observed_at timestamptz;owner_ok boolean;
BEGIN
 SELECT count(*)=5 AND bool_and(pg_has_role(current_user,c.relowner,'USAGE')) INTO owner_ok
 FROM pg_class AS c WHERE c.relnamespace='public'::regnamespace
  AND c.relname=ANY(ARRAY['restore_raw_disk_receipts','restores','restore_block_receipts','restore_resource_bindings','restore_node_topology_receipts']);
 IF owner_ok IS NOT TRUE THEN RAISE EXCEPTION 'raw disk receipt requires installation table owner' USING ERRCODE='42501';END IF;
 -- Future normal writer already holds workspace->instance->operations->restore.
 -- Restore fence first here, then immutable resource rows in deterministic order.
 SELECT r.* INTO restore_row FROM public.restores AS r WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.restore_id FOR UPDATE;
 PERFORM i.id FROM public.restore_resource_intents AS i WHERE i.tenant_id=NEW.tenant_id AND i.restore_id=NEW.restore_id ORDER BY i.id FOR SHARE;
 PERFORM b.intent_id FROM public.restore_resource_bindings AS b WHERE b.tenant_id=NEW.tenant_id AND b.restore_id=NEW.restore_id ORDER BY b.intent_id FOR SHARE;
 SELECT r.* INTO raw_row FROM public.restore_block_receipts AS r WHERE r.tenant_id=NEW.tenant_id AND r.restore_id=NEW.restore_id FOR SHARE;
 SELECT t.* INTO topology_row FROM public.restore_node_topology_receipts AS t WHERE t.id=NEW.node_topology_receipt_id FOR SHARE;
 SELECT b.* INTO pvc_binding FROM public.restore_resource_intents AS i JOIN public.restore_resource_bindings AS b ON b.tenant_id=i.tenant_id AND b.restore_id=i.restore_id AND b.intent_id=i.id
  WHERE i.tenant_id=NEW.tenant_id AND i.restore_id=NEW.restore_id AND i.kind='BLOCK_PVC';
 SELECT i.* INTO pv_intent FROM public.restore_resource_intents AS i WHERE i.tenant_id=NEW.tenant_id AND i.restore_id=NEW.restore_id AND i.kind='BLOCK_PV';
 SELECT b.* INTO pv_binding FROM public.restore_resource_bindings AS b WHERE b.tenant_id=NEW.tenant_id AND b.restore_id=NEW.restore_id AND b.intent_id=pv_intent.id;
 now_at:=clock_timestamp();NEW.recorded_at:=now_at;
 IF public.sandbox_restore_raw_disk_payload_valid(NEW.cloud_identity,NEW.cloud_evidence) IS NOT TRUE THEN
  RAISE EXCEPTION 'raw disk receipt requires strict fixed identity and evidence shape' USING ERRCODE='23514';END IF;
 binding_json:=NEW.cloud_identity->'binding';observed_at:=(NEW.cloud_evidence->>'observed_at')::timestamptz;
 IF restore_row.id IS NULL OR raw_row.restore_id IS NULL OR topology_row.id IS NULL OR pvc_binding.intent_id IS NULL OR pv_binding.intent_id IS NULL
  OR restore_row.status IS DISTINCT FROM 'RESTORE_PENDING'
  OR public.sandbox_restore_authorized(NEW.tenant_id,NEW.restore_id,true) IS NOT TRUE
  OR pv_intent.namespace IS DISTINCT FROM '' OR pv_intent.expected_object IS NOT NULL OR pv_intent.name IS DISTINCT FROM 'disk-'||pvc_binding.uid::text
  OR raw_row.pvc_uid IS DISTINCT FROM pvc_binding.uid OR raw_row.pv_uid IS DISTINCT FROM pv_binding.uid OR raw_row.pv_name IS DISTINCT FROM pv_intent.name
  OR raw_row.size_bytes IS DISTINCT FROM restore_row.size_gib*1073741824::bigint
  OR raw_row.recorded_at<pvc_binding.observed_at OR raw_row.recorded_at<pv_binding.observed_at-interval '2 seconds'
  OR EXISTS(SELECT 1 FROM public.backups AS source WHERE source.tenant_id=restore_row.tenant_id AND source.id=restore_row.backup_id
   AND(source.source->>'pv_uid'=raw_row.pv_uid::text OR source.source->>'cloud_disk'=raw_row.cloud_disk))
  OR EXISTS(SELECT 1 FROM public.backup_clone_receipts AS clone WHERE clone.tenant_id=restore_row.tenant_id AND clone.backup_id=restore_row.backup_id
   AND(clone.pvc_uid=pvc_binding.uid OR clone.pv_uid=pv_binding.uid OR clone.cloud_disk=raw_row.cloud_disk))
  OR topology_row.restore_profile_id IS DISTINCT FROM restore_row.profile_id
  OR topology_row.restore_report_sha256 IS DISTINCT FROM restore_row.storage_contract->>'report_sha256'
  OR binding_json IS DISTINCT FROM jsonb_build_object('account_id',restore_row.storage_contract->'mapping'->>'account_id',
   'region',restore_row.storage_contract->'mapping'->>'region','disk_id',raw_row.cloud_disk,'zone_id',topology_row.zone_id,
   'deployment',restore_row.storage_contract->'mapping'->>'deployment','namespace','sandbox-system','pvc_name','sbx-bvol-'||restore_row.id::text,
   'pv_name',pv_intent.name,'kms_key_id',restore_row.storage_contract->'mapping'->>'workspace_kms_key_id','size_gib',restore_row.size_gib)
  OR observed_at<now_at-interval '10 seconds' OR observed_at>now_at+interval '2 seconds'
  OR raw_row.recorded_at<observed_at-interval '2 seconds' OR raw_row.recorded_at>now_at+interval '2 seconds'
  OR pvc_binding.observed_at>observed_at+interval '2 seconds' OR pv_binding.observed_at>now_at+interval '2 seconds' THEN
  RAISE EXCEPTION 'raw disk receipt parent, PV, topology, frozen encryption or observation identity differs' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER raw_disk_insert_guard BEFORE INSERT ON restore_raw_disk_receipts
 FOR EACH ROW EXECUTE FUNCTION sandbox_guard_restore_raw_disk();
REVOKE ALL ON FUNCTION sandbox_guard_restore_raw_disk() FROM PUBLIC;
DO $$
DECLARE ordinary_role text;
BEGIN
 FOREACH ordinary_role IN ARRAY ARRAY['sandbox_app','sandbox_worker','sandbox_admission','sandbox_gateway','sandbox_termination','sandbox_fencing','sandbox_volume_deleter','sandbox_backup','sandbox_restore_gc'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles AS r WHERE r.rolname=ordinary_role) THEN
   EXECUTE format('REVOKE ALL ON TABLE public.restore_raw_disk_receipts FROM %I',ordinary_role);
   EXECUTE format('REVOKE ALL ON FUNCTION public.sandbox_restore_raw_disk_payload_valid(jsonb,jsonb),public.sandbox_guard_restore_raw_disk() FROM %I',ordinary_role);
  END IF;
 END LOOP;
END $$;
