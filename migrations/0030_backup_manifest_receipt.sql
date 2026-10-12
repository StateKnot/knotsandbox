-- Preserve the complete verified v2 manifest rather than an ambiguous summary.
-- Inventory data stays in OSS. The bounded envelope additionally pins verifier
-- endpoint and the approved signing public-key fingerprint.
ALTER TABLE backup_vault_receipts DROP CONSTRAINT backup_vault_receipts_manifest_check;
ALTER TABLE backup_vault_receipts ADD CONSTRAINT backup_vault_receipts_manifest_check
 CHECK(jsonb_typeof(manifest)='object'
   AND manifest ?& ARRAY['manifest','signing_key_sha256','vault_endpoint']
   AND octet_length(manifest::text)<=1114112
   AND jsonb_typeof(manifest->'manifest')='object'
   AND octet_length((manifest->'manifest')::text)<=1048576
   AND manifest->>'signing_key_sha256' ~ '^[0-9a-f]{64}$'
   AND char_length(manifest->>'vault_endpoint') BETWEEN 1 AND 256);
