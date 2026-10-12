-- Installation-wide operator audit; this table has no tenant-facing grant.
CREATE TABLE runtime_node_enrollments (
    id uuid PRIMARY KEY,
    runtime_node_id uuid NOT NULL UNIQUE REFERENCES runtime_nodes(id),
    cluster_epoch uuid NOT NULL,
    artifact_sha256 text NOT NULL CHECK(artifact_sha256~'^[0-9a-f]{64}$'),
    terraform_output_sha256 text NOT NULL CHECK(terraform_output_sha256~'^[0-9a-f]{64}$'),
    settings_sha256 text NOT NULL CHECK(settings_sha256~'^[0-9a-f]{64}$'),
    certification_report_sha256 text NOT NULL CHECK(certification_report_sha256~'^[0-9a-f]{64}$'),
    certification_expires_at timestamptz NOT NULL,
    observed_node_resource_version text NOT NULL CHECK(char_length(observed_node_resource_version) BETWEEN 1 AND 256),
    observed_at timestamptz NOT NULL,
    database_role text NOT NULL,
    receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object' AND octet_length(receipt::text)<=16384),
    registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK(certification_expires_at>registered_at),
    CHECK(observed_at>=registered_at-interval '10 seconds' AND observed_at<=registered_at+interval '2 seconds')
);
REVOKE ALL ON runtime_node_enrollments FROM PUBLIC;
CREATE TRIGGER runtime_node_enrollments_append_only BEFORE UPDATE OR DELETE ON runtime_node_enrollments
FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_audit_mutation();
