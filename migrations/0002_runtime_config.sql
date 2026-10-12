-- Installation state is owned by the operator, not writable by the HTTP API.
CREATE TABLE platform_configuration (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    cluster_epoch uuid NOT NULL,
    safe_mode boolean NOT NULL DEFAULT true,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- A project is provisioned by the cluster operator before accepting workloads.
ALTER TABLE projects ADD COLUMN runtime_namespace text
    CHECK (runtime_namespace ~ '^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$');
ALTER TABLE projects ADD COLUMN storage_class text;
CREATE UNIQUE INDEX project_runtime_namespace ON projects(runtime_namespace)
    WHERE runtime_namespace IS NOT NULL;
REVOKE ALL ON platform_configuration FROM PUBLIC;
