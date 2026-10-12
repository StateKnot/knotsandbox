-- PostgreSQL CHECK accepts NULL. Assert required evidence explicitly instead of
-- relying on equality expressions whose result may be unknown.
ALTER TABLE instances ADD CONSTRAINT held_activity_has_generation
    CHECK (NOT slot_held OR activity_generation IS NOT NULL);
ALTER TABLE executions ADD CONSTRAINT succeeded_execution_has_exit_code
    CHECK (status <> 'SUCCEEDED' OR (exit_code IS NOT NULL AND exit_code = 0));

-- A PVC and its sole instance must use the same immutable namespace.
ALTER TABLE workspaces ADD CONSTRAINT workspace_namespace_identity
    UNIQUE (tenant_id, project_id, id, namespace);
ALTER TABLE instances ADD CONSTRAINT instance_workspace_namespace_matches
    FOREIGN KEY (tenant_id, project_id, workspace_id, namespace)
    REFERENCES workspaces(tenant_id, project_id, id, namespace);

-- The runtime may recheck a previously resolved principal without reading the
-- global directory. This function cannot change or enumerate identity records.
CREATE FUNCTION sandbox_principal_enabled(principal uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    SELECT COALESCE((SELECT p.enabled FROM public.principals p WHERE p.id = principal), false)
$$;
REVOKE ALL ON FUNCTION sandbox_principal_enabled(uuid) FROM PUBLIC;
