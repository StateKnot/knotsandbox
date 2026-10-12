ALTER TABLE instances ADD CONSTRAINT instance_workspace_operation_identity
    UNIQUE(tenant_id,project_id,id,workspace_id);
ALTER TABLE operations ADD CONSTRAINT operation_instance_requires_workspace
    CHECK(instance_id IS NULL OR workspace_id IS NOT NULL);
ALTER TABLE operations ADD CONSTRAINT operation_workspace_is_instance_workspace
    FOREIGN KEY(tenant_id,project_id,instance_id,workspace_id)
    REFERENCES instances(tenant_id,project_id,id,workspace_id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE external_resources ADD CONSTRAINT external_resource_workspace_matches_instance
    FOREIGN KEY(tenant_id,project_id,instance_id,workspace_id)
    REFERENCES instances(tenant_id,project_id,id,workspace_id);

-- Operations that existed before routing-index installation must be claimable.
-- Same exclusive owner enumeration as timer migration; runtime stays under RLS.
ALTER TABLE tenants NO FORCE ROW LEVEL SECURITY;
DO $$
DECLARE tenant uuid;
BEGIN
    FOR tenant IN SELECT id FROM tenants LOOP
        PERFORM set_config('app.tenant_id',tenant::text,true);
        UPDATE operations SET next_attempt_at=next_attempt_at
        WHERE tenant_id=tenant AND status IN ('QUEUED','RUNNING','WAITING');
    END LOOP;
    PERFORM set_config('app.tenant_id','',true);
END;
$$;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
