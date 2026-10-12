-- Deliberately fail if historical ledgers contain duplicate active identities.
-- Operators must investigate duplicates; migration never deletes resource evidence.
CREATE UNIQUE INDEX external_live_pod_identity
    ON external_resources(tenant_id,instance_id,generation)
    WHERE provider='kubernetes' AND kind='POD' AND status<>'DELETED';
CREATE UNIQUE INDEX external_live_pvc_identity
    ON external_resources(tenant_id,workspace_id)
    WHERE provider='kubernetes' AND kind='PVC' AND status<>'DELETED';
CREATE UNIQUE INDEX external_live_policy_identity
    ON external_resources(tenant_id,instance_id)
    WHERE provider='kubernetes' AND kind='CILIUM_POLICY' AND status<>'DELETED';
