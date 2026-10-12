CREATE OR REPLACE FUNCTION sandbox_prevent_scope_change() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR (to_jsonb(NEW)->'project_id') IS DISTINCT FROM (to_jsonb(OLD)->'project_id') THEN
        RAISE EXCEPTION 'resource identity and scope are immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION sandbox_preserve_runtime_identity() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_TABLE_NAME='instances' THEN
        IF (NEW.workspace_id,NEW.namespace,NEW.pod_name) IS DISTINCT FROM
           (OLD.workspace_id,OLD.namespace,OLD.pod_name) THEN
            RAISE EXCEPTION 'instance workspace binding is immutable' USING ERRCODE='23514';
        END IF;
    ELSIF TG_TABLE_NAME='workspaces' THEN
        IF (NEW.namespace,NEW.pvc_name,NEW.storage_class) IS DISTINCT FROM
           (OLD.namespace,OLD.pvc_name,OLD.storage_class) THEN
            RAISE EXCEPTION 'workspace runtime binding is immutable' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER instance_runtime_identity_immutable BEFORE UPDATE ON instances
FOR EACH ROW EXECUTE FUNCTION sandbox_preserve_runtime_identity();
CREATE TRIGGER workspace_runtime_identity_immutable BEFORE UPDATE ON workspaces
FOR EACH ROW EXECUTE FUNCTION sandbox_preserve_runtime_identity();
REVOKE ALL ON FUNCTION sandbox_preserve_runtime_identity() FROM PUBLIC;
