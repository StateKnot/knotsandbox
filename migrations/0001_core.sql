-- PostgreSQL 17+. Run as the migration owner, never as the API login.
-- Runtime grants are deliberately separate: scripts/sql/roles.sql.

CREATE FUNCTION sandbox_current_tenant_id() RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE
SET search_path = pg_catalog
AS $$ SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid $$;

CREATE TABLE tenants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    enabled boolean NOT NULL DEFAULT true,
    authz_version bigint NOT NULL DEFAULT 1 CHECK (authz_version > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Global identity directory. Tenant authorization lives in grants, not here.
-- API roles receive only the narrowly scoped resolver function below.
CREATE TABLE principals (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind text NOT NULL CHECK (kind IN ('USER', 'SERVICE', 'SYSTEM')),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 128),
    enabled boolean NOT NULL DEFAULT true,
    authz_version bigint NOT NULL DEFAULT 1 CHECK (authz_version > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE principal_identities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id uuid NOT NULL REFERENCES principals(id),
    issuer text NOT NULL CHECK (char_length(issuer) BETWEEN 1 AND 2048),
    subject text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 512),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (issuer, subject)
);
CREATE INDEX principal_identities_principal ON principal_identities(principal_id);

CREATE FUNCTION sandbox_resolve_identity(identity_issuer text, identity_subject text)
RETURNS TABLE (principal_id uuid, kind text, enabled boolean, authz_version bigint)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    SELECT p.id, p.kind, p.enabled AND i.enabled, p.authz_version
    FROM public.principal_identities i
    JOIN public.principals p ON p.id = i.principal_id
    WHERE i.issuer = identity_issuer AND i.subject = identity_subject
$$;
REVOKE ALL ON FUNCTION sandbox_resolve_identity(text, text) FROM PUBLIC;

CREATE TABLE projects (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    enabled boolean NOT NULL DEFAULT true,
    authz_version bigint NOT NULL DEFAULT 1 CHECK (authz_version > 0),
    max_ttl_seconds bigint NOT NULL CHECK (max_ttl_seconds BETWEEN 1 AND 31536000),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE TABLE grants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    project_id uuid,
    principal_id uuid NOT NULL REFERENCES principals(id),
    action text NOT NULL CHECK (action = '*' OR action ~ '^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$'),
    enabled boolean NOT NULL DEFAULT true,
    expires_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id),
    UNIQUE NULLS NOT DISTINCT (tenant_id, project_id, principal_id, action)
);
CREATE INDEX grants_principal ON grants (tenant_id, principal_id, project_id) WHERE enabled;

CREATE TABLE template_versions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    version bigint NOT NULL CHECK (version > 0),
    image_ref text NOT NULL CHECK (char_length(image_ref) BETWEEN 1 AND 2048),
    image_digest text NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    runner_version text NOT NULL CHECK (char_length(runner_version) BETWEEN 1 AND 64),
    status text NOT NULL CHECK (status IN ('DRAFT', 'APPROVED', 'REVOKED')),
    capabilities jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(capabilities) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name, version)
);

CREATE TABLE security_policy_versions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    version bigint NOT NULL CHECK (version > 0),
    status text NOT NULL CHECK (status IN ('DRAFT', 'APPROVED', 'REVOKED')),
    rules jsonb NOT NULL CHECK (jsonb_typeof(rules) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name, version)
);

CREATE TABLE workspaces (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    size_gib bigint NOT NULL CHECK (size_gib > 0),
    storage_class text NOT NULL CHECK (char_length(storage_class) BETWEEN 1 AND 253),
    cloud_volume_id text,
    csi_volume_id text,
    zone text,
    key_ref text,
    namespace text NOT NULL CHECK (namespace ~ '^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$'),
    pvc_name text NOT NULL CHECK (pvc_name = 'ws-' || id::text),
    status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'AVAILABLE', 'IN_USE', 'DELETING', 'DELETED', 'ERROR', 'UNKNOWN')),
    attachment_generation bigint NOT NULL DEFAULT 0 CHECK (attachment_generation >= 0),
    active_operation_id uuid,
    retention_until timestamptz,
    delete_authorization_ref text,
    delete_requested_at timestamptz,
    deleted_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, project_id, id),
    UNIQUE (namespace, pvc_name),
    CHECK (status <> 'DELETED' OR deleted_at IS NOT NULL),
    CHECK (status <> 'DELETING' OR delete_requested_at IS NOT NULL)
);
CREATE UNIQUE INDEX workspace_cloud_volume ON workspaces(cloud_volume_id) WHERE cloud_volume_id IS NOT NULL;
CREATE INDEX workspace_retention_due ON workspaces(retention_until, id)
    WHERE status = 'AVAILABLE' AND retention_until IS NOT NULL AND delete_authorization_ref IS NOT NULL;

CREATE TABLE instances (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    template_version_id uuid NOT NULL,
    security_policy_version_id uuid NOT NULL,
    workspace_id uuid NOT NULL UNIQUE,
    cpu_millis bigint NOT NULL CHECK (cpu_millis > 0),
    memory_mib bigint NOT NULL CHECK (memory_mib > 0),
    desired_state text NOT NULL CHECK (desired_state IN ('RUNNING', 'STOPPED', 'DELETED')),
    observed_state text NOT NULL DEFAULT 'PENDING' CHECK (observed_state IN ('PENDING', 'STARTING', 'RUNNING', 'STOPPING', 'STOPPED', 'DELETING', 'DELETED', 'ERROR', 'UNKNOWN', 'QUARANTINED')),
    spec_version bigint NOT NULL DEFAULT 1 CHECK (spec_version > 0),
    runtime_generation bigint NOT NULL DEFAULT 1 CHECK (runtime_generation > 0),
    cluster_epoch uuid NOT NULL,
    launch_id uuid NOT NULL UNIQUE,
    pod_uid uuid,
    namespace text NOT NULL CHECK (namespace ~ '^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$'),
    pod_name text NOT NULL CHECK (pod_name = 'sbx-ws-' || workspace_id::text),
    observed_at timestamptz,
    active_operation_id uuid,
    activity_kind text CHECK (activity_kind IN ('EXECUTION', 'TERMINAL', 'FILE_WRITE')),
    activity_id uuid,
    activity_generation bigint,
    slot_held boolean NOT NULL DEFAULT false,
    compute_lease_id uuid NOT NULL UNIQUE,
    compute_lease_version bigint NOT NULL DEFAULT 1 CHECK (compute_lease_version > 0),
    compute_lease_started_at timestamptz NOT NULL,
    compute_lease_expires_at timestamptz NOT NULL,
    idle_timeout_seconds bigint CHECK (idle_timeout_seconds > 0),
    last_activity_at timestamptz,
    idle_since timestamptz,
    stop_reason text CHECK (stop_reason IN ('USER_REQUESTED', 'LEASE_EXPIRED', 'IDLE', 'EXECUTION_TIMEOUT', 'EXECUTION_CANCELLED', 'SECURITY', 'MAINTENANCE')),
    stop_accepted_at timestamptz,
    deleted_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id),
    FOREIGN KEY (tenant_id, project_id, workspace_id) REFERENCES workspaces(tenant_id, project_id, id),
    FOREIGN KEY (tenant_id, template_version_id) REFERENCES template_versions(tenant_id, id),
    FOREIGN KEY (tenant_id, security_policy_version_id) REFERENCES security_policy_versions(tenant_id, id),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, project_id, id),
    UNIQUE (namespace, pod_name),
    CHECK (compute_lease_expires_at > compute_lease_started_at),
    CHECK ((slot_held AND activity_kind IS NOT NULL AND activity_id IS NOT NULL
            AND activity_generation = runtime_generation)
        OR (NOT slot_held AND activity_kind IS NULL AND activity_id IS NULL AND activity_generation IS NULL)),
    CHECK (NOT slot_held OR idle_since IS NULL),
    CHECK ((stop_reason IS NULL) = (stop_accepted_at IS NULL)),
    CHECK (observed_state <> 'DELETED' OR deleted_at IS NOT NULL)
);
CREATE INDEX instances_project_list ON instances(tenant_id, project_id, created_at DESC, id DESC);
CREATE INDEX instances_expiry_due ON instances(compute_lease_expires_at, id)
    WHERE desired_state = 'RUNNING' AND stop_accepted_at IS NULL;
CREATE INDEX instances_idle_due ON instances(idle_since, id)
    WHERE desired_state = 'RUNNING' AND idle_timeout_seconds IS NOT NULL AND NOT slot_held AND stop_accepted_at IS NULL;

CREATE TABLE operations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    instance_id uuid,
    workspace_id uuid,
    kind text NOT NULL CHECK (kind IN ('CREATE', 'START', 'STOP', 'RESTART', 'DELETE', 'RENEW', 'EXECUTE', 'DELETE_WORKSPACE')),
    status text NOT NULL DEFAULT 'QUEUED' CHECK (status IN ('QUEUED', 'RUNNING', 'WAITING', 'SUCCEEDED', 'FAILED', 'CANCELLED')),
    stage text NOT NULL DEFAULT 'ACCEPTED' CHECK (char_length(stage) BETWEEN 1 AND 128),
    request jsonb NOT NULL CHECK (jsonb_typeof(request) = 'object' AND octet_length(request::text) <= 1048576),
    actor_principal_id uuid NOT NULL REFERENCES principals(id),
    request_id uuid NOT NULL,
    deadline timestamptz NOT NULL,
    lease_owner text,
    lease_token bigint NOT NULL DEFAULT 0 CHECK (lease_token >= 0),
    lease_until timestamptz,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    wait_reason text,
    cancel_requested boolean NOT NULL DEFAULT false,
    error jsonb CHECK (error IS NULL OR jsonb_typeof(error) = 'object'),
    compute_lease_id uuid,
    stop_reason text CHECK (stop_reason IN ('USER_REQUESTED', 'LEASE_EXPIRED', 'IDLE', 'EXECUTION_TIMEOUT', 'EXECUTION_CANCELLED', 'SECURITY', 'MAINTENANCE')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id),
    FOREIGN KEY (tenant_id, project_id, instance_id) REFERENCES instances(tenant_id, project_id, id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, project_id, workspace_id) REFERENCES workspaces(tenant_id, project_id, id) DEFERRABLE INITIALLY DEFERRED,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, project_id, id),
    UNIQUE (tenant_id, project_id, instance_id, id),
    UNIQUE (tenant_id, project_id, workspace_id, id),
    CHECK (instance_id IS NOT NULL OR workspace_id IS NOT NULL),
    CHECK ((lease_owner IS NULL) = (lease_until IS NULL)),
    CHECK (status <> 'WAITING' OR wait_reason IS NOT NULL),
    CHECK ((status IN ('SUCCEEDED', 'FAILED', 'CANCELLED')) = (completed_at IS NOT NULL)),
    CHECK (stop_reason IS DISTINCT FROM 'LEASE_EXPIRED' OR (kind = 'STOP' AND compute_lease_id IS NOT NULL))
);
CREATE UNIQUE INDEX operation_one_active_lifecycle ON operations(tenant_id, instance_id)
    WHERE instance_id IS NOT NULL AND kind IN ('CREATE', 'START', 'STOP', 'RESTART', 'DELETE')
      AND status IN ('QUEUED', 'RUNNING', 'WAITING');
CREATE UNIQUE INDEX operation_one_expiry_stop ON operations(tenant_id, instance_id, compute_lease_id)
    WHERE kind = 'STOP' AND stop_reason = 'LEASE_EXPIRED';
CREATE INDEX operations_claimable ON operations(next_attempt_at, created_at, id)
    WHERE status IN ('QUEUED', 'RUNNING', 'WAITING');
CREATE INDEX operations_instance_history ON operations(tenant_id, instance_id, created_at DESC, id DESC);

ALTER TABLE instances ADD CONSTRAINT instance_active_operation_matches
    FOREIGN KEY (tenant_id, project_id, id, active_operation_id)
    REFERENCES operations(tenant_id, project_id, instance_id, id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE workspaces ADD CONSTRAINT workspace_active_operation_matches
    FOREIGN KEY (tenant_id, project_id, id, active_operation_id)
    REFERENCES operations(tenant_id, project_id, workspace_id, id) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE executions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    instance_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    runtime_generation bigint NOT NULL CHECK (runtime_generation > 0),
    launch_id uuid NOT NULL,
    pod_uid uuid NOT NULL,
    status text NOT NULL DEFAULT 'QUEUED' CHECK (status IN ('QUEUED', 'DISPATCHING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'TIMED_OUT', 'CANCELLED', 'OUTCOME_UNKNOWN')),
    slot_held boolean NOT NULL DEFAULT true,
    dispatch_attempt_id uuid,
    dispatch_attempted_at timestamptz,
    deadline timestamptz NOT NULL,
    timeout_seconds integer NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 3600),
    termination_status text NOT NULL DEFAULT 'NOT_REQUESTED' CHECK (termination_status IN ('NOT_REQUESTED', 'PENDING', 'CONFIRMED', 'UNKNOWN')),
    exit_code integer,
    output_status text NOT NULL DEFAULT 'PENDING' CHECK (output_status IN ('PENDING', 'COMPLETE', 'TRUNCATED', 'PARTIAL', 'LOST')),
    output_manifest jsonb CHECK (output_manifest IS NULL OR jsonb_typeof(output_manifest) = 'object'),
    client_reference text CHECK (char_length(client_reference) <= 256),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    FOREIGN KEY (tenant_id, project_id, instance_id) REFERENCES instances(tenant_id, project_id, id),
    FOREIGN KEY (tenant_id, project_id, instance_id, operation_id) REFERENCES operations(tenant_id, project_id, instance_id, id),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, project_id, id),
    UNIQUE (operation_id),
    CHECK ((dispatch_attempt_id IS NULL) = (dispatch_attempted_at IS NULL)),
    CHECK (status NOT IN ('DISPATCHING', 'RUNNING', 'SUCCEEDED', 'OUTCOME_UNKNOWN') OR dispatch_attempted_at IS NOT NULL),
    CHECK (slot_held OR termination_status = 'CONFIRMED'),
    CHECK (status <> 'SUCCEEDED' OR exit_code = 0),
    CHECK (status NOT IN ('SUCCEEDED', 'FAILED', 'TIMED_OUT', 'CANCELLED') OR completed_at IS NOT NULL)
);
CREATE UNIQUE INDEX execution_one_active_per_instance ON executions(tenant_id, instance_id) WHERE slot_held;
CREATE INDEX executions_deadline ON executions(deadline, id) WHERE termination_status <> 'CONFIRMED';
CREATE INDEX executions_instance_history ON executions(tenant_id, instance_id, created_at DESC, id DESC);

CREATE TABLE idempotency_keys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    principal_id uuid NOT NULL REFERENCES principals(id),
    operation_name text NOT NULL CHECK (char_length(operation_name) BETWEEN 1 AND 128),
    target_id uuid NOT NULL,
    key_hash text NOT NULL CHECK (key_hash ~ '^[0-9a-f]{64}$'),
    request_hash text NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    operation_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    response_status smallint NOT NULL CHECK (response_status BETWEEN 200 AND 299),
    response_body jsonb NOT NULL CHECK (jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    tombstone_until timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id),
    FOREIGN KEY (tenant_id, project_id, operation_id) REFERENCES operations(tenant_id, project_id, id),
    UNIQUE (tenant_id, principal_id, operation_name, target_id, key_hash),
    CHECK (expires_at >= created_at + interval '7 days'),
    CHECK (tombstone_until >= expires_at + interval '90 days')
);
CREATE INDEX idempotency_cleanup ON idempotency_keys(tombstone_until);

CREATE TABLE quota_accounts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    project_id uuid,
    dimension text NOT NULL CHECK (dimension IN ('INSTANCES', 'CPU_MILLIS', 'MEMORY_MIB', 'WORKSPACE_GIB', 'EXECUTIONS')),
    limit_value bigint NOT NULL CHECK (limit_value >= 0),
    pending bigint NOT NULL DEFAULT 0 CHECK (pending >= 0),
    allocated bigint NOT NULL DEFAULT 0 CHECK (allocated >= 0),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id),
    UNIQUE (tenant_id, id),
    UNIQUE NULLS NOT DISTINCT (tenant_id, project_id, dimension),
    CHECK (pending::numeric + allocated::numeric <= limit_value::numeric)
);

CREATE TABLE quota_reservations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    quota_account_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    amount bigint NOT NULL CHECK (amount > 0),
    status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ALLOCATED', 'RELEASED')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    released_at timestamptz,
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id),
    FOREIGN KEY (tenant_id, quota_account_id) REFERENCES quota_accounts(tenant_id, id),
    FOREIGN KEY (tenant_id, project_id, operation_id) REFERENCES operations(tenant_id, project_id, id),
    UNIQUE (tenant_id, id),
    UNIQUE (quota_account_id, operation_id, resource_id),
    CHECK ((status = 'RELEASED') = (released_at IS NOT NULL))
);
CREATE INDEX reservations_resource ON quota_reservations(tenant_id, resource_id) WHERE status <> 'RELEASED';

-- A tenant-wide account may fund any project in that tenant. A project account
-- may only fund its own project; a tenant-only FK cannot express this condition.
CREATE FUNCTION sandbox_validate_reservation_scope() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM public.quota_accounts q
        WHERE q.tenant_id = NEW.tenant_id AND q.id = NEW.quota_account_id
          AND (q.project_id IS NULL OR q.project_id = NEW.project_id)
    ) THEN
        RAISE EXCEPTION 'quota reservation account scope mismatch' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER reservation_account_scope BEFORE INSERT OR UPDATE ON quota_reservations
    FOR EACH ROW EXECUTE FUNCTION sandbox_validate_reservation_scope();

CREATE TABLE audit_events (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    project_id uuid,
    actor_principal_id uuid REFERENCES principals(id),
    request_id uuid NOT NULL,
    operation_id uuid,
    resource_id uuid,
    action text NOT NULL CHECK (char_length(action) BETWEEN 1 AND 128),
    outcome text NOT NULL CHECK (outcome IN ('ACCEPTED', 'DENIED', 'SUCCEEDED', 'FAILED', 'UNKNOWN')),
    details jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object' AND octet_length(details::text) <= 65536),
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (id, occurred_at),
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id),
    FOREIGN KEY (tenant_id, operation_id) REFERENCES operations(tenant_id, id)
) PARTITION BY RANGE (occurred_at);
CREATE TABLE audit_events_default PARTITION OF audit_events DEFAULT;
CREATE INDEX audit_events_tenant_time ON audit_events(tenant_id, occurred_at DESC, id DESC);
CREATE INDEX audit_events_operation ON audit_events(tenant_id, operation_id, occurred_at);

CREATE TABLE domain_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    project_id uuid NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    event_type text NOT NULL CHECK (char_length(event_type) BETWEEN 1 AND 128),
    schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version > 0),
    operation_id uuid,
    request_id uuid NOT NULL,
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 65536),
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    published_at timestamptz,
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id),
    FOREIGN KEY (tenant_id, project_id, operation_id) REFERENCES operations(tenant_id, project_id, id),
    UNIQUE (tenant_id, aggregate_id, aggregate_version, event_type)
);
CREATE INDEX domain_events_outbox ON domain_events(occurred_at, id) WHERE published_at IS NULL;
CREATE INDEX domain_events_tenant_time ON domain_events(tenant_id, occurred_at DESC, id DESC);

CREATE TABLE external_resources (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    instance_id uuid,
    workspace_id uuid,
    provider text NOT NULL CHECK (char_length(provider) BETWEEN 1 AND 64),
    kind text NOT NULL CHECK (char_length(kind) BETWEEN 1 AND 64),
    provider_id text NOT NULL CHECK (char_length(provider_id) BETWEEN 1 AND 2048),
    generation bigint NOT NULL CHECK (generation > 0),
    owner_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('PENDING', 'ACTIVE', 'DELETING', 'DELETED', 'UNKNOWN', 'QUARANTINED')),
    observed_at timestamptz,
    delete_requested_at timestamptz,
    deleted_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id),
    FOREIGN KEY (tenant_id, project_id, operation_id) REFERENCES operations(tenant_id, project_id, id),
    FOREIGN KEY (tenant_id, project_id, instance_id) REFERENCES instances(tenant_id, project_id, id),
    FOREIGN KEY (tenant_id, project_id, workspace_id) REFERENCES workspaces(tenant_id, project_id, id),
    UNIQUE (tenant_id, id),
    UNIQUE (provider, kind, provider_id),
    CHECK (status <> 'DELETED' OR deleted_at IS NOT NULL)
);
CREATE INDEX external_resources_owner ON external_resources(tenant_id, owner_id);
CREATE INDEX external_resources_cleanup ON external_resources(delete_requested_at, id) WHERE status = 'DELETING';

-- Row ownership cannot be reassigned after creation, even by a compromised API
-- query with a matching tenant context. Data migrations use separate privileges.
CREATE FUNCTION sandbox_prevent_scope_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR (to_jsonb(NEW)->'project_id') IS DISTINCT FROM (to_jsonb(OLD)->'project_id') THEN
        RAISE EXCEPTION 'resource scope is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION sandbox_preserve_workspace_binding() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF (NEW.namespace, NEW.pvc_name) IS DISTINCT FROM (OLD.namespace, OLD.pvc_name) THEN
        RAISE EXCEPTION 'workspace namespace and PVC identity are immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER workspace_binding_immutable BEFORE UPDATE ON workspaces
    FOR EACH ROW EXECUTE FUNCTION sandbox_preserve_workspace_binding();

CREATE FUNCTION sandbox_preserve_instance_binding() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF (NEW.workspace_id, NEW.namespace, NEW.pod_name)
       IS DISTINCT FROM (OLD.workspace_id, OLD.namespace, OLD.pod_name) THEN
        RAISE EXCEPTION 'instance workspace and Kubernetes name are immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER instance_binding_immutable BEFORE UPDATE ON instances
    FOR EACH ROW EXECUTE FUNCTION sandbox_preserve_instance_binding();

CREATE FUNCTION sandbox_prevent_audit_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'audit records are append only' USING ERRCODE = '23514';
END;
$$;
CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_audit_mutation();

CREATE FUNCTION sandbox_preserve_operation_request() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF (NEW.request, NEW.kind, NEW.actor_principal_id, NEW.request_id, NEW.instance_id, NEW.workspace_id)
       IS DISTINCT FROM
       (OLD.request, OLD.kind, OLD.actor_principal_id, OLD.request_id, OLD.instance_id, OLD.workspace_id) THEN
        RAISE EXCEPTION 'operation request and target are immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER operation_request_immutable BEFORE UPDATE ON operations
    FOR EACH ROW EXECUTE FUNCTION sandbox_preserve_operation_request();

CREATE FUNCTION sandbox_preserve_version_content() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF (to_jsonb(NEW) - 'status') IS DISTINCT FROM (to_jsonb(OLD) - 'status') THEN
        RAISE EXCEPTION 'version content is immutable; publish a new version' USING ERRCODE = '23514';
    END IF;
    IF OLD.status = 'REVOKED' AND NEW.status <> 'REVOKED' THEN
        RAISE EXCEPTION 'revoked version cannot be re-enabled' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER template_content_immutable BEFORE UPDATE ON template_versions
    FOR EACH ROW EXECUTE FUNCTION sandbox_preserve_version_content();
CREATE TRIGGER security_policy_content_immutable BEFORE UPDATE ON security_policy_versions
    FOR EACH ROW EXECUTE FUNCTION sandbox_preserve_version_content();

CREATE FUNCTION sandbox_preserve_event_content() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'domain events are append only' USING ERRCODE = '23514';
    END IF;
    IF (to_jsonb(NEW) - 'published_at') IS DISTINCT FROM (to_jsonb(OLD) - 'published_at') THEN
        RAISE EXCEPTION 'domain event content is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER domain_event_content_immutable BEFORE UPDATE OR DELETE ON domain_events
    FOR EACH ROW EXECUTE FUNCTION sandbox_preserve_event_content();

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenants
    USING (id = sandbox_current_tenant_id())
    WITH CHECK (id = sandbox_current_tenant_id());

DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'projects', 'grants', 'template_versions', 'security_policy_versions',
        'workspaces', 'instances', 'operations', 'executions', 'idempotency_keys',
        'quota_accounts', 'quota_reservations', 'audit_events', 'audit_events_default',
        'domain_events', 'external_resources'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING (tenant_id = sandbox_current_tenant_id()) WITH CHECK (tenant_id = sandbox_current_tenant_id())',
            table_name
        );
        IF table_name NOT IN ('audit_events', 'audit_events_default') THEN
            EXECUTE format(
                'CREATE TRIGGER immutable_scope BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_scope_change()',
                table_name
            );
        END IF;
    END LOOP;
END;
$$;

-- No connection may opt in to another tenant accidentally through PUBLIC grants.
-- The API must use SET LOCAL/set_config(..., true) inside every transaction.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
