-- Capture only facts written after this migration. Existing reservation IDs are
-- frozen under the owner lock; absence of a contract never makes a new row legacy.
LOCK TABLE public.quota_reservations IN ACCESS EXCLUSIVE MODE;
CREATE TABLE quota_resource_legacy_baseline (
    reservation_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    captured_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (tenant_id,reservation_id) REFERENCES public.quota_reservations(tenant_id,id)
);
-- FORCE RLS also applies to a non-superuser migration owner. This transaction's
-- exclusive lock protects the complete baseline while the owner reads all rows.
ALTER TABLE public.quota_reservations NO FORCE ROW LEVEL SECURITY;
INSERT INTO public.quota_resource_legacy_baseline(reservation_id,tenant_id)
    SELECT id,tenant_id FROM public.quota_reservations;
ALTER TABLE public.quota_reservations FORCE ROW LEVEL SECURITY;

CREATE TABLE launch_resource_contracts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    instance_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation>0),
    launch_id uuid NOT NULL,
    cluster_epoch uuid NOT NULL,
    operation_id uuid NOT NULL,
    cpu_millis bigint NOT NULL,
    memory_mib bigint NOT NULL,
    source text NOT NULL DEFAULT 'REQUESTED_COMPUTE_QUOTA'
        CHECK (source='REQUESTED_COMPUTE_QUOTA'),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((cpu_millis,memory_mib) IN ((1000,2048),(2000,4096),(4000,8192))),
    UNIQUE (tenant_id,id),
    UNIQUE (tenant_id,instance_id,generation,launch_id,cluster_epoch),
    UNIQUE (tenant_id,operation_id),
    FOREIGN KEY (tenant_id,project_id,instance_id,workspace_id)
        REFERENCES public.instances(tenant_id,project_id,id,workspace_id),
    FOREIGN KEY (tenant_id,project_id,instance_id,operation_id)
        REFERENCES public.operations(tenant_id,project_id,instance_id,id)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id,project_id,workspace_id,operation_id)
        REFERENCES public.operations(tenant_id,project_id,workspace_id,id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE quota_resource_receipts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    reservation_id uuid NOT NULL,
    quota_account_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    operation_kind text NOT NULL,
    purpose text NOT NULL CHECK (purpose IN (
        'ORDINARY_COMPUTE','INSTANCE_LIFETIME','WORKSPACE_STORAGE',
        'EXECUTION','FILE_PROCESS','FILE_CONTENT','BACKUP_ISOLATED_COMPUTE',
        'BACKUP_RETAINED_STORAGE','BACKUP_TEMP_STORAGE','RESTORE_ISOLATED_COMPUTE',
        'RESTORE_TEMP_STORAGE','LEGACY_UNBOUND')),
    dimension text NOT NULL CHECK (dimension IN (
        'INSTANCES','CPU_MILLIS','MEMORY_MIB','WORKSPACE_GIB','EXECUTIONS',
        'BACKUP_GIB','BACKUP_TEMP_GIB','FILE_TRANSFERS','FILE_TRANSFER_BYTES')),
    unit text NOT NULL CHECK (unit IN ('COUNT','MILLICORES','MIB','GIB','BYTES')),
    account_scope text NOT NULL CHECK (account_scope IN ('TENANT','PROJECT')),
    account_project_id uuid,
    amount bigint NOT NULL CHECK (amount>0),
    limit_value bigint NOT NULL CHECK (limit_value>=0),
    account_version bigint NOT NULL CHECK (account_version>0),
    pending_value bigint NOT NULL CHECK (pending_value>=0),
    allocated_value bigint NOT NULL CHECK (allocated_value>=0),
    previous_status text CHECK (previous_status IN ('PENDING','ALLOCATED')),
    status text NOT NULL CHECK (status IN ('PENDING','ALLOCATED','RELEASED')),
    history_start text NOT NULL CHECK (history_start IN ('CAPTURED','LEGACY_UNBOUND')),
    captured_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((account_scope='TENANT' AND account_project_id IS NULL)
        OR (account_scope='PROJECT' AND account_project_id IS NOT NULL AND account_project_id=project_id)),
    CHECK (unit=CASE dimension WHEN 'CPU_MILLIS' THEN 'MILLICORES'
        WHEN 'MEMORY_MIB' THEN 'MIB' WHEN 'FILE_TRANSFER_BYTES' THEN 'BYTES'
        WHEN 'WORKSPACE_GIB' THEN 'GIB' WHEN 'BACKUP_GIB' THEN 'GIB'
        WHEN 'BACKUP_TEMP_GIB' THEN 'GIB' ELSE 'COUNT' END),
    CHECK (pending_value::numeric+allocated_value::numeric<=limit_value::numeric),
    CHECK ((status='PENDING' AND previous_status IS NULL AND history_start='CAPTURED')
        OR (status='ALLOCATED' AND previous_status='PENDING')
        OR (status='RELEASED' AND previous_status IN ('PENDING','ALLOCATED'))),
    UNIQUE (tenant_id,id),
    UNIQUE (tenant_id,reservation_id,status),
    FOREIGN KEY (tenant_id,reservation_id) REFERENCES public.quota_reservations(tenant_id,id),
    FOREIGN KEY (tenant_id,quota_account_id) REFERENCES public.quota_accounts(tenant_id,id),
    FOREIGN KEY (tenant_id,project_id,operation_id) REFERENCES public.operations(tenant_id,project_id,id),
    FOREIGN KEY (tenant_id,account_project_id) REFERENCES public.projects(tenant_id,id)
);
CREATE INDEX quota_resource_receipts_resource_page
    ON public.quota_resource_receipts(tenant_id,project_id,resource_id,captured_at,id);
CREATE INDEX quota_resource_receipts_operation
    ON public.quota_resource_receipts(tenant_id,operation_id,reservation_id,status);

CREATE TABLE launch_quota_bindings (
    tenant_id uuid NOT NULL,
    reservation_id uuid NOT NULL,
    contract_id uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,reservation_id),
    FOREIGN KEY (tenant_id,reservation_id) REFERENCES public.quota_reservations(tenant_id,id),
    FOREIGN KEY (tenant_id,contract_id) REFERENCES public.launch_resource_contracts(tenant_id,id)
);
CREATE INDEX launch_quota_bindings_contract
    ON public.launch_quota_bindings(tenant_id,contract_id,reservation_id);

DO $resource$
DECLARE tab text;
BEGIN
    FOREACH tab IN ARRAY ARRAY['launch_resource_contracts','quota_resource_receipts',
        'launch_quota_bindings','quota_resource_legacy_baseline'] LOOP
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);
        EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
        EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.sandbox_current_tenant_id()) WITH CHECK(tenant_id=public.sandbox_current_tenant_id())',tab);
        EXECUTE format('CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.sandbox_prevent_audit_mutation()',tab);
        EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',tab);
    END LOOP;
END
$resource$;
-- The owner-created baseline is permanently closed after its one migration copy.
CREATE TRIGGER baseline_closed BEFORE INSERT ON public.quota_resource_legacy_baseline
    FOR EACH ROW EXECUTE FUNCTION public.sandbox_prevent_audit_mutation();

CREATE FUNCTION sandbox_guard_quota_resource_identity() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $resource$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'quota accounting identities are retained' USING ERRCODE='23514';
    END IF;
    IF TG_TABLE_NAME='quota_accounts' THEN
        IF (NEW.id,NEW.tenant_id,NEW.project_id,NEW.dimension)
            IS DISTINCT FROM (OLD.id,OLD.tenant_id,OLD.project_id,OLD.dimension) THEN
            RAISE EXCEPTION 'quota account scope and unit are immutable' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP='INSERT' THEN
        IF NEW.status<>'PENDING' OR NEW.released_at IS NOT NULL THEN
            RAISE EXCEPTION 'new quota reservation must start pending' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    IF (NEW.id,NEW.tenant_id,NEW.project_id,NEW.quota_account_id,NEW.operation_id,
            NEW.resource_id,NEW.amount,NEW.created_at)
        IS DISTINCT FROM (OLD.id,OLD.tenant_id,OLD.project_id,OLD.quota_account_id,
            OLD.operation_id,OLD.resource_id,OLD.amount,OLD.created_at) THEN
        RAISE EXCEPTION 'quota reservation origin and amount are immutable' USING ERRCODE='23514';
    END IF;
    IF NEW.status IS NOT DISTINCT FROM OLD.status THEN
        IF NEW.released_at IS DISTINCT FROM OLD.released_at THEN
            RAISE EXCEPTION 'quota release time is immutable' USING ERRCODE='23514';
        END IF;
    ELSIF NOT ((OLD.status='PENDING' AND NEW.status IN ('ALLOCATED','RELEASED'))
        OR (OLD.status='ALLOCATED' AND NEW.status='RELEASED')) THEN
        RAISE EXCEPTION 'quota reservation state cannot regress' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END
$resource$;
CREATE TRIGGER quota_resource_identity_guard BEFORE INSERT OR UPDATE OR DELETE
    ON public.quota_reservations FOR EACH ROW
    EXECUTE FUNCTION public.sandbox_guard_quota_resource_identity();
CREATE TRIGGER quota_account_resource_identity_guard BEFORE UPDATE OR DELETE
    ON public.quota_accounts FOR EACH ROW
    EXECUTE FUNCTION public.sandbox_guard_quota_resource_identity();

CREATE FUNCTION sandbox_capture_quota_resource() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $resource$
DECLARE
    account public.quota_accounts;
    origin public.operations;
    selected_purpose text;
    selected_unit text;
    historical boolean;
    previous text;
BEGIN
    IF TG_OP='UPDATE' AND NEW.status IS NOT DISTINCT FROM OLD.status THEN RETURN NEW; END IF;
    SELECT * INTO account FROM public.quota_accounts
        WHERE tenant_id=NEW.tenant_id AND id=NEW.quota_account_id;
    SELECT * INTO origin FROM public.operations
        WHERE tenant_id=NEW.tenant_id AND project_id=NEW.project_id AND id=NEW.operation_id;
    IF account.id IS NULL OR origin.id IS NULL
        OR (account.project_id IS NOT NULL AND account.project_id<>NEW.project_id) THEN
        RAISE EXCEPTION 'quota accounting requires exact scoped origin' USING ERRCODE='23514';
    END IF;
    SELECT EXISTS(SELECT 1 FROM public.quota_resource_legacy_baseline
        WHERE tenant_id=NEW.tenant_id AND reservation_id=NEW.id) INTO historical;
    selected_purpose:=CASE
        WHEN account.dimension IN ('CPU_MILLIS','MEMORY_MIB') AND origin.kind IN ('CREATE','START','RESTART')
            AND origin.instance_id=NEW.resource_id THEN 'ORDINARY_COMPUTE'
        WHEN account.dimension IN ('CPU_MILLIS','MEMORY_MIB') AND origin.kind='BACKUP'
            AND EXISTS(SELECT 1 FROM public.backups b WHERE b.tenant_id=NEW.tenant_id
                AND b.project_id=NEW.project_id AND b.id=NEW.resource_id AND b.operation_id=NEW.operation_id)
            THEN 'BACKUP_ISOLATED_COMPUTE'
        WHEN account.dimension IN ('CPU_MILLIS','MEMORY_MIB') AND origin.kind='RESTORE'
            AND origin.instance_id=NEW.resource_id THEN 'RESTORE_ISOLATED_COMPUTE'
        WHEN account.dimension='INSTANCES' AND origin.kind IN ('CREATE','RESTORE')
            AND origin.instance_id=NEW.resource_id THEN 'INSTANCE_LIFETIME'
        WHEN account.dimension='WORKSPACE_GIB' AND origin.kind IN ('CREATE','RESTORE')
            AND origin.workspace_id=NEW.resource_id THEN 'WORKSPACE_STORAGE'
        WHEN account.dimension='EXECUTIONS' AND origin.kind='EXECUTE'
            AND origin.instance_id=NEW.resource_id THEN 'EXECUTION'
        WHEN account.dimension='FILE_TRANSFERS' AND origin.kind='FILE_TRANSFER'
            AND origin.instance_id=NEW.resource_id THEN 'FILE_PROCESS'
        WHEN account.dimension='FILE_TRANSFER_BYTES' AND origin.kind='FILE_TRANSFER'
            AND origin.instance_id=NEW.resource_id THEN 'FILE_CONTENT'
        WHEN account.dimension='BACKUP_GIB' AND origin.kind='BACKUP' THEN 'BACKUP_RETAINED_STORAGE'
        WHEN account.dimension='BACKUP_TEMP_GIB' AND origin.kind='BACKUP' THEN 'BACKUP_TEMP_STORAGE'
        WHEN account.dimension='BACKUP_TEMP_GIB' AND origin.kind='RESTORE' THEN 'RESTORE_TEMP_STORAGE'
        WHEN historical THEN 'LEGACY_UNBOUND'
        ELSE NULL END;
    IF selected_purpose IS NULL THEN
        RAISE EXCEPTION 'unsupported new quota resource origin' USING ERRCODE='23514';
    END IF;
    selected_unit:=CASE account.dimension
        WHEN 'CPU_MILLIS' THEN 'MILLICORES' WHEN 'MEMORY_MIB' THEN 'MIB'
        WHEN 'FILE_TRANSFER_BYTES' THEN 'BYTES'
        WHEN 'WORKSPACE_GIB' THEN 'GIB' WHEN 'BACKUP_GIB' THEN 'GIB'
        WHEN 'BACKUP_TEMP_GIB' THEN 'GIB' ELSE 'COUNT' END;
    IF TG_OP='UPDATE' THEN previous:=OLD.status; END IF;
    INSERT INTO public.quota_resource_receipts(tenant_id,project_id,reservation_id,
        quota_account_id,operation_id,resource_id,operation_kind,purpose,dimension,unit,
        account_scope,account_project_id,amount,limit_value,account_version,pending_value,
        allocated_value,previous_status,status,history_start)
    VALUES(NEW.tenant_id,NEW.project_id,NEW.id,NEW.quota_account_id,NEW.operation_id,
        NEW.resource_id,origin.kind,selected_purpose,account.dimension,selected_unit,
        CASE WHEN account.project_id IS NULL THEN 'TENANT' ELSE 'PROJECT' END,
        account.project_id,NEW.amount,account.limit_value,account.version,account.pending,
        account.allocated,previous,NEW.status,CASE WHEN historical THEN 'LEGACY_UNBOUND' ELSE 'CAPTURED' END);
    RETURN NEW;
END
$resource$;
CREATE TRIGGER quota_resource_capture AFTER INSERT OR UPDATE OF status
    ON public.quota_reservations FOR EACH ROW
    EXECUTE FUNCTION public.sandbox_capture_quota_resource();

-- The launch transition, rather than a later quota query, supplies identity.
-- CREATE has not inserted its operation yet; the scoped operation FKs above are
-- deferred. RESTORE creates a STOPPED target and has an independent quota purpose.
CREATE FUNCTION sandbox_capture_launch_resource() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $resource$
BEGIN
    IF TG_OP='UPDATE' AND (NEW.runtime_generation,NEW.launch_id,NEW.cluster_epoch)
        IS NOT DISTINCT FROM (OLD.runtime_generation,OLD.launch_id,OLD.cluster_epoch) THEN
        RETURN NEW;
    END IF;
    IF NEW.desired_state<>'RUNNING' THEN RETURN NEW; END IF;
    IF NEW.active_operation_id IS NULL
        OR (TG_OP='INSERT' AND NEW.runtime_generation<>1) THEN
        RAISE EXCEPTION 'new compute launch requires originating operation' USING ERRCODE='23514';
    END IF;
    IF TG_OP='UPDATE' AND (NEW.runtime_generation::numeric<>OLD.runtime_generation::numeric+1
        OR NEW.launch_id=OLD.launch_id) THEN
        RAISE EXCEPTION 'new compute launch requires next generation and new launch identity' USING ERRCODE='23514';
    END IF;
    INSERT INTO public.launch_resource_contracts(tenant_id,project_id,instance_id,
        workspace_id,generation,launch_id,cluster_epoch,operation_id,cpu_millis,memory_mib)
    VALUES(NEW.tenant_id,NEW.project_id,NEW.id,NEW.workspace_id,NEW.runtime_generation,
        NEW.launch_id,NEW.cluster_epoch,NEW.active_operation_id,NEW.cpu_millis,NEW.memory_mib);
    RETURN NEW;
END
$resource$;
CREATE TRIGGER launch_resource_capture AFTER INSERT OR UPDATE OF runtime_generation,launch_id,cluster_epoch
    ON public.instances FOR EACH ROW EXECUTE FUNCTION public.sandbox_capture_launch_resource();

CREATE FUNCTION sandbox_bind_launch_quota() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $resource$
DECLARE
    contract public.launch_resource_contracts;
    origin public.operations;
    instance public.instances;
    selected_operation uuid;
    selected_tenant uuid;
    row_count bigint;
    matching_count bigint;
    cpu_tenant_count bigint;
    cpu_project_count bigint;
    memory_tenant_count bigint;
    memory_project_count bigint;
    previous_tenant text:=current_setting('app.tenant_id',true);
BEGIN
    selected_tenant:=NEW.tenant_id;
    PERFORM set_config('app.tenant_id',selected_tenant::text,true);
    IF TG_TABLE_NAME='quota_reservations' THEN
        SELECT * INTO origin FROM public.operations
            WHERE tenant_id=NEW.tenant_id AND id=NEW.operation_id;
        IF origin.kind NOT IN ('CREATE','START','RESTART')
            OR NOT EXISTS(SELECT 1 FROM public.quota_resource_receipts r
                WHERE r.tenant_id=NEW.tenant_id AND r.reservation_id=NEW.id
                    AND r.status='PENDING' AND r.purpose='ORDINARY_COMPUTE') THEN
            PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
            RETURN NEW;
        END IF;
        selected_operation:=NEW.operation_id;
    ELSE
        selected_operation:=NEW.operation_id;
    END IF;
    SELECT * INTO contract FROM public.launch_resource_contracts
        WHERE tenant_id=selected_tenant AND operation_id=selected_operation;
    IF contract.id IS NULL THEN
        RAISE EXCEPTION 'ordinary compute quota requires a captured new launch transition' USING ERRCODE='23514';
    END IF;
    SELECT * INTO origin FROM public.operations
        WHERE tenant_id=contract.tenant_id AND project_id=contract.project_id AND id=contract.operation_id;
    SELECT * INTO instance FROM public.instances
        WHERE tenant_id=contract.tenant_id AND project_id=contract.project_id AND id=contract.instance_id;
    IF origin.id IS NULL OR origin.kind NOT IN ('CREATE','START','RESTART')
        OR origin.instance_id IS DISTINCT FROM contract.instance_id
        OR origin.workspace_id IS DISTINCT FROM contract.workspace_id
        OR instance.id IS NULL OR instance.desired_state<>'RUNNING'
        OR (instance.workspace_id,instance.runtime_generation,instance.launch_id,
            instance.cluster_epoch,instance.active_operation_id,instance.cpu_millis,instance.memory_mib)
            IS DISTINCT FROM (contract.workspace_id,contract.generation,contract.launch_id,
                contract.cluster_epoch,contract.operation_id,contract.cpu_millis,contract.memory_mib)
        OR (origin.kind='CREATE' AND contract.generation<>1)
        OR (origin.kind='START' AND contract.generation<=1)
        OR (origin.kind='RESTART' AND origin.restart_generation IS DISTINCT FROM contract.generation) THEN
        RAISE EXCEPTION 'compute quota must bind the exact committed new launch and operation' USING ERRCODE='23514';
    END IF;
    -- Read the immediate PENDING snapshots, including intermediate transitions
    -- within this transaction. Do not reconstruct them from final account totals.
    SELECT count(*),
        count(*) FILTER (WHERE r.project_id=contract.project_id
            AND r.resource_id=contract.instance_id AND r.history_start='CAPTURED'
            AND ((r.dimension='CPU_MILLIS' AND r.amount=contract.cpu_millis AND r.unit='MILLICORES')
                OR (r.dimension='MEMORY_MIB' AND r.amount=contract.memory_mib AND r.unit='MIB'))),
        count(*) FILTER (WHERE r.dimension='CPU_MILLIS' AND r.account_scope='TENANT'),
        count(*) FILTER (WHERE r.dimension='CPU_MILLIS' AND r.account_scope='PROJECT'),
        count(*) FILTER (WHERE r.dimension='MEMORY_MIB' AND r.account_scope='TENANT'),
        count(*) FILTER (WHERE r.dimension='MEMORY_MIB' AND r.account_scope='PROJECT')
    INTO row_count,matching_count,cpu_tenant_count,cpu_project_count,memory_tenant_count,memory_project_count
    FROM public.quota_resource_receipts r WHERE r.tenant_id=contract.tenant_id
        AND r.operation_id=contract.operation_id AND r.status='PENDING' AND r.purpose='ORDINARY_COMPUTE';
    IF row_count<>4 OR matching_count<>4 OR cpu_tenant_count<>1 OR cpu_project_count<>1
        OR memory_tenant_count<>1 OR memory_project_count<>1 THEN
        RAISE EXCEPTION 'new compute launch requires exact CPU and memory in both quota scopes' USING ERRCODE='23514';
    END IF;
    INSERT INTO public.launch_quota_bindings(tenant_id,reservation_id,contract_id)
        SELECT r.tenant_id,r.reservation_id,contract.id FROM public.quota_resource_receipts r
        WHERE r.tenant_id=contract.tenant_id AND r.operation_id=contract.operation_id
            AND r.status='PENDING' AND r.purpose='ORDINARY_COMPUTE'
        ON CONFLICT (tenant_id,reservation_id) DO NOTHING;
    IF (SELECT count(*) FROM public.launch_quota_bindings b
        JOIN public.quota_resource_receipts r ON r.tenant_id=b.tenant_id AND r.reservation_id=b.reservation_id
        WHERE r.tenant_id=contract.tenant_id AND r.operation_id=contract.operation_id
            AND r.status='PENDING' AND r.purpose='ORDINARY_COMPUTE' AND b.contract_id=contract.id)<>4 THEN
        RAISE EXCEPTION 'compute reservation cannot move between launch contracts' USING ERRCODE='23514';
    END IF;
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
    RETURN NEW;
EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
    RAISE;
END
$resource$;
CREATE CONSTRAINT TRIGGER launch_resource_quota_complete AFTER INSERT ON public.launch_resource_contracts
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.sandbox_bind_launch_quota();
CREATE CONSTRAINT TRIGGER quota_resource_launch_binding AFTER INSERT ON public.quota_reservations
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.sandbox_bind_launch_quota();

-- A reservation remains linked to its original launch after RESTART changes
-- instances. These are read-only lookups: no quota -> workspace/instance lock.
-- Other purposes retain their existing process, object and backup proof guards;
-- their status receipts never assert ordinary-VM physical resource release.
CREATE FUNCTION sandbox_guard_compute_quota_release() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $resource$
DECLARE
    contract public.launch_resource_contracts;
    previous_tenant text:=current_setting('app.tenant_id',true);
BEGIN
    PERFORM set_config('app.tenant_id',NEW.tenant_id::text,true);
    IF NEW.status<>'RELEASED' OR OLD.status='RELEASED' THEN
        PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
        RETURN NEW;
    END IF;
    IF NOT EXISTS(SELECT 1 FROM public.quota_resource_receipts r
        WHERE r.tenant_id=NEW.tenant_id AND r.reservation_id=NEW.id
            AND r.status='RELEASED' AND r.purpose='ORDINARY_COMPUTE') THEN
        PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
        RETURN NEW;
    END IF;
    IF EXISTS(SELECT 1 FROM public.quota_resource_legacy_baseline b
        WHERE b.tenant_id=NEW.tenant_id AND b.reservation_id=NEW.id) THEN
        PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
        RETURN NEW;
    END IF;
    SELECT c.* INTO contract FROM public.launch_quota_bindings b
        JOIN public.launch_resource_contracts c ON c.tenant_id=b.tenant_id AND c.id=b.contract_id
        WHERE b.tenant_id=NEW.tenant_id AND b.reservation_id=NEW.id;
    IF contract.id IS NULL OR NOT (
        EXISTS(SELECT 1 FROM public.local_termination_proofs p
            JOIN public.termination_cleanup_receipts cleanup ON cleanup.tenant_id=p.tenant_id AND cleanup.proof_id=p.id
            WHERE p.tenant_id=contract.tenant_id AND p.project_id=contract.project_id
                AND p.instance_id=contract.instance_id AND p.workspace_id=contract.workspace_id
                AND p.generation=contract.generation AND p.launch_id=contract.launch_id
                AND p.cluster_epoch=contract.cluster_epoch AND cleanup.old_pod_uid=p.pod_uid)
        OR EXISTS(SELECT 1 FROM public.never_authorized_closures closure
            WHERE closure.tenant_id=contract.tenant_id AND closure.project_id=contract.project_id
                AND closure.instance_id=contract.instance_id AND closure.workspace_id=contract.workspace_id
                AND closure.generation=contract.generation AND closure.launch_id=contract.launch_id
                AND closure.cluster_epoch=contract.cluster_epoch
                AND public.sandbox_never_authorized(contract.tenant_id,contract.instance_id,
                    contract.workspace_id,contract.generation,contract.launch_id,contract.cluster_epoch,closure.id))) THEN
        RAISE EXCEPTION 'compute quota release requires the original launch trusted closure and cleanup' USING ERRCODE='23514';
    END IF;
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
    RETURN NEW;
EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('app.tenant_id',COALESCE(previous_tenant,''),true);
    RAISE;
END
$resource$;
CREATE CONSTRAINT TRIGGER compute_quota_release_proof AFTER UPDATE OF status ON public.quota_reservations
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.sandbox_guard_compute_quota_release();

REVOKE ALL ON FUNCTION public.sandbox_guard_quota_resource_identity(),
    public.sandbox_capture_quota_resource(),public.sandbox_capture_launch_resource(),
    public.sandbox_bind_launch_quota(),public.sandbox_guard_compute_quota_release() FROM PUBLIC;
