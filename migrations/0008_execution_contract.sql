-- Typed evidence is written only after the worker validates the current Pod,
-- PVC and network policy. Historical RUNNING rows have no such evidence and
-- cannot accept new commands until observed again by the worker.
ALTER TABLE instances
    ADD COLUMN ready_generation bigint,
    ADD COLUMN ready_launch_id uuid,
    ADD COLUMN ready_pod_uid uuid,
    ADD COLUMN ready_cluster_epoch uuid,
    ADD COLUMN ready_observed_at timestamptz,
    ADD CONSTRAINT ready_evidence_complete CHECK (
        (ready_generation IS NULL AND ready_launch_id IS NULL AND ready_pod_uid IS NULL
          AND ready_cluster_epoch IS NULL AND ready_observed_at IS NULL)
        OR (ready_generation>0 AND ready_generation IS NOT NULL AND ready_launch_id IS NOT NULL
          AND ready_pod_uid IS NOT NULL AND ready_cluster_epoch IS NOT NULL AND ready_observed_at IS NOT NULL)
    );

ALTER TABLE executions
    ADD COLUMN version bigint NOT NULL DEFAULT 1 CHECK(version>0),
    ADD COLUMN cluster_epoch uuid,
    ADD COLUMN cancel_requested_at timestamptz,
    ADD COLUMN cancel_operation_id uuid,
    ADD CONSTRAINT execution_cancel_operation_scope
        FOREIGN KEY(tenant_id,project_id,instance_id,cancel_operation_id)
        REFERENCES operations(tenant_id,project_id,instance_id,id) DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT execution_cancel_evidence_complete
        CHECK ((cancel_requested_at IS NULL)=(cancel_operation_id IS NULL)),
    ADD CONSTRAINT attempted_execution_cannot_be_queued
        CHECK(status<>'QUEUED' OR dispatch_attempt_id IS NULL);

-- No historical epoch is fabricated. New execution acceptance always writes it;
-- legacy executions with no epoch cannot be dispatched by the new worker gate.
CREATE FUNCTION sandbox_preserve_execution_identity() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF (NEW.operation_id,NEW.runtime_generation,NEW.launch_id,NEW.pod_uid,NEW.cluster_epoch,
        NEW.deadline,NEW.timeout_seconds) IS DISTINCT FROM
       (OLD.operation_id,OLD.runtime_generation,OLD.launch_id,OLD.pod_uid,OLD.cluster_epoch,
        OLD.deadline,OLD.timeout_seconds) THEN
        RAISE EXCEPTION 'execution launch and deadline are immutable' USING ERRCODE='23514';
    END IF;
    IF OLD.dispatch_attempt_id IS NOT NULL AND
       (NEW.dispatch_attempt_id,NEW.dispatch_attempted_at) IS DISTINCT FROM
       (OLD.dispatch_attempt_id,OLD.dispatch_attempted_at) THEN
        RAISE EXCEPTION 'execution dispatch evidence cannot be replaced or cleared' USING ERRCODE='23514';
    END IF;
    IF OLD.dispatch_attempt_id IS NULL AND NEW.dispatch_attempt_id IS NOT NULL AND
       (OLD.status<>'QUEUED' OR NEW.status<>'DISPATCHING' OR NEW.termination_status<>'NOT_REQUESTED'
          OR NEW.cancel_requested_at IS NOT NULL) THEN
        RAISE EXCEPTION 'only an uncancelled queued execution can begin its one dispatch' USING ERRCODE='23514';
    END IF;
    IF OLD.status='OUTCOME_UNKNOWN' AND NEW.status<>'OUTCOME_UNKNOWN' THEN
        RAISE EXCEPTION 'VM termination does not resolve an unknown execution outcome' USING ERRCODE='23514';
    END IF;
    IF OLD.termination_status='CONFIRMED' AND NEW.termination_status<>'CONFIRMED' THEN
        RAISE EXCEPTION 'execution termination evidence cannot regress' USING ERRCODE='23514';
    END IF;
    NEW.version := OLD.version+1;
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END;
$$;
CREATE TRIGGER execution_dispatch_evidence_immutable BEFORE UPDATE ON executions
FOR EACH ROW EXECUTE FUNCTION sandbox_preserve_execution_identity();
REVOKE ALL ON FUNCTION sandbox_preserve_execution_identity() FROM PUBLIC;
