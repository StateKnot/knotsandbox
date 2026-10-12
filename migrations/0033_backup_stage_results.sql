-- A container's reported exit is diagnostic data, never a VM-death proof.
-- Immutable per-attempt results let trusted cleanup finish failed SEAL jobs
-- without treating an absent or unverifiable vault as a successful backup.
CREATE TABLE backup_stage_results (
 attempt_id uuid PRIMARY KEY,
 tenant_id uuid NOT NULL,
 backup_id uuid NOT NULL,
 exit_code integer NOT NULL CHECK (exit_code BETWEEN -2147483648 AND 2147483647),
 finished_at timestamptz NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,attempt_id),
 FOREIGN KEY(tenant_id,backup_id,attempt_id)
   REFERENCES backup_attempts(tenant_id,backup_id,id)
);
ALTER TABLE backup_stage_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE backup_stage_results FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON backup_stage_results
 USING(tenant_id=public.sandbox_current_tenant_id())
 WITH CHECK(tenant_id=public.sandbox_current_tenant_id());
CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON backup_stage_results
 FOR EACH ROW EXECUTE FUNCTION sandbox_prevent_audit_mutation();
REVOKE ALL ON backup_stage_results FROM PUBLIC;
