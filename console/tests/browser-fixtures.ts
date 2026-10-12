import { readFileSync } from "node:fs";
export const tenant = "00000000-0000-4000-8000-000000000001",
  project = "00000000-0000-4000-8000-000000000002",
  instance = "00000000-0000-4000-8000-000000000003",
  principal = "00000000-0000-4000-8000-000000000004";
export const now = new Date().toISOString();
export const session = {
  tenant_id: tenant,
  principal_id: principal,
  csrf_token: "a".repeat(43),
  absolute_expires_at: now,
  idle_expires_at: now,
};
export const resource = {
  id: instance,
  tenant_id: tenant,
  project_id: project,
  name: "production-workspace",
  template_version_id: project,
  security_policy_version_id: project,
  workspace_id: project,
  desired_state: "RUNNING",
  observed_state: "UNKNOWN",
  spec_version: 7,
  runtime_generation: 1,
  active_operation_id: null,
  cpu_millis: 1000,
  memory_mib: 2048,
  compute_lease_id: project,
  compute_lease_version: 1,
  compute_lease_started_at: now,
  compute_lease_expires_at: now,
  stop_reason: null,
  stop_accepted_at: null,
  observed_at: null,
  slot_held: true,
  created_at: now,
  updated_at: now,
};
export const caps = {
  api_version: "v1",
  build_version: "contract-test",
  project_id: project,
  api_features: {
    instance_lifecycle: true,
    instance_details: true,
    instance_security: true,
    runtime_metrics: false,
    file_transfer: false,
    health_diagnostics: false,
    control_plane_diagnoses: true,
    automation_notifications: false,
  },
  flavors: [{ name: "cpu1-mem2", cpu_millis: 1000, memory_mib: 2048 }],
  limits: {},
  runtime_certification: "NOT_ASSERTED",
};
export const detail = {
  instance: resource,
  as_of: now,
  workspace: {
    id: project,
    size_gib: 20,
    status: "IN_USE",
    retention_until: null,
    delete_requested_at: null,
    deleted_at: null,
    updated_at: now,
  },
  template: {
    id: project,
    name: "approved-template",
    version: 1,
    status: "APPROVED",
  },
  security_policy: {
    id: project,
    name: "restricted-network",
    version: 1,
    status: "APPROVED",
  },
  compute_lease: { state: "ACTIVE", remaining_seconds: 1200 },
  lifecycle_observation: { status: "UNKNOWN" },
  launch_readiness: {
    source: "LIFECYCLE_RECONCILER",
    status: "UNVERIFIED",
    verified_at: null,
    verified_generation: null,
    matches_current_launch: false,
    matches_current_cluster_epoch: false,
  },
  runtime_health: {
    status: "UNKNOWN",
    reason: "CONTINUOUS_OBSERVATION_UNAVAILABLE",
  },
  active_execution: { state: "NONE", resource: null },
};
export const security = {
  ...JSON.parse(
    readFileSync(
      new URL(
        "../../tests/fixtures/security/instance-security.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ),
  instance_id: instance,
  project_id: project,
  spec_version: resource.spec_version,
  runtime_generation: resource.runtime_generation,
  as_of: now,
};
