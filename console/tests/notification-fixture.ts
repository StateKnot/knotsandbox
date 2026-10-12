import {
  tenant,
  project,
  instance,
  principal,
  now,
} from "./browser-fixtures.ts";
export const notification = {
  id: "00000000-0000-4000-8000-000000000020",
  tenant_id: tenant,
  project_id: project,
  instance_id: instance,
  automation_id: "00000000-0000-4000-8000-000000000021",
  run_id: "00000000-0000-4000-8000-000000000022",
  source_event_id: "00000000-0000-4000-8000-000000000020",
  source_run_version: 3,
  source_status: "OUTCOME_UNKNOWN",
  created_at: now,
  acknowledged_at: null as string | null,
  acknowledged_by: null as string | null,
  version: 1,
};
export const acknowledgedNotification = {
  ...notification,
  version: 2,
  acknowledged_at: now,
  acknowledged_by: principal,
};
