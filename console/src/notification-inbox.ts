import { ApiFailure, ETAG, UUID } from "./api.ts";
import type { Schema, Session } from "./api.ts";

const NIL = "00000000-0000-0000-0000-000000000000";
const FIELDS =
  "id tenant_id project_id instance_id automation_id run_id source_event_id source_run_version source_status created_at acknowledged_at acknowledged_by version".split(
    " ",
  );
function invalid(): never {
  throw new ApiFailure("INVALID_AUTOMATION_NOTIFICATION");
}
function object(value: unknown, fields: string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid();
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).length !== fields.length ||
    fields.some((key) => !Object.hasOwn(record, key))
  )
    invalid();
  return record;
}
function uuid(value: unknown): value is string {
  return (
    typeof value === "string" &&
    UUID.test(value) &&
    value !== NIL &&
    value.toLowerCase() === value
  );
}
function integer(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1;
}
function date(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

// Historical notification reads do not require a creation-contract version.
// This deployment flag never substitutes for automations:read/write authority.
export function notificationsEnabled(caps: unknown, project: string): boolean {
  if (!caps || typeof caps !== "object" || Array.isArray(caps)) return false;
  const value = caps as Record<string, unknown>;
  const features = value.api_features;
  return (
    value.project_id === project &&
    uuid(project) &&
    !!features &&
    typeof features === "object" &&
    !Array.isArray(features) &&
    (features as Record<string, unknown>).automation_notifications === true
  );
}

export function notificationId(value: unknown): value is string {
  return uuid(value);
}

export function scopedNotification(
  value: unknown,
  session: Session,
  project: string,
  instance?: string,
  id?: string,
): Schema["AutomationNotification"] {
  const row = object(value, FIELDS);
  if (
    ![
      row.id,
      row.tenant_id,
      row.project_id,
      row.instance_id,
      row.automation_id,
      row.run_id,
      row.source_event_id,
    ].every(uuid) ||
    row.tenant_id !== session.tenant_id ||
    row.project_id !== project ||
    (instance !== undefined && row.instance_id !== instance) ||
    (id !== undefined && row.id !== id) ||
    row.id !== row.source_event_id ||
    !integer(row.source_run_version) ||
    ![1, 2].includes(row.version as number) ||
    !["FAILED", "OUTCOME_UNKNOWN"].includes(row.source_status as string) ||
    !date(row.created_at) ||
    !(
      (row.version === 1 &&
        row.acknowledged_at === null &&
        row.acknowledged_by === null) ||
      (row.version === 2 &&
        date(row.acknowledged_at) &&
        uuid(row.acknowledged_by) &&
        Date.parse(row.acknowledged_at) >= Date.parse(row.created_at as string))
    )
  )
    invalid();
  return row as unknown as Schema["AutomationNotification"];
}

export function notificationPage(
  value: unknown,
  session: Session,
  project: string,
  instance?: string,
): Schema["AutomationNotificationPage"] {
  const page = object(value, ["items", "next_cursor", "cutoff"]);
  if (
    !Array.isArray(page.items) ||
    page.items.length > 20 ||
    !date(page.cutoff) ||
    !(
      page.next_cursor === null ||
      (typeof page.next_cursor === "string" &&
        page.next_cursor.length > 0 &&
        page.next_cursor.length <= 2048)
    )
  )
    invalid();
  const items = page.items.map((row) =>
    scopedNotification(row, session, project, instance),
  );
  if (new Set(items.map((row) => row.id)).size !== items.length) invalid();
  return {
    items,
    next_cursor: page.next_cursor as string | null,
    cutoff: page.cutoff,
  };
}

export function notificationEtag(
  response: Response | string | null,
  version: number,
): string {
  const value =
    response instanceof Response ? response.headers.get("etag") : response;
  if (
    !integer(version) ||
    !value ||
    !ETAG.test(value) ||
    value !== `"${version}"`
  )
    throw new ApiFailure("INVALID_NOTIFICATION_ETAG");
  return value;
}

export function notificationAckPath(id: string): string {
  if (!uuid(id)) invalid();
  return `/v1/automation-notifications/${id}/actions/acknowledge`;
}

export function notificationAckId(path: string): string | null {
  const match =
    /^\/v1\/automation-notifications\/([0-9a-f-]{36})\/actions\/acknowledge$/.exec(
      path,
    );
  return match && uuid(match[1]) ? match[1] : null;
}

export function notificationReceipt(
  value: unknown,
  session: Session,
  project: string,
  original: Schema["AutomationNotification"],
): Schema["AutomationNotificationReceipt"] {
  const receipt = object(value, ["resource", "idempotency_expires_at"]);
  const row = scopedNotification(
    receipt.resource,
    session,
    project,
    original.instance_id,
    original.id,
  );
  const immutable = [
    "automation_id",
    "run_id",
    "source_event_id",
    "source_run_version",
    "source_status",
    "created_at",
  ] as const;
  if (
    !date(receipt.idempotency_expires_at) ||
    row.acknowledged_at === null ||
    row.acknowledged_by !== session.principal_id ||
    row.version !== original.version + 1 ||
    immutable.some((key) => row[key] !== original[key])
  )
    invalid();
  return {
    resource: row,
    idempotency_expires_at: receipt.idempotency_expires_at,
  };
}
