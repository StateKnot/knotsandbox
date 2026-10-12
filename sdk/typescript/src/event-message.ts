import { EventStreamError, UUID, object, code, fail } from "./sse.ts";
import type { Frame } from "./sse.js";
import type { EventStreamMessage } from "./events.js";
import type { components } from "./schema.js";
type EventRecord = components["schemas"]["EventRecord"];

export function decodeEventStreamMessage(frame: Frame, tenantId: string, projectId: string): EventStreamMessage {
  let value: unknown;
  try { value = JSON.parse(frame.data); } catch { throw fail(); }
  if (!object(value)) throw fail();
  if (frame.event === "stream.error") {
    if (frame.id !== undefined || !code(value.code) || typeof value.retryable !== "boolean" || typeof value.request_id !== "string" || !UUID.test(value.request_id)) throw fail();
    throw new EventStreamError(value.code, value.retryable, undefined, value.request_id);
  }
  if (!frame.id || typeof value.sequence !== "string" || !/^(0|[1-9][0-9]{0,18})$/.test(value.sequence) || BigInt(value.sequence) > 9223372036854775807n) throw fail();
  if (frame.event === "stream.checkpoint") return { type: frame.event, cursor: frame.id, sequence: value.sequence };
  const e = value.event;
  if (frame.event !== "domain.event" || value.sequence === "0" || !object(e) ||
      ![e.id, e.tenant_id, e.project_id, e.aggregate_id, e.request_id].every(v => typeof v === "string" && UUID.test(v)) ||
      String(e.tenant_id).toLowerCase() !== tenantId.toLowerCase() || String(e.project_id).toLowerCase() !== projectId.toLowerCase() ||
      !(e.operation_id === null || typeof e.operation_id === "string" && UUID.test(e.operation_id)) ||
      typeof e.event_type !== "string" || e.event_type.length > 256 ||
      typeof e.aggregate_version !== "number" || !Number.isSafeInteger(e.aggregate_version) || e.aggregate_version < 1 ||
      typeof e.schema_version !== "number" || !Number.isSafeInteger(e.schema_version) || e.schema_version < 1 ||
      typeof e.occurred_at !== "string" || !Number.isFinite(Date.parse(e.occurred_at))) throw fail();
  return { type: frame.event, cursor: frame.id, sequence: value.sequence, event: e as EventRecord };
}
