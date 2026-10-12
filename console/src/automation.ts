import { ApiFailure, UUID } from "./api.ts";
import type { Schema, Session } from "./api.ts";

const encoder = new TextEncoder();
const ACTIONS = [
  "START",
  "STOP",
  "RESTART",
  "DELETE",
  "RENEW",
  "EXECUTE",
  "BACKUP",
];
const TRIGGERS = ["ONCE", "CRON_UTC", "EVENT"];
const NIL = "00000000-0000-0000-0000-000000000000";
export type AutomationContract = NonNullable<
  Schema["Capabilities"]["automation"]
>;

// A recognized creation contract is deployment data, never user authority or
// evidence that a worker/cloud runtime has been certified. Keep historic
// metadata and original request reconciliation independent from this parser.
export function automationContract(value: unknown): AutomationContract | null {
  try {
    const v = object(
      value,
      "schema_version supported_actions supported_triggers clock time_zone cron missed_run_policy skipped_runs_consume_budget known_automated_events_retrigger outcome_unknown_policy limits assurance",
    );
    const choices = (value: unknown, known: string[]) =>
      Array.isArray(value) &&
      value.length === known.length &&
      value.every(
        (entry) => typeof entry === "string" && known.includes(entry),
      ) &&
      new Set(value).size === value.length;
    const cron = object(
      v.cron,
      "field_count seconds_field year_field day_of_month_and_week",
    );
    const limits = object(
      v.limits,
      "run_budget minimum_interval_seconds grace_seconds delegation_lifetime_seconds live_policies_per_project live_policies_per_tenant name_bytes_max cron_expression_bytes_max event_type_bytes_max",
    );
    const range = (
      value: unknown,
      minimum: number,
      maximum: number,
      exclusive = false,
    ) => {
      const field = exclusive ? "exclusive_minimum" : "minimum";
      const r = object(value, `${field} maximum`);
      return r[field] === minimum && r.maximum === maximum;
    };
    if (
      v.schema_version !== 1 ||
      !choices(v.supported_actions, ACTIONS) ||
      !choices(v.supported_triggers, TRIGGERS) ||
      v.clock !== "POSTGRESQL" ||
      v.time_zone !== "UTC" ||
      cron.field_count !== 7 ||
      cron.seconds_field !== "0" ||
      cron.year_field !== "*" ||
      cron.day_of_month_and_week !== "INTERSECTION" ||
      v.missed_run_policy !== "AT_MOST_ONE_WITHIN_GRACE_ELSE_SKIP_SPAN" ||
      v.skipped_runs_consume_budget !== true ||
      v.known_automated_events_retrigger !== false ||
      v.outcome_unknown_policy !== "RECONCILE_ORIGINAL_ONLY" ||
      v.assurance !== "API_CONTRACT_ONLY" ||
      !range(limits.run_budget, 1, 10000) ||
      !range(limits.minimum_interval_seconds, 60, 86400) ||
      !range(limits.grace_seconds, 1, 3600) ||
      !range(limits.delegation_lifetime_seconds, 60, 31622400, true) ||
      limits.live_policies_per_project !== 100 ||
      limits.live_policies_per_tenant !== 1000 ||
      limits.name_bytes_max !== 128 ||
      limits.cron_expression_bytes_max !== 128 ||
      limits.event_type_bytes_max !== 128
    )
      return null;
    return v as unknown as AutomationContract;
  } catch {
    return null;
  }
}

export function automationSupports(
  contract: AutomationContract,
  action: string,
  trigger: string,
): boolean {
  return (
    (contract.supported_actions as string[]).includes(action) &&
    (contract.supported_triggers as string[]).includes(trigger)
  );
}
function invalid(): never {
  throw new ApiFailure("INVALID_AUTOMATION_INPUT");
}
function uuid(value: unknown): value is string {
  return typeof value === "string" && UUID.test(value) && value !== NIL;
}
export function isAutomationId(value: unknown): value is string {
  return uuid(value);
}
function text(form: FormData, name: string): string {
  const values = form.getAll(name);
  if (values.length !== 1 || typeof values[0] !== "string") invalid();
  return values[0];
}
function clean(value: string): boolean {
  // Rust serde rejects unpaired UTF-16 surrogates; do not silently encode U+FFFD.
  for (let i = 0; i < value.length; i++) {
    const n = value.charCodeAt(i);
    if (n >= 0xd800 && n <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
    } else if (n >= 0xdc00 && n <= 0xdfff) return false;
  }
  return !value.includes("\0");
}
function boundedJson(value: unknown): void {
  if (encoder.encode(JSON.stringify(value)).length > 65536) invalid();
}
export function strictInteger(value: string, min: number, max: number): number {
  if (
    !Number.isSafeInteger(min) ||
    !Number.isSafeInteger(max) ||
    min > max ||
    !/^(0|[1-9][0-9]*)$/.test(value)
  )
    invalid();
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < min || n > max) invalid();
  return n;
}
function utc(value: string): bigint {
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z$/.exec(
      value,
    );
  if (!match) invalid();
  const date = new Date(value),
    parts = match.slice(1, 7).map(Number);
  if (
    !Number.isFinite(date.getTime()) ||
    date.getUTCFullYear() !== parts[0] ||
    date.getUTCMonth() + 1 !== parts[1] ||
    date.getUTCDate() !== parts[2] ||
    date.getUTCHours() !== parts[3] ||
    date.getUTCMinutes() !== parts[4] ||
    date.getUTCSeconds() !== parts[5]
  )
    invalid();
  return (
    BigInt(date.getTime()) * 1000n +
    BigInt((match[7] ?? "").padEnd(6, "0").slice(3))
  );
}
function json(value: string): unknown {
  if (encoder.encode(value).length > 65536 || !clean(value)) invalid();
  try {
    return JSON.parse(value);
  } catch {
    return invalid();
  }
}
function environment(value: string): Record<string, string> {
  // A string-only map parser preserves duplicate-key rejection, including escaped keys.
  if (encoder.encode(value).length > 65536 || !clean(value)) invalid();
  let offset = 0;
  const whitespace = () => {
    while (/[\t\n\r ]/.test(value[offset] ?? "x")) offset++;
  };
  const token = () => {
    whitespace();
    const match =
      /"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/y;
    match.lastIndex = offset;
    const found = match.exec(value);
    if (!found) invalid();
    offset = match.lastIndex;
    const result = JSON.parse(found[0]) as string;
    if (!clean(result)) invalid();
    return result;
  };
  const result: Record<string, string> = Object.create(null);
  whitespace();
  if (value[offset++] !== "{") invalid();
  whitespace();
  if (value[offset] !== "}") {
    while (true) {
      const key = token();
      whitespace();
      if (value[offset++] !== ":") invalid();
      const entry = token();
      if (
        Object.hasOwn(result, key) ||
        !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(key) ||
        key.startsWith("SANDBOX_") ||
        ["PATH", "HOME", "TMPDIR"].includes(key) ||
        encoder.encode(entry).length > 4096
      )
        invalid();
      result[key] = entry;
      whitespace();
      if (value[offset] === "}") break;
      if (value[offset++] !== ",") invalid();
    }
  }
  offset++;
  whitespace();
  const entries = Object.entries(result);
  if (
    offset !== value.length ||
    entries.length > 64 ||
    entries.reduce(
      (size, [key, entry]) =>
        size + encoder.encode(key).length + encoder.encode(entry).length + 2,
      0,
    ) > 16384
  )
    invalid();
  return result;
}
export function buildCreateAutomation(
  form: FormData,
  contract: AutomationContract,
  maxTtlSeconds: number,
  now = Date.now(),
): Schema["CreateAutomation"] {
  if (
    !automationContract(contract) ||
    !Number.isSafeInteger(maxTtlSeconds) ||
    maxTtlSeconds < 60 ||
    !Number.isSafeInteger(now)
  )
    invalid();
  const name = text(form, "name"),
    kind = text(form, "action_kind");
  const limits = contract.limits;
  if (!automationSupports(contract, kind, text(form, "trigger_kind")))
    invalid();
  if (
    !name.trim() ||
    encoder.encode(name).length > limits.name_bytes_max ||
    !clean(name) ||
    /[\u0000-\u001f\u007f-\u009f]/.test(name)
  )
    invalid();
  let action: Schema["AutomationAction"];
  switch (kind) {
    case "START":
    case "RENEW":
      action = {
        kind,
        ttl_seconds: strictInteger(
          text(form, "ttl_seconds"),
          60,
          maxTtlSeconds,
        ),
      };
      break;
    case "STOP":
    case "RESTART":
    case "DELETE":
      action = { kind };
      break;
    case "EXECUTE": {
      if (
        text(form, "non_sensitive") !== "on" ||
        text(form, "hard_stop_instance") !== "on"
      )
        invalid();
      const argv = json(text(form, "argv"));
      if (
        !Array.isArray(argv) ||
        argv.length < 1 ||
        argv.length > 64 ||
        argv.some((arg) => typeof arg !== "string" || !clean(arg)) ||
        argv[0] === "" ||
        argv.reduce(
          (size: number, arg: string) => size + encoder.encode(arg).length + 1,
          0,
        ) > 65536
      )
        invalid();
      const cwd = text(form, "cwd"),
        public_env = environment(text(form, "public_env"));
      if (
        !clean(cwd) ||
        !cwd.startsWith("/") ||
        cwd.split("/").includes("..") ||
        cwd.split("/").filter((part) => part && part !== ".")[0] !== "workspace"
      )
        invalid();
      const referenceValues = form.getAll("client_reference");
      if (
        referenceValues.length > 1 ||
        (referenceValues.length === 1 && typeof referenceValues[0] !== "string")
      )
        invalid();
      const reference = (referenceValues[0] as string | undefined) ?? "";
      if (
        !clean(reference) ||
        encoder.encode(reference).length > 128 ||
        /[\u0000-\u001f\u007f-\u009f]/.test(reference)
      )
        invalid();
      const request: Schema["CreateExecution"] = {
        argv: argv as string[],
        public_env,
        cwd,
        timeout_seconds: strictInteger(text(form, "timeout_seconds"), 1, 3600),
        output_limit_bytes: strictInteger(
          text(form, "output_limit_bytes"),
          0,
          16 * 1024 * 1024,
        ),
        on_timeout: "HARD_STOP_INSTANCE",
        ...(reference ? { client_reference: reference } : {}),
      };
      // The runtime-generated UUID has this exact encoded length; this is a size check only.
      boundedJson({
        execution_id: "00000000-0000-4000-8000-000000000001",
        argv: request.argv,
        env: public_env,
        cwd,
        timeout_seconds: request.timeout_seconds,
        output_limit_bytes: request.output_limit_bytes,
      });
      action = { kind, request };
      break;
    }
    case "BACKUP": {
      const profile_id = text(form, "backup_profile_id");
      if (!uuid(profile_id)) invalid();
      action = {
        kind,
        request: {
          profile_id,
          retention_days: strictInteger(text(form, "retention_days"), 31, 3650),
        },
      };
      break;
    }
    default:
      return invalid();
  }
  const expires = text(form, "delegation_expires_at"),
    end = utc(expires),
    start = BigInt(now) * 1000n;
  if (
    end <=
      start +
        BigInt(limits.delegation_lifetime_seconds.exclusive_minimum) *
          1_000_000n ||
    end >
      start + BigInt(limits.delegation_lifetime_seconds.maximum) * 1_000_000n
  )
    invalid();
  let trigger: Schema["AutomationTrigger"];
  switch (text(form, "trigger_kind")) {
    case "ONCE": {
      const at = text(form, "once_at"),
        instant = utc(at);
      if (instant <= start || instant >= end) invalid();
      trigger = { kind: "ONCE", at };
      break;
    }
    case "CRON_UTC": {
      const input = text(form, "cron_expression");
      if (
        encoder.encode(input).length > limits.cron_expression_bytes_max ||
        /[^\x00-\x7f]/.test(input)
      )
        invalid();
      const parts = input.trim().split(/[\t\n\v\f\r ]+/);
      if (
        parts.length !== contract.cron.field_count ||
        parts[0] !== contract.cron.seconds_field ||
        parts[6] !== contract.cron.year_field ||
        parts.some((part) => !/^[A-Za-z0-9*,/?\-]+$/.test(part))
      )
        invalid();
      // Full cron grammar, next occurrence and live delegation authority remain server checks.
      trigger = { kind: "CRON_UTC", expression: parts.join(" ") };
      break;
    }
    case "EVENT": {
      const event_type = text(form, "event_type"),
        aggregate_id = text(form, "aggregate_id");
      if (
        !/^[a-z0-9._:-]+$/.test(event_type) ||
        encoder.encode(event_type).length > limits.event_type_bytes_max ||
        !uuid(aggregate_id)
      )
        invalid();
      trigger = { kind: "EVENT", event_type, aggregate_id };
      break;
    }
    default:
      return invalid();
  }
  const result: Schema["CreateAutomation"] = {
    name,
    action,
    trigger,
    delegation_expires_at: expires,
    run_budget: strictInteger(
      text(form, "run_budget"),
      limits.run_budget.minimum,
      limits.run_budget.maximum,
    ),
    minimum_interval_seconds: strictInteger(
      text(form, "minimum_interval_seconds"),
      limits.minimum_interval_seconds.minimum,
      limits.minimum_interval_seconds.maximum,
    ),
    grace_seconds: strictInteger(
      text(form, "grace_seconds"),
      limits.grace_seconds.minimum,
      limits.grace_seconds.maximum,
    ),
  };
  boundedJson(result);
  return result;
}
export function automationCreatePath(instanceId: string): string {
  if (!uuid(instanceId)) throw new ApiFailure("INVALID_INSTANCE_ID");
  return `/v1/instances/${instanceId.toLowerCase()}/automations`;
}
export function automationActionPath(
  policyId: string,
  action: "pause" | "resume" | "revoke",
): string {
  if (!uuid(policyId) || !["pause", "resume", "revoke"].includes(action))
    throw new ApiFailure("INVALID_AUTOMATION_ID");
  const paths = {
    pause: "/v1/automations/{id}/actions/pause",
    resume: "/v1/automations/{id}/actions/resume",
    revoke: "/v1/automations/{id}/actions/revoke",
  };
  return paths[action].replace("{id}", policyId.toLowerCase());
}
function object(value: unknown, keys: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid();
  const record = value as Record<string, unknown>,
    names = keys.split(" ");
  if (
    Object.keys(record).length !== names.length ||
    names.some((key) => !Object.hasOwn(record, key))
  )
    invalid();
  return record;
}
function integer(
  value: unknown,
  min: number,
  max = Number.MAX_SAFE_INTEGER,
): boolean {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= min &&
    value <= max
  );
}
function date(value: unknown): boolean {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}
function optionalDate(value: unknown): boolean {
  return value === null || date(value);
}
function optionalUuid(value: unknown): boolean {
  return value === null || uuid(value);
}
export function scopedAutomation(
  value: unknown,
  session: Session,
  projectId: string,
  instanceId: string,
  id?: string,
): Schema["Automation"] {
  const v = object(
    value,
    "id tenant_id project_id instance_id workspace_id creator_principal_id name action_kind trigger_kind scheduled_at cron_expression event_type event_aggregate_id next_due_at status version run_budget emitted_runs minimum_interval_seconds grace_seconds delegation_expires_at delegation_revoked_at created_at updated_at",
  );
  if (
    ![
      v.id,
      v.tenant_id,
      v.project_id,
      v.instance_id,
      v.workspace_id,
      v.creator_principal_id,
    ].every(uuid) ||
    v.tenant_id !== session.tenant_id ||
    v.project_id !== projectId ||
    v.instance_id !== instanceId ||
    (id !== undefined && v.id !== id) ||
    typeof v.name !== "string" ||
    !v.name ||
    encoder.encode(v.name).length > 128 ||
    !ACTIONS.includes(v.action_kind as string) ||
    !TRIGGERS.includes(v.trigger_kind as string) ||
    !["ACTIVE", "PAUSED", "REVOKED", "EXHAUSTED", "EXPIRED"].includes(
      v.status as string,
    ) ||
    !integer(v.version, 1) ||
    !integer(v.run_budget, 1, 10000) ||
    !integer(v.emitted_runs, 0, v.run_budget as number) ||
    !integer(v.minimum_interval_seconds, 60, 86400) ||
    !integer(v.grace_seconds, 1, 3600) ||
    ![v.created_at, v.updated_at, v.delegation_expires_at].every(date) ||
    ![v.scheduled_at, v.next_due_at, v.delegation_revoked_at].every(
      optionalDate,
    ) ||
    !optionalUuid(v.event_aggregate_id) ||
    !(v.cron_expression === null || typeof v.cron_expression === "string") ||
    !(v.event_type === null || typeof v.event_type === "string")
  )
    invalid();
  if (
    v.trigger_kind === "ONCE"
      ? !date(v.scheduled_at) ||
        v.cron_expression !== null ||
        v.event_type !== null ||
        v.event_aggregate_id !== null
      : v.trigger_kind === "CRON_UTC"
        ? v.scheduled_at !== null ||
          typeof v.cron_expression !== "string" ||
          v.event_type !== null ||
          v.event_aggregate_id !== null
        : v.scheduled_at !== null ||
          v.cron_expression !== null ||
          typeof v.event_type !== "string" ||
          !uuid(v.event_aggregate_id)
  )
    invalid();
  return v as unknown as Schema["Automation"];
}
export function scopedAutomationRun(
  value: unknown,
  session: Session,
  projectId: string,
  policyId: string,
  id?: string,
): Schema["AutomationRun"] {
  const v = object(
    value,
    "id tenant_id project_id automation_id version automation_version scheduled_for source_event_id source_event_sequence skipped_through operation_kind expected_resource_version expected_generation status operation_id failure_code deadline created_at updated_at completed_at",
  );
  if (
    ![v.id, v.tenant_id, v.project_id, v.automation_id].every(uuid) ||
    v.tenant_id !== session.tenant_id ||
    v.project_id !== projectId ||
    v.automation_id !== policyId ||
    (id !== undefined && v.id !== id) ||
    ![v.version, v.automation_version, v.expected_resource_version].every((n) =>
      integer(n, 1),
    ) ||
    !integer(v.expected_generation, 0) ||
    !ACTIONS.includes(v.operation_kind as string) ||
    ![
      "PENDING",
      "CLAIMED",
      "DISPATCHING",
      "SUBMITTED",
      "SUCCEEDED",
      "FAILED",
      "SKIPPED",
      "CANCELLED",
      "OUTCOME_UNKNOWN",
    ].includes(v.status as string) ||
    ![v.deadline, v.created_at, v.updated_at].every(date) ||
    ![v.scheduled_for, v.skipped_through, v.completed_at].every(optionalDate) ||
    ![v.source_event_id, v.operation_id].every(optionalUuid) ||
    !(
      v.source_event_sequence === null || integer(v.source_event_sequence, 1)
    ) ||
    !(
      v.failure_code === null ||
      (typeof v.failure_code === "string" &&
        /^[A-Z][A-Z0-9_]{0,127}$/.test(v.failure_code))
    )
  )
    invalid();
  return v as unknown as Schema["AutomationRun"];
}
