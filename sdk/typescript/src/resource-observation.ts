import type { components } from "./schema.js";

type Accounting = components["schemas"]["ResourceAccounting"];
type Vector = components["schemas"]["PodResourceVector"];
type Overhead = components["schemas"]["PodResourceOverhead"];
const MAX_INTEGER = 9223372036854775807n;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const nonNilUuid = (value: unknown): value is string =>
  typeof value === "string" && UUID.test(value) && value !== "00000000-0000-0000-0000-000000000000";
function decimal(value: unknown): value is string {
  return typeof value === "string" && /^(0|[1-9][0-9]{0,18})$/.test(value) && BigInt(value) <= MAX_INTEGER;
}
function object(value: unknown, fields: string[]): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) &&
    Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));
}
function amounts(value: unknown, ephemeral: boolean): value is Record<string, string> {
  const fields = ["cpu_millis", "memory_bytes", ...(ephemeral ? ["ephemeral_storage_bytes"] : [])];
  return object(value, fields) && fields.every(field => decimal(value[field]));
}
function resourceVersion(value: unknown): value is string {
  return typeof value === "string" && /^[!-~]{1,256}$/.test(value);
}

/** Validate fixed evidence and precise integers without turning missing data into
 * zero. Class GET metadata does not certify an adopted admission version. */
export function validatePodResourceEvidence(data: Accounting, workspaceId?: string): void {
  const observation: unknown = data.pod_resource_observation;
  if (data.pod_resource_evidence === "NOT_CAPTURED" && observation === null) return;
  const invalid = () => { throw new Error("RESOURCE_ACCOUNTING_RESPONSE_INVALID"); };
  if (data.pod_resource_evidence !== "KUBERNETES_API_READBACK" ||
      !object(observation, ["id", "instance_id", "workspace_id", "generation", "launch_id", "cluster_epoch",
        "pod_uid", "pod_resource_version", "node_uid", "node_boot_id", "runtime_class", "workload_request",
        "workload_limit", "pod_overhead", "effective_request", "effective_limit", "source", "observed_at", "recorded_at"])) {
    invalid();
    return;
  }
  const value = observation;
  if (!["id", "instance_id", "workspace_id", "launch_id", "cluster_epoch", "pod_uid", "node_uid", "node_boot_id"]
      .every(field => nonNilUuid(value[field])) ||
      value.instance_id !== data.instance_id || value.launch_id !== data.selected_launch_id ||
      value.cluster_epoch !== data.cluster_epoch || (workspaceId !== undefined && value.workspace_id !== workspaceId) ||
      !decimal(value.generation) || value.generation === "0" || !resourceVersion(value.pod_resource_version) ||
      value.source !== "KUBERNETES_API_READBACK" ||
      ![value.observed_at, value.recorded_at].every(time => typeof time === "string" && Number.isFinite(Date.parse(time))) ||
      (data.contract !== null && (value.generation !== data.contract.generation || value.workspace_id !== data.contract.workspace_id))) {
    invalid();
  }
  const klass = value.runtime_class;
  if (!object(klass, ["uid", "resource_version", "config_sha256", "overhead"]) ||
      !nonNilUuid(klass.uid) || !resourceVersion(klass.resource_version) ||
      typeof klass.config_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(klass.config_sha256) ||
      !amounts(klass.overhead, false) || !amounts(value.pod_overhead, false) ||
      ![value.workload_request, value.workload_limit, value.effective_request, value.effective_limit].every(amount => amounts(amount, true))) {
    invalid();
    return;
  }
  const overhead = value.pod_overhead as Overhead;
  const classOverhead = klass.overhead as Overhead;
  const request = value.workload_request as Vector;
  const limit = value.workload_limit as Vector;
  if (!["1000:2147483648", "2000:4294967296", "4000:8589934592"].includes(`${request.cpu_millis}:${request.memory_bytes}`) ||
      (data.contract !== null && (!decimal(data.contract.cpu_millis) || !decimal(data.contract.memory_mib) ||
        request.cpu_millis !== data.contract.cpu_millis ||
        BigInt(request.memory_bytes) !== BigInt(data.contract.memory_mib) * 1048576n))) invalid();
  for (const field of ["cpu_millis", "memory_bytes", "ephemeral_storage_bytes"] as const) {
    if (request[field] === "0" || request[field] !== limit[field]) invalid();
    const extra = field === "ephemeral_storage_bytes" ? 0n : BigInt(overhead[field]);
    if (field !== "ephemeral_storage_bytes" && overhead[field] !== classOverhead[field]) invalid();
    for (const [workloadName, effectiveName] of [["workload_request", "effective_request"], ["workload_limit", "effective_limit"]] as const) {
      const workload = value[workloadName] as Vector;
      const effective = value[effectiveName] as Vector;
      const sum = BigInt(workload[field]) + extra;
      if (sum > MAX_INTEGER || BigInt(effective[field]) !== sum) invalid();
    }
  }
}
