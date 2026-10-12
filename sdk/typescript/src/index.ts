import createClient from "openapi-fetch";
import type { components, paths } from "./schema.js";
import { abortable, createSandboxFetch, delay, validatedBaseUrl } from "./transport.js";
import type { TransportOptions } from "./transport.js";

export * from "./transport.js";
export * from "./events.js";
export * from "./output-stream.js";
export * from "./files.js";
export type { components, paths } from "./schema.js";

export function createSandboxClient(options: TransportOptions) {
  return createClient<paths>({
    baseUrl: validatedBaseUrl(options).href.replace(/\/$/, ""),
    fetch: createSandboxFetch(options),
    headers: { "X-Tenant-ID": options.tenantId },
  });
}

export type SandboxClient = ReturnType<typeof createSandboxClient>;
export type Operation = components["schemas"]["Operation"];
export type Execution = components["schemas"]["Execution"];
export type InstanceSecurity = components["schemas"]["InstanceSecurity"];
export type Automation = components["schemas"]["Automation"];
export type AutomationRun = components["schemas"]["AutomationRun"];
export type AutomationCapability = components["schemas"]["AutomationCapability"];
export type AutomationNotification = components["schemas"]["AutomationNotification"];
export type AutomationNotificationPage = components["schemas"]["AutomationNotificationPage"];
export type AutomationNotificationReceipt = components["schemas"]["AutomationNotificationReceipt"];
export type TenantAuditRecord = components["schemas"]["TenantAuditRecord"];
export type TenantAuditRecordPage = components["schemas"]["TenantAuditRecordPage"];
export interface WaitOptions {
  timeoutMs?: number;
  pollIntervalMs?: number;
  signal?: AbortSignal;
}
export type WaitResult =
  | { kind: "terminal"; operation: Operation }
  | { kind: "timeout"; operationId: string; lastObserved: Operation | undefined };
export type ExecutionWaitResult =
  | { kind: "result"; execution: Execution }
  | { kind: "outcome_unknown"; execution: Execution }
  | { kind: "timeout"; executionId: string; lastObserved: Execution | undefined };
export type AutomationRunWaitResult =
  | { kind: "terminal"; run: AutomationRun }
  | { kind: "outcome_unknown"; run: AutomationRun }
  | { kind: "timeout"; runId: string; lastObserved: AutomationRun | undefined };

/** A wait deadline only stops polling; it never cancels or resubmits server work. */
export async function waitOperation(
  client: SandboxClient,
  tenantId: string,
  operationId: string,
  options: WaitOptions = {},
): Promise<WaitResult> {
  const result = await pollUntil<Operation>(async signal => {
    const result = await client.GET("/v1/operations/{id}", {
      params: { path: { id: operationId }, header: { "X-Tenant-ID": tenantId } }, signal,
    });
    if (result.error || !result.data) {
      throw new OperationQueryError(operationId, result.response.status, result.error);
    }
    return result.data;
  }, operation => ["SUCCEEDED", "FAILED", "CANCELLED"].includes(operation.status), options);
  return result.kind === "done"
    ? { kind: "terminal", operation: result.resource }
    : { kind: "timeout", operationId, lastObserved: result.lastObserved };
}

/**
 * Waits only for a command result or an explicit unknown outcome. Neither a
 * result nor caller timeout proves that the VM or its background work stopped.
 * An unknown outcome must be reconciled, never resubmitted as a new execution.
 */
export async function waitExecution(
  client: SandboxClient,
  tenantId: string,
  executionId: string,
  options: WaitOptions = {},
): Promise<ExecutionWaitResult> {
  const result = await pollUntil<Execution>(async signal => {
    const result = await client.GET("/v1/executions/{id}", {
      params: { path: { id: executionId }, header: { "X-Tenant-ID": tenantId } }, signal,
    });
    if (result.error || !result.data) {
      throw new ExecutionQueryError(executionId, result.response.status, result.error);
    }
    return result.data;
  }, execution => ["SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELLED", "OUTCOME_UNKNOWN"].includes(execution.status), options);
  if (result.kind === "timeout") return { kind: "timeout", executionId, lastObserved: result.lastObserved };
  return {
    kind: result.resource.status === "OUTCOME_UNKNOWN" ? "outcome_unknown" : "result",
    execution: result.resource,
  };
}

/**
 * Polls only the exact persisted run. SUBMITTED is acceptance, not completion;
 * UNKNOWN must be reconciled and never creates a replacement rule or action.
 * Requires the server's formally installed automation feature (migration 0039).
 */
export async function waitAutomationRun(
  client: SandboxClient,
  tenantId: string,
  runId: string,
  options: WaitOptions = {},
): Promise<AutomationRunWaitResult> {
  const result = await pollUntil<AutomationRun>(async signal => {
    const response = await client.GET("/v1/automation-runs/{id}", {
      params: { path: { id: runId }, header: { "X-Tenant-ID": tenantId } }, signal,
    });
    if (response.error || !response.data) {
      throw new AutomationRunQueryError(runId, response.response.status, response.error);
    }
    return response.data;
  }, run => ["SUCCEEDED", "FAILED", "SKIPPED", "CANCELLED", "OUTCOME_UNKNOWN"].includes(run.status), options);
  if (result.kind === "timeout") return { kind: "timeout", runId, lastObserved: result.lastObserved };
  return {
    kind: result.resource.status === "OUTCOME_UNKNOWN" ? "outcome_unknown" : "terminal",
    run: result.resource,
  };
}

async function pollUntil<T>(
  read: (signal: AbortSignal) => Promise<T>,
  done: (resource: T) => boolean,
  options: WaitOptions,
): Promise<{ kind: "done"; resource: T } | { kind: "timeout"; lastObserved: T | undefined }> {
  const timeoutMs = options.timeoutMs ?? 60000;
  const pollMs = options.pollIntervalMs ?? 2000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 86400000 ||
      !Number.isSafeInteger(pollMs) || pollMs < 1 || pollMs > 60000) throw new Error("INVALID_WAIT_CONFIGURATION");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const signal = options.signal ? AbortSignal.any([options.signal, controller.signal]) : controller.signal;
  let lastObserved: T | undefined;
  try {
    for (;;) {
      signal.throwIfAborted();
      lastObserved = await abortable(read(signal), signal);
      if (done(lastObserved)) return { kind: "done", resource: lastObserved };
      await delay(pollMs, signal);
    }
  } catch (error) {
    if (options.signal?.aborted) throw options.signal.reason;
    if (controller.signal.aborted) return { kind: "timeout", lastObserved };
    throw error;
  } finally { clearTimeout(timer); }
}

export class ExecutionQueryError extends Error {
  constructor(
    public readonly executionId: string,
    public readonly status: number,
    public readonly problem: components["schemas"]["Problem"] | undefined,
  ) {
    super("EXECUTION_QUERY_FAILED");
    this.name = "ExecutionQueryError";
  }
}

export class OperationQueryError extends Error {
  constructor(
    public readonly operationId: string,
    public readonly status: number,
    public readonly problem: components["schemas"]["Problem"] | undefined,
  ) {
    super("OPERATION_QUERY_FAILED");
    this.name = "OperationQueryError";
  }
}

export class AutomationRunQueryError extends Error {
  constructor(
    public readonly runId: string,
    public readonly status: number,
    public readonly problem: components["schemas"]["Problem"] | undefined,
  ) {
    super("AUTOMATION_RUN_QUERY_FAILED");
    this.name = "AutomationRunQueryError";
  }
}
