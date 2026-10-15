# TypeScript microservice client

Node.js 22+ ESM client for the implemented OpenAPI contract. Request/response types are generated from `openapi/sandbox-api.yaml`; the transport adds bounded retries, token refresh, tenant binding and operation polling. This is a service-to-service client. Browser sign-in and BFF sessions use separate flows.

```sh
cd sdk/typescript
npm ci --ignore-scripts
npm run generate
npm test
```

`dist` contains the ESM implementation and declarations after building. The package is private until the full release gates pass. API additions require regenerating `src/schema.d.ts` and checking the diff.

## Calling the API

File data uses `uploadFilePart` and `downloadFile` from this package; the ordinary JSON transport rejects file content routes. Upload parts are immutable, at most 1 MiB, and are sent exactly once. A failed or interrupted PUT returns `outcomeUnknown=true`: query the transfer before recovery and never automatically resend bytes. Downloads return at most 100 MiB only after matching the retained transfer version, complete byte length and SHA-256. See [the file API flow](../../docs/file-transfers.md) for admission, staging, commit, quotas and whole-instance timeout behavior.

```ts
import { createSandboxClient, waitOperation } from '@sandbox-platform/client';

const tenantId = config.tenantId;
const client = createSandboxClient({
  baseUrl: config.sandboxApiUrl, // HTTPS; secrets must never be URL parameters.
  tenantId,
  tokenProvider: {
    // Delegate OAuth to your identity library/workload identity integration.
    // Return a raw access token, never an ID token or a "Bearer " prefix.
    // Implement cached access tokens, forceRefresh and the abort signal.
    getToken: ({ forceRefresh, signal }) => identity.getSandboxAccessToken({ forceRefresh, signal }),
  },
});

// Persist this key with the caller's business job BEFORE submitting. Read it
// back when recovering a timeout or restarting the caller; never invent a new
// key to resolve an ambiguous submission or an IDEMPOTENCY_EXPIRED response.
const idempotencyKey = job.sandboxCreateKey;
const receipt = await client.POST('/v1/instances', {
  params: { header: { 'X-Tenant-ID': tenantId, 'Idempotency-Key': idempotencyKey } },
  body: {
    project_id: config.projectId,
    name: job.sandboxName,
    template_version_id: config.templateId,
    security_profile_id: config.securityPolicyId,
    flavor: 'cpu1-mem2',
    workspace: { size_gib: 20 },
    ttl_seconds: 3600,
  },
});
if (receipt.error) {
  // Branch on receipt.error.code and preserve the business job/key.
  throw new Error(receipt.error.code);
}
if (!receipt.data) throw new Error('MISSING_RECEIPT');
await jobs.saveSandboxReceipt(job.id, receipt.data);
const result = await waitOperation(client, tenantId, receipt.data.operation.id, { timeoutMs: 60000 });
// timeout: retain operationId and query again later; do not cancel or recreate.
// terminal: inspect operation.status; FAILED and CANCELLED are not success.
```

For existing-resource mutations provide the exact strong `ETag` returned by the server as `If-Match`. A retry must use the same ETag, body and key as the original attempt. A `412` requires reading current state and making a new business decision; the SDK does not silently change the precondition. `X-Tenant-ID` in a request must equal the client's bound tenant.

For command execution, persist the accepted execution ID as well as the operation ID and use `waitExecution(client, tenantId, executionId)`. It returns `result`, `outcome_unknown`, or `timeout`. An operation can be cancelled while the command's result remains unknown. The execution response's `termination_status`, `slot_held`, and `output_status` stay separate: a successful command can have truncated output and a live VM; a timed-out command can still be awaiting VM termination. The helper never submits another execution or a cancellation.

Automation APIs require normal migration **0039**, dedicated API grants and current caller authorization. `scheduled_tasks`/`event_automation` indicate checked routes; actual dispatch requires the independent `sandbox-automation` worker. After installation, persist an automation run ID and use `waitAutomationRun(client, tenantId, runId)`. `SUBMITTED` means the linked operation was accepted and may still be running. The helper polls the same run with GET only, returns `outcome_unknown` immediately for `UNKNOWN`, and treats a deadline as `timeout`. Neither result schedules another run, changes a policy, cancels work or retries a mutation. `SUCCEEDED`, `FAILED`, `SKIPPED` and `CANCELLED` remain distinct terminal statuses. A revoked `automations:read` grant produces a query error rather than a replacement task.

Read output using the generated `GET /v1/executions/{id}/output` method and a separately granted `executions:output:read` permission:

```ts
const page = await client.GET('/v1/executions/{id}/output', {
  params: {
    path: { id: job.executionId },
    header: { 'X-Tenant-ID': tenantId },
    query: { after_segment: job.lastConsumedSegment ?? -1, limit: 1 },
  },
});
if (page.error) throw new Error(page.error.code);
if (!page.data) throw new Error('MISSING_OUTPUT_PAGE');
// Store consumed segment positions with the caller's job. A segment may be
// delivered again after caller failure; deduplicate before applying side effects.
await jobs.consumeOutputPage(job.id, page.data);
```

Frames contain base64 bytes from an untrusted workload. Segment positions differ from frame sequence numbers and per-stream byte offsets. `has_more: false` on a `PENDING` page means no further segments were committed in that snapshot; it is not end-of-output. `manifest_verified` checks the manifest against the complete index; bytes of segments not on this page have not been downloaded by this request. A verified empty output has `final_segment_sequence: -1`. Do not print raw control bytes to an administrator terminal or inject decoded text as HTML. Pagination does not renew activity or prove that the workload stopped.

## Failure behavior

- HTTPS is required. Explicit `allowLoopbackHttp` supports only literal `127.0.0.1` and `::1` for local integration tests. The configured origin/path is enforced, cookies are removed and redirects are never followed.
- Default per-attempt deadline is 5 seconds, including token acquisition and response-body reading. The whole request has a 20-second budget and at most 4 attempts. Bodies are limited to 64 KiB for requests and 2 MiB for management responses. Cancellation bounds local work; it never proves a remote command stopped.
- Connection failures and `408/429/502/503/504` can retry with the original request. A structured `application/problem+json` response with `retryable: false` is returned immediately, including an output integrity failure. `Retry-After` is honored; a delay beyond the budget returns the response without retrying early. `401` can force a token refresh once. Other `4xx` and `500` are returned without retries.
- HTTP problems follow `openapi-fetch`'s `{ data, error, response }` result. Non-HTTP failures throw `SandboxTransportError` with `code`, `outcomeUnknown` and the original `idempotencyKey`. It does not include tokens, body contents, or identity-provider error details. `outcomeUnknown` means a mutation may have reached the server; reconcile its receipt with the same key.
- `waitOperation` only makes GET requests. A polling deadline returns `{kind:'timeout', operationId, lastObserved}`. Caller abort stops polling. Neither path sends a cancellation or replays an execution.

Pass an OAuth token provider that uses your chosen IdP's supported client authentication (workload identity, certificate, `private_key_jwt`, or managed secret). This SDK does not implement an identity provider or store client secrets. The API independently verifies signatures and product grants for both standalone Keycloak and configured external OIDC.

Unit tests include a real local HTTP redirect, replay after a simulated lost commit response, 401 refresh limits, retry budgets, unchanged preconditions, body/deadline bounds, tenant mismatches, operation/execution polling and unknown outcomes. The Rust `keycloak` integration suite also starts a real HTTP listener and invokes this built client in a separate Node process using real Keycloak and PostgreSQL. It checks refresh after a 401, a lost response after the server commits, duplicate-free replay, renewal, stale ETag rejection, stopping, and polling timeouts without cancellation. Run `npm run build` before that suite. This does not certify a real sandbox VM or a production deployment. Project events use the dedicated `subscribeEvents` async iterator; see [event streaming and recovery](../../docs/event-stream-sdk.md). Execution output has a [separate resumable stream](../../docs/execution-output-stream.md); management buffering must not be reused for a stream. File transfer and terminal sessions remain separate work.

### Resource accounting

Use `getResourceAccounting` for the read-only launch request, trusted Pod configuration and quota receipt
view. It requires current `instances:read`; the helper validates UUIDs and bounded
pagination inputs and preserves decimal strings, including 19-digit account
values. It makes no mutation and never releases quota.

```ts
import { getResourceAccounting } from '@sandbox-platform/client';

const abortController = new AbortController();
// Omit launchId to read the current contract and all associated purposes/history.
const accountingOptions = { limit: 50, signal: abortController.signal };
const first = await getResourceAccounting(client, tenantId, job.instanceId, accountingOptions);
if (first.contract) {
  // Keep these as strings for storage/display; use BigInt for exact arithmetic.
  await jobs.saveRequestedCompute(job.id, {
    launchId: first.contract.launch_id,
    cpuMillis: first.contract.cpu_millis,
    memoryMiB: first.contract.memory_mib,
  });
}
const second = first.receipts.next_cursor === null ? null :
  await getResourceAccounting(client, tenantId, job.instanceId, {
    ...accountingOptions,
    cursor: first.receipts.next_cursor,
  });

// An explicit launchId narrows receipts to ordinary compute bound to that launch.
const launchPage = await getResourceAccounting(client, tenantId, job.instanceId, {
  launchId: job.recordedLaunchId,
  limit: 50,
  signal: abortController.signal,
});
```

Continue a page with the same tenant, identity, instance, launch filter (including
its omission), and limit. Cursors expire after 24 hours and bind the platform
epoch, current generation/launch, selected launch and exact first-page observation ID
or absence. A later COMMIT never changes an earlier page's `NOT_CAPTURED`, even if
its insertion timestamp precedes cutoff. A changed selected launch or filter requires a fresh first
page. `ResourceAccountingQueryError` exposes the HTTP `status` and structured
`problem`; permission rejection must clear any previously displayed evidence.

`REQUESTED_COMPUTE_QUOTA` describes admitted CPU/memory requests. `KUBERNETES_API_READBACK`
with non-null `pod_resource_observation` describes immutable configuration captured
through trusted launch registration. Workload request/limit, Pod overhead, and effective
request/limit have fixed `cpu_millis`, `memory_bytes` and `ephemeral_storage_bytes` keys
(overhead has only CPU/memory). Class configuration is a separate observation; its
opaque GET resourceVersion does not prove which Class version admission adopted.
The helper validates observation scope, fixed keys, canonical decimal integers no larger
than i64_MAX, and checked effective sums without JavaScript Number conversion.
Missing observations remain `NOT_CAPTURED` with null; missing old contracts remain
`HISTORY_START_NOT_CAPTURED` and legacy receipts remain `LEGACY_UNBOUND`.
Tenant and project quota scopes must not be added together, and neither receipt
amounts nor requested compute are utilization denominators. A `RELEASED` receipt
applies to that purpose; it does not prove every resource was released. See
[resource accounting](../../docs/resource-accounting.md) for history, closure
proofs and the maintenance upgrade gate.

### Runtime metrics and cold backups

The generated `GET /v1/instances/{id}/security` returns `InstanceSecurity` and
requires current `instances:read`. Its optional operation summary also requires
`operations:read`; otherwise the summary is `REDACTED` with a null resource.

```ts
const security = await client.GET('/v1/instances/{id}/security', {
  params: { path: { id: job.instanceId }, header: { 'X-Tenant-ID': tenantId } },
});
if (security.error) throw new Error(security.error.code);
if (!security.data) throw new Error('MISSING_SECURITY_VIEW');
// Preserve UNKNOWN as unknown. Neither an approved template nor a recorded
// policy or launch proves independent runtime enforcement.
await jobs.saveSecurityObservation(job.id, security.data);
```

The API does not return raw policy documents, host identities or launch
receipts. `rules_sha256` identifies bounded PostgreSQL JSONB UTF-8 text, with
exact stored numeric values; it is not a signature or a cross-version canonical
hash. `X-Instance-ETag` describes the instance mutation version, not this changing
security view. A `404` hides withdrawn visibility; a `409
SECURITY_TARGET_CHANGED` requires a fresh GET. Discard an older view when access
is withdrawn. See [security evidence and permissions](../../docs/instance-security.md).

Use the generated `GET /v1/instances/{id}/metrics` with `metric`, RFC3339 `start`/`end`, `step_seconds`, and optionally a recorded `launch_id`. Historical requests remain bound to the current platform epoch. Check each point's `status`: `STALE` and `MISSING` have a null value, while a measured zero can be `FRESH`. Do not sum the two collectors or infer application health from host resource accounting. See [the metric contract](../../docs/runtime-metrics.md).

Cold backups require a STOPPED instance, trusted cleanup of all earlier writers, `backups:create`, and an enabled operator-reviewed profile. Read the workspace's ETag, then persist the original key/body/ETag before submission:

```ts
const backup = await client.POST('/v1/workspaces/{id}/backups', {
  params: {
    path: { id: workspaceId },
    header: { 'X-Tenant-ID': tenantId, 'Idempotency-Key': job.backupKey, 'If-Match': workspaceEtag },
  },
  body: { profile_id: config.backupProfileId, retention_days: 31 },
});
if (backup.error) throw new Error(backup.error.code);
if (!backup.data) throw new Error('MISSING_BACKUP_RECEIPT');
await jobs.saveBackupReceipt(job.id, backup.data);
```

`X-Workspace-ETag` describes the held workspace; `GET /v1/backups/{id}` returns the backup's own ETag and requires `backups:read`. A 202 or completed CAPTURE does not mean an independent backup is available. Poll the operation with `operations:read` and read the backup record; only `AVAILABLE` denotes completed vault verification and trusted task cleanup. A caller timeout does not cancel the backup or release its hold. Backup availability is separate from a successfully restored new workspace and from production recovery certification.

Dependency references: [openapi-fetch API](https://openapi-ts.dev/openapi-fetch/api), [OpenAPI TypeScript](https://openapi-ts.dev/introduction).

### Workspace data deletion

`DELETE /v1/instances/{id}` retains the independent workspace. To destroy data,
first read `GET /v1/workspaces/{id}` with `workspaces:read`, save its `ETag`, and
use the separate `workspaces:delete` grant. The destructive request requires an
explicit matching UUID confirmation, a durable key, and the workspace's ETag:

```ts
const accepted = await client.DELETE("/v1/workspaces/{id}", {
  params: {
    path: { id: workspaceId },
    header: {
      "X-Tenant-ID": tenantId,
      "Idempotency-Key": persistedDeletionKey,
      "If-Match": workspaceEtag,
    },
  },
  body: { confirm_workspace_id: workspaceId },
});
```

Acceptance creates an irreversible deletion intent. A `202` receipt does not
prove that the disk was destroyed or storage quota released. Poll its operation;
never make another key after an ambiguous response. A retention deadline, active
hold or unresolved runtime safety can block acceptance with `409`. No SDK helper
automatically deletes a workspace when an instance is removed.

租户账户审计使用生成的 `GET /v1/tenant-audit-records`，仅传 `limit` 和 `cursor`；需要独立租户 `tenant_audit:read` 授权及当前身份，项目管理员权限不授予该范围。返回当前租户 `project_id=null` 的脱敏记录，每页重新核验撤权／到期。游标必须保持租户、主体与页大小一致，不能混用项目或账户登记游标。部署和授权说明见[租户账户审计](../../docs/tenant-audit.md)。

诊断报告能力由 `api_features.control_plane_diagnoses` 表示；旧部署缺少该字段时按不支持处理。`health_diagnostics` 表示完整运行健康诊断，不能用来判断控制面报告 API 是否可用。

使用 `POST /v1/instances/{id}/diagnoses` 创建，需要 `diagnoses:create`、`instances:read` 和持久 `Idempotency-Key`，不要求实例 `If-Match`。可提交 `{ include_operations: false, include_executions: false }` 仅请求实例范围证据；附加范围的内容仍受当前读取权限限制。受理后保留 `resource.id`，通过 `GET /v1/diagnoses/{id}` 的 `status` 读取进度和结果，只需要 `diagnoses:read` 与 `instances:read`。不必为了轮询报告增加 `operations:read`；如果确需读取 Operation，另外授权该范围。

对 `PENDING` 进行有界 GET 轮询，到原 `deadline` 或终态停止；读取失败可显式重读，不能自动重新创建报告。创建结果未知时沿原 body 和幂等键重试。`UNKNOWN` 是证据不足，`EVIDENCE_REDACTED` 是当前附加权限不足，均不能解释为健康。报告仅包含控制面快照，读取时按当前权限脱敏，30天后清除报告内容。
