// Invoked only by the real Rust/Keycloak/PostgreSQL integration test. Secrets
// arrive through a private stdin pipe, never CLI arguments, files, or logs.
import { createSandboxClient, waitOperation } from '../dist/index.js';

function check(condition, code) { if (!condition) throw new Error(code); }

async function main() {
  let bytes = 0;
  const chunks = [];
  for await (const chunk of process.stdin) {
    bytes += chunk.length;
    check(bytes <= 65536, 'INTEGRATION_INPUT_LIMIT');
    chunks.push(chunk);
  }
  const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  let refreshed = false;
  let refreshCount = 0;
  let lostResponse = false;
  let createCount = 0;
  const observedBodies = [];
  const client = createSandboxClient({
    baseUrl: input.baseUrl,
    tenantId: input.tenantId,
    allowLoopbackHttp: true,
    tokenProvider: {
      async getToken({ forceRefresh }) {
        if (forceRefresh) { refreshed = true; refreshCount++; }
        return refreshed ? input.accessToken : 'deliberately-invalid-access-token';
      },
    },
    async fetch(request) {
      const create = request.method === 'POST' && new URL(request.url).pathname === '/v1/instances';
      if (create) {
        createCount++;
        check(request.headers.get('idempotency-key') === 'sdk-live-create', 'CREATE_KEY_CHANGED');
        observedBodies.push(await request.clone().text());
      }
      const response = await globalThis.fetch(request);
      if (create && response.status === 202 && !lostResponse) {
        // The real server has committed. Lose the receipt before the SDK sees
        // it, so the next request must retrieve the same durable operation.
        lostResponse = true;
        await response.arrayBuffer();
        throw new TypeError('INJECTED_RECEIPT_LOSS');
      }
      return response;
    },
  });
  const createOptions = {
    params: { header: { 'X-Tenant-ID': input.tenantId, 'Idempotency-Key': 'sdk-live-create' } },
    body: input.createRequest,
  };
  const created = await client.POST('/v1/instances', createOptions);
  check(created.response.status === 202 && created.data && !created.error, 'CREATE_RECEIPT_MISSING');
  check(refreshCount === 1 && createCount === 3 && lostResponse, 'RETRY_OR_REFRESH_CONTRACT_FAILED');
  check(observedBodies.every(body => body === observedBodies[0]), 'CREATE_BODY_CHANGED');
  const id = created.data.resource.id;
  const operationId = created.data.operation.id;
  const initialEtag = created.response.headers.get('etag');
  check(initialEtag, 'INITIAL_ETAG_MISSING');

  const replay = await client.POST('/v1/instances', createOptions);
  check(replay.data?.resource.id === id && replay.data?.operation.id === operationId, 'DURABLE_REPLAY_CHANGED_IDENTITY');
  const readOptions = { params: { path: { id }, header: { 'X-Tenant-ID': input.tenantId } } };
  const read = await client.GET('/v1/instances/{id}', readOptions);
  check(read.response.status === 200 && read.data?.id === id, 'READ_FAILED');
  const renewed = await client.POST('/v1/instances/{id}/actions/renew', {
    params: { path: { id }, header: { 'X-Tenant-ID': input.tenantId, 'Idempotency-Key': 'sdk-live-renew', 'If-Match': initialEtag } },
    body: { expires_at: new Date(Date.parse(read.data.compute_lease_expires_at) + 300000).toISOString() },
  });
  check(renewed.response.status === 200 && renewed.data?.resource.compute_lease_version === read.data.compute_lease_version + 1, 'RENEW_FAILED');
  const stale = await client.POST('/v1/instances/{id}/actions/stop', {
    params: { path: { id }, header: { 'X-Tenant-ID': input.tenantId, 'Idempotency-Key': 'sdk-live-stale-stop', 'If-Match': initialEtag } }, body: {},
  });
  check(stale.response.status === 412 && stale.error?.code === 'VERSION_MISMATCH', 'STALE_ETAG_ACCEPTED');
  const stopped = await client.POST('/v1/instances/{id}/actions/stop', {
    params: { path: { id }, header: { 'X-Tenant-ID': input.tenantId, 'Idempotency-Key': 'sdk-live-stop', 'If-Match': renewed.response.headers.get('etag') } }, body: {},
  });
  check(stopped.response.status === 202 && stopped.data?.resource.desired_state === 'STOPPED', 'STOP_FAILED');
  const wait = await waitOperation(client, input.tenantId, stopped.data.operation.id, { timeoutMs: 100, pollIntervalMs: 25 });
  check(wait.kind === 'timeout' && wait.operationId === stopped.data.operation.id, 'WAIT_MUST_NOT_COMPLETE_QUEUED_OPERATION');
  const afterWait = await client.GET('/v1/instances/{id}', readOptions);
  check(afterWait.data?.active_operation_id === stopped.data.operation.id, 'WAIT_CANCELLED_SERVER_OPERATION');
  process.stdout.write(JSON.stringify({ instance_id: id, create_operation_id: operationId, stop_operation_id: stopped.data.operation.id }));
}

main().catch(error => {
  // Only fixed assertions and SDK error codes are useful in this test's logs.
  const code = error instanceof Error && /^[A-Z_]{1,100}$/.test(error.message) ? error.message : 'SDK_INTEGRATION_FAILED';
  process.stderr.write(`${code}\n`);
  process.exitCode = 1;
});
