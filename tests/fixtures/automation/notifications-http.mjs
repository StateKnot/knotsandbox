// Real signed loopback requests use the public generated SDK. Credentials enter
// only through private stdin. The first real committed ACK response is consumed
// and discarded to exercise the transport's unchanged-request recovery.
import assert from 'node:assert/strict';
import { createSandboxClient } from '../../../sdk/typescript/dist/index.js';

let input = '';
for await (const chunk of process.stdin) input += chunk;
const { baseUrl, tenantId, token, projectId, instanceId, notificationId } = JSON.parse(input);
const attempts = [];
let firstReceipt;
let firstHttpRequestId;
const key = 'notification-sdk-ack';
const client = createSandboxClient({
  baseUrl, tenantId, allowLoopbackHttp: true,
  tokenProvider: { async getToken() { return token; } },
  requestTimeoutMs: 2000, totalTimeoutMs: 6000, maxAttempts: 2,
  fetch: async request => {
    if (request.method !== 'POST') return globalThis.fetch(request);
    assert.equal(new URL(request.url).pathname, `/v1/automation-notifications/${notificationId}/actions/acknowledge`);
    const body = await request.clone().text();
    attempts.push({ key: request.headers.get('idempotency-key'), etag: request.headers.get('if-match'), body });
    const response = await globalThis.fetch(request);
    if (attempts.length === 1 && response.status === 200) {
      firstHttpRequestId = response.headers.get('x-request-id');
      assert.ok(firstHttpRequestId);
      firstReceipt = JSON.parse(await response.text());
      throw new TypeError('SIMULATED_COMMITTED_ACK_RESPONSE_LOSS');
    }
    return response;
  },
});

try {
  const params = { header: { 'X-Tenant-ID': tenantId } };
  const capabilities = await client.GET('/v1/capabilities', {
    params: { ...params, query: { project_id: projectId } },
  });
  assert.equal(capabilities.response.status, 200);
  assert.equal(capabilities.data.api_features.automation_notifications, true);
  assert.equal(capabilities.data.runtime_certification, 'NOT_ASSERTED');
  const listed = await client.GET('/v1/automation-notifications', {
    params: { ...params, query: { project_id: projectId, instance_id: instanceId, limit: 1 } },
  });
  assert.equal(listed.response.status, 200);
  assert.equal(listed.data.items.length, 1);
  assert.equal(listed.data.items[0].id, notificationId);
  assert.equal(listed.data.items[0].source_status, 'FAILED');
  assert.ok(listed.data.cutoff);
  const detail = await client.GET('/v1/automation-notifications/{id}', {
    params: { ...params, path: { id: notificationId } },
  });
  assert.equal(detail.response.status, 200);
  const etag = detail.response.headers.get('etag');
  assert.equal(etag, '"1"');
  assert.equal(detail.data.acknowledged_at, null);
  const acknowledged = await client.POST('/v1/automation-notifications/{id}/actions/acknowledge', {
    params: { path: { id: notificationId }, header: {
      'X-Tenant-ID': tenantId, 'Idempotency-Key': key, 'If-Match': etag,
    } }, body: {},
  });
  assert.equal(acknowledged.response.status, 200);
  assert.equal(acknowledged.response.headers.get('etag'), '"2"');
  assert.deepEqual(acknowledged.data, firstReceipt);
  assert.equal(acknowledged.data.resource.version, 2);
  assert.equal(acknowledged.data.resource.source_status, 'FAILED');
  assert.equal(acknowledged.data.resource.run_id, detail.data.run_id);
  assert.equal(acknowledged.data.resource.source_run_version, detail.data.source_run_version);
  assert.deepEqual(attempts, Array(2).fill({ key, etag, body: '{}' }));
  process.stdout.write(JSON.stringify({ receipt: acknowledged.data, mutation_requests: attempts.length,
    first_response_discarded: true, notification_id: notificationId, first_http_request_id: firstHttpRequestId }));
} catch (error) {
  process.stderr.write(JSON.stringify({ name: error?.name, code: error?.code }));
  process.exitCode = 1;
}
