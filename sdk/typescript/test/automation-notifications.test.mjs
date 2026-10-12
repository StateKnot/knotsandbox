import assert from 'node:assert/strict';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import test from 'node:test';
import { createSandboxClient } from '../dist/index.js';

const notification = JSON.parse(await readFile(new URL('./fixtures/automation-notification.json', import.meta.url), 'utf8'));
const tenant = notification.tenant_id;
const cutoff = '2026-10-11T00:01:00Z';
const header = { 'X-Tenant-ID': tenant };
const path = { id: notification.id };

async function withHttp(handler, run) {
  const errors = [];
  const server = createServer((request, response) => {
    Promise.resolve().then(() => handler(request, response)).catch(error => {
      errors.push(error);
      response.writeHead(500, { 'content-type': 'application/problem+json' });
      response.end(JSON.stringify({ code: 'TEST_HANDLER_FAILED', retryable: false }));
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const sdk = createSandboxClient({
      baseUrl: `http://127.0.0.1:${server.address().port}`, tenantId: tenant,
      allowLoopbackHttp: true, maxAttempts: 2,
      tokenProvider: { getToken: async () => 'test-notification-access-token' },
    });
    await run(sdk);
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    assert.deepEqual(errors, []);
  }
}

function authenticated(request) {
  assert.equal(request.headers['x-tenant-id'], tenant);
  assert.equal(request.headers.authorization, 'Bearer test-notification-access-token');
  assert.equal(request.headers.cookie, undefined);
}

function json(response, value, status = 200, headers = {}) {
  response.writeHead(status, { 'content-type': status >= 400 ? 'application/problem+json' : 'application/json', ...headers });
  response.end(JSON.stringify(value));
}

test('HTTP notification pagination retains project, instance and signed cutoff without submitting work', async () => {
  let calls = 0;
  await withHttp((request, response) => {
    authenticated(request);
    assert.equal(request.method, 'GET');
    assert.equal(request.headers['idempotency-key'], undefined);
    assert.equal(request.headers['if-match'], undefined);
    const url = new URL(request.url, 'http://127.0.0.1');
    assert.equal(url.pathname, '/v1/automation-notifications');
    assert.equal(url.searchParams.get('project_id'), notification.project_id);
    assert.equal(url.searchParams.get('instance_id'), notification.instance_id);
    assert.equal(url.searchParams.get('limit'), '1');
    assert.equal(url.searchParams.get('cursor'), calls === 0 ? null : 'signed-project-cutoff');
    json(response, ++calls === 1
      ? { items: [notification], next_cursor: 'signed-project-cutoff', cutoff }
      : { items: [], next_cursor: null, cutoff });
  }, async sdk => {
    const query = { project_id: notification.project_id, instance_id: notification.instance_id, limit: 1 };
    const first = await sdk.GET('/v1/automation-notifications', { params: { query, header } });
    assert.deepEqual(first.data.items, [notification]);
    assert.equal(first.data.items[0].source_status, 'OUTCOME_UNKNOWN');
    const second = await sdk.GET('/v1/automation-notifications', {
      params: { query: { ...query, cursor: first.data.next_cursor }, header },
    });
    assert.deepEqual(second.data, { items: [], next_cursor: null, cutoff: first.data.cutoff });
    assert.equal(calls, 2);
  });
});

test('HTTP notification detail exposes its ETag and revoked visibility never returns a cached fact', async () => {
  let calls = 0;
  await withHttp((request, response) => {
    authenticated(request);
    assert.equal(request.method, 'GET');
    assert.equal(request.url, `/v1/automation-notifications/${notification.id}`);
    if (++calls === 1) json(response, notification, 200, { etag: '"1"' });
    else json(response, { code: 'NOT_FOUND', retryable: false }, 404);
  }, async sdk => {
    const first = await sdk.GET('/v1/automation-notifications/{id}', { params: { path, header } });
    assert.deepEqual(first.data, notification);
    assert.equal(first.response.headers.get('etag'), '"1"');
    const revoked = await sdk.GET('/v1/automation-notifications/{id}', { params: { path, header } });
    assert.equal(revoked.data, undefined);
    assert.equal(revoked.error.code, 'NOT_FOUND');
    assert.equal(revoked.response.status, 404);
    assert.equal(calls, 2);
  });
});

test('HTTP lost ACK reuses the original key, empty body and ETag; conflicts never submit replacement work', async () => {
  const recorded = [];
  const resource = { ...notification, acknowledged_at: '2026-10-11T00:02:00Z',
    acknowledged_by: '00000000-0000-4000-8000-000000000007', version: 2 };
  const receipt = { resource, idempotency_expires_at: '2026-10-18T00:02:00Z' };
  await withHttp(async (request, response) => {
    authenticated(request);
    assert.equal(request.method, 'POST');
    assert.equal(request.url, `/v1/automation-notifications/${notification.id}/actions/acknowledge`);
    let body = '';
    for await (const chunk of request) body += chunk;
    assert.equal(body, '{}');
    recorded.push({ key: request.headers['idempotency-key'], etag: request.headers['if-match'], body });
    if (recorded.length === 1) {
      // The server has committed; only its reply is lost.
      request.socket.destroy();
    } else if (request.headers['idempotency-key'] === 'ack-original' && request.headers['if-match'] === '"1"') {
      json(response, receipt, 200, { etag: '"2"' });
    } else if (request.headers['idempotency-key'] === 'ack-original') {
      json(response, { code: 'IDEMPOTENCY_KEY_REUSED', retryable: false }, 409);
    } else {
      json(response, { code: 'PRECONDITION_FAILED', retryable: false }, 412);
    }
  }, async sdk => {
    const ack = (key, etag) => sdk.POST('/v1/automation-notifications/{id}/actions/acknowledge', {
      params: { path, header: { ...header, 'Idempotency-Key': key, 'If-Match': etag } }, body: {},
    });
    const recovered = await ack('ack-original', '"1"');
    assert.deepEqual(recovered.data, receipt);
    assert.equal(recovered.response.headers.get('etag'), '"2"');
    assert.equal(recovered.data.resource.source_status, 'OUTCOME_UNKNOWN');
    assert.equal(recovered.data.resource.source_run_version, notification.source_run_version);
    assert.equal(recovered.data.resource.run_id, notification.run_id);
    assert.deepEqual(recorded, Array(2).fill({ key: 'ack-original', etag: '"1"', body: '{}' }));
    const conflicting = await ack('ack-original', '"2"');
    assert.equal(conflicting.data, undefined);
    assert.equal(conflicting.response.status, 409);
    const stale = await ack('ack-new', '"1"');
    assert.equal(stale.data, undefined);
    assert.equal(stale.response.status, 412);
    assert.equal(recorded.length, 4, '409 and 412 must not be retried');
  });
});
