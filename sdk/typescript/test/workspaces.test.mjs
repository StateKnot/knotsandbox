import assert from 'node:assert/strict';
import test from 'node:test';
import { createSandboxClient } from '../dist/index.js';
const tenant = '00000000-0000-4000-8000-000000000001';
const workspace = '00000000-0000-4000-8000-000000000002';
const opts = (fetch) => ({ baseUrl: 'https://sandbox.example', tenantId: tenant, tokenProvider: { getToken: async () => 'access-token' }, fetch });
const params = { path: { id: workspace }, header: { 'X-Tenant-ID': tenant, 'Idempotency-Key': 'persisted-workspace-delete', 'If-Match': '"7"' } };
const body = { confirm_workspace_id: workspace };

test('workspace destructive DELETE preserves confirmation, ETag and key after an ambiguous response', async () => {
  const requests = [];
  const client = createSandboxClient(opts(async request => {
    requests.push({ method: request.method, path: new URL(request.url).pathname, body: await request.text(), key: request.headers.get('idempotency-key'), etag: request.headers.get('if-match'), tenant: request.headers.get('x-tenant-id') });
    if (requests.length === 1) throw new TypeError('lost after commit');
    return new Response(JSON.stringify({ resource: { id: workspace, status: 'DELETING', spec_version: 8 }, operation: { id: tenant, status: 'ACCEPTED' }, idempotency_expires_at: '2026-10-04T00:00:00Z' }), { status: 202, headers: { 'content-type': 'application/json', etag: '"8"', location: `/v1/operations/${tenant}`, 'retry-after': '2' } });
  }));
  const result = await client.DELETE('/v1/workspaces/{id}', { params, body });
  assert.equal(result.response.status, 202); assert.equal(result.data.resource.status, 'DELETING');
  assert.equal(result.response.headers.get('etag'), '"8"');
  assert.deepEqual(requests, Array(2).fill({ method: 'DELETE', path: `/v1/workspaces/${workspace}`, body: JSON.stringify(body), key: 'persisted-workspace-delete', etag: '"7"', tenant }));
});

test('workspace DELETE without both durable headers is rejected before network', async () => {
  let called = 0;
  const client = createSandboxClient(opts(async () => { called++; throw new Error('must not send'); }));
  for (const header of [{ 'X-Tenant-ID': tenant }, { 'X-Tenant-ID': tenant, 'Idempotency-Key': 'retained-key' }]) {
    await assert.rejects(client.DELETE('/v1/workspaces/{id}', { params: { path: { id: workspace }, header }, body }));
  }
  assert.equal(called, 0);
});

test('retention rejection is returned once and never treated as deletion success', async () => {
  let called = 0;
  const client = createSandboxClient(opts(async () => { called++; return new Response(JSON.stringify({ status: 409, code: 'WORKSPACE_RETENTION_ACTIVE', retryable: false }), { status: 409, headers: { 'content-type': 'application/problem+json' } }); }));
  const result = await client.DELETE('/v1/workspaces/{id}', { params, body });
  assert.equal(result.data, undefined); assert.equal(result.error.code, 'WORKSPACE_RETENTION_ACTIVE'); assert.equal(called, 1);
});
