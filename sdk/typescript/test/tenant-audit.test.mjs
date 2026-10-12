import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { createSandboxClient } from '../dist/index.js';

const tenant = '00000000-0000-4000-8000-000000000001';
const page = JSON.parse(await readFile(new URL('./fixtures/tenant-audit-page.json', import.meta.url), 'utf8'));
function client(fetch) {
  return createSandboxClient({
    baseUrl: 'https://sandbox.example', tenantId: tenant,
    tokenProvider: { getToken: async () => 'public-test-access-token' }, fetch,
  });
}

test('tenant audit uses only tenant authentication and stable pagination parameters', async () => {
  const calls = [];
  const sdk = client(async request => {
    assert.equal(request.method, 'GET');
    assert.equal(request.headers.get('authorization'), 'Bearer public-test-access-token');
    assert.equal(request.headers.get('x-tenant-id'), tenant);
    assert.equal(request.headers.get('idempotency-key'), null);
    assert.equal(request.headers.get('if-match'), null);
    const url = new URL(request.url);
    assert.equal(url.pathname, '/v1/tenant-audit-records');
    assert.equal(url.searchParams.get('limit'), '1');
    assert.equal(url.searchParams.has('project_id'), false);
    calls.push(url);
    return Response.json(page);
  });
  const params = { header: { 'X-Tenant-ID': tenant }, query: { limit: 1 } };
  const initial = await sdk.GET('/v1/tenant-audit-records', { params });
  assert.deepEqual(initial.data, page);
  const next = await sdk.GET('/v1/tenant-audit-records', {
    params: { ...params, query: { limit: 1, cursor: initial.data.next_cursor } },
  });
  assert.equal(calls.length, 2);
  assert.equal(calls[1].searchParams.get('cursor'), page.next_cursor);
  assert.equal(next.data.items[0].project_id, null);
});

test('revoked tenant audit authorization returns an error with no cached page or retry', async () => {
  let calls = 0;
  const sdk = client(async () => ++calls === 1 ? Response.json(page) : Response.json(
    { code: 'NOT_FOUND', retryable: false },
    { status: 404, headers: { 'content-type': 'application/problem+json' } },
  ));
  const params = { header: { 'X-Tenant-ID': tenant }, query: { limit: 1 } };
  assert.deepEqual((await sdk.GET('/v1/tenant-audit-records', { params })).data, page);
  const denied = await sdk.GET('/v1/tenant-audit-records', { params });
  assert.equal(denied.data, undefined);
  assert.equal(denied.error.code, 'NOT_FOUND');
  assert.equal(calls, 2);
});
