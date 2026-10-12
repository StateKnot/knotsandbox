import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createSandboxClient } from '../dist/index.js';

const tenant = '00000000-0000-4000-8000-000000000001';
const enabled = JSON.parse(await readFile(new URL('./fixtures/capabilities-automation.json', import.meta.url), 'utf8'));
const params = { query: { project_id: enabled.project_id }, header: { 'X-Tenant-ID': tenant } };

function client(fetch) {
  return createSandboxClient({
    baseUrl: 'https://sandbox.example', tenantId: tenant,
    tokenProvider: { getToken: async () => 'public-test-access-token' }, fetch,
  });
}

test('capability discovery preserves the enabled automation contract and never submits work', async () => {
  let calls = 0;
  const sdk = client(async request => {
    calls++;
    assert.equal(request.method, 'GET');
    const url = new URL(request.url);
    assert.equal(url.pathname, '/v1/capabilities');
    assert.equal(url.searchParams.get('project_id'), enabled.project_id);
    assert.equal(request.headers.get('x-tenant-id'), tenant);
    assert.equal(request.headers.get('authorization'), 'Bearer public-test-access-token');
    assert.equal(request.headers.get('idempotency-key'), null);
    assert.equal(request.headers.get('if-match'), null);
    assert.equal(request.body, null);
    return Response.json(enabled, { headers: { 'cache-control': 'no-store' } });
  });
  const result = await sdk.GET('/v1/capabilities', { params });
  assert.equal(calls, 1);
  assert.deepEqual(result.data, enabled);
  assert.equal(result.data.automation.assurance, 'API_CONTRACT_ONLY');
  assert.equal(result.data.runtime_certification, 'NOT_ASSERTED');
  assert.equal(result.data.automation.outcome_unknown_policy, 'RECONCILE_ORIGINAL_ONLY');
  assert.equal(result.response.headers.get('cache-control'), 'no-store');
});

test('disabled automation is an explicit null and never inferred from a previous read', async () => {
  const disabled = structuredClone(enabled);
  disabled.api_features.scheduled_tasks = false;
  disabled.api_features.event_automation = false;
  disabled.api_features.automation_notifications = false;
  disabled.automation = null;
  let calls = 0;
  const sdk = client(async () => Response.json(++calls === 1 ? enabled : disabled));
  const initial = await sdk.GET('/v1/capabilities', { params });
  assert.deepEqual(initial.data.automation, enabled.automation);
  const result = await sdk.GET('/v1/capabilities', { params });
  assert.equal(calls, 2);
  assert.ok(Object.hasOwn(result.data, 'automation'));
  assert.equal(result.data.automation, null);
  assert.equal(result.data.api_features.scheduled_tasks, false);
  assert.equal(result.data.api_features.event_automation, false);
  assert.equal(result.data.api_features.automation_notifications, false);
});

test('revoked capability visibility returns the error without cached contract or replacement work', async () => {
  let calls = 0;
  const sdk = client(async request => {
    assert.equal(request.method, 'GET');
    if (++calls === 1) return Response.json(enabled);
    return Response.json({ code: 'NOT_FOUND', retryable: false }, {
      status: 404, headers: { 'content-type': 'application/problem+json' },
    });
  });
  const initial = await sdk.GET('/v1/capabilities', { params });
  assert.ok(initial.data.automation);
  const result = await sdk.GET('/v1/capabilities', { params });
  assert.equal(calls, 2);
  assert.equal(result.data, undefined);
  assert.equal(result.error.code, 'NOT_FOUND');
  assert.equal(result.response.status, 404);
});
