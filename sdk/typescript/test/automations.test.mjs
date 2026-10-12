import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createSandboxClient, waitAutomationRun, AutomationRunQueryError,
} from '../dist/index.js';

const tenant = '00000000-0000-4000-8000-000000000001';
const id = '00000000-0000-4000-8000-000000000002';
function client(send) {
  return createSandboxClient({
    baseUrl: 'https://sandbox.example.test', tenantId: tenant,
    tokenProvider: { getToken: async () => 'test-access-token' }, fetch: send,
  });
}
const body = (status) => new Response(JSON.stringify({ id, status }), {
  status: 200, headers: { 'content-type': 'application/json' },
});

test('UNKNOWN returns the original run and never sends replacement work', async () => {
  const requests = [];
  const result = await waitAutomationRun(client(async (request) => {
    requests.push(request);
    return body('OUTCOME_UNKNOWN');
  }), tenant, id);
  assert.equal(result.kind, 'outcome_unknown');
  assert.equal(result.run.id, id);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, 'GET');
  assert.equal(new URL(requests[0].url).pathname, `/v1/automation-runs/${id}`);
});

test('SUBMITTED keeps polling the same run until physical business completion', async () => {
  let calls = 0;
  const result = await waitAutomationRun(client(async (request) => {
    assert.equal(request.method, 'GET');
    assert.equal(new URL(request.url).pathname, `/v1/automation-runs/${id}`);
    return body(++calls === 1 ? 'SUBMITTED' : 'SUCCEEDED');
  }), tenant, id, { pollIntervalMs: 1 });
  assert.equal(calls, 2);
  assert.equal(result.kind, 'terminal');
  assert.equal(result.run.status, 'SUCCEEDED');
});

test('disabled feature or revoked access is an error, not invented completion', async () => {
  let calls = 0;
  await assert.rejects(waitAutomationRun(client(async (request) => {
    assert.equal(request.method, 'GET');
    calls++;
    return new Response(JSON.stringify({ code: 'RESOURCE_NOT_FOUND' }), {
      status: 404, headers: { 'content-type': 'application/problem+json' },
    });
  }), tenant, id), (error) => error instanceof AutomationRunQueryError &&
    error.status === 404 && error.runId === id);
  assert.equal(calls, 1);
});

test('wait timeout aborts a stalled read without resubmission or cancel', async () => {
  let calls = 0;
  const result = await waitAutomationRun(client(async () => {
    calls++;
    return new Promise(() => {});
  }), tenant, id, { timeoutMs: 20, pollIntervalMs: 1 });
  assert.equal(result.kind, 'timeout');
  assert.equal(result.runId, id);
  assert.equal(result.lastObserved, undefined);
  assert.equal(calls, 1);
});
