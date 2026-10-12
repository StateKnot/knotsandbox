import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import test from 'node:test';
import { createSandboxClient, createSandboxFetch, SandboxTransportError, ExecutionQueryError, waitExecution, waitOperation } from '../dist/index.js';

const tenant = '00000000-0000-4000-8000-000000000001';
const operationId = '00000000-0000-4000-8000-000000000002';
const baseUrl = 'https://sandbox.example';
const options = (extra = {}) => ({ baseUrl, tenantId: tenant, tokenProvider: { getToken: async () => 'access-token' }, ...extra });
const json = (value, status = 200, headers = {}) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json', ...headers } });
const post = (headers = {}) => new Request(`${baseUrl}/v1/instances`, {
  method: 'POST', headers: { 'idempotency-key': 'persisted-command-1', 'content-type': 'application/json', ...headers },
  body: JSON.stringify({ name: 'example' }),
});

test('ambiguous connection failure replays exactly the same key, body and tenant', async () => {
  const received = [];
  const send = createSandboxFetch(options({ fetch: async (request) => {
    received.push({ key: request.headers.get('idempotency-key'), body: await request.text(), tenant: request.headers.get('x-tenant-id') });
    if (received.length === 1) throw new TypeError('connection lost after commit');
    return json({ operation_id: operationId }, 202);
  } }));
  assert.equal((await send(post())).status, 202);
  assert.equal(received.length, 2);
  assert.deepEqual(received[0], received[1]);
  assert.equal(received[0].tenant, tenant);
});

test('mutation admission guards run before token acquisition or network I/O', async () => {
  let called = 0;
  const send = createSandboxFetch(options({ tokenProvider: { getToken: async () => { called++; return 'token'; } } }));
  await assert.rejects(send(new Request(`${baseUrl}/v1/instances`, { method: 'POST', body: '{}' })), { code: 'IDEMPOTENCY_KEY_REQUIRED' });
  await assert.rejects(send(new Request(`${baseUrl}/v1/instances/id/actions/stop`, { method: 'POST', headers: { 'idempotency-key': 'original' }, body: '{}' })), { code: 'STRONG_ETAG_REQUIRED' });
  await assert.rejects(send(new Request(`${baseUrl}/v1/instances`, { headers: { 'x-tenant-id': operationId } })), { code: 'TENANT_CONTEXT_MISMATCH' });
  assert.equal(called, 0);
});

test('401 refreshes once; authorization failures never create an infinite refresh loop', async () => {
  const refreshes = []; let calls = 0;
  const send = createSandboxFetch(options({ tokenProvider: { getToken: async ({ forceRefresh }) => { refreshes.push(forceRefresh); return `token-${refreshes.length}`; } }, fetch: async () => { calls++; return json({ code: 'UNAUTHORIZED' }, 401); } }));
  assert.equal((await send(post())).status, 401);
  assert.deepEqual(refreshes, [false, true]);
  assert.equal(calls, 2);
});

test('4xx conflicts, expired receipts and programming errors are not retried', async () => {
  for (const status of [403, 404, 409, 410, 412, 422, 500]) {
    let calls = 0;
    const send = createSandboxFetch(options({ fetch: async () => { calls++; return json({ code: 'FAILURE' }, status); } }));
    assert.equal((await send(post())).status, status);
    assert.equal(calls, 1);
  }
});

test('Retry-After beyond the caller budget is returned without retrying early', async () => {
  let calls = 0;
  const send = createSandboxFetch(options({ requestTimeoutMs: 20, totalTimeoutMs: 50, fetch: async () => { calls++; return json({}, 429, { 'retry-after': '300' }); } }));
  assert.equal((await send(post())).status, 429);
  assert.equal(calls, 1);
});

test('a structured non-retryable integrity error is not retried just because its status is 502', async () => {
  let calls = 0;
  const send = createSandboxFetch(options({ fetch: async () => {
    calls++;
    return json({ code: 'OUTPUT_INTEGRITY_FAILED', retryable: false }, 502, { 'content-type': 'application/problem+json; charset=utf-8' });
  } }));
  const response = await send(new Request(`${baseUrl}/v1/executions/${operationId}/output`));
  assert.equal(response.status, 502);
  assert.equal((await response.json()).code, 'OUTPUT_INTEGRITY_FAILED');
  assert.equal(calls, 1);
});

test('retryable responses stop after four attempts without replacing the key or precondition', async () => {
  const received = [];
  const send = createSandboxFetch(options({ fetch: async (request) => { received.push([request.headers.get('idempotency-key'), request.headers.get('if-match')]); return json({}, 503, { 'retry-after': '0' }); } }));
  const request = new Request(`${baseUrl}/v1/instances/${operationId}/actions/stop`, { method: 'POST', body: '{}', headers: { 'idempotency-key': 'durable-stop-1', 'if-match': '"17"' } });
  assert.equal((await send(request)).status, 503);
  assert.deepEqual(received, Array(4).fill(['durable-stop-1', '"17"']));
});

test('redirect and foreign origin cannot forward an access token', async () => {
  let calls = 0;
  const send = createSandboxFetch(options({ fetch: async (request) => { calls++; assert.equal(request.redirect, 'manual'); assert.equal(request.credentials, 'omit'); return new Response(null, { status: 307, headers: { location: 'https://other.example/leak' } }); } }));
  await assert.rejects(send(new Request('https://other.example/v1/instances')), { code: 'REQUEST_OUTSIDE_CONFIGURED_API' });
  await assert.rejects(send(post()), { code: 'REDIRECT_REJECTED', outcomeUnknown: true });
  assert.equal(calls, 1);
});

test('HTTP is restricted to explicitly opted-in literal loopback', () => {
  for (const url of ['http://sandbox.example', 'http://localhost', 'http://127.0.0.1.example', 'https://user:secret@sandbox.example', 'https://sandbox.example?token=secret']) {
    assert.throws(() => createSandboxFetch(options({ baseUrl: url, allowLoopbackHttp: true })));
  }
  assert.throws(() => createSandboxFetch(options({ baseUrl: 'http://127.0.0.1:8080' })));
  assert.doesNotThrow(() => createSandboxFetch(options({ baseUrl: 'http://127.0.0.1:8080', allowLoopbackHttp: true })));
});

test('health probes omit access tokens and cookies', async () => {
  let authCalls = 0;
  const send = createSandboxFetch(options({ tokenProvider: { getToken: async () => { authCalls++; return 'token'; } }, fetch: async (request) => {
    assert.equal(request.headers.get('authorization'), null); assert.equal(request.headers.get('cookie'), null); return new Response(null, { status: 204 });
  } }));
  assert.equal((await send(new Request(`${baseUrl}/health/live`, { headers: { authorization: 'Bearer private', cookie: 'session=private' } }))).status, 204);
  assert.equal(authCalls, 0);
});

test('request and response bodies are bounded without leaking data in errors', async () => {
  let calls = 0;
  const send = createSandboxFetch(options({ maxResponseBytes: 1024, fetch: async () => { calls++; return new Response('private'.repeat(500)); } }));
  await assert.rejects(send(new Request(`${baseUrl}/v1/instances`, { method: 'POST', headers: { 'idempotency-key': 'key' }, body: 'x'.repeat(65537) })), { code: 'BODY_LIMIT_EXCEEDED', outcomeUnknown: false });
  assert.equal(calls, 0);
  await assert.rejects(send(post()), (error) => error.code === 'BODY_LIMIT_EXCEEDED' && error.outcomeUnknown && !String(error).includes('private'));
  assert.equal(calls, 1);
});

test('token provider stalls cannot exceed the request deadline or dispatch a command', async () => {
  let calls = 0;
  const start = performance.now();
  const send = createSandboxFetch(options({ requestTimeoutMs: 20, totalTimeoutMs: 50, tokenProvider: { getToken: () => new Promise(() => {}) }, fetch: async () => { calls++; return json({}); } }));
  await assert.rejects(send(post()), { code: 'IDENTITY_PROVIDER_FAILURE', outcomeUnknown: false });
  assert.equal(calls, 0);
  assert.ok(performance.now() - start < 1000);
});

test('a slow response body is bounded by the deadline, not only the initial headers', async () => {
  const send = createSandboxFetch(options({ requestTimeoutMs: 20, totalTimeoutMs: 30, maxAttempts: 1, fetch: async () => new Response(new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode('{')); } })) }));
  await assert.rejects(send(post()), { code: 'TRANSPORT_INTERRUPTED', outcomeUnknown: true, idempotencyKey: 'persisted-command-1' });
});

test('caller cancellation preserves uncertainty and does not initiate another attempt', async () => {
  const controller = new AbortController(); let calls = 0;
  const send = createSandboxFetch(options({ fetch: async () => { calls++; controller.abort(); return new Promise(() => {}); } }));
  await assert.rejects(send(new Request(post(), { signal: controller.signal })), { outcomeUnknown: true });
  assert.equal(calls, 1);
});

test('an interrupted success body is retried using the original receipt key', async () => {
  let calls = 0;
  const send = createSandboxFetch(options({ requestTimeoutMs: 20, totalTimeoutMs: 1500, fetch: async (request) => {
    assert.equal(request.headers.get('idempotency-key'), 'persisted-command-1');
    calls++;
    if (calls === 1) return new Response(new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode('{')); } }), { status: 202 });
    return json({ operation_id: operationId }, 202);
  } }));
  const response = await send(post());
  assert.deepEqual(await response.json(), { operation_id: operationId });
  assert.equal(calls, 2);
});

test('network failure after a forced refresh does not force another refresh', async () => {
  let calls = 0; const refreshes = [];
  const send = createSandboxFetch(options({ tokenProvider: { getToken: async ({ forceRefresh }) => { refreshes.push(forceRefresh); return 'token'; } }, fetch: async () => {
    calls++;
    if (calls === 1) return json({}, 401);
    if (calls === 2) throw new TypeError('connection interrupted');
    return json({}, 202);
  } }));
  assert.equal((await send(post())).status, 202);
  assert.deepEqual(refreshes, [false, true, false]);
});

test('operation wait preserves ID and does not submit cancellation on timeout', async () => {
  const calls = [];
  const client = createSandboxClient(options({ fetch: async (request) => { calls.push(request.method); return json({ id: operationId, status: 'WAITING', stage: 'WAITING_TERMINATION' }); } }));
  const result = await waitOperation(client, tenant, operationId, { timeoutMs: 25, pollIntervalMs: 5 });
  assert.equal(result.kind, 'timeout'); assert.equal(result.operationId, operationId);
  assert.ok(calls.length >= 1); assert.ok(calls.every((method) => method === 'GET'));
});

test('operation FAILED is a terminal result, not an HTTP failure or a resubmission', async () => {
  const client = createSandboxClient(options({ fetch: async () => json({ id: operationId, status: 'FAILED', error: { code: 'CAPACITY' } }) }));
  const result = await waitOperation(client, tenant, operationId);
  assert.equal(result.kind, 'terminal'); assert.equal(result.operation.status, 'FAILED');
});

test('unknown execution returns immediately, preserves safety stop evidence and only reads', async () => {
  const execution = { id: operationId, status: 'OUTCOME_UNKNOWN', slot_held: true, termination_status: 'PENDING', output_status: 'PARTIAL', cancel_operation_id: tenant };
  const requests = [];
  const client = createSandboxClient(options({ fetch: async request => {
    requests.push([request.method, new URL(request.url).pathname]);
    return json(execution);
  } }));
  const result = await waitExecution(client, tenant, operationId);
  assert.deepEqual(result, { kind: 'outcome_unknown', execution });
  assert.deepEqual(requests, [['GET', `/v1/executions/${operationId}`]]);
});

test('execution result does not manufacture VM termination or complete output', async () => {
  for (const [status, termination, slot, output] of [
    ['SUCCEEDED', 'NOT_REQUESTED', false, 'TRUNCATED'],
    ['FAILED', 'NOT_REQUESTED', false, 'COMPLETE'],
    ['TIMED_OUT', 'PENDING', true, 'PARTIAL'],
    ['CANCELLED', 'CONFIRMED', false, 'LOST'],
  ]) {
    const execution = { id: operationId, status, termination_status: termination, slot_held: slot, output_status: output };
    const client = createSandboxClient(options({ fetch: async request => { assert.equal(request.method, 'GET'); return json(execution); } }));
    assert.deepEqual(await waitExecution(client, tenant, operationId), { kind: 'result', execution });
  }
});

test('execution polling timeout preserves execution ID and most recent server evidence', async () => {
  const execution = { id: operationId, status: 'RUNNING', slot_held: true, termination_status: 'NOT_REQUESTED', output_status: 'PENDING' };
  let calls = 0;
  const client = createSandboxClient(options({ fetch: async request => { calls++; assert.equal(request.method, 'GET'); return json(execution); } }));
  const result = await waitExecution(client, tenant, operationId, { timeoutMs: 25, pollIntervalMs: 5 });
  assert.ok(calls >= 1);
  assert.deepEqual(result, { kind: 'timeout', executionId: operationId, lastObserved: execution });
});

test('execution polling respects current revocation and caller abort without resubmission', async () => {
  let calls = 0;
  const client = createSandboxClient(options({ fetch: async () => { calls++; return json({ code: 'FORBIDDEN' }, 403); } }));
  await assert.rejects(waitExecution(client, tenant, operationId), error =>
    error instanceof ExecutionQueryError && error.executionId === operationId && error.status === 403 && error.problem.code === 'FORBIDDEN');
  const controller = new AbortController();
  const reason = new Error('caller stopped waiting');
  controller.abort(reason);
  await assert.rejects(waitExecution(client, tenant, operationId, { signal: controller.signal }), error => error === reason);
  assert.equal(calls, 1);
});

test('only implemented creation endpoints omit a pre-existing resource ETag', async () => {
  let calls = 0;
  const send = createSandboxFetch(options({ fetch: async () => { calls++; return json({}, 201); } }));
  const createGrant = new Request(`${baseUrl}/v1/projects/${operationId}/grants`, {
    method: 'POST', headers: { 'idempotency-key': 'grant-create' }, body: '{}',
  });
  assert.equal((await send(createGrant)).status, 201);
  assert.equal((await send(new Request(`${baseUrl}/v1/service-clients`, {
    method: 'POST', headers: { 'idempotency-key': 'client-create' }, body: '{}',
  }))).status, 201);
  for (const [method, path] of [
    ['PATCH', `/v1/projects/${operationId}/grants/${tenant}`],
    ['DELETE', `/v1/projects/${operationId}/grants/${tenant}`],
    ['POST', `/v1/projects/${operationId}/grants/${tenant}`],
    ['PATCH', `/v1/service-clients/${operationId}`],
    ['POST', `/v1/service-clients/${operationId}`],
  ]) {
    await assert.rejects(send(new Request(`${baseUrl}${path}`, { method, headers: { 'idempotency-key': 'unchanged' }, body: '{}' })), { code: 'STRONG_ETAG_REQUIRED' });
  }
  assert.equal(calls, 2);
});

test('real HTTP redirect is never followed and receives only the bound tenant', async (t) => {
  let leaks = 0; let received = 0;
  const server = createServer((request, response) => {
    if (request.url === '/leak') { leaks++; response.end(); return; }
    received++; assert.equal(request.headers['x-tenant-id'], tenant);
    response.writeHead(307, { location: '/leak' }); response.end();
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => { server.closeAllConnections(); server.close(); });
  const url = `http://127.0.0.1:${server.address().port}`;
  const send = createSandboxFetch(options({ baseUrl: url, allowLoopbackHttp: true }));
  await assert.rejects(send(new Request(`${url}/v1/instances`)), SandboxTransportError);
  assert.equal(received, 1); assert.equal(leaks, 0);
});
