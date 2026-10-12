import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import test from 'node:test';
import { createSandboxClient, subscribeEvents } from '../dist/index.js';

const tenant = '00000000-0000-4000-8000-000000000001';
const project = '00000000-0000-4000-8000-000000000002';
const event = { id: '00000000-0000-4000-8000-000000000003', tenant_id: tenant, project_id: project,
  aggregate_id: tenant, aggregate_version: 1, event_type: '实例.created', schema_version: 1,
  operation_id: null, request_id: tenant, occurred_at: '2026-10-03T00:00:00Z' };
const cfg = extra => ({ baseUrl: 'https://sandbox.example', tenantId: tenant,
  tokenProvider: { getToken: async () => 'short-access-token' }, ...extra });
const options = extra => ({ projectId: project, totalTimeoutMs: 3000, ...extra });
const frame = (type, id, value, eol = '\n') => `event: ${type}${eol}${id ? `id: ${id}${eol}` : ''}data: ${JSON.stringify(value)}${eol}${eol}`;
const checkpoint = (id = 'cursor-0', sequence = '0', eol) => frame('stream.checkpoint', id, { sequence }, eol);
const domain = (id = 'cursor-1', sequence = '1', eol) => frame('domain.event', id, { sequence, event }, eol);
const stream = (bytes, chunkSize = bytes.length) => new Response(new ReadableStream({
  start(controller) { for (let n = 0; n < bytes.length; n += chunkSize) controller.enqueue(bytes.slice(n, n + chunkSize)); controller.close(); }
}), { headers: { 'content-type': 'text/event-stream' } });
const sse = (text, chunkSize) => stream(new TextEncoder().encode(text), chunkSize);

test('UTF8 and CRLF split anywhere; checkpoint acknowledged only after caller advances', async () => {
  const saved = [];
  const it = subscribeEvents(cfg({ fetch: async () => sse(checkpoint('cursor-0', '0', '\r\n') + ': heartbeat\r\n\r\n' + domain('cursor-1', '9007199254740993', '\r\n'), 1) }), options({ onCursor: cursor => saved.push(cursor) }));
  const first = await it.next();
  assert.equal(first.value.type, 'stream.checkpoint'); assert.deepEqual(saved, []);
  const second = await it.next();
  assert.equal(second.value.sequence, '9007199254740993'); assert.equal(second.value.event.event_type, '实例.created');
  assert.deepEqual(saved, ['cursor-0']);
  await it.return();
  assert.deepEqual(saved, ['cursor-0'], 'return does not acknowledge caller work');
});

test('network loss refreshes token and reconnects only from delivered checkpoint', async () => {
  const calls = [], refreshes = []; let sends = 0;
  const it = subscribeEvents(cfg({ tokenProvider: { getToken: async ({ forceRefresh }) => { refreshes.push(forceRefresh); return 'token'; } }, fetch: async request => {
    calls.push(request);
    return sse(++sends === 1 ? checkpoint('ack-0') + 'id: partial-never-ack\nevent: domain.event\ndata: {' : checkpoint('ack-0') + domain('next-1'));
  } }), options({ maxReconnects: 1 }));
  assert.equal((await it.next()).value.cursor, 'ack-0');
  assert.equal((await it.next()).value.cursor, 'ack-0');
  assert.equal((await it.next()).value.cursor, 'next-1');
  await it.return();
  assert.deepEqual(refreshes, [false, true]);
  assert.equal(calls[1].headers.get('last-event-id'), 'ack-0');
  assert.equal(calls[0].headers.get('x-tenant-id'), tenant);
  assert.equal(calls[0].credentials, 'omit'); assert.equal(calls[0].redirect, 'manual');
  assert.equal(new URL(calls[0].url).searchParams.has('token'), false);
});

test('400, 403, 409 and 410 never clear cursor or retry', async () => {
  for (const status of [400, 403, 409, 410]) {
    let calls = 0;
    const it = subscribeEvents(cfg({ fetch: async request => { calls++; assert.equal(request.headers.get('last-event-id'), 'saved-cursor');
      return new Response(JSON.stringify({ code: 'EVENT_HISTORY_UNAVAILABLE', retryable: true }), { status, headers: { 'content-type': 'application/problem+json' } });
    } }), options({ lastEventId: 'saved-cursor' }));
    await assert.rejects(it.next(), { code: 'EVENT_HISTORY_UNAVAILABLE', status, retryable: false });
    assert.equal(calls, 1);
  }
});

test('retryable service failure is bounded; Retry-After beyond budget is not shortened', async () => {
  let calls = 0;
  const it = subscribeEvents(cfg({ fetch: async () => { calls++; return new Response(JSON.stringify({ code: 'EVENT_STREAM_LIMIT', retryable: true }),
    { status: 503, headers: { 'content-type': 'application/problem+json', 'retry-after': '300' } }); } }), options({ totalTimeoutMs: 100 }));
  await assert.rejects(it.next(), { code: 'EVENT_STREAM_LIMIT', status: 503 }); assert.equal(calls, 1);
  calls = 0;
  const limited = subscribeEvents(cfg({ fetch: async () => { calls++; throw new TypeError('internal secret marker'); } }), options({ maxReconnects: 1 }));
  await assert.rejects(limited.next(), { code: 'EVENT_RECONNECT_LIMIT' }); assert.equal(calls, 2);
});

test('stream error cannot acknowledge progress; nonretryable errors close without replay', async () => {
  const saved = [];
  const it = subscribeEvents(cfg({ fetch: async () => sse(checkpoint() + frame('stream.error', null, { code: 'NOT_FOUND', retryable: false, request_id: tenant })) }), options({ onCursor: id => saved.push(id) }));
  await it.next(); await assert.rejects(it.next(), { code: 'NOT_FOUND', requestId: tenant });
  assert.deepEqual(saved, ['cursor-0']);
});

test('oversized, invalid UTF8, wrong scope and backward positions fail closed', async () => {
  for (const response of [
    sse('data: ' + 'a'.repeat(256 * 1024)),
    sse('data:\r\n'.repeat(40000)),
    stream(new Uint8Array([100, 97, 116, 97, 58, 32, 255, 10, 10])),
    sse(checkpoint() + frame('domain.event', 'next', { sequence: '1', event: { ...event, tenant_id: project } })),
    sse(checkpoint() + frame('domain.event', 'unsafe-version', { sequence: '1', event: { ...event, aggregate_version: Number.MAX_SAFE_INTEGER + 1 } })),
    sse(checkpoint('one', '2') + domain('back', '1')),
  ]) {
    const it = subscribeEvents(cfg({ fetch: async () => response }), options());
    await assert.rejects(async () => { for await (const _ of it) {} }, e => ['EVENT_FRAME_LIMIT', 'INVALID_EVENT_STREAM'].includes(e.code));
  }
});

test('missing initial checkpoint must not silently jump latest; cursor persistence failure is fatal', async () => {
  let calls = 0;
  const empty = subscribeEvents(cfg({ fetch: async () => { calls++; return sse(''); } }), options());
  await assert.rejects(empty.next(), { code: 'EVENT_CHECKPOINT_MISSING' }); assert.equal(calls, 1);
  const broken = subscribeEvents(cfg({ fetch: async () => new Response(new ReadableStream({ start(c) { c.error(new Error('reset')); } }),
    { headers: { 'content-type': 'text/event-stream' } }) }), options());
  await assert.rejects(broken.next(), { code: 'EVENT_CHECKPOINT_MISSING' });
  const it = subscribeEvents(cfg({ fetch: async () => sse(checkpoint() + domain()) }), options({ onCursor: () => { throw new Error('db secret'); } }));
  await it.next(); await assert.rejects(it.next(), { code: 'EVENT_CURSOR_PERSIST_FAILED' });
});

test('ordinary JSON client refuses streaming before obtaining a token', async () => {
  const client = createSandboxClient(cfg({ tokenProvider: { getToken: async () => { assert.fail('must not acquire token'); } } }));
  await assert.rejects(client.GET('/v1/events/stream', { params: { query: { project_id: project }, header: { 'X-Tenant-ID': tenant } } }), { code: 'STREAMING_TRANSPORT_REQUIRED' });
});

test('token refresh after 401 is attempted once, including no application progress', async () => {
  const refreshes = []; let calls = 0;
  const it = subscribeEvents(cfg({ tokenProvider: { getToken: async ({ forceRefresh }) => { refreshes.push(forceRefresh); return 'token'; } },
    fetch: async () => { calls++; return new Response('{}', { status: 401, headers: { 'content-type': 'application/problem+json' } }); }
  }), options());
  await assert.rejects(it.next(), { status: 401, retryable: false });
  assert.equal(calls, 2); assert.deepEqual(refreshes, [false, true]);
});

test('caller abort and total timeout bound transports that ignore AbortSignal', async () => {
  const control = new AbortController();
  const it = subscribeEvents(cfg({ fetch: async () => new Promise(() => {}) }), options({ signal: control.signal }));
  const pending = it.next(); control.abort(new Error('caller stopped'));
  await assert.rejects(pending, /caller stopped/);
  const hung = subscribeEvents(cfg({ tokenProvider: { getToken: async () => new Promise(() => {}) } }), options({ totalTimeoutMs: 20 }));
  await assert.rejects(hung.next(), { code: 'EVENT_STREAM_TIMEOUT' });
});

test('real HTTP stream keeps credentials in headers and never follows redirect', async () => {
  const requests = [];
  const server = createServer((req, res) => { requests.push(req.url); res.writeHead(302, { location: '/steal' }); res.end(); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  try {
    const it = subscribeEvents(cfg({ baseUrl: `http://127.0.0.1:${server.address().port}`, allowLoopbackHttp: true }), options());
    await assert.rejects(it.next(), { code: 'REDIRECT_REJECTED' });
    assert.equal(requests.length, 1); assert.equal(requests[0].includes('token'), false);
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});
