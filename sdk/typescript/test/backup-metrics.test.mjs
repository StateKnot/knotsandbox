import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { createSandboxClient } from '../dist/index.js';
const tenant = '00000000-0000-4000-8000-000000000001';
const resource = '00000000-0000-4000-8000-000000000002';
const clientFor = fetch => createSandboxClient({ baseUrl: 'https://sandbox.example', tenantId: tenant, tokenProvider: { getToken: async () => 'test-access-token' }, fetch });

test('diagnosis creation retries the same request without an instance mutation precondition', async () => {
  const sent = [];
  const client = clientFor(async request => {
    sent.push({method: request.method, path: new URL(request.url).pathname, key: request.headers.get('idempotency-key'), etag: request.headers.get('if-match'), body: await request.text()});
    if (sent.length === 1) throw new TypeError('response lost');
    return Response.json({resource: {id: resource, status: 'PENDING', report: null}, operation: {id: resource, kind: 'DIAGNOSE', status: 'QUEUED'}}, {status: 202});
  });
  const result = await client.POST('/v1/instances/{id}/diagnoses', {params: {path: {id: resource}, header: {'X-Tenant-ID': tenant, 'Idempotency-Key': 'durable-diagnosis-key'}}, body: {include_operations: false, include_executions: false}});
  assert.equal(result.data.operation.kind, 'DIAGNOSE');
  assert.equal(result.data.resource.report, null);
  assert.equal(sent.length, 2);
  assert.deepEqual(sent[0], sent[1]);
  assert.equal(sent[0].etag, null);
  assert.equal(sent[0].key, 'durable-diagnosis-key');
});

test('cold backup retry preserves workspace precondition and identity after lost response', async () => {
  const sent = [];
  const client = clientFor(async request => {
    sent.push({ path: new URL(request.url).pathname, method: request.method, key: request.headers.get('idempotency-key'), etag: request.headers.get('if-match'), body: await request.text() });
    if (sent.length === 1) throw new TypeError('test response lost');
    return new Response(JSON.stringify({ resource: { id: resource, status: 'QUEUED' }, operation: { id: resource, kind: 'BACKUP', status: 'QUEUED' }, workspace_version: 8 }), { status: 202, headers: { 'content-type': 'application/json', 'x-workspace-etag': '"8"', location: `/v1/operations/${resource}` } });
  });
  const body = { profile_id: resource, retention_days: 31 };
  const result = await client.POST('/v1/workspaces/{id}/backups', { params: { path: { id: resource }, header: { 'X-Tenant-ID': tenant, 'Idempotency-Key': 'persisted-cold-backup-key', 'If-Match': '"7"' } }, body });
  assert.equal(result.data.operation.kind, 'BACKUP');
  assert.equal(result.data.resource.status, 'QUEUED');
  assert.equal(result.response.headers.get('x-workspace-etag'), '"8"');
  assert.deepEqual(sent, Array(2).fill({ path: `/v1/workspaces/${resource}/backups`, method: 'POST', key: 'persisted-cold-backup-key', etag: '"7"', body: JSON.stringify(body) }));
});

test('cold backup missing workspace ETag is rejected before sending', async () => {
  let sent = 0;
  const client = clientFor(async () => { sent++; throw new Error('unexpected'); });
  await assert.rejects(client.POST('/v1/workspaces/{id}/backups', { params: { path: { id: resource }, header: { 'X-Tenant-ID': tenant, 'Idempotency-Key': 'persisted-cold-backup-key' } }, body: { profile_id: resource, retention_days: 31 } }), error => error.code === 'STRONG_ETAG_REQUIRED');
  assert.equal(sent, 0);
});

test('metrics preserves an explicit launch and missing values without mutation or zero filling', async () => {
  const client = clientFor(async request => {
    assert.equal(request.method, 'GET');
    assert.equal(request.headers.get('idempotency-key'), null);
    const query = new URL(request.url).searchParams;
    assert.equal(query.get('launch_id'), resource);
    assert.equal(query.get('metric'), 'VM_MEMORY_BYTES');
    assert.equal(query.get('step_seconds'), '15');
    return Response.json({ instance_id: resource, launch_id: resource, series: { points: [{ evaluated_at: '2026-10-03T00:00:00Z', observed_at: null, value: null, status: 'MISSING', collector_replica: null }] } });
  });
  const result = await client.GET('/v1/instances/{id}/metrics', { params: { path: { id: resource }, header: { 'X-Tenant-ID': tenant }, query: { metric: 'VM_MEMORY_BYTES', start: '2026-10-03T00:00:00Z', end: '2026-10-03T00:01:00Z', step_seconds: 15, launch_id: resource } } });
  assert.equal(result.data.series.points[0].status, 'MISSING');
  assert.equal(result.data.series.points[0].value, null);
});

test('host efficiency metrics keep fixed selectors, units, genuine zero and missing samples', async () => {
  for (const [metric, unit, value] of [
    ['VM_CPU_THROTTLED_PERIODS_PER_SECOND', 'periods_per_second', 2],
    ['VM_CPU_THROTTLED_SECONDS_PER_SECOND', 'seconds_per_second', 1.5],
    ['VM_MEMORY_ANON_BYTES', 'bytes', 4096],
    ['VM_MEMORY_FILE_BYTES', 'bytes', 8192],
    ['VM_MEMORY_OOM_EVENTS_PER_SECOND', 'events_per_second', 0],
    ['VM_MEMORY_OOM_KILLS_PER_SECOND', 'events_per_second', 0.2],
  ]) {
    const client = clientFor(async request => {
      assert.equal(request.method, 'GET');
      assert.equal(request.headers.get('idempotency-key'), null);
      assert.equal(request.headers.get('x-tenant-id'), tenant);
      const query = new URL(request.url).searchParams;
      assert.equal(query.get('metric'), metric);
      assert.equal(query.get('launch_id'), resource);
      return Response.json({ instance_id: resource, launch_id: resource, series: { metric, unit, points: [
        { value, status: 'FRESH', collector_replica: 'a' },
        { value: null, status: 'MISSING', collector_replica: null },
      ] } });
    });
    const result = await client.GET('/v1/instances/{id}/metrics', { params: { path: { id: resource }, header: { 'X-Tenant-ID': tenant }, query: { metric, start: '2026-10-12T00:00:00Z', end: '2026-10-12T00:01:00Z', step_seconds: 15, launch_id: resource } } });
    assert.equal(result.data.series.unit, unit);
    assert.equal(result.data.series.points[0].value, value);
    assert.equal(result.data.series.points[1].value, null);
  }
});

test('capacity metrics use real HTTP, retain raw cores/bytes and gaps, and never reuse a denied series', async () => {
  const samples = new Map([
    ['VM_CPU_CAPACITY_CORES', { unit: 'cores', values: [0.75, 2.5] }],
    ['VM_MEMORY_CAPACITY_BYTES', { unit: 'bytes', values: [536870912, 8589934592] }],
  ]);
  const received = [];
  const denied = new Set();
  const server = createServer((request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    const metric = url.searchParams.get('metric');
    assert.equal(request.method, 'GET');
    assert.equal(url.pathname, `/v1/instances/${resource}/metrics`);
    assert.equal(request.headers.authorization, 'Bearer test-access-token');
    assert.equal(request.headers['x-tenant-id'], tenant);
    assert.equal(request.headers['idempotency-key'], undefined);
    assert.equal(request.headers['if-match'], undefined);
    assert.equal(url.searchParams.get('launch_id'), resource);
    assert.equal(url.searchParams.get('start'), '2026-10-13T00:00:00Z');
    assert.equal(url.searchParams.get('end'), '2026-10-13T00:01:00Z');
    assert.equal(url.searchParams.get('step_seconds'), '15');
    assert(samples.has(metric));
    received.push(metric);
    if (denied.has(metric)) {
      response.writeHead(404, { 'content-type': 'application/problem+json', 'cache-control': 'no-store' });
      response.end(JSON.stringify({ code: 'RESOURCE_NOT_FOUND', retryable: false }));
      return;
    }
    const sample = samples.get(metric);
    response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    response.end(JSON.stringify({ instance_id: resource, launch_id: resource,
      generation: 1, cluster_epoch: tenant, queried_at: '2026-10-13T00:01:00Z', series: {
      metric, unit: sample.unit, source: 'HOST_VM_RUNTIME', stale_after_seconds: 60, points: [
        { evaluated_at: '2026-10-13T00:00:00Z', observed_at: '2026-10-13T00:00:00Z', value: sample.values[0], status: 'FRESH', collector_replica: 'a' },
        { evaluated_at: '2026-10-13T00:00:15Z', observed_at: null, value: null, status: 'MISSING', collector_replica: null },
        { evaluated_at: '2026-10-13T00:00:30Z', observed_at: '2026-10-12T23:58:00Z', value: null, status: 'STALE', collector_replica: 'a' },
        { evaluated_at: '2026-10-13T00:00:45Z', observed_at: '2026-10-13T00:00:45Z', value: sample.values[1], status: 'FRESH', collector_replica: 'a' },
      ],
    } }));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const client = createSandboxClient({
      baseUrl: `http://127.0.0.1:${server.address().port}`, allowLoopbackHttp: true,
      tenantId: tenant, tokenProvider: { getToken: async () => 'test-access-token' },
    });
    for (const [metric, sample] of samples) {
      const params = { path: { id: resource }, header: { 'X-Tenant-ID': tenant }, query: {
        metric, start: '2026-10-13T00:00:00Z', end: '2026-10-13T00:01:00Z', step_seconds: 15, launch_id: resource,
      } };
      const result = await client.GET('/v1/instances/{id}/metrics', { params });
      assert.equal(result.response.status, 200);
      assert.equal(result.data.series.metric, metric);
      assert.equal(result.data.series.unit, sample.unit);
      assert.equal(result.data.series.source, 'HOST_VM_RUNTIME');
      assert.deepEqual(result.data.series.points.map(point => [point.value, point.status]), [
        [sample.values[0], 'FRESH'], [null, 'MISSING'], [null, 'STALE'], [sample.values[1], 'FRESH'],
      ]);
      denied.add(metric);
      const revoked = await client.GET('/v1/instances/{id}/metrics', { params });
      assert.equal(revoked.response.status, 404);
      assert.equal(revoked.data, undefined);
      assert.equal(revoked.error.code, 'RESOURCE_NOT_FOUND');
    }
    assert.deepEqual(received, [...samples.keys()].flatMap(metric => [metric, metric]));
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});
