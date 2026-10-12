import assert from 'node:assert/strict';
import test from 'node:test';
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
