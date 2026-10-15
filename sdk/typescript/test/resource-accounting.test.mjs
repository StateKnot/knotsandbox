import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { abortable, createSandboxClient, getResourceAccounting, ResourceAccountingQueryError } from '../dist/index.js';

const tenant = '00000000-0000-4000-8000-000000000001';
const instance = '00000000-0000-4000-8000-000000000002';
const launch = '00000000-0000-4000-8000-000000000003';
const now = '2026-10-15T00:00:00Z';
function fixturePage() {
  return {
    instance_id: instance, selected_launch_id: launch, cluster_epoch: tenant,
    request_evidence: 'CAPTURED', pod_resource_evidence: 'NOT_CAPTURED',
    pod_resource_observation: null,
    contract: { id: launch, instance_id: instance, workspace_id: tenant,
      generation: '9007199254740993', launch_id: launch, cluster_epoch: tenant,
      operation_id: instance, cpu_millis: '1000', memory_mib: '2048',
      source: 'REQUESTED_COMPUTE_QUOTA', recorded_at: now },
    receipts: { cutoff: now, next_cursor: 'signed.opaque.cursor', items: [{
      id: launch, reservation_id: launch, quota_account_id: tenant, operation_id: instance,
      resource_id: instance, operation_kind: 'START', purpose: 'ORDINARY_COMPUTE',
      dimension: 'CPU_MILLIS', unit: 'MILLICORES', account_scope: 'TENANT',
      account_project_id: null, amount: '1000', limit_value: '9223372036854775807',
      account_version: '9007199254740993', pending_value: '9007199254740993', allocated_value: '0',
      previous_status: null, status: 'PENDING', history_start: 'CAPTURED', captured_at: now,
      contract_id: launch, generation: '9007199254740993', launch_id: launch, cluster_epoch: tenant,
    }] },
  };
}
function observedPage() {
  const page = fixturePage();
  page.pod_resource_evidence = 'KUBERNETES_API_READBACK';
  const workload = { cpu_millis: '1000', memory_bytes: '2147483648', ephemeral_storage_bytes: '1073741824' };
  const overhead = { cpu_millis: '40', memory_bytes: '9007199254740993' };
  const effective = { cpu_millis: '1040', memory_bytes: '9007201402224641', ephemeral_storage_bytes: '1073741824' };
  page.pod_resource_observation = {
    id: launch, instance_id: instance, workspace_id: tenant, generation: page.contract.generation,
    launch_id: launch, cluster_epoch: tenant, pod_uid: instance, pod_resource_version: 'opaque:pod-rv',
    node_uid: tenant, node_boot_id: launch,
    runtime_class: { uid: launch, resource_version: 'opaque:class-rv', config_sha256: 'a'.repeat(64), overhead: { ...overhead } },
    workload_request: { ...workload }, workload_limit: { ...workload }, pod_overhead: { ...overhead },
    effective_request: { ...effective }, effective_limit: { ...effective },
    source: 'KUBERNETES_API_READBACK', observed_at: now, recorded_at: now,
  };
  return page;
}
async function serverClient(handler) {
  const server = createServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return {
    client: createSandboxClient({
      baseUrl: `http://127.0.0.1:${server.address().port}`, allowLoopbackHttp: true,
      tenantId: tenant, maxAttempts: 1,
      tokenProvider: { getToken: async () => 'resource-accounting-test-token' },
    }),
    close: async () => {
      server.closeAllConnections();
      await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    },
  };
}

test('real HTTP readonly pages preserve decimal precision and unchanged launch/cursor scope', { timeout: 10000 }, async () => {
  const queries = [];
  const sample = fixturePage();
  const fixture = await serverClient((request, response) => {
    assert.equal(request.method, 'GET');
    assert.equal(request.headers.authorization, 'Bearer resource-accounting-test-token');
    assert.equal(request.headers['x-tenant-id'], tenant);
    assert.equal(request.headers['idempotency-key'], undefined);
    assert.equal(request.headers['if-match'], undefined);
    const url = new URL(request.url, 'http://127.0.0.1');
    assert.equal(url.pathname, `/v1/instances/${instance}/resource-accounting`);
    assert.equal(url.searchParams.get('launch_id'), launch);
    assert.equal(url.searchParams.get('limit'), '1');
    assert.equal(url.searchParams.has('project_id'), false);
    queries.push(url.searchParams.get('cursor'));
    response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    response.end(JSON.stringify(sample));
  });
  try {
    const first = await getResourceAccounting(fixture.client, tenant, instance, { launchId: launch, limit: 1 });
    assert.deepEqual(first, sample);
    const second = await getResourceAccounting(fixture.client, tenant, instance, {
      launchId: launch, limit: 1, cursor: first.receipts.next_cursor,
    });
    assert.deepEqual(queries, [null, 'signed.opaque.cursor']);
    assert.equal(second.contract.generation, '9007199254740993');
    assert.equal(second.receipts.items[0].amount, '1000');
    assert.equal(second.receipts.items[0].pending_value, '9007199254740993');
    assert.equal(second.receipts.items[0].limit_value, '9223372036854775807');
    assert.equal(second.receipts.items[0].account_version, '9007199254740993');
    assert.equal(second.receipts.items[0].allocated_value, '0');
    assert.equal(second.pod_resource_evidence, 'NOT_CAPTURED');
  } finally { await fixture.close(); }
});

test('real HTTP revocation does not reuse a page or retry a hidden resource', { timeout: 10000 }, async () => {
  let calls = 0;
  const fixture = await serverClient((_request, response) => {
    const denied = ++calls > 1;
    response.writeHead(denied ? 404 : 200, { 'content-type': denied ? 'application/problem+json' : 'application/json' });
    response.end(JSON.stringify(denied ? { code: 'NOT_FOUND', retryable: false } : fixturePage()));
  });
  try {
    const first = await getResourceAccounting(fixture.client, tenant, instance);
    assert.equal(first.contract.cpu_millis, '1000');
    await assert.rejects(getResourceAccounting(fixture.client, tenant, instance), error =>
      error instanceof ResourceAccountingQueryError && error.status === 404 && error.problem.code === 'NOT_FOUND');
    assert.equal(calls, 2);
  } finally { await fixture.close(); }
});

test('trusted Pod observations retain exact byte quantities and opaque versions over real HTTP', { timeout: 10000 }, async () => {
  const sample = observedPage();
  const fixture = await serverClient((_request, response) => {
    response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    response.end(JSON.stringify(sample));
  });
  try {
    const page = await getResourceAccounting(fixture.client, tenant, instance);
    assert.deepEqual(page, sample);
    assert.equal(page.pod_resource_observation.pod_overhead.memory_bytes, '9007199254740993');
    assert.equal(page.pod_resource_observation.effective_request.memory_bytes, '9007201402224641');
    assert.equal(page.pod_resource_observation.runtime_class.resource_version, 'opaque:class-rv');
  } finally { await fixture.close(); }
});

test('malformed, conflicting and wrongly scoped evidence fails closed instead of presenting zero', { timeout: 10000 }, async () => {
  let sample;
  const fixture = await serverClient((_request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(sample));
  });
  try {
    for (const damage of [
      page => { page.pod_resource_observation.workload_request.cpu_millis = 1000; },
      page => { page.pod_resource_observation.workload_request.memory_bytes = '9223372036854775808'; },
      page => { page.pod_resource_observation.workload_request.memory_bytes = '10000000000000000000'; },
      page => { page.pod_resource_observation.workload_request.memory_bytes = '01'; },
      page => { page.pod_resource_observation.workload_request.memory_bytes = '-1'; },
      page => { page.pod_resource_observation.runtime_class.resource_version = 17; },
      page => { page.pod_resource_observation.workload_request['nvidia.com/gpu'] = '1'; },
      page => { page.pod_resource_observation.source = 'HOST_MEASURED'; },
      page => { page.pod_resource_observation = null; },
      page => { page.pod_resource_evidence = 'NOT_CAPTURED'; },
      page => { page.pod_resource_observation.effective_limit.cpu_millis = '0'; },
      page => { page.pod_resource_observation.instance_id = tenant; },
      page => { page.pod_resource_observation.runtime_class.overhead.cpu_millis = '0'; },
      page => {
        page.pod_resource_observation.workload_request.ephemeral_storage_bytes = '0';
        page.pod_resource_observation.workload_limit.ephemeral_storage_bytes = '0';
        page.pod_resource_observation.effective_request.ephemeral_storage_bytes = '0';
        page.pod_resource_observation.effective_limit.ephemeral_storage_bytes = '0';
      },
      page => {
        page.pod_resource_observation.workload_limit.cpu_millis = '2000';
        page.pod_resource_observation.effective_limit.cpu_millis = '2040';
      },
      page => { page.contract.memory_mib = '4096'; },
    ]) {
      sample = observedPage();
      damage(sample);
      await assert.rejects(getResourceAccounting(fixture.client, tenant, instance), /RESOURCE_ACCOUNTING_RESPONSE_INVALID/);
    }
  } finally { await fixture.close(); }
});

test('real HTTP caller cancellation terminates a waiting readonly page', { timeout: 10000 }, async context => {
  let arrived;
  const received = new Promise(resolve => { arrived = resolve; });
  const fixture = await serverClient(() => arrived());
  try {
    const controller = new AbortController();
    const pending = getResourceAccounting(fixture.client, tenant, instance, { signal: AbortSignal.any([controller.signal, context.signal]) });
    const rejected = assert.rejects(pending);
    await abortable(received, context.signal);
    controller.abort(new DOMException('Caller left instance', 'AbortError'));
    await rejected;
  } finally { await fixture.close(); }
});

test('invalid identifiers and unbounded page parameters never reach transport', async () => {
  let sent = 0;
  const client = createSandboxClient({ baseUrl: 'https://sandbox.example', tenantId: tenant,
    tokenProvider: { getToken: async () => 'resource-accounting-test-token' },
    fetch: async () => { sent++; throw new Error('unexpected HTTP'); } });
  for (const options of [{ limit: 0 }, { limit: 101 }, { limit: 1.5 }, { limit: NaN },
    { launchId: '../another-launch' }, { cursor: '' }, { cursor: 'a'.repeat(2049) }]) {
    await assert.rejects(getResourceAccounting(client, tenant, instance, options), /INVALID_RESOURCE_ACCOUNTING_QUERY/);
  }
  await assert.rejects(getResourceAccounting(client, 'other', instance), /INVALID_RESOURCE_ACCOUNTING_QUERY/);
  await assert.rejects(getResourceAccounting(client, tenant, 'other'), /INVALID_RESOURCE_ACCOUNTING_QUERY/);
  assert.equal(sent, 0);
});
