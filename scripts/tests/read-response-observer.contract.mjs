// Actual Chromium + native loopback HTTP contracts. These fixtures certify the
// observer seam, not product identity, database, Kata/GPU or cloud deployment.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { isAbsolute } from 'node:path';
import { before, after, test } from 'node:test';
import { chromium } from '../../console/node_modules/playwright-core/index.mjs';
import { installMutationResponseObserver, mutationResponseJson, observeReadResponse } from './mutation-response-observer.mjs';

assert.equal(process.argv.length, 4);
assert.equal(process.argv[2], '--chrome');
assert(isAbsolute(process.argv[3]));
const id = '00000000-0000-4000-8000-000000000001';
const tenant = '00000000-0000-4000-8000-000000000002';
const project = '00000000-0000-4000-8000-000000000003';
const slot = '__sandboxMutationResponseObserver';
const profiles = ['SERVICE_CLIENT', 'DIAGNOSIS', 'AUTOMATION', 'GRANT', 'NOTIFICATION', 'LIFECYCLE'];
const detail = `/v1/diagnoses/${id}`;
const targets = [
  '/v1/service-clients?limit=1&cursor=opaque_signed_cursor',
  `/v1/service-clients/${id}`, detail, `/v1/automations/${id}`,
  `/v1/automations/${id}/runs?project_id=${project}&instance_id=${id}&limit=20&cursor=opaque_run_cursor`,
  `/v1/automation-notifications?project_id=${project}&instance_id=${id}&limit=100&cursor=opaque_notice_cursor`,
  `/v1/automation-notifications/${id}`, `/v1/instances/${id}/details`,
];
let server, browser, origin;
const calls = [];
const truncatedResponses = new Map();
const options = { timeout: 30000 };
function expected(method, target, status = 200) {
  return status === 404 ? { code: 'RESOURCE_NOT_FOUND' } : { resource: { id, version: 4 }, method, target };
}
before(async () => {
  server = createServer((request, response) => {
    if (request.url === '/') {
      response.setHeader('content-type', 'text/html');
      response.end('<p>One-shot read observation</p><script>window.sdkSend=fetch.bind(window)</script>'); return;
    }
    if (!request.url.startsWith('/v1/') && !request.url.startsWith('/auth/')) { response.writeHead(204); response.end(); return; }
    calls.push({ method: request.method, target: request.url, tenant: request.headers['x-tenant-id'], headers: Object.keys(request.headers).sort() });
    const scenario = request.headers['x-scenario'];
    if (scenario === 'redirect') { response.writeHead(307, { location: '/redirect-target' }); response.end(); return; }
    const status = scenario?.startsWith('status') ? Number(scenario.slice(6)) : request.method === 'POST' ? 201 : 200;
    response.statusCode = status;
    response.setHeader('content-type', 'application/json');
    if (status !== 404) response.setHeader('etag', '"4"');
    if (request.url.endsWith('/details')) response.setHeader('x-instance-etag', '"4"');
    if (scenario === 'invalid') { response.end('{invalid'); return; }
    if (scenario === 'invalid_utf8') { response.end(Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d])); return; }
    if (scenario === 'abort' || scenario === 'stall') { response.write('{"resource":'); return; }
    if (scenario === 'truncated') {
      response.setHeader('content-length', '900'); response.flushHeaders(); response.write('{"resource":');
      truncatedResponses.set(request.url, response); return;
    }
    const body = expected(request.method, request.url, status);
    if (scenario?.startsWith('credential:')) body.resource.nested = { [scenario.slice(11)]: 'public-contract-credential-sentinel' };
    if (scenario === 'boundary' || scenario === 'overflow') {
      body.text = '';
      body.text = 'a'.repeat(256 * 1024 - Buffer.byteLength(JSON.stringify(body)) + (scenario === 'overflow' ? 1 : 0));
    }
    response.end(JSON.stringify(body));
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  origin = 'http://127.0.0.1:' + server.address().port;
  browser = await chromium.launch({ headless: true, executablePath: process.argv[3] });
}, { timeout: 30000 });
after(async () => {
  await browser?.close(); server?.closeAllConnections();
  if (server?.listening) await new Promise((resolve) => server.close(resolve));
});
async function pageFor(install = true) {
  const page = await browser.newPage();
  await page.addInitScript(() => {
    const nativeFetch = window.fetch, clone = Response.prototype.clone;
    window.nativeCalls = 0; window.cloneCalls = 0; window.headerReads = [];
    Response.prototype.clone = function () { window.cloneCalls++; return Reflect.apply(clone, this, []); };
    window.fetch = function (...args) {
      window.nativeCalls++; window.nativeInput = args[0]; window.nativeInit = args[1];
      window.nativePromise = Reflect.apply(nativeFetch, this, args);
      window.nativePromise.then((response) => { window.nativeResponse = response; }, () => {});
      return window.nativePromise;
    };
  });
  if (install) await installMutationResponseObserver(page, origin, profiles);
  await page.goto(origin); return page;
}
async function start(page, target = detail, scenario = 'valid', options = {}) {
  await page.evaluate(({ target, tenant, scenario, options }) => {
    delete window.originalBody; delete window.originalBodyFailed; delete window.originalFetchFailed;
    window.control = new AbortController();
    let headers = { 'X-Scenario': scenario, Authorization: 'public-contract-auth-sentinel' };
    if (options.tenant !== null) headers['X-Tenant-ID'] = options.tenant ?? tenant;
    if (options.method && options.method !== 'GET') headers['Idempotency-Key'] = options.key;
    if (options.headers === 'pairs') headers = Object.entries(headers);
    if (options.headers === 'object') {
      const lower = {};
      for (const [key, value] of Object.entries(headers)) lower[key.toLowerCase()] = value;
      headers = lower;
    }
    const request = new Request(target, { method: options.method ?? 'GET', headers, signal: window.control.signal, redirect: 'error' });
    const get = request.headers.get.bind(request.headers);
    request.headers.get = (name) => { window.headerReads.push(name.toLowerCase()); return get(name); };
    window.originalInput = request;
    const pending = (options.direct ? window.fetch : window.sdkSend)(request);
    window.promiseSame = pending === window.nativePromise;
    window.operation = pending.then(async (response) => {
      window.responseSame = response === window.nativeResponse;
      try { window.originalBody = await response.json(); }
      catch { window.originalBodyFailed = true; }
    }, () => { window.originalFetchFailed = true; });
  }, { target: origin + target, tenant, scenario, options });
}
async function native(page) {
  await page.evaluate(() => window.operation);
  assert.deepEqual(await page.evaluate(() => [window.promiseSame, window.responseSame,
    window.nativeInput === window.originalInput, window.nativeInput.signal === window.originalInput.signal]), [true, true, true, true]);
}
async function observe(page, target = detail, scenario = 'valid', options = {}) {
  return observeReadResponse(page, origin, target, tenant, async () => { await start(page, target, scenario, options); await native(page); });
}
async function assertFresh(page) {
  const { body } = await observe(page); assert.deepEqual(body, expected('GET', detail));
}

test('same real GET native and external CDP bodies agree before retention loss and one clone remains after actual Network.disable', options, async () => {
  const count = calls.length, page = await pageFor(), cdp = await page.context().newCDPSession(page);
  try {
    await cdp.send('Network.enable'); let requestId, originalResponse;
    cdp.on('Network.responseReceived', (event) => { if (event.response.url === origin + detail) requestId = event.requestId; });
    const result = await observeReadResponse(page, origin, detail, tenant, async () => {
      const pending = page.waitForResponse((response) => response.url() === origin + detail);
      await start(page); await native(page); originalResponse = await pending;
      assert(requestId); assert.equal(originalResponse.status(), 200);
      const cdpJson = async () => { const actual = await cdp.send('Network.getResponseBody', { requestId }); return JSON.parse(actual.base64Encoded ? Buffer.from(actual.body, 'base64').toString('utf8') : actual.body); };
      assert.deepEqual(await cdpJson(), await page.evaluate(() => window.originalBody));
      await cdp.send('Network.disable');
      await assert.rejects(cdpJson(), /No resource with given identifier found|No data found for resource with given identifier/);
      originalResponse.json = cdpJson; // A genuine CDP request; no fabricated body or exception.
    });
    assert.equal(result.response, originalResponse); assert.equal(result.response.status(), 200);
    assert.deepEqual(result.body, expected('GET', detail));
    assert.deepEqual(result.body, await page.evaluate(() => window.originalBody));
    await assert.rejects(result.response.json(), /No resource with given identifier found|No data found for resource with given identifier/);
    assert.equal(calls.length - count, 1); assert.deepEqual(await page.evaluate(() => [window.nativeCalls, window.cloneCalls]), [1, 1]);
    assert.equal(calls[count].tenant, tenant);
    assert(!calls[count].headers.some((name) => name.includes('observer') || name.includes('ticket')));
  } finally { await cdp.detach(); await page.close(); }
});

test('all eight closed real business GET routes preserve native Request Promise Response signal and exact query/status/ETag', options, async () => {
  const count = calls.length, page = await pageFor();
  try {
    for (const [index, target] of targets.entries()) {
      const result = await observe(page, target, 'valid', { headers: ['default', 'pairs', 'object'][index % 3] });
      assert.equal(result.response.url(), origin + target); assert.equal(result.response.status(), 200);
      assert.equal(await result.response.headerValue('etag'), '"4"'); assert.deepEqual(result.body, expected('GET', target));
    }
    assert.deepEqual(calls.slice(count).map(({ method, target, tenant: actual }) => [method, target, actual]), targets.map((target) => ['GET', target, tenant]));
    assert.deepEqual(await page.evaluate(() => [window.nativeCalls, window.cloneCalls]), [targets.length, targets.length]);
    assert.deepEqual(await page.evaluate(() => window.headerReads), targets.map(() => 'x-tenant-id'));
  } finally { await page.close(); }
});

test('actual native string/Request plus RequestInit header representations and method overrides keep arguments identities and correlation', options, async () => {
  const page = await pageFor(), count = calls.length;
  try {
    for (const form of ['headers', 'pairs', 'object']) {
      const result = await observeReadResponse(page, origin, detail, tenant, async () => {
        await page.evaluate(({ target, tenant, form }) => {
          window.control = new AbortController();
          const pairs = [['X-Tenant-ID', tenant], ['Authorization', 'public-contract-auth-sentinel']];
          const headers = form === 'headers' ? new Headers(pairs) : form === 'pairs' ? pairs : Object.fromEntries(pairs);
          const input = form === 'headers' ? target : new Request(target, { method: 'POST', headers: { 'X-Tenant-ID': '00000000-0000-4000-8000-000000000099' } });
          const init = { method: 'GET', headers, signal: window.control.signal };
          window.originalInput = input; window.originalInit = init;
          const pending = window.sdkSend(input, init); window.promiseSame = pending === window.nativePromise;
          window.operation = pending.then(async (response) => { window.responseSame = response === window.nativeResponse; window.originalBody = await response.json(); });
        }, { target: origin + detail, tenant, form });
        await page.evaluate(() => window.operation);
        assert.deepEqual(await page.evaluate(() => [window.promiseSame, window.responseSame, window.originalInput === window.nativeInput,
          window.originalInit === window.nativeInit, window.nativeInit.signal === window.control.signal]), [true, true, true, true, true]);
      });
      assert.equal(await result.response.request().headerValue('x-tenant-id'), tenant); assert.deepEqual(result.body, expected('GET', detail));
    }
    assert.equal(calls.length - count, 3); assert.deepEqual(await page.evaluate(() => [window.nativeCalls, window.cloneCalls]), [3, 3]);
  } finally { await page.close(); }
});

test('actual duplicated tenant header values cannot be mistaken for one valid tenant or cloned', options, async () => {
  const page = await pageFor(), count = calls.length;
  try {
    await assert.rejects(observeReadResponse(page, origin, detail, tenant, async () => {
      await page.evaluate(({ target, tenant }) => {
        const pending = window.sdkSend(target, { headers: [['X-Tenant-ID', tenant], ['X-Tenant-ID', tenant]] });
        window.operation = pending.then(async (response) => { window.originalBody = await response.json(); });
      }, { target: origin + detail, tenant });
      await page.evaluate(() => window.operation);
    }), /READ_OBSERVER_TENANT_MISMATCH/);
    assert.equal(calls.length - count, 1); assert.equal(calls[count].tenant, tenant + ', ' + tenant);
    assert.equal(await page.evaluate(() => window.cloneCalls), 0); await assertFresh(page);
  } finally { await page.close(); }
});

test('no explicit arm means no GET/auth/credential/unrelated clone and no header inspection', options, async () => {
  const page = await pageFor(), count = calls.length;
  try {
    for (const target of [...targets, '/auth/session', `/v1/service-clients/${id}/credentials`, '/v1/unrelated']) { await start(page, target); await native(page); }
    assert.equal(await page.evaluate(() => window.cloneCalls), 0); assert.deepEqual(await page.evaluate(() => window.headerReads), []);
    assert.equal(calls.length - count, targets.length + 3);
  } finally { await page.close(); }
});

test('armed reads leave auth credential wrong-query and other-route requests untouched before the one matching GET', options, async () => {
  const page = await pageFor(), count = calls.length, target = targets[0];
  try {
    const result = await observeReadResponse(page, origin, target, tenant, async () => {
      for (const other of ['/auth/session', `/v1/service-clients/${id}/credentials`, '/v1/service-clients?limit=2', `/v1/automations/${id}`]) { await start(page, other); await native(page); }
      assert.equal(await page.evaluate(() => window.cloneCalls), 0); assert.deepEqual(await page.evaluate(() => window.headerReads), []);
      await start(page, target); await native(page);
    });
    assert.deepEqual(result.body, expected('GET', target)); assert.equal(calls.length - count, 5);
    assert.deepEqual(await page.evaluate(() => [window.nativeCalls, window.cloneCalls]), [5, 1]);
    assert.deepEqual(await page.evaluate(() => window.headerReads), ['x-tenant-id']);
  } finally { await page.close(); }
});

test('invalid origin routes hashes credentials unknown/duplicate query values and formal cursor/limit bounds cannot arm or call trigger', options, async () => {
  const page = await pageFor(), count = calls.length; let invoked = 0;
  try {
    const invalid = ['/auth/session', `/v1/service-clients/${id}/credentials`, '/v1/unrelated', detail + '?limit=1', detail + '#fragment',
      'https://other-origin.invalid' + detail, '/v1/service-clients?limit=0', '/v1/service-clients?limit=101', '/v1/service-clients?limit=1&limit=2',
      '/v1/service-clients?token=opaque', '/v1/service-clients?cursor=' + 'a'.repeat(2049), '/v1/service-clients?cursor=%00',
      `/v1/automations/${id}/runs?limit=20`, `/v1/automations/${id}/runs?project_id=invalid`,
      `/v1/automation-notifications?project_id=${project}&cursor=` + 'a'.repeat(2049)];
    for (const target of invalid) await assert.rejects(observeReadResponse(page, origin, target, tenant, () => { invoked++; }), /READ_OBSERVER_(SCOPE|QUERY)/);
    await assert.rejects(observeReadResponse(page, origin, detail, 'wrong-tenant', () => { invoked++; }), /READ_OBSERVER_TENANT/);
    assert.equal(invoked, 0); assert.equal(calls.length, count); assert.equal(await page.evaluate(() => window.cloneCalls), 0);
    await assertFresh(page);
  } finally { await page.close(); }
});

test('wrong and missing actual tenant headers reject without cloning and release the observation for a fresh read', options, async () => {
  const page = await pageFor();
  try {
    for (const actual of [project, null]) {
      const before = await page.evaluate(() => window.cloneCalls);
      await assert.rejects(observe(page, detail, 'valid', { tenant: actual }), /READ_OBSERVER_TENANT_MISMATCH/);
      assert.equal(await page.evaluate(() => window.cloneCalls), before); await assertFresh(page);
    }
  } finally { await page.close(); }
});

test('concurrent and reentrant helper calls reject before their trigger while the original arm completes', options, async () => {
  const page = await pageFor(); let signalArmed, release, secondCalled = false;
  const armed = new Promise((resolve) => { signalArmed = resolve; }), released = new Promise((resolve) => { release = resolve; });
  try {
    const first = observeReadResponse(page, origin, detail, tenant, async () => {
      signalArmed(); await released;
      await assert.rejects(observeReadResponse(page, origin, detail, tenant, () => { secondCalled = true; }), /READ_OBSERVER_CONCURRENT/);
      await start(page); await native(page);
    });
    await armed;
    await assert.rejects(observeReadResponse(page, origin, detail, tenant, () => { secondCalled = true; }), /READ_OBSERVER_CONCURRENT/);
    release(); assert.deepEqual((await first).body, expected('GET', detail)); assert.equal(secondCalled, false);
    assert.deepEqual(await page.evaluate(() => [window.nativeCalls, window.cloneCalls]), [1, 1]);
  } finally { release?.(); await page.close(); }
});

test('two original matching GETs fail the ticket closed with one clone and no replacement request', options, async () => {
  const page = await pageFor(), count = calls.length;
  try {
    await assert.rejects(observeReadResponse(page, origin, detail, tenant, async () => {
      await start(page); await native(page); await start(page); await native(page);
    }), /READ_OBSERVER_DUPLICATE/);
    assert.equal(calls.length - count, 2); assert.deepEqual(await page.evaluate(() => [window.nativeCalls, window.cloneCalls]), [2, 1]);
    await assertFresh(page);
  } finally { await page.close(); }
});

test('only explicit service-client list arm can observe its original opaque cursor with the actual full URL', options, async () => {
  const page = await pageFor(), count = calls.length;
  try {
    const result = await observeReadResponse(page, origin, '/v1/service-clients', tenant, async () => { await start(page, targets[0]); await native(page); });
    assert.equal(result.response.url(), origin + targets[0]); assert.deepEqual(result.body, expected('GET', targets[0]));
    assert.equal(calls.length - count, 1); assert.deepEqual(await page.evaluate(() => [window.nativeCalls, window.cloneCalls]), [1, 1]);
  } finally { await page.close(); }
});

test('a path-only service-client list arm rejects illegal actual query before cloning the original HTTP', options, async () => {
  const page = await pageFor(), count = calls.length;
  try {
    await assert.rejects(observeReadResponse(page, origin, '/v1/service-clients', tenant, async () => { await start(page, '/v1/service-clients?limit=101'); await native(page); }), /READ_OBSERVER_QUERY/);
    assert.equal(calls.length - count, 1); assert.equal(await page.evaluate(() => window.cloneCalls), 0); await assertFresh(page);
  } finally { await page.close(); }
});

test('different legal query on a second service-client list GET still rejects the one path ticket as duplicate', options, async () => {
  const page = await pageFor(), count = calls.length;
  try {
    await assert.rejects(observeReadResponse(page, origin, '/v1/service-clients', tenant, async () => {
      await start(page, targets[0]); await native(page); await start(page, '/v1/service-clients?limit=2&cursor=another_opaque_cursor'); await native(page);
    }), /READ_OBSERVER_DUPLICATE/);
    assert.equal(calls.length - count, 2); assert.equal(await page.evaluate(() => window.cloneCalls), 1); await assertFresh(page);
  } finally { await page.close(); }
});

test('actual read receipt cannot be consumed with corrupted ETag full URL or instance-ETag association metadata', options, async () => {
  for (const field of ['etag', 'url', 'request-url', 'x-instance-etag']) {
    const page = await pageFor(); const target = field === 'url' ? targets[0] : field === 'x-instance-etag' ? targets[7] : detail;
    try {
      // Deliberately corrupt only association metadata on the real Playwright
      // Response. Its body and the original native request remain untouched.
      page.on('response', (response) => {
        if (response.url() !== origin + target) return;
        if (field === 'url') response.url = () => origin + '/v1/service-clients?limit=2';
        else if (field === 'request-url') response.request().url = () => origin + detail + '?wrong=1';
        else {
          const header = response.headerValue.bind(response);
          response.headerValue = (name) => name.toLowerCase() === field ? Promise.resolve('"999"') : header(name);
        }
      });
      await assert.rejects(observeReadResponse(page, origin, field === 'url' ? '/v1/service-clients' : target, tenant, async () => { await start(page, target); await native(page); }), /READ_OBSERVER_MISMATCH/);
      assert.equal(await page.evaluate(() => window.cloneCalls), 1);
    } finally { await page.close(); }
  }
});

test('the original HTTP404 with no ETag remains observable once without converting it to success', options, async () => {
  const page = await pageFor();
  try {
    const result = await observe(page, detail, 'status404'); assert.equal(result.response.status(), 404);
    assert.equal(await result.response.headerValue('etag'), null); assert.deepEqual(result.body, { code: 'RESOURCE_NOT_FOUND' });
    await assertFresh(page);
  } finally { await page.close(); }
});

test('unapproved real HTTP statuses fail closed without a clone or accepted body', options, async () => {
  const page = await pageFor();
  try {
    for (const status of [400, 401, 403, 500, 204]) {
      await assert.rejects(observe(page, detail, 'status' + status), /READ_OBSERVER_STATUS_REJECTED/);
      assert.equal(await page.evaluate(() => window.cloneCalls), 0);
    }
    await assertFresh(page);
  } finally { await page.close(); }
});

test('real malformed/truncated native body failures and strict UTF-8 observer rejection preserve original behavior', options, async () => {
  const page = await pageFor();
  try {
    for (const scenario of ['invalid', 'invalid_utf8', 'truncated']) {
      const count = calls.length;
      const operation = scenario === 'truncated' ? observeReadResponse(page, origin, detail, tenant, async () => {
        const response = page.waitForResponse((actual) => actual.url() === origin + detail);
        await start(page, detail, scenario); assert.equal((await response).status(), 200);
        // The actual native Response has reached the SDK before destroying the
        // original incomplete HTTP stream, so this specifically proves body
        // failure rather than an indeterminate pre-header fetch failure.
        await page.waitForFunction(() => window.responseSame === true);
        const upstream = truncatedResponses.get(detail); assert(upstream);
        truncatedResponses.delete(detail); upstream.destroy(); await native(page);
      }) : observe(page, detail, scenario);
      await assert.rejects(operation, /READ_OBSERVER_(BODY_UNAVAILABLE|FETCH_FAILED)/);
      await page.evaluate(() => window.operation);
      if (scenario === 'invalid_utf8') {
        // Response.json's native UTF-8 replacement is retained. Only the
        // observer's strict decoder rejects these actual invalid wire bytes.
        assert.deepEqual(await page.evaluate(() => window.originalBody), { '\ufffd': 1 });
        assert.equal(await page.evaluate(() => !!window.originalBodyFailed), false);
      } else assert.equal(await page.evaluate(() => window.originalBodyFailed), true);
      assert.equal(calls.length - count, 1); await assertFresh(page);
    }
  } finally { await page.close(); }
});

test('every credential field is rejected without exposing its actual original HTTP JSON in errors', options, async () => {
  const page = await pageFor();
  try {
    for (const field of ['authorization', 'cookie', 'set_cookie', 'password', 'client_secret', 'access_token', 'refresh_token', 'id_token', 'csrf_token']) {
      await assert.rejects(observe(page, detail, 'credential:' + field), (error) => /READ_OBSERVER_CREDENTIAL_FIELD_REJECTED/.test(error.message) && !error.message.includes('public-contract-credential-sentinel'));
      assert.equal(await page.evaluate(() => window.originalBody.resource.nested[Object.keys(window.originalBody.resource.nested)[0]]), 'public-contract-credential-sentinel');
    }
    await assertFresh(page);
  } finally { await page.close(); }
});

test('actual raw JSON byte cap accepts exactly256KiB and rejects one additional byte', options, async () => {
  const page = await pageFor();
  try {
    const result = await observe(page, detail, 'boundary'); assert.equal(Buffer.byteLength(JSON.stringify(result.body)), 256 * 1024);
    await assert.rejects(observe(page, detail, 'overflow'), /READ_OBSERVER_BODY_TOO_LARGE/);
    assert.equal(await page.evaluate(() => new TextEncoder().encode(JSON.stringify(window.originalBody)).length), 256 * 1024 + 1);
    await assertFresh(page);
  } finally { await page.close(); }
});

test('original caller abort remains an actual native body failure and no observed success', options, async () => {
  const page = await pageFor();
  try {
    await assert.rejects(observeReadResponse(page, origin, detail, tenant, async () => {
      const pending = page.waitForResponse((response) => response.url() === origin + detail);
      await start(page, detail, 'abort'); await pending;
      await page.evaluate(() => window.control.abort()); await native(page);
    }), /READ_OBSERVER_(BODY_UNAVAILABLE|FETCH_FAILED)/);
    await page.evaluate(() => window.operation);
    assert.equal(await page.evaluate(() => window.control.signal.aborted), true); await assertFresh(page);
  } finally { await page.close(); }
});

test('native redirect-error fetch failure remains original and does not follow or retry HTTP', options, async () => {
  const page = await pageFor(), count = calls.length;
  try {
    await assert.rejects(observeReadResponse(page, origin, detail, tenant, async () => { await start(page, detail, 'redirect'); await page.evaluate(() => window.operation); }), /READ_OBSERVER_FETCH_FAILED/);
    await page.evaluate(() => window.operation);
    assert.equal(await page.evaluate(() => window.originalFetchFailed), true); assert.equal(calls.length - count, 1);
    assert.equal(await page.evaluate(() => window.cloneCalls), 0); await assertFresh(page);
  } finally { await page.close(); }
});

test('trigger failure releases its arm without reading unrelated later responses', options, async () => {
  const page = await pageFor();
  try {
    await assert.rejects(observeReadResponse(page, origin, detail, tenant, () => { throw new Error('original-trigger-failed'); }), /original-trigger-failed/);
    await start(page); await native(page); assert.equal(await page.evaluate(() => window.cloneCalls), 0);
    await assertFresh(page);
  } finally { await page.close(); }
});

test('actual reload invalidates the old ticket and preserves one wrapper with no carried read arm', options, async () => {
  const page = await pageFor();
  try {
    await assert.rejects(observeReadResponse(page, origin, detail, tenant, async () => { await start(page, detail, 'stall'); await page.reload(); }), /READ_OBSERVER_NAVIGATION/);
    await page.waitForLoadState(); await start(page); await native(page);
    assert.equal(await page.evaluate(() => window.cloneCalls), 0); await assertFresh(page);
    assert.deepEqual(await page.evaluate(() => [window.nativeCalls, window.cloneCalls]), [2, 1]);
  } finally { await page.close(); }
});

test('unknown missing response actually times out within its bounded observation and never leaves an arm', options, async () => {
  const page = await pageFor(), count = calls.length, began = performance.now();
  try {
    await assert.rejects(observeReadResponse(page, origin, detail, tenant, () => {}), /READ_OBSERVER_TIMEOUT/);
    assert(performance.now() - began >= 14500 && performance.now() - began < 18000);
    assert.equal(calls.length, count); await start(page); await native(page); assert.equal(await page.evaluate(() => window.cloneCalls), 0);
    await assertFresh(page);
  } finally { await page.close(); }
});

test('actual stalled clone hits the bounded deadline without aborting the original native signal', options, async () => {
  const page = await pageFor(), began = performance.now();
  try {
    await assert.rejects(observeReadResponse(page, origin, detail, tenant, async () => { await start(page, detail, 'stall'); }), /READ_OBSERVER_(TIMEOUT|EXPIRED)/);
    assert(performance.now() - began >= 14500 && performance.now() - began < 18000);
    assert.equal(await page.evaluate(() => window.control.signal.aborted), false);
    await page.evaluate(() => window.control.abort()); await page.evaluate(() => window.operation); await assertFresh(page);
  } finally { await page.close(); }
});

async function mutation(page) {
  const path = '/v1/service-clients', pending = page.waitForResponse((response) => response.url() === origin + path && response.request().method() === 'POST');
  await start(page, path, 'valid', { method: 'POST', key: randomUUID() }); await native(page); return pending;
}
test('read and mutation receipts share exactly the original sixteen-response budget and successful read consumes its slot', options, async () => {
  const page = await pageFor(), count = calls.length;
  try {
    let last;
    for (let index = 0; index < 15; index++) last = await mutation(page);
    await assertFresh(page); // 15 retained mutations + the one read == 16.
    last = await mutation(page); // Read was consumed; this is the 16th retained receipt.
    let called = false;
    await assert.rejects(observeReadResponse(page, origin, detail, tenant, () => { called = true; }), /READ_OBSERVER_BUDGET_OR_DUPLICATE/);
    assert.equal(called, false); assert.equal(calls.length - count, 17);
    await mutationResponseJson(page, last, 'SERVICE_CLIENT'); await assertFresh(page);
  } finally { await page.close(); }
});

test('mutation overflow during a read arm fails both consumers closed without changing any original requests', options, async () => {
  const page = await pageFor(), count = calls.length; let last;
  try {
    await assert.rejects(observeReadResponse(page, origin, detail, tenant, async () => {
      for (let index = 0; index < 16; index++) last = await mutation(page);
      await start(page); await native(page);
    }), /READ_OBSERVER_BUDGET_OR_DUPLICATE/);
    await assert.rejects(mutationResponseJson(page, last, 'SERVICE_CLIENT'), /SERVICE_CLIENT_OBSERVER_BUDGET_OR_DUPLICATE/);
    assert.equal(calls.length - count, 17); assert.equal(await page.evaluate(() => window.nativeCalls), 17);
  } finally { await page.close(); }
});

test('standalone read setup followed by mutation registration keeps one shared wrapper and compatibility aliases', options, async () => {
  const page = await pageFor(false);
  try {
    const result = await observeReadResponse(page, origin, detail, tenant, async () => { await start(page, detail, 'valid', { direct: true }); await native(page); });
    assert.deepEqual(result.body, expected('GET', detail));
    await page.evaluate(() => { window.observedFetch = window.fetch; });
    await installMutationResponseObserver(page, origin, profiles);
    assert.equal(await page.evaluate(() => window.fetch === window.observedFetch), true);
    await page.reload(); const response = await mutation(page); await mutationResponseJson(page, response, 'SERVICE_CLIENT'); await assertFresh(page);
    assert.equal(await page.evaluate((slot) => window.__sandboxServiceClientResponseObserver === window[slot].profile('SERVICE_CLIENT') && window.__sandboxDiagnosisResponseObserver === window[slot].profile('DIAGNOSIS'), slot), true);
    assert.deepEqual(await page.evaluate(() => [window.nativeCalls, window.cloneCalls]), [2, 2]);
  } finally { await page.close(); }
});

// Actual prior-request identity regression: both original HTTP requests keep
// product-style no-store cache semantics and carry no observer header/ticket.
async function inflightScenario(abortOld, signal) {
  const target = detail;
  const requests = [], upstreams = [], timers = [];
  let browser, page, firstArrivedResolve, firstArrivedReject;
  const firstArrived = new Promise((resolve, reject) => { firstArrivedResolve = resolve; firstArrivedReject = reject; });
  const onFirstArrivalCancelled = () => firstArrivedReject(signal.reason);
  const server = createServer((req, res) => {
    if (req.url === '/') { res.setHeader('content-type', 'text/html'); res.end('<p>Actual in-flight read correlation</p><script>window.sdkSend=fetch.bind(window)</script>'); return; }
    if (req.url !== target) { res.writeHead(204); res.end(); return; }
    assert.equal(req.method, 'GET'); assert.equal(req.headers['x-tenant-id'], tenant);
    const body = { sequence: requests.length + 1, cutoff: new Date().toISOString() };
    requests.push({ method: req.method, target: req.url, tenant: req.headers['x-tenant-id'], body }); upstreams.push(res);
    if (requests.length === 1) firstArrivedResolve();
    if (requests.length === 2) {
      const reply = (index) => { upstreams[index].writeHead(200, { 'content-type': 'application/json', etag: '"4"' }); upstreams[index].end(JSON.stringify(requests[index].body)); };
      if (!abortOld) { timers.push(setTimeout(() => reply(0), 100)); timers.push(setTimeout(() => reply(1), 200)); }
      else {
        res.writeHead(200, { 'content-type': 'application/json', etag: '"4"' }); res.write('{');
        timers.push(setTimeout(() => res.end(JSON.stringify(body).slice(1)), 200));
      }
    }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const origin = 'http://127.0.0.1:' + server.address().port;
  try {
    browser = await chromium.launch({ headless: true, executablePath: process.argv[3] }); page = await browser.newPage();
    await page.addInitScript(() => {
      const nativeFetch = window.fetch, clone = Response.prototype.clone;
      window.nativeRecords = []; window.cloneCalls = 0; window.states = {};
      Response.prototype.clone = function () { window.cloneCalls++; return Reflect.apply(clone, this, []); };
      window.fetch = function (...args) {
        const promise = Reflect.apply(nativeFetch, this, args), record = { input: args[0], promise };
        window.nativeRecords.push(record); promise.then((response) => { record.response = response; }, () => {}); return promise;
      };
    });
    await installMutationResponseObserver(page, origin, ['DIAGNOSIS']); await page.goto(origin);
    const start = async (label) => page.evaluate(({ label, url, tenant }) => {
      const control = new AbortController(), input = new Request(url, { cache: 'no-store', headers: { 'X-Tenant-ID': tenant }, signal: control.signal });
      const promise = window.sdkSend(input), record = window.nativeRecords.at(-1);
      const state = { input, control, promiseSame: record.promise === promise }; window.states[label] = state;
      state.done = promise.then(async (response) => { state.responseSame = record.response === response; state.body = await response.json(); }, () => { state.fetchFailed = true; });
    }, { label, url: origin + target, tenant });
    const oldStarted = page.waitForRequest((request) => request.url() === origin + target);
    await start('old'); const oldRequest = await oldStarted;
    // A Playwright request event proves browser initiation, not HTTP arrival.
    // Gate on the actual server handler before asserting the first request.
    signal.addEventListener('abort', onFirstArrivalCancelled, { once: true });
    if (signal.aborted) onFirstArrivalCancelled();
    try { await firstArrived; }
    finally { signal.removeEventListener('abort', onFirstArrivalCancelled); }
    assert.equal(requests.length, 1);
    const newStarted = page.waitForRequest((request) => request.url() === origin + target);
    let actual, failure;
    try {
      actual = await observeReadResponse(page, origin, target, tenant, async () => {
        await start('new');
        if (abortOld) {
          await page.waitForFunction(() => window.states.new.responseSame === true);
          await page.evaluate(() => { setTimeout(() => window.states.old.control.abort(), 100); });
        }
        await page.evaluate(() => window.states.new.done);
      });
    } catch (error) { failure = error; }
    const newRequest = await newStarted;
    await page.evaluate(() => Promise.all([window.states.old.done, window.states.new.done]));
    const native = await page.evaluate(() => ({
      calls: window.nativeRecords.length, clones: window.cloneCalls,
      old: { body: window.states.old.body, fetchFailed: !!window.states.old.fetchFailed, promiseSame: window.states.old.promiseSame, responseSame: window.states.old.responseSame },
      fresh: { body: window.states.new.body, promiseSame: window.states.new.promiseSame, responseSame: window.states.new.responseSame },
      identities: window.nativeRecords.every((record, index) => record.input === window.states[index ? 'new' : 'old'].input && record.input.signal === window.states[index ? 'new' : 'old'].input.signal),
    }));
    assert.equal(requests.length, 2); assert.equal(native.calls, 2); assert.equal(native.clones, 1); assert.equal(native.identities, true);
    assert.equal(native.old.promiseSame, true); assert.equal(native.fresh.promiseSame, true); assert.equal(native.fresh.responseSame, true);
    assert.deepEqual(native.fresh.body, requests[1].body);
    if (!abortOld) {
      assert.equal(native.old.responseSame, true); assert.deepEqual(native.old.body, requests[0].body); assert.ifError(failure);
      console.log('ACTUAL_SAME_URL_TENANT_STATUS_ETAG_INFLIGHT_GETS', JSON.stringify({ responseSequence: (await actual.response.json()).sequence, cloneSequence: actual.body.sequence, requests: requests.length, clones: native.clones, oldRequestMatched: actual.response.request() === oldRequest, newRequestMatched: actual.response.request() === newRequest }));
      assert.equal(actual.response.request() === newRequest, true, 'Must return the newly armed actual Request object, never an older same-URL response');
      assert.deepEqual(actual.body, requests[1].body);
    } else {
      assert.equal(native.old.fetchFailed, true);
      console.log('ACTUAL_PRE_ARM_OLD_GET_ABORT_WITH_FRESH_NATIVE_BODY_SUCCESS', JSON.stringify({ failure: failure?.message, freshSequence: native.fresh.body.sequence, requests: requests.length, clones: native.clones }));
      assert.ifError(failure); assert.equal(actual.response.request() === newRequest, true); assert.deepEqual(actual.body, requests[1].body);
    }
  } finally {
    signal.removeEventListener('abort', onFirstArrivalCancelled);
    for (const timer of timers) clearTimeout(timer);
    try { await browser?.close(); }
    finally { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); }
  }
}

test('older same-URL same-tenant GET response cannot be combined with the newly armed native clone', options, (context) => inflightScenario(false, context.signal));
test('older same-URL same-tenant in-flight GET abort cannot invalidate the newly armed original GET', options, (context) => inflightScenario(true, context.signal));
