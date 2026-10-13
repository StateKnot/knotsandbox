// Real Chromium/native HTTP contracts for this test-only observation adapter.
// Product BFF/identity/database acceptance is independently required.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { isAbsolute } from 'node:path';
import { before, after, test } from 'node:test';
import { chromium } from '../../console/node_modules/playwright-core/index.mjs';
import { installDiagnosisResponseObserver, diagnosisMutationJson } from './diagnosis-response-observer.mjs';
import { installServiceClientResponseObserver, serviceClientMutationJson } from './service-client-response-observer.mjs';

assert.equal(process.argv.length, 4);
assert.equal(process.argv[2], '--chrome');
assert(isAbsolute(process.argv[3]));
const instance = '00000000-0000-4000-8000-000000000001';
const path = '/v1/instances/' + instance + '/diagnoses';
const slot = '__sandboxDiagnosisResponseObserver';
const accepted = { resource: { id: '00000000-0000-4000-8000-000000000002', version: 1,
  operation_id: '00000000-0000-4000-8000-000000000003', instance_id: instance, status: 'PENDING' },
  operation: { id: '00000000-0000-4000-8000-000000000003' } };
const calls = [];
let origin, server, browser;
before(async () => {
  server = createServer((request, response) => {
    if (request.url === '/') {
      response.setHeader('content-type', 'text/html');
      response.end('<p>Native diagnosis observation</p><script>window.sdkSend=fetch.bind(window)</script>');
      return;
    }
    if (!request.url.startsWith('/v1/') && !request.url.startsWith('/auth/')) {
      response.writeHead(204); response.end(); return;
    }
    calls.push({ method: request.method, path: request.url });
    const scenario = request.headers['x-scenario'];
    if (scenario === 'native_failure') {
      response.writeHead(307, { location: '/redirect-must-not-be-followed' }); response.end(); return;
    }
    const diagnosis = request.method === 'POST' && /^\/v1\/instances\/[^/]+\/diagnoses$/.test(request.url);
    response.statusCode = scenario === 'status' ? 200 : diagnosis ? 202 : 200;
    response.setHeader('content-type', 'application/json');
    response.setHeader('etag', diagnosis ? '"1"' : '"3"');
    if (scenario === 'invalid') { response.end('{invalid'); return; }
    if (scenario === 'abort') { response.write('{"resource":'); return; }
    if (scenario === 'truncated') {
      response.setHeader('content-length', '900'); response.end('{"resource":'); return;
    }
    const body = diagnosis ? structuredClone(accepted) : { resource: { version: 3 } };
    if (scenario === 'large') body.text = 'a'.repeat(300 * 1024);
    if (scenario === 'credential') body.resource.access_token = 'public-contract-sentinel';
    response.end(JSON.stringify(body));
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  origin = 'http://127.0.0.1:' + server.address().port;
  browser = await chromium.launch({ headless: true, executablePath: process.argv[3] });
}, { timeout: 30000 });
after(async () => {
  await browser?.close();
  server?.closeAllConnections();
  if (server?.listening) await new Promise((resolve) => server.close(resolve));
});
async function pageFor({ clients = false, early = true } = {}) {
  const page = await browser.newPage();
  await page.addInitScript(() => {
    const nativeFetch = window.fetch;
    window.fetch = function (...args) {
      window.nativeInput = args[0];
      window.nativePromise = Reflect.apply(nativeFetch, this, args);
      window.nativePromise.then((response) => { window.nativeResponse = response; }, () => {});
      return window.nativePromise;
    };
  });
  if (clients) await installServiceClientResponseObserver(page, origin);
  if (early) await installDiagnosisResponseObserver(page, origin);
  await page.goto(origin);
  if (!early) await installDiagnosisResponseObserver(page, origin);
  return page;
}
async function start(page, scenario = 'valid', key = randomUUID(), target = path, method = 'POST') {
  await page.evaluate(({ target, key, scenario, method }) => {
    window.control = new AbortController();
    const request = new Request(target, { method, headers: {
      'Idempotency-Key': key, 'X-Scenario': scenario, 'Authorization': 'public-contract-sentinel',
    }, signal: window.control.signal, redirect: 'error',
    ...(method === 'POST' || method === 'PATCH' ? { body: '{}' } : {}) });
    const header = request.headers.get.bind(request.headers);
    window.headerReads = [];
    request.headers.get = (name) => { window.headerReads.push(name.toLowerCase()); return header(name); };
    window.originalInput = request;
    const pending = window.sdkSend(request);
    window.promiseSame = pending === window.nativePromise;
    window.operation = pending.then(async (response) => {
      window.responseSame = response === window.nativeResponse;
      try { window.originalBody = await response.json(); }
      catch { window.originalBodyFailed = true; }
    }, () => { window.originalFetchFailed = true; });
  }, { target: origin + target, key, scenario, method });
  return key;
}
async function send(page, scenario = 'valid', key = randomUUID(), target = path, method = 'POST') {
  const pending = page.waitForResponse((reply) => new URL(reply.url()).pathname === target && reply.request().method() === method);
  await start(page, scenario, key, target, method);
  return pending;
}
function single(count, target = path, method = 'POST') {
  assert.deepEqual(calls.slice(count), [{ method, path: target }]);
}
async function nativeIdentities(page) {
  await page.evaluate(() => window.operation);
  assert.deepEqual(await page.evaluate(() => [window.promiseSame, window.responseSame,
    window.nativeInput === window.originalInput, window.nativeInput.signal === window.originalInput.signal]), [true, true, true, true]);
  assert.deepEqual(await page.evaluate(() => window.headerReads), ['idempotency-key']);
}
const options = { timeout: 20000 };

test('same native 202 replay survives actual CDP observation-session body loss', options, async () => {
  const count = calls.length, page = await pageFor();
  const cdp = await page.context().newCDPSession(page);
  try {
    await cdp.send('Network.enable');
    let requestId;
    cdp.on('Network.responseReceived', (event) => {
      if (event.response.url === origin + path) requestId = event.requestId;
    });
    const response = await send(page);
    await page.evaluate(() => window.operation);
    assert(requestId, 'the body read must use this real POST request ID');
    assert.equal(response.status(), 202);
    assert.equal(await response.headerValue('etag'), '"1"');
    assert.deepEqual(await page.evaluate(() => window.originalBody), accepted);
    const readCdp = async () => {
      const actual = await cdp.send('Network.getResponseBody', { requestId });
      return JSON.parse(actual.base64Encoded ? Buffer.from(actual.body, 'base64').toString('utf8') : actual.body);
    };
    assert.deepEqual(await readCdp(), accepted, 'CDP initially saw the very same server receipt');
    // Clear only this external session's retained Network state after native
    // body consumption. Do not cancel/replace/retry the actual HTTP request.
    await cdp.send('Network.disable');
    await assert.rejects(readCdp(), /No resource with given identifier found|No data found for resource with given identifier/);
    // This adapter invokes actual Chromium CDP; it never invents an exception.
    response.json = readCdp;
    assert.deepEqual(await diagnosisMutationJson(page, response), accepted);
    single(count);
  } finally { await cdp.detach(); await page.close(); }
});

test('native Promise/Request/signal/Response identities survive; consume removes scoped JSON', options, async () => {
  const count = calls.length, page = await pageFor();
  try {
    const response = await send(page);
    assert.deepEqual(await diagnosisMutationJson(page, response), accepted);
    await nativeIdentities(page);
    const key = await response.request().headerValue('idempotency-key');
    assert.equal(await page.evaluate(({ slot, id }) => window[slot].has(id), {
      slot, id: JSON.stringify(['POST', path, key]),
    }), false);
    single(count);
  } finally { await page.close(); }
});

test('invalid JSON/truncation/original abort/overflow remain failures', { timeout: 40000 }, async () => {
  for (const scenario of ['invalid', 'truncated', 'abort', 'large']) {
    const count = calls.length, page = await pageFor();
    try {
      const response = await send(page, scenario);
      if (scenario === 'abort') await page.evaluate(() => window.control.abort());
      await assert.rejects(diagnosisMutationJson(page, response), /DIAGNOSIS_OBSERVER_BODY_UNAVAILABLE|DIAGNOSIS_OBSERVER_BODY_TOO_LARGE/);
      await page.evaluate(() => window.operation);
      if (scenario !== 'large') assert.equal(await page.evaluate(() => !!window.originalBodyFailed), true);
      single(count);
    } finally { await page.close(); }
  }
});

test('clone failure never changes a successful original response', options, async () => {
  const count = calls.length, page = await pageFor();
  try {
    await page.evaluate(() => { Response.prototype.clone = () => { throw new Error('public-contract-clone-failure'); }; });
    const response = await send(page);
    await assert.rejects(diagnosisMutationJson(page, response), /DIAGNOSIS_OBSERVER_BODY_UNAVAILABLE/);
    await page.evaluate(() => window.operation);
    assert.deepEqual(await page.evaluate(() => window.originalBody), accepted);
    single(count);
  } finally { await page.close(); }
});

test('native fetch failure cannot become an observed success', options, async () => {
  const count = calls.length, page = await pageFor();
  try {
    const key = await start(page, 'native_failure');
    await page.evaluate(() => window.operation);
    assert.equal(await page.evaluate(() => !!window.originalFetchFailed), true);
    await assert.rejects(page.evaluate(({ slot, id }) => window[slot].take(id, 202, '"1"'), {
      slot, id: JSON.stringify(['POST', path, key]),
    }), /DIAGNOSIS_OBSERVER_FETCH_FAILED/);
    single(count);
  } finally { await page.close(); }
});

test('record budget and duplicate correlations fail closed without extra HTTP', options, async () => {
  for (const duplicate of [false, true]) {
    const count = calls.length, page = await pageFor();
    try {
      const key = randomUUID(), requests = duplicate ? 2 : 17;
      let response;
      for (let index = 0; index < requests; index++) {
        response = await send(page, 'valid', duplicate ? key : randomUUID());
        await page.evaluate(() => window.operation);
      }
      await assert.rejects(diagnosisMutationJson(page, response), /DIAGNOSIS_OBSERVER_BUDGET_OR_DUPLICATE/);
      assert.deepEqual(calls.slice(count), Array.from({ length: requests }, () => ({ method: 'POST', path })));
    } finally { await page.close(); }
  }
});

test('ETag/status/method/origin mismatch and unmatched keys cannot substitute a body', options, async () => {
  const count = calls.length, page = await pageFor();
  try {
    const response = await send(page), mismatch = Object.create(response);
    mismatch.headerValue = async (name) => name.toLowerCase() === 'etag' ? '"9"' : response.headerValue(name);
    await assert.rejects(diagnosisMutationJson(page, mismatch), /DIAGNOSIS_OBSERVER_MISMATCH/);
    await assert.rejects(page.evaluate(({ slot, id }) => window[slot].take(id, 202, '"1"'), {
      slot, id: JSON.stringify(['POST', path, randomUUID()]),
    }), /DIAGNOSIS_OBSERVER_UNMATCHED/);
    const wrongStatus = Object.create(response); wrongStatus.status = () => 200;
    await assert.rejects(diagnosisMutationJson(page, wrongStatus), /DIAGNOSIS_OBSERVER_SCOPE/);
    const wrongMethod = Object.create(response);
    wrongMethod.request = () => ({ method: () => 'GET', headerValue: async () => randomUUID() });
    await assert.rejects(diagnosisMutationJson(page, wrongMethod), /DIAGNOSIS_OBSERVER_SCOPE/);
    const wrongOrigin = Object.create(response);
    wrongOrigin.url = () => 'http://localhost:' + server.address().port + path;
    await assert.rejects(diagnosisMutationJson(page, wrongOrigin), /DIAGNOSIS_OBSERVER_ORIGIN/);
    single(count);
  } finally { await page.close(); }
});

test('credential fields fail closed; auth and diagnosis GET remain unobserved', options, async () => {
  const count = calls.length, page = await pageFor();
  try {
    const response = await send(page, 'credential');
    await assert.rejects(diagnosisMutationJson(page, response), /DIAGNOSIS_OBSERVER_CREDENTIAL_FIELD_REJECTED/);
    for (const target of ['/auth/session', '/v1/diagnoses/' + instance]) {
      const key = await start(page, 'valid', randomUUID(), target, 'GET');
      await page.evaluate(() => window.operation);
      assert.equal(await page.evaluate(({ slot, id }) => window[slot].has(id), {
        slot, id: JSON.stringify(['GET', target, key]),
      }), false);
    }
    assert.equal(calls.length - count, 3);
  } finally { await page.close(); }
});

test('observer survives real reload before captured SDK initialization', options, async () => {
  const count = calls.length, page = await pageFor();
  try {
    await page.reload();
    assert.deepEqual(await diagnosisMutationJson(page, await send(page)), accepted);
    single(count);
  } finally { await page.close(); }
});

test('late installation cannot replace a captured native SDK fetch', options, async () => {
  const count = calls.length;
  for (const early of [false, true]) {
    const page = await pageFor({ early });
    try {
      const key = randomUUID(), response = await send(page, 'valid', key);
      await page.evaluate(() => window.operation);
      assert.deepEqual(await page.evaluate(() => window.originalBody), accepted);
      assert.equal(await page.evaluate(({ slot, id }) => window[slot].has(id), {
        slot, id: JSON.stringify(['POST', path, key]),
      }), early);
      if (early) assert.deepEqual(await diagnosisMutationJson(page, response), accepted);
    } finally { await page.close(); }
  }
  assert.deepEqual(calls.slice(count), [{ method: 'POST', path }, { method: 'POST', path }]);
});

test('service-client/diagnosis observers stack with native identities and disjoint scopes across reload', options, async () => {
  const count = calls.length, page = await pageFor({ clients: true });
  const clientPath = '/v1/service-clients/' + instance;
  try {
    for (const reload of [false, true]) {
      if (reload) await page.reload();
      const response = await send(page);
      assert.deepEqual(await diagnosisMutationJson(page, response), accepted);
      await nativeIdentities(page);
      const key = await response.request().headerValue('idempotency-key');
      assert.equal(await page.evaluate((id) => window.__sandboxServiceClientResponseObserver.has(id), JSON.stringify(['POST', path, key])), false);
      const client = await send(page, 'valid', randomUUID(), clientPath, 'PATCH');
      assert.equal((await serviceClientMutationJson(page, client)).resource.version, 3);
      await nativeIdentities(page);
      const clientKey = await client.request().headerValue('idempotency-key');
      assert.equal(await page.evaluate(({ slot, id }) => window[slot].has(id), {
        slot, id: JSON.stringify(['PATCH', clientPath, clientKey]),
      }), false);
    }
    assert.deepEqual(calls.slice(count), [{ method: 'POST', path }, { method: 'PATCH', path: clientPath },
      { method: 'POST', path }, { method: 'PATCH', path: clientPath }]);
  } finally { await page.close(); }
});

test('another instance and invalid route scope cannot consume this response', options, async () => {
  const count = calls.length, page = await pageFor();
  try {
    const response = await send(page), key = await response.request().headerValue('idempotency-key');
    const otherPath = '/v1/instances/00000000-0000-4000-8000-000000000099/diagnoses';
    await assert.rejects(page.evaluate(({ slot, id }) => window[slot].take(id, 202, '"1"'), {
      slot, id: JSON.stringify(['POST', otherPath, key]),
    }), /DIAGNOSIS_OBSERVER_UNMATCHED/);
    for (const url of [origin + path + '?query=1', origin + path + '#fragment', origin + '/v1/instances/not-a-uuid/diagnoses']) {
      const wrongPath = Object.create(response); wrongPath.url = () => url;
      await assert.rejects(diagnosisMutationJson(page, wrongPath), /DIAGNOSIS_OBSERVER_SCOPE/);
    }
    assert.deepEqual(await diagnosisMutationJson(page, response), accepted);
    single(count);
  } finally { await page.close(); }
});
