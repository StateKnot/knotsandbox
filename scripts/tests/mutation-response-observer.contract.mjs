// Chromium + native loopback HTTP contracts. These fixtures do not certify
// real product identity, business results, database or cloud deployment.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { isAbsolute } from 'node:path';
import { before, after, test } from 'node:test';
import { chromium } from '../../console/node_modules/playwright-core/index.mjs';
import { installMutationResponseObserver, mutationResponseJson as readObserved } from './mutation-response-observer.mjs';
import { installServiceClientResponseObserver } from './service-client-response-observer.mjs';
import { installDiagnosisResponseObserver } from './diagnosis-response-observer.mjs';

assert.equal(process.argv.length, 4);
assert.equal(process.argv[2], '--chrome');
assert(isAbsolute(process.argv[3]));
const id = '00000000-0000-4000-8000-000000000001';
const names = ['SERVICE_CLIENT', 'DIAGNOSIS', 'AUTOMATION', 'GRANT', 'NOTIFICATION', 'LIFECYCLE'];
const matrix = [
  ['SERVICE_CLIENT', 'POST', '/v1/service-clients', 201],
  ['SERVICE_CLIENT', 'PATCH', `/v1/service-clients/${id}`, 200],
  ['DIAGNOSIS', 'POST', `/v1/instances/${id}/diagnoses`, 202],
  ['AUTOMATION', 'POST', `/v1/instances/${id}/automations`, 201],
  ...['pause', 'resume', 'revoke'].map((action) => ['AUTOMATION', 'POST', `/v1/automations/${id}/actions/${action}`, 200]),
  ['GRANT', 'POST', `/v1/projects/${id}/grants`, 201],
  ['GRANT', 'PATCH', `/v1/projects/${id}/grants/${id}`, 200],
  ['GRANT', 'DELETE', `/v1/projects/${id}/grants/${id}`, 200],
  ['NOTIFICATION', 'POST', `/v1/automation-notifications/${id}/actions/acknowledge`, 200],
  ['LIFECYCLE', 'POST', `/v1/instances/${id}/actions/stop`, 202],
];
const automation = matrix[3];
const slot = '__sandboxMutationResponseObserver';
const calls = [];
let origin, server, browser;
function responseBody(method, path, status) {
  return status === 404 ? { code: 'RESOURCE_NOT_FOUND' } : { resource: { version: 1 }, method, path };
}
before(async () => {
  server = createServer((request, response) => {
    if (request.url === '/') {
      response.setHeader('content-type', 'text/html');
      response.end('<p>Native mutation observation</p><script>window.sdkSend=fetch.bind(window)</script>');
      return;
    }
    if (!request.url.startsWith('/v1/') && !request.url.startsWith('/auth/')) {
      response.writeHead(204); response.end(); return;
    }
    calls.push({ method: request.method, path: request.url });
    const scenario = request.headers['x-scenario'];
    if (scenario === 'native_failure') {
      response.writeHead(307, { location: '/must-not-follow-redirect' }); response.end(); return;
    }
    const route = matrix.find((row) => row[1] === request.method && row[2] === request.url);
    const status = scenario === 'notice404' ? 404 : scenario === 'rejected' ? 400 : route?.[3] ?? 200;
    response.statusCode = status;
    response.setHeader('content-type', 'application/json');
    if (status !== 404) response.setHeader('etag', '"1"');
    if (scenario === 'invalid') { response.end('{invalid'); return; }
    if (scenario === 'abort') { response.write('{"resource":'); return; }
    if (scenario === 'truncated') { response.setHeader('content-length', '900'); response.end('{"resource":'); return; }
    const body = responseBody(request.method, request.url, status);
    if (scenario === 'large') body.text = 'a'.repeat(300 * 1024);
    if (scenario === 'credential') body.resource = { nested: { refresh_token: 'public-contract-sentinel' } };
    response.end(JSON.stringify(body));
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject); server.listen(0, '127.0.0.1', resolve);
  });
  origin = 'http://127.0.0.1:' + server.address().port;
  browser = await chromium.launch({ headless: true, executablePath: process.argv[3] });
}, { timeout: 30000 });
after(async () => {
  await browser?.close(); server?.closeAllConnections();
  if (server?.listening) await new Promise((resolve) => server.close(resolve));
});
async function pageFor(profiles = names) {
  const page = await browser.newPage();
  await page.addInitScript(() => {
    const nativeFetch = window.fetch;
    window.nativeCalls = 0; window.cloneCalls = 0;
    const clone = Response.prototype.clone;
    Response.prototype.clone = function () { window.cloneCalls++; return Reflect.apply(clone, this, []); };
    window.fetch = function (...args) {
      window.nativeCalls++; window.nativeInput = args[0];
      window.nativePromise = Reflect.apply(nativeFetch, this, args);
      window.nativePromise.then((response) => { window.nativeResponse = response; }, () => {});
      return window.nativePromise;
    };
  });
  await installMutationResponseObserver(page, origin, profiles);
  await page.goto(origin);
  return page;
}
async function start(page, row = automation, scenario = 'valid', key = randomUUID()) {
  await page.evaluate(({ method, target, scenario, key }) => {
    window.control = new AbortController();
    const request = new Request(target, { method, headers: {
      'Idempotency-Key': key, 'X-Scenario': scenario, 'Authorization': 'public-contract-sentinel',
    }, signal: window.control.signal, redirect: 'error',
    ...(method === 'POST' || method === 'PATCH' ? { body: '{}' } : {}) });
    const header = request.headers.get.bind(request.headers);
    window.headerReads = []; window.originalInput = request;
    request.headers.get = (name) => { window.headerReads.push(name.toLowerCase()); return header(name); };
    const pending = window.sdkSend(request);
    window.promiseSame = pending === window.nativePromise;
    window.operation = pending.then(async (response) => {
      window.responseSame = response === window.nativeResponse;
      try { window.originalBody = await response.json(); }
      catch { window.originalBodyFailed = true; }
    }, () => { window.originalFetchFailed = true; });
  }, { method: row[1], target: origin + row[2], scenario, key });
  return key;
}
async function send(page, row = automation, scenario = 'valid', key = randomUUID()) {
  const pending = page.waitForResponse((response) => new URL(response.url()).pathname === row[2] && response.request().method() === row[1]);
  await start(page, row, scenario, key); return pending;
}
async function native(page) {
  await page.evaluate(() => window.operation);
  assert.deepEqual(await page.evaluate(() => [window.promiseSame, window.responseSame,
    window.nativeInput === window.originalInput, window.nativeInput.signal === window.originalInput.signal]), [true, true, true, true]);
}
const options = { timeout: 20000 };

test('actual CDP state-loss keeps the same native automation POST201 receipt independently readable', options, async () => {
  const count = calls.length, page = await pageFor(), cdp = await page.context().newCDPSession(page);
  try {
    await cdp.send('Network.enable'); let requestId;
    cdp.on('Network.responseReceived', (event) => { if (event.response.url === origin + automation[2]) requestId = event.requestId; });
    const response = await send(page); await native(page);
    assert(requestId); assert.equal(response.status(), 201);
    const expected = responseBody(automation[1], automation[2], 201);
    assert.deepEqual(await page.evaluate(() => window.originalBody), expected);
    const cdpJson = async () => {
      const actual = await cdp.send('Network.getResponseBody', { requestId });
      return JSON.parse(actual.base64Encoded ? Buffer.from(actual.body, 'base64').toString('utf8') : actual.body);
    };
    assert.deepEqual(await cdpJson(), expected);
    await cdp.send('Network.disable');
    await assert.rejects(cdpJson(), /No resource with given identifier found|No data found for resource with given identifier/);
    response.json = cdpJson; // Real CDP call, never an invented error or body.
    assert.deepEqual(calls.slice(count), [{ method: automation[1], path: automation[2] }]);
    assert.deepEqual(await readObserved(page, response, 'AUTOMATION'), expected);
  } finally { await cdp.detach(); await page.close(); }
});

test('all six profiles route every closed method/path/status and preserve native objects with one fetch/clone', options, async () => {
  const count = calls.length, page = await pageFor();
  try {
    for (const row of matrix) {
      const response = await send(page, row);
      assert.equal(response.status(), row[3]); assert.equal(await response.headerValue('etag'), '"1"');
      assert.deepEqual(await readObserved(page, response, row[0]), responseBody(row[1], row[2], row[3]));
      await native(page);
      assert.deepEqual(await page.evaluate(() => window.headerReads), ['idempotency-key']);
    }
    assert.deepEqual(calls.slice(count), matrix.map((row) => ({ method: row[1], path: row[2] })));
    assert.deepEqual(await page.evaluate(() => [window.nativeCalls, window.cloneCalls]), [matrix.length, matrix.length]);
  } finally { await page.close(); }
});

test('profiles not explicitly registered cannot capture other business responses', options, async () => {
  const page = await pageFor(['SERVICE_CLIENT']);
  try {
    const key = await start(page); await native(page);
    assert.equal(await page.evaluate(({ slot, id }) => window[slot].profile('SERVICE_CLIENT').has(id), {
      slot, id: JSON.stringify(['POST', automation[2], key]),
    }), false);
    assert.equal(await page.evaluate(() => window.cloneCalls), 0);
    assert.equal(await page.evaluate((slot) => !!window[slot].profile('AUTOMATION'), slot), false);
  } finally { await page.close(); }
});

test('wrong-profile consume is isolated and cannot delete a matching original receipt', options, async () => {
  const page = await pageFor();
  try {
    const response = await send(page), key = await response.request().headerValue('idempotency-key');
    await assert.rejects(page.evaluate(({ slot, id }) => window[slot].profile('GRANT').take(id, 201, '"1"'), {
      slot, id: JSON.stringify(['POST', automation[2], key]),
    }), /GRANT_OBSERVER_UNMATCHED/);
    assert.deepEqual(await readObserved(page, response, 'AUTOMATION'), responseBody('POST', automation[2], 201));
  } finally { await page.close(); }
});

test('repeated registration and compatibility aliases share one wrapper and records', options, async () => {
  const page = await pageFor(['GRANT']);
  try {
    await page.evaluate(() => { window.observerFetch = window.fetch; });
    await installServiceClientResponseObserver(page, origin);
    await installDiagnosisResponseObserver(page, origin);
    await installMutationResponseObserver(page, origin, names);
    assert.equal(await page.evaluate(() => window.fetch === window.observerFetch), true);
    assert.equal(await page.evaluate((slot) => window.__sandboxServiceClientResponseObserver === window[slot].profile('SERVICE_CLIENT') &&
      window.__sandboxDiagnosisResponseObserver === window[slot].profile('DIAGNOSIS'), slot), true);
    const response = await send(page); await readObserved(page, response, 'AUTOMATION'); await native(page);
    assert.deepEqual(await page.evaluate(() => [window.nativeCalls, window.cloneCalls]), [1, 1]);
  } finally { await page.close(); }
});

test('multiple self-contained initializers restore all profiles after real reload without wrapper stacking', options, async () => {
  const page = await pageFor(['LIFECYCLE']);
  try {
    await installDiagnosisResponseObserver(page, origin);
    await installMutationResponseObserver(page, origin, ['GRANT', 'AUTOMATION']);
    await installServiceClientResponseObserver(page, origin);
    await installMutationResponseObserver(page, origin, ['NOTIFICATION']);
    await page.reload();
    assert.deepEqual(await page.evaluate(({ slot, names }) => names.map((name) => !!window[slot].profile(name)), { slot, names }), names.map(() => true));
    const response = await send(page); await readObserved(page, response, 'AUTOMATION'); await native(page);
    assert.deepEqual(await page.evaluate(() => [window.nativeCalls, window.cloneCalls]), [1, 1]);
  } finally { await page.close(); }
});

test('one global sixteen-response budget spans all six profiles and fails every consumer closed', options, async () => {
  const count = calls.length, page = await pageFor();
  try {
    let response;
    for (let index = 0; index < 17; index++) { response = await send(page, matrix[index % matrix.length]); await native(page); }
    for (const name of names) {
      await assert.rejects(page.evaluate(({ slot, name }) => window[slot].profile(name).take('any', 200, null), { slot, name }), /OBSERVER_BUDGET_OR_DUPLICATE/);
    }
    assert.equal(calls.length - count, 17); assert.equal(await page.evaluate(() => window.nativeCalls), 17);
  } finally { await page.close(); }
});

test('an unconsumed duplicate correlation fails closed without replacing native HTTP', options, async () => {
  const count = calls.length, page = await pageFor();
  try {
    const key = randomUUID(); await send(page, automation, 'valid', key); await native(page);
    const response = await send(page, automation, 'valid', key); await native(page);
    await assert.rejects(readObserved(page, response, 'AUTOMATION'), /AUTOMATION_OBSERVER_BUDGET_OR_DUPLICATE/);
    assert.equal(calls.length - count, 2); assert.equal(await page.evaluate(() => window.nativeCalls), 2);
  } finally { await page.close(); }
});

test('same business key on different method/path remains distinctly correlated', options, async () => {
  const page = await pageFor();
  try {
    const key = randomUUID(), first = await send(page, automation, 'valid', key);
    const second = await send(page, matrix[7], 'valid', key);
    assert.deepEqual(await readObserved(page, second, 'GRANT'), responseBody(matrix[7][1], matrix[7][2], 201));
    assert.deepEqual(await readObserved(page, first, 'AUTOMATION'), responseBody(automation[1], automation[2], 201));
  } finally { await page.close(); }
});

test('specific notification404 is consumed before the same original key succeeds with200', options, async () => {
  const count = calls.length, page = await pageFor(), row = matrix[10], key = randomUUID();
  try {
    const denied = await send(page, row, 'notice404', key);
    assert.equal(denied.status(), 404); assert.equal(await denied.headerValue('etag'), null);
    assert.deepEqual(await readObserved(page, denied, 'NOTIFICATION'), { code: 'RESOURCE_NOT_FOUND' });
    const replay = await send(page, row, 'valid', key);
    assert.equal(replay.status(), 200); assert.equal(await replay.headerValue('etag'), '"1"');
    assert.deepEqual(await readObserved(page, replay, 'NOTIFICATION'), responseBody(row[1], row[2], 200));
    assert.deepEqual(calls.slice(count), [{ method: row[1], path: row[2] }, { method: row[1], path: row[2] }]);
  } finally { await page.close(); }
});

test('invalid JSON/truncation/original abort/raw byte overflow remain hard failures', { timeout: 40000 }, async () => {
  for (const scenario of ['invalid', 'truncated', 'abort', 'large']) {
    const count = calls.length, page = await pageFor();
    try {
      const response = await send(page, automation, scenario);
      if (scenario === 'abort') await page.evaluate(() => window.control.abort());
      await assert.rejects(readObserved(page, response, 'AUTOMATION'), /AUTOMATION_OBSERVER_BODY_UNAVAILABLE|AUTOMATION_OBSERVER_BODY_TOO_LARGE/);
      await page.evaluate(() => window.operation);
      if (scenario !== 'large') assert.equal(await page.evaluate(() => !!window.originalBodyFailed), true);
      assert.deepEqual(calls.slice(count), [{ method: 'POST', path: automation[2] }]);
    } finally { await page.close(); }
  }
});

test('clone failure never changes the application original successful response', options, async () => {
  const page = await pageFor();
  try {
    await page.evaluate(() => { Response.prototype.clone = () => { throw new Error('public-contract-clone-failure'); }; });
    const response = await send(page);
    await assert.rejects(readObserved(page, response, 'AUTOMATION'), /AUTOMATION_OBSERVER_BODY_UNAVAILABLE/);
    await native(page); assert.deepEqual(await page.evaluate(() => window.originalBody), responseBody('POST', automation[2], 201));
  } finally { await page.close(); }
});

test('native fetch/redirect failure is preserved without observed success or extra request', options, async () => {
  const count = calls.length, page = await pageFor();
  try {
    const key = await start(page, automation, 'native_failure'); await page.evaluate(() => window.operation);
    assert.equal(await page.evaluate(() => !!window.originalFetchFailed), true);
    await assert.rejects(page.evaluate(({ slot, id }) => window[slot].profile('AUTOMATION').take(id, 201, '"1"'), {
      slot, id: JSON.stringify(['POST', automation[2], key]),
    }), /AUTOMATION_OBSERVER_FETCH_FAILED/);
    assert.deepEqual(calls.slice(count), [{ method: 'POST', path: automation[2] }]);
  } finally { await page.close(); }
});

test('credential JSON is rejected while GET/auth/credential routes and unrelated errors are never cloned', options, async () => {
  const page = await pageFor();
  try {
    const response = await send(page, automation, 'credential');
    await assert.rejects(readObserved(page, response, 'AUTOMATION'), /AUTOMATION_OBSERVER_CREDENTIAL_FIELD_REJECTED/);
    const count = await page.evaluate(() => window.cloneCalls);
    for (const row of [
      ['AUTOMATION', 'GET', automation[2], 200], ['AUTOMATION', 'GET', '/auth/session', 200],
      ['AUTOMATION', 'POST', '/auth/login', 200], ['SERVICE_CLIENT', 'POST', `/v1/service-clients/${id}/credentials`, 200],
    ]) { await send(page, row); await native(page); }
    await send(page, automation, 'rejected'); await native(page);
    assert.equal(await page.evaluate(() => window.cloneCalls), count);
  } finally { await page.close(); }
});

test('closed profile/scope/status/ETag/origin checks prevent another receipt substitution', options, async () => {
  const page = await pageFor();
  try {
    await assert.rejects(installMutationResponseObserver(page, origin, ['UNKNOWN']), /MUTATION_OBSERVER_PROFILE/);
    await assert.rejects(installMutationResponseObserver(page, origin, []), /MUTATION_OBSERVER_PROFILE/);
    const response = await send(page), wrong = Object.create(response);
    const otherRouteStatus = Object.create(response); otherRouteStatus.status = () => 200;
    await assert.rejects(readObserved(page, otherRouteStatus, 'AUTOMATION'), /AUTOMATION_OBSERVER_MISMATCH/);
    const client = await send(page, matrix[1]), clientWrongStatus = Object.create(client);
    clientWrongStatus.status = () => 201;
    await assert.rejects(readObserved(page, clientWrongStatus, 'SERVICE_CLIENT'), /SERVICE_CLIENT_OBSERVER_MISMATCH/);
    assert.deepEqual(await readObserved(page, client, 'SERVICE_CLIENT'), responseBody(matrix[1][1], matrix[1][2], 200));
    wrong.headerValue = async (name) => name.toLowerCase() === 'etag' ? '"9"' : response.headerValue(name);
    await assert.rejects(readObserved(page, wrong, 'AUTOMATION'), /AUTOMATION_OBSERVER_MISMATCH/);
    const wrongStatus = Object.create(response); wrongStatus.status = () => 202;
    await assert.rejects(readObserved(page, wrongStatus, 'AUTOMATION'), /AUTOMATION_OBSERVER_SCOPE/);
    const wrongOrigin = Object.create(response); wrongOrigin.url = () => 'http://localhost:' + server.address().port + automation[2];
    await assert.rejects(readObserved(page, wrongOrigin, 'AUTOMATION'), /AUTOMATION_OBSERVER_ORIGIN/);
    const wrongMethod = Object.create(response);
    wrongMethod.request = () => ({ method: () => 'GET', headerValue: async () => randomUUID() });
    await assert.rejects(readObserved(page, wrongMethod, 'AUTOMATION'), /AUTOMATION_OBSERVER_SCOPE/);
    for (const url of [origin + automation[2] + '?x=1', origin + automation[2] + '#x', origin + '/v1/instances/invalid/automations']) {
      const wrongPath = Object.create(response); wrongPath.url = () => url;
      await assert.rejects(readObserved(page, wrongPath, 'AUTOMATION'), /AUTOMATION_OBSERVER_SCOPE/);
    }
  } finally { await page.close(); }
});
