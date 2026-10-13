// Real loopback HTTP + browser contracts for the test observation adapter.
// These checks do not certify product identity, database, cloud or isolation.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { isAbsolute } from 'node:path';
import { before, after, test } from 'node:test';
import { chromium } from '../../console/node_modules/playwright-core/index.mjs';
import { installServiceClientResponseObserver, serviceClientMutationJson } from './service-client-response-observer.mjs';

assert.equal(process.argv.length, 4);
assert.equal(process.argv[2], '--chrome');
assert(isAbsolute(process.argv[3]), 'an explicit installed browser is required');
const uuid = '00000000-0000-4000-8000-000000000001';
const path = '/v1/service-clients/' + uuid;
const slot = '__sandboxServiceClientResponseObserver';
const calls = [];
let origin, server, browser;
before(async () => {
  server = createServer((request, response) => {
    if (request.url === '/') {
      response.setHeader('content-type', 'text/html');
      response.end('<p>Real native fetch observation contract</p><script>window.sdkSend=fetch.bind(window)</script>');
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
    response.setHeader('content-type', 'application/json');
    const registration = request.method === 'POST' && request.url === '/v1/service-clients';
    response.statusCode = registration ? 201 : 200;
    response.setHeader('etag', registration ? '"1"' : '"3"');
    if (scenario === 'invalid') { response.end('{invalid'); return; }
    if (scenario === 'abort') { response.write('{"resource":'); return; }
    if (scenario === 'truncated') {
      response.setHeader('content-length', '900'); response.end('{"resource":'); return;
    }
    const value = { resource: { version: registration ? 1 : 3 }, text: scenario === 'large' ? 'a'.repeat(300 * 1024) : 'actual server bytes' };
    if (scenario === 'credential') value.resource.access_token = 'public-contract-sentinel';
    response.end(JSON.stringify(value));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  origin = 'http://127.0.0.1:' + server.address().port;
  browser = await chromium.launch({ headless: true, executablePath: process.argv[3] });
});
after(async () => {
  await browser?.close();
  server?.closeAllConnections();
  if (server?.listening) await new Promise((resolve) => server.close(resolve));
});

async function pageFor() {
  const page = await browser.newPage();
  await page.goto(origin);
  await page.evaluate(() => {
    const nativeFetch = window.fetch;
    window.fetch = function (...args) {
      window.nativeInput = args[0];
      window.nativePromise = Reflect.apply(nativeFetch, this, args);
      window.nativePromise.then((response) => { window.nativeResponse = response; }, () => {});
      return window.nativePromise;
    };
  });
  await installServiceClientResponseObserver(page, origin);
  return page;
}

async function start(page, scenario = 'valid', key = randomUUID(), target = path, method = 'PATCH') {
  await page.evaluate(({ target, key, scenario, method }) => {
    window.control = new AbortController();
    const request = new Request(target, { method, headers: {
      'Idempotency-Key': key, 'X-Scenario': scenario, 'Authorization': 'public-contract-sentinel',
    }, signal: window.control.signal, redirect: 'error' });
    const readHeader = request.headers.get.bind(request.headers);
    window.requestHeaderReads = [];
    request.headers.get = (name) => { window.requestHeaderReads.push(name.toLowerCase()); return readHeader(name); };
    window.originalInput = request;
    const pending = fetch(request);
    window.promiseSame = pending === window.nativePromise;
    window.operation = pending.then(async (response) => {
      window.responseSame = response === window.nativeResponse;
      try { window.originalBody = await response.json(); }
      catch { window.originalBodyFailed = true; }
    }, () => { window.originalFetchFailed = true; });
  }, { target: origin + target, key, scenario, method });
  return key;
}

async function send(page, scenario = 'valid', key = randomUUID()) {
  const pending = page.waitForResponse((reply) => new URL(reply.url()).pathname === path && reply.request().method() === 'PATCH');
  await start(page, scenario, key);
  return pending;
}

function assertNoReplacement(beforeCount, expected) {
  const actual = calls.slice(beforeCount);
  assert.equal(actual.length, expected);
  assert(actual.every((call) => call.method === 'PATCH' && call.path === path));
}

test('registration observes its actual POST 201 body and ETag without a second request', async () => {
  const beforeCount = calls.length;
  const page = await pageFor();
  try {
    const pending = page.waitForResponse((reply) => new URL(reply.url()).pathname === '/v1/service-clients' && reply.request().method() === 'POST');
    await start(page, 'valid', randomUUID(), '/v1/service-clients', 'POST');
    const response = await pending;
    assert.equal(response.status(), 201);
    assert.equal(await response.headerValue('etag'), '"1"');
    const observed = await serviceClientMutationJson(page, response);
    assert.equal(observed.resource.version, 1);
    await page.evaluate(() => window.operation);
    assert.deepEqual(await page.evaluate(() => window.originalBody), observed);
    assert.deepEqual(calls.slice(beforeCount), [{ method: 'POST', path: '/v1/service-clients' }]);
  } finally { await page.close(); }
});

test('CDP body failure still validates the same native response; caller identities remain intact', async () => {
  const beforeCount = calls.length;
  const page = await pageFor();
  try {
    const response = await send(page);
    // Fault only the external body observation channel, never browser HTTP.
    response.json = async () => { throw new Error('No resource with given identifier found'); };
    await assert.rejects(response.json(), /No resource/);
    const observed = await serviceClientMutationJson(page, response);
    assert.equal(observed.resource.version, 3);
    await page.evaluate(() => window.operation);
    assert.deepEqual(await page.evaluate(() => window.originalBody), observed);
    assert.deepEqual(await page.evaluate(() => [window.promiseSame, window.responseSame,
      window.nativeInput === window.originalInput, window.nativeInput.signal === window.originalInput.signal]), [true, true, true, true]);
    assert.deepEqual(await page.evaluate(() => window.requestHeaderReads), ['idempotency-key']);
    const key = await response.request().headerValue('idempotency-key');
    assert.equal(await page.evaluate(({ slot, id }) => window[slot].has(id), {
      slot, id: JSON.stringify(['PATCH', path, key]),
    }), false, 'a consumed body must be removed');
    assertNoReplacement(beforeCount, 1);
  } finally { await page.close(); }
});

test('invalid JSON, truncated body, original signal abort and byte overflow remain hard failures', async () => {
  for (const scenario of ['invalid', 'truncated', 'abort', 'large']) {
    const beforeCount = calls.length;
    const page = await pageFor();
    try {
      const response = await send(page, scenario);
      if (scenario === 'abort') await page.evaluate(() => window.control.abort());
      await assert.rejects(serviceClientMutationJson(page, response), /SERVICE_CLIENT_OBSERVER_BODY_UNAVAILABLE|SERVICE_CLIENT_OBSERVER_BODY_TOO_LARGE/);
      await page.evaluate(() => window.operation);
      if (scenario !== 'large') assert.equal(await page.evaluate(() => !!window.originalBodyFailed), true);
      assertNoReplacement(beforeCount, 1);
    } finally { await page.close(); }
  }
});

test('clone failure fails observation without changing the successful original response', async () => {
  const beforeCount = calls.length;
  const page = await pageFor();
  try {
    await page.evaluate(() => { Response.prototype.clone = () => { throw new Error('public-contract-clone-failure'); }; });
    const response = await send(page);
    await assert.rejects(serviceClientMutationJson(page, response), /SERVICE_CLIENT_OBSERVER_BODY_UNAVAILABLE/);
    await page.evaluate(() => window.operation);
    assert.equal(await page.evaluate(() => window.originalBody.resource.version), 3);
    assertNoReplacement(beforeCount, 1);
  } finally { await page.close(); }
});

test('native fetch failure is preserved and cannot become an observed success', async () => {
  const beforeCount = calls.length;
  const page = await pageFor();
  try {
    const key = await start(page, 'native_failure');
    await page.evaluate(() => window.operation);
    assert.equal(await page.evaluate(() => !!window.originalFetchFailed), true);
    await assert.rejects(page.evaluate(({ slot, id }) => window[slot].take(id, 200, '"3"'), {
      slot, id: JSON.stringify(['PATCH', path, key]),
    }), /SERVICE_CLIENT_OBSERVER_FETCH_FAILED/);
    assertNoReplacement(beforeCount, 1);
  } finally { await page.close(); }
});

test('record overflow and duplicate correlation keys fail closed without extra requests', async () => {
  for (const duplicate of [false, true]) {
    const beforeCount = calls.length;
    const page = await pageFor();
    try {
      const count = duplicate ? 2 : 17;
      const key = randomUUID();
      let response;
      for (let i = 0; i < count; i++) {
        response = await send(page, 'valid', duplicate ? key : randomUUID());
        await page.evaluate(() => window.operation);
      }
      await assert.rejects(serviceClientMutationJson(page, response), /SERVICE_CLIENT_OBSERVER_BUDGET_OR_DUPLICATE/);
      assertNoReplacement(beforeCount, count);
    } finally { await page.close(); }
  }
});

test('status mismatch, unmatched keys, wrong method and wrong origin cannot substitute another body', async () => {
  const beforeCount = calls.length;
  const page = await pageFor();
  try {
    const response = await send(page);
    const mismatched = Object.create(response);
    mismatched.status = () => 201;
    await assert.rejects(serviceClientMutationJson(page, mismatched), /SERVICE_CLIENT_OBSERVER_MISMATCH/);
    await assert.rejects(page.evaluate(({ slot, id }) => window[slot].take(id, 200, '"3"'), {
      slot, id: JSON.stringify(['PATCH', path, randomUUID()]),
    }), /SERVICE_CLIENT_OBSERVER_UNMATCHED/);
    const wrongMethod = Object.create(response);
    wrongMethod.request = () => ({ method: () => 'GET', headerValue: async () => randomUUID() });
    await assert.rejects(serviceClientMutationJson(page, wrongMethod), /SERVICE_CLIENT_OBSERVER_SCOPE/);
    const wrongOrigin = Object.create(response);
    wrongOrigin.url = () => 'http://localhost:' + server.address().port + path;
    await assert.rejects(serviceClientMutationJson(page, wrongOrigin), /SERVICE_CLIENT_OBSERVER_ORIGIN/);
    assertNoReplacement(beforeCount, 1);
  } finally { await page.close(); }
});

test('credential-shaped response fields are rejected; auth endpoint bodies are never observed', async () => {
  const beforeCount = calls.length;
  const page = await pageFor();
  try {
    const response = await send(page, 'credential');
    await assert.rejects(serviceClientMutationJson(page, response), /SERVICE_CLIENT_OBSERVER_CREDENTIAL_FIELD_REJECTED/);
    const key = await start(page, 'valid', randomUUID(), '/auth/session');
    await page.evaluate(() => window.operation);
    assert.equal(await page.evaluate(({ slot, id }) => window[slot].has(id), {
      slot, id: JSON.stringify(['PATCH', '/auth/session', key]),
    }), false);
    assert.equal(calls.length - beforeCount, 2);
  } finally { await page.close(); }
});

test('the same observer is installed after a real page reload', async () => {
  const beforeCount = calls.length;
  const page = await pageFor();
  try {
    await page.reload();
    const response = await send(page);
    assert.equal((await serviceClientMutationJson(page, response)).resource.version, 3);
    assertNoReplacement(beforeCount, 1);
  } finally { await page.close(); }
});

test('HTML bootstrap that captures fetch requires observation before the SDK is constructed', async () => {
  const beforeCount = calls.length;
  for (const installEarly of [false, true]) {
    const page = await browser.newPage();
    try {
      if (installEarly) await installServiceClientResponseObserver(page, origin);
      await page.goto(origin);
      if (!installEarly) await installServiceClientResponseObserver(page, origin);
      const key = randomUUID();
      const pending = page.waitForResponse((reply) => new URL(reply.url()).pathname === path && reply.request().method() === 'PATCH');
      await page.evaluate(({ path, key }) => {
        window.sdkOperation = window.sdkSend(new Request(path, {
          method: 'PATCH', headers: { 'Idempotency-Key': key }, redirect: 'error',
        })).then(async (response) => { window.sdkBody = await response.json(); });
      }, { path: origin + path, key });
      const response = await pending;
      await page.evaluate(() => window.sdkOperation);
      assert.equal(await page.evaluate(({ slot, id }) => window[slot].has(id), {
        slot, id: JSON.stringify(['PATCH', path, key]),
      }), installEarly, 'late instrumentation cannot replace a fetch reference already captured by an SDK');
      if (installEarly) {
        assert.deepEqual(await serviceClientMutationJson(page, response), await page.evaluate(() => window.sdkBody));
      }
      assert.equal(await page.evaluate(() => window.sdkBody.resource.version), 3);
    } finally { await page.close(); }
  }
  assertNoReplacement(beforeCount, 2);
});
