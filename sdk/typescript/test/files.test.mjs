import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:http';
import test from 'node:test';
import { uploadFilePart, downloadFile, createSandboxFetch } from '../dist/index.js';

const tenant = '00000000-0000-4000-8000-000000000001';
const transfer = '00000000-0000-4000-8000-000000000002';
const bytes = new TextEncoder().encode('binary\0workspace\ufffd');
const digest = data => createHash('sha256').update(data).digest('hex');
const options = extra => ({ baseUrl: 'https://sandbox.example', tenantId: tenant,
  tokenProvider: { getToken: async () => 'access-token' }, ...extra });
const upload = extra => ({ transferId: transfer, index: 0, ifMatch: '"2"', bytes, ...extra });
const download = extra => ({ transferId: transfer, expectedVersion: 3,
  expectedByteLength: bytes.length, expectedSha256: digest(bytes), ...extra });
const acknowledgement = (extra = {}, headers = {}) => new Response(JSON.stringify({ index: 0,
  byte_length: bytes.length, sha256: digest(bytes), transfer_version: 3, ...extra }),
  { headers: { 'content-type': 'application/json', etag: '"3"', ...headers } });
const content = (body = bytes, headers = {}) => new Response(body,
  { headers: { 'content-type': 'application/octet-stream', 'content-length': String(bytes.length),
    'x-content-sha256': digest(bytes), etag: '"3"', ...headers } });

test('file PUT never retries uncertain I/O, 401 or retryable status and reports an unknown outcome', async () => {
  for (const failure of [() => { throw new TypeError('lost after PUT'); },
    () => new Response('{}', { status: 401 }), () => new Response('{}', { status: 503 }),
    () => acknowledgement({ sha256: '0'.repeat(64) }), () => acknowledgement({}, { etag: '"4"' }),
    () => new Response(null, { status: 307, headers: { location: 'https://other.example' } })]) {
    let calls = 0, tokens = 0;
    await assert.rejects(uploadFilePart(options({ tokenProvider: { getToken: async () => { tokens++; return 'token'; } },
      fetch: async () => { calls++; return failure(); } }), upload()), { outcomeUnknown: true });
    assert.equal(calls, 1); assert.equal(tokens, 1);
  }
});

test('file PUT snapshots caller bytes before token work and does not leak cookie or redirect credentials', async () => {
  const source = new Uint8Array(bytes); let release;
  const gate = new Promise(resolve => { release = resolve; });
  const received = [];
  const work = uploadFilePart(options({ tokenProvider: { getToken: async () => { await gate; return 'token'; } },
    fetch: async request => {
      received.push(new Uint8Array(await request.arrayBuffer()));
      assert.equal(request.headers.get('x-content-sha256'), digest(bytes));
      assert.equal(request.headers.get('x-tenant-id'), tenant);
      assert.equal(request.headers.get('authorization'), 'Bearer token');
      assert.equal(request.headers.get('cookie'), null);
      assert.equal(request.headers.get('idempotency-key'), null);
      assert.equal(request.redirect, 'manual'); assert.equal(request.credentials, 'omit');
      return acknowledgement();
    } }), upload({ bytes: source }));
  source.fill(1); release();
  assert.equal((await work).transfer_version, 3);
  assert.deepEqual(received, [bytes]);
});

test('data validation and generic transport separation precede token and network work', async () => {
  let calls = 0;
  const transport = options({ tokenProvider: { getToken: async () => { calls++; return 'token'; } },
    fetch: async () => { calls++; return acknowledgement(); } });
  for (const invalid of [{ index: 100 }, { index: -1 }, { ifMatch: 'W/"2"' },
    { bytes: new Uint8Array(0) }, { bytes: new Uint8Array(1048577) }, { transferId: '../other' }]) {
    await assert.rejects(uploadFilePart(transport, upload(invalid)), { code: 'INVALID_FILE_CONFIGURATION', outcomeUnknown: false });
  }
  for (const invalid of [{ expectedByteLength: 104857601 }, { expectedSha256: 'UPPERCASE' }, { expectedVersion: 0 }]) {
    await assert.rejects(downloadFile(transport, download(invalid)), { code: 'INVALID_FILE_CONFIGURATION' });
  }
  const send = createSandboxFetch(transport);
  for (const suffix of ['', '/0']) {
    await assert.rejects(send(new Request(`https://sandbox.example/v1/file-transfers/${transfer}/content${suffix}`)),
      { code: 'FILE_DATA_TRANSPORT_REQUIRED' });
  }
  assert.equal(calls, 0);
});

test('download returns only complete data matching frozen version, length and full SHA', async () => {
  const actual = await downloadFile(options({ fetch: async () => content() }), download());
  assert.deepEqual(actual, bytes);
  for (const response of [content(new Uint8Array(bytes.length)), content(bytes.slice(1)),
    content(new Uint8Array(bytes.length + 1)), content(bytes, { etag: '"4"' }),
    content(bytes, { 'content-encoding': 'gzip' }), content(bytes, { 'x-content-sha256': '0'.repeat(64) })]) {
    await assert.rejects(downloadFile(options({ fetch: async () => response }), download()), { outcomeUnknown: false });
  }
  const empty = new Uint8Array(0);
  assert.deepEqual(await downloadFile(options({ fetch: async () => content(empty,
    { 'content-length': '0', 'x-content-sha256': digest(empty) }) }), download({ expectedByteLength: 0,
      expectedSha256: digest(empty) })), empty);
});

test('ignored aborts and stalled bodies remain deadline bounded; no partial bytes are returned', async () => {
  await assert.rejects(uploadFilePart(options({ fetch: async () => new Promise(() => {}) }), upload({ timeoutMs: 30 })),
    { code: 'FILE_TRANSPORT_INTERRUPTED', outcomeUnknown: true });
  let cancelled = false;
  const stalled = new ReadableStream({ start(controller) { controller.enqueue(bytes.slice(0, 1)); },
    cancel() { cancelled = true; } });
  await assert.rejects(downloadFile(options({ fetch: async () => content(stalled) }), download({ timeoutMs: 30 })),
    { code: 'FILE_TRANSPORT_INTERRUPTED' });
  assert.equal(cancelled, true);
});

test('real TCP byte channel preserves exact headers, bytes and acknowledgement', async () => {
  const requests = [];
  const server = createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks); requests.push({ method: req.method, body });
    assert.equal(req.headers['x-tenant-id'], tenant); assert.equal(req.headers.authorization, 'Bearer access-token');
    if (req.method === 'PUT') {
      assert.equal(req.headers['content-length'], String(bytes.length));
      assert.equal(req.headers['x-content-sha256'], digest(bytes));
      assert.equal(req.headers['if-match'], '"2"'); assert.deepEqual(new Uint8Array(body), bytes);
      res.writeHead(200, { 'content-type': 'application/json', etag: '"3"' });
      res.end(JSON.stringify({ index: 0, byte_length: bytes.length, sha256: digest(bytes), transfer_version: 3 }));
    } else {
      res.writeHead(200, { 'content-type': 'application/octet-stream', etag: '"3"',
        'content-length': String(bytes.length), 'x-content-sha256': digest(bytes) }); res.end(bytes);
    }
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  try {
    const transport = options({ baseUrl: `http://127.0.0.1:${server.address().port}`, allowLoopbackHttp: true });
    assert.equal((await uploadFilePart(transport, upload())).transfer_version, 3);
    assert.deepEqual(await downloadFile(transport, download()), bytes);
    assert.deepEqual(requests.map(r => r.method), ['PUT', 'GET']);
  } finally { await new Promise(resolve => server.close(resolve)); }
});
