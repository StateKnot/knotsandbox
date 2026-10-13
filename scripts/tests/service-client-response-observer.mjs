// Read the same real browser response without depending on CDP body retention.
// The SDK receives its original native fetch Promise, Request/signal and Response.
// This is test observation only: no request, response, retry or success is invented.
const slot = '__sandboxServiceClientResponseObserver';

export async function installServiceClientResponseObserver(page, origin) {
  if (new URL(origin).origin !== origin) throw new Error('SERVICE_CLIENT_OBSERVER_ORIGIN');
  const setup = ({ slot, origin }) => {
    if (window[slot]) {
      if (window[slot].origin !== origin) throw new Error('SERVICE_CLIENT_OBSERVER_ORIGIN');
      return;
    }
    const records = new Map();
    const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
    const maxBytes = 256 * 1024;
    // At most 16 retained replies, each <=256 KiB: <=4 MiB raw JSON in total.
    let fatal = false;
    const nativeFetch = window.fetch;
    const scopeOf = (input, init) => {
      try {
        const url = new URL(input instanceof Request ? input.url : String(input), location.href);
        const method = (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
        if (url.origin !== origin || url.search || url.hash) return null;
        if (!(method === 'POST' && url.pathname === '/v1/service-clients') &&
            !(method === 'PATCH' && url.pathname.startsWith('/v1/service-clients/') &&
              uuid.test(url.pathname.slice('/v1/service-clients/'.length)))) return null;
        // Inspect only this business correlation key, never authentication headers.
        const headers = init?.headers ?? (input instanceof Request ? input.headers : undefined);
        let key;
        if (headers instanceof Headers) key = headers.get('Idempotency-Key');
        else if (Array.isArray(headers)) {
          const pair = headers.find((pair) => String(pair[0]).toLowerCase() === 'idempotency-key');
          if (pair) key = pair[1];
        } else if (headers) {
          const name = Object.keys(headers).find((name) => name.toLowerCase() === 'idempotency-key');
          if (name) key = headers[name];
        }
        return typeof key === 'string' && uuid.test(key)
          ? { id: JSON.stringify([method, url.pathname, key]) } : null;
      } catch { return null; }
    };
    const containsCredentialField = (value) => {
      if (!value || typeof value !== 'object') return false;
      const forbidden = /^(authorization|cookie|set_cookie|password|client_secret|access_token|refresh_token|id_token|csrf_token)$/;
      return Object.keys(value).some((key) => forbidden.test(key.toLowerCase().replaceAll('-', '_'))
        || containsCredentialField(value[key]));
    };
    window.fetch = function (...args) {
      const nativePromise = Reflect.apply(nativeFetch, this, args);
      const scope = scopeOf(args[0], args[1]);
      if (!scope) return nativePromise;
      if (records.has(scope.id) || records.size >= 16) {
        fatal = true;
        return nativePromise;
      }
      const record = {};
      records.set(scope.id, record);
      record.reply = nativePromise.then(async (response) => {
        const metadata = { status: response.status, etag: response.headers.get('etag') };
        if (![200, 201].includes(metadata.status)) {
          records.delete(scope.id);
          return { error: 'STATUS_REJECTED' };
        }
        let reader;
        try {
          const cloned = response.clone();
          if (!cloned.body) return { error: 'BODY_MISSING' };
          reader = cloned.body.getReader();
          const chunks = [];
          let size = 0;
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            size += value.length;
            if (size > maxBytes) return { error: 'BODY_TOO_LARGE' };
            chunks.push(value);
          }
          const bytes = new Uint8Array(size);
          let offset = 0;
          for (const value of chunks) { bytes.set(value, offset); offset += value.length; }
          const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
          if (containsCredentialField(data)) return { error: 'CREDENTIAL_FIELD_REJECTED' };
          return { ...metadata, data };
        } catch { return { error: 'BODY_UNAVAILABLE' }; }
        finally {
          // Cancel only the observer branch; never await it or cancel SDK input.
          if (reader) { void reader.cancel().catch(() => {}); reader.releaseLock(); }
        }
      }, () => ({ error: 'FETCH_FAILED' }));
      // Attach observation without awaiting the clone or replacing the Promise.
      return nativePromise;
    };
    Object.defineProperty(window, slot, { value: {
      origin,
      has: (id) => fatal || records.has(id),
      take: async (id, status, etag) => {
        if (fatal) throw new Error('SERVICE_CLIENT_OBSERVER_BUDGET_OR_DUPLICATE');
        const record = records.get(id);
        if (!record) throw new Error('SERVICE_CLIENT_OBSERVER_UNMATCHED');
        try {
          const reply = await record.reply;
          if (reply.error) throw new Error('SERVICE_CLIENT_OBSERVER_' + reply.error);
          if (reply.status !== status || reply.etag !== etag) throw new Error('SERVICE_CLIENT_OBSERVER_MISMATCH');
          return reply.data;
        } finally { records.delete(id); }
      },
    }});
  };
  await page.addInitScript(setup, { slot, origin });
  await page.evaluate(setup, { slot, origin });
}

export async function serviceClientMutationJson(page, response) {
  const request = response.request();
  const key = await request.headerValue('idempotency-key');
  const url = new URL(response.url());
  const method = request.method();
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  if (!uuid.test(key ?? '') || url.search || url.hash || ![200, 201].includes(response.status()) ||
      !(method === 'POST' && url.pathname === '/v1/service-clients' ||
        method === 'PATCH' && url.pathname.startsWith('/v1/service-clients/') &&
        uuid.test(url.pathname.slice('/v1/service-clients/'.length)))) {
    throw new Error('SERVICE_CLIENT_OBSERVER_SCOPE');
  }
  if (await page.evaluate((slot) => window[slot]?.origin, slot) !== url.origin) {
    throw new Error('SERVICE_CLIENT_OBSERVER_ORIGIN');
  }
  const id = JSON.stringify([method, url.pathname, key]);
  await page.waitForFunction(({ slot, id }) => window[slot]?.has(id), { slot, id }, { timeout: 15000 });
  return page.evaluate(({ slot, id, origin, status, etag }) => {
    if (window[slot]?.origin !== origin) throw new Error('SERVICE_CLIENT_OBSERVER_ORIGIN');
    return window[slot].take(id, status, etag);
  }, { slot, id, origin: url.origin, status: response.status(), etag: await response.headerValue('etag') });
}
