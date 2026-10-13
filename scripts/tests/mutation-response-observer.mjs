// Test-only native response observation. Closed business profiles, one fetch
// wrapper and one 16 x 256 KiB raw-response budget; no request/retry is invented.
// Reads additionally require one explicit, document-local, bounded observation.
const readBusy = new WeakSet();
const readInstalled = new WeakMap();
const readTimeout = 15000;
const slot = '__sandboxMutationResponseObserver';
const uuid = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const definitions = {
  SERVICE_CLIENT: { prefix: 'SERVICE_CLIENT_OBSERVER_', alias: '__sandboxServiceClientResponseObserver', routes: [
    { method: 'POST', path: '^/v1/service-clients$', statuses: [201] },
    { method: 'PATCH', path: '^/v1/service-clients/' + uuid + '$', statuses: [200] },
  ] },
  DIAGNOSIS: { prefix: 'DIAGNOSIS_OBSERVER_', alias: '__sandboxDiagnosisResponseObserver', routes: [
    { method: 'POST', path: '^/v1/instances/' + uuid + '/diagnoses$', statuses: [202] },
  ] },
  AUTOMATION: { prefix: 'AUTOMATION_OBSERVER_', routes: [
    { method: 'POST', path: '^/v1/instances/' + uuid + '/automations$', statuses: [201] },
    { method: 'POST', path: '^/v1/automations/' + uuid + '/actions/(pause|resume|revoke)$', statuses: [200] },
  ] },
  GRANT: { prefix: 'GRANT_OBSERVER_', routes: [
    { method: 'POST', path: '^/v1/projects/' + uuid + '/grants$', statuses: [201] },
    { method: 'PATCH', path: '^/v1/projects/' + uuid + '/grants/' + uuid + '$', statuses: [200] },
    { method: 'DELETE', path: '^/v1/projects/' + uuid + '/grants/' + uuid + '$', statuses: [200] },
  ] },
  NOTIFICATION: { prefix: 'NOTIFICATION_OBSERVER_', routes: [
    { method: 'POST', path: '^/v1/automation-notifications/' + uuid + '/actions/acknowledge$', statuses: [200, 404] },
  ] },
  LIFECYCLE: { prefix: 'LIFECYCLE_OBSERVER_', routes: [
    { method: 'POST', path: '^/v1/instances/' + uuid + '/actions/stop$', statuses: [202] },
  ] },
};
function definition(profile) {
  if (typeof profile !== 'string' || !Object.hasOwn(definitions, profile)) throw new Error('MUTATION_OBSERVER_PROFILE');
  return definitions[profile];
}

export async function installMutationResponseObserver(page, origin, profiles) {
  if (!Array.isArray(profiles) || profiles.length < 1 || profiles.length > 6 || new Set(profiles).size !== profiles.length) {
    throw new Error('MUTATION_OBSERVER_PROFILE');
  }
  profiles.forEach(definition);
  return installResponseObserver(page, origin, profiles);
}

async function installResponseObserver(page, origin, profiles) {
  const prefix = profiles.length ? definition(profiles[0]).prefix : 'READ_OBSERVER_';
  if (new URL(origin).origin !== origin) throw new Error(prefix + 'ORIGIN');
  // Entire setup is self-contained for addInitScript. Every initializer can
  // create the same core or register profiles; execution order is immaterial.
  const setup = ({ slot, origin, profiles, definitions, uuid }) => {
    const prefix = profiles.length ? definitions[profiles[0]].prefix : 'READ_OBSERVER_';
    if (window[slot]) {
      if (window[slot].origin !== origin) throw new Error(prefix + 'ORIGIN');
      window[slot].register(profiles);
      return;
    }
    const enabled = new Map(), records = new Map();
    const keyPattern = new RegExp('^' + uuid + '$');
    const maxBytes = 256 * 1024;
    let fatal = false, readTicket = null;
    const nonce = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) => byte.toString(16).padStart(2, '0')).join('');
    const documentId = nonce();
    const readRoutes = [
      { path: '^/v1/service-clients$', query: { limit: 'limit', cursor: 2048 }, loose: true },
      { path: '^/v1/service-clients/' + uuid + '$' },
      { path: '^/v1/diagnoses/' + uuid + '$' },
      { path: '^/v1/automations/' + uuid + '$' },
      { path: '^/v1/automations/' + uuid + '/runs$', query: { project_id: 'uuid', instance_id: 'uuid', limit: 'limit', cursor: 4096 }, project: true },
      { path: '^/v1/automation-notifications$', query: { project_id: 'uuid', instance_id: 'uuid', limit: 'limit', cursor: 2048 }, project: true },
      { path: '^/v1/automation-notifications/' + uuid + '$' },
      { path: '^/v1/instances/' + uuid + '/details$' },
    ];
    // This is a closed subset of the real API's business GETs. It cannot arm
    // credentials, auth, arbitrary paths, unknown queries or unbounded cursors.
    const selectRead = (raw) => {
      if (typeof raw !== 'string' || raw.length > 16384) throw new Error('READ_OBSERVER_SCOPE');
      const url = new URL(raw, origin);
      if (url.origin !== origin || url.username || url.password || url.hash) throw new Error('READ_OBSERVER_SCOPE');
      const route = readRoutes.find((item) => new RegExp(item.path).test(url.pathname));
      if (!route) throw new Error('READ_OBSERVER_SCOPE');
      const seen = new Set();
      for (const [name, value] of url.searchParams) {
        const rule = route.query?.[name];
        if (!rule || seen.has(name)) throw new Error('READ_OBSERVER_QUERY');
        seen.add(name);
        if (rule === 'uuid' ? !keyPattern.test(value)
          : rule === 'limit' ? !/^(?:[1-9][0-9]?|100)$/.test(value)
          : !value.length || value.length > rule || !/^[\x21-\x7e]+$/.test(value)) throw new Error('READ_OBSERVER_QUERY');
      }
      if (route.project && !seen.has('project_id')) throw new Error('READ_OBSERVER_QUERY');
      return { url: url.href, path: url.pathname, loose: !!route.loose && !url.search };
    };
    const correlationHeader = (input, init, target) => {
      const headers = init?.headers ?? (input instanceof Request ? input.headers : undefined);
      if (headers instanceof Headers) return headers.get(target);
      if (Array.isArray(headers)) {
        const pairs = headers.filter((pair) => String(pair[0]).toLowerCase() === target.toLowerCase());
        return pairs.length === 1 ? pairs[0][1] : undefined;
      }
      if (headers) {
        const names = Object.keys(headers).filter((name) => name.toLowerCase() === target.toLowerCase());
        return names.length === 1 ? headers[names[0]] : undefined;
      }
    };
    const readScopeOf = (input, init) => {
      if (!readTicket) return null;
      try {
        const url = new URL(input instanceof Request ? input.url : String(input), location.href);
        const method = (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
        if (method !== 'GET' || (readTicket.scope.loose ? url.origin !== origin || url.pathname !== readTicket.scope.path : url.href !== readTicket.scope.url)) return null;
        selectRead(url.href);
        // Only this business header is inspected; authentication is untouched.
        if (correlationHeader(input, init, 'X-Tenant-ID') !== readTicket.tenant) { readTicket.error = 'TENANT_MISMATCH'; return null; }
        if (readTicket.started) { readTicket.error = 'DUPLICATE'; return null; }
        if (readTicket.cancelled || performance.now() >= readTicket.deadline) { readTicket.error = 'TIMEOUT'; return null; }
        readTicket.started = true; readTicket.url = url.href;
        return { ticket: readTicket, id: readTicket.token, profile: 'READ', statuses: [200, 404] };
      } catch { readTicket.error = 'QUERY'; return null; }
    };
    const cancelRead = (token) => {
      if (!readTicket || readTicket.token !== token) return;
      readTicket.cancelled = true; clearTimeout(readTicket.timer);
      readTicket.cancel?.();
      records.delete(token); readTicket = null;
    };
    const read = {
      arm: (target, tenant) => {
        if (readTicket) throw new Error('READ_OBSERVER_CONCURRENT');
        if (fatal || records.size >= 16) throw new Error('READ_OBSERVER_BUDGET_OR_DUPLICATE');
        if (typeof tenant !== 'string' || !keyPattern.test(tenant)) throw new Error('READ_OBSERVER_TENANT');
        const scope = selectRead(target), token = nonce();
        readTicket = { scope, tenant, token, documentId, deadline: performance.now() + 15000, started: false };
        // Reserve from the same budget before the request. No payload is read
        // until the first scoped native fetch after this explicit arm.
        records.set(token, readTicket);
        readTicket.timer = setTimeout(() => cancelRead(token), 15000);
        return { token, documentId, ...scope };
      },
      cancel: cancelRead,
      take: async (ticket, metadata) => {
        if (ticket.documentId !== documentId || !readTicket || readTicket.token !== ticket.token) throw new Error('READ_OBSERVER_EXPIRED');
        const record = readTicket;
        try {
          if (fatal) throw new Error('READ_OBSERVER_BUDGET_OR_DUPLICATE');
          if (record.error) throw new Error('READ_OBSERVER_' + record.error);
          if (!record.started || !record.reply) throw new Error('READ_OBSERVER_UNMATCHED');
          const reply = await record.reply;
          if (fatal) throw new Error('READ_OBSERVER_BUDGET_OR_DUPLICATE');
          if (record.error) throw new Error('READ_OBSERVER_' + record.error);
          if (reply.error) throw new Error('READ_OBSERVER_' + reply.error);
          if (metadata.method !== 'GET' || metadata.tenant !== record.tenant || metadata.requestUrl !== record.url || metadata.url !== record.url || reply.url !== record.url ||
              reply.status !== metadata.status || reply.etag !== metadata.etag || reply.instanceEtag !== metadata.instanceEtag) throw new Error('READ_OBSERVER_MISMATCH');
          return reply.data;
        } finally { cancelRead(ticket.token); }
      },
    };
    const register = (names) => {
      for (const name of names) {
        if (!Object.hasOwn(definitions, name)) throw new Error('MUTATION_OBSERVER_PROFILE');
        if (enabled.has(name)) continue;
        const spec = definitions[name];
        const profile = {
          origin,
          has: (id) => fatal || records.get(id)?.profile === name,
          take: async (id, status, etag) => {
            if (fatal) throw new Error(spec.prefix + 'BUDGET_OR_DUPLICATE');
            const record = records.get(id);
            if (!record || record.profile !== name) throw new Error(spec.prefix + 'UNMATCHED');
            try {
              const reply = await record.reply;
              if (reply.error) throw new Error(spec.prefix + reply.error);
              if (reply.status !== status || reply.etag !== etag) throw new Error(spec.prefix + 'MISMATCH');
              return reply.data;
            } finally { records.delete(id); }
          },
        };
        enabled.set(name, profile);
        if (spec.alias) Object.defineProperty(window, spec.alias, { value: profile });
      }
    };
    const scopeOf = (input, init) => {
      try {
        const url = new URL(input instanceof Request ? input.url : String(input), location.href);
        const method = (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
        if (url.origin !== origin || url.search || url.hash) return null;
        let selected;
        for (const name of enabled.keys()) {
          const route = definitions[name].routes.find((route) => route.method === method && new RegExp(route.path).test(url.pathname));
          if (route) selected = { profile: name, statuses: route.statuses };
        }
        if (!selected) return null;
        const headers = init?.headers ?? (input instanceof Request ? input.headers : undefined);
        let key;
        // Inspect one business correlation header, never authentication headers.
        if (headers instanceof Headers) key = headers.get('Idempotency-Key');
        else if (Array.isArray(headers)) {
          const pair = headers.find((pair) => String(pair[0]).toLowerCase() === 'idempotency-key');
          if (pair) key = pair[1];
        } else if (headers) {
          const name = Object.keys(headers).find((name) => name.toLowerCase() === 'idempotency-key');
          if (name) key = headers[name];
        }
        return typeof key === 'string' && keyPattern.test(key)
          ? { ...selected, id: JSON.stringify([method, url.pathname, key]) } : null;
      } catch { return null; }
    };
    const containsCredentialField = (value) => {
      if (!value || typeof value !== 'object') return false;
      const forbidden = /^(authorization|cookie|set_cookie|password|client_secret|access_token|refresh_token|id_token|csrf_token)$/;
      return Object.keys(value).some((key) => forbidden.test(key.toLowerCase().replaceAll('-', '_')) || containsCredentialField(value[key]));
    };
    const capture = async (response, scope) => {
      const control = scope.ticket;
      const metadata = { status: response.status, etag: response.headers.get('etag'),
        ...(control ? { url: response.url, instanceEtag: response.headers.get('x-instance-etag') } : {}) };
      if (!scope.statuses.includes(metadata.status)) {
        if (!control) records.delete(scope.id);
        return { error: 'STATUS_REJECTED' };
      }
      if (control && (control.cancelled || metadata.url !== control.url || response.redirected)) return { error: 'MISMATCH' };
      let reader, timer;
      try {
        const clone = response.clone();
        if (!clone.body) return { error: 'BODY_MISSING' };
        reader = clone.body.getReader();
        if (control) control.cancel = () => { void reader.cancel().catch(() => {}); };
        const timeout = control ? new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error('READ_OBSERVER_TIMEOUT')), Math.max(0, control.deadline - performance.now()));
        }) : null;
        const chunks = [];
        let size = 0;
        for (;;) {
          if (control?.cancelled) return { error: 'EXPIRED' };
          const { done, value } = await (timeout ? Promise.race([reader.read(), timeout]) : reader.read());
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
      } catch (error) { return { error: error?.message === 'READ_OBSERVER_TIMEOUT' ? 'TIMEOUT' : 'BODY_UNAVAILABLE' }; }
      finally {
        clearTimeout(timer);
        // Only the observer tee branch is cancelled; never await it or touch
        // the application's original response or abort signal.
        if (reader) { void reader.cancel().catch(() => {}); reader.releaseLock(); }
        if (control) control.cancel = null;
      }
    };
    const nativeFetch = window.fetch;
    window.fetch = function (...args) {
      const nativePromise = Reflect.apply(nativeFetch, this, args);
      const scope = readScopeOf(args[0], args[1]) ?? scopeOf(args[0], args[1]);
      if (!scope) return nativePromise;
      if (scope.ticket) {
        scope.ticket.reply = nativePromise.then((response) => capture(response, scope), () => ({ error: 'FETCH_FAILED' }));
      } else {
        if (records.has(scope.id) || records.size >= 16) { fatal = true; return nativePromise; }
        const record = { profile: scope.profile };
        records.set(scope.id, record);
        record.reply = nativePromise.then((response) => capture(response, scope), () => ({ error: 'FETCH_FAILED' }));
      }
      return nativePromise;
    };
    Object.defineProperty(window, slot, { value: {
      origin, register, read, profile: (name) => enabled.get(name),
    }});
    register(profiles);
  };
  const input = { slot, origin, profiles, definitions, uuid };
  await page.addInitScript(setup, input);
  await page.evaluate(setup, input);
}

export async function mutationResponseJson(page, response, profile) {
  const spec = definition(profile), request = response.request();
  const key = await request.headerValue('idempotency-key'), url = new URL(response.url()), method = request.method();
  const route = spec.routes.find((route) => route.method === method && new RegExp(route.path).test(url.pathname));
  const status = response.status(), profileStatuses = spec.routes.flatMap((route) => route.statuses);
  if (!new RegExp('^' + uuid + '$').test(key ?? '') || url.search || url.hash || !route || !profileStatuses.includes(status)) {
    throw new Error(spec.prefix + 'SCOPE');
  }
  // A known status belonging to a different route is mismatched metadata.
  // Reject immediately, before waiting for or consuming any browser body.
  if (!route.statuses.includes(status)) throw new Error(spec.prefix + 'MISMATCH');
  if (await page.evaluate(({ slot, profile }) => window[slot]?.profile(profile)?.origin, { slot, profile }) !== url.origin) {
    throw new Error(spec.prefix + 'ORIGIN');
  }
  const id = JSON.stringify([method, url.pathname, key]);
  await page.waitForFunction(({ slot, profile, id }) => window[slot]?.profile(profile)?.has(id), { slot, profile, id }, { timeout: 15000 });
  return page.evaluate(({ slot, profile, id, origin, status, etag, prefix }) => {
    if (window[slot]?.profile(profile)?.origin !== origin) throw new Error(prefix + 'ORIGIN');
    return window[slot].profile(profile).take(id, status, etag);
  }, { slot, profile, id, origin: url.origin, status, etag: await response.headerValue('etag'), prefix: spec.prefix });
}


// Observe the caller's original business GET and return its original Playwright
// Response together with the bounded native clone. A target is exact, except an
// explicitly armed /v1/service-clients list may select its opaque legal cursor.
// One arm per page, no retries, no changed headers, no cross-navigation ticket.
export async function observeReadResponse(page, origin, target, tenant, trigger) {
  if (readBusy.has(page)) throw new Error('READ_OBSERVER_CONCURRENT');
  if (typeof trigger !== 'function') throw new Error('READ_OBSERVER_TRIGGER');
  if (new URL(origin).origin !== origin) throw new Error('READ_OBSERVER_ORIGIN');
  readBusy.add(page);
  let ticket, timer, onResponse, onNavigation, onClosed, onFailed, cancelled = false, rejectInvalidation;
  const invalidation = new Promise((_, reject) => { rejectInvalidation = reject; });
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('READ_OBSERVER_TIMEOUT')), readTimeout);
  });
  try {
    const work = async () => {
      if (readInstalled.get(page) !== origin && !await page.evaluate(({ slot, origin }) => window[slot]?.origin === origin && !!window[slot].read, { slot, origin })) {
        await installResponseObserver(page, origin, []);
      }
      if (cancelled) throw new Error('READ_OBSERVER_EXPIRED');
      readInstalled.set(page, origin);
      ticket = await page.evaluate(({ slot, origin, target, tenant }) => {
        if (window[slot]?.origin !== origin) throw new Error('READ_OBSERVER_ORIGIN');
        return window[slot].read.arm(target, tenant);
      }, { slot, origin, target, tenant });
      if (cancelled) {
        await page.evaluate(({ slot, ticket }) => window[slot]?.read.cancel(ticket.token), { slot, ticket });
        throw new Error('READ_OBSERVER_EXPIRED');
      }
      const responsePromise = new Promise((resolve) => {
        onResponse = (response) => {
          const actual = new URL(response.url());
          if (response.request().method() === 'GET' && (ticket.loose ? actual.origin === origin && actual.pathname === ticket.path : actual.href === ticket.url)) resolve(response);
        };
        onFailed = (request) => {
          const actual = new URL(request.url());
          if (request.method() === 'GET' && (ticket.loose ? actual.origin === origin && actual.pathname === ticket.path : actual.href === ticket.url)) rejectInvalidation(new Error('READ_OBSERVER_FETCH_FAILED'));
        };
        onNavigation = (frame) => { if (frame === page.mainFrame()) rejectInvalidation(new Error('READ_OBSERVER_NAVIGATION')); };
        onClosed = () => rejectInvalidation(new Error('READ_OBSERVER_PAGE_CLOSED'));
        page.on('response', onResponse); page.on('requestfailed', onFailed); page.on('framenavigated', onNavigation); page.on('close', onClosed); page.on('crash', onClosed);
      });
      // Await the original UI trigger as well as its original network response;
      // duplicates issued by that trigger are rejected before consumption.
      const [response] = await Promise.all([responsePromise, Promise.resolve().then(trigger)]);
      const request = response.request();
      const metadata = { method: request.method(), requestUrl: request.url(), url: response.url(), tenant: await request.headerValue('x-tenant-id'),
        status: response.status(), etag: await response.headerValue('etag'), instanceEtag: await response.headerValue('x-instance-etag') };
      const body = await page.evaluate(({ slot, ticket, metadata }) => window[slot].read.take(ticket, metadata), { slot, ticket, metadata });
      return { response, body };
    };
    return await Promise.race([work(), deadline, invalidation]);
  } finally {
    cancelled = true; clearTimeout(timer);
    if (onResponse) page.off('response', onResponse);
    if (onFailed) page.off('requestfailed', onFailed);
    if (onNavigation) page.off('framenavigated', onNavigation);
    if (onClosed) { page.off('close', onClosed); page.off('crash', onClosed); }
    if (ticket && !page.isClosed()) {
      let cleanupTimer;
      await Promise.race([
        page.evaluate(({ slot, ticket }) => window[slot]?.read.cancel(ticket.token), { slot, ticket }).catch(() => {}),
        new Promise((resolve) => { cleanupTimer = setTimeout(resolve, 1000); }),
      ]);
      clearTimeout(cleanupTimer);
    }
    readBusy.delete(page);
  }
}
