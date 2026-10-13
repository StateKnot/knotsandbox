// Test-only native response observation. Closed business profiles, one fetch
// wrapper and one 16 x 256 KiB raw-response budget; no request/retry is invented.
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
  const prefix = definition(profiles[0]).prefix;
  profiles.forEach(definition);
  if (new URL(origin).origin !== origin) throw new Error(prefix + 'ORIGIN');
  // Entire setup is self-contained for addInitScript. Every initializer can
  // create the same core or register profiles; execution order is immaterial.
  const setup = ({ slot, origin, profiles, definitions, uuid }) => {
    const prefix = definitions[profiles[0]].prefix;
    if (window[slot]) {
      if (window[slot].origin !== origin) throw new Error(prefix + 'ORIGIN');
      window[slot].register(profiles);
      return;
    }
    const enabled = new Map(), records = new Map();
    const keyPattern = new RegExp('^' + uuid + '$');
    const maxBytes = 256 * 1024;
    let fatal = false;
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
    const nativeFetch = window.fetch;
    window.fetch = function (...args) {
      const nativePromise = Reflect.apply(nativeFetch, this, args);
      const scope = scopeOf(args[0], args[1]);
      if (!scope) return nativePromise;
      if (records.has(scope.id) || records.size >= 16) { fatal = true; return nativePromise; }
      const record = { profile: scope.profile };
      records.set(scope.id, record);
      record.reply = nativePromise.then(async (response) => {
        const metadata = { status: response.status, etag: response.headers.get('etag') };
        if (!scope.statuses.includes(metadata.status)) {
          records.delete(scope.id);
          return { error: 'STATUS_REJECTED' };
        }
        let reader;
        try {
          const clone = response.clone();
          if (!clone.body) return { error: 'BODY_MISSING' };
          reader = clone.body.getReader();
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
          // Only the observer tee branch is cancelled; never await it or touch
          // the application's original response or abort signal.
          if (reader) { void reader.cancel().catch(() => {}); reader.releaseLock(); }
        }
      }, () => ({ error: 'FETCH_FAILED' }));
      return nativePromise;
    };
    Object.defineProperty(window, slot, { value: {
      origin, register, profile: (name) => enabled.get(name),
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
