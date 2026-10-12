// Actual Chrome -> cookie-authenticated BFF -> API -> PostgreSQL events.
// The only event producer is one real CSRF-protected diagnoses POST. The
// parent claims/completes it through sandbox_worker and changes events:read.
// No HTTP route replacement, invented frame/event or browser bearer exists.
import assert from 'node:assert/strict';

export async function eventsConsole(page, config, coordinate) {
  const step = (name) => process.stderr.write(`EVENTS_LIVE_STEP ${name}\n`);
  const origin = new URL(config.origin).origin;
  const streamPath = '/v1/events/stream';
  const requests = [];
  const track = (request) => {
    const url = new URL(request.url());
    if (url.origin !== origin || url.pathname !== streamPath) return;
    const headers = request.headers();
    requests.push({
      method: request.method(),
      tenant: headers['x-tenant-id'],
      project: url.searchParams.get('project_id'),
      instance: url.searchParams.get('instance_id'),
      replay: url.searchParams.get('replay') ?? 'latest',
      cursor: headers['last-event-id'] ?? null,
      bearer: Boolean(headers.authorization),
      urlCredential: url.username !== '' || url.password !== ''
        || [...url.searchParams.keys()].some((key) => /token|secret|authorization|password/i.test(key)),
    });
  };
  const streamResponse = () => page.waitForResponse((reply) => {
    const url = new URL(reply.url());
    return url.origin === origin && url.pathname === streamPath
      && reply.request().method() === 'GET';
  });
  const panel = page.getByTestId('event-stream-panel');
  const state = async (value) => page.waitForFunction((state) =>
    document.querySelector('[data-testid="event-stream-panel"]')?.getAttribute('data-state') === state, value);
  const rows = () => panel.getByRole('table', { name: '最近实时事件', exact: true }).locator('tbody tr');
  const eventRow = (type, aggregate) => rows().filter({ hasText: type }).filter({ hasText: aggregate });
  const cursor = async () => {
    const value = await panel.getAttribute('data-cursor');
    assert.equal(typeof value, 'string');
    assert.match(value, /^[A-Za-z0-9_-]{1,32}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    assert(value.length <= 2048);
    return value;
  };
  const checkRequest = (request) => {
    assert.equal(request.method, 'GET');
    assert.equal(request.tenant, config.tenant);
    assert.equal(request.project, config.project);
    assert(request.instance === null || request.instance === config.instance);
    assert.equal(request.bearer, false);
    assert.equal(request.urlCredential, false);
  };
  page.on('request', track);
  try {
    step('OPEN_LIVE_CHECKPOINT');
    await page.getByRole('button', { name: '操作 / 事件 / 审计', exact: true }).click();
    await page.getByRole('combobox', { name: '记录类型', exact: true }).selectOption('events');
    await panel.getByRole('heading', { name: '实时事件提示', exact: true }).waitFor();
    assert.equal(requests.length, 0, 'event subscriptions require explicit user activation');
    const opening = streamResponse();
    await panel.getByRole('button', { name: '开启实时提示', exact: true }).click();
    const opened = await opening;
    assert.equal(opened.status(), 200);
    assert.equal(opened.headers()['content-type']?.split(';')[0].trim(), 'text/event-stream');
    await state('LIVE');
    await panel.getByText('基线已确认', { exact: true }).waitFor();
    const baseline = await cursor();
    assert.equal(requests.length, 1);
    checkRequest(requests[0]);
    assert.equal(requests[0].cursor, null);
    assert.equal(requests[0].replay, 'latest');

    step('ACTUAL_CSRF_EVENT_PRODUCER');
    const produced = await page.evaluate(async ({ tenant, project, instance }) => {
      const sessionResponse = await fetch('/auth/session', { cache: 'no-store' });
      if (sessionResponse.status !== 200) return { status: sessionResponse.status, code: 'SESSION_UNAVAILABLE' };
      const session = await sessionResponse.json();
      if (session.tenant_id !== tenant || typeof session.csrf_token !== 'string') {
        return { status: 0, code: 'SESSION_SCOPE_MISMATCH' };
      }
      const key = crypto.randomUUID();
      const response = await fetch(`/v1/instances/${instance}/diagnoses`, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        headers: { 'X-Tenant-ID': tenant, 'X-CSRF-Token': session.csrf_token,
          'Idempotency-Key': key, 'Content-Type': 'application/json' },
        body: JSON.stringify({ include_operations: false, include_executions: false }),
      });
      const body = await response.json();
      // Only resource/operation correlation IDs leave this private page call.
      return { status: response.status, key, id: body.resource?.id,
        operation: body.operation?.id, state: body.resource?.status,
        tenant: body.resource?.tenant_id, project: body.resource?.project_id,
        instance: body.resource?.instance_id, boundOperation: body.resource?.operation_id,
        requestedProject: project };
    }, { tenant: config.tenant, project: config.project, instance: config.instance });
    assert.equal(produced.status, 202, 'the normal API must actually accept the event producer');
    for (const value of [produced.key, produced.id, produced.operation]) assert.match(value, /^[0-9a-f-]{36}$/);
    assert.equal(produced.state, 'PENDING');
    assert.equal(produced.tenant, config.tenant);
    assert.equal(produced.project, config.project);
    assert.equal(produced.instance, config.instance);
    assert.equal(produced.boundOperation, produced.operation);
    await eventRow('diagnoses.accepted', produced.id).waitFor();
    assert.equal(await eventRow('diagnoses.accepted', produced.id).count(), 1);
    assert((await eventRow('diagnoses.accepted', produced.id).innerText()).includes(produced.operation));
    await page.waitForFunction((baseline) => {
      const value = document.querySelector('[data-testid="event-stream-panel"]')?.getAttribute('data-cursor');
      return Boolean(value && value !== baseline);
    }, baseline);
    const acknowledged = await cursor();

    step('STOP_RETAINS_ORIGINAL_CURSOR');
    await panel.getByRole('button', { name: '停止实时提示', exact: true }).click();
    await state('STOPPED');
    assert.equal(await cursor(), acknowledged);
    assert.equal(requests.length, 1);
    const journalHasProducer = await page.evaluate((key) =>
      JSON.parse(localStorage.getItem('sandbox.console.intents.v1') ?? '[]').some((entry) => entry.key === key), produced.key);
    assert.equal(journalHasProducer, false, 'this direct HTTP producer does not claim UI journal coverage');
    await coordinate('events_accepted_stopped', 'events_diagnosis_complete');
    assert.equal(requests.length, 1, 'normal worker completion while stopped cannot silently reconnect');
    assert.equal(await cursor(), acknowledged);
    assert.equal(await eventRow('diagnoses.completed', produced.id).count(), 0);

    step('RECONNECT_EXACT_LAST_EVENT_ID');
    const reopening = streamResponse();
    await panel.getByRole('button', { name: '从原断点重连', exact: true }).click();
    assert.equal((await reopening).status(), 200);
    await state('LIVE');
    await eventRow('diagnoses.completed', produced.id).waitFor();
    assert.equal(requests.length, 2);
    requests.forEach(checkRequest);
    assert.equal(requests[1].cursor, acknowledged);
    assert.equal(await eventRow('diagnoses.accepted', produced.id).count(), 1);
    assert.equal(await eventRow('diagnoses.completed', produced.id).count(), 1);
    assert((await eventRow('diagnoses.completed', produced.id).innerText()).includes(produced.operation));
    assert((await rows().count()) <= 50);
    await page.waitForFunction((acknowledged) => {
      const value = document.querySelector('[data-testid="event-stream-panel"]')?.getAttribute('data-cursor');
      return Boolean(value && value !== acknowledged);
    }, acknowledged);
    const completedCursor = await cursor();
    assert.notEqual(completedCursor, acknowledged);
    await coordinate('events_completed_received', 'events_read_revoked');

    step('LIVE_GRANT_REVOCATION_CLEARS_EVENTS');
    await state('DENIED');
    await panel.getByRole('alert').filter({ hasText: 'RESOURCE_NOT_FOUND' }).waitFor();
    assert.equal((await panel.getAttribute('data-cursor')) ?? '', '');
    assert.equal(await rows().count(), 0);
    assert.equal(await eventRow('diagnoses.accepted', produced.id).count(), 0);
    assert.equal(await eventRow('diagnoses.completed', produced.id).count(), 0);
    const denied = await page.evaluate(async ({ tenant, project }) => {
      const response = await fetch(`/v1/events?project_id=${project}&limit=1`, {
        headers: { 'X-Tenant-ID': tenant }, cache: 'no-store',
      });
      return { status: response.status, code: (await response.json()).code };
    }, { tenant: config.tenant, project: config.project });
    assert.equal(denied.status, 404);
    assert.equal(denied.code, 'RESOURCE_NOT_FOUND');
    const streamCountBeforeRestore = requests.length;
    await coordinate('events_read_denied', 'events_read_restored');
    assert.equal(requests.length, streamCountBeforeRestore, 'grant restoration alone never starts a stream');
    assert.equal((await panel.getAttribute('data-cursor')) ?? '', '');
    assert.equal(await rows().count(), 0);

    step('EXPLICIT_NEW_BASELINE_ONLY');
    const rebuilt = streamResponse();
    await panel.getByRole('button', { name: '重建实时基线', exact: true }).click();
    assert.equal((await rebuilt).status(), 200);
    await state('LIVE');
    await panel.getByText('基线已确认', { exact: true }).waitFor();
    await cursor();
    assert.equal(requests.length, streamCountBeforeRestore + 1);
    checkRequest(requests.at(-1));
    assert.equal(requests.at(-1).cursor, null);
    assert.equal(requests.at(-1).replay, 'latest');
    assert.equal(await eventRow('diagnoses.accepted', produced.id).count(), 0);
    assert.equal(await eventRow('diagnoses.completed', produced.id).count(), 0);
    await panel.getByRole('button', { name: '停止实时提示', exact: true }).click();
    await state('STOPPED');
    const storedCursor = await page.evaluate((values) =>
      [...Object.entries(localStorage), ...Object.entries(sessionStorage)].some((entry) =>
        values.some((value) => entry[1].includes(value))), [baseline, acknowledged, completedCursor]);
    assert.equal(storedCursor, false, 'stream cursors remain component memory, not browser storage');
    await coordinate('events_complete', 'events_checked');
    step('VERIFIED');
  } finally {
    page.off('request', track);
  }
}
