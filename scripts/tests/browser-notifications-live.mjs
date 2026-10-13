// Actual Chrome -> cookie BFF -> formal notification API -> PostgreSQL.
// Rust produces a real FAILED run and changes live grants between phases. The
// only transport fault drops one reply after route.fetch commits the real ACK.
// No business response, identity, source event or notification is mocked.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mutationResponseJson, observeReadResponse } from './mutation-response-observer.mjs';

export async function notificationsConsole(page, config, coordinate) {
  const step = (name) => process.stderr.write(`NOTIFICATIONS_LIVE_STEP ${name}\n`);
  const origin = new URL(config.origin).origin;
  const source = await coordinate('notifications_ready', 'notifications_start');
  assert.match(source.notice_id, /^[0-9a-f-]{36}$/);
  assert.match(source.run_id, /^[0-9a-f-]{36}$/);
  assert.match(source.automation_id, /^[0-9a-f-]{36}$/);
  assert.equal(source.source_status, 'FAILED');
  assert(Number.isSafeInteger(source.source_run_version));
  const listPath = '/v1/automation-notifications';
  const detailPath = `${listPath}/${source.notice_id}`;
  const ackPath = detailPath + '/actions/acknowledge';
  const panel = () => page.getByTestId('automation-inbox');
  const detail = () => page.getByTestId('automation-notification-detail');
  const match = (reply, method, path) => {
    const url = new URL(reply.url());
    return url.origin === origin && url.pathname === path && reply.request().method() === method;
  };
  const read = async (path) => {
    step('NATIVE_GET_BODY_READ');
    const result = await page.evaluate(async ({ path, tenant }) => {
      const reply = await fetch(path, { headers: { 'X-Tenant-ID': tenant }, cache: 'no-store' });
      return { status: reply.status, etag: reply.headers.get('etag'), body: await reply.json() };
    }, { path, tenant: config.tenant });
    step('NATIVE_GET_BODY_READ_COMPLETE');
    return result;
  };
  const sourceFields = ['id', 'tenant_id', 'project_id', 'instance_id', 'automation_id',
    'run_id', 'source_event_id', 'source_run_version', 'source_status', 'created_at'];
  const checkSource = (resource, reference) => {
    assert.deepEqual(Object.keys(resource).sort(), [...sourceFields,
      'acknowledged_at', 'acknowledged_by', 'version'].sort());
    assert.equal(resource.id, source.notice_id);
    assert.equal(resource.tenant_id, config.tenant);
    assert.equal(resource.project_id, config.project);
    assert.equal(resource.instance_id, config.instance);
    assert.equal(resource.automation_id, source.automation_id);
    assert.equal(resource.run_id, source.run_id);
    assert.equal(resource.source_status, source.source_status);
    assert.equal(resource.source_run_version, source.source_run_version);
    assert.match(resource.source_event_id, /^[0-9a-f-]{36}$/);
    assert(Number.isFinite(Date.parse(resource.created_at)));
    if (reference) for (const field of sourceFields) assert.deepEqual(resource[field], reference[field]);
  };
  const attempts = [];
  let bearer = false;
  let workloadMutations = 0;
  let operationReads = 0;
  const track = (request) => {
    const url = new URL(request.url());
    if (url.origin !== origin) return;
    if (request.headers().authorization) bearer = true;
    if (url.pathname === ackPath && request.method() === 'POST') attempts.push({
      key: request.headers()['idempotency-key'], etag: request.headers()['if-match'],
      body: request.postData(),
    });
    if (request.method() === 'GET' && /^\/v1\/operations\//.test(url.pathname)) operationReads++;
    if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method()) &&
      /^\/v1\/(instances|automations|executions|file-transfers|backups)(\/|$)/.test(url.pathname)) {
      workloadMutations++;
    }
  };
  const openInbox = async () => {
    await page.getByRole('button', { name: '自动化通知', exact: true }).click();
    await page.getByRole('table', { name: '自动化异常通知列表', exact: true }).waitFor();
  };
  const openNotice = async () => {
    const { response: reply, body: resource } = await observeReadResponse(page, origin, detailPath, config.tenant,
      () => panel().getByRole('button', { name: `查看通知 ${source.notice_id}`, exact: true }).click());
    assert.equal(reply.status(), 200);
    step('DETAIL_GET_BODY_READ');
    step('DETAIL_GET_BODY_READ_COMPLETE');
    checkSource(resource);
    assert.equal(reply.headers().etag, `"${resource.version}"`);
    await page.waitForFunction(({ id, version }) => {
      const element = document.querySelector('[data-testid="automation-notification-detail"]');
      return element?.getAttribute('data-notification-id') === id
        && element.getAttribute('data-version') === String(version);
    }, { id: source.notice_id, version: resource.version });
    return resource;
  };
  let original;
  let committed;
  const journal = async () => page.evaluate((key) =>
    JSON.parse(localStorage.getItem('sandbox.console.intents.v1') ?? '[]').find((row) => row.key === key), original.key);
  const assertUnknown = async () => {
    const saved = await journal();
    assert.equal(saved.state, 'UNKNOWN');
    assert.equal(saved.path, ackPath);
    assert.equal(saved.method, 'POST');
    assert.equal(saved.etag, original.etag);
    assert.deepEqual(saved.body, {});
    assert.equal(saved.operationId, null);
    assert.equal(saved.resourceId, null);
  };
  const retry = async () => {
    const row = page.getByRole('row').filter({ hasText: original.key });
    await row.getByRole('button', { name: '显式重试原请求', exact: true }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByRole('textbox').fill(original.key);
    await dialog.getByRole('button', { name: '确认提交', exact: true }).click();
  };
  page.on('request', track);
  try {
    step('REAL_WORKER_FAILURE_LIST_AND_DETAIL');
    await openInbox();
    const listing = await read(`${listPath}?project_id=${config.project}&limit=20`);
    assert.equal(listing.status, 200);
    assert.deepEqual(Object.keys(listing.body).sort(), ['cutoff', 'items', 'next_cursor']);
    assert.equal(listing.body.items.length, 1);
    assert.equal(listing.body.next_cursor, null);
    assert(Number.isFinite(Date.parse(listing.body.cutoff)));
    checkSource(listing.body.items[0]);
    const before = await openNotice();
    assert.equal(before.version, 1);
    assert.equal(before.acknowledged_at, null);
    assert.equal(before.acknowledged_by, null);

    step('ACTUAL_COOKIE_CSRF_ORIGIN_AND_SHAPE_REJECTIONS');
    const negative = await page.evaluate(async ({ ackPath, detailPath, tenant }) => {
      const session = await (await fetch('/auth/session')).json();
      const send = async (kind) => {
        const headers = { 'X-Tenant-ID': tenant, 'Content-Type': 'application/json',
          'Idempotency-Key': crypto.randomUUID(), 'If-Match': '"1"' };
        if (kind !== 'csrf') headers['X-CSRF-Token'] = session.csrf_token;
        if (kind === 'precondition') delete headers['If-Match'];
        const reply = await fetch(ackPath, { method: 'POST', headers,
          body: kind === 'shape' ? '{"retry":true}' : '{}', redirect: 'error' });
        return { status: reply.status, code: (await reply.json()).code };
      };
      const anonymous = await fetch(detailPath, { credentials: 'omit', headers: { 'X-Tenant-ID': tenant } });
      return { anonymous: { status: anonymous.status, code: (await anonymous.json()).code },
        csrf: await send('csrf'), precondition: await send('precondition'), shape: await send('shape') };
    }, { ackPath, detailPath, tenant: config.tenant });
    assert.deepEqual(negative.anonymous, { status: 401, code: 'UNAUTHENTICATED' });
    assert.deepEqual(negative.csrf, { status: 403, code: 'PERMISSION_DENIED' });
    assert.deepEqual(negative.precondition, { status: 428, code: 'PRECONDITION_REQUIRED' });
    assert.equal(negative.shape.status, 400);
    const sessionReply = await page.context().request.get(origin + '/auth/session');
    assert.equal(sessionReply.status(), 200);
    const csrf = (await sessionReply.json()).csrf_token;
    assert.equal(typeof csrf, 'string');
    const originDenied = await page.context().request.post(origin + ackPath, {
      headers: { Origin: 'https://untrusted-origin.invalid', 'X-Tenant-ID': config.tenant,
        'X-CSRF-Token': csrf, 'Content-Type': 'application/json',
        'Idempotency-Key': randomUUID(), 'If-Match': '"1"' },
      data: '{}', maxRedirects: 0,
    });
    assert.equal(originDenied.status(), 403);
    step('ORIGIN_DENIED_API_BODY_READ');
    assert.equal((await originDenied.json()).code, 'PERMISSION_DENIED');
    step('ORIGIN_DENIED_API_BODY_READ_COMPLETE');
    const unchanged = await read(detailPath);
    assert.equal(unchanged.status, 200);
    assert.deepEqual(unchanged.body, before);

    step('ACTUAL_ACK_COMMIT_THEN_REPLY_LOSS');
    await page.route(origin + ackPath, async (route) => {
      if (route.request().method() !== 'POST') return route.continue();
      const request = route.request();
      original = { key: request.headers()['idempotency-key'],
        etag: request.headers()['if-match'], body: request.postData() };
      assert.match(original.key, /^[0-9a-f-]{36}$/);
      assert.equal(original.etag, '"1"');
      assert.equal(original.body, '{}');
      assert(request.headers()['x-csrf-token']);
      assert.equal(request.headers().authorization, undefined);
      const reply = await route.fetch({ maxRedirects: 0 });
      assert.equal(reply.status(), 200, 'normal ACK commits before its only reply fault');
      assert.equal(reply.headers().etag, '"2"');
      step('ACK_FAULT_COMMITTED_API_BODY_READ');
      committed = await reply.json();
      step('ACK_FAULT_COMMITTED_API_BODY_READ_COMPLETE');
      assert.deepEqual(Object.keys(committed).sort(), ['idempotency_expires_at', 'resource']);
      checkSource(committed.resource, before);
      assert.equal(committed.resource.version, 2);
      assert.match(committed.resource.acknowledged_by, /^[0-9a-f-]{36}$/);
      assert(Number.isFinite(Date.parse(committed.resource.acknowledged_at)));
      assert(Number.isFinite(Date.parse(committed.idempotency_expires_at)));
      step('ACK_REAL_COMMIT_200_V2');
      await route.abort('failed');
    }, { times: 1 });
    await panel().getByLabel('输入通知 ID 确认', { exact: true }).fill(source.notice_id);
    await panel().getByRole('button', { name: '确认通知已阅', exact: true }).click();
    await panel().getByRole('alert').filter({ hasText: /NETWORK_FAILURE|REQUEST_INTERRUPTED/ }).first().waitFor();
    step('ACK_TRANSPORT_ERROR_DISPLAYED');
    assert(original && committed);
    await assertUnknown();
    step('ACK_UNKNOWN_ORIGINAL_PERSISTED');
    assert.equal(attempts.filter((value) => value.key === original.key).length, 1);
    const readback = await read(detailPath);
    assert.equal(readback.status, 200);
    assert.equal(readback.etag, '"2"');
    assert.deepEqual(readback.body, committed.resource,
      'normal read sees the actual committed ACK while the original reply remains unknown');
    await page.waitForFunction((id) => {
      const element = document.querySelector('[data-testid="automation-notification-detail"]');
      return element?.getAttribute('data-notification-id') === id
        && element.getAttribute('data-version') === '2';
    }, source.notice_id);
    await panel().getByRole('status').filter({ hasText: '此通知已有未确认请求' }).waitFor();
    assert.equal(await panel().getByRole('button', { name: '确认通知已阅', exact: true }).count(), 0,
      'the current version is already acknowledged, so the console removes its ACK form');
    await assertUnknown();
    step('ACK_NORMAL_READBACK_V2_AND_NO_FORM');

    step('STALE_NEW_KEY_REJECTED_WITHOUT_JOURNAL_REPLACEMENT');
    const stale = await page.evaluate(async ({ path, tenant }) => {
      const session = await (await fetch('/auth/session')).json();
      const reply = await fetch(path, { method: 'POST', headers: {
        'X-Tenant-ID': tenant, 'X-CSRF-Token': session.csrf_token,
        'Content-Type': 'application/json', 'Idempotency-Key': crypto.randomUUID(), 'If-Match': '"1"',
      }, body: '{}', redirect: 'error' });
      return { status: reply.status, code: (await reply.json()).code };
    }, { path: ackPath, tenant: config.tenant });
    assert.deepEqual(stale, { status: 412, code: 'VERSION_MISMATCH' });
    await assertUnknown();
    await page.reload();
    await page.getByLabel('项目 ID', { exact: true }).fill(config.project);
    await page.getByRole('button', { name: '进入项目', exact: true }).click();
    await page.getByRole('button', { name: '请求记录', exact: true }).click();
    await assertUnknown();
    await coordinate('notifications_ack_lost', 'notification_write_revoked');

    step('CURRENT_WRITE_REVOCATION_DENIES_ORIGINAL_REPLAY');
    const deniedWrite = page.waitForResponse((reply) => match(reply, 'POST', ackPath));
    await retry();
    const writeReply = await deniedWrite;
    assert.equal(writeReply.status(), 404);
    step('DENIED_WRITE_BODY_READ');
    assert.equal((await mutationResponseJson(page, writeReply, 'NOTIFICATION')).code, 'RESOURCE_NOT_FOUND');
    step('DENIED_WRITE_BODY_READ_COMPLETE');
    assert.equal(writeReply.request().headers()['idempotency-key'], original.key);
    assert.equal(writeReply.request().headers()['if-match'], original.etag);
    assert.equal(writeReply.request().postData(), original.body);
    await page.getByRole('alert').filter({ hasText: 'RESOURCE_NOT_FOUND' }).first().waitFor();
    await assertUnknown();
    assert.equal(attempts.filter((value) => value.key === original.key).length, 2);
    await openInbox();
    const acknowledged = await openNotice();
    assert.deepEqual(acknowledged, committed.resource, 'write revocation still permits authorized historical reads');
    assert.equal(await panel().getByRole('button', { name: '确认通知已阅', exact: true }).count(), 0);
    await coordinate('notifications_write_denied', 'notification_read_revoked');

    step('CURRENT_READ_REVOCATION_CLEARS_LIST_AND_DETAIL');
    const { response: refreshDenial, body: refreshDeniedBody } = await observeReadResponse(page, origin,
      `${listPath}?project_id=${config.project}&limit=20`, config.tenant,
      () => panel().getByRole('button', { name: '刷新通知', exact: true }).click());
    assert.equal(refreshDenial.status(), 404);
    step('REFRESH_DENIED_GET_BODY_READ');
    assert.equal(refreshDeniedBody.code, 'RESOURCE_NOT_FOUND');
    step('REFRESH_DENIED_GET_BODY_READ_COMPLETE');
    await panel().getByRole('alert').filter({ hasText: 'RESOURCE_NOT_FOUND' }).first().waitFor();
    await page.waitForFunction(() => !document.querySelector('[data-testid="automation-notification-detail"]')
      && !document.querySelector('table[aria-label="自动化异常通知列表"]'));
    assert.equal(await detail().count(), 0);
    assert.equal(await panel().getByRole('table', { name: '自动化异常通知列表', exact: true }).count(), 0);
    const listDenied = await read(`${listPath}?project_id=${config.project}&limit=20`);
    assert.equal(listDenied.status, 404);
    assert.equal(listDenied.body.code, 'RESOURCE_NOT_FOUND');
    await page.getByRole('button', { name: '请求记录', exact: true }).click();
    const { response: readReply, body: readDeniedBody } = await observeReadResponse(page, origin, detailPath, config.tenant,
      retry);
    assert.equal(readReply.status(), 404);
    step('JOURNAL_DENIED_GET_BODY_READ');
    assert.equal(readDeniedBody.code, 'RESOURCE_NOT_FOUND');
    step('JOURNAL_DENIED_GET_BODY_READ_COMPLETE');
    await page.getByRole('alert').filter({ hasText: 'RESOURCE_NOT_FOUND' }).first().waitFor();
    await assertUnknown();
    assert.equal(attempts.filter((value) => value.key === original.key).length, 2,
      'revoked read stops the journal before another ACK request');
    await coordinate('notifications_read_denied', 'notifications_permissions_restored');

    step('RESTORED_AUTHORITY_REPLAYS_EXACT_ORIGINAL_ACK');
    const replaying = page.waitForResponse((reply) => match(reply, 'POST', ackPath));
    await retry();
    const replay = await replaying;
    assert.equal(replay.status(), 200);
    assert.equal(replay.headers().etag, '"2"');
    assert.equal(replay.request().headers()['idempotency-key'], original.key);
    assert.equal(replay.request().headers()['if-match'], original.etag);
    assert.equal(replay.request().postData(), original.body);
    assert(replay.request().headers()['x-csrf-token']);
    step('ACK_REPLAY_RECEIPT_BODY_READ');
    assert.deepEqual(await mutationResponseJson(page, replay, 'NOTIFICATION'), committed);
    step('ACK_REPLAY_RECEIPT_BODY_READ_COMPLETE');
    const row = page.getByRole('row').filter({ hasText: original.key });
    await row.getByText('ACCEPTED', { exact: true }).waitFor();
    const saved = await journal();
    assert.equal(saved.state, 'ACCEPTED');
    assert.equal(saved.body, null);
    assert.equal(saved.resourceId, source.notice_id);
    assert.equal(saved.operationId, null);
    assert.equal(saved.etag, original.etag);
    const originals = attempts.filter((value) => value.key === original.key);
    assert.equal(originals.length, 3);
    for (const value of originals) assert.deepEqual(value, original);
    const notificationJournal = await page.evaluate((path) =>
      JSON.parse(localStorage.getItem('sandbox.console.intents.v1') ?? '[]').filter((value) => value.path === path), ackPath);
    assert.equal(notificationJournal.length, 1, 'rejections and explicit replay never create a replacement intent');
    await openInbox();
    assert.deepEqual(await openNotice(), committed.resource);
    assert.equal(await panel().getByRole('button', { name: '确认通知已阅', exact: true }).count(), 0);
    assert.equal(operationReads, 0);
    assert.equal(workloadMutations, 0, 'reading/acknowledging historical notifications cannot redispatch a workload');
    assert.equal(bearer, false);
    const storage = await page.evaluate(() => JSON.stringify({
      local: Object.entries(localStorage), session: Object.entries(sessionStorage), cookies: document.cookie,
    }));
    assert(!/access_token|refresh_token|eyJ[a-zA-Z0-9_-]+\./.test(storage));
    await coordinate('notifications_complete', 'notifications_checked');
    step('VERIFIED');
  } finally {
    page.off('request', track);
  }
}
