// Actual Chrome -> cookie BFF -> formal automation API -> PostgreSQL.
// A real committed creation reply is dropped once. Every policy mutation uses
// the normal UI/journal except the two explicit CSRF/stale-ETag negative probes.
// The future ONCE trigger is never dispatched and no response body is mocked.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mutationResponseJson } from './mutation-response-observer.mjs';

export async function automationsConsole(page, config, coordinate) {
  const step = (name) => process.stderr.write(`AUTOMATIONS_LIVE_STEP ${name}\n`);
  const origin = new URL(config.origin).origin;
  const createPath = `/v1/instances/${config.instance}/automations`;
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
  let creates = 0;
  let changes = 0;
  let operationReads = 0;
  let bearer = false;
  const track = (request) => {
    const url = new URL(request.url());
    if (url.origin !== origin) return;
    if (request.headers().authorization) bearer = true;
    if (request.method() === 'POST' && url.pathname === createPath) creates++;
    if (request.method() === 'POST' && /^\/v1\/automations\/[0-9a-f-]+\/actions\//.test(url.pathname)) changes++;
    if (request.method() === 'GET' && /^\/v1\/operations\//.test(url.pathname)) operationReads++;
  };
  const panel = page.getByTestId('automation-panel');
  const detail = () => page.getByTestId('automation-detail');
  const confirm = async (button) => {
    await button.click();
    const dialog = page.getByRole('dialog');
    await dialog.getByRole('textbox').fill(config.instance);
    await dialog.getByRole('button', { name: '确认提交', exact: true }).click();
  };
  const state = async (id, status, version) => page.waitForFunction(({ id, status, version }) => {
    const value = document.querySelector('[data-testid="automation-detail"]');
    return value?.getAttribute('data-automation-id') === id
      && value.getAttribute('data-status') === status
      && value.getAttribute('data-version') === String(version);
  }, { id, status, version });
  const publicMetadata = (value) => {
    for (const forbidden of ['action', 'request', 'original_request', 'operation_request', 'command', 'env', 'identity_subject', 'identity_issuer']) {
      assert.equal(Object.hasOwn(value, forbidden), false, 'automation public metadata must not expose private workload/identity data');
    }
  };
  page.on('request', track);
  try {
    step('NORMAL_CAPABILITY_AND_EMPTY_BASELINE');
    const capabilities = await read(`/v1/capabilities?project_id=${config.project}`);
    assert.equal(capabilities.status, 200);
    assert.equal(capabilities.body.api_features.scheduled_tasks, true);
    assert.equal(capabilities.body.api_features.event_automation, true);
    assert.equal(capabilities.body.api_features.automation_notifications, true);
    assert.equal(capabilities.body.automation.schema_version, 1);
    assert.equal(capabilities.body.automation.assurance, 'API_CONTRACT_ONLY');
    assert.equal(capabilities.body.automation.time_zone, 'UTC');
    assert.deepEqual(capabilities.body.automation.supported_actions, ['START', 'STOP', 'RESTART', 'DELETE', 'RENEW', 'EXECUTE', 'BACKUP']);
    assert.deepEqual(capabilities.body.automation.supported_triggers, ['ONCE', 'CRON_UTC', 'EVENT']);
    assert.equal(capabilities.body.runtime_certification, 'NOT_ASSERTED');
    step('REAL_COOKIE_INBOX_BASELINE');
    await page.getByRole('button', { name: '自动化通知', exact: true }).click();
    await page.getByRole('table', { name: '自动化异常通知列表', exact: true }).waitFor();
    const notices = await read(`/v1/automation-notifications?project_id=${config.project}&limit=20`);
    assert.equal(notices.status, 200);
    assert.deepEqual(Object.keys(notices.body).sort(), ['cutoff', 'items', 'next_cursor']);
    assert.deepEqual(notices.body.items, []);
    assert.equal(notices.body.next_cursor, null);
    assert.ok(Number.isFinite(Date.parse(notices.body.cutoff)));
    await page.getByRole('table', { name: '自动化异常通知列表', exact: true }).getByRole('row').first().waitFor();
    await page.getByRole('button', { name: '实例', exact: true }).click();
    await page.getByRole('button', { name: config.name, exact: true }).click();
    await page.getByRole('tab', { name: '定时与自动化', exact: true }).click();
    await panel.waitFor();
    await coordinate('automations_ready', 'automations_start');

    step('FUTURE_ONCE_EXPLICIT_DELEGATION');
    const at = new Date(Date.now() + 30 * 60 * 1000).toISOString();
    const expires = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    const form = page.getByTestId('automation-create');
    for (const [label, key] of [['运行次数上限', 'run_budget'], ['最小间隔（秒）', 'minimum_interval_seconds'], ['允许延迟（秒）', 'grace_seconds']]) {
      const input = form.getByLabel(label, { exact: true });
      assert.equal(await input.getAttribute('min'), String(capabilities.body.automation.limits[key].minimum));
      assert.equal(await input.getAttribute('max'), String(capabilities.body.automation.limits[key].maximum));
    }
    await form.getByLabel('策略名称', { exact: true }).fill('Live bounded future RENEW');
    await form.getByLabel('未来动作', { exact: true }).selectOption('RENEW');
    await form.getByLabel('触发方式', { exact: true }).selectOption('ONCE');
    await form.getByLabel('单次执行时间（UTC）', { exact: true }).fill(at);
    await form.getByLabel('委派到期时间（UTC）', { exact: true }).fill(expires);
    await form.getByLabel('运行次数上限', { exact: true }).fill('1');
    await form.getByLabel('最小间隔（秒）', { exact: true }).fill('60');
    await form.getByLabel('允许延迟（秒）', { exact: true }).fill('300');
    await form.getByLabel('计算租期（秒）', { exact: true }).fill('3600');
    await form.getByLabel('我明确授权在期限内按规则提交所选动作', { exact: true }).check();
    await form.getByRole('button', { name: '预览自动化授权', exact: true }).click();
    assert.equal(creates, 0, 'preview is local and cannot submit a policy');
    let original;
    let actual;
    await page.route(origin + createPath, async (route) => {
      if (route.request().method() !== 'POST') return route.continue();
      const request = route.request();
      original = { key: request.headers()['idempotency-key'], body: request.postData(), etag: request.headers()['if-match'] };
      assert.match(original.key, /^[0-9a-f-]{36}$/);
      assert.match(original.etag, /^"[1-9][0-9]*"$/);
      assert(request.headers()['x-csrf-token']);
      assert.deepEqual(JSON.parse(original.body), {
        name: 'Live bounded future RENEW', action: { kind: 'RENEW', ttl_seconds: 3600 },
        trigger: { kind: 'ONCE', at }, delegation_expires_at: expires,
        run_budget: 1, minimum_interval_seconds: 60, grace_seconds: 300,
      });
      const reply = await route.fetch({ maxRedirects: 0 });
      assert.equal(reply.status(), 201, 'the formal API actually commits before the only reply fault');
      step('CREATION_FAULT_COMMITTED_API_BODY_READ');
      actual = await reply.json();
      step('CREATION_FAULT_COMMITTED_API_BODY_READ_COMPLETE');
      assert.equal(reply.headers().etag, '"1"');
      assert.equal(actual.resource.status, 'ACTIVE');
      assert.equal(actual.resource.version, 1);
      assert.equal(actual.resource.tenant_id, config.tenant);
      assert.equal(actual.resource.project_id, config.project);
      assert.equal(actual.resource.instance_id, config.instance);
      assert.equal(actual.resource.action_kind, 'RENEW');
      assert.equal(actual.resource.trigger_kind, 'ONCE');
      assert.equal(actual.resource.emitted_runs, 0);
      assert.equal(Object.hasOwn(actual, 'operation'), false);
      publicMetadata(actual.resource);
      await route.abort('failed');
    }, { times: 1 });
    step('COMMITTED_CREATION_ACK_LOSS');
    await confirm(page.getByTestId('automation-consent').getByRole('button', { name: '创建自动化策略', exact: true }));
    await page.getByRole('alert').filter({ hasText: /NETWORK_FAILURE|REQUEST_INTERRUPTED/ }).first().waitFor();
    assert(original && actual);
    assert.equal(creates, 1);
    const journal = () => page.evaluate((key) =>
      JSON.parse(localStorage.getItem('sandbox.console.intents.v1') ?? '[]').find((row) => row.key === key), original.key);
    const unknown = await journal();
    assert.equal(unknown.state, 'UNKNOWN');
    assert.equal(unknown.path, createPath);
    assert.equal(unknown.etag, original.etag);
    assert.equal(unknown.body, null, 'sensitive automation bodies never enter persisted storage');
    assert.equal(unknown.bodySha256, createHash('sha256').update(original.body).digest('hex'));

    step('RELOAD_RECOVER_AND_ORIGINAL_KEY_REPLAY');
    await page.reload();
    await page.getByLabel('项目 ID', { exact: true }).fill(config.project);
    await page.getByRole('button', { name: '进入项目', exact: true }).click();
    await page.getByRole('button', { name: '请求记录', exact: true }).click();
    const row = page.getByRole('row').filter({ hasText: original.key });
    await row.getByLabel('完全相同的原自动化创建 JSON', { exact: true }).fill(original.body);
    await row.getByRole('button', { name: '恢复原请求参数', exact: true }).click();
    assert.equal(creates, 1, 'rehydration only restores the exact body in memory');
    await row.getByRole('button', { name: '显式重试原请求', exact: true }).click();
    const retryDialog = page.getByRole('dialog');
    await retryDialog.getByRole('textbox').fill(original.key);
    const retried = page.waitForResponse((reply) => match(reply, 'POST', createPath));
    await retryDialog.getByRole('button', { name: '确认提交', exact: true }).click();
    const replay = await retried;
    assert.equal(replay.status(), 201);
    assert.equal(replay.request().headers()['idempotency-key'], original.key);
    assert.equal(replay.request().headers()['if-match'], original.etag);
    assert.equal(replay.request().postData(), original.body);
    assert(replay.request().headers()['x-csrf-token']);
    step('CREATION_REPLAY_RECEIPT_BODY_READ');
    const accepted = await mutationResponseJson(page, replay, 'AUTOMATION');
    step('CREATION_REPLAY_RECEIPT_BODY_READ_COMPLETE');
    assert.deepEqual(accepted, actual);
    await row.getByRole('button', { name: '打开自动化策略', exact: true }).waitFor();
    const stored = await journal();
    assert.equal(stored.state, 'ACCEPTED');
    assert.equal(stored.body, null);
    assert.equal(stored.operationId, null);
    assert.equal(stored.resourceId, actual.resource.id);
    assert.equal(creates, 2);
    await coordinate('automations_replayed', 'automation_operation_read_revoked');

    step('POLICY_AND_RUNS_WITHOUT_OPERATION_READ');
    const policyPath = `/v1/automations/${actual.resource.id}`;
    const runsPath = policyPath + '/runs';
    const opening = page.waitForResponse((reply) => match(reply, 'GET', policyPath));
    await row.getByRole('button', { name: '打开自动化策略', exact: true }).click();
    const opened = await opening;
    assert.equal(opened.status(), 200);
    assert.equal(opened.headers().etag, '"1"');
    step('POLICY_GET_BODY_READ');
    assert.deepEqual(await opened.json(), actual.resource);
    step('POLICY_GET_BODY_READ_COMPLETE');
    await state(actual.resource.id, 'ACTIVE', 1);
    const runs = page.waitForResponse((reply) => match(reply, 'GET', runsPath));
    await panel.getByRole('button', { name: '刷新运行历史', exact: true }).click();
    const history = await runs;
    assert.equal(history.status(), 200);
    assert.equal(new URL(history.url()).searchParams.get('project_id'), config.project);
    step('RUN_HISTORY_GET_BODY_READ');
    const historyBody = await history.json();
    step('RUN_HISTORY_GET_BODY_READ_COMPLETE');
    assert.deepEqual(historyBody.items, []);
    assert.equal(historyBody.next_cursor, null);
    assert.equal(await panel.getByRole('table', { name: '自动化运行历史', exact: true }).locator('tbody tr').count(), 0);
    assert.equal(operationReads, 0, 'policy/run UI never requests operations evidence');

    const action = async (name, suffix, expectedStatus, version) => {
      const reply = page.waitForResponse((value) => match(value, 'POST', policyPath + '/actions/' + suffix));
      await confirm(detail().getByRole('button', { name, exact: true }));
      const result = await reply;
      assert.equal(result.status(), 200);
      assert.equal(result.headers().etag, `"${version}"`);
      assert.equal(result.request().headers()['if-match'], `"${version - 1}"`);
      assert(result.request().headers()['x-csrf-token']);
      assert.deepEqual(JSON.parse(result.request().postData()), {});
      step('ACTION_RECEIPT_BODY_READ');
      const body = await mutationResponseJson(page, result, 'AUTOMATION');
      step('ACTION_RECEIPT_BODY_READ_COMPLETE');
      assert.equal(body.resource.id, actual.resource.id);
      assert.equal(body.resource.status, expectedStatus);
      assert.equal(body.resource.version, version);
      publicMetadata(body.resource);
      await state(actual.resource.id, expectedStatus, version);
    };
    step('PAUSE_FRESH_ETAG');
    await action('暂停策略', 'pause', 'PAUSED', 2);
    step('ACTUAL_CSRF_AND_STALE_ETAG_REJECTIONS');
    const negative = await page.evaluate(async ({ path, tenant }) => {
      const session = await (await fetch('/auth/session')).json();
      const request = async (csrf, etag) => {
        const headers = { 'X-Tenant-ID': tenant, 'Content-Type': 'application/json',
          'Idempotency-Key': crypto.randomUUID(), 'If-Match': etag };
        if (csrf) headers['X-CSRF-Token'] = session.csrf_token;
        const reply = await fetch(path, { method: 'POST', headers, body: '{}', redirect: 'error' });
        return { status: reply.status, code: (await reply.json()).code };
      };
      return { csrf: await request(false, '"2"'), stale: await request(true, '"1"') };
    }, { path: policyPath + '/actions/resume', tenant: config.tenant });
    assert.deepEqual(negative.csrf, { status: 403, code: 'PERMISSION_DENIED' });
    assert.deepEqual(negative.stale, { status: 412, code: 'VERSION_MISMATCH' });
    await state(actual.resource.id, 'PAUSED', 2);
    step('RESUME_AND_PERMANENT_REVOKE');
    step('RESUME_FRESH_ETAG');
    await action('恢复策略', 'resume', 'ACTIVE', 3);
    step('PERMANENT_REVOKE_FRESH_ETAG');
    await action('永久撤销策略', 'revoke', 'REVOKED', 4);
    assert.equal(creates, 2);
    assert.equal(changes, 5, 'only three accepted UI transitions and two explicit rejection probes');
    assert.equal(operationReads, 0);
    await coordinate('automations_changed', 'automation_read_revoked');

    step('REAL_READ_REVOCATION_CLEARS_POLICY_AND_RUNS');
    const denial = page.waitForResponse((reply) => match(reply, 'GET', policyPath));
    await panel.getByRole('button', { name: '重新读取策略', exact: true }).click();
    const denied = await denial;
    assert.equal(denied.status(), 404);
    step('POLICY_DENIED_GET_BODY_READ');
    assert.equal((await denied.json()).code, 'RESOURCE_NOT_FOUND');
    step('POLICY_DENIED_GET_BODY_READ_COMPLETE');
    await panel.getByRole('alert').filter({ hasText: 'RESOURCE_NOT_FOUND' }).first().waitFor();
    assert.equal(await detail().count(), 0);
    assert.equal(await panel.getByRole('table', { name: '自动化运行历史', exact: true }).count(), 0);
    const deniedRuns = await read(runsPath + `?project_id=${config.project}`);
    assert.equal(deniedRuns.status, 404);
    assert.equal(deniedRuns.body.code, 'RESOURCE_NOT_FOUND');
    await coordinate('automation_read_denied', 'automations_permissions_restored');

    step('EXPLICIT_READ_RESTORED_WITHOUT_NEW_POLICY');
    const rereading = page.waitForResponse((reply) => match(reply, 'GET', policyPath));
    await panel.getByRole('button', { name: '重新读取策略', exact: true }).click();
    const restored = await rereading;
    assert.equal(restored.status(), 200);
    assert.equal(restored.headers().etag, '"4"');
    step('POLICY_RESTORED_GET_BODY_READ');
    const restoredPolicy = await restored.json();
    step('POLICY_RESTORED_GET_BODY_READ_COMPLETE');
    assert.equal(restoredPolicy.id, actual.resource.id);
    assert.equal(restoredPolicy.status, 'REVOKED');
    assert.equal(restoredPolicy.emitted_runs, 0);
    publicMetadata(restoredPolicy);
    await state(actual.resource.id, 'REVOKED', 4);
    assert.equal(creates, 2);
    assert.equal(changes, 5);
    assert.equal(operationReads, 0);
    assert.equal(bearer, false);
    const storage = await page.evaluate(() => JSON.stringify({
      local: Object.entries(localStorage), session: Object.entries(sessionStorage), cookies: document.cookie,
    }));
    assert(!/access_token|refresh_token|eyJ[a-zA-Z0-9_-]+\./.test(storage));
    assert(!storage.includes(original.body));
    const finalJournal = await journal();
    assert.equal(finalJournal.body, null);
    assert.equal(finalJournal.state, 'ACCEPTED');
    await coordinate('automations_complete', 'automations_checked');
    step('VERIFIED');
  } finally {
    page.off('request', track);
  }
}
