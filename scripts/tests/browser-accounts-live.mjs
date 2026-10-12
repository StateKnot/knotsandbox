// Real UI/BFF/API requests only. One committed PATCH response is deliberately
// dropped; no response body, identity or database result is synthesized.
import assert from 'node:assert/strict';

export async function accountConsole(page, config, coordinate) {
  const step = (name) => process.stderr.write(`ACCOUNT_LIVE_STEP ${name}\n`);
  const statusSignal = (name, status) => {
    if (Number.isInteger(status) && status >= 100 && status <= 599) {
      process.stderr.write(`ACCOUNT_LIVE_HTTP_STATUS ${name} ${status}\n`);
    }
  };
  const origin = new URL(config.origin).origin;
  const match = (response, method, path) => {
    const url = new URL(response.url());
    return url.origin === origin && url.pathname === path && response.request().method() === method;
  };
  const api = async (path, method, body, headers = {}) => page.evaluate(async (input) => {
    const session = await (await fetch('/auth/session')).json();
    const response = await fetch(input.path, {
      method: input.method,
      headers: { 'X-Tenant-ID': session.tenant_id, 'X-CSRF-Token': session.csrf_token,
        ...(input.body === undefined ? {} : { 'Content-Type': 'application/json' }), ...input.headers },
      ...(input.body === undefined ? {} : { body: JSON.stringify(input.body) }),
    });
    return { status: response.status, body: await response.json(), etag: response.headers.get('etag') };
  }, { path, method, body, headers });

  step('NAVIGATE');
  await page.getByRole('button', { name: '账户与授权', exact: true }).click();
  step('NAVIGATION_CLICKED');
  await page.getByRole('heading', { name: '账户与项目授权', exact: true }).waitFor();
  step('ACCOUNT_HEADING_VISIBLE');
  await page.getByLabel('机器身份每页条数', { exact: true }).selectOption('1');
  step('CLIENT_LIMIT_SELECTED');
  const created = [];
  for (const client of config.accounts.clients) {
    step('REGISTER_FIELDS');
    const form = page.getByTestId('service-client-register');
    await form.getByLabel('OIDC签发方', { exact: true }).fill(config.accounts.issuer);
    await form.getByLabel('主体标识', { exact: true }).fill(client.subject);
    await form.getByLabel('OAuth客户端标识', { exact: true }).fill(client.client_id);
    await form.getByLabel('显示名称', { exact: true }).fill(client.display_name);
    const pending = page.waitForResponse((r) => match(r, 'POST', '/v1/service-clients'));
    await form.getByRole('button', { name: '登记机器身份', exact: true }).click();
    const response = await pending;
    assert.equal(response.status(), 201);
    const body = await response.json();
    assert.equal(body.resource.subject, client.subject);
    assert.equal(body.resource.issuer, config.accounts.issuer);
    assert.equal(response.headers().etag, '"1"');
    assert(response.request().headers()['x-csrf-token']);
    assert.match(response.request().headers()['idempotency-key'], /^[0-9a-f-]{36}$/);
    created.push(body.resource);
  }
  step('CLIENT_PAGINATION');
  step('CLIENT_PAGE_ONE_ROW_WAIT');
  await page.getByRole('button', { name: `查看机器身份 ${created[1].display_name}`, exact: true }).waitFor();
  step('CLIENT_PAGE_ONE_ROW_VISIBLE');
  step('CLIENT_PAGE_TWO_RESPONSE_LISTENER');
  const next = page.waitForResponse((r) => match(r, 'GET', '/v1/service-clients') && new URL(r.url()).searchParams.has('cursor'));
  step('CLIENT_PAGE_NEXT_BUTTON_CLICK');
  await page.getByRole('button', { name: '机器身份下一页', exact: true }).click();
  step('CLIENT_PAGE_NEXT_BUTTON_CLICKED');
  step('CLIENT_PAGE_TWO_RESPONSE_WAIT');
  const pageTwo = await next;
  step('CLIENT_PAGE_TWO_RESPONSE_RECEIVED');
  assert.equal(pageTwo.status(), 200);
  assert.equal(new URL(pageTwo.url()).searchParams.get('limit'), '1');
  step('CLIENT_PAGE_TWO_BODY_VERIFY');
  assert.deepEqual((await pageTwo.json()).items.map((v) => v.id), [created[0].id]);
  step('CLIENT_PAGE_TWO_BODY_VERIFIED');
  step('CLIENT_PAGE_TWO_ROW_CLICK');
  await page.getByRole('button', { name: `查看机器身份 ${created[0].display_name}`, exact: true }).click();
  step('CLIENT_PAGE_TWO_ROW_CLICKED');
  const clientPath = `/v1/service-clients/${created[0].id}`;
  const detail = page.getByTestId('service-client-detail');
  step('CLIENT_DETAIL_NAME_WAIT');
  await detail.getByLabel('机器身份名称', { exact: true }).waitFor();
  step('CLIENT_DETAIL_NAME_VISIBLE');
  step('GRANT_CREATE');
  const grant = page.getByTestId('grant-create');
  await grant.getByLabel('授权主体 UUID', { exact: true }).fill(created[0].principal_id);
  await grant.getByLabel('授权动作', { exact: true }).selectOption('instances:read');
  await grant.getByLabel('授权无到期时间', { exact: true }).check();
  const grantPending = page.waitForResponse((r) => match(r, 'POST', `/v1/projects/${config.project}/grants`));
  await grant.getByRole('button', { name: '创建项目授权', exact: true }).click();
  const grantResponse = await grantPending;
  assert.equal(grantResponse.status(), 201);
  const permission = (await grantResponse.json()).resource;
  assert.equal(permission.principal_id, created[0].principal_id);
  assert.equal(permission.action, 'instances:read');
  await coordinate('machine_granted', 'machine_read_allowed');

  step('COMMITTED_ACK_LOSS');
  let dropped;
  let patchCount = 0;
  const fault = async (route) => {
    if (route.request().method() !== 'PATCH') return route.continue();
    patchCount++;
    const request = route.request();
    dropped = { key: request.headers()['idempotency-key'], etag: request.headers()['if-match'], body: request.postData() };
    assert.equal(dropped.etag, '"1"');
    const actual = await route.fetch({ maxRedirects: 0 });
    assert.equal(actual.status(), 200, 'BFF really committed before the injected lost response');
    assert.equal((await actual.json()).resource.version, 2);
    await route.abort('failed');
  };
  await page.route(origin + clientPath, fault, { times: 1 });
  await detail.getByLabel('启用此租户机器身份', { exact: true }).uncheck();
  await detail.getByRole('button', { name: '保存机器身份', exact: true }).click();
  await page.getByRole('alert').filter({ hasText: /NETWORK_FAILURE|REQUEST_INTERRUPTED/ }).first().waitFor();
  assert.equal(patchCount, 1);
  assert(dropped);
  step('ORIGINAL_REPLAY_WITHOUT_PROJECT');
  await page.reload();
  assert.equal(await page.getByLabel('项目 ID', { exact: true }).inputValue(), '');
  await page.getByRole('button', { name: '请求记录', exact: true }).click();
  await page.getByRole('button', { name: '显式重试原请求', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByRole('textbox').fill(dropped.key);
  const retryPending = page.waitForResponse((r) => match(r, 'PATCH', clientPath));
  await dialog.getByRole('button', { name: '确认提交', exact: true }).click();
  const retried = await retryPending;
  assert.equal(retried.status(), 200);
  assert.equal(retried.request().headers()['idempotency-key'], dropped.key);
  assert.equal(retried.request().headers()['if-match'], dropped.etag);
  assert.equal(retried.request().postData(), dropped.body);
  assert.equal((await retried.json()).resource.version, 2);
  await coordinate('machine_disabled', 'machine_read_denied');
  await page.getByLabel('项目 ID', { exact: true }).fill(config.project);
  await page.getByRole('button', { name: '进入项目', exact: true }).click();

  step('STALE_ETAG_AND_CSRF');
  step('STALE_PATCH_SEND');
  const stale = await api(clientPath, 'PATCH', { enabled: true, display_name: created[0].display_name },
    { 'Idempotency-Key': crypto.randomUUID(), 'If-Match': '"1"' });
  statusSignal('STALE_PATCH', stale.status);
  step('STALE_PATCH_STATUS_ASSERT');
  assert.equal(stale.status, 412);
  step('STALE_PATCH_STATUS_VERIFIED');
  step('STALE_PATCH_CODE_ASSERT');
  assert.equal(stale.body.code, 'VERSION_MISMATCH');
  step('STALE_PATCH_CODE_VERIFIED');
  step('NO_CSRF_PATCH_SEND');
  const noCsrf = await page.evaluate(async ({ path, tenant }) => {
    const response = await fetch(path, { method: 'PATCH', headers: { 'X-Tenant-ID': tenant,
      'Content-Type': 'application/json', 'Idempotency-Key': crypto.randomUUID(), 'If-Match': '"2"' },
      body: JSON.stringify({ enabled: true, display_name: 'No CSRF' }) });
    return { status: response.status, code: (await response.json()).code };
  }, { path: clientPath, tenant: config.tenant });
  statusSignal('NO_CSRF_PATCH', noCsrf.status);
  step('NO_CSRF_PATCH_STATUS_ASSERT');
  assert.equal(noCsrf.status, 403);
  step('NO_CSRF_PATCH_STATUS_VERIFIED');
  step('CLIENT_REENABLE');
  step('CLIENT_REENABLE_NAVIGATE');
  await page.getByRole('button', { name: '账户与授权', exact: true }).click();
  step('CLIENT_REENABLE_LIMIT_SELECT');
  await page.getByLabel('机器身份每页条数', { exact: true }).selectOption('1');
  step('CLIENT_REENABLE_NEXT_BUTTON_CLICK');
  await page.getByRole('button', { name: '机器身份下一页', exact: true }).click();
  step('CLIENT_REENABLE_NEXT_BUTTON_CLICKED');
  step('CLIENT_REENABLE_ROW_CLICK');
  await page.getByRole('button', { name: `查看机器身份 ${created[0].display_name}`, exact: true }).click();
  step('CLIENT_REENABLE_ROW_CLICKED');
  const fresh = page.waitForResponse((r) => match(r, 'GET', clientPath));
  step('CLIENT_REENABLE_FRESH_READ_CLICK');
  await detail.getByRole('button', { name: '重新读取机器身份', exact: true }).click();
  step('CLIENT_REENABLE_FRESH_READ_RESPONSE_WAIT');
  assert.equal((await fresh).headers().etag, '"2"');
  step('CLIENT_REENABLE_FRESH_READ_VERIFIED');
  await detail.getByLabel('启用此租户机器身份', { exact: true }).check();
  const enablePending = page.waitForResponse((r) => match(r, 'PATCH', clientPath));
  await detail.getByRole('button', { name: '保存机器身份', exact: true }).click();
  const enabled = await enablePending;
  assert.equal(enabled.status(), 200);
  assert.equal(enabled.request().headers()['if-match'], '"2"');
  assert.equal((await enabled.json()).resource.version, 3);
  await coordinate('machine_enabled', 'machine_read_restored');

  step('GRANT_ENABLE_DISABLE_REVOKE');
  await page.getByRole('button', { name: `查看授权 instances:read ${created[0].principal_id}`, exact: true }).click();
  const permissionDetail = page.getByTestId('grant-detail');
  for (const [enabled, version, sent, expected] of [
    [false, 1, 'machine_grant_disabled', 'machine_grant_read_denied'],
    [true, 2, 'machine_grant_enabled', 'machine_grant_read_restored'],
  ]) {
    const checkbox = permissionDetail.getByLabel('启用此项目授权', { exact: true });
    if (enabled) await checkbox.check(); else await checkbox.uncheck();
    const pending = page.waitForResponse((r) => match(r, 'PATCH', `/v1/projects/${config.project}/grants/${permission.id}`));
    await permissionDetail.getByRole('button', { name: '保存项目授权', exact: true }).click();
    const changed = await pending;
    assert.equal(changed.status(), 200);
    assert.equal(changed.request().headers()['if-match'], `"${version}"`);
    assert.equal((await changed.json()).resource.version, version + 1);
    await coordinate(sent, expected);
  }
  await permissionDetail.getByRole('button', { name: '撤销项目授权', exact: true }).click();
  const revokePending = page.waitForResponse((r) => match(r, 'DELETE', `/v1/projects/${config.project}/grants/${permission.id}`));
  await permissionDetail.getByRole('button', { name: '确认撤销项目授权', exact: true }).click();
  const revoked = await revokePending;
  assert.equal(revoked.status(), 200);
  assert.equal(revoked.request().postData(), null);
  assert.equal(revoked.request().headers()['content-type'], undefined);
  assert.equal(revoked.request().headers()['if-match'], '"3"');
  assert.equal((await revoked.json()).resource.enabled, false);
  await coordinate('machine_grant_revoked', 'machine_grant_denied');
  const journal = await page.evaluate(() => JSON.parse(localStorage.getItem('sandbox.console.intents.v1') ?? '[]'));
  assert(journal.length >= 6);
  assert(journal.every((row) => row.state === 'ACCEPTED' && row.body === null));
  await coordinate('accounts_complete', 'accounts_checked');
  return { clientPath, replay: dropped };
}

export async function accountRevocation(page, config, accepted) {
  await page.getByRole('button', { name: '账户与授权', exact: true }).click();
  await page.getByRole('alert').filter({ hasText: 'RESOURCE_NOT_FOUND' }).first().waitFor();
  assert.equal(await page.getByRole('button', { name: /^查看机器身份 / }).count(), 0);
  const denied = await page.evaluate(async ({ tenant, project, accepted }) => {
    const session = await (await fetch('/auth/session')).json();
    const common = { 'X-Tenant-ID': tenant, 'X-CSRF-Token': session.csrf_token };
    const rows = await Promise.all([fetch('/v1/service-clients', { headers: common }),
      fetch(`/v1/projects/${project}/grants`, { headers: common }),
      fetch(accepted.clientPath, { method: 'PATCH', headers: { ...common,
        'Content-Type': 'application/json', 'Idempotency-Key': accepted.replay.key, 'If-Match': accepted.replay.etag },
        body: accepted.replay.body })]);
    return Promise.all(rows.map(async (r) => ({ status: r.status, code: (await r.json()).code })));
  }, { ...config, accepted });
  assert(denied.every((v) => v.status === 404 && v.code === 'RESOURCE_NOT_FOUND'));
}
