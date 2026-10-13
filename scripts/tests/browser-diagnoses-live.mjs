// Actual Chrome -> BFF/API -> PostgreSQL. Only a committed POST's response is
// dropped. The worker and authorization changes are coordinated with Rust;
// neither report bodies nor database results are mocked by this driver.
import assert from 'node:assert/strict';
import { diagnosisMutationJson } from './diagnosis-response-observer.mjs';
import { observeReadResponse } from './mutation-response-observer.mjs';

export async function diagnosesConsole(page, config, coordinate) {
  const step = (name) => process.stderr.write(`DIAGNOSES_LIVE_STEP ${name}\n`);
  const origin = new URL(config.origin).origin;
  const path = `/v1/instances/${config.instance}/diagnoses`;
  const match = (response, method, target) => {
    const url = new URL(response.url());
    return url.origin === origin && url.pathname === target && response.request().method() === method;
  };
  const read = async (target) => page.evaluate(async (path) => {
    const session = await (await fetch('/auth/session')).json();
    const response = await fetch(path, { headers: { 'X-Tenant-ID': session.tenant_id } });
    return { status: response.status, body: await response.json() };
  }, target);
  let posts = 0;
  let operationReads = 0;
  const count = (request) => {
    const url = new URL(request.url());
    if (url.origin !== origin) return;
    if (url.pathname === path && request.method() === 'POST') posts++;
    if (/^\/v1\/operations\//.test(url.pathname) && request.method() === 'GET') operationReads++;
  };
  page.on('request', count);
  try {
    step('CAPABILITIES');
    const capabilities = await read(`/v1/capabilities?project_id=${config.project}`);
    assert.equal(capabilities.status, 200);
    assert.equal(capabilities.body.api_features.control_plane_diagnoses, true);
    assert.equal(capabilities.body.api_features.health_diagnostics, false);
    await page.getByRole('button', { name: '实例', exact: true }).click();
    await page.getByRole('button', { name: config.name, exact: true }).click();
    await page.getByRole('tab', { name: '健康诊断', exact: true }).click();
    assert.equal(await page.getByLabel('包含操作证据', { exact: true }).isChecked(), false);
    assert.equal(await page.getByLabel('包含执行证据', { exact: true }).isChecked(), false);

    step('COMMITTED_ACK_LOSS');
    let original;
    let actualAccepted;
    const fault = async (route) => {
      if (route.request().method() !== 'POST') return route.continue();
      const request = route.request();
      original = { key: request.headers()['idempotency-key'], body: request.postData() };
      assert.match(original.key, /^[0-9a-f-]{36}$/);
      assert(request.headers()['x-csrf-token']);
      assert.deepEqual(JSON.parse(original.body), { include_operations: false, include_executions: false });
      const response = await route.fetch({ maxRedirects: 0 });
      assert.equal(response.status(), 202, 'the real API commits before Chrome loses its reply');
      actualAccepted = await response.json();
      assert.equal(actualAccepted.resource.status, 'PENDING');
      assert.equal(actualAccepted.resource.tenant_id, config.tenant);
      assert.equal(actualAccepted.resource.project_id, config.project);
      assert.equal(actualAccepted.resource.instance_id, config.instance);
      assert.equal(actualAccepted.resource.operation_id, actualAccepted.operation.id);
      await route.abort('failed');
    };
    await page.route(origin + path, fault, { times: 1 });
    await page.getByRole('button', { name: '创建诊断报告', exact: true }).click();
    await page.getByRole('alert').filter({ hasText: /NETWORK_FAILURE|REQUEST_INTERRUPTED/ }).first().waitFor();
    assert(original && actualAccepted);
    assert.equal(posts, 1);
    const journalRow = async () => page.evaluate((key) =>
      JSON.parse(localStorage.getItem('sandbox.console.intents.v1') ?? '[]').find((row) => row.key === key), original.key);
    const unknown = await journalRow();
    assert.equal(unknown.state, 'UNKNOWN');
    assert.equal(unknown.path, path);
    assert.equal(unknown.method, 'POST');
    assert.deepEqual(unknown.body, JSON.parse(original.body));

    step('RELOAD_ORIGINAL_REPLAY');
    await page.reload();
    assert.equal(await page.getByLabel('项目 ID', { exact: true }).inputValue(), '');
    await page.getByLabel('项目 ID', { exact: true }).fill(config.project);
    await page.getByRole('button', { name: '进入项目', exact: true }).click();
    await page.getByRole('button', { name: '请求记录', exact: true }).click();
    const row = page.getByRole('row').filter({ hasText: original.key });
    await row.getByRole('button', { name: '显式重试原请求', exact: true }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByRole('textbox').fill(original.key);
    const retried = page.waitForResponse((response) => match(response, 'POST', path));
    await dialog.getByRole('button', { name: '确认提交', exact: true }).click();
    const replay = await retried;
    assert.equal(replay.status(), 202);
    step('REPLAY_HTTP_202');
    assert.equal(replay.request().headers()['idempotency-key'], original.key);
    assert.equal(replay.request().postData(), original.body);
    assert(replay.request().headers()['x-csrf-token']);
    step('REPLAY_RECEIPT_BODY_READ');
    const accepted = await diagnosisMutationJson(page, replay);
    step('REPLAY_RECEIPT_BODY_READ_COMPLETE');
    assert.equal(accepted.resource.id, actualAccepted.resource.id);
    assert.equal(accepted.operation.id, actualAccepted.operation.id);
    await row.getByRole('button', { name: '打开报告', exact: true }).waitFor();
    const saved = await journalRow();
    assert.equal(saved.state, 'ACCEPTED');
    assert.equal(saved.body, null);
    assert.equal(saved.resourceId, accepted.resource.id);
    assert.equal(saved.operationId, accepted.operation.id);
    assert.equal(posts, 2);
    await coordinate('diagnoses_replayed', 'diagnosis_complete');

    step('STRUCTURED_REPORT_WITHOUT_OPERATION_READ');
    const reportPath = `/v1/diagnoses/${accepted.resource.id}`;
    const { response, body: report } = await observeReadResponse(page, origin, reportPath, config.tenant,
      () => row.getByRole('button', { name: '打开报告', exact: true }).click());
    assert.equal(response.status(), 200);
    step('STRUCTURED_REPORT_BODY_READ');
    step('STRUCTURED_REPORT_BODY_READ_COMPLETE');
    assert.equal(report.id, accepted.resource.id);
    assert.equal(report.tenant_id, config.tenant);
    assert.equal(report.project_id, config.project);
    assert.equal(report.instance_id, config.instance);
    assert.equal(report.operation_id, accepted.operation.id);
    assert.equal(report.status, 'COMPLETE');
    assert.equal(report.ruleset_version, 'control-plane/v1');
    assert(report.snapshot_at && report.completed_at);
    assert(report.report.checks.length > 0);
    assert(report.report.checks.every((check) => check.evidence_scope === 'INSTANCE'));
    assert(report.report.checks.some((check) => check.status === 'UNKNOWN'));
    const view = page.getByTestId('diagnosis-report');
    await view.getByText('COMPLETE', { exact: true }).waitFor();
    for (const [attribute, value] of Object.entries({
      'data-diagnosis-id': report.id, 'data-tenant-id': config.tenant,
      'data-project-id': config.project, 'data-instance-id': config.instance,
    })) assert.equal(await view.getAttribute(attribute), value);
    const identityText = await view.innerText();
    assert(Number.isSafeInteger(report.requested_generation));
    assert(identityText.includes(`请求时运行代次 ${report.requested_generation}`));
    assert(identityText.includes(report.requested_launch_id));
    assert(identityText.includes(report.cluster_epoch));
    const checks = view.getByRole('table', { name: '诊断检查', exact: true });
    assert.equal(await checks.locator('tbody tr').count(), report.report.checks.length);
    for (const [index, check] of report.report.checks.entries()) {
      const rendered = checks.locator('tbody tr').nth(index);
      assert((await rendered.innerText()).includes(check.rule));
      assert((await rendered.innerText()).includes(check.code));
      assert((await rendered.innerText()).includes(check.recommendation));
      for (const evidence of check.evidence) assert((await rendered.innerText()).includes(evidence.source));
    }
    assert.equal(operationReads, 0, 'opening a diagnosis never fetches its operation');
    const operation = await read(`/v1/operations/${accepted.operation.id}`);
    assert.equal(operation.status, 404, 'the same browser actor really lacks operations:read');
    assert.equal(operation.body.code, 'RESOURCE_NOT_FOUND');
    await coordinate('diagnosis_report_checked', 'diagnosis_read_revoked');

    step('READ_REVOCATION_CLEARS_EVIDENCE');
    const { response: denial, body: denialBody } = await observeReadResponse(page, origin, reportPath, config.tenant,
      () => page.getByRole('button', { name: '刷新报告', exact: true }).click());
    assert.equal(denial.status(), 404);
    step('READ_REVOCATION_HTTP_404');
    assert.equal(denialBody.code, 'RESOURCE_NOT_FOUND');
    step('READ_REVOCATION_BODY_CHECKED');
    await page.getByRole('alert').filter({ hasText: 'RESOURCE_NOT_FOUND' }).first().waitFor();
    assert.equal(await page.getByTestId('diagnosis-report').count(), 0);
    assert.equal(await page.getByRole('table', { name: '诊断检查', exact: true }).count(), 0);
    assert.equal(posts, 2, 'revocation cannot automatically create a replacement diagnosis');
    step('READ_REVOCATION_UI_CLEARED');
    await coordinate('diagnosis_read_denied', 'diagnosis_permissions_restored');
    step('READ_PERMISSION_RESTORED');
    const { response: restoredResponse, body: restoredReport } = await observeReadResponse(page, origin, reportPath, config.tenant,
      () => page.getByRole('button', { name: '刷新报告', exact: true }).click());
    assert.equal(restoredResponse.status(), 200);
    step('READ_RESTORED_HTTP_200');
    step('READ_RESTORED_BODY_CHECKED');
    assert.deepEqual(restoredReport, report);
    await page.getByTestId('diagnosis-report').getByText('COMPLETE', { exact: true }).waitFor();
    assert.equal(posts, 2);
    await coordinate('diagnoses_complete', 'diagnoses_checked');
    step('VERIFIED');
  } finally {
    page.off('request', count);
  }
}
