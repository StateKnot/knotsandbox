// Real Chrome → compiled console → Rust BFF/API → Keycloak/PostgreSQL.
// Test credentials arrive only over a private pipe. No traces or response
// bodies are emitted; this file never mocks HTTP or identity. Opt-in screenshots
// use only a canonical private evidence directory and authenticated console
// checkpoints. Never capture IdP passwords, tokens, cookies or credentials.
import { chromium } from '../../console/node_modules/playwright-core/index.mjs';
import { createInterface } from 'node:readline';
import assert from 'node:assert/strict';
import { lstat, realpath, mkdir, open } from 'node:fs/promises';
import { isAbsolute, resolve, join } from 'node:path';
import { createHash } from 'node:crypto';
import { accountConsole, accountRevocation } from './browser-accounts-live.mjs';
import { diagnosesConsole } from './browser-diagnoses-live.mjs';
import { eventsConsole } from './browser-events-live.mjs';
import { automationsConsole } from './browser-automations-live.mjs';
import { notificationsConsole } from './browser-notifications-live.mjs';
import { installServiceClientResponseObserver } from './service-client-response-observer.mjs';
import { installDiagnosisResponseObserver } from './diagnosis-response-observer.mjs';
import { installMutationResponseObserver } from './mutation-response-observer.mjs';


const screenshotPlan = [
  { file: '01-instance-details.png', checkpoint: 'instance_details', caption: '真实登录后的实例详情；创建仍在排队，未运行 VM。' },
  { file: '02-accounts-management.png', checkpoint: 'accounts_management', caption: '真实服务身份、项目授权变更及原键重放完成。' },
  { file: '03-diagnosis-complete.png', checkpoint: 'diagnosis_complete', caption: '正常 worker 完成控制面诊断；读权限恢复后显式刷新报告。' },
  { file: '04-events-replayed.png', checkpoint: 'events_replayed', caption: '按原断点重连，真实受理事件与完成事件均可见。' },
  { file: '05-automation-revoked.png', checkpoint: 'automation_revoked', caption: '未来 ONCE 策略创建、重放、暂停、恢复及撤销；零运行。' },
  { file: '06-notification-acknowledged.png', checkpoint: 'notification_acknowledged', caption: '真实 FAILED 通知已阅；丢失回执与读写撤权后原键重放完成。' },
  { file: '07-instance-current-before-stop.png', checkpoint: 'instance_current_before_stop', caption: '正常续期产生新版本，停止前重新读取当前实例及 ETag。' },
  { file: '08-stop-accepted.png', checkpoint: 'stop_accepted', caption: '真实停止 API 返回 202，只证明操作已受理。' },
  { file: '09-permission-revoked-login.png', checkpoint: 'permission_revoked_login', caption: '当前授权撤销、租户成员禁用后返回登录；旧数据已清除。' },
];

async function privateScreenshotEvidence(config, setStage) {
  const directory = process.env.SANDBOX_BROWSER_EVIDENCE_DIR;
  if (!directory) return { capture: async () => {}, complete: async () => {} };
  assert(isAbsolute(directory) && resolve(directory) === directory,
    'screenshot evidence directory must be absolute and canonical');
  assert.equal(await realpath(directory), directory);
  const parent = await lstat(directory);
  assert(parent.isDirectory() && !parent.isSymbolicLink());
  assert.equal(parent.mode & 0o777, 0o700);
  if (typeof process.getuid === 'function') assert.equal(parent.uid, process.getuid());
  const images = join(directory, 'browser-screenshots');
  await mkdir(images, { mode: 0o700 });
  const imageDirectory = await lstat(images);
  assert(imageDirectory.isDirectory() && !imageDirectory.isSymbolicLink());
  assert.equal(imageDirectory.mode & 0o777, 0o700);
  assert.equal(await realpath(images), images);
  const rows = [];
  const writePrivate = async (path, bytes, label) => {
    setStage(label + '_private_open');
    const target = await open(path, 'wx', 0o600);
    try {
      setStage(label + '_private_write');
      await target.writeFile(bytes);
      setStage(label + '_private_sync');
      await target.sync();
    } finally { await target.close(); }
    setStage(label + '_private_mode_check');
    const metadata = await lstat(path);
    assert(metadata.isFile() && !metadata.isSymbolicLink());
    assert.equal(metadata.mode & 0o777, 0o600);
  };
  return {
    capture: async (checkpoint, page) => {
      const entry = screenshotPlan.find((value) => value.checkpoint === checkpoint);
      assert(entry && !rows.some((row) => row.checkpoint === checkpoint));
      const label = 'screenshot_' + entry.checkpoint;
      setStage(label + '_preconditions');
      const location = new URL(page.url());
      assert.equal(location.origin, config.origin, 'screenshots are limited to the real console origin');
      assert.equal(location.pathname, '/');
      assert.equal(location.search, '');
      assert.equal(location.hash, '');
      assert.equal(await page.locator('input[type="password"], #password').count(), 0,
        'never capture an identity password form');
      setStage(label + '_privacy_check');
      const text = await page.locator('body').innerText();
      assert(!text.includes(config.password), 'never capture a private login credential');
      assert(!/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(text),
        'never capture a visible bearer token');
      setStage(label + '_capture_png');
      const bytes = await page.screenshot({ fullPage: true, type: 'png' });
      await writePrivate(join(images, entry.file), bytes, label);
      rows.push({ ...entry, mode: '0600', bytes: bytes.length,
        sha256: createHash('sha256').update(bytes).digest('hex') });
    },
    complete: async () => {
      setStage('screenshot_manifest_checkpoint_order');
      assert.deepEqual(rows.map((row) => row.checkpoint), screenshotPlan.map((row) => row.checkpoint));
      const manifest = { version: 1, status: 'CAPTURED_CHECKPOINTS_NOT_MANUAL_INTERACTION',
        real_flow: 'Chrome/compiled console/Keycloak/BFF/API/PostgreSQL',
        manual_interaction: false, cloud_certified: false, vm_running_demonstrated: false,
        scope: 'Private screenshots of actual automated browser checks; the passing test, source/artifact binding and backend facts remain independent required evidence.',
        files: rows };
      await writePrivate(join(images, 'manifest.json'), Buffer.from(JSON.stringify(manifest, null, 2) + '\n'), 'screenshot_manifest');
    },
  };
}

const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
const lines = input[Symbol.asyncIterator]();
const next = async () => {
  const value = await lines.next();
  assert(!value.done, 'missing test coordination');
  return JSON.parse(value.value);
};
const receipt = (phase) => process.stdout.write(JSON.stringify({ phase }) + '\n');
let browser;
let page;
let transportFailure = null;
const navigations = [];
let stage = 'start';
try {
  const config = await next();
  assert(new URL(config.origin).hostname === '127.0.0.1');
  stage = 'screenshot_evidence_setup';
  const screenshotEvidence = await privateScreenshotEvidence(config, (value) => { stage = value; });
  browser = await chromium.launch({
    headless: true,
    ...(process.env.SANDBOX_TEST_CHROME
      ? { executablePath: process.env.SANDBOX_TEST_CHROME }
      : {}),
  });
  // The HTTPS entrypoints use the repository's public, local-only test leaf.
  // This is explicitly not evidence for production CA/TLS provisioning.
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  page = await context.newPage();
  // BrowserApi captures fetch at construction; observe before console bootstrap.
  await installServiceClientResponseObserver(page, config.origin);
  await installDiagnosisResponseObserver(page, config.origin);
  await installMutationResponseObserver(page, config.origin,
    ['AUTOMATION', 'GRANT', 'NOTIFICATION', 'LIFECYCLE']);
  page.on('requestfailed', (request) => {
    const code = request.failure()?.errorText;
    if (typeof code === 'string' && /^net::ERR_[A-Z_]+$/.test(code)) transportFailure = code;
  });
  page.on('response', (response) => {
    if (response.request().isNavigationRequest() && navigations.length < 8) {
      const host = new URL(response.url()).hostname;
      if (['127.0.0.1', 'localhost'].includes(host)) navigations.push({ host, status: response.status() });
    }
  });
  page.setDefaultTimeout(15000);
  const seen = { login: 0, callback: 0, stop: 0 };
  let leakedCredential = false;
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (url.origin !== config.origin) return;
    const headers = request.headers();
    if (headers.authorization) leakedCredential = true;
    if (url.pathname === '/auth/login') seen.login++;
    if (url.pathname === '/auth/callback') seen.callback++;
    if (url.pathname.endsWith('/actions/stop')) seen.stop++;
  });
  await page.goto(config.origin);
  stage = 'console_login';
  await page.getByLabel(/^租户 ID/).fill(config.tenant);
  stage = 'begin_login';
  const loginResponse = page.waitForResponse((r) =>
    new URL(r.url()).origin === config.origin && new URL(r.url()).pathname === '/auth/login',
  );
  await page.getByRole('button', { name: '继续安全登录 →', exact: true }).click();
  assert((await loginResponse).status() === 200, 'login challenge was not accepted');
  stage = 'keycloak_login';
  stage = 'keycloak_username';
  await page.locator('#username').fill(config.username);
  assert(new URL(page.url()).hostname === 'localhost', 'identity must be on a different browser site');
  stage = 'keycloak_password';
  await page.locator('#password').fill(config.password);
  stage = 'keycloak_submit';
  await page.locator('#kc-login').click();
  await page.waitForURL(config.origin + '/');
  stage = 'project_read';
  await page.getByLabel('项目 ID', { exact: true }).fill(config.project);
  await page.getByRole('button', { name: '进入项目', exact: true }).click();
  const instance = page.getByRole('button', { name: config.name, exact: true });
  await instance.waitFor({ state: 'visible' });
  await instance.click();
  stage = 'instance_details_heading';
  await page.getByRole('heading', { name: config.name, exact: true }).waitFor();
  stage = 'instance_details_observed_state';
  await page.locator('.instance-pane .summary-grid').getByText('实际状态', { exact: true }).waitFor();
  await screenshotEvidence.capture('instance_details', page);
  stage = 'account_management';
  const accountAccepted = await accountConsole(page, config, async (sent, expected) => {
    receipt(sent);
    assert((await next()).phase === expected);
  });
  await screenshotEvidence.capture('accounts_management', page);
  stage = 'diagnosis_management';
  await diagnosesConsole(page, config, async (sent, expected) => {
    receipt(sent);
    assert((await next()).phase === expected);
  });
  await screenshotEvidence.capture('diagnosis_complete', page);
  stage = 'event_management';
  await eventsConsole(page, config, async (sent, expected) => {
    if (sent === 'events_completed_received') await screenshotEvidence.capture('events_replayed', page);
    receipt(sent);
    assert((await next()).phase === expected);
  });
  stage = 'automation_management';
  await automationsConsole(page, config, async (sent, expected) => {
    receipt(sent);
    assert((await next()).phase === expected);
  });
  await screenshotEvidence.capture('automation_revoked', page);
  stage = 'notification_management';
  await notificationsConsole(page, config, async (sent, expected) => {
    receipt(sent);
    const state = await next();
    assert(state.phase === expected);
    return state;
  });
  await screenshotEvidence.capture('notification_acknowledged', page);
  stage = 'fresh_instance_details_navigation';
  const currentInstance = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return url.origin === config.origin && url.pathname === `/v1/instances/${config.instance}/details`
      && response.request().method() === 'GET';
  });
  await page.getByRole('button', { name: '实例', exact: true }).click();
  await page.getByRole('button', { name: config.name, exact: true }).click();
  const instanceResponse = await currentInstance;
  stage = 'fresh_instance_details_version_verification';
  assert.equal(instanceResponse.status(), 200);
  const currentDetails = await instanceResponse.json();
  const currentResource = currentDetails.instance;
  assert.equal(currentResource.id, config.instance);
  assert.equal(currentResource.tenant_id, config.tenant);
  assert.equal(currentResource.project_id, config.project);
  assert(Number.isSafeInteger(currentResource.spec_version) && currentResource.spec_version > 1);
  const currentEtag = `"${currentResource.spec_version}"`;
  assert.equal(instanceResponse.headers()['x-instance-etag'], currentEtag);
  await page.getByRole('heading', { name: config.name, exact: true }).waitFor();
  await screenshotEvidence.capture('instance_current_before_stop', page);
  stage = 'stop_acceptance';
  await page.getByRole('button', { name: '停止实例', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByRole('textbox').fill(config.name);
  const stopResponse = page.waitForResponse((r) =>
    new URL(r.url()).pathname === `/v1/instances/${config.instance}/actions/stop`,
  );
  await page.getByRole('button', { name: '确认提交', exact: true }).click();
  const stopped = await stopResponse;
  assert(stopped.status() === 202, 'stop was not accepted');
  assert.equal(stopped.request().headers()['if-match'], currentEtag,
    'stop uses the freshly read instance version after the real notification-source renewal');
  assert(seen.login === 1 && seen.callback === 1 && seen.stop === 1);
  assert(!leakedCredential, 'browser sent a bearer credential');
  const cookies = await context.cookies(config.origin);
  const cookie = cookies.find((v) => v.name === '__Host-sandbox-session');
  assert(cookie && cookie.httpOnly && cookie.secure && cookie.sameSite === 'Strict');
  assert(!cookies.some((v) => /token|csrf|refresh/i.test(v.name)));
  const storage = await page.evaluate(() => ({
    local: Object.entries(localStorage),
    session: Object.entries(sessionStorage),
    cookies: document.cookie,
  }));
  assert(storage.cookies === '');
  assert(!JSON.stringify(storage).match(/access_token|refresh_token|eyJ[a-zA-Z0-9_-]+\./));
  await page.getByRole('dialog').waitFor({ state: 'hidden' });
  await screenshotEvidence.capture('stop_accepted', page);
  receipt('accepted');

  assert((await next()).phase === 'grants_revoked');
  stage = 'grant_denial';
  const denied = await page.evaluate(async ({ id, tenant }) => {
    const response = await fetch(`/v1/instances/${id}`, {
      headers: { 'X-Tenant-ID': tenant },
    });
    return { status: response.status, code: (await response.json()).code };
  }, { id: config.instance, tenant: config.tenant });
  assert(denied.status === 404 && denied.code === 'RESOURCE_NOT_FOUND');
  await accountRevocation(page, config, accountAccepted);
  receipt('grant_denied');

  assert((await next()).phase === 'member_disabled');
  stage = 'membership_denial';
  await page.reload();
  await page.getByLabel(/^租户 ID/).waitFor({ state: 'visible' });
  assert((await page.getByRole('button', { name: config.name, exact: true }).count()) === 0);
  assert(!leakedCredential);
  await screenshotEvidence.capture('permission_revoked_login', page);
  await screenshotEvidence.complete();
  receipt('member_denied');
  await context.close();
  await browser.close();
  browser = undefined;
  input.close();
} catch (error) {
  const diagnostics = { stage, transportFailure, navigations };
  if (['TimeoutError', 'AssertionError', 'Error'].includes(error?.name)) diagnostics.errorType = error.name;
  // Emit only fixed categories; the original message can contain private URLs.
  const errorText = typeof error?.message === 'string' ? error.message : '';
  const evidenceCodes = { EACCES: 'EVIDENCE_PERMISSION_DENIED', EPERM: 'EVIDENCE_PERMISSION_DENIED',
    EEXIST: 'EVIDENCE_PATH_EXISTS', ENOENT: 'EVIDENCE_PATH_MISSING',
    ENOSPC: 'EVIDENCE_DISK_FULL', EIO: 'EVIDENCE_IO_ERROR' };
  if (Object.hasOwn(evidenceCodes, error?.code)) {
    diagnostics.errorCode = error.code;
    diagnostics.errorCategory = evidenceCodes[error.code];
  } else if (/strict mode violation/.test(errorText)) {
    diagnostics.errorCategory = 'STRICT_LOCATOR_AMBIGUOUS';
  } else if (/Page\.captureScreenshot|Unable to capture screenshot|Failed to capture screenshot/.test(errorText)) {
    diagnostics.errorCategory = 'SCREENSHOT_CAPTURE_FAILED';
  } else if (/Cannot take screenshot larger than|Cannot take screenshot with 0 width|Cannot take screenshot with 0 height/.test(errorText)) {
    diagnostics.errorCategory = 'SCREENSHOT_DIMENSION_INVALID';
  } else if (stage.endsWith('_capture_png') && /waiting for fonts to load/.test(errorText) && !/fonts loaded/.test(errorText)) {
    diagnostics.errorCategory = 'SCREENSHOT_FONT_WAIT_FAILED';
  } else if (/No resource with given identifier found|No data found for resource with given identifier/.test(errorText)) {
    diagnostics.errorCategory = 'RESPONSE_BODY_UNAVAILABLE';
  } else if (/Target page, context or browser has been closed/.test(errorText)) {
    diagnostics.errorCategory = 'BROWSER_CLOSED';
  } else if (/Execution context was destroyed/.test(errorText)) {
    diagnostics.errorCategory = 'CONTEXT_DESTROYED';
  } else if (error?.name === 'TimeoutError') {
    diagnostics.errorCategory = 'TIMEOUT';
  }
  if (page && !page.isClosed()) {
    diagnostics.accountNavigation = await page.getByRole('button', { name: '账户与授权', exact: true }).count().catch(() => 0);
    diagnostics.accountHeading = await page.getByRole('heading', { name: '账户与项目授权', exact: true }).count().catch(() => 0);
    diagnostics.accountLimit = await page.getByLabel('机器身份每页条数', { exact: true }).count().catch(() => 0);
    diagnostics.usernameFields = await page.locator('#username').count().catch(() => 0);
    diagnostics.passwordFields = await page.locator('#password').count().catch(() => 0);
    diagnostics.keycloakErrorPage = await page.locator('#kc-error-message').count().catch(() => 0);
    try {
      const body = await page.locator('body').innerText({ timeout: 1000 });
      if (body.length <= 4096) {
        const code = JSON.parse(body).code;
        if (typeof code === 'string' && /^[A-Z_]{3,64}$/.test(code)) diagnostics.apiCode = code;
      }
    } catch { /* Never print HTML, identity errors, tokens, or callback parameters. */ }
  }
  process.stderr.write(`BROWSER_LIVE_FAILED ${JSON.stringify(diagnostics)}; private identity details omitted\n`);
  await browser?.close();
  input.close();
  process.exitCode = 1;
}
