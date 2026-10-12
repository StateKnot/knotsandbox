import { test, expect } from "@playwright/test";
import {
  tenant,
  project,
  instance,
  principal,
  now,
  session,
  resource,
  caps,
  detail,
  security,
} from "./browser-fixtures.ts";
test("compiled browser UI displays honest unknown/disabled states and enforces confirmation plus CSRF; logout removes data", async ({
  page,
}) => {
  let authorized = true,
    securityRevoked = false,
    stops = 0,
    stopKey = "";
  await page.route("**/auth/session", (route) =>
    route.fulfill({
      status: authorized ? 200 : 401,
      contentType: authorized ? "application/json" : "application/problem+json",
      body: JSON.stringify(
        authorized ? session : { code: "BROWSER_LOGIN_REQUIRED" },
      ),
    }),
  );
  await page.route("**/auth/logout", async (route) => {
    expect(route.request().headers()["authorization"]).toBeUndefined();
    expect(route.request().headers()["x-csrf-token"]).toBe(session.csrf_token);
    authorized = false;
    await route.fulfill({ status: 204 });
  });
  await page.route("**/v1/**", async (route) => {
    const r = route.request(),
      url = new URL(r.url());
    expect(r.headers()["authorization"]).toBeUndefined();
    expect(r.headers()["x-tenant-id"]).toBe(tenant);
    let body: unknown;
    if (r.method() === "GET" && url.pathname === "/v1/capabilities")
      body = caps;
    else if (r.method() === "GET" && url.pathname === "/v1/instances")
      body = { items: [resource], next_after: null };
    else if (
      r.method() === "GET" &&
      url.pathname === `/v1/instances/${instance}/details`
    )
      body = detail;
    else if (
      r.method() === "GET" &&
      url.pathname === `/v1/instances/${instance}/security`
    ) {
      if (securityRevoked) {
        await route.fulfill({
          status: 404,
          contentType: "application/problem+json",
          body: JSON.stringify({ code: "NOT_FOUND" }),
        });
        return;
      }
      body = security;
    } else if (
      r.method() === "POST" &&
      url.pathname === `/v1/instances/${instance}/actions/stop`
    ) {
      stops++;
      expect(r.headers()["x-csrf-token"]).toBe(session.csrf_token);
      expect(r.headers()["if-match"]).toBe('"7"');
      expect(r.headers()["idempotency-key"]).toMatch(/^[0-9a-f-]{36}$/);
      stopKey = r.headers()["idempotency-key"];
      body = {
        resource,
        operation: { id: project, status: "QUEUED" },
        idempotency_expires_at: now,
      };
    } else {
      await route.fulfill({
        status: 404,
        contentType: "application/problem+json",
        body: JSON.stringify({ code: "NOT_FOUND" }),
      });
      return;
    }
    await route.fulfill({
      status:
        r.method() === "POST" &&
        url.pathname === `/v1/instances/${instance}/actions/stop`
          ? 202
          : 200,
      contentType: "application/json",
      body: JSON.stringify(body),
    });
  });
  await page.goto("/");
  await page.getByLabel("项目 ID", { exact: true }).fill(project);
  await page.getByRole("button", { name: "进入项目", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "production-workspace", exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "production-workspace", exact: true })
    .click();
  await expect(
    page.locator("p").filter({ hasText: "尚未配置持续健康观测" }),
  ).toBeVisible();
  await page.getByRole("tab", { name: "监控", exact: true }).click();
  await expect(page.getByText("当前部署未开启运行时指标。")).toBeVisible();
  await page.getByRole("tab", { name: "安全防护", exact: true }).click();
  const securityPanel = page.getByRole("tabpanel");
  await expect(
    securityPanel.getByRole("heading", { name: "期望安全配置" }),
  ).toBeVisible();
  await expect(
    securityPanel.getByText("暂无独立验证", { exact: true }),
  ).toHaveCount(3);
  await expect(
    securityPanel.getByText(
      "模板批准、对象记录和历史启动验证不能证明当前隔离已生效。",
    ),
  ).toBeVisible();
  await expect(
    securityPanel.getByText("账本已记录对象", { exact: true }),
  ).toBeVisible();
  await expect(
    securityPanel.getByText("授权期限覆盖计算租期", { exact: true }),
  ).toBeVisible();
  await expect(
    securityPanel.getByText("尚未采集", { exact: true }),
  ).toBeVisible();
  securityRevoked = true;
  await page.getByRole("button", { name: "刷新详情", exact: true }).click();
  await expect(securityPanel.getByRole("alert")).toHaveText(/^NOT_FOUND/);
  await expect(
    securityPanel.getByRole("heading", { name: "期望安全配置" }),
  ).toHaveCount(0);
  await page.getByRole("tab", { name: "详情与安全", exact: true }).click();
  await page.evaluate(() => window.scrollTo(0, 0));
  const sidebar = await page.locator("aside").boundingBox();
  expect(sidebar?.y).toBe(0);
  await page.screenshot({
    path: "../.local/console-instance-desktop.png",
    fullPage: true,
  });
  await page.getByRole("button", { name: "停止实例", exact: true }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  expect(stops).toBe(0);
  await expect(
    page.getByRole("button", { name: "确认提交", exact: true }),
  ).toBeDisabled();
  await page
    .getByRole("dialog")
    .getByRole("textbox")
    .fill("production-workspace");
  await page.getByRole("button", { name: "确认提交", exact: true }).click();
  await expect(page.getByRole("dialog")).not.toBeVisible();
  expect(stops).toBe(1);
  await expect(
    page.getByText(
      `回执已确认 · 幂等键 ${stopKey}。请重新读取资源或操作的当前状态。`,
      { exact: true },
    ),
  ).toBeVisible();
  await page.getByRole("button", { name: "请求记录", exact: true }).click();
  await expect(page.getByText("ACCEPTED", { exact: true })).toBeVisible();
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage }));
  expect(stored).not.toMatch(/csrf_token|access_token|refresh_token|Bearer/);
  await page.getByRole("button", { name: "退出", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "进入你的工作空间" }),
  ).toBeVisible();
  await expect(
    page.getByText("production-workspace", { exact: true }),
  ).not.toBeVisible();
});
test("unauthenticated mobile layout and denied API never invent resource values or leak markup", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.route("**/auth/session", (route) =>
    route.fulfill({
      status: 401,
      contentType: "application/problem+json",
      body: JSON.stringify({
        code: "BROWSER_LOGIN_REQUIRED",
        detail: "<img src=x onerror=alert(1)>",
      }),
    }),
  );
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "进入你的工作空间" }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "继续安全登录 →" }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: "../.local/console-login-mobile.png",
    fullPage: true,
  });
});
test("control-plane diagnosis reports progress without operation reads, reopen from receipts and reject stale scope", async ({
  page,
}) => {
  const diagnosis = "00000000-0000-4000-8000-000000000005",
    other = "00000000-0000-4000-8000-000000000006",
    failed = "00000000-0000-4000-8000-000000000007",
    expired = "00000000-0000-4000-8000-000000000008",
    short = "00000000-0000-4000-8000-000000000009",
    disconnected = "00000000-0000-4000-8000-00000000000a",
    nextProject = "00000000-0000-4000-8000-00000000000b";
  let enabled = false,
    posts = 0,
    reads = 0,
    operationReads = 0,
    hidden = false,
    shortReads = 0,
    disconnectedReads = 0;
  const deadline = new Date(Date.now() + 25_000).toISOString();
  const report = (id: string, status: string = "COMPLETE") => ({
    id,
    tenant_id: tenant,
    project_id: project,
    instance_id: instance,
    operation_id: project,
    requested_generation: 1,
    requested_launch_id: project,
    cluster_epoch: project,
    ruleset_version: "control-plane/v1",
    status,
    version: 1,
    created_at: now,
    deadline,
    retention_until: new Date(Date.now() + 86400_000).toISOString(),
    snapshot_at: status === "COMPLETE" ? now : null,
    completed_at: status === "COMPLETE" ? now : null,
    failure_code: status === "FAILED" ? "OBSERVATION_FAILED" : null,
    report:
      status === "COMPLETE"
        ? {
            overall: "UNKNOWN",
            checks: [
              {
                rule: "runtime-observation",
                status: "UNKNOWN",
                code: "CONTINUOUS_OBSERVATION_UNAVAILABLE",
                evidence_scope: "INSTANCE",
                recommendation: "READ_INSTANCE_STATE",
                evidence: [
                  {
                    source: "CONTROL_PLANE_SNAPSHOT",
                    observed_at: now,
                    resource_id: instance,
                    state: "UNKNOWN",
                    deadline: null,
                  },
                ],
              },
              {
                rule: "operation-history",
                status: "UNKNOWN",
                code: "EVIDENCE_REDACTED",
                evidence_scope: "OPERATIONS",
                evidence: [],
                recommendation: "REQUEST_EVIDENCE_READ_PERMISSION",
              },
            ],
          }
        : null,
  });
  await page.route("**/auth/session", (route) =>
    route.fulfill({ json: session }),
  );
  await page.route("**/v1/**", async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    expect(request.headers()["authorization"]).toBeUndefined();
    expect(request.headers()["x-tenant-id"]).toBe(tenant);
    if (path === "/v1/capabilities") {
      await route.fulfill({
        json: {
          ...caps,
          api_features: {
            ...caps.api_features,
            control_plane_diagnoses: enabled,
          },
        },
      });
    } else if (path === "/v1/instances") {
      await route.fulfill({ json: { items: [resource], next_after: null } });
    } else if (path === `/v1/instances/${instance}/details`) {
      await route.fulfill({ json: detail });
    } else if (
      path === `/v1/instances/${instance}/diagnoses` &&
      request.method() === "POST"
    ) {
      posts++;
      expect(request.postDataJSON()).toEqual({
        include_operations: false,
        include_executions: true,
      });
      expect(request.headers()["x-csrf-token"]).toBe(session.csrf_token);
      expect(request.headers()["idempotency-key"]).toMatch(/^[0-9a-f-]{36}$/);
      expect(request.headers()["if-match"]).toBeUndefined();
      await route.fulfill({
        status: 202,
        json: {
          resource: report(diagnosis, "PENDING"),
          operation: { id: project, status: "QUEUED" },
          idempotency_expires_at: now,
        },
      });
    } else if (path === `/v1/diagnoses/${diagnosis}`) {
      reads++;
      if (hidden)
        await route.fulfill({
          status: 404,
          contentType: "application/problem+json",
          json: { code: "NOT_FOUND" },
        });
      else
        await route.fulfill({
          json: report(diagnosis, reads === 1 ? "PENDING" : "COMPLETE"),
        });
    } else if (path === `/v1/diagnoses/${other}`) {
      const foreign = report(other);
      foreign.instance_id = other;
      foreign.report!.checks[0]!.code = "FOREIGN_INSTANCE_SECRET";
      await route.fulfill({ json: foreign });
    } else if (
      path === `/v1/diagnoses/${failed}` ||
      path === `/v1/diagnoses/${expired}`
    ) {
      await route.fulfill({
        json: report(
          path.endsWith(failed) ? failed : expired,
          path.endsWith(failed) ? "FAILED" : "EXPIRED",
        ),
      });
    } else if (path === `/v1/diagnoses/${short}`) {
      shortReads++;
      await route.fulfill({
        json: {
          ...report(short, "PENDING"),
          deadline: new Date(Date.now() + 250).toISOString(),
        },
      });
    } else if (path === `/v1/diagnoses/${disconnected}`) {
      disconnectedReads++;
      if (disconnectedReads > 1) await route.abort("failed");
      else await route.fulfill({ json: report(disconnected, "PENDING") });
    } else {
      if (path.startsWith("/v1/operations/")) operationReads++;
      await route.fulfill({
        status: 404,
        contentType: "application/problem+json",
        json: { code: "NOT_FOUND" },
      });
    }
  });
  await page.goto("/");
  await page.getByLabel("项目 ID", { exact: true }).fill(project);
  await page.getByRole("button", { name: "进入项目", exact: true }).click();
  await page
    .getByRole("button", { name: "production-workspace", exact: true })
    .click();
  await page.getByRole("tab", { name: "健康诊断", exact: true }).click();
  const panel = page.getByRole("tabpanel");
  await expect(
    panel.getByRole("button", { name: "创建诊断报告", exact: true }),
  ).toBeDisabled();
  enabled = true;
  await page.getByRole("button", { name: "刷新", exact: true }).click();
  await expect(
    panel.getByRole("button", { name: "创建诊断报告", exact: true }),
  ).toBeEnabled();
  await expect(
    panel.getByLabel("包含操作证据", { exact: true }),
  ).not.toBeChecked();
  await expect(
    panel.getByLabel("包含执行证据", { exact: true }),
  ).not.toBeChecked();
  await panel.getByLabel("包含执行证据", { exact: true }).check();
  await panel
    .getByRole("button", { name: "创建诊断报告", exact: true })
    .click();
  await expect(
    panel.getByTestId("diagnosis-report").getByText("PENDING", { exact: true }),
  ).toBeVisible();
  await expect(panel.getByRole("table", { name: "诊断检查" })).toBeVisible();
  await expect(panel.getByText("REDACTED", { exact: true })).toBeVisible();
  await expect(panel.getByTestId("diagnosis-report")).toHaveAttribute(
    "data-instance-id",
    instance,
  );
  const terminalReads = reads;
  await page.waitForTimeout(2200);
  expect(reads).toBe(terminalReads);
  expect(posts).toBe(1);
  expect(operationReads).toBe(0);
  async function query(id: string) {
    await panel.getByLabel("诊断 ID", { exact: true }).fill(id);
    await panel.getByRole("button", { name: "查询报告", exact: true }).click();
  }
  await query(other);
  await expect(panel.getByRole("alert")).toHaveText("DIAGNOSIS_SCOPE_MISMATCH");
  await expect(
    page.getByText("FOREIGN_INSTANCE_SECRET", { exact: true }),
  ).toHaveCount(0);
  await expect(panel.getByTestId("diagnosis-report")).toHaveCount(0);
  await query(failed);
  await expect(panel.getByText("FAILED", { exact: true })).toBeVisible();
  await expect(
    panel.getByText("诊断失败 · OBSERVATION_FAILED", { exact: true }),
  ).toBeVisible();
  await query(expired);
  await expect(panel.getByText("EXPIRED", { exact: true })).toBeVisible();
  await expect(panel.getByRole("table", { name: "诊断检查" })).toHaveCount(0);
  await query(short);
  await expect(panel.getByText(/自动刷新已停止/)).toBeVisible();
  expect(shortReads).toBe(1);
  await query(disconnected);
  await expect(panel.getByRole("alert")).toHaveText("NETWORK_FAILURE");
  const networkReads = disconnectedReads;
  await page.waitForTimeout(2200);
  expect(disconnectedReads).toBe(networkReads);
  expect(posts).toBe(1);
  await page.getByRole("button", { name: "请求记录", exact: true }).click();
  await page.getByRole("button", { name: "打开报告", exact: true }).click();
  await expect(page.getByTestId("diagnosis-report")).toHaveAttribute(
    "data-diagnosis-id",
    diagnosis,
  );
  await expect(page.getByText("COMPLETE", { exact: true })).toBeVisible();
  expect(posts).toBe(1);
  expect(operationReads).toBe(0);
  hidden = true;
  await page.getByRole("button", { name: "刷新报告", exact: true }).click();
  await expect(page.getByRole("alert")).toHaveText("NOT_FOUND");
  await expect(page.getByTestId("diagnosis-report")).toHaveCount(0);
  hidden = false;
  await page.getByLabel("项目 ID", { exact: true }).fill(nextProject);
  await page.getByRole("button", { name: "进入项目", exact: true }).click();
  await expect(page.getByTestId("diagnosis-report")).toHaveCount(0);
  await page.getByRole("button", { name: "打开报告", exact: true }).click();
  await expect(page.getByRole("alert")).toHaveText("DIAGNOSIS_SCOPE_MISMATCH");
  await expect(page.getByRole("table", { name: "诊断检查" })).toHaveCount(0);
  expect(posts).toBe(1);
  expect(operationReads).toBe(0);
});
test("late automatic diagnosis response is rejected at the original deadline without inventing expiry", async ({
  page,
}) => {
  const diagnosis = "00000000-0000-4000-8000-00000000000c";
  const fixedTime = Date.now(),
    deadlineMillis = fixedTime + 60_000;
  const pending = {
    id: diagnosis,
    tenant_id: tenant,
    project_id: project,
    instance_id: instance,
    operation_id: project,
    requested_generation: 1,
    requested_launch_id: project,
    cluster_epoch: project,
    ruleset_version: "control-plane/v1",
    status: "PENDING",
    version: 1,
    created_at: new Date(fixedTime).toISOString(),
    deadline: new Date(deadlineMillis).toISOString(),
    retention_until: new Date(fixedTime + 86400_000).toISOString(),
    snapshot_at: null,
    completed_at: null,
    failure_code: null,
    report: null,
  };
  let posts = 0,
    reads = 0,
    clockCrossed = false;
  let releaseResponse!: () => void;
  const readyToReply = new Promise<void>((resolve) => {
    releaseResponse = resolve;
  });
  await page.clock.setFixedTime(fixedTime);
  try {
    await page.route("**/auth/session", (route) =>
      route.fulfill({ json: session }),
    );
    await page.route("**/v1/**", async (route) => {
      const request = route.request(),
        path = new URL(request.url()).pathname;
      if (path === "/v1/capabilities") await route.fulfill({ json: caps });
      else if (path === "/v1/instances")
        await route.fulfill({ json: { items: [resource], next_after: null } });
      else if (path === `/v1/instances/${instance}/details`)
        await route.fulfill({ json: detail });
      else if (
        path === `/v1/instances/${instance}/diagnoses` &&
        request.method() === "POST"
      ) {
        posts++;
        await route.fulfill({
          status: 202,
          json: {
            resource: pending,
            operation: { id: project, status: "QUEUED" },
            idempotency_expires_at: now,
          },
        });
      } else if (path === `/v1/diagnoses/${diagnosis}`) {
        reads++;
        if (reads === 1) await route.fulfill({ json: pending });
        else {
          expect(reads).toBe(2);
          await readyToReply;
          expect(await page.evaluate(() => Date.now())).toBeLessThan(
            deadlineMillis,
          );
          // Fixed Date only changes wall time: the automatic request's native
          // AbortSignal.timeout still has almost 60 real seconds remaining.
          await page.clock.setFixedTime(deadlineMillis + 1);
          clockCrossed = true;
          await route.fulfill({
            json: {
              ...pending,
              status: "COMPLETE",
              version: 2,
              snapshot_at: now,
              completed_at: now,
              report: {
                overall: "UNKNOWN",
                checks: [
                  {
                    rule: "late-response",
                    status: "UNKNOWN",
                    code: "LATE_RESPONSE_MUST_NOT_RENDER",
                    evidence_scope: "INSTANCE",
                    evidence: [],
                    recommendation: "READ_INSTANCE_STATE",
                  },
                ],
              },
            },
          });
        }
      } else
        await route.fulfill({
          status: 404,
          contentType: "application/problem+json",
          json: { code: "NOT_FOUND" },
        });
    });
    await page.goto("/");
    await page.getByLabel("项目 ID", { exact: true }).fill(project);
    await page.getByRole("button", { name: "进入项目", exact: true }).click();
    await page
      .getByRole("button", { name: "production-workspace", exact: true })
      .click();
    await page.getByRole("tab", { name: "健康诊断", exact: true }).click();
    const panel = page.getByRole("tabpanel");
    await panel
      .getByRole("button", { name: "创建诊断报告", exact: true })
      .click();
    await expect(
      panel
        .getByTestId("diagnosis-report")
        .getByText("PENDING", { exact: true }),
    ).toBeVisible();
    const lateResponse = page.waitForResponse(
      (response) =>
        new URL(response.url()).pathname === `/v1/diagnoses/${diagnosis}` &&
        reads === 2,
    );
    releaseResponse();
    const lateReply = await lateResponse;
    expect(lateReply.status()).toBe(200);
    await expect(panel.getByRole("alert")).toHaveText(
      "DIAGNOSIS_REFRESH_DEADLINE",
    );
    expect(clockCrossed).toBe(true);
    await expect(panel.getByTestId("diagnosis-report")).toHaveCount(0);
    await expect(
      panel.getByText("LATE_RESPONSE_MUST_NOT_RENDER", { exact: true }),
    ).toHaveCount(0);
    await expect(panel.getByText("COMPLETE", { exact: true })).toHaveCount(0);
    await expect(panel.getByText("EXPIRED", { exact: true })).toHaveCount(0);
    await page.waitForTimeout(2200);
    expect(reads).toBe(2);
    expect(posts).toBe(1);
  } finally {
    releaseResponse();
    await page.clock.setSystemTime(Date.now());
  }
});
test("cookie event hints connect only explicitly, preserve resume position and clear rejected or changed scope", async ({
  page,
  baseURL,
}) => {
  const liveSession = {
    ...session,
    absolute_expires_at: new Date(Date.now() + 3600_000).toISOString(),
    idle_expires_at: new Date(Date.now() + 3600_000).toISOString(),
  };
  let phase: "baseline" | "batch" | "pending" | "denied" | "fresh" | "reset" =
      "baseline",
    resetStatus = 410,
    snapshotReads = 0,
    posts = 0,
    authorized = true;
  const streams: {
    cursor: string | undefined;
    project: string | null;
    instance: string | null;
  }[] = [];
  let releasePending!: () => void;
  const pendingReply = new Promise<void>((resolve) => {
    releasePending = resolve;
  });
  const frame = (type: string, cursor: string | null, data: unknown) =>
    `event: ${type}\n${cursor ? `id: ${cursor}\n` : ""}data: ${JSON.stringify(data)}\n\n`;
  const checkpoint = (cursor: string, sequence = "0") =>
    frame("stream.checkpoint", cursor, { sequence });
  const eventId = (index: number) =>
    `00000000-0000-4000-8000-${String(100 + index).padStart(12, "0")}`;
  const domain = (index: number, cursor: string) =>
    frame("domain.event", cursor, {
      sequence: String(index),
      event: {
        id: eventId(index),
        tenant_id: tenant,
        project_id: project,
        aggregate_id: instance,
        aggregate_version: 1,
        event_type: `fixture.event.${index}`,
        schema_version: 1,
        operation_id: project,
        request_id: principal,
        occurred_at: now,
      },
    });
  await page.context().addCookies([
    {
      name: "event_fixture_session",
      value: "COOKIE_ONLY",
      url: baseURL!,
      httpOnly: true,
    },
  ]);
  await page.route("**/auth/session", (route) =>
    route.fulfill({
      status: authorized ? 200 : 401,
      json: authorized ? liveSession : { code: "BROWSER_LOGIN_REQUIRED" },
    }),
  );
  await page.route("**/auth/logout", async (route) => {
    authorized = false;
    await route.fulfill({ status: 204 });
  });
  await page.route("**/v1/**", async (route) => {
    const request = route.request(),
      url = new URL(request.url());
    if (request.method() === "POST") posts++;
    if (url.pathname === "/v1/capabilities")
      await route.fulfill({ json: caps });
    else if (url.pathname === "/v1/instances")
      await route.fulfill({ json: { items: [resource], next_after: null } });
    else if (url.pathname === `/v1/instances/${instance}/details`)
      await route.fulfill({ json: detail });
    else if (url.pathname === "/v1/events/stream") {
      expect(request.method()).toBe("GET");
      expect(request.headers()["authorization"]).toBeUndefined();
      expect(request.headers()["cookie"]).toContain(
        "event_fixture_session=COOKIE_ONLY",
      );
      expect(request.headers()["x-tenant-id"]).toBe(tenant);
      expect(request.headers()["accept"]).toBe("text/event-stream");
      expect([...url.searchParams.keys()].sort()).toEqual(
        url.searchParams.has("instance_id")
          ? ["instance_id", "project_id"]
          : ["project_id"],
      );
      streams.push({
        cursor: request.headers()["last-event-id"],
        project: url.searchParams.get("project_id"),
        instance: url.searchParams.get("instance_id"),
      });
      if (phase === "pending") {
        await pendingReply;
        try {
          await route.fulfill({
            contentType: "text/event-stream",
            body: checkpoint("UNCONSUMED", "51"),
          });
        } catch {
          /* The explicit stop has cancelled this request. */
        }
      } else if (phase === "reset")
        await route.fulfill({
          status: resetStatus,
          contentType: "application/problem+json",
          json: {
            code:
              resetStatus === 400
                ? "INVALID_CURSOR"
                : resetStatus === 409
                  ? "EVENT_CURSOR_AHEAD"
                  : "EVENT_CURSOR_EXPIRED",
          },
        });
      else {
        const body =
          phase === "baseline"
            ? checkpoint("BASELINE")
            : phase === "batch"
              ? checkpoint("BASELINE") +
                Array.from({ length: 51 }, (_, index) =>
                  domain(index + 1, `POSITION_${index + 1}`),
                ).join("") +
                domain(51, "POSITION_51_DUPLICATE")
              : phase === "denied"
                ? checkpoint("POSITION_51_DUPLICATE", "51") +
                  frame("stream.error", null, {
                    code: "RESOURCE_NOT_FOUND",
                    retryable: false,
                    request_id: principal,
                  })
                : checkpoint("FRESH_BASELINE", "51") +
                  domain(52, "POSITION_52");
        await route.fulfill({ contentType: "text/event-stream", body });
      }
    } else if (url.pathname === "/v1/events") {
      snapshotReads++;
      await route.fulfill({
        status: 503,
        contentType: "application/problem+json",
        json: { code: "DEPENDENCY_UNAVAILABLE" },
      });
    } else
      await route.fulfill({
        status: 404,
        contentType: "application/problem+json",
        json: { code: "RESOURCE_NOT_FOUND" },
      });
  });
  try {
    await page.goto("/");
    await page.getByLabel("项目 ID", { exact: true }).fill(project);
    await page.getByRole("button", { name: "进入项目", exact: true }).click();
    await page
      .getByRole("button", { name: "操作 / 事件 / 审计", exact: true })
      .click();
    await page
      .getByRole("combobox", { name: "记录类型", exact: true })
      .selectOption("events");
    const live = page.getByTestId("event-stream-panel"),
      table = live.getByRole("table", { name: "最近实时事件", exact: true });
    await expect(live).toHaveAttribute("data-state", "IDLE");
    await expect(
      page.getByRole("alert").filter({ hasText: "DEPENDENCY_UNAVAILABLE" }),
    ).toBeVisible();
    expect(streams).toHaveLength(0);
    await live
      .getByRole("button", { name: "开启实时提示", exact: true })
      .click();
    await expect(live).toHaveAttribute("data-state", "STOPPED");
    await expect(live).toHaveAttribute("data-cursor", "BASELINE");
    await expect(live.getByText(/基线已确认/)).toBeVisible();
    expect(streams[0]).toEqual({ cursor: undefined, project, instance: null });
    const snapshotBefore = snapshotReads;
    await page
      .getByRole("button", { name: "读取最新快照", exact: true })
      .click();
    await expect.poll(() => snapshotReads).toBeGreaterThan(snapshotBefore);
    expect(streams).toHaveLength(1);
    await expect(live).toHaveAttribute("data-cursor", "BASELINE");
    phase = "batch";
    await live
      .getByRole("button", { name: "从原断点重连", exact: true })
      .click();
    await expect(live).toHaveAttribute("data-state", "STOPPED");
    await expect(live).toHaveAttribute("data-cursor", "POSITION_51_DUPLICATE");
    expect(streams[1]!.cursor).toBe("BASELINE");
    await expect(table.locator("tbody tr")).toHaveCount(50);
    await expect(table.locator(`[data-event-id="${eventId(1)}"]`)).toHaveCount(
      0,
    );
    await expect(table.locator(`[data-event-id="${eventId(51)}"]`)).toHaveCount(
      1,
    );
    await expect(
      table.getByText("fixture.event.51", { exact: true }),
    ).toBeVisible();
    expect(
      await page.evaluate(() => JSON.stringify({ ...localStorage })),
    ).not.toMatch(/BASELINE|POSITION_|fixture\.event/);
    phase = "pending";
    await live
      .getByRole("button", { name: "从原断点重连", exact: true })
      .click();
    await expect(live).toHaveAttribute("data-state", "CONNECTING");
    await expect.poll(() => streams.length).toBe(3);
    await live
      .getByRole("button", { name: "停止实时提示", exact: true })
      .click();
    releasePending();
    await expect(
      live.getByRole("button", { name: "从原断点重连", exact: true }),
    ).toBeEnabled();
    await expect(live).toHaveAttribute("data-cursor", "POSITION_51_DUPLICATE");
    await expect(table.locator("tbody tr")).toHaveCount(50);
    phase = "denied";
    await live
      .getByRole("button", { name: "从原断点重连", exact: true })
      .click();
    await expect(live).toHaveAttribute("data-state", "DENIED");
    await expect(live).toHaveAttribute("data-cursor", "");
    await expect(table.locator("tbody tr")).toHaveCount(0);
    await expect(live.getByRole("alert")).toHaveText(
      new RegExp(`RESOURCE_NOT_FOUND.*${principal}`),
    );
    const deniedConnections = streams.length;
    phase = "fresh";
    await page
      .getByRole("button", { name: "读取最新快照", exact: true })
      .click();
    expect(streams).toHaveLength(deniedConnections);
    await live
      .getByRole("button", { name: "重建实时基线", exact: true })
      .click();
    await expect(live).toHaveAttribute("data-cursor", "POSITION_52");
    expect(streams.at(-1)!.cursor).toBeUndefined();
    await expect(table.locator("tbody tr")).toHaveCount(1);
    for (const status of [400, 409, 410]) {
      phase = "reset";
      resetStatus = status;
      await live
        .getByRole("button", { name: "从原断点重连", exact: true })
        .click();
      await expect(live).toHaveAttribute("data-state", "RESET_REQUIRED");
      await expect(live).toHaveAttribute("data-cursor", "");
      await expect(table.locator("tbody tr")).toHaveCount(0);
      const beforeRebuild = streams.length;
      phase = "fresh";
      await live
        .getByRole("button", { name: "重建实时基线", exact: true })
        .click();
      await expect(live).toHaveAttribute("data-cursor", "POSITION_52");
      expect(streams).toHaveLength(beforeRebuild + 1);
      expect(streams.at(-1)!.cursor).toBeUndefined();
    }
    const beforeScope = streams.length;
    await page
      .getByRole("combobox", { name: "记录类型", exact: true })
      .selectOption("operations");
    await expect(live).toHaveCount(0);
    await page
      .getByRole("combobox", { name: "记录类型", exact: true })
      .selectOption("events");
    await expect(live).toHaveAttribute("data-state", "IDLE");
    await expect(live).toHaveAttribute("data-cursor", "");
    await expect(table.locator("tbody tr")).toHaveCount(0);
    expect(streams).toHaveLength(beforeScope);
    await page.getByRole("button", { name: "实例", exact: true }).click();
    await page
      .getByRole("button", { name: "production-workspace", exact: true })
      .click();
    await page
      .getByRole("button", { name: "操作 / 事件 / 审计", exact: true })
      .click();
    await page
      .getByRole("combobox", { name: "记录类型", exact: true })
      .selectOption("events");
    await expect(live).toHaveAttribute("data-cursor", "");
    expect(streams).toHaveLength(beforeScope);
    await live
      .getByRole("button", { name: "开启实时提示", exact: true })
      .click();
    await expect(live).toHaveAttribute("data-cursor", "POSITION_52");
    expect(streams.at(-1)!.instance).toBe(instance);
    await page
      .getByLabel("项目 ID", { exact: true })
      .fill("00000000-0000-4000-8000-00000000000d");
    await page.getByRole("button", { name: "进入项目", exact: true }).click();
    await page
      .getByRole("combobox", { name: "记录类型", exact: true })
      .selectOption("events");
    await expect(live).toHaveAttribute("data-state", "IDLE");
    await expect(table.locator("tbody tr")).toHaveCount(0);
    await page.getByRole("button", { name: "退出", exact: true }).click();
    await expect(live).toHaveCount(0);
    expect(posts).toBe(0);
  } finally {
    releasePending();
  }
});
