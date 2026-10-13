import { test, expect } from "@playwright/test";
import type { Page, Route } from "@playwright/test";
import {
  tenant,
  project,
  instance,
  principal,
  session,
  resource,
  caps,
  detail,
} from "./browser-fixtures.ts";

import { automationCapability } from "./automation-fixture.ts";

const policyId = "00000000-0000-4000-8000-000000000010";
const runId = "00000000-0000-4000-8000-000000000011";
const future = (seconds: number) =>
  new Date(Date.now() + seconds * 1000).toISOString();
const policy = () => ({
  id: policyId,
  tenant_id: tenant,
  project_id: project,
  instance_id: instance,
  workspace_id: project,
  creator_principal_id: principal,
  name: "finite-renewal-policy",
  action_kind: "RENEW",
  trigger_kind: "ONCE",
  scheduled_at: future(1800),
  cron_expression: null,
  event_type: null,
  event_aggregate_id: null,
  next_due_at: future(1800),
  status: "ACTIVE",
  version: 1,
  run_budget: 1,
  emitted_runs: 0,
  minimum_interval_seconds: 60,
  grace_seconds: 60,
  delegation_expires_at: future(3600),
  delegation_revoked_at: null as string | null,
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
});
const run = () => ({
  id: runId,
  tenant_id: tenant,
  project_id: project,
  automation_id: policyId,
  version: 1,
  automation_version: 1,
  scheduled_for: future(1800),
  source_event_id: null,
  source_event_sequence: null,
  skipped_through: null,
  operation_kind: "RENEW",
  expected_resource_version: 7,
  expected_generation: 1,
  status: "OUTCOME_UNKNOWN",
  operation_id: null,
  failure_code: null,
  deadline: future(3600),
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  completed_at: null,
});
async function reply(
  route: Route,
  value: unknown,
  status = 200,
  etag?: string,
) {
  await route.fulfill({
    status,
    contentType:
      status >= 400 ? "application/problem+json" : "application/json",
    headers: etag ? { etag } : {},
    body: JSON.stringify(value),
  });
}
async function fixture(page: Page, handle: (route: Route) => Promise<boolean>) {
  await page.route("**/auth/session", (route) => reply(route, session));
  await page.route("**/v1/**", async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    expect(request.headers()["authorization"]).toBeUndefined();
    expect(request.headers()["x-tenant-id"]).toBe(tenant);
    if (request.method() !== "GET")
      expect(request.headers()["x-csrf-token"]).toBe(session.csrf_token);
    if (await handle(route)) return;
    if (path === "/v1/capabilities") {
      await reply(route, {
        ...caps,
        automation: automationCapability,
        api_features: {
          ...caps.api_features,
          scheduled_tasks: true,
          event_automation: true,
        },
        limits: { ttl_seconds: { minimum: 60, default: 300, maximum: 86400 } },
      });
    } else if (path === "/v1/instances")
      await reply(route, { items: [resource], next_after: null });
    else if (path === `/v1/instances/${instance}/details`)
      await reply(route, detail);
    else if (path === `/v1/instances/${instance}`)
      await reply(route, resource, 200, '"7"');
    else await reply(route, { code: "RESOURCE_NOT_FOUND" }, 404);
  });
}
async function enter(page: Page) {
  await page.goto("/");
  await page.getByLabel("项目 ID", { exact: true }).fill(project);
  await page.getByRole("button", { name: "进入项目", exact: true }).click();
  await page.getByRole("button", { name: resource.name, exact: true }).click();
  await page.getByRole("tab", { name: "定时与自动化", exact: true }).click();
  await expect(page.getByTestId("automation-panel")).toHaveAttribute(
    "data-instance-id",
    instance,
  );
}
async function fillRenewal(page: Page) {
  const form = page.getByTestId("automation-create");
  await form
    .getByLabel("策略名称", { exact: true })
    .fill("finite-renewal-policy");
  await form.getByLabel("未来动作", { exact: true }).selectOption("RENEW");
  await form.getByLabel("触发方式", { exact: true }).selectOption("ONCE");
  await form
    .getByLabel("单次执行时间（UTC）", { exact: true })
    .fill(future(1800));
  await form
    .getByLabel("委派到期时间（UTC）", { exact: true })
    .fill(future(3600));
  await form.getByLabel("运行次数上限", { exact: true }).fill("1");
  await form.getByLabel("最小间隔（秒）", { exact: true }).fill("60");
  await form.getByLabel("允许延迟（秒）", { exact: true }).fill("60");
  await form.getByLabel("计算租期（秒）", { exact: true }).fill("600");
  await form.locator('input[name="authorize"]').check();
  await form
    .getByRole("button", { name: "预览自动化授权", exact: true })
    .click();
  await expect(page.getByTestId("automation-consent")).toBeVisible();
}
async function confirm(page: Page, button: string, target: string) {
  await page.getByRole("button", { name: button, exact: true }).click();
  const dialog = page
    .getByRole("dialog")
    .filter({ has: page.getByLabel(`输入 ${target} 确认`, { exact: true }) });
  await dialog.getByLabel(`输入 ${target} 确认`, { exact: true }).fill(target);
  await dialog.getByRole("button", { name: "确认提交", exact: true }).click();
}

test("automation creation uses finite authorization and a fresh ETag; lost receipt reload requires identical original payload and key", async ({
  page,
}) => {
  const current = policy();
  let invalidCapability = false;
  const attempts: { key: string; etag: string; body: unknown }[] = [];
  await fixture(page, async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    if (path === "/v1/capabilities" && invalidCapability) {
      await reply(route, {
        ...caps,
        automation: null,
        api_features: {
          ...caps.api_features,
          scheduled_tasks: true,
          event_automation: true,
        },
        limits: {},
      });
    } else if (path === "/v1/automations") {
      await reply(route, {
        items: attempts.length ? [current] : [],
        next_cursor: null,
        cutoff: new Date().toISOString(),
      });
    } else if (path === `/v1/instances/${instance}/automations`) {
      expect(request.method()).toBe("POST");
      const value = {
        key: request.headers()["idempotency-key"]!,
        etag: request.headers()["if-match"]!,
        body: request.postDataJSON(),
      };
      attempts.push(value);
      expect(value.etag).toBe('"7"');
      expect(value.key).toMatch(/^[0-9a-f-]{36}$/);
      expect(value.body).toMatchObject({
        action: { kind: "RENEW", ttl_seconds: 600 },
        trigger: { kind: "ONCE" },
        run_budget: 1,
        minimum_interval_seconds: 60,
        grace_seconds: 60,
      });
      if (attempts.length === 1) await route.abort("connectionfailed");
      else
        await reply(
          route,
          { resource: current, idempotency_expires_at: future(3600) },
          201,
          '"1"',
        );
    } else if (path === `/v1/automations/${policyId}`)
      await reply(route, current, 200, '"1"');
    else if (path === `/v1/automations/${policyId}/runs`)
      await reply(route, {
        items: [],
        next_cursor: null,
        cutoff: new Date().toISOString(),
      });
    else return false;
    return true;
  });
  await enter(page);
  await fillRenewal(page);
  expect(attempts).toHaveLength(0);
  await confirm(page, "创建自动化策略", instance);
  await expect.poll(() => attempts.length).toBe(1);
  await expect(page.getByRole("dialog").getByRole("alert")).toContainText(
    "NETWORK_FAILURE",
  );
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "取消", exact: true })
    .click();
  await page.getByRole("button", { name: "请求记录", exact: true }).click();
  await expect(page.getByText("UNKNOWN", { exact: true })).toBeVisible();
  const stored = await page.evaluate(() =>
    JSON.parse(localStorage.getItem("sandbox.console.intents.v1") ?? "[]"),
  );
  expect(stored).toHaveLength(1);
  expect(stored[0].body).toBeNull();
  expect(stored[0].bodySha256).toMatch(/^[a-f0-9]{64}$/);
  expect(JSON.stringify(stored)).not.toContain("finite-renewal-policy");
  invalidCapability = true;
  await page.getByRole("button", { name: "刷新", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "显式重试原请求", exact: true }),
  ).toBeVisible();
  expect(attempts).toHaveLength(1);
  await page.reload();
  await page.getByLabel("项目 ID", { exact: true }).fill(project);
  await page.getByRole("button", { name: "进入项目", exact: true }).click();
  await page.getByRole("button", { name: "请求记录", exact: true }).click();
  expect(attempts).toHaveLength(1);
  const payload = page.getByLabel("完全相同的原自动化创建 JSON", {
    exact: true,
  });
  await payload.fill(
    JSON.stringify({
      ...(attempts[0]!.body as object),
      name: "replacement-is-forbidden",
    }),
  );
  await page
    .getByRole("button", { name: "恢复原请求参数", exact: true })
    .click();
  await expect(
    page.getByRole("alert").filter({ hasText: "INTENT_BODY_MISMATCH" }),
  ).toBeVisible();
  expect(attempts).toHaveLength(1);
  await payload.fill(JSON.stringify(attempts[0]!.body));
  await page
    .getByRole("button", { name: "恢复原请求参数", exact: true })
    .click();
  expect(attempts).toHaveLength(1);
  await confirm(page, "显式重试原请求", attempts[0]!.key);
  await expect(page.getByText("ACCEPTED", { exact: true })).toBeVisible();
  expect(attempts).toHaveLength(2);
  expect(attempts[1]).toEqual(attempts[0]);
  const final = await page.evaluate(() =>
    JSON.parse(localStorage.getItem("sandbox.console.intents.v1") ?? "[]"),
  );
  expect(final[0].resourceId).toBe(policyId);
  expect(final[0].body).toBeNull();
});

test("policy management uses each fresh version; run metadata does not require operation reads and revocation clears draft and evidence", async ({
  page,
}) => {
  const current = policy(),
    original = run();
  let denied = false;
  const actions: { path: string; body: unknown; etag: string; key: string }[] =
    [];
  const operationReads: string[] = [];
  await fixture(page, async (route) => {
    const request = route.request(),
      url = new URL(request.url()),
      path = url.pathname;
    if (path.startsWith("/v1/operations")) {
      operationReads.push(path);
      await reply(route, { code: "RESOURCE_NOT_FOUND" }, 404);
    } else if (
      path.startsWith("/v1/automations") ||
      path.startsWith("/v1/automation-runs")
    ) {
      if (denied) {
        await reply(route, { code: "RESOURCE_NOT_FOUND" }, 404);
        return true;
      }
      if (path === "/v1/automations") {
        expect(url.searchParams.get("project_id")).toBe(project);
        expect(url.searchParams.get("instance_id")).toBe(instance);
        await reply(route, {
          items: [current],
          next_cursor: null,
          cutoff: new Date().toISOString(),
        });
      } else if (path === `/v1/automations/${policyId}`)
        await reply(route, current, 200, `"${current.version}"`);
      else if (path === `/v1/automations/${policyId}/runs`)
        await reply(route, {
          items: [original],
          next_cursor: null,
          cutoff: new Date().toISOString(),
        });
      else if (path === `/v1/automation-runs/${runId}`)
        await reply(route, original, 200, '"1"');
      else if (/\/actions\/(pause|resume|revoke)$/.test(path)) {
        const action = path.split("/").at(-1)!;
        expect(request.method()).toBe("POST");
        expect(request.postDataJSON()).toEqual({});
        expect(request.headers()["if-match"]).toBe(`"${current.version}"`);
        actions.push({
          path,
          body: request.postDataJSON(),
          etag: request.headers()["if-match"]!,
          key: request.headers()["idempotency-key"]!,
        });
        current.status =
          action === "pause"
            ? "PAUSED"
            : action === "resume"
              ? "ACTIVE"
              : "REVOKED";
        current.version++;
        if (action === "revoke")
          current.delegation_revoked_at = new Date().toISOString();
        await reply(
          route,
          { resource: current, idempotency_expires_at: future(3600) },
          200,
          `"${current.version}"`,
        );
      } else await reply(route, { code: "RESOURCE_NOT_FOUND" }, 404);
    } else return false;
    return true;
  });
  await enter(page);
  await page
    .getByRole("button", { name: `查看策略 ${policyId}`, exact: true })
    .click();
  await expect(page.getByTestId("automation-detail")).toHaveAttribute(
    "data-status",
    "ACTIVE",
  );
  await confirm(page, "暂停策略", instance);
  await expect(page.getByTestId("automation-detail")).toHaveAttribute(
    "data-status",
    "PAUSED",
  );
  await confirm(page, "恢复策略", instance);
  await expect(page.getByTestId("automation-detail")).toHaveAttribute(
    "data-status",
    "ACTIVE",
  );
  await page.getByLabel("原运行 ID", { exact: true }).fill(runId);
  await page.getByRole("button", { name: "查询原运行", exact: true }).click();
  await expect(page.getByTestId("automation-run-detail")).toContainText(
    "OUTCOME_UNKNOWN",
  );
  expect(operationReads).toEqual([]);
  await confirm(page, "永久撤销策略", instance);
  await expect(page.getByTestId("automation-detail")).toHaveAttribute(
    "data-status",
    "REVOKED",
  );
  expect(actions.map((value) => value.etag)).toEqual(['"1"', '"2"', '"3"']);
  expect(new Set(actions.map((value) => value.key)).size).toBe(3);
  await page
    .getByTestId("automation-create")
    .getByLabel("策略名称", { exact: true })
    .fill("discard-draft-on-denial");
  denied = true;
  await page.getByRole("button", { name: "重新读取策略", exact: true }).click();
  await expect(page.getByTestId("automation-detail")).toHaveCount(0);
  await expect(page.getByTestId("automation-run-detail")).toHaveCount(0);
  await expect(page.getByTestId("automation-create")).toHaveCount(0);
  await expect(
    page
      .getByTestId("automation-panel")
      .getByRole("alert")
      .filter({ hasText: "RESOURCE_NOT_FOUND" }),
  ).toBeVisible();
  denied = false;
  await page.getByRole("button", { name: "重新读取策略", exact: true }).click();
  await expect(page.getByTestId("automation-detail")).toHaveAttribute(
    "data-status",
    "REVOKED",
  );
  await expect(
    page
      .getByTestId("automation-create")
      .getByLabel("策略名称", { exact: true }),
  ).toHaveValue("");
});

test("cross-instance policy responses and disabled capabilities cannot expose or submit automation data", async ({
  page,
}) => {
  let enabled = true,
    writes = 0,
    reads = 0;
  let malformed: "partial" | "null" | null = null;
  const other = {
    ...policy(),
    instance_id: project,
    name: "wrong-instance-private-name",
  };
  await fixture(page, async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    if (path === "/v1/capabilities" && malformed)
      await reply(
        route,
        malformed === "partial" ? { project_id: project } : null,
      );
    else if (path === "/v1/capabilities")
      await reply(route, {
        ...caps,
        automation: automationCapability,
        api_features: {
          ...caps.api_features,
          scheduled_tasks: enabled,
          event_automation: enabled,
        },
        limits: { ttl_seconds: { minimum: 60, default: 300, maximum: 86400 } },
      });
    else if (path === "/v1/automations") {
      reads++;
      await reply(route, {
        items: [other],
        next_cursor: null,
        cutoff: new Date().toISOString(),
      });
    } else if (request.method() !== "GET" && path.includes("automation")) {
      writes++;
      await reply(route, {}, 503);
    } else return false;
    return true;
  });
  await enter(page);
  await expect(
    page.getByTestId("automation-panel").getByRole("alert"),
  ).toBeVisible();
  await expect(
    page.getByText("wrong-instance-private-name", { exact: true }),
  ).toHaveCount(0);
  enabled = false;
  await page.getByRole("button", { name: "刷新详情", exact: true }).click();
  await expect(page.getByTestId("automation-create")).toHaveCount(0);
  for (const value of ["partial", "null"] as const) {
    malformed = value;
    await page.getByRole("button", { name: "刷新详情", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "实例控制台", exact: true }),
    ).toBeVisible();
    await expect(page.getByTestId("automation-create")).toHaveCount(0);
  }
  expect(writes).toBe(0);
  expect(reads).toBeGreaterThan(0);
});

test("unknown creation contracts clear draft consent while preserving scoped reads and safety actions", async ({
  page,
}) => {
  const current = policy();
  let contractValue: unknown = automationCapability;
  let creationWrites = 0;
  const safetyActions: string[] = [];
  await fixture(page, async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    if (path === "/v1/capabilities") {
      await reply(route, {
        ...caps,
        automation: contractValue,
        api_features: {
          ...caps.api_features,
          scheduled_tasks: true,
          event_automation: true,
        },
        limits: { ttl_seconds: { minimum: 60, default: 300, maximum: 86400 } },
      });
    } else if (path === "/v1/automations") {
      await reply(route, {
        items: [current],
        next_cursor: null,
        cutoff: new Date().toISOString(),
      });
    } else if (path === `/v1/automations/${policyId}`) {
      await reply(route, current, 200, `"${current.version}"`);
    } else if (path === `/v1/automations/${policyId}/runs`) {
      await reply(route, {
        items: [],
        next_cursor: null,
        cutoff: new Date().toISOString(),
      });
    } else if (path === `/v1/instances/${instance}/automations`) {
      creationWrites++;
      await reply(route, {}, 503);
    } else if (/\/actions\/(pause|resume|revoke)$/.test(path)) {
      const action = path.split("/").at(-1)!;
      expect(request.headers()["if-match"]).toBe(`"${current.version}"`);
      expect(request.postDataJSON()).toEqual({});
      safetyActions.push(action);
      current.status = action === "pause" ? "PAUSED" : "REVOKED";
      current.version++;
      if (action === "revoke")
        current.delegation_revoked_at = new Date().toISOString();
      await reply(
        route,
        { resource: current, idempotency_expires_at: future(3600) },
        200,
        `"${current.version}"`,
      );
    } else return false;
    return true;
  });
  await enter(page);
  await page
    .getByRole("button", { name: `查看策略 ${policyId}`, exact: true })
    .click();
  const bad = [
    null,
    { ...automationCapability, schema_version: 2 },
    {
      ...automationCapability,
      limits: {
        ...automationCapability.limits,
        run_budget: { minimum: 1, maximum: 10001 },
      },
    },
    { ...automationCapability, skipped_runs_consume_budget: "true" },
  ];
  for (const value of bad) {
    await fillRenewal(page);
    contractValue = value;
    await page.getByRole("button", { name: "刷新详情", exact: true }).click();
    await expect(page.getByTestId("automation-create")).toHaveCount(0);
    await expect(page.getByTestId("automation-consent")).toHaveCount(0);
    await expect(
      page.getByText(/自动化创建合同缺失、不完整或版本不受支持/),
    ).toBeVisible();
    await expect(page.getByTestId("automation-detail")).toHaveAttribute(
      "data-status",
      "ACTIVE",
    );
    await expect(
      page.getByRole("button", { name: "暂停策略", exact: true }),
    ).toBeEnabled();
    await expect(
      page.getByRole("button", { name: "永久撤销策略", exact: true }),
    ).toBeEnabled();
    expect(creationWrites).toBe(0);
    contractValue = automationCapability;
    await page.getByRole("button", { name: "刷新详情", exact: true }).click();
    await expect(
      page
        .getByTestId("automation-create")
        .getByLabel("策略名称", { exact: true }),
    ).toHaveValue("");
    await expect(page.getByTestId("automation-consent")).toHaveCount(0);
  }
  contractValue = null;
  await page.getByRole("button", { name: "刷新详情", exact: true }).click();
  await confirm(page, "暂停策略", instance);
  await expect(page.getByTestId("automation-detail")).toHaveAttribute(
    "data-status",
    "PAUSED",
  );
  await expect(
    page.getByRole("button", { name: "恢复策略", exact: true }),
  ).toBeDisabled();
  await confirm(page, "永久撤销策略", instance);
  await expect(page.getByTestId("automation-detail")).toHaveAttribute(
    "data-status",
    "REVOKED",
  );
  expect(safetyActions).toEqual(["pause", "revoke"]);
  expect(creationWrites).toBe(0);
});
