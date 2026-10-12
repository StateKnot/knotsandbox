import { test, expect } from "@playwright/test";
import type { Page, Route } from "@playwright/test";
import {
  caps,
  session,
  tenant,
  project,
  instance,
  resource,
} from "./browser-fixtures.ts";
import { notification } from "./notification-fixture.ts";

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
async function fixture(
  page: Page,
  handle: (route: Route) => Promise<boolean>,
  feature: boolean | undefined = true,
) {
  await page.route("**/auth/session", (route) => reply(route, session));
  await page.route("**/v1/**", async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    expect(request.headers()["authorization"]).toBeUndefined();
    expect(request.headers()["x-tenant-id"]).toBe(tenant);
    if (request.method() !== "GET")
      expect(request.headers()["x-csrf-token"]).toBe(session.csrf_token);
    if (await handle(route)) return;
    if (path === "/v1/capabilities")
      await reply(route, {
        ...caps,
        automation: null,
        api_features: {
          ...caps.api_features,
          ...(feature === undefined
            ? {}
            : { automation_notifications: feature }),
        },
      });
    else if (path === "/v1/instances")
      await reply(route, { items: [resource], next_after: null });
    else await reply(route, { code: "RESOURCE_NOT_FOUND" }, 404);
  });
}
async function enter(page: Page) {
  await page.goto("/");
  await page.getByLabel("项目 ID", { exact: true }).fill(project);
  await page.getByRole("button", { name: "进入项目", exact: true }).click();
  await page.getByRole("button", { name: "自动化通知", exact: true }).click();
}
async function open(page: Page) {
  await page
    .getByRole("button", { name: `查看通知 ${notification.id}`, exact: true })
    .click();
  await expect(
    page.getByTestId("automation-notification-detail"),
  ).toHaveAttribute("data-notification-id", notification.id);
}
async function acknowledge(page: Page) {
  await page
    .getByLabel("输入通知 ID 确认", { exact: true })
    .fill(notification.id);
  await page.getByRole("button", { name: "确认通知已阅", exact: true }).click();
}

async function retryOriginal(page: Page, key: string) {
  await page
    .getByRole("button", { name: "显式重试原请求", exact: true })
    .click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel(`输入 ${key} 确认`, { exact: true }).fill(key);
  await dialog.getByRole("button", { name: "确认提交", exact: true }).click();
}

test("inbox pagination binds project and optional instance; explicit acknowledgement changes only the notice", async ({
  page,
}) => {
  const current = structuredClone(notification),
    queries: URL[] = [],
    actions: string[] = [];
  let ackWrites = 0;
  await fixture(page, async (route) => {
    const request = route.request(),
      url = new URL(request.url()),
      path = url.pathname;
    if (path === "/v1/automation-notifications") {
      queries.push(url);
      expect(url.searchParams.get("project_id")).toBe(project);
      expect(url.searchParams.get("limit")).toBe("20");
      await reply(route, {
        items: url.searchParams.has("cursor") ? [] : [current],
        next_cursor: url.searchParams.has("cursor")
          ? null
          : "same.cutoff.cursor",
        cutoff: current.created_at,
      });
    } else if (path === `/v1/automation-notifications/${notification.id}`)
      await reply(route, current, 200, `"${current.version}"`);
    else if (
      path ===
      `/v1/automation-notifications/${notification.id}/actions/acknowledge`
    ) {
      ackWrites++;
      expect(request.headers()["if-match"]).toBe('"1"');
      expect(request.headers()["idempotency-key"]).toMatch(/^[0-9a-f-]{36}$/);
      expect(request.postDataJSON()).toEqual({});
      current.version = 2;
      current.acknowledged_at = new Date().toISOString();
      current.acknowledged_by = session.principal_id;
      await reply(
        route,
        {
          resource: current,
          idempotency_expires_at: new Date(Date.now() + 3600000).toISOString(),
        },
        200,
        '"2"',
      );
    } else if (request.method() !== "GET") {
      actions.push(path);
      await reply(route, {}, 503);
    } else return false;
    return true;
  });
  await enter(page);
  await expect(page.getByTestId("automation-inbox")).toContainText(
    "发生时的历史通知",
  );
  await expect(
    page.getByRole("table", { name: "自动化异常通知列表" }),
  ).toContainText("OUTCOME_UNKNOWN");
  await open(page);
  await expect(
    page.getByRole("button", { name: "确认通知已阅", exact: true }),
  ).toBeDisabled();
  await page.getByRole("button", { name: "下一页通知", exact: true }).click();
  await expect(
    page.getByText("当前筛选没有通知。", { exact: true }),
  ).toBeVisible();
  expect(queries.at(-1)!.searchParams.get("cursor")).toBe("same.cutoff.cursor");
  await page.getByLabel("实例 ID（可选）", { exact: true }).fill(instance);
  await page.getByRole("button", { name: "应用实例筛选", exact: true }).click();
  await expect(page.getByTestId("automation-notification-detail")).toHaveCount(
    0,
  );
  await expect(
    page.getByRole("button", {
      name: `查看通知 ${notification.id}`,
      exact: true,
    }),
  ).toBeVisible();
  expect(queries.at(-1)!.searchParams.get("cursor")).toBeNull();
  expect(queries.at(-1)!.searchParams.get("instance_id")).toBe(instance);
  await open(page);
  await acknowledge(page);
  await expect(
    page.getByTestId("automation-notification-detail"),
  ).toContainText(session.principal_id);
  await expect(
    page.getByRole("button", { name: "确认通知已阅", exact: true }),
  ).toHaveCount(0);
  expect(ackWrites).toBe(1);
  expect(actions).toEqual([]);
});

test("lost committed acknowledgement preserves the original method, body, ETag and key across reload", async ({
  page,
}) => {
  const current = structuredClone(notification);
  const attempts: { key: string; etag: string; body: unknown; path: string }[] =
    [];
  await fixture(page, async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    if (path === "/v1/automation-notifications")
      await reply(route, {
        items: [current],
        next_cursor: null,
        cutoff: current.created_at,
      });
    else if (path === `/v1/automation-notifications/${notification.id}`)
      await reply(route, current, 200, `"${current.version}"`);
    else if (
      path ===
      `/v1/automation-notifications/${notification.id}/actions/acknowledge`
    ) {
      attempts.push({
        key: request.headers()["idempotency-key"]!,
        etag: request.headers()["if-match"]!,
        body: request.postDataJSON(),
        path,
      });
      if (attempts.length === 1) {
        current.version = 2;
        current.acknowledged_at = new Date().toISOString();
        current.acknowledged_by = session.principal_id;
      }
      if (attempts.length === 1) await route.abort("connectionfailed");
      else
        await reply(
          route,
          {
            resource: current,
            idempotency_expires_at: new Date(
              Date.now() + 3600000,
            ).toISOString(),
          },
          200,
          '"2"',
        );
    } else return false;
    return true;
  });
  await enter(page);
  await open(page);
  await acknowledge(page);
  await expect(
    page.getByRole("alert").filter({ hasText: "NETWORK_FAILURE" }).first(),
  ).toBeVisible();
  expect(attempts).toHaveLength(1);
  const stored = await page.evaluate(() =>
    JSON.parse(localStorage.getItem("sandbox.console.intents.v1") ?? "[]"),
  );
  expect(stored[0]).toMatchObject({
    state: "UNKNOWN",
    body: {},
    etag: '"1"',
    key: attempts[0]!.key,
  });
  await page.reload();
  await page.getByLabel("项目 ID", { exact: true }).fill(project);
  await page.getByRole("button", { name: "进入项目", exact: true }).click();
  await page.getByRole("button", { name: "请求记录", exact: true }).click();
  await page
    .getByRole("button", { name: "显式重试原请求", exact: true })
    .click();
  const dialog = page.getByRole("dialog");
  await dialog
    .getByLabel(`输入 ${attempts[0]!.key} 确认`, { exact: true })
    .fill(attempts[0]!.key);
  await dialog.getByRole("button", { name: "确认提交", exact: true }).click();
  await expect(page.getByText("ACCEPTED", { exact: true })).toBeVisible();
  expect(attempts).toHaveLength(2);
  expect(attempts[1]).toEqual(attempts[0]);
});

test("revoked or foreign notification reads clear evidence and prevent acknowledgement", async ({
  page,
}) => {
  let denied = false,
    foreign = false,
    writes = 0;
  await fixture(page, async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    if (
      path.startsWith("/v1/automation-notifications") &&
      request.method() !== "GET"
    ) {
      writes++;
      await reply(route, {}, 503);
    } else if (path === "/v1/automation-notifications") {
      if (denied) await reply(route, { code: "RESOURCE_NOT_FOUND" }, 404);
      else
        await reply(route, {
          items: [{ ...notification, project_id: foreign ? tenant : project }],
          next_cursor: null,
          cutoff: notification.created_at,
        });
    } else if (path === `/v1/automation-notifications/${notification.id}`)
      await reply(route, notification, 200, '"1"');
    else return false;
    return true;
  });
  await enter(page);
  await open(page);
  await page
    .getByLabel("输入通知 ID 确认", { exact: true })
    .fill(notification.id);
  denied = true;
  await page.getByRole("button", { name: "刷新通知", exact: true }).click();
  await expect(
    page.getByTestId("automation-inbox").getByRole("alert"),
  ).toContainText("RESOURCE_NOT_FOUND");
  await expect(page.getByTestId("automation-notification-detail")).toHaveCount(
    0,
  );
  await expect(
    page.getByRole("button", { name: "确认通知已阅", exact: true }),
  ).toHaveCount(0);
  denied = false;
  foreign = true;
  await page.getByRole("button", { name: "刷新通知", exact: true }).click();
  await expect(
    page.getByTestId("automation-inbox").getByRole("alert"),
  ).toContainText("INVALID_AUTOMATION_NOTIFICATION");
  await expect(
    page.getByRole("table", { name: "自动化异常通知列表" }),
  ).toHaveCount(0);
  expect(writes).toBe(0);
});

test("old or disabled deployments never send inbox requests even with a project selected", async ({
  page,
}) => {
  let available: unknown = undefined,
    requests = 0;
  await fixture(page, async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/v1/capabilities")
      await reply(route, {
        ...caps,
        api_features: {
          ...caps.api_features,
          automation_notifications: available,
        },
      });
    else if (path.startsWith("/v1/automation-notifications")) {
      requests++;
      await reply(route, {}, 503);
    } else return false;
    return true;
  });
  await enter(page);
  for (const value of [undefined, false, "true", null]) {
    available = value;
    await page.getByRole("button", { name: "刷新", exact: true }).click();
    await expect(
      page.getByRole("button", { name: "刷新通知", exact: true }),
    ).toBeDisabled();
    await expect(
      page.getByRole("button", { name: "应用实例筛选", exact: true }),
    ).toBeDisabled();
  }
  expect(requests).toBe(0);
});

test("malformed HTTP-success receipts remain UNKNOWN; reload replay validates the current immutable source before acceptance", async ({
  page,
}) => {
  const current = structuredClone(notification);
  const attempts: { key: string; etag: string; body: unknown; path: string }[] =
    [];
  await fixture(page, async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    if (path === "/v1/automation-notifications")
      await reply(route, {
        items: [current],
        next_cursor: null,
        cutoff: current.created_at,
      });
    else if (path === `/v1/automation-notifications/${notification.id}`)
      await reply(route, current, 200, `"${current.version}"`);
    else if (
      path ===
      `/v1/automation-notifications/${notification.id}/actions/acknowledge`
    ) {
      attempts.push({
        key: request.headers()["idempotency-key"]!,
        etag: request.headers()["if-match"]!,
        body: request.postDataJSON(),
        path,
      });
      if (attempts.length === 1) {
        current.version = 2;
        current.acknowledged_at = new Date().toISOString();
        current.acknowledged_by = session.principal_id;
      }
      await reply(
        route,
        {
          resource: {
            ...current,
            ...(attempts.length === 1 ? { project_id: tenant } : {}),
            ...(attempts.length === 2 ? { run_id: instance } : {}),
          },
          idempotency_expires_at: new Date(Date.now() + 3600000).toISOString(),
        },
        200,
        '"2"',
      );
    } else return false;
    return true;
  });
  await enter(page);
  await open(page);
  await acknowledge(page);
  await expect(
    page
      .getByRole("alert")
      .filter({ hasText: "INVALID_AUTOMATION_NOTIFICATION" })
      .first(),
  ).toBeVisible();
  await expect(page.getByTestId("automation-notification-detail")).toHaveCount(
    0,
  );
  await expect(page.getByText(/回执已确认/)).toHaveCount(0);
  const original = attempts[0]!;
  const saved = async () =>
    await page.evaluate(() =>
      JSON.parse(localStorage.getItem("sandbox.console.intents.v1") ?? "[]"),
    );
  expect((await saved())[0]).toMatchObject({
    state: "UNKNOWN",
    key: original.key,
    body: {},
    etag: '"1"',
  });
  await page.reload();
  await page.getByLabel("项目 ID", { exact: true }).fill(project);
  await page.getByRole("button", { name: "进入项目", exact: true }).click();
  await page.getByRole("button", { name: "请求记录", exact: true }).click();
  await retryOriginal(page, original.key);
  await expect(
    page
      .getByRole("alert")
      .filter({ hasText: "INVALID_AUTOMATION_NOTIFICATION" })
      .first(),
  ).toBeVisible();
  expect((await saved())[0]).toMatchObject({
    state: "UNKNOWN",
    key: original.key,
    body: {},
    etag: '"1"',
  });
  await expect(page.getByText("ACCEPTED", { exact: true })).toHaveCount(0);
  await retryOriginal(page, original.key);
  await expect(page.getByText("ACCEPTED", { exact: true })).toBeVisible();
  expect(attempts).toHaveLength(3);
  expect(attempts[1]).toEqual(original);
  expect(attempts[2]).toEqual(original);
});

test("a stale notification ETag is rejected; the console reads the confirmed current resource without replacing the failed request", async ({
  page,
}) => {
  const current = structuredClone(notification);
  let writes = 0;
  await fixture(page, async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    if (path === "/v1/automation-notifications")
      await reply(route, {
        items: [current],
        next_cursor: null,
        cutoff: current.created_at,
      });
    else if (path === `/v1/automation-notifications/${notification.id}`)
      await reply(route, current, 200, `"${current.version}"`);
    else if (
      path ===
      `/v1/automation-notifications/${notification.id}/actions/acknowledge`
    ) {
      writes++;
      expect(request.headers()["if-match"]).toBe('"1"');
      expect(request.postDataJSON()).toEqual({});
      current.version = 2;
      current.acknowledged_at = new Date().toISOString();
      current.acknowledged_by = tenant;
      await reply(route, { code: "VERSION_MISMATCH" }, 412);
    } else return false;
    return true;
  });
  await enter(page);
  await open(page);
  await acknowledge(page);
  await expect(
    page.getByRole("alert").filter({ hasText: "通知版本已变化" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "刷新通知", exact: true }).click();
  await expect(
    page.getByTestId("automation-notification-detail"),
  ).toHaveAttribute("data-version", "2");
  await expect(
    page.getByTestId("automation-notification-detail"),
  ).toContainText(tenant);
  await expect(
    page.getByRole("button", { name: "确认通知已阅", exact: true }),
  ).toHaveCount(0);
  const stored = await page.evaluate(() =>
    JSON.parse(localStorage.getItem("sandbox.console.intents.v1") ?? "[]"),
  );
  expect(stored).toHaveLength(1);
  expect(stored[0]).toMatchObject({
    state: "REJECTED",
    body: null,
    etag: '"1"',
    error: "VERSION_MISMATCH",
  });
  expect(writes).toBe(1);
});
