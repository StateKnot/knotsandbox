import { test, expect } from "@playwright/test";
import type { Page, Route } from "@playwright/test";
import { tenant, principal, session, now } from "./browser-fixtures.ts";

const record = {
  id: "00000000-0000-4000-8000-000000000015",
  tenant_id: tenant,
  project_id: null,
  actor_principal_id: principal,
  request_id: "00000000-0000-4000-8000-000000000016",
  operation_id: null,
  resource_id: "00000000-0000-4000-8000-000000000017",
  action: "service_clients:update",
  outcome: "SUCCEEDED",
  occurred_at: now,
};
async function reply(route: Route, body: unknown, status = 200) {
  await route.fulfill({
    status,
    contentType:
      status >= 400 ? "application/problem+json" : "application/json",
    body: JSON.stringify(body),
  });
}
async function fixture(page: Page, handle: (route: Route) => Promise<void>) {
  await page.route("**/auth/session", (route) => reply(route, session));
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    expect(request.method()).toBe("GET");
    expect(request.headers()["authorization"]).toBeUndefined();
    expect(request.headers()["x-tenant-id"]).toBe(tenant);
    expect(request.headers()["idempotency-key"]).toBeUndefined();
    const url = new URL(request.url());
    if (url.pathname === "/v1/tenant-audit-records") {
      expect(url.searchParams.has("project_id")).toBe(false);
      expect(url.searchParams.has("instance_id")).toBe(false);
      await handle(route);
    } else if (url.pathname === "/v1/service-clients") {
      await reply(route, { items: [], next_cursor: null, cutoff: now });
    } else await reply(route, { code: "NOT_FOUND" }, 404);
  });
  await page.goto("/");
  await page.getByRole("button", { name: "账户与授权", exact: true }).click();
}

test("tenant account audit works without a project, pages with the same limit and clears stale data after revocation", async ({
  page,
}) => {
  let revoked = false;
  const queries: URL[] = [];
  await fixture(page, async (route) => {
    const url = new URL(route.request().url());
    queries.push(url);
    if (revoked) {
      await reply(route, { code: "NOT_FOUND" }, 404);
    } else {
      await reply(route, {
        items: url.searchParams.has("cursor")
          ? [{ ...record, id: principal, action: "service_clients:create" }]
          : [record],
        next_cursor: url.searchParams.has("cursor") ? null : "signed.cursor",
        cutoff: now,
      });
    }
  });
  const audit = page.getByRole("region", { name: "租户账户审计", exact: true });
  await expect(
    audit.getByRole("button", { name: "读取租户账户审计" }),
  ).toBeVisible();
  expect(queries).toHaveLength(0);
  await audit.getByLabel("账户审计每页条数").selectOption("1");
  await audit.getByRole("button", { name: "读取租户账户审计" }).click();
  await expect(
    audit.getByText("service_clients:update", { exact: true }),
  ).toBeVisible();
  expect(queries[0]!.searchParams.get("limit")).toBe("1");
  await audit.getByRole("button", { name: "账户审计下一页" }).click();
  await expect(
    audit.getByText("service_clients:create", { exact: true }),
  ).toBeVisible();
  await expect(
    audit.getByText("service_clients:update", { exact: true }),
  ).toHaveCount(0);
  expect(queries[1]!.searchParams.get("limit")).toBe("1");
  expect(queries[1]!.searchParams.get("cursor")).toBe("signed.cursor");
  revoked = true;
  await audit.getByRole("button", { name: "账户审计第一页" }).click();
  await expect(audit.getByRole("alert")).toHaveText("NOT_FOUND");
  await expect(
    audit.getByText("service_clients:create", { exact: true }),
  ).toHaveCount(0);
  await expect(
    audit.getByRole("button", { name: "账户审计下一页" }),
  ).toBeDisabled();
  expect(queries[2]!.searchParams.has("cursor")).toBe(false);
});

for (const [name, changed] of [
  ["another tenant", { tenant_id: principal }],
  ["a project record", { project_id: principal }],
  ["missing explicit null project scope", { project_id: undefined }],
] as const) {
  test(`tenant audit rejects ${name} without rendering its metadata`, async ({
    page,
  }) => {
    await fixture(page, (route) =>
      reply(route, {
        items: [{ ...record, ...changed }],
        next_cursor: "foreign.cursor",
        cutoff: now,
      }),
    );
    const audit = page.getByRole("region", {
      name: "租户账户审计",
      exact: true,
    });
    await audit.getByRole("button", { name: "读取租户账户审计" }).click();
    await expect(audit.getByRole("alert")).toHaveText(
      "TENANT_AUDIT_SCOPE_MISMATCH",
    );
    await expect(
      audit.getByText("service_clients:update", { exact: true }),
    ).toHaveCount(0);
    await expect(
      audit.getByRole("button", { name: "账户审计下一页" }),
    ).toBeDisabled();
  });
}

test("a late tenant audit page cannot overwrite the current page after a limit change", async ({
  page,
}) => {
  let release!: () => void;
  let received!: () => void;
  let finished!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const firstReceived = new Promise<void>((resolve) => {
    received = resolve;
  });
  const firstFinished = new Promise<void>((resolve) => {
    finished = resolve;
  });
  await fixture(page, async (route) => {
    const url = new URL(route.request().url());
    if (url.searchParams.get("limit") === "20") {
      received();
      await held;
      await reply(route, {
        items: [record],
        next_cursor: "old.cursor",
        cutoff: now,
      });
      finished();
    } else {
      await reply(route, {
        items: [{ ...record, action: "service_clients:create" }],
        next_cursor: null,
        cutoff: now,
      });
    }
  });
  const audit = page.getByRole("region", { name: "租户账户审计", exact: true });
  await audit.getByRole("button", { name: "读取租户账户审计" }).click();
  await firstReceived;
  await audit.getByLabel("账户审计每页条数").selectOption("1");
  await expect(
    audit.getByText("service_clients:create", { exact: true }),
  ).toBeVisible();
  release();
  await firstFinished;
  await page.evaluate(
    () =>
      new Promise<void>((resolve) => {
        requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
      }),
  );
  await expect(
    audit.getByText("service_clients:update", { exact: true }),
  ).toHaveCount(0);
  await expect(
    audit.getByText("service_clients:create", { exact: true }),
  ).toBeVisible();
  await expect(
    audit.getByRole("button", { name: "账户审计下一页" }),
  ).toBeDisabled();
});
