import { test, expect } from "@playwright/test";
import {
  tenant,
  project,
  instance,
  session,
  resource,
  caps,
  detail,
} from "./browser-fixtures.ts";

for (const capability of [false, undefined, "true"]) {
  test(`backup capability ${typeof capability} ${String(capability)} blocks workspace and backup requests`, async ({
    page,
  }) => {
    const reads: string[] = [];
    await page.route("**/auth/session", (route) =>
      route.fulfill({ json: session }),
    );
    await page.route("**/v1/**", async (route) => {
      const request = route.request();
      const path = new URL(request.url()).pathname;
      expect(request.headers()["authorization"]).toBeUndefined();
      expect(request.headers()["x-tenant-id"]).toBe(tenant);
      if (path === "/v1/capabilities")
        await route.fulfill({
          json: {
            ...caps,
            api_features: { ...caps.api_features, backup_restore: capability },
          },
        });
      else if (path === "/v1/instances")
        await route.fulfill({ json: { items: [resource], next_after: null } });
      else if (path === `/v1/instances/${instance}/details`)
        await route.fulfill({ json: detail });
      else {
        if (
          path.startsWith("/v1/workspaces/") ||
          path.startsWith("/v1/backups/")
        )
          reads.push(`${request.method()} ${path}`);
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
    await page.getByRole("tab", { name: "备份", exact: true }).click();
    const panel = page.getByRole("tabpanel");
    await expect(panel.getByRole("status")).toHaveCount(0);
    expect(reads, "unsupported backup routes must remain unused").toEqual([]);
    await expect(
      panel.getByText("当前部署未提供工作区备份服务。", { exact: true }),
    ).toBeVisible();
    await expect(panel.getByRole("alert")).toHaveCount(0);
    await expect(panel.getByRole("textbox")).toHaveCount(0);
    await expect(panel.getByRole("button")).toHaveCount(0);
    expect(reads).toEqual([]);
    // Reloading details refreshes capabilities too; unsupported deployment stays
    // inert on a second mount instead of accidentally looking up the workspace.
    await page.getByRole("button", { name: "刷新详情", exact: true }).click();
    await expect(
      panel.getByText("当前部署未提供工作区备份服务。", { exact: true }),
    ).toBeVisible();
    await expect(panel.getByRole("status")).toHaveCount(0);
    expect(reads).toEqual([]);
  });
}

test("enabled backup capability preserves permission-hidden 404 responses", async ({
  page,
}) => {
  const reads: string[] = [];
  await page.route("**/auth/session", (route) =>
    route.fulfill({ json: session }),
  );
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/v1/capabilities")
      await route.fulfill({
        json: {
          ...caps,
          api_features: { ...caps.api_features, backup_restore: true },
        },
      });
    else if (path === "/v1/instances")
      await route.fulfill({ json: { items: [resource], next_after: null } });
    else if (path === `/v1/instances/${instance}/details`)
      await route.fulfill({ json: detail });
    else {
      if (path.startsWith("/v1/workspaces/") || path.startsWith("/v1/backups/"))
        reads.push(`${request.method()} ${path}`);
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
  await page.getByRole("tab", { name: "备份", exact: true }).click();
  const panel = page.getByRole("tabpanel");
  await expect(panel.getByRole("alert")).toHaveText("NOT_FOUND");
  expect(reads).toEqual([`GET /v1/workspaces/${resource.workspace_id}`]);
  await panel.getByLabel("备份 ID", { exact: true }).fill(project);
  await panel.getByRole("button", { name: "查询备份", exact: true }).click();
  await expect(panel.getByRole("alert")).toHaveCount(2);
  await expect(panel.getByText("NOT_FOUND", { exact: true })).toHaveCount(2);
  expect(reads).toEqual([
    `GET /v1/workspaces/${resource.workspace_id}`,
    `GET /v1/backups/${project}`,
  ]);
  await expect(
    panel.getByText("当前部署未提供工作区备份服务。", { exact: true }),
  ).toHaveCount(0);
  await expect(
    panel.getByRole("button", { name: "提交冷备份请求", exact: true }),
  ).toHaveCount(0);
});
