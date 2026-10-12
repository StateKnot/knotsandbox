import { test, expect } from "@playwright/test";
import type { Page, Route } from "@playwright/test";
import {
  tenant,
  project,
  instance,
  now,
  session,
  resource,
  caps,
  detail,
} from "./browser-fixtures.ts";

const pressureMetrics = [
  {
    metric: "VM_CPU_THROTTLED_PERIODS_PER_SECOND",
    label: "CPU 限流周期速率",
    unit: "periods_per_second",
    explanation: "不包含上级配额的限流",
  },
  {
    metric: "VM_CPU_THROTTLED_SECONDS_PER_SECOND",
    label: "CPU 限流时间速率",
    unit: "seconds_per_second",
    explanation: "可能大于 1",
  },
  {
    metric: "VM_MEMORY_ANON_BYTES",
    label: "匿名内存用量",
    unit: "bytes",
    explanation: "与文件内存相加不等于内存总用量",
  },
  {
    metric: "VM_MEMORY_FILE_BYTES",
    label: "文件内存用量",
    unit: "bytes",
    explanation: "并非全部可回收",
  },
  {
    metric: "VM_MEMORY_OOM_EVENTS_PER_SECOND",
    label: "内存不足事件速率",
    unit: "events_per_second",
    explanation: "不等于进程被终止次数",
  },
  {
    metric: "VM_MEMORY_OOM_KILLS_PER_SECOND",
    label: "内存不足终止进程速率",
    unit: "events_per_second",
    explanation: "不代表实例被终止",
  },
];

function response(metric: string, unit: string, missing = false) {
  return {
    instance_id: instance,
    generation: resource.runtime_generation,
    launch_id: project,
    cluster_epoch: project,
    queried_at: now,
    series: {
      metric,
      unit,
      source: "HOST_VM_RUNTIME",
      stale_after_seconds: 60,
      points: [
        {
          evaluated_at: now,
          observed_at: missing ? null : now,
          value: missing ? null : 0,
          status: missing ? "MISSING" : "FRESH",
          collector_replica: missing ? null : "collector-a",
        },
        {
          evaluated_at: now,
          observed_at: null,
          value: null,
          status: "MISSING",
          collector_replica: null,
        },
        {
          evaluated_at: now,
          observed_at: missing ? null : now,
          value: null,
          status: missing ? "MISSING" : "STALE",
          collector_replica: missing ? null : "collector-a",
        },
        {
          evaluated_at: now,
          observed_at: missing ? null : now,
          value: missing ? null : 2.4,
          status: missing ? "MISSING" : "FRESH",
          collector_replica: missing ? null : "collector-a",
        },
      ],
    },
  };
}

async function openMetrics(
  page: Page,
  respond: (route: Route, url: URL) => Promise<void>,
) {
  await page.route("**/auth/session", (route) =>
    route.fulfill({ json: session }),
  );
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    expect(request.method(), "monitoring must not issue mutations").toBe("GET");
    expect(request.headers()["authorization"]).toBeUndefined();
    expect(request.headers()["x-tenant-id"]).toBe(tenant);
    if (url.pathname === "/v1/capabilities")
      await route.fulfill({
        json: {
          ...caps,
          api_features: { ...caps.api_features, runtime_metrics: true },
        },
      });
    else if (url.pathname === "/v1/instances")
      await route.fulfill({ json: { items: [resource], next_after: null } });
    else if (url.pathname === `/v1/instances/${instance}/details`)
      await route.fulfill({ json: detail });
    else if (url.pathname === `/v1/instances/${instance}/metrics`) {
      expect(url.searchParams.get("step_seconds")).toBe("15");
      const start = Date.parse(url.searchParams.get("start") ?? "");
      const end = Date.parse(url.searchParams.get("end") ?? "");
      expect(end - start).toBe(15 * 60_000);
      await respond(route, url);
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
  await page.getByRole("tab", { name: "监控", exact: true }).click();
  return page.getByRole("tabpanel");
}

test("pressure selections query the authorized metric and preserve zero and gaps without presenting utilization", async ({
  page,
}) => {
  const queried: string[] = [];
  const panel = await openMetrics(page, async (route, url) => {
    const metric = url.searchParams.get("metric") ?? "";
    queried.push(metric);
    const unit = pressureMetrics.find((item) => item.metric === metric)?.unit;
    await route.fulfill({ json: response(metric, unit ?? "cores") });
  });
  const select = panel.getByRole("combobox", { name: "指标", exact: true });
  await expect(select.locator("option")).toHaveText([
    "CPU 消耗核数",
    "CPU 限流周期速率",
    "CPU 限流时间速率",
    "内存总用量",
    "匿名内存用量",
    "文件内存用量",
    "内存不足事件速率",
    "内存不足终止进程速率",
    "块设备读取速率",
    "块设备写入速率",
    "宿主运行时任务数",
  ]);
  await expect(panel.getByRole("img")).toBeVisible();

  for (const item of pressureMetrics) {
    const read = page.waitForResponse((result) => {
      const url = new URL(result.url());
      return (
        url.pathname === `/v1/instances/${instance}/metrics` &&
        url.searchParams.get("metric") === item.metric
      );
    });
    await select.selectOption({ label: item.label });
    await read;
    await expect(
      panel.getByRole("img", { name: new RegExp(`^${item.label}；`) }),
    ).toBeVisible();
    await expect(
      panel.locator("p").filter({ hasText: item.explanation }),
    ).toBeVisible();
    await expect(
      panel.locator("p").filter({ hasText: `（${item.unit}）` }),
    ).toBeVisible();
    const rows = panel.getByRole("table").locator("tbody tr");
    await expect(rows).toHaveCount(4);
    await expect(rows.nth(0).locator("td").nth(2)).toHaveText("0");
    await expect(rows.nth(1).locator("td").nth(2)).toHaveText("—");
    await expect(rows.nth(1).locator("td").nth(3)).toHaveText("MISSING");
    await expect(rows.nth(2).locator("td").nth(2)).toHaveText("—");
    await expect(rows.nth(2).locator("td").nth(3)).toHaveText("STALE");
    await expect(rows.nth(3).locator("td").nth(2)).toHaveText("2.4");
    await expect(panel.locator("svg circle")).toHaveCount(2);
    await expect(panel.locator("svg circle").first()).toHaveAttribute(
      "cy",
      "160",
    );
    await expect(panel.locator("svg circle").last()).toHaveAttribute(
      "cy",
      "20",
    );
    await expect(panel).not.toContainText("%");
    await expect(panel.getByRole("button")).toHaveText(["查询最近 15 分钟"]);
  }
  expect(queried).toEqual([
    "VM_CPU_CORES",
    ...pressureMetrics.map((item) => item.metric),
  ]);
});

test("an unsupported pressure series stays missing and a permission-hidden refresh removes its prior chart", async ({
  page,
}) => {
  let revoked = false;
  const panel = await openMetrics(page, async (route, url) => {
    if (revoked) {
      await route.fulfill({
        status: 404,
        contentType: "application/problem+json",
        json: { code: "NOT_FOUND" },
      });
      return;
    }
    const metric = url.searchParams.get("metric") ?? "";
    await route.fulfill({
      json: response(
        metric,
        metric === "VM_CPU_CORES" ? "cores" : "bytes",
        metric === "VM_MEMORY_FILE_BYTES",
      ),
    });
  });
  await expect(panel.getByRole("img")).toBeVisible();
  await panel
    .getByRole("combobox", { name: "指标", exact: true })
    .selectOption("VM_MEMORY_FILE_BYTES");
  await expect(
    panel.getByRole("img", { name: /^文件内存用量；/ }),
  ).toBeVisible();
  await expect(panel.locator("svg circle")).toHaveCount(0);
  const rows = panel.getByRole("table").locator("tbody tr");
  await expect(rows).toHaveCount(4);
  for (const row of await rows.all()) {
    await expect(row.locator("td").nth(2)).toHaveText("—");
    await expect(row.locator("td").nth(3)).toHaveText("MISSING");
  }
  await expect(
    panel.getByText(
      "缺失、过期或当前节点不支持的指标保留为空，不代表用量为零。",
      { exact: true },
    ),
  ).toBeVisible();

  await panel
    .getByRole("combobox", { name: "指标", exact: true })
    .selectOption("VM_MEMORY_ANON_BYTES");
  await expect(
    panel.getByRole("img", { name: /^匿名内存用量；/ }),
  ).toBeVisible();
  await expect(panel.locator("svg circle")).toHaveCount(2);
  revoked = true;
  await panel
    .getByRole("button", { name: "查询最近 15 分钟", exact: true })
    .click();
  await expect(panel.getByRole("alert")).toHaveText("NOT_FOUND");
  await expect(panel.getByRole("img")).toHaveCount(0);
  await expect(panel.getByRole("table")).toHaveCount(0);
  await expect(
    panel.getByText("HOST_VM_RUNTIME", { exact: false }),
  ).toHaveCount(0);
});
