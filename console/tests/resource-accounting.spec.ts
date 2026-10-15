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

const otherLaunch = "00000000-0000-4000-8000-000000000007";
const otherInstance = "00000000-0000-4000-8000-000000000008";
function accounting(id = instance, launch = project) {
  return {
    instance_id: id,
    selected_launch_id: launch,
    cluster_epoch: tenant,
    request_evidence: "CAPTURED",
    pod_resource_evidence: "NOT_CAPTURED",
    pod_resource_observation: null,
    contract: {
      id: launch,
      instance_id: id,
      workspace_id: project,
      generation: "1",
      launch_id: launch,
      cluster_epoch: tenant,
      operation_id: id,
      cpu_millis: "1000",
      memory_mib: "2048",
      source: "REQUESTED_COMPUTE_QUOTA",
      recorded_at: now,
    },
    receipts: {
      cutoff: now,
      next_cursor: null as string | null,
      items: [
        {
          id: "00000000-0000-4000-8000-000000000005",
          reservation_id: project,
          quota_account_id: project,
          operation_id: id,
          resource_id: id,
          operation_kind: "CREATE",
          purpose: "ORDINARY_COMPUTE",
          dimension: "CPU_MILLIS",
          unit: "MILLICORES",
          account_scope: "TENANT",
          account_project_id: null as string | null,
          amount: "1000",
          limit_value: "9223372036854775807",
          account_version: "9007199254740993",
          pending_value: "9007199254740993",
          allocated_value: "0",
          previous_status: null,
          status: "PENDING",
          history_start: "CAPTURED",
          captured_at: now,
          contract_id: launch,
          generation: "1",
          launch_id: launch,
          cluster_epoch: tenant,
        },
        {
          id: "00000000-0000-4000-8000-000000000006",
          reservation_id: tenant,
          quota_account_id: tenant,
          operation_id: id,
          resource_id: id,
          operation_kind: "CREATE",
          purpose: "ORDINARY_COMPUTE",
          dimension: "MEMORY_MIB",
          unit: "MIB",
          account_scope: "PROJECT",
          account_project_id: project,
          amount: "2048",
          limit_value: "8192",
          account_version: "2",
          pending_value: "2048",
          allocated_value: "0",
          previous_status: null,
          status: "PENDING",
          history_start: "CAPTURED",
          captured_at: now,
          contract_id: launch,
          generation: "1",
          launch_id: launch,
          cluster_epoch: tenant,
        },
      ],
    },
  };
}

function observedAccounting() {
  const workload = {
    cpu_millis: "1000",
    memory_bytes: "2147483648",
    ephemeral_storage_bytes: "1073741824",
  };
  const overhead = { cpu_millis: "40", memory_bytes: "9007199254740993" };
  const effective = {
    cpu_millis: "1040",
    memory_bytes: "9007201402224641",
    ephemeral_storage_bytes: "1073741824",
  };
  return {
    ...accounting(),
    pod_resource_evidence: "KUBERNETES_API_READBACK",
    pod_resource_observation: {
      id: otherLaunch,
      instance_id: instance,
      workspace_id: project,
      generation: "1",
      launch_id: project,
      cluster_epoch: tenant,
      pod_uid: instance,
      pod_resource_version: "opaque:pod-rv",
      node_uid: tenant,
      node_boot_id: otherLaunch,
      runtime_class: {
        uid: otherLaunch,
        resource_version: "opaque:class-rv",
        config_sha256: "a".repeat(64),
        overhead: { ...overhead },
      },
      workload_request: { ...workload },
      workload_limit: { ...workload },
      pod_overhead: { ...overhead },
      effective_request: { ...effective },
      effective_limit: { ...effective },
      source: "KUBERNETES_API_READBACK",
      observed_at: now,
      recorded_at: now,
    },
  };
}

async function openLedger(
  page: Page,
  respond: (route: Route, url: URL) => Promise<void>,
) {
  await page.route("**/auth/session", (route) =>
    route.fulfill({ json: session }),
  );
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    expect(request.method(), "resource history must remain read-only").toBe(
      "GET",
    );
    expect(request.headers()["authorization"]).toBeUndefined();
    expect(request.headers()["x-tenant-id"]).toBe(tenant);
    expect(request.headers()["idempotency-key"]).toBeUndefined();
    expect(request.headers()["if-match"]).toBeUndefined();
    if (url.pathname === "/v1/capabilities")
      await route.fulfill({ json: caps });
    else if (url.pathname === "/v1/instances")
      await route.fulfill({
        json: {
          items: [
            resource,
            { ...resource, id: otherInstance, name: "other-workspace" },
          ],
          next_after: null,
        },
      });
    else if (url.pathname.endsWith("/details")) {
      const id = url.pathname.split("/")[3];
      await route.fulfill({
        json: {
          ...detail,
          instance: {
            ...resource,
            id,
            name: id === instance ? resource.name : "other-workspace",
          },
        },
      });
    } else if (url.pathname.endsWith("/resource-accounting"))
      await respond(route, url);
    else await route.fulfill({ status: 404, json: { code: "NOT_FOUND" } });
  });
  await page.goto("/");
  await page.getByLabel("项目 ID", { exact: true }).fill(project);
  await page.getByRole("button", { name: "进入项目", exact: true }).click();
  await page.getByRole("button", { name: resource.name, exact: true }).click();
  await page.getByRole("tab", { name: "资源账本", exact: true }).click();
  return page.getByRole("tabpanel");
}

test("quota scopes and exact decimal strings remain distinct from missing Pod observations", async ({
  page,
}) => {
  const panel = await openLedger(page, async (route) => {
    await route.fulfill({ json: accounting() });
  });
  await expect(
    panel.getByRole("table", { name: "资源配额状态记录" }),
  ).toBeVisible();
  await expect(
    panel.getByRole("cell", { name: "租户配额 CPU_MILLIS", exact: true }),
  ).toBeVisible();
  await expect(
    panel.getByRole("cell", { name: "项目配额 MEMORY_MIB", exact: true }),
  ).toBeVisible();
  await expect(
    panel.getByRole("cell", {
      name: "上限 9223372036854775807 待分配 9007199254740993 · 已分配 0 账户版本 9007199254740993",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    panel.getByText("账户版本 9007199254740993", { exact: true }),
  ).toBeVisible();
  await expect(
    panel.getByText("实际 Pod 资源：UNKNOWN · NOT_CAPTURED", { exact: true }),
  ).toBeVisible();
  await expect(
    panel.getByText("1000 millicores", { exact: true }),
  ).toBeVisible();
  await expect(
    panel.getByRole("cell", { name: "PENDING CAPTURED", exact: true }),
  ).toHaveCount(2);
  await expect(
    panel.getByRole("button", { name: "资源账本下一页" }),
  ).toBeDisabled();
  await expect(panel.getByText(/\d+\s*%/)).toHaveCount(0);
});

test("trusted Pod configuration shows separate fixed quantities and exact bytes without a utilization claim", async ({
  page,
}) => {
  const panel = await openLedger(page, async (route) => {
    await route.fulfill({ json: observedAccounting() });
  });
  const observed = panel.getByLabel("可信 Pod 资源观察", { exact: true });
  await expect(observed).toBeVisible();
  await expect(
    observed.getByRole("row", {
      name: "工作负载 request 1000 2147483648 1073741824",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    observed.getByRole("row", {
      name: "Pod overhead 40 9007199254740993 不适用",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    observed.getByRole("row", {
      name: "有效 request 1040 9007201402224641 1073741824",
      exact: true,
    }),
  ).toBeVisible();
  await observed.getByText("观察来源与归属", { exact: true }).click();
  await expect(
    observed.getByText("opaque:class-rv", { exact: true }),
  ).toBeVisible();
  await expect(observed.getByText(/不证明 Pod 创建时采用该版本/)).toBeVisible();
  await expect(
    panel.getByText("实际 Pod 资源：UNKNOWN · NOT_CAPTURED", { exact: true }),
  ).toHaveCount(0);
  await expect(panel.getByText(/\d+\s*%/)).toHaveCount(0);
});

test("failed reads and invalid observation quantities or scope clear prior trusted evidence", async ({
  page,
}) => {
  let mode = "allowed";
  const panel = await openLedger(page, async (route) => {
    if (mode === "denied" || mode === "unavailable") {
      await route.fulfill({
        status: mode === "denied" ? 404 : 503,
        json: { code: mode === "denied" ? "NOT_FOUND" : "UNAVAILABLE" },
      });
      return;
    }
    const data = observedAccounting();
    if (mode === "overflow")
      data.pod_resource_observation.pod_overhead.memory_bytes =
        "9223372036854775808";
    if (mode === "foreign")
      data.pod_resource_observation.workspace_id = otherLaunch;
    if (mode === "wrong-sum")
      data.pod_resource_observation.effective_request.cpu_millis = "0";
    await route.fulfill({ json: data });
  });
  for (const next of [
    "denied",
    "unavailable",
    "overflow",
    "foreign",
    "wrong-sum",
  ]) {
    mode = "allowed";
    await panel.getByRole("button", { name: "资源账本第一页" }).click();
    await expect(
      panel.getByLabel("可信 Pod 资源观察", { exact: true }),
    ).toBeVisible();
    mode = next;
    await panel.getByRole("button", { name: "资源账本第一页" }).click();
    await expect(panel.getByRole("alert")).toBeVisible();
    await expect(
      panel.getByLabel("可信 Pod 资源观察", { exact: true }),
    ).toHaveCount(0);
    await expect(panel.getByRole("table")).toHaveCount(0);
    await expect(
      panel.getByText("9007201402224641", { exact: true }),
    ).toHaveCount(0);
  }
});

test("bounded pagination resets on launch selection and never adds tenant/project quantities", async ({
  page,
}) => {
  const queries: URL[] = [];
  const panel = await openLedger(page, async (route, url) => {
    queries.push(url);
    const data = accounting(
      instance,
      url.searchParams.get("launch_id") ?? project,
    );
    data.receipts.items = data.receipts.items.slice(0, 1);
    data.receipts.next_cursor = url.searchParams.has("cursor")
      ? null
      : "signed.opaque.cursor";
    await route.fulfill({ json: data });
  });
  await expect(panel.getByRole("table")).toBeVisible();
  await panel.getByLabel("资源账本每页条数").selectOption("1");
  await expect.poll(() => queries.at(-1)?.searchParams.get("limit")).toBe("1");
  await panel.getByRole("button", { name: "资源账本下一页" }).click();
  await expect
    .poll(() => queries.at(-1)?.searchParams.get("cursor"))
    .toBe("signed.opaque.cursor");
  await expect(
    panel.getByRole("button", { name: "资源账本下一页" }),
  ).toBeDisabled();
  await panel.getByLabel("筛选启动 ID").fill(otherLaunch);
  await panel.getByRole("button", { name: "选择启动", exact: true }).click();
  await expect
    .poll(() => queries.at(-1)?.searchParams.get("launch_id"))
    .toBe(otherLaunch);
  expect(queries.at(-1)?.searchParams.has("cursor")).toBe(false);
  await expect(
    panel.getByText(`选中启动 ${otherLaunch}`, { exact: true }),
  ).toBeVisible();
  expect(
    queries.every((url) => Number(url.searchParams.get("limit")) <= 100),
  ).toBe(true);
});

test("refresh denial and a foreign project receipt both erase prior evidence", async ({
  page,
}) => {
  let mode = "allowed";
  const panel = await openLedger(page, async (route) => {
    if (mode === "denied") {
      await route.fulfill({ status: 404, json: { code: "NOT_FOUND" } });
      return;
    }
    const data = accounting();
    if (mode === "foreign")
      data.receipts.items[1].account_project_id = otherLaunch;
    await route.fulfill({ json: data });
  });
  await expect(panel.getByRole("table")).toBeVisible();
  mode = "denied";
  await panel.getByRole("button", { name: "资源账本第一页" }).click();
  await expect(panel.getByRole("alert")).toContainText("NOT_FOUND");
  await expect(panel.getByRole("table")).toHaveCount(0);
  await expect(panel.getByText("1000 millicores", { exact: true })).toHaveCount(
    0,
  );
  mode = "foreign";
  await panel.getByRole("button", { name: "资源账本第一页" }).click();
  await expect(panel.getByRole("alert")).toContainText(
    "RESOURCE_ACCOUNTING_RESPONSE_INVALID",
  );
  await expect(panel.getByRole("table")).toHaveCount(0);
});

test("uncaptured request history and an empty page stay unknown rather than becoming zero", async ({
  page,
}) => {
  const panel = await openLedger(page, async (route) => {
    const data = {
      ...accounting(),
      contract: null,
      request_evidence: "HISTORY_START_NOT_CAPTURED",
    };
    data.receipts.items = [];
    await route.fulfill({ json: data });
  });
  await expect(
    panel.getByText(/启动申请：UNKNOWN · HISTORY_START_NOT_CAPTURED/),
  ).toBeVisible();
  await expect(
    panel.getByText("当前页没有已捕获的配额状态记录；不代表资源用量为零。", {
      exact: true,
    }),
  ).toBeVisible();
  await expect(panel.getByLabel("启动申请合同")).toHaveCount(0);
  await expect(panel.getByText(/\d+\s*%/)).toHaveCount(0);
});

test("a late abandoned launch read cannot replace the selected launch page", async ({
  page,
}) => {
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  let arrived = false;
  let settled = false;
  try {
    const panel = await openLedger(page, async (route, url) => {
      if (!url.searchParams.has("launch_id")) {
        arrived = true;
        await held;
        try {
          await route.fulfill({ json: accounting() });
        } catch {
          /* Client aborted this exact obsolete request. */
        }
        settled = true;
      } else await route.fulfill({ json: accounting(instance, otherLaunch) });
    });
    await expect.poll(() => arrived).toBe(true);
    await panel.getByLabel("筛选启动 ID").fill(otherLaunch);
    await panel.getByRole("button", { name: "选择启动", exact: true }).click();
    await expect(
      panel.getByText(`选中启动 ${otherLaunch}`, { exact: true }),
    ).toBeVisible();
    release();
    await expect.poll(() => settled).toBe(true);
    await expect(
      panel.getByText(`选中启动 ${project}`, { exact: true }),
    ).toHaveCount(0);
    await expect(
      panel.getByText(`选中启动 ${otherLaunch}`, { exact: true }),
    ).toBeVisible();
  } finally {
    release();
  }
});

test("switching instance cancels a waiting page and removes the previous instance evidence", async ({
  page,
}) => {
  let hold = false;
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  let arrived = false;
  let settled = false;
  try {
    const panel = await openLedger(page, async (route, url) => {
      const id = url.pathname.split("/")[3];
      if (hold && id === instance) {
        arrived = true;
        await held;
        try {
          await route.fulfill({ json: observedAccounting() });
        } catch {
          /* Exact abandoned instance request. */
        }
        settled = true;
      } else
        await route.fulfill({
          json:
            id === instance
              ? observedAccounting()
              : accounting(id, otherLaunch),
        });
    });
    await expect(
      panel.getByLabel("可信 Pod 资源观察", { exact: true }),
    ).toBeVisible();
    hold = true;
    await panel.getByRole("button", { name: "资源账本第一页" }).click();
    await expect.poll(() => arrived).toBe(true);
    await page
      .getByRole("button", { name: "other-workspace", exact: true })
      .click();
    await page.getByRole("tab", { name: "资源账本", exact: true }).click();
    await expect(
      panel.getByText(`选中启动 ${otherLaunch}`, { exact: true }),
    ).toBeVisible();
    await expect(
      panel.getByLabel("可信 Pod 资源观察", { exact: true }),
    ).toHaveCount(0);
    release();
    await expect.poll(() => settled).toBe(true);
    await expect(
      panel.getByText(`选中启动 ${project}`, { exact: true }),
    ).toHaveCount(0);
    await expect(
      panel.getByLabel("可信 Pod 资源观察", { exact: true }),
    ).toHaveCount(0);
  } finally {
    release();
  }
});
