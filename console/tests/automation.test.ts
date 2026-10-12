import test from "node:test";
import assert from "node:assert/strict";
import { ApiFailure } from "../src/api.ts";
import type { Schema, Session } from "../src/api.ts";
import {
  buildCreateAutomation,
  strictInteger,
  automationCreatePath,
  automationActionPath,
  scopedAutomation,
  scopedAutomationRun,
  automationContract,
} from "../src/automation.ts";
import { automationCapability } from "./automation-fixture.ts";
const contract = automationContract(automationCapability)!;
const tenant = "00000000-0000-4000-8000-000000000001",
  principal = "00000000-0000-4000-8000-000000000002";
const project = "00000000-0000-4000-8000-000000000003",
  instance = "00000000-0000-4000-8000-000000000004";
const policy = "00000000-0000-4000-8000-000000000005",
  profile = "00000000-0000-4000-8000-000000000006";
const session: Session = {
  tenant_id: tenant,
  principal_id: principal,
  csrf_token: "a".repeat(43),
  absolute_expires_at: "2026-10-10T01:00:00Z",
  idle_expires_at: "2026-10-10T01:00:00Z",
};
const now = Date.parse("2026-10-10T00:00:00Z");
function form(action = "STOP", trigger = "ONCE"): FormData {
  const data = new FormData();
  for (const [key, value] of Object.entries({
    name: "按明确期限停止",
    action_kind: action,
    trigger_kind: trigger,
    once_at: "2026-10-10T00:02:00.000001Z",
    cron_expression: "0 */15 * * * * *",
    event_type: "instance.started",
    aggregate_id: instance,
    delegation_expires_at: "2026-10-10T01:00:00.123456Z",
    run_budget: "3",
    minimum_interval_seconds: "60",
    grace_seconds: "30",
    ttl_seconds: "600",
    argv: '["printf","你好"]',
    public_env: '{"LANG":"C.UTF-8"}',
    cwd: "/workspace/a",
    timeout_seconds: "30",
    output_limit_bytes: "4096",
    non_sensitive: "on",
    hard_stop_instance: "on",
    backup_profile_id: profile,
    retention_days: "31",
  }))
    data.set(key, value);
  return data;
}
const invalid = (work: () => unknown) =>
  assert.throws(
    work,
    (e) => e instanceof ApiFailure && e.code === "INVALID_AUTOMATION_INPUT",
  );

test("creation requires a complete recognized deployment contract; API-only assurance never grants permissions", () => {
  assert.equal(contract.schema_version, 1);
  assert.equal(contract.assurance, "API_CONTRACT_ONLY");
  const reordered = structuredClone(automationCapability);
  reordered.supported_actions.reverse();
  reordered.supported_triggers.reverse();
  assert.notEqual(automationContract(reordered), null);
  const bad = [
    null,
    undefined,
    {},
    { ...automationCapability, schema_version: 2 },
    { ...automationCapability, assurance: "CLOUD_CERTIFIED" },
    { ...automationCapability, clock: "BROWSER" },
    { ...automationCapability, time_zone: "Asia/Shanghai" },
    { ...automationCapability, supported_actions: ["RESTORE"] },
    {
      ...automationCapability,
      supported_actions: automationCapability.supported_actions.slice(1),
    },
    {
      ...automationCapability,
      supported_actions: [
        "START",
        ...automationCapability.supported_actions.slice(0, 6),
      ],
    },
    { ...automationCapability, supported_triggers: ["ONCE", "EVENT"] },
    {
      ...automationCapability,
      cron: { ...automationCapability.cron, field_count: 5 },
    },
    { ...automationCapability, missed_run_policy: "REPLAY_ALL" },
    { ...automationCapability, skipped_runs_consume_budget: false },
    { ...automationCapability, known_automated_events_retrigger: true },
    { ...automationCapability, outcome_unknown_policy: "DISPATCH_NEW" },
    {
      ...automationCapability,
      limits: {
        ...automationCapability.limits,
        live_policies_per_project: 101,
      },
    },
    {
      ...automationCapability,
      limits: {
        ...automationCapability.limits,
        run_budget: { minimum: 1, maximum: NaN },
      },
    },
    {
      ...automationCapability,
      limits: {
        ...automationCapability.limits,
        delegation_lifetime_seconds: { minimum: 60, maximum: 31622400 },
      },
    },
    { ...automationCapability, permissions: ["automations:write"] },
  ];
  for (const value of bad) {
    assert.equal(automationContract(value), null);
    invalid(() =>
      buildCreateAutomation(form(), value as typeof contract, 3600, now),
    );
  }
});

test("contract name limit counts UTF-8 bytes and finite delegation uses an exclusive minimum", () => {
  const f = form();
  f.set("name", "界".repeat(42));
  assert.equal(
    buildCreateAutomation(f, contract, 3600, now).name,
    "界".repeat(42),
  );
  f.set("name", "界".repeat(43));
  invalid(() => buildCreateAutomation(f, contract, 3600, now));
  const minimum = form();
  minimum.set("delegation_expires_at", "2026-10-10T00:01:00Z");
  invalid(() => buildCreateAutomation(minimum, contract, 3600, now));
  minimum.set("delegation_expires_at", "2026-10-10T00:01:00.000001Z");
  minimum.set("once_at", "2026-10-10T00:00:59Z");
  assert.equal(
    buildCreateAutomation(minimum, contract, 3600, now).run_budget,
    contract.limits.run_budget.minimum + 2,
  );
});

test("seven formal actions and three explicit UTC trigger shapes produce bounded API bodies", () => {
  for (const action of [
    "START",
    "STOP",
    "RESTART",
    "DELETE",
    "RENEW",
    "EXECUTE",
    "BACKUP",
  ]) {
    for (const trigger of ["ONCE", "CRON_UTC", "EVENT"]) {
      const result = buildCreateAutomation(
        form(action, trigger),
        contract,
        3600,
        now,
      );
      assert.equal(result.action.kind, action);
      assert.equal(result.trigger.kind, trigger);
      assert.equal(result.delegation_expires_at, "2026-10-10T01:00:00.123456Z");
      assert.equal(result.run_budget, 3);
      if (result.action.kind === "EXECUTE")
        assert.equal(result.action.request.on_timeout, "HARD_STOP_INSTANCE");
      if (["STOP", "RESTART", "DELETE"].includes(action))
        assert.deepEqual(result.action, { kind: action });
    }
  }
  const cron = form("STOP", "CRON_UTC");
  cron.set("cron_expression", " 0\t*/15 * * * * * ");
  assert.deepEqual(buildCreateAutomation(cron, contract, 3600, now).trigger, {
    kind: "CRON_UTC",
    expression: "0 */15 * * * * *",
  });
});
test("raw integers reject truncation, exponents, signs, whitespace and unsafe values", () => {
  for (const value of [
    "",
    " 60",
    "60 ",
    "060",
    "+60",
    "-0",
    "60.0",
    "6e1",
    "NaN",
    "9007199254740992",
  ])
    invalid(() => strictInteger(value, 0, Number.MAX_SAFE_INTEGER));
  assert.equal(strictInteger("0", 0, 1), 0);
  for (const [field, value] of [
    ["run_budget", "0"],
    ["grace_seconds", "3601"],
    ["minimum_interval_seconds", "59"],
    ["ttl_seconds", "3601"],
  ]) {
    const f = form("RENEW");
    f.set(field!, value!);
    invalid(() => buildCreateAutomation(f, contract, 3600, now));
  }
  const duplicate = form();
  duplicate.append("run_budget", "1");
  invalid(() => buildCreateAutomation(duplicate, contract, 3600, now));
});
test("UTC parsing preserves microseconds and rejects local/DST, leap seconds and calendar rollovers", () => {
  for (const value of [
    "2026-10-10T01:00",
    "2026-10-10T01:00:00+00:00",
    "2026-10-10T24:00:00Z",
    "2026-10-10T23:60:00Z",
    "2026-10-10T23:59:60Z",
    "2026-02-30T01:00:00Z",
    "2026-10-10T01:00:00.1234567Z",
    "2026-10-10T00:01:00Z",
    "2028-10-10T01:00:00Z",
  ]) {
    const f = form();
    f.set("delegation_expires_at", value);
    invalid(() => buildCreateAutomation(f, contract, 3600, now));
  }
  const near = form();
  near.set("once_at", "2026-10-10T01:00:00.123455Z");
  assert.equal(
    (buildCreateAutomation(near, contract, 3600, now).trigger as { at: string })
      .at,
    "2026-10-10T01:00:00.123455Z",
  );
  near.set("once_at", "2026-10-10T01:00:00.123456Z");
  invalid(() => buildCreateAutomation(near, contract, 3600, now));
  for (const key of ["non_sensitive", "hard_stop_instance"]) {
    const f = form("EXECUTE");
    f.delete(key);
    invalid(() => buildCreateAutomation(f, contract, 3600, now));
  }
});
test("execution boundary rejects duplicate/escaped environment names, reserved fields, NUL and encoded size overflow", () => {
  for (const env of [
    '{"A":"1","A":"2"}',
    '{"A":"1","\\u0041":"2"}',
    '{"PATH":"a"}',
    '{"SANDBOX_TOKEN":"a"}',
    '{"9A":"1"}',
    '{"A":7}',
    '{"A":"\\u0000"}',
    '{"A":"\\ud800"}',
    '{"A":"1",}',
    "[]",
  ]) {
    const f = form("EXECUTE");
    f.set("public_env", env);
    invalid(() => buildCreateAutomation(f, contract, 3600, now));
  }
  for (const cwd of [
    "/other",
    "/workspace/../other",
    "workspace/a",
    "/workspace\0",
  ]) {
    const f = form("EXECUTE");
    f.set("cwd", cwd);
    invalid(() => buildCreateAutomation(f, contract, 3600, now));
  }
  for (const argv of [
    "[]",
    '[""]',
    '["x",7]',
    '["x","\\ud800"]',
    JSON.stringify(["x", "界".repeat(22000)]),
  ]) {
    const f = form("EXECUTE");
    f.set("argv", argv);
    invalid(() => buildCreateAutomation(f, contract, 3600, now));
  }
  const overEnv = form("EXECUTE");
  overEnv.set(
    "public_env",
    JSON.stringify(
      Object.fromEntries(
        Array.from({ length: 5 }, (_, i) => [`K${i}`, "x".repeat(4096)]),
      ),
    ),
  );
  invalid(() => buildCreateAutomation(overEnv, contract, 3600, now));
  const encoded = form("EXECUTE");
  encoded.set("argv", JSON.stringify(["x", "\\".repeat(32000)]));
  encoded.set("public_env", JSON.stringify({ A: "x".repeat(1500) }));
  invalid(() => buildCreateAutomation(encoded, contract, 3600, now));
});
test("unpublished actions, malformed triggers and unscoped path identifiers cannot be dispatched", () => {
  invalid(() => buildCreateAutomation(form("RESTORE"), contract, 3600, now));
  for (const value of [
    "*/5 * * * *",
    "1 * * * * * *",
    "0 * * * * * 2026",
    "TZ=Asia/Shanghai 0 * * * * * *",
  ]) {
    const f = form("STOP", "CRON_UTC");
    f.set("cron_expression", value);
    invalid(() => buildCreateAutomation(f, contract, 3600, now));
  }
  const badEvent = form("STOP", "EVENT");
  badEvent.set("event_type", "anything\nelse");
  invalid(() => buildCreateAutomation(badEvent, contract, 3600, now));
  assert.equal(
    automationCreatePath(instance),
    `/v1/instances/${instance}/automations`,
  );
  assert.equal(
    automationActionPath(policy, "revoke"),
    `/v1/automations/${policy}/actions/revoke`,
  );
  assert.throws(() => automationCreatePath("../"));
  assert.throws(() =>
    automationCreatePath("00000000-0000-0000-0000-000000000000"),
  );
});
const metadata: Schema["Automation"] = {
  id: policy,
  tenant_id: tenant,
  project_id: project,
  instance_id: instance,
  workspace_id: profile,
  creator_principal_id: principal,
  name: "停止",
  action_kind: "STOP",
  trigger_kind: "ONCE",
  scheduled_at: "2026-10-10T00:02:00Z",
  cron_expression: null,
  event_type: null,
  event_aggregate_id: null,
  next_due_at: "2026-10-10T00:02:00Z",
  status: "ACTIVE",
  version: 1,
  run_budget: 3,
  emitted_runs: 0,
  minimum_interval_seconds: 60,
  grace_seconds: 30,
  delegation_expires_at: "2026-10-10T01:00:00Z",
  delegation_revoked_at: null,
  created_at: "2026-10-10T00:00:00Z",
  updated_at: "2026-10-10T00:00:00Z",
};
test("metadata/history decoders reject foreign scope, unsafe versions and unexpected argument disclosure", () => {
  assert.equal(
    scopedAutomation(metadata, session, project, instance, policy).id,
    policy,
  );
  for (const change of [
    { tenant_id: project },
    { project_id: tenant },
    { instance_id: policy },
    { id: instance },
    { version: 1.5 },
    { action: { kind: "EXECUTE", request: { argv: ["private"] } } },
  ])
    invalid(() =>
      scopedAutomation(
        { ...metadata, ...change },
        session,
        project,
        instance,
        policy,
      ),
    );
  const run: Schema["AutomationRun"] = {
    id: profile,
    tenant_id: tenant,
    project_id: project,
    automation_id: policy,
    version: 1,
    automation_version: 1,
    scheduled_for: "2026-10-10T00:02:00Z",
    source_event_id: null,
    source_event_sequence: null,
    skipped_through: null,
    operation_kind: "STOP",
    expected_resource_version: 1,
    expected_generation: 1,
    status: "SUBMITTED",
    operation_id: instance,
    failure_code: null,
    deadline: "2026-10-10T00:02:30Z",
    created_at: "2026-10-10T00:00:00Z",
    updated_at: "2026-10-10T00:00:00Z",
    completed_at: null,
  };
  assert.equal(
    scopedAutomationRun(run, session, project, policy, profile).status,
    "SUBMITTED",
  );
  assert.equal(
    scopedAutomationRun(
      { ...run, expected_generation: 0 },
      session,
      project,
      policy,
      profile,
    ).expected_generation,
    0,
  );
  for (const change of [
    { automation_id: instance },
    { tenant_id: project },
    { project_id: tenant },
    { version: 9007199254740992 },
    { expected_generation: -1 },
    { argv: ["private"] },
  ])
    invalid(() =>
      scopedAutomationRun(
        { ...run, ...change },
        session,
        project,
        policy,
        profile,
      ),
    );
});
