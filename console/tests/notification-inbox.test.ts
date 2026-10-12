import test from "node:test";
import assert from "node:assert/strict";
import { ApiFailure, BrowserApi } from "../src/api.ts";
import { IntentJournal } from "../src/journal.ts";
import {
  notificationsEnabled,
  notificationPage,
  scopedNotification,
  notificationAckPath,
  notificationAckId,
  notificationEtag,
  notificationReceipt,
} from "../src/notification-inbox.ts";
import {
  session,
  project,
  instance,
  tenant,
  caps,
  now,
} from "./browser-fixtures.ts";
import {
  notification,
  acknowledgedNotification,
} from "./notification-fixture.ts";
const invalid = (work: () => unknown) =>
  assert.throws(work, (error) => error instanceof ApiFailure);

test("notification discovery requires the exact project deployment flag, independently of creation-contract versions", () => {
  const value = {
    ...caps,
    automation: null,
    api_features: { automation_notifications: true },
  };
  assert.equal(notificationsEnabled(value, project), true);
  for (const change of [
    null,
    {},
    caps,
    { ...value, project_id: tenant },
    { ...value, api_features: { automation_notifications: "true" } },
    { ...value, api_features: { automation_notifications: false } },
  ])
    assert.equal(notificationsEnabled(change, project), false);
});

test("notification decoder binds tenant/project/optional instance and keeps source status separate from current run state", () => {
  assert.equal(
    scopedNotification(
      notification,
      session,
      project,
      instance,
      notification.id,
    ).source_status,
    "OUTCOME_UNKNOWN",
  );
  for (const change of [
    { tenant_id: project },
    { project_id: tenant },
    { instance_id: project },
    { id: instance },
    { run_id: "00000000-0000-0000-0000-000000000000" },
    { source_status: "SUCCEEDED" },
    { source_run_version: 9007199254740992 },
    { version: 0 },
    { version: 3 },
    { version: 2 },
    { source_event_id: tenant },
    { version: 1, acknowledged_at: now, acknowledged_by: session.principal_id },
    {
      version: 2,
      acknowledged_at: "2000-01-01T00:00:00Z",
      acknowledged_by: session.principal_id,
    },
    { acknowledged_at: now },
    { acknowledged_by: session.principal_id },
    { created_at: "bad" },
    { argv: ["secret"] },
  ])
    invalid(() =>
      scopedNotification(
        { ...notification, ...change },
        session,
        project,
        instance,
        notification.id,
      ),
    );
  assert.equal(
    scopedNotification(acknowledgedNotification, session, project)
      .acknowledged_by,
    session.principal_id,
  );
});

test("opaque pagination preserves cutoff and rejects duplicate records, wrong scope and malformed cursor", () => {
  const page = {
    items: [notification],
    next_cursor: "opaque.signed.cursor",
    cutoff: now,
  };
  assert.deepEqual(notificationPage(page, session, project), page);
  for (const change of [
    { items: [notification, notification] },
    { items: [{ ...notification, project_id: tenant }] },
    { items: Array(21).fill(notification) },
    { next_cursor: "" },
    { next_cursor: "x".repeat(2049) },
    { cutoff: "not-a-time" },
    { surprise: "private" },
  ])
    invalid(() => notificationPage({ ...page, ...change }, session, project));
});

test("acknowledgement uses the exact current ETag and accepts only the same immutable source with a confirmed actor/version", () => {
  assert.equal(
    notificationAckPath(notification.id),
    `/v1/automation-notifications/${notification.id}/actions/acknowledge`,
  );
  assert.equal(
    notificationEtag(
      new Response(null, { headers: { etag: '"1"' } }),
      notification.version,
    ),
    '"1"',
  );
  for (const value of [null, 'W/"1"', '"2"'])
    invalid(() =>
      notificationEtag(
        new Response(null, { headers: value ? { etag: value } : {} }),
        notification.version,
      ),
    );
  invalid(() => notificationAckPath("../run"));
  assert.equal(
    notificationAckId(notificationAckPath(notification.id)),
    notification.id,
  );
  assert.equal(
    notificationAckId(`/v1/instances/${instance}/actions/acknowledge`),
    null,
  );
  const receipt = {
    resource: acknowledgedNotification,
    idempotency_expires_at: now,
  };
  assert.deepEqual(
    notificationReceipt(
      receipt,
      session,
      project,
      scopedNotification(notification, session, project),
    ),
    receipt,
  );
  for (const change of [
    { source_status: "FAILED" },
    { run_id: instance },
    { source_run_version: 4 },
    { version: 1 },
    { acknowledged_by: tenant },
    { acknowledged_at: null },
  ])
    invalid(() =>
      notificationReceipt(
        { ...receipt, resource: { ...acknowledgedNotification, ...change } },
        session,
        project,
        scopedNotification(notification, session, project),
      ),
    );
});

test("a validator rejection after HTTP success remains UNKNOWN with the original replayable ACK, even when its local error has a 4xx status", async () => {
  let value: string | null = null;
  const storage = {
    getItem: () => value,
    setItem: (_key: string, next: string) => {
      value = next;
    },
  };
  const lock = async <T>(work: () => Promise<T>) => await work();
  const attempts: Request[] = [];
  const api = new BrowserApi(
    "https://console.example",
    () => {},
    async (request) => {
      attempts.push((request as Request).clone());
      return new Response(
        JSON.stringify({
          resource: acknowledgedNotification,
          idempotency_expires_at: now,
        }),
        {
          headers: { "content-type": "application/json", etag: '"2"' },
        },
      );
    },
  );
  api.setSession(session);
  const journal = new IntentJournal(storage, lock);
  const intent = await journal.create(
    session,
    notificationAckPath(notification.id),
    {},
    '"1"',
  );
  await assert.rejects(
    journal.execute(api, session, intent.key, () => {
      throw new ApiFailure("INVALID_AUTOMATION_NOTIFICATION", 412);
    }),
    /INVALID_AUTOMATION_NOTIFICATION/,
  );
  assert.deepEqual(journal.list(session)[0], {
    ...intent,
    state: "UNKNOWN",
    error: "INVALID_AUTOMATION_NOTIFICATION",
  });
  const reloaded = new IntentJournal(storage, lock);
  await reloaded.execute(api, session, intent.key, (data, response) => {
    const receipt = notificationReceipt(
      data,
      session,
      project,
      scopedNotification(notification, session, project),
    );
    notificationEtag(response.etag, receipt.resource.version);
  });
  assert.equal(reloaded.list(session)[0]!.state, "ACCEPTED");
  assert.equal(attempts.length, 2);
  for (const request of attempts) {
    assert.equal(request.method, "POST");
    assert.equal(request.headers.get("idempotency-key"), intent.key);
    assert.equal(request.headers.get("if-match"), '"1"');
    assert.equal(await request.text(), "{}");
  }
});
