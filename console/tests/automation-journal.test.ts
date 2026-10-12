import test from "node:test";
import assert from "node:assert/strict";
import { ApiFailure, BrowserApi } from "../src/api.ts";
import type { Session } from "../src/api.ts";
import { IntentJournal, JOURNAL_SLOT } from "../src/journal.ts";
import type { JournalLock } from "../src/journal.ts";
const id = "00000000-0000-4000-8000-000000000001";
const session: Session = {
  tenant_id: id,
  principal_id: "00000000-0000-4000-8000-000000000002",
  csrf_token: "a".repeat(43),
  absolute_expires_at: "2027-10-10T01:00:00Z",
  idle_expires_at: "2027-10-10T01:00:00Z",
};
const path = `/v1/instances/${id}/automations`;
const body = {
  action: {
    kind: "EXECUTE",
    request: {
      argv: ["python3", "-c", "private command"],
      public_env: { A: "private environment", B: "public" },
    },
  },
  name: "fixture",
  trigger: { kind: "EVENT", aggregate_id: id, event_type: "instance.started" },
};
function sharedLock(): JournalLock {
  let held = false;
  return async <T>(work: () => Promise<T>): Promise<T> => {
    if (held) throw new ApiFailure("REQUEST_ALREADY_PENDING");
    held = true;
    try {
      return await work();
    } finally {
      held = false;
    }
  };
}
class Memory {
  value: string | null = null;
  readonly lock = sharedLock();
  fail = false;
  getItem() {
    return this.value;
  }
  setItem(_key: string, value: string) {
    if (this.fail) throw Error("unavailable");
    this.value = value;
  }
}
const response = () =>
  new Response(JSON.stringify({ resource: { id } }), {
    status: 201,
    headers: { "content-type": "application/json" },
  });
const code = (expected: string) => (error: unknown) =>
  error instanceof ApiFailure && error.code === expected;

test("sensitive creation persists no command/environment, and unknown reload needs exact original-body recovery", async () => {
  const storage = new Memory(),
    first = new IntentJournal(storage, storage.lock);
  const received: Request[] = [];
  const api = new BrowserApi(
    "https://console.example",
    () => {},
    async (request) => {
      received.push((request as Request).clone());
      if (received.length === 1) throw Error("lost receipt");
      return response();
    },
  );
  api.setSession(session);
  const mutable = structuredClone(body);
  const intent = await first.create(session, path, mutable, '"7"');
  mutable.action.request.argv.reverse();
  assert.equal(intent.body, null);
  assert.match(intent.bodySha256!, /^[0-9a-f]{64}$/);
  assert.equal(first.hasPayload(session, intent.key), true);
  assert.equal(storage.value!.includes("private command"), false);
  assert.equal(storage.value!.includes("private environment"), false);
  await assert.rejects(first.execute(api, session, intent.key));
  assert.equal(first.list(session)[0]!.state, "UNKNOWN");
  const reloaded = new IntentJournal(storage, storage.lock);
  assert.equal(reloaded.hasPayload(session, intent.key), false);
  const durable = storage.value;
  await assert.rejects(
    reloaded.execute(api, session, intent.key),
    code("INTENT_PAYLOAD_REQUIRED"),
  );
  assert.equal(received.length, 1);
  assert.equal(storage.value, durable);
  await assert.rejects(
    reloaded.rehydrate(session, intent.key, { ...body, name: "different" }),
    code("INTENT_BODY_MISMATCH"),
  );
  assert.equal(reloaded.hasPayload(session, intent.key), false);
  await assert.rejects(
    reloaded.create(session, path, body, '"8"'),
    code("RECONCILE_ORIGINAL_REQUEST_FIRST"),
  );
  await reloaded.rehydrate(session, intent.key, {
    trigger: {
      event_type: "instance.started",
      aggregate_id: id,
      kind: "EVENT",
    },
    name: "fixture",
    action: {
      request: {
        public_env: { B: "public", A: "private environment" },
        argv: ["python3", "-c", "private command"],
      },
      kind: "EXECUTE",
    },
  });
  assert.equal(reloaded.hasPayload(session, intent.key), true);
  assert.equal(storage.value, durable);
  await reloaded.execute(api, session, intent.key);
  assert.equal(received.length, 2);
  assert.equal(await received[0]!.text(), await received[1]!.text());
  assert.equal(received[1]!.headers.get("idempotency-key"), intent.key);
  assert.equal(received[1]!.headers.get("if-match"), '"7"');
  assert.equal(reloaded.list(session)[0]!.state, "ACCEPTED");
  assert.equal(reloaded.list(session)[0]!.resourceId, id);
  assert.equal(reloaded.hasPayload(session, intent.key), false);
  assert.equal(storage.value!.includes("private command"), false);
});
test("array order is part of the hash, while object ordering is canonical", async () => {
  const storage = new Memory(),
    journal = new IntentJournal(storage, storage.lock);
  const intent = await journal.create(session, path, body, '"1"');
  journal.forgetPayloads();
  const reversed = structuredClone(body);
  reversed.action.request.argv.reverse();
  await assert.rejects(
    journal.rehydrate(session, intent.key, reversed),
    code("INTENT_BODY_MISMATCH"),
  );
  assert.equal(journal.hasPayload(session, intent.key), false);
  const extra = { ...body, ignored: true };
  await assert.rejects(
    journal.rehydrate(session, intent.key, extra),
    code("INTENT_BODY_MISMATCH"),
  );
});
test("actor/CSRF changes cannot reuse memory, and forgetting invalidates a pending rehydration", async () => {
  const storage = new Memory(),
    journal = new IntentJournal(storage, storage.lock);
  const intent = await journal.create(session, path, body, '"1"');
  let requests = 0;
  const api = new BrowserApi(
    "https://console.example",
    () => {},
    async () => {
      requests++;
      return response();
    },
  );
  api.setSession(session);
  const other = {
    ...session,
    principal_id: "00000000-0000-4000-8000-000000000003",
  };
  assert.equal(journal.hasPayload(other, intent.key), false);
  await assert.rejects(
    journal.rehydrate(other, intent.key, body),
    code("INTENT_SCOPE_REJECTED"),
  );
  await assert.rejects(
    journal.execute(api, other, intent.key),
    code("INTENT_SCOPE_REJECTED"),
  );
  const fresh = { ...session, csrf_token: "b".repeat(43) };
  api.setSession(fresh);
  assert.equal(journal.hasPayload(fresh, intent.key), false);
  const previous = storage.value;
  await assert.rejects(
    journal.execute(api, fresh, intent.key),
    code("INTENT_PAYLOAD_REQUIRED"),
  );
  assert.equal(storage.value, previous);
  assert.equal(requests, 0);
  journal.forgetPayloads();
  const recovery = journal.rehydrate(fresh, intent.key, body);
  journal.forgetPayloads();
  await assert.rejects(recovery, code("INTENT_SCOPE_REJECTED"));
  assert.equal(journal.hasPayload(fresh, intent.key), false);
  await journal.rehydrate(fresh, intent.key, body);
  await journal.execute(api, fresh, intent.key);
  assert.equal(requests, 1);
});
test("whole JSON limit is checked before persistence and a storage failure cannot create a dispatchable secret", async () => {
  const storage = new Memory(),
    journal = new IntentJournal(storage, storage.lock);
  const atLimit = await journal.create(session, path, "x".repeat(65534), null);
  assert.equal(journal.hasPayload(session, atLimit.key), true);
  const durable = storage.value;
  await assert.rejects(
    journal.rehydrate(session, atLimit.key, "x".repeat(65535)),
    code("INVALID_INTENT_BODY"),
  );
  assert.equal(storage.value, durable);
  const secondStorage = new Memory(),
    second = new IntentJournal(secondStorage, secondStorage.lock);
  secondStorage.fail = true;
  await assert.rejects(
    second.create(session, path, body, '"1"'),
    code("INTENT_STORAGE_UNAVAILABLE"),
  );
  assert.equal(secondStorage.value, null);
  assert.deepEqual(second.list(session), []);
});
test("one origin-wide lock prevents cross-tab dispatch, and explicit recovery preserves the same durable intent", async () => {
  const storage = new Memory(),
    first = new IntentJournal(storage, storage.lock),
    second = new IntentJournal(storage, storage.lock);
  const intent = await first.create(session, path, body, '"2"');
  await second.rehydrate(session, intent.key, body);
  let release!: () => void, started!: () => void;
  const wait = new Promise<void>((resolve) => {
    release = resolve;
  });
  const entered = new Promise<void>((resolve) => {
    started = resolve;
  });
  let requests = 0;
  const api = new BrowserApi(
    "https://console.example",
    () => {},
    async () => {
      requests++;
      started();
      await wait;
      return response();
    },
  );
  api.setSession(session);
  const pending = first.execute(api, session, intent.key);
  await entered;
  try {
    await assert.rejects(
      second.execute(api, session, intent.key),
      code("REQUEST_ALREADY_PENDING"),
    );
  } finally {
    release();
  }
  await pending;
  assert.equal(requests, 1);
  await assert.rejects(
    second.execute(api, session, intent.key),
    code("INTENT_SCOPE_REJECTED"),
  );
});
test("old ordinary intents and action bodies retain their existing non-sensitive journal behavior", async () => {
  const storage = new Memory(),
    journal = new IntentJournal(storage, storage.lock);
  const old = await journal.create(
    session,
    `/v1/instances/${id}/executions`,
    { argv: ["ordinary existing payload"] },
    '"1"',
  );
  assert.equal(old.bodySha256, undefined);
  assert.equal(storage.value!.includes("ordinary existing payload"), true);
  const action = await journal.create(
    session,
    `/v1/automations/${id}/actions/pause`,
    {},
    '"2"',
  );
  assert.equal(action.bodySha256, undefined);
  assert.deepEqual(action.body, {});
  const tampered = JSON.parse(storage.value!) as Record<string, unknown>[];
  tampered[0]!.bodySha256 = "a".repeat(64);
  storage.setItem(JOURNAL_SLOT, JSON.stringify(tampered));
  assert.throws(
    () => new IntentJournal(storage, storage.lock),
    code("INTENT_STORAGE_INVALID"),
  );
});
