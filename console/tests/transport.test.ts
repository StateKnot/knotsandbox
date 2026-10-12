import test from "node:test";
import assert from "node:assert/strict";
import { ApiFailure, BrowserApi, boundedBody } from "../src/api.ts";
import type { Session } from "../src/api.ts";
import { IntentJournal } from "../src/journal.ts";
import type { JournalLock } from "../src/journal.ts";
import {
  sha,
  stageFile,
  verifiedDownload,
  workspacePath,
} from "../src/files.ts";
const id = "00000000-0000-4000-8000-000000000001";
const session: Session = {
  tenant_id: id,
  principal_id: "00000000-0000-4000-8000-000000000002",
  csrf_token: "a".repeat(43),
  absolute_expires_at: new Date(Date.now() + 3600000).toISOString(),
  idle_expires_at: new Date(Date.now() + 1800000).toISOString(),
};
const json = (v: unknown, status = 200) =>
  new Response(JSON.stringify(v), {
    status,
    headers: {
      "content-type":
        status >= 400 ? "application/problem+json" : "application/json",
      "x-request-id": id,
    },
  });
function sharedLock(): JournalLock {
  let locked = false;
  return async <T>(work: () => Promise<T>): Promise<T> => {
    if (locked) throw new ApiFailure("REQUEST_ALREADY_PENDING");
    locked = true;
    try {
      return await work();
    } finally {
      locked = false;
    }
  };
}

class Memory {
  readonly lock = sharedLock();
  value: string | null = null;
  getItem() {
    return this.value;
  }
  setItem(_key: string, value: string) {
    this.value = value;
  }
}
test("cookie transport is origin/tenant confined, never accepts bearer credentials, and adds CSRF only for mutations", async () => {
  const received: Request[] = [];
  const api = new BrowserApi(
    "https://console.example",
    () => {},
    async (request) => {
      received.push(request as Request);
      return json({ ok: true });
    },
  );
  api.setSession(session);
  await api.raw("/v1/instances", "POST", {}, { "idempotency-key": id });
  const r = received[0]!;
  assert.equal(r.credentials, "same-origin");
  assert.equal(r.redirect, "error");
  assert.equal(r.headers.get("authorization"), null);
  assert.equal(r.headers.get("x-csrf-token"), session.csrf_token);
  assert.equal(r.headers.get("x-tenant-id"), session.tenant_id);
  await api.raw("/v1/instances");
  assert.equal(received[1]!.headers.get("x-csrf-token"), null);
  await assert.rejects(
    api.fetch(new Request("https://elsewhere.example/v1/instances")),
    /REQUEST_SCOPE_REJECTED/,
  );
  await assert.rejects(
    api.raw("/v1/instances", "GET", undefined, {
      authorization: "Bearer secret",
    }),
    /MIXED_CREDENTIALS_REJECTED/,
  );
  await assert.rejects(
    api.raw("/v1/instances", "GET", undefined, {
      "x-tenant-id": session.principal_id,
    }),
    /TENANT_MISMATCH/,
  );
  assert.equal(received.length, 2);
});
test("unauthorized response invalidates the session while retaining the bounded public problem code", async () => {
  let revoked = 0;
  const api = new BrowserApi(
    "https://console.example",
    () => revoked++,
    async () =>
      json({ code: "BROWSER_LOGIN_REQUIRED", private: "not echoed" }, 401),
  );
  api.setSession(session);
  await assert.rejects(
    api.raw("/auth/session"),
    (error: unknown) =>
      error instanceof ApiFailure &&
      error.code === "BROWSER_LOGIN_REQUIRED" &&
      !error.message.includes("private"),
  );
  assert.equal(revoked, 1);
  await assert.rejects(api.raw("/v1/instances"), /BROWSER_LOGIN_REQUIRED/);
});
test("unknown mutation survives reload with identical key, body and version; duplicate/new tenant replay is refused", async () => {
  const storage = new Memory();
  let attempt = 0;
  const received: Request[] = [];
  const api = new BrowserApi(
    "https://console.example",
    () => {},
    async (request) => {
      received.push((request as Request).clone());
      if (attempt++ === 0) throw Error("network lost");
      return json({ operation: { id }, resource: { id } });
    },
  );
  api.setSession(session);
  const journal = new IntentJournal(storage, storage.lock);
  const row = await journal.create(
    session,
    `/v1/instances/${id}/executions`,
    { argv: ["python3", "-c", "print(1)"] },
    '"7"',
  );
  await assert.rejects(journal.execute(api, session, row.key));
  assert.equal(journal.list(session)[0]!.state, "UNKNOWN");
  const recovered = new IntentJournal(storage, storage.lock);
  await assert.rejects(
    recovered.create(session, row.path, { argv: ["other"] }, '"8"'),
    /RECONCILE_ORIGINAL_REQUEST_FIRST/,
  );
  await assert.rejects(
    recovered.execute(
      api,
      { ...session, tenant_id: session.principal_id },
      row.key,
    ),
    /INTENT_SCOPE_REJECTED/,
  );
  await recovered.execute(api, session, row.key);
  assert.equal(received.length, 2);
  assert.equal(await received[0]!.text(), await received[1]!.text());
  assert.equal(
    received[0]!.headers.get("idempotency-key"),
    received[1]!.headers.get("idempotency-key"),
  );
  assert.equal(received[1]!.headers.get("if-match"), '"7"');
  assert.equal(recovered.list(session)[0]!.state, "ACCEPTED");
  assert.equal(recovered.list(session)[0]!.operationId, id);
  assert.doesNotMatch(storage.value!, /access_token|refresh_token|csrf_token/);
});
test("failed durable browser journal storage prevents dispatch", async () => {
  const journal = new IntentJournal(
    {
      getItem: () => null,
      setItem: () => {
        throw Error("quota");
      },
    },
    sharedLock(),
  );
  await assert.rejects(
    journal.create(session, "/v1/instances", {}, null),
    /INTENT_STORAGE_UNAVAILABLE/,
  );
});
for (const path of [
  `/v1/service-clients/${id}`,
  `/v1/projects/${id}/grants/${session.principal_id}`,
]) {
  test(`PATCH ${path} recovers the original intent and preserves an unknown outcome after a later version rejection`, async () => {
    const storage = new Memory();
    const received: Request[] = [];
    const api = new BrowserApi(
      "https://console.example",
      () => {},
      async (input) => {
        received.push((input as Request).clone());
        if (received.length === 1) throw Error("acknowledgement lost");
        if (received.length === 2)
          return json({ code: "VERSION_MISMATCH" }, 412);
        return json({ resource: { id } });
      },
    );
    api.setSession(session);
    const body = { enabled: false, display_name: "integration client" };
    const first = new IntentJournal(storage, storage.lock);
    const intent = await first.create(session, path, body, '"7"', "PATCH");
    body.enabled = true;
    await assert.rejects(
      first.execute(api, session, intent.key),
      /NETWORK_FAILURE/,
    );
    const recovered = new IntentJournal(storage, storage.lock);
    await assert.rejects(
      recovered.execute(api, session, intent.key),
      /VERSION_MISMATCH/,
    );
    assert.equal(recovered.list(session)[0]!.state, "UNKNOWN");
    await assert.rejects(
      recovered.create(session, path, body, '"8"', "PATCH"),
      /RECONCILE_ORIGINAL_REQUEST_FIRST/,
    );
    await recovered.execute(api, session, intent.key);
    for (const request of received) {
      assert.equal(request.method, "PATCH");
      assert.equal(request.headers.get("idempotency-key"), intent.key);
      assert.equal(request.headers.get("if-match"), '"7"');
      assert.equal(request.headers.get("x-csrf-token"), session.csrf_token);
      assert.equal(request.headers.get("x-tenant-id"), session.tenant_id);
      assert.deepEqual(await request.json(), {
        enabled: false,
        display_name: "integration client",
      });
    }
    assert.equal(recovered.list(session)[0]!.state, "ACCEPTED");
    assert.equal(recovered.list(session)[0]!.resourceId, id);
    assert.equal(recovered.list(session)[0]!.body, null);
  });
}
test("journal rejects unsupported mutation methods before persistence", async () => {
  const storage = new Memory();
  const journal = new IntentJournal(storage, storage.lock);
  await assert.rejects(
    journal.create(session, "/v1/service-clients", {}, null, "GET" as "POST"),
    /INVALID_INTENT/,
  );
  assert.equal(storage.value, null);
});
test("grant revocation replays DELETE without a JSON body or content type", async () => {
  const storage = new Memory();
  const received: Request[] = [];
  const api = new BrowserApi(
    "https://console.example",
    () => {},
    async (input) => {
      received.push((input as Request).clone());
      if (received.length === 1) throw Error("response lost");
      return json({ resource: { id } });
    },
  );
  api.setSession(session);
  const journal = new IntentJournal(storage, storage.lock);
  await assert.rejects(
    journal.create(
      session,
      `/v1/projects/${id}/grants/${id}`,
      { enabled: false },
      '"7"',
      "DELETE",
    ),
    /INVALID_INTENT/,
  );
  const row = await journal.create(
    session,
    `/v1/projects/${id}/grants/${id}`,
    null,
    '"7"',
    "DELETE",
  );
  await assert.rejects(journal.execute(api, session, row.key));
  await new IntentJournal(storage, storage.lock).execute(api, session, row.key);
  for (const request of received) {
    assert.equal(request.method, "DELETE");
    assert.equal(request.headers.get("content-type"), null);
    assert.equal(await request.text(), "");
    assert.equal(request.headers.get("if-match"), '"7"');
    assert.equal(request.headers.get("idempotency-key"), row.key);
  }
});
test("response limits cancel readers and abort interrupts a stalled response", async () => {
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    start(c) {
      c.enqueue(new Uint8Array(33));
    },
    cancel() {
      cancelled = true;
    },
  });
  await assert.rejects(
    boundedBody(stream, 32, new AbortController().signal),
    /RESPONSE_TOO_LARGE/,
  );
  assert.equal(cancelled, true);
  const controller = new AbortController();
  const stalled = new ReadableStream<Uint8Array>();
  const wait = boundedBody(stalled, 10, controller.signal);
  controller.abort();
  await assert.rejects(wait);
});
test("file path rejects escape, aliases and controls; unverified bytes never escape download", async () => {
  for (const path of [
    "/absolute",
    "a//b",
    "a/../b",
    "a/./b",
    "a\\b",
    "a\u0000b",
  ])
    assert.throws(() => workspacePath(path), /INVALID_WORKSPACE_PATH/);
  assert.equal(workspacePath("src/main.py"), "src/main.py");
  const bytes = new Uint8Array([1, 2, 3]);
  const digest = await sha(bytes);
  const original = globalThis.fetch;
  const transfer = {
    id,
    direction: "DOWNLOAD",
    status: "SUCCEEDED",
    content_status: "FROZEN",
    version: 3,
    observed_bytes: 3,
    observed_sha256: digest,
  } as Parameters<typeof verifiedDownload>[2];
  try {
    globalThis.fetch = async () =>
      new Response(new Uint8Array([1, 2, 4]), {
        headers: {
          "content-type": "application/octet-stream",
          "content-length": "3",
          "x-content-sha256": digest,
          etag: '"3"',
        },
      });
    const api = new BrowserApi("https://console.example", () => {});
    api.setSession(session);
    await assert.rejects(
      verifiedDownload(api, session, transfer, new AbortController().signal),
      /FILE_INTEGRITY_FAILED/,
    );
  } finally {
    globalThis.fetch = original;
  }
});
test("browser upload uses known bytes with CSRF but no forbidden explicit Content-Length header and never auto-retries", async () => {
  const original = globalThis.fetch;
  let attempts = 0;
  const file = new File([new Uint8Array([1, 2, 3])], "sample.bin");
  const transfer = {
    id,
    direction: "UPLOAD",
    status: "WAITING_UPLOAD",
    version: 3,
    byte_limit: 3,
  } as Parameters<typeof stageFile>[2];
  const api = new BrowserApi("https://console.example", () => {});
  api.setSession(session);
  try {
    globalThis.fetch = async (input, init) => {
      attempts++;
      assert.equal(new Headers(init?.headers).get("content-length"), null);
      assert.equal(
        new Headers(init?.headers).get("x-csrf-token"),
        session.csrf_token,
      );
      assert.equal(init?.credentials, "same-origin");
      assert.match(String(input), new RegExp(`/content/0$`));
      throw Error("network loss");
    };
    await assert.rejects(
      stageFile(
        api,
        session,
        transfer,
        file,
        new AbortController().signal,
        () => {},
      ),
    );
    assert.equal(attempts, 1);
  } finally {
    globalThis.fetch = original;
  }
});
test("browser session rejects additional OAuth fields without echoing them", () => {
  const api = new BrowserApi("https://console.example", () => {});
  assert.throws(
    () =>
      api.setSession({
        ...session,
        access_token: "PRIVATE_TOKEN_MUST_NOT_ECHO",
      } as Session),
    (error: unknown) =>
      error instanceof ApiFailure &&
      error.code === "INVALID_BROWSER_SESSION" &&
      !error.message.includes("PRIVATE_TOKEN"),
  );
});
test("logout cancellation stops an active bounded file download before bytes can be returned", async () => {
  const original = globalThis.fetch;
  const api = new BrowserApi("https://console.example", () => {});
  api.setSession(session);
  let opened!: () => void;
  const ready = new Promise<void>((resolve) => (opened = resolve));
  const transfer = {
    id,
    direction: "DOWNLOAD",
    status: "SUCCEEDED",
    content_status: "FROZEN",
    version: 3,
    observed_bytes: 3,
    observed_sha256: "a".repeat(64),
  } as Parameters<typeof verifiedDownload>[2];
  try {
    globalThis.fetch = async () => {
      opened();
      return new Response(new ReadableStream<Uint8Array>(), {
        headers: {
          "content-type": "application/octet-stream",
          "content-length": "3",
          "x-content-sha256": transfer.observed_sha256!,
          etag: '"3"',
        },
      });
    };
    const pending = verifiedDownload(
      api,
      session,
      transfer,
      new AbortController().signal,
    );
    await ready;
    api.cancelAll();
    await assert.rejects(pending);
  } finally {
    globalThis.fetch = original;
  }
});

test("origin-shared lock rereads stale tabs and captures body before waiting", async () => {
  const storage = new Memory(),
    first = new IntentJournal(storage, storage.lock),
    stale = new IntentJournal(storage, storage.lock);
  const body = { argv: ["safe"] };
  const creating = first.create(session, "/v1/instances", body, null);
  body.argv[0] = "changed-after-call";
  const row = await creating;
  assert.deepEqual(row.body, { argv: ["safe"] });
  (row.body as { argv: string[] }).argv[0] = "changed-returned-copy";
  await assert.rejects(
    stale.create(session, row.path, {}, null),
    /RECONCILE_ORIGINAL_REQUEST_FIRST/,
  );
  assert.deepEqual(stale.list(session)[0]!.body, { argv: ["safe"] });
});

test("same-key concurrent tabs dispatch once and rejected overlap cannot downgrade the ACK", async () => {
  const storage = new Memory(),
    first = new IntentJournal(storage, storage.lock),
    second = new IntentJournal(storage, storage.lock);
  let release!: () => void,
    opened!: () => void,
    calls = 0;
  const gate = new Promise<void>((resolve) => (release = resolve)),
    ready = new Promise<void>((resolve) => (opened = resolve));
  const api = new BrowserApi(
    "https://console.example",
    () => {},
    async () => {
      calls++;
      opened();
      await gate;
      return json({ operation: { id } });
    },
  );
  api.setSession(session);
  const row = await first.create(
    session,
    "/v1/instances",
    { argv: ["private-input"] },
    null,
  );
  const a = first.execute(api, session, row.key);
  await ready;
  const b = second.execute(api, session, row.key);
  const refused = assert.rejects(b, /REQUEST_ALREADY_PENDING/);
  release();
  await a;
  await refused;
  assert.equal(calls, 1);
  assert.equal(second.list(session)[0]!.state, "ACCEPTED");
  assert.equal(second.list(session)[0]!.body, null);
  assert.doesNotMatch(storage.value!, /private-input/);
});

test("late local persistence exception preserves an already saved ACK and never resends", async () => {
  const storage = new Memory();
  const journal = new IntentJournal(
    {
      getItem: () => storage.value,
      setItem: (_key, value) => {
        storage.value = value;
        if (value.includes('"ACCEPTED"')) throw Error("late local error");
      },
    },
    storage.lock,
  );
  const row = await journal.create(
    session,
    "/v1/instances",
    { argv: ["private-input"] },
    null,
  );
  let calls = 0;
  const api = new BrowserApi(
    "https://console.example",
    () => {},
    async () => {
      calls++;
      return json({ operation: { id } });
    },
  );
  api.setSession(session);
  await assert.rejects(
    journal.execute(api, session, row.key),
    /INTENT_STORAGE_UNAVAILABLE/,
  );
  assert.equal(journal.list(session)[0]!.state, "ACCEPTED");
  assert.equal(journal.list(session)[0]!.body, null);
  await assert.rejects(
    journal.execute(api, session, row.key),
    /INTENT_SCOPE_REJECTED/,
  );
  assert.equal(calls, 1);
});

test("missing native lock support refuses mutations; queued original actor cannot switch", async () => {
  const storage = new Memory();
  await assert.rejects(
    new IntentJournal(storage, null).create(session, "/v1/instances", {}, null),
    /BROWSER_LOCKS_REQUIRED/,
  );
  assert.equal(storage.value, null);
  const journal = new IntentJournal(storage, storage.lock),
    row = await journal.create(session, "/v1/instances", {}, null);
  let sent = false;
  const api = new BrowserApi(
    "https://console.example",
    () => {},
    async () => {
      sent = true;
      return json({});
    },
  );
  api.setSession({ ...session, principal_id: id });
  await assert.rejects(
    journal.execute(api, session, row.key),
    /BROWSER_LOGIN_REQUIRED/,
  );
  assert.equal(sent, false);
  assert.equal(journal.list(session)[0]!.state, "READY");
});

test("lost committed receipt then revoked permission cannot clear an unknown request across tabs", async () => {
  const storage = new Memory(),
    first = new IntentJournal(storage, storage.lock),
    next = new IntentJournal(storage, storage.lock);
  let attempt = 0;
  const requests: Request[] = [];
  const api = new BrowserApi(
    "https://console.example",
    () => {},
    async (request) => {
      requests.push((request as Request).clone());
      if (attempt++ === 0) throw Error("receipt lost after commit");
      if (attempt === 2) return json({ code: "PERMISSION_DENIED" }, 403);
      return json({ operation: { id } });
    },
  );
  api.setSession(session);
  const row = await first.create(
    session,
    "/v1/instances",
    { name: "original" },
    '"7"',
  );
  await assert.rejects(first.execute(api, session, row.key));
  await assert.rejects(
    next.execute(api, session, row.key),
    /PERMISSION_DENIED/,
  );
  assert.equal(first.list(session)[0]!.state, "UNKNOWN");
  assert.deepEqual(first.list(session)[0]!.body, { name: "original" });
  await assert.rejects(
    first.create(session, row.path, { name: "new" }, '"8"'),
    /RECONCILE_ORIGINAL_REQUEST_FIRST/,
  );
  await next.execute(api, session, row.key);
  assert.equal(first.list(session)[0]!.state, "ACCEPTED");
  for (const request of requests) {
    assert.equal(request.headers.get("idempotency-key"), row.key);
    assert.equal(request.headers.get("if-match"), '"7"');
    assert.deepEqual(await request.json(), { name: "original" });
  }
});

test("first definitive denial can reject READY but idempotency conflict stays UNKNOWN", async () => {
  for (const [code, state] of [
    ["PERMISSION_DENIED", "REJECTED"],
    ["IDEMPOTENCY_CONFLICT", "UNKNOWN"],
  ] as const) {
    const storage = new Memory(),
      journal = new IntentJournal(storage, storage.lock);
    const api = new BrowserApi(
      "https://console.example",
      () => {},
      async () => json({ code }, 409),
    );
    api.setSession(session);
    const row = await journal.create(
      session,
      "/v1/instances",
      { name: "original" },
      null,
    );
    await assert.rejects(journal.execute(api, session, row.key));
    assert.equal(journal.list(session)[0]!.state, state);
    if (state === "UNKNOWN")
      await assert.rejects(
        journal.create(session, row.path, {}, null),
        /RECONCILE_ORIGINAL_REQUEST_FIRST/,
      );
  }
});

test("failed ACK storage leaves a attempted record; later 404 cannot authorize a fresh key", async () => {
  const storage = new Memory();
  let failAck = true,
    attempt = 0;
  const journal = new IntentJournal(
    {
      getItem: () => storage.value,
      setItem: (_key, value) => {
        if (failAck && value.includes('"ACCEPTED"')) {
          failAck = false;
          throw Error("quota before ACK save");
        }
        storage.value = value;
      },
    },
    storage.lock,
  );
  const api = new BrowserApi(
    "https://console.example",
    () => {},
    async () =>
      attempt++ === 0
        ? json({ operation: { id } })
        : json({ code: "RESOURCE_NOT_FOUND" }, 404),
  );
  api.setSession(session);
  const row = await journal.create(
    session,
    "/v1/instances",
    { name: "original" },
    null,
  );
  await assert.rejects(
    journal.execute(api, session, row.key),
    /INTENT_STORAGE_UNAVAILABLE/,
  );
  await assert.rejects(
    journal.execute(api, session, row.key),
    /RESOURCE_NOT_FOUND/,
  );
  assert.equal(journal.list(session)[0]!.state, "UNKNOWN");
  assert.deepEqual(journal.list(session)[0]!.body, { name: "original" });
  await assert.rejects(
    journal.create(session, row.path, {}, null),
    /RECONCILE_ORIGINAL_REQUEST_FIRST/,
  );
});

test("overlapping explicit callers are not queued into an automatic retry after a lost receipt", async () => {
  const storage = new Memory(),
    first = new IntentJournal(storage, storage.lock),
    other = new IntentJournal(storage, storage.lock);
  let opened!: () => void,
    release!: () => void,
    calls = 0;
  const ready = new Promise<void>((resolve) => (opened = resolve)),
    gate = new Promise<void>((resolve) => (release = resolve));
  const api = new BrowserApi(
    "https://console.example",
    () => {},
    async () => {
      calls++;
      opened();
      await gate;
      throw Error("lost receipt");
    },
  );
  api.setSession(session);
  const row = await first.create(session, "/v1/instances", {}, null);
  const attempt = first.execute(api, session, row.key),
    lost = assert.rejects(attempt);
  await ready;
  await assert.rejects(
    other.execute(api, session, row.key),
    /REQUEST_ALREADY_PENDING/,
  );
  release();
  await lost;
  assert.equal(calls, 1);
  assert.equal(other.list(session)[0]!.state, "UNKNOWN");
});
