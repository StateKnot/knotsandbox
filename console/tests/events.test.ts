import test from "node:test";
import assert from "node:assert/strict";
import { BrowserApi, EventStreamError } from "../src/api.ts";
import type { Session } from "../src/api.ts";
const tenant = "00000000-0000-4000-8000-000000000001";
const project = "00000000-0000-4000-8000-000000000002";
const instance = "00000000-0000-4000-8000-000000000003";
const requestId = "00000000-0000-4000-8000-000000000004";
const session: Session = {
  tenant_id: tenant,
  principal_id: instance,
  csrf_token: "x".repeat(43),
  absolute_expires_at: "2027-01-01T00:00:00Z",
  idle_expires_at: "2027-01-01T00:00:00Z",
};
function frame(
  event: string,
  data: unknown,
  id: string | null = "opaque.cursor",
) {
  return `event: ${event}\n${id === null ? "" : `id: ${id}\n`}data: ${JSON.stringify(data)}\n\n`;
}
const checkpoint = (sequence = "0") => frame("stream.checkpoint", { sequence });
function domain(sequence = "1", changes = {}) {
  return frame("domain.event", {
    sequence,
    event: {
      id: requestId,
      tenant_id: tenant,
      project_id: project,
      aggregate_id: requestId,
      request_id: requestId,
      operation_id: null,
      event_type: "diagnosis.completed",
      aggregate_version: 1,
      schema_version: 1,
      occurred_at: "2026-10-09T00:00:00Z",
      ...changes,
    },
  });
}
function sse(text: string) {
  return new Response(text, {
    headers: { "content-type": "text/event-stream; charset=utf-8" },
  });
}
function api(send: typeof fetch, unauthorized = () => {}) {
  const api = new BrowserApi("https://console.example", unauthorized, send);
  api.setSession(session);
  return api;
}
function open(api: BrowserApi, overrides = {}) {
  return api.eventStream({
    session,
    projectId: project,
    signal: new AbortController().signal,
    ...overrides,
  });
}
const code = (expected: string, status?: number) => (error: unknown) =>
  error instanceof EventStreamError &&
  error.code === expected &&
  (status === undefined || error.status === status) &&
  error.message === expected;
async function flush() {
  for (let i = 0; i < 20; i++) await Promise.resolve();
}

test("SSE uses exact cookie GET scope without bearer, CSRF, retry or latest reset", async () => {
  const requests: Request[] = [];
  const stream = open(
    api(async (input) => {
      requests.push(input as Request);
      return sse(checkpoint() + domain());
    }),
    { instanceId: instance, lastEventId: "old.cursor" },
  );
  const items = [];
  for await (const item of stream) items.push(item);
  assert.equal(items.length, 2);
  assert.equal(items[1]?.type, "domain.event");
  assert.equal(requests.length, 1);
  const r = requests[0]!;
  const u = new URL(r.url);
  assert.equal(u.origin, "https://console.example");
  assert.equal(u.pathname, "/v1/events/stream");
  assert.deepEqual(
    [...u.searchParams],
    [
      ["project_id", project],
      ["instance_id", instance],
    ],
  );
  assert.equal(r.method, "GET");
  assert.equal(r.credentials, "same-origin");
  assert.equal(r.redirect, "error");
  assert.equal(r.cache, "no-store");
  assert.equal(r.headers.get("accept"), "text/event-stream");
  assert.equal(r.headers.get("x-tenant-id"), tenant);
  assert.equal(r.headers.get("last-event-id"), "old.cursor");
  for (const h of [
    "authorization",
    "cookie",
    "x-csrf-token",
    "idempotency-key",
  ])
    assert.equal(r.headers.get(h), null);
  assert.equal(r.signal.aborted, true);
});
test("invalid input and stale actor never dispatch", async () => {
  let calls = 0;
  const client = api(async () => {
    calls++;
    return sse(checkpoint());
  });
  for (const o of [
    { projectId: "bad" },
    { instanceId: "bad" },
    { lastEventId: "\r\nsecret" },
    { lastEventId: "x".repeat(2049) },
  ])
    await assert.rejects(
      open(client, o).next(),
      code("INVALID_STREAM_CONFIGURATION"),
    );
  client.setSession({ ...session, principal_id: requestId });
  await assert.rejects(
    open(client).next(),
    code("BROWSER_LOGIN_REQUIRED", 401),
  );
  assert.equal(calls, 0);
});
test("401 immediately clears session with a hung body and retains only validated request ID", async () => {
  let logout = 0,
    cancelled = 0;
  const body = new ReadableStream<Uint8Array>({
    cancel() {
      cancelled++;
    },
  });
  const client = api(
    async () =>
      new Response(body, {
        status: 401,
        headers: { "x-request-id": requestId },
      }),
    () => logout++,
  );
  await assert.rejects(
    open(client).next(),
    (e) =>
      code("BROWSER_LOGIN_REQUIRED", 401)(e) &&
      (e as EventStreamError).requestId === requestId,
  );
  assert.equal(logout, 1);
  assert.equal(cancelled, 1);
  await assert.rejects(
    open(client).next(),
    code("BROWSER_LOGIN_REQUIRED", 401),
  );
});
test("HTTP problems expose fixed safe codes and status without automatic retries", async () => {
  for (const status of [400, 403, 404, 409, 410, 503]) {
    let calls = 0;
    const client = api(async () => {
      calls++;
      return new Response(
        JSON.stringify({
          code: "RESOURCE_NOT_FOUND",
          retryable: true,
          detail: "private credential",
        }),
        {
          status,
          headers: {
            "content-type": "application/problem+json",
            "x-request-id": requestId,
          },
        },
      );
    });
    await assert.rejects(
      open(client).next(),
      (e) =>
        code("RESOURCE_NOT_FOUND", status)(e) &&
        (e as EventStreamError).retryable === (status === 503),
    );
    assert.equal(calls, 1);
  }
  const client = api(
    async () =>
      new Response(
        JSON.stringify({ code: "unsafe credential text", retryable: false }),
        {
          status: 410,
          headers: {
            "content-type": "application/problem+json",
            "x-request-id": "unsafe",
          },
        },
      ),
  );
  await assert.rejects(
    open(client).next(),
    (e) =>
      code("EVENT_STREAM_HTTP_ERROR", 410)(e) &&
      (e as EventStreamError).requestId === undefined,
  );
});
test("redirect, non-SSE content and missing checkpoint are refused", async () => {
  for (const [r, c] of [
    [new Response(null, { status: 302 }), "REDIRECT_REJECTED"],
    [
      new Response(checkpoint(), {
        headers: { "content-type": "application/json" },
      }),
      "INVALID_EVENT_STREAM",
    ],
    [sse(""), "EVENT_CHECKPOINT_MISSING"],
  ] as const)
    await assert.rejects(open(api(async () => r)).next(), code(c));
});
test("shared decoder enforces initial checkpoint and exact signed64-bit monotonic sequences", async () => {
  for (const text of [
    domain(),
    checkpoint("9223372036854775808"),
    checkpoint("1") + domain("0"),
    checkpoint("9") + domain("8"),
    checkpoint("01"),
  ])
    await assert.rejects(async () => {
      for await (const _ of open(api(async () => sse(text)))) {
      }
    }, code("INVALID_EVENT_STREAM"));
  const stream = open(
    api(async () =>
      sse(checkpoint("9007199254740992") + domain("9007199254740993")),
    ),
  );
  assert.equal((await stream.next()).value?.sequence, "9007199254740992");
  assert.equal((await stream.next()).value?.sequence, "9007199254740993");
  assert.equal((await stream.next()).done, true);
});
test("foreign scope, malformed UTF8 and oversized frames do not reach consumers", async () => {
  for (const text of [
    checkpoint() + domain("1", { tenant_id: requestId }),
    checkpoint() + domain("1", { project_id: requestId }),
    `:${"x".repeat(256 * 1024)}\n\n`,
  ])
    await assert.rejects(
      async () => {
        for await (const _ of open(api(async () => sse(text)))) {
        }
      },
      (e) => code("INVALID_EVENT_STREAM")(e) || code("EVENT_FRAME_LIMIT")(e),
    );
  await assert.rejects(
    open(
      api(
        async () =>
          new Response(new Uint8Array([255, 10, 10]), {
            headers: { "content-type": "text/event-stream" },
          }),
      ),
    ).next(),
    code("INVALID_EVENT_STREAM"),
  );
});
test("stream.error preserves only decoder-validated code and request ID", async () => {
  const stream = open(
    api(async () =>
      sse(
        checkpoint() +
          frame(
            "stream.error",
            {
              code: "PERMISSION_REVOKED",
              retryable: false,
              request_id: requestId,
              detail: "not echoed",
            },
            null,
          ),
      ),
    ),
  );
  await stream.next();
  await assert.rejects(
    stream.next(),
    (e) =>
      code("PERMISSION_REVOKED")(e) &&
      (e as EventStreamError).requestId === requestId,
  );
});
test("actor changes during fetch or between buffered frames reject the old actor", async () => {
  let release!: (r: Response) => void;
  const client = api(
    async () => await new Promise<Response>((r) => (release = r)),
  );
  const pending = open(client).next();
  await flush();
  client.setSession({ ...session, principal_id: requestId });
  release(sse(checkpoint()));
  await assert.rejects(pending, code("BROWSER_LOGIN_REQUIRED", 401));
  const buffered = api(async () => sse(checkpoint() + domain()));
  const stream = open(buffered);
  await stream.next();
  buffered.setSession({ ...session, principal_id: requestId });
  await assert.rejects(stream.next(), code("BROWSER_LOGIN_REQUIRED", 401));
});
test("return and logout cancel actual bodies without background pumping", async () => {
  let pulls = 0,
    cancels = 0;
  const body = new ReadableStream<Uint8Array>(
    {
      pull(c) {
        pulls++;
        if (pulls === 1) c.enqueue(new TextEncoder().encode(checkpoint()));
      },
      cancel() {
        cancels++;
      },
    },
    { highWaterMark: 0 },
  );
  const client = api(
    async () =>
      new Response(body, { headers: { "content-type": "text/event-stream" } }),
  );
  const stream = open(client);
  await stream.next();
  assert.equal(pulls, 1);
  await stream.return(undefined);
  await flush();
  assert.equal(cancels, 1);
  let stopped = 0;
  const active = api(
    async () =>
      new Response(
        new ReadableStream(
          {
            cancel() {
              stopped++;
            },
          },
          { highWaterMark: 0 },
        ),
        { headers: { "content-type": "text/event-stream" } },
      ),
  );
  const pending = open(active).next();
  await flush();
  active.requireNewLogin();
  await assert.rejects(pending, code("EVENT_STREAM_INTERRUPTED"));
  assert.equal(stopped, 1);
});
test("abort reasons cannot leak and ignored-signal transports cancel late response bodies", async () => {
  const abort = new AbortController();
  let release!: (r: Response) => void,
    cancelled = 0;
  const client = api(
    async () => await new Promise<Response>((r) => (release = r)),
  );
  const pending = open(client, { signal: abort.signal }).next();
  await flush();
  abort.abort(new EventStreamError("SECRET_IN_CALLER_REASON", false));
  await assert.rejects(pending, code("EVENT_STREAM_INTERRUPTED"));
  release(
    new Response(
      new ReadableStream({
        cancel() {
          cancelled++;
        },
      }),
      { headers: { "content-type": "text/event-stream" } },
    ),
  );
  await flush();
  assert.equal(cancelled, 1);
});
test("connect timeout and late Ready-first headers cannot bypass the fixed10s bound", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const pending = open(
    api(async () => await new Promise<Response>(() => {})),
  ).next();
  await flush();
  t.mock.timers.tick(10000);
  await assert.rejects(pending, code("EVENT_STREAM_TIMEOUT"));
  let now = 0;
  t.mock.method(performance, "now", () => now);
  await assert.rejects(
    open(
      api(async () => {
        now = 10001;
        return sse(checkpoint());
      }),
    ).next(),
    code("EVENT_STREAM_TIMEOUT"),
  );
});
test("read-idle45s and caller lifetime300s cancel connections even while yielding", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const pending = open(
    api(
      async () =>
        new Response(new ReadableStream({}), {
          headers: { "content-type": "text/event-stream" },
        }),
    ),
  ).next();
  await flush();
  t.mock.timers.tick(45000);
  await assert.rejects(
    pending,
    (e) =>
      code("EVENT_STREAM_TIMEOUT")(e) || code("EVENT_STREAM_INTERRUPTED")(e),
  );
  let cancels = 0,
    pulls = 0;
  const stream = open(
    api(
      async () =>
        new Response(
          new ReadableStream<Uint8Array>(
            {
              pull(c) {
                pulls++;
                c.enqueue(new TextEncoder().encode(checkpoint()));
              },
              cancel() {
                cancels++;
              },
            },
            { highWaterMark: 0 },
          ),
          { headers: { "content-type": "text/event-stream" } },
        ),
    ),
  );
  await stream.next();
  t.mock.timers.tick(300000);
  await flush();
  assert.equal(cancels, 1);
  assert.equal(pulls, 1);
  await assert.rejects(stream.next(), code("EVENT_STREAM_TIMEOUT"));
});

test("error bodies above64KiB cannot disclose their problem fields", async () => {
  let cancelled = 0;
  const body = new ReadableStream<Uint8Array>({
    start(c) {
      c.enqueue(
        new TextEncoder().encode(
          JSON.stringify({
            code: "PRIVATE_VALID_LOOKING_CODE",
            retryable: false,
            detail: "x".repeat(65536),
          }),
        ),
      );
    },
    cancel() {
      cancelled++;
    },
  });
  await assert.rejects(
    open(
      api(
        async () =>
          new Response(body, {
            status: 410,
            headers: { "content-type": "application/problem+json" },
          }),
      ),
    ).next(),
    code("EVENT_STREAM_HTTP_ERROR", 410),
  );
  assert.equal(cancelled, 1);
});

test("late Ready-first reads are rejected even before the idle timer callback runs", async (t) => {
  let now = 0;
  t.mock.method(performance, "now", () => now);
  const body = new ReadableStream<Uint8Array>(
    {
      pull(c) {
        now += 45001;
        c.enqueue(new TextEncoder().encode(checkpoint()));
      },
    },
    { highWaterMark: 0 },
  );
  await assert.rejects(
    open(
      api(
        async () =>
          new Response(body, {
            headers: { "content-type": "text/event-stream" },
          }),
      ),
    ).next(),
    code("EVENT_STREAM_TIMEOUT"),
  );
});
