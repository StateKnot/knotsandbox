import createClient from "openapi-fetch";
import type { paths, components } from "../../sdk/typescript/src/schema.js";
import { decodeEventStreamMessage } from "../../sdk/typescript/src/event-message.ts";
import {
  CURSOR,
  EventStreamError,
  frames,
  httpError,
} from "../../sdk/typescript/src/sse.ts";
import { abortable } from "../../sdk/typescript/src/transport.ts";
import type { EventStreamMessage } from "../../sdk/typescript/src/events.js";
export type { EventStreamMessage } from "../../sdk/typescript/src/events.js";
export { EventStreamError } from "../../sdk/typescript/src/sse.ts";
export type Schema = components["schemas"];
export type Session = Schema["BrowserSession"];
export const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const ETAG = /^"[1-9][0-9]*"$/;
const INSTANCE_ACTIONS = {
  start: "/v1/instances/{id}/actions/start",
  stop: "/v1/instances/{id}/actions/stop",
  restart: "/v1/instances/{id}/actions/restart",
  renew: "/v1/instances/{id}/actions/renew",
} as const satisfies Record<string, keyof paths>;
export function instanceActionPath(
  id: string,
  action: keyof typeof INSTANCE_ACTIONS,
): string {
  if (!UUID.test(id)) throw new ApiFailure("INVALID_INSTANCE_ID");
  return INSTANCE_ACTIONS[action].replace("{id}", id);
}
export function validateSession(value: unknown): Session {
  if (typeof value !== "object" || value === null)
    throw new ApiFailure("INVALID_BROWSER_SESSION");
  const v = value as Record<string, unknown>;
  const fields = [
    "tenant_id",
    "principal_id",
    "csrf_token",
    "absolute_expires_at",
    "idle_expires_at",
  ];
  if (
    Object.keys(v).length !== fields.length ||
    fields.some((k) => typeof v[k] !== "string") ||
    typeof v.tenant_id !== "string" ||
    !UUID.test(v.tenant_id) ||
    typeof v.principal_id !== "string" ||
    !UUID.test(v.principal_id) ||
    typeof v.csrf_token !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(v.csrf_token) ||
    !Number.isFinite(Date.parse(String(v.absolute_expires_at))) ||
    !Number.isFinite(Date.parse(String(v.idle_expires_at)))
  )
    throw new ApiFailure("INVALID_BROWSER_SESSION");
  return {
    tenant_id: v.tenant_id,
    principal_id: v.principal_id,
    csrf_token: v.csrf_token,
    absolute_expires_at: String(v.absolute_expires_at),
    idle_expires_at: String(v.idle_expires_at),
  };
}
export class ApiFailure extends Error {
  readonly code: string;
  readonly status: number | null;
  readonly requestId: string | null;
  constructor(
    code: string,
    status: number | null = null,
    requestId: string | null = null,
  ) {
    super(code);
    this.name = "ApiFailure";
    this.code = code;
    this.status = status;
    this.requestId = requestId;
  }
}
export async function boundedBody(
  body: ReadableStream<Uint8Array> | null,
  max: number,
  signal: AbortSignal,
): Promise<Uint8Array<ArrayBuffer>> {
  if (!body) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0,
    complete = false;
  const abort = () => {
    void reader.cancel().catch(() => {});
  };
  signal.addEventListener("abort", abort, { once: true });
  try {
    for (;;) {
      signal.throwIfAborted();
      const next = await reader.read();
      signal.throwIfAborted();
      if (next.done) {
        complete = true;
        break;
      }
      size += next.value.length;
      if (size > max) throw new ApiFailure("RESPONSE_TOO_LARGE");
      chunks.push(next.value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    return bytes;
  } finally {
    signal.removeEventListener("abort", abort);
    if (!complete) void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}
export function problem(response: Response, value: unknown): ApiFailure {
  const code =
    typeof value === "object" &&
    value !== null &&
    "code" in value &&
    typeof value.code === "string" &&
    /^[A-Z][A-Z0-9_]{0,127}$/.test(value.code)
      ? value.code
      : "REQUEST_FAILED";
  const id = response.headers.get("x-request-id");
  return new ApiFailure(code, response.status, id && UUID.test(id) ? id : null);
}
export function unwrap<T>(result: {
  data?: T;
  error?: unknown;
  response: Response;
}): T {
  if (!result.response.ok) throw problem(result.response, result.error);
  if (result.data === undefined)
    throw new ApiFailure("INVALID_RESPONSE", result.response.status);
  return result.data;
}
export class BrowserApi {
  private session: Session | null = null;
  private readonly active = new Set<AbortController>();
  readonly client;
  constructor(
    readonly origin: string,
    private readonly onUnauthorized: () => void,
    private readonly send: typeof fetch = globalThis.fetch.bind(globalThis),
  ) {
    const target = new URL(origin);
    if (
      target.origin !== origin ||
      (target.protocol !== "https:" &&
        !(
          target.protocol === "http:" &&
          ["127.0.0.1", "[::1]"].includes(target.hostname)
        ))
    )
      throw new ApiFailure("INVALID_ORIGIN");
    this.client = createClient<paths>({ baseUrl: origin, fetch: this.fetch });
  }
  setSession(value: Session | null) {
    this.session = value === null ? null : validateSession(value);
  }
  assertActor(session: Pick<Session, "tenant_id" | "principal_id">) {
    if (
      !this.session ||
      this.session.tenant_id !== session.tenant_id ||
      this.session.principal_id !== session.principal_id
    )
      throw new ApiFailure("BROWSER_LOGIN_REQUIRED", 401);
  }
  fileLease(session: Session, parent: AbortSignal) {
    this.assertActor(session);
    const controller = new AbortController();
    this.active.add(controller);
    return {
      signal: AbortSignal.any([parent, controller.signal]),
      end: () => {
        controller.abort();
        this.active.delete(controller);
      },
    };
  }
  cancelAll() {
    for (const controller of this.active) controller.abort();
    this.active.clear();
  }
  requireNewLogin() {
    this.session = null;
    this.cancelAll();
    this.onUnauthorized();
  }
  /** One cookie-authenticated connection; the caller owns reconnect and its cursor. */
  async *eventStream(input: {
    session: Session;
    projectId: string;
    instanceId?: string;
    lastEventId?: string;
    signal: AbortSignal;
  }): AsyncGenerator<EventStreamMessage> {
    const session = validateSession(input.session);
    const { projectId, instanceId, lastEventId, signal: parent } = input;
    if (
      !UUID.test(projectId) ||
      (instanceId !== undefined && !UUID.test(instanceId)) ||
      (lastEventId !== undefined && !CURSOR.test(lastEventId))
    )
      throw new EventStreamError("INVALID_STREAM_CONFIGURATION", false);
    const controller = new AbortController();
    const signal = AbortSignal.any([parent, controller.signal]);
    const expiresAt = performance.now() + 300000;
    const connectsUntil = performance.now() + 10000;
    const timedOut = () =>
      controller.abort(new EventStreamError("EVENT_STREAM_TIMEOUT", false));
    const totalTimer = setTimeout(timedOut, 300000);
    const connectTimer = setTimeout(timedOut, 10000);
    let response: Response | undefined;
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let closed = false;
    let unauthorized = false;
    const close = () => {
      if (closed) return;
      closed = true;
      clearTimeout(totalTimer);
      clearTimeout(connectTimer);
      this.active.delete(controller);
      controller.abort();
      // Cancel even while the consumer is paused at a yielded message.
      if (reader) {
        const held = reader;
        void held
          .cancel()
          .catch(() => {})
          .finally(() => held.releaseLock());
      } else if (response?.body && !response.body.locked) {
        void response.body.cancel().catch(() => {});
      }
    };
    const current = () => {
      signal.throwIfAborted();
      this.assertActor(session);
      if (performance.now() >= expiresAt)
        throw new EventStreamError("EVENT_STREAM_TIMEOUT", false);
    };
    const safe = (error: unknown): EventStreamError => {
      if (unauthorized) {
        const id = response?.headers.get("x-request-id");
        return new EventStreamError(
          "BROWSER_LOGIN_REQUIRED",
          false,
          401,
          id && UUID.test(id) ? id : undefined,
        );
      }
      if (parent.aborted)
        return new EventStreamError("EVENT_STREAM_INTERRUPTED", false);
      if (controller.signal.reason instanceof EventStreamError)
        return controller.signal.reason;
      if (error instanceof ApiFailure)
        return new EventStreamError(
          error.code,
          false,
          error.status ?? undefined,
          error.requestId ?? undefined,
        );
      if (signal.aborted)
        return new EventStreamError("EVENT_STREAM_INTERRUPTED", false);
      if (error instanceof EventStreamError) return error;
      return new EventStreamError("EVENT_STREAM_INTERRUPTED", false);
    };
    this.active.add(controller);
    signal.addEventListener("abort", close, { once: true });
    try {
      current();
      const url = new URL("/v1/events/stream", this.origin);
      url.searchParams.set("project_id", projectId);
      if (instanceId !== undefined)
        url.searchParams.set("instance_id", instanceId);
      const headers = new Headers({
        "x-tenant-id": session.tenant_id,
        accept: "text/event-stream",
      });
      if (lastEventId !== undefined) headers.set("last-event-id", lastEventId);
      const pending = this.send(
        new Request(url, {
          headers,
          signal,
          credentials: "same-origin",
          redirect: "error",
          cache: "no-store",
        }),
      ).then((value) => {
        if (closed || signal.aborted) void value.body?.cancel().catch(() => {});
        return value;
      });
      response = await abortable(pending, signal);
      current();
      if (performance.now() >= connectsUntil)
        throw new EventStreamError("EVENT_STREAM_TIMEOUT", false);
      clearTimeout(connectTimer);
      if (response.status >= 300 && response.status < 400)
        throw new EventStreamError("REDIRECT_REJECTED", false, response.status);
      if (response.status !== 200) {
        // Invalidate the browser session immediately, before reading an error body.
        if (response.status === 401) {
          unauthorized = true;
          this.requireNewLogin();
          throw new EventStreamError("BROWSER_LOGIN_REQUIRED", false, 401);
        }
        const error = await httpError(response, signal, 10000);
        current();
        throw error;
      }
      if (
        response.headers.get("content-type")?.split(";", 1)[0]?.trim() !==
          "text/event-stream" ||
        !response.body
      )
        throw new EventStreamError("INVALID_EVENT_STREAM", false);
      reader = response.body.getReader();
      const held = reader;
      // No background pump. The shared parser requests exactly one bounded read.
      const body = new ReadableStream<Uint8Array>(
        {
          pull: async (output) => {
            const readUntil = performance.now() + 45000;
            const idle = setTimeout(timedOut, 45000);
            try {
              const next = await abortable(held.read(), signal);
              current();
              if (performance.now() >= readUntil)
                throw new EventStreamError("EVENT_STREAM_TIMEOUT", false);
              if (next.done) output.close();
              else output.enqueue(next.value);
            } catch (error) {
              controller.abort(safe(error));
              output.error(safe(error));
            } finally {
              clearTimeout(idle);
            }
          },
          cancel: () => {
            void held.cancel().catch(() => {});
          },
        },
        { highWaterMark: 0 },
      );
      let checkpoint = false;
      let previousSequence: bigint | undefined;
      for await (const frame of frames(body, signal, 45000)) {
        current();
        const item = decodeEventStreamMessage(
          frame,
          session.tenant_id,
          projectId,
        );
        if (!checkpoint && item.type !== "stream.checkpoint")
          throw new EventStreamError("INVALID_EVENT_STREAM", false);
        const sequence = BigInt(item.sequence);
        if (previousSequence !== undefined && sequence < previousSequence)
          throw new EventStreamError("INVALID_EVENT_STREAM", false);
        checkpoint = true;
        previousSequence = sequence;
        current();
        yield item;
        current();
      }
      current();
      if (!checkpoint)
        throw new EventStreamError("EVENT_CHECKPOINT_MISSING", false);
    } catch (error) {
      throw safe(error);
    } finally {
      signal.removeEventListener("abort", close);
      close();
    }
  }
  readonly fetch = async (input: Request): Promise<Response> => {
    const url = new URL(input.url);
    if (
      url.origin !== this.origin ||
      !/^\/(v1\/|auth\/(login|session|logout)$)/.test(url.pathname) ||
      url.username ||
      url.password ||
      url.hash
    )
      throw new ApiFailure("REQUEST_SCOPE_REJECTED");
    const headers = new Headers(input.headers);
    if (headers.has("authorization") || headers.has("cookie"))
      throw new ApiFailure("MIXED_CREDENTIALS_REJECTED");
    const mutation = !["GET", "HEAD", "OPTIONS"].includes(input.method);
    if (url.pathname.startsWith("/v1/")) {
      if (!this.session) throw new ApiFailure("BROWSER_LOGIN_REQUIRED", 401);
      const tenant = headers.get("x-tenant-id");
      if (
        tenant &&
        tenant.toLowerCase() !== this.session.tenant_id.toLowerCase()
      )
        throw new ApiFailure("TENANT_MISMATCH");
      headers.set("x-tenant-id", this.session.tenant_id);
    }
    if (mutation && url.pathname !== "/auth/login") {
      if (!this.session) throw new ApiFailure("BROWSER_LOGIN_REQUIRED", 401);
      headers.set("x-csrf-token", this.session.csrf_token);
    }
    const controller = new AbortController();
    this.active.add(controller);
    const signal = AbortSignal.any([input.signal, controller.signal]);
    const timer = setTimeout(
      () =>
        controller.abort(new DOMException("Request timeout", "TimeoutError")),
      20000,
    );
    try {
      const response = await this.send(
        new Request(input, {
          headers,
          signal,
          credentials: "same-origin",
          redirect: "error",
          cache: "no-store",
        }),
      );
      const type = response.headers
        .get("content-type")
        ?.split(";", 1)[0]
        ?.trim();
      if (
        response.status !== 204 &&
        type !== "application/json" &&
        type !== "application/problem+json"
      )
        throw new ApiFailure("INVALID_CONTENT_TYPE", response.status);
      const bytes = await boundedBody(response.body, 4 * 1024 * 1024, signal);
      if (response.status === 401 && url.pathname !== "/auth/login") {
        this.session = null;
        for (const other of this.active)
          if (other !== controller) other.abort();
        this.onUnauthorized();
      }
      const outputHeaders = new Headers(response.headers);
      outputHeaders.delete("content-length");
      outputHeaders.delete("content-encoding");
      return new Response(response.status === 204 ? null : bytes, {
        status: response.status,
        statusText: response.statusText,
        headers: outputHeaders,
      });
    } catch (error) {
      if (error instanceof ApiFailure) throw error;
      throw new ApiFailure(
        signal.aborted ? "REQUEST_INTERRUPTED" : "NETWORK_FAILURE",
      );
    } finally {
      clearTimeout(timer);
      this.active.delete(controller);
    }
  };
  async raw<T>(
    path: string,
    method = "GET",
    body?: unknown,
    headers?: HeadersInit,
  ): Promise<{ data: T; etag: string | null; requestId: string | null }> {
    const h = new Headers(headers);
    if (body !== undefined) h.set("content-type", "application/json");
    const encoded = body === undefined ? undefined : JSON.stringify(body);
    if (
      encoded !== undefined &&
      new TextEncoder().encode(encoded).length > 65536
    )
      throw new ApiFailure("REQUEST_TOO_LARGE");
    const init: RequestInit = { method, headers: h };
    if (encoded !== undefined) init.body = encoded;
    const response = await this.fetch(
      new Request(new URL(path, this.origin), init),
    );
    const value: unknown =
      response.status === 204 ? null : await response.json();
    if (!response.ok) throw problem(response, value);
    return {
      data: value as T,
      etag: response.headers.get("etag"),
      requestId: response.headers.get("x-request-id"),
    };
  }
}
export async function fileData(
  api: BrowserApi,
  session: Session,
  path: string,
  method: "GET" | "PUT",
  headers: Headers,
  body: Uint8Array<ArrayBuffer> | undefined,
  maxBytes: number,
  signal: AbortSignal,
): Promise<{ bytes: Uint8Array<ArrayBuffer>; headers: Headers }> {
  if (
    headers.has("authorization") ||
    headers.has("cookie") ||
    (headers.has("x-tenant-id") &&
      headers.get("x-tenant-id") !== session.tenant_id)
  )
    throw new ApiFailure("MIXED_CREDENTIALS_REJECTED");
  if (
    !/^\/v1\/file-transfers\/[0-9a-f-]{36}\/content(?:\/(?:[0-9]|[1-9][0-9]))?$/.test(
      path,
    ) ||
    !UUID.test(session.tenant_id)
  )
    throw new ApiFailure("INVALID_FILE_REQUEST");
  headers.set("x-tenant-id", session.tenant_id);
  if (method === "PUT") headers.set("x-csrf-token", session.csrf_token);
  const lease = api.fileLease(session, signal);
  const combined = AbortSignal.any([
    lease.signal,
    AbortSignal.timeout(method === "PUT" ? 20000 : 300000),
  ]);
  const init: RequestInit = {
    method,
    headers,
    signal: combined,
    redirect: "error",
    credentials: "same-origin",
    cache: "no-store",
  };
  if (body) init.body = body;
  try {
    const response = await fetch(new URL(path, api.origin), init);
    const bytes = await boundedBody(
      response.body,
      response.ok ? maxBytes : 65536,
      combined,
    );
    if (!response.ok) {
      let value: unknown;
      try {
        value = JSON.parse(new TextDecoder().decode(bytes));
      } catch {
        value = null;
      }
      if (response.status === 401) api.requireNewLogin();
      throw problem(response, value);
    }
    return { bytes, headers: response.headers };
  } finally {
    lease.end();
  }
}
