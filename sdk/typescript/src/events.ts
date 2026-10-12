import { abortable, delay, validatedBaseUrl } from "./transport.js";
import type { TransportOptions } from "./transport.js";
import type { components } from "./schema.js";
import { EventStreamError, UUID, CURSOR, fail, bounded, deadline, frames, httpError } from "./sse.js";
import { decodeEventStreamMessage } from "./event-message.js";

type EventRecord = components["schemas"]["EventRecord"];
export type EventStreamMessage =
  | { type: "stream.checkpoint"; cursor: string; sequence: string }
  | { type: "domain.event"; cursor: string; sequence: string; event: EventRecord };
export interface EventStreamOptions {
  projectId: string;
  instanceId?: string;
  replay?: "latest" | "all";
  lastEventId?: string;
  signal?: AbortSignal;
  /** Applied to the complete iterator lifetime, including caller processing. */
  totalTimeoutMs?: number;
  connectTimeoutMs?: number;
  /** Bounds a pending network read; time spent in the caller is not idle I/O. */
  idleTimeoutMs?: number;
  maxReconnects?: number;
  /** Runs only when the caller advances after a yielded message. Persist durably. */
  onCursor?: (cursor: string) => void | Promise<void>;
}
export { EventStreamError } from "./sse.js";
/** At least once. Atomically deduplicate event.id with the caller's side effects. */
export async function* subscribeEvents(transport: TransportOptions, options: EventStreamOptions): AsyncGenerator<EventStreamMessage> {
  const base = validatedBaseUrl(transport);
  if (!UUID.test(options.projectId) || options.instanceId !== undefined && !UUID.test(options.instanceId) ||
      options.replay !== undefined && !["latest", "all"].includes(options.replay) ||
      options.lastEventId !== undefined && !CURSOR.test(options.lastEventId)) throw new EventStreamError("INVALID_STREAM_CONFIGURATION", false);
  const totalMs = bounded(options.totalTimeoutMs ?? 3600000, 1, 86400000);
  const connectMs = bounded(options.connectTimeoutMs ?? 10000, 1, 20000);
  const idleMs = bounded(options.idleTimeoutMs ?? 45000, 1, 120000);
  const reconnects = bounded(options.maxReconnects ?? 8, 0, 100);
  const url = new URL(base.href.replace(/\/$/, "") + "/v1/events/stream");
  url.searchParams.set("project_id", options.projectId);
  if (options.instanceId) url.searchParams.set("instance_id", options.instanceId);
  if (options.replay) url.searchParams.set("replay", options.replay);
  const overall = deadline(totalMs, options.signal);
  const expiresAt = performance.now() + totalMs;
  const send = transport.fetch ?? globalThis.fetch;
  let cursor = options.lastEventId, previousSequence: bigint | undefined;
  let attempts = 0, refreshed401 = false;
  try {
    for (;;) {
      overall.signal.throwIfAborted();
      const connection = new AbortController();
      const signal = AbortSignal.any([overall.signal, connection.signal]);
      const opening = deadline(connectMs, signal);
      let response: Response | undefined;
      let failure: EventStreamError | undefined;
      try {
        let token: string;
        try { token = await abortable(transport.tokenProvider.getToken({ forceRefresh: attempts > 0, signal: opening.signal }), opening.signal); }
        catch { overall.signal.throwIfAborted(); throw new EventStreamError("IDENTITY_PROVIDER_FAILURE", false); }
        if (!/^[\x21-\x7e]{1,16384}$/.test(token)) throw new EventStreamError("INVALID_ACCESS_TOKEN", false);
        const headers = new Headers({ authorization: `Bearer ${token}`, "x-tenant-id": transport.tenantId, accept: "text/event-stream" });
        if (cursor) headers.set("last-event-id", cursor);
        response = await abortable(send(new Request(url, { headers, signal, redirect: "manual", credentials: "omit", cache: "no-store" })), opening.signal);
        opening.clear();
        if (response.status >= 300 && response.status < 400) throw new EventStreamError("REDIRECT_REJECTED", false, response.status);
        if (response.status !== 200) {
          failure = await httpError(response, signal, connectMs);
          if (response.status === 401 && !refreshed401) {
            refreshed401 = true;
            failure = new EventStreamError(failure.code, true, failure.status, failure.requestId);
          }
          throw failure;
        }
        if (response.headers.get("content-type")?.split(";", 1)[0]?.trim() !== "text/event-stream" || !response.body) throw fail();
        let checkpoint = false;
        for await (const frame of frames(response.body, signal, idleMs)) {
          const item = decodeEventStreamMessage(frame, transport.tenantId, options.projectId);
          if (!checkpoint && item.type !== "stream.checkpoint") throw fail();
          checkpoint = true;
          const sequence = BigInt(item.sequence);
          if (previousSequence !== undefined && sequence < previousSequence) throw fail();
          yield item;
          // Code after yield runs only when the caller requests the next item.
          // return()/throw()/consumer failure leave this cursor unacknowledged.
          overall.signal.throwIfAborted();
          try { await abortable(Promise.resolve(options.onCursor?.(item.cursor)), overall.signal); }
          catch { overall.signal.throwIfAborted(); throw new EventStreamError("EVENT_CURSOR_PERSIST_FAILED", false); }
          cursor = item.cursor;
          previousSequence = sequence;
        }
        // With latest and no accepted initial position, silently reconnecting
        // after a lost checkpoint could skip intervening committed events.
        if (!checkpoint && cursor === undefined) throw new EventStreamError("EVENT_CHECKPOINT_MISSING", false);
      } catch (error) {
        overall.signal.throwIfAborted();
        failure = error instanceof EventStreamError ? error : new EventStreamError("EVENT_STREAM_INTERRUPTED", true);
        if (failure.retryable && response?.status === 200 && cursor === undefined) {
          throw new EventStreamError("EVENT_CHECKPOINT_MISSING", false);
        }
        if (!failure.retryable) throw failure;
      } finally {
        opening.clear(); connection.abort();
        if (response?.body && !response.body.locked) void response.body.cancel().catch(() => {});
      }
      if (attempts >= reconnects) throw new EventStreamError("EVENT_RECONNECT_LIMIT", false);
      let pause = Math.floor(Math.min(5000, 250 * 2 ** Math.min(attempts, 5)) * (0.5 + Math.random()));
      if (response) {
        const retry = response.headers.get("retry-after");
        if (retry !== null) {
          const parsed = /^\d+$/.test(retry) ? Number(retry) * 1000 : Date.parse(retry) - Date.now();
          if (Number.isFinite(parsed)) pause = Math.max(pause, parsed);
        }
      }
      if (pause >= expiresAt - performance.now()) throw failure ?? new EventStreamError("EVENT_STREAM_TIMEOUT", false);
      attempts++;
      await delay(pause, overall.signal);
    }
  } finally { overall.clear(); }
}
