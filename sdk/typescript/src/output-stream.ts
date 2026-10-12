import { abortable, delay, validatedBaseUrl } from "./transport.js";
import type { TransportOptions } from "./transport.js";
import type { EventStreamOptions } from "./events.js";
import type { components } from "./schema.js";
import { EventStreamError, UUID, CURSOR, object, code, bounded, deadline, frames, httpError } from "./sse.js";
import type { Frame } from "./sse.js";

type OutputSegment = components["schemas"]["ExecutionOutputSegment"];
export type ExecutionOutputStreamOptions = Omit<EventStreamOptions, "projectId" | "instanceId" | "replay"> & { executionId: string };
export type ExecutionOutputStreamMessage =
  | { type: "output.checkpoint"; cursor: string; executionId: string; afterSegment: number }
  | { type: "output.segment"; cursor: string; executionId: string; segment: OutputSegment }
  | { type: "output.end"; cursor: string; executionId: string; afterSegment: number;
      outputStatus: "COMPLETE" | "TRUNCATED" | "PARTIAL" | "LOST"; manifestVerified: boolean; finalSegmentSequence: number | null };
const fail = () => new EventStreamError("INVALID_OUTPUT_STREAM", false);
const position = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= -1 && v <= 4095;
const integer = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;

function message(frame: Frame, executionId: string): ExecutionOutputStreamMessage {
  let value: unknown;
  try { value = JSON.parse(frame.data); } catch { throw fail(); }
  if (!object(value)) throw fail();
  if (frame.event === "stream.error") {
    if (frame.id !== undefined || !code(value.code) || typeof value.retryable !== "boolean" || typeof value.request_id !== "string" || !UUID.test(value.request_id)) throw fail();
    // Integrity/cursor reconciliation must never silently reset or retry.
    const fatal = ["OUTPUT_INTEGRITY_FAILED", "OUTPUT_CURSOR_EXPIRED", "OUTPUT_CURSOR_AHEAD", "OUTPUT_EPOCH_CHANGED", "OUTPUT_HISTORY_UNAVAILABLE", "INVALID_CURSOR"].includes(value.code);
    throw new EventStreamError(value.code, !fatal && value.retryable, undefined, value.request_id);
  }
  if (!frame.id || typeof value.execution_id !== "string" || value.execution_id.toLowerCase() !== executionId.toLowerCase()) throw fail();
  if (frame.event === "output.checkpoint" && position(value.after_segment)) {
    return { type: frame.event, cursor: frame.id, executionId, afterSegment: value.after_segment };
  }
  if (frame.event === "output.segment") {
    const segment = value.segment;
    if (!object(segment) || !position(segment.sequence) || segment.sequence < 0 || !Array.isArray(segment.frames) || segment.frames.length === 0 || segment.frames.length > 4096) throw fail();
    let previous = -1;
    for (const f of segment.frames) {
      if (!object(f) || !integer(f.sequence) || f.sequence <= previous || !integer(f.offset) || !["stdout", "stderr"].includes(String(f.stream)) ||
          typeof f.data !== "string" || f.data.length === 0 || f.data.length > 8192 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(f.data)) throw fail();
      try { if (btoa(atob(f.data)) !== f.data) throw fail(); } catch { throw fail(); }
      previous = f.sequence;
    }
    return { type: frame.event, cursor: frame.id, executionId, segment: segment as OutputSegment };
  }
  if (frame.event === "output.end" && position(value.after_segment) && typeof value.manifest_verified === "boolean" &&
      (value.final_segment_sequence === null || position(value.final_segment_sequence)) &&
      ["COMPLETE", "TRUNCATED", "PARTIAL", "LOST"].includes(String(value.output_status))) {
    if (["COMPLETE", "TRUNCATED"].includes(String(value.output_status)) && (!value.manifest_verified || value.final_segment_sequence !== value.after_segment)) throw fail();
    if (value.manifest_verified !== (value.final_segment_sequence !== null) || value.manifest_verified && value.final_segment_sequence !== value.after_segment) throw fail();
    return { type: frame.event, cursor: frame.id, executionId, afterSegment: value.after_segment,
      outputStatus: value.output_status as "COMPLETE" | "TRUNCATED" | "PARTIAL" | "LOST", manifestVerified: value.manifest_verified, finalSegmentSequence: value.final_segment_sequence };
  }
  throw fail();
}

/** Output end means committed bytes are drained, never that the VM stopped. */
export async function* subscribeExecutionOutput(transport: TransportOptions, options: ExecutionOutputStreamOptions): AsyncGenerator<ExecutionOutputStreamMessage> {
  const base = validatedBaseUrl(transport);
  if (!UUID.test(options.executionId) || options.lastEventId !== undefined && !CURSOR.test(options.lastEventId)) throw new EventStreamError("INVALID_STREAM_CONFIGURATION", false);
  const totalMs = bounded(options.totalTimeoutMs ?? 3600000, 1, 86400000);
  const connectMs = bounded(options.connectTimeoutMs ?? 10000, 1, 20000);
  const idleMs = bounded(options.idleTimeoutMs ?? 45000, 1, 120000);
  const reconnects = bounded(options.maxReconnects ?? 8, 0, 100);
  const url = new URL(base.href.replace(/\/$/, "") + "/v1/executions/" + options.executionId + "/output/stream");
  const overall = deadline(totalMs, options.signal);
  const expiresAt = performance.now() + totalMs;
  const send = transport.fetch ?? globalThis.fetch;
  let cursor = options.lastEventId, previousSegment: number | undefined;
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
          if (failure.code === "OUTPUT_INTEGRITY_FAILED") failure = new EventStreamError(failure.code, false, failure.status, failure.requestId);
          if (response.status === 401 && !refreshed401) {
            refreshed401 = true;
            failure = new EventStreamError(failure.code, true, failure.status, failure.requestId);
          }
          throw failure;
        }
        if (response.headers.get("content-type")?.split(";", 1)[0]?.trim() !== "text/event-stream" || !response.body) throw fail();
        let checkpoint = false;
        for await (const frame of frames(response.body, signal, idleMs, 1024 * 1024)) {
          const item = message(frame, options.executionId);
          if (!checkpoint && item.type !== "output.checkpoint") throw fail();
          checkpoint = true;
          const segment = item.type === "output.segment" ? item.segment.sequence : item.afterSegment;
          if (previousSegment !== undefined && (item.type === "output.segment" ? segment !== previousSegment + 1 : segment !== previousSegment)) throw fail();
          if (previousSegment === undefined && item.type === "output.checkpoint" && cursor === undefined && segment !== -1) throw fail();
          yield item;
          // Code after yield runs only when the caller requests the next item.
          // return()/throw()/consumer failure leave this cursor unacknowledged.
          overall.signal.throwIfAborted();
          try { await abortable(Promise.resolve(options.onCursor?.(item.cursor)), overall.signal); }
          catch { overall.signal.throwIfAborted(); throw new EventStreamError("OUTPUT_CURSOR_PERSIST_FAILED", false); }
          cursor = item.cursor;
          previousSegment = segment;
          if (item.type === "output.end") return;
        }
        // Never restart silently when no initial position was delivered.
        if (!checkpoint && cursor === undefined) throw new EventStreamError("OUTPUT_CHECKPOINT_MISSING", false);
      } catch (error) {
        overall.signal.throwIfAborted();
        failure = error instanceof EventStreamError ? error : new EventStreamError("EVENT_STREAM_INTERRUPTED", true);
        if (failure.retryable && response?.status === 200 && cursor === undefined) {
          throw new EventStreamError("OUTPUT_CHECKPOINT_MISSING", false);
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
