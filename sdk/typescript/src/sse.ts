import { abortable } from "./transport.ts";

export class EventStreamError extends Error {
  constructor(public readonly code: string, public readonly retryable: boolean,
              public readonly status: number | undefined = undefined,
              public readonly requestId: string | undefined = undefined) {
    super(code);
    this.name = "EventStreamError";
  }
}
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const CURSOR = /^[\x21-\x7e]{1,2048}$/;
const RETRY_HTTP = new Set([408, 429, 502, 503, 504]);
export const object = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
export const code = (v: unknown): v is string => typeof v === "string" && /^[A-Z][A-Z0-9_]{0,95}$/.test(v);
export const fail = () => new EventStreamError("INVALID_EVENT_STREAM", false);
export function bounded(value: number, min: number, max: number): number {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new EventStreamError("INVALID_STREAM_CONFIGURATION", false);
  return value;
}
export function deadline(ms: number, parent?: AbortSignal) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new EventStreamError("EVENT_STREAM_TIMEOUT", false)), ms);
  return { signal: parent ? AbortSignal.any([parent, controller.signal]) : controller.signal,
           abort: () => controller.abort(), clear: () => clearTimeout(timer) };
}
async function read(reader: ReadableStreamDefaultReader<Uint8Array>, signal: AbortSignal, ms: number) {
  const idle = deadline(ms, signal);
  try { return await abortable(reader.read(), idle.signal); }
  finally { idle.clear(); }
}
export interface Frame { event: string; id: string | undefined; data: string }
/** No background pump: the reader pauses at every complete frame yielded. */
export async function* frames(body: ReadableStream<Uint8Array>, signal: AbortSignal, idleMs: number, frameLimit = 256 * 1024): AsyncGenerator<Frame> {
  const reader = body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  const line = new Uint8Array(frameLimit);
  let used = 0, size = 0, skipLf = false, firstLine = true;
  let event = "", id: string | undefined, data: string[] = [];
  const endLine = (): Frame | undefined => {
    let text: string;
    try { text = decoder.decode(line.subarray(0, used)); } catch { throw fail(); }
    used = 0;
    if (firstLine) { firstLine = false; text = text.replace(/^\uFEFF/, ""); }
    if (text === "") {
      const frame = data.length ? { event, id, data: data.join("\n") } : undefined;
      event = ""; id = undefined; data = []; size = 0;
      return frame;
    }
    if (text.startsWith(":")) return undefined;
    const split = text.indexOf(":");
    const field = split < 0 ? text : text.slice(0, split);
    let value = split < 0 ? "" : text.slice(split + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    if (field === "data") data.push(value);
    else if (field === "event") { if (event) throw fail(); event = value; }
    else if (field === "id") { if (id !== undefined || !CURSOR.test(value)) throw fail(); id = value; }
    // retry is intentionally ignored: the caller's bounded reconnect policy wins.
    return undefined;
  };
  try {
    for (;;) {
      let item: ReadableStreamReadResult<Uint8Array>;
      try { item = await read(reader, signal, idleMs); }
      catch { signal.throwIfAborted(); throw new EventStreamError("EVENT_STREAM_INTERRUPTED", true); }
      if (item.done) return; // An incomplete frame at EOF is never acknowledged.
      for (const byte of item.value) {
        signal.throwIfAborted();
        if (skipLf) {
          skipLf = false;
          if (byte === 10) {
            if (++size > frameLimit) throw new EventStreamError("EVENT_FRAME_LIMIT", false);
            continue;
          }
        }
        if (++size > frameLimit) throw new EventStreamError("EVENT_FRAME_LIMIT", false);
        if (byte === 10 || byte === 13) {
          const frame = endLine();
          skipLf = byte === 13;
          if (frame) yield frame;
        } else { line[used++] = byte; }
      }
    }
  } finally { void reader.cancel().catch(() => {}); reader.releaseLock(); }
}
export async function httpError(response: Response, signal: AbortSignal, timeout: number): Promise<EventStreamError> {
  const headerId = response.headers.get("x-request-id");
  const requestId = headerId && UUID.test(headerId) ? headerId : undefined;
  let result = new EventStreamError("EVENT_STREAM_HTTP_ERROR", RETRY_HTTP.has(response.status), response.status, requestId);
  if (!response.body) return result;
  const reading = deadline(timeout, signal);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = []; let size = 0;
  try {
    for (;;) {
      const item = await abortable(reader.read(), reading.signal);
      if (item.done) break;
      size += item.value.byteLength;
      if (size > 65536) return result;
      chunks.push(item.value);
    }
    if (response.headers.get("content-type")?.split(";", 1)[0]?.trim() !== "application/problem+json") return result;
    const bytes = new Uint8Array(size); let at = 0;
    for (const chunk of chunks) { bytes.set(chunk, at); at += chunk.byteLength; }
    const body: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (object(body) && code(body.code) && typeof body.retryable === "boolean") {
      result = new EventStreamError(body.code, RETRY_HTTP.has(response.status) && body.retryable, response.status, requestId);
    }
  } catch { signal.throwIfAborted(); }
  finally { reading.clear(); void reader.cancel().catch(() => {}); reader.releaseLock(); }
  return result;
}
