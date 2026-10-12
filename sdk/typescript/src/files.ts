import { abortable, SandboxTransportError, validatedBaseUrl } from "./transport.js";
import type { TransportOptions } from "./transport.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHA = /^[0-9a-f]{64}$/;
const ETAG = /^"[1-9][0-9]*"$/;
const PART_BYTES = 1024 * 1024;
const MAX_BYTES = 100 * PART_BYTES;
export interface FilePartAcknowledgement {
  index: number;
  byte_length: number;
  sha256: string;
  transfer_version: number;
}
export interface FileDataOptions { signal?: AbortSignal; timeoutMs?: number }
export interface UploadFilePartOptions extends FileDataOptions {
  transferId: string;
  index: number;
  /** Transfer ETag. Immutable part indexes may be staged concurrently at this version. */
  ifMatch: string;
  bytes: Uint8Array;
}
export interface DownloadFileOptions extends FileDataOptions {
  transferId: string;
  /** From GET transfer; all bytes must match before they are returned. */
  expectedVersion: number;
  expectedByteLength: number;
  expectedSha256: string;
}

function fail(code: string, unknown = false): SandboxTransportError {
  return new SandboxTransportError(code, unknown, null);
}
function deadline(ms: number, parent?: AbortSignal) {
  if (!Number.isSafeInteger(ms) || ms < 1 || ms > 300000) throw fail("INVALID_FILE_CONFIGURATION");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new DOMException("File deadline exceeded", "TimeoutError")), ms);
  return { signal: parent ? AbortSignal.any([parent, controller.signal]) : controller.signal,
    stop: () => { clearTimeout(timer); controller.abort(); } };
}
async function sha(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("");
}
async function read(body: ReadableStream<Uint8Array> | null, limit: number, signal: AbortSignal): Promise<Uint8Array<ArrayBuffer>> {
  if (!body) return new Uint8Array(0);
  const reader = body.getReader(), chunks: Uint8Array[] = [];
  let length = 0, complete = false;
  try {
    for (;;) {
      const next = await abortable(reader.read(), signal);
      if (next.done) { complete = true; break; }
      length += next.value.byteLength;
      if (length > limit) throw fail("FILE_BODY_LIMIT_EXCEEDED");
      chunks.push(next.value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return bytes;
  } finally {
    if (!complete) void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}
async function headers(transport: TransportOptions, signal: AbortSignal): Promise<Headers> {
  let token: string;
  try { token = await abortable(transport.tokenProvider.getToken({ forceRefresh: false, signal }), signal); }
  catch { throw fail("IDENTITY_PROVIDER_FAILURE"); }
  if (!/^[\x21-\x7e]{1,16384}$/.test(token)) throw fail("INVALID_ACCESS_TOKEN");
  return new Headers({ authorization: `Bearer ${token}`, "x-tenant-id": transport.tenantId });
}
function url(transport: TransportOptions, transfer: string, suffix: string): URL {
  if (!UUID.test(transfer)) throw fail("INVALID_FILE_CONFIGURATION");
  return new URL(validatedBaseUrl(transport).href.replace(/\/$/, "") + `/v1/file-transfers/${transfer}/content${suffix}`);
}
async function requireStatus(response: Response, signal: AbortSignal): Promise<void> {
  if (response.status >= 300 && response.status < 400) throw fail("REDIRECT_REJECTED");
  if (response.status === 200) return;
  let code = "FILE_REQUEST_FAILED";
  const bytes = await read(response.body, 65536, signal);
  if (response.headers.get("content-type")?.split(";", 1)[0]?.trim() === "application/problem+json") {
    try {
      const problem: unknown = JSON.parse(new TextDecoder().decode(bytes));
      if (typeof problem === "object" && problem !== null && "code" in problem &&
          typeof problem.code === "string" && /^[A-Z][A-Z0-9_]{0,127}$/.test(problem.code)) code = problem.code;
    } catch { /* Keep the bounded public error code; never echo an upstream body. */ }
  }
  throw fail(code);
}

/** Exactly one PUT; an interrupted/failed response never automatically resends bytes. */
export async function uploadFilePart(transport: TransportOptions, options: UploadFilePartOptions): Promise<FilePartAcknowledgement> {
  const target = url(transport, options.transferId, `/${options.index}`);
  if (!Number.isSafeInteger(options.index) || options.index < 0 || options.index > 99 || !ETAG.test(options.ifMatch) ||
      !(options.bytes instanceof Uint8Array) || options.bytes.byteLength < 1 || options.bytes.byteLength > PART_BYTES) throw fail("INVALID_FILE_CONFIGURATION");
  // Copy before the first await: caller changes cannot alter the admitted bytes.
  const bytes = new Uint8Array(options.bytes);
  const budget = deadline(options.timeoutMs ?? 20000, options.signal);
  let dispatched = false, response: Response | undefined;
  try {
    const digest = await abortable(sha(bytes), budget.signal);
    const requestHeaders = await headers(transport, budget.signal);
    requestHeaders.set("content-type", "application/octet-stream");
    requestHeaders.set("content-length", String(bytes.byteLength));
    requestHeaders.set("x-content-sha256", digest);
    requestHeaders.set("if-match", options.ifMatch);
    const request = new Request(target, { method: "PUT", headers: requestHeaders, body: bytes,
      signal: budget.signal, redirect: "manual", credentials: "omit", cache: "no-store" });
    dispatched = true;
    response = await abortable((transport.fetch ?? globalThis.fetch)(request), budget.signal);
    await requireStatus(response, budget.signal);
    if (response.headers.get("content-type")?.split(";", 1)[0]?.trim() !== "application/json") throw fail("INVALID_FILE_ACKNOWLEDGEMENT");
    let receipt: unknown;
    try { receipt = JSON.parse(new TextDecoder().decode(await read(response.body, 65536, budget.signal))); }
    catch { throw fail("INVALID_FILE_ACKNOWLEDGEMENT"); }
    if (typeof receipt !== "object" || receipt === null || !("index" in receipt) || receipt.index !== options.index ||
        !("byte_length" in receipt) || receipt.byte_length !== bytes.byteLength || !("sha256" in receipt) || receipt.sha256 !== digest ||
        !("transfer_version" in receipt) || typeof receipt.transfer_version !== "number" || !Number.isSafeInteger(receipt.transfer_version) || receipt.transfer_version < 1 ||
        response.headers.get("etag") !== `"${receipt.transfer_version}"`) throw fail("INVALID_FILE_ACKNOWLEDGEMENT");
    return receipt as FilePartAcknowledgement;
  } catch (error) {
    throw fail(error instanceof SandboxTransportError ? error.code : "FILE_TRANSPORT_INTERRUPTED", dispatched);
  } finally {
    budget.stop();
    if (response?.body && !response.body.locked) void response.body.cancel().catch(() => {});
  }
}

/** Bounded whole-file read. No partial or unverified bytes escape to the caller. */
export async function downloadFile(transport: TransportOptions, options: DownloadFileOptions): Promise<Uint8Array<ArrayBuffer>> {
  const target = url(transport, options.transferId, "");
  if (!Number.isSafeInteger(options.expectedVersion) || options.expectedVersion < 1 ||
      !Number.isSafeInteger(options.expectedByteLength) || options.expectedByteLength < 0 || options.expectedByteLength > MAX_BYTES ||
      !SHA.test(options.expectedSha256)) throw fail("INVALID_FILE_CONFIGURATION");
  const budget = deadline(options.timeoutMs ?? 300000, options.signal);
  let response: Response | undefined;
  try {
    const requestHeaders = await headers(transport, budget.signal);
    requestHeaders.set("accept", "application/octet-stream");
    response = await abortable((transport.fetch ?? globalThis.fetch)(new Request(target, { headers: requestHeaders,
      signal: budget.signal, redirect: "manual", credentials: "omit", cache: "no-store" })), budget.signal);
    await requireStatus(response, budget.signal);
    if (response.headers.get("content-type")?.split(";", 1)[0]?.trim() !== "application/octet-stream" ||
        response.headers.get("content-encoding") && response.headers.get("content-encoding") !== "identity" ||
        response.headers.get("content-length") !== String(options.expectedByteLength) ||
        response.headers.get("x-content-sha256") !== options.expectedSha256 ||
        response.headers.get("etag") !== `"${options.expectedVersion}"`) throw fail("FILE_CONTENT_CHANGED");
    const bytes = await read(response.body, options.expectedByteLength, budget.signal);
    if (bytes.byteLength !== options.expectedByteLength || await abortable(sha(bytes), budget.signal) !== options.expectedSha256) throw fail("FILE_INTEGRITY_FAILED");
    return bytes;
  } catch (error) {
    throw fail(error instanceof SandboxTransportError ? error.code : "FILE_TRANSPORT_INTERRUPTED");
  } finally {
    budget.stop();
    if (response?.body && !response.body.locked) void response.body.cancel().catch(() => {});
  }
}
