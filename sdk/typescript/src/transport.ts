/** The caller owns durable idempotency keys; this transport never invents one. */
export interface TokenProvider {
  getToken(options: { forceRefresh: boolean; signal: AbortSignal }): Promise<string>;
}

export interface TransportOptions {
  baseUrl: string;
  tenantId: string;
  tokenProvider: TokenProvider;
  /** Development only: literal loopback addresses, never arbitrary HTTP hosts. */
  allowLoopbackHttp?: boolean;
  requestTimeoutMs?: number;
  totalTimeoutMs?: number;
  maxAttempts?: number;
  maxResponseBytes?: number;
  fetch?: typeof globalThis.fetch;
}

export class SandboxTransportError extends Error {
  constructor(
    public readonly code: string,
    public readonly outcomeUnknown: boolean,
    public readonly idempotencyKey: string | null,
  ) {
    super(code);
    this.name = "SandboxTransportError";
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RETRYABLE = new Set([408, 429, 502, 503, 504]);
const MUTATIONS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

function boundedInteger(value: number, min: number, max: number): number {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new SandboxTransportError("INVALID_TRANSPORT_CONFIGURATION", false, null);
  }
  return value;
}

export function validatedBaseUrl(options: TransportOptions): URL {
  const url = new URL(options.baseUrl);
  const loopback = ["127.0.0.1", "[::1]"].includes(url.hostname);
  if (
    url.username || url.password || url.search || url.hash ||
    (url.protocol !== "https:" && !(options.allowLoopbackHttp && loopback && url.protocol === "http:")) ||
    !UUID.test(options.tenantId)
  ) {
    throw new SandboxTransportError("INVALID_TRANSPORT_CONFIGURATION", false, null);
  }
  url.pathname = url.pathname.replace(/\/+$/, "");
  return url;
}

function deadline(timeoutMs: number, parent?: AbortSignal) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new DOMException("Deadline exceeded", "TimeoutError")), timeoutMs);
  const signal = parent ? AbortSignal.any([parent, controller.signal]) : controller.signal;
  return { signal, clear: () => clearTimeout(timer) };
}

/** Also bounds callbacks/transports that accidentally ignore their signal. */
export async function abortable<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  signal.throwIfAborted();
  let onAbort: () => void = () => {};
  const abort = new Promise<never>((_, reject) => {
    onAbort = () => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
  });
  try { return await Promise.race([work, abort]); }
  finally { signal.removeEventListener("abort", onAbort); }
}

export async function delay(ms: number, signal: AbortSignal): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await abortable(new Promise<void>((resolve) => { timer = setTimeout(resolve, ms); }), signal);
  } finally { clearTimeout(timer); }
}

async function boundedBody(body: ReadableStream<Uint8Array> | null, limit: number, signal: AbortSignal): Promise<ArrayBuffer> {
  if (!body) return new ArrayBuffer(0);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  let finished = false;
  try {
    for (;;) {
      const { done, value } = await abortable(reader.read(), signal);
      if (done) { finished = true; break; }
      length += value.byteLength;
      if (length > limit) throw new SandboxTransportError("BODY_LIMIT_EXCEEDED", false, null);
      chunks.push(value);
    }
    const joined = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { joined.set(chunk, offset); offset += chunk.byteLength; }
    return joined.buffer;
  } finally {
    if (!finished) void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

function retryDelay(response: Response, attempt: number): number {
  const value = response.headers.get("retry-after");
  if (value !== null) {
    if (/^\d+$/.test(value)) return Number(value) * 1000;
    const at = Date.parse(value);
    if (Number.isFinite(at)) return Math.max(0, at - Date.now());
  }
  return Math.floor(250 * 2 ** attempt * (0.5 + Math.random()));
}

export function createSandboxFetch(options: TransportOptions): (request: Request) => Promise<Response> {
  const base = validatedBaseUrl(options);
  const basePath = base.pathname.replace(/\/+$/, "");
  const requestMs = boundedInteger(options.requestTimeoutMs ?? 5000, 1, 20000);
  const totalMs = boundedInteger(options.totalTimeoutMs ?? 20000, requestMs, 60000);
  const attempts = boundedInteger(options.maxAttempts ?? 4, 1, 4);
  const responseLimit = boundedInteger(options.maxResponseBytes ?? 2 * 1024 * 1024, 1024, 16 * 1024 * 1024);
  const send = options.fetch ?? globalThis.fetch;

  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const path = url.pathname.slice(basePath.length);
    const mutation = MUTATIONS.has(request.method);
    const key = request.headers.get("idempotency-key");
    const fail = (code: string, unknown = false) => new SandboxTransportError(code, unknown, key);
    if (url.origin !== base.origin || url.username || url.password || url.hash ||
        !url.pathname.startsWith(`${basePath}/`) || !(path.startsWith("/v1/") || path.startsWith("/health/"))) {
      throw fail("REQUEST_OUTSIDE_CONFIGURED_API");
    }
    if (!["GET", "HEAD", ...MUTATIONS].includes(request.method)) throw fail("UNSUPPORTED_METHOD");
    if (path === "/v1/events/stream" || /^\/v1\/executions\/[0-9a-f-]{36}\/output\/stream$/i.test(path)) throw fail("STREAMING_TRANSPORT_REQUIRED");
    if (/^\/v1\/file-transfers\/[0-9a-f-]{36}\/content(?:\/\d+)?$/i.test(path)) throw fail("FILE_DATA_TRANSPORT_REQUIRED");
    if (path.startsWith("/v1/") && request.headers.has("x-tenant-id") &&
        request.headers.get("x-tenant-id") !== options.tenantId) throw fail("TENANT_CONTEXT_MISMATCH");
    if (mutation && (!key || !/^[\x21-\x7e]{1,128}$/.test(key))) throw fail("IDEMPOTENCY_KEY_REQUIRED");
    const createsResource = request.method === "POST" && (path === "/v1/instances" || path === "/v1/service-clients" ||
      /^\/v1\/instances\/[0-9a-f-]{36}\/diagnoses$/i.test(path) ||
      /^\/v1\/projects\/[0-9a-f-]{36}\/grants$/i.test(path));
    if (mutation && !createsResource &&
        !/^"[1-9][0-9]*"$/.test(request.headers.get("if-match") ?? "")) throw fail("STRONG_ETAG_REQUIRED");

    const overall = deadline(totalMs, request.signal);
    const expiresAt = performance.now() + totalMs;
    let dispatched = false;
    try {
      const body = mutation && request.body ? await boundedBody(request.body, 65536, overall.signal) : undefined;
      let refreshed = false;
      let forceRefresh = false;
      for (let attempt = 0; attempt < attempts; attempt++) {
        overall.signal.throwIfAborted();
        const single = deadline(Math.min(requestMs, Math.max(1, expiresAt - performance.now())), overall.signal);
        let response: Response | undefined;
        let explicitlyNonRetryable = false;
        try {
          const headers = new Headers(request.headers);
          if (path.startsWith("/v1/")) {
            let token: string;
            try {
              token = await abortable(options.tokenProvider.getToken({ forceRefresh, signal: single.signal }), single.signal);
            } catch { throw fail("IDENTITY_PROVIDER_FAILURE", dispatched && mutation); }
            forceRefresh = false;
            if (!/^[\x21-\x7e]{1,16384}$/.test(token)) throw fail("INVALID_ACCESS_TOKEN", dispatched && mutation);
            headers.set("authorization", `Bearer ${token}`);
            headers.set("x-tenant-id", options.tenantId);
          } else {
            headers.delete("authorization");
            headers.delete("x-tenant-id");
          }
          headers.delete("cookie");
          dispatched = true;
          response = await abortable(send(new Request(url, {
            method: request.method, headers, body: body ?? null,
            signal: single.signal, redirect: "manual", credentials: "omit", cache: "no-store",
          })), single.signal);
          if (response.status >= 300 && response.status < 400) {
            void response.body?.cancel().catch(() => {});
            throw fail("REDIRECT_REJECTED", mutation);
          }
          const bytes = await boundedBody(response.body, responseLimit, single.signal);
          if (RETRYABLE.has(response.status) && response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase() === "application/problem+json") {
            try {
              const problem: unknown = JSON.parse(new TextDecoder().decode(bytes));
              explicitlyNonRetryable = typeof problem === "object" && problem !== null &&
                "retryable" in problem && problem.retryable === false;
            } catch { /* Preserve malformed responses for the typed client's error handling. */ }
          }
          const responseHeaders = new Headers(response.headers);
          // Fetch may have decompressed the body; do not advertise compressed
          // byte counts/encoding for the bounded, reconstructed response.
          responseHeaders.delete("content-encoding");
          responseHeaders.delete("content-length");
          response = new Response([204, 205, 304].includes(response.status) ? null : bytes, {
            status: response.status, statusText: response.statusText, headers: responseHeaders,
          });
        } catch (error) {
          if (error instanceof SandboxTransportError) {
            throw fail(error.code, mutation && dispatched);
          }
          if (overall.signal.aborted || attempt + 1 === attempts) throw fail("TRANSPORT_INTERRUPTED", mutation && dispatched);
          response = undefined; // Headers alone are not a complete, reusable receipt.
          // The immutable body, key and If-Match are reused even if the server committed.
        } finally { single.clear(); }

        let pause = Math.floor(250 * 2 ** attempt * (0.5 + Math.random()));
        if (response) {
          if (response.status === 401 && path.startsWith("/v1/") && !refreshed && attempt + 1 < attempts) {
            refreshed = true;
            forceRefresh = true;
            pause = 0;
          } else {
            forceRefresh = false;
            if (!RETRYABLE.has(response.status) || explicitlyNonRetryable || attempt + 1 === attempts) return response;
            pause = retryDelay(response, attempt);
          }
          if (pause >= expiresAt - performance.now()) return response;
        }
        await delay(pause, overall.signal);
      }
      throw fail("TRANSPORT_INTERRUPTED", mutation && dispatched);
    } catch (error) {
      if (error instanceof SandboxTransportError) throw error;
      throw fail("TRANSPORT_INTERRUPTED", mutation && dispatched);
    } finally { overall.clear(); }
  };
}
