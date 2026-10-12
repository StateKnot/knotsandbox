import { ApiFailure, ETAG, UUID } from "./api.ts";
import type { BrowserApi, Session } from "./api.ts";
export interface Intent {
  key: string;
  tenantId: string;
  principalId: string;
  path: string;
  method: "POST" | "PATCH" | "DELETE";
  body: unknown;
  /** Present only on sensitive automation creation; the durable body is always null. */
  bodySha256?: string;
  etag: string | null;
  createdAt: string;
  state: "READY" | "PENDING" | "UNKNOWN" | "ACCEPTED" | "REJECTED";
  operationId: string | null;
  resourceId: string | null;
  error: string | null;
}
export const JOURNAL_SLOT = "sandbox.console.intents.v1";
const GRANT_ITEM = /^\/v1\/projects\/[0-9a-f-]{36}\/grants\/[0-9a-f-]{36}$/;
const AUTOMATION_CREATE =
  /^\/v1\/instances\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/automations$/;
const HASH = /^[0-9a-f]{64}$/;
function sensitive(path: string, method: string): boolean {
  return method === "POST" && AUTOMATION_CREATE.test(path);
}
function snapshotBody(body: unknown): unknown {
  try {
    const encoded = JSON.stringify(structuredClone(body ?? null));
    if (new TextEncoder().encode(encoded).length > 64 * 1024)
      throw Error("limit");
    return JSON.parse(encoded);
  } catch {
    throw new ApiFailure("INVALID_INTENT_BODY");
  }
}
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}
async function payloadHash(body: unknown): Promise<string> {
  try {
    const hash = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(canonical(body)),
    );
    return Array.from(new Uint8Array(hash), (n) =>
      n.toString(16).padStart(2, "0"),
    ).join("");
  } catch {
    throw new ApiFailure("INVALID_INTENT_BODY");
  }
}
export type JournalLock = <T>(work: () => Promise<T>) => Promise<T>;
export type ReceiptValidator<T> = (
  data: T,
  receipt: { etag: string | null; requestId: string | null },
) => void;
function browserLock(): JournalLock | null {
  if (typeof navigator === "undefined" || !navigator.locks) return null;
  return async <T>(work: () => Promise<T>) =>
    await navigator.locks.request(
      JOURNAL_SLOT,
      { ifAvailable: true },
      async (lock) => {
        if (!lock) throw new ApiFailure("REQUEST_ALREADY_PENDING");
        return await work();
      },
    );
}
function valid(v: unknown): v is Intent {
  if (typeof v !== "object" || v === null) return false;
  const i = v as Partial<Intent>;
  return (
    typeof i.key === "string" &&
    UUID.test(i.key) &&
    typeof i.tenantId === "string" &&
    UUID.test(i.tenantId) &&
    typeof i.principalId === "string" &&
    UUID.test(i.principalId) &&
    typeof i.path === "string" &&
    /^\/v1\/[a-z0-9/-]+$/.test(i.path) &&
    ["POST", "PATCH", "DELETE"].includes(i.method ?? "") &&
    ["READY", "PENDING", "UNKNOWN", "ACCEPTED", "REJECTED"].includes(
      i.state ?? "",
    ) &&
    typeof i.createdAt === "string" &&
    Number.isFinite(Date.parse(i.createdAt)) &&
    Object.hasOwn(i, "body") &&
    (sensitive(i.path, i.method ?? "")
      ? i.body === null &&
        typeof i.bodySha256 === "string" &&
        HASH.test(i.bodySha256)
      : i.bodySha256 === undefined) &&
    !(i.method === "DELETE" && GRANT_ITEM.test(i.path) && i.body !== null) &&
    (i.etag === null || (typeof i.etag === "string" && ETAG.test(i.etag))) &&
    (i.operationId === null ||
      (typeof i.operationId === "string" && UUID.test(i.operationId))) &&
    (i.resourceId === null ||
      (typeof i.resourceId === "string" && UUID.test(i.resourceId))) &&
    (i.error === null ||
      (typeof i.error === "string" && /^[A-Z][A-Z0-9_]{0,127}$/.test(i.error)))
  );
}
export class IntentJournal {
  private readonly payloads = new Map<
    string,
    {
      tenantId: string;
      principalId: string;
      csrf: string;
      hash: string;
      body: unknown;
    }
  >();
  private payloadGeneration = 0;
  constructor(
    private readonly storage: Pick<Storage, "getItem" | "setItem">,
    private readonly lock: JournalLock | null = browserLock(),
  ) {
    this.read();
  }
  private read(): Intent[] {
    let value: string | null;
    try {
      value = this.storage.getItem(JOURNAL_SLOT);
    } catch {
      throw new ApiFailure("INTENT_STORAGE_UNAVAILABLE");
    }
    if (!value) return [];
    if (value.length > 2 * 1024 * 1024)
      throw new ApiFailure("INTENT_STORAGE_INVALID");
    let parsed: unknown;
    try {
      parsed = JSON.parse(value);
    } catch {
      throw new ApiFailure("INTENT_STORAGE_INVALID");
    }
    if (
      !Array.isArray(parsed) ||
      parsed.length > 40 ||
      !parsed.every(valid) ||
      new Set(parsed.map((i) => i.key)).size !== parsed.length
    )
      throw new ApiFailure("INTENT_STORAGE_INVALID");
    return parsed;
  }
  list(session: Session): Intent[] {
    return this.read()
      .filter(
        (i) =>
          i.tenantId === session.tenant_id &&
          i.principalId === session.principal_id,
      )
      .map((i) => ({
        ...i,
        body: structuredClone(i.body),
        state: i.state === "PENDING" ? "UNKNOWN" : i.state,
      }));
  }
  forgetPayloads(): boolean {
    const hadPayloads = this.payloads.size > 0;
    this.payloadGeneration++;
    this.payloads.clear();
    return hadPayloads;
  }
  hasPayload(session: Session, key: string): boolean {
    const row = this.read().find((i) => i.key === key);
    if (
      !row ||
      row.tenantId !== session.tenant_id ||
      row.principalId !== session.principal_id ||
      !["READY", "PENDING", "UNKNOWN"].includes(row.state)
    )
      return false;
    if (!row.bodySha256) return true;
    const value = this.payloads.get(key);
    return (
      value !== undefined &&
      value.tenantId === session.tenant_id &&
      value.principalId === session.principal_id &&
      value.csrf === session.csrf_token &&
      value.hash === row.bodySha256
    );
  }
  async rehydrate(session: Session, key: string, body: unknown): Promise<void> {
    const tenantId = session.tenant_id,
      principalId = session.principal_id,
      csrf = session.csrf_token;
    const generation = this.payloadGeneration;
    const snapshot = snapshotBody(body),
      hash = await payloadHash(snapshot);
    return this.exclusive(async () => {
      if (generation !== this.payloadGeneration)
        throw new ApiFailure("INTENT_SCOPE_REJECTED");
      const row = this.read().find((i) => i.key === key);
      if (
        !row ||
        row.tenantId !== tenantId ||
        row.principalId !== principalId ||
        !row.bodySha256 ||
        !["READY", "PENDING", "UNKNOWN"].includes(row.state)
      )
        throw new ApiFailure("INTENT_SCOPE_REJECTED");
      if (hash !== row.bodySha256) throw new ApiFailure("INTENT_BODY_MISMATCH");
      this.payloads.set(key, {
        tenantId,
        principalId,
        csrf,
        hash,
        body: JSON.parse(canonical(snapshot)),
      });
    });
  }
  private save(rows: Intent[]) {
    try {
      this.storage.setItem(JOURNAL_SLOT, JSON.stringify(rows));
    } catch {
      throw new ApiFailure("INTENT_STORAGE_UNAVAILABLE");
    }
  }
  private exclusive<T>(work: () => Promise<T>): Promise<T> {
    if (!this.lock)
      return Promise.reject(new ApiFailure("BROWSER_LOCKS_REQUIRED"));
    return this.lock(work);
  }
  async create(
    session: Session,
    path: string,
    body: unknown,
    etag: string | null,
    method: "POST" | "PATCH" | "DELETE" = "POST",
  ): Promise<Intent> {
    // Capture ownership before waiting for another tab. Store precisely the JSON
    // that will be sent, rather than retaining a caller's mutable object.
    const snapshot = snapshotBody(body);
    if (
      !UUID.test(session.tenant_id) ||
      !UUID.test(session.principal_id) ||
      !/^\/v1\/[a-z0-9/-]+$/.test(path) ||
      !["POST", "PATCH", "DELETE"].includes(method) ||
      (method === "DELETE" && GRANT_ITEM.test(path) && snapshot !== null) ||
      (etag !== null && !ETAG.test(etag))
    )
      throw new ApiFailure("INVALID_INTENT");
    const tenantId = session.tenant_id,
      principalId = session.principal_id,
      csrf = session.csrf_token;
    const generation = this.payloadGeneration;
    const hash = sensitive(path, method)
      ? await payloadHash(snapshot)
      : undefined;
    return this.exclusive(async () => {
      if (hash && generation !== this.payloadGeneration)
        throw new ApiFailure("INTENT_SCOPE_REJECTED");
      const rows = this.read();
      if (
        rows.some(
          (i) =>
            i.tenantId === tenantId &&
            i.principalId === principalId &&
            i.path === path &&
            ["READY", "PENDING", "UNKNOWN"].includes(i.state),
        )
      )
        throw new ApiFailure("RECONCILE_ORIGINAL_REQUEST_FIRST");
      const unresolved = rows.filter((i) =>
        ["READY", "UNKNOWN", "PENDING"].includes(i.state),
      );
      if (unresolved.length >= 20)
        throw new ApiFailure("RECONCILE_PENDING_REQUESTS_FIRST");
      const retained = [
        ...unresolved,
        ...rows.filter((i) => !unresolved.includes(i)).slice(-19),
      ];
      const row: Intent = {
        key: crypto.randomUUID(),
        tenantId,
        principalId,
        path,
        method,
        body: hash ? null : snapshot,
        ...(hash ? { bodySha256: hash } : {}),
        etag,
        createdAt: new Date().toISOString(),
        state: "READY",
        operationId: null,
        resourceId: null,
        error: null,
      };
      retained.push(row);
      this.save(retained);
      for (const key of this.payloads.keys())
        if (!retained.some((i) => i.key === key)) this.payloads.delete(key);
      if (hash)
        this.payloads.set(row.key, {
          tenantId,
          principalId,
          csrf,
          hash,
          body: JSON.parse(canonical(snapshot)),
        });
      return structuredClone(row);
    });
  }
  async execute<T>(
    api: BrowserApi,
    session: Session,
    key: string,
    validateReceipt?: ReceiptValidator<T>,
  ): Promise<T> {
    const tenantId = session.tenant_id,
      principalId = session.principal_id;
    // One origin-wide Web Lock spans the durable attempt and HTTP response.
    // Busy attempts are rejected, never queued as an implicit retry if the
    // first response is lost. A closed tab releases the lock; the saved
    // key/body remain explicitly replayable under a newly acquired lock.
    return this.exclusive(async () => {
      const rows = this.read(),
        row = rows.find((i) => i.key === key);
      if (
        !row ||
        row.tenantId !== tenantId ||
        row.principalId !== principalId ||
        !["READY", "PENDING", "UNKNOWN"].includes(row.state)
      )
        throw new ApiFailure("INTENT_SCOPE_REJECTED");
      api.assertActor({ tenant_id: tenantId, principal_id: principalId });
      const payload = row.bodySha256 ? this.payloads.get(key) : undefined;
      if (
        row.bodySha256 &&
        (!payload ||
          payload.tenantId !== tenantId ||
          payload.principalId !== principalId ||
          payload.csrf !== session.csrf_token ||
          payload.hash !== row.bodySha256)
      )
        throw new ApiFailure("INTENT_PAYLOAD_REQUIRED");
      const previouslyAttempted = row.state !== "READY";
      row.state = "PENDING";
      this.save(rows);
      const headers = new Headers({ "idempotency-key": row.key });
      if (row.etag) headers.set("if-match", row.etag);
      // Grant revocation has no request body. Other DELETE routes retain their
      // existing JSON contract, including workspace retention choices.
      const grantRevocation =
        row.method === "DELETE" && GRANT_ITEM.test(row.path);
      let data: T;
      let received = false;
      try {
        const result = await api.raw<T>(
          row.path,
          row.method,
          grantRevocation
            ? undefined
            : structuredClone(payload ? payload.body : row.body),
          headers,
        );
        data = result.data;
        received = true;
        validateReceipt?.(data, result);
      } catch (error) {
        row.state =
          !received &&
          !previouslyAttempted &&
          error instanceof ApiFailure &&
          !error.code.startsWith("IDEMPOTENCY_") &&
          error.status !== null &&
          error.status >= 400 &&
          error.status < 500 &&
          ![408, 429].includes(error.status)
            ? "REJECTED"
            : "UNKNOWN";
        row.error =
          error instanceof ApiFailure ? error.code : "REQUEST_INTERRUPTED";
        if (row.state === "REJECTED") {
          row.body = null;
          this.payloads.delete(key);
        }
        this.save(rows);
        throw error;
      }
      // Receipt persistence errors must not enter the transport failure branch:
      // an acknowledged operation cannot be downgraded by a late local error.
      row.state = "ACCEPTED";
      row.body = null;
      row.error = null;
      this.payloads.delete(key);
      if (typeof data === "object" && data !== null) {
        const d = data as {
          operation?: { id?: unknown };
          resource?: { id?: unknown };
        };
        if (typeof d.operation?.id === "string" && UUID.test(d.operation.id))
          row.operationId = d.operation.id;
        if (typeof d.resource?.id === "string" && UUID.test(d.resource.id))
          row.resourceId = d.resource.id;
      }
      this.save(rows);
      return data;
    });
  }
}
