// Actual generated transport -> signed Rust TCP interface -> PostgreSQL.
// Credentials arrive only through stdin; failures expose no request or token.
import assert from "node:assert/strict";
import { createSandboxClient } from "../../../sdk/typescript/dist/index.js";
try {
  let input = "";
  for await (const chunk of process.stdin) {
    input += chunk;
    if (Buffer.byteLength(input) > 8192) throw new Error("INPUT_LIMIT");
  }
  const { baseUrl, tenantId, token, phase } = JSON.parse(input);
  assert.ok(["AVAILABLE", "REVOKED"].includes(phase));
  let calls = 0;
  const client = createSandboxClient({
    baseUrl,
    tenantId,
    allowLoopbackHttp: true,
    tokenProvider: { async getToken() { calls++; return token; } },
    requestTimeoutMs: 2000,
    totalTimeoutMs: 4000,
    maxAttempts: 1,
    maxResponseBytes: 65536,
  });
  const get = (cursor) => client.GET("/v1/tenant-audit-records", {
    params: { header: { "X-Tenant-ID": tenantId }, query: { limit: 1, ...(cursor ? { cursor } : {}) } },
  });
  const first = await get();
  if (phase === "REVOKED") {
    assert.equal(first.response.status, 404);
    assert.equal(first.error.code, "RESOURCE_NOT_FOUND");
    assert.equal(calls, 1);
  } else {
    assert.equal(first.response.status, 200);
    assert.equal(first.response.headers.get("cache-control"), "no-store");
    assert.equal(first.data.items.length, 1);
    assert.equal(first.data.items[0].tenant_id, tenantId);
    assert.equal(first.data.items[0].project_id, null);
    assert.ok(!JSON.stringify(first.data).includes("PRIVATE_TENANT_AUDIT_MARKER"));
    assert.ok(first.data.next_cursor);
    const next = await get(first.data.next_cursor);
    assert.equal(next.response.status, 200);
    assert.equal(next.data.cutoff, first.data.cutoff);
    assert.notEqual(next.data.items[0].id, first.data.items[0].id);
    assert.equal(calls, 2);
  }
  process.stdout.write(JSON.stringify({ phase, status: first.response.status, token_provider_calls: calls }));
} catch {
  process.stderr.write("SDK_TENANT_AUDIT_HTTP_FAILED");
  process.exitCode = 1;
}
