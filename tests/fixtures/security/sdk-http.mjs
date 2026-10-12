// Actual generated SDK transport → signed Rust TCP API → PostgreSQL.
// Credentials arrive through a private stdin pipe; only a bounded public
// receipt leaves this helper. No fetch replacement or manual auth headers.
import assert from "node:assert/strict";
import { createSandboxClient } from "../../../sdk/typescript/dist/index.js";
try {
  let input = "";
  for await (const chunk of process.stdin) {
    input += chunk;
    if (Buffer.byteLength(input) > 8192) throw new Error("INPUT_LIMIT");
  }
  const { baseUrl, tenantId, token, instanceId, phase, specVersion } = JSON.parse(input);
  assert.ok(["AVAILABLE", "REDACTED", "REVOKED"].includes(phase));
  let calls = 0;
  const client = createSandboxClient({
    baseUrl, tenantId, allowLoopbackHttp: true,
    tokenProvider: { async getToken() { calls++; return token; } },
    requestTimeoutMs: 2000, totalTimeoutMs: 4000, maxAttempts: 1,
    maxResponseBytes: 65536,
  });
  const result = await client.GET("/v1/instances/{id}/security", {
    params: { path: { id: instanceId }, header: { "X-Tenant-ID": tenantId } },
  });
  assert.equal(calls, 1);
  assert.equal(result.response.headers.get("cache-control"), "no-store");
  if (phase === "REVOKED") {
    assert.equal(result.response.status, 404);
    assert.equal(result.data, undefined);
    assert.equal(result.error?.code, "RESOURCE_NOT_FOUND");
  } else {
    assert.equal(result.response.status, 200);
    assert.equal(result.error, undefined);
    assert.equal(result.response.headers.get("x-instance-etag"), `"${specVersion}"`);
    const report = result.data;
    assert.equal(report.instance_id, instanceId);
    assert.equal(report.runtime_certification, "NOT_ASSERTED");
    for (const key of ["applied_policy", "runtime_isolation", "image_verification"]) {
      assert.equal(report[key].status, "UNKNOWN");
    }
    assert.equal(report.active_operation.state, phase);
    if (phase === "AVAILABLE") {
      assert.equal(report.active_operation.resource.error.code, "DEPENDENCY_UNAVAILABLE");
      assert.equal(report.active_operation.resource.error.retryable, true);
      assert.deepEqual(Object.keys(report.active_operation.resource.error).sort(), ["code", "retryable"]);
    } else assert.equal(report.active_operation.resource, null);
    assert.ok(!JSON.stringify(report).includes("never-return-sdk-private-error"));
  }
  process.stdout.write(JSON.stringify({ phase, status: result.response.status, token_provider_calls: calls }));
} catch {
  process.stderr.write("SDK_SECURITY_HTTP_FAILED");
  process.exitCode = 1;
}
