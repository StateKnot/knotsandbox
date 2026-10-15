import assert from "node:assert/strict";
import { createSandboxClient, getResourceAccounting, ResourceAccountingQueryError } from "../../../sdk/typescript/dist/index.js";
try {
  let text = "";
  for await (const part of process.stdin) {
    text += part;
    if (Buffer.byteLength(text) > 16384) throw Error("INPUT_LIMIT");
  }
  const {baseUrl, tenantId, token, instanceId, phase, cursor, observation} = JSON.parse(text);
  assert.ok(["MISSING_PINNED", "CAPTURED", "REVOKED"].includes(phase));
  const client = createSandboxClient({baseUrl, tenantId, allowLoopbackHttp: true,
    tokenProvider: { async getToken() { return token; } }, maxAttempts: 1,
    requestTimeoutMs: 2000, totalTimeoutMs: 4000});
  if (phase === "REVOKED") {
    await assert.rejects(getResourceAccounting(client, tenantId, instanceId, {limit: 2}),
      error => error instanceof ResourceAccountingQueryError && error.status === 404);
  } else {
    const page = await getResourceAccounting(client, tenantId, instanceId, {limit: 2, ...(cursor ? {cursor} : {})});
    if (phase === "MISSING_PINNED") {
      assert.equal(page.pod_resource_evidence, "NOT_CAPTURED");
      assert.equal(page.pod_resource_observation, null);
    } else {
      assert.equal(page.pod_resource_evidence, "KUBERNETES_API_READBACK");
      assert.deepEqual(page.pod_resource_observation, observation);
      assert.equal(page.pod_resource_observation.pod_overhead.memory_bytes, "9007199254740993");
      assert.equal(page.pod_resource_observation.effective_request.memory_bytes, "9007201402224641");
    }
  }
  process.stdout.write(JSON.stringify({phase, status: "PASS"}));
} catch {
  process.stderr.write("OBSERVED_RESOURCE_ACCOUNTING_ACTUAL_SDK_FAILED");
  process.exitCode = 1;
}
