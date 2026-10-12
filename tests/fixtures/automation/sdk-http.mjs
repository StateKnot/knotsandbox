// Real loopback microservice test. Input credentials arrive via private stdin,
// never argv, environment dumps or output. Only scoped capabilities and exact-run GET.
import { createSandboxClient, waitAutomationRun } from "../../../sdk/typescript/dist/index.js";
let input = "";
for await (const chunk of process.stdin) input += chunk;
const { baseUrl, tenantId, token, projectId, runId, timeoutMs } = JSON.parse(input);
const client = createSandboxClient({
  baseUrl, tenantId, allowLoopbackHttp: true,
  tokenProvider: { async getToken() { return token; } },
  requestTimeoutMs: 2000, totalTimeoutMs: 4000, maxAttempts: 1,
});
try {
  const capabilities = await client.GET("/v1/capabilities", { params: { query: { project_id: projectId } } });
  if (capabilities.error || capabilities.response.status !== 200 || capabilities.data?.automation?.schema_version !== 1) throw new Error("CAPABILITY_CONTRACT_UNAVAILABLE");
  const result = await waitAutomationRun(client, tenantId, runId, { timeoutMs, pollIntervalMs: 50 });
  const run = result.kind === "timeout" ? result.lastObserved : result.run;
  process.stdout.write(JSON.stringify({ kind: result.kind, status: run?.status, automation: capabilities.data.automation }));
} catch (error) {
  process.stderr.write(JSON.stringify({ name: error?.name, code: error?.code }));
  process.exitCode = 1;
}
