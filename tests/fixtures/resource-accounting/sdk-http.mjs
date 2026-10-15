import assert from "node:assert/strict";
import { createSandboxClient } from "../../../sdk/typescript/dist/index.js";
try {
  let input="";
  for await (const part of process.stdin) { input+=part; if(Buffer.byteLength(input)>8192) throw Error("INPUT_LIMIT"); }
  const {baseUrl,tenantId,token,instanceId,phase}=JSON.parse(input);
  assert.ok(["AVAILABLE","REVOKED"].includes(phase));
  const client=createSandboxClient({baseUrl,tenantId,allowLoopbackHttp:true,
    tokenProvider:{async getToken(){return token;}},maxAttempts:1,requestTimeoutMs:2000,totalTimeoutMs:4000});
  const result=await client.GET("/v1/instances/{id}/resource-accounting",{
    params:{header:{"X-Tenant-ID":tenantId},path:{id:instanceId},query:{limit:100}}});
  if(phase==="REVOKED") { assert.equal(result.response.status,404);assert.equal(result.error.code,"RESOURCE_NOT_FOUND"); }
  else {
    assert.equal(result.response.status,200);assert.equal(result.data.pod_resource_evidence,"NOT_CAPTURED");
    assert.equal(result.data.receipts.items.length,8);
    for(const r of result.data.receipts.items) {
      assert.equal(typeof r.amount,"string");
      assert.equal(r.limit_value,r.dimension==="CPU_MILLIS"?"9007199254740993":"9223372036854775807");
    }
  }
  process.stdout.write(JSON.stringify({phase,status:result.response.status}));
} catch { process.stderr.write("RESOURCE_ACCOUNTING_ACTUAL_SDK_FAILED");process.exitCode=1; }
