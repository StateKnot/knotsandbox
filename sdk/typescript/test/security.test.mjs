import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createSandboxClient } from '../dist/index.js';
const security = JSON.parse(await readFile(new URL('../../../tests/fixtures/security/instance-security.json', import.meta.url), 'utf8'));
const tenant = '00000000-0000-4000-8000-000000000001';

test('scoped security read preserves unknown enforcement and redacted operation without dispatching changes', async () => {
  const expected = { ...security, active_operation: { state: 'REDACTED', resource: null } };
  let calls = 0;
  const client = createSandboxClient({baseUrl:'https://sandbox.example',tenantId:tenant,
    tokenProvider:{getToken:async ()=>'public-test-access-token'},
    fetch:async request=>{
      calls++;
      assert.equal(request.method,'GET');
      assert.equal(new URL(request.url).pathname,`/v1/instances/${security.instance_id}/security`);
      assert.equal(request.headers.get('x-tenant-id'),tenant);
      assert.equal(request.headers.get('authorization'),'Bearer public-test-access-token');
      assert.equal(request.headers.get('idempotency-key'),null);
      assert.equal(request.headers.get('if-match'),null);
      assert.equal(request.body,null);
      return Response.json(expected,{headers:{'x-instance-etag':'"3"'}});
    }});
  const result = await client.GET('/v1/instances/{id}/security',{params:{path:{id:security.instance_id},header:{'X-Tenant-ID':tenant}}});
  assert.equal(calls,1);
  assert.deepEqual(result.data,expected);
  assert.equal(result.data.applied_policy.status,'UNKNOWN');
  assert.equal(result.data.runtime_certification,'NOT_ASSERTED');
  assert.equal(result.data.active_operation.resource,null);
});

test('security projection conflicts and revoked visibility remain errors without a stale or synthesized view', async () => {
  for(const [status,code] of [[404,'NOT_FOUND'],[409,'SECURITY_TARGET_CHANGED']]){
    let calls=0;
    const client=createSandboxClient({baseUrl:'https://sandbox.example',tenantId:tenant,
      tokenProvider:{getToken:async ()=>'public-test-access-token'},fetch:async ()=>{
        calls++;return Response.json({code},{status,headers:{'content-type':'application/problem+json'}});
      }});
    const result=await client.GET('/v1/instances/{id}/security',{params:{path:{id:security.instance_id},header:{'X-Tenant-ID':tenant}}});
    assert.equal(calls,1);
    assert.equal(result.data,undefined);
    assert.equal(result.error.code,code);
  }
});
