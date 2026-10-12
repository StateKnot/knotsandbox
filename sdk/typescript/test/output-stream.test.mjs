import assert from 'node:assert/strict';
import test from 'node:test';
import { createSandboxClient, subscribeExecutionOutput } from '../dist/index.js';
const tenant='00000000-0000-4000-8000-000000000001', execution='00000000-0000-4000-8000-000000000002';
const cfg=extra=>({baseUrl:'https://sandbox.example',tenantId:tenant,tokenProvider:{getToken:async()=> 'token'},...extra});
const opts=extra=>({executionId:execution,totalTimeoutMs:3000,...extra});
const frame=(event,id,data,eol='\n')=>`event: ${event}${eol}${id ? `id: ${id}${eol}`:''}data: ${JSON.stringify(data)}${eol}${eol}`;
const cp=(id='cp',after=-1)=>frame('output.checkpoint',id,{execution_id:execution,after_segment:after});
const segment=(id='s0',sequence=0,frames=[{sequence:1,stream:'stdout',offset:0,data:'aGVsbG8='}])=>frame('output.segment',id,{execution_id:execution,segment:{sequence,frames}});
const end=(status='COMPLETE',verified=true,final=0)=>frame('output.end','end',{execution_id:execution,after_segment:0,output_status:status,manifest_verified:verified,final_segment_sequence:final});
const sse=(text,chunkSize=Infinity)=>new Response(new ReadableStream({start(c){const bytes=new TextEncoder().encode(text);for(let p=0;p<bytes.length;p+=chunkSize)c.enqueue(bytes.slice(p,p+chunkSize));c.close();}}),{headers:{'content-type':'text/event-stream'}});

test('output bytes, CRLF chunking and final cursor remain unacknowledged until next',async()=>{
 const saved=[];let calls=0;
 const it=subscribeExecutionOutput(cfg({fetch:async()=>{calls++;return sse((cp()+segment()+end()).replaceAll('\n','\r\n'),1);}}),opts({onCursor:c=>saved.push(c)}));
 assert.equal((await it.next()).value.type,'output.checkpoint');assert.deepEqual(saved,[]);
 const data=(await it.next()).value;assert.equal(data.segment.frames[0].data,'aGVsbG8=');assert.deepEqual(saved,['cp']);
 const terminal=(await it.next()).value;assert.equal(terminal.type,'output.end');assert.equal(terminal.manifestVerified,true);assert.deepEqual(saved,['cp','s0']);
 assert.equal((await it.next()).done,true);assert.deepEqual(saved,['cp','s0','end']);assert.equal(calls,1);
});

test('partial and lost end preserve incompleteness; break does not acknowledge end',async()=>{
 for(const status of ['PARTIAL','LOST']){
  const saved=[];const it=subscribeExecutionOutput(cfg({fetch:async()=>sse(cp()+segment()+end(status,false,null))}),opts({onCursor:c=>saved.push(c)}));
  await it.next();await it.next();const e=(await it.next()).value;assert.equal(e.outputStatus,status);assert.equal(e.manifestVerified,false);assert.equal(e.finalSegmentSequence,null);
  await it.return();assert.deepEqual(saved,['cp','s0']);
 }
});

test('connection loss refreshes token and resumes only the last consumed segment',async()=>{
 const calls=[],refresh=[];let sends=0;
 const it=subscribeExecutionOutput(cfg({tokenProvider:{getToken:async({forceRefresh})=>{refresh.push(forceRefresh);return 'token';}},fetch:async request=>{calls.push(request);return ++sends===1?sse(cp()+segment()+'event: output.segment\nid: never-ack\ndata: {'):sse(cp('resume',0)+end('TRUNCATED',true,0));}}),opts({maxReconnects:1}));
 await it.next();await it.next();assert.equal((await it.next()).value.afterSegment,0);assert.equal(calls[1].headers.get('last-event-id'),'s0');assert.equal(new URL(calls[0].url).search,'');assert.deepEqual(refresh,[false,true]);
 assert.equal((await it.next()).value.outputStatus,'TRUNCATED');assert.equal((await it.next()).done,true);
});

test('409/410 and integrity or restore-epoch errors never retry or clear caller cursor',async()=>{
 for(const status of [409,410,502]){
  let calls=0;const it=subscribeExecutionOutput(cfg({fetch:async r=>{calls++;assert.equal(r.headers.get('last-event-id'),'saved');return new Response(JSON.stringify({code:'OUTPUT_INTEGRITY_FAILED',retryable:true}),{status,headers:{'content-type':'application/problem+json'}});}}),opts({lastEventId:'saved'}));
  await assert.rejects(it.next(),{code:'OUTPUT_INTEGRITY_FAILED',retryable:false});assert.equal(calls,1);
 }
 for(const code of ['OUTPUT_INTEGRITY_FAILED','OUTPUT_HISTORY_UNAVAILABLE']){
  let calls=0;const it=subscribeExecutionOutput(cfg({fetch:async()=>{calls++;return sse(cp()+frame('stream.error',null,{code,retryable:true,request_id:tenant}));}}),opts());
  await it.next();await assert.rejects(it.next(),{code,retryable:false});assert.equal(calls,1);
 }
});

test('segment gap, duplicate, wrong execution, unsafe number, malformed base64 and false complete fail closed',async()=>{
 for(const text of [cp()+segment('gap',1),cp()+segment()+segment('dup',0),cp()+segment().replace(execution,tenant),cp()+segment('large',0,[{sequence:9007199254740992,stream:'stdout',offset:0,data:'YQ=='}]),cp()+segment('bad',0,[{sequence:1,stream:'stdout',offset:0,data:'Yf=='}]),cp()+segment()+end('COMPLETE',false,null),cp('skip',2)]){
  const it=subscribeExecutionOutput(cfg({fetch:async()=>sse(text)}),opts());
  await assert.rejects(async()=>{for await(const _ of it){}},{code:'INVALID_OUTPUT_STREAM'});
 }
});

test('larger output segment accepted under one MiB; oversized and invalid UTF8 fail closed',async()=>{
 const frames=Array.from({length:45},(_,i)=>({sequence:i+1,stream:'stdout',offset:i*6144,data:'YWFh'.repeat(2048)}));
 const it=subscribeExecutionOutput(cfg({fetch:async()=>sse(cp()+segment('big',0,frames)+end())}),opts());
 await it.next();assert.equal((await it.next()).value.segment.frames.length,45);await it.return();
 const huge=subscribeExecutionOutput(cfg({fetch:async()=>sse('data: '+'x'.repeat(1024*1024))}),opts());await assert.rejects(huge.next(),{code:'EVENT_FRAME_LIMIT'});
 const bad=subscribeExecutionOutput(cfg({fetch:async()=>new Response(new ReadableStream({start(c){c.enqueue(new Uint8Array([100,97,116,97,58,32,255,10,10]));c.close();}}),{headers:{'content-type':'text/event-stream'}})}),opts());await assert.rejects(bad.next(),{code:'INVALID_EVENT_STREAM'});
});

test('missing checkpoint, failed persistence, cancellation and JSON misuse remain bounded',async()=>{
 let calls=0;const missing=subscribeExecutionOutput(cfg({fetch:async()=>{calls++;return sse('');}}),opts());await assert.rejects(missing.next(),{code:'OUTPUT_CHECKPOINT_MISSING'});assert.equal(calls,1);
 const it=subscribeExecutionOutput(cfg({fetch:async()=>sse(cp()+segment())}),opts({onCursor:()=>{throw new Error('storage secret');}}));await it.next();await assert.rejects(it.next(),{code:'OUTPUT_CURSOR_PERSIST_FAILED'});
 const control=new AbortController();const blocked=subscribeExecutionOutput(cfg({fetch:async()=>new Promise(()=>{})}),opts({signal:control.signal}));const pending=blocked.next();control.abort(new Error('caller stopped'));await assert.rejects(pending,/caller stopped/);
 const client=createSandboxClient(cfg({tokenProvider:{getToken:async()=>assert.fail('must not obtain token')}}));await assert.rejects(client.GET('/v1/executions/{id}/output/stream',{params:{path:{id:execution},header:{'X-Tenant-ID':tenant}}}),{code:'STREAMING_TRANSPORT_REQUIRED'});
});
