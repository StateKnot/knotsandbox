// Actual Rust TCP API + PostgreSQL; credentials arrive only through stdin.
import { EventStreamError, subscribeExecutionOutput } from '../../dist/index.js';

const check = value => { if (!value) throw new Error('OUTPUT_STREAM_INTEGRATION_FAILED'); };
const emit = value => process.stdout.write(JSON.stringify(value) + '\n');
async function* controls() {
  let buffer = '', size = 0;
  for await (const bytes of process.stdin) {
    size += bytes.length; check(size <= 65536);
    buffer += bytes.toString('utf8');
    for (;;) {
      const end = buffer.indexOf('\n'); if (end < 0) break;
      const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
      yield JSON.parse(line);
    }
  }
  check(buffer.length === 0);
}
async function nextOf(iterator, type) {
  const next = await iterator.next(); check(!next.done && next.value.type === type);
  return next.value;
}
async function main() {
  const input = controls(), setup = await input.next(); check(!setup.done);
  const { baseUrl, tenantId, executionId, token } = setup.value;
  const transport = { baseUrl, tenantId, allowLoopbackHttp: true, tokenProvider: { getToken: async () => token } };
  const options = { executionId, totalTimeoutMs: 60000, maxReconnects: 1 };
  const saved = [];
  const first = subscribeExecutionOutput(transport, { ...options, onCursor: cursor => saved.push(cursor) });
  const checkpoint = await nextOf(first, 'output.checkpoint'); check(checkpoint.afterSegment === -1);
  const one = await nextOf(first, 'output.segment');
  check(one.segment.sequence === 0 && atob(one.segment.frames[0].data) === 'a');
  await first.return();
  check(saved.length === 1 && saved[0] === checkpoint.cursor);
  // Explicit application consumption supplies the recovery point, not return().
  emit({ phase: 'received', sequence: one.segment.sequence });
  const resumed = subscribeExecutionOutput(transport, { ...options, lastEventId: one.cursor });
  const resumedCheckpoint = await nextOf(resumed, 'output.checkpoint'); check(resumedCheckpoint.afterSegment === 0);
  const two = await nextOf(resumed, 'output.segment');
  check(two.segment.sequence === 1 && atob(two.segment.frames[0].data) === 'b');
  emit({ phase: 'resumed', sequence: two.segment.sequence });
  const close = await input.next(); check(!close.done && close.value.action === 'closed');
  const end = await nextOf(resumed, 'output.end');
  check(end.afterSegment === 1 && end.outputStatus === 'COMPLETE' && end.manifestVerified && end.finalSegmentSequence === 1);
  check((await resumed.next()).done);
  emit({ phase: 'complete' });
  const revoked = await input.next(); check(!revoked.done && revoked.value.action === 'revoked');
  const denied = subscribeExecutionOutput(transport, { ...options, lastEventId: end.cursor });
  try {
    await denied.next(); throw new Error('REVOCATION_NOT_OBSERVED');
  } catch (error) {
    check(error instanceof EventStreamError && !error.retryable && ['RESOURCE_NOT_FOUND', 'PERMISSION_DENIED'].includes(error.code));
    emit({ phase: 'revoked' });
  } finally { await denied.return(); }
}
const timer = setTimeout(() => { process.stderr.write('OUTPUT_STREAM_INTEGRATION_TIMEOUT\n'); process.exit(1); }, 75000);
try { await main(); }
catch { process.stderr.write('OUTPUT_STREAM_INTEGRATION_FAILED\n'); process.exitCode = 1; }
finally { clearTimeout(timer); process.stdin.destroy(); }
