// Real Rust API + PostgreSQL fixture only. Secrets enter via a private stdin
// pipe; stdout is a machine protocol consumed by the parent test, not a log.
import { EventStreamError, subscribeEvents } from '../../dist/index.js';

function check(condition) { if (!condition) throw new Error('EVENT_STREAM_INTEGRATION_FAILED'); }
async function* inputLines() {
  let buffer = '', bytes = 0;
  for await (const chunk of process.stdin) {
    bytes += chunk.length; check(bytes <= 65536);
    buffer += chunk.toString('utf8');
    for (;;) {
      const end = buffer.indexOf('\n'); if (end < 0) break;
      const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
      yield JSON.parse(line);
    }
  }
  check(buffer.length === 0);
}
function emit(value) { process.stdout.write(JSON.stringify(value) + '\n'); }
async function domain(iterator) {
  for (;;) {
    const next = await iterator.next(); check(!next.done);
    if (next.value.type === 'domain.event') return next.value;
    check(next.value.type === 'stream.checkpoint');
  }
}
async function main() {
  const input = inputLines();
  const firstInput = await input.next(); check(!firstInput.done);
  const { baseUrl, tenantId, projectId, token } = firstInput.value;
  const config = { baseUrl, tenantId, allowLoopbackHttp: true,
    tokenProvider: { getToken: async () => token } };
  const settings = { projectId, replay: 'all', totalTimeoutMs: 60000, maxReconnects: 1 };
  const first = subscribeEvents(config, settings);
  const received = await domain(first);
  // Explicitly consuming received makes its cursor the recovery point. return()
  // does not implicitly acknowledge it; pass it deliberately into the new stream.
  await first.return();
  emit({ phase: 'received', eventId: received.event.id, cursor: received.cursor });
  const resumed = subscribeEvents(config, { ...settings, lastEventId: received.cursor });
  try {
    const next = await domain(resumed);
    check(next.event.id !== received.event.id);
    emit({ phase: 'resumed', eventId: next.event.id, cursor: next.cursor });
    // Do not advance while parent commits revocation. Parent then sends exactly
    // one {action:"continue"} line; the next pull must observe the live denial.
    const control = await input.next(); check(!control.done && control.value.action === 'continue');
    try {
      await resumed.next();
      throw new Error('EVENT_STREAM_REVOCATION_NOT_OBSERVED');
    } catch (error) {
      check(error instanceof EventStreamError && !error.retryable && ['RESOURCE_NOT_FOUND', 'PERMISSION_DENIED'].includes(error.code));
      emit({ phase: 'revoked', code: error.code });
    }
  } finally { await resumed.return(); }
}
const timeout = setTimeout(() => { process.stderr.write('EVENT_STREAM_INTEGRATION_TIMEOUT\n'); process.exit(1); }, 75000);
try { await main(); }
catch { process.stderr.write('EVENT_STREAM_INTEGRATION_FAILED\n'); process.exitCode = 1; }
finally { clearTimeout(timeout); process.stdin.destroy(); }
