import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyCircuitLifecycle, leaseEvidence } from './mesh-evidence.mjs';

const row = (circuitId, at, bytesSent = 7) => ({ circuitId, at: new Date(at).toISOString(), bytesReceived: 8, bytesSent });
test('early recovery is a replacement, never inferred to be natural expiry', () => {
  const result = classifyCircuitLifecycle('old', [row('old', 100), row('new', 300)],
    [{ name: 'circuit_closed', circuitId: 'old', reason: 'peer-left', at: 200 }]);
  assert.equal(result.replacement.to, 'new'); assert.equal(result.naturalTTL.status, 'NOT_OBSERVED');
});
test('new admission can extend a long participation interval without a fixed renewal-event count', () => {
  const sample = (at, sessionId, expiry) => ({ at: new Date(at).toISOString(), B: { sessionId, sessionExpiresAt: expiry, nativeConnected: true } });
  const result = leaseEvidence([sample(100, 'first', 300), sample(200, 'fresh', 500), sample(400, 'fresh', 800)], 'B');
  assert.equal(result.unexpiredReportedLeases, true); assert.equal(result.observedSessionGenerations, 2); assert.equal(result.observedLeaseExpiries, 3);
  assert.equal(leaseEvidence([sample(600, 'expired', 500)], 'B').unexpiredReportedLeases, false);
});
test('exact expiry requires later bidirectional authenticated native evidence', () => {
  const event = { name: 'circuit_closed', circuitId: 'old', reason: 'circuit-expired', at: 200 };
  for (const rows of [[row('new', 100)], [row('old', 300)], [row('new', 300, 0)]]) {
    assert.equal(classifyCircuitLifecycle('old', rows, [event]).naturalTTL.status, 'NOT_OBSERVED');
  }
  const result = classifyCircuitLifecycle('old', [row('old', 100), row('new', 300)], [event]);
  assert.equal(result.naturalTTL.status, 'OBSERVED'); assert.equal(result.naturalTTL.successor, 'new');
});
