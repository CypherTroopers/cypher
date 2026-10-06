// Acceptance evidence classification only. A new circuit ID alone never proves TTL expiry.
export function classifyCircuitLifecycle(startCircuit, history, events) {
  const transfers = history.filter(row => row.bytesReceived > 0 && row.bytesSent > 0);
  const replacement = transfers.find(row => row.circuitId !== startCircuit) || null;
  const expirations = events.filter(row => row.name === 'circuit_closed' && row.reason === 'circuit-expired');
  const expiry = expirations.find(event => transfers.some(row => row.circuitId !== event.circuitId && Date.parse(row.at) >= event.at)) || null;
  const afterExpiry = expiry && transfers.find(row => row.circuitId !== expiry.circuitId && Date.parse(row.at) >= expiry.at);
  return {
    replacement: replacement && { from: startCircuit, to: replacement.circuitId, firstObservedAt: replacement.at,
      bytesReceived: replacement.bytesReceived, bytesSent: replacement.bytesSent, cause: 'not-inferred-from-circuit-id' },
    naturalTTL: { status: expiry ? 'OBSERVED' : 'NOT_OBSERVED',
      ...(expiry ? { expiredCircuit: expiry.circuitId, eventAt: expiry.at, reason: expiry.reason,
        createdAt: expiry.createdAt, expiresAt: expiry.expiresAt, successor: afterExpiry.circuitId,
        successorObservedAt: afterExpiry.at, bytesReceived: afterExpiry.bytesReceived, bytesSent: afterExpiry.bytesSent }
        : { reason: 'No exact circuit-expired event followed by a different authenticated native circuit carrying bytes in both directions.' }) },
  };
}

export function leaseEvidence(samples, browser) {
  const active = samples.filter(sample => sample[browser].nativeConnected || sample[browser].peers?.some(peer => peer.connected));
  const remaining = active.map(sample => sample[browser].sessionExpiresAt - Date.parse(sample.at));
  return { activeSamples: active.length, unexpiredReportedLeases: active.length > 0 && remaining.every(ms => Number.isFinite(ms) && ms > 0),
    minimumSampledRemainingMs: remaining.length ? Math.min(...remaining) : null,
    observedSessionGenerations: new Set(samples.map(sample => sample[browser].sessionId).filter(Boolean)).size,
    observedLeaseExpiries: new Set(samples.map(sample => sample[browser].sessionExpiresAt).filter(Number.isFinite)).size,
    scope: 'Reported expiry progression only; this does not establish authoritative native lease existence during a stale status or 401 gap.' };
}
