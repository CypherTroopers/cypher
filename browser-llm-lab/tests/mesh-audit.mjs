#!/usr/bin/env node
// Preserve measured runner output, then classify claims without changing observations.
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { classifyCircuitLifecycle, leaseEvidence } from './mesh-evidence.mjs';

const input = process.argv[2];
assert(input?.endsWith('.json'), 'Usage: node tests/mesh-audit.mjs /tmp/run-report.json');
const raw = await readFile(input), report = JSON.parse(raw);
assert(report.status !== 'RUNNING', 'Never audit an active runner as a final result');
const eventsPath = input.replace(/\.json$/, '-events.json');
const eventsRaw = await readFile(eventsPath), events = JSON.parse(eventsRaw);
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const rawPath = input.replace(/\.json$/, '-runner.json');
try { await writeFile(rawPath, raw, { flag: 'wx' }); }
catch (error) { if (error.code !== 'EEXIST') throw error; assert.equal(sha256(await readFile(rawPath)), sha256(raw), 'Never replace an existing different raw report'); }
const first = report.samples[0], last = report.samples.at(-1);
const lifecycles = classifyCircuitLifecycle(report.startCircuit, report.nativeCircuitHistory, events);
const timedStart = Date.parse(report.soakStartedAt), timedEnd = timedStart + report.soakElapsedMs;
const timedClosures = events.filter(row => row.name === 'circuit_closed' && row.at >= timedStart && row.at <= timedEnd);
const pairedLosses = [...new Set(timedClosures.filter(row => row.reason === 'peer-left').map(row => row.circuitId))]
  .map(circuitId => ({ circuitId, events: timedClosures.filter(row => row.circuitId === circuitId && row.reason === 'peer-left') }))
  .filter(row => ['B', 'C'].every(browser => row.events.some(event => event.browser === browser)))
  .map(row => ({ circuitId: row.circuitId, firstObservedAt: new Date(Math.min(...row.events.map(event => event.at))).toISOString(),
    browserReasons: Object.fromEntries(row.events.map(event => [event.browser, event.reason])), originatingCause: 'UNDETERMINED' }));
const metrics = name => {
  const rows = report.samples.map(sample => sample[name]);
  const rates = report.samples.slice(1).map((sample, i) => {
    const prior = report.samples[i], seconds = (sample.elapsedMs - prior.elapsedMs) / 1000;
    return { seconds, bytesPerSecond: Math.max(0, sample[name].totalBytes - prior[name].totalBytes) / seconds };
  });
  return { samples: rows.length, finalState: last?.[name].state, finalTotalApplicationBytes: last?.[name].totalBytes,
    finalHopReceipts: last?.[name].acknowledgedCount, maxApplicationReservationBytes: Math.max(0, ...rows.map(row => row.appBytes)),
    maxSampledQueuedBytes: Math.max(0, ...rows.map(row => row.queuedBytes)),
    maxSampleIntervalAverageApplicationBytesPerSecond: Math.max(0, ...rates.map(row => row.bytesPerSecond)),
    sampleIntervalSecondsRange: [Math.min(...rates.map(row => row.seconds)), Math.max(...rates.map(row => row.seconds))],
    automaticReadmissionsDuringTimedInterval: last?.[name].reconnects - first?.[name].reconnects,
    observedRTCPaths: [...new Set(rows.flatMap(row => row.peers.map(peer => peer.path)))],
    sessionRenewalEvents: events.filter(row => row.browser === name && row.name === 'session-renewed').length };
};
const audit = {
  auditedAt: new Date().toISOString(), rawReport: rawPath, rawReportSha256: sha256(raw), eventsPath, eventsSha256: sha256(eventsRaw),
  runnerStatus: report.status, elapsedMs: report.soakElapsedMs, circuitLifecycle: lifecycles,
  claimCorrection: 'A replacement circuit ID alone is not proof of natural 30-minute expiry. Preserve raw observations and classify exact expiry separately.',
  continuity: { B: metrics('B'), C: metrics('C'), uninterrupted: ['B', 'C'].every(name => last?.[name].reconnects === first?.[name].reconnects),
    unsolicitedPairedLosses: pairedLosses, interpretation: 'Manual participation continued through recovery; this is not an uninterrupted-circuit stability claim.' },
  capacityAcceptance: {
    advertisedCircuitCapacity: report.expectedCapacity || null,
    observedMaximumBrowserCircuits: Math.max(0, ...report.samples.flatMap(sample => ['B', 'C'].map(name => sample[name].circuits || 0))),
    observedMaximumEndpointCircuits: Math.max(0, ...report.samples.flatMap(sample => ['B', 'C'].map(name => sample[name].endpointCircuits || 0))),
    observedLeaseRenewals: report.observedLeaseRenewals || null,
    nativeCapacityBoundaryTest: 'Separate native/gateway/Worker fixture evidence; not established by this two-Common browser run.',
    fortyDistinctNativePeers: 'NOT_RUN; deployment has two registered Common identities.',
    eightyBrowserSustainedPerformance: 'NOT_RUN',
    meaning: 'Applied capacity and successful real transport are separate from sustained load at the configured maximum.'
  },
  nonfatalPeerErrors: report.peerErrors, gatewayDropReasons: last?.B.nativeStatus?.gateway?.dropReasons || last?.C.nativeStatus?.gateway?.dropReasons,
  leaseContinuity: Object.fromEntries(['B', 'C'].map(name => [name, leaseEvidence(report.samples, name)])),
  gatewayCounterScope: 'Service-wide aggregate, not per-client attribution.',
  observerReference: report.finalNative?.reference, headProgress: report.headProgress,
  limits: { sameHostOnly: report.sameHostOnly, actualLLM: report.actualLLM, actualPhoneHardware: false,
    differentAccessNetworks: 'NOT_RUN', actualFourBrowserNativePath: 'NOT_RUN', applicationBytesExcludeTransportFraming: true },
};
if (process.argv[3]) {
  const sourceRaw = await readFile(process.argv[3]), source = JSON.parse(sourceRaw);
  audit.sourceAvailabilityChange = { artifact: process.argv[3], sha256: sha256(sourceRaw),
    at: source.adminAddPeerUTC, scope: source.scope, accepted: source.adminAddPeerAccepted,
    beforeHeads: Object.fromEntries(Object.entries(source.before).map(([key, value]) => [key, value.head])),
    bConfigChanges: source.bConfigChanges, browserGatewayPinChanges: source.browserGatewayPinChanges,
    processRestarts: source.processRestarts, meaning: 'A received an ordinary TCP upstream during the timed run. B remained isolated and received chain data through its browser mesh route.' };
}
if (process.argv[4]) {
  const bytes = await readFile(process.argv[4]), verification = JSON.parse(bytes);
  audit.finalImplementationVerification = { artifact: process.argv[4], sha256: sha256(bytes), ...verification };
}
if (process.argv[5]) {
  const bytes = await readFile(process.argv[5]), cleanup = JSON.parse(bytes);
  audit.separateCleanupObservation = { artifact: process.argv[5], sha256: sha256(bytes), at: cleanup.utc,
    nodes: Object.fromEntries(['a', 'b'].map(key => [key, { sessions: cleanup.nodes[key].meshStatus.sessions,
      routes: cleanup.nodes[key].meshStatus.routes, meshPeers: cleanup.nodes[key].peers.filter(peer => peer.network?.transport === 'browser-mesh') }])),
    meaning: 'Read-only observation after runner finally closed its own browser processes; no other participant lease was deleted.' };
}
const audited = { ...report, audit, circuitLifecycle: lifecycles };
if (audited.rotation) { audited.legacyRunnerRotation = audited.rotation; delete audited.rotation; }
const auditedPath = input.replace(/\.json$/, '-audited.json');
await writeFile(auditedPath, JSON.stringify(audited, null, 2));
console.log(JSON.stringify({ auditedPath, ...audit }, null, 2));
