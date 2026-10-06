"""Extract numeric/public-digest metrics; never copy encrypted frame bodies."""
import base64
import collections
import datetime
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
report_path = root / 'native-discovery-browser-report.json'
events_path = root / 'native-discovery-browser-report-events.json'
report_bytes = report_path.read_bytes()
events_bytes = events_path.read_bytes()
report = json.loads(report_bytes)
events = json.loads(events_bytes)
assert report['status'] == 'PASS'

proofs = []
for name in ('rawProof', 'alternativeRawProof', 'abruptReplacementRawProof'):
    proof = report[name]
    sent = base64.b64decode(proof['sent']['frame']['data'], validate=True)
    received = base64.b64decode(proof['received']['frame']['data'], validate=True)
    digest = hashlib.sha256(sent).hexdigest()
    assert sent == received
    assert digest == proof['receipt']['digest']
    assert len(sent) == proof['receipt']['rawBytes']
    proofs.append({'stage': name, 'sender': proof['sender'], 'receiver': proof['receiver'],
                   'rawBytes': len(sent), 'sha256': digest,
                   'independentSentReceivedBytesEqual': True, 'hopReceiptDigestMatched': True,
                   'path': proof['receipt']['path'], 'receiptMeaning': proof['receipt']['meaning']})

snapshots = []
def walk(value):
    if isinstance(value, dict):
        if all(isinstance(value.get(key), (int, float)) for key in ('queuedBytes', 'appBytes')) and isinstance(value.get('capacities'), dict):
            snapshots.append(value)
        for child in value.values():
            walk(child)
    elif isinstance(value, list):
        for child in value:
            walk(child)
walk(report)
sample_metrics = {}
for browser in ('B', 'C'):
    rows = [sample[browser] for sample in report['samples']]
    sample_metrics[browser] = {
        'samples': len(rows),
        'maxQueueBytes': max(row['queuedBytes'] for row in rows),
        'maxAppReservationBytes': max(row['appBytes'] for row in rows),
        'maxObservedBrowserPeers': max(row['connectedPeers'] for row in rows),
        'maxObservedCommonAttachments': max(row['nativeConnections'] for row in rows),
        'maxObservedCircuits': max(row['circuits'] for row in rows),
        'maxAccountedSessionBytes': max(row['totalBytes'] for row in rows),
        'queueLimitBytes': rows[0]['capacities']['queueBytes'],
        'appReservationLimitBytes': rows[0]['capacities']['appBytes'],
        'configuredBrowserPeerCapacity': rows[0]['capacities']['peers'],
        'configuredCommonAttachmentCapacity': rows[0]['capacities']['commonConnections'],
        'configuredCircuitCapacity': rows[0]['capacities']['circuits'],
    }

acknowledgements = {}
for browser in ('A', 'B', 'C', 'D'):
    rows = [event for event in events if event.get('browser') == browser and event.get('name') == 'acknowledged']
    ids = {(row.get('generation'), row.get('fromSessionId'), row.get('toSessionId'), row.get('requestId')) for row in rows}
    assert len(ids) == len(rows), 'Receipt events must not double-count request/session identities'
    acknowledgements[browser] = {'uniqueReceiptEvents': len(rows), 'rawBytesAcceptedByPeerHop': sum(row['rawBytes'] for row in rows)}

ttl = report['circuitLifecycle']['naturalTTL']
ttl_summary = {key: ttl[key] for key in ('status', 'reason', 'expiredCircuit', 'createdAt', 'expiresAt', 'eventAt', 'successor', 'successorObservedAt', 'bytesReceived', 'bytesSent')}
ttl_summary['configuredLifetimeMs'] = ttl['expiresAt'] - ttl['createdAt']
ttl_summary['observedExpiryAfterCreationMs'] = ttl['eventAt'] - ttl['createdAt']
ttl_summary['expiryDetectionDelayMs'] = ttl['eventAt'] - ttl['expiresAt']
ttl_summary['successorObservationAfterExpiryMs'] = round(datetime.datetime.fromisoformat(ttl['successorObservedAt'].replace('Z', '+00:00')).timestamp() * 1000) - ttl['eventAt']

hashes = []
for height, values in report['finalNative']['hashes'].items():
    assert values['a'] == values['b'] == values['reference']
    hashes.append({'height': int(height), 'hash': values['a'], 'commonACommonBReferenceEqual': True})
abrupt = next(row for row in report['checkpoints'] if row['name'].startswith('SIGKILL'))
errors = [event for event in events if event.get('name') == 'error']
summary = {
    'generatedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'status': 'PASS',
    'inputs': [{'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()} for path, raw in ((report_path, report_bytes), (events_path, events_bytes))],
    'scope': {'sameHostOnly': report['sameHostOnly'], 'distinctTLSGatewayOrigins': 2,
              'nativeBIsolated': report['nativeBIsolated'], 'realWebRTC': report['webRTCPath'],
              'directDataInjection': report['directInjection'], 'forcedDirect': report['forceDirect'],
              'actualPhoneHardware': False, 'actualLLMRun': report['actualLLM'],
              'note': 'Loopback TLS origins and independent Chromium processes on one host; does not establish separate geographic regions, physical mobile devices, TURN, or 20/40 simultaneous-load performance.'},
    'startedAt': report['startedAt'], 'finishedAt': report['finishedAt'],
    'soakStartedAt': report['soakStartedAt'], 'soakElapsedMs': report['soakElapsedMs'],
    'soakMinutes': report['soakElapsedMs'] / 60000,
    'renewalEvents': report['renewals'], 'leaseContinuity': report['leaseContinuity'],
    'blockProgress': report['headProgress'],
    'finalHeads': {name: node['head'] for name, node in report['finalNative']['nodes'].items()},
    'matchingCanonicalBlockHashes': hashes,
    'independentRawProofs': proofs,
    'naturalCircuitTTL': ttl_summary,
    'abruptCDeathReclaimedMs': abrupt['reclaimedMs'],
    'sampledResources': {'sampleScope': 'Observed snapshots, not continuously measured peak; appBytes is Worker application reservation accounting, not operating-system RAM.',
                         'allReportSnapshots': len(snapshots),
                         'maxObservedQueueBytes': max(row['queuedBytes'] for row in snapshots),
                         'maxObservedAppReservationBytes': max(row['appBytes'] for row in snapshots),
                         'browserSamples': sample_metrics},
    'hopAcknowledgements': {'meaning': 'Peer browser bounded queue acceptance only; not Common consumption, native credit, consensus, or finality.', 'perBrowser': acknowledgements},
    'events': {'total': len(events), 'names': dict(collections.Counter(event.get('name') for event in events)),
               'nonfatalPeerErrors': [{key: row.get(key) for key in ('browser', 'at', 'code', 'fatal')} for row in errors],
               'runnerErrors': len(report['errors'])},
    'sourceHashesUnchanged': not report['changedCoreFiles'],
    'lifecycle': report['lifecycle'],
    'cleanupResolution': str(root / 'native-browser-owned-cleanup-resolution.json'),
}
output = root / 'native-browser-final-metrics.json'
output.write_text(json.dumps(summary, indent=2) + '\n')
lines = [
    '# Native / browser mesh final acceptance: compact metrics', '',
    '- Source run: `native-discovery-browser-report.json`; status **PASS**; source code hashes unchanged.',
    f'- Measured soak: **{report["soakElapsedMs"]:,} ms = 31 minutes + 3 ms**; B/C each renewed their lease **15 times**.',
    '- Native Common B head: **4008 → 4017**; final A/B/reference heads all **4017**. B had only the browser-mesh native route.',
    '- Two loopback TLS gateway origins; independent real Chromium A/B/C/D processes and real direct WebRTC. One physical host; separate regions/networks, physical phones, TURN and actual LLM execution are not established by this run.',
    f'- Natural 30-minute circuit expiration observed after **{ttl_summary["observedExpiryAfterCreationMs"]:,} ms**, reason `circuit-expired` (**{ttl_summary["expiryDetectionDelayMs"]} ms** after scheduled expiry). A successor authenticated circuit was observed **{ttl_summary["successorObservationAfterExpiryMs"]:,} ms** later with **{ttl["bytesReceived"]} received / {ttl["bytesSent"]} sent** native stream bytes.',
    f'- Abrupt C browser death reclaimed its native route and B queue in **{abrupt["reclaimedMs"]:,} ms**; new D provided a fresh authenticated route.',
    '',
    '| Browser samples | Count | Max queue / limit | Max app reservation / limit | Max observed peer / Common / circuit |',
    '|---|---:|---:|---:|---:|',
]
for browser, row in sample_metrics.items():
    lines.append(f'| {browser} | {row["samples"]} | {row["maxQueueBytes"]:,} / {row["queueLimitBytes"]:,} B | {row["maxAppReservationBytes"]:,} / {row["appReservationLimitBytes"]:,} B | {row["maxObservedBrowserPeers"]} / {row["maxObservedCommonAttachments"]} / {row["maxObservedCircuits"]} |')
lines += ['', 'These are sampled maxima and application reservation accounting, not continuous memory peaks or OS RAM. Configured capacities were 20 browser peers / 20 Common attachments / 40 circuits; the path-isolated run used one Common attachment per browser and does not prove full-capacity sustained performance.', '', '| Exact encrypted-byte proof | Bytes | SHA-256 |', '|---|---:|---|']
for proof in proofs:
    lines.append(f'| {proof["sender"]} → {proof["receiver"]} | {proof["rawBytes"]} | `{proof["sha256"]}` |')
lines += ['', 'All three proofs compare independently observed sender/receiver bytes and matching hop receipt digests. Receipts mean bounded browser queue acceptance; they are not native consumption or consensus/finality proofs. Encrypted payloads are deliberately omitted from this summary.', '', '| Native block height | Matching A / B / reference canonical hash |', '|---:|---|']
for row in hashes:
    lines.append(f'| {row["height"]} | `{row["hash"]}` |')
lines += ['', f'Events: {len(events):,}; runner errors: 0; **two nonfatal `invalid_receipt` peer events** (A once, C once) were recorded separately. Do not describe this as zero peer errors.', '', 'Trusted tab hide/freeze stopped participation; resume stayed OFF; navigation terminated the last Worker. This was Chromium with a mobile viewport, not phone hardware.', '', 'The original cleanup audit reported two remaining temporary profiles. `native-browser-owned-cleanup-resolution.json` preserves that history and records their subsequent exact-path removal with PIDs absent and symlinks rejected.', '']
(root / 'native-browser-final-metrics.md').write_text('\n'.join(lines))
print(json.dumps({'json': str(output), 'markdown': str(root / 'native-browser-final-metrics.md'), 'soakElapsedMs': summary['soakElapsedMs'], 'renewals': summary['renewalEvents'], 'maxQueueBytes': summary['sampledResources']['maxObservedQueueBytes'], 'maxAppReservationBytes': summary['sampledResources']['maxObservedAppReservationBytes'], 'proofBytes': [proof['rawBytes'] for proof in proofs], 'nonfatalPeerErrors': len(errors)}, indent=2))
