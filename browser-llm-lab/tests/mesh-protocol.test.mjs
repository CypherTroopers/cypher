import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { MESH_PROTOCOL, MESH_CHANNEL, MESH_LIMITS, nativeCapacity, strictJSON, validateConfig, validateAdvertisement,
  validateNativeFrame, validatePeerMessage, encodePeerMessage, enodePublicKey, encodeBase64, chunkDigest } from '../public/mesh-protocol.js';
const now = 1700000000000;
const network = { chainId: 10101919, genesisHash: '0x' + '22'.repeat(32) };
import { fixtureIdentity, signMeshAdvertisement } from './mesh-signing-fixtures.mjs';
const identity = fixtureIdentity(), publicKey = identity.publicKey, nodeId = identity.nodeId;
const enode = `enode://${publicKey}@127.0.0.1:30445?discport=0`;
const config = { network, nodes: [{ id: 'common-a', nodeId, enode }] };
const session = '44'.repeat(16), circuitId = '55'.repeat(16);
const errorCode = code => error => error?.code === code;
const payload = () => ({ version: 1, network, enode, bootId: '66'.repeat(16), issuedAt: now, expiresAt: now + 120000 });
const ad = (value = payload(), raw = JSON.stringify(value)) => signMeshAdvertisement(value, identity, raw);
const data = (raw = Uint8Array.of(1, 2, 3)) => ({ type: 'data', session, circuitId, seq: 1, data: encodeBase64(raw) });
const receipt = () => ({ requestId: '88'.repeat(16), circuitId, seq: 1, direction: 'forward', digest: '99'.repeat(32), rawBytes: 3 });
const frame = (native = data()) => ({ type: 'FRAME', v: 1, fromSessionId: 'peer-session-a', toSessionId: 'peer-session-b', frame: native, receipt: native.type === 'data' ? receipt() : null });

test('mesh uses distinct native protocol and DataChannel identifiers with bounded resources', () => {
  assert.equal(MESH_PROTOCOL, 'cypher-browser-mesh/1'); assert.equal(MESH_CHANNEL, 'cypher-common-mesh/1');
  assert.equal(MESH_LIMITS.chunkBytes, 8192); assert.equal(MESH_LIMITS.frameBytes, 16384);
  validateConfig(config);
});

test('endpoint configuration rejects duplicate labels, native identities and public keys', () => {
  const other = { id: 'common-b', nodeId: 'aa'.repeat(32), publicKey: 'bb'.repeat(64) };
  validateConfig({ network, nodes: [...config.nodes, other] });
  for (const duplicate of [{ ...other, id: 'common-a' }, { ...other, nodeId }, { ...other, publicKey }])
    assert.throws(() => validateConfig({ network, nodes: [...config.nodes, duplicate] }), errorCode('configuration'));
  for (const nodes of [[], Array.from({ length: 65 }, () => other)]) assert.throws(() => validateConfig({ network, nodes }));
  assert.throws(() => validateConfig({ network, nodes: [{ ...other, nodeId: 'not-a-native-id' }] }));
});

test('canonical enode parsing accepts literal addresses and never accepts DNS or credentials', () => {
  assert.equal(enodePublicKey(enode), publicKey);
  assert.equal(enodePublicKey(`enode://${publicKey}`), publicKey);
  assert.equal(enodePublicKey(`enode://${publicKey}@[::1]:30445?discport=0`), publicKey);
  for (const endpoint of ['example.com:30445', '127.0.0.1:65536', '0127.0.0.1:30445', '256.1.1.1:1',
    '127.0.0.1:030445', '[:::]:30445', 'user@127.0.0.1:30445', '127.0.0.1:30445/path', '127.0.0.1:30445?token=secret'])
    assert.throws(() => enodePublicKey(`enode://${publicKey}@${endpoint}`));
});

test('advertisement cryptographic verification preserves exact signed payload bytes', () => {
  const raw = JSON.stringify(payload(), null, 2) + '\n', advertisement = ad(payload(), raw);
  const result = validateAdvertisement(advertisement, config, now);
  assert.equal(Buffer.from(result.raw).toString(), raw); assert.equal(result.advertisement.payloadBase64, advertisement.payloadBase64);
  assert.equal(result.nodeId, nodeId); assert.equal(result.sourceId, 'common-a');
  assert.equal(result.publicKey, publicKey);
  const invalid = { ...advertisement, signatureHex: '77'.repeat(64) + '00' };
  assert.throws(() => validateAdvertisement(invalid, config, now), errorCode('invalid_signature'));
});

test('advertisements reject other networks, forged native keys, duplicate/extra fields and bad signatures', () => {
  for (const wrong of [{ ...network, chainId: 1 }, { ...network, genesisHash: '0x' + 'ab'.repeat(32) }])
    assert.throws(() => validateAdvertisement(ad({ ...payload(), network: wrong }), config, now), errorCode('wrong_network'));
  assert.throws(() => validateAdvertisement(ad({ ...payload(), enode: `enode://${'aa'.repeat(64)}@127.0.0.1:3` }), config, now), errorCode('invalid_signature'));
  for (const malformed of [ad({ ...payload(), extra: 1 }), { ...ad(), extra: 1 }, ad(payload(), JSON.stringify(payload()).replace('"version":1', '"version":1,"\\u0076ersion":1'))])
    assert.throws(() => validateAdvertisement(malformed, config, now));
  for (const signatureHex of ['', 'aa'.repeat(64), 'AA'.repeat(64) + '00', 'aa'.repeat(64) + '02'])
    assert.throws(() => validateAdvertisement({ ...ad(), signatureHex }, config, now));
});

test('advertisement expiry, future observation, TTL and 2KiB raw bounds are enforced', () => {
  validateAdvertisement(ad(), config, now + 119999);
  assert.throws(() => validateAdvertisement(ad(), config, now + 120000), errorCode('stale_advertisement'));
  validateAdvertisement(ad(), config, now - 10000);
  assert.throws(() => validateAdvertisement(ad(), config, now - 10001), errorCode('stale_advertisement'));
  for (const invalid of [{ ...payload(), expiresAt: now + 120001 }, { ...payload(), expiresAt: now }, { ...payload(), issuedAt: -1 }, { ...payload(), bootId: 'old-process' }])
    assert.throws(() => validateAdvertisement(ad(invalid), config, now), errorCode('stale_advertisement'));
  assert.throws(() => validateAdvertisement(ad(payload(), ' '.repeat(2049) + JSON.stringify(payload())), config, now));
});

test('native hello and route-less local advertisement require explicit context flags', () => {
  const hello = { type: 'hello', session, browserId: 'browser-A', protocol: MESH_PROTOCOL, advertisement: ad() };
  assert.throws(() => validateNativeFrame(hello)); assert.deepEqual(validateNativeFrame(hello, { allowHello: true }), hello);
  const update = { type: 'advertisement', session, advertisement: ad() };
  assert.throws(() => validateNativeFrame(update)); assert.deepEqual(validateNativeFrame(update, { allowLocalAdvertisement: true }), update);
  assert.throws(() => validatePeerMessage(frame(hello)));
  assert.throws(() => validatePeerMessage(frame(update)));
});

test('native routes bind a current generation and bounded non-looping browser labels', () => {
  const open = { type: 'open', session, circuitId, target: nodeId, advertisement: ad(), route: ['browser-A', 'browser-B'] };
  assert.deepEqual(validateNativeFrame(JSON.stringify(open)), open);
  for (const route of [[], ['browser-A', 'browser-A'], ['a', 'b', 'c', 'd', 'e'], ['../address']])
    assert.throws(() => validateNativeFrame({ ...open, route }));
  for (const broken of [{ ...open, session: 'old-session' }, { ...open, circuitId: '0' }, { ...open, target: enode }, { ...open, url: 'http://host/' }])
    assert.throws(() => validateNativeFrame(broken));
  assert.throws(() => validateNativeFrame(JSON.stringify(open).replace('"type":"open"', '"type":"open","type":"data"')));
});

test('opaque stream chunks preserve bytes and enforce canonical base64, ordered sequence format and 8KiB cap', () => {
  const bytes = new Uint8Array(8192).fill(0xff), native = data(bytes);
  assert.deepEqual(validateNativeFrame(native), native);
  for (const broken of [{ ...native, data: encodeBase64(new Uint8Array(8193)) }, { ...native, data: '' },
    { ...native, data: 'AB==' }, { ...native, data: 'AQ' }, { ...native, seq: 0 }, { ...native, seq: 1.5 }, { ...native, seq: Number.MAX_SAFE_INTEGER + 1 }])
    assert.throws(() => validateNativeFrame(broken));
  const credit = { type: 'credit', session, circuitId, seq: 1, bytes: 8192 }; validateNativeFrame(credit);
  for (const count of [0, 8193, -1, 1.5]) assert.throws(() => validateNativeFrame({ ...credit, bytes: count }));
});

test('browser FRAME and hop receipt bind both sessions, circuit and sequence; native credit is distinct', () => {
  const message = frame(); assert.deepEqual(validatePeerMessage(encodePeerMessage(message)), message);
  for (const broken of [{ ...message, receipt: null }, { ...message, fromSessionId: '' }, { ...message, toSessionId: '' },
    { ...message, receipt: { ...receipt(), circuitId: 'aa'.repeat(16) } }, { ...message, receipt: { ...receipt(), seq: 2 } },
    { ...message, receipt: { ...receipt(), direction: 'consensus-finalized' } }, { ...message, receipt: { ...receipt(), rawBytes: 8193 } }])
    assert.throws(() => validatePeerMessage(broken));
  const nativeCredit = { type: 'credit', session, circuitId, seq: 1, bytes: 3 };
  validatePeerMessage(frame(nativeCredit));
  assert.throws(() => validatePeerMessage({ ...frame(nativeCredit), receipt: receipt() }));
  const confirmation = { type: 'RECEIPT', v: 1, fromSessionId: 'session-b', toSessionId: 'session-a', receipt: receipt() };
  validatePeerMessage(confirmation);
  const missing = { ...confirmation, receipt: { ...receipt() } }; delete missing.receipt.requestId; assert.throws(() => validatePeerMessage(missing));
});

test('peer HELLO/heartbeat schemas and total frame bounds reject legacy or ambiguous messages', () => {
  const hello = { type: 'HELLO', v: 1, network, peerId: 'peer-A', sessionId: 'session-A', browserId: 'browser-A' };
  validatePeerMessage(hello);
  assert.throws(() => validatePeerMessage({ ...hello, v: 2 }));
  assert.throws(() => validatePeerMessage({ type: 'ACK', v: 1 }));
  const ping = { type: 'PING', v: 1, fromSessionId: 'a', toSessionId: 'b', nonce: '11'.repeat(16) }; validatePeerMessage(ping);
  assert.throws(() => validatePeerMessage({ ...ping, nonce: 'short' }));
  assert.throws(() => validatePeerMessage(' '.repeat(MESH_LIMITS.frameBytes) + JSON.stringify(ping)), errorCode('oversize'));
  assert.throws(() => strictJSON('{"type":"PING","\\u0074ype":"PONG"}'), errorCode('invalid_json'));
});

test('hop chunk digest independently hashes complete opaque bytes without interpreting RLPx', async () => {
  const raw = Uint8Array.from([0, 255, 65, 128, 0]);
  assert.equal(await chunkDigest(raw), createHash('sha256').update(raw).digest('hex'));
  assert.notEqual(await chunkDigest(raw), await chunkDigest(Uint8Array.from([0, 255, 65, 128, 1])));
  await assert.rejects(chunkDigest(new Uint8Array())); await assert.rejects(chunkDigest(new Uint8Array(8193)));
});


test('negotiated Common capacities admit recognized profiles and fail closed on malformed or future limits', () => {
  const modern = { maxSessions: 80, nativePeers: 40, circuits: 40, circuitsPerSession: 40, pendingInbound: 4, pendingOutbound: 4 };
  assert.deepEqual(nativeCapacity(modern), modern);
  assert.equal(nativeCapacity().circuitsPerSession, 2, 'Old public gateways cannot silently grant new capacity');
  for (const value of [null, {}, { ...modern, circuits: 41 }, { ...modern, pendingInbound: 5 }, { ...modern, nativePeers: 4 }, { ...modern, maxSessions: '80' }])
    assert.throws(() => nativeCapacity(value), errorCode('configuration'));
  assert.equal(MESH_LIMITS.peers, 20); assert.equal(MESH_LIMITS.nativeConnections, 20); assert.equal(MESH_LIMITS.circuits, 40); assert.equal(MESH_LIMITS.endpointCircuits, 40);
  assert.equal(MESH_LIMITS.pendingHandshakes, 8); assert.equal(MESH_LIMITS.pendingPerDirection, 4);
  assert.equal(MESH_LIMITS.queueFrames, 64); assert.equal(MESH_LIMITS.queueBytes, 512 * 1024); assert.equal(MESH_LIMITS.appBytes, 4 * 1024 * 1024);
});


test('independently signed Common advertisements are discovered without fixed operator pins', () => {
  const other = fixtureIdentity(2), value = { ...payload(), enode: other.enode };
  const result = validateAdvertisement(signMeshAdvertisement(value, other), config, now);
  assert.equal(result.nodeId, other.nodeId); assert.equal(result.sourceId, other.nodeId);
  assert.throws(() => validateAdvertisement(signMeshAdvertisement(value, identity), config, now), errorCode('invalid_signature'));
});
