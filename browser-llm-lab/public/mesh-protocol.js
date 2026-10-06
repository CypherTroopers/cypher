// Browsers verify exact native secp256k1 advertisements before storing routes.
// Native Common endpoints independently authenticate advertisements and RLPx.
import { strictJSON, exactFields, asBytes, byteLength, decodeBase64, encodeBase64,
  validateNetwork, sameNetwork, protocolError, TokenBucket } from './relay-protocol.js';
import { enodePublicKey, verifyMeshAdvertisement } from './mesh-discovery.js';
export { enodePublicKey };
export { strictJSON, asBytes, byteLength, decodeBase64, encodeBase64, validateNetwork, sameNetwork, protocolError, TokenBucket };
export const MESH_PROTOCOL = 'cypher-browser-mesh/1';
export const MESH_CHANNEL = 'cypher-common-mesh/1';
export const MESH_LIMITS = Object.freeze({ frameBytes: 16384, chunkBytes: 8192, peers: 20, nativeConnections: 20, hops: 4,
  circuits: 40, endpointCircuits: 40, pendingHandshakes: 8, pendingPerDirection: 4, hopReceipts: 128, queueFrames: 64, queueBytes: 512 * 1024,
  inputFrames: 128, appBytes: 4 * 1024 * 1024, transferBytes: 100 * 1024 * 1024,
  advertisementTTL: 120000, circuitTTL: 1800000, openTimeout: 8000, heartbeat: 5000, peerTimeout: 15000 });
// Only these deployed native capacity profiles are understood by this version.
// Absence keeps an old gateway compatible without granting its Common new capacity.
export function nativeCapacity(limits) {
  const legacy = { maxSessions: 8, nativePeers: 4, circuits: 8, circuitsPerSession: 2, pendingInbound: 4, pendingOutbound: 4 };
  if (limits === undefined) return legacy;
  check(limits && typeof limits === 'object' && !Array.isArray(limits), 'Invalid Common capacity.', 'configuration');
  const modern = limits.maxSessions === 80 && limits.nativePeers === 40 && limits.circuits === 40 && limits.circuitsPerSession === 40;
  const old = limits.maxSessions === 8 && limits.nativePeers === 4 && limits.circuits === 8 && limits.circuitsPerSession === 2;
  check((modern || old) && limits.pendingInbound === 4 && limits.pendingOutbound === 4, 'Unsupported Common capacity profile.', 'configuration');
  return Object.fromEntries(Object.keys(legacy).map(key => [key, limits[key]]));
}
export const validLabel = v => typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/u.test(v);
export const validRandomId = v => typeof v === 'string' && /^[0-9a-f]{32}$/u.test(v);
export const validNodeId = v => typeof v === 'string' && /^[0-9a-f]{64}$/u.test(v);
const integer = (v, min = 0, max = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(v) && v >= min && v <= max;
export function check(condition, message, code = 'invalid_message') { if (!condition) throw protocolError(code, message); }
const object = input => typeof input === 'string' || input instanceof ArrayBuffer || ArrayBuffer.isView(input) ? strictJSON(input, MESH_LIMITS.frameBytes) : input;
export function validateConfig(config) {
  validateNetwork(config?.network);
  check(Array.isArray(config.nodes) && config.nodes.length >= 1 && config.nodes.length <= 64, 'Pinned Common endpoints are required.', 'configuration');
  const ids = new Set(), keys = new Set(), labels = new Set();
  for (const node of config.nodes) {
    const key = node.publicKey || enodePublicKey(node.enode);
    check(validLabel(node.id) && validNodeId(node.nodeId) && /^[0-9a-f]{128}$/u.test(key) && !labels.has(node.id) && !ids.has(node.nodeId) && !keys.has(key), 'Invalid or duplicate Common identity pin.', 'configuration');
    ids.add(node.nodeId); keys.add(key); labels.add(node.id);
  }
  return config;
}
export function validateAdvertisement(advertisement, config, now = Date.now()) {
  const verified = verifyMeshAdvertisement(advertisement, config.network, now);
  // A known direct attachment supplies a display label; it is no longer an
  // allowlist for transit advertisements from independently verified Commons.
  const node = config.nodes?.find(n => (n.publicKey || enodePublicKey(n.enode)) === verified.publicKey);
  return { ...verified, advertisement: verified.envelope, sourceId: node?.id || verified.nodeId };
}
export function validateRoute(route) {
  check(Array.isArray(route) && route.length >= 1 && route.length <= MESH_LIMITS.hops && route.every(validLabel) && new Set(route).size === route.length, 'Invalid or looping browser route.');
  return route;
}
export function validateNativeFrame(input, { allowHello = false, allowLocalAdvertisement = false } = {}) {
  const frame = object(input), common = ['type', 'session'];
  check(frame && validRandomId(frame.session), 'Invalid native connection generation.');
  const schemas = {
    hello: [...common, 'browserId', 'protocol', 'advertisement'],
    advertisement: [...common, 'advertisement', ...(allowLocalAdvertisement && !Object.hasOwn(frame, 'route') ? [] : ['route'])],
    open: [...common, 'circuitId', 'target', 'advertisement', 'route'], opened: [...common, 'circuitId'],
    data: [...common, 'circuitId', 'seq', 'data'], credit: [...common, 'circuitId', 'seq', 'bytes'], close: [...common, 'circuitId', 'reason']
  };
  check(schemas[frame.type] && (frame.type !== 'hello' || allowHello), 'Unexpected native frame type.');
  exactFields(frame, schemas[frame.type]);
  if (frame.type === 'hello') check(frame.protocol === MESH_PROTOCOL && validLabel(frame.browserId), 'Invalid native HELLO.');
  if (frame.route !== undefined) validateRoute(frame.route);
  if (frame.advertisement !== undefined) exactFields(frame.advertisement, ['payloadBase64', 'signatureHex']);
  if (frame.circuitId !== undefined) check(validRandomId(frame.circuitId), 'Invalid circuit ID.');
  if (frame.type === 'open') check(validNodeId(frame.target), 'Invalid target node ID.');
  if (frame.type === 'data') check(integer(frame.seq, 1) && decodeBase64(frame.data, MESH_LIMITS.chunkBytes).length >= 1, 'Invalid stream chunk.');
  if (frame.type === 'credit') check(integer(frame.seq, 1) && integer(frame.bytes, 1, MESH_LIMITS.chunkBytes), 'Invalid native credit.');
  if (frame.type === 'close') check(validLabel(frame.reason), 'Invalid circuit close reason.');
  check(byteLength(JSON.stringify(frame)) <= MESH_LIMITS.frameBytes, 'Native frame exceeds limit.', 'oversize');
  return frame;
}
function receiptFields(receipt, includeRequest = true) {
  exactFields(receipt, [...(includeRequest ? ['requestId'] : []), 'circuitId', 'seq', 'direction', 'digest', 'rawBytes']);
  check((!includeRequest || validRandomId(receipt.requestId)) && validRandomId(receipt.circuitId) && integer(receipt.seq, 1) &&
    ['forward', 'reverse'].includes(receipt.direction) && validNodeId(receipt.digest) && integer(receipt.rawBytes, 1, MESH_LIMITS.chunkBytes), 'Invalid hop receipt binding.');
}
export function validatePeerMessage(input) {
  const message = object(input), common = ['type', 'v'], sessions = [...common, 'fromSessionId', 'toSessionId'];
  const schemas = { HELLO: [...common, 'network', 'peerId', 'sessionId', 'browserId'], FRAME: [...sessions, 'frame', 'receipt'],
    RECEIPT: [...sessions, 'receipt'], PING: [...sessions, 'nonce'], PONG: [...sessions, 'nonce'] };
  check(message && schemas[message.type] && message.v === 1, 'Invalid mesh peer message.'); exactFields(message, schemas[message.type]);
  if (message.type === 'HELLO') { validateNetwork(message.network); check([message.peerId, message.sessionId, message.browserId].every(validLabel), 'Invalid peer HELLO.'); }
  else check(validLabel(message.fromSessionId) && validLabel(message.toSessionId), 'Invalid peer session binding.');
  if (message.type === 'FRAME') {
    validateNativeFrame(message.frame);
    if (message.frame.type === 'data') { receiptFields(message.receipt); check(message.receipt.circuitId === message.frame.circuitId && message.receipt.seq === message.frame.seq, 'Receipt differs from forwarded frame.'); }
    else check(message.receipt === null, 'Only opaque DATA receives a hop receipt.');
  }
  if (message.type === 'RECEIPT') receiptFields(message.receipt);
  if (message.type === 'PING' || message.type === 'PONG') check(validRandomId(message.nonce), 'Invalid heartbeat nonce.');
  check(byteLength(JSON.stringify(message)) <= MESH_LIMITS.frameBytes, 'Peer frame exceeds limit.', 'oversize');
  return message;
}
export const encodePeerMessage = message => JSON.stringify(validatePeerMessage(message));
export async function chunkDigest(raw) {
  check(raw instanceof Uint8Array && raw.length >= 1 && raw.length <= MESH_LIMITS.chunkBytes, 'Invalid digest chunk.');
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', raw))].map(v => v.toString(16).padStart(2, '0')).join('');
}
