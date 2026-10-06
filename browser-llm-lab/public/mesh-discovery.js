// Public discovery authenticates identities and endpoint claims, not consensus,
// physical location, Common role, or an anonymous browser's native affiliation.
import { secp256k1, keccak_256 } from './vendor/mesh-crypto.js';
import { strictJSON, exactFields, decodeBase64, encodeBase64, byteLength, validateNetwork, sameNetwork, protocolError } from './relay-protocol.js';
const encoder = new TextEncoder();
const integer = (v, min = 0, max = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(v) && v >= min && v <= max;
const randomId = v => typeof v === 'string' && /^[0-9a-f]{32}$/u.test(v);
const nodeId = v => typeof v === 'string' && /^[0-9a-f]{64}$/u.test(v);
const label = v => typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/u.test(v);
function check(value, message, code = 'invalid_message') { if (!value) throw protocolError(code, message); }
const hex = bytes => Array.from(bytes, v => v.toString(16).padStart(2, '0')).join('');
const unhex = value => Uint8Array.from(value.match(/../gu), v => parseInt(v, 16));
const concat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0; for (const p of parts) { out.set(p, at); at += p.length; } return out; };
export const DISCOVERY_DOMAINS = Object.freeze({ advertisement: 'cypher-browser-mesh-advertisement-v1\0', endpoint: 'cypher-browser-mesh-endpoint-v1\0',
  browser: 'cypher-browser-mesh-browser-v1\0', signal: 'cypher-browser-mesh-signal-v1\0', challenge: 'cypher-browser-mesh-rendezvous-auth-v1\0' });
export const DISCOVERY_LIMITS = Object.freeze({ endpoints: 64, rendezvous: 4, recordTTL: 120000, signalTTL: 30000, challengeTTL: 5000,
  envelopeBytes: 8192, payloadBytes: 4096, signalBytes: 32768, clockSkew: 10000 });
function hash(domain, raw) { return keccak_256(concat(encoder.encode(domain), raw)); }
function parseEnvelope(envelope, rawLimit = 4096, envelopeLimit = 8192) {
  if (typeof envelope === 'string' || envelope instanceof ArrayBuffer || ArrayBuffer.isView(envelope)) envelope = strictJSON(envelope, envelopeLimit);
  exactFields(envelope, ['payloadBase64', 'signatureHex']);
  check(byteLength(JSON.stringify(envelope)) <= envelopeLimit, 'Signed envelope exceeds size limit.', 'oversize');
  check(typeof envelope.signatureHex === 'string' && /^[0-9a-f]{128}0[01]$/u.test(envelope.signatureHex), 'Invalid recoverable signature encoding.', 'invalid_signature');
  const raw = decodeBase64(envelope.payloadBase64, rawLimit);
  return { envelope: { ...envelope }, raw, payload: strictJSON(raw, rawLimit) };
}
function verifyBytes(envelope, domain, raw, publicKey) {
  check(typeof publicKey === 'string' && /^[0-9a-f]{128}$/u.test(publicKey), 'Invalid public identity.', 'invalid_signature');
  const signature = unhex(envelope.signatureHex), recovered = concat(signature.subarray(64), signature.subarray(0, 64));
  let valid = false;
  try { valid = secp256k1.verify(recovered, hash(domain, raw), unhex('04' + publicKey), { prehash: false, format: 'recovered', lowS: true }); } catch { /* Fail closed on invalid curve points. */ }
  check(valid, 'Signed discovery record failed native identity verification.', 'invalid_signature');
}
function signBytes(domain, raw, identity) {
  const signed = secp256k1.sign(hash(domain, raw), identity.privateKey, { prehash: false, format: 'recovered', lowS: true });
  check(signed[0] <= 1, 'Unsupported recovery ID.', 'invalid_signature');
  return hex(concat(signed.subarray(1), signed.subarray(0, 1)));
}
function signed(payload, domain, identity) { const raw = encoder.encode(JSON.stringify(payload)); return { payloadBase64: encodeBase64(raw), signatureHex: signBytes(domain, raw, identity) }; }
function networkTime(payload, network, now, ttl = 120000) {
  validateNetwork(network); validateNetwork(payload.network);
  check(payload.version === 1 && sameNetwork(payload.network, network), 'Discovery record is for a different network.', 'wrong_network');
  check(integer(now) && integer(payload.issuedAt) && integer(payload.expiresAt, 1) && payload.issuedAt <= now + 10000 && payload.expiresAt > now &&
    payload.expiresAt > payload.issuedAt && payload.expiresAt - payload.issuedAt <= ttl, 'Discovery record expired or has invalid time bounds.', 'stale_advertisement');
}
export function enodePublicKey(enode) {
  check(typeof enode === 'string' && enode.length <= 512, 'Invalid enode.');
  const incomplete = /^enode:\/\/([0-9a-f]{128})$/u.exec(enode); if (incomplete) return incomplete[1];
  const match = /^enode:\/\/([0-9a-f]{128})@([^/?#]+)(?:\?discport=(0|[1-9][0-9]{0,4}))?$/u.exec(enode);
  check(match, 'Only canonical enode public identities and numeric IP endpoints are accepted.');
  const endpoint = /^(?:\[([0-9a-f:]+)\]|((?:[0-9]{1,3}\.){3}[0-9]{1,3})):(0|[1-9][0-9]{0,4})$/u.exec(match[2]);
  check(endpoint && Number(endpoint[3]) <= 65535 && (match[3] === undefined || Number(match[3]) <= 65535), 'Invalid numeric enode endpoint.');
  if (endpoint[2]) check(endpoint[2].split('.').every(v => String(Number(v)) === v && Number(v) <= 255), 'Invalid IPv4 endpoint.');
  else { try { check(new URL(`http://[${endpoint[1]}]/`).hostname === `[${endpoint[1]}]`, 'Noncanonical IPv6 endpoint.'); } catch { throw protocolError('invalid_message', 'Invalid IPv6 endpoint.'); } }
  return match[1];
}
export function publicKeyNodeId(publicKey) {
  check(typeof publicKey === 'string' && /^[0-9a-f]{128}$/u.test(publicKey), 'Invalid public identity.');
  check(secp256k1.utils.isValidPublicKey(unhex('04' + publicKey)), 'Invalid curve point.', 'invalid_signature');
  return hex(keccak_256(unhex(publicKey)));
}
export function verifyMeshAdvertisement(envelope, network, now = Date.now()) {
  const record = parseEnvelope(envelope, 2048, 4096), { payload, raw } = record;
  exactFields(payload, ['version', 'network', 'enode', 'bootId', 'issuedAt', 'expiresAt']);
  networkTime(payload, network, now);
  check(randomId(payload.bootId), 'Invalid Common boot ID.', 'stale_advertisement');
  const publicKey = enodePublicKey(payload.enode); verifyBytes(record.envelope, DISCOVERY_DOMAINS.advertisement, raw, publicKey);
  return { ...record, publicKey, nodeId: publicKeyNodeId(publicKey) };
}
// A TLS origin is a transport claim, never a request to proxy arbitrary URLs.
// Server-side dialers must additionally resolve/recheck public DNS addresses.
export function safeGatewayOrigin(value) {
  check(typeof value === 'string' && value.length <= 255 && !/[\\\s]/u.test(value), 'Invalid public gateway origin.', 'unsafe_origin');
  let url; try { url = new URL(value); } catch { throw protocolError('unsafe_origin', 'Invalid public gateway origin.'); }
  check(url.protocol === 'https:' && url.origin === value && !url.username && !url.password && url.pathname === '/' && !url.search && !url.hash,
    'Gateway must be a canonical HTTPS origin without a path or credentials.', 'unsafe_origin');
  check(!url.port || Number(url.port) >= 1, 'Gateway port is invalid.', 'unsafe_origin');
  const host = url.hostname;
  if (host.startsWith('[')) {
    // Public IPv6 unicast only: excludes loopback, ULA, link-local, mapped IPv4,
    // multicast and translation prefixes. URL canonicalization rejects aliases.
    check(/^\[[23][0-9a-f]{3}:/u.test(host), 'Gateway IPv6 address is not public unicast.', 'unsafe_origin');
    const groups = host.slice(1, -1).split(':'), first = parseInt(groups[0], 16), second = parseInt(groups[1] || '0', 16);
    check(first !== 0x2002 && !(first === 0x2001 && (second < 0x200 || second === 0xdb8)) && first !== 0x3fff,
      'Reserved or transition IPv6 gateway.', 'unsafe_origin');
  } else if (/^[0-9.]+$/u.test(host)) {
    const parts = host.split('.').map(Number), [a, b, c] = parts;
    check(parts.length === 4 && parts.every((v, i) => integer(v, 0, 255) && String(v) === host.split('.')[i]), 'Invalid gateway address.', 'unsafe_origin');
    check(a !== 0 && a !== 10 && a !== 127 && a < 224 && !(a === 100 && b >= 64 && b <= 127) && !(a === 169 && b === 254) &&
      !(a === 172 && b >= 16 && b <= 31) && !(a === 192 && (b === 168 || b === 0 || b === 2 || b === 88 && c === 99)) && !(a === 198 && (b === 18 || b === 19 || b === 51 && c === 100)) && !(a === 203 && b === 0 && c === 113),
    'Gateway address is private or reserved.', 'unsafe_origin');
  } else {
    check(host.includes('.') && !host.endsWith('.') && host.split('.').every(part => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(part)) &&
      !/(?:^|\.)(?:localhost|local|internal|lan|home|invalid|test)$/u.test(host), 'Gateway hostname is not public.', 'unsafe_origin');
  }
  return value;
}
export function verifyEndpoint(envelope, network, now = Date.now()) {
  const record = parseEnvelope(envelope), { payload, raw } = record;
  exactFields(payload, ['version', 'network', 'enode', 'sourceId', 'gatewayOrigin', 'bootId', 'sequence', 'issuedAt', 'expiresAt']);
  networkTime(payload, network, now);
  check(label(payload.sourceId) && randomId(payload.bootId) && integer(payload.sequence, 1), 'Invalid endpoint generation.');
  const origin = safeGatewayOrigin(payload.gatewayOrigin), publicKey = enodePublicKey(payload.enode);
  verifyBytes(record.envelope, DISCOVERY_DOMAINS.endpoint, raw, publicKey);
  return { ...record, publicKey, nodeId: publicKeyNodeId(publicKey), origin, sourceId: payload.sourceId, expiresAt: payload.expiresAt };
}
// This cache is RAM-only. A retained high-water mark also bounds restart/replay
// metadata; live candidates are never evicted to admit a flood of new identities.
export class EndpointCache {
  constructor(network, { now = Date.now, maxEntries = 64 } = {}) {
    validateNetwork(network); check(typeof now === 'function' && integer(maxEntries, 1, 64), 'Invalid endpoint cache limits.');
    this.network = { ...network }; this.now = now; this.maxEntries = maxEntries; this.records = new Map();
  }
  prune() {
    const now = this.now();
    for (const [id, state] of this.records) {
      for (const [boot, expires] of state.retired) if (expires + 10000 <= now) state.retired.delete(boot);
      if (state.record.expiresAt + 10000 <= now && state.retired.size === 0) this.records.delete(id);
    }
  }
  add(envelope) {
    const record = verifyEndpoint(envelope, this.network, this.now()); this.prune();
    const old = this.records.get(record.nodeId), p = record.payload;
    if (old) {
      const prior = old.record.payload;
      check(!old.retired.has(p.bootId), 'Previously retired Common boot was replayed.', 'sequence_rollback');
      if (p.bootId === prior.bootId) {
        check(p.sequence >= prior.sequence && p.issuedAt >= prior.issuedAt, 'Endpoint sequence moved backwards.', 'sequence_rollback');
        if (p.sequence === prior.sequence) {
          check(record.envelope.payloadBase64 === old.record.envelope.payloadBase64 && record.envelope.signatureHex === old.record.envelope.signatureHex, 'Endpoint changed without advancing its sequence.', 'sequence_rollback');
          return old.record;
        }
      } else {
        check(p.issuedAt > prior.issuedAt, 'New Common boot predates the current advertisement.', 'sequence_rollback');
        check(old.retired.size < 8, 'Common restarted too often within the replay window.', 'resource_limit');
        old.retired.set(prior.bootId, prior.expiresAt);
      }
      old.record = record;
    } else {
      check(this.records.size < this.maxEntries, 'Endpoint cache is at capacity.', 'resource_limit');
      this.records.set(record.nodeId, { record, retired: new Map() });
    }
    return record;
  }
  values() { this.prune(); const now = this.now(); return [...this.records.values()].map(v => v.record).filter(v => v.expiresAt > now); }
  get(id) { this.prune(); const value = this.records.get(id)?.record; return value?.expiresAt > this.now() ? value : undefined; }
}
export function createBrowserIdentity() {
  const privateKey = secp256k1.utils.randomSecretKey(), publicKeyHex = hex(secp256k1.getPublicKey(privateKey, false).subarray(1));
  return { privateKey, publicKeyHex, peerId: publicKeyNodeId(publicKeyHex).slice(0, 32) };
}
export function signBrowserRecord(fields, identity) {
  const payload = { version: 1, network: fields.network, peerId: identity.peerId, sessionId: fields.sessionId, browserId: fields.browserId,
    nodeId: fields.nodeId, sourceId: fields.sourceId, publicKeyHex: identity.publicKeyHex, rendezvous: fields.rendezvous, issuedAt: fields.issuedAt, expiresAt: fields.expiresAt };
  const envelope = signed(payload, DISCOVERY_DOMAINS.browser, identity);
  verifyBrowserRecord(envelope, fields.network, fields.issuedAt); return envelope;
}
export function verifyBrowserRecord(envelope, network, now = Date.now()) {
  const record = parseEnvelope(envelope), { payload, raw } = record;
  exactFields(payload, ['version', 'network', 'peerId', 'sessionId', 'browserId', 'nodeId', 'sourceId', 'publicKeyHex', 'rendezvous', 'issuedAt', 'expiresAt']);
  networkTime(payload, network, now);
  check([payload.peerId, payload.sessionId, payload.browserId].every(randomId) && nodeId(payload.nodeId) && label(payload.sourceId), 'Invalid browser identity or generation.');
  check(Array.isArray(payload.rendezvous) && payload.rendezvous.length >= 1 && payload.rendezvous.length <= 4 && new Set(payload.rendezvous).size === payload.rendezvous.length, 'Invalid rendezvous origins.');
  payload.rendezvous.forEach(safeGatewayOrigin);
  verifyBytes(record.envelope, DISCOVERY_DOMAINS.browser, raw, payload.publicKeyHex);
  check(publicKeyNodeId(payload.publicKeyHex).slice(0, 32) === payload.peerId, 'Browser identity does not match signing key.', 'invalid_signature');
  return { ...payload, ...record, publicKey: payload.publicKeyHex };
}
function validateSignalPayload(payload, network, now) {
  exactFields(payload, ['version', 'network', 'from', 'to', 'fromSessionId', 'toSessionId', 'seq', 'type', 'value', 'issuedAt', 'expiresAt']);
  networkTime(payload, network, now, 30000);
  check([payload.from, payload.to, payload.fromSessionId, payload.toSessionId].every(randomId) && payload.from !== payload.to && integer(payload.seq, 1), 'Invalid signal identity, generation or sequence.');
  check(['offer', 'answer', 'ice'].includes(payload.type), 'Invalid signed signal type.');
  if (payload.type !== 'ice') check(typeof payload.value === 'string' && byteLength(payload.value) <= 20000 && payload.value.length > 0, 'Invalid SDP.');
  else if (payload.value !== null) {
    exactFields(payload.value, ['candidate', 'sdpMid', 'sdpMLineIndex', 'usernameFragment']);
    check(typeof payload.value.candidate === 'string' && byteLength(payload.value.candidate) <= 2048 &&
      (payload.value.sdpMid === null || typeof payload.value.sdpMid === 'string' && payload.value.sdpMid.length <= 256) &&
      (payload.value.sdpMLineIndex === null || integer(payload.value.sdpMLineIndex, 0, 65535)) &&
      (payload.value.usernameFragment === null || typeof payload.value.usernameFragment === 'string' && payload.value.usernameFragment.length <= 256), 'Invalid ICE candidate.');
  }
}
export function signSignal(payload, identity) {
  validateSignalPayload(payload, payload.network, payload.issuedAt);
  check(payload.from === identity.peerId, 'Signal signer identity mismatch.', 'invalid_signature');
  const result = signed(payload, DISCOVERY_DOMAINS.signal, identity);
  parseEnvelope(result, 24000, 32768); return result;
}
export function verifySignal(envelope, record, network, now = Date.now()) {
  const browser = verifyBrowserRecord(record.envelope || record, network, now), signedRecord = parseEnvelope(envelope, 24000, 32768), { payload, raw } = signedRecord;
  validateSignalPayload(payload, network, now);
  check(payload.from === browser.peerId && payload.fromSessionId === browser.sessionId, 'Signal is for a stale browser identity or generation.', 'wrong_session');
  verifyBytes(signedRecord.envelope, DISCOVERY_DOMAINS.signal, raw, browser.publicKey); return payload;
}
function challengeBytes(challenge, record, now, clockSkew = 0) {
  exactFields(challenge, ['nonce', 'origin', 'expiresAt']);
  check(integer(now) && nodeId(challenge.nonce) && integer(challenge.expiresAt, 1) && challenge.expiresAt > now - clockSkew &&
    challenge.expiresAt <= now + DISCOVERY_LIMITS.challengeTTL + clockSkew, 'Invalid or expired rendezvous challenge.', 'stale_challenge');
  safeGatewayOrigin(challenge.origin);
  return encoder.encode(JSON.stringify({ nonce: challenge.nonce, origin: challenge.origin, expiresAt: challenge.expiresAt, recordDigest: hex(keccak_256(record.raw)) }));
}
export function signChallenge(challenge, recordEnvelope, identity, now = Date.now()) {
  const parsed = parseEnvelope(recordEnvelope), record = verifyBrowserRecord(recordEnvelope, parsed.payload.network, now);
  check(record.peerId === identity.peerId && record.publicKey === identity.publicKeyHex && record.rendezvous.includes(challenge.origin), 'Challenge is not bound to this browser or rendezvous.', 'wrong_session');
  // The browser clock can differ from the issuing gateway. The challenge has
  // no issuedAt, so only the gateway can enforce its exact five-second lease.
  // Tolerate the existing bounded discovery skew here; verification stays strict.
  return signBytes(DISCOVERY_DOMAINS.challenge, challengeBytes(challenge, record, now, DISCOVERY_LIMITS.clockSkew), identity);
}
export function verifyChallenge(challenge, recordEnvelope, signatureHex, network, now = Date.now()) {
  const record = verifyBrowserRecord(recordEnvelope, network, now);
  check(record.rendezvous.includes(challenge.origin), 'Challenge origin is absent from the signed browser record.', 'unsafe_origin');
  check(typeof signatureHex === 'string' && /^[0-9a-f]{128}0[01]$/u.test(signatureHex), 'Invalid challenge signature encoding.', 'invalid_signature');
  verifyBytes({ signatureHex }, DISCOVERY_DOMAINS.challenge, challengeBytes(challenge, record, now), record.publicKey); return record;
}
