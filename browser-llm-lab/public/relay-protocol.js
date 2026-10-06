// Public header distribution authenticates a pinned source observation, not consensus finality.
export const LIMITS = Object.freeze({ maxHeaderBytes: 8192, maxHeaders: 32, maxManifestBytes: 16384,
  maxEnvelopeBytes: 24576, maxDataBytes: 16384, maxControlBytes: 4096, maxPeers: 3,
  cacheBytes: 256 * 1024, appBytes: 4 * 1024 * 1024, transferBytes: 100 * 1024 * 1024,
  metadataRate: 3072, metadataBurst: 24576, controlRate: 1024, controlBurst: 4096 });
export const MANIFEST_DOMAIN = "cypher-browser-header-manifest-v1\0";
export const HEADER_DOMAIN = "cypher-common-lightnode-header-overlay-v1\0";
const encoder = new TextEncoder(), decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
export function protocolError(code, message) { return Object.assign(new Error(message), { code }); }
function check(value, message, code = "invalid_message") { if (!value) throw protocolError(code, message); }
export const byteLength = value => typeof value === "string" ? encoder.encode(value).length : value.byteLength;
export function asBytes(input, limit) {
  check(typeof input === "string" || input instanceof ArrayBuffer || ArrayBuffer.isView(input), "Expected UTF-8 wire bytes.");
  check((typeof input === "string" ? input.length : input.byteLength) <= limit, "Wire byte limit exceeded.", "oversize");
  const bytes = typeof input === "string" ? encoder.encode(input) : input instanceof ArrayBuffer ? new Uint8Array(input)
    : new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  check(bytes.byteLength <= limit, "Wire byte limit exceeded.", "oversize");
  return bytes;
}

// A recursive JSON reader rejects duplicate decoded keys before object construction.
// Protocol numbers are canonical safe integers; sequence is a decimal uint64 string.
export function strictJSON(input, maxBytes = LIMITS.maxDataBytes, { allowDecimals = false } = {}) {
  const bytes = asBytes(input, maxBytes);
  let text;
  try { text = decoder.decode(bytes); } catch { throw protocolError("invalid_json", "Invalid UTF-8."); }
  let at = 0, count = 0;
  const bad = () => { throw protocolError("invalid_json", "Invalid, ambiguous, or excessive JSON."); };
  const space = () => { while (/[\x20\x09\x0a\x0d]/u.test(text[at] || "!")) at++; };
  function string() {
    if (text[at++] !== '"') bad();
    const start = at - 1;
    while (at < text.length) {
      const char = text[at++];
      if (char === '"') {
        let value;
        try { value = JSON.parse(text.slice(start, at)); } catch { bad(); }
        for (const scalar of value) { const point = scalar.codePointAt(0); if (point >= 0xd800 && point <= 0xdfff) bad(); }
        return value;
      }
      if (char === "\\") at++;
      else if (char.charCodeAt(0) < 32) bad();
    }
    bad();
  }
  function value(depth) {
    if (depth > 16 || ++count > 4096) bad();
    space(); const char = text[at];
    if (char === '"') return string();
    if (char === "{") {
      at++; space(); const result = {}, seen = new Set();
      if (text[at] === "}") { at++; return result; }
      while (at < text.length) {
        space(); const key = string(); if (seen.has(key)) bad(); seen.add(key);
        space(); if (text[at++] !== ":") bad();
        const child = value(depth + 1);
        Object.defineProperty(result, key, { value: child, enumerable: true, configurable: true, writable: true });
        space(); const next = text[at++]; if (next === "}") return result; if (next !== ",") bad();
      }
      bad();
    }
    if (char === "[") {
      at++; space(); const result = [];
      if (text[at] === "]") { at++; return result; }
      while (at < text.length) {
        result.push(value(depth + 1)); space(); const next = text[at++];
        if (next === "]") return result; if (next !== ",") bad();
      }
      bad();
    }
    for (const [wire, literal] of [["true", true], ["false", false], ["null", null]]) {
      if (text.startsWith(wire, at)) { at += wire.length; return literal; }
    }
    // Unsigned display metadata may contain country coordinates. Signed
    // payloads and protocol frames keep the default canonical integer reader.
    const match = (allowDecimals ? /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u : /^-?(?:0|[1-9][0-9]*)/u).exec(text.slice(at));
    if (!match || match[0] === "-0") bad();
    at += match[0].length; const number = Number(match[0]);
    if (allowDecimals ? !Number.isFinite(number) || Math.abs(number) > Number.MAX_SAFE_INTEGER || Object.is(number, -0) : !Number.isSafeInteger(number)) bad();
    return number;
  }
  const result = value(0); space(); if (at !== text.length) bad(); return result;
}
export function exactFields(value, names) {
  check(value && typeof value === "object" && !Array.isArray(value), "Expected object.");
  const keys = Object.keys(value);
  check(keys.length === names.length && keys.every(key => names.includes(key)), "Missing or unknown field.");
}
export const validId = value => typeof value === "string" && /^[A-Za-z0-9_-]{1,96}$/u.test(value);
export const validDigest = value => typeof value === "string" && /^[0-9a-f]{64}$/u.test(value);
const hash = value => typeof value === "string" && /^0x[0-9a-f]{64}$/u.test(value) && !/^0x0{64}$/u.test(value);
const integer = (value, min = 0, max = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(value) && value >= min && value <= max;
export function validateNetwork(network) {
  exactFields(network, ["chainId", "genesisHash"]);
  check(integer(network.chainId, 1) && hash(network.genesisHash), "Invalid pinned network.", "wrong_network");
  return network;
}
export const sameNetwork = (a, b) => a?.chainId === b?.chainId && a?.genesisHash === b?.genesisHash;
export function decodeBase64(value, maxBytes = LIMITS.maxHeaderBytes) {
  check(typeof value === "string" && value.length <= Math.ceil(maxBytes / 3) * 4 &&
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value), "Invalid base64.");
  let raw;
  try { raw = atob(value); } catch { throw protocolError("invalid_message", "Invalid base64."); }
  check(raw.length <= maxBytes && btoa(raw) === value, "Noncanonical or excessive base64.");
  return Uint8Array.from(raw, char => char.charCodeAt(0));
}
export function encodeBase64(bytes) {
  let text = ""; for (let offset = 0; offset < bytes.length; offset += 4096)
    text += String.fromCharCode(...bytes.subarray(offset, offset + 4096));
  return btoa(text);
}
const hexBytes = text => Uint8Array.from(text.match(/../gu), pair => parseInt(pair, 16));
const hex = raw => [...new Uint8Array(raw)].map(value => value.toString(16).padStart(2, "0")).join("");
const concat = (...parts) => { const result = new Uint8Array(parts.reduce((n, part) => n + part.length, 0)); let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; } return result; };
export async function headerDigest(network, height, raw) {
  validateNetwork(network); check(integer(height, 1), "Invalid header height.");
  check(raw instanceof Uint8Array && raw.length >= 1 && raw.length <= LIMITS.maxHeaderBytes, "Unsupported header size.", "unsupported_header_size");
  const chain = new Uint8Array(8), number = new Uint8Array(8);
  new DataView(chain.buffer).setBigUint64(0, BigInt(network.chainId));
  new DataView(number.buffer).setBigUint64(0, BigInt(height));
  return hex(await crypto.subtle.digest("SHA-256", concat(encoder.encode(HEADER_DOMAIN), chain, hexBytes(network.genesisHash.slice(2)), number, raw)));
}
export function validatePacket(input) {
  const packet = typeof input === "string" || input instanceof ArrayBuffer || ArrayBuffer.isView(input) ? strictJSON(input) : input;
  exactFields(packet, ["version", "network", "height", "headerRLP", "digest"]);
  validateNetwork(packet.network);
  check(packet.version === 1 && integer(packet.height, 1) && validDigest(packet.digest), "Invalid packet.");
  check(decodeBase64(packet.headerRLP).length >= 1, "Empty header.");
  return packet;
}
export function validateManifest(manifest) {
  exactFields(manifest, ["version", "network", "sourceId", "sourceBootId", "sequence", "observedAt", "expiresAt", "headHeight", "headHash", "entries"]);
  validateNetwork(manifest.network);
  check(manifest.version === 1 && validId(manifest.sourceId) && manifest.sourceId.length <= 64 &&
    typeof manifest.sourceBootId === "string" && /^[0-9a-f]{32}$/u.test(manifest.sourceBootId), "Invalid manifest identity.");
  check(typeof manifest.sequence === "string" && /^(0|[1-9][0-9]{0,19})$/u.test(manifest.sequence) &&
    BigInt(manifest.sequence) <= 18446744073709551615n, "Invalid manifest sequence.");
  check(integer(manifest.observedAt) && integer(manifest.expiresAt, 1) && manifest.expiresAt > manifest.observedAt &&
    manifest.expiresAt - manifest.observedAt <= 30000, "Invalid manifest lifetime.");
  check(integer(manifest.headHeight) && hash(manifest.headHash) && Array.isArray(manifest.entries) &&
    manifest.entries.length === Math.min(32, manifest.headHeight), "Incomplete recent window.");
  if (!manifest.headHeight) { check(manifest.headHash === manifest.network.genesisHash, "Invalid genesis head."); return manifest; }
  const seen = new Set(), first = manifest.headHeight - manifest.entries.length + 1;
  manifest.entries.forEach((entry, index) => {
    exactFields(entry, ["height", "blockHash", "parentHash", "digest", "rawBytes"]);
    check(entry.height === first + index && hash(entry.blockHash) && hash(entry.parentHash) && validDigest(entry.digest) &&
      integer(entry.rawBytes, 1, LIMITS.maxHeaderBytes) && !seen.has(entry.digest), "Invalid manifest entry.");
    check((entry.height !== 1 || entry.parentHash === manifest.network.genesisHash) &&
      (index === 0 || entry.parentHash === manifest.entries[index - 1].blockHash), "Manifest parent discontinuity.");
    seen.add(entry.digest);
  });
  check(manifest.entries.at(-1).blockHash === manifest.headHash, "Manifest head mismatch.");
  return manifest;
}
export async function verifyManifest(input, trust, previous = null, now = Date.now()) {
  const wire = asBytes(input, LIMITS.maxEnvelopeBytes), envelope = strictJSON(wire, LIMITS.maxEnvelopeBytes);
  exactFields(envelope, ["keyId", "manifestBase64", "signatureBase64"]);
  check(validId(envelope.keyId) && envelope.keyId.length <= 64, "Invalid key ID.");
  const raw = decodeBase64(envelope.manifestBase64, LIMITS.maxManifestBytes), signature = decodeBase64(envelope.signatureBase64, 64);
  check(signature.length === 64, "P-256 signature must use 64-byte r||s.", "invalid_signature");
  const manifest = validateManifest(strictJSON(raw, LIMITS.maxManifestBytes));
  validateNetwork(trust.network);
  check(sameNetwork(manifest.network, trust.network), "Manifest network differs from operator pins.", "wrong_network");
  check(Array.isArray(trust.sources) && trust.sources.length >= 1 && trust.sources.length <= 2, "Invalid pinned source set.", "untrusted_source");
  const source = trust.sources.find(row => row.sourceId === manifest.sourceId && row.keyId === envelope.keyId);
  check(source && source.jwk && source.jwk.kty === "EC" && source.jwk.crv === "P-256" && !Object.hasOwn(source.jwk, "d"), "Untrusted manifest source/key.", "untrusted_source");
  let key;
  try { key = await crypto.subtle.importKey("jwk", source.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]); }
  catch { throw protocolError("untrusted_source", "Invalid pinned public key."); }
  const signed = concat(encoder.encode(MANIFEST_DOMAIN), raw);
  check(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, signed), "Manifest signature rejected.", "invalid_signature");
  check(integer(now) && manifest.observedAt <= now + 5000, "Device clock or source observation is ahead of the allowed clock window.", "clock_skew");
  check(manifest.expiresAt > now, "Source observation has expired.", "stale_manifest");
  const id = hex(await crypto.subtle.digest("SHA-256", signed));
  let bootChanged = false;
  if (previous) {
    check(previous.manifest.sourceId === manifest.sourceId, "Sequence state belongs to another source.");
    bootChanged = previous.manifest.sourceBootId !== manifest.sourceBootId;
    check(manifest.observedAt >= previous.manifest.observedAt, "Source observation moved backwards.", "manifest_rollback");
    if (!bootChanged) {
      check(BigInt(manifest.sequence) >= BigInt(previous.manifest.sequence), "Source sequence moved backwards.", "manifest_rollback");
      check(manifest.sequence !== previous.manifest.sequence || id === previous.id, "Source equivocated at the same sequence.", "manifest_equivocation");
    }
  }
  return { manifest, id, keyId: envelope.keyId, rawBytes: raw, wireBytes: wire.byteLength, bootChanged };
}

const COMMON = ["type", "v"];
const SCHEMAS = {
  HELLO: [...COMMON, "network", "peerId", "sessionId"],
  INV: [...COMMON, "sourceId", "manifestId", "digests"],
  WANT: [...COMMON, "requestId", "digest", "sourceId", "deadline"],
  DATA: [...COMMON, "requestId", "sessionId", "sourceId", "manifestId", "packet"],
  ACK: [...COMMON, "requestId", "fromPeerId", "fromSessionId", "toPeerId", "toSessionId", "digest", "rawBytes", "status"],
  NACK: [...COMMON, "requestId", "digest", "reason"],
  PING: [...COMMON, "nonce"], PONG: [...COMMON, "nonce"], LEAVE: [...COMMON, "reason"],
};
export const NACK_REASONS = Object.freeze(["invalid", "expired", "busy", "outside_window", "unknown_digest", "unsolicited", "budget", "timeout"]);
export function validateMessage(input) {
  const message = typeof input === "string" || input instanceof ArrayBuffer || ArrayBuffer.isView(input) ? strictJSON(input) : input;
  check(message && SCHEMAS[message.type], "Unknown relay message."); exactFields(message, SCHEMAS[message.type]);
  check(message.v === 1, "Unsupported relay version.");
  if (message.type === "HELLO") { validateNetwork(message.network); check(validId(message.peerId) && validId(message.sessionId), "Invalid HELLO identity."); }
  if (message.sourceId !== undefined) check(validId(message.sourceId) && message.sourceId.length <= 64, "Invalid source ID.");
  if (message.manifestId !== undefined) check(validDigest(message.manifestId), "Invalid manifest ID.");
  if (message.requestId !== undefined) check(typeof message.requestId === "string" && /^[0-9a-f]{32}$/u.test(message.requestId), "Invalid request ID.");
  if (message.digest !== undefined) check(validDigest(message.digest), "Invalid digest.");
  if (message.type === "INV") check(Array.isArray(message.digests) && message.digests.length <= 32 &&
    message.digests.every(validDigest) && new Set(message.digests).size === message.digests.length, "Invalid inventory.");
  if (message.type === "WANT") check(integer(message.deadline, 1), "Invalid request deadline.");
  if (message.type === "DATA") { check(validId(message.sessionId), "Invalid DATA session."); validatePacket(message.packet); }
  if (message.type === "ACK") check([message.fromPeerId, message.fromSessionId, message.toPeerId, message.toSessionId].every(validId) &&
    integer(message.rawBytes, 1, 8192) && ["accepted", "duplicate"].includes(message.status), "Invalid receipt.");
  if (message.type === "NACK") check(NACK_REASONS.includes(message.reason), "Invalid rejection reason.");
  if (["PING", "PONG"].includes(message.type)) check(typeof message.nonce === "string" && /^[0-9a-f]{16}$/u.test(message.nonce), "Invalid heartbeat.");
  if (message.type === "LEAVE") check(["off", "hidden", "limit", "error"].includes(message.reason), "Invalid leave reason.");
  const length = typeof input === "string" || input instanceof ArrayBuffer || ArrayBuffer.isView(input) ? byteLength(input) : byteLength(JSON.stringify(message));
  check(length <= (message.type === "DATA" ? LIMITS.maxDataBytes : LIMITS.maxControlBytes), "Relay frame exceeds its byte limit.", "oversize");
  return message;
}
export function encodeMessage(message) { validateMessage(message); return JSON.stringify(message); }
export class TokenBucket {
  constructor(rate, burst, now = 0) { this.rate = rate; this.burst = burst; this.tokens = burst; this.last = now; }
  refill(now) { this.tokens = Math.min(this.burst, this.tokens + Math.max(0, now - this.last) * this.rate / 1000); this.last = Math.max(this.last, now); }
  take(bytes, now) { this.refill(now); if (bytes > this.tokens) return false; this.tokens -= bytes; return true; }
  set(rate, burst, now) { this.refill(now); this.rate = rate; this.burst = burst; this.tokens = Math.min(this.tokens, burst); }
}
