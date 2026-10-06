import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { LIMITS, MANIFEST_DOMAIN, HEADER_DOMAIN, strictJSON, validateNetwork, validateManifest, verifyManifest,
  headerDigest, validatePacket, decodeBase64, encodeBase64, validateMessage, encodeMessage, TokenBucket } from "../public/relay-protocol.js";
// Portable copy of node/browserrelay/testdata/protocol-vectors.json, generated independently
// by Node WebCrypto and verified by native Go. Public scalar-1 TEST key; never an operational key.
const vector = {
  "description": "Non-production independent Node WebCrypto vector; private scalar is public test value 1. Header bytes test digest only, not header validity.",
  "publicJwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
    "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
    "ext": true,
    "key_ops": [
      "verify"
    ]
  },
  "header": {
    "network": {
      "chainId": 1,
      "genesisHash": "0x2222222222222222222222222222222222222222222222222222222222222222"
    },
    "height": 1,
    "rawHex": "c0",
    "digest": "192a7ac674b698ad897c3707804a314d646d645744c2662103d88aa11a9c9b52"
  },
  "envelope": {
    "keyId": "test_key",
    "manifestBase64": "eyJ2ZXJzaW9uIjoxLCJuZXR3b3JrIjp7ImNoYWluSWQiOjEsImdlbmVzaXNIYXNoIjoiMHgyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyIn0sInNvdXJjZUlkIjoidGVzdF9zb3VyY2UiLCJzb3VyY2VCb290SWQiOiIzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMyIsInNlcXVlbmNlIjoiMSIsIm9ic2VydmVkQXQiOjE3MDAwMDAwMDAwMDAsImV4cGlyZXNBdCI6MTcwMDAwMDAzMDAwMCwiaGVhZEhlaWdodCI6MSwiaGVhZEhhc2giOiIweDExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEiLCJlbnRyaWVzIjpbeyJoZWlnaHQiOjEsImJsb2NrSGFzaCI6IjB4MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMSIsInBhcmVudEhhc2giOiIweDIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIiLCJkaWdlc3QiOiIxOTJhN2FjNjc0YjY5OGFkODk3YzM3MDc4MDRhMzE0ZDY0NmQ2NDU3NDRjMjY2MjEwM2Q4OGFhMTFhOWM5YjUyIiwicmF3Qnl0ZXMiOjF9XX0=",
    "signatureBase64": "rc9HcY0iYzZZmj/+JT3GT8ZXiz00cZOCl2iRc+mUe0mzQ9YGCItgbkhL1ZWaEkWpFJunNF/RaEXlH7k/CmffOw=="
  },
  "manifestId": "35a5daef46ffa75954a5c28bc0802d90fc19f74cad8a8a8f11c1952b40b8ccda"
}
;
const now = 1700000000000, text = new TextEncoder();
const base = JSON.parse(Buffer.from(vector.envelope.manifestBase64, "base64"));
const trust = { network: vector.header.network, sources: [{ sourceId: "test_source", keyId: "test_key", jwk: vector.publicJwk }] };
const clone = object => structuredClone(object);
const failure = code => error => error?.code === code;
const signedFixture = async () => {
  const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const ownTrust = { network: clone(trust.network), sources: [{ sourceId: "test_source", keyId: "test_key", jwk: await crypto.subtle.exportKey("jwk", keys.publicKey) }] };
  const sign = async (manifest, rawOverride, domain = MANIFEST_DOMAIN) => {
    const raw = text.encode(rawOverride ?? JSON.stringify(manifest));
    const bytes = Buffer.concat([Buffer.from(domain), Buffer.from(raw)]);
    const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, bytes));
    return JSON.stringify({ keyId: "test_key", manifestBase64: encodeBase64(raw), signatureBase64: encodeBase64(signature) });
  };
  return { sign, trust: ownTrust };
};

test("native HeaderDigest vector binds exact raw bytes, network and uint64 height", async () => {
  const raw = Uint8Array.from(Buffer.from(vector.header.rawHex, "hex"));
  assert.equal(await headerDigest(vector.header.network, 1, raw), vector.header.digest);
  for (const [network, height, changed] of [[vector.header.network, 1, Uint8Array.of(0xc1, 0x80)],
    [vector.header.network, 2, raw], [{ ...vector.header.network, chainId: 2 }, 1, raw],
    [{ ...vector.header.network, genesisHash: "0x" + "33".repeat(32) }, 1, raw]]) {
    const chain = Buffer.alloc(8), number = Buffer.alloc(8); chain.writeBigUInt64BE(BigInt(network.chainId)); number.writeBigUInt64BE(BigInt(height));
    const expected = createHash("sha256").update(Buffer.concat([Buffer.from(HEADER_DOMAIN), chain,
      Buffer.from(network.genesisHash.slice(2), "hex"), number, changed])).digest("hex");
    assert.equal(await headerDigest(network, height, changed), expected); assert.notEqual(expected, vector.header.digest);
  }
  await assert.rejects(headerDigest(vector.header.network, 0, raw));
  await assert.rejects(headerDigest(vector.header.network, 1, new Uint8Array(8193)), failure("unsupported_header_size"));
});

test("native P-256 vector authenticates exact manifest bytes and domain", async () => {
  const result = await verifyManifest(JSON.stringify(vector.envelope), trust, null, now);
  assert.equal(result.id, vector.manifestId); assert.deepEqual(result.manifest, base);
  assert.equal(Buffer.from(result.rawBytes).toString(), Buffer.from(vector.envelope.manifestBase64, "base64").toString());
  const tampered = { ...vector.envelope, manifestBase64: Buffer.from(JSON.stringify(base, null, 2)).toString("base64") };
  await assert.rejects(verifyManifest(JSON.stringify(tampered), trust, null, now), failure("invalid_signature"));
  const fixture = await signedFixture();
  await assert.rejects(verifyManifest(await fixture.sign(base, undefined, "wrong-domain\0"), fixture.trust, null, now), failure("invalid_signature"));
});

test("strict JSON rejects duplicate decoded keys, malformed UTF-8, fractions and unsafe integers", () => {
  for (const invalid of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"outer":{"x":1,"x":2}}',
    '{"v":-0}', '{"v":1.0}', '{"v":1e0}', '{"v":9007199254740992}', '{"v":01}',
    '{"v":"\\ud800"}', '{}{}', 'true false', '{"a":1,}', '[1,]']) assert.throws(() => strictJSON(invalid), failure("invalid_json"), invalid);
  assert.throws(() => strictJSON(Uint8Array.of(0xc0, 0xaf)), failure("invalid_json"));
  assert.throws(() => strictJSON("[".repeat(18) + "0" + "]".repeat(18)), failure("invalid_json"));
  const safe = strictJSON('{"__proto__":{"polluted":true},"unicode":"日本語"}');
  assert.equal({}.polluted, undefined); assert.equal(safe.unicode, "日本語"); assert.ok(Object.hasOwn(safe, "__proto__"));
});

test("signed but ambiguous, missing, and unknown manifest fields remain invalid", async () => {
  const f = await signedFixture();
  for (const value of [{ ...base, unknown: true }, { ...base, entries: [{ ...base.entries[0], unknown: 1 }] },
    { ...base, network: { ...base.network, alias: true } }]) await assert.rejects(verifyManifest(await f.sign(value), f.trust, null, now));
  const missing = clone(base); delete missing.sourceBootId;
  await assert.rejects(verifyManifest(await f.sign(missing), f.trust, null, now));
  const ambiguous = JSON.stringify(base).replace('"version":1', '"version":1,"\\u0076ersion":1');
  await assert.rejects(verifyManifest(await f.sign(base, ambiguous), f.trust, null, now), failure("invalid_json"));
  await assert.rejects(verifyManifest(JSON.stringify({ ...vector.envelope, unknown: 1 }), trust, null, now));
});

test("source, key and both network fields must match provisioned trust pins", async () => {
  for (const network of [{ ...trust.network, chainId: 2 }, { ...trust.network, genesisHash: "0x" + "44".repeat(32) }])
    await assert.rejects(verifyManifest(JSON.stringify(vector.envelope), { ...trust, network }, null, now), failure("wrong_network"));
  for (const source of [{ ...trust.sources[0], sourceId: "other" }, { ...trust.sources[0], keyId: "other" },
    { ...trust.sources[0], jwk: { ...vector.publicJwk, d: "private-material-is-not-trust" } }])
    await assert.rejects(verifyManifest(JSON.stringify(vector.envelope), { ...trust, sources: [source] }, null, now), failure("untrusted_source"));
  const f = await signedFixture();
  await assert.rejects(verifyManifest(JSON.stringify(vector.envelope), f.trust, null, now), failure("invalid_signature"));
  assert.throws(() => validateNetwork({ ...trust.network, chainId: 0 }), failure("wrong_network"));
});

test("expiry and clock boundaries reject stale or future source observations", async () => {
  const wire = JSON.stringify(vector.envelope);
  await verifyManifest(wire, trust, null, now + 29999);
  await assert.rejects(verifyManifest(wire, trust, null, now + 30000), failure("stale_manifest"));
  await verifyManifest(wire, trust, null, now - 5000);
  await assert.rejects(verifyManifest(wire, trust, null, now - 5001), failure("clock_skew"));
  assert.throws(() => validateManifest({ ...base, expiresAt: now + 30001 }));
  assert.throws(() => validateManifest({ ...base, expiresAt: now }));
});

test("uint64 sequences remain exact above 2^53 and reject rollback or equivocation", async () => {
  const f = await signedFixture(); const a = { ...base, sequence: "9007199254740992" };
  const first = await verifyManifest(await f.sign(a), f.trust, null, now);
  const second = await verifyManifest(await f.sign({ ...a, sequence: "9007199254740993" }), f.trust, first, now);
  assert.equal(second.manifest.sequence, "9007199254740993");
  await assert.rejects(verifyManifest(await f.sign(a), f.trust, second, now), failure("manifest_rollback"));
  await assert.rejects(verifyManifest(await f.sign({ ...a, expiresAt: now + 29000 }), f.trust, first, now), failure("manifest_equivocation"));
  const repeated = await verifyManifest(await f.sign(a), f.trust, first, now); assert.equal(repeated.id, first.id);
  validateManifest({ ...base, sequence: "18446744073709551615" });
  for (const sequence of ["18446744073709551616", "01", "-1", "1e3", 1]) assert.throws(() => validateManifest({ ...base, sequence }));
});

test("new source boot resets sequence but cannot roll observed time backwards; reorg is allowed", async () => {
  const f = await signedFixture(); const first = await verifyManifest(await f.sign({ ...base, sequence: "99" }), f.trust, null, now);
  const restart = { ...base, sequence: "0", sourceBootId: "55".repeat(16), observedAt: now + 1, expiresAt: now + 30001 };
  const next = await verifyManifest(await f.sign(restart), f.trust, first, now + 1); assert.equal(next.bootChanged, true);
  await assert.rejects(verifyManifest(await f.sign({ ...restart, observedAt: now - 1, expiresAt: now + 29999 }), f.trust, first, now), failure("manifest_rollback"));
  const reorg = clone(base); reorg.sequence = "100"; reorg.headHash = "0x" + "66".repeat(32); reorg.entries[0].blockHash = reorg.headHash;
  reorg.entries[0].digest = "77".repeat(32);
  assert.equal((await verifyManifest(await f.sign(reorg), f.trust, first, now)).manifest.headHash, reorg.headHash);
});

test("manifest window validates contiguous parents, unique digests, complete size and full byte length", () => {
  const m = clone(base); m.headHeight = 2; m.headHash = "0x" + "44".repeat(32);
  m.entries.push({ ...base.entries[0], height: 2, parentHash: base.headHash, blockHash: m.headHash, digest: "55".repeat(32) });
  validateManifest(m);
  for (const change of [x => x.entries.pop(), x => x.entries[1].parentHash = x.network.genesisHash,
    x => x.entries[1].digest = x.entries[0].digest, x => x.entries[0].rawBytes = 8193,
    x => x.entries[0].height = 0, x => x.headHash = x.network.genesisHash]) { const broken = clone(m); change(broken); assert.throws(() => validateManifest(broken)); }
  validateManifest({ ...base, headHeight: 0, headHash: base.network.genesisHash, entries: [] });
});

test("canonical base64 and packet size caps reject alias encodings and oversized complete headers", () => {
  assert.deepEqual(decodeBase64("wA=="), Uint8Array.of(0xc0));
  for (const value of ["wB==", "wA", "wA==\n", "wA__", " wA==", "wA==="]) assert.throws(() => decodeBase64(value));
  const raw = new Uint8Array(8192).fill(255); assert.deepEqual(decodeBase64(encodeBase64(raw)), raw);
  assert.throws(() => decodeBase64(encodeBase64(new Uint8Array(8193))));
  const packet = { version: 1, network: vector.header.network, height: 1, headerRLP: "wA==", digest: vector.header.digest };
  assert.deepEqual(validatePacket(JSON.stringify(packet)), packet);
  for (const broken of [{ ...packet, headerRLP: "" }, { ...packet, height: 0 }, { ...packet, extra: 1 },
    { ...packet, digest: packet.digest.toUpperCase() }]) assert.throws(() => validatePacket(broken));
  assert.throws(() => strictJSON(" ".repeat(LIMITS.maxDataBytes + 1)), failure("oversize"));
  assert.throws(() => strictJSON('"' + "あ".repeat(6000) + '"'), failure("oversize"));
});

test("ACK wire schema binds request, both peers/sessions, digest and byte count", () => {
  const ack = { type: "ACK", v: 1, requestId: "11".repeat(16), fromPeerId: "B", fromSessionId: "session-B",
    toPeerId: "A", toSessionId: "session-A", digest: vector.header.digest, rawBytes: 8192, status: "accepted" };
  assert.deepEqual(validateMessage(encodeMessage(ack)), ack);
  assert.equal(validateMessage({ ...ack, status: "duplicate" }).status, "duplicate");
  for (const field of ["requestId", "fromPeerId", "fromSessionId", "toPeerId", "toSessionId", "digest", "rawBytes", "status"]) {
    const missing = { ...ack }; delete missing[field]; assert.throws(() => validateMessage(missing));
  }
  for (const broken of [{ ...ack, rawBytes: 0 }, { ...ack, rawBytes: 8193 }, { ...ack, status: "sent" },
    { ...ack, requestId: "1" }, { ...ack, fromSessionId: "" }, { ...ack, extra: true }]) assert.throws(() => validateMessage(broken));
  // Per-session request matching and duplicate accounting are tested in relay-worker.test.mjs.
});

test("inventory and control frames enforce finite inventories, versions and wire budgets", () => {
  const inv = { type: "INV", v: 1, sourceId: "test_source", manifestId: vector.manifestId, digests: [vector.header.digest] };
  validateMessage(inv);
  assert.throws(() => validateMessage({ ...inv, digests: [vector.header.digest, vector.header.digest] }));
  assert.throws(() => validateMessage({ ...inv, digests: Array.from({ length: 33 }, (_, i) => i.toString(16).padStart(64, "0")) }));
  assert.throws(() => validateMessage({ ...inv, v: 2 }));
  assert.throws(() => validateMessage(" ".repeat(4096) + JSON.stringify(inv)), failure("oversize"));
  assert.throws(() => validateMessage({ type: "NACK", v: 1, requestId: "11".repeat(16), digest: vector.header.digest, reason: "arbitrary error body" }));
});

test("token bucket bounds bursts, uses elapsed time, resists backwards clock and clamps reduced budgets", () => {
  const b = new TokenBucket(1024, 16384, 0);
  assert.equal(b.take(16384, 0), true); assert.equal(b.take(1, 0), false);
  assert.equal(b.take(1024, 1000), true); assert.equal(b.take(1, 500), false);
  assert.equal(b.take(512, 1500), true); assert.equal(b.take(1, 1500), false);
  b.refill(1e9); assert.equal(b.tokens, 16384);
  b.set(512, 8192, 1e9); assert.equal(b.tokens, 8192);
  assert.equal(b.take(8192, 1e9), true); assert.equal(b.take(512, 1e9 + 1000), true);
  assert.equal(b.take(1, 1e9 + 1000), false);
});

test('unsigned metadata decimal mode retains duplicate-key, UTF-8, depth and finite-number protection', () => {
  const parse = text => strictJSON(text, 8192, { allowDecimals: true });
  assert.deepEqual(parse('{"geo":{"lat":35.68,"lon":139.75}}'), { geo: { lat: 35.68, lon: 139.75 } });
  assert.throws(() => strictJSON('{"lat":35.68}', 8192));
  for (const wire of ['{"x":1,"\\u0078":2}', '{"x":1e999}', '{"x":9007199254740992}', '{"x":-0.0}', '{"x":01.0}', '['.repeat(18) + '0' + ']'.repeat(18)]) assert.throws(() => parse(wire));
  assert.throws(() => strictJSON(Uint8Array.from([123,34,120,34,58,34,255,34,125]), 8192, { allowDecimals: true }));
});
