import test from "node:test";
import assert from "node:assert/strict";
import { RelayEngine } from "../public/relay-worker.js";
import { MANIFEST_DOMAIN, LIMITS, encodeBase64, headerDigest, encodeMessage } from "../public/relay-protocol.js";
const encoder = new TextEncoder();
const network = { chainId: 10101919, genesisHash: "0x" + "22".repeat(32) };
const start = 1700000000000;
async function fixture(rawLength = 128) {
  const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
  const trust = { network, sources: [{ sourceId: "fixture-source", keyId: "fixture-key", jwk }] };
  async function publication({ sequence = "1", now = start, salt = 1, blockHash = "0x" + "33".repeat(32) } = {}) {
    const raw = new Uint8Array(rawLength).fill(salt), digest = await headerDigest(network, 1, raw);
    const packet = { version: 1, network, height: 1, digest, headerRLP: encodeBase64(raw) };
    const manifest = { version: 1, network, sourceId: "fixture-source", sourceBootId: "44".repeat(16), sequence,
      observedAt: now, expiresAt: now + 30000, headHeight: 1, headHash: blockHash,
      entries: [{ height: 1, blockHash, parentHash: network.genesisHash, digest, rawBytes: raw.length }] };
    const bytes = encoder.encode(JSON.stringify(manifest));
    const signed = new Uint8Array(encoder.encode(MANIFEST_DOMAIN).length + bytes.length);
    signed.set(encoder.encode(MANIFEST_DOMAIN)); signed.set(bytes, encoder.encode(MANIFEST_DOMAIN).length);
    const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, signed));
    const envelope = JSON.stringify({ keyId: "fixture-key", manifestBase64: encodeBase64(bytes), signatureBase64: encodeBase64(signature) });
    return { packet, manifest, envelope, raw };
  }
  return { trust, publication, initial: await publication() };
}
async function pair({ rawLength = 128, autoSeed = true, roles = ["seed", "peer"] } = {}) {
  const f = await fixture(rawLength), queue = [], messages = [], events = [], engines = new Map();
  let time = start;
  for (const [index, id] of ["A", "B"].entries()) {
    const engine = new RelayEngine({ now: () => time, post: message => { queue.push({ from: id, message }); events.push({ from: id, message }); } });
    engines.set(id, engine);
    await engine.accept({ type: "init", config: { ...f.trust, role: roles[index], allowFallback: false }, identity: { peerId: id, sessionId: `session-${id}` }, generation: id });
    await engine.accept({ type: "manifest", sourceId: "fixture-source", envelope: f.initial.envelope, https: true });
  }
  await engines.get("A").accept({ type: "peerOpen", peerId: "B", sessionId: "session-B", maxMessageSize: 16384, path: "direct" });
  await engines.get("B").accept({ type: "peerOpen", peerId: "A", sessionId: "session-A", maxMessageSize: 16384, path: "direct" });
  const drain = async ({ tamper, drop, confirm = true } = {}) => {
    let steps = 0;
    while (queue.length) {
      assert.ok(++steps < 1000, "Fixture message queue must settle");
      const { from, message } = queue.shift(), sender = engines.get(from);
      if (message.type === "send") {
        let wire = JSON.parse(message.text); messages.push({ from, peerId: message.peerId, wire });
        if (confirm) await sender.accept({ type: "sent", sendId: message.sendId, ok: true, bufferedAmount: 0 });
        if (drop?.(from, wire)) continue;
        wire = tamper?.(from, wire) || wire;
        await engines.get(message.peerId)?.accept({ type: "message", peerId: from, buffer: encoder.encode(JSON.stringify(wire)).buffer });
      } else if (message.type === "needHeaders" && autoSeed && from === "A") {
        assert.ok(message.digests.includes(f.initial.packet.digest));
        await sender.accept({ type: "account", bytes: encoder.encode(JSON.stringify(f.initial.packet)).length, direction: "in", kind: "https" });
        await sender.accept({ type: "seed", sourceId: "fixture-source", packet: JSON.stringify(f.initial.packet) });
      }
    }
  };
  const advance = async milliseconds => { time += milliseconds; for (const engine of engines.values()) await engine.accept({ type: "tick" }); };
  return { ...f, queue, engines, events, messages, drain, advance, now: () => time };
}

test("A verifies gateway bytes, B requests actual DATA, and only B's accepted ACK counts", async () => {
  const p = await pair(); await p.drain();
  const a = p.engines.get("A"), b = p.engines.get("B");
  assert.equal(a.cache.size, 1); assert.equal(b.cache.size, 1);
  const received = [...b.cache.values()][0];
  assert.equal(received.receivedFrom, "A"); assert.deepEqual(received.raw, p.initial.raw);
  assert.equal(b.stats.gatewayBytes, 0); assert.equal(a.stats.acknowledgedCount, 1);
  assert.equal(a.stats.acknowledgedBytes, p.initial.raw.length);
  assert.ok(p.messages.some(row => row.from === "B" && row.wire.type === "WANT"));
  assert.ok(p.messages.some(row => row.from === "A" && row.wire.type === "DATA"));
  assert.ok(p.messages.some(row => row.from === "B" && row.wire.type === "ACK"));
  assert.equal(a.receipts[0].path, "direct");
  assert.ok(!p.events.some(row => row.message.fatal));
});

test("a send without remote receipt never increases acknowledged bytes", async () => {
  const p = await pair(); await p.drain({ drop: (_from, wire) => wire.type === "ACK" });
  assert.equal(p.engines.get("B").cache.size, 1);
  assert.equal(p.engines.get("A").stats.acknowledgedCount, 0);
  assert.ok(p.engines.get("A").stats.sentBytes > 0);
});

test("a repeated actual DATA send counts retry bytes even if the first ACK was lost", async () => {
  const p = await pair(); await p.drain({ drop: (_from, wire) => wire.type === "ACK" });
  const a = p.engines.get("A");
  assert.equal(a.stats.retryBytes, 0);
  await a.accept({ type: "message", peerId: "B", buffer: encoder.encode(encodeMessage({ type: "WANT", v: 1,
    requestId: "bb".repeat(16), sourceId: "fixture-source", digest: p.initial.packet.digest, deadline: p.now() + 10000 })).buffer });
  await p.drain({ drop: (_from, wire) => wire.type === "DATA" });
  assert.ok(a.stats.retryBytes > 0);
  assert.equal(a.stats.acknowledgedCount, 0);
});

test("invalid initialization reports its requested generation to the controller", async () => {
  const output = [], engine = new RelayEngine({ post: message => output.push(message) });
  await engine.accept({ type: "init", config: {}, identity: {}, generation: "new-generation" });
  assert.equal(output.at(-1).type, "stopped");
  assert.equal(output.at(-1).generation, "new-generation");
  assert.equal(output.find(row => row.type === "event").fatal, true);
});

test("forged session receipts and replayed receipts never add successful transfers", async () => {
  const p = await pair(); let ack;
  await p.drain({ drop: (from, wire) => { if (from === "B" && wire.type === "ACK") { ack = wire; return true; } return false; } });
  const a = p.engines.get("A"); assert.ok(ack);
  await a.accept({ type: "message", peerId: "B", buffer: encoder.encode(JSON.stringify({ ...ack, fromSessionId: "old-session" })).buffer });
  assert.equal(a.stats.acknowledgedCount, 0);
  await a.accept({ type: "message", peerId: "B", buffer: encoder.encode(JSON.stringify(ack)).buffer });
  assert.equal(a.stats.acknowledgedCount, 1);
  await a.accept({ type: "message", peerId: "B", buffer: encoder.encode(JSON.stringify(ack)).buffer });
  assert.equal(a.stats.acknowledgedCount, 1);
});

test("altered RLP is rejected even with the expected request, height and digest", async () => {
  const p = await pair();
  await p.drain({ tamper: (_from, wire) => wire.type === "DATA" ? { ...wire,
    packet: { ...wire.packet, headerRLP: encodeBase64(new Uint8Array(128).fill(9)) } } : wire });
  assert.equal(p.engines.get("B").cache.size, 0);
  assert.equal(p.engines.get("A").stats.acknowledgedCount, 0);
  assert.ok(p.events.some(row => row.from === "B" && row.message.code === "invalid_digest"));
});

test("receiver accepts exact bytes from a different still-equivalent manifest ID", async () => {
  const p = await pair({ autoSeed: false });
  const refresh = await p.publication({ sequence: "2" });
  await p.engines.get("B").accept({ type: "manifest", sourceId: "fixture-source", envelope: refresh.envelope, https: true });
  await p.engines.get("A").accept({ type: "seed", sourceId: "fixture-source", packet: JSON.stringify(p.initial.packet) });
  await p.drain();
  assert.equal(p.engines.get("B").cache.size, 1);
  assert.equal(p.engines.get("A").stats.acknowledgedCount, 1);
});

test("same blockHash with changed SignInfo bytes evicts the old digest immediately", async () => {
  const p = await pair(); await p.drain();
  const changed = await p.publication({ sequence: "2", salt: 8 });
  assert.equal(changed.manifest.headHash, p.initial.manifest.headHash);
  assert.notEqual(changed.packet.digest, p.initial.packet.digest);
  const a = p.engines.get("A");
  await a.accept({ type: "manifest", sourceId: "fixture-source", envelope: changed.envelope, https: true });
  assert.equal(a.cache.size, 0);
  assert.equal(a.current("fixture-source", p.initial.packet.digest), null);
});

test("manifest expiry removes advertisements/cache and refuses old pending DATA", async () => {
  const p = await pair(); await p.drain();
  await p.advance(30001);
  assert.equal(p.engines.get("A").cache.size, 0); assert.equal(p.engines.get("B").cache.size, 0);
  assert.equal(p.engines.get("A").snapshot().sources[0].fresh, false);
});

test("AI loading stops new bulk requests and generation supports one full 8KiB header", async () => {
  const p = await pair({ rawLength: 8192, autoSeed: false });
  const a = p.engines.get("A"), b = p.engines.get("B");
  await b.accept({ type: "aiLoad", state: "loading" });
  await a.accept({ type: "seed", sourceId: "fixture-source", packet: JSON.stringify(p.initial.packet) });
  await p.drain();
  assert.equal(b.requests.size, 0); assert.equal(b.cache.size, 0);
  await a.accept({ type: "aiLoad", state: "generating" });
  await b.accept({ type: "aiLoad", state: "generating" });
  await p.drain();
  assert.equal(b.cacheBytes, 8192); assert.equal(a.stats.acknowledgedBytes, 8192);
  assert.ok(a.snapshot().appBytes < LIMITS.appBytes);
});

test("peer role waits eight seconds before requesting an explicit gateway fallback", async () => {
  const f = await fixture(), output = []; let now = start;
  const engine = new RelayEngine({ now: () => now, post: message => output.push(message) });
  await engine.accept({ type: "init", config: { ...f.trust, role: "peer", allowFallback: true }, identity: { peerId: "B", sessionId: "session-B" }, generation: "test" });
  await engine.accept({ type: "manifest", sourceId: "fixture-source", envelope: f.initial.envelope, https: true });
  assert.equal(output.filter(row => row.type === "needHeaders").length, 0);
  now += 7999; await engine.accept({ type: "tick" });
  assert.equal(output.filter(row => row.type === "needHeaders").length, 0);
  now++; await engine.accept({ type: "tick" });
  assert.equal(output.find(row => row.type === "needHeaders").reason, "fallback");
});

test("OFF discards queued work/cache and the ON transfer cap stops the worker", async () => {
  const p = await pair(); await p.drain(); const a = p.engines.get("A");
  await a.accept({ type: "account", bytes: LIMITS.transferBytes, direction: "in", kind: "signal" });
  assert.equal(a.active, false); assert.equal(a.cache.size, 0); assert.equal(a.peers.size, 0);
  assert.ok(p.events.some(row => row.from === "A" && row.message.type === "stopped" && row.message.reason === "limit"));
  await a.accept({ type: "tick" }); assert.equal(a.cache.size, 0);
  await p.engines.get("B").accept({ type: "stop", reason: "hidden" });
  assert.equal(p.engines.get("B").active, false);
});

test("controller send confirmation is required before accepting returned DATA", async () => {
  const p = await pair({ autoSeed: false });
  await p.drain();
  // Inject a well-formed DATA without any sent WANT. It must not enter RAM cache.
  const packet = { type: "DATA", v: 1, requestId: "aa".repeat(16), sessionId: "session-A", sourceId: "fixture-source",
    manifestId: p.engines.get("A").manifests.get("fixture-source").id, packet: p.initial.packet };
  await p.engines.get("B").accept({ type: "message", peerId: "A", buffer: encoder.encode(encodeMessage(packet)).buffer });
  assert.equal(p.engines.get("B").cache.size, 0);
  assert.ok(p.events.some(row => row.message.code === "unsolicited"));
});

test("small outbound controls wait for the per-peer ten-message sliding window", async () => {
  const f = await fixture(), output = []; let now = start, sent = 0;
  const engine = new RelayEngine({ now: () => now, post: message => output.push(message) });
  await engine.accept({ type: "init", config: { ...f.trust, role: "peer", allowFallback: false },
    identity: { peerId: "A", sessionId: "session-A" }, generation: "burst" });
  await engine.accept({ type: "peerOpen", peerId: "B", sessionId: "session-B", maxMessageSize: 16384 });
  const peer = engine.peers.get("B");
  for (let index = 0; index < 25; index++) engine.enqueue(peer, { type: "PING", v: 1, nonce: index.toString(16).padStart(16, "0") });
  const confirm = async () => {
    while (output.length) {
      const message = output.shift(); if (message.type !== "send") continue;
      sent++; await engine.accept({ type: "sent", sendId: message.sendId, ok: true, bufferedAmount: 0 });
    }
  };
  await confirm(); assert.equal(sent, 10); assert.equal(engine.queue.length, 16);
  now += 999; await engine.accept({ type: "tick" }); await confirm(); assert.equal(sent, 10);
  now++; await engine.accept({ type: "tick" }); await confirm(); assert.equal(sent, 20);
  now += 1000; await engine.accept({ type: "tick" }); await confirm(); assert.equal(sent, 26);
});
