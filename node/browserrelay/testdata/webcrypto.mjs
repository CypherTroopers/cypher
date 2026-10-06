// Independent browser-compatible WebCrypto check. The scalar 1 key below is
// public TEST DATA ONLY, never an operator signing key.
import { createECDH, createHash, webcrypto } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const domain = Buffer.from("cypher-browser-header-manifest-v1\0");
const headerDomain = Buffer.from("cypher-common-lightnode-header-overlay-v1\0");
const vectorPath = new URL("protocol-vectors.json", import.meta.url);
const sha256 = bytes => createHash("sha256").update(bytes).digest("hex");
const u64 = n => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const digestHeader = (network, height, raw) => sha256(Buffer.concat([
  headerDomain, u64(network.chainId), Buffer.from(network.genesisHash.slice(2), "hex"), u64(height), raw,
]));

if (process.argv[2] === "--generate") {
  const d = Buffer.alloc(32); d[31] = 1;
  const ec = createECDH("prime256v1"); ec.setPrivateKey(d);
  const point = ec.getPublicKey();
  const publicJwk = { kty: "EC", crv: "P-256", x: point.subarray(1, 33).toString("base64url"), y: point.subarray(33).toString("base64url"), ext: true, key_ops: ["verify"] };
  const privateKey = await webcrypto.subtle.importKey("jwk", { ...publicJwk, d: d.toString("base64url"), key_ops: ["sign"] }, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const network = { chainId: 1, genesisHash: "0x" + "22".repeat(32) };
  // Opaque codec bytes, deliberately not a valid Cypher header fixture.
  const raw = Buffer.from("c0", "hex");
  const manifest = {
    version: 1, network, sourceId: "test_source", sourceBootId: "33".repeat(16), sequence: "1",
    observedAt: 1700000000000, expiresAt: 1700000030000, headHeight: 1, headHash: "0x" + "11".repeat(32),
    entries: [{ height: 1, blockHash: "0x" + "11".repeat(32), parentHash: network.genesisHash, digest: digestHeader(network, 1, raw), rawBytes: raw.length }],
  };
  const bytes = Buffer.from(JSON.stringify(manifest));
  const signed = Buffer.concat([domain, bytes]);
  const signature = Buffer.from(await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, signed));
  if (signature.length !== 64) throw new Error("WebCrypto signature must be raw r || s");
  const vector = {
    description: "Non-production independent Node WebCrypto vector; private scalar is public test value 1. Header bytes test digest only, not header validity.",
    publicJwk, header: { network, height: 1, rawHex: raw.toString("hex"), digest: digestHeader(network, 1, raw) },
    envelope: { keyId: "test_key", manifestBase64: bytes.toString("base64"), signatureBase64: signature.toString("base64") },
    manifestId: sha256(signed),
  };
  await writeFile(vectorPath, JSON.stringify(vector, null, 2) + "\n");
  console.log(`Generated ${fileURLToPath(vectorPath)}`);
} else {
  const vector = JSON.parse(await readFile(vectorPath, "utf8"));
  const envelope = process.argv[2] ? JSON.parse(await readFile(process.argv[2], "utf8")) : vector.envelope;
  const publicKey = await webcrypto.subtle.importKey("jwk", vector.publicJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const bytes = Buffer.from(envelope.manifestBase64, "base64");
  const signature = Buffer.from(envelope.signatureBase64, "base64");
  if (signature.length !== 64 || !await webcrypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, signature, Buffer.concat([domain, bytes]))) throw new Error("signature mismatch");
  if (digestHeader(vector.header.network, vector.header.height, Buffer.from(vector.header.rawHex, "hex")) !== vector.header.digest) throw new Error("header digest mismatch");
  if (!process.argv[2] && sha256(Buffer.concat([domain, bytes])) !== vector.manifestId) throw new Error("manifest ID mismatch");
  const wrongDomain = Buffer.from("cypher-browser-header-manifest-v1");
  if (await webcrypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, signature, Buffer.concat([wrongDomain, bytes]))) throw new Error("missing NUL accepted");
  console.log("WebCrypto signature, full-byte digest and domain checks: PASS");
}
