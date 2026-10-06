// Deterministic PUBLIC test keys only. Never use these keys in deployed services.
import { secp256k1, keccak_256 } from '../public/vendor/mesh-crypto.js';
import { DISCOVERY_DOMAINS, publicKeyNodeId } from '../public/mesh-discovery.js';
export const fixtureNetwork = { chainId: 10101919, genesisHash: '0x' + '22'.repeat(32) };
export const fixtureNow = 1700000000000;
const encoder = new TextEncoder();
export const hex = bytes => Array.from(bytes, v => v.toString(16).padStart(2, '0')).join('');
const concat = (...parts) => { const bytes = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let offset = 0; for (const p of parts) { bytes.set(p, offset); offset += p.length; } return bytes; };
export function fixtureIdentity(seed = 1) {
  const privateKey = typeof seed === 'number' ? Uint8Array.from(Buffer.from(seed.toString(16).padStart(64, '0'), 'hex')) : keccak_256(encoder.encode(String(seed)));
  const publicKeyHex = hex(secp256k1.getPublicKey(privateKey, false).subarray(1)), nodeId = publicKeyNodeId(publicKeyHex);
  return { privateKey, publicKeyHex, publicKey: publicKeyHex, nodeId, peerId: nodeId.slice(0, 32), enode: `enode://${publicKeyHex}@127.0.0.1:30445?discport=0` };
}
export function signDiscoveryRaw(raw, identity = fixtureIdentity(), domain = DISCOVERY_DOMAINS.advertisement) {
  raw = typeof raw === 'string' ? encoder.encode(raw) : raw;
  const signature = secp256k1.sign(keccak_256(concat(encoder.encode(domain), raw)), identity.privateKey, { prehash: false, format: 'recovered', lowS: true });
  return { payloadBase64: Buffer.from(raw).toString('base64'), signatureHex: hex(concat(signature.subarray(1), signature.subarray(0, 1))) };
}
export function signMeshAdvertisement(payload, identity = fixtureIdentity(), raw = JSON.stringify(payload)) {
  return signDiscoveryRaw(raw, identity, DISCOVERY_DOMAINS.advertisement);
}
export function meshAdvertisement(identity = fixtureIdentity(), overrides = {}, now = fixtureNow) {
  return signMeshAdvertisement({ version: 1, network: fixtureNetwork, enode: identity.enode, bootId: '66'.repeat(16), issuedAt: now, expiresAt: now + 120000, ...overrides }, identity);
}
export function endpointAdvertisement(identity = fixtureIdentity(), overrides = {}, now = fixtureNow) {
  return signDiscoveryRaw(JSON.stringify({ version: 1, network: fixtureNetwork, enode: identity.enode, sourceId: 'common-a', gatewayOrigin: 'https://gateway.example.org',
    bootId: '66'.repeat(16), sequence: 1, issuedAt: now, expiresAt: now + 120000, ...overrides }), identity, DISCOVERY_DOMAINS.endpoint);
}
