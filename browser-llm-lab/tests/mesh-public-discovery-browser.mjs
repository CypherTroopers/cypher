#!/usr/bin/env node
// Opt-in LIVE acceptance: a home gateway knows only real Common A; the browser
// discovers signed real Common B through the public directory and connects to
// B's public WSS endpoint. This is NOT a WebRTC or native RLPx acceptance test.
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFile, writeFile, lstat, mkdtemp, rename, rm, chmod, realpath } from 'node:fs/promises';
import { resolve, join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash, X509Certificate } from 'node:crypto';
import { createGateway } from '../relay/gateway.mjs';
import { validateConfig } from '../relay/config.mjs';
import { verifyEndpoint } from '../public/mesh-discovery.js';
import { createMeshTLSFixture } from './mesh-tls-fixture.mjs';

assert.equal(process.env.MESH_PUBLIC_REMOTE_ACCEPTANCE, '1', 'Explicit MESH_PUBLIC_REMOTE_ACCEPTANCE=1 is required; this test uses live owner sockets and public WSS.');
assert.equal(process.env.MESH_ALLOW_GATEWAY_RESTART, '1', 'Explicit MESH_ALLOW_GATEWAY_RESTART=1 is required; the exact gateway restarts twice.');
assert.equal(process.env.MESH_PUBLIC_SOAK_STOPPED, '1', 'Explicit MESH_PUBLIC_SOAK_STOPPED=1 is required after the timed native soak ends.');
const root = fileURLToPath(new URL('../', import.meta.url));
const liveRoot = resolve(process.env.MESH_LIVE_ROOT || root), configPath = join(liveRoot, 'relay/config.json');
const pm2Home = join(liveRoot, '.runtime/mesh-gateway/pm2'), appName = 'cypher-browser-mesh-gateway';
const output = process.env.MESH_PUBLIC_REMOTE_REPORT || '/tmp/cypher-public-remote-discovery-browser-report.json';
const execute = promisify(execFile), sleep = ms => new Promise(r => setTimeout(r, ms));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const report = { status: 'RUNNING', startedAt: new Date().toISOString(), actualNative: true, sameHostOnly: true,
  nativeConfigChanged: false, nativeRestarted: false, webRTCClaim: false, directDescriptorInjection: false, requestInterception: false,
  checkpoints: [], errors: [], http: [], restarts: [], cleanup: {} };
let interrupted = null;
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => { interrupted = signal; report.interrupted = signal; });
const save = () => writeFile(output, JSON.stringify(report, null, 2));
async function checkpoint(name, detail = {}) { report.checkpoints.push({ name, at: new Date().toISOString(), ...detail }); await save(); console.log('PASS', name); }
async function until(check, label, ms = 60000, restoring = false) { const end = Date.now() + ms; while (Date.now() < end) { if (interrupted && !restoring) throw new Error('Acceptance interrupted by ' + interrupted); const value = await check(); if (value) return value; await sleep(250); } throw new Error('Timed out: ' + label); }
const files = ['public/mesh-controller.js','public/mesh-discovery-client.js','public/mesh-discovery.js','public/mesh-worker.js','public/mesh-protocol.js','relay/gateway.mjs','relay/discovery.mjs'];
const hashes = async () => Object.fromEntries(await Promise.all(files.map(async file => [file, sha(await readFile(resolve(root, file)))])));
let tls, homeGateway, browser, page, temp, originalBytes, originalStat, appliedHash, configChanged = false, liveConfig, homeNode, remoteNode;

async function appIdentity() {
  assert((await lstat(join(pm2Home, 'rpc.sock'))).isSocket(), 'Existing exact PM2 daemon socket required; do not start a daemon');
  const result = await execute('/usr/local/bin/pm2', ['jlist'], { env: { ...process.env, PM2_HOME: pm2Home }, timeout: 15000, maxBuffer: 4 * 1048576 });
  const found = JSON.parse(result.stdout).filter(row => row.name === appName); assert.equal(found.length, 1, 'Unique exact gateway PM2 app required');
  const row = found[0], env = row.pm2_env;
  assert.equal(env.pm_exec_path, join(liveRoot, 'relay/main.mjs')); assert.equal(env.pm_cwd, liveRoot);
  assert.deepEqual(env.args, [configPath]); assert.equal(basename(env.exec_interpreter), 'node');
  assert(Number.isSafeInteger(row.pm_id) && row.pm_id >= 0 && Number.isSafeInteger(row.pid) && row.pid > 0);
  assert.equal(env.status, 'online');
  return { id: row.pm_id, pid: row.pid, script: env.pm_exec_path, cwd: env.pm_cwd, args: env.args };
}
async function restartGateway(reason) {
  const before = await appIdentity();
  await execute('/usr/local/bin/pm2', ['restart', String(before.id)], { env: { ...process.env, PM2_HOME: pm2Home }, timeout: 30000, maxBuffer: 1048576 });
  const after = await appIdentity(); assert.equal(after.id, before.id);
  report.restarts.push({ reason, before, after, at: new Date().toISOString() });
}
async function guardedWrite(expectedHash, bytes) {
  const current = await lstat(configPath); assert(current.isFile() && !current.isSymbolicLink());
  assert.equal(current.uid, originalStat.uid); assert.equal(current.mode & 0o777, originalStat.mode & 0o777);
  assert.equal(sha(await readFile(configPath)), expectedHash, 'Configuration changed concurrently; refusing to overwrite');
  const pending = configPath + '.remote-acceptance-' + process.pid;
  try {
    await writeFile(pending, bytes, { flag: 'wx', mode: originalStat.mode & 0o777 });
    await chmod(pending, originalStat.mode & 0o777);
    assert.equal(sha(await readFile(configPath)), expectedHash, 'Configuration changed before rename');
    await rename(pending, configPath);
  } finally { await rm(pending, { force: true }); }
}
async function publicJSON(path, origin = liveConfig.origin) {
  const response = await fetch(liveConfig.origin + '/relay/v1/mesh' + path, { headers: { Origin: origin }, redirect: 'error', credentials: 'omit', signal: AbortSignal.timeout(5000) });
  assert.equal(response.status, 200, 'Public metadata request must succeed');
  const text = await response.text(); assert(Buffer.byteLength(text) <= 262144); return JSON.parse(text);
}
async function nativeStatus(node) {
  return new Promise((resolveStatus, reject) => {
    const request = http.request({ socketPath: node.socketPath, path: '/relay/v1/mesh/status', headers: { Origin: liveConfig.nativeOrigin || liveConfig.origin }, agent: false, signal: AbortSignal.timeout(5000) }, response => {
      const chunks = []; let size = 0;
      response.on('data', chunk => { size += chunk.length; if (size > 65536) request.destroy(new Error('Bounded native status exceeded')); else chunks.push(chunk); });
      response.on('error', reject); response.on('end', () => { try { assert.equal(response.statusCode, 200); resolveStatus(JSON.parse(Buffer.concat(chunks).toString())); } catch (error) { reject(error); } });
    }); request.on('error', reject); request.end();
  });
}

try {
  report.sourceHashes = await hashes();
  assert.equal(await realpath(configPath), configPath, 'Operational config must not use symlinks');
  originalStat = await lstat(configPath); assert(originalStat.isFile() && (originalStat.mode & 0o022) === 0);
  assert.equal(originalStat.uid, process.getuid()); originalBytes = await readFile(configPath);
  assert(originalBytes.length <= 65536); liveConfig = JSON.parse(originalBytes); validateConfig(liveConfig);
  assert(liveConfig.enabled && liveConfig.discovery?.enabled);
  homeNode = liveConfig.nodes.find(node => node.id === 'common-a'); remoteNode = liveConfig.nodes.find(node => node.id === 'common-b');
  assert(homeNode && remoteNode && homeNode.nodeId !== remoteNode.nodeId);
  report.publicOrigin = liveConfig.origin; report.originalConfigHash = sha(originalBytes);
  report.originalConfigMode = (originalStat.mode & 0o777).toString(8); report.originalGateway = await appIdentity();
  report.nativeBaseline = await Promise.all([homeNode, remoteNode].map(async node => ({ sourceId: node.id, status: await nativeStatus(node) })));
  assert(report.nativeBaseline.every(row => row.status.sessions === 0 && row.status.circuits === 0), 'All owned browser tests must be stopped before gateway restart');
  const directory = await publicJSON('/discovery');
  const verified = directory.endpoints.map(envelope => verifyEndpoint(envelope, liveConfig.network));
  assert(verified.some(endpoint => endpoint.nodeId === remoteNode.nodeId && endpoint.origin === liveConfig.origin));
  report.publicEndpointPreflight = verified.map(record => ({ nodeId: record.nodeId, sourceId: record.sourceId, origin: record.origin, expiresAt: record.expiresAt }));
  temp = await mkdtemp('/tmp/cypher-public-remote-acceptance-'); await chmod(temp, 0o700);
  await writeFile(join(temp, 'config-original.json'), originalBytes, { flag: 'wx', mode: 0o600 });
  tls = await createMeshTLSFixture({ root, names: ['remote-native-home'] }); const homeOrigin = tls.origins[0]; report.homeOrigin = homeOrigin;
  const allowed = liveConfig.discovery.allowedOrigins || []; assert(!allowed.includes(homeOrigin) && allowed.length < 8);
  const patched = structuredClone(liveConfig); patched.discovery.allowedOrigins = [...allowed, homeOrigin]; validateConfig(patched);
  const patchedBytes = Buffer.from(JSON.stringify(patched, null, 2) + '\n'); appliedHash = sha(patchedBytes); report.temporaryConfigHash = appliedHash;
  assert(!interrupted, 'Interrupted before operational change');
  await guardedWrite(report.originalConfigHash, patchedBytes); configChanged = true; await restartGateway('allow temporary exact frontend Origin');
  await until(async () => { try { await publicJSON('/config', homeOrigin); return true; } catch { return false; } }, 'public gateway after scoped restart');
  homeGateway = createGateway({ config: { enabled: true, origin: homeOrigin, nativeOrigin: liveConfig.nativeOrigin || liveConfig.origin, network: liveConfig.network,
    nodes: [homeNode], limits: { maxSessions: 4, maxSessionsPerClient: 4, maxConnections: 16, httpBytesPerSecond: 1048576, maxPeers: 20, maxCommonConnections: 20 },
    discovery: { enabled: true, bootstrapOrigins: [liveConfig.origin], allowedOrigins: [homeOrigin] }, iceServers: [] } });
  await homeGateway.listen({ port: 0 }); tls.addGateway(0, homeGateway);
  const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || '/tmp/browser-llm-preview/node_modules/playwright/index.mjs');
  const certificate = new X509Certificate(await readFile(join(tls.directory, 'tls.crt')));
  const fixtureSPKI = createHash('sha256').update(certificate.publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
  browser = await chromium.launch({ executablePath: process.env.CHROMIUM || '/tmp/browser-llm-browsers/chromium-1243/chrome-linux64/chrome', headless: true,
    args: ['--no-sandbox','--no-proxy-server',`--host-resolver-rules=${tls.hostResolverRules}`,`--ignore-certificate-errors-spki-list=${fixtureSPKI}`],
    env: { ...process.env, XDG_CONFIG_HOME: join(temp, 'chrome-config'), XDG_CACHE_HOME: join(temp, 'chrome-cache') } });
  const info = await (await browser.newBrowserCDPSession()).send('SystemInfo.getProcessInfo'); report.browserPid = info.processInfo.find(row => row.type === 'browser')?.id;
  page = await (await browser.newContext()).newPage();
  page.on('pageerror', error => report.errors.push(error.message));
  page.on('response', response => { const url = new URL(response.url()); if (url.origin === liveConfig.origin && url.pathname.startsWith('/relay/v1/mesh/')) {
    report.http.push({ origin: url.origin, path: url.pathname, method: response.request().method(), status: response.status(), at: Date.now() }); if (report.http.length > 128) report.http.shift();
  } });
  await page.goto(homeOrigin);
  await page.evaluate(async () => { const { MeshController } = await import('/mesh-controller.js'); window.mesh = new MeshController({ maxCommonConnections: 20 }); await mesh.start(); });
  await until(async () => page.evaluate(remoteId => { const state = mesh.snapshot(), remote = state.commonConnections.find(row => row.nodeId === remoteId);
    return state.nativeConnections === 2 && remote?.connected && remote.endpointVerified && remote.browserSignatureVerified; }, remoteNode.nodeId), 'real remote Common endpoint discovery and independent Worker signature verification', 90000);
  const connected = await page.evaluate(remoteId => ({ snapshot: mesh.snapshot(), homeConfigNodes: mesh.config.nodes.map(node => node.nodeId),
    descriptors: mesh.discovery.endpoints().map(record => ({ nodeId: record.nodeId, sourceId: record.sourceId, origin: record.origin, bootId: record.payload.bootId, expiresAt: record.expiresAt })),
    foreignLease: [...mesh.attachments.values()].filter(a => a.session.nodeId === remoteId).map(a => ({ origin: a.session.remoteOrigin, ownRoot: !a.session.parentId,
      distinctToken: a.session.token !== mesh.session.token, distinctLease: a.session.id !== mesh.session.id, nativeSession: a.nativeSession, browserId: a.session.browserId })) }), remoteNode.nodeId);
  assert.deepEqual(connected.homeConfigNodes, [homeNode.nodeId]); assert(!connected.homeConfigNodes.includes(remoteNode.nodeId));
  assert.equal(connected.foreignLease.length, 1); assert.deepEqual(connected.foreignLease[0].origin, liveConfig.origin);
  assert(connected.foreignLease[0].ownRoot && connected.foreignLease[0].distinctToken && connected.foreignLease[0].distinctLease);
  assert(report.http.some(row => row.path.endsWith('/discovery') && row.status === 200));
  assert(report.http.some(row => row.path.endsWith('/sessions') && row.method === 'POST' && row.status === 201));
  await checkpoint('Unlisted real Common B is discovered from public HTTPS, signature-verified in Worker and connected through its own public WSS lease', connected);
  await page.evaluate(() => mesh.stop());
  await until(async () => (await Promise.all([homeNode, remoteNode].map(nativeStatus))).every(status => status.sessions === 0 && status.circuits === 0) && homeGateway.stats().sessions === 0, 'owned native leases released');
  assert.equal(await page.evaluate(() => mesh.snapshot().nativeConnections), 0);
  await checkpoint('OFF removes both owned Common sessions and circuits', { native: await Promise.all([homeNode, remoteNode].map(nativeStatus)), home: homeGateway.stats(), http: report.http });
  assert.equal(report.errors.length, 0); report.status = 'PASS';
} catch (error) {
  report.status = 'FAIL'; report.failure = error.stack;
  if (page) report.lastSnapshot = await page.evaluate(() => window.mesh?.snapshot()).catch(() => null);
  console.error(error.message); process.exitCode = 1;
} finally {
  try { await page?.evaluate(() => window.mesh?.stop()); } catch {}
  const cleanupError = (scope, error) => { report.cleanup[scope + 'Error'] = error.message; report.errors.push(scope + ': ' + error.message); report.status = 'FAIL'; process.exitCode = 1; };
  await browser?.close().catch(error => cleanupError('browser', error));
  await homeGateway?.close().catch(error => cleanupError('homeGateway', error));
  await tls?.close().catch(error => { report.cleanup.retainedTLSDirectory = tls.directory; cleanupError('TLSFixture', error); });
  if (configChanged) {
    try {
      await guardedWrite(appliedHash, originalBytes); configChanged = false;
      await restartGateway('restore original exact configuration');
      assert.equal(sha(await readFile(configPath)), report.originalConfigHash); assert.equal((await lstat(configPath)).mode & 0o777, originalStat.mode & 0o777);
      await until(async () => { try { await publicJSON('/config'); return true; } catch { return false; } }, 'restored public gateway', 60000, true);
      report.cleanup.configRestored = true;
    } catch (error) { report.cleanup.restoreError = error.message; report.status = 'FAIL'; process.exitCode = 1; }
  } else report.cleanup.configRestored = originalBytes ? sha(await readFile(configPath)) === report.originalConfigHash : true;
  if (temp && report.cleanup.configRestored) { await rm(temp, { recursive: true, force: true }); report.cleanup.backupRemoved = true; }
  else if (temp) report.cleanup.recoveryBackup = join(temp, 'config-original.json');
  if (liveConfig && homeNode && remoteNode) {
    report.cleanup.native = await Promise.all([homeNode, remoteNode].map(async node => ({ sourceId: node.id, status: await nativeStatus(node).catch(error => ({ error: error.message })) })));
    if (!report.cleanup.native.every(row => row.status.sessions === 0 && row.status.circuits === 0)) { report.status = 'FAIL'; report.errors.push('Native session/circuit cleanup was not confirmed'); process.exitCode = 1; }
  }
  if (report.browserPid) {
    report.cleanup.browserExited = !(await lstat('/proc/' + report.browserPid).catch(() => null));
    if (!report.cleanup.browserExited) { report.status = 'FAIL'; report.errors.push('Owned browser exit was not confirmed'); process.exitCode = 1; }
  }
  report.sourceHashesAfter = await hashes(); if (JSON.stringify(report.sourceHashes) !== JSON.stringify(report.sourceHashesAfter)) { report.status = 'FAIL'; report.errors.push('Product sources changed during acceptance'); process.exitCode = 1; }
  report.finishedAt = new Date().toISOString(); await save();
}
