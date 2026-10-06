#!/usr/bin/env node
// Synthetic renderer fixtures only. No controller, gateway admission or real mesh traffic.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const stage = resolve(process.env.MAP_STAGE || fileURLToPath(new URL('../', import.meta.url)));
const live = resolve(process.env.MESH_LIVE_ROOT || fileURLToPath(new URL('../', import.meta.url)));
const artifacts = resolve(process.env.MAP_FIXTURE_ARTIFACTS || '/tmp/cypher-map-fixtures');
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || '/tmp/browser-llm-preview/node_modules/playwright/index.mjs');
await mkdir(artifacts, { recursive: true });
const html = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Synthetic map fixture</title>
<link rel="stylesheet" href="/relay.css"><style>html,body{margin:0;background:#061019;color:#cee8ef;font:14px system-ui}main{width:min(1180px,100%);margin:auto;padding:20px 0}h1,p{margin:12px 20px;font-size:14px}.relay-map-wrap{margin:0 12px}canvas{display:block;width:100%;height:auto}</style>
<main><h1>SYNTHETIC RENDERER FIXTURE — NO NETWORK PARTICIPATION</h1><p id="fixtureLabel"></p><div class="relay-map-wrap"><canvas id="map" width="960" height="448" aria-label="Synthetic fixture map"></canvas></div></main>
<script type="module">import { RelayMap, MAP_LIMITS } from '/relay-map.js';const map = new RelayMap(document.getElementById('map'));globalThis.fixture={map,limits:MAP_LIMITS,set:(snapshot,label)=>{document.getElementById('fixtureLabel').textContent=label;map.set(snapshot)},transfer:event=>map.transfer(event),inspect:()=>map.inspect(),image:()=>document.getElementById('map').toDataURL()};globalThis.fixtureReady=true;</script>`;
const server = createServer(async (req, res) => {
  try {
    const path = new URL(req.url, 'http://localhost').pathname;
    if (path === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(html); return; }
    if (!['/relay-map.js', '/relay.css', '/assets/earth-land.json'].includes(path)) { res.writeHead(404); res.end(); return; }
    let bytes; try { bytes = await readFile(resolve(stage, 'public', '.' + path)); }
    catch { if (path === '/relay-map.js') throw Error('Staged renderer missing'); bytes = await readFile(resolve(live, 'public', '.' + path)); }
    res.writeHead(200, { 'Content-Type': path.endsWith('.js') ? 'text/javascript' : path.endsWith('.css') ? 'text/css' : 'application/json', 'Cache-Control': 'no-store' }); res.end(bytes);
  } catch { res.writeHead(500); res.end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const report = { kind: 'SYNTHETIC_RENDERER_FIXTURES', syntheticCoordinates: true, realMeshParticipation: false,
  startedAt: new Date().toISOString(), status: 'RUNNING', cases: [], screenshots: [], errors: [], externalRequests: [], sessionAdmissions: 0 };
const sourceHashes=async()=>Object.fromEntries(await Promise.all(['relay-map.js','relay.css'].map(async name=>[name,createHash('sha256').update(await readFile(resolve(stage,'public',name))).digest('hex')])));
report.sourceHashes=await sourceHashes();
const browser = await chromium.launch({ headless: true,
  executablePath: process.env.CHROMIUM || '/tmp/browser-llm-browsers/chromium-1243/chrome-linux64/chrome', args: ['--no-sandbox'],
  env: { ...process.env, XDG_CONFIG_HOME: '/tmp/cypher-map-fixture-config', XDG_CACHE_HOME: '/tmp/cypher-map-fixture-cache' } });
const JP = { countryCode: 'JP', label: 'Japan', lat: 36, lon: 138, accuracy: 'country', source: 'synthetic-fixture' };
const US = { countryCode: 'US', label: 'United States', lat: 38, lon: -97, accuracy: 'country', source: 'synthetic-fixture' };
const peer = (id, geo) => ({ peerId: id, geo, connected: true, path: 'direct' });
const snapshot = (selfGeo, peers, requested = true) => ({ selfGeo, peers, requested, state: requested ? 'ACTIVE' : 'OFF' });
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const inspect = page => page.evaluate(() => fixture.inspect());
const image = page => page.evaluate(() => fixture.image());
async function checkLayout(page, expected) {
  const info = await inspect(page);
  assert.equal(info.layout.nodes.length, expected);
  assert.equal(info.layout.links.length, Math.max(0, expected - 1), 'Every connected browser retains its connection line');
  assert.equal(new Set(info.layout.nodes.map(node => node.id)).size, expected, 'Participants are individually represented');
  const geometry = await page.evaluate(() => ({ width: innerWidth, scrollWidth: document.documentElement.scrollWidth,
    canvas: (() => { const r = document.getElementById('map').getBoundingClientRect(); return { width: r.width, height: r.height }; })() }));
  assert(geometry.scrollWidth <= geometry.width + 1, 'No horizontal overflow');
  assert(info.layout.height <= 1400, 'Expanded canvas height remains bounded for the maximum participant count');
  assert.equal(Math.round(geometry.canvas.height), info.layout.height, 'Logical layout matches the actual rendered canvas height');
  for (const node of info.layout.nodes) {
    assert(Number.isFinite(node.x) && Number.isFinite(node.y), 'Every visible node has finite layout coordinates');
    assert(node.x>=0&&node.y>=0&&node.x<=info.layout.width&&node.y<=info.layout.height,'Every participant endpoint remains inside the canvas');
    const box=node.labelBox;
    assert(box.x>=0&&box.y>=0&&box.x+box.width<=info.layout.width+1&&box.y+box.height<=info.layout.height+1,'Every node label remains inside the visible canvas');
    if (node.located) {
      assert(node.geo && node.anchor, 'Geographic pin has a real fixture country coordinate');
      assert(Math.hypot(node.x-node.anchor.x,node.y-node.anchor.y)<=40,'Known-country pins stay near their real country anchor; only label cards may use distant collision fallback');
    }
    else { assert.equal(node.geo, null); assert.equal(node.anchor, null); assert(info.layout.dock, 'Unknown nodes belong in the separate location-unknown area'); }
  }
  return { ...info, geometry };
}
function separatedLabels(info) {
  const nodes=info.layout.nodes;
  for(let i=0;i<nodes.length;i++)for(let j=i+1;j<nodes.length;j++){
    const a=nodes[i].labelBox,b=nodes[j].labelBox;
    assert(!(a.x<b.x+b.width&&a.x+a.width>b.x&&a.y<b.y+b.height&&a.y+a.height>b.y),`Labels ${nodes[i].id}/${nodes[j].id} must not overlap`);
  }
}
async function shot(page, name) {
  const path = resolve(artifacts, name + '.png'); await page.screenshot({ path, fullPage: true }); report.screenshots.push(path);
}
async function fixtureCase(page, name, state, expected) {
  await page.evaluate(({ state, name }) => fixture.set(state, name), { state, name });
  await sleep(70); const info = await checkLayout(page, expected); report.cases.push({ name, layout: info.layout, geometry: info.geometry }); return info;
}
try {
  for (const width of [390, 1440]) {
    const context = await browser.newContext({ viewport: { width, height: 900 }, reducedMotion: 'no-preference' });
    const page = await context.newPage();
    page.on('pageerror', error => report.errors.push(error.message));
    page.on('request', req => { if (!req.url().startsWith(origin)) report.externalRequests.push(req.url()); if (req.method() === 'POST' && req.url().includes('/sessions')) report.sessionAdmissions++; });
    await page.goto(origin, { waitUntil: 'networkidle' }); await page.waitForFunction(() => fixtureReady);
    const known = snapshot(JP, [peer('us-peer', US)]);
    const idle = await fixtureCase(page, `${width}: JP self and US peer`, known, 2);
    assert.equal(idle.layout.nodes.filter(node => node.located).length, 2);
    assert.equal(idle.pulses.length, 0); assert.equal(idle.pendingFrame, false);
    const idleImage = await image(page); await sleep(220); assert.equal(await image(page), idleImage, 'No invented traffic animation while idle');
    await shot(page, `${width}-jp-us-idle`);
    await page.evaluate(() => fixture.transfer({ name: 'received', peerId: 'us-peer' })); await sleep(70);
    const moving = await inspect(page), imageA = await image(page);
    assert(moving.activityCount > idle.activityCount); assert(moving.pulses.length > 0); assert(moving.pendingFrame);
    assert.equal(moving.pulses.at(-1).from,'us-peer');assert.equal(moving.pulses.at(-1).to,'self');
    await sleep(220); const moved = await inspect(page); assert(moved.drawCount > moving.drawCount); assert.notEqual(await image(page), imageA, 'An event produces visibly advancing packet animation');
    await shot(page, `${width}-jp-us-transfer`);
    await sleep(await page.evaluate(() => fixture.limits.pulseMs + 60));
    const between=await inspect(page);assert.equal(between.pulses.length,0);
    await page.evaluate(() => fixture.transfer({name:'forwarded',peerId:'us-peer'}));
    await sleep(80);const lateBefore=await inspect(page),lateImage=await image(page);
    assert.equal(lateBefore.pulses.at(-1).from,'self');assert.equal(lateBefore.pulses.at(-1).to,'us-peer');
    await sleep(180);const lateAfter=await inspect(page);
    assert(lateAfter.drawCount>lateBefore.drawCount,'A new transfer starts animation while the prior static activity badge is still visible');
    assert.notEqual(await image(page),lateImage,'Second burst advances actual canvas pixels');
    report.cases.push({name:`${width}: late burst animates during previous badge lifetime`,drawDelta:lateAfter.drawCount-lateBefore.drawCount});
    await page.setViewportSize({width:width===390?430:1280,height:900});await sleep(80);
    const resized=await inspect(page),resizedPulse=resized.pulses.at(-1);
    for(const [key,id] of [['a',resizedPulse.from],['b',resizedPulse.to]]){
      const endpoint=resized.layout.nodes.find(node=>node.id===id);assert(Math.hypot(resizedPulse.curve[key].x-endpoint.x,resizedPulse.curve[key].y-endpoint.y)<1,'Active particles reproject to current node geometry after resize');
    }
    await page.setViewportSize({width,height:900});await sleep(80);
    await sleep(await page.evaluate(() => Math.max(fixture.limits.pulseMs, fixture.limits.activityMs) + 100)); const drained = await inspect(page); assert.equal(drained.pulses.length, 0); assert.equal(drained.pendingFrame, false);
    await sleep(160); assert.equal((await inspect(page)).drawCount, drained.drawCount, 'Animation stops after event lifetime');
    report.cases.push({ name: `${width}: event advances actual canvas; idle scheduler stops`, activityCount: moved.activityCount, drawDelta: moved.drawCount - moving.drawCount });
    const grouped = await fixtureCase(page, `${width}: self and two distinct peers in Japan`, snapshot(JP, [peer('jp-a', JP), peer('jp-b', JP)]), 3);
    assert.equal(new Set(grouped.layout.nodes.map(node => `${node.x},${node.y}`)).size, 3, 'Same-country participants keep distinct visible pins');
    for (let i = 0; i < grouped.layout.nodes.length; i++) for (let j = i + 1; j < grouped.layout.nodes.length; j++) {
      const a = grouped.layout.nodes[i], b = grouped.layout.nodes[j]; assert(Math.hypot(a.x - b.x, a.y - b.y) >= 10, 'Same-country pins are visibly separated');
    }
    await page.evaluate(() => fixture.transfer({ name: 'acknowledged', peerId: 'jp-a' })); await sleep(100);
    const acknowledged=await inspect(page);assert.equal(acknowledged.pulses.at(-1).from,'jp-a');assert.equal(acknowledged.pulses.at(-1).to,'self');
    await shot(page, `${width}-same-country`);
    const fourKnown=await fixtureCase(page,`${width}: maximum four same-country browsers`,snapshot(JP,[peer('jp-a',JP),peer('jp-b',JP),peer('jp-c',JP)]),4);
    separatedLabels(fourKnown);await shot(page,`${width}-same-country-four`);
    const missingPeer = await fixtureCase(page, `${width}: unknown peer remains visible`, snapshot(JP, [peer('unknown-peer', null), peer('us-peer', US)]), 3);
    assert.equal(missingPeer.layout.nodes.filter(node => !node.located).length, 1); await shot(page, `${width}-unknown-peer`);
    const missingSelf = await fixtureCase(page, `${width}: unknown self and peer, one known peer`, snapshot(null, [peer('unknown-peer', null), peer('us-peer', US)]), 3);
    assert.equal(missingSelf.layout.nodes.find(node => node.self).located, false);
    assert.equal(missingSelf.layout.nodes.filter(node => !node.located).length, 2);
    await page.evaluate(() => fixture.transfer({ name: 'received', peerId: 'unknown-peer' })); await sleep(100); await shot(page, `${width}-unknown-self-and-peer`);
    const twentyPeers=Array.from({length:20},(_,index)=>peer(`browser-${String(index+1).padStart(2,'0')}`,JP));
    const denseCountry=await fixtureCase(page,`${width}: self plus 20 peers in the same country`,snapshot(JP,twentyPeers),21);
    assert.equal(denseCountry.layout.nodes.filter(node=>node.located).length,21);
    assert.equal(new Set(denseCountry.layout.nodes.map(node=>`${node.x},${node.y}`)).size,21,'Every same-country participant has a distinct visible endpoint');
    separatedLabels(denseCountry);await shot(page,`${width}-twenty-same-country`);
    const DE={countryCode:'DE',label:'Germany',lat:51,lon:10,accuracy:'country',source:'synthetic-fixture'};
    const AU={countryCode:'AU',label:'Australia',lat:-25,lon:134,accuracy:'country',source:'synthetic-fixture'};
    const mixedPeers=twentyPeers.map((node,index)=>({...node,geo:[JP,US,DE,AU,null][index%5]}));
    const denseMixed=await fixtureCase(page,`${width}: self plus 20 mixed-country and unlocated peers`,snapshot(JP,mixedPeers),21);
    assert.equal(denseMixed.layout.nodes.filter(node=>!node.located).length,4);
    separatedLabels(denseMixed);await shot(page,`${width}-twenty-mixed`);
    const denseUnknown=await fixtureCase(page,`${width}: self plus 20 unlocated peers`,snapshot(null,twentyPeers.map(node=>({...node,geo:null}))),21);
    assert(denseUnknown.layout.nodes.every(node=>!node.located&&node.anchor===null&&node.geo===null));
    assert(denseUnknown.layout.links.every(link=>!link.geographic));separatedLabels(denseUnknown);
    await shot(page,`${width}-twenty-unknown`);
    await page.evaluate(()=>fixture.transfer({name:'received',peerId:'browser-20'}));await sleep(80);
    const denseTransfer=await inspect(page);assert.equal(denseTransfer.pulses.at(-1).from,'browser-20','The twentieth connection still carries actual-event particles');
    await fixtureCase(page,`${width}: disconnected and duplicate peers do not add participants`,snapshot(JP,[...twentyPeers,peer('browser-01',JP),{...peer('pending-peer',US),connected:false}]),21);
    const allUnknown = await fixtureCase(page, `${width}: all four locations unknown`, snapshot(null, [peer('unknown-a', null), peer('unknown-b', null),peer('unknown-c',null)]), 4);
    assert(allUnknown.layout.nodes.every(node => !node.located && node.geo === null && node.anchor === null));
    assert(allUnknown.layout.links.every(link => !link.geographic));separatedLabels(allUnknown);await shot(page, `${width}-all-unknown`);
    const burst=await page.evaluate(()=>{const before=fixture.inspect();for(let i=0;i<1000;i++)fixture.transfer({name:'received',peerId:'unknown-a'});return {before,after:fixture.inspect()}});
    assert.equal(burst.after.activityCount-burst.before.activityCount,1000);assert(burst.after.pulses.length<=24);
    assert(burst.after.drawCount-burst.before.drawCount<=2,'A synchronous event burst must not bypass the frame scheduler');
    report.cases.push({name:`${width}: 1000 transfer events remain bounded and coalesce draws`,events:1000,immediateDraws:burst.after.drawCount-burst.before.drawCount,pulses:burst.after.pulses.length});
    await page.evaluate(() => fixture.transfer({ name: 'received', peerId: 'unknown-a' }));
    await page.evaluate(() => fixture.set({ requested: false, state: 'OFF', selfGeo: null, peers: [] }, 'Node OFF — no active nodes or animation'));
    const off = await checkLayout(page, 0); assert.equal(off.pulses.length, 0); assert.equal(off.pendingFrame, false);
    await page.evaluate(() => fixture.transfer({ name: 'received', peerId: 'unknown-a' })); await sleep(120);
    const stillOff = await inspect(page); assert.equal(stillOff.activityCount, off.activityCount); assert.equal(stillOff.pendingFrame, false); await shot(page, `${width}-off`);
    report.cases.push({ name: `${width}: OFF cancels and ignores subsequent transfer events`, pendingFrame: stillOff.pendingFrame });
    await context.close();
  }
  const context = await browser.newContext({ viewport: { width: 390, height: 900 }, reducedMotion: 'reduce' });
  const page = await context.newPage(); page.on('pageerror', error => report.errors.push(error.message));
  await page.goto(origin, { waitUntil: 'networkidle' }); await page.waitForFunction(() => fixtureReady);
  const initial = await fixtureCase(page, '390: reduced motion', snapshot(JP, [peer('us-peer', US)]), 2);
  assert.equal(initial.reducedMotion, true); const before = await image(page);
  await page.evaluate(() => fixture.transfer({ name: 'acknowledged', peerId: 'us-peer' })); await sleep(60);
  const reduced = await inspect(page); assert(reduced.activityCount > initial.activityCount); assert.equal(reduced.pulses.length, 0);
  const reducedImage = await image(page); assert.notEqual(reducedImage, before, 'Reduced motion keeps a static actual-activity indication');
  await sleep(220); assert.equal((await inspect(page)).drawCount, reduced.drawCount); assert.equal(await image(page), reducedImage, 'Reduced-motion packet indicator does not move');
  await shot(page, '390-reduced-motion-activity'); await context.close();
  assert.deepEqual(report.errors, []); assert.deepEqual(report.externalRequests, []); assert.equal(report.sessionAdmissions, 0);
  report.finalHashes=await sourceHashes();assert.deepEqual(report.finalHashes,report.sourceHashes,'Renderer and CSS remain unchanged throughout fixture validation');
  report.status = 'PASS';
} catch (error) { report.status = 'FAIL'; report.error = error.stack; process.exitCode = 1; }
finally { report.finishedAt = new Date().toISOString(); await writeFile(resolve(artifacts, 'report.json'), JSON.stringify(report, null, 2)); await browser.close(); await new Promise(resolve => server.close(resolve)); console.log(report.status, resolve(artifacts, 'report.json')); }
