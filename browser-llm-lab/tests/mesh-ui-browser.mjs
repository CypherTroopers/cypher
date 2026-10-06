#!/usr/bin/env node
// Public UI acceptance, separate from the isolated native/byte-verification soak.
// Use only normal page navigation/button clicks. Never inject controllers, frames or DOM state.
import assert from 'node:assert/strict';
import {writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';

const origin=process.env.MESH_UI_ORIGIN||'https://ai-test.make-cph-great-again.community';
const output=process.env.MESH_UI_REPORT||'/tmp/cypher-mesh-ui-browser-report.json';
const shots=process.env.MESH_UI_SCREENSHOTS||'/tmp/cypher-mesh-ui-browser';
const expectedCapacity=Number(process.env.MESH_EXPECT_NATIVE_CAPACITY||0);
const expectedCommons=Number(process.env.MESH_EXPECT_COMMON_CONNECTIONS||0);
assert(Number.isInteger(expectedCommons)&&expectedCommons>=0&&expectedCommons<=20,'Expected Common count must be 0 (discover) or 1..20');
assert.equal(process.env.MESH_UI_JOIN_AUTHORIZED,'1','Joining is disabled: obtain the parent soak-completion gate before setting MESH_UI_JOIN_AUTHORIZED=1.');
assert.equal(new URL(origin).origin,origin,'Use an exact public origin without paths or query parameters.');
assert.equal(new URL(origin).protocol,'https:','This acceptance uses public HTTPS with normal DNS.');
const {chromium}=await import(process.env.PLAYWRIGHT_MODULE||'playwright');
const participants=[],report={startedAt:new Date().toISOString(),status:'RUNNING',origin,
  normalPublicDNS:true,independentBrowserProcesses:true,controllerInjection:false,DOMInjection:false,
  requestInterception:false,forcedTransport:false,physicalPhone:false,viewportPhoneOnly:true,
  foreignPeersPossible:true,isolationClaim:false,exactEncryptedByteVerification:false,
  limits:'Displayed counters prove UI behavior and browser hop receipt activity; native authentication and byte verification belong to the separate mesh soak.',
  checkpoints:[],screenshots:[],pageErrors:[],participants:{},cleanup:[],navigationRetries:[]};
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const save=()=>writeFile(output,JSON.stringify(report,null,2)+'\n');
const sanitize=value=>String(value).replace(/\b[a-fA-F0-9]{32,}\b/g,'[opaque identifier]').replace(/\bBearer\s+\S+/gi,'Bearer [redacted]').slice(0,400);
async function checkpoint(name,detail={}){report.checkpoints.push({name,at:new Date().toISOString(),...detail});await save();console.log('PASS',name);}
async function readUI(p){
  // Read-only DOM evaluation. No controller/session access and no page mutation.
  const ui=await p.page.evaluate(()=>{
    const text=id=>document.getElementById(id)?.textContent?.trim()||'';
    const canvas=document.getElementById('relayMap'),data=canvas?.dataset||{};
    const map={known:Number(data.mapKnown||0),unknown:Number(data.mapUnknown||0),events:Number(data.mapEvents||0),
      received:Number(data.mapReceived||0),sent:Number(data.mapForwarded||0),acknowledged:Number(data.mapAcknowledged||0),
      frames:Number(data.mapFrames||0),pulses:Number(data.mapPulses||0),nodes:JSON.parse(data.mapNodes||'[]'),
      ariaLabel:canvas?.getAttribute('aria-label')||''};
    return {state:text('relayState'),common:text('relayCommonPeers'),commonHint:text('relayCommonPeerHint'),
      commonConnections:Array.from(document.querySelectorAll('#relayCommonList [data-common-source]'),row=>({sourceId:row.getAttribute('data-common-source'),connected:row.getAttribute('data-common-connected')==='true',label:row.textContent})),map,
      peers:text('relayPeers'),circuits:text('relayCommonCircuits'),circuitHint:text('relayCommonCircuitHint'),connectionLimits:text('relayConnectionLimits'),receipts:text('relayReceiptsCount'),
      acknowledged:text('relayReceiptsBytes'),native:text('relayNativeState'),signal:text('relaySignalState'),
      stream:text('relayStream'),route:text('relayDataRoute'),mapCaption:text('relayMapCaption'),mapTitle:document.querySelector('.relay-map-title')?.textContent?.trim()||'',
      reason:text('relayReason'),error:text('relayErrors'),visibility:document.visibilityState,
      onDisabled:document.getElementById('relayOn')?.disabled,offDisabled:document.getElementById('relayOff')?.disabled,
      width:innerWidth,documentWidth:document.documentElement.scrollWidth,bodyWidth:document.body.scrollWidth,
      mapWidth:document.getElementById('relayMap')?.getBoundingClientRect().width||0};
  });
  assert.match(ui.connectionLimits,/Common attachment limit: 20\b/,'Public initial, active and OFF details retain the configured 20-Common ceiling');
  for(const key of ['peers','common','circuits'])assert.match(ui[key],/^(0|[1-9]\d*)$/,p.name+' '+key+' shows an actual integer count without a capacity denominator');
  ui.peerCount=Number(ui.peers);ui.commonCount=Number(ui.common);ui.circuitCount=Number(ui.circuits);ui.receiptCount=Number.parseInt(ui.receipts,10);
  assert(ui.commonCount>=0&&ui.commonCount<=20,'Common connections count stays within 20 actual WSS attachments');
  assert(ui.peerCount>=0&&ui.peerCount<=20,'Connected browser count stays within 20 RTC neighbors');
  assert.equal(ui.commonCount,ui.commonConnections.filter(connection=>connection.connected).length,'Primary Common count equals the actual connected source cards');
  const sourceHints=ui.commonHint.match(/^(.+)\s*·\s*WSS connected$/)?.[1].trim().split(/,\s*/)||[];
  ui.sourceIds=ui.commonConnections.filter(connection=>connection.connected).map(connection=>connection.sourceId);
  assert.deepEqual(sourceHints,ui.sourceIds,'The Common hint names exactly the connected source cards');
  ui.location=/your location:\s*(unknown|unavailable)/.test(ui.mapCaption)?'unknown':ui.mapCaption.match(/you:\s*(.+)$/)?.[1]?.split('. Pins show ')[0]||null;
  report.participants[p.name]={...report.participants[p.name],latestUI:ui,sessionPOSTs:p.sessionPOSTs};return ui;
}
async function waitFor(label,predicate,timeout=90000){
  const end=Date.now()+timeout;
  while(Date.now()<end){if(await predicate())return;await sleep(400);}
  await Promise.allSettled(participants.map(readUI));await save();throw new Error(label+' timed out');
}
async function menu(p){
  const toggle=p.page.locator('#sidebarToggle');
  if(await toggle.isVisible()&&await toggle.getAttribute('aria-expanded')!=='true'){
    await toggle.click();await p.page.waitForFunction(()=>document.getElementById('sidebar').getBoundingClientRect().left>=-1);
  }
}
async function nodeView(p){
  await menu(p);
  await p.page.locator('#navRelay').click();
  if(p.width<=960)await p.page.waitForFunction(()=>document.getElementById('sidebar').getBoundingClientRect().right<=1);
  await p.page.locator('#relayOn').scrollIntoViewIfNeeded();
}
async function noOverflow(p){const ui=await readUI(p);assert(ui.documentWidth<=ui.width+1&&ui.bodyWidth<=ui.width+1,p.name+' has horizontal overflow');return ui;}
async function screenshot(p,kind,target='#relayOn'){
  await p.page.locator(target).scrollIntoViewIfNeeded();await sleep(350);
  const path=`${shots}-${p.name}-${kind}.png`;await p.page.screenshot({path});report.screenshots.push(path);
}
async function spawn(name,width,height){
  const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM||'/tmp/browser-llm-browsers/chromium-1243/chrome-linux64/chrome',
    args:['--no-sandbox'],env:{...process.env,XDG_CONFIG_HOME:'/tmp/cypher-mesh-ui-chrome-config',XDG_CACHE_HOME:'/tmp/cypher-mesh-ui-chrome-cache'}});
  const p={name,width,browser,sessionPOSTs:0};participants.push(p);
  p.context=await browser.newContext({viewport:{width,height},hasTouch:width===390,isMobile:width===390});p.page=await p.context.newPage();
  p.page.on('request',request=>{if(request.method()==='POST'&&new URL(request.url()).pathname==='/relay/v1/mesh/sessions')p.sessionPOSTs++;});
  p.page.on('pageerror',error=>report.pageErrors.push({browser:name,message:sanitize(error.message)}));
  const cdp=await browser.newBrowserCDPSession(),info=await cdp.send('SystemInfo.getProcessInfo');
  const browserPID=info.processInfo.find(row=>row.type==='browser')?.id;await cdp.detach();
  report.participants[name]={browserPID,viewport:{width,height}};
  const response=await p.page.goto(origin,{waitUntil:'domcontentloaded',timeout:30000});
  assert.equal(response?.status(),200,'Public page must load successfully');
  report.participants[name].publicPage={httpStatus:response.status(),server:response.headers().server||null,
    cloudflareColo:response.headers()['cf-ray']?.split('-').at(-1)||null};
  await p.page.waitForFunction(()=>typeof document.getElementById('relayOn')?.onclick==='function'&&typeof document.getElementById('navRelay')?.onclick==='function');
  await nodeView(p);
  const ui=await noOverflow(p);assert.equal(ui.state,'OFF');assert.equal(ui.commonCount,0);assert.equal(ui.peerCount,0);assert.equal(ui.circuitCount,0);
  assert.equal(ui.mapTitle,'YOUR BROWSER CONNECTIONS · LIVE','The map states its local browser connection scope');
  assert.equal(p.sessionPOSTs,0,'Loading the actual page must not auto-join');assert.equal(ui.visibility,'visible');
  assert.equal(ui.map.nodes.length,0);assert.equal(ui.map.events,0);assert.equal(ui.map.pulses,0);
  return p;
}
async function off(p){
  if(p.page.isClosed())return;
  await nodeView(p);
  if(await p.page.locator('#relayOff').isEnabled())await p.page.locator('#relayOff').click();
  await waitFor(p.name+' Node OFF',async()=>{const ui=await readUI(p);return ui.state==='OFF'&&ui.commonCount===0&&ui.peerCount===0&&ui.circuitCount===0;},15000);
}
async function reloadPublicPage(p){
  // Retry only transport-level navigation failures after explicit OFF. Each
  // attempt is an ordinary page load; runtime assertions are never retried.
  for(let attempt=0;attempt<3;attempt++){
    try{
      const response=attempt===0?await p.page.reload({waitUntil:'domcontentloaded',timeout:30000}):
        await p.page.goto(origin,{waitUntil:'domcontentloaded',timeout:30000});
      assert.equal(response?.status(),200,'Reloaded public page must return HTTP200');
      await p.page.waitForFunction(()=>typeof document.getElementById('relayOn')?.onclick==='function'&&typeof document.getElementById('navRelay')?.onclick==='function');
      return;
    }catch(error){
      if(attempt===2||!/net::ERR_(CONNECTION_CLOSED|CONNECTION_RESET|NETWORK_CHANGED|TIMED_OUT)\b/.test(error.message))throw error;
      report.navigationRetries.push({browser:p.name,attempt:attempt+1,message:sanitize(error.message)});await sleep(700);
    }
  }
}

try{
  await save();const desktop=await spawn('desktop',1440,900),mobile=await spawn('mobile',390,844);
  assert.notEqual(report.participants.desktop.browserPID,report.participants.mobile.browserPID,'Participants must have independent browser processes');
  await checkpoint('Two independent public UI pages initially OFF with no admission and no horizontal overflow');
  await desktop.page.locator('#relayOn').click();
  await waitFor('Desktop has an actual Common connection',async()=>(await readUI(desktop)).commonCount>=1);
  await mobile.page.locator('#relayOn').click();
  await waitFor('Mobile has an actual Common connection',async()=>(await readUI(mobile)).commonCount>=1);
  await waitFor('Both UI pages show connected browser peers and growing hop ACKs',async()=>{
    const [left,right]=await Promise.all([readUI(desktop),readUI(mobile)]);
    return left.commonCount>=1&&right.commonCount>=1&&left.peerCount>0&&right.peerCount>0&&left.receiptCount>0&&right.receiptCount>0;
  },150000);
  if(expectedCommons)await waitFor(`Both UI pages show ${expectedCommons} actual Common connections`,async()=>{
    const readings=await Promise.all([readUI(desktop),readUI(mobile)]);return readings.every(ui=>ui.commonCount===expectedCommons);
  });
  const active=await Promise.all([noOverflow(desktop),noOverflow(mobile)]);
  report.active={desktop:active[0],mobile:active[1]};
  for(const ui of active)assert.match(ui.circuitHint,/^Open across Common links · \d+ opening$/,'Open circuits and pending opens are described separately');
  if(expectedCapacity){
    for(const ui of active){
      assert.match(ui.connectionLimits,/Browser peer limit: 20\b/,'Browser RTC neighbor limit appears in connection details');
      assert.match(ui.connectionLimits,/Common attachment limit: 20\b/,'Common attachment limit appears in connection details');
      assert.match(ui.connectionLimits,/Shared browser circuit policy: 40 total across all Common links and browser peers/);
      assert.equal(Number(ui.connectionLimits.match(/Endpoint circuit limit: (\d+)\b/)?.[1]),expectedCapacity,'Connection details show the applied endpoint circuit limit');
      const shared=ui.connectionLimits.match(/Common shares (\d+) circuits across up to (\d+) sessions/);
      assert(shared,'Connection details explicitly describe shared Common capacity');
      assert.equal(Number(shared[1]),expectedCapacity,'Shared Common circuit limit matches expected capacity');
      assert.equal(Number(shared[2]),80,'Common capacity is explicitly shared across up to 80 sessions');
      assert(ui.circuitCount<=expectedCapacity,'The open circuit count stays within its separately displayed bound');
    }
    await checkpoint('Desktop/mobile primary counters show actual integers; connection details separately show applied limits and shared Common capacity',{expectedCapacity});
  }
  await checkpoint('Actual UI Common connections, browser peers and ACK counters increased from initial zero',{
    desktopACK:active[0].receiptCount,mobileACK:active[1].receiptCount,
    assignments:active.map(ui=>ui.sourceIds),locations:active.map(ui=>ui.location),
    geoValidation:active.every(ui=>ui.location&&ui.location!=='unknown')?'Provider country labels visible':'NOT_AVAILABLE for unknown provider country; no coordinates invented'});
  for(const p of participants){
    await p.page.locator('#relayMap').scrollIntoViewIfNeeded();
    await waitFor(p.name+' real map transfer animation',async()=>{const ui=await readUI(p);return ui.map.events>0&&ui.map.pulses>0;},45000);
    const before=await readUI(p),pixelsBefore=await p.page.locator('#relayMap').evaluate(canvas=>canvas.toDataURL());
    assert.equal(before.map.nodes.length,before.peerCount+1,'Every connected browser plus self is visibly represented');
    assert.equal(before.map.known+before.map.unknown,before.map.nodes.length);
    assert(before.map.nodes.every(n=>Number.isFinite(n.x)&&Number.isFinite(n.y)));
    for(const node of before.map.nodes){
      if(node.located)assert(node.anchor&&Math.hypot(node.x-node.anchor.x,node.y-node.anchor.y)<=40,'Actual provider-country pins stay near their projected anchors');
      else assert.equal(node.anchor,null,'An actual unlocated participant has no geographic anchor');
    }
    assert(before.map.nodes.filter(n=>!n.located).every(n=>/unavailable/i.test(n.countryLabel)),'Unlocated actual participants receive no fabricated country label');
    await sleep(160);const after=await readUI(p),pixelsAfter=await p.page.locator('#relayMap').evaluate(canvas=>canvas.toDataURL());
    assert(after.map.frames>before.map.frames,'Actual transfer advances map drawing');
    assert.notEqual(pixelsAfter,pixelsBefore,'Actual transfer changes rendered canvas pixels');
    report.participants[p.name].mapActivity={before:before.map,after:after.map,
      pixelHashes:[pixelsBefore,pixelsAfter].map(value=>createHash('sha256').update(value).digest('hex')),
      syntheticCoordinates:false,syntheticEvents:false};
    await screenshot(p,'map-actual-activity','#relayMap');
  }
  await checkpoint('Actual received/sent/ACK events animate map pixels; every connected browser is represented without invented country coordinates');
  for(const p of participants){await screenshot(p,'active');await screenshot(p,'metrics','#relayCommonPeers');}
  await checkpoint('Desktop1440 and mobile390 active UI screenshots saved with no horizontal overflow');
  await off(desktop);await off(mobile);
  const counts=participants.map(p=>p.sessionPOSTs);
  const offMapCounts=(await Promise.all(participants.map(readUI))).map(ui=>ui.map.events);
  for(const p of participants){
    await menu(p);
    await p.page.locator('#navHome').click();await nodeView(p);
  }
  await sleep(16000); // Covers the normal reconnect delay after an explicit OFF.
  for(let index=0;index<participants.length;index++){
    const p=participants[index],ui=await noOverflow(p);
    assert.equal(ui.state,'OFF');assert.equal(ui.commonCount,0);assert.equal(ui.peerCount,0);assert.equal(ui.circuitCount,0);assert.equal(p.sessionPOSTs,counts[index],'OFF must cancel automatic readmission');
    assert.equal(ui.map.nodes.length,0);assert.equal(ui.map.pulses,0);assert.equal(ui.map.events,offMapCounts[index],'OFF ignores late traffic without map activity');
    await screenshot(p,'off');await reloadPublicPage(p);await nodeView(p);
  }
  await sleep(4000);
  for(let index=0;index<participants.length;index++){
    const p=participants[index],ui=await noOverflow(p);
    assert.equal(ui.state,'OFF');assert.equal(ui.commonCount,0);assert.equal(ui.peerCount,0);assert.equal(ui.circuitCount,0);assert.equal(p.sessionPOSTs,counts[index],'Reload must not auto-join');
  }
  await checkpoint('Owned Node OFF shows zero actual Common connections, browser peers and open circuits; Home navigation and reload do not restart participation');
  assert.equal(report.pageErrors.length,0,'Public pages must have no uncaught JavaScript errors');report.status='PASS';
}catch(error){report.status='FAIL';report.error=sanitize(error.message);process.exitCode=1;}
finally{
  // No global/native cleanup: only the two browser pages created by this script.
  for(const p of participants){
    try{await off(p);report.cleanup.push({browser:p.name,ownedPageOFF:true});}
    catch(error){report.cleanup.push({browser:p.name,ownedPageOFF:false,reason:sanitize(error.message),browserCloseFallback:true});}
    await p.browser.close().catch(()=>{});
  }
  report.finishedAt=new Date().toISOString();await save();console.log(report.status,output);
}
