import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {once} from 'node:events';
import {mkdtemp,rm,writeFile,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes,createHmac} from 'node:crypto';
import {WebSocket,WebSocketServer} from 'ws';
import {createGateway} from '../relay/gateway.mjs';
import {validateConfig,loadConfig} from '../relay/config.mjs';
const BASE='/relay/v1/mesh',origin='https://relay.example',network={chainId:10101919,genesisHash:'0x'+'1'.repeat(64)};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function until(check){for(let n=0;n<300;n++){const result=check();if(result)return result;await sleep(5);}throw new Error('Expected fixture state not observed');}
async function fixture(t,overrides={},nodeCount=2){
  const directory=await mkdtemp(join(tmpdir(),'mesh-gateway-'));let clock=Date.now(),delay=0,fault='';
  let nativeConfig={version:1,sessionSeconds:300,renewAfterSeconds:120,maxSessions:80,maxFrameBytes:16384,nativeMaxFrameBytes:4194304,nativePeers:40,initialState:'OFF'};
  let statusValue=null,metadataDelay=0,configDelay=0;const peers=[],clients=[];
  for(let index=0;index<nodeCount;index++){
    const sessions=new Map(),records={requests:[],frames:[],pongs:[],active:0,peakActive:0},node={id:'common-'+index,nodeId:(index+2).toString(16).padStart(64,'0'),socketPath:join(directory,`node-${index}.sock`),
      enode:`enode://${(index+3).toString(16).padStart(128,'0')}@127.0.0.1:${30445+index}?discport=0`};
    const server=http.createServer(async(req,res)=>{
      records.active++;records.peakActive=Math.max(records.peakActive,records.active);res.once('close',()=>records.active--);
      records.requests.push({path:req.url,method:req.method,origin:req.headers.origin,authorization:req.headers.authorization});
      if(req.headers.origin!==origin){res.writeHead(403);res.end();return;}
      if(req.url===BASE+'/config'){if(configDelay)await sleep(configDelay);res.end(typeof nativeConfig==='string'?nativeConfig:JSON.stringify(nativeConfig));return;}
      if(metadataDelay)await sleep(metadataDelay);
      if(req.url===BASE+'/sessions'&&req.method==='POST'){
        for await(const chunk of req){};
        if(delay)await sleep(delay);const token=randomBytes(32).toString('hex'),session={token,browserId:randomBytes(16).toString('hex'),expiresAt:clock+300000,ws:null};sessions.set(token,session);
        res.writeHead(201);res.end(JSON.stringify({token,browserId:session.browserId,expiresAt:session.expiresAt}));return;
      }
      const token=req.headers.authorization?.slice(7),session=sessions.get(token);
      if(req.url===BASE+'/status'){res.end(fault==='large'?'x'.repeat(65537):JSON.stringify(statusValue??{running:true,sessions:sessions.size,circuits:0,candidates:0,receivedBytes:0,sentBytes:0,routes:[]}));return;}
      if(!session||session.expiresAt<=clock){res.writeHead(401);res.end();return;}
      if(req.url===BASE+'/renew'&&req.method==='POST'){session.expiresAt=clock+300000;res.end(JSON.stringify({expiresAt:session.expiresAt}));return;}
      if(req.url===BASE+'/sessions'&&req.method==='DELETE'){if(fault==='release-unavailable'){res.writeHead(503);res.end();return;}sessions.delete(token);session.ws?.close();res.writeHead(204);res.end();return;}
      res.writeHead(404);res.end();
    });
    const wss=new WebSocketServer({noServer:true,autoPong:false,maxPayload:16384});
    server.on('upgrade',(req,socket,head)=>{if(req.url!==BASE+'/connect'||req.headers.origin!==origin){socket.destroy();return;}wss.handleUpgrade(req,socket,head,ws=>wss.emit('connection',ws));});
    wss.on('connection',ws=>{ws.on('error',()=>{});let session=null;
      ws.on('message',(data,binary)=>{
        if(!session){const auth=JSON.parse(data);session=sessions.get(auth.token);if(!session||session.ws){ws.close(1008);return;}session.ws=ws;
          const payload={version:1,network,enode:fault==='pin'?node.enode.replace(node.enode.slice(8,136), '55'.repeat(64)):fault==='nat'?node.enode.replace('127.0.0.1','127.0.0.2'):node.enode,bootId:'a'.repeat(32),issuedAt:clock,expiresAt:clock+120000};
          const hello={type:'hello',session:randomBytes(16).toString('hex'),browserId:session.browserId,protocol:'cypher-browser-mesh/1',
            advertisement:{payloadBase64:Buffer.from(JSON.stringify(payload)).toString('base64'),signatureHex:'1'.repeat(130)}};
          session.hello=Buffer.from(JSON.stringify(hello,null,2)+'\n');ws.send(session.hello,{binary:false});return;}
        records.frames.push({bytes:Buffer.from(data),binary});ws.send(data,{binary:false});
      });
      ws.on('pong',data=>records.pongs.push(Buffer.from(data)));ws.on('close',()=>{if(session)sessions.delete(session.token);});
    });
    await new Promise(r=>server.listen(node.socketPath,r));peers.push({node,server,wss,sessions,records});
  }
  const config={enabled:true,origin,nativeOrigin:origin,network,nodes:peers.map(p=>p.node),limits:{maxSessions:8,maxSessionsPerClient:8,maxConnections:32,httpBytesPerSecond:1048576},...overrides};
  const gateway=createGateway({config,now:()=>clock});await gateway.listen({port:0});const endpoint=`http://127.0.0.1:${gateway.server.address().port}`;
  const request=async(path,options={})=>{const res=await fetch(endpoint+path,{...options,headers:{Origin:origin,...options.headers}});const text=await res.text();let body;try{body=JSON.parse(text);}catch{}return{status:res.status,text,body};};
  const admit=async(sourceId,headers={})=>{const response=await request(BASE+'/sessions',{method:'POST',headers:{'Content-Type':'application/json',...headers},body:JSON.stringify(sourceId?{sourceId}: {})});assert.equal(response.status,201,JSON.stringify(response.body));return response.body;};
  const auth=s=>({Authorization:'Bearer '+s.token});
  const connect=async(session,signal=false,{autoPong=true,token=session?.token,headers={}}={})=>{
    const ws=new WebSocket(endpoint.replace('http:','ws:')+BASE+(signal?'/signal':'/connect'),{origin,autoPong,headers});clients.push(ws);const messages=[],raw=[];
    ws.on('error',()=>{});ws.on('message',data=>{raw.push(Buffer.from(data));messages.push(JSON.parse(data));});await once(ws,'open');
    if(session){ws.send(JSON.stringify(signal?{type:'auth',id:session.id,token}:{token}));await until(()=>messages.find(m=>m.type===(signal?'ready':'hello')));}
    return{ws,messages,raw,wait:predicate=>until(()=>messages.find(predicate))};
  };
  t.after(async()=>{clients.forEach(ws=>ws.terminate());await gateway.close();for(const peer of peers){for(const ws of peer.wss.clients)ws.terminate();await new Promise(r=>peer.wss.close(r));await new Promise(r=>peer.server.close(r));}await rm(directory,{recursive:true,force:true});});
  return{gateway,config,endpoint,request,admit,auth,connect,peers,directory,advance:ms=>clock+=ms,setDelay:ms=>delay=ms,setFault:value=>fault=value,setNativeConfig:value=>nativeConfig=value,setStatus:value=>statusValue=value,setMetadataDelay:value=>metadataDelay=value,setConfigDelay:value=>configDelay=value};
}

test('mesh admission is disabled by default and operator pins are bounded',async t=>{
  const f=await fixture(t,{enabled:false});assert.equal((await f.request(BASE+'/config')).body.enabled,false);
  assert.equal((await f.request(BASE+'/sessions',{method:'POST',body:'{}'})).status,503);
  assert.throws(()=>validateConfig({...f.config,enabled:true,limits:{}}),/explicit/);
  assert.throws(()=>validateConfig({...f.config,listenHost:'0.0.0.0'}),/loopback/);
  assert.throws(()=>validateConfig({...f.config,nodes:[{...f.config.nodes[0],nodeId:'1'.repeat(128)}]}),/identity/);
  assert.throws(()=>validateConfig({...f.config,nodes:[{...f.config.nodes[0],enode:f.config.nodes[0].enode.replace('127.0.0.1','private.example')}]}),/numeric/);
  assert.throws(()=>validateConfig({...f.config,sources:[]}),/configuration/);
});
test('public config contains Common pins but no Unix path, token or TURN secret',async t=>{
  const f=await fixture(t),reply=await f.request(BASE+'/config');assert.equal(reply.status,200);assert.equal(reply.body.protocol,'cypher-browser-mesh/1');
  assert.equal(reply.body.connectPath,BASE+'/connect');assert.equal(reply.body.nodes.length,2);assert.equal(reply.text.includes('socketPath'),false);assert.equal(f.gateway.stats().sessions,0);
  const path=join(f.directory,'config.json');await writeFile(path,JSON.stringify(f.config));const loaded=await loadConfig(path);assert.equal(loaded.nodes.length,2);
  const entrypoint=createGateway({config:loaded});await entrypoint.close();
  await writeFile(path,'{"enabled":true,"enabled":false}');await assert.rejects(loadConfig(path));const link=join(f.directory,'link');await symlink(path,link);await assert.rejects(loadConfig(link),/Linked/);
});
test('Origin, bearer and allowlisted source enforce admission with no URL or old owner API',async t=>{
  const f=await fixture(t);
  assert.equal((await f.request(BASE+'/sessions',{method:'POST',headers:{Origin:'https://evil.example'},body:'{}'})).status,403);
  assert.equal((await f.request(BASE+'/sessions',{method:'POST',body:'{"sourceId":"https://evil.example"}'})).status,400);
  for(const path of ['/relay/v1/head','/relay/v1/headers/'+'f'.repeat(64),'/relay/v1/source-config','/relay/v1/sessions'])assert.equal((await f.request(path)).status,404);
  assert.equal((await f.request(BASE+'/status')).status,401);assert.equal((await f.request(BASE+'/status?token=secret')).status,400);
});
test('round-robin assigns fixed Commons and native secret is never returned',async t=>{
  const f=await fixture(t),a=await f.admit(),b=await f.admit(),c=await f.admit();assert.deepEqual([a.sourceId,b.sourceId,c.sourceId],['common-0','common-1','common-0']);
  for(const app of[a,b,c]){const native=[...f.peers.find(p=>p.node.id===app.sourceId).sessions.values()].find(n=>n.browserId===app.browserId);assert.ok(native);assert.notEqual(app.token,native.token);assert.equal(JSON.stringify(app).includes(native.token),false);}
  const chosen=await f.admit('common-1');assert.equal(chosen.sourceId,'common-1');assert.equal(chosen.role,undefined);
});
test('actual Unix WebSocket preserves native hello and native frame bytes in both directions',async t=>{
  const f=await fixture(t),a=await f.admit(),connection=await f.connect(a),native=[...f.peers[0].sessions.values()][0];
  assert.deepEqual(connection.raw[0],native.hello);
  const payload=' {"type":"data","session":"'+'b'.repeat(32)+'","circuitId":"'+'c'.repeat(32)+'","seq":1,"data":"AAEC"} \n';
  connection.ws.send(payload);await connection.wait(m=>m.type==='data');assert.equal(f.peers[0].records.frames[0].bytes.toString(),payload);assert.equal(connection.raw[1].toString(),payload);
  assert.equal(f.peers[1].records.frames.length,0,'Proxy never routes the Common frame to another Common');
});
test('native identity mismatch revokes the browser session',async t=>{
  const f=await fixture(t);f.setFault('pin');const a=await f.admit(),connection=await f.connect(null);connection.ws.send(JSON.stringify({token:a.token}));await once(connection.ws,'close');assert.equal(f.gateway.stats().sessions,0);
});
test('native connect authenticates its first message, rejects query tokens and duplicate attachment',async t=>{
  const f=await fixture(t),a=await f.admit(),good=await f.connect(a);
  const extra=await f.connect(null);extra.ws.send(JSON.stringify({token:a.token}));await once(extra.ws,'close');assert.equal(good.ws.readyState,1);
  const unauthorized=await f.connect(null);unauthorized.ws.send('{"type":"data"}');await once(unauthorized.ws,'close');
  const bad=new WebSocket(f.endpoint.replace('http:','ws:')+BASE+'/connect?token='+a.token,{origin});bad.on('error',()=>{});await once(bad,'unexpected-response').then(([,res])=>assert.equal(res.statusCode,403));bad.terminate();
});
test('native close invalidates app lease and signaling; reconnect requires a new POST',async t=>{
  const f=await fixture(t),a=await f.admit(),front=await f.connect(a),signal=await f.connect(a,true),native=[...f.peers[0].sessions.values()][0];
  const closed=once(signal.ws,'close');native.ws.close();await closed;await until(()=>f.gateway.stats().sessions===0);
  assert.equal((await f.request(BASE+'/renew',{method:'POST',headers:f.auth(a)})).status,401);const next=await f.admit('common-0');assert.notEqual(next.browserId,a.browserId);assert.notEqual(next.token,a.token);
});
test('native Ping waits for browser Pong, and withheld Pong is never masked by proxy autopong',async t=>{
  const f=await fixture(t),a=await f.admit(),front=await f.connect(a),native=[...f.peers[0].sessions.values()][0];native.ws.ping('live');await until(()=>f.peers[0].records.pongs.length===1);assert.equal(f.peers[0].records.pongs[0].toString(),'live');front.ws.close();await until(()=>f.gateway.stats().sessions===0);
  const b=await f.admit('common-0'),silent=await f.connect(b,false,{autoPong:false}),second=[...f.peers[0].sessions.values()][0];second.ws.ping('no-browser-pong');await sleep(30);assert.equal(f.peers[0].records.pongs.length,1);
  const ended=once(silent.ws,'close');f.advance(15001);f.gateway.sweep();await ended;assert.equal(f.gateway.stats().sessions,0);
});
test('pending POST abandoned by browser deletes the newborn native lease',async t=>{
  const f=await fixture(t);f.setDelay(100);const req=http.request(f.endpoint+BASE+'/sessions',{method:'POST',headers:{Origin:origin,'Content-Type':'application/json'} });req.on('error',()=>{});req.end('{}');await sleep(25);req.destroy();
  await until(()=>f.peers[0].records.requests.some(r=>r.method==='DELETE'));assert.equal(f.peers[0].sessions.size,0);assert.equal(f.gateway.stats().sessions,0);
});
test('renew and OFF propagate native bearer privately and refresh TURN credentials',async t=>{
  const dir=await mkdtemp(join(tmpdir(),'mesh-turn-')),secretPath=join(dir,'secret'),secret='a'.repeat(64);await writeFile(secretPath,secret,{mode:0o600});t.after(()=>rm(dir,{recursive:true,force:true}));
  const f=await fixture(t,{turn:{urls:['turn:turn.example:34790?transport=udp'],secretPath,ttlSeconds:300}}),a=await f.admit();const config=await f.request(BASE+'/config');assert.equal(config.body.turnEnabled,true);assert.equal(config.text.includes('credential'),false);assert.equal(config.text.includes(secretPath),false);
  const ice=a.iceServers[0];assert.equal(ice.credential,createHmac('sha1',secret).update(ice.username).digest('base64'));
  f.advance(120000);const renewed=await f.request(BASE+'/renew',{method:'POST',headers:f.auth(a)});assert.equal(renewed.status,200);assert.ok(renewed.body.expiresAt>a.expiresAt);assert.notEqual(renewed.body.iceServers[0].credential,ice.credential);
  assert.equal((await f.request(BASE+'/sessions',{method:'DELETE',headers:f.auth(a)})).status,204);assert.equal(f.peers[0].sessions.size,0);assert.equal(f.gateway.stats().sessions,0);
});
test('bounded native responses and frames stop abusive sources or clients',async t=>{
  const f=await fixture(t),a=await f.admit();f.setFault('large');assert.equal((await f.request(BASE+'/status',{headers:f.auth(a)})).status,502);f.setFault('');
  const front=await f.connect(a);front.ws.send('x'.repeat(16385));assert.equal((await once(front.ws,'close'))[0],1009);await until(()=>f.gateway.stats().sessions===0);
  const b=await f.admit('common-1'),signal=await f.connect(b,true);signal.ws.send('x'.repeat(32769));assert.equal((await once(signal.ws,'close'))[0],1009);
});
test('peer signaling prefers another Common and enforces assigned pairs, ICE caps and no token forwarding',async t=>{
  const f=await fixture(t),a=await f.admit(),b=await f.admit(),left=await f.connect(a,true),right=await f.connect(b,true);await left.wait(m=>m.type==='peers'&&m.peers.length===1);
  const peer=left.messages.filter(m=>m.type==='peers').at(-1).peers[0];assert.equal(peer.sourceId,b.sourceId);assert.equal(peer.browserId,b.browserId);
  for(let round=0;round<2;round++){f.advance(1000);left.ws.send(JSON.stringify({type:'offer',to:b.peerId,sdp:'v=0\r\n'+round}));await right.wait(m=>m.type==='offer'&&m.sdp.endsWith(String(round)));
    for(let n=0;n<40;n++){if(n%5===0)f.advance(1000);const candidate=`candidate:${round}:${n}`;right.ws.send(JSON.stringify({type:'ice',to:a.peerId,candidate:{candidate}}));await left.wait(m=>m.type==='ice'&&m.candidate.candidate===candidate);}}
  assert.equal(right.ws.readyState,1);assert.ok(left.messages.every(m=>m.token===undefined));
  left.ws.send(JSON.stringify({type:'offer',to:'f'.repeat(32),sdp:'v=0'}));assert.equal((await once(left.ws,'close'))[0],1008);
});
test('per-client concurrent admission reservations, aggregate quota and proxy metadata remain bounded',async t=>{
  const limits={maxSessions:8,maxSessionsPerClient:1,maxConnections:32,httpBytesPerSecond:1048576};const f=await fixture(t,{limits,trustedClientIpHeader:'x-relay-client-ip',trustedCountryHeader:'x-relay-country'});
  const a=await f.admit(undefined,{'x-relay-client-ip':'203.0.113.1','x-relay-country':'JP'});assert.equal(a.geo.countryCode,'JP');assert.equal(JSON.stringify(a).includes('203.0.113.1'),false);
  assert.equal((await f.request(BASE+'/sessions',{method:'POST',headers:{'x-relay-client-ip':'203.0.113.1'},body:'{}'})).status,429);const b=await f.admit(undefined,{'x-relay-client-ip':'203.0.113.2'});assert.notEqual(b.id,a.id);
  const trusted=await fetch(f.endpoint+BASE+'/status',{headers:{...f.auth(a),'Sec-Fetch-Site':'same-origin'}});assert.equal(trusted.status,200);
  assert.equal((await fetch(f.endpoint+BASE+'/status',{headers:f.auth(a)})).status,403);
});
test('duplicate JSON, extra fields, body limits and expired session revival are rejected',async t=>{
  const f=await fixture(t);
  for(const body of['{"sourceId":"common-0","sourceId":"common-1"}','{"userApproved":true}','{"url":"http://private"}'])assert.equal((await f.request(BASE+'/sessions',{method:'POST',body})).status,400);
  assert.equal((await f.request(BASE+'/sessions',{method:'POST',body:'x'.repeat(1025)})).status,413);
  const a=await f.admit();f.advance(300001);f.gateway.sweep();assert.equal((await f.request(BASE+'/renew',{method:'POST',headers:f.auth(a)})).status,401);
});

test('native payload counts both directions against the ON quota, and renewal does not reset it',async t=>{
  const f=await fixture(t,{limits:{maxSessions:8,maxSessionsPerClient:8,maxConnections:32,httpBytesPerSecond:1048576,maxSessionTransferBytes:1048576}});
  const a=await f.admit(),front=await f.connect(a),native=[...f.peers[0].sessions.values()][0];
  const before=(await f.request(BASE+'/status',{headers:f.auth(a)})).body.session.transferredBytes;
  assert.equal((await f.request(BASE+'/renew',{method:'POST',headers:f.auth(a)})).status,200);
  const after=(await f.request(BASE+'/status',{headers:f.auth(a)})).body.session.transferredBytes;assert.ok(after>before);
  const closed=once(front.ws,'close');
  for(let index=0;index<150&&front.ws.readyState===1;index++){
    f.advance(1000);front.ws.send(JSON.stringify({type:'data',session:'b'.repeat(32),circuitId:'c'.repeat(32),seq:index+1,data:'A'.repeat(8000)}));await sleep(4);
  }
  await closed;assert.equal(f.gateway.stats().sessions,0);await until(()=>f.peers[0].sessions.size===0);assert.ok(f.peers[0].records.frames.length<100);
});

test('a new native lease is released when the initial public session response has no bandwidth budget',async t=>{
  const f=await fixture(t,{limits:{maxSessions:8,maxSessionsPerClient:8,maxConnections:32,httpBytesPerSecond:4096}});
  // Freeze fixture time and exhaust shared egress with public metadata; no browser receives a token for a failed POST.
  for(let index=0;index<60;index++){
    const response=await f.request(BASE+'/config');if(response.status===429)break;
  }
  let issued=0,failed=false;
  for(let index=0;index<4;index++){
    const response=await f.request(BASE+'/sessions',{method:'POST',body:'{}'});
    if(response.status===201)issued++;
    if(response.status===429&&response.body.error.code==='bandwidth_capacity'){failed=true;break;}
  }
  assert.equal(failed,true,'Fixture reaches response-bandwidth failure after native session creation');
  await until(()=>f.peers.reduce((count,p)=>count+p.sessions.size,0)===issued);
  assert.equal(f.gateway.stats().sessions,issued,'No unreachable lease is retained without a returned opaque token');
});

test('authenticated diagnostics distinguish upstream close from withheld browser Pong using fixed counters only',async t=>{
  const f=await fixture(t),a=await f.admit(),first=await f.connect(a);
  const firstClosed=once(first.ws,'close');[...f.peers[0].sessions.values()][0].ws.close();await firstClosed;
  assert.equal(f.gateway.stats().dropReasons.upstream_closed,1);
  const b=await f.admit('common-0'),silent=await f.connect(b,false,{autoPong:false});
  [...f.peers[0].sessions.values()][0].ws.ping('deadline');await sleep(25);
  const secondClosed=once(silent.ws,'close');f.advance(15001);f.gateway.sweep();await secondClosed;
  const c=await f.admit(),status=await f.request(BASE+'/status',{headers:f.auth(c)});
  assert.equal(status.status,200);assert.equal(status.body.gateway.dropReasons.upstream_closed,1);assert.equal(status.body.gateway.dropReasons.pong_timeout,1);
  assert.ok(Object.values(status.body.gateway.dropReasons).every(value=>Number.isSafeInteger(value)&&value>=0));
  assert.equal(JSON.stringify(status.body.gateway).includes(c.token),false);
  const snapshot=f.gateway.stats();snapshot.dropReasons.upstream_closed=999;
  assert.equal(f.gateway.stats().dropReasons.upstream_closed,1,'Returned counters cannot mutate gateway state');
});

const expandedLimits={maxSessions:160,maxSessionsPerClient:80,maxConnections:384,httpBytesPerSecond:1048576};
const clientIP=index=>({'x-relay-client-ip':`198.51.${Math.floor(index/250)}.${index%250+1}`});
const nativeProfile=(maxSessions=80,nativePeers=40)=>({version:1,sessionSeconds:300,renewAfterSeconds:120,maxSessions,maxFrameBytes:16384,nativeMaxFrameBytes:4194304,nativePeers,initialState:'OFF'});
const capacityFixture=t=>fixture(t,{limits:expandedLimits,trustedClientIpHeader:'x-relay-client-ip'});

test('expanded capacity preserves resource budgets and reserves both browser sockets plus metadata',async t=>{
  const f=await capacityFixture(t),config=(await f.request(BASE+'/config')).body;
  assert.equal(config.limits.maxSessions,160);assert.equal(config.limits.maxConnections,384);assert.equal(config.limits.maxSessionsPerClient,80);
  assert.equal(config.limits.maxPeers,20);assert.equal(config.limits.maxCommonConnections,20);assert.equal(config.limits.maxSessionsPerCommon,80);
  assert.equal(config.limits.sessionBytesPerSecond,65536);assert.equal(config.limits.maxNativeFrameBytes,16384);
  assert.equal(config.limits.maxNativeBufferedBytes,65536);assert.equal(config.limits.maxNativeResponseBytes,16384);assert.equal(config.limits.maxNativeStatusBytes,65536);
  assert.throws(()=>validateConfig({...f.config,limits:{...expandedLimits,maxConnections:320}}),/two sockets/);
  assert.throws(()=>validateConfig({...f.config,limits:{...expandedLimits,maxSessions:161}}),/registered Common/);
  assert.throws(()=>validateConfig({...f.config,limits:{...expandedLimits,maxPeers:40}}),/peer capacity/);
  assert.throws(()=>validateConfig({...f.config,limits:{...expandedLimits,maxPeers:21}}),/peer capacity/);
  assert.throws(()=>validateConfig({...f.config,limits:{...expandedLimits,maxCommonConnections:21}}),/Common attachment capacity/);
  assert.throws(()=>validateConfig({...f.config,limits:{...expandedLimits,maxSessionsPerClient:81}}),/client session capacity/);
  assert.equal(validateConfig({...f.config,limits:{...expandedLimits,maxPeers:1,maxCommonConnections:1}}).limits.maxPeers,1);
  const nodes=Array.from({length:64},(_,i)=>({...f.config.nodes[0],id:`common-${i}`,nodeId:(i+1).toString(16).padStart(64,'0'),socketPath:`/tmp/mesh-cap-${i}.sock`}));
  assert.equal(validateConfig({...f.config,nodes}).nodes.length,64);
  assert.throws(()=>validateConfig({...f.config,nodes:[...nodes,{...nodes[0],id:'overflow'}]}),/Common node pins/);
});

test('per-Common admission accepts 80, rejects 81 and reuses a released slot',async t=>{
  const f=await capacityFixture(t),sessions=[];
  for(let index=0;index<80;index++){f.advance(1000);sessions.push(await f.admit('common-0',clientIP(index)));}
  assert.equal(f.gateway.stats().nodes['common-0'].sessions,80);assert.equal(f.peers[0].sessions.size,80);
  const denied=await f.request(BASE+'/sessions',{method:'POST',headers:clientIP(81),body:'{"sourceId":"common-0"}'});
  assert.equal(denied.status,503);assert.equal(denied.body.error.code,'native_capacity');
  assert.equal((await f.request(BASE+'/sessions',{method:'DELETE',headers:{...f.auth(sessions[0]),...clientIP(0)}})).status,204);
  const replacement=await f.admit('common-0',clientIP(82));assert.notEqual(replacement.id,sessions[0].id);
  assert.equal(f.peers[0].sessions.size,80);assert.equal(f.gateway.stats().nodes['common-0'].pending,0);
  assert.deepEqual(replacement.nativeLimits,{maxSessions:80,nativePeers:40,circuits:40,circuitsPerSession:40,pendingInbound:4,pendingOutbound:4});
});

test('160 global leases include pending reservations and support 320 simultaneous browser sockets',async t=>{
  const f=await capacityFixture(t),sessions=[];
  for(let index=0;index<152;index++){f.advance(1000);sessions.push(await f.admit(undefined,clientIP(index)));}
  f.setDelay(100);
  const pending=Array.from({length:16},(_,i)=>f.request(BASE+'/sessions',{method:'POST',headers:clientIP(152+i),body:'{}'}));
  await until(()=>f.gateway.stats().pendingAdmissions===8);const snapshot=f.gateway.stats();
  assert.equal(snapshot.sessions+snapshot.pendingAdmissions,160);assert.ok(Object.values(snapshot.nodes).every(n=>n.sessions+n.pending<=80));
  const results=await Promise.all(pending);assert.equal(results.filter(r=>r.status===201).length,8);assert.equal(results.filter(r=>r.body?.error?.code==='session_capacity').length,8);
  sessions.push(...results.filter(r=>r.status===201).map(r=>r.body));f.setDelay(0);
  assert.equal(f.gateway.stats().sessions,160);assert.equal(f.gateway.stats().pendingAdmissions,0);assert.deepEqual(f.peers.map(p=>p.sessions.size),[80,80]);
  // Distinct trusted proxy client metadata matches the independent clients used for admission.
  for(let index=0;index<sessions.length;index++){
    f.advance(50);await f.connect(sessions[index],false,{headers:clientIP(index)});
    f.advance(50);await f.connect(sessions[index],true,{headers:clientIP(index)});
  }
  assert.equal(f.gateway.stats().webSockets,320);assert.equal(f.gateway.stats().sessions,160);
  assert.ok(f.gateway.stats().connections>=320&&f.gateway.stats().connections<=384);
  for(const peer of f.peers){assert.equal(peer.wss.clients.size,80);assert.ok(peer.records.peakActive<=8);}
});

test('native admission pacing stays one per second with a burst of eight at expanded capacity',async t=>{
  const f=await capacityFixture(t);
  for(let index=0;index<8;index++)await f.admit('common-0',clientIP(index));
  const attempt=index=>f.request(BASE+'/sessions',{method:'POST',headers:clientIP(index),body:'{"sourceId":"common-0"}'});
  assert.equal((await attempt(9)).body.error.code,'native_admission_rate');f.advance(999);
  assert.equal((await attempt(10)).body.error.code,'native_admission_rate');f.advance(1);
  assert.equal((await attempt(11)).status,201);assert.equal(f.peers[0].records.requests.filter(r=>r.path===BASE+'/sessions'&&r.method==='POST').length,9);
  assert.equal(f.gateway.stats().pendingAdmissions,0);
});

test('live native capability checks honor legacy limits and refresh safely after upgrade',async t=>{
  const f=await capacityFixture(t);f.setNativeConfig(nativeProfile(8,4));let first;
  for(let index=0;index<8;index++){f.advance(1000);first=await f.admit('common-0',clientIP(index));}
  assert.equal(first.nativeLimits.circuitsPerSession,2);assert.equal(first.nativeLimits.circuits,8);
  assert.equal((await f.request(BASE+'/sessions',{method:'POST',headers:clientIP(10),body:'{"sourceId":"common-0"}'})).body.error.code,'native_capacity');
  f.setNativeConfig(nativeProfile());f.advance(30001);const expanded=await f.admit('common-0',clientIP(11));
  assert.equal(expanded.nativeLimits.circuitsPerSession,40);assert.equal(expanded.nativeLimits.maxSessions,80);
  assert.equal(f.peers[0].records.requests.filter(r=>r.path===BASE+'/config').length,2);
});

test('unknown, malformed and duplicate-key native capability profiles fail before issuing any lease',async t=>{
  const f=await capacityFixture(t);
  const invalid=[nativeProfile(80,4),nativeProfile(81,40),{...nativeProfile(),maxFrameBytes:32768},{...nativeProfile(),version:2},JSON.stringify(nativeProfile()).replace('"version":1','"version":1,"version":1')];
  for(let index=0;index<invalid.length;index++){
    f.setNativeConfig(invalid[index]);f.advance(1000);
    const reply=await f.request(BASE+'/sessions',{method:'POST',headers:clientIP(index),body:'{"sourceId":"common-0"}'});assert.equal(reply.status,502);
  }
  assert.equal(f.peers[0].sessions.size,0);assert.equal(f.gateway.stats().pendingAdmissions,0);assert.equal(f.gateway.stats().nodes['common-0'].metadata,0);
});

function fullStatus(){
  return {running:true,sessions:80,circuits:40,candidates:64,receivedBytes:Number.MAX_SAFE_INTEGER,sentBytes:Number.MAX_SAFE_INTEGER,
    routes:Array.from({length:40},(_,index)=>({circuitId:(index+1).toString(16).padStart(32,'0'),remoteId:'a'.repeat(64),sessionId:'b'.repeat(32),relayIds:Array.from({length:4},(_,hop)=>String(hop)+'x'.repeat(63))}))};
}
test('40 maximum-length routes exceed 16 KiB but fit bounded status metadata and remain coalesced',async t=>{
  const f=await capacityFixture(t),sessions=[];for(let i=0;i<8;i++)sessions.push(await f.admit('common-0',clientIP(i)));const a=sessions[0],status=fullStatus(),size=Buffer.byteLength(JSON.stringify(status));
  assert.ok(size>16384&&size<65536);f.setStatus(status);f.setMetadataDelay(40);
  const replies=await Promise.all(sessions.map((session,index)=>f.request(BASE+'/status',{headers:{...f.auth(session),...clientIP(index)}})));
  assert.ok(replies.every(r=>r.status===200&&r.body.routes.length===40));assert.equal(f.peers[0].records.requests.filter(r=>r.path===BASE+'/status').length,1);
  assert.deepEqual(replies[0].body.nativeLimits,a.nativeLimits);assert.equal(f.gateway.stats().nodes['common-0'].metadata,0);
  f.advance(1001);f.setFault('large');assert.equal((await f.request(BASE+'/status',{headers:f.auth(a)})).body.error.code,'native_response_limit');
  f.setFault('');f.setStatus({...status,circuits:41,routes:[...status.routes,status.routes[0]]});assert.equal((await f.request(BASE+'/status',{headers:f.auth(a)})).body.error.code,'invalid_native_status');
});

test('metadata requests reserve at most eight IPC slots with no hidden keep-alive backlog',async t=>{
  const f=await capacityFixture(t),sessions=[];for(let index=0;index<9;index++){f.advance(1000);sessions.push(await f.admit('common-0',clientIP(index)));}
  f.setMetadataDelay(100);const pending=sessions.map((session,index)=>f.request(BASE+'/renew',{method:'POST',headers:{...f.auth(session),...clientIP(index)}}));
  await until(()=>f.gateway.stats().nodes['common-0'].metadata===8);const replies=await Promise.all(pending);
  assert.equal(replies.filter(r=>r.status===200).length,8);assert.equal(replies.filter(r=>r.body?.error?.code==='native_metadata_capacity').length,1);
  assert.ok(f.peers[0].records.peakActive<=8);assert.equal(f.gateway.stats().nodes['common-0'].metadata,0);
});

test('OFF revokes all local leases immediately and retries bounded native cleanup when metadata is full',async t=>{
  const f=await capacityFixture(t),sessions=[];
  for(let index=0;index<9;index++){f.advance(1000);sessions.push(await f.admit('common-0',clientIP(index)));}
  f.setMetadataDelay(100);
  const pending=sessions.map((session,index)=>f.request(BASE+'/sessions',{method:'DELETE',headers:{...f.auth(session),...clientIP(index)}}));
  await until(()=>f.gateway.stats().sessions===0);assert.ok(f.gateway.stats().nodes['common-0'].releasing<=9);
  const replies=await Promise.all(pending);assert.ok(replies.every(reply=>reply.status===204));
  assert.equal(f.gateway.stats().nodes['common-0'].releasing,1);assert.equal(f.peers[0].sessions.size,1);
  assert.equal((await f.request(BASE+'/renew',{method:'POST',headers:f.auth(sessions[8])})).status,401);
  f.advance(1001);f.gateway.sweep();await until(()=>f.gateway.stats().nodes['common-0'].releasing===0);
  assert.equal(f.peers[0].sessions.size,0);assert.ok(f.peers[0].records.peakActive<=8);
});

test('upstream restart invalidates cached capacities before the next public lease',async t=>{
  const f=await capacityFixture(t),first=await f.admit('common-0'),front=await f.connect(first),native=[...f.peers[0].sessions.values()][0];
  assert.equal(first.nativeLimits.circuitsPerSession,40);f.setNativeConfig(nativeProfile(8,4));
  const closed=once(front.ws,'close');native.ws.close();await closed;await until(()=>f.gateway.stats().sessions===0);
  const next=await f.admit('common-0');assert.equal(next.nativeLimits.circuitsPerSession,2);
  assert.equal(f.peers[0].records.requests.filter(r=>r.path===BASE+'/config').length,2);
});

test('aborted admission stops after a shared metadata read and does not probe another Common',async t=>{
  const f=await capacityFixture(t);f.setConfigDelay(100);f.setNativeConfig(nativeProfile(80,4));
  const req=http.request(f.endpoint+BASE+'/sessions',{method:'POST',headers:{Origin:origin,'Content-Type':'application/json'}});req.on('error',()=>{});req.end('{}');
  await until(()=>f.peers[0].records.requests.some(r=>r.path===BASE+'/config'));req.destroy();
  await until(()=>f.gateway.stats().pendingAdmissions===0);
  assert.equal(f.peers[0].sessions.size,0);assert.equal(f.peers[1].records.requests.length,0);
  assert.equal(f.gateway.stats().nodes['common-0'].metadata,0);
});

test('unavailable native cleanup retains capacity until acknowledgement or the actual lease deadline',async t=>{
  const f=await capacityFixture(t),first=await f.admit('common-0');f.setFault('release-unavailable');
  assert.equal((await f.request(BASE+'/sessions',{method:'DELETE',headers:f.auth(first)})).status,204);
  assert.equal(f.gateway.stats().sessions,0);assert.equal(f.gateway.stats().nodes['common-0'].releasing,1);
  f.advance(1001);f.gateway.sweep();await until(()=>f.gateway.stats().nodes['common-0'].metadata===0);
  assert.equal(f.gateway.stats().nodes['common-0'].releasing,1);
  f.setFault('');f.advance(1001);f.gateway.sweep();await until(()=>f.gateway.stats().nodes['common-0'].releasing===0);assert.equal(f.peers[0].sessions.size,0);
  const next=await f.admit('common-0');f.advance(299000);f.setFault('release-unavailable');
  assert.equal((await f.request(BASE+'/sessions',{method:'DELETE',headers:f.auth(next)})).status,204);
  assert.equal(f.gateway.stats().nodes['common-0'].releasing,1);
  f.advance(1001);f.gateway.sweep();assert.equal(f.gateway.stats().nodes['common-0'].releasing,0,'Cleanup expires at the existing lease deadline, without starting a fresh five-minute deadline');
});

const attachRequest=(f,root,sourceId,headers={})=>f.request(BASE+'/sessions',{method:'POST',headers:{...f.auth(root),...headers},body:JSON.stringify({sourceId,attach:true})});
async function attach(f,root,sourceId,headers={}){const reply=await attachRequest(f,root,sourceId,headers);assert.equal(reply.status,201,JSON.stringify(reply.body));return reply.body;}
const groupFixture=(t,overrides={})=>fixture(t,{limits:expandedLimits,...overrides},21);

test('one browser admits and connects 20 distinct Commons; attachment 21 never reaches a native source',async t=>{
  const f=await groupFixture(t),root=await f.admit('common-0'),leases=[root],signal=await f.connect(root,true);
  assert.equal(root.maxAttachments,20);
  for(let index=1;index<20;index++){f.advance(1000);const child=await attach(f,root,'common-'+index);leases.push(child);
    assert.equal(child.parentId,root.id);assert.equal(child.peerId,root.peerId);assert.notEqual(child.browserId,root.browserId);}
  const denied=await attachRequest(f,root,'common-20');assert.equal(denied.status,409);assert.equal(denied.body.error.code,'attachment_capacity');
  assert.equal(f.peers[20].records.requests.length,0);assert.equal(f.gateway.stats().sessions,20);
  assert.equal((await attachRequest(f,root,'common-1')).body.error.code,'duplicate_source');
  const connections=[];for(const lease of leases){f.advance(1000);connections.push(await f.connect(lease));}
  assert.equal(f.gateway.stats().webSockets,21);assert.ok(f.peers.slice(0,20).every(peer=>peer.wss.clients.size===1));
  const childWire=' {"type":"data","session":"'+'b'.repeat(32)+'","circuitId":"'+'c'.repeat(32)+'","seq":1,"data":"AAEC"} \n';
  connections[19].ws.send(childWire);await connections[19].wait(message=>message.type==='data');assert.equal(f.peers[19].records.frames[0].bytes.toString(),childWire);
  const childSignal=await f.connect(null,true);childSignal.ws.send(JSON.stringify({type:'auth',id:leases[1].id,token:leases[1].token}));assert.equal((await once(childSignal.ws,'close'))[0],1008);
  const status=await f.request(BASE+'/status',{headers:f.auth(root)});assert.equal(status.body.participants,1);assert.equal(status.body.leases,20);assert.equal(status.body.session.attachments,20);
  assert.equal(signal.ws.readyState,1);assert.equal(signal.messages.at(-1).peers.length,0,'Children cannot create fake browser peers');
  assert.equal((await f.request(BASE+'/sessions',{method:'DELETE',headers:f.auth(root)})).status,204);
  await until(()=>f.gateway.stats().sessions===0&&f.peers.every(peer=>peer.sessions.size===0));
  assert.ok(f.peers.every(peer=>peer.records.peakActive<=8));
});

test('attachments require root bearer, the same client, explicit source and strict body fields',async t=>{
  const f=await groupFixture(t,{trustedClientIpHeader:'x-relay-client-ip'}),headers=clientIP(1),root=await f.admit('common-0',headers);
  const request=(body,extra={})=>f.request(BASE+'/sessions',{method:'POST',headers:{...headers,...extra},body});
  assert.equal((await request('{"attach":true,"sourceId":"common-1"}')).status,401);
  assert.equal((await attachRequest(f,root,'common-1',clientIP(2))).status,403);
  for(const body of['{"attach":true}','{"attach":false,"sourceId":"common-1"}','{"attach":null,"sourceId":"common-1"}',
    '{"attach":true,"sourceId":"common-1","parentId":"'+root.id+'"}','{"attach":true,"sourceId":"common-1","token":"'+root.token+'"}',
    '{"attach":true,"attach":true,"sourceId":"common-1"}'])assert.equal((await request(body,f.auth(root))).status,400);
  assert.equal((await attachRequest(f,root,'unregistered',headers)).body.error.code,'unknown_source');
  const child=await attach(f,root,'common-1',headers);
  assert.equal((await attachRequest(f,child,'common-2',headers)).status,403);
  assert.equal(f.gateway.stats().sessions,2);assert.equal(f.peers[2].records.requests.length,0);
});

test('group source and capacity reservations include pending child admissions and root OFF cancels them',async t=>{
  const f=await groupFixture(t),root=await f.admit('common-0');
  for(let index=1;index<19;index++){f.advance(1000);await attach(f,root,'common-'+index);}
  f.advance(1000);f.setDelay(100);
  const pending=attachRequest(f,root,'common-19');await until(()=>f.gateway.stats().pendingAdmissions===1&&f.peers[19].records.requests.some(r=>r.method==='POST'));
  const duplicate=await attachRequest(f,root,'common-19');assert.equal(duplicate.body.error.code,'duplicate_source');
  const overflow=await attachRequest(f,root,'common-20');assert.equal(overflow.body.error.code,'attachment_capacity');assert.equal(f.peers[20].records.requests.length,0);
  assert.equal((await f.request(BASE+'/sessions',{method:'DELETE',headers:f.auth(root)})).status,204);
  assert.equal(f.gateway.stats().sessions,0,'Root and all established children are revoked before pending native completion');
  const cancelled=await pending;assert.equal(cancelled.status,401);assert.equal(f.gateway.stats().pendingAdmissions,0);
  await until(()=>f.peers.every(peer=>peer.sessions.size===0));assert.ok(Object.values(f.gateway.stats().nodes).every(node=>node.pending===0&&node.releasing===0));
});

test('a child renews and fails independently; root loss cascades the remaining native leases',async t=>{
  const f=await groupFixture(t),root=await f.admit('common-0'),child=await attach(f,root,'common-1'),other=await attach(f,root,'common-2');
  const rootWire=await f.connect(root),childWire=await f.connect(child),otherWire=await f.connect(other),signal=await f.connect(root,true);
  f.advance(120000);const renewal=await f.request(BASE+'/renew',{method:'POST',headers:f.auth(child)});assert.equal(renewal.status,200);assert.ok(renewal.body.expiresAt>child.expiresAt);
  assert.equal([...f.peers[0].sessions.values()][0].expiresAt,root.expiresAt,'Child renewal does not renew the root');
  const closed=once(childWire.ws,'close');[...f.peers[1].sessions.values()][0].ws.close();await closed;await until(()=>f.gateway.stats().sessions===2);
  assert.equal(rootWire.ws.readyState,1);assert.equal(otherWire.ws.readyState,1);assert.equal(signal.ws.readyState,1);
  const replacement=await attach(f,root,'common-1');assert.notEqual(replacement.id,child.id);
  const parentClosed=once(rootWire.ws,'close');[...f.peers[0].sessions.values()][0].ws.close();await parentClosed;
  await until(()=>f.gateway.stats().sessions===0&&f.peers.every(peer=>peer.sessions.size===0));
  for(const lease of [root,other,replacement])assert.equal((await f.request(BASE+'/renew',{method:'POST',headers:f.auth(lease)})).status,401);
});

test('failed and abandoned child admissions return source reservations and retain the root',async t=>{
  const f=await groupFixture(t),root=await f.admit('common-0');f.setNativeConfig(nativeProfile(81,40));
  assert.equal((await attachRequest(f,root,'common-1')).status,502);assert.equal(f.gateway.stats().pendingAdmissions,0);
  f.setNativeConfig(nativeProfile());const child=await attach(f,root,'common-1');assert.equal(child.parentId,root.id);
  f.setDelay(100);const req=http.request(f.endpoint+BASE+'/sessions',{method:'POST',headers:{Origin:origin,...f.auth(root),'Content-Type':'application/json'}});req.on('error',()=>{});req.end('{"attach":true,"sourceId":"common-2"}');
  await until(()=>f.peers[2].records.requests.some(r=>r.method==='POST'));req.destroy();
  await until(()=>f.gateway.stats().pendingAdmissions===0&&f.peers[2].records.requests.some(r=>r.method==='DELETE'));
  assert.equal(f.gateway.stats().sessions,2);assert.equal(f.peers[2].sessions.size,0);f.setDelay(0);f.advance(1000);
  assert.equal((await attach(f,root,'common-2')).parentId,root.id);
});

test('root and children share a cumulative transfer budget that survives renew and child replacement',async t=>{
  const f=await groupFixture(t,{limits:{...expandedLimits,maxSessionTransferBytes:1048576}}),root=await f.admit('common-0');let child=await attach(f,root,'common-1');
  const rootWire=await f.connect(root);let childWire=await f.connect(child);
  const before=(await f.request(BASE+'/status',{headers:f.auth(child)})).body.session.transferredBytes;
  f.advance(1000);assert.equal((await f.request(BASE+'/renew',{method:'POST',headers:f.auth(root)})).status,200);assert.equal((await f.request(BASE+'/renew',{method:'POST',headers:f.auth(child)})).status,200);
  const after=(await f.request(BASE+'/status',{headers:f.auth(root)})).body.session.transferredBytes;assert.ok(after>before);
  for(let index=0;index<10;index++){f.advance(1000);childWire.ws.send(JSON.stringify({type:'data',data:'A'.repeat(8000),seq:index}));await sleep(4);}
  const used=(await f.request(BASE+'/status',{headers:f.auth(child)})).body.session.transferredBytes;assert.ok(used>100000);
  assert.equal((await f.request(BASE+'/sessions',{method:'DELETE',headers:f.auth(child)})).status,204);
  child=await attach(f,root,'common-1');childWire=await f.connect(child);
  assert.ok((await f.request(BASE+'/status',{headers:f.auth(child)})).body.session.transferredBytes>used,'Replacing a child cannot reset group accounting');
  for(let index=0;index<150&&f.gateway.stats().sessions;index++){
    const wire=index%2?childWire:rootWire;f.advance(1000);wire.ws.send(JSON.stringify({type:'data',data:'A'.repeat(8000),seq:index}));await sleep(4);
  }
  await until(()=>f.gateway.stats().sessions===0&&f.peers.every(peer=>peer.sessions.size===0));
  const frames=f.peers.reduce((sum,peer)=>sum+peer.records.frames.length,0);assert.ok(frames>40&&frames<100,'Combined traffic consumes one 1 MiB group budget, not one per attachment');
  assert.equal(f.gateway.stats().dropReasons.transfer_limit,2);
});

test('one group shares the fixed incoming and outgoing bandwidth bursts across native attachments',async t=>{
  for(const direction of ['in','out']){
    const f=await groupFixture(t),root=await f.admit('common-0'),child=await attach(f,root,'common-1'),rootWire=await f.connect(root),childWire=await f.connect(child);
    const natives=f.peers.slice(0,2).map(peer=>[...peer.sessions.values()][0]),wires=[rootWire,childWire],payload=JSON.stringify({type:'data',data:'A'.repeat(16000)});
    // Frozen fixture clock makes the single 128 KiB burst observable. Each lease
    // individually sends less than that burst, while the combined group exceeds it.
    for(let index=0;index<12&&f.gateway.stats().sessions===2;index++){
      if(direction==='in')wires[index%2].ws.send(payload);else natives[index%2].ws.send(payload);await sleep(5);
    }
    await until(()=>f.gateway.stats().sessions<2);assert.ok(f.gateway.stats().sessions<=1);
    assert.ok(f.peers[0].records.frames.length<9&&f.peers[1].records.frames.length<9);
  }
});

test('actual signaling assigns 20 distinct browser peers and never admits a 21st neighbor',async t=>{
  const f=await groupFixture(t,{trustedClientIpHeader:'x-relay-client-ip'}),roots=[],signals=[];
  for(let index=0;index<21;index++){f.advance(1000);const root=await f.admit('common-'+index,clientIP(index));roots.push(root);signals.push(await f.connect(root,true,{headers:clientIP(index)}));}
  await until(()=>signals.every(signal=>signal.messages.filter(message=>message.type==='peers'||message.type==='ready').at(-1).peers.length===20));
  for(let index=0;index<signals.length;index++){
    const peers=signals[index].messages.filter(message=>message.type==='peers'||message.type==='ready').at(-1).peers;
    assert.equal(new Set(peers.map(peer=>peer.peerId)).size,20);assert.ok(peers.every(peer=>peer.id!==roots[index].id));
    assert.deepEqual(new Set(peers.map(peer=>peer.id)),new Set(roots.filter((_,i)=>i!==index).map(root=>root.id)));
  }
  f.advance(1000);const extra=await f.admit('common-0',clientIP(22)),extraSignal=await f.connect(extra,true,{headers:clientIP(22)});signals.push(extraSignal);await sleep(30);
  for(const signal of signals){assert.equal(signal.ws.readyState,1);const peers=signal.messages.filter(message=>message.type==='peers'||message.type==='ready').at(-1).peers;assert.equal(peers.length,20);assert.equal(new Set(peers.map(peer=>peer.peerId)).size,peers.length);}
  const left=signals[0],peer=left.messages.filter(message=>message.type==='peers'||message.type==='ready').at(-1).peers[0],right=signals[roots.findIndex(root=>root.peerId===peer.peerId)];
  f.advance(1000);left.ws.send(JSON.stringify({type:'offer',to:peer.peerId,sdp:'v=0\r\n20-peer-fixture'}));await right.wait(message=>message.type==='offer'&&message.from===roots[0].peerId);
});

test('the client quota admits four groups of 20 Commons and rejects native lease 81',async t=>{
  const f=await groupFixture(t),roots=[];
  for(let group=0;group<4;group++){
    f.advance(2000);const root=await f.admit('common-0');roots.push(root);
    for(let index=1;index<20;index++){f.advance(2000);await attach(f,root,'common-'+index);}
  }
  assert.equal(f.gateway.stats().sessions,80);assert.ok(f.peers.slice(0,20).every(peer=>peer.sessions.size===4));
  const denied=await f.request(BASE+'/sessions',{method:'POST',body:'{}'});assert.equal(denied.status,429);assert.equal(denied.body.error.code,'client_session_capacity');
  for(const root of roots)assert.equal((await f.request(BASE+'/sessions',{method:'DELETE',headers:f.auth(root)})).status,204);
  await until(()=>f.gateway.stats().sessions===0&&f.peers.every(peer=>peer.sessions.size===0));
});


test('a changed numeric native address retains its owner-pinned identity and exact signed envelope', async t => {
  const f = await fixture(t); f.setFault('nat'); const session = await f.admit('common-0'), connection = await f.connect(session);
  const upstream = [...f.peers[0].sessions.values()][0];
  assert.deepEqual(connection.raw[0], upstream.hello);
  assert.equal(JSON.parse(Buffer.from(connection.messages[0].advertisement.payloadBase64, 'base64')).enode, f.config.nodes[0].enode.replace('127.0.0.1','127.0.0.2'));
  assert.equal(f.gateway.stats().sessions, 1);
});
