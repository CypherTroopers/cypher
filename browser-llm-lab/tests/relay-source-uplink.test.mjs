import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { WebSocket } from 'ws';
import { createGateway } from '../relay/gateway.mjs';
import { validateConfig } from '../relay/config.mjs';
import { createSourceUplink, verifySourceProof } from '../relay/source-uplink.mjs';
import { fixtureIdentity, fixtureNetwork, fixtureNow, endpointAdvertisement, meshAdvertisement, signDiscoveryRaw } from './mesh-signing-fixtures.mjs';

const BASE='/relay/v1/mesh',origin='https://gateway.example.org';
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(check,ms=5000){const start=Date.now();while(Date.now()-start<ms){const result=check();if(result)return result;await sleep(5);}throw new Error('Expected source fixture state not observed');}
const proof=(bytes,identity)=>signDiscoveryRaw(bytes,identity,'cypher-browser-mesh-source-v1\0').signatureHex;
const caps={version:1,sessionSeconds:300,renewAfterSeconds:120,maxSessions:80,maxFrameBytes:16384,nativeMaxFrameBytes:4194304,nativePeers:40,initialState:'OFF'};
async function fixture(t,{overrides={}}={}){
  let clock=fixtureNow;const clients=[],sources=[],sequences=new Map();
  const config={enabled:true,origin,network:fixtureNetwork,nodes:[],trustedClientIpHeader:'x-client-ip',
    limits:{maxSessions:80,maxSessionsPerClient:80,maxConnections:200,httpRequestsPerSecond:512,httpBytesPerSecond:1048576,admissionsPerMinute:256},
    sourceUplink:{enabled:true,maxSources:32,maxSourcesPerClient:8},discovery:{enabled:true,bootstrapOrigins:[],allowedOrigins:[]},...overrides};
  const gateway=createGateway({config,now:()=>clock});await gateway.listen({port:0});const url=`http://127.0.0.1:${gateway.server.address().port}`;
  async function request(path,options={}){const result=await fetch(url+BASE+path,{...options,headers:{Origin:origin,...options.headers}});const text=await result.text();let body;try{body=JSON.parse(text);}catch{}return{status:result.status,body,text};}
  async function source(seed=1,{auth=true,endpoint,signature,ip='198.51.100.1',autoPong=true,headers={},holdConfig=false,holdSessions=false,holdOpen=false,nativeConfig=caps}={}){
    const identity=fixtureIdentity(seed),ws=new WebSocket(url.replace('http:','ws:')+BASE+'/source',{origin,autoPong,headers:{'X-Client-IP':ip,...headers}});
    clients.push(ws);ws.on('error',()=>{});
    const packets=[],leases=new Map(),streams=new Map(),frames=[],pongs=[],requests=[];const sequence=(sequences.get(identity.nodeId)||0)+1;sequences.set(identity.nodeId,sequence);let record=endpoint??endpointAdvertisement(identity,{sourceId:identity.nodeId,sequence},clock),challenge;
    const send=value=>{if(ws.readyState===1)ws.send(JSON.stringify(value));};
    const reply=(packet,status,body='')=>send({kind:'reply',id:packet.id,status,body:Buffer.from(body).toString('base64')});
    ws.on('close',()=>{streams.clear();leases.clear();});
    ws.on('message',data=>{
      const packet=JSON.parse(data);packets.push(packet);
      if(packet.kind==='challenge'){challenge=Buffer.from(packet.challenge,'base64');if(auth)send({kind:'auth',endpoint:record,signatureHex:signature??proof(challenge,identity)});return;}
      if(packet.kind==='request'){
        requests.push(packet);const suffix=packet.path.slice(BASE.length+1);
        if(suffix==='config'){if(!holdConfig)reply(packet,200,JSON.stringify(nativeConfig));return;}
        if(suffix==='status'){reply(packet,200,JSON.stringify({running:true,sessions:leases.size,circuits:0,candidates:0,receivedBytes:0,sentBytes:0,routes:[]}));return;}
        if(suffix==='sessions'&&packet.method==='POST'){
          if(holdSessions)return;const token=randomBytes(32).toString('hex'),lease={token,browserId:randomBytes(16).toString('hex'),expiresAt:clock+300000};leases.set(token,lease);reply(packet,201,JSON.stringify(lease));return;
        }
        const lease=leases.get(packet.token);if(!lease){reply(packet,401);return;}
        if(suffix==='renew'){lease.expiresAt=clock+300000;reply(packet,200,JSON.stringify({expiresAt:lease.expiresAt}));return;}
        if(packet.method==='DELETE'){leases.delete(packet.token);reply(packet,204);return;}
        reply(packet,404);return;
      }
      if(packet.kind==='open'){assert.ok(leases.has(packet.token));streams.set(packet.id,{token:packet.token,authenticated:false});if(!holdOpen)send({kind:'opened',id:packet.id});return;}
      if(packet.kind==='message'){
        const stream=streams.get(packet.id);if(!stream)return;const raw=Buffer.from(packet.data,'base64');
        if(!stream.authenticated){assert.equal(JSON.parse(raw).token,stream.token);stream.authenticated=true;const lease=leases.get(stream.token);
          stream.hello=Buffer.from(JSON.stringify({type:'hello',protocol:'cypher-browser-mesh/1',session:randomBytes(16).toString('hex'),browserId:lease.browserId,advertisement:meshAdvertisement(identity,{},clock)},null,2)+'\n');
          send({kind:'message',id:packet.id,data:stream.hello.toString('base64')});
        }else{frames.push(raw);send(packet);}return;
      }
      if(packet.kind==='pong'){pongs.push(Buffer.from(packet.data,'base64'));return;}
      if(packet.kind==='close'){const stream=streams.get(packet.id);if(stream)leases.delete(stream.token);streams.delete(packet.id);return;}
    });
    await once(ws,'open');await until(()=>challenge);
    if(auth)await until(()=>gateway.config.nodes.some(n=>n.nodeId===identity.nodeId)||ws.readyState===3);
    const value={ws,identity,packets,leases,streams,frames,pongs,requests,send,reply,get challenge(){return challenge;},get record(){return record;},
      advertise(overrides={}){record=endpointAdvertisement(identity,{sourceId:identity.nodeId,sequence:JSON.parse(Buffer.from(record.payloadBase64,'base64')).sequence+1,...overrides},clock);send({kind:'advertise',endpoint:record});}};
    sources.push(value);return value;
  }
  async function admit(sourceId,parent){const response=await request('/sessions',{method:'POST',headers:parent?{Authorization:'Bearer '+parent.token}:{},body:JSON.stringify({sourceId,...parent?{attach:true}:{}})});assert.equal(response.status,201,response.text);return response.body;}
  async function connect(session){const ws=new WebSocket(url.replace('http:','ws:')+BASE+'/connect',{origin}),raw=[];clients.push(ws);ws.on('error',()=>{});ws.on('message',data=>raw.push(Buffer.from(data)));await once(ws,'open');ws.send(JSON.stringify({token:session.token}));await until(()=>raw.length||ws.readyState===3);return{ws,raw};}
  t.after(async()=>{for(const ws of clients)ws.terminate();await gateway.close();});
  return{gateway,config,url,request,source,admit,connect,sources,now:()=>clock,advance:ms=>clock+=ms};
}

test('source uplink is opt-in and explicit source/IP/target capacities stay bounded',async t=>{
  const f=await fixture(t);
  assert.equal(f.gateway.stats().sourceUplink.enabled,true);
  assert.throws(()=>validateConfig({...f.config,sourceUplink:{enabled:true,maxSourcesPerClient:9}}),/source client/);
  assert.throws(()=>validateConfig({...f.config,sourceUplink:{enabled:true,arbitraryProxy:true}}),/source uplink/);
  assert.throws(()=>validateConfig({...f.config,sourceUplink:{enabled:false}}),/Common node/);
  const off=await fixture(t,{overrides:{enabled:false,sourceUplink:undefined}});
  const ws=new WebSocket(off.url.replace('http:','ws:')+BASE+'/source',{origin});ws.on('error',()=>{});await new Promise(resolve=>ws.once('close',resolve));assert.equal(off.gateway.stats().sourceUplink.sources,0);
});

test('unknown signed native identity becomes a public Common without a manual key/socket pin',async t=>{
  const f=await fixture(t),source=await f.source();
  const config=await f.request('/config');assert.equal(config.body.nodes.length,1);assert.equal(config.body.nodes[0].id,source.identity.nodeId);
  assert.deepEqual(Object.keys(config.body.nodes[0]).sort(),['enode','id','nodeId']);
  const discovery=await f.request('/discovery');assert.deepEqual(discovery.body.endpoints,[source.record]);
  const session=await f.admit(source.identity.nodeId);assert.equal(session.nativeLimits.circuits,40);
  assert.equal(source.requests.some(p=>p.path.endsWith('/endpoint')),false);
  const status=await f.request('/status',{headers:{Authorization:'Bearer '+session.token}});assert.equal(status.status,200);assert.equal(status.body.sessions,1);
  const renew=await f.request('/renew',{method:'POST',headers:{Authorization:'Bearer '+session.token}});assert.equal(renew.status,200);
  await f.request('/sessions',{method:'DELETE',headers:{Authorization:'Bearer '+session.token}});assert.equal(source.leases.size,0);
});

test('native text bytes and native Ping/browser Pong traverse the source stream unchanged',async t=>{
  const f=await fixture(t),source=await f.source(),session=await f.admit(source.identity.nodeId),front=await f.connect(session);
  const [id,stream]=[...source.streams][0];assert.deepEqual(front.raw[0],stream.hello);
  const text=Buffer.from(' {"type":"credit", "session":"abc", "bytes":42}\n');front.ws.send(text,{binary:false});await until(()=>front.raw.length===2);
  assert.deepEqual(source.frames[0],text);assert.deepEqual(front.raw[1],text);
  const control=Buffer.from([0,7,255]);source.send({kind:'ping',id,data:control.toString('base64')});await until(()=>source.pongs.length);assert.deepEqual(source.pongs[0],control);
  front.ws.terminate();await until(()=>source.streams.size===0&&source.leases.size===0&&f.gateway.stats().sessions===0);
});

test('invalid proof, endpoint bindings, outer duplicate keys and challenge replay cannot admit sources',async t=>{
  for(const kind of ['wrong-key','network','origin','label','expired','duplicate-key','replay']){
    const f=await fixture(t);const identity=fixtureIdentity(),overrides={sourceId:identity.nodeId};
    if(kind==='network')overrides.network={...fixtureNetwork,chainId:2};
    if(kind==='origin')overrides.gatewayOrigin='https://elsewhere.example.org';
    if(kind==='label')overrides.sourceId='common-mine';
    if(kind==='expired'){overrides.issuedAt=f.now()-130000;overrides.expiresAt=f.now()-10000;}
    const source=await f.source(1,{auth:false});let signature=proof(source.challenge,identity);
    if(kind==='wrong-key')signature=proof(source.challenge,fixtureIdentity(2));
    if(kind==='replay')signature=proof(Buffer.from(source.challenge.toString().replace('"nonce":"','"nonce":"00')),identity);
    const endpoint=endpointAdvertisement(identity,overrides,f.now());
    if(kind==='duplicate-key')source.ws.send('{"kind":"auth","kind":"auth","endpoint":'+JSON.stringify(endpoint)+',"signatureHex":"'+signature+'"}');
    else source.send({kind:'auth',endpoint,signatureHex:signature});
    await until(()=>source.ws.readyState===3);assert.equal(f.gateway.config.nodes.length,0,kind);assert.equal(f.gateway.stats().sessions,0);
  }
});

test('active or pinned native identity cannot be replaced; reconnect makes a fresh target generation',async t=>{
  const f=await fixture(t),first=await f.source(),duplicate=await f.source(1,{auth:false});
  duplicate.send({kind:'auth',endpoint:duplicate.record,signatureHex:proof(duplicate.challenge,duplicate.identity)});await until(()=>duplicate.ws.readyState===3);
  assert.equal(f.gateway.config.nodes.length,1);const session=await f.admit(first.identity.nodeId);
  first.ws.terminate();await until(()=>f.gateway.config.nodes.length===0&&f.gateway.stats().sessions===0);
  assert.deepEqual((await f.request('/discovery')).body.endpoints,[]);
  f.advance(1100);const replacement=await f.source();assert.equal(f.gateway.config.nodes.length,1);
  assert.equal((await f.request('/status',{headers:{Authorization:'Bearer '+session.token}})).status,401);
  const fresh=await f.admit(replacement.identity.nodeId);assert.notEqual(fresh.id,session.id);
  const pinned=fixtureIdentity(3);const p=await fixture(t,{overrides:{nodes:[{id:'local-common',nodeId:pinned.nodeId,enode:pinned.enode,socketPath:'/tmp/not-opened-uplink-test.sock'}]}});
  const denied=await p.source(3);await until(()=>denied.ws.readyState===3);assert.equal(p.gateway.config.nodes.length,1);assert.equal(p.gateway.stats().sourceUplink.sources,0);
});

test('20 source identities support 20 distinct Common attachments under one existing browser group',async t=>{
  const f=await fixture(t);const sources=[];
  for(let index=0;index<20;index++){sources.push(await f.source(index+1,{ip:`198.51.100.${index+1}`}));f.advance(30);}
  const parent=await f.admit(sources[0].identity.nodeId),sessions=[parent];
  for(const source of sources.slice(1)){f.advance(150);sessions.push(await f.admit(source.identity.nodeId,parent));}
  assert.equal(f.gateway.config.nodes.length,20);assert.equal(f.gateway.stats().sessions,20);assert.equal(new Set(sessions.map(s=>s.nodeId)).size,20);
  assert.ok(sources.every(s=>s.leases.size===1));
  await f.request('/sessions',{method:'DELETE',headers:{Authorization:'Bearer '+parent.token}});
  await until(()=>sources.every(s=>s.leases.size===0));assert.equal(f.gateway.stats().sessions,0);
});

test('source death closes only its child lease, while primary death tears down its whole group',async t=>{
  const f=await fixture(t),a=await f.source(1),b=await f.source(2),parent=await f.admit(a.identity.nodeId),child=await f.admit(b.identity.nodeId,parent);
  b.ws.terminate();await until(()=>f.gateway.stats().sessions===1);assert.equal((await f.request('/status',{headers:{Authorization:'Bearer '+parent.token}})).status,200);
  assert.equal((await f.request('/status',{headers:{Authorization:'Bearer '+child.token}})).status,401);
  f.advance(1100);const b2=await f.source(2);await f.admit(b2.identity.nodeId,parent);
  a.ws.terminate();await until(()=>f.gateway.stats().sessions===0&&b2.leases.size===0);assert.equal(f.gateway.config.nodes.length,1);
});

test('source disappearance during delayed issuance cannot commit a stale browser session',async t=>{
  const f=await fixture(t),source=await f.source(1,{holdSessions:true});
  const pending=f.request('/sessions',{method:'POST',body:JSON.stringify({sourceId:source.identity.nodeId})});await until(()=>source.requests.some(p=>p.path.endsWith('/sessions')));
  source.ws.terminate();const result=await pending;assert.equal(result.status,502);assert.equal(f.gateway.stats().sessions,0);assert.equal(f.gateway.stats().pendingAdmissions,0);
  f.advance(1100);await f.source();assert.equal(f.gateway.config.nodes.length,1);assert.equal(f.gateway.stats().nodes[source.identity.nodeId].pending,0);
});

test('endpoint renewal keeps exact signature; rollback or malformed/unsolicited packets retire the source',async t=>{
  const f=await fixture(t),source=await f.source();f.advance(1000);source.advertise();await until(()=>f.gateway.stats().sourceUplink.receivedBytes>0);
  await sleep(20);assert.deepEqual((await f.request('/discovery')).body.endpoints,[source.record]);
  source.send({kind:'advertise',endpoint:source.record});await until(()=>source.ws.readyState===3);assert.equal(f.gateway.config.nodes.length,0);
  const tests=[{kind:'request',id:'00'.repeat(16),method:'GET',path:'/rpc'},{kind:'opened',id:'00'.repeat(16)},
    {kind:'message',id:'00'.repeat(16),data:'AA'},{kind:'reply',id:'00'.repeat(16),status:200,body:''}];
  for(let i=0;i<tests.length;i++){const other=await f.source(i+2,{ip:`198.51.100.${i+2}`});other.send(tests[i]);await until(()=>other.ws.readyState===3);}
});

test('source auth verifies independent fixed native recoverable signature bytes',()=>{
  const raw=Buffer.from('{"version":1,"origin":"https://gateway.example.org","nonce":"00112233445566778899aabbccddeeff","expiresAt":1700000005000}');
  const signature='dcb374f9e1e6c983cedaeaf69f4978622c7273e3d2f8141584e9c135e78848e1080e2609bee35350ae509d7f23f179dbd7ab8ae36f6b61c03b8d4f56aa1f5a3701';
  verifySourceProof(raw,signature,fixtureIdentity().publicKeyHex);
  assert.throws(()=>verifySourceProof(Buffer.concat([raw,Buffer.from(' ')]),signature,fixtureIdentity().publicKeyHex));
});

test('late opened/data/close after browser departure cannot revive a native stream or kill its source',async t=>{
  const f=await fixture(t),source=await f.source(1,{holdOpen:true}),session=await f.admit(source.identity.nodeId);
  const ws=new WebSocket(f.url.replace('http:','ws:')+BASE+'/connect',{origin});ws.on('error',()=>{});await once(ws,'open');ws.send(JSON.stringify({token:session.token}));
  await until(()=>source.streams.size===1);const id=[...source.streams.keys()][0];ws.terminate();await until(()=>source.streams.size===0&&f.gateway.stats().sessions===0);
  source.send({kind:'opened',id});source.send({kind:'message',id,data:Buffer.from('{}').toString('base64')});source.send({kind:'close',id});await sleep(20);
  assert.equal(source.ws.readyState,1);assert.equal(f.gateway.stats().sourceUplink.streams,0);assert.equal(f.gateway.config.nodes.length,1);
});

test('a signed endpoint expiry withdraws source and owned leases before its HTTP lease ends',async t=>{
  const f=await fixture(t),key=fixtureIdentity(),source=await f.source(1,{endpoint:endpointAdvertisement(key,{sourceId:key.nodeId,expiresAt:f.now()+5000},f.now())});
  const session=await f.admit(key.nodeId);assert.ok(session.expiresAt>f.now()+5000);f.advance(5001);f.gateway.sweep();
  await until(()=>source.ws.readyState===3);assert.equal(f.gateway.config.nodes.length,0);assert.equal(f.gateway.stats().sessions,0);assert.equal(source.leases.size,0);
});

test('source HTTP response byte bounds and deadlines reject without retaining admission slots',async t=>{
  for(const mode of ['oversize','timeout']){
    const f=await fixture(t),source=await f.source(1,{holdSessions:true}),pending=f.request('/sessions',{method:'POST',body:JSON.stringify({sourceId:source.identity.nodeId})});
    await until(()=>source.requests.some(p=>p.path.endsWith('/sessions')));
    if(mode==='oversize'){const request=source.requests.find(p=>p.path.endsWith('/sessions'));source.reply(request,201,'x'.repeat(16385));}
    const response=await pending;assert.equal(response.status,502,mode);await until(()=>source.ws.readyState===3);
    assert.equal(f.gateway.stats().pendingAdmissions,0);assert.equal(f.gateway.stats().sourceUplink.metadata,0);assert.equal(f.gateway.config.nodes.length,0);
  }
});

test('source unauthenticated slots, per-IP admissions and exact Origin are bounded',async t=>{
  const f=await fixture(t),a=await f.source(1,{auth:false}),b=await f.source(2,{auth:false});
  for(const headers of [{Origin:origin},{Origin:'https://unknown.example.org','X-Client-IP':'198.51.100.7'}]){
    const ws=new WebSocket(f.url.replace('http:','ws:')+BASE+'/source',{origin:headers.Origin,headers:{'X-Client-IP':'198.51.100.1',...headers}});ws.on('error',()=>{});
    const result=await new Promise(resolve=>{ws.on('unexpected-response',(_,res)=>{res.resume();ws.terminate();resolve(res.statusCode);});ws.on('open',()=>{ws.terminate();resolve(101);});});
    assert.equal(result,403);
  }
  assert.equal(f.gateway.stats().sourceUplink.pending,2);a.ws.terminate();b.ws.terminate();await until(()=>f.gateway.stats().sourceUplink.pending===0);
});

test('source outer frame and inner base64/control limits are enforced independently',async t=>{
  for(const mode of ['outer','inner','control']){
    const f=await fixture(t),source=await f.source(),session=await f.admit(source.identity.nodeId),front=await f.connect(session),id=[...source.streams.keys()][0];
    if(mode==='outer')source.ws.send(' '.repeat(98305));
    else source.send({kind:mode==='inner'?'message':'ping',id,data:Buffer.alloc(mode==='inner'?16385:126).toString('base64')});
    await until(()=>source.ws.readyState===3&&front.ws.readyState===3);assert.equal(f.gateway.stats().sourceUplink.streams,0);assert.equal(f.gateway.stats().sessions,0);
  }
});

test('4096 retired stream IDs force a fresh source generation instead of an unbounded history or permanent refusal',async t=>{
  const identity=fixtureIdentity(15),config=validateConfig({enabled:true,origin,network:fixtureNetwork,nodes:[],
    limits:{maxSessions:80,maxConnections:200,httpBytesPerSecond:1048576},sourceUplink:{enabled:true,maxSources:1,maxSourcesPerClient:1}});
  let transport;const owner={key:'fixture-owner'};
  // Isolate the lifetime history limit from separately tested byte/message rates.
  const manager=createSourceUplink({settings:config,now:Date.now,makeBucket:()=>({take:()=>true}),sockets:new Set(),takeBytes:()=>true,
    onAdd:async(record,value)=>{transport=value;return{nodeId:record.nodeId};},onRemove:()=>{},onRefresh:()=>{}});
  const server=http.createServer();server.on('upgrade',(req,socket,head)=>manager.upgrade(req,socket,head,owner));await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const ws=new WebSocket(`ws://127.0.0.1:${server.address().port}${BASE}/source`,{origin});ws.on('error',()=>{});
  ws.on('message',raw=>{const packet=JSON.parse(raw);if(packet.kind==='challenge'){const challenge=Buffer.from(packet.challenge,'base64');ws.send(JSON.stringify({kind:'auth',endpoint:endpointAdvertisement(identity,{sourceId:identity.nodeId},Date.now()),signatureHex:proof(challenge,identity)}));}
    else if(packet.kind==='open')ws.send(JSON.stringify({kind:'opened',id:packet.id}));});
  t.after(async()=>{ws.terminate();await manager.close();await new Promise(resolve=>server.close(resolve));});
  await until(()=>transport);
  const ids=new Set();for(let index=0;index<4096;index++){
    const stream=transport.connect('aa'.repeat(32));stream.on('error',()=>{});await once(stream,'open');assert.equal(ids.has(stream.id),false);ids.add(stream.id);stream.terminate();
  }
  assert.equal(transport.closed,false);assert.equal(manager.stats().streams,0);
  const refused=transport.connect('aa'.repeat(32));refused.on('error',()=>{});await new Promise(resolve=>refused.once('close',resolve));
  assert.equal(transport.closed,true);assert.equal(manager.stats().sources,0);
});
