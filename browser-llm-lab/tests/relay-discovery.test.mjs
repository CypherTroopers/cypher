import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import { randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import { once } from 'node:events';
import { mkdtemp,rm,readFile }  from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { WebSocket } from 'ws';
import { createMeshTLSFixture } from './mesh-tls-fixture.mjs';
import { fileURLToPath } from 'node:url';
import { createGateway } from '../relay/gateway.mjs';
import { validateConfig } from '../relay/config.mjs';
import { fixtureIdentity,fixtureNetwork,fixtureNow,endpointAdvertisement } from './mesh-signing-fixtures.mjs';
import { signBrowserRecord,signChallenge,signSignal,verifyEndpoint,verifySignal } from '../public/mesh-discovery.js';

const BASE='/relay/v1/mesh',origin='https://gateway.example.org',frontend='https://browser.example.org';
const wait=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(check){for(let n=0;n<400;n++){const value=check();if(value)return value;await wait(5);}throw new Error('Expected discovery fixture state not observed');}
async function fixture(t,{gatewayOrigin=origin,overrides={},native=false,identitySeed=1}={}){
  let clock=fixtureNow,localEndpoint=null;const sockets=[],nativeRequests=[];let local=null,directory=null;
  const identity=fixtureIdentity(identitySeed),nodes=[],nativeLeases=new Map();
  if(native){directory=await mkdtemp(join(tmpdir(),'mesh-discovery-'));const socketPath=join(directory,'native.sock');
    local=http.createServer((req,res)=>{nativeRequests.push({url:req.url,origin:req.headers.origin});
      if(req.url===BASE+'/endpoint'&&localEndpoint){res.end(JSON.stringify(localEndpoint));return;}
      if(req.url===BASE+'/config'){res.end(JSON.stringify({version:1,sessionSeconds:300,renewAfterSeconds:120,maxSessions:80,maxFrameBytes:16384,nativeMaxFrameBytes:4194304,nativePeers:40,initialState:'OFF'}));return;}
      if(req.url===BASE+'/sessions'&&req.method==='POST'){const token=randomBytes(32).toString('hex'),value={token,browserId:randomBytes(16).toString('hex'),expiresAt:clock+300000};nativeLeases.set(token,value);res.writeHead(201);res.end(JSON.stringify(value));return;}
      if(req.url===BASE+'/sessions'&&req.method==='DELETE'){nativeLeases.delete(req.headers.authorization?.slice(7));res.writeHead(204);res.end();return;}

      res.writeHead(404);res.end();});await new Promise(resolve=>local.listen(socketPath,resolve));
    nodes.push({id:'common-a',nodeId:identity.nodeId,enode:identity.enode,socketPath});
  }
  const config={enabled:native,origin:gatewayOrigin,network:fixtureNetwork,nodes,
    limits:{maxSessions:8,maxSessionsPerClient:8,maxConnections:32,httpBytesPerSecond:1048576},
    discovery:{enabled:true,bootstrapOrigins:[],allowedOrigins:[frontend]},...overrides};
  const gateway=createGateway({config,now:()=>clock});await gateway.listen({port:0});const url=`http://127.0.0.1:${gateway.server.address().port}`;
  async function request(path='/discovery',options={}){
    const response=await fetch(url+BASE+path,{...options,headers:{Origin:frontend,...options.headers}}),text=await response.text();let body;
    try{body=JSON.parse(text);}catch{}return{status:response.status,body,text,headers:response.headers};
  }
  const record=(key,overrides={})=>signBrowserRecord({network:fixtureNetwork,sessionId:'aa'.repeat(16),browserId:'bb'.repeat(16),
    nodeId:identity.nodeId,sourceId:'common-a',rendezvous:[gatewayOrigin],issuedAt:clock,expiresAt:clock+120000,...overrides},key);
  async function connect(key=fixtureIdentity(5),{record:envelope=record(key),proof,auth=true,autoPong=true,headers={}}={}){
    const ws=new WebSocket(url.replace('http:','ws:')+BASE+'/rendezvous',{origin:frontend,autoPong,headers}),messages=[];sockets.push(ws);
    ws.on('error',()=>{});ws.on('message',raw=>messages.push(JSON.parse(raw)));await once(ws,'open');const challengeMessage=await until(()=>messages.find(value=>value.type==='challenge'));
    const {type,...challenge}=challengeMessage;
    if(auth){ws.send(JSON.stringify({type:'auth',record:envelope,signatureHex:proof??signChallenge(challenge,envelope,key,clock)}));
      await until(()=>messages.some(value=>value.type==='ready')||ws.readyState===3);}
    return{ws,messages,challenge,key,record:envelope,wait:type=>until(()=>messages.find(value=>value.type===type)),send:value=>ws.send(JSON.stringify(value))};
  }
  function signal(from,to,{seq=1,type='offer',value='v=0\r\n',...overrides}={}){
    const a=JSON.parse(Buffer.from(from.record.payloadBase64,'base64')),b=JSON.parse(Buffer.from(to.record.payloadBase64,'base64'));
    return signSignal({version:1,network:fixtureNetwork,from:a.peerId,to:b.peerId,fromSessionId:a.sessionId,toSessionId:b.sessionId,
      seq,type,value,issuedAt:clock,expiresAt:clock+30000,...overrides},from.key);
  }
  t.after(async()=>{sockets.forEach(ws=>ws.terminate());await gateway.close();if(local)await new Promise(resolve=>local.close(resolve));if(directory)await rm(directory,{recursive:true,force:true});});
  return{gateway,config,url,request,connect,record,signal,identity,nativeRequests,now:()=>clock,advance:ms=>clock+=ms,setLocalEndpoint:value=>localEndpoint=value};
}

test('discovery is opt-in, publishes only configured hints, and applies explicit cross-origin CORS',async t=>{
  const f=await fixture(t),config=await f.request('/config');assert.equal(config.body.discovery.version,1);
  assert.equal(config.headers.get('Access-Control-Allow-Origin'),frontend);
  const preflight=await f.request('/sessions',{method:'OPTIONS',headers:{'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'Authorization, Content-Type'}});
  assert.equal(preflight.status,204);assert.equal(preflight.headers.get('Access-Control-Allow-Origin'),frontend);
  assert.equal((await f.request('/discovery',{headers:{Origin:'https://evil.example.org'}})).status,403);
  assert.equal((await f.request('/discovery?token=secret')).status,400);
  const off=await fixture(t,{overrides:{discovery:{enabled:false}}});assert.equal((await off.request('/config',{headers:{Origin:origin}})).body.discovery,undefined);
  assert.equal((await off.request('/discovery',{headers:{Origin:origin}})).status,404);
  assert.throws(()=>validateConfig({...f.config,discovery:{enabled:true,allowedOrigins:['*']}}));
  assert.throws(()=>validateConfig({...f.config,discovery:{enabled:true,bootstrapOrigins:Array(9).fill('https://x.example.org')}}));
});
test('a previously unlisted Common self-announces exact signed bytes without any gateway network dial',async t=>{
  const f=await fixture(t,{native:true}),key=fixtureIdentity(22),envelope=endpointAdvertisement(key,{gatewayOrigin:'https://far-away.example.org'},f.now());
  const result=await f.request('/discovery',{method:'POST',body:JSON.stringify({endpoint:envelope})});assert.equal(result.status,202);assert.equal(result.body.nodeId,key.nodeId);
  const directory=await f.request();assert.deepEqual(directory.body.endpoints,[envelope]);assert.equal(directory.body.peers.length,0);
  assert.equal(verifyEndpoint(directory.body.endpoints[0],fixtureNetwork,f.now()).nodeId,key.nodeId);
  assert.equal(f.gateway.stats().sessions,0);assert.ok(f.nativeRequests.every(row=>row.url===BASE+'/endpoint'));
  f.advance(120001);f.gateway.sweep();assert.deepEqual((await f.request()).body.endpoints,[]);
});
test('endpoint publication rejects tampering, different networks, expired and ambiguous JSON',async t=>{
  const f=await fixture(t),key=fixtureIdentity(22),valid=endpointAdvertisement(key,{},f.now());
  const corrupt={...valid,signatureHex:'00'+valid.signatureHex.slice(2)};
  for(const endpoint of[corrupt,endpointAdvertisement(key,{network:{...fixtureNetwork,chainId:99}},f.now()),endpointAdvertisement(key,{},f.now()-120001)]){
    assert.equal((await f.request('/discovery',{method:'POST',body:JSON.stringify({endpoint})})).status,400);f.advance(1001);
  }
  assert.equal((await f.request('/discovery',{method:'POST',body:'{"endpoint":{},"endpoint":{}}'})).status,400);
  assert.equal(f.gateway.stats().discovery.endpoints,0);
});
test('directory caches at most64 native identities, rejects65, and reclaims expired slots',async t=>{
  const f=await fixture(t);
  for(let n=1;n<=64;n++){f.advance(1001);assert.equal((await f.request('/discovery',{method:'POST',body:JSON.stringify({endpoint:endpointAdvertisement(fixtureIdentity(n+100),{},f.now())})})).status,202);}
  f.advance(1001);const extra=endpointAdvertisement(fixtureIdentity(999),{},f.now());
  assert.equal((await f.request('/discovery',{method:'POST',body:JSON.stringify({endpoint:extra})})).status,429);
  const directory=await f.request();assert.equal(directory.body.endpoints.length,64);assert.ok(Buffer.byteLength(directory.text)<=262144);
  f.advance(131000);const fresh=endpointAdvertisement(fixtureIdentity(999),{},f.now());
  assert.equal((await f.request('/discovery',{method:'POST',body:JSON.stringify({endpoint:fresh})})).status,202);
});
test('fixed Unix endpoint polling requires exact local node identity, source, origin and native envelope without pinning its native IP',async t=>{
  const f=await fixture(t,{native:true});f.setLocalEndpoint(endpointAdvertisement(f.identity,{},f.now()));await f.gateway.refreshDiscovery();
  assert.equal((await f.request()).body.endpoints.length,1);assert.equal(f.nativeRequests[0].origin,origin);
  f.advance(30001);f.setLocalEndpoint(endpointAdvertisement(f.identity,{sequence:2,gatewayOrigin:'https://other.example.org'},f.now()));await f.gateway.refreshDiscovery();
  assert.equal(verifyEndpoint((await f.request()).body.endpoints[0],fixtureNetwork,f.now()).payload.sequence,1);
  f.advance(30001);f.setLocalEndpoint(endpointAdvertisement(f.identity,{sequence:3},f.now()));await f.gateway.refreshDiscovery();
  assert.equal(verifyEndpoint((await f.request()).body.endpoints[0],fixtureNetwork,f.now()).payload.sequence,3);
  f.advance(30001);f.setLocalEndpoint(endpointAdvertisement(f.identity,{sequence:4,enode:f.identity.enode.replace('127.0.0.1','13.1.2.3')},f.now()));await f.gateway.refreshDiscovery();
  assert.equal(verifyEndpoint((await f.request()).body.endpoints[0],fixtureNetwork,f.now()).payload.sequence,4);
});
test('independent visitors authenticate by challenge and route signed signals without Common lease registration',async t=>{
  const f=await fixture(t),a=await f.connect(fixtureIdentity(5)),b=await f.connect(fixtureIdentity(6));assert.equal(f.gateway.stats().sessions,0);
  assert.equal(f.gateway.stats().discovery.peers,2);const directory=await f.request();assert.equal(directory.body.peers.length,2);
  const message=f.signal(a,b);a.send({type:'signal',message});const received=await b.wait('signal');
  assert.deepEqual(received.message,message);assert.deepEqual(received.record,a.record);
  assert.equal(verifySignal(received.message,received.record,fixtureNetwork,f.now()).type,'offer');
  assert.ok((await b.wait('ready')).peers.some(env=>env.payloadBase64===a.record.payloadBase64));
  a.ws.close();await until(()=>f.gateway.stats().discovery.peers===1);assert.equal((await f.request()).body.peers.length,1);
});
test('two independent gateways accept the same signed browser records for cross-gateway rendezvous',async t=>{
  const f=await fixture(t),g=await fixture(t,{gatewayOrigin:'https://region-b.example.org'}),aKey=fixtureIdentity(11),bKey=fixtureIdentity(12);
  const aRecord=f.record(aKey,{rendezvous:[origin,'https://region-b.example.org']}),bRecord=g.record(bKey,{rendezvous:[origin,'https://region-b.example.org']});
  const aHome=await f.connect(aKey,{record:aRecord}),bHome=await g.connect(bKey,{record:bRecord});
  assert.equal((await f.request()).body.peers.length,1);assert.equal((await g.request()).body.peers.length,1);
  const aRemote=await g.connect(aKey,{record:aRecord});aRemote.send({type:'signal',message:g.signal(aRemote,bHome)});
  const forwarded=await bHome.wait('signal');assert.deepEqual(forwarded.record,aRecord);assert.equal(f.gateway.stats().discovery.signals,0);assert.equal(g.gateway.stats().discovery.signals,1);
  assert.equal(aHome.ws.readyState,1);assert.equal(f.gateway.stats().sessions+g.gateway.stats().sessions,0);
});
test('challenge proof cannot be replayed on another socket and duplicate live peer identities are rejected',async t=>{
  const f=await fixture(t),key=fixtureIdentity(8),a=await f.connect(key),signature=signChallenge(a.challenge,a.record,key,f.now());
  const replay=await f.connect(key,{record:a.record,proof:signature});assert.equal(replay.ws.readyState,3);assert.equal(a.ws.readyState,1);
  const duplicate=await f.connect(key,{record:a.record});assert.equal(duplicate.ws.readyState,3);assert.equal(f.gateway.stats().discovery.peers,1);
});
test('signed signal replay closes sender without forwarding duplicates',async t=>{
  const f=await fixture(t),a=await f.connect(fixtureIdentity(5)),b=await f.connect(fixtureIdentity(6)),message=f.signal(a,b);
  a.send({type:'signal',message});await b.wait('signal');a.send({type:'signal',message});await until(()=>a.ws.readyState===3);
  assert.equal(b.messages.filter(value=>value.type==='signal').length,1);
});
test('delayed signed signal to departed B preserves A-to-C signaling while replay and forgery remain fatal',async t=>{
  const f=await fixture(t),a=await f.connect(fixtureIdentity(5)),b=await f.connect(fixtureIdentity(6)),c=await f.connect(fixtureIdentity(7));
  a.send({type:'signal',message:f.signal(a,b)});await b.wait('signal');
  const delayed=f.signal(a,b,{seq:2,type:'ice',value:null});
  b.ws.close();await until(()=>f.gateway.stats().discovery.peers===2);
  a.send({type:'signal',message:delayed});await until(()=>f.gateway.stats().discovery.droppedUnavailableSignals===1);
  assert.equal(a.ws.readyState,1);assert.equal(c.ws.readyState,1);assert.equal(f.gateway.stats().discovery.invalid,0);
  const next=f.signal(a,c);a.send({type:'signal',message:next});assert.deepEqual((await c.wait('signal')).message,next);
  assert.equal(b.messages.filter(value=>value.type==='signal').length,1);
  // The harmless drop still advances the old destination's sequence high-water.
  a.send({type:'signal',message:delayed});await until(()=>a.ws.readyState===3);
  assert.equal(f.gateway.stats().discovery.droppedUnavailableSignals,1);
  const forged=f.signal(c,b);forged.signatureHex=(forged.signatureHex[0]==='0'?'1':'0')+forged.signatureHex.slice(1);
  c.send({type:'signal',message:forged});await until(()=>c.ws.readyState===3);
  assert.equal(f.gateway.stats().discovery.invalid,2);assert.equal(f.gateway.stats().discovery.droppedUnavailableSignals,1);
  const reasons=f.gateway.stats().discovery.rejectionReasons;assert.equal(reasons.signal_replay,1);assert.equal(reasons.invalid_signature_or_schema,1);
  reasons.signal_replay=999;assert.equal(f.gateway.stats().discovery.rejectionReasons.signal_replay,1,'Stats must not expose mutable counters');
});
test('old destination generation is dropped after B rejoins and fresh B generation remains reachable',async t=>{
  const f=await fixture(t),a=await f.connect(fixtureIdentity(15)),keyB=fixtureIdentity(16),b=await f.connect(keyB);
  const delayed=f.signal(a,b);b.ws.close();await until(()=>f.gateway.stats().discovery.peers===1);
  f.advance(1);const nextB=await f.connect(keyB,{record:f.record(keyB,{sessionId:'dd'.repeat(16)})});
  a.send({type:'signal',message:delayed});await until(()=>f.gateway.stats().discovery.droppedUnavailableSignals===1);
  assert.equal(a.ws.readyState,1);assert.equal(nextB.messages.filter(value=>value.type==='signal').length,0);
  const fresh=f.signal(a,nextB);a.send({type:'signal',message:fresh});assert.deepEqual((await nextB.wait('signal')).message,fresh);
  assert.equal(f.gateway.stats().discovery.invalid,0);
});
test('expired destination lease is dropped without closing a current sender',async t=>{
  const f=await fixture(t),a=await f.connect(fixtureIdentity(25)),keyB=fixtureIdentity(26),b=await f.connect(keyB,{record:f.record(keyB,{expiresAt:f.now()+1})});
  f.advance(2);a.send({type:'signal',message:f.signal(a,b)});await until(()=>f.gateway.stats().discovery.droppedUnavailableSignals===1);
  assert.equal(a.ws.readyState,1);assert.equal(b.messages.filter(value=>value.type==='signal').length,0);assert.equal(f.gateway.stats().discovery.invalid,0);
});
test('unavailable destination drops retain the finite sequence-history bound',async t=>{
  const f=await fixture(t),a=await f.connect(fixtureIdentity(35)),b=await f.connect(fixtureIdentity(36));
  for(let n=1;n<=40;n++){
    f.advance(250);a.send({type:'signal',message:f.signal(a,b,{to:n.toString(16).padStart(32,'0')})});
    await until(()=>f.gateway.stats().discovery.droppedUnavailableSignals===n);
  }
  a.send({type:'signal',message:f.signal(a,b,{to:'ff'.repeat(16)})});await until(()=>a.ws.readyState===3);
  assert.equal(f.gateway.stats().discovery.droppedUnavailableSignals,40);assert.equal(f.gateway.stats().discovery.rejectionReasons.signal_history_capacity,1);
  assert.equal(b.messages.filter(value=>value.type==='signal').length,0);
});
test('fresh record renews same browser generation, while expiry and backdated renewal cannot resurrect it',async t=>{
  const f=await fixture(t),a=await f.connect(fixtureIdentity(5));f.advance(1000);
  const renewed=f.record(a.key);a.send({type:'renew',record:renewed});assert.equal((await a.wait('renewed')).expiresAt,f.now()+120000);
  a.send({type:'renew',record:a.record});await until(()=>a.ws.readyState===3);assert.equal(f.gateway.stats().discovery.peers,0);
  const b=await f.connect(fixtureIdentity(6));f.advance(120001);f.gateway.sweep();await until(()=>b.ws.readyState===3);assert.equal(f.gateway.stats().discovery.peers,0);
});
test('IP visitor admission, invalid binary, oversized frames and preauth control stay bounded',async t=>{
  const f=await fixture(t,{overrides:{limits:{maxSessions:2,maxSessionsPerClient:2,maxConnections:16,httpBytesPerSecond:1048576}}});
  const a=await f.connect(fixtureIdentity(5)),b=await f.connect(fixtureIdentity(6));
  const denied=new WebSocket(f.url.replace('http:','ws:')+BASE+'/rendezvous',{origin:frontend});denied.on('error',()=>{});
  assert.equal((await once(denied,'unexpected-response'))[1].statusCode,403);denied.terminate();
  a.ws.send(Buffer.from('{}'));await until(()=>a.ws.readyState===3);
  const c=await f.connect(fixtureIdentity(7),{auth:false});c.ws.ping('preauth');await until(()=>c.ws.readyState===3);
  b.ws.send('x'.repeat(32769));await until(()=>b.ws.readyState===3);
  await until(()=>f.gateway.stats().discovery.visitors===0);assert.equal(f.gateway.stats().discovery.queuedBytes,0);
});
test('rendezvous heartbeat relies on real Pong, and silent connections are reclaimed',async t=>{
  const f=await fixture(t),a=await f.connect(fixtureIdentity(5),{autoPong:false});
  f.advance(5001);f.gateway.sweep();assert.equal(a.ws.readyState,1);f.advance(10000);f.gateway.sweep();await until(()=>a.ws.readyState===3);
  assert.equal(f.gateway.stats().discovery.visitors,0);assert.equal(f.gateway.stats().discovery.peers,0);
});
test('an unknown gateway Origin can self-publish only its own signed endpoint and cannot access sessions',async t=>{
  const f=await fixture(t),remote='https://new-region.example.org',headers={Origin:remote};
  const preflight=await f.request('/discovery',{method:'OPTIONS',headers:{...headers,'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'content-type'}});
  assert.equal(preflight.status,204);assert.equal(preflight.headers.get('Access-Control-Allow-Headers'),'Content-Type');
  assert.equal((await f.request('/discovery',{method:'OPTIONS',headers:{...headers,'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'authorization'}})).status,403);
  assert.equal((await f.request('/sessions',{method:'POST',headers,body:'{}'})).status,403);
  assert.equal((await f.request('/discovery',{headers})).status,403);
  const endpoint=endpointAdvertisement(fixtureIdentity(81),{gatewayOrigin:remote},f.now());
  assert.equal((await f.request('/discovery',{method:'POST',headers,body:JSON.stringify({endpoint})})).status,202);
  const mismatch=endpointAdvertisement(fixtureIdentity(82),{},f.now());
  assert.equal((await f.request('/discovery',{method:'POST',headers,body:JSON.stringify({endpoint:mismatch})})).status,403);
  assert.equal(f.gateway.stats().discovery.endpoints,1);
});
test('signal replay high-water mark survives sender and recipient reconnect within the signature lifetime',async t=>{
  const f=await fixture(t),keyA=fixtureIdentity(51),keyB=fixtureIdentity(52),a=await f.connect(keyA),b=await f.connect(keyB),message=f.signal(a,b);
  a.send({type:'signal',message});await b.wait('signal');a.ws.close();await until(()=>f.gateway.stats().discovery.peers===1);
  const again=await f.connect(keyA,{record:a.record});again.send({type:'signal',message});await until(()=>again.ws.readyState===3);
  assert.equal(b.messages.filter(row=>row.type==='signal').length,1);
  b.ws.close();await until(()=>f.gateway.stats().discovery.peers===0);
  const receiver=await f.connect(keyB,{record:b.record}),sender=await f.connect(keyA,{record:a.record});sender.send({type:'signal',message});await until(()=>sender.ws.readyState===3);
  assert.equal(receiver.messages.filter(row=>row.type==='signal').length,0);
});
test('rendezvous advertises at most20 peers and caps each sender at20 live destinations',async t=>{
  const f=await fixture(t,{overrides:{limits:{maxSessions:24,maxSessionsPerClient:24,maxConnections:64,httpBytesPerSecond:1048576}}}),clients=[];
  for(let index=0;index<22;index++){clients.push(await f.connect(fixtureIdentity(200+index)));f.advance(100);}
  const sender=clients[0];
  for(let index=1;index<=20;index++){f.advance(1000);sender.send({type:'signal',message:f.signal(sender,clients[index],{seq:index})});await clients[index].wait('signal');}
  sender.send({type:'signal',message:f.signal(sender,clients[21],{seq:21})});await until(()=>sender.ws.readyState===3);
  assert.equal(clients[21].messages.filter(row=>row.type==='signal').length,0);
  f.gateway.sweep();await wait(250);
  assert.ok(clients.slice(0,20).some(client=>client.messages.some(message=>message.peers?.some(envelope=>envelope.payloadBase64===clients[21].record.payloadBase64))),'A late arrival appears in prior participants ring neighborhoods');
  for(const client of clients)for(const message of client.messages)if(message.peers)assert.ok(message.peers.length<=20);
  assert.equal(f.gateway.stats().discovery.signals,20);assert.ok(f.gateway.stats().discovery.queuedBytes<=24*65536);
});
test('self-announcement publisher only posts local native claims to configured HTTPS seeds at bounded intervals',async t=>{
  const calls=[];
  t.mock.method(https,'request',(url,options,reply)=>{
    const request=new EventEmitter();request.end=body=>{
      calls.push({url:String(url),options,body:JSON.parse(body)});
      queueMicrotask(()=>{const response=Readable.from([Buffer.from('{"ok":true}')]);response.statusCode=202;reply(response);});
    };return request;
  });
  const seed='https://seed.example.org',f=await fixture(t,{native:true,overrides:{discovery:{enabled:true,bootstrapOrigins:[origin,seed],allowedOrigins:[frontend]}}});
  const local=endpointAdvertisement(f.identity,{},f.now());f.setLocalEndpoint(local);await f.gateway.refreshDiscovery();f.gateway.sweep();
  await until(()=>f.gateway.stats().discovery.publications===1);
  assert.equal(calls[0].url,seed+BASE+'/discovery');assert.equal(calls[0].options.headers.Origin,origin);assert.equal(calls[0].options.agent,false);
  assert.deepEqual(calls[0].body,{endpoint:local});
  const remote=endpointAdvertisement(fixtureIdentity(70),{gatewayOrigin:'https://do-not-dial.example.org'},f.now());
  await f.request('/discovery',{method:'POST',body:JSON.stringify({endpoint:remote})});f.gateway.sweep();assert.equal(calls.length,1);
  f.advance(29999);f.gateway.sweep();assert.equal(calls.length,1);f.advance(2);f.gateway.sweep();await until(()=>calls.length===2);
  assert.ok(calls.every(call=>call.url===seed+BASE+'/discovery'));assert.ok(f.gateway.stats().discovery.publicationSlots<=8*64);
});
test('bootstrap publication rejects oversized responses and redirects without following advertised URLs',async t=>{
  let calls=0;
  t.mock.method(https,'request',(url,options,reply)=>{
    const request=new EventEmitter();request.end=()=>queueMicrotask(()=>{
      calls++;const response=Readable.from([Buffer.alloc(calls===1?4097:0)]);response.statusCode=calls===1?202:302;response.headers={location:'https://unconfigured.example.org'};reply(response);
    });options.signal.addEventListener('abort',()=>{});return request;
  });
  const f=await fixture(t,{native:true,overrides:{discovery:{enabled:true,bootstrapOrigins:['https://seed.example.org'],allowedOrigins:[frontend]}}});
  f.setLocalEndpoint(endpointAdvertisement(f.identity,{},f.now()));await f.gateway.refreshDiscovery();f.gateway.sweep();await until(()=>f.gateway.stats().discovery.publicationFailures===1);
  f.advance(30001);f.gateway.sweep();await until(()=>f.gateway.stats().discovery.publicationFailures===2);assert.equal(calls,2);assert.equal(f.gateway.stats().discovery.publications,0);
});
test('rendezvous location hints use trusted proxy country metadata, separate from signed peer records',async t=>{
  const f=await fixture(t,{overrides:{trustedCountryHeader:'x-relay-country'}}),a=await f.connect(fixtureIdentity(41),{headers:{'x-relay-country':'JP'}}),b=await f.connect(fixtureIdentity(42));
  const ready=await b.wait('ready'),id=fixtureIdentity(41).peerId;
  assert.equal(ready.peerLocations[id].countryCode,'JP');assert.equal(ready.peerLocations[id].accuracy,'country');
  assert.equal(JSON.parse(Buffer.from(a.record.payloadBase64,'base64')).geo,undefined);
  assert.ok(Object.keys(ready.peerLocations).length<=20);
});
test('client quota combines native leases and discovery visitors in either admission order',async t=>{
  for(const visitorsFirst of[true,false]){
    const f=await fixture(t,{native:true,overrides:{limits:{maxSessions:2,maxSessionsPerClient:2,maxConnections:16,httpBytesPerSecond:1048576}}});
    const admit=()=>f.request('/sessions',{method:'POST',body:'{}'});
    if(visitorsFirst){
      const first=await f.connect(fixtureIdentity(501));assert.equal((await admit()).status,201);
      assert.equal((await admit()).status,429);assert.equal(f.gateway.stats().sessions+f.gateway.stats().discovery.visitors,2);
      first.ws.close();await until(()=>f.gateway.stats().discovery.visitors===0);assert.equal((await admit()).status,201);
    }else{
      assert.equal((await admit()).status,201);await f.connect(fixtureIdentity(502));
      const denied=new WebSocket(f.url.replace('http:','ws:')+BASE+'/rendezvous',{origin:frontend});denied.on('error',()=>{});
      assert.equal((await once(denied,'unexpected-response'))[1].statusCode,403);denied.terminate();
      assert.equal(f.gateway.stats().sessions+f.gateway.stats().discovery.visitors,2);
    }
  }
});
test('actual verified TLS auto-publication introduces an unknown regional Common without manual seed registration',async t=>{
  const tls=await createMeshTLSFixture({root:fileURLToPath(new URL('../',import.meta.url)),names:['publisher-a','directory-b']}),origins=tls.origins;
  const ca=await readFile(join(tls.directory,'tls.crt')),original=https.request,handshakes=[],requests=[];
  // Only fixture transport resolution and CA trust differ. The production
  // publisher performs the real HTTP exchange and processes the real response.
  // No global hosts, OS trust store, advertised envelope or response is mocked.
  t.mock.method(https,'request',(url,options,reply)=>{
    const target=new URL(url);assert.ok(origins.includes(target.origin));
    const lookup=(host,lookupOptions,callback)=>{
      assert.ok(origins.some(origin=>new URL(origin).hostname===host));
      queueMicrotask(()=>lookupOptions?.all?callback(null,[{address:'127.0.0.1',family:4}]):callback(null,'127.0.0.1',4));
    };
    const request=original.call(https,url,{...options,ca,lookup},reply);
    request.on('socket',socket=>socket.once('secureConnect',()=>handshakes.push({authorized:socket.authorized,servername:socket.servername})));
    return request;
  });
  const a=await fixture(t,{native:true,gatewayOrigin:origins[0],identitySeed:601,overrides:{discovery:{enabled:true,bootstrapOrigins:[origins[1]],allowedOrigins:[frontend]}}});
  const b=await fixture(t,{native:true,gatewayOrigin:origins[1],identitySeed:602});
  tls.addGateway(0,a.gateway);tls.addGateway(1,b.gateway);t.after(()=>tls.close());
  b.gateway.server.prependListener('request',req=>{if(req.url===BASE+'/discovery'&&req.method==='POST')requests.push({origin:req.headers.origin,authorization:req.headers.authorization??null});});
  a.advance(30001);b.advance(30001);
  const descriptor=endpointAdvertisement(a.identity,{gatewayOrigin:origins[0]},a.now());a.setLocalEndpoint(descriptor);
  b.setLocalEndpoint(endpointAdvertisement(b.identity,{gatewayOrigin:origins[1]},b.now()));
  await Promise.all([a.gateway.refreshDiscovery(),b.gateway.refreshDiscovery()]);a.gateway.sweep();
  await until(()=>a.gateway.stats().discovery.publications===1);
  const catalog=await b.request('/discovery');assert.equal(catalog.status,200);
  assert.ok(catalog.body.endpoints.some(record=>record.payloadBase64===descriptor.payloadBase64&&record.signatureHex===descriptor.signatureHex));
  assert.equal(b.config.nodes.length,1);assert.equal(b.config.nodes[0].nodeId,b.identity.nodeId);
  assert.equal(b.config.discovery.allowedOrigins.includes(origins[0]),false);
  assert.deepEqual(requests,[{origin:origins[0],authorization:null}]);
  assert.deepEqual(handshakes,[{authorized:true,servername:new URL(origins[1]).hostname}]);
  assert.equal(a.gateway.stats().discovery.publicationFailures,0);assert.equal(b.gateway.stats().discovery.acceptedEndpoints,1);
});
