import https from 'node:https';
import { randomBytes } from 'node:crypto';
import { WebSocketServer } from 'ws';
import { countryCentroid } from './geo.mjs';
import { strictJSON } from '../public/relay-protocol.js';
import { EndpointCache, verifyEndpoint, verifyBrowserRecord, verifyChallenge, verifySignal, safeGatewayOrigin } from '../public/mesh-discovery.js';

const BASE='/relay/v1/mesh';
const REJECTION_CODES=['signal_capacity','authentication_required','identity_in_use','session_expired','invalid_renewal','invalid_signal','signal_replay','signal_history_capacity','peer_capacity','ice_capacity','invalid_control','invalid_signature_or_schema'];
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).every(key=>keys.includes(key));
const fault=(code,status=400)=>Object.assign(new Error(code),{code,status});

/** Discovery never dials a client-supplied URL. Only the browser follows signed
 * endpoint claims. Local signed endpoint polling uses existing owner Unix pins.
 * Browser records are self-certified identities, not Common role certificates. */
export function createDiscovery({settings,now,makeBucket,nativeRequest,respond,takeBytes,takeSignalBytes,sockets,clientOccupancy,currentNodes=()=>settings.nodes}) {
  const limits=settings.limits,enabled=settings.discovery?.enabled===true;
  const endpoints=new EndpointCache(settings.network,{now,maxEntries:64}),withdrawnLocal=new Map();
  // Removing an uplink withdraws it immediately but retains sequence/boot replay
  // history for its signed lifetime. A remote POST cannot resurrect that source.
  const visibleEndpoints=()=>endpoints.values().filter(record=>!withdrawnLocal.has(record.nodeId));
  const peers=new Map(),visitors=new Set(),histories=new Map(),publications=new Map(),publicationAttempts=new Map(),originNext=new Map();
  const wss=new WebSocketServer({noServer:true,maxPayload:32768,perMessageDeflate:false,autoPong:false});
  let closed=false,polling=false,nextPoll=0,dirty=false,publicationCursor=0;
  const metrics={acceptedEndpoints:0,rejectedEndpoints:0,authentications:0,signals:0,droppedUnavailableSignals:0,expired:0,invalid:0,receivedBytes:0,sentBytes:0,publications:0,publicationFailures:0};
  const rejectionReasons=Object.fromEntries(REJECTION_CODES.map(code=>[code,0]));
  const rejectVisitor=(visitor,code)=>{
    const reason=Object.hasOwn(rejectionReasons,code)?code:'invalid_signature_or_schema';
    rejectionReasons[reason]=Math.min(Number.MAX_SAFE_INTEGER,rejectionReasons[reason]+1);
    metrics.invalid=Math.min(Number.MAX_SAFE_INTEGER,metrics.invalid+1);terminate(visitor);
  };
  const publication=enabled?{version:1,bootstrapOrigins:settings.discovery.bootstrapOrigins,directoryPath:BASE+'/discovery',rendezvousPath:BASE+'/rendezvous'}:null;
  const countClient=key=>[...visitors].filter(visitor=>visitor.owner.key===key).length;
  function ownerBudget(owner){
    owner.discoveryPosts??=makeBucket(1,4);owner.discoveryBytes??=0;
    return owner;
  }
  function charge(visitor,size){
    const owner=visitor.owner;
    if(owner.discoveryBytes+size>limits.maxSessionTransferBytes)return false;
    owner.discoveryBytes+=size;owner.expires=Math.max(owner.expires,now()+60000);return true;
  }
  function terminate(visitor){
    if(visitor.ended)return;visitor.ended=true;visitors.delete(visitor);clearTimeout(visitor.authTimer);
    if(visitor.record&&peers.get(visitor.record.peerId)===visitor){
      const departed=visitor.record;peers.delete(departed.peerId);dirty=true;
      // Retain a bounded sequence high-water mark across reconnects for the
      // complete signed-signal lifetime plus allowed clock skew.
      const history=histories.get(departed.peerId);if(history)history.expiresAt=Math.max(now()+40000,...[...visitor.sequences.values()].map(value=>value.expiresAt));
      for(const other of peers.values()){
        if(other.listed.has(departed.peerId)||other.targets.has(departed.peerId))enqueue(other,{type:'peer-left',peerId:departed.peerId});
        other.targets.delete(departed.peerId);
        other.queue=other.queue.filter(item=>{if(item.signalFrom!==departed.peerId)return true;other.queueBytes-=item.size;return false;});
      }
    }
    visitor.queue.length=0;visitor.queueBytes=0;visitor.pendingPeers=null;visitor.targets=new Map();visitor.listed.clear();
    visitor.ws.terminate();
  }
  function enqueue(visitor,value,{peerUpdate=false,signalFrom=null,signalSession=null,expiresAt=null}={}) {
    if(visitor.ended||visitor.ws.readyState!==1)return false;
    const text=JSON.stringify(value),size=Buffer.byteLength(text);
    if(size>32768){terminate(visitor);return false;}
    if(peerUpdate&&visitor.pendingPeers)visitor.queueBytes-=visitor.pendingPeers.size;
    if(visitor.queueBytes+size>65536||visitor.queue.length+(visitor.pendingPeers&&!peerUpdate?1:0)>=64){terminate(visitor);return false;}
    const item={text,size,signalFrom,signalSession,expiresAt};visitor.queueBytes+=size;
    if(peerUpdate)visitor.pendingPeers=item;else visitor.queue.push(item);
    flush(visitor);return !visitor.ended;
  }
  function flush(visitor){
    if(visitor.ended||visitor.ws.readyState!==1)return;
    // Reliable SDP/ICE retain order. Peer-list updates coalesce under churn.
    while(visitor.queue.length){const first=visitor.queue[0];
      if(!first.signalFrom||(first.expiresAt>now()&&peers.get(first.signalFrom)?.record.sessionId===first.signalSession))break;
      visitor.queue.shift();visitor.queueBytes-=first.size;
    }
    const item=visitor.queue[0]||visitor.pendingPeers;if(!item)return;
    if(visitor.ws.bufferedAmount+item.size>65536)return;
    if(!visitor.outgoing.take(item.size))return;
    if(!takeBytes(item.size)||!takeSignalBytes(item.size)||!charge(visitor,item.size)){terminate(visitor);return;}
    if(visitor.queue.length)visitor.queue.shift();else visitor.pendingPeers=null;
    visitor.queueBytes-=item.size;metrics.sentBytes+=item.size;
    try{visitor.ws.send(item.text);}catch{terminate(visitor);}
  }
  function peerList(visitor){
    const records=[],ids=new Set();let size=0;
    const active=[...peers.values()].filter(other=>other.record.expiresAt>now()).sort((a,b)=>a.record.peerId.localeCompare(b.record.peerId));
    const at=active.indexOf(visitor),candidates=[];
    // Twenty reciprocal ring neighbors keep late arrivals discoverable once the
    // directory grows beyond a single full neighborhood. This is not an index
    // of every browser on the network.
    for(let distance=1;distance<active.length&&candidates.length<Math.min(20,limits.maxPeers);distance++)for(const direction of[1,-1]){
      const other=active[(at+direction*distance+active.length)%active.length];
      if(!other||other===visitor||candidates.includes(other))continue;
      candidates.push(other);if(candidates.length>=Math.min(20,limits.maxPeers))break;
    }
    for(const other of candidates){
      const envelope=other.record.envelope,bytes=Buffer.byteLength(JSON.stringify(envelope));
      if(size+bytes>24000)break;records.push(envelope);ids.add(other.record.peerId);size+=bytes;
    }
    visitor.listed=ids;return records;
  }
  function peerMetadata(visitor){
    const records=peerList(visitor),peerLocations={};
    for(const id of visitor.listed)peerLocations[id]=peers.get(id)?.geo??null;
    return {peers:records,peerLocations};
  }
  function publish(){
    if(!dirty)return;dirty=false;
    for(const visitor of peers.values())enqueue(visitor,{type:'peers',...peerMetadata(visitor)},{peerUpdate:true});
  }
  async function refreshNative(){
    if(!enabled||closed||polling||nextPoll>now())return;
    polling=true;nextPoll=now()+30000;let cursor=0;const nodes=currentNodes();
    const poll=async()=>{while(cursor<nodes.length&&!closed){const node=nodes[cursor++];
      try{
        const reply=await nativeRequest(node,'endpoint');if(closed||reply.status!==200||!currentNodes().includes(node))continue;
        const envelope=strictJSON(reply.body,8192),record=verifyEndpoint(envelope,settings.network,now());
        if(record.nodeId!==node.nodeId||record.sourceId!==node.id||record.origin!==settings.origin)continue;
        endpoints.add(envelope);
      }catch{/* An older Common without /endpoint remains usable through its local pins. */}
    }};
    try{await Promise.all([poll(),poll()]);}finally{polling=false;}
  }
  // Automatic announcements target operator-configured bootstrap origins only.
  // Remote records in the public directory are never server-side dial targets.
  function pumpPublication(){
    if(!enabled||closed||publications.size>=2)return;
    const origins=settings.discovery.bootstrapOrigins.filter(value=>value!==settings.origin);
    const local=visibleEndpoints().filter(record=>record.origin===settings.origin&&currentNodes().some(node=>node.nodeId===record.nodeId&&node.id===record.sourceId));
    const total=origins.length*local.length;if(!total)return;
    for(let offset=0;offset<total;offset++){
      const index=publicationCursor++%total,origin=origins[index%origins.length],record=local[Math.floor(index/origins.length)],key=origin+':'+record.nodeId;
      if(publications.has(key)||(publicationAttempts.get(key)??0)>now()||(originNext.get(origin)??0)>now())continue;
      publicationAttempts.set(key,now()+30000);originNext.set(origin,now()+1000);
      const body=Buffer.from(JSON.stringify({endpoint:record.envelope}));
      if(!takeBytes(body.length)){metrics.publicationFailures++;return;}
      const controller=new AbortController();publications.set(key,controller);let size=0,done=false;
      const finish=success=>{if(done)return;done=true;clearTimeout(timer);publications.delete(key);metrics[success?'publications':'publicationFailures']++;};
      const request=https.request(new URL(BASE+'/discovery',origin),{method:'POST',agent:false,signal:controller.signal,
        headers:{Origin:settings.origin,'Content-Type':'application/json','Content-Length':body.length,Connection:'close'}},response=>{
        response.on('data',chunk=>{size+=chunk.length;if(size>4096||!takeBytes(chunk.length)){finish(false);controller.abort();}});
        response.on('end',()=>finish(response.statusCode===202));response.on('error',()=>finish(false));
      });
      const timer=setTimeout(()=>{finish(false);controller.abort();},2000);timer.unref();request.on('error',()=>finish(false));request.end(body);return;
    }
  }
  function publicationOrigin(req,path){
    if(!enabled||path!=='discovery'||!['POST','OPTIONS'].includes(req.method))return false;
    try{safeGatewayOrigin(req.headers.origin);}catch{return false;}
    if(req.method==='POST')return true;
    return req.headers['access-control-request-method']==='POST'&&String(req.headers['access-control-request-headers']??'').split(',').filter(Boolean).every(key=>key.trim().toLowerCase()==='content-type');
  }
  async function readBody(req){
    if(Number(req.headers['content-length'])>16384)throw fault('body_limit',413);
    return new Promise((resolve,reject)=>{
      const chunks=[];let size=0,done=false;
      const fail=error=>{if(done)return;done=true;req.pause();reject(error);};
      req.on('error',()=>fail(fault('invalid_body')));req.on('aborted',()=>fail(fault('invalid_body')));
      req.on('data',chunk=>{size+=chunk.length;if(size>16384)return fail(fault('body_limit',413));chunks.push(chunk);});
      req.on('end',()=>{if(done)return;done=true;
        try{if(!takeBytes(size))throw fault('bandwidth_capacity',429);resolve(strictJSON(Buffer.concat(chunks,size),16384));}
        catch(error){reject(error.status?error:fault('invalid_body'));}
      });
    });
  }
  async function handle(req,res,path,owner){
    if(path!=='discovery')return false;
    if(!enabled)throw fault('not_found',404);
    if(req.method==='GET'){
      if(req.headers['transfer-encoding']||Number(req.headers['content-length']??0)!==0)throw fault('body_denied');
      const value={version:1,network:settings.network,endpoints:[],peers:[]};
      let size=Buffer.byteLength(JSON.stringify(value));
      for(const item of visibleEndpoints()){
        const bytes=Buffer.byteLength(JSON.stringify(item.envelope));if(size+bytes>262000)break;value.endpoints.push(item.envelope);size+=bytes+1;
      }
      for(const visitor of peers.values()){
        if(visitor.record.expiresAt<=now())continue;
        const bytes=Buffer.byteLength(JSON.stringify(visitor.record.envelope));
        if(value.peers.length>=64||size+bytes>262000)break;value.peers.push(visitor.record.envelope);size+=bytes+1;
      }
      respond(res,200,value);return true;
    }
    if(req.method==='POST'){
      if(!ownerBudget(owner).discoveryPosts.take())throw fault('publication_rate',429);
      const value=await readBody(req);
      if(!exact(value,['endpoint'])||!value.endpoint)throw fault('invalid_body');
      try{const candidate=verifyEndpoint(value.endpoint,settings.network,now());
        if(![settings.origin,...settings.discovery.allowedOrigins].includes(req.headers.origin)&&candidate.origin!==req.headers.origin)throw fault('publication_origin_mismatch',403);
        const record=endpoints.add(value.endpoint);metrics.acceptedEndpoints++;respond(res,202,{nodeId:record.nodeId,expiresAt:record.expiresAt});}
      catch(error){metrics.rejectedEndpoints++;if(error.status)throw error;throw fault(error.code==='resource_limit'?'discovery_capacity':'invalid_endpoint',error.code==='resource_limit'?429:400);}
      return true;
    }
    throw fault('method_denied',405);
  }
  function upgrade(req,socket,head,owner){
    if(!enabled||closed)throw fault('discovery_disabled');
    if(histories.size>=limits.maxSessions*4||visitors.size>=limits.maxSessions||countClient(owner.key)+clientOccupancy(owner.key)>=limits.maxSessionsPerClient)throw fault('discovery_capacity',429);
    if(!owner.admissions.take())throw fault('admission_rate',429);
    ownerBudget(owner);
    wss.handleUpgrade(req,socket,head,ws=>{
      ws.clientKey=owner.key;sockets.add(ws);
      const challenge={nonce:randomBytes(32).toString('hex'),origin:settings.origin,expiresAt:now()+5000};
      const visitor={ws,owner,challenge,geo:settings.trustedCountryHeader?countryCentroid(req.headers[settings.trustedCountryHeader]):null,record:null,targets:new Map(),sequences:new Map(),listed:new Set(),queue:[],queueBytes:0,pendingPeers:null,ended:false,
        incoming:makeBucket(limits.signalingBytesPerSecond,32768),outgoing:makeBucket(limits.signalingBytesPerSecond,32768),messages:makeBucket(10,20),control:makeBucket(2,4),
        lastPing:now(),lastPong:now(),ping:null};visitors.add(visitor);
      visitor.authTimer=setTimeout(()=>terminate(visitor),5000);visitor.authTimer.unref();
      ws.on('error',()=>{});ws.on('close',()=>{sockets.delete(ws);terminate(visitor);});
      ws.on('ping',()=>rejectVisitor(visitor,'invalid_control'));
      ws.on('pong',payload=>{
        if(!visitor.record||!visitor.control.take()||!visitor.ping||payload.toString('hex')!==visitor.ping||!takeBytes(payload.length)||!charge(visitor,payload.length))return terminate(visitor);
        visitor.ping=null;visitor.lastPong=now();
      });
      ws.on('message',(data,binary)=>{try{
        if(binary||visitor.ended||!visitor.messages.take()||!visitor.incoming.take(data.length)||!takeBytes(data.length)||!takeSignalBytes(data.length)||!charge(visitor,data.length))throw fault('signal_capacity');
        metrics.receivedBytes+=data.length;const value=strictJSON(data,32768);
        if(!visitor.record){
          if(!exact(value,['type','record','signatureHex'])||value.type!=='auth')throw fault('authentication_required');
          const record=verifyChallenge(challenge,value.record,value.signatureHex,settings.network,now());
          if(peers.has(record.peerId))throw fault('identity_in_use');
          const previous=histories.get(record.peerId);
          if(previous&&previous.sessionId===record.sessionId)visitor.sequences=previous.sequences;
          else histories.set(record.peerId,{sessionId:record.sessionId,sequences:visitor.sequences,expiresAt:record.expiresAt});
          visitor.record=record;peers.set(record.peerId,visitor);clearTimeout(visitor.authTimer);metrics.authentications++;dirty=true;
          enqueue(visitor,{type:'ready',...peerMetadata(visitor),expiresAt:record.expiresAt});return;
        }
        if(visitor.record.expiresAt<=now())throw fault('session_expired');
        if(value.type==='leave'&&exact(value,['type'])){terminate(visitor);return;}
        if(value.type==='ping'&&exact(value,['type'])){enqueue(visitor,{type:'pong'});return;}
        if(value.type==='renew'&&exact(value,['type','record'])){
          const record=verifyBrowserRecord(value.record,settings.network,now()),old=visitor.record;
          if(record.peerId!==old.peerId||record.sessionId!==old.sessionId||record.publicKey!==old.publicKey||record.browserId!==old.browserId||record.nodeId!==old.nodeId||record.sourceId!==old.sourceId||
            !record.rendezvous.includes(settings.origin)||record.issuedAt<old.issuedAt||record.expiresAt<old.expiresAt||record.issuedAt===old.issuedAt&&record.envelope.payloadBase64!==old.envelope.payloadBase64)throw fault('invalid_renewal');
          visitor.record=record;dirty=true;enqueue(visitor,{type:'renewed',expiresAt:record.expiresAt});return;
        }
        if(value.type!=='signal'||!exact(value,['type','message']))throw fault('invalid_signal');
        const signal=verifySignal(value.message,visitor.record,settings.network,now()),target=peers.get(signal.to);
        for(const [id,prior] of visitor.sequences)if(prior.expiresAt<=now())visitor.sequences.delete(id);
        const sequenceKey=signal.to+':'+signal.toSessionId,prior=visitor.sequences.get(sequenceKey);
        if(prior&&signal.seq<=prior.seq)throw fault('signal_replay');
        if(!prior&&visitor.sequences.size>=Math.max(20,limits.maxPeers*2))throw fault('signal_history_capacity');
        visitor.sequences.set(sequenceKey,{seq:signal.seq,expiresAt:Math.max(prior?.expiresAt??0,signal.expiresAt)});
        // A signed offer/ICE may arrive after its destination leaves or obtains
        // a new generation. Preserve replay history, but do not disconnect the
        // healthy sender and cascade this ordinary peer departure through rooms.
        if(!target||target.record.expiresAt<=now()||signal.toSessionId!==target.record.sessionId){
          const route=visitor.targets.get(signal.to);
          if(route&&(!target||target.record.expiresAt<=now()||route.sessionId!==target.record.sessionId))visitor.targets.delete(signal.to);
          metrics.droppedUnavailableSignals=Math.min(Number.MAX_SAFE_INTEGER,metrics.droppedUnavailableSignals+1);dirty=true;return;
        }
        let route=visitor.targets.get(signal.to);
        if(route&&route.sessionId!==signal.toSessionId){visitor.targets.delete(signal.to);route=null;}
        if(!route){if(visitor.targets.size>=limits.maxPeers)throw fault('peer_capacity');route={sessionId:signal.toSessionId,ice:0};visitor.targets.set(signal.to,route);}
        if(signal.type==='offer')route.ice=0;
        if(signal.type==='ice'&&++route.ice>limits.maxIceCandidates)throw fault('ice_capacity');
        if(!enqueue(target,{type:'signal',record:visitor.record.envelope,message:value.message},{signalFrom:visitor.record.peerId,signalSession:visitor.record.sessionId,expiresAt:Math.min(visitor.record.expiresAt,signal.expiresAt)}))throw fault('peer_capacity');metrics.signals++;
      }catch(error){rejectVisitor(visitor,error.code);}});
      enqueue(visitor,{type:'challenge',...challenge});
    });
  }
  function sweep(){
    if(closed||!enabled)return;
    endpoints.prune();for(const [id,expiry] of withdrawnLocal)if(expiry<=now())withdrawnLocal.delete(id);for(const [id,history] of histories)if(!peers.has(id)&&history.expiresAt<=now())histories.delete(id);void refreshNative();
    for(const visitor of visitors){
      if(visitor.record&&visitor.record.expiresAt<=now()){metrics.expired++;terminate(visitor);continue;}
      if(!visitor.record&&visitor.challenge.expiresAt<=now()){terminate(visitor);continue;}
      if(visitor.record&&now()-visitor.lastPong>=15000){terminate(visitor);continue;}
      if(visitor.record&&now()-visitor.lastPing>=5000){
        visitor.lastPing=now();
        if(!visitor.ping){const ping=randomBytes(8);visitor.ping=ping.toString('hex');
          if(!takeBytes(ping.length)||!charge(visitor,ping.length)){terminate(visitor);continue;}
          try{visitor.ws.ping(ping);}catch{terminate(visitor);continue;}
        }
      }
      flush(visitor);
    }
    publish();pumpPublication();
  }
  const timer=setInterval(sweep,100);timer.unref();
  return {publication,publicationOrigin,handle,upgrade,sweep,refreshNative,countClient,
    addLocalEndpoint:envelope=>{const record=endpoints.add(envelope);withdrawnLocal.delete(record.nodeId);return record;},removeLocalEndpoint:nodeId=>{const record=endpoints.get(nodeId);if(record)withdrawnLocal.set(nodeId,record.expiresAt+10000);},
    stats:()=>({enabled,endpoints:visibleEndpoints().length,peers:peers.size,visitors:visitors.size,replayEntries:histories.size,publishing:publications.size,publicationSlots:publicationAttempts.size,queuedBytes:[...visitors].reduce((n,v)=>n+v.queueBytes,0),...metrics,rejectionReasons:{...rejectionReasons}}),
    close:async()=>{if(closed)return;closed=true;clearInterval(timer);for(const controller of publications.values())controller.abort();for(const visitor of [...visitors])terminate(visitor);endpoints.records.clear();withdrawnLocal.clear();histories.clear();publicationAttempts.clear();originNext.clear();await new Promise(resolve=>wss.close(resolve));},
  };
}
