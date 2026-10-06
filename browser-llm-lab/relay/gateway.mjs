import http from 'node:http';
import { randomBytes,createHash,timingSafeEqual } from 'node:crypto';
import { isIP,connect as connectUnix } from 'node:net';
import { WebSocket,WebSocketServer } from 'ws';
import { strictJSON } from '../public/relay-protocol.js';
import { validateConfig } from './config.mjs';
import { countryCentroid } from './geo.mjs';
import { loadTurnSecret,turnCredentials } from './turn.mjs';
import { createDiscovery } from './discovery.mjs';
import { enodePublicKey } from '../public/mesh-discovery.js';
import { createSourceUplink } from './source-uplink.mjs';

const BASE='/relay/v1/mesh',TOKEN=/^[a-f0-9]{64}$/;
const headers={'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
const exact=(obj,keys)=>obj&&typeof obj==='object'&&!Array.isArray(obj)&&Object.keys(obj).every(key=>keys.includes(key));
const fault=(code,status=400)=>Object.assign(new Error(code),{code,status});
const hash=token=>createHash('sha256').update(token).digest();
const opaque=()=>randomBytes(16).toString('hex');
class Bucket {
  constructor(rate,burst,now){Object.assign(this,{rate,burst,now,tokens:burst,last:now()});}
  take(n=1){const at=this.now();this.tokens=Math.min(this.burst,this.tokens+Math.max(0,at-this.last)*this.rate/1000);this.last=at;if(n>this.tokens)return false;this.tokens-=n;return true;}
}

/** One browser group owns at most 20 distinct Common leases and one signaling identity. */
export function createGateway({config,now=Date.now}={}) {
  const settings=validateConfig(config),limits=settings.limits;
  const turnSecret=settings.turn?loadTurnSecret(settings.turn.secretPath):null;
  const iceServers=session=>settings.turn?[...settings.iceServers,turnCredentials(settings.turn,turnSecret,session,now())]:settings.iceServers;
  const sessions=new Map(),sockets=new Set(),connections=new Set(),clients=new Map(),pending=new Set();
  // Fixed categories only: no tokens, identities, frame contents or remote addresses in diagnostics.
  const dropReasons=Object.fromEntries(['session_ended','session_expired','pong_timeout','transfer_limit','response_failed',
    'native_capacity','invalid_native_frame','invalid_native_hello','invalid_native_advertisement','native_pin_mismatch',
    'upstream_closed','upstream_error','native_auth_timeout','invalid_control','signal_capacity','client_closed','manual_off','gateway_shutdown'].map(reason=>[reason,0]));
  // State follows an immutable target generation, not its reusable sourceId.
  // A disconnected uplink may have outstanding HTTP callbacks during reconnect.
  const targets=new Map(settings.nodes.map(node=>[node.id,node])),nodeState=new Map();
  const currentNodes=()=>[...targets.values()];
  const activeNode=node=>targets.get(node.id)===node;
  const newNodeState=node=>{const state={pending:0,metadata:0,requests:new Bucket(16,32,now),
    admissions:new Bucket(limits.nativeAdmissionsPerSecond,limits.nativeAdmissionBurst,now),capabilities:null,capabilityEpoch:0,configAt:0,configRead:null,status:null,statusAt:0,statusRead:null,releases:new Map()};nodeState.set(node,state);return state;};
  settings.nodes.forEach(newNodeState);
  let order=0,nodeIndex=0,closed=false,pendingAdmissions=0;
  const requests=new Bucket(limits.httpRequestsPerSecond,limits.httpRequestsPerSecond*2,now);
  const bytes=new Bucket(limits.httpBytesPerSecond,Math.max(65536,limits.httpBytesPerSecond*2),now);
  const signalBytes=new Bucket(limits.maxSessions*limits.signalingBytesPerSecond,Math.max(32768,limits.maxSessions*32768),now);
  const publicConfig={version:1,enabled:settings.enabled,protocol:'cypher-browser-mesh/1',initialState:'OFF',network:settings.network,
    nodes:settings.nodes.map(({id,nodeId,enode})=>({id,nodeId,enode})),sessionSeconds:300,renewAfterSeconds:120,
    maxFrameBytes:limits.maxNativeFrameBytes,nativeMaxFrameBytes:4*1048576,signalPath:BASE+'/signal',connectPath:BASE+'/connect',
    iceServers:settings.iceServers,turnEnabled:Boolean(settings.turn),limits};
  const nativeCount=node=>[...sessions.values()].filter(s=>s.node===node).length+nodeState.get(node).pending+nodeState.get(node).releases.size;
  const updatePublicNodes=()=>{publicConfig.nodes=currentNodes().map(({id,nodeId,enode})=>({id,nodeId,enode}));};
  async function capabilities(node) {
    const state=nodeState.get(node);
    if(state.capabilities&&now()-state.configAt<limits.nativeConfigCacheMs)return state.capabilities;
    if(state.configRead)return state.configRead;
    const epoch=state.capabilityEpoch;
    state.configRead=(async()=>{
      const reply=await nativeRequest(node,'config');if(reply.status!==200)throw fault('native_config_unavailable',502);
      const value=strictJSON(reply.body,limits.maxNativeResponseBytes);
      if(!exact(value,['version','sessionSeconds','renewAfterSeconds','maxSessions','maxFrameBytes','nativeMaxFrameBytes','nativePeers','initialState'])||
        value.version!==1||value.sessionSeconds!==300||value.renewAfterSeconds!==120||value.maxFrameBytes!==16384||value.nativeMaxFrameBytes!==4194304||value.initialState!=='OFF')
        throw fault('unsupported_native_config',502);
      // v1 has no circuit fields. Only these two audited Common profiles are supported;
      // never infer an arbitrary circuit capacity from an unrecognized peer/session pair.
      const expanded=value.maxSessions===80&&value.nativePeers===40,legacy=value.maxSessions===8&&value.nativePeers===4;
      if(!expanded&&!legacy)throw fault('unsupported_native_capacity',502);
      const caps=Object.freeze({maxSessions:value.maxSessions,nativePeers:value.nativePeers,circuits:expanded?40:8,
        circuitsPerSession:expanded?40:2,pendingInbound:4,pendingOutbound:4});
      if(epoch!==state.capabilityEpoch)throw fault('native_config_changed',503);
      state.capabilities=caps;state.configAt=now();return caps;
    })();
    try{return await state.configRead;}finally{state.configRead=null;}
  }
  function invalidateNative(node){const state=nodeState.get(node);state.configAt=0;state.status=null;state.capabilityEpoch++;}
  async function choose(sourceId,cancelled=()=>false) {
    if(sourceId!==undefined&&!targets.has(sourceId))throw fault('unknown_source');
    // Rotate the first choice while retaining every Common as a bounded fallback.
    const start=nodeIndex++;
    const available=currentNodes(),nodes=sourceId===undefined?available.map((_,index)=>available[(start+index)%available.length]):available.filter(n=>n.id===sourceId);
    let denied=fault('native_capacity',503);
    for(const node of nodes){
      if(cancelled())throw fault('admission_cancelled',499);
      const state=nodeState.get(node);let caps;
      try{caps=await capabilities(node);}catch(cause){denied=cause;continue;}
      if(cancelled())throw fault('admission_cancelled',499);
      if(!activeNode(node)){denied=fault('native_unavailable',503);continue;}
      if(nativeCount(node)>=Math.min(limits.maxSessionsPerCommon,caps.maxSessions)){denied=fault('native_capacity',503);continue;}
      if(!state.admissions.take()){denied=fault('native_admission_rate',429);continue;}
      state.pending++;return{node,caps};
    }
    throw denied;
  }
  function client(req) {
    let address=req.socket.remoteAddress;
    const supplied=settings.trustedClientIpHeader&&req.headers[settings.trustedClientIpHeader];
    if(typeof supplied==='string'&&supplied.length<=45&&isIP(supplied))address=supplied;
    const key=createHash('sha256').update(String(address)).digest('hex');let entry=clients.get(key);
    if(!entry){if(clients.size>=4096)throw fault('client_capacity',429);entry={key,pending:0,requests:new Bucket(32,64,now),admissions:new Bucket(limits.admissionsPerMinute/60,limits.admissionsPerMinute,now)};clients.set(key,entry);}
    entry.expires=now()+60000;return entry;
  }
  const allowedOrigins=new Set([settings.origin,...(settings.discovery?.enabled?settings.discovery.allowedOrigins:[])]);
  const validOrigin=(req,read=false)=>typeof req.headers.origin==='string'?allowedOrigins.has(req.headers.origin):read&&req.headers['sec-fetch-site']==='same-origin';
  function charge(session,size){const group=session.group;if(group.transferred+size>limits.maxSessionTransferBytes){drop(group.root,{reason:'transfer_limit'});return false;}group.transferred+=size;return true;}
  function account(session,size,direction='out') {
    return bytes.take(size)&&session[direction==='in'?'incoming':'outgoing'].take(size)&&charge(session,size);
  }
  function respond(res,status,value,session=null) {
    if(res.destroyed||res.writableEnded)return false;
    const data=Buffer.isBuffer(value)?value:Buffer.from(JSON.stringify(value));
    if(!bytes.take(data.length)||session&&(!session.outgoing.take(data.length)||!charge(session,data.length))){
      try{res.writeHead(429,headers);res.end('{"error":{"code":"bandwidth_capacity"}}');}catch{}
      return false;
    }
    try{res.writeHead(status,{...headers,'Content-Length':data.length});res.end(data);return true;}catch{return false;}
  }
  function authToken(token){if(!TOKEN.test(token??''))throw fault('session_required',401);const supplied=hash(token);
    const session=[...sessions.values()].find(s=>timingSafeEqual(s.tokenHash,supplied));if(!session||session.expiresAt<=now())throw fault('session_required',401);return session;}
  function authenticate(req){const bearer=req.headers.authorization;if(typeof bearer!=='string'||!/^Bearer [a-f0-9]{64}$/.test(bearer))throw fault('session_required',401);
    const session=authToken(bearer.slice(7));if(!session.requests.take())throw fault('session_rate',429);return session;}
  function nativeRequest(node,path,{method='GET',token,body}={}) {
    if(!['config','sessions','renew','status','endpoint'].includes(path))return Promise.reject(fault('native_path_denied'));
    const state=nodeState.get(node);
    if(state.metadata>=limits.nativeMetadataConcurrency)return Promise.reject(fault('native_metadata_capacity',503));
    if(!state.requests.take())return Promise.reject(fault('native_rate',429));
    if(node.uplink?.closed)return Promise.reject(fault('native_unavailable',502));
    state.metadata++;const maxResponse=path==='status'?limits.maxNativeStatusBytes:limits.maxNativeResponseBytes;
    if(node.uplink)return node.uplink.request(path,{method,token,body,maxResponse}).finally(()=>{state.metadata--;});
    return new Promise((resolve,reject)=>{
      const controller=new AbortController();pending.add(controller);let size=0,done=false;const parts=[];
      const finish=(cause,result)=>{if(done)return;done=true;clearTimeout(timer);pending.delete(controller);state.metadata--;cause?reject(cause):resolve(result);};
      const req=http.request({socketPath:node.socketPath,path:BASE+'/'+path,method,signal:controller.signal,
        agent:false,headers:{Connection:'close',Origin:settings.nativeOrigin,...token?{Authorization:'Bearer '+token}:{},...body?{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)}:{}}},res=>{
        res.on('data',chunk=>{size+=chunk.length;if(size>maxResponse){finish(fault('native_response_limit',502));res.destroy();req.destroy();return;}parts.push(chunk);});
        res.on('end',()=>finish(null,{status:res.statusCode,body:Buffer.concat(parts,size)}));res.on('error',()=>finish(fault('native_unavailable',502)));
      });
      const timer=setTimeout(()=>{finish(fault('native_timeout',502));controller.abort();},2000);timer.unref();
      req.on('error',()=>finish(fault('native_unavailable',502)));if(body)req.write(body);req.end();
    });
  }
  async function nativeStatus(node) {
    const state=nodeState.get(node);
    if(state.status&&now()-state.statusAt<limits.nativeStatusCacheMs)return state.status;
    if(state.statusRead)return state.statusRead;
    state.statusRead=(async()=>{
      const reply=await nativeRequest(node,'status');if(reply.status!==200)throw fault('native_unavailable',502);
      const value=strictJSON(reply.body,limits.maxNativeStatusBytes),caps=state.capabilities;
      if(!exact(value,['running','sessions','circuits','candidates','receivedBytes','sentBytes','routes'])||typeof value.running!=='boolean'||
        !['sessions','circuits','candidates','receivedBytes','sentBytes'].every(key=>Number.isSafeInteger(value[key])&&value[key]>=0)||
        value.sessions>(caps?.maxSessions??80)||value.circuits>(caps?.circuits??40)||value.candidates>64||!Array.isArray(value.routes)||value.routes.length!==value.circuits||
        value.routes.some(route=>!exact(route,['circuitId','remoteId','relayIds','sessionId'])||!/^[a-f0-9]{32}$/.test(route.circuitId??'')||
          !/^[a-f0-9]{64}$/.test(route.remoteId??'')||!/^[a-f0-9]{32}$/.test(route.sessionId??'')||!Array.isArray(route.relayIds)||route.relayIds.length>4||
          route.relayIds.some(id=>typeof id!=='string'||!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(id))))throw fault('invalid_native_status',502);
      state.status=value;state.statusAt=now();return value;
    })();
    try{return await state.statusRead;}finally{state.statusRead=null;}
  }
  // Native HTTP leases without an attached WS also need deterministic cleanup.
  // Failed cleanup is retained within the same 80-slot budget, retried at most once
  // per second, and forgotten only on native acknowledgement or lease expiry.
  function releaseNative(node,token,expiresAt=now()+limits.sessionLeaseMs) {
    if(!token||node.uplink?.closed)return Promise.resolve();const state=nodeState.get(node);
    if(!state.releases.has(token)){
      if(state.releases.size>=limits.maxSessionsPerCommon)return Promise.resolve();
      state.releases.set(token,{expiresAt,inFlight:null,retryAt:0});
    }
    return flushRelease(node,token,state.releases.get(token));
  }
  function flushRelease(node,token,entry) {
    const state=nodeState.get(node);
    if(entry.expiresAt<=now()){state.releases.delete(token);return Promise.resolve();}
    if(entry.inFlight)return entry.inFlight;
    if(entry.retryAt>now()||state.metadata>=limits.nativeMetadataConcurrency)return Promise.resolve();
    entry.retryAt=now()+1000;
    entry.inFlight=nativeRequest(node,'sessions',{method:'DELETE',token}).then(reply=>{
      if(reply.status===204||reply.status===401||reply.status===404)state.releases.delete(token);
    }).catch(()=>{}).finally(()=>{entry.inFlight=null;});
    return entry.inFlight;
  }

  const peerList=session=>[...session.peers].map(id=>[...sessions.values()].find(s=>!s.parentId&&s.peerId===id)).filter(s=>s?.signal?.readyState===1)
    .map(s=>({id:s.id,peerId:s.peerId,browserId:s.browserId,sourceId:s.node.id,nodeId:s.node.nodeId,initiator:session.order<s.order,geo:s.geo}));
  function sendSignal(session,value){if(closed||session?.signal?.readyState!==1)return false;const data=JSON.stringify(value),size=Buffer.byteLength(data);
    if(session.signal.bufferedAmount+size>limits.maxSignalBufferedBytes||!account(session,size)){drop(session,{reason:'signal_capacity'});return false;}session.signal.send(data);return true;}
  function pair(){const active=[...sessions.values()].filter(s=>!s.parentId&&s.signal?.readyState===1).sort((a,b)=>a.order-b.order),before=new Map(active.map(s=>[s.peerId,new Set(s.peers)]));
    const byPeer=new Map(active.map(s=>[s.peerId,s]));
    for(const s of active)for(const id of s.peers)if(!byPeer.get(id)?.peers.has(s.peerId))s.peers.delete(id);
    const connect=(a,b)=>{if(a!==b&&a.peers.size<limits.maxPeers&&b.peers.size<limits.maxPeers){a.peers.add(b.peerId);b.peers.add(a.peerId);}};
    // Keep existing reciprocal links: rebuilding every full neighbor list on a
    // join multiplies signaling traffic at degree 20. Fill vacancies first.
    for(const cross of [true,false])for(let distance=1;distance<active.length;distance++)for(let index=0;index<active.length;index++){
      const a=active[index],b=active[(index+distance)%active.length];if((a.node.id!==b.node.id)===cross)connect(a,b);
    }
    // A saturated graph must still admit a new browser. Replace one existing
    // edge with two edges through it; existing degrees stay unchanged and each
    // browser requires at most ten swaps at the maximum configured degree.
    for(const s of active)for(const cross of [true,false])for(const a of active){
      if(s.peers.size+2>limits.maxPeers)break;
      if(a===s||s.peers.has(a.peerId)||(a.node.id!==s.node.id)!==cross)continue;
      const b=[...a.peers].map(id=>byPeer.get(id)).find(peer=>peer&&peer!==s&&!s.peers.has(peer.peerId));
      if(!b)continue;a.peers.delete(b.peerId);b.peers.delete(a.peerId);connect(a,s);connect(b,s);
    }
    for(const s of active){const prior=before.get(s.peerId);if(prior.size===s.peers.size&&[...prior].every(id=>s.peers.has(id)))continue;
      for(const id of prior)if(!s.peers.has(id)){s.ice.delete(id);sendSignal(s,{type:'peer-left',peerId:id});}sendSignal(s,{type:'peers',peers:peerList(s)});}}
  function drop(session,{release=true,reason='session_ended'}={}) {
    if(sessions.get(session.id)!==session)return;
    // Remove the complete group synchronously before asynchronous native cleanup.
    // Pending children observe the missing root and release any lease returned later.
    const victims=session.parentId?[session]:[...session.group.members],releases=[];
    for(const victim of victims){
      if(sessions.get(victim.id)!==victim)continue;
      if(reason==='upstream_closed'||reason==='upstream_error')invalidateNative(victim.node);
      sessions.delete(victim.id);victim.group.members.delete(victim);victim.group.sources.delete(victim.node.id);
      const token=victim.nativeToken;victim.nativeToken=null;
      const category=Object.hasOwn(dropReasons,reason)?reason:'session_ended';dropReasons[category]=Math.min(Number.MAX_SAFE_INTEGER,dropReasons[category]+1);
      clearTimeout(victim.nativeAuthTimer);victim.front?.terminate();victim.upstream?.terminate();victim.signal?.close(1000,'native session ended');victim.peers.clear();
      if(release)releases.push(releaseNative(victim.node,token,victim.expiresAt));
    }
    pair();return Promise.all(releases);
  }
  function sweep(){for(const s of sessions.values()){
      if(s.expiresAt<=now())drop(s,{reason:'session_expired'});
      else if(s.nativePings&&[...s.nativePings.values()].some(p=>p.deadline<=now()))drop(s,{reason:'pong_timeout'});
    }
    for(const [key,c] of clients)if(c.expires<=now()&&!c.pending&&![...sockets].some(ws=>ws.clientKey===key))clients.delete(key);
    for(const [node,state] of nodeState){
      for(const [token,entry] of state.releases)void flushRelease(node,token,entry);
      if(!activeNode(node)&&!state.pending&&!state.metadata&&!state.releases.size)nodeState.delete(node);
    }
    sourceUplink?.sweep();}
  const discovery=createDiscovery({settings,now,currentNodes,makeBucket:(rate,burst)=>new Bucket(rate,burst,now),nativeRequest,respond,
    takeBytes:n=>bytes.take(n),takeSignalBytes:n=>signalBytes.take(n),sockets,clientOccupancy:key=>[...sessions.values()].filter(s=>s.clientKey===key).length+(clients.get(key)?.pending??0)});
  if(discovery.publication)publicConfig.discovery=discovery.publication;
  async function addUplink(record,transport){
    if(closed||targets.size>=64||targets.has(record.sourceId)||currentNodes().some(node=>node.nodeId===record.nodeId))throw fault('source_conflict',409);
    const node=Object.freeze({id:record.sourceId,nodeId:record.nodeId,enode:record.payload.enode,uplink:transport});
    newNodeState(node);
    try{
      await capabilities(node);
      if(closed||transport.closed||targets.size>=64||targets.has(node.id)||currentNodes().some(other=>other.nodeId===node.nodeId))throw fault('source_conflict',409);
      discovery.addLocalEndpoint(record.envelope);
      targets.set(node.id,node);updatePublicNodes();return node;
    }catch(error){nodeState.delete(node);throw error;}
  }
  function removeUplink(node){
    if(!node)return;
    if(activeNode(node)){targets.delete(node.id);updatePublicNodes();discovery.removeLocalEndpoint(node.nodeId);}
    for(const session of [...sessions.values()])if(session.node===node)drop(session,{reason:'upstream_closed'});
    nodeState.get(node)?.releases.clear();
  }
  const sourceUplink=createSourceUplink({settings,now,makeBucket:(rate,burst)=>new Bucket(rate,burst,now),sockets,
    takeBytes:n=>bytes.take(n),onAdd:addUplink,onRemove:removeUplink,onRefresh:(node,envelope)=>{if(activeNode(node))discovery.addLocalEndpoint(envelope);}});
  const timer=setInterval(sweep,1000);timer.unref();
  async function body(req){if(Number(req.headers['content-length'])>1024)throw fault('body_limit',413);return new Promise((resolve,reject)=>{
    const chunks=[];let size=0,done=false;const fail=e=>{if(done)return;done=true;req.pause();reject(e);};req.on('error',()=>fail(fault('invalid_body')));req.on('aborted',()=>fail(fault('invalid_body')));
    req.on('data',chunk=>{size+=chunk.length;if(size>1024)return fail(fault('body_limit',413));chunks.push(chunk);});req.on('end',()=>{if(done)return;done=true;req.bodyBytes=size;
      try{resolve(size?strictJSON(Buffer.concat(chunks,size),1024):{});}catch{reject(fault('invalid_body'));}});});}
  const server=http.createServer({maxHeaderSize:8192,requestTimeout:5000,headersTimeout:3000,keepAliveTimeout:5000},async(req,res)=>{
    try{
      sweep();if(closed)throw fault('unavailable',503);const owner=client(req);if(!requests.take()||!owner.requests.take())throw fault('request_rate',429);
      const url=new URL(req.url,'http://loopback');if(url.search||url.hash||url.pathname.includes('%'))throw fault('invalid_path');
      if(!url.pathname.startsWith(BASE+'/'))throw fault('not_found',404);
      const path=url.pathname.slice(BASE.length+1),publisherOrigin=discovery.publicationOrigin(req,path);
      if(!validOrigin(req,req.method==='GET')&&!publisherOrigin)throw fault('origin_denied',403);
      if(allowedOrigins.has(req.headers.origin)||publisherOrigin)res.setHeader('Access-Control-Allow-Origin',req.headers.origin);res.setHeader('Vary','Origin');
      if(req.method==='OPTIONS'){const method=req.headers['access-control-request-method'],wanted=req.headers['access-control-request-headers']??'';
        if((!validOrigin(req)&&!publisherOrigin)||!['GET','POST','DELETE'].includes(method)||wanted.split(',').filter(Boolean).some(key=>!['authorization','content-type'].includes(key.trim().toLowerCase())))throw fault('preflight_denied',403);
        res.writeHead(204,{'Access-Control-Allow-Methods':method,'Access-Control-Allow-Headers':publisherOrigin&&!validOrigin(req)?'Content-Type':'Authorization, Content-Type','Access-Control-Max-Age':'60'});res.end();return;}
      if(path==='config'&&req.method==='GET'){respond(res,200,publicConfig);return;}
      if(await discovery.handle(req,res,path,owner))return;
      if(!settings.enabled)throw fault('admission_disabled',503);
      if(path==='sessions'&&req.method==='POST'){
        const request=await body(req);if(!exact(request,['sourceId','attach'])||request.sourceId!==undefined&&typeof request.sourceId!=='string'||
          Object.hasOwn(request,'attach')&&(request.attach!==true||typeof request.sourceId!=='string'))throw fault('invalid_body');
        const parent=request.attach===true?authenticate(req):null;
        if(parent&&(parent.parentId||parent.clientKey!==owner.key))throw fault('attachment_parent_required',403);
        if(request.sourceId!==undefined&&!targets.has(request.sourceId))throw fault('unknown_source');
        if(parent&&parent.group.sources.has(request.sourceId))throw fault('duplicate_source',409);
        if(parent&&parent.group.sources.size>=limits.maxCommonConnections)throw fault('attachment_capacity',409);
        if(sessions.size+pendingAdmissions>=limits.maxSessions)throw fault('session_capacity',503);
        if([...sessions.values()].filter(s=>s.clientKey===owner.key).length+owner.pending+discovery.countClient(owner.key)>=limits.maxSessionsPerClient)throw fault('client_session_capacity',429);
        if(!owner.admissions.take())throw fault('admission_rate',429);
        if(parent&&!account(parent,req.bodyBytes,'in'))throw fault('bandwidth_capacity',429);
        // Reserve both the slot and source before the first native metadata await.
        if(parent)parent.group.sources.add(request.sourceId);
        pendingAdmissions++;owner.pending++;
        let node,caps,committed=false;
        let frontGone=false;res.once('close',()=>{if(!res.writableEnded)frontGone=true;});
        const parentGone=()=>parent&&(sessions.get(parent.id)!==parent||parent.expiresAt<=now());
        const cancelled=()=>frontGone||res.destroyed||closed||parentGone()||(node&&!activeNode(node));
        try{
          ({node,caps}=await choose(request.sourceId,cancelled));
          if(cancelled()){if(parentGone())throw fault('session_required',401);if(node&&!activeNode(node))throw fault('native_unavailable',503);return;}
          const reply=await nativeRequest(node,'sessions',{method:'POST',body:'{}'});if(reply.status!==201){if(reply.status!==429)invalidateNative(node);throw fault('native_admission_failed',reply.status===429?429:502);}
          const native=strictJSON(reply.body,limits.maxNativeResponseBytes);
          if(!exact(native,['token','browserId','expiresAt'])||!TOKEN.test(native.token??'')||!/^[a-f0-9]{32}$/.test(native.browserId??'')||!Number.isSafeInteger(native.expiresAt)||native.expiresAt<=now()||native.expiresAt>now()+305000)throw fault('invalid_native_session',502);
          if(cancelled()){await releaseNative(node,native.token,native.expiresAt);if(parentGone())throw fault('session_required',401);if(node&&!activeNode(node))throw fault('native_unavailable',503);return;}
          const group=parent?.group??{root:null,members:new Set(),sources:new Set([node.id]),transferred:req.bodyBytes,
            incoming:new Bucket(limits.sessionBytesPerSecond,131072,now),outgoing:new Bucket(limits.sessionBytesPerSecond,131072,now)};
          const token=randomBytes(32).toString('hex'),session={id:opaque(),peerId:parent?.peerId??opaque(),parentId:parent?.id??null,group,browserId:native.browserId,node,nativeLimits:caps,nativeToken:native.token,tokenHash:hash(token),
            expiresAt:Math.min(native.expiresAt,now()+limits.sessionLeaseMs),order:++order,clientKey:owner.key,peers:new Set(),ice:new Map(),signal:null,front:null,upstream:null,
            geo:settings.trustedCountryHeader?countryCentroid(req.headers[settings.trustedCountryHeader]):null,
            requests:new Bucket(limits.sessionRequestsPerSecond,16,now),incoming:group.incoming,outgoing:group.outgoing,
            signals:new Bucket(limits.signalingBytesPerSecond,32768,now),messages:new Bucket(10,20,now),control:new Bucket(10,20,now)};
          if(!parent)group.root=session;group.members.add(session);sessions.set(session.id,session);committed=true;
          // A failed initial response gives the browser no token with which to release its new native lease.
          res.once('error',()=>drop(session,{reason:'response_failed'}));res.once('close',()=>{if(!res.writableFinished)drop(session,{reason:'response_failed'});});
          if(!respond(res,201,{id:session.id,peerId:session.peerId,browserId:session.browserId,sourceId:node.id,nodeId:node.nodeId,token,
            expiresAt:session.expiresAt,peers:[],iceServers:iceServers(session),geo:session.geo,nativeLimits:session.nativeLimits,
            ...parent?{parentId:parent.id}:{maxAttachments:limits.maxCommonConnections}},session))drop(session,{reason:'response_failed'});
        }finally{pendingAdmissions--;owner.pending--;if(node)nodeState.get(node).pending--;if(parent&&!committed)parent.group.sources.delete(request.sourceId);}
        return;
      }
      if(!['renew','sessions','status'].includes(path))throw fault('not_found',404);
      if(req.headers['transfer-encoding']||Number(req.headers['content-length']??0)!==0)throw fault('body_denied');
      const session=authenticate(req);
      if(path==='sessions'&&req.method==='DELETE'){await drop(session,{reason:'manual_off'});
        res.writeHead(204,headers);res.end();return;}
      if(path==='renew'&&req.method==='POST'){
        const reply=await nativeRequest(session.node,'renew',{method:'POST',token:session.nativeToken});if(reply.status!==200){drop(session);throw fault('native_renew_failed',reply.status===401?401:502);}
        const native=strictJSON(reply.body,limits.maxNativeResponseBytes);if(!exact(native,['expiresAt'])||!Number.isSafeInteger(native.expiresAt)||native.expiresAt<=now()||native.expiresAt>now()+305000){drop(session);throw fault('invalid_native_renewal',502);}
        if(sessions.get(session.id)!==session)throw fault('session_required',401);session.expiresAt=Math.min(native.expiresAt,now()+limits.sessionLeaseMs);
        respond(res,200,{expiresAt:session.expiresAt,iceServers:iceServers(session)},session);return;
      }
      if(path==='status'&&req.method==='GET'){
        const native=await nativeStatus(session.node);
        respond(res,200,{...native,sourceId:session.node.id,nodeId:session.node.nodeId,participants:[...sessions.values()].filter(s=>s.signal?.readyState===1).length,
          leases:sessions.size,nativeLimits:session.nativeLimits,session:{transferredBytes:session.group.transferred,transferLimitBytes:limits.maxSessionTransferBytes,
            attachments:session.group.members.size,maxAttachments:limits.maxCommonConnections},gateway:{dropReasons:{...dropReasons}}},session);return;
      }
      throw fault('method_denied',405);
    }catch(cause){if(!res.headersSent&&!res.destroyed)respond(res,cause.status??502,{error:{code:cause.code??'native_unavailable'}});
      if(['body_limit','invalid_body'].includes(cause.code))res.on('finish',()=>req.destroy());}
  });
  server.maxConnections=limits.maxConnections;server.on('connection',socket=>{connections.add(socket);socket.on('close',()=>connections.delete(socket));});
  const signaling=new WebSocketServer({noServer:true,maxPayload:limits.maxSignalBytes,perMessageDeflate:false,autoPong:false});
  const nativeFront=new WebSocketServer({noServer:true,maxPayload:limits.maxNativeFrameBytes,perMessageDeflate:false,autoPong:false});
  server.on('upgrade',(req,socket,head)=>{try{
    sweep();const owner=client(req);
    if(closed||![BASE+'/signal',BASE+'/connect',BASE+'/rendezvous',BASE+'/source'].includes(req.url)||sockets.size>=limits.maxConnections||!requests.take()||!owner.requests.take())throw fault('upgrade_denied');
    if(req.url===BASE+'/source'){sourceUplink.upgrade(req,socket,head,owner);return;}
    if(!validOrigin(req))throw fault('upgrade_denied');
    if(req.url===BASE+'/rendezvous'){discovery.upgrade(req,socket,head,owner);return;}
    if(!settings.enabled)throw fault('admission_disabled');
    const key=owner.key;if([...sockets].filter(ws=>ws.clientKey===key).length>=limits.maxSignalConnectionsPerClient*2)throw fault('client_connection_capacity');
    const receiver=req.url===BASE+'/signal'?signaling:nativeFront;receiver.handleUpgrade(req,socket,head,ws=>{ws.clientKey=key;receiver.emit('connection',ws);});
  }catch{socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');}});
  signaling.on('connection',ws=>{
    sockets.add(ws);let session=null;const authTimer=setTimeout(()=>ws.terminate(),limits.authTimeoutMs);authTimer.unref();ws.on('error',()=>{});
    const control=()=>{if(!session||!session.control.take())ws.close(1008,'invalid control');};ws.on('ping',control);ws.on('pong',control);
    ws.on('close',()=>{clearTimeout(authTimer);sockets.delete(ws);if(session?.signal===ws){session.signal=null;session.peers.clear();session.ice.clear();pair();}});
    ws.on('message',(data,binary)=>{try{
      if(binary||!signalBytes.take(data.length))throw fault('signal_capacity');const message=strictJSON(data,limits.maxSignalBytes);
      if(!session){if(!exact(message,['type','id','token'])||message.type!=='auth')throw fault('authentication_required');const found=authToken(message.token);
        if(found.id!==message.id||found.parentId||found.signal)throw fault('authentication_failed');session=found;session.signal=ws;clearTimeout(authTimer);pair();
        if(!account(session,data.length,'in'))throw fault('signal_rate');sendSignal(session,{type:'ready',id:session.id,peerId:session.peerId,browserId:session.browserId,sourceId:session.node.id,nodeId:session.node.nodeId,expiresAt:session.expiresAt,peers:peerList(session),geo:session.geo,iceServers:iceServers(session)});return;}
      if(session.expiresAt<=now()){drop(session);return;}if(!account(session,data.length,'in')||!session.messages.take()||!session.signals.take(data.length))throw fault('signal_rate');
      if(message.type==='leave'&&exact(message,['type'])){drop(session,{reason:'manual_off'});return;}if(message.type==='ping'&&exact(message,['type'])){sendSignal(session,{type:'pong'});return;}
      if(!['offer','answer','ice'].includes(message.type)||!exact(message,['type','to',message.type==='ice'?'candidate':'sdp'])||!session.peers.has(message.to))throw fault('unassigned_peer');
      const target=[...sessions.values()].find(s=>!s.parentId&&s.peerId===message.to);if(!target?.peers.has(session.peerId)||target.signal?.readyState!==1)throw fault('peer_unavailable');
      if(message.type==='ice'){
        const c=message.candidate;if(c!==null&&(!exact(c,['candidate','sdpMid','sdpMLineIndex','usernameFragment'])||typeof c.candidate!=='string'||c.candidate.length>4096||
          c.sdpMid!=null&&(typeof c.sdpMid!=='string'||c.sdpMid.length>128)||c.usernameFragment!=null&&(typeof c.usernameFragment!=='string'||c.usernameFragment.length>128)||
          c.sdpMLineIndex!=null&&(!Number.isInteger(c.sdpMLineIndex)||c.sdpMLineIndex<0||c.sdpMLineIndex>65535)))throw fault('invalid_ice');
        const count=(session.ice.get(message.to)??0)+1;if(count>limits.maxIceCandidates)throw fault('ice_capacity');session.ice.set(message.to,count);
      }else{if(typeof message.sdp!=='string'||!message.sdp.length||Buffer.byteLength(message.sdp)>32000)throw fault('invalid_sdp');if(message.type==='offer'){session.ice.set(message.to,0);target.ice.set(session.peerId,0);}}
      if(!sendSignal(target,{...message,from:session.peerId}))throw fault('peer_capacity');
    }catch{ws.close(1008,'invalid or limited signaling');}});
  });
  nativeFront.on('connection',front=>{
    sockets.add(front);let session=null;const timer=setTimeout(()=>front.terminate(),limits.nativeAuthTimeoutMs);timer.unref();front.on('error',()=>{});
    front.on('close',()=>{clearTimeout(timer);sockets.delete(front);if(session?.front===front)drop(session,{reason:'client_closed'});});
    const abort=(reason='invalid_control')=>{if(session)drop(session,{reason});else front.close(1008,'invalid native connection');};
    front.on('ping',()=>abort());
    front.on('pong',data=>{
      if(!session?.nativeReady||!session.control.take()||data.length>125)return abort();const key=data.toString('hex'),ping=session.nativePings.get(key);
      if(!ping||!account(session,data.length,'in'))return abort();session.nativePings.delete(key);if(session.upstream.readyState===1)session.upstream.pong(data);else abort();
    });
    front.on('message',(data,binary)=>{try{
      if(!session){const message=strictJSON(data,limits.maxNativeFrameBytes);if(!exact(message,['token']))throw fault('authentication_required');
        const found=authToken(message.token);if(found.front||found.upstream)throw fault('already_attached');session=found;session.front=front;session.nativeReady=false;session.nativePings=new Map();clearTimeout(timer);
        if(!account(session,data.length,'in')||!nodeState.get(session.node).requests.take())throw fault('native_capacity');
        const upstream=session.node.uplink?session.node.uplink.connect(session.nativeToken):new WebSocket('ws://localhost'+BASE+'/connect',{createConnection:()=>connectUnix({path:session.node.socketPath}),origin:settings.nativeOrigin,maxPayload:limits.maxNativeFrameBytes,
          perMessageDeflate:false,autoPong:false,handshakeTimeout:2000});session.upstream=upstream;upstream.on('error',()=>abort('upstream_error'));upstream.on('close',()=>drop(session,{reason:'upstream_closed'}));
        session.nativeAuthTimer=setTimeout(()=>abort('native_auth_timeout'),limits.nativeAuthTimeoutMs);session.nativeAuthTimer.unref();
        upstream.on('open',()=>{if(sessions.get(session.id)!==session||front.readyState!==1)return upstream.terminate();upstream.send(JSON.stringify({token:session.nativeToken}));});
        upstream.on('message',(raw,isBinary)=>{try{
          if(isBinary||raw.length>limits.maxNativeFrameBytes||front.readyState!==1)throw fault('invalid_native_frame');
          if(!session.nativeReady){const hello=strictJSON(raw,limits.maxNativeFrameBytes);
            if(!exact(hello,['type','session','browserId','protocol','advertisement'])||hello.type!=='hello'||hello.protocol!=='cypher-browser-mesh/1'||hello.browserId!==session.browserId||!/^[a-f0-9]{32}$/.test(hello.session??''))throw fault('invalid_native_hello');
            const ad=hello.advertisement;if(!exact(ad,['payloadBase64','signatureHex'])||typeof ad.payloadBase64!=='string'||!/^([A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(ad.payloadBase64))throw fault('invalid_native_advertisement');
            const payload=strictJSON(Buffer.from(ad.payloadBase64,'base64'),8192);
            let publicKey;try{publicKey=enodePublicKey(payload.enode);}catch{throw fault('native_pin_mismatch');}
            if(publicKey!==enodePublicKey(session.node.enode)||payload.network?.chainId!==settings.network.chainId||payload.network?.genesisHash!==settings.network.genesisHash)throw fault('native_pin_mismatch');
            session.nativeReady=true;clearTimeout(session.nativeAuthTimer);
          }
          if(front.bufferedAmount+raw.length>limits.maxNativeBufferedBytes||!account(session,raw.length))throw fault('native_capacity');front.send(raw,{binary:false});
        }catch(cause){abort(cause.code||'invalid_native_frame');}});
        upstream.on('ping',payload=>{
          if(!session.nativeReady||!session.control.take()||payload.length>125||front.readyState!==1||!account(session,payload.length))return abort();const key=payload.toString('hex');
          if(session.nativePings.size>=3&&!session.nativePings.has(key))return abort();if(!session.nativePings.has(key))session.nativePings.set(key,{deadline:now()+limits.nativePingTimeoutMs});front.ping(payload);
        });
        upstream.on('pong',()=>abort());return;
      }
      if(binary||!session.nativeReady||session.upstream.readyState!==1||session.expiresAt<=now()||data.length>limits.maxNativeFrameBytes||
        session.upstream.bufferedAmount+data.length>limits.maxNativeBufferedBytes||!account(session,data.length,'in'))throw fault('native_capacity');
      session.upstream.send(data,{binary:false});
    }catch(cause){abort(cause.code||'invalid_native_frame');}});
  });
  return {server,config:publicConfig,sweep:()=>{sweep();discovery.sweep();},refreshDiscovery:discovery.refreshNative,stats:()=>({sourceUplink:sourceUplink.stats(),discovery:discovery.stats(),sessions:sessions.size,pendingAdmissions,webSockets:sockets.size,connections:connections.size,rateBuckets:clients.size,nodes:Object.fromEntries([...nodeState].filter(([node])=>activeNode(node)).map(([node,state])=>[node.id,{sessions:nativeCount(node)-state.pending-state.releases.size,pending:state.pending,releasing:state.releases.size,metadata:state.metadata,limits:state.capabilities}])),dropReasons:{...dropReasons}}),
    listen:({port=settings.listenPort,host=settings.listenHost}={})=>new Promise((resolve,reject)=>{if(!['127.0.0.1','::1'].includes(host))return reject(new Error('Loopback listener required'));server.once('error',reject);server.listen(port,host,()=>{server.removeListener('error',reject);resolve(server.address());});}),
    close:async()=>{if(closed)return;closed=true;clearInterval(timer);await sourceUplink.close();await discovery.close();for(const s of [...sessions.values()])drop(s,{reason:'gateway_shutdown'});for(const ws of sockets)ws.terminate();for(const c of connections)c.destroy();
      for(const controller of pending)controller.abort();await Promise.all([new Promise(r=>signaling.close(r)),new Promise(r=>nativeFront.close(r))]);if(server.listening)await new Promise(r=>server.close(r));},
  };
}
