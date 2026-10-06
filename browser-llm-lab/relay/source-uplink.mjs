import { EventEmitter } from 'node:events';
import { randomBytes } from 'node:crypto';
import { WebSocketServer } from 'ws';
import { strictJSON, exactFields, decodeBase64 } from '../public/relay-protocol.js';
import { EndpointCache, verifyEndpoint } from '../public/mesh-discovery.js';
import { secp256k1, keccak_256 } from '../public/vendor/mesh-crypto.js';

const BASE='/relay/v1/mesh',ID=/^[a-f0-9]{32}$/,TOKEN=/^[a-f0-9]{64}$/;
const PACKET=98304,QUEUE=524288,HISTORY=4096;
const DOMAIN=Buffer.from('cypher-browser-mesh-source-v1\0');
const fault=code=>Object.assign(new Error(code),{code,status:502});
const check=(condition,code)=>{if(!condition)throw fault(code);};
const opaque=()=>randomBytes(16).toString('hex');
const unbase64=(value,max)=>Buffer.from(decodeBase64(value,max));
function exact(value,fields){exactFields(value,fields);}
export function verifySourceProof(challenge,signatureHex,publicKey) {
  check(typeof signatureHex==='string'&&/^[a-f0-9]{130}$/.test(signatureHex),'source_signature');
  const signature=Buffer.from(signatureHex,'hex');check(signature[64]<=1,'source_signature');
  const digest=keccak_256(Buffer.concat([DOMAIN,Buffer.from(challenge)]));
  const recovered=secp256k1.recoverPublicKey(Buffer.concat([signature.subarray(64),signature.subarray(0,64)]),digest,{prehash:false});
  check(Buffer.from(secp256k1.Point.fromBytes(recovered).toBytes(false)).subarray(1).toString('hex')===publicKey,'source_signature');
  check(secp256k1.verify(signature.subarray(0,64),digest,Buffer.from('04'+publicKey,'hex'),{prehash:false,lowS:true}),'source_signature');
}

/** An authenticated outbound native transport; it never dials a supplied URL,
 * socket or RPC path. All browser accounting remains in the existing gateway. */
export function createSourceUplink({settings,now,makeBucket,sockets,takeBytes,onAdd,onRemove,onRefresh}) {
  const enabled=settings.sourceUplink?.enabled===true,visitors=new Set();
  const wss=new WebSocketServer({noServer:true,maxPayload:PACKET,perMessageDeflate:false,autoPong:false});
  const cache=new EndpointCache(settings.network,{now,maxEntries:64});
  let closed=false;
  const metrics={accepted:0,rejected:0,receivedBytes:0,sentBytes:0,expired:0,timeouts:0};
  const countClient=key=>[...visitors].filter(v=>v.owner.key===key).length;
  function terminate(v) {
    if(v.closed)return;v.closed=true;visitors.delete(v);clearTimeout(v.authTimer);
    // Remove the target before notifying stream callbacks or rejecting metadata.
    onRemove(v.node);
    for(const row of v.requests.values()){clearTimeout(row.timer);row.reject(fault('source_disconnected'));}
    v.requests.clear();
    for(const stream of [...v.streams.values()])finishStream(v,stream,false);
    v.queue.length=0;v.queueBytes=0;v.writes=0;v.writeBytes=0;v.writeTimes.clear();v.ids.clear();
    v.ws.terminate();
  }
  function reject(v){metrics.rejected++;terminate(v);}
  function enqueue(v,packet,stream=null) {
    if(v.closed||v.ws.readyState!==1)return false;
    const text=JSON.stringify(packet),size=Buffer.byteLength(text);
    if(size>PACKET||v.queue.length+v.writes>=64||v.queueBytes+v.writeBytes+size>QUEUE){reject(v);return false;}
    const row={text,size,stream,enqueued:now()};v.queue.push(row);v.queueBytes+=size;if(stream)stream.bufferedAmount+=size;
    pump(v);return !v.closed;
  }
  function pump(v) {
    if(v.closed||v.ws.readyState!==1)return;
    if(v.queue.some(row=>now()-row.enqueued>2000)||v.writeTimes.size&&now()-Math.min(...v.writeTimes.values())>2000){metrics.timeouts++;terminate(v);return;}
    while(v.queue.length){
      const row=v.queue[0];
      if(v.ws.bufferedAmount+row.size>QUEUE)return;
      if(!v.outBytes.take(row.size)||!v.outMessages.take())return;
      if(!takeBytes(row.size)){reject(v);return;}
      v.queue.shift();v.queueBytes-=row.size;v.writes++;v.writeBytes+=row.size;
      const writeId=++v.writeSequence;v.writeTimes.set(writeId,now());metrics.sentBytes+=row.size;
      try{v.ws.send(row.text,error=>{
        if(v.closed)return;
        v.writes--;v.writeBytes-=row.size;v.writeTimes.delete(writeId);
        if(row.stream)row.stream.bufferedAmount=Math.max(0,row.stream.bufferedAmount-row.size);
        if(error)terminate(v);
      });}catch{terminate(v);return;}
    }
  }
  function remember(v,id){check(v.ids.size<HISTORY&&!v.ids.has(id),'source_history_capacity');v.ids.add(id);}
  function finishStream(v,stream,notify=true) {
    if(stream.readyState===3)return;
    stream.readyState=3;clearTimeout(stream.timer);v.streams.delete(stream.id);stream.bufferedAmount=0;
    // Purge this stream before enqueue can pump any previously delayed text.
    v.queue=v.queue.filter(row=>{if(row.stream!==stream)return true;v.queueBytes-=row.size;return false;});
    if(notify&&!v.closed)enqueue(v,{kind:'close',id:stream.id});
    stream.emit('close');stream.removeAllListeners();
  }
  function connect(v,token) {
    const stream=new EventEmitter();Object.assign(stream,{id:opaque(),readyState:0,bufferedAmount:0,timer:null});
    const send=(kind,data,max)=>{
      check(stream.readyState===1&&!v.closed,'source_stream_closed');const raw=Buffer.from(data);
      check(raw.length<=max,'source_stream_limit');
      if(!enqueue(v,{kind,id:stream.id,data:raw.toString('base64')},stream))throw fault('source_unavailable');
    };
    stream.send=(data,options={})=>{check(options.binary!==true,'source_binary_denied');send('message',data,16384);};
    stream.pong=data=>send('pong',data,125);
    stream.close=stream.terminate=()=>finishStream(v,stream);
    // EventEmitter consumers install handlers immediately after connect returns.
    queueMicrotask(()=>{
      try{
        if(stream.readyState!==0)return;
        check(!v.closed&&TOKEN.test(token)&&v.streams.size<80,'source_stream_capacity');remember(v,stream.id);
        v.streams.set(stream.id,stream);
        if(!enqueue(v,{kind:'open',id:stream.id,token}))throw fault('source_unavailable');
        stream.timer=setTimeout(()=>{metrics.timeouts++;finishStream(v,stream);},3000);stream.timer.unref();
      }catch(error){if(error.code==='source_history_capacity')terminate(v);if(stream.listenerCount('error'))stream.emit('error',error);finishStream(v,stream);}
    });
    return stream;
  }
  function request(v,path,{method='GET',token,body,maxResponse=16384}={}) {
    if(v.closed)return Promise.reject(fault('source_disconnected'));
    if(path==='endpoint')return Promise.resolve({status:200,body:Buffer.from(JSON.stringify(v.record.envelope))});
    const valid=(method==='GET'&&['config','status'].includes(path)&&token===undefined&&body===undefined)||
      (path==='sessions'&&method==='POST'&&token===undefined&&[undefined,'','{}'].includes(body))||
      ((path==='renew'&&method==='POST'||path==='sessions'&&method==='DELETE')&&TOKEN.test(token??'')&&body===undefined);
    if(!valid)return Promise.reject(fault('source_path_denied'));
    if(v.requests.size>=8)return Promise.reject(fault('source_metadata_capacity'));
    return new Promise((resolve,rejectRequest)=>{
      const id=opaque(),row={resolve,reject:rejectRequest,maxResponse:Math.min(path==='status'?65536:16384,maxResponse),timer:null};
      if(v.requests.has(id)||v.ids.has(id)){rejectRequest(fault('source_id_collision'));return;}
      v.requests.set(id,row);
      row.timer=setTimeout(()=>{metrics.timeouts++;terminate(v);},3000);row.timer.unref();
      if(!enqueue(v,{kind:'request',id,method,path:BASE+'/'+path,...token?{token}:{},...body!==undefined?{body:Buffer.from(body).toString('base64')}:{}}))terminate(v);
    });
  }
  function validateRecord(v,envelope,{renew=false}={}) {
    const record=verifyEndpoint(envelope,settings.network,now());
    check(record.sourceId===record.nodeId&&record.origin===settings.origin,'source_endpoint_identity');
    if(renew)check(record.nodeId===v.record.nodeId&&record.sourceId===v.record.sourceId&&record.payload.bootId===v.record.payload.bootId&&
      record.payload.sequence>v.record.payload.sequence,'source_endpoint_generation');
    return cache.add(envelope);
  }
  async function authenticate(v,message) {
    exact(message,['kind','endpoint','signatureHex']);
    check(message.kind==='auth'&&!v.authenticating&&v.challengeExpires>now(),'source_authentication');
    const record=verifyEndpoint(message.endpoint,settings.network,now());
    verifySourceProof(v.challenge,message.signatureHex,record.publicKey);
    check(![...visitors].some(other=>other!==v&&other.record?.nodeId===record.nodeId),'source_duplicate');
    v.record=validateRecord(v,message.endpoint);v.authenticating=true;clearTimeout(v.authTimer);
    const transport={get closed(){return v.closed;},request:(path,options)=>request(v,path,options),connect:token=>connect(v,token)};
    // The native first receives ready, then handles the capability probe. The
    // target is not public/admissible until onAdd has validated that response.
    if(!enqueue(v,{kind:'ready',sourceId:record.sourceId,nodeId:record.nodeId}))return;
    try{
      const node=await onAdd(v.record,transport);
      if(v.closed){onRemove(node);return;}
      v.node=node;v.authenticating=false;v.lastPong=now();metrics.accepted++;
    }catch{reject(v);}
  }
  function message(v,raw,binary) {
    try{
      check(!binary&&raw.length<=(v.record?PACKET:8192)&&v.inBytes.take(raw.length)&&v.inMessages.take()&&takeBytes(raw.length),'source_message_capacity');
      metrics.receivedBytes+=raw.length;
      const packet=strictJSON(raw,v.record?PACKET:8192);
      if(!v.record){void authenticate(v,packet).catch(()=>reject(v));return;}
      if(packet.kind==='advertise'){
        exact(packet,['kind','endpoint']);check(!v.authenticating,'source_initializing');
        const record=validateRecord(v,packet.endpoint,{renew:true});onRefresh(v.node,record.envelope);v.record=record;return;
      }
      check(ID.test(packet.id??''),'source_invalid_id');
      if(packet.kind==='reply'){
        exact(packet,['kind','id','status','body']);const row=v.requests.get(packet.id);
        check(row&&Number.isSafeInteger(packet.status)&&packet.status>=100&&packet.status<=599,'source_reply');
        const body=unbase64(packet.body,row.maxResponse);check(packet.status!==204||body.length===0,'source_reply');
        v.requests.delete(packet.id);clearTimeout(row.timer);row.resolve({status:packet.status,body});return;
      }
      const stream=v.streams.get(packet.id);
      if(packet.kind==='close'){
        exact(packet,['kind','id']);check(stream||v.ids.has(packet.id),'source_unknown_stream');if(stream)finishStream(v,stream,false);return;
      }
      if(packet.kind==='opened'){
        exact(packet,['kind','id']);if(!stream&&v.ids.has(packet.id))return;check(stream?.readyState===0,'source_opened');stream.readyState=1;clearTimeout(stream.timer);stream.emit('open');return;
      }
      check(['message','ping','pong'].includes(packet.kind),'source_invalid_type');exact(packet,['kind','id','data']);
      const rawData=unbase64(packet.data,packet.kind==='message'?16384:125);
      // In-flight packets after our local close cannot recreate their stream.
      if(!stream&&v.ids.has(packet.id))return;
      check(stream?.readyState===1,'source_unknown_stream');
      if(packet.kind==='message')stream.emit('message',rawData,false);else stream.emit(packet.kind,rawData);
    }catch{reject(v);}
  }
  function upgrade(req,socket,head,owner) {
    check(enabled&&!closed&&settings.enabled&&req.headers.origin===settings.origin,'source_disabled_or_origin');
    owner.sourceAdmissions??=makeBucket(1,4);
    check(owner.sourceAdmissions.take()&&visitors.size<settings.sourceUplink.maxSources&&countClient(owner.key)<settings.sourceUplink.maxSourcesPerClient&&
      [...visitors].filter(v=>!v.node).length<8&&[...visitors].filter(v=>v.owner.key===owner.key&&!v.node).length<2,'source_admission_capacity');
    wss.handleUpgrade(req,socket,head,ws=>{
      if(closed){ws.terminate();return;}
      const expiresAt=now()+5000,challenge=Buffer.from(JSON.stringify({version:1,origin:settings.origin,nonce:opaque(),expiresAt}));
      const v={ws,owner,challenge,challengeExpires:expiresAt,record:null,node:null,closed:false,authenticating:false,requests:new Map(),streams:new Map(),ids:new Set(),
        queue:[],queueBytes:0,writes:0,writeBytes:0,writeSequence:0,writeTimes:new Map(),lastPing:now(),lastPong:now(),ping:null,
        inBytes:makeBucket(393216,524288),outBytes:makeBucket(393216,524288),inMessages:makeBucket(128,256),outMessages:makeBucket(128,256),
        inControl:makeBucket(32,80),outControl:makeBucket(32,80),authTimer:null};
      visitors.add(v);sockets.add(ws);ws.clientKey=owner.key;
      v.authTimer=setTimeout(()=>terminate(v),5000);v.authTimer.unref();
      ws.on('error',()=>terminate(v));ws.on('close',()=>{sockets.delete(ws);terminate(v);});ws.on('message',(raw,binary)=>message(v,raw,binary));
      ws.on('ping',raw=>{
        if(!v.record||raw.length>125||!v.inControl.take()||!v.outControl.take()||!takeBytes(raw.length*2)){reject(v);return;}
        try{ws.pong(raw);}catch{terminate(v);}
      });
      ws.on('pong',raw=>{
        if(!v.record||!v.inControl.take()||!v.ping||raw.toString('hex')!==v.ping||!takeBytes(raw.length)){reject(v);return;}
        v.ping=null;v.lastPong=now();
      });
      enqueue(v,{kind:'challenge',challenge:challenge.toString('base64')});
    });
  }
  function sweep() {
    if(closed)return;cache.prune();
    for(const v of visitors){
      if(!v.record&&v.challengeExpires<=now()){terminate(v);continue;}
      if(v.record&&(v.record.expiresAt<=now()||now()-v.lastPong>=15000)){metrics.expired++;terminate(v);continue;}
      if(v.record&&!v.ping&&now()-v.lastPing>=5000){
        const ping=randomBytes(8);v.ping=ping.toString('hex');v.lastPing=now();
        if(!v.outControl.take()||!takeBytes(ping.length)){reject(v);continue;}
        try{v.ws.ping(ping);}catch{terminate(v);continue;}
      }
      pump(v);
    }
  }
  const timer=setInterval(sweep,100);timer.unref();
  return {upgrade,sweep,stats:()=>({enabled,sources:[...visitors].filter(v=>v.node).length,pending:[...visitors].filter(v=>!v.node).length,
    streams:[...visitors].reduce((n,v)=>n+v.streams.size,0),metadata:[...visitors].reduce((n,v)=>n+v.requests.size,0),
    queuedBytes:[...visitors].reduce((n,v)=>n+v.queueBytes+v.writeBytes,0),...metrics}),
    close:async()=>{if(closed)return;closed=true;clearInterval(timer);for(const v of [...visitors])terminate(v);cache.records.clear();await new Promise(resolve=>wss.close(resolve));}};
}
