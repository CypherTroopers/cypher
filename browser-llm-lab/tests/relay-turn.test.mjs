// Optional real coturn allocation/security test. No secret or issued credential is printed.
import test from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import { createHmac,createHash,randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { loadTurnSecret,turnCredentials } from '../relay/turn.mjs';

const enabled=process.env.RELAY_TURN_TEST==='1';
const endpoint={host:process.env.RELAY_TURN_HOST||'127.0.0.1',port:Number(process.env.RELAY_TURN_PORT||34790)};
const secretPath=process.env.RELAY_TURN_SECRET||fileURLToPath(new URL('../.runtime/relay-turn/rest-secret',import.meta.url));
const attribute=(type,value)=>{const out=Buffer.alloc(4+value.length+((4-value.length%4)%4));out.writeUInt16BE(type);out.writeUInt16BE(value.length,2);value.copy(out,4);return out;};
function message(type,attrs,key) {
  let body=Buffer.concat(attrs),header=Buffer.alloc(20);header.writeUInt16BE(type);header.writeUInt16BE(body.length+(key?24:0),2);
  header.writeUInt32BE(0x2112a442,4);randomBytes(12).copy(header,8);
  if(key)body=Buffer.concat([body,attribute(8,createHmac('sha1',key).update(Buffer.concat([header,body])).digest())]);
  return Buffer.concat([header,body]);
}
function parse(bytes) {
  assert.ok(bytes.length>=20,'Bounded STUN response header');const attrs=new Map();
  for(let at=20;at+4<=bytes.length;){const kind=bytes.readUInt16BE(at),size=bytes.readUInt16BE(at+2);assert.ok(at+4+size<=bytes.length);attrs.set(kind,bytes.subarray(at+4,at+4+size));at+=4+size+((4-size%4)%4);}
  const error=attrs.get(9);return {type:bytes.readUInt16BE(0),attrs,code:error?error[2]*100+error[3]:null};
}
function transact(socket,request) {
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{cleanup();reject(new Error('TURN response timed out'));},3000);
    const cleanup=()=>{clearTimeout(timer);socket.off('message',received);socket.off('error',failed);};
    const failed=()=>{cleanup();reject(new Error('TURN socket failed'));};
    const received=bytes=>{if(bytes.length<20||!bytes.subarray(8,20).equals(request.subarray(8,20)))return;cleanup();try{resolve(parse(bytes));}catch(cause){reject(cause);}};
    socket.on('message',received);socket.on('error',failed);socket.send(request,endpoint.port,endpoint.host,err=>{if(err)failed();});
  });
}
async function client(t,credential) {
  const socket=dgram.createSocket('udp4');t.after(()=>socket.close());
  const initial=await transact(socket,message(3,[attribute(0x19,Buffer.from([17,0,0,0]))]));
  assert.equal(initial.code,401,'Unauthenticated TURN allocation requires authentication');
  const realm=initial.attrs.get(0x14),nonce=initial.attrs.get(0x15);assert.ok(realm&&nonce);
  const username=Buffer.from(credential.username),key=createHash('md5').update(Buffer.concat([username,Buffer.from(':'),realm,Buffer.from(':'+credential.credential)])).digest();
  const auth=[attribute(6,username),attribute(0x14,realm),attribute(0x15,nonce)];
  return {socket,allocate:()=>transact(socket,message(3,[...auth,attribute(0x19,Buffer.from([17,0,0,0]))],key)),
    request:(type,attrs)=>transact(socket,message(type,[...auth,...attrs],key))};
}

test('actual isolated coturn rejects unauthenticated, expired and forged credentials', {skip:!enabled},async t=>{
  const secret=loadTurnSecret(secretPath),peerId=randomBytes(16).toString('hex');
  const valid=turnCredentials({urls:[],ttlSeconds:300},secret,{peerId,expiresAt:Date.now()+300000});
  const forged=await client(t,{...valid,credential:'invalid-credential'});assert.notEqual((await forged.allocate()).type,0x103);
  const username=`${Math.floor(Date.now()/1000)-60}:${peerId}`;
  const expired=await client(t,{username,credential:createHmac('sha1',secret).update(username).digest('base64')});
  assert.notEqual((await expired.allocate()).type,0x103);
});

test('actual isolated coturn enforces six allocations per peer and rejects private peer permissions', {skip:!enabled},async t=>{
  const secret=loadTurnSecret(secretPath),peerId=randomBytes(16).toString('hex');
  const credential=turnCredentials({urls:[],ttlSeconds:300},secret,{peerId,expiresAt:Date.now()+300000});
  const clients=[];
  t.after(async()=>{for(const row of clients)await row.request(4,[attribute(0xd,Buffer.alloc(4))]).catch(()=>{});});
  for(let index=0;index<7;index++){
    const row=await client(t,credential);clients.push(row);const result=await row.allocate();
    if(index<6)assert.equal(result.type,0x103,'Valid credential obtains bounded allocation');
    else assert.equal(result.code,486,'Seventh allocation exceeds per-user quota');
  }
  const peer=Buffer.alloc(8);peer[1]=1;peer.writeUInt16BE(9^0x2112,2);peer.writeUInt32BE((0x0a000001^0x2112a442)>>>0,4);
  assert.equal((await clients[0].request(8,[attribute(0x12,peer)])).code,403,'Private network permission is refused');
});

test('actual isolated coturn delivers data between two public relay allocations', {skip:!enabled},async t=>{
  const secret=loadTurnSecret(secretPath),rows=[];
  t.after(async()=>{for(const row of rows)await row.request(4,[attribute(0xd,Buffer.alloc(4))]).catch(()=>{});});
  for(let index=0;index<2;index++){
    const row=await client(t,turnCredentials({urls:[],ttlSeconds:300},secret,{peerId:randomBytes(16).toString('hex'),expiresAt:Date.now()+300000}));
    const result=await row.allocate();assert.equal(result.type,0x103);row.relay=result.attrs.get(0x16);rows.push(row);
  }
  for(let index=0;index<2;index++){
    const response=await rows[index].request(8,[attribute(0x12,rows[1-index].relay)]);
    assert.deepEqual({type:response.type,code:response.code},{type:0x108,code:null},'Public relay permission accepted');
  }
  const received=new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{rows[1].socket.off('message',handler);reject(new Error('TURN relay data timed out'));},3000);
    const handler=bytes=>{const response=parse(bytes);if(response.type!==0x17)return;clearTimeout(timer);rows[1].socket.off('message',handler);resolve(response.attrs.get(0x13));};rows[1].socket.on('message',handler);
  });
  const payload=Buffer.from('actual bounded authenticated TURN data');
  rows[0].socket.send(message(0x16,[attribute(0x12,rows[1].relay),attribute(0x13,payload)]),endpoint.port,endpoint.host);
  assert.deepEqual(await received,payload);
});
