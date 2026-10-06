import { readFile, lstat } from 'node:fs/promises';
import { isAbsolute, normalize } from 'node:path';
import { isIP } from 'node:net';
import { strictJSON, validateNetwork } from '../public/relay-protocol.js';

const fields = (value, allowed, label) => {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !allowed.includes(key)))
    throw new Error(`Invalid ${label}`);
};
const id = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value);
const bounded = (value, fallback, min, max, label) => {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < min || result > max) throw new Error(`Invalid ${label}`);
  return result;
};
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
const validated=new WeakSet();

/** Unix targets remain operator-pinned. Opt-in native uplinks authenticate their own identity; no client URL is dialed. */
export function validateConfig(input) {
  if(validated.has(input))return input;
  fields(input, ['enabled','origin','nativeOrigin','listenHost','listenPort','network','nodes','limits','iceServers',
    'trustedCountryHeader','trustedClientIpHeader','turn','discovery','sourceUplink'], 'gateway configuration');
  if (input.enabled !== undefined && typeof input.enabled !== 'boolean') throw new Error('Invalid admission switch');
  const origin = new URL(input.origin);
  if (origin.origin !== input.origin || origin.username || origin.password ||
    !(origin.protocol === 'https:' || (origin.protocol === 'http:' && ['127.0.0.1','[::1]','localhost'].includes(origin.hostname))))
    throw new Error('An exact HTTPS or loopback origin is required');
  validateNetwork(input.network);
  const nativeOrigin=input.nativeOrigin??input.origin,nativeURL=new URL(nativeOrigin);
  if(nativeURL.origin!==nativeOrigin||nativeURL.username||nativeURL.password||
    !(nativeURL.protocol==='https:'||(nativeURL.protocol==='http:'&&['127.0.0.1','[::1]','localhost'].includes(nativeURL.hostname))))throw new Error('Invalid native Origin pin');
  if (!Array.isArray(input.nodes) || input.nodes.length > 64 || (input.enabled && !input.nodes.length && input.sourceUplink?.enabled!==true)) throw new Error('Invalid Common node pins');
  const nodes = input.nodes.map(node => {
    fields(node,['id','nodeId','enode','socketPath'],'Common node pin');
    if(!id(node.id)||typeof node.nodeId!=='string'||!/^[a-f0-9]{64}$/.test(node.nodeId)||
      typeof node.socketPath!=='string'||!isAbsolute(node.socketPath)||normalize(node.socketPath)!==node.socketPath||node.socketPath.length>100)
      throw new Error('Invalid Common identity or Unix socket');
    if(typeof node.enode!=='string'||node.enode.length>256||!/^enode:\/\/[a-f0-9]{128}@/.test(node.enode))throw new Error('Invalid enode pin');
    const descriptor=new URL(node.enode),host=descriptor.hostname.replace(/^\[|\]$/g,'');
    if(!isIP(host)||descriptor.password||descriptor.hash||descriptor.pathname||!descriptor.port||Number(descriptor.port)>65535||
      (descriptor.search&&!/^\?discport=\d{1,5}$/.test(descriptor.search)))throw new Error('Canonical numeric enode pin required');
    return structuredClone(node);
  });
  if(new Set(nodes.map(node=>node.id)).size!==nodes.length||new Set(nodes.map(node=>node.nodeId)).size!==nodes.length||
    new Set(nodes.map(node=>node.socketPath)).size!==nodes.length)throw new Error('Duplicate Common node pins');
  const raw = input.limits ?? {};
  fields(raw, ['maxSessions','maxSessionsPerClient','maxSessionTransferBytes','maxConnections','maxPeers','maxCommonConnections','httpRequestsPerSecond','httpBytesPerSecond',
    'sessionRequestsPerSecond','sessionBytesPerSecond','admissionsPerMinute','signalingBytesPerSecond'], 'capacity limits');
  if (input.enabled && ['maxSessions','maxConnections','httpBytesPerSecond'].some(key => !Object.hasOwn(raw,key)))
    throw new Error('Public admission requires explicit session, connection and bandwidth capacity');
  const limits = {
    maxSessions: bounded(raw.maxSessions,32,1,512,'session capacity'),
    maxConnections: bounded(raw.maxConnections,128,1,1024,'connection capacity'),
    maxPeers: bounded(raw.maxPeers,20,1,20,'peer capacity'),
    maxCommonConnections: bounded(raw.maxCommonConnections,20,1,20,'Common attachment capacity'),
    httpRequestsPerSecond: bounded(raw.httpRequestsPerSecond,128,1,4096,'HTTP rate'),
    httpBytesPerSecond: bounded(raw.httpBytesPerSecond,1048576,4096,64*1048576,'bandwidth'),
    sessionRequestsPerSecond: bounded(raw.sessionRequestsPerSecond,8,1,32,'session rate'),
    sessionBytesPerSecond: bounded(raw.sessionBytesPerSecond,65536,4096,1048576,'session bandwidth'),
    admissionsPerMinute: bounded(raw.admissionsPerMinute,32,1,256,'admission rate'),
    signalingBytesPerSecond: bounded(raw.signalingBytesPerSecond,4096,1024,4096,'signaling rate'),
    sessionLeaseMs:300000,renewAfterMs:120000,authTimeoutMs:5000,
    maxSignalBytes:32768,maxSignalBufferedBytes:65536,maxIceCandidates:64,
    maxNativeFrameBytes:16384,maxNativeBufferedBytes:65536,maxNativeResponseBytes:16384,maxNativeStatusBytes:65536,nativeAuthTimeoutMs:3000,
    maxSessionsPerCommon:80,nativeMetadataConcurrency:8,nativeConfigCacheMs:30000,nativeStatusCacheMs:1000,
    nativeAdmissionsPerSecond:1,nativeAdmissionBurst:8,
    nativePingTimeoutMs:15000,maxNativeControlBytes:125,maxNativeControlPerSecond:10,
  };
  limits.maxSessionsPerClient=bounded(raw.maxSessionsPerClient,Math.min(80,limits.maxSessions),1,Math.min(80,limits.maxSessions),'client session capacity');
  limits.maxSignalConnectionsPerClient=limits.maxSessionsPerClient+2;
  limits.maxSessionTransferBytes=bounded(raw.maxSessionTransferBytes,100*1048576,1048576,100*1048576,'session transfer budget');
  if (limits.maxConnections < 2*limits.maxSessions+8) throw new Error('Connection capacity must cover two sockets per session and eight HTTP slots');
  if(input.enabled===true&&input.sourceUplink?.enabled!==true&&limits.maxSessions>nodes.length*limits.maxSessionsPerCommon)throw new Error('Session capacity exceeds registered Common capacity');
  let sourceUplink=null;
  if(input.sourceUplink!==undefined&&input.sourceUplink!==null){
    fields(input.sourceUplink,['enabled','maxSources','maxSourcesPerClient'],'source uplink configuration');
    if(typeof input.sourceUplink.enabled!=='boolean')throw new Error('Invalid source uplink switch');
    sourceUplink={enabled:input.sourceUplink.enabled,maxSources:bounded(input.sourceUplink.maxSources,32,1,64,'source capacity'),
      maxSourcesPerClient:bounded(input.sourceUplink.maxSourcesPerClient,Math.min(4,input.sourceUplink.maxSources??32),1,8,'source client capacity')};
    if(sourceUplink.enabled&&(origin.protocol!=='https:'||sourceUplink.maxSources+nodes.length>64||sourceUplink.maxSourcesPerClient>sourceUplink.maxSources))throw new Error('Invalid source uplink capacity or origin');
  }
  const iceServers = input.iceServers ?? [];
  if (!Array.isArray(iceServers) || iceServers.length > 4) throw new Error('Invalid ICE configuration');
  for (const server of iceServers) {
    fields(server,['urls','username','credential'],'ICE server');
    const urls = Array.isArray(server.urls) ? server.urls : [server.urls];
    if (!urls.length || urls.length > 4 || urls.some(url => typeof url !== 'string' || url.length > 256 || !/^(?:stun|stuns):[a-z0-9.-]+(?::\d{1,5})?$/i.test(url)) ||
      server.username !== undefined || server.credential !== undefined)
      throw new Error('Static ICE configuration supports STUN only; TURN needs a short-lived credential issuer');
  }
  // Discovery is opt-in. Bootstrap locations are transport hints, never trusted Common keys.
  let discovery=null;
  if(input.discovery!==undefined&&input.discovery!==null){
    fields(input.discovery,['enabled','bootstrapOrigins','allowedOrigins'],'discovery configuration');
    if(typeof input.discovery.enabled!=='boolean')throw new Error('Invalid discovery switch');
    const origins=(values,label)=>{
      if(!Array.isArray(values)||values.length>8||new Set(values).size!==values.length)throw new Error(`Invalid ${label}`);
      return values.map(value=>{const url=new URL(value);
        if(url.origin!==value||url.protocol!=='https:'||url.username||url.password||value.length>256)throw new Error(`Invalid ${label}`);return value;});
    };
    discovery={enabled:input.discovery.enabled,bootstrapOrigins:origins(input.discovery.bootstrapOrigins??[],'discovery bootstrap origins'),
      allowedOrigins:origins(input.discovery.allowedOrigins??[],'discovery allowed origins')};
  }
  let turn=null;
  if(input.turn!==undefined&&input.turn!==null) {
    fields(input.turn,['urls','secretPath','ttlSeconds'],'TURN issuer');
    const urls=Array.isArray(input.turn.urls)?input.turn.urls:[input.turn.urls];
    if(!urls.length||urls.length>4||urls.some(url=>typeof url!=='string'||url.length>256||
      !/^turns?:(?:[a-z0-9.-]+|\[[a-f0-9:]+\])(?::\d{1,5})?(?:\?transport=(?:udp|tcp))?$/i.test(url)||
      /^turns:.*\?transport=udp$/i.test(url)||
      /:(\d+)(?:\?|$)/.test(url)&&(Number(url.match(/:(\d+)(?:\?|$)/)[1])<1||Number(url.match(/:(\d+)(?:\?|$)/)[1])>65535)))throw new Error('Invalid TURN URLs');
    const secretPath=input.turn.secretPath;
    if(typeof secretPath!=='string'||!isAbsolute(secretPath)||normalize(secretPath)!==secretPath||secretPath.length>512)
      throw new Error('Invalid TURN secret path');
    turn={urls:structuredClone(urls),secretPath,ttlSeconds:bounded(input.turn.ttlSeconds,300,120,600,'TURN credential lifetime')};
  }
  for (const key of ['trustedCountryHeader','trustedClientIpHeader']) {
    if (input[key] !== undefined && input[key] !== null && (typeof input[key] !== 'string' || !/^x-[a-z0-9-]{1,48}$/.test(input[key])))
      throw new Error('Invalid trusted proxy header');
  }
  if (input.listenHost !== undefined && !['127.0.0.1','::1'].includes(input.listenHost)) throw new Error('Gateway must bind loopback');
  const result=freeze({enabled:input.enabled === true,origin:input.origin,listenHost:input.listenHost ?? '127.0.0.1',
    listenPort:bounded(input.listenPort,8091,1,65535,'listen port'),nativeOrigin,network:structuredClone(input.network),nodes,limits,
    iceServers:structuredClone(iceServers),turn,discovery,sourceUplink,
    trustedCountryHeader:input.trustedCountryHeader ?? null,trustedClientIpHeader:input.trustedClientIpHeader ?? null});
  validated.add(result);return result;
}

export async function loadConfig(path) {
  if (!isAbsolute(path) || normalize(path) !== path) throw new Error('An absolute configuration path is required');
  for (let current = path; ; current = current.slice(0,current.lastIndexOf('/')) || '/') {
    if ((await lstat(current)).isSymbolicLink()) throw new Error('Linked configuration path denied');
    if (current === '/') break;
  }
  const stat = await lstat(path);
  if (!stat.isFile() || stat.size > 65536) throw new Error('Configuration must be a bounded regular file');
  const bytes = await readFile(path);
  if (bytes.length > 65536) throw new Error('Configuration exceeds limit');
  return validateConfig(strictJSON(bytes,65536));
}
