import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {verifyEndpoint} from '../public/mesh-discovery.js';
const origin='https://ai-test.make-cph-great-again.community';
const manifest=JSON.parse(await readFile(new URL('./web-change-manifest.json',import.meta.url),'utf8'));
const fetchPublic=async path=>{
 const response=await fetch(origin+path,{headers:{Origin:origin},redirect:'error',signal:AbortSignal.timeout(15000)});
 assert.equal(response.status,200,path);const bytes=Buffer.from(await response.arrayBuffer());assert(bytes.length<=1048576);
 return {bytes,contentType:response.headers.get('content-type'),cacheControl:response.headers.get('cache-control')};
};
const config=JSON.parse((await fetchPublic('/relay/v1/mesh/config')).bytes);
assert.equal(config.protocol,'cypher-browser-mesh/1');assert.equal(config.initialState,'OFF');
assert.equal(config.limits.maxPeers,20);assert.equal(config.limits.maxCommonConnections,20);assert(config.discovery);
const assets=await Promise.all(manifest.changes.filter(row=>row.path.startsWith('public/')).map(async row=>{
 const value=await fetchPublic('/'+row.path.slice(7));const hash=createHash('sha256').update(value.bytes).digest('hex');
 assert.equal(hash,row.after,row.path);assert.match(value.cacheControl,/no-store/);
 return {path:row.path,sha256:hash,bytes:value.bytes.length,contentType:value.contentType,cacheControl:value.cacheControl};
}));
const directory=JSON.parse((await fetchPublic('/relay/v1/mesh/discovery')).bytes);
assert.deepEqual(directory.network,config.network);assert.equal(directory.endpoints.length,2);
const endpoints=directory.endpoints.map(envelope=>{
 const record=verifyEndpoint(envelope,config.network);assert.equal(record.origin,origin);
 assert(config.nodes.some(node=>node.id===record.sourceId&&node.nodeId===record.nodeId));
 return {sourceId:record.sourceId,nodeId:record.nodeId,origin:record.origin,bootId:record.payload.bootId,sequence:record.payload.sequence,issuedAt:record.payload.issuedAt,expiresAt:record.expiresAt,browserVerifierAccepted:true};
});
const output=process.argv[2]||new URL('./public-release-readonly.json',import.meta.url);
const report={status:'PASS',at:new Date().toISOString(),origin,assets,endpoints,limits:config.limits,initialState:config.initialState,sessionAdmissions:0};
await writeFile(output,JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({status:report.status,assets:assets.length,signatureVerifiedEndpoints:endpoints.map(row=>({sourceId:row.sourceId,sequence:row.sequence,expiresAt:row.expiresAt})),initialState:config.initialState}));
