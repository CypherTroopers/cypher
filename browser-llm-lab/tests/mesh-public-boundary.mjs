#!/usr/bin/env node
// Read-only deployment checks; this script never joins a mesh session.
import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
const origin = process.env.MESH_PUBLIC_ORIGIN || 'https://ai-test.make-cph-great-again.community';
const rows = [], checks = [
 ['config', '/relay/v1/mesh/config', 200, {Origin:origin}],
 ['foreign-origin', '/relay/v1/mesh/config', 403, {Origin:'https://untrusted.invalid'}],
 ['status-needs-session', '/relay/v1/mesh/status', 401, {Origin:origin}],
 ['query-token-denied', '/relay/v1/mesh/status?token=fixture-invalid', 400, {Origin:origin}],
 ...['source-config','source-status','head','headers/'+'a'.repeat(64),'sessions'].map(path=>['owner-'+path,'/relay/v1/'+path,404,{}]),
 ...['relay/config.json','.runtime/mesh-a/source.json','.runtime/mesh-a/data/cypher/nodekey','node.ipc','server.py','package.json'].map(path=>['private-'+path,'/'+path,404,{}]),
];
for(const [name,path,expected,headers] of checks){
 const response=await fetch(origin+path,{headers,redirect:'error',signal:AbortSignal.timeout(10000)});
 const body=await response.text();assert.equal(response.status,expected,name);
 if(name==='config'){
  const config=JSON.parse(body);assert.equal(config.protocol,'cypher-browser-mesh/1');assert.equal(config.initialState,'OFF');
  assert(config.nodes.length===2&&config.nodes.every(node=>!('socketPath' in node)));
  assert(!/"(?:token|secretPath|credential|signingKeyPath)"\s*:/u.test(body));
 }
 rows.push({name,path,status:response.status});
}
await writeFile(process.env.MESH_BOUNDARY_REPORT||'/tmp/cypher-mesh-public-boundary.json',JSON.stringify({at:new Date().toISOString(),origin,status:'PASS',readOnly:true,checks:rows},null,2)+'\n');
console.log(`PASS ${rows.length} read-only public boundary checks`);
