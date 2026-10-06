import { readFile, writeFile } from 'node:fs/promises';
import { chromium } from '/tmp/browser-llm-preview/node_modules/playwright/index.mjs';
const report=JSON.parse(await readFile(new URL('./native-discovery-browser-report.json',import.meta.url),'utf8')),closed=[];
const reason=process.argv[2]||'Controlled acceptance stop before client stale record signaling correction; new 30-minute run required';
for (const [name,row] of Object.entries(report.processes)) {
 try {
  const command=(await readFile(`/proc/${row.browserPid}/cmdline`,'utf8')).replaceAll('\0',' ');
  if (!/^[ABC]$/.test(name) || !command.startsWith('/tmp/browser-llm-browsers/chromium-1243/chrome-linux64/chrome ') || !command.includes('--remote-debugging-port=0')) throw new Error('Owned browser executable mismatch');
  const profile=command.match(new RegExp('(?:^| )--user-data-dir=(/tmp/cypher-mesh-'+name+'-[a-zA-Z0-9]+)(?: |$)'))?.[1];
  if (!profile) throw new Error('Owned browser profile mismatch');
  const port=Number((await readFile(profile+'/DevToolsActivePort','utf8')).split('\n')[0]);
  const browser=await chromium.connectOverCDP('http://127.0.0.1:'+port,{noDefaults:true,timeout:5000});
  for(const context of browser.contexts())for(const page of context.pages())await page.evaluate(()=>globalThis.mesh?.stop('Acceptance restart for signaling correction')).catch(()=>{});
  const cdp=await browser.newBrowserCDPSession();await cdp.send('Browser.close').catch(()=>{});closed.push({name,pid:row.browserPid});
 } catch(error) {closed.push({name,pid:row.browserPid,error:error.message});}
}
await writeFile(new URL('./native-discovery-restart-reason.json',import.meta.url),JSON.stringify({reason,at:new Date().toISOString(),closed},null,2));
console.log(JSON.stringify(closed));
