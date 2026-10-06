import { loadConfig } from './config.mjs';
import { createGateway } from './gateway.mjs';

const path=process.argv[2];
if (!path) {process.stderr.write('Usage: node relay/main.mjs /absolute/owner-config.json\n');process.exitCode=1;}
else {
  try {
    const gateway=createGateway({config:await loadConfig(path)});
    await gateway.listen();
    process.stdout.write('Common mesh gateway listening on configured loopback endpoint.\n');
    let stopping=false;
    for(const signal of ['SIGINT','SIGTERM'])process.on(signal,async()=>{if(stopping)return;stopping=true;await gateway.close();});
  } catch {process.stderr.write('Relay configuration or startup failed.\n');process.exitCode=1;}
}
