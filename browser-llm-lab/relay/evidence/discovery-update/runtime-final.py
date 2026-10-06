#!/usr/bin/env python3
"""Read only process identity and artifact metadata; never print PM2 environments."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import datetime

root=Path('/root/browser-llm-lab')
evidence=Path('/tmp/cypher-mesh-discovery-20261003/evidence')
baseline=json.loads((evidence/'runtime-before.json').read_text())
names={r['name'] for r in baseline['root']}
def snapshot(home):
    assert (Path(home)/'rpc.sock').exists()
    result=subprocess.run(['/usr/local/bin/pm2','jlist'],env=dict(os.environ,PM2_HOME=home,PM2_SILENT='true',NO_COLOR='1'),capture_output=True,text=True,check=True,timeout=30)
    return [{'name':r['name'],'pid':r['pid'],'status':r['pm2_env']['status'],'started':r['pm2_env']['pm_uptime'],'script':r['pm2_env']['pm_exec_path'],'cwd':r['pm2_env']['pm_cwd']}
            for r in json.loads(result.stdout) if r['name'] in names or r['name'] in ['cypher-browser-mesh-gateway','cypher-header-turn']]
current={'root':snapshot('/root/.pm2'),'gateway':snapshot(str(root/'.runtime/mesh-gateway/pm2')),'turn':snapshot(str(root/'.runtime/relay-turn/pm2'))}
original=[r for r in baseline['root'] if r['name'] in [f'cypher{i}' for i in range(7)]+['cyphermine']]
assert len(original)==8 and all(r in current['root'] for r in original)
assert all(r['status']=='online' for rows in current.values() for r in rows)
artifacts=[]
for name in ['a','b']:
    path=root/f'.runtime/mesh-{name}'
    config=json.loads((path/'source.json').read_text())
    assert config['mesh']['publicGatewayOrigin']=='https://ai-test.make-cph-great-again.community'
    artifacts.append({'source':name,'binarySha256':hashlib.sha256((path/'cypher').read_bytes()).hexdigest(),'configSha256':hashlib.sha256((path/'source.json').read_bytes()).hexdigest(),
                      'socketMode':oct((path/'source.sock').stat().st_mode & 0o777),'directoryMode':oct(path.stat().st_mode & 0o777)})
assert all(r['binarySha256']=='be38686525295758caecfad9e76ddda4fc9579e3521b3651662fbf464e07052c' for r in artifacts)
result={'status':'PASS','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'originalEightUnchanged':True,'processes':current,'nativeArtifacts':artifacts}
(evidence/'runtime-final.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'status':'PASS','originalEightUnchanged':True,'ownedProcesses':[{k:r[k] for k in ['name','pid','status']} for rows in current.values() for r in rows if r['name'] not in {x['name'] for x in original}]}))
