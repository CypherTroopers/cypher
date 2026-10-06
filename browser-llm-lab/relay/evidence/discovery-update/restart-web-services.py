#!/usr/bin/env python3
"""Restart only the reviewed Python frontend and private mesh gateway PM2 apps."""
import datetime
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path('/root/browser-llm-lab')
EVIDENCE = Path('/tmp/cypher-mesh-discovery-20261003/evidence')
GATEWAY_HOME = str(ROOT / '.runtime/mesh-gateway/pm2')
BASELINE = json.loads((EVIDENCE / 'runtime-before.json').read_text())

def pm2(home, *args):
    assert (Path(home) / 'rpc.sock').exists(), 'Do not create a new PM2 daemon'
    result = subprocess.run(['/usr/local/bin/pm2', *args], env=dict(os.environ, PM2_HOME=home, PM2_SILENT='true', NO_COLOR='1'), capture_output=True, text=True, timeout=40)
    assert result.returncode == 0, f'PM2 operation failed ({result.returncode})'
    return result.stdout

def snapshot(home):
    return [{'name': r['name'], 'pid': r['pid'], 'status': r['pm2_env']['status'], 'started': r['pm2_env']['pm_uptime'],
             'script': r['pm2_env']['pm_exec_path'], 'cwd': r['pm2_env']['pm_cwd']} for r in json.loads(pm2(home, 'jlist'))]

before = {'root': snapshot('/root/.pm2'), 'gateway': snapshot(GATEWAY_HOME)}
protected = [r for r in before['root'] if r['name'] != 'server']
for original in BASELINE['root']:
    if original['name'] not in [f'cypher{i}' for i in range(7)] + ['cyphermine']:
        continue
    assert original in before['root'], f'Original native process changed: {original["name"]}'
for home, name, script, rows in [('/root/.pm2', 'server', str(ROOT / 'server.py'), before['root']),
                                (GATEWAY_HOME, 'cypher-browser-mesh-gateway', str(ROOT / 'relay/main.mjs'), before['gateway'])]:
    matches = [r for r in rows if r['name'] == name]
    assert len(matches) == 1 and matches[0]['script'] == script and matches[0]['cwd'] == str(ROOT)
    pm2(home, 'restart', name)
time.sleep(2)
after = {'root': snapshot('/root/.pm2'), 'gateway': snapshot(GATEWAY_HOME)}
assert all(row in after['root'] for row in protected), 'An unrelated native process changed'
assert all(r['status'] == 'online' for r in after['root'] if r['name'] == 'server')
assert all(r['status'] == 'online' for r in after['gateway'])
result = {'status': 'PASS', 'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'before': before, 'after': after,
          'originalEightUnchanged': True, 'dedicatedCommonsUnchanged': True, 'turnRestarted': False}
(EVIDENCE / 'web-service-rollout.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'status': result['status'], 'frontend': next(r for r in after['root'] if r['name'] == 'server'),
                  'gateway': after['gateway'], 'nativeProcessesUnchanged': True}))
