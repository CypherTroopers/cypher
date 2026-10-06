#!/usr/bin/env python3
"""Scoped proxy body-bound adjustment; native/other server locations unchanged."""
import datetime, hashlib, json, os, subprocess
from pathlib import Path

root=Path('/root/browser-llm-lab')
stage=Path('/tmp/cypher-mesh-discovery-20261003')
installed=Path('/etc/nginx/sites-available/ai-test.make-cph-great-again.community')
record=root/'relay/nginx-site.conf'
expected='812be7106a163c5227dfbbb93106651a5dd201796f0e638a3acdb13c8c459d5f'
sha=lambda b:hashlib.sha256(b).hexdigest()
before=installed.read_bytes()
assert installed.is_file() and not installed.is_symlink()
assert sha(before)==expected and record.read_bytes()==before
old=b'        client_max_body_size 1k;\n'
assert before.count(old)==1
after=before.replace(old,b'        # Discovery accepts up to 16KiB; other APIs retain gateway-side 1KiB guards.\n        client_max_body_size 16k;\n')
backup=root/'.runtime/releases/mesh-discovery-v1/nginx-before.conf'
backup.parent.mkdir(parents=True,exist_ok=True)
with backup.open('xb') as f:f.write(before)
os.chmod(backup,0o600)
result={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'before':sha(before),'after':sha(after),'path':str(installed),'change':'mesh proxy request body limit 1KiB to16KiB; gateway per-API validation unchanged','status':'RUNNING'}
try:
    assert sha(installed.read_bytes())==expected
    installed.write_bytes(after)
    check=subprocess.run(['/usr/sbin/nginx','-t'],capture_output=True,text=True,timeout=20)
    result['nginxTest']={'exitCode':check.returncode,'stdout':check.stdout,'stderr':check.stderr}
    assert check.returncode==0
    subprocess.run(['/usr/sbin/nginx','-s','reload'],check=True,capture_output=True,text=True,timeout=20)
    assert record.read_bytes()==before
    record.write_bytes(after); (stage/'relay/nginx-site.conf').write_bytes(after)
    result['status']='PASS'
except Exception as error:
    installed.write_bytes(before)
    subprocess.run(['/usr/sbin/nginx','-t'],check=True,capture_output=True,text=True,timeout=20)
    subprocess.run(['/usr/sbin/nginx','-s','reload'],check=True,capture_output=True,text=True,timeout=20)
    result.update(status='FAIL_ROLLED_BACK',error=str(error));raise
finally:
    (stage/'evidence/proxy-body-limit-rollout.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
