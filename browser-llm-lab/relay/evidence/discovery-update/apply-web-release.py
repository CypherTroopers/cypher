#!/usr/bin/env python3
"""Apply the reviewed discovery files; preserve the live dirty tree and public snapshot."""
import ctypes
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

STAGE = Path('/tmp/cypher-mesh-discovery-20261003')
ROOT = Path('/root/browser-llm-lab')
BACKUP = ROOT / '.runtime/releases/mesh-discovery-v1/web-before'
EVIDENCE = STAGE / 'evidence'
baseline = json.loads((EVIDENCE / 'baseline.json').read_text())
manifest = json.loads((EVIDENCE / 'web-change-manifest.json').read_text())
assert not manifest['conflicts'], 'Review concurrent changes before applying'
assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip() == baseline['head']

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None

for change in manifest['changes']:
    path = Path(change['path'])
    assert not path.is_absolute() and '..' not in path.parts
    assert digest(ROOT / path) == change['before'], f'Live work changed: {path}'
    assert digest(STAGE / path) == change['after'], f'Staged work changed: {path}'
assert not BACKUP.exists(), 'Do not overwrite rollback snapshot'
BACKUP.mkdir(parents=True, mode=0o700)
(BACKUP / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
shutil.copytree(ROOT / 'public', BACKUP / 'public', symlinks=True)

def atomic_copy(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp = destination.with_name(destination.name + '.discovery-next')
    assert not temp.exists()
    shutil.copy2(source, temp)
    os.replace(temp, destination)

for change in manifest['changes']:
    path = Path(change['path'])
    if path.parts[0] == 'public':
        atomic_copy(STAGE / path, BACKUP / path)
    else:
        if change['before'] is not None:
            old = BACKUP / path
            old.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / path, old)
        atomic_copy(STAGE / path, ROOT / path)

# One Linux directory exchange makes all module URLs available together. The
# exchanged directory under web-before now contains the complete previous UI.
libc = ctypes.CDLL(None, use_errno=True)
renameat2 = libc.renameat2
renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
renameat2.restype = ctypes.c_int
if renameat2(-100, os.fsencode(BACKUP / 'public'), -100, os.fsencode(ROOT / 'public'), 2):
    raise OSError(ctypes.get_errno(), 'Atomic public directory exchange failed')
for change in manifest['changes']:
    assert digest(ROOT / change['path']) == change['after']
result = {'status': 'APPLIED_FILES_SERVICES_REQUIRE_RESTART', 'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'backup': str(BACKUP), 'changes': manifest['changes'], 'headUnchanged': True}
(EVIDENCE / 'web-file-rollout.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'status': result['status'], 'files': len(manifest['changes']), 'backup': str(BACKUP)}))
