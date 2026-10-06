#!/usr/bin/env python3
"""Scoped, baseline-checked preparation/application for the 20-connection web update."""
import ctypes, hashlib, json, os, pathlib, shutil, sys, datetime
ROOT=pathlib.Path('/root/browser-llm-lab')
STAGE=pathlib.Path('/tmp/cypher-mesh-20x20-20261003')
RELEASE=ROOT/'.runtime/releases/mesh-20x20-v1'
BASE=json.loads((STAGE/'evidence/baseline.json').read_text())
GATEWAY=['relay/config.mjs','relay/gateway.mjs','relay/config.json']
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def verify():
 for rel, old in BASE['files'].items():
  p=ROOT/rel
  if not p.is_file() or digest(p)!=old:raise RuntimeError('Existing work changed since baseline: '+rel)
def save(value):
 (RELEASE/'deployment.json').write_text(json.dumps(value,indent=2)+'\n')
mode=sys.argv[1]
if mode=='prepare':
 verify()
 RELEASE.mkdir(parents=True,exist_ok=False)
 shutil.copytree(STAGE/'public',RELEASE/'public')
 for rel in GATEWAY:
  target=RELEASE/'previous'/rel;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/rel,target)
 changes={rel:{'before':old,'after':digest(STAGE/rel)} for rel,old in BASE['files'].items() if (STAGE/rel).is_file() and digest(STAGE/rel)!=old}
 save({'preparedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'state':'PREPARED','changes':changes,'nativeModified':False})
 print('Prepared bounded gateway rollback and complete public tree; live files unchanged.')
elif mode=='gateway':
 verify()
 state=json.loads((RELEASE/'deployment.json').read_text());assert state['state']=='PREPARED'
 for rel in GATEWAY:
  target=ROOT/rel;tmp=target.with_name(target.name+'.twenty-prepared');shutil.copy2(STAGE/rel,tmp);os.replace(tmp,target)
 state['state']='GATEWAY_FILES_APPLIED';save(state);print('Gateway files applied; restart the scoped gateway before public exchange.')
elif mode=='public':
 state=json.loads((RELEASE/'deployment.json').read_text());assert state['state']=='GATEWAY_FILES_APPLIED'
 for rel,old in BASE['files'].items():
  if rel.startswith('public/') and digest(ROOT/rel)!=old:raise RuntimeError('Public tree changed: '+rel)
 libc=ctypes.CDLL(None,use_errno=True)
 if libc.renameat2(-100,os.fsencode(ROOT/'public'),-100,os.fsencode(RELEASE/'public'),2)!=0:raise OSError(ctypes.get_errno(),'Atomic public directory exchange failed')
 for rel,change in state['changes'].items():
  if rel in GATEWAY or rel.startswith('public/'):assert digest(ROOT/rel)==change['after'],rel
 state['state']='DEPLOYED';state['deployedAt']=datetime.datetime.now(datetime.timezone.utc).isoformat();save(state)
 print('Atomic public tree exchange complete; previous public files retained in release/public.')
else:raise ValueError('Expected prepare, gateway, or public')
