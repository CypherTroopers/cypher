import argparse,hashlib,json,os,signal,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path.cwd()/'scripts/dex'))
from live_finance import Runner,atomic,web
from live_observe import observation,rpc,processes
from live_auth import network_identity,credentials,COMMON_RPC_RECIPIENT
repo=Path.cwd(); out=Path('/tmp/common-dex-live-test.x5z_05oq/public/dex-stop-isolation.json')
candidate=repo/'build/stage/live-generation-candidate'
names=['cyphermine']+['cypherdex%d'%i for i in range(1,7)]
result={'started':time.time(),'purpose':'all DEX sidecars stopped; CLX ordinary signed transaction through unchanged Common RPC; same DB restore','status':'RUNNING','actions':[]}
restoring=False
def interrupted(signum,frame):
 if restoring:
  result.setdefault('deferred_signals',[]).append(signum); return
 raise InterruptedError('operator interrupt')
signal.signal(signal.SIGTERM,interrupted)
signal.signal(signal.SIGINT,interrupted)
def save(): atomic(out,result)
def checked(p):
 t=processes()
 if p['pid'] not in t or t[p['pid']][:2]!=(p['ppid'],p['start_ticks']): raise ValueError('PID identity changed')
 if hashlib.sha256(Path('/proc/%d/exe'%p['pid']).read_bytes()).hexdigest()!=p['exe_sha256']: raise ValueError('exe changed')
args=argparse.Namespace(candidate=candidate,helper=Path('/tmp/common-dex-live-test.x5z_05oq/dex-live-finance'),observer=None,output=repo/'build/stage/live-finance-20260923-smoke',active_indices=list(range(7)),mode='drive',min_memory_gib=4)
r=Runner(args); restore=[]
try:
 r.preflight(); initial=observation(repo,True,True)
 result['before']={'apps':[], 'dex':[web('http://127.0.0.1:%d/v1/status'%(19000+i)) for i in range(7)], 'certified_records':[web('http://127.0.0.1:%d/v1/certified?height=15'%(19000+i))['Record']['Checkpoint'] for i in range(7)]}
 for name in names:
  a=next(x for x in initial['apps'] if x['name']==name)
  ps=a['processes']; parent=next(p for p in ps if p['pid']==a['pid']); children=[p for p in ps if p['role']=='dex-validator']
  if len(children)!=1 or children[0]['ppid']!=parent['pid']: raise ValueError('not exactly one owned sidecar')
  child=children[0]; checked(parent); checked(child)
  result['before']['apps'].append({'name':name,'parent':{k:parent[k] for k in ('pid','ppid','start_ticks','exe_sha256','datadir','ipc')},'sidecar':{k:child[k] for k in ('pid','ppid','start_ticks','exe_sha256')},'datadir_inode':os.stat(parent['datadir']).st_ino,'manifest':child['flags']['--dex.config']})
 save()
 for a in result['before']['apps']:
  restore.append(a['name']); result['actions'].append({'name':a['name'],'action':'sidecar_SIGTERM_intent','pid':a['sidecar']['pid']}); save()
  checked(a['parent']); checked(a['sidecar']); os.kill(a['sidecar']['pid'],signal.SIGTERM)
 deadline=time.monotonic()+30
 while time.monotonic()<deadline:
  if all(a['sidecar']['pid'] not in processes() for a in result['before']['apps']): break
  time.sleep(.2)
 else: raise ValueError('sidecar graceful exit deadline')
 for a in result['before']['apps']: checked(a['parent'])
 before=rpc(repo/'chaindb0/cypher.ipc','eth_getBlockByNumber',['latest',False])
 result['all_dex_stopped']=True; result['clx_before']={k:before[k] for k in ('number','hash','stateRoot')}; save()
 business='isolation-all-dex-off-ordinary-transfer'
 r.wait_tx(business,'funding-source',r.keys['synthetic-oracle'],1)
 tx=r.state['transactions'][business]
 after=rpc(repo/'chaindb0/cypher.ipc','eth_getBlockByNumber',['latest',False])
 if int(after['number'],16)<=int(before['number'],16): raise ValueError('ordinary CLX failed to advance')
 result['ordinary_tx']={k:tx[k] for k in ('hash','nonce','sender','to','value','gas','gas_price','stage','receipt')}
 result['clx_after']={k:after[k] for k in ('number','hash','stateRoot')}
 result['status']='ORDINARY_CLX_PASS_AWAITING_RESTORE_AND_INDEPENDENT_FINALITY';save()
except Exception as e:
 result['error']=type(e).__name__+': '+str(e); result['status']='FAIL'; save()
finally:
 restoring=True
 result['restore']=[]
 for name in restore:
  try:
   v=subprocess.run(['pm2','restart',name],capture_output=True,timeout=45)
   result['restore'].append({'name':name,'exit':v.returncode})
  except Exception as e:
   result['restore'].append({'name':name,'error':type(e).__name__})
  save()
 try:
  deadline=time.monotonic()+90
  while True:
   try:
    statuses=[web('http://127.0.0.1:%d/v1/status'%(19000+i)) for i in range(7)]
    if all(s['State']=='active' and s['Certified']==15 and s['Finalized']==0 for s in statuses): break
   except Exception: pass
   if time.monotonic()>deadline: raise ValueError('DEX same-DB restore deadline')
   time.sleep(.5)
  current_records=[web('http://127.0.0.1:%d/v1/certified?height=15'%(19000+i))['Record']['Checkpoint'] for i in range(7)]
  if current_records!=result['before']['certified_records']: raise ValueError('certified checkpoint changed on restore')
  table=processes()
  if any(a['parent']['pid'] in table or a['sidecar']['pid'] in table for a in result['before']['apps']): raise ValueError('old process survived restart')
  config,expected=network_identity(repo,candidate/'public/inventory.json')
  name,ipc,address,password=credentials(config)[-1]
  if rpc(ipc,'eth_getBlockByNumber',['0x0',False])['hash']!=expected: raise ValueError('Common genesis changed')
  if rpc(ipc,'personal_unlockAccount',[address,password,0]) is not True: raise ValueError('Common signer unlock failed')
  reward=rpc(ipc,'personal_getCommonRPCRewardAddress',[address])
  if not reward.get('configured') or reward.get('rewardRecipient','').lower()!=COMMON_RPC_RECIPIENT: raise ValueError('Common reward recipient changed')
  result['after_dex']=statuses; result['after_processes']=observation(repo,True,True)
  for old in result['before']['apps']:
   app=next(a for a in result['after_processes']['apps'] if a['name']==old['name'])
   parent=next(p for p in app['processes'] if p['pid']==app['pid']); children=[p for p in app['processes'] if p['role']=='dex-validator']
   if len(children)!=1 or children[0]['ppid']!=parent['pid']: raise ValueError('restored process hierarchy')
   if parent['datadir']!=old['parent']['datadir'] or os.stat(parent['datadir']).st_ino!=old['datadir_inode']: raise ValueError('restored datadir changed')
   if parent['exe_sha256']!=old['parent']['exe_sha256'] or children[0]['exe_sha256']!=old['sidecar']['exe_sha256'] or children[0]['flags']['--dex.config']!=old['manifest']: raise ValueError('restored exe/manifest changed')
  if result['status']!='FAIL': result['status']='CANONICAL_OBSERVED_RESTORED_AWAITING_FINALITY'
 except Exception as e:
  result['restore_error']=type(e).__name__+': '+str(e);result['status']='FAIL'
 result['finished']=time.time();save();r.helper.close();r.lock.close()
print(json.dumps({'status':result['status'],'path':str(out),'error':result.get('error'),'restore_error':result.get('restore_error')}))
if result['status']=='FAIL': raise SystemExit(1)
