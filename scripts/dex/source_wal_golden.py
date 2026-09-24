#!/usr/bin/env python3
"""Independent codec-only relay source WAL/account-bundle vectors; no CLX proof."""
import argparse,hashlib,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[2]
def rlp(v):
 if isinstance(v,list):
  x=b''.join(rlp(i) for i in v); b=0xc0
 else:
  x=v if isinstance(v,bytes) else (v.to_bytes((v.bit_length()+7)//8,'big') if v else b''); b=0x80
  if len(x)==1 and x[0]<128:return x
 if len(x)<56:return bytes([b+len(x)])+x
 n=len(x).to_bytes((len(x).bit_length()+7)//8,'big');return bytes([b+55+len(n)])+n+x
def compact(v):return json.dumps(v,separators=(',',':'))
payload={'version':1,'bootstrap':'11'*32,'segments':[]}
p=compact(payload)
checksum=hashlib.sha256(b'common-dex/relay-source-wal/v1\0'+p.encode()).hexdigest()
vector={'spec':'docs/dex/relay-source-spec.md','authenticates_state':False,'empty_wal':{'payload':p,'checksum':checksum,'envelope':compact({'payload':payload,'checksum':checksum})},'account_bundle':{'root':'11'*32,'address':'22'*20,'account_proof':['c0'],'slots':[{'key':'33'*32,'proof':[]}],'encoded':rlp([1,b'\x11'*32,b'\x22'*20,[b'\xc0'],[[b'\x33'*32,[]]]]).hex()}}
out=json.dumps(vector,indent=2)+'\n'
p=ROOT/'dex/testdata/source_wal.json'
a=argparse.ArgumentParser();a.add_argument('--check',action='store_true');args=a.parse_args()
if args.check:
 if p.read_text()!=out:raise SystemExit('source WAL golden mismatch')
 print('relay source codec-only WAL/account bundle golden PASS')
else:p.write_text(out)
