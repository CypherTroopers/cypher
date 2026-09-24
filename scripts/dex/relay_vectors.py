#!/usr/bin/env python3
"""Independent relay core RLP/envelope vectors fixed before Go implementation."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

ROOT=Path(__file__).resolve().parents[2]
PATH=ROOT/'dex/testdata/relay.json'
def digest(label,b): return hashlib.sha256(label.encode()+b'\0'+b).digest()
def rlp(v):
    if isinstance(v,int): v=b'' if v==0 else v.to_bytes((v.bit_length()+7)//8,'big')
    if isinstance(v,list): b=b''.join(map(rlp,v)); prefix=192
    else:
        b=v;prefix=128
        if len(b)==1 and b[0]<128:return b
    if len(b)<56:return bytes([prefix+len(b)])+b
    n=len(b).to_bytes((len(b).bit_length()+7)//8,'big')
    return bytes([prefix+55+len(n)])+n+b
def vectors():
    domain=struct.pack('>HQ',1,10101919)+bytes([1])*32+bytes([2])*32+struct.pack('>Q',1)+bytes([3])*32
    custody=bytes.fromhex('0000000000000000000000000000000000de0001')
    payers=[bytes([4])*20,bytes(20),bytes([5])*20,bytes([6])*20]
    limits=[15000000,0,15000000,500000]
    gas=(1000000000).to_bytes(32,'big');cap=(10**18).to_bytes(32,'big')
    binding=rlp([1,domain,custody,payers,limits,gas,cap]); bh=digest('common-dex/relay/binding/v1',binding)
    job=[1,3,bytes([7])*32,b'CDXN\0\2\4\0\0\0\0\0',b'fixture-authorization',[],bytes([8])*20]
    record=[1,job,b'queued',[0,0,bytes(32),b'',bytes(32),0,bytes(32)],b'',b'']
    state=rlp([1,bh,2,0,[0]*4,[bytes(20)]*4,[record]])
    disk=b'CDXR'+struct.pack('>HI',1,len(state))+state+digest('common-dex/relay/store/v1',state)
    return {'domain':domain.hex(),'custody':custody.hex(),'payers':[p.hex() for p in payers],'gas_limits':limits,'gas_price':str(10**9),'max_gas_cost':str(10**18),'binding':binding.hex(),'binding_hash':bh.hex(),'job':rlp(job).hex(),'state':state.hex(),'disk':disk.hex()}
def main():
    p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');a=p.parse_args()
    raw=json.dumps(vectors(),sort_keys=True,indent=2)+'\n'
    if a.check:
        if PATH.read_text()!=raw:raise SystemExit('relay golden mismatch')
        print('PASS: relay binding/job/state/durable envelope independent vectors')
    else:PATH.write_text(raw)
if __name__=='__main__':main()
