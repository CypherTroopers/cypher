#!/usr/bin/env python3
"""Independent bundle framing/count-tree golden; opaque proof is not valid FHS."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / 'dex/testdata/settlement_bundle.json'

def digest(label, raw):
    return hashlib.sha256(label.encode()+b'\0'+raw).digest()

def values():
    domain = struct.pack('>HQ',1,10101919)+bytes([1])*32+bytes([2])*32+struct.pack('>Q',1)+bytes([3])*32
    custody = bytes.fromhex('0000000000000000000000000000000000de0001')
    amount = lambda n: n.to_bytes(32,'big')
    def claim(kind, cid, n, period):
        return domain+struct.pack('>QB',18,kind)+bytes([cid])*32+bytes([4])*20+bytes([5])*20+struct.pack('>I',0)+amount(n)+struct.pack('>Q',period)
    withdrawal = claim(1,6,10,0)
    rewards = [claim(2,7,2,1),claim(2,8,3,1)]
    wl = digest('common-dex/claim/v1',withdrawal)
    rl = [digest('common-dex/claim/v1',r) for r in rewards]
    wr = digest('common-dex/merkle-count/v1',struct.pack('>I',1)+wl)
    rr = digest('common-dex/merkle-count/v1',struct.pack('>I',2)+digest('common-dex/merkle/v1',rl[0]+rl[1]))
    finance = struct.pack('>H',1)+domain+custody+struct.pack('>Q',18)+bytes([9])*32+b''.join(amount(x) for x in [0,1,0,0,10,2,3])+struct.pack('>QQQ',1,1,10)+bytes([10])*32
    # Checkpoint field order is independently declared by the protocol spec.
    cp = struct.pack('>HBQ',1,1,10101919)+bytes([1])*32+bytes([2])*32+struct.pack('>Q',1)+bytes([3])*32+struct.pack('>Q',18)+bytes([11])*32+bytes([12])*32+bytes([13])*32+struct.pack('>QQQ',18,18,257)+bytes([14])*32+struct.pack('>QQ',3,3)+bytes(32)+wr+amount(10)+struct.pack('>Q',1)+rr+amount(5)+digest('common-dex/finance/v1',finance)+bytes([15])*32+struct.pack('>H',4)
    proof = bytes.fromhex('c102')
    paths = [withdrawal+struct.pack('>IIB',0,1,0), rewards[0]+struct.pack('>IIB',0,2,1)+rl[1], rewards[1]+struct.pack('>IIB',1,2,1)+rl[0]]
    raw = b'CDXB'+struct.pack('>H',1)+cp+finance+struct.pack('>I',len(proof))+proof+struct.pack('>HH',1,2)+b''.join(paths)
    assert len(cp)==525 and len(finance)==456 and len(withdrawal)==239
    return {'version':1,'proof_note':'Opaque invalid-FHS placeholder: codec fixture only','checkpoint':cp.hex(),'finance':finance.hex(),'proof':proof.hex(),'withdrawal':withdrawal.hex(),'rewards':[x.hex() for x in rewards],'encoded':raw.hex(),'hash':digest('common-dex/settlement-bundle/v1',raw).hex(),'snapshot_origin_example':digest('common-dex/bootstrap-snapshot/v1',b'{"fixture":1}').hex()}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');a=p.parse_args()
    raw=json.dumps(values(),indent=2,sort_keys=True)+'\n'
    if a.check:
        assert TARGET.read_text()==raw,'settlement bundle golden mismatch'
        print('PASS: bundle v1 framing, counted paths, finance binding and bootstrap digest')
    else:
        TARGET.write_text(raw)
