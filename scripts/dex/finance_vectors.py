#!/usr/bin/env python3
"""Independent fixed finance/deposit/count-tree bytes, created before Go code."""
import argparse, hashlib, json
from pathlib import Path

def H(domain, raw): return hashlib.sha256(domain.encode('ascii')+b'\0'+raw).digest()
def I(n,width): return n.to_bytes(width,'big')
def domain(): return b''.join(I(n,s) for n,s in [(1,2),(10101919,8),(1,32),(2,32),(1,8),(3,32)])
def tree(leaves):
    count=len(leaves)
    if not count: return bytes(32), []
    size=1
    while size<count: size*=2
    layer=list(leaves)+[H('common-dex/merkle-empty/v1',b'')]*(size-count)
    paths=[[] for _ in leaves];indices=list(range(count))
    while len(layer)>1:
        for j,index in enumerate(indices): paths[j].append(layer[index^1]);indices[j]//=2
        layer=[H('common-dex/merkle/v1',layer[j]+layer[j+1]) for j in range(0,len(layer),2)]
    return H('common-dex/merkle-count/v1',I(count,4)+layer[0]),paths

def make():
    summaries=[]
    for sequence,period,amounts in [(1,0,[200*10**18,0,0,0,0,0,0]),(14,1,[0,84*10**15,0,0,10*10**18,42*10**15,958*10**15])]:
        raw=I(1,2)+domain()+I(9,20)+I(sequence,8)+I(0 if sequence==1 else 7,32)+b''.join(I(n,32) for n in amounts)+I(period,8)+I(1 if period else 0,8)+I(10 if period else 0,8)+I(9 if period else 0,32)
        assert len(raw)==456
        summaries.append(dict(encoded=raw.hex(),hash=H('common-dex/finance/v1',raw).hex()))
    deposits=[]
    for idx,amount in enumerate([100*10**18,100*10**18,10**18]):
        raw=I(1,2)+domain()+I(9,20)+I(idx,8)+I(idx+4,20)+I(amount,32)+I(100+idx,8)+I(50+idx,32)
        assert len(raw)==236
        deposits.append(dict(encoded=raw.hex(),hash=H('common-dex/deposit/v1',raw).hex()))
    hashes=[bytes.fromhex(d['hash']) for d in deposits]
    trees=[]
    for count in [0,1,2,3]:
        root,paths=tree(hashes[:count]);trees.append(dict(count=count,root=root.hex(),paths=[[s.hex() for s in p] for p in paths]))
    return dict(schema=1,summaries=summaries,deposits=deposits,trees=trees)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');args=p.parse_args()
    target=Path(__file__).resolve().parents[2]/'dex/testdata/finance.json';expected=make()
    if args.check:
        assert json.loads(target.read_text())==expected
        print('PASS: 2 finance, 3 deposit, 4 counted-tree independent golden vectors')
    else: target.write_text(json.dumps(expected,indent=2)+'\n')
