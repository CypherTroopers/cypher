#!/usr/bin/env python3
"""Independent claim byte/hash/path vectors, before Go implementation."""
import argparse
import hashlib
import json
from pathlib import Path


def h(domain, data):
    return hashlib.sha256(domain.encode('ascii') + b'\0' + data).digest()


def make():
    domain = b''.join(n.to_bytes(size, 'big') for n, size in [(1,2),(10101919,8),(1,32),(2,32),(1,8),(3,32)])
    leaves = []
    for identifier, kind, amount, period in [(1,1,10**18,0),(2,2,10**17,7)]:
        raw = domain + (1).to_bytes(8,'big') + bytes([kind]) + identifier.to_bytes(32,'big') + (4).to_bytes(20,'big') + (5).to_bytes(20,'big') + bytes(4) + amount.to_bytes(32,'big') + period.to_bytes(8,'big')
        assert len(raw) == 239
        leaf = h('common-dex/claim/v1', raw)
        nullifier = h('common-dex/nullifier/v1', domain[:74] + bytes([kind]) + identifier.to_bytes(32,'big'))
        leaves.append(dict(encoded=raw.hex(),hash=leaf.hex(),nullifier=nullifier.hex()))
    root = h('common-dex/merkle/v1',bytes.fromhex(leaves[0]['hash'])+bytes.fromhex(leaves[1]['hash']))
    return dict(schema=1,leaves=leaves,root=root.hex())


if __name__ == '__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    path=Path(__file__).resolve().parents[2]/'dex/testdata/claims.json'
    expected=make()
    if args.check:
        assert json.loads(path.read_text())==expected, 'claim vector mismatch'
        print('PASS: 2 claim encodings, leaf hashes, cross-epoch nullifiers and Merkle root')
    else:
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(expected,indent=2)+'\n')
