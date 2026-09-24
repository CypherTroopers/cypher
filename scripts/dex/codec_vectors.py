#!/usr/bin/env python3
"""Independent fixed-width codec vectors. --check never rewrites expectations."""
import argparse
import hashlib
import json
from pathlib import Path

FIELDS = [
    ('version', 2), ('proofMode', 1), ('chainID', 8), ('genesis', 32),
    ('dexID', 32), ('epoch', 8), ('committee', 32), ('sequence', 8),
    ('previous', 32), ('preRoot', 32), ('postRoot', 32), ('firstBlock', 8),
    ('lastBlock', 8), ('clxHeight', 8), ('clxHash', 32), ('inboxStart', 8),
    ('inboxEnd', 8), ('inboxRoot', 32), ('withdrawalRoot', 32),
    ('withdrawalTotal', 32), ('rewardPeriod', 8), ('rewardRoot', 32),
    ('rewardTotal', 32), ('fundingRef', 32), ('dataRoot', 32), ('dataSchema', 2),
]


def digest(domain, data):
    return hashlib.sha256(domain.encode('ascii') + b'\0' + data).hexdigest()


def vectors():
    result = []
    for name, seed in [('empty_actions', 1), ('reserved_native_claims', 7)]:
        values = {key: i * seed for i, (key, _) in enumerate(FIELDS, 1)}
        values.update(version=1, proofMode=1, chainID=10101919, dataSchema=1,
                      firstBlock=1, lastBlock=3, inboxStart=0, inboxEnd=2)
        if seed == 1:
            for key in ['withdrawalTotal', 'rewardTotal', 'rewardPeriod']:
                values[key] = 0
        else:
            values['withdrawalTotal'] = 10**18
            values['rewardTotal'] = 5 * 10**17
        raw = b''.join(values[key].to_bytes(size, 'big') for key, size in FIELDS)
        assert len(raw) == 525
        epoch_raw = b''.join(values[key].to_bytes(dict(FIELDS)[key], 'big')
                             for key in ['version', 'chainID', 'genesis', 'dexID', 'epoch', 'committee'])
        result.append(dict(name=name, values={k: str(v) for k, v in values.items()},
                           encoded=raw.hex(), hash=digest('common-dex/checkpoint/v1', raw),
                           epoch_key=digest('common-dex/epoch/v1', epoch_raw)))
    return {'schema': 1, 'source': 'independent Python integers and hashlib; devnet only', 'vectors': result}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    path = Path(__file__).resolve().parents[2] / 'dex/testdata/checkpoint.json'
    expected = vectors()
    if args.check:
        assert json.loads(path.read_text()) == expected, 'checkpoint golden mismatch'
        print('PASS: 2 canonical checkpoint and epoch-domain vectors (525 bytes each)')
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(expected, indent=2) + '\n')
