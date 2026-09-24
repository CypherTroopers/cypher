#!/usr/bin/env python3
"""Independent integer model and canonical fee frontier vectors (no Go calls)."""
import argparse
import hashlib
import json
from pathlib import Path


def make():
    by_period, closed_total, root, vectors = {}, 0, bytes(32), []
    for height in range(1, 321):
        # Sparse, deliberately varying inputs cross 64/128 boundaries; no float.
        fee = (height * height + 19) * 10**9 if height % 7 == 0 else 0
        period = (height - 1) // 10 + 1
        by_period[period] = by_period.get(period, 0) + fee
        close = (height - 4) // 10 if height >= 14 and height % 10 == 4 else 0
        if close:
            amount = by_period.pop(close, 0)
            closed_total += amount
            payload = root + close.to_bytes(8, 'big') + amount.to_bytes(32, 'big')
            root = hashlib.sha256(b'common-dex/closed-fee-period/v1\0' + payload).digest()
        closed = max(0, (height - 4) // 10)
        state = {'Version': 1, 'ClosedPeriod': closed,
                 'ClosedTotal': list(closed_total.to_bytes(32, 'big')),
                 'ClosedRoot': list(root),
                 'Open': [{'Period': p, 'Total': list(n.to_bytes(32, 'big'))}
                          for p, n in sorted(by_period.items()) if n],
                 'LastFee': list(fee.to_bytes(32, 'big'))}
        vectors.append({'height': height, 'fee': str(fee), 'close': close,
                        'outstanding': str(sum(by_period.values())),
                        'canonical': json.dumps(state, separators=(',', ':'))})
    return {'schema': 1, 'steps': vectors}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    target = Path(__file__).resolve().parents[2] / 'dex/testdata/financial_storage.json'
    data = make()
    if args.check:
        assert json.loads(target.read_text()) == data
        print('PASS: independent 320-block fee history, 31 sequential period closes')
    else:
        target.write_text(json.dumps(data, indent=2) + '\n')
