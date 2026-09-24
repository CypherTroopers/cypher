#!/usr/bin/env python3
"""Read-only finite common-block comparison on the exact fourteen PM2 nodes.

This checks ordinary full-sync results, not independent proof authentication.
It never repairs head metadata, changes peers, starts mining or sends a TX.
"""
import argparse
import json
from pathlib import Path
import time

from live_observe import APPS, ADDED_COMMONS, BLOCK_FIELDS, rpc


def compare(root, timeout):
    nodes = {name: root / ('chaindbmine' if name == 'cyphermine' else 'chaindb' + name[6:]) / 'cypher.ipc'
             for name in APPS}
    nodes.update({name: root / 'build/stage/live-commons' / ('chaindbdex' + name[9:]) / 'cypher.ipc'
                  for name in ADDED_COMMONS})
    source = nodes['cyphermine']
    target = rpc(source, 'eth_getBlockByNumber', ['latest', False])
    target = {k: target[k] for k in BLOCK_FIELDS}
    genesis = rpc(source, 'eth_getBlockByNumber', ['0x0', False])['hash']
    start = time.monotonic()
    result = {'status': 'RUNNING', 'scope': 'ordinary full-sync equality; no independent finality proof',
              'genesis': genesis, 'target': target, 'nodes': {}, 'observations': 0}
    while time.monotonic() - start < timeout:
        result['observations'] += 1
        result['nodes'] = {}
        for name, ipc in nodes.items():
            try:
                if rpc(ipc, 'eth_getBlockByNumber', ['0x0', False])['hash'] != genesis:
                    raise ValueError('foreign genesis')
                block = rpc(ipc, 'eth_getBlockByNumber', [target['number'], False])
                if block is None:
                    continue
                if {k: block[k] for k in BLOCK_FIELDS} != target:
                    raise ValueError('common height hash/root/receipt mismatch')
                mining = rpc(ipc, 'eth_mining')
                if name in ('cyphermine',) + ADDED_COMMONS and mining is not False:
                    raise ValueError('Common unexpectedly started mining')
                result['nodes'][name] = {'number': block['number'], 'hash': block['hash'],
                                         'state_root': block['stateRoot'], 'receipts_root': block['receiptsRoot'],
                                         'mining': mining, 'dex_engine': rpc(ipc, 'debug_dexExecutionStats')}
            except (OSError, KeyError):
                continue
        if len(result['nodes']) == 14:
            result['status'] = 'PASS(LIVE)'
            break
        time.sleep(1)
    if result['status'] != 'PASS(LIVE)':
        result['status'] = 'FAIL'
    result['elapsed_seconds'] = time.monotonic() - start
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=120)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 900:
        raise SystemExit('timeout must be within 1..900 seconds')
    result = compare(Path(__file__).resolve().parents[2], args.timeout)
    with args.output.open('x') as file:
        json.dump(result, file, indent=2)
        file.write('\n')
    print(json.dumps({k: result[k] for k in ('status', 'scope', 'elapsed_seconds')}))
    if result['status'] != 'PASS(LIVE)':
        raise SystemExit(1)
