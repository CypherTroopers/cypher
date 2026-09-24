#!/usr/bin/env python3
"""One authorized same-DB restart of the added, DEX-OFF cypherdex6 Common."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import time

from live_observe import digest, rpc, BLOCK_FIELDS, processes


def run(root, output):
    if socket.gethostname() != 'vmi3365213' or os.getuid() != 0:
        raise ValueError('named host/root only')
    if (root / 'build/stage/live-deployment.json').exists():
        raise ValueError('this test is restricted to pre-init DEX-OFF Common')
    app_name = 'cypherdex6'
    data = root / 'build/stage/live-commons/chaindbdex6'
    ipc = data / 'cypher.ipc'
    app = next(a for a in json.loads(subprocess.check_output(['pm2', 'jlist'])) if a['name'] == app_name)
    if (app['pm2_env']['pm_cwd'] != str(root) or app['pm2_env']['pm_exec_path'] != str(root / 'build/stage/live-commons/common6/start.sh') or
            app['pm2_env']['status'] != 'online' or rpc(ipc, 'eth_mining') is not False):
        raise ValueError('unexpected Common role/process binding')
    pid = app['pid']
    ticks = processes()[pid][1]
    binary_hash = digest(Path('/proc') / str(pid) / 'exe')
    data_identity = (data.stat().st_dev, data.stat().st_ino)
    genesis_hash = rpc(ipc, 'eth_getBlockByNumber', ['0x0', False])['hash']
    head = rpc(ipc, 'eth_getBlockByNumber', ['latest', False])
    expected = {k: head[k] for k in BLOCK_FIELDS}
    result = {'status': 'RUNNING', 'app': app_name, 'pid_before': pid, 'start_ticks_before': ticks,
              'binary_sha256': binary_hash, 'genesis': genesis_hash, 'target': expected,
              'init': False, 'database_replaced': False}
    def save():
        temporary = output.with_suffix('.new')
        temporary.write_text(json.dumps(result, indent=2) + '\n')
        temporary.replace(output)
    if output.exists():
        raise ValueError('fresh result path required')
    save()
    try:
        subprocess.run(['pm2', 'stop', app_name], check=True, capture_output=True, timeout=90)
        if processes().get(pid, (None, None))[1] == ticks:
            raise ValueError('old node still alive after named stop')
        result['old_process_exited'] = True
        save()
        subprocess.run(['pm2', 'restart', app_name], check=True, capture_output=True, timeout=90)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                block = rpc(ipc, 'eth_getBlockByNumber', [head['number'], False])
                if block and {k: block[k] for k in BLOCK_FIELDS} == expected and rpc(ipc, 'eth_mining') is False:
                    break
            except (OSError, ValueError):
                pass
            time.sleep(.5)
        else:
            raise ValueError('same-DB recovery deadline')
        after = next(a for a in json.loads(subprocess.check_output(['pm2', 'jlist'])) if a['name'] == app_name)
        new_pid = after['pid']
        if (new_pid == pid or after['pm2_env']['status'] != 'online' or
                digest(Path('/proc') / str(new_pid) / 'exe') != binary_hash or
                rpc(ipc, 'eth_getBlockByNumber', ['0x0', False])['hash'] != genesis_hash or
                (data.stat().st_dev, data.stat().st_ino) != data_identity):
            raise ValueError('restart identity mismatch')
        result.update(status='PASS(LIVE)', pid_after=new_pid, start_ticks_after=processes()[new_pid][1],
                      restored_block=expected, mining=False)
    except Exception as error:
        result.update(status='FAIL', error_type=type(error).__name__)
        save()
        raise
    save()
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run(Path(__file__).resolve().parents[2], args.output)
    print(json.dumps({k: result[k] for k in ('status', 'app', 'pid_before', 'pid_after')}))
