#!/usr/bin/env python3
"""Explicit, scoped one-time upgrade; no database/key access or source edits.

Default is a read-only preflight. --apply replaces only the two owned Common
executables and MaxPeers values, then restarts their exact existing PM2 ids.
The backup/JSON report is retained for inspection and manual rollback.
"""
import argparse
import fcntl
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
import tomllib

ROOT = Path('/root/browser-llm-lab')
CANDIDATE = Path('/root/cypher/build/bin/cypher')
NEW_SHA = '3efc534447a00e0abb0926f04325d78f498e5077d75e31ffd5b4e48c29f9ee29'
OLD_SHA = '3bafe0f18343f18533ef8528ab314ddaa7264953c2bc2ad9f33376ef5756bc6f'
RELEASE = ROOT / '.runtime/releases/capacity-v1/native'
ORIGIN = 'https://ai-test.make-cph-great-again.community'
PM2_ENV = {**os.environ, 'PM2_HOME': '/root/.pm2', 'PM2_SILENT': 'true', 'NO_COLOR': '1'}


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(*args, timeout=40):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError('Scoped command failed: ' + args[0] + ' (exit ' + str(result.returncode) + ')')
    return result.stdout


def pm2(*args):
    result = subprocess.run(['/usr/local/bin/pm2', *args], env=PM2_ENV,
                            capture_output=True, text=True, timeout=40, check=False)
    if result.returncode:
        raise RuntimeError('Scoped PM2 operation failed, exit ' + str(result.returncode))
    return result.stdout


def processes():
    return json.loads(pm2('jlist'))


def selected(rows, name):
    p = ROOT / '.runtime' / ('mesh-' + name)
    matches = [row for row in rows if row.get('name') == 'cypher-browser-mesh-' + name]
    assert len(matches) == 1, 'Dedicated PM2 name is not unique'
    row = matches[0]
    e = row['pm2_env']
    assert (e['pm_exec_path'] == str(p / 'mesh-start.sh') and e['pm_cwd'] == str(p)
            and e['exec_interpreter'] == 'none' and not e.get('args')
            and isinstance(row['pm_id'], int)), 'Dedicated PM2 identity changed'
    return row


def safe_process(row):
    e = row['pm2_env']
    return {'name': row['name'], 'pmId': row['pm_id'], 'pid': row.get('pid', 0),
            'startedAt': e.get('pm_uptime'), 'restarts': e.get('restart_time'),
            'status': e.get('status'), 'script': e.get('pm_exec_path')}


def mesh_config(path):
    conn = http.client.HTTPConnection('localhost', timeout=4)
    conn.sock = socket.socket(socket.AF_UNIX)
    conn.sock.settimeout(4)
    try:
        conn.sock.connect(str(path))
        conn.request('GET', '/relay/v1/mesh/config', headers={'Origin': ORIGIN})
        response = conn.getresponse()
        data = response.read(16385)
        assert response.status == 200 and len(data) <= 16384
        return json.loads(data)
    finally:
        conn.close()


def wait_for(label, fn, timeout=40):
    until = time.monotonic() + timeout
    last = None
    while time.monotonic() < until:
        try:
            value = fn()
            if value:
                return value
        except (OSError, ValueError, AssertionError, RuntimeError) as error:
            last = type(error).__name__
        time.sleep(.5)
    raise RuntimeError(label + ' timed out; last failure=' + str(last))


def atomic_copy(source, dest):
    temporary = dest.with_name(dest.name + '.capacity-upgrade-tmp')
    assert not temporary.exists(), 'Unexpected pending binary copy'
    shutil.copy2(source, temporary)
    assert sha(temporary) == NEW_SHA
    os.chmod(temporary, 0o700)
    with temporary.open('rb') as stream:
        os.fsync(stream.fileno())
    os.replace(temporary, dest)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--report', type=Path, default=Path(__file__).with_name('native-upgrade.json'))
    args = parser.parse_args()
    report = {'at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'status': 'PREFLIGHT', 'apply': args.apply, 'oldSHA256': OLD_SHA,
              'candidateSHA256': NEW_SHA, 'nodes': {}, 'actions': [],
              'databaseOrKeyMutation': False, 'nativeSourceMutation': False}

    def save():
        args.report.write_text(json.dumps(report, indent=2) + '\n')

    with (ROOT / '.runtime/managed-startup.lock').open('a') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert sha(CANDIDATE) == NEW_SHA, 'Candidate hash changed'
        assert 'exec unshare -Urn -- python3 ./mesh-exec.py' in (ROOT / '.runtime/mesh-b/mesh-start.sh').read_text().splitlines()
        rows = processes()
        owned = {selected(rows, n)['pm_id'] for n in 'ab'}
        report['unrelatedBefore'] = [safe_process(row) for row in rows if row['pm_id'] not in owned]
        for name in 'ab':
            p = ROOT / '.runtime' / ('mesh-' + name)
            row = selected(rows, name)
            assert row['pm2_env']['status'] == 'online' and row['pid'] > 0
            assert sha(p / 'cypher') == OLD_SHA
            assert sha(Path('/proc') / str(row['pid']) / 'exe') == OLD_SHA
            text = (p / 'node.toml').read_text()
            config = tomllib.loads(text)
            assert text.count('MaxPeers = 8') == 1 and config['Node']['P2P']['MaxPendingPeers'] == 4
            assert config['Node']['HTTPHost'] == '' and config['Node']['WSHost'] == ''
            assert config['Eth']['TxQUIC']['Enabled'] is False
            native = mesh_config(p / 'source.sock')
            assert native['maxSessions'] == 8 and native['nativePeers'] == 4
            report['nodes'][name] = {'before': safe_process(row), 'oldConfig': native,
                                     'nodeConfigSHA256': sha(p / 'node.toml'),
                                     'sourceConfigSHA256': sha(p / 'source.json'),
                                     'launcherSHA256': sha(p / 'mesh-start.sh'),
                                     'execSHA256': sha(p / 'mesh-exec.py')}
        save()
        if not args.apply:
            print('PASS scoped preflight; no runtime changes', args.report)
            return
        assert not RELEASE.exists(), 'Upgrade backup already exists; inspect before retry'
        RELEASE.mkdir(parents=True, mode=0o700)
        try:
            for name in 'ab':
                p = ROOT / '.runtime' / ('mesh-' + name)
                backup = RELEASE / name
                backup.mkdir(mode=0o700)
                for filename in ('cypher', 'node.toml'):
                    shutil.copy2(p / filename, backup / filename)
                assert sha(backup / 'cypher') == OLD_SHA
                row = selected(processes(), name)
                assert safe_process(row) == report['nodes'][name]['before'], 'Process changed before stop'
                pm2('stop', str(row['pm_id']))
                report['actions'].append({'stop': name, 'pmId': row['pm_id']})
                save()
                wait_for(name + ' process/socket cleanup', lambda: (
                    selected(processes(), name)['pm2_env']['status'] == 'stopped'
                    and not (p / 'source.sock').exists() and not (p / 'node.ipc').exists()
                    and not Path('/proc/' + str(row['pid'])).exists()))
            for name in 'ab':
                p = ROOT / '.runtime' / ('mesh-' + name)
                assert sha(p / 'node.toml') == report['nodes'][name]['nodeConfigSHA256']
                atomic_copy(CANDIDATE, p / 'cypher')
                text = (p / 'node.toml').read_text().replace('MaxPeers = 8', 'MaxPeers = 40')
                temporary = p / 'node.toml.capacity-upgrade-tmp'
                with temporary.open('x') as stream:
                    stream.write(text)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(temporary, 0o600)
                os.replace(temporary, p / 'node.toml')
                report['actions'].append({'replaceBinaryAndMaxPeers': name})
                save()
            for name in 'ab':
                row = selected(processes(), name)
                assert row['pm2_env']['status'] == 'stopped'
                pm2('restart', str(row['pm_id']))
                p = ROOT / '.runtime' / ('mesh-' + name)
                native = wait_for(name + ' updated private API', lambda: mesh_config(p / 'source.sock'))
                assert native['maxSessions'] == 80 and native['nativePeers'] == 40
                current = selected(processes(), name)
                assert current['pm2_env']['status'] == 'online'
                assert sha(Path('/proc') / str(current['pid']) / 'exe') == NEW_SHA
                assert sha(p / 'source.json') == report['nodes'][name]['sourceConfigSHA256']
                assert sha(p / 'mesh-start.sh') == report['nodes'][name]['launcherSHA256']
                assert sha(p / 'mesh-exec.py') == report['nodes'][name]['execSHA256']
                report['nodes'][name]['after'] = safe_process(current)
                report['nodes'][name]['newConfig'] = native
                report['actions'].append({'restartVerified': name, 'pid': current['pid']})
                save()
            module = importlib.util.spec_from_file_location('mesh_inspector', ROOT / 'relay/mesh-native-inspect.py')
            inspector = importlib.util.module_from_spec(module)
            module.loader.exec_module(inspector)
            report['nativeInspection'] = inspector.inspect()
            bpid = report['nodes']['b']['after']['pid']
            interfaces = json.loads(run('nsenter', '-t', str(bpid), '-U', '-n', '--', 'ip', '-j', 'link', 'show'))
            routes4 = json.loads(run('nsenter', '-t', str(bpid), '-U', '-n', '--', 'ip', '-j', 'route', 'show'))
            routes6 = json.loads(run('nsenter', '-t', str(bpid), '-U', '-n', '--', 'ip', '-j', '-6', 'route', 'show'))
            assert {row['ifname'] for row in interfaces} == {'lo'} and not routes4
            assert all(row.get('dev') == 'lo' for row in routes6)
            bns = os.readlink('/proc/' + str(bpid) + '/ns/net')
            hostns = os.readlink('/proc/self/ns/net')
            assert bns != hostns
            report['isolation'] = {'bNamespace': bns, 'hostNamespace': hostns,
                                    'interfaces': interfaces, 'routes4': routes4, 'routes6': routes6}
            report['unrelatedAfter'] = [safe_process(row) for row in processes() if row['pm_id'] not in owned]
            report['unrelatedUnchanged'] = report['unrelatedBefore'] == report['unrelatedAfter']
            if not report['unrelatedUnchanged']:
                before = {row['pmId']: row for row in report['unrelatedBefore']}
                after = {row['pmId']: row for row in report['unrelatedAfter']}
                report['unrelatedChanges'] = [{'pmId': key, 'before': before.get(key), 'after': after.get(key)}
                                              for key in sorted(before.keys() | after.keys()) if before.get(key) != after.get(key)]
                report['unrelatedChangeAttribution'] = 'Observed separately; this helper never mutates other PM2 entries. External process changes do not stop verified healthy dedicated Commons.'
            report['status'] = 'PASS'
            report['rollback'] = 'Stop only the exact A/B PM2 ids after revalidating identities; preserve current files as failed candidate evidence, restore backup cypher/node.toml atomically, then restart only the original namespace-preserving launchers. Never init/reset/open/copy databases. Recheck old8/4 configs and B isolation. Do not blindly retry if startup fails.'
            save()
            print('PASS scoped native upgrade', args.report)
        except Exception as error:
            report['status'] = 'FAIL'
            report['error'] = type(error).__name__ + ': ' + str(error)
            # A failed candidate must not remain in an automatic restart loop.
            for name in 'ab':
                try:
                    row = selected(processes(), name)
                    if row['pm2_env']['status'] not in ('stopped', 'errored'):
                        pm2('stop', str(row['pm_id']))
                except Exception as stopping:
                    report['actions'].append({'stopFailure': name, 'kind': type(stopping).__name__})
            save()
            raise


if __name__ == '__main__':
    main()
