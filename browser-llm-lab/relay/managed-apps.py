#!/usr/bin/python3
"""Manage only the web gateway and TURN; native Common lifecycle is separate."""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PM2 = '/usr/local/bin/pm2'
APPS = (
    {'name': 'cypher-header-turn', 'home': str(ROOT / '.runtime/relay-turn/pm2'),
     'ecosystem': 'turn.ecosystem.json', 'script': '.runtime/relay-turn/start.sh',
     'cwd': '.runtime/relay-turn', 'args': [], 'interpreter': 'none'},
    {'name': 'cypher-browser-mesh-gateway', 'home': str(ROOT / '.runtime/mesh-gateway/pm2'),
     'ecosystem': 'gateway.ecosystem.json', 'script': 'relay/main.mjs',
     'cwd': '.', 'args': [str(ROOT / 'relay/config.json')], 'interpreter': 'node'},
)


class ManagedError(Exception):
    pass


def run_pm2(app, *args):
    # PM2's list contains environment variables. Never print its raw output.
    env = dict(os.environ, PM2_HOME=app['home'], PM2_SILENT='true', NO_COLOR='1')
    try:
        result = subprocess.run([PM2, *args], env=env, capture_output=True,
                                text=True, timeout=40, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ManagedError(f"{app['name']}: PM2 command unavailable or timed out") from error
    if result.returncode:
        raise ManagedError(f"{app['name']}: PM2 command failed (exit {result.returncode})")
    return result.stdout


def processes(app):
    # A read-only status/check must not create a PM2 daemon.
    if not (Path(app['home']) / 'rpc.sock').exists():
        return []
    try:
        rows = json.loads(run_pm2(app, 'jlist'))
    except (ValueError, TypeError) as error:
        raise ManagedError(f"{app['name']}: invalid PM2 status response") from error
    if not isinstance(rows, list):
        raise ManagedError(f"{app['name']}: invalid PM2 process list")
    return rows


def selected(app, rows):
    found = [row for row in rows if row.get('name') == app['name']]
    if len(found) > 1:
        raise ManagedError(f"{app['name']}: duplicate name; refusing to change processes")
    if not found:
        return None
    row = found[0]
    env = row.get('pm2_env', {})
    interpreter = env.get('exec_interpreter')
    accepted = ('node', '/usr/local/bin/node') if app['interpreter'] == 'node' else ('none',)
    if (env.get('pm_exec_path') != str(ROOT / app['script'])
            or env.get('pm_cwd') != str(ROOT / app['cwd'])
            or (env.get('args') or []) != app['args']
            or interpreter not in accepted
            or not isinstance(row.get('pm_id'), int)):
        raise ManagedError(f"{app['name']}: process identity differs; refusing to change it")
    return row


def preflight():
    for app in APPS:
        path = ROOT / 'relay' / app['ecosystem']
        try:
            config = json.loads(path.read_text())
            entries = [entry for entry in config['apps'] if entry['name'] == app['name']]
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise ManagedError(f"{app['name']}: ecosystem descriptor unavailable") from error
        if len(entries) != 1:
            raise ManagedError(f"{app['name']}: ecosystem entry must be unique")
        entry = entries[0]
        if (entry.get('script') != str(ROOT / app['script'])
                or (entry.get('args') or []) != app['args']
                or Path(entry.get('cwd', '')) != ROOT / app['cwd']
                or entry.get('interpreter', 'node') != app['interpreter']):
            raise ManagedError(f"{app['name']}: ecosystem identity differs")
        if not (ROOT / app['script']).is_file():
            raise ManagedError(f"{app['name']}: launcher is missing")
    if not (ROOT / 'relay/config.json').is_file():
        raise ManagedError('Mesh gateway configuration is missing')


def operate(command):
    if command in ('start', 'check'):
        preflight()
    # Validate all names before touching any process, including stop operations.
    snapshots = {}
    for app in APPS:
        if app['home'] not in snapshots:
            snapshots[app['home']] = processes(app)
        selected(app, snapshots[app['home']])
    apps = reversed(APPS) if command == 'stop' else APPS
    for app in apps:
        # Refresh immediately before the action; another operator may have acted.
        row = selected(app, processes(app))
        state = row.get('pm2_env', {}).get('status', 'unknown') if row else 'absent'
        pid = row.get('pid', 0) if row else 0
        if command in ('status', 'check'):
            print(f"{app['name']}: {state}, pid={pid}")
            continue
        if command == 'start':
            if state == 'online':
                print(f"{app['name']}: already online, pid={pid}; unchanged")
                continue
            if row is None:
                run_pm2(app, 'start', str(ROOT / 'relay' / app['ecosystem']), '--only', app['name'])
            elif state in ('stopped', 'errored'):
                run_pm2(app, 'restart', str(row['pm_id']))
            else:
                raise ManagedError(f"{app['name']}: currently {state}; no restart attempted")
            after = selected(app, processes(app))
            if not after or after.get('pm2_env', {}).get('status') != 'online':
                raise ManagedError(f"{app['name']}: start did not reach online state")
            print(f"{app['name']}: started, pid={after.get('pid', 0)}")
        elif command == 'stop':
            if row is None or state in ('stopped', 'errored'):
                print(f"{app['name']}: {state}; unchanged")
                continue
            run_pm2(app, 'stop', str(row['pm_id']))
            print(f"{app['name']}: stopped; runtime data retained")


def main(argv):
    if len(argv) != 1 or argv[0] not in ('start', 'stop', 'status', 'check'):
        print('Usage: relay/start-managed.sh start|stop|status|check', file=sys.stderr)
        return 2
    try:
        lock_path = ROOT / '.runtime/managed-startup.lock'
        with lock_path.open('a') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            operate(argv[0])
        return 0
    except BlockingIOError:
        print('Another scoped mesh operation is running; no action taken', file=sys.stderr)
        return 1
    except (ManagedError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
