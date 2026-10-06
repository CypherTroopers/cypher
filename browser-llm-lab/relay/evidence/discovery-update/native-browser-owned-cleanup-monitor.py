"""Read-only audit of browser PIDs explicitly recorded by our acceptance runner.

Never enumerates /proc, signals a process, reads a key, or deletes a profile.
Writes only its own JSON evidence. Run in host process namespace.
"""
import datetime
import json
import os
import pathlib
import re
import sys
import time

ROOT = pathlib.Path('/tmp/cypher-mesh-discovery-20261003/evidence')
SOURCE = ROOT / 'native-discovery-browser-report.json'
OUTPUT = ROOT / 'native-browser-owned-cleanup.json'

def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def proc(pid):
    directory = pathlib.Path('/proc') / str(pid)
    try:
        stat = (directory / 'stat').read_text()
        tail = stat[stat.rfind(')') + 2:].split()
        argv = (directory / 'cmdline').read_bytes().decode('utf-8', errors='replace').split('\0')
        if argv and not argv[-1]:
            argv.pop()
        return {'present': True, 'state': tail[0], 'startTicks': tail[19], 'argv': argv}
    except FileNotFoundError:
        return {'present': False}
    except (PermissionError, ProcessLookupError) as error:
        return {'present': None, 'error': str(error)}

def profile_from_command(name, argv):
    # Chrome's process title may flatten argv into one NUL-terminated string.
    matches = re.findall(r'(?:^|\s)--user-data-dir=(/tmp/cypher-mesh-' + re.escape(name) + r'-[A-Za-z0-9]+)(?=\s|$)', ' '.join(argv))
    return matches[0] if len(matches) == 1 else None

if '--capture-d' in sys.argv:
    capture_deadline = time.monotonic() + 20 * 60
    while time.monotonic() < capture_deadline:
        try:
            report = json.loads(SOURCE.read_text())
            item = report.get('processes', {}).get('D', {})
            pid = item.get('browserPid')
            if isinstance(pid, int) and pid > 1:
                observed = proc(pid)
                profile = profile_from_command('D', observed.get('argv', []))
                if observed.get('present') is True and profile:
                    row = {'name': 'D', 'pid': pid, 'firstSeenAt': stamp(), 'origin': item.get('origin'), 'initialProcess': observed, 'profile': profile, 'profileValidated': True, 'profilePresentWhenCaptured': pathlib.Path(profile).is_dir()}
                    (ROOT / 'native-browser-owned-d-capture.json').write_text(json.dumps(row, indent=2) + '\n')
                    print(json.dumps({key: row[key] for key in ('name', 'pid', 'profile', 'firstSeenAt')}), flush=True)
                    sys.exit(0)
            if report.get('status') in ('PASS', 'FAIL'):
                break
        except (OSError, ValueError):
            pass
        time.sleep(1)
    print('D browser could not be captured while alive', flush=True)
    sys.exit(1)

if '--finalize-existing' in sys.argv:
    audit = json.loads(OUTPUT.read_text())
    audit['monitorInitialStatus'] = audit['status']
    d_capture = ROOT / 'native-browser-owned-d-capture.json'
    if d_capture.exists():
        row = json.loads(d_capture.read_text())
        key = 'D:' + str(row['pid'])
        if not audit['ownedBrowsers'].get(key, {}).get('initialProcess'):
            audit['ownedBrowsers'][key] = row
    for browser in audit['ownedBrowsers'].values():
        initial = browser.get('initialProcess', {})
        profile = profile_from_command(browser['name'], initial.get('argv', []))
        browser['profileValidated'] = profile is not None
        if profile:
            browser['profile'] = profile
            browser['profilePresent'] = pathlib.Path(profile).exists()
        observed = proc(browser['pid'])
        browser['currentProcess'] = {k: value for k, value in observed.items() if k != 'argv'}
        browser['sameOwnedProcessAlive'] = observed.get('present') is True and observed.get('startTicks') == initial.get('startTicks')
        browser['lastCheckedAt'] = stamp()
    audit['status'] = 'CLEAN' if audit['ownedBrowsers'] and all(row.get('profileValidated') and not row['sameOwnedProcessAlive'] and not row.get('profilePresent', True) and row['currentProcess'].get('present') is not None for row in audit['ownedBrowsers'].values()) else 'REMAINDERS_OR_UNVERIFIED'
    audit['finishedAt'] = stamp()
    audit['updatedAt'] = stamp()
    OUTPUT.write_text(json.dumps(audit, indent=2) + '\n')
    print(json.dumps({'status': audit['status'], 'browsers': [{key: row.get(key) for key in ('name', 'pid', 'profile', 'sameOwnedProcessAlive', 'profilePresent')} for row in audit['ownedBrowsers'].values()]}), flush=True)
    sys.exit(0)

audit = {
    'startedAt': stamp(), 'status': 'RUNNING', 'sourceReport': str(SOURCE),
    'scope': 'Only browserPid values from this acceptance report; no other process scan, signals, native calls, or deletion',
    'ownedBrowsers': {}, 'sourceStatus': None, 'hostPidNamespace': os.readlink('/proc/self/ns/pid'),
}
deadline = time.monotonic() + 35 * 60
terminal_since = None
while True:
    try:
        source = json.loads(SOURCE.read_text())
        audit['sourceStatus'] = source.get('status')
        audit['sourceFinishedAt'] = source.get('finishedAt')
        for name, item in source.get('processes', {}).items():
            if name not in ('A', 'B', 'C', 'D'):
                continue
            pid = item.get('browserPid')
            if not isinstance(pid, int) or pid < 2:
                continue
            observed = proc(pid)
            key = name + ':' + str(pid)
            browser = audit['ownedBrowsers'].setdefault(key, {'name': name, 'pid': pid, 'firstSeenAt': stamp(), 'origin': item.get('origin')})
            if 'initialProcess' not in browser and observed.get('present') is True:
                browser['initialProcess'] = observed
                profile = profile_from_command(name, observed.get('argv', []))
                browser['profileValidated'] = profile is not None
                if browser['profileValidated']:
                    browser['profile'] = profile
                    browser['profilePresentWhenCaptured'] = pathlib.Path(profile).is_dir()
            browser['currentProcess'] = {k: value for k, value in observed.items() if k != 'argv'}
            initial = browser.get('initialProcess', {})
            browser['sameOwnedProcessAlive'] = observed.get('present') is True and observed.get('startTicks') == initial.get('startTicks')
            if browser.get('profileValidated'):
                browser['profilePresent'] = pathlib.Path(browser['profile']).exists()
            browser['lastCheckedAt'] = stamp()
        if source.get('status') in ('PASS', 'FAIL'):
            terminal_since = terminal_since or time.monotonic()
        if terminal_since is not None and time.monotonic() - terminal_since >= 45:
            audit['status'] = 'CLEAN' if audit['ownedBrowsers'] and all(row.get('profileValidated') and not row['sameOwnedProcessAlive'] and not row.get('profilePresent', True) and row['currentProcess'].get('present') is not None for row in audit['ownedBrowsers'].values()) else 'REMAINDERS_OR_UNVERIFIED'
            audit['finishedAt'] = stamp()
    except Exception as error:
        audit['lastReadError'] = type(error).__name__ + ': ' + str(error)
    if time.monotonic() >= deadline and audit['status'] == 'RUNNING':
        audit['status'] = 'MONITOR_TIMEOUT'
        audit['finishedAt'] = stamp()
    audit['updatedAt'] = stamp()
    temp = OUTPUT.with_suffix('.json.pending')
    temp.write_text(json.dumps(audit, indent=2) + '\n')
    temp.replace(OUTPUT)
    if audit['status'] != 'RUNNING':
        print(json.dumps({'status': audit['status'], 'sourceStatus': audit['sourceStatus'], 'output': str(OUTPUT), 'browsers': [{key: row.get(key) for key in ('name', 'pid', 'profile', 'sameOwnedProcessAlive', 'profilePresent')} for row in audit['ownedBrowsers'].values()]}), flush=True)
        break
    time.sleep(10)
