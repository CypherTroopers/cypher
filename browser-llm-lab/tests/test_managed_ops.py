"""Scoped PM2 operations: no daemon, process, or network access in these tests."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('managed_apps', Path(__file__).resolve().parents[1] / 'relay/managed-apps.py')
managed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(managed)


def row(app, index, state='online'):
    return {'name': app['name'], 'pm_id': index, 'pid': 7000 + index,
            'pm2_env': {'pm_exec_path': str(managed.ROOT / app['script']),
                        'pm_cwd': str(managed.ROOT / app['cwd']),
                        'args': app['args'], 'exec_interpreter': app['interpreter'],
                        'status': state}}


class ScopedOperationsTests(unittest.TestCase):
    def setUp(self):
        self.rows = [row(app, i + 20) for i, app in enumerate(managed.APPS)]
        self.actions = []
        self.preflight = patch.object(managed, 'preflight')
        self.processes = patch.object(managed, 'processes', side_effect=lambda app: self.rows)
        self.runner = patch.object(managed, 'run_pm2', side_effect=self.run_pm2)
        for mock in (self.preflight, self.processes, self.runner):
            mock.start()
            self.addCleanup(mock.stop)
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)

    def run_pm2(self, app, *args):
        self.actions.append((app['name'], app['home'], args))
        current = next((item for item in self.rows if item['name'] == app['name']), None)
        if args[0] == 'start':
            self.rows.append(row(app, 99))
        elif args[0] == 'restart':
            current['pm2_env']['status'] = 'online'
        elif args[0] == 'stop':
            current['pm2_env']['status'] = 'stopped'
        else:
            self.fail(f'Unexpected process command: {args}')
        return ''

    def test_online_start_is_strictly_read_only(self):
        managed.operate('start')
        self.assertEqual(self.actions, [])

    def test_missing_app_uses_only_its_ecosystem_entry_and_dedicated_home(self):
        app = managed.APPS[1]
        self.rows.pop()
        managed.operate('start')
        self.assertEqual(self.actions, [(app['name'], app['home'],
            ('start', str(managed.ROOT / 'relay' / app['ecosystem']), '--only', app['name']))])

    def test_stopped_owned_app_restarts_only_its_verified_numeric_id(self):
        self.rows[1]['pm2_env']['status'] = 'stopped'
        managed.operate('start')
        self.assertEqual([action[2] for action in self.actions], [('restart', '21')])

    def test_foreign_name_collision_aborts_before_starting_anything(self):
        self.rows.pop(0)
        self.rows[-1]['pm2_env']['pm_exec_path'] = '/tmp/unrelated-server.mjs'
        with self.assertRaisesRegex(managed.ManagedError, 'identity differs'):
            managed.operate('start')
        self.assertEqual(self.actions, [])

    def test_duplicate_name_aborts_before_mutation(self):
        self.rows.append(dict(self.rows[1], pm_id=84))
        with self.assertRaisesRegex(managed.ManagedError, 'duplicate name'):
            managed.operate('stop')
        self.assertEqual(self.actions, [])

    def test_native_binary_cannot_replace_the_gateway_identity(self):
        self.rows[1]['pm2_env']['pm_exec_path'] = str(managed.ROOT / '.runtime/mesh-b/cypher')
        with self.assertRaisesRegex(managed.ManagedError, 'identity differs'):
            managed.operate('start')
        self.assertEqual(self.actions, [])

    def test_unexpected_working_directory_is_rejected_before_any_action(self):
        self.rows[1]['pm2_env']['pm_cwd'] = '/tmp/unrelated-workspace'
        with self.assertRaisesRegex(managed.ManagedError, 'identity differs'):
            managed.operate('start')
        self.assertEqual(self.actions, [])

    def test_pending_start_is_not_interrupted(self):
        self.rows[0]['pm2_env']['status'] = 'launching'
        with self.assertRaisesRegex(managed.ManagedError, 'no restart attempted'):
            managed.operate('start')
        self.assertEqual(self.actions, [])

    def test_stop_addresses_only_owned_ids_in_reverse_dependency_order(self):
        self.rows.append({'name': 'cypher0', 'pm_id': 0, 'pid': 1234, 'pm2_env': {}})
        managed.operate('stop')
        self.assertEqual([action[2] for action in self.actions],
                         [('stop', '21'), ('stop', '20')])
        self.assertEqual(self.rows[-1]['pid'], 1234)

    def test_status_and_check_do_not_change_processes(self):
        managed.operate('status')
        managed.operate('check')
        self.assertEqual(self.actions, [])

    def test_production_scope_excludes_standard_common_and_old_native_fixtures(self):
        self.assertEqual([app['name'] for app in managed.APPS],
                         ['cypher-header-turn', 'cypher-browser-mesh-gateway'])
        native = [{'name': name, 'pm_id': 100 + i, 'pid': 12000 + i,
                   'pm2_env': {'status': 'online', 'pm_exec_path': '/native/untouched'}}
                  for i, name in enumerate(['cyphermine', 'cypher-browser-mesh-a', 'cypher-browser-mesh-b'])]
        self.rows.extend(native)
        managed.operate('stop')
        self.assertEqual([action[0] for action in self.actions],
                         ['cypher-browser-mesh-gateway', 'cypher-header-turn'])
        self.assertTrue(all(item['pm2_env']['status'] == 'online' for item in native))

    def test_root_is_derived_from_module_location(self):
        self.assertEqual(managed.ROOT, Path(managed.__file__).resolve().parents[1])


class ProductionPreflightTests(unittest.TestCase):
    def test_production_preflight_requires_no_native_fixture_launchers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            apps = []
            for configured in managed.APPS:
                app = dict(configured)
                if app['args']:
                    app['args'] = [str(root / 'relay/config.json')]
                apps.append(app)
                script = root / app['script']
                script.parent.mkdir(parents=True, exist_ok=True)
                script.write_text('# fixture')
                descriptor = root / 'relay' / app['ecosystem']
                descriptor.parent.mkdir(parents=True, exist_ok=True)
                descriptor.write_text(json.dumps({'apps': [{'name': app['name'],
                    'script': str(script), 'cwd': str(root / app['cwd']),
                    'args': app['args'], 'interpreter': app['interpreter']}]}))
            (root / 'relay/config.json').write_text('{}')
            with patch.object(managed, 'ROOT', root), patch.object(managed, 'APPS', tuple(apps)):
                managed.preflight()
            self.assertFalse((root / '.runtime/mesh-a').exists())
            self.assertFalse((root / '.runtime/mesh-b').exists())


if __name__ == '__main__':
    unittest.main()
