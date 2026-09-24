import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from live_roles import COMMONS, ROLE_PATH, dex_arguments
import live_auth as auth


class LocalRoleBinding(unittest.TestCase):
    def fixture(self, root, chain=10101919, version=4):
        (root / 'build/stage').mkdir(parents=True)
        raw = json.dumps({'config': {'chainId': chain,
                        'dexDevnet': {'version': version, 'dexId': '0x' + '22' * 32},
                        'committee': {str(i): {} for i in range(7)}}}).encode()
        (root / 'genesis.json').write_bytes(raw)
        inventory_path = root / 'build/stage/inventory.json'
        inventory = {'ChainID': chain, 'GenesisSHA256': hashlib.sha256(raw).hexdigest(),
                     'Genesis': '0x' + '11' * 32, 'DEXID': '0x' + '22' * 32,
                     'DEXCommittee': '0x' + '33' * 32, 'ConfigurationVersion': version}
        inventory_path.write_text(json.dumps(inventory))
        role = {'version': 1, 'chain_id': chain, 'dex_id': inventory['DEXID'],
                'genesis_sha256': inventory['GenesisSHA256'], 'participants': {},
                'generation_inventory': str(inventory_path),
                'generation_inventory_sha256': hashlib.sha256(inventory_path.read_bytes()).hexdigest()}
        for index, name in enumerate(COMMONS):
            path = root / 'build/stage' / (name + '.json')
            manifest = json.dumps({'Version': 2, 'Devnet': True, 'Mode': 'native-finance',
                      'Index': index, 'Domain': {'Version': 1, 'Epoch': 1, 'ChainID': chain,
                      'Genesis': [17] * 32, 'DEXID': [34] * 32, 'Committee': [51] * 32}}).encode()
            path.write_bytes(manifest)
            role['participants'][name] = {'enabled': True, 'manifest': str(path),
                                          'sha256': hashlib.sha256(manifest).hexdigest()}
        (root / ROLE_PATH).write_text(json.dumps(role))
        return role

    def test_ancestry_selection_requires_version_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            role = self.fixture(root, version=5)
            self.assertIn('--dex.validator', dex_arguments(root, 'cyphermine'))
            for i in range(7):
                self.assertEqual(dex_arguments(root, 'cypher' + str(i)), [])
            path = Path(role['generation_inventory'])
            inv = json.loads(path.read_bytes())
            inv['ConfigurationVersion'] = 4
            path.write_text(json.dumps(inv))
            role['generation_inventory_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
            (root / ROLE_PATH).write_text(json.dumps(role))
            with self.assertRaises(ValueError):
                dex_arguments(root, 'cyphermine')

    def test_default_off_and_committee_never_participates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in COMMONS:
                self.assertEqual(dex_arguments(root, name), [])
            self.fixture(root)
            for i in range(7):
                self.assertEqual(dex_arguments(root, 'cypher' + str(i)), [])
            self.assertEqual(sum('--dex.validator' in dex_arguments(root, n) for n in COMMONS), 7)

    def test_same_chain_or_different_chain_requires_complete_matching_identity(self):
        for chain in (10101919, 10101920, 42):
            with self.subTest(chain=chain), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                role = self.fixture(root, chain)
                self.assertIn('--dex.validator', dex_arguments(root, 'cyphermine'))
                config, genesis = auth.network_identity(root, Path(role['generation_inventory']))
                self.assertEqual(config['chainId'], chain)
                self.assertEqual(genesis, '0x' + '11' * 32)

    def test_independent_disable_and_wrong_generation_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            role = self.fixture(root)
            role['participants']['cypherdex1']['enabled'] = False
            (root / ROLE_PATH).write_text(json.dumps(role))
            self.assertEqual(dex_arguments(root, 'cypherdex1'), [])
            self.assertIn('--dex.validator', dex_arguments(root, 'cyphermine'))
            (root / 'genesis.json').write_bytes((root / 'genesis.json').read_bytes() + b' ')
            with self.assertRaises(ValueError):
                dex_arguments(root, 'cyphermine')

    def test_manifest_tamper_duplicate_and_symlink_rejected(self):
        for mutation in ('tamper', 'duplicate', 'symlink'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                role = self.fixture(root)
                path = Path(role['participants']['cyphermine']['manifest'])
                if mutation == 'tamper':
                    path.write_text('{}')
                elif mutation == 'duplicate':
                    role['participants']['cypherdex1']['manifest'] = str(path)
                    (root / ROLE_PATH).write_text(json.dumps(role))
                else:
                    copy = path.with_suffix('.copy')
                    path.rename(copy)
                    path.symlink_to(copy)
                with self.assertRaises(ValueError):
                    dex_arguments(root, 'cyphermine')

    def test_reviewed_manifest_still_requires_active_full_domain(self):
        mutations = {'Genesis': [99] * 32, 'DEXID': [99] * 32, 'Committee': [99] * 32,
                     'Epoch': 2, 'Version': True, 'ChainID': 10101920}
        for field, value in mutations.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                role = self.fixture(root)
                item = role['participants']['cyphermine']
                path = Path(item['manifest'])
                manifest = json.loads(path.read_bytes())
                manifest['Domain'][field] = value
                raw = json.dumps(manifest).encode()
                path.write_bytes(raw)
                item['sha256'] = hashlib.sha256(raw).hexdigest()
                (root / ROLE_PATH).write_text(json.dumps(role))
                with self.assertRaises(ValueError):
                    dex_arguments(root, 'cyphermine')

    def test_inventory_required_hashed_bounded_and_not_symlinked(self):
        for mutation in ('missing', 'hash', 'chain', 'version', 'dex', 'zero-genesis',
                         'symlink', 'hardlink', 'oversize', 'foreign-path'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                role = self.fixture(root)
                path = Path(role['generation_inventory'])
                inventory = json.loads(path.read_bytes())
                if mutation == 'missing':
                    del role['generation_inventory']
                elif mutation == 'hash':
                    role['generation_inventory_sha256'] = '0' * 64
                elif mutation == 'symlink':
                    saved = path.with_suffix('.saved')
                    path.rename(saved)
                    path.symlink_to(saved)
                elif mutation == 'hardlink':
                    path.with_suffix('.link').hardlink_to(path)
                elif mutation == 'oversize':
                    path.write_bytes(b' ' * (1024 * 1024 + 1))
                    role['generation_inventory_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                elif mutation == 'foreign-path':
                    outside = root / 'inventory.json'
                    outside.write_bytes(path.read_bytes())
                    role['generation_inventory'] = str(outside)
                else:
                    field, value = {'chain': ('ChainID', 10101920), 'version': ('ConfigurationVersion', 3),
                                    'dex': ('DEXID', '0x' + '44' * 32),
                                    'zero-genesis': ('Genesis', '0x' + '00' * 32)}[mutation]
                    inventory[field] = value
                    path.write_text(json.dumps(inventory))
                    role['generation_inventory_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                (root / ROLE_PATH).write_text(json.dumps(role))
                with self.assertRaises(ValueError):
                    dex_arguments(root, 'cyphermine')

    def test_auth_requires_explicit_reviewed_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            role = self.fixture(root)
            path = Path(role['generation_inventory'])
            with self.assertRaises(ValueError):
                auth.network_identity(root)
            alternate = path.with_suffix('.alternate')
            alternate.write_bytes(path.read_bytes())
            with self.assertRaises(ValueError):
                auth.network_identity(root, alternate)
            role['generation_inventory_sha256'] = '0' * 64
            (root / ROLE_PATH).write_text(json.dumps(role))
            with self.assertRaises(ValueError):
                auth.network_identity(root, path)

    def test_auth_same_chain_old_database_rejects_before_signed_or_stateful_calls(self):
        for mode in ('preflight', 'restore'):
            for wrong in ('genesis', 'chain'):
                with self.subTest(mode=mode, wrong=wrong), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    role = self.fixture(root)
                    calls = []
                    records = [('cypher' + str(i), root / str(i), '0x' + 'aa' * 20, 'fake')
                               for i in range(7)]
                    records.append(('cyphermine', root / 'mine', '0x' + 'bb' * 20, 'fake'))
                    def query(ipc, method, params=None):
                        calls.append((ipc, method))
                        if method == 'eth_getBlockByNumber':
                            self.assertEqual(params, ['0x0', False])
                            return {'hash': '0x' + ('99' if wrong == 'genesis' and ipc == root / 'mine' else '11') * 32}
                        if method == 'eth_chainId':
                            return hex(10101920 if wrong == 'chain' and ipc == root / 'mine' else 10101919)
                        raise AssertionError('no signature/unlock/start allowed before all endpoint identities pass')
                    with patch.object(auth, 'REPO', root), patch.object(auth, 'credentials', return_value=records), patch.object(auth, 'rpc', side_effect=query):
                        with self.assertRaises(ValueError):
                            auth.execute(mode, Path(role['generation_inventory']))
                    self.assertTrue(calls)
                    self.assertTrue(all(method in ('eth_getBlockByNumber', 'eth_chainId') for _, method in calls))

    def test_explicit_role_restore_does_not_touch_other_running_roles(self):
        for target in ('cyphermine', 'cypher0'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                role = self.fixture(root)
                records = [(name, root / name, '0x' + 'aa' * 20, 'fake')
                           for name in ('cypher0', 'cyphermine')]
                calls = []
                def query(ipc, method, params=None):
                    self.assertEqual(ipc, root / target)
                    calls.append(method)
                    return {'eth_getBlockByNumber': {'hash': '0x' + '11' * 32},
                            'eth_chainId': hex(10101919),
                            'personal_unlockAccount': True,
                            'personal_getCommonRPCRewardAddress': {
                                'configured': True, 'rewardRecipient': auth.COMMON_RPC_RECIPIENT},
                            'miner_start': 'Mining started', 'eth_mining': target != 'cyphermine',
                            'miner_status': {'scope': 'unit'}}[method]
                with patch.object(auth, 'REPO', root), patch.object(auth, 'credentials', return_value=records), patch.object(auth, 'rpc', side_effect=query):
                    result = auth.execute('restore', Path(role['generation_inventory']), [target])
                self.assertEqual([item['app'] for item in result['records']], [target])
                self.assertEqual('miner_start' in calls, target != 'cyphermine')

    def test_explicit_invalid_role_targets_fail_before_rpc(self):
        for targets in ([], ['cypher0', 'cypher0'], ['unrelated-service']):
            with self.subTest(targets=targets), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                role = self.fixture(root)
                records = [('cypher0', root / 'cypher0', '0x' + 'aa' * 20, 'fake')]
                with patch.object(auth, 'REPO', root), patch.object(auth, 'credentials', return_value=records), patch.object(auth, 'rpc') as query:
                    with self.assertRaises(ValueError):
                        auth.execute('restore', Path(role['generation_inventory']), targets)
                    query.assert_not_called()


if __name__ == '__main__':
    unittest.main()
