"""Execute the user's init script only against disposable mock directories."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]

class InitPaths(unittest.TestCase):
    def test_exact_dex_runtime_cleanup_keeps_nodekeys_and_keystores(self):
        with tempfile.TemporaryDirectory(prefix='dex-init-path-test-') as td:
            root = Path(td)
            shutil.copyfile(REPO/'init.sh', root/'init.sh')
            (root/'genesis.json').write_text('{"config":{"chainId":10101919}}')
            fake = root/'mock-bin'; fake.mkdir()
            log = root/'calls'
            body = '#!/usr/bin/env python3\nimport json,os,sys\nwith open(os.environ["INIT_TEST_LOG"],"a") as f:f.write(json.dumps(sys.argv)+"\\n")\n'
            (fake/'pm2').write_text(body); (fake/'pm2').chmod(0o700)
            binary = root/'build/bin/cypher-linux-amd64'; binary.parent.mkdir(parents=True)
            binary.write_text(body); binary.chmod(0o700)
            dirs = [root/f'chaindb{i}' for i in range(7)] + [root/'chaindbmine'] + [root/f'build/stage/live-commons/chaindbdex{i}' for i in range(1,7)]
            for d in dirs:
                (d/'cypher/chaindata').mkdir(parents=True)
                (d/'cypher/chaindata/old').write_text('old')
                (d/'cypher/nodekey').write_text('NODEKEY')
                (d/'keystore').mkdir(); (d/'keystore/key').write_text('KEYSTORE')
                (d/'history').mkdir(); (d/'history/old').write_text('old')
            generations = [root/f'build/stage/{n}' for n in ('live-generation-candidate','live-generation-finality-v5')]
            for g in generations:
                (g/'keys').mkdir(parents=True); (g/'keys/vote.key').write_text('TEST KEY')
                for n in ('cyphermine/dex','cypherdex1/dex','cyphermine/dex/submission','cypherdex1/dex/submission','relay-0','relay-1'):
                    (g/'runtime'/n).mkdir(parents=True,exist_ok=True); (g/'runtime'/n/'WAL').write_text('old')
            env = dict(os.environ, PATH=str(fake)+os.pathsep+os.environ['PATH'], INIT_TEST_LOG=str(log), PYTHONDONTWRITEBYTECODE='1')
            subprocess.run(['bash', str(root/'init.sh')], cwd=root,env=env,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
            calls=[json.loads(s) for s in log.read_text().splitlines()]
            self.assertEqual(calls[0][1], 'stop')
            # Standalone relay nodes were retired by the explicit user request.
            # The current process layout is CLX7 plus Common7; submission WALs
            # belong inside the Common-owned DEX data directory.
            expected=[f'cypher{i}' for i in range(7)]+['cyphermine']+[f'cypherdex{i}' for i in range(1,7)]
            self.assertEqual(calls[0][2:],expected)
            self.assertNotIn('cypherdex-relay0',calls[0]); self.assertNotIn('cypherdex-relay1',calls[0])
            self.assertEqual(len(calls),15)
            for d, call in zip(dirs,calls[1:]):
                self.assertEqual(call[1:],['--datadir',str(d.relative_to(root)),'init',str(root/'genesis.json')])
                self.assertEqual((d/'cypher/nodekey').read_text(),'NODEKEY')
                self.assertEqual((d/'keystore/key').read_text(),'KEYSTORE')
                self.assertFalse((d/'cypher/chaindata').exists()); self.assertFalse((d/'history').exists())
            for g in generations:
                if g.name == 'live-generation-finality-v5':
                    names = ['cyphermine'] + ['cypherdex'+str(i) for i in range(1,7)]
                    self.assertEqual({p.name for p in (g/'runtime').iterdir()},set(names))
                    for name in names:
                        parent = g/'runtime'/name
                        self.assertEqual(list(parent.iterdir()),[])
                        self.assertEqual(parent.stat().st_mode & 0o777,0o700)
                else:
                    self.assertEqual(list((g/'runtime').iterdir()),[])
                self.assertEqual((g/'keys/vote.key').read_text(),'TEST KEY')
            self.assertEqual(json.loads((root/'genesis.json').read_text())['config']['chainId'],10101919)
