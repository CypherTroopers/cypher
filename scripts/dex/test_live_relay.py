import json
from pathlib import Path
import tempfile
import unittest

import live_relay as relay


class RelayLauncherTest(unittest.TestCase):
    def fixture(self, temporary, chain_id=10101919, generation=None, version=4):
        repo = Path(temporary)
        directory = repo/(relay.CANDIDATE if generation is None else Path("build/stage")/generation)
        directory.mkdir(parents=True, mode=0o700)
        for child in ("public", "relays", "runtime"):
            (directory/child).mkdir(mode=0o700)
        genesis = {"config":{"chainId":chain_id, "dexDevnet":{"version":version,"dexId":"0x"+"22"*32}}}
        raw = json.dumps(genesis).encode()
        inv = {"ChainID":chain_id,"ConfigurationVersion":version,"DEXID":"0x"+"22"*32,
               "Genesis":"0x"+"11"*32,"DEXCommittee":"0x"+"33"*32,"GenesisSHA256":relay.digest(raw)}
        (directory/"genesis.json").write_bytes(raw)
        (directory/"public/inventory.json").write_text(json.dumps(inv))
        for index in range(2):
            config = {"Version":2,"Devnet":True,"Domain":{"Version":1,"ChainID":chain_id,"Epoch":1,
                       "Genesis":[17]*32,"DEXID":[34]*32,"Committee":[51]*32},
                      "DataDir":str(directory/f"runtime/relay-{index}"),"SourceURL":"http://127.0.0.1:8999",
                      "SubmitURL":"http://127.0.0.1:8999","DEXURL":f"http://127.0.0.1:{19000+index}",
                      "MaxHeight":4096,"Payers":[{"Address":"0x"+f"{index*3+lane+1:040x}",
                          "KeyFile":str(directory/f"keys/relay-{index}-{lane}.key")} for lane in range(3)]}
            (directory/f"relays/relay-{index}.json").write_text(json.dumps(config))
        (repo/"genesis.json").write_bytes(raw)
        (repo/"build/stage/live-deployment.json").write_text(json.dumps({"version":1,
          "genesis_sha256":inv["GenesisSHA256"],"chain_id":inv["ChainID"],"dex_id":inv["DEXID"],
          "generation_inventory":str(directory/"public/inventory.json"),
          "generation_inventory_sha256":relay.digest((directory/"public/inventory.json").read_bytes())}))
        (repo/"build/bin").mkdir()
        binary = repo/"build/bin/cypher-linux-amd64"
        binary.write_text("not executed in test")
        binary.chmod(0o700)
        return repo, directory

    @staticmethod
    def query(method, params):
        if method == "eth_chainId" and params == []:
            return hex(10101919)
        if method == "eth_getBlockByNumber" and params == ["0x0", False]:
            return {"hash":"0x"+"11"*32}
        raise AssertionError("unexpected RPC method or latest trust")

    def test_prepare_only_two_relays_and_exec_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, directory = self.fixture(temporary)
            plan = relay.prepare(repo)
            self.assertFalse(plan["started"])
            apps = json.loads((directory/"pm2-relays/ecosystem.json").read_text())["apps"]
            self.assertEqual([a["name"] for a in apps], list(relay.NAMES))
            for index, app in enumerate(apps):
                self.assertIn("exec python3",Path(app["script"]).read_text())
                self.assertTrue(app["treekill"])
                self.assertEqual(app["kill_timeout"],30000)
                self.assertEqual(relay.command(repo,index,self.query),[str(repo/"build/bin/cypher-linux-amd64"),
                    "dex-relay","--relay.config",str(directory/f"relays/relay-{index}.json")])
                self.assertFalse((directory/f"runtime/relay-{index}").exists())
            before=(directory/"pm2-relays/plan.json").read_bytes()
            with self.assertRaises(FileExistsError):relay.prepare(repo)
            self.assertEqual(before,(directory/"pm2-relays/plan.json").read_bytes())

    def test_old_genesis_missing_activation_and_foreign_domain_reject_before_rpc(self):
        for failure in ("old-genesis","missing-activation","foreign-domain", "inventory-hash", "inventory-missing"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                repo,directory=self.fixture(temporary)
                relay.prepare(repo)
                if failure=="old-genesis":(repo/"genesis.json").write_text('{"config":{"chainId":10101919}}')
                elif failure=="missing-activation":(repo/"build/stage/live-deployment.json").unlink()
                elif failure == "foreign-domain":
                    p=repo/"build/stage/live-deployment.json"
                    x=json.loads(p.read_text());x["dex_id"]="0x"+"44"*32;p.write_text(json.dumps(x))
                else:
                    p=repo/"build/stage/live-deployment.json"
                    x=json.loads(p.read_text())
                    if failure == "inventory-hash":x["generation_inventory_sha256"] = "0" * 64
                    else:del x["generation_inventory"]
                    p.write_text(json.dumps(x))
                def forbidden(*args):raise AssertionError("RPC must not be called before local activation")
                with self.assertRaises((ValueError,FileNotFoundError)):relay.command(repo,0,forbidden)

    def test_source_running_old_database_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo,directory=self.fixture(temporary);relay.prepare(repo)
            for wrong in ("chain","genesis"):
                def query(method,params):
                    if wrong=="chain" and method=="eth_chainId":return hex(10101920)
                    if wrong=="genesis" and method=="eth_getBlockByNumber":return {"hash":"0x"+"99"*32}
                    return self.query(method,params)
                with self.assertRaises(ValueError):relay.command(repo,0,query)

    def test_bound_chain_is_not_a_fixed_candidate_number(self):
        for chain in (10101919, 10101920, 42):
            with self.subTest(chain=chain), tempfile.TemporaryDirectory() as temporary:
                repo,directory=self.fixture(temporary, chain);relay.prepare(repo)
                def query(method,params):
                    if method == "eth_chainId" and params == []:return hex(chain)
                    return self.query(method,params)
                self.assertEqual(relay.command(repo,0,query)[1], "dex-relay")

    def test_reviewed_domain_fields_must_match_candidate_genesis(self):
        for field, value in (("Genesis", [99]*32), ("DEXID", [99]*32), ("Committee", [99]*32),
                             ("Epoch", 2), ("ChainID", 10101920)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                repo,directory=self.fixture(temporary)
                p=directory/"relays/relay-0.json"
                data=json.loads(p.read_text());data["Domain"][field]=value;p.write_text(json.dumps(data))
                with self.assertRaises(ValueError):relay.prepare(repo)
                self.assertFalse((directory/"pm2-relays").exists())

    def test_changed_config_symlink_and_duplicate_payer_rejected(self):
        for failure in ("changed","symlink","duplicate-payer","wrong-datadir"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                repo,directory=self.fixture(temporary);relay.prepare(repo)
                p=directory/"relays/relay-1.json"
                if failure=="symlink":
                    saved=p.with_suffix(".saved");p.rename(saved);p.symlink_to(saved)
                else:
                    x=json.loads(p.read_text())
                    if failure=="changed":x["PollMillis"]=999
                    elif failure=="duplicate-payer":x["Payers"][1]["Address"]=x["Payers"][0]["Address"]
                    else:x["DataDir"]=str(repo/"chaindb0")
                    p.write_text(json.dumps(x))
                with self.assertRaises(ValueError):relay.command(repo,0,self.query)

    def test_no_third_index_or_runtime_parent_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo,directory=self.fixture(temporary);relay.prepare(repo)
            with self.assertRaises(ValueError):relay.command(repo,2,self.query)
            (directory/"runtime").rmdir()
            with self.assertRaises(ValueError):relay.command(repo,0,self.query)
            self.assertFalse((directory/"runtime").exists())

    def test_active_inventory_selects_new_candidate_without_legacy_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, directory = self.fixture(temporary, generation="live-generation-finality-v5", version=5)
            relay.prepare(repo, directory)
            # A corrupt old candidate must not influence authenticated selection.
            legacy = repo/relay.CANDIDATE
            legacy.mkdir(mode=0o700)
            (legacy/"genesis.json").write_text("obsolete")
            for index in (0, 1):
                self.assertEqual(relay.command(repo,index,self.query)[-1],
                                 str(directory/f"relays/relay-{index}.json"))

    def test_explicit_prepare_does_not_require_or_change_activation(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, directory = self.fixture(temporary, generation="live-generation-finality-v5", version=5)
            activation = repo/"build/stage/live-deployment.json"
            activation.unlink()
            plan = relay.prepare(repo, directory.relative_to(repo))
            self.assertFalse(plan["started"])
            self.assertFalse(activation.exists())
            with self.assertRaises(FileNotFoundError):
                relay.command(repo,0,lambda *_:self.fail("RPC before activation"))

    def test_candidate_path_cannot_escape_or_use_symlink(self):
        for kind in ("foreign", "traversal", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                repo, directory = self.fixture(temporary)
                if kind == "foreign":
                    selected = repo.parent/directory.name
                elif kind == "traversal":
                    selected = directory/".."/directory.name
                else:
                    selected = directory.parent/"alias"
                    selected.symlink_to(directory, target_is_directory=True)
                with self.assertRaises(ValueError):relay.prepare(repo,selected)
                self.assertFalse((directory/"pm2-relays").exists())

    def test_active_inventory_noncanonical_location_rejected_before_rpc(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, directory = self.fixture(temporary)
            relay.prepare(repo)
            unexpected = directory/"public/renamed-inventory.json"
            unexpected.write_bytes((directory/"public/inventory.json").read_bytes())
            path = repo/"build/stage/live-deployment.json"
            active = json.loads(path.read_text())
            active["generation_inventory"] = str(unexpected)
            path.write_text(json.dumps(active))
            with self.assertRaises(ValueError):
                relay.command(repo,0,lambda *_:self.fail("RPC before canonical selection"))


if __name__ == "__main__":
    unittest.main()
