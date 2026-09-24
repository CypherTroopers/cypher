#!/usr/bin/env python3
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import live_generation_plan as planner


class GenerationPlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.old = {"config": {"chainId": 10101919, "committee": {str(i): {} for i in range(7)},
                               "fairHotstuff": True, "fixedCommittee": True, "fixedLeader": False}}
        (self.root / "genesis.json").write_text(json.dumps(self.old))
        self.observation = {"host": planner.HOST, "uid": 0, "workspace": str(self.root),
                            "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
                            "observed_utc": "2026-09-23T12:00:00Z", "apps": []}
        self.now = 1790164800
        self.new_id = 10101920
        self.dex_id = "0x" + "a1" * 32
        for i, name in enumerate(planner.APPS):
            suffix = "mine" if name == "cyphermine" else name.removeprefix("cypher")
            path = self.root / ("chaindb" + suffix)
            (path / "keystore").mkdir(parents=True)
            (path / "keystore/secret-wallet.json").write_text("SECRET-WALLET-CONTENT")
            (path / "cypher/chaindata").mkdir(parents=True)
            (path / "cypher/nodekey").write_text("SECRET-NODEKEY-CONTENT")
            (path / "cypher/chaindata/CURRENT").write_text("EXISTING-DATABASE")
            node = {"pid": 100 + i, "start_ticks": 50 + i, "datadir": str(path),
                    "exe_sha256": "ab" * 32,
                    "flags": {"--datadir": str(path)},
                    "rpc": {"chain_id": hex(10101919),
                            "genesis": {"number": "0x0", "hash": "0x" + "11" * 32,
                                        "stateRoot": "0x" + "22" * 32}}}
            self.observation["apps"].append({"name": name, "pm_id": i, "pid": node["pid"], "pm2": {"status": "online"}, "processes": [node]})

    def add_stopped_commons(self):
        for i, name in enumerate(planner.ADDED_COMMONS, 1):
            path = self.root / "build/stage/live-commons" / ("chaindbdex" + str(i))
            (path / "keystore").mkdir(parents=True)
            (path / "keystore/unit-secret").write_text("SECRET-STOPPED-WALLET")
            (path / "cypher").mkdir()
            (path / "cypher/nodekey").write_text("SECRET-STOPPED-NODEKEY")
            self.observation["apps"].append({"name": name, "pm_id": 7 + i, "pid": 0,
                                            "pm2": {"status": "stopped"}, "processes": []})

    def make(self, **kwargs):
        args = {"workspace": self.root, "observation": self.observation,
                "new_chain_id": self.new_id, "dex_id": self.dex_id, "now": self.now}
        args.update(kwargs)
        return planner.plan(**args)

    def test_plan_is_blocked_exact_targets_and_does_not_read_keys_or_mutate_data(self):
        before = {str(p.relative_to(self.root)): (p.stat().st_ino, p.stat().st_size, p.stat().st_mtime_ns)
                  for p in self.root.rglob("*")}
        real_read = Path.read_bytes
        reads = []

        def checked_read(path):
            reads.append(path)
            self.assertEqual(path, self.root / "genesis.json")
            return real_read(path)

        with mock.patch.object(Path, "read_bytes", checked_read):
            result = self.make()
        self.assertTrue(reads)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertFalse(result["reset_authorized"])
        self.assertFalse(result["executor_implemented"])
        self.assertEqual([x["pm2_name"] for x in result["targets"]], list(planner.APPS))
        self.assertEqual(len({x["archive_datadir"] for x in result["targets"]}), 8)
        encoded = json.dumps(result)
        self.assertNotIn("SECRET-", encoded)
        self.assertNotIn("secret-wallet.json", encoded)
        self.assertIsNone(result["new_generation"]["genesis_hash"])
        after = {str(p.relative_to(self.root)): (p.stat().st_ino, p.stat().st_size, p.stat().st_mtime_ns)
                 for p in self.root.rglob("*")}
        self.assertEqual(before, after)

    def test_new_chain_id_and_domain_required(self):
        for value in (10101919, 0, -1, 2**64, True):
            with self.subTest(chain_id=value), self.assertRaises(ValueError):
                self.make(new_chain_id=value)
        for value in ("0x" + "00" * 32, "not-a-hash", "0x11"):
            with self.subTest(dex_id=value), self.assertRaises(ValueError):
                self.make(dex_id=value)

    def test_explicit_same_chain_mode_preserves_id_and_reports_replay_limit(self):
        value = self.make(new_chain_id=10101919, preserve_chain_id=True)
        self.assertEqual(value["new_generation"]["chain_id"], 10101919)
        self.assertTrue(value["chain_id_preserved"])
        self.assertIn("do NOT prevent old ordinary CLX signed TX replay", value["replay_policy"])
        self.assertFalse(value["reset_authorized"])
        with self.assertRaises(ValueError):
            self.make(new_chain_id=10101920, preserve_chain_id=True)

    def test_wrong_host_workspace_or_user_refused(self):
        for field, value in (("host", "other-host"), ("uid", 1000), ("workspace", "/other")):
            observation = copy.deepcopy(self.observation)
            observation[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.make(observation=observation)

    def test_stale_and_future_observations_refused(self):
        for now in (self.now + 901, self.now - 31):
            with self.subTest(now=now), self.assertRaises(ValueError):
                self.make(now=now)

    def test_app_addition_or_missing_node_requires_new_inventory(self):
        for mutation in (lambda apps: apps.pop(),
                         lambda apps: apps.append({"name": "other-service"}),
                         lambda apps: apps[0].update(name="start-cypher0"),
                         lambda apps: apps[0].update(processes=[])):
            observation = copy.deepcopy(self.observation)
            mutation(observation["apps"])
            with self.assertRaises(ValueError):
                self.make(observation=observation)

    def test_node_identity_mismatch_and_duplicate_process_refused(self):
        for field, value in (("datadir", "/unrelated/database"), ("pid", 101), ("start_ticks", 0)):
            observation = copy.deepcopy(self.observation)
            observation["apps"][0]["processes"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.make(observation=observation)

    def test_split_genesis_or_chain_id_refused(self):
        for field in ("hash", "stateRoot"):
            observation = copy.deepcopy(self.observation)
            observation["apps"][1]["processes"][0]["rpc"]["genesis"][field] = "0x" + "33" * 32
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.make(observation=observation)
        observation = copy.deepcopy(self.observation)
        observation["apps"][1]["processes"][0]["rpc"]["chain_id"] = "0x1"
        with self.assertRaises(ValueError):
            self.make(observation=observation)

    def test_datadir_symlink_refused(self):
        path = self.root / "chaindb0"
        path.rename(self.root / "renamed")
        path.symlink_to(self.root / "renamed", target_is_directory=True)
        with self.assertRaises(ValueError):
            self.make()

    def test_secret_symlink_or_hardlink_refused_without_reading(self):
        secret = self.root / "chaindb0/cypher/nodekey"
        secret.unlink()
        secret.symlink_to(self.root / "genesis.json")
        with self.assertRaises(ValueError):
            self.make()
        secret.unlink()
        secret.hardlink_to(self.root / "chaindb1/cypher/nodekey")
        with self.assertRaises(ValueError):
            self.make()

    def test_archive_never_merges_existing_destination(self):
        destination = self.root / "build/stage/live-generations" / ("chain-" + str(self.new_id) + "-dex-" + self.dex_id[2:18])
        destination.mkdir(parents=True)
        with self.assertRaises(ValueError):
            self.make()

    def test_candidate_genesis_identity_checked_but_never_authorizes_execution(self):
        candidate = copy.deepcopy(self.old)
        candidate["config"]["chainId"] = self.new_id
        candidate["config"]["dexDevnet"] = {"dexId": self.dex_id, "committee": [{} for _ in range(7)]}
        path = self.root / "candidate.json"
        path.write_text(json.dumps(candidate))
        result = self.make(new_genesis=path)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("full Go", result["new_generation"]["genesis_validation"])
        self.assertFalse(result["reset_authorized"])
        candidate["config"]["chainId"] += 1
        path.write_text(json.dumps(candidate))
        with self.assertRaises(ValueError):
            self.make(new_genesis=path)
        with self.assertRaises(ValueError):
            self.make(new_genesis=self.root / "genesis.json")

    def test_stopped_added_commons_require_explicit_mode_and_preserve_unknown_genesis(self):
        self.add_stopped_commons()
        with self.assertRaises(ValueError):
            self.make(include_added_commons=True)
        with self.assertRaises(ValueError):
            self.make(allow_stopped_added_commons=True)
        result = self.make(include_added_commons=True, allow_stopped_added_commons=True)
        self.assertEqual(len(result["targets"]), 14)
        self.assertTrue(result["allow_stopped_added_commons"])
        self.assertEqual(result["old_generation"]["genesis_hash"], "0x" + "11" * 32)
        for node in result["targets"][8:]:
            self.assertEqual(node["observed_status"], "stopped")
            self.assertEqual(node["observed_pid"], 0)
            self.assertIsNone(node["observed_start_ticks"])
            self.assertIsNone(node["observed_exe_sha256"])
            self.assertEqual(node["old_db_genesis_status"], "NOT_OBSERVED_STOPPED")
        self.assertNotIn("SECRET-", json.dumps(result))

    def test_stopped_mode_rejects_foreign_processes_errored_state_and_core_nodes(self):
        self.add_stopped_commons()
        mutations = [lambda a: a[8].update(pid=99),
                     lambda a: a[8].update(processes=[{"pid": 99}]),
                     lambda a: a[8]["pm2"].update(status="errored"),
                     lambda a: a[8]["pm2"].update(status="online"),
                     lambda a: a[0].update(pid=0, pm2={"status": "stopped"}, processes=[]),
                     lambda a: a[7].update(pid=0, pm2={"status": "stopped"}, processes=[])]
        for mutate in mutations:
            obs = copy.deepcopy(self.observation); mutate(obs["apps"])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.make(observation=obs, include_added_commons=True, allow_stopped_added_commons=True)

    def test_online_pm2_executable_and_pid_are_bound(self):
        for mutate in (lambda a: a.update(pid=999), lambda a: a["pm2"].update(status="errored"),
                       lambda a: a["processes"][0].update(exe_sha256="invalid")):
            obs = copy.deepcopy(self.observation); mutate(obs["apps"][0])
            with self.assertRaises(ValueError): self.make(observation=obs)


if __name__ == "__main__":
    unittest.main()
