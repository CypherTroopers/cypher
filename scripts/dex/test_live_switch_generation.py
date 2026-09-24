import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from live_switch_generation import Switch, TARGETS, APPS, ADDED_COMMONS, HOST, sha


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))
    path.chmod(0o600)


class FakeHost:
    def __init__(self, apps):
        self.values = apps
        self.calls = []
        self.busy = False
        self.init_calls = []

    def apps(self): return self.values
    def boot(self): return "00000000-0000-0000-0000-000000000000"
    def pid_ticks(self): return {a["pid"]: a["pid"] * 10 for a in self.values if a["pid"]}
    def exe_hash(self, pid): return "1" * 64
    def writers(self, paths): return self.busy

    def pm2(self, *args):
        self.calls.append(args)
        config = json.loads(Path(args[1]).read_text())
        for setting in config["apps"]:
            a = next(a for a in self.values if a["name"] == setting["name"])
            a["pid"] = 0 if setting.get("autorestart") is False else 5000 + len(self.calls)
            a["pm2_env"]["status"] = "stopped" if not a["pid"] else "online"

    def initialize(self, binary, datadir, genesis, log):
        self.init_calls.append(str(datadir))
        (datadir / "cypher" / "new-test-db").write_text("new generation only")
        log.write_text("unit fake normal init, not an actual process")


class SwitchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.now = time.time()
        write(self.repo / "genesis.json", {"config": {"chainId": 10101919}})
        for binary in ("cypher", "cypher-linux-amd64"):
            p = self.repo / "build/bin" / binary
            p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(b"old public binary")
        release = self.repo / "build/stage/live-q3-release/bin/cypher-linux-amd64"
        release.parent.mkdir(parents=True); release.write_bytes(b"new public binary")
        candidate = self.repo / "build/stage/candidate/genesis.json"
        dex = "0x" + "12" * 32
        write(candidate, {"config": {"chainId": 10101920, "dexDevnet": {"dexId": dex}}})
        inv = candidate.parent / "inventory.json"
        write(inv, {"GenesisSHA256": sha(candidate), "ChainID": 10101920, "DEXID": dex, "AllocPreserved": True, "CLXCommitteePreserved": True})
        label = "chain-10101920-dex-1212121212121212"
        archive = self.repo / "build/stage/live-generations" / label
        nodes, apps, configs = [], [], []
        for index, name in enumerate(TARGETS):
            if name in ADDED_COMMONS:
                num = name.removeprefix("cypherdex")
                datadir = self.repo / "build/stage/live-commons" / ("chaindbdex" + num)
                script = self.repo / "build/stage/live-commons" / ("common" + num) / "start.sh"
            else:
                datadir = self.repo / ("chaindbmine" if name == "cyphermine" else "chaindb" + name.removeprefix("cypher"))
                script = self.repo / ("start-" + name + ".sh")
            (datadir / "keystore").mkdir(parents=True)
            (datadir / "keystore" / "private-test-key").write_text("unit private test material")
            (datadir / "cypher").mkdir()
            (datadir / "cypher/nodekey").write_text("unit node key")
            (datadir / "cypher/old-vote-wal").write_text("must remain in archive")
            script.parent.mkdir(parents=True, exist_ok=True); script.write_text("#!/bin/sh\nexit 0\n")
            node_stat = datadir.stat(); pid = 1000 + index
            nodes.append({"pm2_name": name, "observed_pid": pid, "observed_start_ticks": pid * 10, "old_datadir": str(datadir), "archive_datadir": str(archive / datadir.name), "datadir_device": node_stat.st_dev, "datadir_inode": node_stat.st_ino})
            env = {"pm_cwd": str(self.repo), "pm_exec_path": str(script), "status": "online"}
            apps.append({"name": name, "pid": pid, "pm2_env": env})
            configs.append({"name": name, "script": str(script), "cwd": str(self.repo), "autorestart": True})
        config = self.repo / "ecosystem.json"; write(config, {"apps": configs})
        self.plan = {"version": 1, "host": HOST, "workspace": str(self.repo), "observed_boot_id": "00000000-0000-0000-0000-000000000000", "observation_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.now)), "generation_label": label, "targets": nodes, "old_generation": {"chain_id": 10101919, "genesis_file_sha256": sha(self.repo / "genesis.json")}, "new_generation": {"chain_id": 10101920, "dex_deployment_id": dex, "genesis_file": str(candidate), "genesis_sha256": sha(candidate)}, "execution": {"release_file": str(release), "release_sha256": sha(release), "old_running_exe_sha256": "1" * 64, "candidate_inventory_file": str(inv), "candidate_inventory_sha256": sha(inv), "validation_status": "PASS(UNIT)", "validation_source_manifest": "unit fixture, never live authorization", "ecosystem_files": [{"path": str(config), "sha256": sha(config)}]}}
        self.plan_path = self.repo / "plan.json"; write(self.plan_path, self.plan)
        self.plan["execution"]["launcher_files"] = [{"path": a["pm2_env"]["pm_exec_path"], "sha256": sha(Path(a["pm2_env"]["pm_exec_path"]))} for a in apps]
        sources = [Path(e["path"]) for e in self.plan["execution"]["launcher_files"]] + [config, candidate, inv]
        for name in ("live_start.py", "live_common.py", "live_roles.py", "live_auth.py", "live_switch_generation.py"):
            f = self.repo / "scripts/dex" / name; f.parent.mkdir(parents=True, exist_ok=True); f.write_text("# unit source\n"); sources.append(f)
        manifest = self.repo / "source.sha256"
        manifest.write_text("".join(sha(f) + "  " + str(f.relative_to(self.repo)) + "\n" for f in sources))
        self.plan["execution"]["validation_source_manifest"] = {"path": str(manifest), "sha256": sha(manifest)}
        write(self.plan_path, self.plan)
        self.approval = self.repo / "approval.json"
        self.authorize()
        self.host = FakeHost(apps)

    def authorize(self):
        write(self.approval, {"version": 1, "approved": True, "operation": "intermediate-generation-reset", "plan_sha256": sha(self.plan_path), "user_instruction_reference": "UNIT FAKE; never live approval", "approved_unix": self.now - 1, "expires_unix": self.now + 3600})

    def switch(self): return Switch(self.repo, self.plan_path, self.host, self.now)

    def stop_added_in_plan(self):
        self.plan["allow_stopped_added_commons"] = True
        for n in self.plan["targets"]:
            if n["pm2_name"] in ADDED_COMMONS:
                n.update(observed_status="stopped", observed_pid=0, observed_start_ticks=None,
                         observed_exe_sha256=None, old_db_genesis_status="NOT_OBSERVED_STOPPED")
        for a in self.host.values:
            if a["name"] in ADDED_COMMONS:
                a["pid"] = 0; a["pm2_env"]["status"] = "stopped"
        write(self.plan_path, self.plan); self.authorize()

    def test_preflight_readonly_and_missing_consent(self):
        s = self.switch()
        before = sorted(str(p) for p in self.repo.rglob("*"))
        self.assertEqual(s.preflight()["status"], "READY_FOR_SEPARATE_USER_APPROVAL")
        self.assertEqual(before, sorted(str(p) for p in self.repo.rglob("*")))
        write(self.approval, {"approved": False})
        with self.assertRaises(ValueError): s.invoke("stop", self.approval)
        self.assertFalse(self.host.calls)

    def test_explicit_preserved_chain_keeps_authentication_and_requires_consent(self):
        candidate = Path(self.plan["new_generation"]["genesis_file"])
        data = json.loads(candidate.read_text())
        data["config"]["chainId"] = 10101919
        write(candidate, data)
        inventory = Path(self.plan["execution"]["candidate_inventory_file"])
        inv = json.loads(inventory.read_text())
        inv.update(ChainID=10101919, GenesisSHA256=sha(candidate))
        write(inventory, inv)
        self.plan["new_generation"].update(chain_id=10101919, genesis_sha256=sha(candidate))
        self.plan["execution"]["candidate_inventory_sha256"] = sha(inventory)
        source = Path(self.plan["execution"]["validation_source_manifest"]["path"])
        entries = [line.split(None, 1)[1] for line in source.read_text().splitlines()]
        source.write_text("".join(sha(self.repo / name) + "  " + name + "\n" for name in entries))
        self.plan["execution"]["validation_source_manifest"]["sha256"] = sha(source)
        write(self.plan_path, self.plan)
        with self.assertRaisesRegex(ValueError, "generation identity"):
            self.switch().preflight()
        self.plan["chain_id_preserved"] = True
        write(self.plan_path, self.plan)
        self.assertEqual(self.switch().preflight()["status"], "READY_FOR_SEPARATE_USER_APPROVAL")
        # An old consent bound to another plan never authorizes this one.
        with self.assertRaisesRegex(ValueError, "approval"):
            self.switch().invoke("stop", self.approval)
        self.assertFalse(self.host.calls)

    def test_four_phases_keep_keys_and_never_copy_wal(self):
        for phase in ("stop", "archive", "init", "start"):
            s = self.switch()
            with patch("live_switch_generation.shutil.disk_usage") as disk:
                disk.return_value.free = 20 * 1024**3
                s.invoke(phase, self.approval)
        self.assertEqual(len(self.host.init_calls), 14)
        for n in self.plan["targets"]:
            old, new = Path(n["archive_datadir"]), Path(n["old_datadir"])
            self.assertTrue((old / "cypher/old-vote-wal").exists())
            self.assertFalse((new / "cypher/old-vote-wal").exists())
            self.assertEqual((old / "keystore/private-test-key").read_bytes(), (new / "keystore/private-test-key").read_bytes())
        with self.assertRaisesRegex(ValueError, "already have signed"):
            self.switch().invoke("archive", self.approval)
        with self.assertRaisesRegex(ValueError, "already have signed"):
            self.switch().invoke("start", self.approval)

    def test_partial_archive_resume_by_original_inode(self):
        s = self.switch(); s.invoke("stop", self.approval)
        first = self.plan["targets"][0]
        Path(first["old_datadir"]).rename(first["archive_datadir"])
        # Simulate process death after rename, before its journal event.
        self.switch().invoke("archive", self.approval)
        self.assertEqual(len(self.switch().state["archived"]), 14)

    def test_stale_foreign_hash_and_writer_refusal(self):
        self.plan["observation_utc"] = "2020-01-01T00:00:00Z"; write(self.plan_path, self.plan)
        with self.assertRaises(ValueError): self.switch().preflight()
        self.plan["host"] = "other-host"; write(self.plan_path, self.plan)
        with self.assertRaises(ValueError): self.switch()
        self.plan["host"] = HOST; self.plan["observation_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.now)); self.plan["review_revision"] = 2; write(self.plan_path, self.plan)
        with self.assertRaisesRegex(ValueError, "approval"):
            self.switch().invoke("stop", self.approval)
        self.authorize(); s = self.switch(); s.invoke("stop", self.approval)
        self.host.busy = True
        with self.assertRaisesRegex(ValueError, "still live"):
            self.switch().invoke("archive", self.approval)

    def test_symlink_secret_and_datadir_refused(self):
        n = self.plan["targets"][0]; datadir = Path(n["old_datadir"])
        hidden = datadir.with_name("hidden-test-data"); datadir.rename(hidden); datadir.symlink_to(hidden)
        with self.assertRaises(ValueError): self.switch().preflight()

    def test_approval_expiry_and_other_apps_untouched(self):
        self.host.values.append({"name": "foreign-service", "pid": 9999, "pm2_env": {"status": "online"}})
        a = json.loads(self.approval.read_text()); a["expires_unix"] = self.now - 1; write(self.approval, a)
        with self.assertRaises(ValueError): self.switch().invoke("stop", self.approval)
        self.authorize(); self.switch().invoke("stop", self.approval)
        self.assertEqual(self.host.values[-1]["pid"], 9999)
        self.assertEqual(self.host.values[-1]["pm2_env"]["status"], "online")

    def test_private_key_symlink_and_changed_launcher_refused(self):
        script = Path(self.host.values[0]["pm2_env"]["pm_exec_path"])
        original = script.read_bytes(); script.write_bytes(original + b"# unexpected edit\n")
        with self.assertRaisesRegex(ValueError, "launcher content"):
            self.switch().preflight()
        script.write_bytes(original)
        self.switch().invoke("stop", self.approval); self.switch().invoke("archive", self.approval)
        source = Path(self.plan["targets"][0]["archive_datadir"]) / "keystore/private-test-key"
        outside = self.repo / "outside-wallet"; outside.write_text("do not copy")
        source.unlink(); source.symlink_to(outside)
        with patch("live_switch_generation.shutil.disk_usage") as disk:
            disk.return_value.free = 20 * 1024**3
            with self.assertRaises(ValueError): self.switch().invoke("init", self.approval)
        self.assertFalse(self.host.init_calls)

    def test_partial_init_retries_without_old_wal_or_rollback(self):
        self.switch().invoke("stop", self.approval); self.switch().invoke("archive", self.approval)
        normal = self.host.initialize
        def once(binary, datadir, genesis, log):
            normal(binary, datadir, genesis, log)
            self.host.initialize = normal
            raise ValueError("unit selected failure after init before journal")
        self.host.initialize = once
        with patch("live_switch_generation.shutil.disk_usage") as disk:
            disk.return_value.free = 20 * 1024**3
            with self.assertRaises(ValueError): self.switch().invoke("init", self.approval)
            self.switch().invoke("init", self.approval)
        self.assertEqual(len(self.host.init_calls), 15)
        self.assertEqual(len(self.switch().state["initialized"]), 14)
        self.assertFalse(self.switch().state["signing_may_have_started"])

    def test_explicit_stopped_six_preflight_then_preserves_stop_and_archives_fourteen(self):
        self.stop_added_in_plan()
        self.assertEqual(self.switch().preflight()["status"], "READY_FOR_SEPARATE_USER_APPROVAL")
        self.assertEqual(self.host.calls, [])
        self.switch().invoke("stop", self.approval)
        maintenance = json.loads(Path(self.host.calls[0][1]).read_text())
        self.assertEqual({a["name"] for a in maintenance["apps"]}, set(APPS))
        self.assertTrue(all(a["pid"] == 0 for a in self.host.values))
        self.switch().invoke("archive", self.approval)
        self.assertEqual(len(self.switch().state["archived"]), 14)
        for n in self.plan["targets"]:
            self.assertTrue((Path(n["archive_datadir"]) / "cypher/old-vote-wal").exists())

    def test_stopped_common_mode_rejects_writer_pid_status_inode_and_unapproved_scope(self):
        self.stop_added_in_plan()
        self.host.busy = True
        with self.assertRaisesRegex(ValueError, "writer still live"): self.switch().preflight()
        self.host.busy = False
        added = next(a for a in self.host.values if a["name"] == ADDED_COMMONS[0])
        added["pid"] = 4000
        with self.assertRaisesRegex(ValueError, "stopped Common changed"): self.switch().preflight()
        added["pid"] = 0; added["pm2_env"]["status"] = "errored"
        with self.assertRaisesRegex(ValueError, "stopped Common changed"): self.switch().preflight()
        added["pm2_env"]["status"] = "stopped"
        self.plan["allow_stopped_added_commons"] = False; write(self.plan_path, self.plan)
        with self.assertRaisesRegex(ValueError, "stopped added-Common identity"): self.switch()
        self.plan["allow_stopped_added_commons"] = True
        n = self.plan["targets"][0]
        n.update(observed_status="stopped", observed_pid=0, observed_start_ticks=None,
                 observed_exe_sha256=None, old_db_genesis_status="NOT_OBSERVED_STOPPED")
        write(self.plan_path, self.plan)
        with self.assertRaisesRegex(ValueError, "stopped added-Common identity"): self.switch()

    def test_stopped_mode_keeps_active_ticks_executable_and_datadir_guards(self):
        self.stop_added_in_plan()
        original = self.host.exe_hash; self.host.exe_hash = lambda pid: "2" * 64
        with self.assertRaisesRegex(ValueError, "executable changed"): self.switch().preflight()
        self.host.exe_hash = original
        self.host.values[0]["pid"] += 1
        with self.assertRaisesRegex(ValueError, "process identity changed"): self.switch().preflight()
        self.host.values[0]["pid"] -= 1
        n = self.plan["targets"][8]; path = Path(n["old_datadir"])
        path.rename(path.with_name("unit-original-stopped-dir")); path.mkdir()
        with self.assertRaisesRegex(ValueError, "datadir identity changed"): self.switch().preflight()


if __name__ == "__main__": unittest.main()
