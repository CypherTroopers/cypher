#!/usr/bin/env python3
import tempfile
import json
from pathlib import Path
import unittest

import live_observe
import live_start


class LiveToolsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "genesis.json").write_text(json.dumps({"config": {
            "chainId": 10101919, "fixedCommittee": True, "fixedLeader": False,
            "committee": {str(i): {"address": "127.0.0.1:" + str(7100 + 2*i),
                                  "coinbase": format(i + 1, "040x")}
                          for i in range(7)}}}))

    def test_secret_arguments_not_observed(self):
        value = live_observe.safe_args(["cypher", "--password", "secret-file",
            "--private-key=secret", "--datadir", "/owned/db", "--http.port=8999",
            "--unknown", "secret2", "--dex.validator", "--unlock", "private-info"])
        self.assertEqual(value, {"--datadir": "/owned/db", "--http.port": "8999", "--dex.validator": True})

    def test_explicit_existing_roles_have_unique_paths_and_ports(self):
        # No role file in this fixture means OFF, independently of the running
        # network. The explicit ON/domain binding has its own role tests.
        root = self.root
        self.assertFalse((root / "build/stage/live-deployment.json").exists())
        commands = [live_start.command(root, name) for name in live_start.APPS]
        for flag in ("--datadir", "--port", "--rnetport"):
            self.assertEqual(len({c[c.index(flag) + 1] for c in commands}), 8)
        for c in commands:
            self.assertNotIn("--mine", c)
            self.assertNotIn("--dex.validator", c)
            self.assertNotIn("--password", c)
            self.assertTrue(Path(c[0]).is_absolute())
        common = commands[-1]
        self.assertEqual(common[common.index("--http.addr") + 1], "127.0.0.1")
        self.assertEqual(common[common.index("--ws.addr") + 1], "127.0.0.1")
        with self.assertRaises(ValueError):
            live_start.command(root, "all")

    def test_unknown_committee_layout_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "genesis.json").write_text(json.dumps({"config": {
                "committee": {}, "fixedCommittee": True, "fixedLeader": False}}))
            with self.assertRaises(ValueError):
                live_start.command(root, "cypher0")


if __name__ == "__main__":
    unittest.main()
