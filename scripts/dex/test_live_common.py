import json
from pathlib import Path
import tempfile
import unittest

from live_common import command, prepare


class AdditionalCommon(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "genesis.json").write_text(json.dumps({"config": {
            "chainId": 10101919, "fixedCommittee": True, "fixedLeader": False,
            "committee": {str(i): {"address": "127.0.0.1:" + str(7100 + 2*i),
                                  "coinbase": format(i + 1, "040x")}
                          for i in range(7)}}}))

    def test_private_distinct_listeners_and_no_optional_work_by_default(self):
        # Exercise real default-OFF lookup without reading the host's active
        # live-deployment selection. Activation is tested in test_live_roles.
        root = self.root
        self.assertFalse((root / "build/stage/live-deployment.json").exists())
        commands = [command(root, i, "0x" + format(i, "040x")) for i in range(1, 7)]
        for flag in ("--datadir", "--rnetport", "--miner.etherbase"):
            self.assertEqual(len({c[c.index(flag)+1] for c in commands}), 6)
        for c in commands:
            for flag in ("--port", "--mine", "--http", "--ws", "--dex.validator", "--unlock"):
                self.assertNotIn(flag, c)
            self.assertEqual(c[c.index("--nat")+1], "extip:127.0.0.1")

    def test_prepare_is_fresh_only_and_does_not_initialize_data(self):
        actual = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for filename in ("genesis.json", "static-nodes.toml"):
                (root / filename).write_bytes((actual / filename).read_bytes())
            p = prepare(root, 1, "0x" + "1" * 40)
            self.assertFalse(p["initialized"])
            self.assertTrue(all("@127.0.0.1:" in peer for peer in p["static_peers"]))
            self.assertFalse((root / "build/stage/live-commons/chaindbdex1").exists())
            with self.assertRaises(FileExistsError):
                prepare(root, 1, "0x" + "1" * 40)

    def test_unlisted_indices_and_unowned_zero_identity_rejected(self):
        root = self.root
        for index in (0, 7, -1):
            with self.assertRaises(ValueError):
                command(root, index, "0x" + "1" * 40)
        with self.assertRaises(ValueError):
            command(root, 1, "0x" + "0" * 40)


if __name__ == "__main__":
    unittest.main()
