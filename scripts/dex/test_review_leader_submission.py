import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import review_leader_submission as review


class ReviewArchiveBoundaryTest(unittest.TestCase):
    def test_untracked_source_included_but_runtime_keys_and_secret_scripts_excluded(self):
        names=["dex/new_untracked.go","dex/testdata/golden.json","docs/dex/leader-submission-spec.md",
               "dex/runtime/WAL/private.json","dex/keys/vote.key","dex/keystore/password.json",
               "build/stage/current/keys/payer.key","build/bin/cypher","unlock.sh","start-mining.sh",
               "scripts/unlock.sh","docs/dex/results/old.log"]
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for name in names:
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text("test fixture only")
            with patch.object(review,"REPO",root),patch.object(review.subprocess,"check_output",return_value=("\0".join(names)+"\0").encode()):
                result=review.source_paths()
            self.assertEqual(result,["dex/new_untracked.go","dex/testdata/golden.json","docs/dex/leader-submission-spec.md"])

    def test_configuration_redaction_preserves_public_identity(self):
        item={"Domain":{"ChainID":10101919},"VoteKeyFile":"private-path", "Payers":[{"Address":"public-address","KeyFile":"local-secret-file"}]}
        out=review.redact(item)
        self.assertEqual(out["Domain"],item["Domain"])
        self.assertEqual(out["Payers"][0]["Address"],"public-address")
        self.assertEqual(out["Payers"][0]["KeyFile"],"<private field omitted>")
        self.assertNotIn("private-path",json.dumps(out))
        self.assertEqual(item["VoteKeyFile"],"private-path")

    def test_raw_log_secret_markers_require_private_review(self):
        for raw in (b'-----BEGIN EC PRIVATE KEY-----',b'{"password":"not-for-publishing"}'):
            self.assertIsNotNone(review.SECRET_MARKER.search(raw))
        self.assertIsNone(review.SECRET_MARKER.search(b'{"test":"PASS","public_key":"public-value"}'))
