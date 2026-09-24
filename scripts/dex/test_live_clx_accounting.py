import copy
import unittest

from live_clx_accounting import model


class IntervalAccounting(unittest.TestCase):
    def setUp(self):
        self.run = {"start": {"number": "0xa", "hash": "parent"},
                    "end": {"number": "0xb", "hash": "block", "stateRoot": "root"},
                    "gas_price": 2, "transactions": [{"hash": "tx", "value": "1"}],
                    "receipts": {"tx": {"from": "Sender", "to": "Coinbase", "status": "0x1",
                        "commonTxApprover": "Sender", "commonTxRewardRecipient": "Reward",
                        "gasUsed": 10, "commonTxApproverReward": 4, "commonTxBurn": 16}}}
        self.blocks = [{"number": 11, "parent_hash": "parent", "actual_hash": "block",
                        "state_root": "root", "transaction_hashes": ["tx"],
                        "issuance_by_recipient": [{"recipient": "Coinbase", "atoms": "100000000000000000000000"}],
                        "issuance_total_atoms": "100000000000000000000000"}]

    def test_static_issuance_is_distinct_from_rpc_reward_and_gas(self):
        result = model(self.run, self.blocks)
        self.assertEqual(result["expected_delta_atoms"], {"sender": "-21", "reward": "4",
                         "coinbase": "100000000000000000000001"})
        self.assertEqual(sum(map(int, result["expected_delta_atoms"].values())), 10**23 - 16)

    def test_unrelated_workload_is_not_silently_ignored(self):
        self.blocks[0]["transaction_hashes"].append("unrelated")
        with self.assertRaisesRegex(ValueError, "unrelated"):
            model(self.run, self.blocks)

    def test_missing_receipt_and_fork_are_rejected(self):
        for change in ("receipt", "parent", "root", "number", "gas"):
            with self.subTest(change=change):
                run, blocks = copy.deepcopy(self.run), copy.deepcopy(self.blocks)
                if change == "receipt":
                    run["receipts"] = {}
                elif change == "gas":
                    run["receipts"]["tx"]["commonTxBurn"] = 15
                else:
                    blocks[0][{"parent": "parent_hash", "root": "state_root", "number": "number"}[change]] = "wrong"
                with self.assertRaises(ValueError):
                    model(run, blocks)


if __name__ == "__main__":
    unittest.main()
