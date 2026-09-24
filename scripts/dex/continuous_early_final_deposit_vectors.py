#!/usr/bin/env python3
"""Independent extended10-early-final-deposit input timing variant.

No Go output is read and no other golden file is modified. This is an arithmetic
check, not authentication, finality, matching, or native-transfer evidence.
Validator names denote ascending recipient order, not actual fixture keys.
"""

import argparse
from fractions import Fraction
import json
from pathlib import Path

from reference_model import ATOMS, QUANTITY_SCALE, charge, equity_conservation, funding, pnl, reward


def atoms(value):
    value = Fraction(value) * ATOMS
    assert value.denominator == 1
    return value.numerator


def calculate():
    accounts = {name: {"cash": 100 * ATOMS, "quantity": 0, "entry": 100 * ATOMS}
                for name in ("alice", "bob")}
    buckets = {"U": 0, "F": 0, "S": 20 * ATOMS, "I": 5 * ATOMS,
               "Z": 0, "W": 0, "R": 0}
    custody = inputs = 225 * ATOMS
    withdrawal_paid = reward_paid = 0
    withdrawal_claims = reward_claims = 0
    fees = {period: 0 for period in range(1, 11)}
    closes = {18: 1, 34: 2, 38: 3, 54: 4, 58: 5, 74: 6, 78: 7, 94: 8, 98: 9, 108: 10}
    mark = 100 * ATOMS
    trace, periods = [], []
    recipient_totals = {f"v{i}": 0 for i in range(7)}

    def check(height, event):
        equity_conservation(mark, accounts, custody, sum(buckets.values()))
        assert custody + withdrawal_paid + reward_paid == inputs
        assert all(value >= 0 for value in buckets.values())
        trader_cash = sum(account["cash"] for account in accounts.values())
        unrealized = {name: pnl(account["entry"], mark, account["quantity"])
                      for name, account in accounts.items()}
        trace.append({"height": height, "event": event, "custody": custody,
                      "inputs": inputs, "withdrawal_paid": withdrawal_paid, "reward_paid": reward_paid,
                      "withdrawal_claims": withdrawal_claims, "reward_claims": reward_claims,
                      "mark": mark, "accounts": {key: account["cash"] for key, account in accounts.items()},
                      "positions": {key: dict(account) for key, account in accounts.items()},
                      "unrealized_pnl": unrealized,
                      "equity": {key: account["cash"] + unrealized[key] for key, account in accounts.items()},
                      "fees_by_period": {str(period): value for period, value in fees.items()}, "buckets": {**buckets, "T": trader_cash}})

    check(0, "authenticated_initial_funding_assumed")
    for height in range(1, 111):
        offset = (height - 1) % 20 + 1
        trading = 1 <= height <= 40 or 61 <= height <= 100
        if 41 <= height <= 60:
            assert all(account["quantity"] == 0 for account in accounts.values())
        if height == 59:
            mark = 100 * ATOMS
            check(height, "flat_interval_oracle")
        if height in (21, 41, 61):
            for account in accounts.values():
                account["cash"] += 20 * ATOMS
            custody += 40 * ATOMS
            inputs += 40 * ATOMS
            check(height, "two_native_deposits_assumed")
        if trading and offset in (7, 11):
            mark = (100 if offset == 7 else 110) * ATOMS
            check(height, "oracle")
        if trading and offset in (9, 13):
            opening = offset == 9
            rates = {"alice": 300 if opening else 100, "bob": 100 if opening else 300}
            collected = 0
            for name, account in accounts.items():
                fee = charge(mark, QUANTITY_SCALE, rates[name])
                collected += fee
                account["cash"] -= fee
                if opening:
                    account["entry"] = mark
                    account["quantity"] = QUANTITY_SCALE if name == "alice" else -QUANTITY_SCALE
                else:
                    account["cash"] += pnl(account["entry"], mark, account["quantity"])
                    account["quantity"] = 0
            fees[(height - 1) // 10 + 1] += collected
            buckets["F"] += collected
            check(height, "open_fill" if opening else "close_fill")
        if trading and offset == 10:
            result = funding(mark, {name: account["quantity"] for name, account in accounts.items()}, 100)
            for name, delta in result["cash_deltas"].items():
                accounts[name]["cash"] += delta
            buckets["Z"] += result["dust"]
            check(height, "funding")
        if height in (14, 37, 77, 97):
            accounts["alice"]["cash"] -= 10 * ATOMS
            buckets["W"] += 10 * ATOMS
            check(height, "withdrawal_reserved")
            if height != 14:
                buckets["W"] -= 10 * ATOMS
                custody -= 10 * ATOMS
                withdrawal_paid += 10 * ATOMS
                withdrawal_claims += 1
                check(height, "native_withdrawal_assumed")
        if height in closes:
            period = closes[height]
            count = 6 if period <= 2 else 7
            result = reward(fees[period], buckets["S"], ATOMS, ATOMS,
                            {f"v{i}": 1 for i in range(count)})
            assert result["budget"] == ATOMS
            buckets["F"] -= result["from_fees"]
            buckets["S"] = result["support_remaining"]
            buckets["R"] += result["budget"]
            check(height, "reward_reserved")
            for name, value in result["allocations"].items():
                recipient_totals[name] += value
            buckets["R"] -= result["budget"]
            custody -= result["budget"]
            reward_paid += result["budget"]
            reward_claims += sum(value > 0 for value in result["allocations"].values())
            periods.append({"period": period, "height": height, "participants": count,
                            "collected_fees": fees[period], **result})
            check(height, "native_reward_claims_assumed")
        if height == 109:
            buckets["W"] -= 10 * ATOMS
            custody -= 10 * ATOMS
            withdrawal_paid += 10 * ATOMS
            withdrawal_claims += 1
            check(height, "original_period1_withdrawal_paid_assumed")
        check(height, "height_boundary")

    # These expectations were fixed in the G3 design, not generated from Go or
    # overwritten by this calculation. Assert all eight custody buckets and the
    # two trader balances, not merely the final total.
    expected = {"U": "0", "T": "279.664", "F": "0.168", "S": "10.168",
                "I": "5", "Z": "0", "W": "0", "R": "0"}
    actual = {**buckets, "T": sum(account["cash"] for account in accounts.values())}
    assert actual == {name: atoms(value) for name, value in expected.items()}
    assert accounts["alice"]["cash"] == atoms("159.796")
    assert accounts["bob"]["cash"] == atoms("119.868")
    assert inputs == atoms("345") and custody == atoms("295")
    assert withdrawal_paid == atoms("40") and reward_paid == atoms("10")
    assert sum(fees.values()) == atoms("0.336")
    assert [fees[p] for p in range(1, 11)] == [atoms(x) for x in
            (".040", ".044", ".040", ".044", "0", "0", ".040", ".044", ".040", ".044")]
    assert withdrawal_claims == 4 and reward_claims == 68
    assert sum(recipient_totals.values()) == reward_paid
    assert all(not account["quantity"] for account in accounts.values())
    return {"version": 1, "fixture": "extended10-early-final-deposit",
            "additional_deposit_heights": [21, 41, 61],
            "claim_count": withdrawal_claims + reward_claims,
            "withdrawal_claim_count": withdrawal_claims, "reward_claim_count": reward_claims,
            "scope": "independent arithmetic only; authentication and transfers assumed",
            "inputs": inputs, "custody": custody, "withdrawal_paid": withdrawal_paid,
            "reward_paid": reward_paid, "buckets": actual,
            "accounts": {name: account["cash"] for name, account in accounts.items()},
            "reward_recipient_rank_totals": recipient_totals, "reward_periods": periods, "trace": trace}



def compare_original(result):
    """Check all111 boundaries against the preserved input timing variant."""
    root = Path(__file__).resolve().parents[2]
    old = json.loads((root / "dex/testdata/continuous-extended10.json").read_text())
    same = ("accounts", "buckets", "claim_count", "custody", "inputs",
            "reward_claim_count", "reward_paid", "reward_periods",
            "reward_recipient_rank_totals", "withdrawal_claim_count", "withdrawal_paid")
    for key in same:
        assert result[key] == old[key], key
    boundaries = [result["trace"][0]] + [r for r in result["trace"] if r["event"] == "height_boundary"]
    assert len(boundaries) == 111
    for row in boundaries:
        h = row["height"]
        prior = [r for r in old["trace"] if r["height"] <= h][-1]
        delta = 40 * ATOMS if 61 <= h < 81 else 0
        assert row["custody"] == prior["custody"] + delta, (h, "custody")
        for who in ("alice", "bob"):
            assert row["accounts"][who] == prior["accounts"][who] + delta // 2, (h, who)
        for bucket, value in prior["buckets"].items():
            assert row["buckets"][bucket] == value, (h, bucket)
        assert row["buckets"]["T"] == sum(row["accounts"].values())
        assert sum(row["buckets"].values()) == row["custody"]
        assert row["custody"] + row["reward_paid"] + row["withdrawal_paid"] == row["inputs"]
        assert sum(row["unrealized_pnl"].values()) == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="assert the fixed G3 expectations and print a concise result")
    args = parser.parse_args()
    result = calculate()
    if args.check:
        golden = Path(__file__).resolve().parents[2] / "dex/testdata/continuous-extended10-early-final-deposit.json"
        assert json.loads(golden.read_text()) == result, "extended10-early-final-deposit golden differs"
        compare_original(result)
        print("PASS: extended10-early-final-deposit (21/41/61), four trade cycles plus flat catch-up interval, "
              "inputs345 - withdrawals40 - rewards10 = custody295; "
              "T279.664 F0.168 S10.168 I5 Z0; Alice159.796 Bob119.868 CLX; "
              "68 reward + 4 withdrawal = 72 claims; golden exact")
    else:
        print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
