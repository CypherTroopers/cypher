#!/usr/bin/env python3
"""Independent integer accounting reference; no crypto, node, or FHS simulation.

The expected values are checked in separately and are never regenerated here.
Run: python3 scripts/dex/reference_model.py --check
"""

import argparse
from fractions import Fraction
import json
from pathlib import Path
import sys

ATOMS = 10**18
QUANTITY_SCALE = 10**8
QUANTITY_LOT = 10**5
PRICE_TICK = 10**3
PPM = 10**6
MAX_MAGNITUDE = 2**128 - 1
MAX_ACCOUNTS = 1024
MAX_VALIDATORS = 7


class Rejected(ValueError):
    pass


def integer(value):
    if isinstance(value, bool):
        raise Rejected("INTEGER")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        canonical = value == "0" or (value.isascii() and value.isdigit()
                                    and not value.startswith("0"))
        canonical = canonical or (value.startswith("-") and len(value) > 1
                                  and value[1:].isascii() and value[1:].isdigit()
                                  and not value[1:].startswith("0"))
        if canonical:
            return int(value)
    raise Rejected("INTEGER")


def bounded(value, signed=False):
    n = integer(value)
    if abs(n) > MAX_MAGNITUDE or (not signed and n < 0):
        raise Rejected("RANGE")
    return n


def ceil_fraction(value):
    return -(-value.numerator // value.denominator)


def floor_fraction(value):
    return value.numerator // value.denominator


def price(value):
    p = bounded(value)
    if not p or p % PRICE_TICK:
        raise Rejected("PRICE_TICK")
    return p


def quantity(value):
    q = bounded(value, signed=True)
    if q % QUANTITY_LOT:
        raise Rejected("QUANTITY_LOT")
    return q


def rate(value):
    r = integer(value)
    if not 0 <= r <= PPM:
        raise Rejected("RATE")
    return r


def notional(p, q):
    n = Fraction(price(p) * abs(quantity(q)), QUANTITY_SCALE)
    if n.denominator != 1:
        raise Rejected("NONINTEGRAL_NOTIONAL")
    return bounded(n.numerator)


def charge(p, q, r):
    return bounded(ceil_fraction(Fraction(notional(p, q) * rate(r), PPM)))


def pnl(entry, exit_price, q):
    result = Fraction(quantity(q) * (price(exit_price) - price(entry)), QUANTITY_SCALE)
    if result.denominator != 1:
        raise Rejected("NONINTEGRAL_PNL")
    return bounded(result.numerator, signed=True)


def funding(p, positions, rate_ppm):
    mark = price(p)
    r = integer(rate_ppm)
    if abs(r) > 10000:
        raise Rejected("FUNDING_RATE")
    if not 1 <= len(positions) <= MAX_ACCOUNTS:
        raise Rejected("ACCOUNT_BOUND")
    qs = {key: quantity(value) for key, value in positions.items()}
    if sum(qs.values()):
        raise Rejected("UNBALANCED_POSITION")
    deltas = {}
    for key, q in sorted(qs.items()):
        cashflow = Fraction(q * mark * r, QUANTITY_SCALE * PPM)
        delta = -ceil_fraction(cashflow) if cashflow > 0 else floor_fraction(-cashflow)
        deltas[key] = bounded(delta, signed=True)
    dust = bounded(-sum(deltas.values()))
    assert dust >= 0
    return {"cash_deltas": deltas, "dust": dust}


def insurance_resolution(cash, insurance):
    balance = bounded(cash, signed=True)
    available = bounded(insurance)
    used = min(max(0, -balance), available)
    balance += used
    debt = max(0, -balance)
    return {"cash": balance, "insurance": available - used, "insurance_used": used,
            "uncovered_debt": debt, "status": "FROZEN" if debt else "NORMAL"}


def equity_conservation(mark, accounts, custody, pools):
    price(mark)
    if not 1 <= len(accounts) <= MAX_ACCOUNTS:
        raise Rejected("ACCOUNT_BOUND")
    if sum(quantity(a["quantity"]) for a in accounts.values()):
        raise Rejected("UNBALANCED_POSITION")
    cash = sum(bounded(a["cash"], signed=True) for a in accounts.values())
    unrealized = sum(pnl(a["entry"], mark, a["quantity"]) for a in accounts.values())
    rights = cash + unrealized + bounded(pools)
    if bounded(custody) != rights:
        raise Rejected("CONSERVATION")
    return {"cash": bounded(cash, signed=True),
            "unrealized": bounded(unrealized, signed=True), "rights": bounded(rights)}


def reward(fees, support, allowance, cap, points, rho_num=1, rho_den=2):
    fees, support, allowance, cap = [bounded(x) for x in (fees, support, allowance, cap)]
    rho_num, rho_den = integer(rho_num), integer(rho_den)
    if not 0 <= rho_num <= rho_den or rho_den <= 0:
        raise Rejected("RHO")
    if not 1 <= len(points) <= MAX_VALIDATORS:
        raise Rejected("VALIDATOR_BOUND")
    scores = {key: bounded(value) for key, value in points.items()}
    if any(value > 10 for value in scores.values()):
        raise Rejected("POINT_BOUND")
    total = sum(scores.values())
    fee_share = fees * rho_num // rho_den
    budget = min(fee_share + min(support, allowance), cap) if total else 0
    from_fees = min(fee_share, budget)
    from_support = budget - from_fees
    allocations = {key: (budget * point // total if total else 0)
                   for key, point in scores.items()}
    if total:
        ranking = sorted(scores, key=lambda key: (-(budget * scores[key] % total), key))
        for key in ranking[:budget - sum(allocations.values())]:
            allocations[key] += 1
    assert sum(allocations.values()) == budget
    assert from_fees + from_support == budget
    return {"budget": budget, "from_fees": from_fees, "from_support": from_support,
            "fees_remaining": fees - from_fees, "support_remaining": support - from_support,
            "allocations": allocations}


def accounting_trace():
    """Fixed C-stage arithmetic scenario. Inputs are final/authenticated by assumption.

    This function has no deposit proof, finality verification, matching engine,
    participation authentication, Merkle proof, or native-chain transfer.
    """
    accounts = {"alice": 100 * ATOMS, "bob": 100 * ATOMS}
    state = {"custody": 225 * ATOMS, "fees": 0, "support": 20 * ATOMS,
             "insurance": 5 * ATOMS, "funding_dust": 0,
             "withdrawal_reserved": 0, "reward_reserved": 0}
    observations = []

    def snapshot(action):
        claims = (sum(accounts.values()) + sum(v for k, v in state.items() if k != "custody"))
        if claims != state["custody"]:
            raise AssertionError("custody conservation")
        observations.append({"action": action, "accounts": dict(accounts), **state})

    def collect_fee(who, p, q, ppm):
        amount = charge(p, q, ppm)
        accounts[who] -= amount
        state["fees"] += amount

    snapshot("deposits_and_funded_pools")
    collect_fee("alice", 100 * ATOMS, QUANTITY_SCALE, 300)
    collect_fee("bob", 100 * ATOMS, QUANTITY_SCALE, 100)
    snapshot("open_pair_at_100_CLX_per_BTC")
    result = funding(105 * ATOMS, {"alice": QUANTITY_SCALE, "bob": -QUANTITY_SCALE}, 1000)
    for who, delta in result["cash_deltas"].items():
        accounts[who] += delta
    state["funding_dust"] += result["dust"]
    snapshot("funding_at_105_CLX_per_BTC")
    gain = pnl(100 * ATOMS, 110 * ATOMS, QUANTITY_SCALE)
    accounts["alice"] += gain
    accounts["bob"] -= gain
    collect_fee("alice", 110 * ATOMS, QUANTITY_SCALE, 300)
    collect_fee("bob", 110 * ATOMS, QUANTITY_SCALE, 100)
    snapshot("close_pair_at_110_CLX_per_BTC")
    distribution = reward(state["fees"], state["support"], 2 * ATOMS, ATOMS,
                          {"v1": 2, "v2": 1, "v3": 1, "v4": 0, "v5": 0, "v6": 0, "v7": 0})
    state["fees"] = distribution["fees_remaining"]
    state["support"] = distribution["support_remaining"]
    state["reward_reserved"] = distribution["budget"]
    snapshot("funded_reward_reservation")
    accounts["alice"] -= 10 * ATOMS
    state["withdrawal_reserved"] += 10 * ATOMS
    snapshot("withdrawal_reservation")
    state["withdrawal_reserved"] -= 10 * ATOMS
    state["custody"] -= 10 * ATOMS
    snapshot("native_withdrawal_paid")
    state["custody"] -= state["reward_reserved"]
    state["reward_reserved"] = 0
    snapshot("native_rewards_paid")
    return {"steps": observations, "reward_allocations": distribution["allocations"]}


def evaluate(operation, args):
    operations = {
        "notional": lambda: notional(args["price"], args["quantity"]),
        "charge": lambda: charge(args["price"], args["quantity"], args["rate_ppm"]),
        "pnl": lambda: pnl(args["entry"], args["exit"], args["quantity"]),
        "funding": lambda: funding(args["price"], args["positions"], args["rate_ppm"]),
        "insurance": lambda: insurance_resolution(args["cash"], args["insurance"]),
        "equity": lambda: equity_conservation(**args),
        "reward": lambda: reward(**args),
        "trace": accounting_trace,
    }
    if operation not in operations:
        raise Rejected("UNKNOWN_OPERATION")
    return operations[operation]()


def json_numbers(value):
    if isinstance(value, int):
        return str(value)
    if isinstance(value, dict):
        return {key: json_numbers(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_numbers(item) for item in value]
    return value


def check(path):
    vectors = json.loads(path.read_text())
    if vectors["schema"] != "common-dex-accounting-v0":
        raise ValueError("unsupported vector schema")
    failed = 0
    for case in vectors["cases"]:
        try:
            actual = {"result": json_numbers(evaluate(case["operation"], case.get("input", {})))}
        except Rejected as exc:
            actual = {"error": str(exc)}
        expected = {key: case[key] for key in ("result", "error") if key in case}
        if actual != expected:
            failed += 1
            print(f"FAIL {case['id']}: expected {expected!r}; actual {actual!r}", file=sys.stderr)
        else:
            print(f"PASS {case['id']}")
    print(f"accounting vectors: {len(vectors['cases']) - failed}/{len(vectors['cases'])} PASS")
    print("Arithmetic only; cryptography, FHS, native settlement and distributed tests: NOT_RUN")
    return bool(failed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="check the fixed golden inputs/outputs")
    parser.add_argument("--vectors", type=Path,
                        default=Path(__file__).resolve().parents[2] / "dex/testdata/accounting.json")
    args = parser.parse_args()
    if not args.check:
        parser.error("--check is required; this tool does not regenerate expected values")
    return check(args.vectors)


if __name__ == "__main__":
    sys.exit(main())
