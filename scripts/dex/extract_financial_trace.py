#!/usr/bin/env python3
"""Extract public IDs and integer accounting from one completed devnet run.

No datadir, keys or RPC is read. Never merge random identities or gas from runs.
The Go integration test owns assertions of bucket/root/receipt correctness; this
script independently reconciles logged transaction gas and native wallet deltas.
"""
import hashlib
import json
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
raw = source.read_bytes()
lines = raw.decode().splitlines()
pass_line = next((s for s in lines if s.startswith("--- PASS: TestFHSNativeFinancial")), None)
if pass_line is None or any(s.startswith("--- FAIL:") for s in lines):
    raise SystemExit("completed PASS financial log required")
names = {
    "CLX_FINALIZED", "CLX_INBOX_EVIDENCE", "CLX_INBOX_ENTRY",
    "DEX_FINALIZED_AND_CLX_SETTLED", "CLAIM_PAID", "NATIVE_BALANCE",
    "NATIVE_LEDGER_RECONCILED", "NORMAL_FINANCIAL_ROLES",
    "NORMAL_COMMON_RPC_DEX_READY", "NORMAL_COMMON_RPC_DEX_RELAY",
    "NORMAL_COMMON_RPC_DEX_CONFIRMED", "CLX_CRASH_REOPEN",
    "DEX_FINANCIAL_FAULT", "DEX_FINANCIAL_ECONOMY", "CLX_ALL_STOPPED",
    "DEX_OFF_PROCESS_FULLSYNC_RESTART", "NATIVE_RPC_PARITY",
    "REWARD_OMISSION_REJECTED", "FINANCIAL_TWO_DOMAIN_TRACE_PASS",
}
events = []
for number, line in enumerate(lines, 1):
    m = re.search(r": ([A-Z][A-Z0-9_]+)\b(.*)$", line)
    if m and m[1] in names:
        fields = dict(re.findall(r"([A-Za-z][A-Za-z0-9_]*)=(\[[^\]]*\]|[^\s;]+)", m[2]))
        events.append({"event": m[1], "line": number, "fields": fields, "raw": line.strip()})

def select(name):
    return [e["fields"] for e in events if e["event"] == name]

txs = select("CLX_FINALIZED")
entries = select("CLX_INBOX_ENTRY")
checkpoints = select("DEX_FINALIZED_AND_CLX_SETTLED")
claims = select("CLAIM_PAID")
ledger = select("NATIVE_LEDGER_RECONCILED")[-1]
balances = [b for b in select("NATIVE_BALANCE") if b["height"] == ledger["height"]]
assert len(txs) == 35 and len({t["tx"] for t in txs}) == 35
assert len(entries) == 4 and {e["index"] for e in entries} == {"0", "1", "2", "3"}
assert len(checkpoints) == 18 and len(claims) == 8
assert ledger["height"] == "69" and ledger["custody"] == "214000000000000000000"
assert len(balances) == int(ledger["accounts"])
assert sum(int(b["delta"]) for b in balances) == -int(ledger["burn"])
assert int(ledger["gas"]) == int(ledger["commonReward"]) + int(ledger["burn"])
assert int(ledger["commonReward"]) * 5 == int(ledger["gas"])
assert sum(int(t["gas"]) for t in txs) * 1600000000 == int(ledger["gas"])
assert sum(int(c["amount"]) for c in claims) == 11000000000000000000
assert all(int(b["initial"]) + int(b["delta"]) == int(b["final"]) for b in balances)
result = {
    "source_log": str(source), "source_sha256": hashlib.sha256(raw).hexdigest(),
    "result": pass_line, "unit": "native CLX atoms (1 CLX = 10^18 atoms)",
    "scope": "One isolated run only. ACK, DEX finality, CLX finality and payment are distinct events.",
    "gas_price_atoms": "1600000000", "transactions": txs, "deposits": entries,
    "checkpoint_submissions": checkpoints, "claims": claims,
    "final_wallets": balances, "final_ledger": ledger,
    "native_buckets_asserted_in_passing_go_scenario": {
        "Uncredited": "0", "Trader": "189916000000000000000", "Fees": "64000000000000000",
        "Support": "19020000000000000000", "Insurance": "5000000000000000000",
        "Dust": "0", "Withdrawals": "0", "Rewards": "0",
    },
    "reward_source_atoms": {"period_fees": "20000000000000000", "support": "980000000000000000"},
    "events": events,
}
destination.write_text(json.dumps(result, indent=2) + "\n")
print(f"PASS: {len(txs)} CLX TX, {len(entries)} deposits, {len(checkpoints)} checkpoints, {len(claims)} claims; wallet deltas = -burn")
