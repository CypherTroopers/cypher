#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

ROOT = Path.cwd()

TX_POOL = ROOT / "core" / "tx_pool.go"
TX_POOL_TEST = ROOT / "core" / "tx_pool_lane_test.go"
GASPRICE = ROOT / "eth" / "gasprice" / "gasprice.go"


def replace_once(path: Path, old: str, new: str, label: str):
    text = path.read_text()

    if new in text:
        print(f"[SKIP] {label}: already applied")
        return

    if old not in text:
        print(f"[ERROR] {label}: target text not found in {path}")
        sys.exit(1)

    path.write_text(text.replace(old, new, 1))
    print(f"[OK] {label}")


def insert_once(path: Path, anchor: str, insert: str, marker: str, label: str):
    text = path.read_text()

    if marker in text:
        print(f"[SKIP] {label}: already applied")
        return

    if anchor not in text:
        print(f"[ERROR] {label}: anchor not found in {path}")
        sys.exit(1)

    path.write_text(text.replace(anchor, anchor + insert, 1))
    print(f"[OK] {label}")


# 1. core/tx_pool.go constants
replace_once(
    TX_POOL,
    """const (
\ttxLaneFastMaxDataBytes = 256
\ttxLaneFastMaxGasPerTx  = uint64(120000)
)
""",
    """const (
\ttxLaneFastMaxDataBytes = 1024
\ttxLaneFastMaxGasPerTx  = uint64(300000)
)
""",
    "update fast-lane limits",
)

# 2. core/tx_pool.go IsFastLaneEligible return logic
replace_once(
    TX_POOL,
    """\tif len(tx.Data()) == 0 {
\t\treturn true
\t}
\tif len(tx.Data()) >= 4 && tx.Data()[0] == 0xa9 && tx.Data()[1] == 0x05 && tx.Data()[2] == 0x9c && tx.Data()[3] == 0xbb {
\t\treturn true
\t}
\treturn false
}
""",
    """\treturn true
}
""",
    "simplify fast-lane data eligibility",
)

# 3. add core/tx_pool_lane_test.go
TX_POOL_TEST.write_text("""package core

import (
\t"math/big"
\t"testing"

\t"github.com/cypherium/cypher/common"
\t"github.com/cypherium/cypher/core/types"
)

func TestIsFastLaneEligible(t *testing.T) {
\tto := common.HexToAddress("0x1")

\tregular := types.NewTransaction(0, to, big.NewInt(1), txLaneFastMaxGasPerTx, big.NewInt(1), make([]byte, txLaneFastMaxDataBytes))
\tif !IsFastLaneEligible(regular) {
\t\tt.Fatalf("expected regular bounded call tx to be fast-lane eligible")
\t}

\tdeploy := types.NewContractCreation(0, big.NewInt(1), txLaneFastMaxGasPerTx, big.NewInt(1), []byte{0x60, 0x00})
\tif IsFastLaneEligible(deploy) {
\t\tt.Fatalf("expected contract-creation tx to be slow-lane")
\t}

\theavyGas := types.NewTransaction(1, to, big.NewInt(1), txLaneFastMaxGasPerTx+1, big.NewInt(1), nil)
\tif IsFastLaneEligible(heavyGas) {
\t\tt.Fatalf("expected tx above fast-lane gas limit to be slow-lane")
\t}

\theavyData := types.NewTransaction(2, to, big.NewInt(1), 21000, big.NewInt(1), make([]byte, txLaneFastMaxDataBytes+1))
\tif IsFastLaneEligible(heavyData) {
\t\tt.Fatalf("expected tx above fast-lane data limit to be slow-lane")
\t}
}
""")
print(f"[OK] write {TX_POOL_TEST}")

# 4. eth/gasprice/gasprice.go exclude contract creation from sampling
insert_once(
    GASPRICE,
    """\tvar prices []*big.Int
\tfor _, tx := range txs {
""",
    """\t\t// Exclude contract creation transactions from price sampling so
\t\t// deploy bursts don't inflate suggested fees for regular traffic.
\t\tif tx.To() == nil {
\t\t\tcontinue
\t\t}
""",
    "deploy bursts don't inflate suggested fees",
    "exclude contract creation txs from gas price sampling",
)

# 5. gofmt
files = [
    "core/tx_pool.go",
    "core/tx_pool_lane_test.go",
    "eth/gasprice/gasprice.go",
]

try:
    subprocess.run(["gofmt", "-w", *files], check=True)
    print("[OK] gofmt")
except FileNotFoundError:
    print("[WARN] gofmt not found, skipped")
except subprocess.CalledProcessError as e:
    print(f"[ERROR] gofmt failed: {e}")
    sys.exit(1)

print("[DONE] patch applied")
