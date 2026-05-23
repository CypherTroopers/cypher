#!/usr/bin/env python3
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path.cwd()

FILES = {
    "transaction": ROOT / "core/types/transaction.go",
    "api": ROOT / "internal/ethapi/api.go",
    "typed_test": ROOT / "core/types/tx_typed_roundtrip_test.go",
}

def die(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)

def backup(path: Path) -> None:
    if not path.exists():
        die(f"missing file: {path}")
    ts = time.strftime("%Y%m%d-%H%M%S")
    dst = path.with_suffix(path.suffix + f".bak.{ts}")
    shutil.copy2(path, dst)
    print(f"[BACKUP] {path} -> {dst}")

def replace_once(text: str, old: str, new: str, label: str) -> tuple[str, bool]:
    if old in text:
        return text.replace(old, new, 1), True
    if new in text:
        print(f"[SKIP] {label}: already applied")
        return text, False
    die(f"{label}: target pattern not found")
    return text, False

def replace_all_or_skip(text: str, old: str, new: str, label: str) -> tuple[str, int]:
    count = text.count(old)
    if count > 0:
        return text.replace(old, new), count
    if new in text:
        print(f"[SKIP] {label}: already applied")
        return text, 0
    die(f"{label}: target pattern not found")
    return text, 0

def ensure_import_crypto_in_test(text: str) -> str:
    if '"github.com/cypherium/cypher/crypto"' in text:
        print("[SKIP] tx_typed_roundtrip_test.go crypto import already exists")
        return text

    old = '''import (
\t"encoding/json"
\t"math/big"
\t"testing"

\t"github.com/cypherium/cypher/common"
)
'''
    new = '''import (
\t"encoding/json"
\t"math/big"
\t"testing"

\t"github.com/cypherium/cypher/common"
\t"github.com/cypherium/cypher/crypto"
)
'''
    if old not in text:
        die("tx_typed_roundtrip_test.go: import block pattern not found")
    print("[PATCH] add crypto import to tx_typed_roundtrip_test.go")
    return text.replace(old, new, 1)

def append_typed_hash_test(text: str) -> str:
    if "TestTypedTransactionHashUsesRawEnvelope" in text:
        print("[SKIP] TestTypedTransactionHashUsesRawEnvelope already exists")
        return text

    test_code = r'''

func TestTypedTransactionHashUsesRawEnvelope(t *testing.T) {
	to := testAddress(1)
	accessList := AccessList{
		{
			Address:     testAddress(2),
			StorageKeys: []common.Hash{testHash(3)},
		},
	}

	txs := []*Transaction{
		{data: &AccessListTx{
			ChainID:    big.NewInt(1236789),
			Nonce:      1,
			GasPrice:   big.NewInt(1000),
			Gas:        21000,
			To:         &to,
			Value:      big.NewInt(1),
			Data:       []byte{0x01, 0x02},
			AccessList: accessList,
			V:          big.NewInt(0),
			R:          big.NewInt(1),
			S:          big.NewInt(1),
		}},
		{data: &DynamicFeeTx{
			ChainID:    big.NewInt(1236789),
			Nonce:      2,
			GasTipCap:  big.NewInt(10),
			GasFeeCap:  big.NewInt(100),
			Gas:        50000,
			To:         &to,
			Value:      big.NewInt(2),
			Data:       []byte{0x03, 0x04},
			AccessList: accessList,
			V:          big.NewInt(0),
			R:          big.NewInt(1),
			S:          big.NewInt(1),
		}},
	}

	for _, tx := range txs {
		enc, err := tx.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary failed: %v", err)
		}
		want := crypto.Keccak256Hash(enc)
		if got := tx.Hash(); got != want {
			t.Fatalf("typed tx hash mismatch: got %s want %s", got.Hex(), want.Hex())
		}
	}
}
'''
    print("[PATCH] append TestTypedTransactionHashUsesRawEnvelope")
    if not text.endswith("\n"):
        text += "\n"
    return text + test_code

def patch_transaction_go() -> None:
    path = FILES["transaction"]
    backup(path)
    text = path.read_text()

    old = '''\t} else if enc, err := tx.MarshalBinary(); err == nil {
\t\tv = rlpHash(enc)
\t}
'''
    new = '''\t} else if enc, err := tx.MarshalBinary(); err == nil {
\t\tv = crypto.Keccak256Hash(enc)
\t}
'''
    text, changed = replace_once(
        text,
        old,
        new,
        "core/types/transaction.go typed Transaction.Hash",
    )
    if changed:
        print("[PATCH] transaction.go: typed tx Hash uses crypto.Keccak256Hash(enc)")
    path.write_text(text)

def patch_api_go() -> None:
    path = FILES["api"]
    backup(path)
    text = path.read_text()

    old = '''\tblob, _ := rlp.EncodeToBytes(txs[index])
\treturn blob
'''
    new = '''\tblob, _ := txs[index].MarshalBinary()
\treturn blob
'''
    text, changed = replace_once(
        text,
        old,
        new,
        "internal/ethapi/api.go newRPCRawTransactionFromBlockIndex",
    )
    if changed:
        print("[PATCH] api.go: raw tx from block index uses MarshalBinary()")

    old = '''\treturn rlp.EncodeToBytes(tx)
'''
    new = '''\treturn tx.MarshalBinary()
'''
    text, count = replace_all_or_skip(
        text,
        old,
        new,
        "internal/ethapi/api.go return raw tx",
    )
    if count:
        print(f"[PATCH] api.go: replaced {count} return rlp.EncodeToBytes(tx) with tx.MarshalBinary()")

    old = '''\tdata, err := rlp.EncodeToBytes(tx)
'''
    new = '''\tdata, err := tx.MarshalBinary()
'''
    text, count = replace_all_or_skip(
        text,
        old,
        new,
        "internal/ethapi/api.go SignTransaction/FillTransaction raw encoding",
    )
    if count:
        print(f"[PATCH] api.go: replaced {count} data, err := rlp.EncodeToBytes(tx) with tx.MarshalBinary()")

    path.write_text(text)

def patch_test_go() -> None:
    path = FILES["typed_test"]
    backup(path)
    text = path.read_text()

    text = ensure_import_crypto_in_test(text)
    text = append_typed_hash_test(text)

    path.write_text(text)

def run_gofmt() -> None:
    files = [str(FILES["transaction"]), str(FILES["api"]), str(FILES["typed_test"])]
    print("[GOFMT] running gofmt")
    subprocess.run(["gofmt", "-w", *files], check=True)

def main() -> None:
    required = [
        ROOT / "core/types/transaction.go",
        ROOT / "core/types/tx_typed_encoding.go",
        ROOT / "internal/ethapi/api.go",
        ROOT / "core/types/tx_typed_roundtrip_test.go",
    ]
    for p in required:
        if not p.exists():
            die(f"run this script from repo root. missing: {p}")

    print(f"[ROOT] {ROOT}")

    patch_transaction_go()
    patch_api_go()
    patch_test_go()
    run_gofmt()

    print("")
    print("DONE")
    print("")
    print("Next commands:")
    print("  go test ./core/types")
    print("  go build -o ./build/bin/cypher ./cmd/cypher")
    print("")
    print("After restarting node with the rebuilt binary, rerun:")
    print("  cd /root/cancun-deploy-test")
    print("  npm run test:typed-raw")
    print("  npm run test:extra")

if __name__ == "__main__":
    main()
