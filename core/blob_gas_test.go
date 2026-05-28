package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

func blobGasTestHash(n byte) common.Hash {
	var h common.Hash
	h[0] = types.BlobCommitmentVersionKZG
	h[31] = n
	return h
}

func blobGasTestConfig(cancunTime uint64) *params.ChainConfig {
	cfg := &params.ChainConfig{}
	cfg.SetModernForkConfig(&params.ModernForkConfig{CancunTime: &cancunTime})
	return cfg
}

func blobGasTestTx(t *testing.T, blobCount int) *types.Transaction {
	t.Helper()
	hashes := make([]common.Hash, blobCount)
	for i := range hashes {
		hashes[i] = blobGasTestHash(byte(i + 1))
	}
	encodedHashes, err := json.Marshal(hashes)
	if err != nil {
		t.Fatalf("failed to marshal blob hashes: %v", err)
	}
	raw := fmt.Sprintf(`{
		"type":"0x3",
		"chainId":"0x304f",
		"nonce":"0x1",
		"maxPriorityFeePerGas":"0x1",
		"maxFeePerGas":"0xa",
		"gas":"0x5208",
		"to":"0x0000000000000000000000000000000000000001",
		"value":"0x0",
		"input":"0x",
		"accessList":[],
		"maxFeePerBlobGas":"0x1",
		"blobVersionedHashes":%s,
		"v":"0x0",
		"r":"0x1",
		"s":"0x1"
	}`, string(encodedHashes))
	var tx types.Transaction
	if err := json.Unmarshal([]byte(raw), &tx); err != nil {
		t.Fatalf("failed to unmarshal blob tx: %v\njson=%s", err, raw)
	}
	return &tx
}

func TestCalcBlobGasUsed(t *testing.T) {
	txs := types.Transactions{blobGasTestTx(t, 1), blobGasTestTx(t, 2)}
	want := uint64(3) * params.BlobTxBlobGasPerBlob
	if got := CalcBlobGasUsed(txs); got != want {
		t.Fatalf("blob gas mismatch: got %d want %d", got, want)
	}
}

func TestValidateBlockBlobGas(t *testing.T) {
	cfg := blobGasTestConfig(0)
	header := &types.Header{Number: big.NewInt(1), Time: 0}
	txs := types.Transactions{blobGasTestTx(t, 1)}
	header.BlobGasUsed = CalcBlobGasUsed(txs)
	if err := ValidateBlockBlobGas(cfg, header, txs); err != nil {
		t.Fatalf("expected valid blob gas, got %v", err)
	}

	header.BlobGasUsed = 0
	if err := ValidateBlockBlobGas(cfg, header, txs); !errors.Is(err, ErrBlobGasUsedMismatch) {
		t.Fatalf("expected blob gas mismatch, got %v", err)
	}
}

func TestValidateBlockBlobGasBeforeCancun(t *testing.T) {
	cfg := blobGasTestConfig(10)
	header := &types.Header{Number: big.NewInt(1), Time: 0}
	txs := types.Transactions{blobGasTestTx(t, 1)}
	if err := ValidateBlockBlobGas(cfg, header, txs); !errors.Is(err, ErrBlobGasUsedMismatch) {
		t.Fatalf("expected pre-Cancun mismatch, got %v", err)
	}
}

func TestValidateBlockBlobGasOverflow(t *testing.T) {
	cfg := blobGasTestConfig(0)
	header := &types.Header{Number: big.NewInt(1), Time: 0}
	txs := types.Transactions{blobGasTestTx(t, 7)}
	header.BlobGasUsed = CalcBlobGasUsed(txs)
	if err := ValidateBlockBlobGas(cfg, header, txs); !errors.Is(err, ErrBlobGasUsedOverflow) {
		t.Fatalf("expected blob gas overflow, got %v", err)
	}
}
