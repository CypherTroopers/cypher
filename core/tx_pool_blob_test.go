package core

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

func txpoolBlobTestHash(n byte) common.Hash {
	var h common.Hash
	h[0] = types.BlobCommitmentVersionKZG
	h[31] = n
	return h
}

func newTxpoolBlobTx(t *testing.T, blobHashes []common.Hash, blobFeeCap *big.Int) *types.Transaction {
	t.Helper()
	return newTxpoolBlobTxWithNonce(t, 1, blobHashes, blobFeeCap)
}

func newTxpoolBlobTxWithNonce(t *testing.T, nonce uint64, blobHashes []common.Hash, blobFeeCap *big.Int) *types.Transaction {
	t.Helper()

	blobHashesJSON := "[]"
	if blobHashes != nil {
		encoded, err := json.Marshal(blobHashes)
		if err != nil {
			t.Fatalf("failed to marshal blob hashes: %v", err)
		}
		blobHashesJSON = string(encoded)
	}
	blobFeeCapJSON := "null"
	if blobFeeCap != nil {
		blobFeeCapJSON = fmt.Sprintf("\"0x%x\"", blobFeeCap)
	}

	raw := fmt.Sprintf(`{
		"type":"0x3",
		"chainId":"0x304f",
		"nonce":"0x%x",
		"maxPriorityFeePerGas":"0x1",
		"maxFeePerGas":"0xa",
		"gas":"0x5208",
		"to":"0x0000000000000000000000000000000000000001",
		"value":"0x0",
		"input":"0x",
		"accessList":[],
		"maxFeePerBlobGas":%s,
		"blobVersionedHashes":%s,
		"v":"0x0",
		"r":"0x1",
		"s":"0x1"
	}`, nonce, blobFeeCapJSON, blobHashesJSON)

	var tx types.Transaction
	if err := json.Unmarshal([]byte(raw), &tx); err != nil {
		t.Fatalf("failed to unmarshal blob tx: %v\njson=%s", err, raw)
	}
	return &tx
}

func TestTxPoolValidateBlobTxHelper(t *testing.T) {
	pool := &TxPool{chainconfig: &params.ChainConfig{}}

	valid := newTxpoolBlobTx(t, []common.Hash{txpoolBlobTestHash(1)}, big.NewInt(1))
	if err := pool.validateBlobTx(valid); err != nil {
		t.Fatalf("expected valid blob tx, got %v", err)
	}

	missingHashes := newTxpoolBlobTx(t, nil, big.NewInt(1))
	if err := pool.validateBlobTx(missingHashes); err != types.ErrBlobTxMissingBlobHashes {
		t.Fatalf("expected missing blob hashes, got %v", err)
	}

	missingFeeCap := newTxpoolBlobTx(t, []common.Hash{txpoolBlobTestHash(1)}, nil)
	if err := pool.validateBlobTx(missingFeeCap); err != types.ErrBlobTxInvalidFeeCap {
		t.Fatalf("expected invalid blob fee cap, got %v", err)
	}
}
