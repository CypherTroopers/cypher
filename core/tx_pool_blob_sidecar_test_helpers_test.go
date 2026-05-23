package core

import (
	"encoding/json"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

func testCoreKZGCommitment(seed byte) types.KZGCommitment {
	var commitment types.KZGCommitment
	for i := range commitment {
		commitment[i] = seed + byte(i)
	}
	return commitment
}

func testBlobTxWithSidecar(t *testing.T) (*types.Transaction, *types.BlobTxSidecar) {
	t.Helper()
	commitment := testCoreKZGCommitment(33)
	hash := types.KZGToVersionedHash(commitment)
	to := common.HexToAddress("0x1000000000000000000000000000000000000001")
	tx := new(types.Transaction)
	payload := map[string]interface{}{
		"type":                 "0x3",
		"chainId":              "0x1",
		"nonce":                "0x0",
		"maxPriorityFeePerGas": "0x1",
		"maxFeePerGas":         "0x2",
		"gas":                  "0x5208",
		"to":                   to.Hex(),
		"value":                "0x0",
		"input":                "0x",
		"accessList":           []interface{}{},
		"maxFeePerBlobGas":     "0x2",
		"blobVersionedHashes":  []string{hash.Hex()},
		"v":                    "0x0",
		"r":                    "0x1",
		"s":                    "0x1",
	}
	blob, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal blob tx payload: %v", err)
	}
	if err := tx.UnmarshalJSON(blob); err != nil {
		t.Fatalf("failed to unmarshal blob tx: %v", err)
	}
	sidecar := &types.BlobTxSidecar{
		Blobs:       []types.Blob{{1, 2, 3}},
		Commitments: []types.KZGCommitment{commitment},
		Proofs:      []types.KZGProof{{}},
	}
	return tx, sidecar
}
