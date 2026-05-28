package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

func testSidecarSelectionBlobTx(t *testing.T, n byte) (*types.Transaction, *types.BlobTxSidecar) {
	t.Helper()
	var commitment types.KZGCommitment
	commitment[47] = n
	hash := types.KZGToVersionedHash(commitment)
	tx := newTxpoolBlobTx(t, []common.Hash{hash}, common.Big1)
	sidecar := &types.BlobTxSidecar{
		Blobs:       []types.Blob{types.Blob{1, 2, 3}},
		Commitments: []types.KZGCommitment{commitment},
		Proofs:      []types.KZGProof{{}},
	}
	return tx, sidecar
}

func TestValidateBlobSidecarsForTransactions(t *testing.T) {
	pool := &TxPool{all: newTxLookup()}
	blobTx, sidecar := testSidecarSelectionBlobTx(t, 1)
	legacyTx := types.NewTransaction(0, common.Address{1}, big.NewInt(0), 21000, big.NewInt(1), nil)

	if err := pool.ValidateBlobSidecarsForTransactions(types.Transactions{legacyTx}); err != nil {
		t.Fatalf("legacy tx should not require sidecar: %v", err)
	}
	if err := pool.ValidateBlobSidecarsForTransactions(types.Transactions{blobTx}); !errors.Is(err, ErrMissingBlobTxSidecar) {
		t.Fatalf("expected missing sidecar error, got %v", err)
	}
	pool.all.Add(blobTx, false)
	pool.storeBlobSidecar(blobTx, sidecar)
	if err := pool.ValidateBlobSidecarsForTransactions(types.Transactions{legacyTx, blobTx}); err != nil {
		t.Fatalf("expected valid sidecars, got %v", err)
	}
}

func TestFilterTransactionsWithBlobSidecars(t *testing.T) {
	pool := &TxPool{all: newTxLookup()}
	withSidecar, sidecar := testSidecarSelectionBlobTx(t, 2)
	withoutSidecar, _ := testSidecarSelectionBlobTx(t, 3)
	legacyTx := types.NewTransaction(1, common.Address{2}, big.NewInt(0), 21000, big.NewInt(1), nil)

	pool.all.Add(withSidecar, false)
	pool.storeBlobSidecar(withSidecar, sidecar)
	filtered := pool.FilterTransactionsWithBlobSidecars(types.Transactions{legacyTx, withSidecar, withoutSidecar, nil})
	if len(filtered) != 2 {
		t.Fatalf("filtered len = %d, want 2", len(filtered))
	}
	if filtered[0] != legacyTx || filtered[1] != withSidecar {
		t.Fatalf("unexpected filtered transactions")
	}
}
