package core

import (
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

func testTxPoolSidecar(t *testing.T, n byte) (*types.Transaction, *types.BlobTxSidecar) {
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

func TestTxPoolBlobSidecarStore(t *testing.T) {
	pool := &TxPool{}
	tx, sidecar := testTxPoolSidecar(t, 1)

	if pool.getBlobSidecar(tx.Hash(), false) != nil {
		t.Fatalf("unexpected sidecar before store")
	}
	pool.storeBlobSidecar(tx, sidecar)
	if got := pool.getBlobSidecar(tx.Hash(), false); got != sidecar {
		t.Fatalf("sidecar pointer mismatch")
	}
	pool.RemoveBlobSidecar(tx.Hash())
	if pool.getBlobSidecar(tx.Hash(), false) != nil {
		t.Fatalf("unexpected sidecar after remove")
	}
}

func TestTxPoolBlobSidecarLazyPrune(t *testing.T) {
	pool := &TxPool{all: newTxLookup()}
	tx, sidecar := testTxPoolSidecar(t, 2)
	pool.storeBlobSidecar(tx, sidecar)
	if got := pool.GetBlobSidecar(tx.Hash()); got != nil {
		t.Fatalf("expected stale sidecar to be pruned, got %v", got)
	}
	if got := pool.getBlobSidecar(tx.Hash(), false); got != nil {
		t.Fatalf("expected sidecar removed after lazy prune")
	}
}

func TestTxPoolPruneBlobSidecars(t *testing.T) {
	pool := &TxPool{all: newTxLookup()}
	tx, sidecar := testTxPoolSidecar(t, 3)
	pool.storeBlobSidecar(tx, sidecar)
	if removed := pool.PruneBlobSidecars(); removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
	if got := pool.getBlobSidecar(tx.Hash(), false); got != nil {
		t.Fatalf("expected sidecar removed after prune")
	}
}
