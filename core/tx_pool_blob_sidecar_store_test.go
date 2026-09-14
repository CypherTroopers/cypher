package core

import (
	"errors"
	"reflect"
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
		Blobs:       []types.Blob{{1, 2, 3}},
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
	got := pool.getBlobSidecar(tx.Hash(), false)
	if !reflect.DeepEqual(got, sidecar) {
		t.Fatalf("stored sidecar mismatch")
	}
	if got == sidecar {
		t.Fatalf("store returned caller-owned sidecar pointer")
	}
	got.Proofs[0][0] = 0xff
	if again := pool.getBlobSidecar(tx.Hash(), false); again.Proofs[0][0] != 0 {
		t.Fatalf("mutating a returned sidecar changed the verified store")
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

func TestTxPoolBlobSidecarStoreHasExplicitByteLimit(t *testing.T) {
	pool := &TxPool{config: TxPoolConfig{GlobalSlots: 1, GlobalQueue: 1}}
	tx, sidecar := testTxPoolSidecar(t, 4)
	sidecar.Blobs[0] = make(types.Blob, 2*txSlotSize)
	if err := pool.storeBlobSidecar(tx, sidecar); !errors.Is(err, ErrBlobSidecarStoreFull) {
		t.Fatalf("store error = %v, want %v", err, ErrBlobSidecarStoreFull)
	}
	store := loadBlobSidecarStore(pool)
	if store == nil {
		t.Fatal("expected initialized bounded sidecar store")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.bytes != 0 || len(store.sidecars) != 0 {
		t.Fatalf("failed quota reservation changed store: bytes=%d entries=%d", store.bytes, len(store.sidecars))
	}
}
