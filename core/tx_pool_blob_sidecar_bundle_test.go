package core

import (
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

func TestBlobSidecarsForTransactionsIgnoresLegacy(t *testing.T) {
	pool := &TxPool{}
	legacy := types.NewTransaction(0, common.Address{}, nil, 21000, nil, nil)
	sidecars, err := pool.BlobSidecarsForTransactions(types.Transactions{legacy})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sidecars != nil {
		t.Fatalf("expected nil sidecars for legacy txs")
	}
}

func TestBlobSidecarsForTransactionsRequiresSidecar(t *testing.T) {
	pool := &TxPool{}
	tx, _ := testBlobTxWithSidecar(t)
	_, err := pool.BlobSidecarsForTransactions(types.Transactions{tx})
	if err != ErrMissingBlobTxSidecar {
		t.Fatalf("expected missing sidecar error, got %v", err)
	}
}

func TestBlobBundlesForTransactionsReturnsBundles(t *testing.T) {
	pool := &TxPool{}
	tx, sidecar := testBlobTxWithSidecar(t)
	pool.storeBlobSidecar(tx, sidecar)
	bundles, err := pool.BlobBundlesForTransactions(types.Transactions{tx})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(bundles) != 1 {
		t.Fatalf("expected one bundle, got %d", len(bundles))
	}
	if bundles[0].Tx.Hash() != tx.Hash() {
		t.Fatalf("bundle tx hash mismatch")
	}
	if bundles[0].Sidecar == nil {
		t.Fatalf("missing bundle sidecar")
	}
}
