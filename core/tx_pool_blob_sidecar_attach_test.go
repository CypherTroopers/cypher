package core

import (
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

func TestAttachBlobSidecarsToTransactions(t *testing.T) {
	pool := &TxPool{}
	legacy := types.NewTransaction(0, common.Address{}, nil, 21000, nil, nil)
	blobTx, sidecar := testBlobTxWithSidecar(t)
	pool.storeBlobSidecar(blobTx, sidecar)

	attached, err := pool.AttachBlobSidecarsToTransactions(types.Transactions{legacy, blobTx})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(attached) != 2 {
		t.Fatalf("expected two transactions, got %d", len(attached))
	}
	if attached[0] != legacy {
		t.Fatalf("legacy transaction should be kept unchanged")
	}
	if attached[1].Hash() != blobTx.Hash() {
		t.Fatalf("attached blob tx hash changed")
	}
	if attached[1] == blobTx {
		t.Fatalf("blob tx should be copied when sidecar is attached")
	}
	if attached[1].BlobSidecar() == nil {
		t.Fatalf("blob sidecar was not attached")
	}
}

func TestAttachBlobSidecarsToTransactionsRequiresSidecar(t *testing.T) {
	pool := &TxPool{}
	blobTx, _ := testBlobTxWithSidecar(t)
	_, err := pool.AttachBlobSidecarsToTransactions(types.Transactions{blobTx})
	if err != ErrMissingBlobTxSidecar {
		t.Fatalf("expected missing sidecar error, got %v", err)
	}
}
