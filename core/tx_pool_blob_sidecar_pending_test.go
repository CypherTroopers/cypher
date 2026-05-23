package core

import (
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

func TestContentWithBlobSidecarsFiltersMissingBlobSidecars(t *testing.T) {
	legacy := types.NewTransaction(0, common.Address{}, nil, 21000, nil, nil)
	blobTx := newTxpoolBlobTxWithNonce(t, 1, []common.Hash{txpoolBlobTestHash(1)}, common.Big1)
	_, sidecar := testTxPoolSidecar(t, 1)
	missingBlobTx := newTxpoolBlobTxWithNonce(t, 2, []common.Hash{txpoolBlobTestHash(2)}, common.Big1)

	addr := common.HexToAddress("0x1234")
	pool := &TxPool{
		pending: map[common.Address]*txList{
			addr: newTxList(true),
		},
		queue: map[common.Address]*txList{},
	}
	pool.pending[addr].Add(legacy, 10)
	pool.pending[addr].Add(blobTx, 10)
	pool.pending[addr].Add(missingBlobTx, 10)
	pool.storeBlobSidecar(blobTx, sidecar)

	pending, queued := pool.ContentWithBlobSidecars()
	if len(queued) != 0 {
		t.Fatalf("expected empty queued map")
	}
	got := pending[addr]
	if len(got) != 2 {
		t.Fatalf("expected legacy + blob tx with sidecar, got %d", len(got))
	}
	for _, tx := range got {
		if tx.Type() == types.BlobTxType && tx.Hash() != blobTx.Hash() {
			t.Fatalf("unexpected blob tx without sidecar was kept")
		}
	}
}
