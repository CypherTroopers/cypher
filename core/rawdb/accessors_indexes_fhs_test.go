package rawdb

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

func TestFHSFinalizedTxLookupStoresExactBlockIdentity(t *testing.T) {
	db := NewMemoryDatabase()
	txs := types.Transactions{
		types.NewTransaction(0, common.Address{1}, big.NewInt(1), 21_000, big.NewInt(1), nil),
		types.NewTransaction(1, common.Address{2}, big.NewInt(1), 21_000, big.NewInt(1), nil),
	}
	block := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(77), Extra: []byte("finalized")}).WithBody(txs, nil)
	WriteFHSFinalizedTxLookupEntries(db, block)
	for _, tx := range txs {
		hash, number, ok := ReadFHSFinalizedTxLookupEntry(db, tx.Hash())
		if !ok || hash != block.Hash() || number != block.NumberU64() {
			t.Fatalf("finalized lookup %s = %s/%d present=%v", tx.Hash(), hash, number, ok)
		}
		if legacyNumber := ReadTxLookupEntry(db, tx.Hash()); legacyNumber == nil || *legacyNumber != block.NumberU64() {
			t.Fatalf("ordinary lookup did not understand finalized entry %s: %v", tx.Hash(), legacyNumber)
		}
	}
	// Receipt sync and the background tx indexer may rewrite the ordinary key
	// after finalization. The exact finality key must survive those rewrites.
	WriteTxLookupEntries(db, block)
	WriteTxLookupEntriesByHash(db, block.NumberU64(), []common.Hash{txs[0].Hash()})
	for _, tx := range txs {
		hash, number, ok := ReadFHSFinalizedTxLookupEntry(db, tx.Hash())
		if !ok || hash != block.Hash() || number != block.NumberU64() {
			t.Fatalf("ordinary reindex erased finalized lookup %s", tx.Hash())
		}
	}
	if _, _, ok := ReadFHSFinalizedTxLookupEntry(db, common.HexToHash("0xdead")); ok {
		t.Fatal("unknown transaction has a finalized lookup")
	}
	ordinary := types.NewTransaction(2, common.Address{3}, big.NewInt(1), 21_000, big.NewInt(1), nil)
	WriteTxLookupEntries(db, types.NewBlockWithHeader(&types.Header{Number: big.NewInt(78)}).WithBody(types.Transactions{ordinary}, nil))
	if _, _, ok := ReadFHSFinalizedTxLookupEntry(db, ordinary.Hash()); ok {
		t.Fatal("ordinary number-only lookup was treated as finalized")
	}
	DeleteTxLookupEntry(db, txs[0].Hash())
	if _, _, ok := ReadFHSFinalizedTxLookupEntry(db, txs[0].Hash()); ok {
		t.Fatal("ordinary tx lookup pruning retained finalized marker")
	}
}
