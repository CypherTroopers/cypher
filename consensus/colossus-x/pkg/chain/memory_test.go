package chain

import (
	"math/big"
	"testing"

	"colossusx/pkg/types"
)

func TestMemoryStoreRoundTrip(t *testing.T) {
	store := NewMemoryStore()
	block := types.Block{Header: types.BlockHeader{Height: 0}}
	if err := store.StoreBlock(block, big.NewInt(1)); err != nil {
		t.Fatal(err)
	}
	if !store.HasBlock(block.BlockHash()) {
		t.Fatalf("expected stored block")
	}
	if _, _, err := store.CurrentTip(); err != nil {
		t.Fatal(err)
	}
}
