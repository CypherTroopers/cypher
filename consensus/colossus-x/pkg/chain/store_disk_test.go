package chain

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"

	cx "colossusx/colossusx"
	"colossusx/pkg/types"
)

func TestDiskStorePersistsBlocksAndTip(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDiskStore(dir)
	if err != nil {
		t.Fatalf("new disk store: %v", err)
	}
	target, err := cx.ParseTargetHex("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	block := types.NewGenesisBlock(types.GenesisConfig{
		ChainID:   "testnet",
		Message:   "genesis",
		Timestamp: 1,
		Bits:      target,
		Spec:      cx.ColossusXSpecWithGrowth(8*1024*1024, cx.DefaultDAGGrowthBytesPerEpoch),
	})
	work := big.NewInt(123)
	if err := store.StoreBlock(block, work); err != nil {
		t.Fatalf("store block: %v", err)
	}
	if err := store.SetCurrentTip(block.BlockHash()); err != nil {
		t.Fatalf("set tip: %v", err)
	}

	reopened, err := NewDiskStore(dir)
	if err != nil {
		t.Fatalf("reopen disk store: %v", err)
	}
	loaded, loadedWork, err := reopened.CurrentTip()
	if err != nil {
		t.Fatalf("current tip: %v", err)
	}
	if loaded.BlockHash() != block.BlockHash() {
		t.Fatalf("wrong tip hash: got %s want %s", loaded.BlockHash(), block.BlockHash())
	}
	if loadedWork.Cmp(work) != 0 {
		t.Fatalf("wrong total work: got %s want %s", loadedWork, work)
	}
}

func TestDiskStoreMigratesLegacySnapshot(t *testing.T) {
	dir := t.TempDir()
	target, err := cx.ParseTargetHex("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	block := types.NewGenesisBlock(types.GenesisConfig{
		ChainID:   "legacy",
		Message:   "legacy-genesis",
		Timestamp: 1,
		Bits:      target,
		Spec:      cx.ColossusXSpecWithGrowth(8*1024*1024, cx.DefaultDAGGrowthBytesPerEpoch),
	})
	hash := block.BlockHash()
	snapshot := diskSnapshot{
		GenesisHash: hash.String(),
		CurrentTip:  hash.String(),
		Blocks:      []diskBlockRecord{{Hash: hash.String(), Block: block}},
		Heights:     map[string]string{"0": hash.String()},
		TotalWork:   map[string]string{hash.String(): "321"},
	}
	data, err := marshalSnapshot(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "chain.json"), data, 0o644); err != nil {
		t.Fatalf("write legacy chain: %v", err)
	}

	store, err := NewDiskStore(dir)
	if err != nil {
		t.Fatalf("new disk store with migration: %v", err)
	}
	loaded, work, err := store.CurrentTip()
	if err != nil {
		t.Fatalf("current tip: %v", err)
	}
	if loaded.BlockHash() != hash {
		t.Fatalf("wrong tip hash: got %s want %s", loaded.BlockHash(), hash)
	}
	if work.String() != "321" {
		t.Fatalf("wrong total work: got %s want 321", work.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "chain_meta.json")); err != nil {
		t.Fatalf("expected metadata file: %v", err)
	}
}
