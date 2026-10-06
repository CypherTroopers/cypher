package core

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
)

func TestGenesisRejectsRetiredNativeTransactionFlag(t *testing.T) {
	blob, err := os.ReadFile("../genesis.json")
	if err != nil {
		t.Fatalf("read genesis: %v", err)
	}
	var genesis Genesis
	if err := json.Unmarshal(blob, &genesis); err != nil {
		t.Fatalf("decode genesis: %v", err)
	}
	// Even a programmatically constructed config cannot revive the retired
	// NativeTx consensus mode.
	genesis.Config.NativeParallel.RequireNativeTransactions = true
	empty := common.HexToAddress("0x000000000000000000000000000000000000cafe")
	genesis.Alloc[empty] = GenesisAccount{
		Storage: map[common.Hash]common.Hash{{1}: {}},
	}
	_, err = genesis.Commit(rawdb.NewMemoryDatabase())
	if err == nil || !strings.Contains(err.Error(), "types 0 through 4") {
		t.Fatalf("commit error = %v, want retired NativeTx flag rejection", err)
	}
}
