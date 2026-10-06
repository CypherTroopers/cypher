package core

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/crypto"
)

func TestCommonRPCRecipientGenesisRestartsAndRejectsOldNetwork(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	defer db.Close()
	genesis := testFairHotstuffGenesis()
	_, current, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatal(err)
	}
	if _, restored, err := SetupGenesisBlock(db, nil); err != nil || restored != current {
		t.Fatalf("new network restart hash=%s error=%v, want %s", restored, err, current)
	}
	old := *genesis
	normalized := *genesis.Config
	normalized.RnetTransport = normalized.EffectiveRnetTransport()
	normalized.RnetFallbackTransport = normalized.EffectiveRnetFallbackTransport()
	encoded, err := json.Marshal(&normalized)
	if err != nil {
		t.Fatal(err)
	}
	old.Mixhash = crypto.Keccak256Hash([]byte("cypher-fhs-genesis-config-v2"), encoded)
	oldDB := rawdb.NewMemoryDatabase()
	defer oldDB.Close()
	if _, _, err := SetupGenesisBlock(oldDB, &old); err == nil || !strings.Contains(err.Error(), "mixHash") {
		t.Fatalf("old network genesis error = %v", err)
	}
	if rawdb.ReadCanonicalHash(oldDB, 0) != (common.Hash{}) {
		t.Fatal("rejected old network genesis was committed")
	}
	if _, _, err := SetupGenesisBlock(db, &old); err == nil {
		t.Fatal("old network replaced the restarted network genesis")
	}
	if rawdb.ReadCanonicalHash(db, 0) != current {
		t.Fatal("rejected old network changed the existing canonical genesis")
	}
}
