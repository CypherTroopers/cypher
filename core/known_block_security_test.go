package core

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
)

func TestResolveKnownBlockUsesPersistedHotstuffProof(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	stored := types.NewBlockWithHeader(&types.Header{
		ParentHash: common.HexToHash("0x01"),
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(1),
		GasLimit:   1,
	})
	stored.SetFHSSignature(
		[]byte("persisted-signature"), []byte{0x1f}, common.HexToHash("0x11"),
		"persisted-leader", 11, common.HexToHash("0xaa"), common.HexToHash("0xbb"),
	)
	rawdb.WriteBlock(db, stored)

	// SignInfo is intentionally excluded from Header.Hash. Model an incoming
	// same-hash block carrying different consensus metadata.
	forged := types.NewBlockWithHeader(stored.Header())
	forged.SetFHSSignature(
		[]byte("forged-signature"), []byte{0x03}, common.HexToHash("0x22"),
		"forged-leader", 99, common.HexToHash("0xcc"), common.HexToHash("0xdd"),
	)
	if forged.Hash() != stored.Hash() {
		t.Fatal("test fixture must keep the same block hash when only SignInfo changes")
	}

	bc := &BlockChain{db: db}
	resolved, err := bc.resolveKnownBlock(forged, false)
	if err != nil {
		t.Fatal(err)
	}
	got, want := resolved.SignInfo(), stored.SignInfo()
	if got.ViewNumber != want.ViewNumber || got.ViewID != want.ViewID || got.LeaderID != want.LeaderID ||
		got.ExtraHash != want.ExtraHash || got.ParentQCID != want.ParentQCID ||
		string(got.Signature) != string(want.Signature) || string(got.Exceptions) != string(want.Exceptions) {
		t.Fatalf("known block adopted incoming SignInfo: got %+v want persisted %+v", got, want)
	}
}

func TestResolveKnownBlockFailsClosedWhenDatabaseEntryIsMissing(t *testing.T) {
	bc := &BlockChain{db: rawdb.NewMemoryDatabase()}
	block := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1)})
	if _, err := bc.resolveKnownBlock(block, false); err == nil {
		t.Fatal("missing persisted known block was accepted")
	}
}
