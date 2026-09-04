package bftview

import (
	"bytes"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/rlp"
)

func TestEnsureCommitteeRLPReplacesCachedCommittee(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	SetCommitteeConfig(db, nil, nil)
	defer SetCommitteeConfig(nil, nil, nil)

	const keyNumber = uint64(100)
	keyHash := common.HexToHash("0x01")
	oldCommittee := &Committee{List: []*common.Cnode{{Address: "old", CoinBase: "old-coinbase", Public: "01"}}}
	newCommittee := &Committee{List: []*common.Cnode{{Address: "new", CoinBase: "new-coinbase", Public: "02"}}}
	oldRLP, err := rlp.EncodeToBytes(oldCommittee)
	if err != nil {
		t.Fatal(err)
	}
	newRLP, err := rlp.EncodeToBytes(newCommittee)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Put(rawdb.CommitteeKey(keyNumber, keyHash), oldRLP); err != nil {
		t.Fatal(err)
	}
	if loaded := LoadMember(keyNumber, keyHash, false); loaded == nil || loaded.List[0].Address != "old" {
		t.Fatalf("old committee was not cached: %#v", loaded)
	}

	changed, err := EnsureCommitteeRLP(keyNumber, keyHash, newRLP)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("replacement did not report a change")
	}
	loaded := LoadMember(keyNumber, keyHash, false)
	if loaded == nil || loaded.List[0].Address != "new" {
		t.Fatalf("stale committee remained cached: %#v", loaded)
	}
	persisted, err := db.Get(rawdb.CommitteeKey(keyNumber, keyHash))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(persisted, newRLP) {
		t.Fatal("replacement RLP was not persisted exactly")
	}

	changed, err = EnsureCommitteeRLP(keyNumber, keyHash, newRLP)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("idempotent replacement reported a change")
	}

	oldCommittee.storeInCache(keyHash, keyNumber, true)
	changed, err = EnsureCommitteeRLP(keyNumber, keyHash, newRLP)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("stale cache was not detected")
	}
	loaded = LoadMember(keyNumber, keyHash, false)
	if loaded == nil || loaded.List[0].Address != "new" {
		t.Fatalf("stale cache was not evicted: %#v", loaded)
	}
}
