package state

import (
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
)

func newTestStateDB(t *testing.T) *StateDB {
	t.Helper()
	s, err := New(common.Hash{}, NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("new statedb: %v", err)
	}
	return s
}

func TestTransientStorageSetGetAndRevert(t *testing.T) {
	s := newTestStateDB(t)
	addr := common.HexToAddress("0x1234")
	key := common.HexToHash("0x01")
	val1 := common.HexToHash("0xaa")
	val2 := common.HexToHash("0xbb")

	if got := s.GetTransientState(addr, key); got != (common.Hash{}) {
		t.Fatalf("expected zero before set, got %x", got)
	}
	s.SetTransientState(addr, key, val1)
	if got := s.GetTransientState(addr, key); got != val1 {
		t.Fatalf("expected %x, got %x", val1, got)
	}
	snap := s.Snapshot()
	s.SetTransientState(addr, key, val2)
	s.RevertToSnapshot(snap)
	if got := s.GetTransientState(addr, key); got != val1 {
		t.Fatalf("expected %x after revert, got %x", val1, got)
	}
}

func TestTransientStorageClearedOnPrepare(t *testing.T) {
	s := newTestStateDB(t)
	addr := common.HexToAddress("0x1234")
	key := common.HexToHash("0x01")
	val := common.HexToHash("0xaa")

	s.SetTransientState(addr, key, val)
	s.Prepare(common.HexToHash("0x1"), common.HexToHash("0x2"), 0)
	if got := s.GetTransientState(addr, key); got != (common.Hash{}) {
		t.Fatalf("expected transient storage to be cleared between txs, got %x", got)
	}
}
