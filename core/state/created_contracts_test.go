package state

import (
	"testing"

	"github.com/cypherium/cypher/common"
)

func TestCreatedContractSnapshotRevert(t *testing.T) {
	s := newTestStateDB(t)
	addr := common.HexToAddress("0x100")

	snap := s.Snapshot()
	s.CreateContract(addr)
	if !s.CreatedContract(addr) {
		t.Fatal("expected created contract marker set")
	}
	s.RevertToSnapshot(snap)
	if s.CreatedContract(addr) {
		t.Fatal("expected created contract marker reverted")
	}
}

func TestCreatedContractClearedOnPrepare(t *testing.T) {
	s := newTestStateDB(t)
	addr := common.HexToAddress("0x200")
	s.CreateContract(addr)
	s.Prepare(common.HexToHash("0x1"), common.HexToHash("0x2"), 1)
	if s.CreatedContract(addr) {
		t.Fatal("expected created contract marker to be cleared on transaction boundary")
	}
}

func TestCreatedContractRevertPreservesPreviousMarker(t *testing.T) {
	s := newTestStateDB(t)
	addr := common.HexToAddress("0x300")

	s.CreateContract(addr)
	snap := s.Snapshot()
	s.CreateContract(addr)
	s.RevertToSnapshot(snap)
	if !s.CreatedContract(addr) {
		t.Fatal("expected pre-existing created contract marker to survive revert")
	}
}
