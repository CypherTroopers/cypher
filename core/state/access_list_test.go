package state

import (
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

func TestAccessListSnapshotRevert(t *testing.T) {
	s := newTestStateDB(t)
	sender := common.HexToAddress("0x100")
	destination := common.HexToAddress("0x200")
	precompile := common.HexToAddress("0x300")
	listed := common.HexToAddress("0x400")
	listedSlot := common.HexToHash("0x01")
	s.PrepareAccessList(sender, &destination, []common.Address{precompile}, types.AccessList{{
		Address:     listed,
		StorageKeys: []common.Hash{listedSlot},
	}})

	snap := s.Snapshot()
	added := common.HexToAddress("0x500")
	addedSlot := common.HexToHash("0x02")
	newListedSlot := common.HexToHash("0x03")
	s.AddAddressToAccessList(added)
	s.AddSlotToAccessList(added, addedSlot)
	s.AddSlotToAccessList(listed, newListedSlot)
	s.RevertToSnapshot(snap)

	for _, addr := range []common.Address{sender, destination, precompile, listed} {
		if !s.AddressInAccessList(addr) {
			t.Fatalf("initial warm address %s was reverted", addr)
		}
	}
	if s.AddressInAccessList(added) {
		t.Fatalf("reverted address %s remains warm", added)
	}
	if _, warm := s.SlotInAccessList(added, addedSlot); warm {
		t.Fatal("reverted slot remains warm")
	}
	if _, warm := s.SlotInAccessList(listed, newListedSlot); warm {
		t.Fatal("slot added after snapshot remains warm")
	}
	if _, warm := s.SlotInAccessList(listed, listedSlot); !warm {
		t.Fatal("initial access-list slot was reverted")
	}
}

func TestAccessListCopyIsIndependent(t *testing.T) {
	s := newTestStateDB(t)
	addr := common.HexToAddress("0x100")
	slot := common.HexToHash("0x01")
	s.PrepareAccessList(addr, nil, nil, nil)

	cpy := s.Copy()
	cpy.AddSlotToAccessList(addr, slot)
	if _, warm := s.SlotInAccessList(addr, slot); warm {
		t.Fatal("access-list slot leaked from StateDB copy")
	}
	if _, warm := cpy.SlotInAccessList(addr, slot); !warm {
		t.Fatal("copied StateDB did not retain its own access-list mutation")
	}
}
