package state

import (
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

type accessListState struct {
	addresses map[common.Address]struct{}
	slots     map[common.Address]map[common.Hash]struct{}
}

func newAccessListState() *accessListState {
	return &accessListState{
		addresses: make(map[common.Address]struct{}),
		slots:     make(map[common.Address]map[common.Hash]struct{}),
	}
}

func (al *accessListState) copy() *accessListState {
	cpy := newAccessListState()
	for addr := range al.addresses {
		cpy.addresses[addr] = struct{}{}
	}
	for addr, slots := range al.slots {
		cpy.slots[addr] = make(map[common.Hash]struct{}, len(slots))
		for slot := range slots {
			cpy.slots[addr][slot] = struct{}{}
		}
	}
	return cpy
}

// PrepareAccessList initializes the Berlin access list for a transaction.
// Sender, destination and precompiles are considered warm, then the transaction
// access list is added. This is a scaffold for EIP-2929/2930 warm/cold gas rules.
func (s *StateDB) PrepareAccessList(sender common.Address, dst *common.Address, precompiles []common.Address, list types.AccessList) {
	s.accessList = newAccessListState()
	s.AddAddressToAccessList(sender)
	if dst != nil {
		s.AddAddressToAccessList(*dst)
	}
	for _, addr := range precompiles {
		s.AddAddressToAccessList(addr)
	}
	for _, tuple := range list {
		s.AddAddressToAccessList(tuple.Address)
		for _, slot := range tuple.StorageKeys {
			s.AddSlotToAccessList(tuple.Address, slot)
		}
	}
}

func (s *StateDB) AddAddressToAccessList(addr common.Address) {
	if s.accessList == nil {
		s.accessList = newAccessListState()
	}
	if _, present := s.accessList.addresses[addr]; present {
		return
	}
	s.journal.append(accessListAddAccountChange{address: addr})
	s.accessList.addresses[addr] = struct{}{}
}

func (s *StateDB) AddSlotToAccessList(addr common.Address, slot common.Hash) {
	if s.accessList == nil {
		s.accessList = newAccessListState()
	}
	if _, present := s.accessList.addresses[addr]; !present {
		s.journal.append(accessListAddAccountChange{address: addr})
		s.accessList.addresses[addr] = struct{}{}
	}
	if s.accessList.slots[addr] == nil {
		s.accessList.slots[addr] = make(map[common.Hash]struct{})
	}
	if _, present := s.accessList.slots[addr][slot]; present {
		return
	}
	s.journal.append(accessListAddSlotChange{address: addr, slot: slot})
	s.accessList.slots[addr][slot] = struct{}{}
}

func (s *StateDB) AddressInAccessList(addr common.Address) bool {
	if s.accessList == nil {
		return false
	}
	_, ok := s.accessList.addresses[addr]
	return ok
}

func (s *StateDB) SlotInAccessList(addr common.Address, slot common.Hash) (addressOk bool, slotOk bool) {
	if s.accessList == nil {
		return false, false
	}
	_, addressOk = s.accessList.addresses[addr]
	if !addressOk {
		return false, false
	}
	_, slotOk = s.accessList.slots[addr][slot]
	return true, slotOk
}
