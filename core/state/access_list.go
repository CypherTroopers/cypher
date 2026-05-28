package state

import (
	"sync"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

type accessListState struct {
	addresses map[common.Address]struct{}
	slots     map[common.Address]map[common.Hash]struct{}
}

var stateAccessLists sync.Map // map[*StateDB]*accessListState

func accessListFor(s *StateDB) *accessListState {
	if s == nil {
		return &accessListState{addresses: make(map[common.Address]struct{}), slots: make(map[common.Address]map[common.Hash]struct{})}
	}
	if existing, ok := stateAccessLists.Load(s); ok {
		return existing.(*accessListState)
	}
	created := &accessListState{
		addresses: make(map[common.Address]struct{}),
		slots:     make(map[common.Address]map[common.Hash]struct{}),
	}
	actual, _ := stateAccessLists.LoadOrStore(s, created)
	return actual.(*accessListState)
}

// PrepareAccessList initializes the Berlin access list for a transaction.
// Sender, destination and precompiles are considered warm, then the transaction
// access list is added. This is a scaffold for EIP-2929/2930 warm/cold gas rules.
func (s *StateDB) PrepareAccessList(sender common.Address, dst *common.Address, precompiles []common.Address, list types.AccessList) {
	al := &accessListState{
		addresses: make(map[common.Address]struct{}),
		slots:     make(map[common.Address]map[common.Hash]struct{}),
	}
	stateAccessLists.Store(s, al)
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
	al := accessListFor(s)
	al.addresses[addr] = struct{}{}
}

func (s *StateDB) AddSlotToAccessList(addr common.Address, slot common.Hash) {
	al := accessListFor(s)
	al.addresses[addr] = struct{}{}
	if al.slots[addr] == nil {
		al.slots[addr] = make(map[common.Hash]struct{})
	}
	al.slots[addr][slot] = struct{}{}
}

func (s *StateDB) AddressInAccessList(addr common.Address) bool {
	al := accessListFor(s)
	_, ok := al.addresses[addr]
	return ok
}

func (s *StateDB) SlotInAccessList(addr common.Address, slot common.Hash) (addressOk bool, slotOk bool) {
	al := accessListFor(s)
	_, addressOk = al.addresses[addr]
	if !addressOk {
		return false, false
	}
	_, slotOk = al.slots[addr][slot]
	return true, slotOk
}
