package state

import "github.com/cypherium/cypher/common"

type transientStorage map[common.Address]map[common.Hash]common.Hash

func newTransientStorage() transientStorage {
	return make(transientStorage)
}

func (t transientStorage) Set(addr common.Address, key, value common.Hash) {
	if value == (common.Hash{}) {
		if slots, ok := t[addr]; ok {
			delete(slots, key)
			if len(slots) == 0 {
				delete(t, addr)
			}
		}
		return
	}
	slots := t[addr]
	if slots == nil {
		slots = make(map[common.Hash]common.Hash)
		t[addr] = slots
	}
	slots[key] = value
}

func (t transientStorage) Get(addr common.Address, key common.Hash) common.Hash {
	if slots, ok := t[addr]; ok {
		return slots[key]
	}
	return common.Hash{}
}
