package vm

import (
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/params"
)

// accessAddressGas returns the dynamic EIP-2929 account access cost and marks
// the address as warm. It is a no-op before Berlin.
func accessAddressGas(evm *EVM, addr common.Address) uint64 {
	if evm == nil || !evm.chainRules.IsBerlin {
		return 0
	}
	if evm.StateDB.AddressInAccessList(addr) {
		return params.WarmStorageReadCostEIP2929
	}
	evm.StateDB.AddAddressToAccessList(addr)
	return params.ColdAccountAccessCostEIP2929
}

// accessSlotGas returns the dynamic EIP-2929 storage slot access cost and marks
// the slot as warm. It is a no-op before Berlin.
func accessSlotGas(evm *EVM, addr common.Address, slot common.Hash) uint64 {
	if evm == nil || !evm.chainRules.IsBerlin {
		return 0
	}
	_, slotOk := evm.StateDB.SlotInAccessList(addr, slot)
	if slotOk {
		return params.WarmStorageReadCostEIP2929
	}
	evm.StateDB.AddSlotToAccessList(addr, slot)
	return params.ColdSloadCostEIP2929
}
