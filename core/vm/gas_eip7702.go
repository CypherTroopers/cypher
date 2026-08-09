package vm

import (
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

var (
	gasCallEIP7702         = makeCallVariantGasEIP7702(gasCall)
	gasCallCodeEIP7702     = makeCallVariantGasEIP7702(gasCallCode)
	gasDelegateCallEIP7702 = makeCallVariantGasEIP7702(gasDelegateCall)
	gasStaticCallEIP7702   = makeCallVariantGasEIP7702(gasStaticCall)
)

func eip7702AccessCost(evm *EVM, addr common.Address) uint64 {
	if evm.StateDB.AddressInAccessList(addr) {
		return params.WarmStorageReadCostEIP2929
	}
	evm.StateDB.AddAddressToAccessList(addr)
	return params.ColdAccountAccessCostEIP2929
}

// makeCallVariantGasEIP7702 charges both the called account and a delegation
// target before computing EIP-150's 63/64 forwarded-gas limit. The local Berlin
// jump table uses zero constant gas for CALL variants, so this wrapper charges
// the full warm/cold access amount rather than only cold-minus-warm.
func makeCallVariantGasEIP7702(oldCalculator gasFunc) gasFunc {
	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		addr := stackAddress(stack, 1)
		total := eip7702AccessCost(evm, addr)
		if !contract.UseGas(total) {
			return 0, ErrOutOfGas
		}
		if target, ok := types.ParseDelegation(evm.StateDB.GetCode(addr)); ok {
			cost := eip7702AccessCost(evm, target)
			if !contract.UseGas(cost) {
				return 0, ErrOutOfGas
			}
			var err error
			total, err = addUint64(total, cost)
			if err != nil {
				return 0, err
			}
		}
		gas, err := oldCalculator(evm, contract, stack, mem, memorySize)
		if err != nil {
			return gas, err
		}
		// The interpreter charges the returned dynamic gas. Restore the access
		// cost deducted above after it has influenced forwarded-gas calculation.
		contract.Gas += total
		return addUint64(gas, total)
	}
}
