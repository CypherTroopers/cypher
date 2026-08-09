package vm

import (
	"errors"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/math"
	"github.com/cypherium/cypher/params"
)

// berlinInstructionSet extends Istanbul with EIP-2929 warm/cold access gas.
var berlinInstructionSet = newBerlinInstructionSet()

func newBerlinInstructionSet() JumpTable {
	instructionSet := newIstanbulInstructionSet()

	instructionSet[BALANCE].constantGas = 0
	instructionSet[BALANCE].dynamicGas = gasBalanceEIP2929

	instructionSet[EXTCODESIZE].constantGas = 0
	instructionSet[EXTCODESIZE].dynamicGas = gasExtCodeSizeEIP2929

	instructionSet[EXTCODECOPY].constantGas = 0
	instructionSet[EXTCODECOPY].dynamicGas = gasExtCodeCopyEIP2929

	instructionSet[EXTCODEHASH].constantGas = 0
	instructionSet[EXTCODEHASH].dynamicGas = gasExtCodeHashEIP2929

	instructionSet[SLOAD].constantGas = 0
	instructionSet[SLOAD].dynamicGas = gasSLoadEIP2929

	instructionSet[SSTORE].dynamicGas = gasSStoreEIP2929

	instructionSet[CALL].constantGas = 0
	instructionSet[CALL].dynamicGas = gasCallEIP2929

	instructionSet[CALLCODE].constantGas = 0
	instructionSet[CALLCODE].dynamicGas = gasCallCodeEIP2929

	instructionSet[DELEGATECALL].constantGas = 0
	instructionSet[DELEGATECALL].dynamicGas = gasDelegateCallEIP2929

	instructionSet[STATICCALL].constantGas = 0
	instructionSet[STATICCALL].dynamicGas = gasStaticCallEIP2929

	instructionSet[SELFDESTRUCT].dynamicGas = gasSelfdestructEIP2929

	return instructionSet
}

func addUint64(a, b uint64) (uint64, error) {
	out, overflow := math.SafeAdd(a, b)
	if overflow {
		return 0, ErrGasUintOverflow
	}
	return out, nil
}

func stackAddress(stack *Stack, pos int) common.Address {
	return common.Address(stack.Back(pos).Bytes20())
}

func gasBalanceEIP2929(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return accessAddressGas(evm, stackAddress(stack, 0)), nil
}

func gasExtCodeSizeEIP2929(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return accessAddressGas(evm, stackAddress(stack, 0)), nil
}

func gasExtCodeHashEIP2929(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return accessAddressGas(evm, stackAddress(stack, 0)), nil
}

func gasExtCodeCopyEIP2929(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := gasExtCodeCopy(evm, contract, stack, mem, memorySize)
	if err != nil {
		return 0, err
	}
	return addUint64(gas, accessAddressGas(evm, stackAddress(stack, 0)))
}

func gasSLoadEIP2929(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	slot := stack.Back(0).Bytes32()
	return accessSlotGas(evm, contract.Address(), slot), nil
}

func makeGasSStoreEIP2929(clearingRefund uint64) gasFunc {
	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		if contract.Gas <= params.SstoreSentryGasEIP2200 {
			return 0, errors.New("not enough gas for reentrancy sentry")
		}
		var cost uint64
		slot := common.Hash(stack.Back(0).Bytes32())
		_, slotWarm := evm.StateDB.SlotInAccessList(contract.Address(), slot)
		if !slotWarm {
			evm.StateDB.AddSlotToAccessList(contract.Address(), slot)
			cost = params.ColdSloadCostEIP2929
		}
		current := evm.StateDB.GetState(contract.Address(), slot)
		value := common.Hash(stack.Back(1).Bytes32())
		if current == value {
			return addUint64(cost, params.WarmStorageReadCostEIP2929)
		}
		original := evm.StateDB.GetCommittedState(contract.Address(), slot)
		if original == current {
			if original == (common.Hash{}) {
				return addUint64(cost, params.SstoreInitGasEIP2200)
			}
			if value == (common.Hash{}) {
				evm.StateDB.AddRefund(clearingRefund)
			}
			return addUint64(cost, params.SstoreCleanGasEIP2200-params.ColdSloadCostEIP2929)
		}
		if original != (common.Hash{}) {
			if current == (common.Hash{}) {
				evm.StateDB.SubRefund(clearingRefund)
			} else if value == (common.Hash{}) {
				evm.StateDB.AddRefund(clearingRefund)
			}
		}
		if original == value {
			if original == (common.Hash{}) {
				evm.StateDB.AddRefund(params.SstoreInitGasEIP2200 - params.WarmStorageReadCostEIP2929)
			} else {
				evm.StateDB.AddRefund(params.SstoreCleanGasEIP2200 - params.ColdSloadCostEIP2929 - params.WarmStorageReadCostEIP2929)
			}
		}
		return addUint64(cost, params.WarmStorageReadCostEIP2929)
	}
}

var (
	gasSStoreEIP2929 = makeGasSStoreEIP2929(params.SstoreClearRefundEIP2200)
	gasSStoreEIP3529 = makeGasSStoreEIP2929(params.SstoreClearsScheduleRefundEIP3529)
)

// makeCallVariantGasEIP2929 charges the warm/cold account access before the
// legacy CALL calculator applies EIP-150's 63/64 rule. The Berlin jump table in
// this codebase has zero constant gas for CALL variants, so the entire access
// cost is charged here, temporarily, and restored into the dynamic result.
// Charging it after oldCalculator would give the callee too much gas on cold
// calls and diverge from EIP-2929.
func makeCallVariantGasEIP2929(oldCalculator gasFunc) gasFunc {
	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		accessGas := accessAddressGas(evm, stackAddress(stack, 1))
		if !contract.UseGas(accessGas) {
			return 0, ErrOutOfGas
		}
		gas, err := oldCalculator(evm, contract, stack, mem, memorySize)
		if err != nil {
			return gas, err
		}
		contract.Gas += accessGas
		return addUint64(gas, accessGas)
	}
}

var (
	gasCallEIP2929         = makeCallVariantGasEIP2929(gasCall)
	gasCallCodeEIP2929     = makeCallVariantGasEIP2929(gasCallCode)
	gasDelegateCallEIP2929 = makeCallVariantGasEIP2929(gasDelegateCall)
	gasStaticCallEIP2929   = makeCallVariantGasEIP2929(gasStaticCall)
)

func gasSelfdestructEIP2929(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := gasSelfdestruct(evm, contract, stack, mem, memorySize)
	if err != nil {
		return 0, err
	}
	address := stackAddress(stack, 0)
	if evm.StateDB.AddressInAccessList(address) {
		return gas, nil
	}
	evm.StateDB.AddAddressToAccessList(address)
	return addUint64(gas, params.ColdAccountAccessCostEIP2929)
}
