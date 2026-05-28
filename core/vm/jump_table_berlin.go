package vm

import (
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

func gasSStoreEIP2929(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	slot := common.Hash(stack.Back(0).Bytes32())
	_, slotWarm := evm.StateDB.SlotInAccessList(contract.Address(), slot)
	gas, err := gasSStoreEIP2200(evm, contract, stack, mem, memorySize)
	if err != nil {
		return 0, err
	}
	if !slotWarm {
		evm.StateDB.AddSlotToAccessList(contract.Address(), slot)
		return addUint64(gas, params.ColdSloadCostEIP2929)
	}
	return gas, nil
}

func gasCallEIP2929(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := gasCall(evm, contract, stack, mem, memorySize)
	if err != nil {
		return 0, err
	}
	return addUint64(gas, accessAddressGas(evm, stackAddress(stack, 1)))
}

func gasCallCodeEIP2929(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := gasCallCode(evm, contract, stack, mem, memorySize)
	if err != nil {
		return 0, err
	}
	return addUint64(gas, accessAddressGas(evm, stackAddress(stack, 1)))
}

func gasDelegateCallEIP2929(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := gasDelegateCall(evm, contract, stack, mem, memorySize)
	if err != nil {
		return 0, err
	}
	return addUint64(gas, accessAddressGas(evm, stackAddress(stack, 1)))
}

func gasStaticCallEIP2929(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := gasStaticCall(evm, contract, stack, mem, memorySize)
	if err != nil {
		return 0, err
	}
	return addUint64(gas, accessAddressGas(evm, stackAddress(stack, 1)))
}

func gasSelfdestructEIP2929(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := gasSelfdestruct(evm, contract, stack, mem, memorySize)
	if err != nil {
		return 0, err
	}
	return addUint64(gas, accessAddressGas(evm, stackAddress(stack, 0)))
}
