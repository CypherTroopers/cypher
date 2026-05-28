package vm

// cancunInstructionSet extends Shanghai with Cancun opcodes.
var cancunInstructionSet = newCancunInstructionSet()

func newCancunInstructionSet() JumpTable {
	instructionSet := newShanghaiInstructionSet()
	instructionSet[BLOBHASH] = &operation{
		execute:     opBlobHash,
		constantGas: GasFastestStep,
		minStack:    minStack(1, 1),
		maxStack:    maxStack(1, 1),
	}
	instructionSet[BLOBBASEFEE] = &operation{
		execute:     opBlobBaseFee,
		constantGas: GasQuickStep,
		minStack:    minStack(0, 1),
		maxStack:    maxStack(0, 1),
	}
	instructionSet[MCOPY] = &operation{
		execute:     opMcopy,
		constantGas: GasFastestStep,
		dynamicGas:  gasMcopy,
		minStack:    minStack(3, 0),
		maxStack:    maxStack(3, 0),
		memorySize:  memoryMcopy,
	}
	instructionSet[TLOAD] = &operation{
		execute:     opTload,
		constantGas: 100,
		minStack:    minStack(1, 1),
		maxStack:    maxStack(1, 1),
	}
	instructionSet[TSTORE] = &operation{
		execute:     opTstore,
		constantGas: 100,
		minStack:    minStack(2, 0),
		maxStack:    maxStack(2, 0),
		writes:      true,
	}
	return instructionSet
}

func gasMcopy(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return memoryCopierGas(2)(evm, contract, stack, mem, memorySize)
}

func memoryMcopy(stack *Stack) (uint64, bool) {
	return calcMemSize64(stack.Back(0), stack.Back(2))
}
