package vm

// shanghaiInstructionSet extends London with EIP-3855 PUSH0.
var shanghaiInstructionSet = newShanghaiInstructionSet()

func newShanghaiInstructionSet() JumpTable {
	instructionSet := newLondonInstructionSet()
	instructionSet[PUSH0] = &operation{
		execute:     opPush0,
		constantGas: GasFastestStep,
		minStack:    minStack(0, 1),
		maxStack:    maxStack(0, 1),
	}
	return instructionSet
}
