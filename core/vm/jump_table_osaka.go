package vm

// osakaInstructionSet extends Prague with EIP-7939 CLZ.
var osakaInstructionSet = newOsakaInstructionSet()

func newOsakaInstructionSet() JumpTable {
	instructionSet := newPragueInstructionSet()
	instructionSet[CLZ] = &operation{
		execute:     opCLZ,
		constantGas: GasFastStep,
		minStack:    minStack(1, 1),
		maxStack:    maxStack(1, 1),
	}
	return instructionSet
}
