package vm

// shanghaiInstructionSet extends London with EIP-3855 PUSH0 and EIP-3860
// initcode metering.
var shanghaiInstructionSet = newShanghaiInstructionSet()

func newShanghaiInstructionSet() JumpTable {
	instructionSet := newLondonInstructionSet()
	instructionSet[PUSH0] = &operation{
		execute:     opPush0,
		constantGas: GasFastestStep,
		minStack:    minStack(0, 1),
		maxStack:    maxStack(0, 1),
	}
	instructionSet[CREATE].dynamicGas = gasCreateEIP3860
	instructionSet[CREATE2].dynamicGas = gasCreate2EIP3860
	return instructionSet
}
