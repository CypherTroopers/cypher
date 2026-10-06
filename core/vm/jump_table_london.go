package vm

// londonInstructionSet extends Berlin with EIP-3198 BASEFEE.
var londonInstructionSet = newLondonInstructionSet()

func newLondonInstructionSet() JumpTable {
	instructionSet := newBerlinInstructionSet()
	instructionSet[SSTORE].dynamicGas = gasSStoreEIP3529
	instructionSet[BASEFEE] = &operation{
		execute:     opBaseFee,
		constantGas: GasQuickStep,
		minStack:    minStack(0, 1),
		maxStack:    maxStack(0, 1),
	}
	return instructionSet
}
