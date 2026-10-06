package vm

// pragueInstructionSet extends Cancun. Prague does not add an opcode; its EVM
// changes are exposed through transaction processing, system calls and
// precompiled contracts.
var pragueInstructionSet = newPragueInstructionSet()

func newPragueInstructionSet() JumpTable {
	instructionSet := newCancunInstructionSet()
	instructionSet[CALL].dynamicGas = gasCallEIP7702
	instructionSet[CALLCODE].dynamicGas = gasCallCodeEIP7702
	instructionSet[DELEGATECALL].dynamicGas = gasDelegateCallEIP7702
	instructionSet[STATICCALL].dynamicGas = gasStaticCallEIP7702
	return instructionSet
}
