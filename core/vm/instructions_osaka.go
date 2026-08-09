package vm

// opCLZ implements EIP-7939. BitLen is zero for zero, making the result 256,
// and otherwise returns the position of the highest set bit in [1, 256].
func opCLZ(pc *uint64, interpreter *EVMInterpreter, callContext *callCtx) ([]byte, error) {
	value := callContext.stack.peek()
	value.SetUint64(uint64(256 - value.BitLen()))
	return nil, nil
}
