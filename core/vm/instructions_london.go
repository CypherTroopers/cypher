package vm

import "github.com/holiman/uint256"

func opBaseFee(pc *uint64, interpreter *EVMInterpreter, callContext *callCtx) ([]byte, error) {
	if interpreter.evm.BaseFee == nil {
		callContext.stack.push(new(uint256.Int))
		return nil, nil
	}
	baseFee, overflow := uint256.FromBig(interpreter.evm.BaseFee)
	if overflow {
		baseFee = new(uint256.Int).SetAllOne()
	}
	callContext.stack.push(baseFee)
	return nil, nil
}
