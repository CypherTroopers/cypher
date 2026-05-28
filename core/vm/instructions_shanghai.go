package vm

import "github.com/holiman/uint256"

func opPush0(pc *uint64, interpreter *EVMInterpreter, callContext *callCtx) ([]byte, error) {
	callContext.stack.push(new(uint256.Int))
	return nil, nil
}
