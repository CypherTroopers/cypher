package vm

import "github.com/cypherium/cypher/common"

func opTload(pc *uint64, interpreter *EVMInterpreter, callContext *callCtx) ([]byte, error) {
	key := common.Hash(callContext.stack.peek().Bytes32())
	val := interpreter.evm.StateDB.GetTransientState(callContext.contract.Address(), key)
	callContext.stack.peek().SetBytes(val.Bytes())
	return nil, nil
}

func opTstore(pc *uint64, interpreter *EVMInterpreter, callContext *callCtx) ([]byte, error) {
	if interpreter.readOnly {
		return nil, ErrWriteProtection
	}
	loc := callContext.stack.pop()
	val := callContext.stack.pop()
	interpreter.evm.StateDB.SetTransientState(callContext.contract.Address(), common.Hash(loc.Bytes32()), common.Hash(val.Bytes32()))
	return nil, nil
}

func opMcopy(pc *uint64, interpreter *EVMInterpreter, callContext *callCtx) ([]byte, error) {
	var (
		dst    = callContext.stack.pop()
		src    = callContext.stack.pop()
		length = callContext.stack.pop()
	)
	if length.IsZero() {
		return nil, nil
	}
	copyData := callContext.memory.GetCopy(int64(src.Uint64()), int64(length.Uint64()))
	callContext.memory.Set(dst.Uint64(), length.Uint64(), copyData)
	return nil, nil
}
