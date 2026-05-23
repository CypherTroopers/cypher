package vm

import "github.com/holiman/uint256"

func opBlobHash(pc *uint64, interpreter *EVMInterpreter, callContext *callCtx) ([]byte, error) {
	idx := callContext.stack.peek().Uint64()
	callContext.stack.peek().Clear()
	if idx < uint64(len(interpreter.evm.BlobHashes)) {
		callContext.stack.peek().SetBytes(interpreter.evm.BlobHashes[idx].Bytes())
	}
	return nil, nil
}

func opBlobBaseFee(pc *uint64, interpreter *EVMInterpreter, callContext *callCtx) ([]byte, error) {
	if interpreter.evm.BlobBaseFee == nil {
		callContext.stack.push(new(uint256.Int))
		return nil, nil
	}
	blobBaseFee, overflow := uint256.FromBig(interpreter.evm.BlobBaseFee)
	if overflow {
		blobBaseFee = new(uint256.Int).SetAllOne()
	}
	callContext.stack.push(blobBaseFee)
	return nil, nil
}
