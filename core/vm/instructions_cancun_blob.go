package vm

import "github.com/holiman/uint256"

func opBlobHash(pc *uint64, interpreter *EVMInterpreter, callContext *callCtx) ([]byte, error) {
	index := callContext.stack.peek()
	// EIP-4844 takes a uint256 index. Values wider than uint64 are necessarily
	// out of range and must not alias a low index through truncation.
	if index.IsUint64() {
		idx := index.Uint64()
		index.Clear()
		if idx < uint64(len(interpreter.evm.BlobHashes)) {
			index.SetBytes(interpreter.evm.BlobHashes[idx].Bytes())
		}
	} else {
		index.Clear()
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
