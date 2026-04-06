package miner

import cx "colossusx/colossusx"

type openCLSharedAllocationKernel interface {
	HashBatchOpenCL(ctx OpenCLContext, spec Spec, header []byte, startNonce cx.Nonce, count uint64, dag rawContiguousDAGBuffer) ([]HashResult, error)
}
