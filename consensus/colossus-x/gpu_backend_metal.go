package miner

import (
	"fmt"

	cx "colossusx/colossusx"
)

type MetalBackend struct{}

func NewMetalBackend() (HashBackend, error) { return &MetalBackend{}, nil }
func (b *MetalBackend) Mode() BackendMode   { return BackendMetal }
func (b *MetalBackend) Description() string {
	return "metal backend requiring shared-memory device execution for colossusx-v2"
}
func (b *MetalBackend) InitializeRuntime() error             { return nil }
func (b *MetalBackend) CUDADeviceOrdinal() (int, bool)       { return 0, false }
func (b *MetalBackend) OpenCLContext() (OpenCLContext, bool) { return OpenCLContext{}, false }
func (b *MetalBackend) MetalContext() (MetalContext, bool) {
	return MetalContext{Device: struct{}{}}, true
}
func (b *MetalBackend) Prepare(dag *DAG) error {
	if dag.Spec().Mode == cx.ModeColossusX && dag.AllocationName() != "metal-shared" {
		return fmt.Errorf("colossusx metal backend requires metal-shared DAG allocation")
	}
	return nil
}
func (b *MetalBackend) Hash(header []byte, nonce cx.Nonce, dag *DAG) HashResult {
	return cx.ColossusXHash(dag.Spec(), header, nonce, dag)
}
func (b *MetalBackend) HashBatch(header []byte, startNonce cx.Nonce, count uint64, dag *DAG) ([]HashResult, error) {
	out := make([]HashResult, 0, count)
	for i := uint64(0); i < count; i++ {
		n, _ := startNonce.AddUint64(i)
		out = append(out, b.Hash(header, n, dag))
	}
	return out, nil
}
