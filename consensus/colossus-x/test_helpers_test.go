package miner

import cx "colossusx/colossusx"

type fakeRuntimeState struct {
	cudaOrdinal int
	cudaOK      bool
	openclCtx   OpenCLContext
	openclOK    bool
}

func (r fakeRuntimeState) CUDADeviceOrdinal() (int, bool) { return r.cudaOrdinal, r.cudaOK }
func (r fakeRuntimeState) OpenCLContext() (OpenCLContext, bool) {
	return r.openclCtx, r.openclOK
}
func (r fakeRuntimeState) MetalContext() (MetalContext, bool) { return MetalContext{}, false }

type fakeGPUBackend struct {
	prepared      bool
	fallbackUsed  bool
	runtimeCalled bool
	scratch       *pooledScratch
}

func (b *fakeGPUBackend) Mode() BackendMode   { return BackendGPU }
func (b *fakeGPUBackend) Description() string { return "test gpu backend" }
func (b *fakeGPUBackend) InitializeRuntime() error {
	b.runtimeCalled = true
	return nil
}
func (b *fakeGPUBackend) CUDADeviceOrdinal() (int, bool)       { return 7, true }
func (b *fakeGPUBackend) OpenCLContext() (OpenCLContext, bool) { return OpenCLContext{}, false }
func (b *fakeGPUBackend) MetalContext() (MetalContext, bool)   { return MetalContext{}, false }
func (b *fakeGPUBackend) Prepare(dag *DAG) error {
	b.prepared = true
	if b.scratch == nil {
		b.scratch = newPooledScratch()
	}
	_, err := newRawContiguousDAGBuffer(dag)
	return err
}
func (b *fakeGPUBackend) Hash(header []byte, nonce cx.Nonce, dag *DAG) HashResult {
	s := b.scratch.acquire(len(header))
	defer b.scratch.release(s)
	view, _ := newUnifiedMemoryDAGViewFromBytes(dag.Spec(), dag.Bytes())
	return latticeHashWithAccessor(dag.Spec(), header, nonce, view, s)
}
func (b *fakeGPUBackend) HashBatch(header []byte, startNonce cx.Nonce, count uint64, dag *DAG) ([]HashResult, error) {
	results := make([]HashResult, 0, count)
	for i := uint64(0); i < count; i++ {
		nonce, ok := startNonce.AddUint64(i)
		if !ok {
			break
		}
		results = append(results, b.Hash(header, nonce, dag))
	}
	return results, nil
}
