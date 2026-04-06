package miner

import (
	"fmt"

	cx "colossusx/colossusx"
)

type UnifiedBackend struct {
	spec               Spec
	shared             unifiedMemoryDAGView
	scratch            *pooledScratch
	strategyName       string
	runtimeProbed      bool
	cudaDeviceOrdinal  int
	cudaAvailable      bool
	openclContext      OpenCLContext
	openclSVMAvailable bool
}

func (b *UnifiedBackend) Mode() BackendMode { return BackendUnified }

func (b *UnifiedBackend) Description() string {
	name := b.strategyName
	if name == "" {
		name = "go-heap"
	}
	return fmt.Sprintf("unified-memory-compatible backend (dag-allocation=%s)", name)
}

func (b *UnifiedBackend) Prepare(dag *DAG) error {
	if dag == nil {
		return ErrNilDAG
	}
	shared, err := newUnifiedMemoryDAGViewFromBytes(dag.Spec(), dag.Bytes())
	if err != nil {
		return err
	}
	b.spec = dag.Spec()
	b.shared = shared
	if named := dag.AllocationName(); named != "" {
		b.strategyName = named
	}
	if b.scratch == nil {
		b.scratch = newPooledScratch()
	}
	return nil
}

func (b *UnifiedBackend) Hash(header []byte, nonce cx.Nonce, dag *DAG) HashResult {
	if b.shared.NodeCount() == 0 {
		if err := b.Prepare(dag); err != nil {
			return HashResult{}
		}
	}
	s := b.scratch.acquire(len(header))
	defer b.scratch.release(s)
	return latticeHashWithAccessor(b.spec, header, nonce, b.shared, s)
}

func (b *UnifiedBackend) HashBatch(header []byte, startNonce cx.Nonce, count uint64, dag *DAG) ([]HashResult, error) {
	if b.shared.NodeCount() == 0 {
		if err := b.Prepare(dag); err != nil {
			return nil, err
		}
	}
	results := make([]HashResult, count)
	for i := uint64(0); i < count; i++ {
		nonce, ok := startNonce.AddUint64(i)
		if !ok {
			return results[:i], nil
		}
		results[i] = b.Hash(header, nonce, dag)
	}
	return results, nil
}
