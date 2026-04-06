package miner

import cx "colossusx/colossusx"

type CPUBackend struct {
	spec    Spec
	view    contiguousDAGView
	scratch *pooledScratch
}

func (b *CPUBackend) Mode() BackendMode { return BackendCPU }
func (b *CPUBackend) Description() string {
	return "cpu backend with a prepared node table and shared core algorithm"
}
func (b *CPUBackend) Prepare(dag *DAG) error {
	if dag == nil {
		return ErrNilDAG
	}
	if b.scratch == nil {
		b.scratch = newPooledScratch()
	}
	b.spec = dag.Spec()
	b.view = contiguousDAGView{dag: dag}
	return nil
}
func (b *CPUBackend) Hash(header []byte, nonce cx.Nonce, dag *DAG) HashResult {
	if b.view.dag == nil && dag != nil {
		_ = b.Prepare(dag)
	}
	if b.view.dag == nil {
		return HashResult{}
	}
	s := b.scratch.acquire(len(header))
	defer b.scratch.release(s)
	return latticeHashWithAccessor(b.spec, header, nonce, b.view, s)
}

func (b *CPUBackend) HashBatch(header []byte, startNonce cx.Nonce, count uint64, dag *DAG) ([]HashResult, error) {
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
