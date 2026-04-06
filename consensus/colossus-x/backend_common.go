package miner

import (
	"errors"
	"sync"
	"unsafe"

	cx "colossusx/colossusx"
)

var ErrNilDAG = errors.New("backend requires a dag")

type hashScratch = cx.HashScratch

func newHashScratch(headerLen int) *hashScratch     { return cx.NewHashScratch(headerLen) }
func ensureSeedInput(s *hashScratch, headerLen int) { cx.EnsureSeedInput(s, headerLen, nil) }

func latticeHashWithAccessor(spec Spec, header []byte, nonce cx.Nonce, accessor cx.DAGAccessor, scratch *hashScratch) HashResult {
	return cx.LatticeHash(spec, header, nonce, accessor, scratch)
}

type contiguousDAGView struct{ dag *DAG }

func (v contiguousDAGView) NodeCount() uint64             { return v.dag.NodeCount() }
func (v contiguousDAGView) ReadNode(i uint64, out []byte) { v.dag.ReadNode(i, out) }

type rawContiguousDAGBuffer struct {
	Ptr       unsafe.Pointer
	Bytes     []byte
	ByteLen   uint64
	NodeSize  uint64
	NodeCount uint64
}

func newRawContiguousDAGBuffer(dag *DAG) (rawContiguousDAGBuffer, error) {
	if dag == nil {
		return rawContiguousDAGBuffer{}, ErrNilDAG
	}
	buf := dag.Bytes()
	if uint64(len(buf)) < dag.Spec().DAGSizeBytes {
		return rawContiguousDAGBuffer{}, errors.New("managed allocation is smaller than the DAG")
	}
	var ptr unsafe.Pointer
	if len(buf) > 0 {
		ptr = unsafe.Pointer(unsafe.SliceData(buf))
	}
	return rawContiguousDAGBuffer{
		Ptr:       ptr,
		Bytes:     buf[:dag.Spec().DAGSizeBytes],
		ByteLen:   dag.Spec().DAGSizeBytes,
		NodeSize:  dag.Spec().NodeSize,
		NodeCount: dag.NodeCount(),
	}, nil
}

// unifiedMemoryDAGView is the CPU reference hashing view for allocations that are
// already contiguous in host-visible memory; true GPU zero-copy/shared-memory paths
// use rawContiguousDAGBuffer directly instead.
type unifiedMemoryDAGView struct {
	buf       []byte
	nodeSize  uint64
	nodeCount uint64
}

func newUnifiedMemoryDAGViewFromBytes(spec Spec, buf []byte) (unifiedMemoryDAGView, error) {
	if uint64(len(buf)) < spec.DAGSizeBytes {
		return unifiedMemoryDAGView{}, errors.New("managed allocation is smaller than the DAG")
	}
	return unifiedMemoryDAGView{buf: buf[:spec.DAGSizeBytes], nodeSize: spec.NodeSize, nodeCount: spec.NodeCount()}, nil
}

func (v unifiedMemoryDAGView) NodeCount() uint64 { return v.nodeCount }
func (v unifiedMemoryDAGView) ReadNode(i uint64, out []byte) {
	off := i * v.nodeSize
	copy(out, v.buf[off:off+v.nodeSize])
}

type pooledScratch struct{ pool sync.Pool }

func newPooledScratch() *pooledScratch {
	return &pooledScratch{pool: sync.Pool{New: func() any { return newHashScratch(0) }}}
}

func (p *pooledScratch) acquire(headerLen int) *hashScratch {
	s := p.pool.Get().(*hashScratch)
	ensureSeedInput(s, headerLen)
	return s
}

func (p *pooledScratch) release(s *hashScratch) { p.pool.Put(s) }
