package miner

import (
	"encoding/binary"

	cx "colossusx/colossusx"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/sha3"
)

type sharedDAGHashKernel interface {
	HashBatchShared(header []byte, startNonce cx.Nonce, count uint64, dag rawContiguousDAGBuffer) ([]HashResult, error)
}

type rawDAGAccessor struct{ dag rawContiguousDAGBuffer }

func (v rawDAGAccessor) NodeCount() uint64 { return v.dag.NodeCount }
func (v rawDAGAccessor) ReadNode(i uint64, out []byte) {
	off := i * v.dag.NodeSize
	copy(out, v.dag.Bytes[off:off+v.dag.NodeSize])
}

// hostReferenceSharedDAGKernel is the validation/reference implementation for
// hashing directly from the canonical contiguous DAG allocation on the host CPU.
// It intentionally does not represent accelerator/device-kernel execution.
type hostReferenceSharedDAGKernel struct {
	spec Spec
}

func newHostReferenceSharedDAGKernel(spec Spec, _ *pooledScratch) *hostReferenceSharedDAGKernel {
	return &hostReferenceSharedDAGKernel{spec: spec}
}

func (k *hostReferenceSharedDAGKernel) HashBatchShared(header []byte, startNonce cx.Nonce, count uint64, dag rawContiguousDAGBuffer) ([]HashResult, error) {
	results := make([]HashResult, 0, count)
	for i := uint64(0); i < count; i++ {
		nonce, ok := startNonce.AddUint64(i)
		if !ok {
			break
		}
		results = append(results, latticeHashSharedBuffer(k.spec, header, nonce, dag))
	}
	return results, nil
}

func latticeHashSharedBuffer(spec Spec, header []byte, nonce cx.Nonce, dag rawContiguousDAGBuffer) HashResult {
	if spec.AlgorithmVersion >= 2 {
		return cx.ColossusXHash(spec, header, nonce, rawDAGAccessor{dag: dag})
	}
	var out HashResult
	if dag.NodeCount == 0 || dag.NodeSize == 0 || dag.ByteLen == 0 {
		return out
	}
	seedInput := make([]byte, 0, len(header)+32)
	seedInput = append(seedInput, header...)
	if nonce != nil {
		seedInput = nonce.AppendTo(seedInput)
	}
	seed512 := sha3.Sum512(seedInput)

	var mix [32]byte
	copy(mix[:], seed512[:32])
	var fnvInput [40]byte
	node := make([]byte, dag.NodeSize)
	for r := uint64(0); r < spec.ReadsPerHash; r++ {
		copy(fnvInput[:32], mix[:])
		binary.LittleEndian.PutUint64(fnvInput[32:], r)

		nodeIdx := fnv1a64(fnvInput[:]) % dag.NodeCount
		readRawDAGNode(dag, nodeIdx, node)

		blakeInput := blake3RoundInput(mix, node, nil)
		sum := blake3.Sum256(blakeInput)
		copy(mix[:], sum[:])
	}

	var finalInput [96]byte
	copy(finalInput[:64], seed512[:])
	copy(finalInput[64:], mix[:])
	final512 := sha3.Sum512(finalInput[:])
	copy(out.Full512[:], final512[:])
	copy(out.Pow256[:], final512[:32])
	return out
}

func readRawDAGNode(dag rawContiguousDAGBuffer, idx uint64, out []byte) {
	off := idx * dag.NodeSize
	copy(out, dag.Bytes[off:off+dag.NodeSize])
}

func blake3RoundInput(mix [32]byte, node []byte, dst []byte) []byte {
	dst = append(dst, mix[:]...)
	dst = append(dst, node...)
	return dst
}

func fnv1a64(data []byte) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	var h uint64 = offset64
	for _, b := range data {
		h ^= uint64(b)
		h *= prime64
	}
	return h
}
