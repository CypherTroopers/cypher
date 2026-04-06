package colossusx

import (
	"encoding/binary"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/sha3"
)

type HashResult struct {
	Pow256  [32]byte
	Full512 [64]byte
}

type DAGAccessor interface {
	NodeCount() uint64
	ReadNode(uint64, []byte)
}

type HashScratch struct {
	seedInput  []byte
	finalInput []byte
	fnvInput   [40]byte
	blakeInput []byte
}

func NewHashScratch(headerLen int) *HashScratch {
	return &HashScratch{
		seedInput:  make([]byte, 0, headerLen+8),
		finalInput: make([]byte, 0, 96),
		blakeInput: make([]byte, 0, 288),
	}
}

func EnsureSeedInput(s *HashScratch, headerLen int, nonce Nonce) {
	need := headerLen + 8
	if nonce != nil {
		buf := make([]byte, 0, headerLen+32)
		buf = nonce.AppendTo(buf)
		if len(buf)+headerLen > need {
			need = headerLen + len(buf)
		}
	}
	if cap(s.seedInput) < need {
		s.seedInput = make([]byte, 0, need)
		return
	}
	s.seedInput = s.seedInput[:0]
}

func LatticeHash(spec Spec, header []byte, nonce Nonce, accessor DAGAccessor, scratch *HashScratch) HashResult {
	if spec.AlgorithmVersion >= 2 {
		return ColossusXHash(spec, header, nonce, accessor)
	}

	var out HashResult
	if accessor == nil || accessor.NodeCount() == 0 {
		return out
	}
	if scratch == nil {
		scratch = NewHashScratch(len(header))
	}
	EnsureSeedInput(scratch, len(header), nonce)
	scratch.seedInput = append(scratch.seedInput, header...)
	if nonce != nil {
		scratch.seedInput = nonce.AppendTo(scratch.seedInput)
	}
	seed512 := sha3.Sum512(scratch.seedInput)

	var mix [32]byte
	copy(mix[:], seed512[:32])

	node := make([]byte, spec.NodeSize)
	for r := uint64(0); r < spec.ReadsPerHash; r++ {
		copy(scratch.fnvInput[:32], mix[:])
		binary.LittleEndian.PutUint64(scratch.fnvInput[32:], r)

		nodeIdx := fnv1a64(scratch.fnvInput[:]) % accessor.NodeCount()
		accessor.ReadNode(nodeIdx, node)

		scratch.blakeInput = blake3RoundInput(mix, node, scratch.blakeInput[:0])
		sum := blake3.Sum256(scratch.blakeInput)
		copy(mix[:], sum[:])
	}

	scratch.finalInput = append(scratch.finalInput[:0], seed512[:]...)
	scratch.finalInput = append(scratch.finalInput, mix[:]...)
	final512 := sha3.Sum512(scratch.finalInput)
	copy(out.Full512[:], final512[:])
	copy(out.Pow256[:], final512[:32])
	return out
}

// The Blake3 round input is a deterministic concatenation of mix state and
// full DAG node bytes.
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
