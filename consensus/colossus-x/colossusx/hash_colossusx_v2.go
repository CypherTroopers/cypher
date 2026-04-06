package colossusx

import (
	"encoding/binary"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/sha3"
)

const ColossusXAuditCellCount = 32

type ColossusXTrace struct {
	InitialHash  [64]byte
	MixDigest    [64]byte
	Accessed     []uint32
	Result       [32]byte
	SolutionHash [32]byte
}

func ColossusXHash(spec Spec, header []byte, nonce Nonce, dag DAGAccessor) HashResult {
	trace := ColossusXTraceHash(spec, header, nonce, dag)
	var out HashResult
	copy(out.Pow256[:], trace.Result[:])
	copy(out.Full512[:], append(trace.InitialHash[:32], trace.MixDigest[:32]...))
	return out
}

func ColossusXTraceHash(spec Spec, header []byte, nonce Nonce, dag DAGAccessor) ColossusXTrace {
	var trace ColossusXTrace
	if dag == nil || dag.NodeCount() == 0 {
		return trace
	}
	seedInput := append([]byte{}, header...)
	if nonce != nil {
		seedInput = nonce.AppendTo(seedInput)
	}
	initial := sha3.Sum512(seedInput)
	mix := initial
	cell := make([]byte, spec.NodeSize)
	accessed := make([]uint32, 0, spec.ReadsPerHash)

	for round := uint64(0); round < spec.ReadsPerHash; round++ {
		index := uint64(fnv1a32(uint32(round), binary.LittleEndian.Uint32(mix[:4]))) % dag.NodeCount()
		accessed = append(accessed, uint32(index))
		dag.ReadNode(index, cell)
		mix = colossusXRoundMix(mix, cell)
	}

	finalInput := make([]byte, 0, len(initial)+len(mix))
	finalInput = append(finalInput, initial[:]...)
	finalInput = append(finalInput, mix[:]...)
	pow := blake3.Sum256(finalInput)
	var nonceBytes [8]byte
	if n64, ok := nonce.(Uint64Nonce); ok {
		binary.LittleEndian.PutUint64(nonceBytes[:], n64.Uint64())
	}
	solutionSeed := append(append(initial[:], mix[:]...), nonceBytes[:]...)
	trace.SolutionHash = blake3.Sum256(solutionSeed)
	trace.InitialHash = initial
	trace.MixDigest = mix
	trace.Result = pow
	trace.Accessed = accessed
	return trace
}

func ColossusXAuditIndices(pow [32]byte, dagCellCount uint64, count uint32) []uint64 {
	if dagCellCount == 0 || count == 0 {
		return nil
	}
	out := make([]uint64, 0, count)
	var ctr [4]byte
	for i := uint32(0); i < count; i++ {
		binary.LittleEndian.PutUint32(ctr[:], i)
		sum := sha3.Sum256(append(pow[:], ctr[:]...))
		idx := binary.LittleEndian.Uint32(sum[:4])
		out = append(out, uint64(idx)%dagCellCount)
	}
	return out
}

func ColossusXAuditIndicesFromSolutionHash(solutionHash [32]byte, dagCellCount uint64, count uint32) []uint64 {
	return ColossusXAuditIndices(solutionHash, dagCellCount, count)
}

func colossusXRoundMix(mix [64]byte, cell []byte) [64]byte {
	words := [16]uint32{}
	for i := range words {
		words[i] = binary.LittleEndian.Uint32(mix[i*4:])
	}
	for q := 0; q+64 <= len(cell); q += 64 {
		quarter := cell[q : q+64]
		for i := 0; i < 16; i++ {
			cw := binary.LittleEndian.Uint32(quarter[i*4:])
			words[i] = fnv1a32(words[i], cw)
		}
	}
	var folded [64]byte
	for i := range words {
		binary.LittleEndian.PutUint32(folded[i*4:], words[i])
	}
	return sha3.Sum512(folded[:])
}

func fnv1a32(a, b uint32) uint32 {
	return (a ^ b) * 0x01000193
}
