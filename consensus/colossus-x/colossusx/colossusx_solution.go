package colossusx

import (
	"encoding/binary"
	"errors"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/sha3"
)

type SolutionCell struct {
	Index uint32
	Data  []byte
	Proof MerkleProof
}

type ColossusXSolution struct {
	Nonce       uint64
	MixDigest   [64]byte
	MiningCells []SolutionCell
	AuditCells  []SolutionCell
}

type CompactSolutionCell struct {
	Index     uint32
	Data      []byte
	ProofRefs []uint32
}

type ColossusXSolutionCompact struct {
	Nonce       uint64
	MixDigest   [64]byte
	Siblings    [][32]byte
	MiningCells []CompactSolutionCell
	AuditCells  []CompactSolutionCell
}

func BuildColossusXSolution(spec Spec, header []byte, nonce uint64, dag DAGAccessor, leaves [][32]byte) (ColossusXSolution, [32]byte, error) {
	prover, err := NewMerkleProverFromLeaves(leaves)
	if err != nil {
		return ColossusXSolution{}, [32]byte{}, err
	}
	return BuildColossusXSolutionWithProver(spec, header, nonce, dag, prover)
}

func BuildColossusXSolutionWithProver(spec Spec, header []byte, nonce uint64, dag DAGAccessor, prover MerkleProver) (ColossusXSolution, [32]byte, error) {
	if dag == nil || dag.NodeCount() == 0 {
		return ColossusXSolution{}, [32]byte{}, errors.New("dag is empty")
	}
	if prover == nil {
		return ColossusXSolution{}, [32]byte{}, errors.New("merkle prover is nil")
	}
	if prover.LeafCount() != dag.NodeCount() {
		return ColossusXSolution{}, [32]byte{}, errors.New("merkle leaves must match dag node count")
	}
	root := prover.Root()
	trace := ColossusXTraceHash(spec, header, NewUint64Nonce(nonce), dag)
	out := ColossusXSolution{
		Nonce:       nonce,
		MixDigest:   trace.MixDigest,
		MiningCells: make([]SolutionCell, 0, len(trace.Accessed)),
		AuditCells:  make([]SolutionCell, 0, ColossusXAuditCellCount),
	}
	for _, idx := range trace.Accessed {
		cell := make([]byte, spec.NodeSize)
		dag.ReadNode(uint64(idx), cell)
		proof, err := prover.Proof(int(idx))
		if err != nil {
			return ColossusXSolution{}, [32]byte{}, err
		}
		out.MiningCells = append(out.MiningCells, SolutionCell{
			Index: idx,
			Data:  cell,
			Proof: proof,
		})
	}
	auditIdx := ColossusXAuditIndicesFromSolutionHash(trace.SolutionHash, dag.NodeCount(), ColossusXAuditCellCount)
	for _, idx := range auditIdx {
		cell := make([]byte, spec.NodeSize)
		dag.ReadNode(idx, cell)
		proof, err := prover.Proof(int(idx))
		if err != nil {
			return ColossusXSolution{}, [32]byte{}, err
		}
		out.AuditCells = append(out.AuditCells, SolutionCell{
			Index: uint32(idx),
			Data:  cell,
			Proof: proof,
		})
	}
	return out, root, nil
}

func BuildColossusXSolutionStreaming(spec Spec, header []byte, nonce uint64, dag DAGAccessor) (ColossusXSolution, [32]byte, error) {
	if dag == nil || dag.NodeCount() == 0 {
		return ColossusXSolution{}, [32]byte{}, errors.New("dag is empty")
	}
	trace := ColossusXTraceHash(spec, header, NewUint64Nonce(nonce), dag)
	auditIdx := ColossusXAuditIndicesFromSolutionHash(trace.SolutionHash, dag.NodeCount(), ColossusXAuditCellCount)
	needed := make([]uint64, 0, len(trace.Accessed)+len(auditIdx))
	seen := make(map[uint64]struct{}, len(trace.Accessed)+len(auditIdx))
	for _, idx := range trace.Accessed {
		key := uint64(idx)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		needed = append(needed, key)
	}
	for _, idx := range auditIdx {
		if _, ok := seen[idx]; ok {
			continue
		}
		seen[idx] = struct{}{}
		needed = append(needed, idx)
	}
	root, proofs, err := BuildMerkleMultiProofFromAccessor(dag, spec.NodeSize, needed)
	if err != nil {
		return ColossusXSolution{}, [32]byte{}, err
	}
	out := ColossusXSolution{
		Nonce:       nonce,
		MixDigest:   trace.MixDigest,
		MiningCells: make([]SolutionCell, 0, len(trace.Accessed)),
		AuditCells:  make([]SolutionCell, 0, ColossusXAuditCellCount),
	}
	for _, idx := range trace.Accessed {
		cell := make([]byte, spec.NodeSize)
		dag.ReadNode(uint64(idx), cell)
		out.MiningCells = append(out.MiningCells, SolutionCell{
			Index: idx,
			Data:  cell,
			Proof: append(MerkleProof(nil), proofs[uint64(idx)]...),
		})
	}
	for _, idx := range auditIdx {
		cell := make([]byte, spec.NodeSize)
		dag.ReadNode(idx, cell)
		out.AuditCells = append(out.AuditCells, SolutionCell{
			Index: uint32(idx),
			Data:  cell,
			Proof: append(MerkleProof(nil), proofs[idx]...),
		})
	}
	return out, root, nil
}

func VerifyColossusXSolution(spec Spec, header []byte, target Target, merkleRoot [32]byte, solution ColossusXSolution) error {
	initialInput := append([]byte{}, header...)
	var nonceLE [8]byte
	binary.LittleEndian.PutUint64(nonceLE[:], solution.Nonce)
	initialInput = append(initialInput, nonceLE[:]...)
	initial := sha3.Sum512(initialInput)
	mix := initial
	if len(solution.MiningCells) != int(spec.ReadsPerHash) {
		return errors.New("invalid mining cell count")
	}
	for round, c := range solution.MiningCells {
		expect := uint32(uint64(fnv1a32(uint32(round), binary.LittleEndian.Uint32(mix[:4]))) % spec.NodeCount())
		if c.Index != expect {
			return errors.New("invalid mining index")
		}
		if len(c.Data) != int(spec.NodeSize) {
			return errors.New("invalid mining cell size")
		}
		leaf := blake3.Sum256(c.Data)
		if !VerifyMerkleProof(merkleRoot, leaf, int(c.Index), c.Proof) {
			return errors.New("invalid mining merkle proof")
		}
		mix = colossusXRoundMix(mix, c.Data)
	}
	if mix != solution.MixDigest {
		return errors.New("mix digest mismatch")
	}
	finalInput := append(initial[:], mix[:]...)
	result := blake3.Sum256(finalInput)
	if !LessOrEqualBE(result, target) {
		return errors.New("pow target mismatch")
	}
	solutionSeed := append(append(initial[:], mix[:]...), nonceLE[:]...)
	solutionHash := blake3.Sum256(solutionSeed)
	expectAudit := ColossusXAuditIndicesFromSolutionHash(solutionHash, spec.NodeCount(), ColossusXAuditCellCount)
	if len(solution.AuditCells) != len(expectAudit) {
		return errors.New("invalid audit cell count")
	}
	for i, c := range solution.AuditCells {
		if uint64(c.Index) != expectAudit[i] {
			return errors.New("invalid audit index")
		}
		leaf := blake3.Sum256(c.Data)
		if !VerifyMerkleProof(merkleRoot, leaf, int(c.Index), c.Proof) {
			return errors.New("invalid audit merkle proof")
		}
	}
	return nil
}

func CompactColossusXSolution(solution ColossusXSolution) ColossusXSolutionCompact {
	pool := make([][32]byte, 0, 256)
	indexBySibling := map[[32]byte]uint32{}
	encodeCell := func(c SolutionCell) CompactSolutionCell {
		refs := make([]uint32, 0, len(c.Proof))
		for _, sib := range c.Proof {
			ref, ok := indexBySibling[sib]
			if !ok {
				ref = uint32(len(pool))
				pool = append(pool, sib)
				indexBySibling[sib] = ref
			}
			refs = append(refs, ref)
		}
		return CompactSolutionCell{Index: c.Index, Data: c.Data, ProofRefs: refs}
	}
	out := ColossusXSolutionCompact{
		Nonce:       solution.Nonce,
		MixDigest:   solution.MixDigest,
		MiningCells: make([]CompactSolutionCell, 0, len(solution.MiningCells)),
		AuditCells:  make([]CompactSolutionCell, 0, len(solution.AuditCells)),
	}
	for _, c := range solution.MiningCells {
		out.MiningCells = append(out.MiningCells, encodeCell(c))
	}
	for _, c := range solution.AuditCells {
		out.AuditCells = append(out.AuditCells, encodeCell(c))
	}
	out.Siblings = pool
	return out
}

func ExpandCompactColossusXSolution(compact ColossusXSolutionCompact) (ColossusXSolution, error) {
	decodeCell := func(c CompactSolutionCell) (SolutionCell, error) {
		proof := make(MerkleProof, 0, len(c.ProofRefs))
		for _, ref := range c.ProofRefs {
			if int(ref) >= len(compact.Siblings) {
				return SolutionCell{}, errors.New("invalid compact proof reference")
			}
			proof = append(proof, compact.Siblings[ref])
		}
		return SolutionCell{Index: c.Index, Data: c.Data, Proof: proof}, nil
	}
	out := ColossusXSolution{
		Nonce:       compact.Nonce,
		MixDigest:   compact.MixDigest,
		MiningCells: make([]SolutionCell, 0, len(compact.MiningCells)),
		AuditCells:  make([]SolutionCell, 0, len(compact.AuditCells)),
	}
	for _, c := range compact.MiningCells {
		d, err := decodeCell(c)
		if err != nil {
			return ColossusXSolution{}, err
		}
		out.MiningCells = append(out.MiningCells, d)
	}
	for _, c := range compact.AuditCells {
		d, err := decodeCell(c)
		if err != nil {
			return ColossusXSolution{}, err
		}
		out.AuditCells = append(out.AuditCells, d)
	}
	return out, nil
}
