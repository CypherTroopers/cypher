package colossusx

import (
	"fmt"
	"sort"

	"github.com/zeebo/blake3"
)

type MerkleProof [][32]byte

type proofSlot struct {
	targetPos  int
	proofLevel int
}

type MerkleProver interface {
	LeafCount() uint64
	Root() [32]byte
	Proof(index int) (MerkleProof, error)
}

type levelMerkleProver struct {
	levels [][][32]byte
}

func (p *levelMerkleProver) LeafCount() uint64 {
	if p == nil || len(p.levels) == 0 {
		return 0
	}
	return uint64(len(p.levels[0]))
}

func (p *levelMerkleProver) Root() [32]byte {
	if p == nil || len(p.levels) == 0 {
		return [32]byte{}
	}
	top := p.levels[len(p.levels)-1]
	if len(top) == 0 {
		return [32]byte{}
	}
	return top[0]
}

func (p *levelMerkleProver) Proof(index int) (MerkleProof, error) {
	if p == nil || len(p.levels) == 0 {
		return nil, fmt.Errorf("merkle prover is empty")
	}
	if index < 0 || index >= len(p.levels[0]) {
		return nil, fmt.Errorf("merkle proof index %d out of range", index)
	}
	proof := make(MerkleProof, 0, len(p.levels)-1)
	idx := index
	for level := 0; level < len(p.levels)-1; level++ {
		nodes := p.levels[level]
		sibling := idx ^ 1
		if sibling >= len(nodes) {
			sibling = idx
		}
		proof = append(proof, nodes[sibling])
		idx /= 2
	}
	return proof, nil
}

func NewMerkleProverFromLeaves(leaves [][32]byte) (MerkleProver, error) {
	if len(leaves) == 0 {
		return nil, fmt.Errorf("merkle leaves are empty")
	}
	return &levelMerkleProver{levels: buildMerkleLevels(leaves)}, nil
}

func NewMerkleProverFromAccessor(accessor DAGAccessor, nodeSize uint64) (MerkleProver, error) {
	if accessor == nil || accessor.NodeCount() == 0 {
		return nil, fmt.Errorf("dag is empty")
	}
	if nodeSize == 0 {
		return nil, fmt.Errorf("node size must be > 0")
	}
	level := make([][32]byte, accessor.NodeCount())
	node := make([]byte, nodeSize)
	for i := uint64(0); i < accessor.NodeCount(); i++ {
		accessor.ReadNode(i, node)
		level[i] = blake3.Sum256(node)
	}
	levels := make([][][32]byte, 0, 32)
	levels = append(levels, level)
	for len(level) > 1 {
		next := make([][32]byte, (len(level)+1)/2)
		for i, out := 0, 0; i < len(level); i, out = i+2, out+1 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			var in [64]byte
			copy(in[:32], left[:])
			copy(in[32:], right[:])
			next[out] = blake3.Sum256(in[:])
		}
		level = next
		levels = append(levels, level)
	}
	return &levelMerkleProver{levels: levels}, nil
}

func buildMerkleLevels(leaves [][32]byte) [][][32]byte {
	levels := make([][][32]byte, 0, 32)
	level := append([][32]byte(nil), leaves...)
	levels = append(levels, level)
	for len(level) > 1 {
		next := make([][32]byte, (len(level)+1)/2)
		for i, out := 0, 0; i < len(level); i, out = i+2, out+1 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			var in [64]byte
			copy(in[:32], left[:])
			copy(in[32:], right[:])
			next[out] = blake3.Sum256(in[:])
		}
		level = next
		levels = append(levels, level)
	}
	return levels
}

func BuildMerkleLeaves(cells [][]byte) [][32]byte {
	leaves := make([][32]byte, len(cells))
	for i := range cells {
		leaves[i] = blake3.Sum256(cells[i])
	}
	return leaves
}

func BuildMerkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return [32]byte{}
	}
	level := append([][32]byte(nil), leaves...)
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			var in [64]byte
			copy(in[:32], left[:])
			copy(in[32:], right[:])
			next = append(next, blake3.Sum256(in[:]))
		}
		level = next
	}
	return level[0]
}

func BuildMerkleProof(leaves [][32]byte, index int) MerkleProof {
	prover, err := NewMerkleProverFromLeaves(leaves)
	if err != nil {
		return nil
	}
	proof, err := prover.Proof(index)
	if err != nil {
		return nil
	}
	return proof
}

func VerifyMerkleProof(root [32]byte, leaf [32]byte, index int, proof MerkleProof) bool {
	h := leaf
	idx := index
	for _, sib := range proof {
		var in [64]byte
		if idx%2 == 0 {
			copy(in[:32], h[:])
			copy(in[32:], sib[:])
		} else {
			copy(in[:32], sib[:])
			copy(in[32:], h[:])
		}
		h = blake3.Sum256(in[:])
		idx /= 2
	}
	return h == root
}

func BuildMerkleMultiProofFromAccessor(accessor DAGAccessor, nodeSize uint64, indices []uint64) ([32]byte, map[uint64]MerkleProof, error) {
	if accessor == nil || accessor.NodeCount() == 0 {
		return [32]byte{}, nil, fmt.Errorf("dag is empty")
	}
	if nodeSize == 0 {
		return [32]byte{}, nil, fmt.Errorf("node size must be > 0")
	}
	nodeCount := accessor.NodeCount()
	uniq := make([]uint64, 0, len(indices))
	seen := make(map[uint64]struct{}, len(indices))
	for _, idx := range indices {
		if idx >= nodeCount {
			return [32]byte{}, nil, fmt.Errorf("merkle proof index %d out of range", idx)
		}
		if _, ok := seen[idx]; ok {
			continue
		}
		seen[idx] = struct{}{}
		uniq = append(uniq, idx)
	}
	sort.Slice(uniq, func(i, j int) bool { return uniq[i] < uniq[j] })
	levelCounts := make([]uint64, 0, 64)
	levelCounts = append(levelCounts, nodeCount)
	for levelCounts[len(levelCounts)-1] > 1 {
		last := levelCounts[len(levelCounts)-1]
		levelCounts = append(levelCounts, (last+1)/2)
	}
	proofDepth := len(levelCounts) - 1
	proofs := make([]MerkleProof, len(uniq))
	filled := make([][]bool, len(uniq))
	for i := range proofs {
		proofs[i] = make(MerkleProof, proofDepth)
		filled[i] = make([]bool, proofDepth)
	}
	wanted := make([]map[uint64][]proofSlot, proofDepth)
	for ti, idx := range uniq {
		for level := 0; level < proofDepth; level++ {
			pos := idx >> level
			sibling := pos ^ 1
			if sibling >= levelCounts[level] {
				sibling = pos
			}
			if wanted[level] == nil {
				wanted[level] = make(map[uint64][]proofSlot)
			}
			wanted[level][sibling] = append(wanted[level][sibling], proofSlot{targetPos: ti, proofLevel: level})
		}
	}
	nextIndex := make([]uint64, len(levelCounts))
	pending := make([][32]byte, len(levelCounts))
	hasPending := make([]bool, len(levelCounts))
	assignWanted := func(level int, idx uint64, h [32]byte) {
		if level >= len(wanted) || wanted[level] == nil {
			return
		}
		for _, slot := range wanted[level][idx] {
			proofs[slot.targetPos][slot.proofLevel] = h
			filled[slot.targetPos][slot.proofLevel] = true
		}
	}
	var emitNode func(level int, h [32]byte)
	emitNode = func(level int, h [32]byte) {
		for {
			if level >= len(nextIndex) {
				nextIndex = append(nextIndex, 0)
				pending = append(pending, [32]byte{})
				hasPending = append(hasPending, false)
			}
			idx := nextIndex[level]
			nextIndex[level]++
			assignWanted(level, idx, h)
			if !hasPending[level] {
				pending[level] = h
				hasPending[level] = true
				return
			}
			h = hashPair(pending[level], h)
			hasPending[level] = false
			level++
		}
	}
	node := make([]byte, nodeSize)
	for i := uint64(0); i < nodeCount; i++ {
		accessor.ReadNode(i, node)
		emitNode(0, blake3.Sum256(node))
	}
	for level := 0; level < proofDepth; level++ {
		if !hasPending[level] {
			continue
		}
		emitNode(level+1, hashPair(pending[level], pending[level]))
		hasPending[level] = false
	}
	rootLevel := len(levelCounts) - 1
	if rootLevel < 0 || !hasPending[rootLevel] {
		return [32]byte{}, nil, fmt.Errorf("merkle root build failed")
	}
	out := make(map[uint64]MerkleProof, len(uniq))
	for i, idx := range uniq {
		for level := 0; level < proofDepth; level++ {
			if !filled[i][level] {
				return [32]byte{}, nil, fmt.Errorf("proof generation incomplete for index %d level %d", idx, level)
			}
		}
		out[idx] = append(MerkleProof(nil), proofs[i]...)
	}
	return pending[rootLevel], out, nil
}

func hashPair(left, right [32]byte) [32]byte {
	var in [64]byte
	copy(in[:32], left[:])
	copy(in[32:], right[:])
	return blake3.Sum256(in[:])
}
