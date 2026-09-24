package protocol

import (
	"encoding/binary"
	"errors"
)

const MaxCountedLeaves = 1024

func countedRoot(count uint32, root Hash) Hash {
	var b [36]byte
	binary.BigEndian.PutUint32(b[:4], count)
	copy(b[4:], root[:])
	return Digest("common-dex/merkle-count/v1", b[:])
}
func BuildCountedTree(leaves []Hash) (Hash, [][]Hash, error) {
	if len(leaves) > MaxCountedLeaves {
		return Hash{}, nil, errors.New("counted tree leaf limit")
	}
	if len(leaves) == 0 {
		return Hash{}, nil, nil
	}
	size := 1
	for size < len(leaves) {
		size *= 2
	}
	layer := make([]Hash, size)
	copy(layer, leaves)
	empty := Digest("common-dex/merkle-empty/v1", nil)
	for i := len(leaves); i < size; i++ {
		layer[i] = empty
	}
	paths := make([][]Hash, len(leaves))
	indices := make([]int, len(leaves))
	for i := range indices {
		indices[i] = i
	}
	for len(layer) > 1 {
		for i, index := range indices {
			paths[i] = append(paths[i], layer[index^1])
			indices[i] /= 2
		}
		next := make([]Hash, len(layer)/2)
		for i := range next {
			next[i] = MerkleParent(layer[2*i], layer[2*i+1])
		}
		layer = next
	}
	return countedRoot(uint32(len(leaves)), layer[0]), paths, nil
}
func VerifyCountedInclusion(root, leaf Hash, index, count uint32, siblings []Hash) error {
	if count == 0 || count > MaxCountedLeaves || index >= count {
		return errors.New("invalid counted inclusion size/index")
	}
	size, depth := uint32(1), 0
	for size < count {
		size *= 2
		depth++
	}
	if len(siblings) != depth {
		return errors.New("noncanonical counted inclusion depth")
	}
	h := leaf
	empty := Digest("common-dex/merkle-empty/v1", nil)
	for i, s := range siblings {
		// A wholly out-of-count sibling has one uniquely defined empty
		// subtree; count commitment must not admit arbitrary padding bytes.
		siblingStart := ((index >> uint(i)) ^ 1) << uint(i)
		if siblingStart >= count && s != empty {
			return errors.New("noncanonical counted tree padding")
		}
		if (index>>uint(i))&1 == 0 {
			h = MerkleParent(h, s)
		} else {
			h = MerkleParent(s, h)
		}
		empty = MerkleParent(empty, empty)
	}
	if countedRoot(count, h) != root {
		return errors.New("claim not included in counted tree")
	}
	return nil
}
