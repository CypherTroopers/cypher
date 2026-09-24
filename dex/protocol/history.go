package protocol

import (
	"encoding/binary"
	"errors"
)

// HistoryDepth bounds the ancestor commitment by the existing 4096-height
// devnet operating budget. A proposal commits its preceding QCs, not itself.
const HistoryDepth = 12
const MaxHistoryCount = (1 << HistoryDepth) - 1

// HistoryFrontier is a bounded append-only accumulator. Branches whose count
// bit is unset are zero, making persisted frontier encoding unambiguous.
type HistoryFrontier struct {
	Count  uint64
	Branch [HistoryDepth]Hash
}

func historyLeaf(qcID Hash) Hash { return Digest("common-dex/history-leaf/v1", qcID[:]) }
func historyNode(level int, left, right Hash) Hash {
	var b [65]byte
	b[0] = byte(level)
	copy(b[1:33], left[:])
	copy(b[33:], right[:])
	return Digest("common-dex/history-node/v1", b[:])
}
func historyEmpty() [HistoryDepth + 1]Hash {
	var empty [HistoryDepth + 1]Hash
	empty[0] = Digest("common-dex/history-empty/v1", nil)
	for level := 0; level < HistoryDepth; level++ {
		empty[level+1] = historyNode(level, empty[level], empty[level])
	}
	return empty
}
func (f HistoryFrontier) validate() error {
	if f.Count > MaxHistoryCount {
		return errors.New("DEX history count bound")
	}
	for level, branch := range f.Branch {
		if (f.Count>>uint(level))&1 == 0 && branch != (Hash{}) || (f.Count>>uint(level))&1 != 0 && branch == (Hash{}) {
			return errors.New("noncanonical DEX history frontier")
		}
	}
	return nil
}

func (f *HistoryFrontier) AppendQCID(qcID Hash) error {
	if f == nil || qcID == (Hash{}) {
		return errors.New("missing DEX history QC identity")
	}
	if err := f.validate(); err != nil {
		return err
	}
	if f.Count == MaxHistoryCount {
		return errors.New("DEX history count bound")
	}
	node := historyLeaf(qcID)
	for level := 0; level < HistoryDepth; level++ {
		if (f.Count>>uint(level))&1 == 0 {
			f.Branch[level] = node
			f.Count++
			return nil
		}
		node = historyNode(level, f.Branch[level], node)
		f.Branch[level] = Hash{}
	}
	return errors.New("DEX history frontier overflow")
}

func (f HistoryFrontier) Root() (Hash, error) {
	if err := f.validate(); err != nil {
		return Hash{}, err
	}
	empty := historyEmpty()
	node := empty[0]
	for level := 0; level < HistoryDepth; level++ {
		if (f.Count>>uint(level))&1 != 0 {
			node = historyNode(level, f.Branch[level], node)
		} else {
			node = historyNode(level, node, empty[level])
		}
	}
	return node, nil
}

// HistoryDataRoot is schema 6's data commitment. The ordinary action commitment
// stays separately recognizable; its meaning is not changed for older schemas.
func HistoryDataRoot(actionRoot, historyRoot Hash, count uint64) (Hash, error) {
	if actionRoot == (Hash{}) || historyRoot == (Hash{}) || count > MaxHistoryCount {
		return Hash{}, errors.New("invalid DEX history data commitment")
	}
	var b [72]byte
	copy(b[:32], actionRoot[:])
	copy(b[32:64], historyRoot[:])
	binary.BigEndian.PutUint64(b[64:], count)
	return Digest("common-dex/history-data/v1", b[:]), nil
}

// BuildHistoryProof is DEX-side work over an already authenticated, ordered
// prefix. CLX receives only the fixed-depth path, never this complete prefix.
func BuildHistoryProof(qcIDs []Hash, index uint64) ([]Hash, error) {
	if len(qcIDs) == 0 || len(qcIDs) > MaxHistoryCount || index >= uint64(len(qcIDs)) {
		return nil, errors.New("DEX history proof range")
	}
	empty := historyEmpty()
	nodes := make([]Hash, 1<<HistoryDepth)
	for i := range nodes {
		nodes[i] = empty[0]
	}
	for i, qcID := range qcIDs {
		if qcID == (Hash{}) {
			return nil, errors.New("missing DEX history QC identity")
		}
		nodes[i] = historyLeaf(qcID)
	}
	path := make([]Hash, 0, HistoryDepth)
	for level := 0; level < HistoryDepth; level++ {
		path = append(path, nodes[index^1])
		for i := 0; i < len(nodes)/2; i++ {
			nodes[i] = historyNode(level, nodes[2*i], nodes[2*i+1])
		}
		nodes = nodes[:len(nodes)/2]
		index >>= 1
	}
	return path, nil
}

// HistoryProofRoot checks all path bounds before computing the candidate root.
// Authentication requires binding this root/count to the signed DataRoot.
func HistoryProofRoot(qcID Hash, index, count uint64, siblings []Hash) (Hash, error) {
	if qcID == (Hash{}) || count == 0 || count > MaxHistoryCount || index >= count || len(siblings) != HistoryDepth {
		return Hash{}, errors.New("DEX history inclusion bounds")
	}
	node := historyLeaf(qcID)
	for level, sibling := range siblings {
		if index&1 == 0 {
			node = historyNode(level, node, sibling)
		} else {
			node = historyNode(level, sibling, node)
		}
		index >>= 1
	}
	return node, nil
}

func VerifyHistoryInclusion(root, qcID Hash, index, count uint64, siblings []Hash) error {
	got, err := HistoryProofRoot(qcID, index, count, siblings)
	if err != nil {
		return err
	}
	if got != root {
		return errors.New("DEX history inclusion root mismatch")
	}
	return nil
}
