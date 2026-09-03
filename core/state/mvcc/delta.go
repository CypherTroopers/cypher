package mvcc

import (
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/cypherium/cypher/common"
)

var (
	ErrConflict         = errors.New("conflicting MVCC transaction declarations")
	ErrStaleBase        = errors.New("stale MVCC delta base version")
	ErrInvalidDelta     = errors.New("invalid MVCC transaction delta")
	ErrDuplicateTxIndex = errors.New("duplicate MVCC transaction index")
	ErrVersionOverflow  = errors.New("MVCC version number overflow")
)

type ChangeKind uint8

const (
	ChangePut ChangeKind = iota + 1
	ChangeDelete
)

// Change is returned only through defensive copies from a sealed Delta.
type Change struct {
	Address common.Address
	Kind    ChangeKind
	Value   []byte
}

// Delta is an immutable transaction result tied to one exact base Version.
type Delta struct {
	baseID      common.Hash
	baseRoot    common.Hash
	txIndex     uint64
	accesses    []DeclaredAccess
	changes     []Change
	hash        common.Hash
	initialized bool
}

func (d *Delta) BaseID() common.Hash {
	if d == nil {
		return common.Hash{}
	}
	return d.baseID
}

func (d *Delta) BaseRoot() common.Hash {
	if d == nil {
		return common.Hash{}
	}
	return d.baseRoot
}

func (d *Delta) TxIndex() uint64 {
	if d == nil {
		return 0
	}
	return d.txIndex
}

func (d *Delta) Hash() common.Hash {
	if d == nil {
		return common.Hash{}
	}
	return d.hash
}

func (d *Delta) Accesses() []DeclaredAccess {
	if d == nil {
		return nil
	}
	return append([]DeclaredAccess(nil), d.accesses...)
}

func (d *Delta) Changes() []Change {
	if d == nil {
		return nil
	}
	result := make([]Change, len(d.changes))
	for index, change := range d.changes {
		result[index] = change
		result[index].Value = cloneBytes(change.Value)
	}
	return result
}

func computeDeltaHash(delta *Delta) common.Hash {
	parts := make([][]byte, 0, 6+2*len(delta.accesses)+4*len(delta.changes))
	parts = append(parts, delta.baseID[:], delta.baseRoot[:], uint64Bytes(delta.txIndex), uint64Bytes(uint64(len(delta.accesses))))
	for _, access := range delta.accesses {
		parts = append(parts, access.Address[:], []byte{byte(access.Mode)})
	}
	parts = append(parts, uint64Bytes(uint64(len(delta.changes))))
	for _, change := range delta.changes {
		parts = append(parts, change.Address[:], []byte{byte(change.Kind)})
		if change.Kind == ChangePut {
			parts = append(parts, uint64Bytes(uint64(len(change.Value))), change.Value)
		}
	}
	return hashParts(DeltaDomain, parts...)
}

func (d *Delta) valid() bool {
	if d == nil || !d.initialized || d.hash != computeDeltaHash(d) {
		return false
	}
	for index, access := range d.accesses {
		if access.Mode != AccessRead && access.Mode != AccessWrite {
			return false
		}
		if index > 0 && !addressLess(d.accesses[index-1].Address, access.Address) {
			return false
		}
	}
	writeAccess := make(map[common.Address]struct{}, len(d.accesses))
	for _, access := range d.accesses {
		if access.Mode == AccessWrite {
			writeAccess[access.Address] = struct{}{}
		}
	}
	for index, change := range d.changes {
		if change.Kind != ChangePut && change.Kind != ChangeDelete {
			return false
		}
		if _, declared := writeAccess[change.Address]; !declared {
			return false
		}
		if change.Kind == ChangeDelete && len(change.Value) != 0 {
			return false
		}
		if index > 0 && !addressLess(d.changes[index-1].Address, change.Address) {
			return false
		}
	}
	return true
}

type observedAccess struct {
	mode    AccessMode
	txIndex uint64
}

// Merge applies sealed deltas in transaction-index order. All deltas must have
// been executed from base. Declared R/W, W/R and W/W overlaps are rejected;
// R/R overlap is permitted.
func Merge(base *Version, deltas []*Delta, workers int) (*Version, error) {
	if !base.valid() {
		return nil, ErrInvalidVersion
	}
	if base.number == math.MaxUint64 {
		return nil, ErrVersionOverflow
	}
	ordered := append([]*Delta(nil), deltas...)
	for _, delta := range ordered {
		if !delta.valid() {
			return nil, ErrInvalidDelta
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].txIndex < ordered[j].txIndex
	})
	for index := 1; index < len(ordered); index++ {
		if ordered[index-1].txIndex == ordered[index].txIndex {
			return nil, fmt.Errorf("%w: %d", ErrDuplicateTxIndex, ordered[index].txIndex)
		}
	}
	// Check lineage after ordering so a malformed input slice cannot change
	// which transaction is reported as the first stale result.
	for _, delta := range ordered {
		if delta.baseID != base.id || delta.baseRoot != base.root {
			return nil, fmt.Errorf("%w: tx %d has base %s, want %s", ErrStaleBase, delta.txIndex, delta.baseID.Hex(), base.id.Hex())
		}
	}

	observed := make(map[common.Address]observedAccess)
	for _, delta := range ordered {
		for _, access := range delta.accesses {
			previous, exists := observed[access.Address]
			if exists && (previous.mode == AccessWrite || access.Mode == AccessWrite) {
				return nil, fmt.Errorf("%w: account %s tx %d mode %d overlaps tx %d mode %d", ErrConflict, access.Address.Hex(), previous.txIndex, previous.mode, delta.txIndex, access.Mode)
			}
			if !exists {
				observed[access.Address] = observedAccess{mode: access.Mode, txIndex: delta.txIndex}
			}
		}
	}

	var shardMaps [ShardCount]map[common.Address][]byte
	touched := make(map[byte]struct{})
	accountCount := base.accountCount
	for _, delta := range ordered {
		for _, change := range delta.changes {
			index := change.Address[0]
			if shardMaps[index] == nil {
				shardMaps[index] = cloneAccountMap(base.shards[index].accounts)
				touched[index] = struct{}{}
			}
			_, existed := shardMaps[index][change.Address]
			switch change.Kind {
			case ChangePut:
				if !existed {
					accountCount++
				}
				shardMaps[index][change.Address] = cloneBytes(change.Value)
			case ChangeDelete:
				if existed {
					delete(shardMaps[index], change.Address)
					accountCount--
				}
			}
		}
	}

	indices := make([]int, 0, len(touched))
	for index := range touched {
		indices = append(indices, int(index))
	}
	sort.Ints(indices)
	inputs := make([]shardCommitmentInput, len(indices))
	for position, index := range indices {
		inputs[position] = shardCommitmentInput{index: byte(index), accounts: shardMaps[index]}
	}
	roots := commitShardRoots(inputs, workers)

	child := &Version{
		parentID:     base.id,
		number:       base.number + 1,
		accountCount: accountCount,
		initialized:  true,
	}
	for index := 0; index < ShardCount; index++ {
		child.shards[index] = base.shards[index]
	}
	for position, index := range indices {
		child.shards[index] = &stateShard{accounts: shardMaps[index], root: roots[position]}
	}
	child.root = computeStateRoot(child.shards)
	child.id = computeVersionID(child.parentID, child.number, child.root)
	return child, nil
}

func cloneAccountMap(source map[common.Address][]byte) map[common.Address][]byte {
	result := make(map[common.Address][]byte, len(source))
	for address, value := range source {
		// Values are themselves immutable and may be shared by COW shards. Public
		// reads and all incoming writes are copied.
		result[address] = value
	}
	return result
}
