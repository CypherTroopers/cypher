package mvcc

import (
	"bytes"
	"errors"

	"github.com/cypherium/cypher/common"
)

var ErrInvalidVersion = errors.New("invalid MVCC state version")

type stateShard struct {
	accounts map[common.Address][]byte
	root     common.Hash
}

// Version is an immutable state snapshot. All fields and backing collections
// are private; byte-returning methods return copies.
type Version struct {
	id           common.Hash
	parentID     common.Hash
	number       uint64
	root         common.Hash
	accountCount uint64
	shards       [ShardCount]*stateShard
	initialized  bool
}

// NewVersion creates the genesis state version from opaque canonical account
// encodings. Input maps and values are copied before publication.
func NewVersion(initial map[common.Address][]byte, workers int) *Version {
	var shardMaps [ShardCount]map[common.Address][]byte
	for address, value := range initial {
		index := address[0]
		if shardMaps[index] == nil {
			shardMaps[index] = make(map[common.Address][]byte)
		}
		shardMaps[index][address] = cloneBytes(value)
	}
	inputs := make([]shardCommitmentInput, ShardCount)
	for index := 0; index < ShardCount; index++ {
		if shardMaps[index] == nil {
			shardMaps[index] = make(map[common.Address][]byte)
		}
		inputs[index] = shardCommitmentInput{index: byte(index), accounts: shardMaps[index]}
	}
	roots := commitShardRoots(inputs, workers)
	version := &Version{accountCount: uint64(len(initial)), initialized: true}
	for index := 0; index < ShardCount; index++ {
		version.shards[index] = &stateShard{accounts: shardMaps[index], root: roots[index]}
	}
	version.root = computeStateRoot(version.shards)
	version.id = computeVersionID(common.Hash{}, 0, version.root)
	return version
}

// NewEmptyVersion creates the canonical empty genesis version.
func NewEmptyVersion(workers int) *Version {
	return NewVersion(nil, workers)
}

// ID identifies both the state and its lineage. Unlike Root, it changes for an
// empty child version because it includes ParentID and Number.
func (v *Version) ID() common.Hash {
	if v == nil {
		return common.Hash{}
	}
	return v.id
}

func (v *Version) ParentID() common.Hash {
	if v == nil {
		return common.Hash{}
	}
	return v.parentID
}

func (v *Version) Number() uint64 {
	if v == nil {
		return 0
	}
	return v.number
}

func (v *Version) Root() common.Hash {
	if v == nil {
		return common.Hash{}
	}
	return v.root
}

func (v *Version) Len() uint64 {
	if v == nil {
		return 0
	}
	return v.accountCount
}

// ShardRoot returns the position-specific commitment for one prefix shard.
func (v *Version) ShardRoot(index byte) common.Hash {
	if v == nil || !v.initialized || v.shards[index] == nil {
		return common.Hash{}
	}
	return v.shards[index].root
}

// Get returns a defensive copy of an account encoding.
func (v *Version) Get(address common.Address) ([]byte, bool) {
	if v == nil || !v.initialized {
		return nil, false
	}
	shard := v.shards[address[0]]
	if shard == nil {
		return nil, false
	}
	value, exists := shard.accounts[address]
	if !exists {
		return nil, false
	}
	return cloneBytes(value), true
}

func (v *Version) valid() bool {
	if v == nil || !v.initialized {
		return false
	}
	for _, shard := range v.shards {
		if shard == nil || shard.accounts == nil {
			return false
		}
	}
	return true
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	return append([]byte(nil), value...)
}

func addressLess(left, right common.Address) bool {
	return bytes.Compare(left[:], right[:]) < 0
}
