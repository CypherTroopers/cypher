package mvcc

import (
	"encoding/binary"
	"sort"
	"sync"

	"github.com/cypherium/cypher/common"
	"github.com/zeebo/blake3"
)

const (
	// ShardCount is fixed by CommitmentFormatVersion. An address belongs to the
	// shard selected by address[0].
	ShardCount = 256

	// CommitmentFormatVersion identifies the byte-exact format documented in
	// doc.go. Changing any domain or encoding rule requires a new version.
	CommitmentFormatVersion uint16 = 1

	// MaxCommitmentWorkers is a local resource bound, not a consensus input.
	// Roots are identical for every positive worker count.
	MaxCommitmentWorkers = 64

	AccountLeafDomain  = "cypher.mvcc.account-leaf.v1\x00"
	AccountNodeDomain  = "cypher.mvcc.account-node.v1\x00"
	AccountEmptyDomain = "cypher.mvcc.account-empty.v1\x00"
	ShardDomain        = "cypher.mvcc.shard.v1\x00"
	ShardNodeDomain    = "cypher.mvcc.shard-node.v1\x00"
	StateDomain        = "cypher.mvcc.state.v1\x00"
	VersionDomain      = "cypher.mvcc.version.v1\x00"
	DeltaDomain        = "cypher.mvcc.delta.v1\x00"
)

func hashParts(domain string, parts ...[]byte) common.Hash {
	hasher := blake3.New()
	_, _ = hasher.Write([]byte(domain))
	for _, part := range parts {
		_, _ = hasher.Write(part)
	}
	var result common.Hash
	copy(result[:], hasher.Sum(nil))
	return result
}

func uint16Bytes(value uint16) []byte {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	return encoded[:]
}

func uint64Bytes(value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return encoded[:]
}

func hashAccountLeaf(address common.Address, value []byte) common.Hash {
	return hashParts(AccountLeafDomain, address[:], uint64Bytes(uint64(len(value))), value)
}

func hashMerkleNode(domain string, level uint16, left, right common.Hash) common.Hash {
	return hashParts(domain, uint16Bytes(level), left[:], right[:])
}

func merkleRoot(leaves []common.Hash, nodeDomain, emptyDomain string) common.Hash {
	if len(leaves) == 0 {
		return hashParts(emptyDomain)
	}
	level := append([]common.Hash(nil), leaves...)
	for depth := uint16(0); len(level) > 1; depth++ {
		next := make([]common.Hash, (len(level)+1)/2)
		for index := 0; index < len(level); index += 2 {
			left := level[index]
			right := left
			if index+1 < len(level) {
				right = level[index+1]
			}
			next[index/2] = hashMerkleNode(nodeDomain, depth, left, right)
		}
		level = next
	}
	return level[0]
}

func computeShardRoot(index byte, accounts map[common.Address][]byte) common.Hash {
	addresses := make([]common.Address, 0, len(accounts))
	for address := range accounts {
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(i, j int) bool {
		return addressLess(addresses[i], addresses[j])
	})
	leaves := make([]common.Hash, len(addresses))
	for i, address := range addresses {
		leaves[i] = hashAccountLeaf(address, accounts[address])
	}
	treeRoot := merkleRoot(leaves, AccountNodeDomain, AccountEmptyDomain)
	return hashParts(ShardDomain, []byte{index}, uint64Bytes(uint64(len(addresses))), treeRoot[:])
}

func computeStateRoot(shards [ShardCount]*stateShard) common.Hash {
	leaves := make([]common.Hash, ShardCount)
	for index, shard := range shards {
		leaves[index] = shard.root
	}
	// The shard tree is never empty because all 256 position-specific shard
	// roots, including empty shards, are committed.
	treeRoot := merkleRoot(leaves, ShardNodeDomain, "")
	return hashParts(StateDomain, uint16Bytes(ShardCount), treeRoot[:])
}

func computeVersionID(parent common.Hash, number uint64, root common.Hash) common.Hash {
	return hashParts(VersionDomain, parent[:], uint64Bytes(number), root[:])
}

type shardCommitmentInput struct {
	index    byte
	accounts map[common.Address][]byte
}

func commitmentWorkerCount(requested, jobs int) int {
	if jobs <= 0 {
		return 0
	}
	if requested < 1 {
		requested = 1
	}
	if requested > MaxCommitmentWorkers {
		requested = MaxCommitmentWorkers
	}
	if requested > jobs {
		requested = jobs
	}
	return requested
}

// commitShardRoots hashes independent shard snapshots with a bounded persistent
// worker set. Each result slot has exactly one writer.
func commitShardRoots(inputs []shardCommitmentInput, requestedWorkers int) []common.Hash {
	roots := make([]common.Hash, len(inputs))
	workers := commitmentWorkerCount(requestedWorkers, len(inputs))
	if workers == 0 {
		return roots
	}
	if workers == 1 {
		for index, input := range inputs {
			roots[index] = computeShardRoot(input.index, input.accounts)
		}
		return roots
	}

	jobs := make(chan int)
	var wait sync.WaitGroup
	wait.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wait.Done()
			for index := range jobs {
				input := inputs[index]
				roots[index] = computeShardRoot(input.index, input.accounts)
			}
		}()
	}
	for index := range inputs {
		jobs <- index
	}
	close(jobs)
	wait.Wait()
	return roots
}
