package core

import (
	"sync"

	"github.com/cypherium/cypher/common"
	parallelstate "github.com/cypherium/cypher/core/parallel"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

// A handoff is an opportunistic node-local optimisation, never consensus
// state. Both entry count and retained schedule memory are bounded so a stream
// of valid competing proposals cannot turn validation into an unbounded cache.
const (
	nativeScheduleHandoffMaxEntries = 16
	nativeScheduleHandoffMaxBytes   = uint64(64 * 1024 * 1024)
	nativeScheduleHandoffBaseBytes  = uint64(256)
	nativeScheduleHandoffWaveBytes  = uint64(64)
	nativeScheduleHandoffIndexBytes = uint64(16)
)

// nativeScheduleConfigIdentity snapshots every genesis-native limit. Using
// values rather than a config pointer prevents a schedule validated under one
// rule set from being consumed after a test/local config replacement.
type nativeScheduleConfigIdentity struct {
	chainID                      string
	requireNativeTransactions    bool
	maxTransactionsPerBlock      uint64
	maxBlockBytes                uint64
	maxTransactionBytes          uint64
	maxAccessesPerTransaction    uint64
	maxAccessesPerBlock          uint64
	maxComputePerTransaction     uint64
	maxComputePerBlock           uint64
	maxCriticalPathCompute       uint64
	maxDependencyDepth           uint64
	maxMemoryBytesPerTransaction uint64
	maxLogBytesPerTransaction    uint64
	maxLogBytesPerBlock          uint64
	maxReceiptBytesPerBlock      uint64
	maxOutputBytesPerTransaction uint64
	replayWindowBlocks           uint64
}

func nativeScheduleIdentity(config *params.ChainConfig) (nativeScheduleConfigIdentity, bool) {
	if config == nil || !config.NativeParallelEnabled() || config.NativeParallel == nil {
		return nativeScheduleConfigIdentity{}, false
	}
	native := config.NativeParallel
	chainID := "<nil>"
	if config.ChainID != nil {
		chainID = config.ChainID.String()
	}
	return nativeScheduleConfigIdentity{
		chainID:                      chainID,
		requireNativeTransactions:    native.RequireNativeTransactions,
		maxTransactionsPerBlock:      native.MaxTransactionsPerBlock,
		maxBlockBytes:                native.MaxBlockBytes,
		maxTransactionBytes:          native.MaxTransactionBytes,
		maxAccessesPerTransaction:    native.MaxAccessesPerTransaction,
		maxAccessesPerBlock:          native.MaxAccessesPerBlock,
		maxComputePerTransaction:     native.MaxComputePerTransaction,
		maxComputePerBlock:           native.MaxComputePerBlock,
		maxCriticalPathCompute:       native.MaxCriticalPathCompute,
		maxDependencyDepth:           native.MaxDependencyDepth,
		maxMemoryBytesPerTransaction: native.MaxMemoryBytesPerTransaction,
		maxLogBytesPerTransaction:    native.MaxLogBytesPerTransaction,
		maxLogBytesPerBlock:          native.MaxLogBytesPerBlock,
		maxReceiptBytesPerBlock:      native.MaxReceiptBytesPerBlock,
		maxOutputBytesPerTransaction: native.MaxOutputBytesPerTransaction,
		replayWindowBlocks:           native.ReplayWindowBlocks,
	}, true
}

type nativeScheduleHandoffKey struct {
	blockHash        common.Hash
	transactionRoot  common.Hash
	transactionCount uint64
	config           nativeScheduleConfigIdentity
}

func nativeScheduleKey(config *params.ChainConfig, block *types.Block) (nativeScheduleHandoffKey, bool) {
	identity, ok := nativeScheduleIdentity(config)
	if !ok || block == nil {
		return nativeScheduleHandoffKey{}, false
	}
	return nativeScheduleHandoffKey{
		blockHash:        block.Hash(),
		transactionRoot:  block.TxHash(),
		transactionCount: uint64(len(block.Transactions())),
		config:           identity,
	}, true
}

func nativeScheduleRetainedBytes(schedule *parallelstate.Schedule) (uint64, bool) {
	if schedule == nil {
		return 0, false
	}
	weight := nativeScheduleHandoffBaseBytes
	for _, wave := range schedule.Waves {
		if weight > nativeScheduleHandoffMaxBytes-nativeScheduleHandoffWaveBytes {
			return 0, false
		}
		weight += nativeScheduleHandoffWaveBytes
		indexes := uint64(len(wave))
		if indexes > (nativeScheduleHandoffMaxBytes-weight)/nativeScheduleHandoffIndexBytes {
			return 0, false
		}
		weight += indexes * nativeScheduleHandoffIndexBytes
	}
	return weight, true
}

type nativeScheduleHandoffEntry struct {
	schedule *parallelstate.Schedule
	bytes    uint64
}

// nativeScheduleHandoff transfers exclusive ownership of a validated schedule
// to the first matching executor. A miss is harmless: Process rebuilds the
// canonical schedule from signed manifests.
type nativeScheduleHandoff struct {
	mu       sync.Mutex
	entries  map[nativeScheduleHandoffKey]nativeScheduleHandoffEntry
	order    []nativeScheduleHandoffKey
	retained uint64
}

func newNativeScheduleHandoff() *nativeScheduleHandoff {
	return &nativeScheduleHandoff{entries: make(map[nativeScheduleHandoffKey]nativeScheduleHandoffEntry)}
}

func (h *nativeScheduleHandoff) publish(config *params.ChainConfig, block *types.Block, schedule *parallelstate.Schedule) bool {
	if h == nil {
		return false
	}
	key, ok := nativeScheduleKey(config, block)
	if !ok {
		return false
	}
	weight, ok := nativeScheduleRetainedBytes(schedule)
	if !ok || weight > nativeScheduleHandoffMaxBytes {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if old, exists := h.entries[key]; exists {
		h.removeLocked(key, old)
	}
	for len(h.entries) >= nativeScheduleHandoffMaxEntries || h.retained > nativeScheduleHandoffMaxBytes-weight {
		if len(h.order) == 0 {
			return false
		}
		oldest := h.order[0]
		entry, exists := h.entries[oldest]
		if !exists {
			h.order = h.order[1:]
			continue
		}
		h.removeLocked(oldest, entry)
	}
	h.entries[key] = nativeScheduleHandoffEntry{schedule: schedule, bytes: weight}
	h.order = append(h.order, key)
	h.retained += weight
	return true
}

func (h *nativeScheduleHandoff) take(config *params.ChainConfig, block *types.Block) *parallelstate.Schedule {
	if h == nil {
		return nil
	}
	key, ok := nativeScheduleKey(config, block)
	if !ok {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	entry, exists := h.entries[key]
	if !exists {
		return nil
	}
	h.removeLocked(key, entry)
	return entry.schedule
}

func (h *nativeScheduleHandoff) removeLocked(key nativeScheduleHandoffKey, entry nativeScheduleHandoffEntry) {
	delete(h.entries, key)
	if entry.bytes <= h.retained {
		h.retained -= entry.bytes
	} else {
		h.retained = 0
	}
	for index := range h.order {
		if h.order[index] == key {
			copy(h.order[index:], h.order[index+1:])
			h.order = h.order[:len(h.order)-1]
			break
		}
	}
}
