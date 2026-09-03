// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

// Package parallel contains consensus-safe scheduling primitives for the
// genesis-native parallel transaction executor. The package deliberately has
// no dependency on StateDB or the VM: proposers and validators must derive the
// exact same dependency waves from signed transaction manifests alone.
package parallel

import (
	"errors"
	"fmt"
	"math"

	"github.com/cypherium/cypher/common"
)

// AccessMode describes how one transaction uses a consensus state resource.
// A write conflicts with every earlier read or write of the same resource;
// reads conflict only with an earlier write.
type AccessMode uint8

const (
	AccessRead AccessMode = iota + 1
	AccessWrite
)

// ResourceKind separates account metadata from contract storage. Keeping the
// unhashed identity in the manifest avoids making scheduler correctness depend
// on collision resistance.
type ResourceKind uint8

const (
	ResourceAccount ResourceKind = iota + 1
	ResourceStorage
)

// Resource identifies one independently lockable item. Storage resources use
// Address and Slot; account resources require a zero Slot.
type Resource struct {
	Kind    ResourceKind
	Address common.Address
	Slot    common.Hash
}

// Access is one canonical read or write declaration.
type Access struct {
	Resource Resource
	Mode     AccessMode
}

// Transaction is the scheduler projection of a signed native transaction.
// Compute is a consensus-declared upper bound, not an execution estimate.
type Transaction struct {
	Accesses []Access
	Compute  uint64
}

// Limits bounds both total work and the longest serial dependency chain. The
// latter prevents a Byzantine proposer from constructing an otherwise valid
// block whose transactions all contend on one hot resource.
type Limits struct {
	Transactions        uint64
	AccessesPerTx       uint64
	AccessesPerBlock    uint64
	ComputePerTx        uint64
	ComputePerBlock     uint64
	CriticalPathCompute uint64
	DependencyDepth     uint64
}

// Schedule groups transaction indexes into deterministic dependency waves.
// All transactions in one wave are conflict-free and may execute concurrently.
type Schedule struct {
	Waves               [][]int
	TotalAccesses       uint64
	TotalCompute        uint64
	CriticalPathCompute uint64
	DependencyDepth     uint64
}

var (
	ErrInvalidResource = errors.New("invalid parallel resource")
	ErrInvalidAccess   = errors.New("invalid parallel access")
	ErrDuplicateAccess = errors.New("duplicate parallel access")
	ErrWorkLimit       = errors.New("parallel work limit exceeded")
)

type resourceFrontier struct {
	writerWave   uint64
	writerFinish uint64
	readerWave   uint64
	readerFinish uint64
	hasWriter    bool
	hasReaders   bool
}

// Planner incrementally builds the same deterministic schedule as Build. A
// rejected transaction leaves the planner unchanged, which lets a proposer
// skip a hot/over-budget candidate without rebuilding the dependency graph for
// every following transaction. Validators still call Build over the final
// canonical block order.
type Planner struct {
	limits    Limits
	frontiers map[Resource]resourceFrontier
	result    Schedule
	txCount   uint64
}

func NewPlanner(limits Limits) *Planner {
	return &Planner{limits: limits, frontiers: make(map[Resource]resourceFrontier)}
}

// TryAdd appends one transaction to the schedule. It is transactional: all
// validation and limit checks complete before any frontier or total changes.
func (p *Planner) TryAdd(tx Transaction) error {
	if p == nil {
		return fmt.Errorf("%w: nil planner", ErrWorkLimit)
	}
	index := p.txCount
	if index >= p.limits.Transactions {
		return fmt.Errorf("%w: transaction %d makes transaction count exceed %d", ErrWorkLimit, index, p.limits.Transactions)
	}
	if tx.Compute == 0 || tx.Compute > p.limits.ComputePerTx {
		return fmt.Errorf("%w: transaction %d compute %d exceeds range 1..%d", ErrWorkLimit, index, tx.Compute, p.limits.ComputePerTx)
	}
	if uint64(len(tx.Accesses)) > p.limits.AccessesPerTx {
		return fmt.Errorf("%w: transaction %d accesses %d exceed %d", ErrWorkLimit, index, len(tx.Accesses), p.limits.AccessesPerTx)
	}
	if uint64(len(tx.Accesses)) > math.MaxUint64-p.result.TotalAccesses || p.result.TotalAccesses+uint64(len(tx.Accesses)) > p.limits.AccessesPerBlock {
		return fmt.Errorf("%w: transaction %d makes access total exceed %d", ErrWorkLimit, index, p.limits.AccessesPerBlock)
	}
	if tx.Compute > math.MaxUint64-p.result.TotalCompute || p.result.TotalCompute+tx.Compute > p.limits.ComputePerBlock {
		return fmt.Errorf("%w: transaction %d makes compute total exceed %d", ErrWorkLimit, index, p.limits.ComputePerBlock)
	}

	seen := make(map[Resource]struct{}, len(tx.Accesses))
	var predecessorWave, predecessorFinish uint64
	for accessIndex, access := range tx.Accesses {
		if err := validateAccess(access); err != nil {
			return fmt.Errorf("transaction %d access %d: %w", index, accessIndex, err)
		}
		if _, exists := seen[access.Resource]; exists {
			return fmt.Errorf("transaction %d access %d: %w", index, accessIndex, ErrDuplicateAccess)
		}
		seen[access.Resource] = struct{}{}
		frontier := p.frontiers[access.Resource]
		if frontier.hasWriter {
			predecessorWave = max(predecessorWave, frontier.writerWave)
			predecessorFinish = max(predecessorFinish, frontier.writerFinish)
		}
		if access.Mode == AccessWrite && frontier.hasReaders {
			predecessorWave = max(predecessorWave, frontier.readerWave)
			predecessorFinish = max(predecessorFinish, frontier.readerFinish)
		}
	}

	wave := uint64(1)
	if predecessorWave != 0 {
		wave = predecessorWave + 1
	}
	if wave > p.limits.DependencyDepth {
		return fmt.Errorf("%w: transaction %d dependency depth %d exceeds %d", ErrWorkLimit, index, wave, p.limits.DependencyDepth)
	}
	if tx.Compute > math.MaxUint64-predecessorFinish {
		return fmt.Errorf("%w: transaction %d critical path overflows", ErrWorkLimit, index)
	}
	finish := predecessorFinish + tx.Compute
	if finish > p.limits.CriticalPathCompute {
		return fmt.Errorf("%w: transaction %d critical path compute %d exceeds %d", ErrWorkLimit, index, finish, p.limits.CriticalPathCompute)
	}

	// All checks have passed. Publish this append atomically to the planner.
	for uint64(len(p.result.Waves)) < wave {
		p.result.Waves = append(p.result.Waves, nil)
	}
	p.result.Waves[wave-1] = append(p.result.Waves[wave-1], int(index))
	for _, access := range tx.Accesses {
		frontier := p.frontiers[access.Resource]
		if access.Mode == AccessRead {
			frontier.hasReaders = true
			frontier.readerWave = max(frontier.readerWave, wave)
			frontier.readerFinish = max(frontier.readerFinish, finish)
		} else {
			frontier.hasWriter = true
			frontier.writerWave = wave
			frontier.writerFinish = finish
			frontier.hasReaders = false
			frontier.readerWave = 0
			frontier.readerFinish = 0
		}
		p.frontiers[access.Resource] = frontier
	}
	p.result.TotalAccesses += uint64(len(tx.Accesses))
	p.result.TotalCompute += tx.Compute
	p.result.CriticalPathCompute = max(p.result.CriticalPathCompute, finish)
	p.result.DependencyDepth = max(p.result.DependencyDepth, wave)
	p.txCount++
	return nil
}

// Schedule returns an immutable snapshot of the accepted plan.
func (p *Planner) Schedule() *Schedule {
	if p == nil {
		return nil
	}
	result := p.result
	result.Waves = make([][]int, len(p.result.Waves))
	for index := range p.result.Waves {
		result.Waves[index] = append([]int(nil), p.result.Waves[index]...)
	}
	return &result
}

// TakeSchedule transfers ownership of the accumulated wave slices and releases
// the frontier table. Callers must not use the planner afterward. This avoids a
// second O(transactions) wave copy on the validator/executor hot path.
func (p *Planner) TakeSchedule() *Schedule {
	if p == nil {
		return nil
	}
	result := p.result
	p.result = Schedule{}
	p.frontiers = nil
	p.txCount = 0
	return &result
}

// Build derives the canonical schedule in block order. It is intentionally
// independent of local worker count, queue timing and map iteration order.
func Build(txs []Transaction, limits Limits) (*Schedule, error) {
	if uint64(len(txs)) > limits.Transactions {
		return nil, fmt.Errorf("%w: transactions %d exceed %d", ErrWorkLimit, len(txs), limits.Transactions)
	}
	planner := NewPlanner(limits)
	for _, tx := range txs {
		if err := planner.TryAdd(tx); err != nil {
			return nil, err
		}
	}
	return planner.Schedule(), nil
}

func validateAccess(access Access) error {
	if access.Mode != AccessRead && access.Mode != AccessWrite {
		return ErrInvalidAccess
	}
	switch access.Resource.Kind {
	case ResourceAccount:
		if access.Resource.Slot != (common.Hash{}) {
			return ErrInvalidResource
		}
	case ResourceStorage:
		// A zero storage slot is valid EVM/program state and must not be rejected.
	default:
		return ErrInvalidResource
	}
	return nil
}

func max(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
