package core

import (
	"fmt"
	"math"
	"sync"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

// A validated sidecar handoff is an opportunistic node-local optimisation,
// never consensus state. It retains only transaction-aligned approvers and
// reward positions, not certificates, transaction hashes, rewards, or block
// bodies. The first matching executor consumes exclusive ownership; a miss
// performs the complete deterministic validation again.
const (
	fhsSidecarHandoffMaxEntries = 16
	fhsSidecarHandoffMaxBytes   = uint64(128 * 1024 * 1024)
	fhsSidecarHandoffBaseBytes  = uint64(512)
	// Charge conservatively for one address, one uint32 position, slice
	// backing/alignment, and allocator overhead per transaction.
	fhsSidecarHandoffTxBytes = uint64(32)

	fhsRewardPositionMissing = uint32(math.MaxUint32)
)

// fhsSidecarValidationContext is resolved from canonical chain state. Both
// fields are signed/consensus boundaries for common-RPC admissions and are
// therefore part of the handoff identity rather than implicit cache state.
type fhsSidecarValidationContext struct {
	genesisHash    common.Hash
	keyBlockNumber uint64
}

func isFHSSidecarHandoffCandidate(config *params.ChainConfig, block *types.Block, body *types.Body) bool {
	if config == nil || !config.FairHotstuff || block == nil || body == nil || len(body.Transactions) == 0 || len(body.CommonTxAdmissionBatches) == 0 {
		return false
	}
	if block.BlockType() != types.FastTx_Block && block.BlockType() != types.SlowTx_Block {
		return false
	}
	return len(body.CommonTxAdmissionRefs) == len(body.Transactions) && len(body.CommonTxRewards) == len(body.Transactions)
}

type fhsSidecarHandoffKey struct {
	blockHash        common.Hash
	transactionRoot  common.Hash
	admissionRoot    common.Hash
	rewardRoot       common.Hash
	genesisHash      common.Hash
	keyHash          common.Hash
	configCommitment common.Hash
	transactionCount uint64
	blockNumber      uint64
	keyBlockNumber   uint64
	blockTimestamp   uint64
	blockType        uint8
}

func makeFHSSidecarHandoffKey(config *params.ChainConfig, block *types.Block, context fhsSidecarValidationContext) (fhsSidecarHandoffKey, bool) {
	if config == nil || !config.FairHotstuff || block == nil || block.Header0() == nil || block.Header0().Number == nil || context.genesisHash == (common.Hash{}) {
		return fhsSidecarHandoffKey{}, false
	}
	configCommitment, err := params.FairHotstuffGenesisCommitment(config)
	if err != nil || configCommitment == (common.Hash{}) {
		return fhsSidecarHandoffKey{}, false
	}
	header := block.Header0()
	return fhsSidecarHandoffKey{
		blockHash:        block.Hash(),
		transactionRoot:  header.TxHash,
		admissionRoot:    header.CommonTxAdmissionRoot,
		rewardRoot:       header.CommonTxRewardRoot,
		genesisHash:      context.genesisHash,
		keyHash:          header.KeyHash,
		configCommitment: configCommitment,
		transactionCount: uint64(len(block.Transactions())),
		blockNumber:      header.Number.Uint64(),
		keyBlockNumber:   context.keyBlockNumber,
		blockTimestamp:   header.Time,
		blockType:        header.BlockType,
	}, true
}

// validatedFHSSidecars is immutable after construction. rewardPositions maps
// transaction index to the already-validated reward position in the immutable
// block body. Keeping positions instead of reward pointers prevents a bounded
// cache entry from retaining the much larger sidecar object graph.
type validatedFHSSidecars struct {
	approvers       []common.Address
	rewardPositions []uint32
}

func (validated *validatedFHSSidecars) rewardForTransaction(body *types.Body, transactionIndex int) (*types.CommonTxReward, bool) {
	if validated == nil || body == nil || transactionIndex < 0 || transactionIndex >= len(validated.rewardPositions) {
		return nil, false
	}
	position := validated.rewardPositions[transactionIndex]
	if position == fhsRewardPositionMissing || uint64(position) >= uint64(len(body.CommonTxRewards)) {
		return nil, false
	}
	reward := body.CommonTxRewards[position]
	return reward, reward != nil
}

func retainedFHSSidecarBytes(validated *validatedFHSSidecars) (uint64, bool) {
	if validated == nil || len(validated.approvers) != len(validated.rewardPositions) {
		return 0, false
	}
	count := uint64(len(validated.approvers))
	if count > (fhsSidecarHandoffMaxBytes-fhsSidecarHandoffBaseBytes)/fhsSidecarHandoffTxBytes {
		return 0, false
	}
	return fhsSidecarHandoffBaseBytes + count*fhsSidecarHandoffTxBytes, true
}

type fhsSidecarHandoffEntry struct {
	validated *validatedFHSSidecars
	bytes     uint64
}

type fhsSidecarHandoff struct {
	mu       sync.Mutex
	entries  map[fhsSidecarHandoffKey]fhsSidecarHandoffEntry
	order    []fhsSidecarHandoffKey
	retained uint64
}

func newFHSSidecarHandoff() *fhsSidecarHandoff {
	return &fhsSidecarHandoff{entries: make(map[fhsSidecarHandoffKey]fhsSidecarHandoffEntry)}
}

// publish transfers the caller's immutable artifact into the bounded handoff.
// It deliberately does not clone the slices: construction returns fresh,
// private backing and callers must relinquish ownership after a successful
// publish. This avoids a second maximum-block-sized allocation on validation.
func (handoff *fhsSidecarHandoff) publish(config *params.ChainConfig, block *types.Block, context fhsSidecarValidationContext, validated *validatedFHSSidecars) bool {
	if handoff == nil || validated == nil {
		return false
	}
	key, ok := makeFHSSidecarHandoffKey(config, block, context)
	if !ok || uint64(len(validated.approvers)) != key.transactionCount {
		return false
	}
	weight, ok := retainedFHSSidecarBytes(validated)
	if !ok || weight > fhsSidecarHandoffMaxBytes {
		return false
	}
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	if old, exists := handoff.entries[key]; exists {
		handoff.removeLocked(key, old)
	}
	for len(handoff.entries) >= fhsSidecarHandoffMaxEntries || handoff.retained > fhsSidecarHandoffMaxBytes-weight {
		if len(handoff.order) == 0 {
			return false
		}
		oldest := handoff.order[0]
		entry, exists := handoff.entries[oldest]
		if !exists {
			handoff.order = handoff.order[1:]
			continue
		}
		handoff.removeLocked(oldest, entry)
	}
	handoff.entries[key] = fhsSidecarHandoffEntry{validated: validated, bytes: weight}
	handoff.order = append(handoff.order, key)
	handoff.retained += weight
	return true
}

func (handoff *fhsSidecarHandoff) take(config *params.ChainConfig, block *types.Block, context fhsSidecarValidationContext) *validatedFHSSidecars {
	if handoff == nil {
		return nil
	}
	key, ok := makeFHSSidecarHandoffKey(config, block, context)
	if !ok {
		return nil
	}
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	entry, exists := handoff.entries[key]
	if !exists {
		return nil
	}
	handoff.removeLocked(key, entry)
	return entry.validated
}

func (handoff *fhsSidecarHandoff) removeLocked(key fhsSidecarHandoffKey, entry fhsSidecarHandoffEntry) {
	delete(handoff.entries, key)
	if entry.bytes <= handoff.retained {
		handoff.retained -= entry.bytes
	} else {
		handoff.retained = 0
	}
	for index := range handoff.order {
		if handoff.order[index] == key {
			copy(handoff.order[index:], handoff.order[index+1:])
			handoff.order = handoff.order[:len(handoff.order)-1]
			break
		}
	}
}

func validateCommonTxSidecarRoots(block *types.Block) error {
	if block == nil || block.Header0() == nil {
		return fmt.Errorf("missing block for common transaction sidecar validation")
	}
	header := block.Header0()
	body := block.Body()
	if hash := types.DeriveCommonTxAdmissionRoot(body.CommonTxAdmissionBatches, body.CommonTxAdmissionRefs); hash != header.CommonTxAdmissionRoot {
		return fmt.Errorf("common tx admission root mismatch: have %x, want %x", hash, header.CommonTxAdmissionRoot)
	}
	if hash := types.DeriveCommonTxRewardRoot(body.CommonTxRewards); hash != header.CommonTxRewardRoot {
		return fmt.Errorf("common tx reward root mismatch: have %x, want %x", hash, header.CommonTxRewardRoot)
	}
	return nil
}

func buildValidatedFHSSidecarLayout(config *params.ChainConfig, block *types.Block, context fhsSidecarValidationContext) (*validatedFHSSidecars, error) {
	if block == nil {
		return nil, fmt.Errorf("missing block for common transaction sidecar validation")
	}
	body := block.Body()
	txs := body.Transactions
	batches := body.CommonTxAdmissionBatches
	refs := body.CommonTxAdmissionRefs

	var approvers []common.Address
	if len(batches) != 0 || len(refs) != 0 {
		if config != nil && config.FairHotstuff && context.genesisHash == (common.Hash{}) {
			return nil, fmt.Errorf("missing Fair HotStuff genesis identity for common tx admission validation")
		}
		var err error
		approvers, err = validateCommonTxAdmissionLayout(config, batches, refs, txs, context.genesisHash)
		if err != nil {
			return nil, err
		}
		for _, batch := range batches {
			if err := validateCommonRPCAdmissionForBlock(batch, context.keyBlockNumber, block.Time()); err != nil {
				return nil, err
			}
		}
	}

	rewardIndex, err := buildCommonRewardIndex(body.CommonTxRewards, txs)
	if err != nil {
		return nil, err
	}
	rewardPositions := make([]uint32, len(txs))
	for index := range rewardPositions {
		rewardPositions[index] = fhsRewardPositionMissing
	}
	for index, tx := range txs {
		if tx == nil || !tx.IsInitialized() {
			return nil, fmt.Errorf("Fair HotStuff transaction %d is nil or uninitialized", index)
		}
		position, exists := rewardIndex[tx.Hash()]
		if !exists {
			if config != nil && config.FairHotstuff {
				return nil, fmt.Errorf("common tx admission without reward for included tx: %s", tx.Hash())
			}
			continue
		}
		rewardPositions[index] = position
		delete(rewardIndex, tx.Hash())
	}
	if len(rewardIndex) != 0 {
		return nil, fmt.Errorf("%d common tx rewards were not consumed by block transactions", len(rewardIndex))
	}
	if config != nil && config.FairHotstuff && len(approvers) != len(txs) {
		return nil, fmt.Errorf("Fair HotStuff transaction count %d does not match validated approver count %d", len(txs), len(approvers))
	}
	return &validatedFHSSidecars{approvers: approvers, rewardPositions: rewardPositions}, nil
}

func verifyCommonTxAdmissionSignatures(batches []*types.CommonTxAdmissionBatch) error {
	validationErrors := make([]error, len(batches))
	for start := 0; start < len(batches); start += parallelValidationMicroBatch {
		end := start + parallelValidationMicroBatch
		if end > len(batches) {
			end = len(batches)
		}
		runBoundedParallelValidation(end-start, func(offset int) {
			index := start + offset
			validationErrors[index] = types.VerifyCommonTxAdmissionSignature(batches[index])
		})
		for index := start; index < end; index++ {
			if validationErrors[index] != nil {
				return validationErrors[index]
			}
		}
	}
	return nil
}

// verifyAndPublishValidatedFHSSidecars is the only publishing seam. Artifacts
// produced from invalid signatures never enter the handoff.
func verifyAndPublishValidatedFHSSidecars(config *params.ChainConfig, block *types.Block, context fhsSidecarValidationContext, validated *validatedFHSSidecars, handoff *fhsSidecarHandoff) error {
	if block == nil {
		return fmt.Errorf("missing block for common transaction sidecar validation")
	}
	if err := verifyCommonTxAdmissionSignatures(block.Body().CommonTxAdmissionBatches); err != nil {
		return err
	}
	if handoff != nil {
		handoff.publish(config, block, context, validated)
	}
	return nil
}

// takeOrValidateFHSSidecars consumes a validated artifact when possible and
// otherwise performs the exact deterministic fallback used by standalone
// StateProcessor callers and concurrent cache misses.
func takeOrValidateFHSSidecars(config *params.ChainConfig, block *types.Block, context fhsSidecarValidationContext, handoff *fhsSidecarHandoff) (*validatedFHSSidecars, error) {
	if handoff != nil {
		if validated := handoff.take(config, block, context); validated != nil {
			return validated, nil
		}
	}
	if err := validateFHSCommonRPCSidecarCardinality(config, block); err != nil {
		return nil, err
	}
	if err := validateCommonTxSidecarRoots(block); err != nil {
		return nil, err
	}
	validated, err := buildValidatedFHSSidecarLayout(config, block, context)
	if err != nil {
		return nil, err
	}
	if err := verifyCommonTxAdmissionSignatures(block.Body().CommonTxAdmissionBatches); err != nil {
		return nil, err
	}
	return validated, nil
}
