// Copyright 2017 The cypherBFT Authors
// This file is part of the cypherBFT library.
//
// The cypherBFT library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The cypherBFT library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the cypherBFT library. If not, see <http://www.gnu.org/licenses/>.

// Package reconfig implements Cypherium reconfiguration.
package reconfig

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/trie"
)

type txService struct {
	s             serviceI
	cph           *ReconfigBackend
	txPool        *core.TxPool
	bc            *core.BlockChain
	kbc           *core.KeyBlockChain
	config        *params.ChainConfig
	mu            sync.Mutex
	mux           *event.TypeMux
	proposedChain *proposedChain
}

var (
	errProposalGenerationChanged = errors.New("proposal generation changed during construction")
	errProposalNoWork            = errors.New("no publishable proposal work")
)

// proposalGeneration identifies every input that makes proposal execution
// deterministic. It is captured while txService.mu protects proposedChain,
// then checked again immediately before the completed block is published.
// This lets expensive selection, EVM execution and encoding run without
// serializing certificate adoption or chain-head maintenance behind txService.mu.
type proposalGeneration struct {
	proposedRevision            uint64
	admissionFinalityGeneration uint64
	parentHash                  common.Hash
	parentRoot                  common.Hash
	parentNumber                uint64
	keyHash                     common.Hash
	keyNumber                   uint64
}

// txProposalCandidate is an unpublished proposal build. Expensive selection,
// execution and encoding may fill it on a worker, but only install may extend
// proposedChain or remove failed transactions from the pool.
type txProposalCandidate struct {
	block               *types.Block
	encoded             []byte
	generation          proposalGeneration
	failedTxes          types.Transactions
	blockType           uint8
	admissionCount      int
	admissionBatchCount int
	rewardCount         int
}

// keyProposalCandidate carries an unpublished key-block carrier and the exact
// transaction/key-chain generation against which it was assembled.
type keyProposalCandidate struct {
	block      *types.Block
	encoded    []byte
	generation proposalGeneration
}

func proposalHasNoPublishableWork(txCount, failedCount int, allowFinality bool) bool {
	return txCount == 0 && failedCount == 0 && !allowFinality
}

// proposalLaneBuildError preserves a real lane failure when the other lane is
// merely empty. Only two no-work results collapse to the sentinel that tells
// the proposal scheduler to wait for a new TxPool/keyblock/finality trigger.
func proposalLaneBuildError(primary, fallback error) error {
	if primary == nil {
		return fallback
	}
	if fallback == nil {
		return nil
	}
	primaryNoWork := errors.Is(primary, errProposalNoWork)
	fallbackNoWork := errors.Is(fallback, errProposalNoWork)
	switch {
	case primaryNoWork && fallbackNoWork:
		return errProposalNoWork
	case primaryNoWork:
		return fallback
	case fallbackNoWork:
		return primary
	default:
		return fallback
	}
}

func (generation proposalGeneration) matches(revision, admissionFinalityGeneration uint64, parent *types.Block, keyBlock *types.KeyBlock) bool {
	if parent == nil || keyBlock == nil || revision != generation.proposedRevision || admissionFinalityGeneration != generation.admissionFinalityGeneration {
		return false
	}
	return parent.Hash() == generation.parentHash &&
		parent.Root() == generation.parentRoot &&
		parent.NumberU64() == generation.parentNumber &&
		keyBlock.Hash() == generation.keyHash &&
		keyBlock.NumberU64() == generation.keyNumber
}

func proposalTransactionSender(config *params.ChainConfig, blockNumber *big.Int, tx *types.Transaction) (common.Address, error) {
	if config == nil || config.ChainID == nil {
		return common.Address{}, errors.New("missing chain configuration for proposal transaction")
	}
	if blockNumber == nil {
		return common.Address{}, errors.New("missing proposal block number")
	}
	if tx == nil || tx.V() == nil {
		return common.Address{}, errors.New("missing proposal transaction signature")
	}
	return types.Sender(types.MakeSignerAutoJudgement(config, blockNumber, tx.V()), tx)
}

func newTxService(s serviceI, backend *ReconfigBackend, config *params.ChainConfig) *txService {
	txS := &txService{
		s:             s,
		cph:           backend,
		bc:            backend.BlockChain(),
		kbc:           backend.KeyBlockChain(),
		txPool:        backend.TxPool(),
		config:        config,
		proposedChain: newProposedChain(),
		mux:           backend.EventMux(),
	}
	txS.proposedChain.clear(txS.bc.CurrentBlock())

	txS.bc.ProcInsertDone = txS.procBlockDone
	if lifecycle, ok := s.(interface {
		beforeFHSFinalizedSyncKeyCommit(*types.Block, *hotstuff.SignedState) (bool, error)
		waitFHSValidationPublication()
		afterFHSFinalizedSyncCommit(*types.Block, *hotstuff.SignedState, *hotstuff.SignedState) error
		finishFHSFinalizedSyncKeyCommit(*types.Block, core.FHSFinalizedSyncKeyCommitOutcome)
	}); ok {
		txS.bc.SetFHSFinalizedSyncLifecycle(
			lifecycle.beforeFHSFinalizedSyncKeyCommit,
			lifecycle.waitFHSValidationPublication,
			lifecycle.afterFHSFinalizedSyncCommit,
			lifecycle.finishFHSFinalizedSyncKeyCommit,
		)
	}

	return txS
}

// proposalExclusionState snapshots the speculative transaction filter without
// scanning it. The expiry lets proposal maintenance wake once when a stale
// exclusion becomes eligible for lazy cleanup.
func (txS *txService) proposalExclusionState() (revision uint64, nextExpiry time.Time, ok bool) {
	if txS == nil {
		return 0, time.Time{}, false
	}
	txS.mu.Lock()
	defer txS.mu.Unlock()
	if txS.proposedChain == nil {
		return 0, time.Time{}, false
	}
	return txS.proposedChain.revision, txS.proposedChain.nextProposedExpiry, true
}

func (txS *txService) buildProposalNewKeyBlock(keyblock *types.KeyBlock) (*keyProposalCandidate, error) {
	txS.mu.Lock()
	defer txS.mu.Unlock()

	work, err := txS.createWork(types.Key_Block)
	if err != nil {
		return nil, err
	}
	if work == nil || work.header == nil || work.header.Number == nil || work.header.Number.Sign() <= 0 {
		return nil, fmt.Errorf("cannot determine key block carrier parent")
	}
	if err := verifyKeyBlockCarrierParent(keyblock, work.header.Number.Uint64()-1); err != nil {
		return nil, err
	}
	generation, err := txS.captureProposalGeneration(work)
	if err != nil {
		return nil, err
	}

	header := work.header
	// commit state root after all state transitions.
	colossusX.AccumulateRewards(txS.bc.Config(), work.publicState, header, nil, nil)
	colossusX.ApplyKeyblockPowReward(work.publicState, keyblock)
	header.Root = work.publicState.IntermediateRoot(false)

	header.BlockType = types.Key_Block
	header.Difficulty = keyblock.Difficulty()
	header.MixDigest = keyblock.MixDigest()
	header.Nonce = types.EncodeNonce(keyblock.Nonce())
	header.KeyHash = keyblock.ParentHash()

	block := types.NewBlock(header, nil, nil, nil, new(trie.Trie))
	block.SetKeyblock(keyblock)

	log.Info("Generated next keyblock", "block num", block.Number(), "key T_number", keyblock.T_Number())

	encoded := block.EncodeToBytes()
	if len(encoded) == 0 {
		return nil, fmt.Errorf("failed to encode key block proposal")
	}
	return &keyProposalCandidate{block: block, encoded: encoded, generation: generation}, nil
}

func (txS *txService) installKeyProposalCandidate(candidate *keyProposalCandidate, beforePublish func() error) error {
	if candidate == nil || candidate.block == nil || len(candidate.encoded) == 0 {
		return fmt.Errorf("incomplete key block proposal candidate")
	}
	txS.mu.Lock()
	defer txS.mu.Unlock()
	if !txS.proposalGenerationCurrentLocked(candidate.generation) {
		return fmt.Errorf("%w: parent=%s key=%s", errProposalGenerationChanged, candidate.generation.parentHash, candidate.generation.keyHash)
	}
	if beforePublish != nil {
		if err := beforePublish(); err != nil {
			return err
		}
	}
	return nil
}

func (txS *txService) tryProposalNewKeyBlock(keyblock *types.KeyBlock) ([]byte, error) {
	candidate, err := txS.buildProposalNewKeyBlock(keyblock)
	if err != nil {
		return nil, err
	}
	if err := txS.installKeyProposalCandidate(candidate, nil); err != nil {
		return nil, err
	}
	return append([]byte(nil), candidate.encoded...), nil
}

func txEffectiveGasPrice(tx *types.Transaction, baseFee *big.Int) *big.Int {
	if baseFee == nil || baseFee.Sign() == 0 {
		return new(big.Int).Set(tx.GasPrice())
	}
	gasFeeCap := tx.GasFeeCap()
	gasTipCap := tx.GasTipCap()
	if gasFeeCap == nil {
		gasFeeCap = tx.GasPrice()
	}
	if gasTipCap == nil {
		gasTipCap = tx.GasPrice()
	}
	tip := new(big.Int).Sub(gasFeeCap, baseFee)
	if tip.Sign() < 0 {
		tip.SetInt64(0)
	}
	if tip.Cmp(gasTipCap) > 0 {
		tip.Set(gasTipCap)
	}
	return new(big.Int).Add(baseFee, tip)
}

func buildCommonTxRewards(txs types.Transactions, receipts types.Receipts, batches []*types.CommonTxAdmissionBatch, refs []types.CommonTxAdmissionRef, baseFee *big.Int) ([]*types.CommonTxReward, error) {
	if len(receipts) != len(txs) {
		return nil, fmt.Errorf("common RPC reward receipt count %d does not match transaction count %d", len(receipts), len(txs))
	}
	if len(refs) != len(txs) {
		return nil, fmt.Errorf("common RPC admission reference count %d does not match transaction count %d", len(refs), len(txs))
	}
	rewards := make([]*types.CommonTxReward, 0, len(txs))
	for i, tx := range txs {
		if tx == nil || receipts[i] == nil {
			return nil, fmt.Errorf("missing transaction or receipt at index %d while building common RPC reward", i)
		}
		txHash := tx.Hash()
		ref := refs[i]
		if int(ref.Batch) >= len(batches) || batches[ref.Batch] == nil {
			return nil, fmt.Errorf("Fair HotStuff transaction %s has invalid common RPC admission batch %d", txHash, ref.Batch)
		}
		batch := batches[ref.Batch]
		if err := batch.ValidateVersion(); err != nil {
			return nil, fmt.Errorf("Fair HotStuff transaction %s has invalid common RPC admission: %w", txHash, err)
		}
		if int(ref.Item) >= len(batch.TxHashes) || batch.TxHashes[ref.Item] != txHash || batch.Miner == (common.Address{}) {
			return nil, fmt.Errorf("Fair HotStuff transaction %s has invalid common RPC admission item %d", txHash, ref.Item)
		}
		actualFee := new(big.Int).Mul(new(big.Int).SetUint64(receipts[i].GasUsed), txEffectiveGasPrice(tx, baseFee))
		reward := new(big.Int).Div(actualFee, big.NewInt(5))
		burn := new(big.Int).Sub(actualFee, reward)
		rewards = append(rewards, &types.CommonTxReward{
			Version:         batch.Version,
			RewardRecipient: batch.RewardRecipient,
			TxHash:          txHash,
			Approver:        batch.Miner,
			ApproverReward:  reward,
			Burn:            burn,
		})
	}
	return rewards, nil
}

// addFHSProposalSidecarWork applies the same admission/reward meter used by
// validators to the final locally constructed sidecars before publication.
func addFHSProposalSidecarWork(meter *core.FHSBlockWorkMeter, batches []*types.CommonTxAdmissionBatch, refs []types.CommonTxAdmissionRef, rewards []*types.CommonTxReward) error {
	if meter == nil {
		return nil
	}
	return meter.AddCommonSidecars(batches, refs, rewards)
}

func applyCommonTxRewards(st *state.StateDB, rewards []*types.CommonTxReward) {
	core.ApplyCommonRPCRewards(st, rewards)
}

// currentProposalParent returns the exact parent whose state a new proposal
// must extend. Callers that also inspect proposedChain must hold txService.mu.
func (txS *txService) currentProposalParent() *types.Block {
	if txS == nil || txS.bc == nil {
		return nil
	}
	parent := txS.bc.CurrentBlock()
	if txS.config != nil && txS.config.FairHotstuff {
		if svc, ok := txS.s.(*Service); ok {
			if certified := svc.highestFHSCertifiedProposal(); certified != nil && certified.Block != nil {
				parent = certified.Block
			}
		}
	}
	return parent
}

// captureProposalGeneration must be called with txService.mu held, after work
// and the proposed-transaction filter have been constructed.
func (txS *txService) captureProposalGeneration(work *work) (proposalGeneration, error) {
	var generation proposalGeneration
	if txS == nil || work == nil || work.header == nil || txS.proposedChain == nil || txS.kbc == nil {
		return generation, fmt.Errorf("cannot capture incomplete proposal generation")
	}
	parent := txS.currentProposalParent()
	keyBlock := txS.kbc.CurrentBlock()
	if parent == nil || keyBlock == nil {
		return generation, fmt.Errorf("cannot capture proposal generation without parent and key block")
	}
	if work.header.ParentHash != parent.Hash() || work.header.Number == nil || work.header.Number.Uint64() != parent.NumberU64()+1 {
		return generation, errProposalGenerationChanged
	}
	// Bind the EVM execution context to the exact authenticated key-block
	// generation captured for this speculative build. This must happen before
	// transaction execution because post-Shanghai PREVRANDAO reads MixDigest.
	// A key-block carrier is different: its outer MixDigest commits the embedded
	// next key block and is filled by buildProposalNewKeyBlock below.
	if work.header.BlockType != types.Key_Block {
		work.header.KeyHash = keyBlock.Hash()
		if txS.config != nil && txS.config.IsShanghai(work.header.Number, work.header.Time) {
			work.header.MixDigest = keyBlock.MixDigest()
		}
	}
	return proposalGeneration{
		proposedRevision:            txS.proposedChain.revision,
		admissionFinalityGeneration: core.CommonRPCAdmissionFinalityGeneration(),
		parentHash:                  parent.Hash(),
		parentRoot:                  parent.Root(),
		parentNumber:                parent.NumberU64(),
		keyHash:                     keyBlock.Hash(),
		keyNumber:                   keyBlock.NumberU64(),
	}, nil
}

// proposalGenerationCurrentLocked must be called with txService.mu held.
func (txS *txService) proposalGenerationCurrentLocked(generation proposalGeneration) bool {
	if txS == nil || txS.proposedChain == nil || txS.kbc == nil {
		return false
	}
	return generation.matches(txS.proposedChain.revision, core.CommonRPCAdmissionFinalityGeneration(), txS.currentProposalParent(), txS.kbc.CurrentBlock())
}

func isEVMOnlyProposalMode(config *params.ChainConfig) bool {
	return config != nil && config.NativeParallelEnabled()
}

// buildProposalNewBlock constructs but does not publish a tx-block proposal.
func (txS *txService) buildProposalNewBlock(blockType uint8) (*txProposalCandidate, error) {
	if txS.config != nil && txS.config.FairHotstuff && blockType != types.FastTx_Block && blockType != types.SlowTx_Block {
		return nil, fmt.Errorf("cannot build Fair HotStuff transaction proposal with block type %d", blockType)
	}
	allAddrTxes, err := txS.loadPendingAddressTxes(blockType)
	if err != nil {
		return nil, err
	}

	var (
		work                  *work
		filteredAddrTxes      AddressTxes
		admissionSelections   map[common.Hash]core.CommonRPCAdmissionResult
		generation            proposalGeneration
		allowFHSFinalityBlock bool
	)
	if err := func() error {
		txS.mu.Lock()
		defer txS.mu.Unlock()

		var err error
		work, err = txS.createWork(blockType)
		if err != nil {
			return err
		}
		filteredAddrTxes = txS.filterProposalTransactions(blockType, allAddrTxes)
		if txS.config != nil && txS.config.FairHotstuff {
			if svc, ok := txS.s.(*Service); ok {
				allowFHSFinalityBlock = svc.needsFHSFinalityBlock()
			}
		}
		var captureErr error
		generation, captureErr = txS.captureProposalGeneration(work)
		return captureErr
	}(); err != nil {
		return nil, err
	}
	if txS.config != nil && txS.config.FairHotstuff {
		if txS.bc == nil || txS.bc.Genesis() == nil || txS.bc.Genesis().Hash() == (common.Hash{}) {
			return nil, fmt.Errorf("cannot filter Fair HotStuff admissions without genesis block")
		}
		filteredAddrTxes, admissionSelections = filterFHSAdmittedAddressTxesWithResults(
			filteredAddrTxes,
			txS.config,
			txS.bc.Genesis().Hash(),
			generation.keyNumber,
			work.header.Number.Uint64(),
			work.header.Time,
		)
	}
	transactions := types.NewTransactionsByPriceAndNonce(txS.config, work.header.Number, filteredAddrTxes)

	var (
		failedTxes          types.Transactions
		proposedBlock       *types.Block
		admissionCount      int
		admissionBatchCount int
		rewardCount         int
	)
	data, err := func() ([]byte, error) {
		// Selection, transaction execution, reward settlement and block encoding
		// intentionally run outside txService.mu. The generation check below is
		// the only path that may publish this speculative result.
		committedTxes, publicReceipts, logs, failed, err := work.commitTransactions(transactions, txS.bc)
		if err != nil {
			return nil, err
		}
		failedTxes = failed
		txCount := len(committedTxes)

		// A proposal attempt can consume only permanently invalid transaction
		// heads (stale nonce, invalid sender or intrinsic-gas failure). Publishing
		// one bounded empty cleanup proposal lets the normal generation barrier
		// remove those heads after publication. Returning early here would skip
		// failed-TX GC forever and repeatedly select the same invalid heads.
		if proposalHasNoPublishableWork(txCount, len(failedTxes), allowFHSFinalityBlock) {
			return nil, errProposalNoWork
		}

		header := work.header
		header.KeyHash = generation.keyHash
		header.BlockType = blockType
		// Blob gas is a block-body commitment. Derive it from the exact set of
		// transactions that survived proposal execution instead of leaving the
		// Cancun header at its zero default.
		header.BlobGasUsed = core.CalcBlobGasUsed(committedTxes)

		if txS.bc == nil || txS.bc.Genesis() == nil {
			return nil, fmt.Errorf("cannot build Fair HotStuff admissions without genesis block")
		}
		admissionResults, err := commonRPCAdmissionResultsForTransactions(committedTxes, admissionSelections)
		if err != nil {
			return nil, err
		}
		commonAdmissionBatches, commonAdmissionRefs, err := core.BuildCommonTxAdmissionsFromResults(committedTxes, admissionResults, txS.config, txS.bc.Genesis().Hash(), generation.keyNumber, header.Number.Uint64(), header.Time)
		if err != nil {
			return nil, fmt.Errorf("build complete Fair HotStuff admission set: %w", err)
		}
		commonRewards, err := buildCommonTxRewards(committedTxes, publicReceipts, commonAdmissionBatches, commonAdmissionRefs, header.BaseFee)
		if err != nil {
			return nil, err
		}
		if err := addFHSProposalSidecarWork(work.fhsWorkMeter, commonAdmissionBatches, commonAdmissionRefs, commonRewards); err != nil {
			return nil, fmt.Errorf("locally constructed Fair HotStuff sidecar work is invalid: %w", err)
		}
		admissionCount = len(commonAdmissionRefs)
		admissionBatchCount = len(commonAdmissionBatches)
		rewardCount = len(commonRewards)
		applyCommonTxRewards(work.publicState, commonRewards)

		// commit state root after all state transitions and Common RPC reward settlement.
		colossusX.AccumulateRewards(txS.bc.Config(), work.publicState, header, committedTxes, nil)
		header.Root = work.publicState.IntermediateRoot(false)

		block := types.NewBlock(header, committedTxes, nil, publicReceipts, new(trie.Trie))
		block.AttachCommonTxData(commonAdmissionBatches, commonAdmissionRefs, commonRewards)
		encodedBlock := block.EncodeToBytes()
		if len(encodedBlock) == 0 {
			return nil, fmt.Errorf("failed to encode tx block proposal")
		}
		if txS.config != nil && txS.config.IsOsaka(header.Number, header.Time) {
			// The FHS direct-child proof is attached only when this proposal is
			// finalized. Reserve its maximum encoded size now so a locally valid
			// proposal cannot become an over-8MiB canonical block later.
			maxProposalSize := txS.config.EffectiveMaxBlockBytes() - uint64(params.FairHotstuffFinalityProofReserveBytes)
			if uint64(len(encodedBlock)) > maxProposalSize {
				return nil, fmt.Errorf("Osaka tx block proposal too large after finality-proof reserve: bytes=%d limit=%d", len(encodedBlock), maxProposalSize)
			}
		}
		if limit := proposalByteLimit(txS.config, blockType); limit > 0 && uint64(len(encodedBlock)) > limit {
			return nil, fmt.Errorf("tx block proposal too large: blockType=%s txs=%d bytes=%d limit=%d", readableTxBlockType(blockType), txCount, len(encodedBlock), limit)
		}

		// update block hash since it is now available, but was not when the
		// receipt/log of individual transactions were created:
		headerHash := block.Hash()
		for _, l := range logs {
			l.BlockHash = headerHash
		}
		proposedBlock = block
		return encodedBlock, nil
	}()
	candidate := &txProposalCandidate{
		block:               proposedBlock,
		encoded:             append([]byte(nil), data...),
		generation:          generation,
		failedTxes:          append(types.Transactions(nil), failedTxes...),
		blockType:           blockType,
		admissionCount:      admissionCount,
		admissionBatchCount: admissionBatchCount,
		rewardCount:         rewardCount,
	}
	return candidate, err
}

// installProposalCandidate is the sole publication point for a staged tx
// proposal. The generation check and proposed-chain extension are atomic with
// respect to all other proposed-chain maintenance; failed TX GC only follows a
// successful publication.
func (txS *txService) installProposalCandidate(candidate *txProposalCandidate, beforePublish func() error) error {
	if candidate == nil || candidate.block == nil || len(candidate.encoded) == 0 {
		return fmt.Errorf("incomplete tx block proposal candidate")
	}
	txS.mu.Lock()
	if !txS.proposalGenerationCurrentLocked(candidate.generation) {
		txS.mu.Unlock()
		return fmt.Errorf("%w: parent=%s key=%s", errProposalGenerationChanged, candidate.generation.parentHash, candidate.generation.keyHash)
	}
	if beforePublish != nil {
		if err := beforePublish(); err != nil {
			txS.mu.Unlock()
			return err
		}
	}
	txS.proposedChain.extend(candidate.block)
	txS.mu.Unlock()

	log.Info("Generated next block", "block num", candidate.block.Number(), "num txes", len(candidate.block.Transactions()),
		"commonAdmissionRefs", candidate.admissionCount, "commonAdmissionBatches", candidate.admissionBatchCount, "commonRewards", candidate.rewardCount)
	elapsed := time.Since(time.Unix(int64(candidate.block.Time()), 0))
	log.Info("🔨  Mined block", "number", candidate.block.Number(), "hash", fmt.Sprintf("%x", candidate.block.Hash().Bytes()[:4]), "elapsed", elapsed)
	return nil
}

// prepareTxProposal tries the preferred lane and then its fallback. Synchronous
// callers publish each candidate before accepting its lane; FHS workers leave
// publication and failed-transaction cleanup to the serialized Apply path.
func (txS *txService) prepareTxProposal(blockType uint8, publish bool) (*txProposalCandidate, error) {
	build := func(lane uint8) (*txProposalCandidate, error) {
		candidate, err := txS.buildProposalNewBlock(lane)
		if err == nil && publish {
			err = txS.installProposalCandidate(candidate, nil)
		}
		return candidate, err
	}
	candidate, primaryErr := build(blockType)
	if primaryErr != nil {
		fallbackType := uint8(types.FastTx_Block)
		if blockType == types.FastTx_Block {
			fallbackType = types.SlowTx_Block
		}
		if publish && !errors.Is(primaryErr, errProposalNoWork) {
			log.Warn("Primary tx block proposal failed, trying fallback lane",
				"primary", readableTxBlockType(blockType),
				"fallback", readableTxBlockType(fallbackType),
				"err", primaryErr)
		}
		var fallbackErr error
		candidate, fallbackErr = build(fallbackType)
		if fallbackErr != nil {
			return nil, proposalLaneBuildError(primaryErr, fallbackErr)
		}
	}
	if publish && len(candidate.failedTxes) > 0 {
		txS.txPool.RemoveBatch(candidate.failedTxes)
		log.Warn("Removed failed proposal txs from txpool", "count", len(candidate.failedTxes))
	}
	return candidate, nil
}

// verifyHotstuffProposal is the production HotStuff proposal validation path.
// A validator must call this only after the ProposalRef has been matched against
// the sidecar body bytes. The returned VerifiedProposal is cached by ProposalID
// and later passed to decideVerifiedProposal after a valid Decide QC.
func (txS *txService) verifyHotstuffProposal(ref *types.HotstuffProposalRef, txblock *types.Block, extra []byte) (*core.VerifiedProposal, error) {
	var parentVerified *core.VerifiedProposal
	if ref != nil && txS.config != nil && txS.config.FairHotstuff {
		if svc, ok := txS.s.(*Service); ok {
			parentVerified = svc.getFHSCertifiedVerified(ref.ParentHash)
		}
	}
	return txS.verifyHotstuffProposalWithParent(ref, txblock, extra, parentVerified)
}

// verifyHotstuffProposalWithParent is also used by fail-closed WAL recovery,
// where an entire uncommitted chain must be validated before any record is
// published into the live certified-proposal maps.
func (txS *txService) verifyHotstuffProposalWithParent(ref *types.HotstuffProposalRef, txblock *types.Block, extra []byte, parentVerified *core.VerifiedProposal) (*core.VerifiedProposal, error) {
	return txS.verifyHotstuffProposalWithKeyContext(ref, txblock, extra, parentVerified, false, false)
}

// verifyHotstuffProposalWithOwnedParent is only for the private snapshot handed
// to one Prepare worker. Consume it even if the live key/ref checks fail, so a
// failed or superseded execution cannot reuse a partially mutated parent.
func (txS *txService) verifyHotstuffProposalWithOwnedParent(ref *types.HotstuffProposalRef, txblock *types.Block, extra []byte, parentSnapshot *core.VerifiedProposal) (*core.VerifiedProposal, error) {
	if parentSnapshot == nil || parentSnapshot.StateDB == nil {
		return nil, fmt.Errorf("missing or consumed hotstuff parent snapshot")
	}
	ownedParent := *parentSnapshot
	parentSnapshot.StateDB = nil
	return txS.verifyHotstuffProposalWithKeyContext(ref, txblock, extra, &ownedParent, false, true)
}

// verifyHistoricalCertifiedProposalWithParent is deliberately separate from
// the live Prepare verifier. It accepts an older KeyHash only when that key
// block is present on the local canonical key chain. The caller must first
// verify the proposal QC with the committee selected by ref.KeyHash.
func (txS *txService) verifyHistoricalCertifiedProposalWithParent(ref *types.HotstuffProposalRef, txblock *types.Block, extra []byte, parentVerified *core.VerifiedProposal) (*core.VerifiedProposal, error) {
	return txS.verifyHotstuffProposalWithKeyContext(ref, txblock, extra, parentVerified, true, false)
}

func (txS *txService) verifyHotstuffProposalWithKeyContext(ref *types.HotstuffProposalRef, txblock *types.Block, extra []byte, parentVerified *core.VerifiedProposal, allowHistoricalKey, ownsParentState bool) (*core.VerifiedProposal, error) {
	if ref == nil {
		return nil, fmt.Errorf("nil hotstuff proposal ref")
	}
	if txblock == nil {
		return nil, fmt.Errorf("nil hotstuff proposal block")
	}
	bc := txS.bc
	kbc := txS.kbc
	proposalID := ref.ProposalID()
	blockNum := txblock.NumberU64()
	header := txblock.Header()

	log.Info("verifyHotstuffProposal",
		"number", blockNum,
		"hash", txblock.Hash(),
		"proposalID", proposalID,
		"viewID", ref.ViewID,
		"leaderID", ref.LeaderID,
		"txs", len(txblock.Transactions()),
		"blockType", txblock.BlockType())

	if ref.Number != blockNum {
		return nil, fmt.Errorf("hotstuff proposal number mismatch: ref=%d block=%d", ref.Number, blockNum)
	}
	if ref.BlockHash != txblock.Hash() {
		return nil, fmt.Errorf("hotstuff proposal hash mismatch: ref=%s block=%s", ref.BlockHash, txblock.Hash())
	}
	if ref.BlockType != txblock.BlockType() {
		return nil, fmt.Errorf("hotstuff proposal block type mismatch: ref=%d block=%d", ref.BlockType, txblock.BlockType())
	}
	if ref.KeyHash != header.KeyHash {
		return nil, fmt.Errorf("hotstuff proposal key hash mismatch: ref=%s block=%s", ref.KeyHash, header.KeyHash)
	}
	if blockNum <= bc.CurrentBlockN() {
		return nil, fmt.Errorf("invalid header, number:%d, current block number:%d", blockNum, bc.CurrentBlockN())
	}
	proposalKey := kbc.CurrentBlock()
	if proposalKey == nil {
		return nil, fmt.Errorf("cannot verify hotstuff proposal: missing current keyblock")
	}
	if header.KeyHash != proposalKey.Hash() {
		if !allowHistoricalKey {
			return nil, fmt.Errorf("keyhash:%x does not match current keyhash: %x", header.KeyHash, proposalKey.Hash())
		}
		historicalKey := kbc.GetBlockByHash(header.KeyHash)
		if historicalKey == nil {
			return nil, fmt.Errorf("historical keyhash is unknown: %x", header.KeyHash)
		}
		canonicalKey := kbc.GetBlockByNumber(historicalKey.NumberU64())
		if canonicalKey == nil || canonicalKey.Hash() != historicalKey.Hash() {
			return nil, fmt.Errorf("historical keyhash is not canonical: %x", header.KeyHash)
		}
		proposalKey = historicalKey
	}
	if err := verifyHotstuffProposalPrevRandao(txS.config, txblock, proposalKey); err != nil {
		return nil, err
	}

	if ownsParentState {
		return bc.ValidateBlockForHotstuffWithOwnedParent(proposalID, ref.ViewNumber, ref.ViewID, ref.LeaderID, txblock, parentVerified)
	}
	return bc.ValidateBlockForHotstuffWithParent(proposalID, ref.ViewNumber, ref.ViewID, ref.LeaderID, txblock, parentVerified)
}

// verifyHotstuffProposalPrevRandao prevents a proposer from choosing the
// post-Shanghai EVM randomness independently of the authenticated key chain.
// Ordinary transaction blocks use the exact key block selected by KeyHash.
// A key-block carrier instead commits the embedded next key block, so its
// outer fields must mirror that signed carrier payload.
func verifyHotstuffProposalPrevRandao(config *params.ChainConfig, block *types.Block, proposalKey *types.KeyBlock) error {
	if config == nil || block == nil {
		return nil
	}
	header := block.Header()
	if header == nil || header.Number == nil || !config.IsShanghai(header.Number, header.Time) {
		return nil
	}
	if block.BlockType() == types.Key_Block {
		carriedKey := types.DecodeToKeyBlock(block.KeyInfo())
		if carriedKey == nil {
			return fmt.Errorf("invalid Fair HotStuff key-block PREVRANDAO carrier")
		}
		if header.KeyHash != carriedKey.ParentHash() {
			return fmt.Errorf("invalid Fair HotStuff key-block PREVRANDAO parent: header keyHash=%s carried parent=%s", header.KeyHash, carriedKey.ParentHash())
		}
		if header.MixDigest != carriedKey.MixDigest() {
			return fmt.Errorf("invalid Fair HotStuff key-block PREVRANDAO: header=%s carried=%s", header.MixDigest, carriedKey.MixDigest())
		}
		return nil
	}
	if proposalKey == nil {
		return fmt.Errorf("cannot verify Fair HotStuff PREVRANDAO without key block")
	}
	if header.KeyHash != proposalKey.Hash() {
		return fmt.Errorf("invalid Fair HotStuff PREVRANDAO key context: header=%s resolved=%s", header.KeyHash, proposalKey.Hash())
	}
	if header.MixDigest != proposalKey.MixDigest() {
		return fmt.Errorf("invalid Fair HotStuff PREVRANDAO: header=%s keyBlock=%s", header.MixDigest, proposalKey.MixDigest())
	}
	return nil
}

// decideVerifiedProposal commits the exact execution result obtained during
// VotePrepare validation. It is used by legacy Decide and by delayed FHS
// 2-chain commit, and deliberately avoids a second StateProcessor execution.
func (txS *txService) decideVerifiedProposal(ref *types.HotstuffProposalRef, verified *core.VerifiedProposal, sig []byte, mask []byte, viewNumber uint64, viewID common.Hash, leaderID string) error {
	return txS.decideVerifiedProposalWithProof(ref, verified, sig, mask, viewNumber, viewID, leaderID, nil)
}

func (txS *txService) decideFHSVerifiedProposal(ref *types.HotstuffProposalRef, verified *core.VerifiedProposal, targetQC *hotstuff.SignedState, proof *core.FHSCommitProof) error {
	if targetQC == nil || proof == nil || len(proof.QCs) == 0 {
		return fmt.Errorf("incomplete FHS 2-chain commit proof")
	}
	return txS.decideVerifiedProposalWithProof(ref, verified, targetQC.Sign, targetQC.Mask, targetQC.Number, targetQC.ViewID, targetQC.LeaderID, proof)
}

func (txS *txService) decideVerifiedProposalWithProof(ref *types.HotstuffProposalRef, verified *core.VerifiedProposal, sig []byte, mask []byte, viewNumber uint64, viewID common.Hash, leaderID string, proof *core.FHSCommitProof) error {
	if ref == nil {
		return fmt.Errorf("nil hotstuff proposal ref")
	}
	if verified == nil {
		return fmt.Errorf("nil verified hotstuff proposal")
	}
	proposalID := ref.ProposalID()
	if proposalID != verified.ProposalID {
		return fmt.Errorf("verified proposal id mismatch: have %s want %s", verified.ProposalID, proposalID)
	}
	if viewID != ref.ViewID || viewID != verified.ViewID {
		return fmt.Errorf("verified proposal view mismatch: decide=%s ref=%s verified=%s", viewID, ref.ViewID, verified.ViewID)
	}
	if viewNumber != ref.ViewNumber || viewNumber != verified.ViewNumber {
		return fmt.Errorf("verified proposal view number mismatch: decide=%d ref=%d verified=%d", viewNumber, ref.ViewNumber, verified.ViewNumber)
	}
	if leaderID != ref.LeaderID || leaderID != verified.LeaderID {
		return fmt.Errorf("verified proposal leader mismatch: decide=%s ref=%s verified=%s", leaderID, ref.LeaderID, verified.LeaderID)
	}
	block := verified.Block
	if block == nil {
		return fmt.Errorf("verified proposal missing block")
	}
	if block.Hash() != ref.BlockHash {
		return fmt.Errorf("verified proposal block hash mismatch: have %s want %s", block.Hash(), ref.BlockHash)
	}

	log.Info("decideVerifiedProposal",
		"number", block.NumberU64(),
		"hash", block.Hash(),
		"proposalID", proposalID,
		"txs", len(block.Transactions()))

	bc := txS.bc
	if bc.HasBlockAndState(block.Hash(), block.NumberU64()) && (txS.config == nil || !txS.config.FairHotstuff) {
		log.Info("decideVerifiedProposal already known", "number", block.NumberU64(), "hash", block.Hash(), "proposalID", proposalID)
		return nil
	}
	if txS.config != nil && txS.config.FairHotstuff {
		block.SetFHSSignature(sig, mask, viewID, leaderID, viewNumber, ref.ExtraHash, ref.ParentQCID)
	} else {
		block.SetSignature(sig, mask, viewID, leaderID, viewNumber)
	}
	var err error
	if txS.config != nil && txS.config.FairHotstuff {
		_, err = bc.CommitFHSVerifiedProposalWithProof(verified, proof, false)
	} else {
		_, err = bc.CommitVerifiedProposal(verified, false)
	}
	if err != nil {
		log.Error("decideVerifiedProposal.CommitVerifiedProposal", "number", block.NumberU64(), "proposalID", proposalID, "error", err)
		return err
	}
	// CommitFHSVerifiedProposal may replace verified.Block with a private,
	// proof-bearing representation while backfilling an already-canonical head.
	// Broadcast that committed representation, not the proofless pointer captured
	// before the commit.
	committedBlock := verified.Block
	if committedBlock == nil {
		return fmt.Errorf("committed verified proposal lost its block")
	}
	txS.mux.Post(core.NewMinedBlockEvent{Block: committedBlock})
	log.Info("decideVerifiedProposal commit ok", "number", committedBlock.NumberU64(), "hash", committedBlock.Hash(), "proposalID", proposalID)
	return nil
}

// -----------------------------------------------------------------------------------------------------
func (txS *txService) procBlockDone(newBlock *types.Block) {
	log.Info("chainBlockEvent...", "number", newBlock.NumberU64())
	txS.txPool.RemoveBatch(newBlock.Transactions())

	if txS.config != nil && txS.config.FairHotstuff {
		txS.mu.Lock()
		txS.proposedChain.markCommitted(newBlock)
		txS.mu.Unlock()
	} else if txS.s.isRunning() {
		txS.updateChainPerNewHead(newBlock)
	} else {
		txS.mu.Lock()
		txS.proposedChain.setHead(newBlock)
		txS.mu.Unlock()
	}

	txS.s.procBlockDone(newBlock)

}

type AddressTxes map[common.Address]types.Transactions

type failedTxAction uint8

const (
	pendingTierSmall  = 64
	pendingTierMedium = 256
	pendingTierLarge  = 1024

	fastPerAccountTierSmall  = 64
	slowPerAccountTierSmall  = 64
	fastPerAccountTierMedium = 128
	slowPerAccountTierMedium = 128
	// Legacy profiles retain a conservative per-account scan window. The
	// genesis-native EVM capacity profile overrides this with its consensus
	// transaction ceiling; the critical-path compute meter remains the bound on
	// inherently serial nonce chains.
	fastPerAccountTierLarge = params.MaxTxCountPerSenderPerBlock
	slowPerAccountTierLarge = params.MaxTxCountPerSenderPerBlock
	fastBlockMaxTxCount     = uint64(params.MaxTxCountPerBlock)
	slowBlockMaxTxCount     = uint64(params.MaxTxCountPerBlock)
	fastBlockGasTargetPct   = uint64(95)
	slowBlockGasTargetPct   = uint64(99)

	fastTxBlockProposalMaxBytes = 64 * 1024 * 1024
	slowTxBlockProposalMaxBytes = 64 * 1024 * 1024

	deployBlockGasTargetPct = uint64(10)
	heavyBlockGasTargetPct  = uint64(5)
	dataBlockGasTargetPct   = uint64(5)
	dexBlockGasTargetPct    = uint64(95)

	// Backlog drain mode.
	// Normal quota protects small/native traffic from heavy/deploy/data bursts.
	// When executable txpool backlog is high, slow blocks should drain more
	// heavy classes instead of leaving pending executable txs for minutes.
	backlogDrainPendingThreshold          = 512
	backlogStrongDrainPendingThreshold    = 2048
	backlogEmergencyDrainPendingThreshold = 8192

	deployDrainGasTargetPct = uint64(20)
	heavyDrainGasTargetPct  = uint64(15)
	dataDrainGasTargetPct   = uint64(15)
	dexDrainGasTargetPct    = uint64(99)

	deployStrongDrainGasTargetPct = uint64(30)
	heavyStrongDrainGasTargetPct  = uint64(25)
	dataStrongDrainGasTargetPct   = uint64(25)
	dexStrongDrainGasTargetPct    = uint64(99)

	deployEmergencyDrainGasTargetPct = uint64(45)
	heavyEmergencyDrainGasTargetPct  = uint64(40)
	dataEmergencyDrainGasTargetPct   = uint64(40)
	dexEmergencyDrainGasTargetPct    = uint64(99)

	deployBlockMaxTxCount = uint64(4)
	heavyBlockMaxTxCount  = uint64(8)
	dataBlockMaxTxCount   = uint64(8)
	dexBlockMaxTxCount    = uint64(params.MaxTxCountPerBlock)

	deployDrainMaxTxCount = uint64(16)
	heavyDrainMaxTxCount  = uint64(32)
	dataDrainMaxTxCount   = uint64(32)

	deployStrongDrainMaxTxCount = uint64(32)
	heavyStrongDrainMaxTxCount  = uint64(64)
	dataStrongDrainMaxTxCount   = uint64(64)

	deployEmergencyDrainMaxTxCount = uint64(64)
	heavyEmergencyDrainMaxTxCount  = uint64(128)
	dataEmergencyDrainMaxTxCount   = uint64(128)
)

const (
	failedTxDropAndShift failedTxAction = iota
	failedTxDropAndPop
	failedTxKeepAndPop
)

func isFastBlockType(blockType uint8) bool {
	return blockType == types.FastTx_Block || blockType == types.Normal_Block
}

func countAddressTxes(addrTxes AddressTxes) int {
	count := 0
	for _, txs := range addrTxes {
		count += len(txs)
	}
	return count
}

func blockProposalLimit(blockType uint8, pending int) int {
	if isFastBlockType(blockType) {
		switch {
		case pending < pendingTierSmall:
			return fastPerAccountTierSmall
		case pending < pendingTierMedium:
			return fastPerAccountTierMedium
		case pending < pendingTierLarge:
			return fastPerAccountTierLarge
		default:
			return fastPerAccountTierLarge
		}
	}

	switch {
	case pending < pendingTierSmall:
		return slowPerAccountTierSmall
	case pending < pendingTierMedium:
		return slowPerAccountTierMedium
	case pending < pendingTierLarge:
		return slowPerAccountTierLarge
	default:
		return slowPerAccountTierLarge
	}
}

func blockProposalLimitForConfig(config *params.ChainConfig, blockType uint8, pending int) int {
	if config != nil && config.NativeParallelEnabled() {
		if isEVMOnlyProposalMode(config) {
			// The aggregate block ceiling remains MaxTransactionsPerBlock. Only a
			// single sender's nonce chain is bounded here because it is inherently
			// serial and must fit the configured critical-path budget. Applying the
			// limit before execution avoids building an oversized serial candidate
			// and then deterministically re-executing its valid prefix.
			return int(params.FairHotstuffEVMWorkLimitsForConfig(config).TransactionsPerSender)
		}
		return int(config.NativeParallel.MaxTransactionsPerBlock)
	}
	return blockProposalLimit(blockType, pending)
}

func proposalByteLimit(config *params.ChainConfig, blockType uint8) uint64 {
	if config != nil && config.NativeParallelEnabled() {
		return config.EffectiveMaxBlockBytes()
	}
	if isFastBlockType(blockType) {
		return fastTxBlockProposalMaxBytes
	}
	return slowTxBlockProposalMaxBytes
}

func limitAddressTxes(addrTxes AddressTxes, perAccount int) AddressTxes {
	if perAccount <= 0 {
		return addrTxes
	}
	limited := make(AddressTxes, len(addrTxes))
	for addr, txs := range addrTxes {
		if len(txs) > perAccount {
			limited[addr] = txs[:perAccount]
		} else {
			limited[addr] = txs
		}
	}
	return limited
}

func filterFHSAdmittedAddressTxesWithResults(addrTxes AddressTxes, config *params.ChainConfig, genesisHash common.Hash, keyBlockNumber uint64, txBlockNumber uint64, timestamp uint64) (AddressTxes, map[common.Hash]core.CommonRPCAdmissionResult) {
	candidates := make(map[common.Hash]core.CommonRPCAdmissionResult)
	maxBatches := params.FairHotstuffWorkLimitsForConfig(config).CommonTxAdmissionBatches
	if config != nil && config.NativeParallelEnabled() {
		maxBatches = params.FairHotstuffEVMWorkLimitsForConfig(config).CommonTxAdmissionBatches
	}
	filtered := limitFHSAdmissionBatchPrefixes(addrTxes, int(maxBatches), func(tx *types.Transaction) (common.Hash, bool) {
		selection, err := core.CommonRPCAdmissionForBlockTransaction(tx, config, genesisHash, keyBlockNumber, txBlockNumber, timestamp)
		if err != nil || selection.Batch == nil {
			return common.Hash{}, false
		}
		candidates[tx.Hash()] = selection
		return selection.Batch.AdmissionID, true
	})
	return filtered, candidates
}

func commonRPCAdmissionResultsForTransactions(txs types.Transactions, selections map[common.Hash]core.CommonRPCAdmissionResult) ([]core.CommonRPCAdmissionResult, error) {
	results := make([]core.CommonRPCAdmissionResult, len(txs))
	for index, tx := range txs {
		if tx == nil {
			return nil, fmt.Errorf("nil transaction at admission result %d", index)
		}
		selection, ok := selections[tx.Hash()]
		if !ok || selection.Batch == nil {
			return nil, fmt.Errorf("filtered transaction %s lost its common RPC admission result", tx.Hash())
		}
		results[index] = selection
	}
	return results, nil
}

// limitFHSAdmissionBatchPrefixes applies the consensus certificate-count bound
// before EVM execution. It greedily selects the certificate which unlocks the
// largest number of transactions at the current sender nonce frontiers. This
// prevents many one-item certificates on an early address from starving a
// later 512-item certificate. Ties use AdmissionID, so map iteration and worker
// scheduling cannot change the proposal. Every selected certificate unlocks at
// least one transaction and the final result retains only executable prefixes.
func limitFHSAdmissionBatchPrefixes(addrTxes AddressTxes, maxBatches int, admissionBatch func(*types.Transaction) (common.Hash, bool)) AddressTxes {
	filtered := make(AddressTxes, len(addrTxes))
	if maxBatches <= 0 || admissionBatch == nil {
		return filtered
	}
	type admittedSender struct {
		address  common.Address
		txs      types.Transactions
		batchIDs []common.Hash
	}
	addresses := make([]common.Address, 0, len(addrTxes))
	for address := range addrTxes {
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(i, j int) bool {
		return bytes.Compare(addresses[i][:], addresses[j][:]) < 0
	})
	senders := make([]admittedSender, 0, len(addresses))
	for _, address := range addresses {
		txs := addrTxes[address]
		batchIDs := make([]common.Hash, 0, len(txs))
		for _, tx := range txs {
			batchID, ok := admissionBatch(tx)
			if !ok || batchID == (common.Hash{}) {
				break
			}
			batchIDs = append(batchIDs, batchID)
		}
		if len(batchIDs) > 0 {
			senders = append(senders, admittedSender{address: address, txs: txs[:len(batchIDs)], batchIDs: batchIDs})
		}
	}
	selectedBatches := make(map[common.Hash]struct{}, maxBatches)
	scores := make(map[common.Hash]int, len(senders))
	for len(selectedBatches) < maxBatches {
		clear(scores)
		for _, sender := range senders {
			frontier := 0
			for frontier < len(sender.batchIDs) {
				if _, selected := selectedBatches[sender.batchIDs[frontier]]; !selected {
					break
				}
				frontier++
			}
			if frontier == len(sender.batchIDs) {
				continue
			}
			candidate := sender.batchIDs[frontier]
			unlocked := 0
			for index := frontier; index < len(sender.batchIDs); index++ {
				batchID := sender.batchIDs[index]
				if batchID != candidate {
					if _, selected := selectedBatches[batchID]; !selected {
						break
					}
				}
				unlocked++
			}
			scores[candidate] += unlocked
		}
		var best common.Hash
		bestScore := 0
		for batchID, score := range scores {
			if score > bestScore || (score == bestScore && score > 0 && (best == (common.Hash{}) || bytes.Compare(batchID[:], best[:]) < 0)) {
				best, bestScore = batchID, score
			}
		}
		if bestScore == 0 {
			break
		}
		selectedBatches[best] = struct{}{}
	}
	for _, sender := range senders {
		count := 0
		for count < len(sender.batchIDs) {
			if _, selected := selectedBatches[sender.batchIDs[count]]; !selected {
				break
			}
			count++
		}
		if count > 0 {
			filtered[sender.address] = sender.txs[:count]
		}
	}
	return filtered
}

func classifyCommitTxError(err error) failedTxAction {
	if err == nil {
		return failedTxKeepAndPop
	}

	switch {
	case errors.Is(err, core.ErrNonceTooLow):
		return failedTxDropAndShift

	case errors.Is(err, core.ErrIntrinsicGas),
		errors.Is(err, core.ErrGasLimit),
		errors.Is(err, core.ErrGasUintOverflow),
		errors.Is(err, core.ErrInvalidSender),
		errors.Is(err, core.ErrFHSPerTransactionWorkLimit):
		return failedTxDropAndPop

	case errors.Is(err, core.ErrNonceTooHigh),
		errors.Is(err, core.ErrGasLimitReached),
		errors.Is(err, core.ErrInsufficientFunds),
		errors.Is(err, core.ErrInsufficientFundsForTransfer):
		return failedTxKeepAndPop

	default:
		return failedTxKeepAndPop
	}
}

func applyFailedTxAction(txes *types.TransactionsByPriceAndNonce, failedTxes *types.Transactions, tx *types.Transaction, action failedTxAction) {
	switch action {
	case failedTxDropAndShift:
		*failedTxes = append(*failedTxes, tx)
		txes.Shift()
	case failedTxDropAndPop:
		*failedTxes = append(*failedTxes, tx)
		txes.Pop()
	default:
		txes.Pop()
	}
}

func logFailedTxAction(tx *types.Transaction, err error, action failedTxAction) {
	switch action {
	case failedTxDropAndShift:
		log.Info("TX failed, dropping stale tx and shifting same-account head", "hash", tx.Hash(), "err", err)
	case failedTxDropAndPop:
		log.Info("TX failed, dropping tx and skipping rest of account for this proposal", "hash", tx.Hash(), "err", err)
	default:
		log.Info("TX failed, keeping tx for retry later and skipping rest of account for this proposal", "hash", tx.Hash(), "err", err)
	}
}

func (txS *txService) updateChainPerNewHead(newBlock *types.Block) {
	txS.mu.Lock()
	defer txS.mu.Unlock()

	txS.proposedChain.accept(newBlock)
}

// nextProposalTimestamp preserves strictly increasing uint64 block times. FHS
// builders share the validator's future-time allowance and return an error for
// a temporary exhausted window instead of publishing an invalid proposal.
func nextProposalTimestamp(config *params.ChainConfig, parentTime uint64, now time.Time) (uint64, error) {
	if parentTime == math.MaxUint64 {
		return 0, fmt.Errorf("cannot create proposal after maximum block timestamp")
	}
	seconds := now.Unix()
	if seconds < 0 {
		return 0, fmt.Errorf("cannot create proposal before the Unix epoch")
	}
	timestamp := uint64(seconds)
	if timestamp <= parentTime {
		timestamp = parentTime + 1
	}
	if config != nil && config.FairHotstuff {
		if err := colossusX.VerifyFHSBlockTimestamp(timestamp, now); err != nil {
			return 0, fmt.Errorf("proposal timestamp %d is not ready: %w", timestamp, err)
		}
	}
	return timestamp, nil
}

// Assumes mu is held.
func (txS *txService) createWork(blockType uint8) (*work, error) {
	parent := txS.bc.CurrentBlock()
	var publicState *state.StateDB
	if txS.config != nil && txS.config.FairHotstuff {
		if svc, ok := txS.s.(*Service); ok {
			if certified := svc.highestFHSCertifiedProposal(); certified != nil && certified.Block != nil {
				parent = certified.Block
				if certified.StateDB != nil {
					publicState = certified.StateDB.Copy()
				}
			}
		}
	}
	if parent == nil {
		return nil, fmt.Errorf("failed to get proposal parent")
	}
	parentNumber := parent.Number()

	tstamp, err := nextProposalTimestamp(txS.config, parent.Time(), time.Now())
	if err != nil {
		return nil, err
	}
	log.Info("createWork", "parent.Difficulty()", parent.Difficulty())

	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     parentNumber.Add(parentNumber, common.Big1),
		Difficulty: parent.Difficulty(), //colossusX.CalcDifficulty(txS.config, uint64(tstamp), parent.Header()),
		GasLimit:   txS.cph.calcGasLimitFunc(parent),
		GasUsed:    0,
		Coinbase:   bftview.GetServerCoinBase(),
		Time:       tstamp,
		BlockType:  blockType,
	}
	if txS.config != nil && txS.config.IsLondon(header.Number) {
		header.BaseFee = big.NewInt(params.FixedBaseFeePerGas)
	}
	if txS.config != nil && txS.config.IsShanghai(header.Number, header.Time) {
		header.WithdrawalsHash = types.EmptyWithdrawalsHash
	}
	if txS.config != nil && txS.config.IsPrague(header.Number, header.Time) {
		header.RequestsHash = types.EmptyRequestsHash
	}
	deriveCancunHeaderFields(txS.config, parent.Header(), header)
	log.Info("createWork", "GasLimit", header.GasLimit)
	if publicState == nil {
		var err error
		publicState, err = txS.bc.StateAt(parent.Root())
		if err != nil {
			return nil, fmt.Errorf("failed to get parent state: %w", err)
		}
	}
	if err := core.ProcessParentBlockHash(txS.config, header, publicState); err != nil {
		// The EIP-2935 call is deterministic system work. Continuing with a
		// partially updated state would create a proposal validators cannot
		// reproduce, so proposal construction must fail closed.
		return nil, fmt.Errorf("failed to store Prague parent block hash: %w", err)
	}
	gasTarget := blockGasTarget(blockType, header.GasLimit)
	pendingTotal, _ := txS.txPool.Stats()

	work := &work{
		config:         txS.config,
		publicState:    publicState,
		header:         header,
		txPool:         txS.txPool,
		maxTxCount:     blockMaxTxCountForConfig(txS.config, blockType),
		gasTarget:      gasTarget,
		resourceBudget: newTxResourceBudgetForConfig(txS.config, blockType, gasTarget, pendingTotal),
		blockType:      blockType,
		size:           header.Size(),
	}
	if txS.config != nil && txS.config.FairHotstuff {
		if isEVMOnlyProposalMode(txS.config) {
			work.fhsWorkMeter = core.NewFHSEVMBlockWorkMeterForConfig(txS.config)
		} else {
			work.fhsWorkMeter = core.NewFHSBlockWorkMeterForConfig(txS.config)
		}
	}
	return work, nil
}

// deriveCancunHeaderFields initializes the fields whose values are known before
// transaction selection. BlobGasUsed is filled from the committed body once
// proposal execution completes.
func deriveCancunHeaderFields(config *params.ChainConfig, parent, header *types.Header) {
	if config == nil || header == nil || header.Number == nil || !config.IsCancun(header.Number, header.Time) {
		return
	}
	header.BlobGasUsed = 0
	if parent == nil {
		header.ExcessBlobGas = 0
		return
	}
	header.ExcessBlobGas = params.CalcExcessBlobGasForFork(
		config.IsOsaka(header.Number, header.Time),
		parent.ExcessBlobGas,
		parent.BlobGasUsed,
		parent.BaseFee,
		config.ActiveBlobConfig(header.Time),
	)
}

func canIncludeBlobGas(config *params.ChainConfig, header *types.Header, tx *types.Transaction) bool {
	if tx == nil || tx.BlobGas() == 0 {
		return true
	}
	if config == nil || header == nil || header.Number == nil || !config.IsCancun(header.Number, header.Time) {
		return false
	}
	maxBlobGas := params.MaxBlobGasPerBlock(config.ActiveBlobConfig(header.Time))
	return header.BlobGasUsed <= maxBlobGas && tx.BlobGas() <= maxBlobGas-header.BlobGasUsed
}

func blockMaxTxCount(blockType uint8) uint64 {
	if isFastBlockType(blockType) {
		return fastBlockMaxTxCount
	}
	return slowBlockMaxTxCount
}

func blockMaxTxCountForConfig(config *params.ChainConfig, blockType uint8) uint64 {
	if config != nil && config.NativeParallelEnabled() {
		if isEVMOnlyProposalMode(config) {
			return params.FairHotstuffEVMWorkLimitsForConfig(config).Transactions
		}
		return config.NativeParallel.MaxTransactionsPerBlock
	}
	return blockMaxTxCount(blockType)
}

func blockGasTarget(blockType uint8, gasLimit uint64) uint64 {
	if blockType == types.Key_Block {
		return 0
	}
	if isFastBlockType(blockType) {
		return gasLimit * fastBlockGasTargetPct / 100
	}
	return gasLimit * slowBlockGasTargetPct / 100
}

func pendingClassesForBlockType(blockType uint8) []core.TxResourceClass {
	if isFastBlockType(blockType) {
		return []core.TxResourceClass{
			core.TxClassNative,
			core.TxClassERC20,
			core.TxClassSmallCall,
		}
	}

	return []core.TxResourceClass{
		core.TxClassDex,
		core.TxClassDeploy,
		core.TxClassHeavy,
		core.TxClassData,
	}
}

func (txS *txService) loadPendingAddressTxes(blockType uint8) (AddressTxes, error) {
	lane := core.TxLaneSlow
	if isFastBlockType(blockType) {
		lane = core.TxLaneFast
	}

	pendingTotal, _ := txS.txPool.Stats()
	maxTx, perAccountLimit := proposalPoolScanLimitsForConfig(txS.config, blockType, pendingTotal, txS.config != nil && txS.config.FairHotstuff)
	gasTarget := uint64(0)
	if head := txS.bc.CurrentBlock(); head != nil && head.Header() != nil {
		gasTarget = blockGasTarget(blockType, head.Header().GasLimit)
	}
	gasTarget = proposalPoolScanGasTarget(gasTarget, txS.config != nil && txS.config.FairHotstuff)

	pending, err := txS.txPool.PendingByLaneAndClassesLimited(
		lane,
		maxTx,
		perAccountLimit,
		gasTarget,
		pendingClassesForBlockType(blockType)...,
	)
	if err != nil {
		return nil, err
	}
	return attachProposalBlobSidecars(txS.txPool, pending), nil
}

type proposalBlobSidecarSource interface {
	GetBlobSidecar(common.Hash) *types.BlobTxSidecar
}

// attachProposalBlobSidecars turns the TxPool's verified immutable sidecar
// store into the exact proposal snapshot. A missing or structurally mismatched
// sidecar truncates that sender's nonce prefix; later nonces cannot execute
// without the omitted BlobTx and must not leak into a proposal.
func attachProposalBlobSidecars(source proposalBlobSidecarSource, addrTxes AddressTxes) AddressTxes {
	if len(addrTxes) == 0 {
		return nil
	}
	attached := make(AddressTxes, len(addrTxes))
	for addr, txs := range addrTxes {
		prefix := make(types.Transactions, 0, len(txs))
		for _, tx := range txs {
			if tx == nil {
				break
			}
			if tx.Type() == types.BlobTxType {
				if source == nil {
					break
				}
				sidecar := source.GetBlobSidecar(tx.Hash())
				if sidecar == nil || tx.ValidateBlobSidecar(sidecar) != nil {
					break
				}
				tx = tx.WithBlobSidecar(sidecar)
			}
			prefix = append(prefix, tx)
		}
		if len(prefix) > 0 {
			attached[addr] = prefix
		}
	}
	return attached
}

// proposalPoolScanLimits keeps the speculative two-chain pipeline bounded
// without hiding the next nonce window. The TxPool remains based on canonical
// state while an FHS proposer executes on its highest certified parent, so the
// pool's first window can consist entirely of transactions already consumed by
// that parent. Read at most one preceding global/per-account window in
// addition to the next proposal window, then re-apply the proposal limit after
// filtering. FHS two-chain commit guarantees there is at most one certified,
// uncommitted parent between those states.
func proposalPoolScanLimits(blockType uint8, pending int, fairHotstuff bool) (maxTx, perAccount int) {
	return proposalPoolScanLimitsForConfig(nil, blockType, pending, fairHotstuff)
}

func proposalPoolScanLimitsForConfig(config *params.ChainConfig, blockType uint8, pending int, fairHotstuff bool) (maxTx, perAccount int) {
	maxTx = int(blockMaxTxCountForConfig(config, blockType))
	perAccount = blockProposalLimitForConfig(config, blockType, pending)
	if fairHotstuff {
		maxTx *= 2
		perAccount *= 2
	}
	return maxTx, perAccount
}

// proposalPoolScanGasTarget mirrors the two-window count scan above. The
// first gas window may consist entirely of transactions already executed by
// the highest certified (but not yet canonical) parent. Selection filters
// those hashes before execution and the work itself retains the ordinary
// one-block gas target, so this only prevents the next nonce window from being
// hidden during the immutable TxPool snapshot.
func proposalPoolScanGasTarget(gasTarget uint64, fairHotstuff bool) uint64 {
	if !fairHotstuff || gasTarget == 0 {
		return gasTarget
	}
	if gasTarget > math.MaxUint64/2 {
		return math.MaxUint64
	}
	return gasTarget * 2
}

// filterProposalTransactions must be called with txService.mu held. It only
// snapshots the speculative-chain exclusion set; sender recovery and heap
// construction are deliberately left to the lock-free proposal build phase.
func (txS *txService) filterProposalTransactions(blockType uint8, allAddrTxes AddressTxes) AddressTxes {
	addrTxes := txS.proposedChain.withoutProposedTxes(allAddrTxes, time.Now())
	pendingTotal, _ := txS.txPool.Stats()
	perAccountLimit := blockProposalLimitForConfig(txS.config, blockType, pendingTotal)
	addrTxes = limitAddressTxes(addrTxes, perAccountLimit)

	availableBeforeFilter := countAddressTxes(allAddrTxes)
	availableTxs := countAddressTxes(addrTxes)

	// Safety fallback:
	// If txpool returned executable candidates but proposedChain filtered all of them,
	// the proposedChain cache may be stale from proposals that were not finally committed.
	// In that case, clear proposedChain to current head and use the raw txpool candidates.
	if availableBeforeFilter > 0 && availableTxs == 0 && (txS.config == nil || !txS.config.FairHotstuff) {
		log.Warn("proposedChain filtered all txpool candidates; clearing stale proposed cache",
			"blockType", readableTxBlockType(blockType),
			"pendingTotal", pendingTotal,
			"availableBeforeFilter", availableBeforeFilter,
			"accountsBeforeFilter", len(allAddrTxes),
			"currentBlock", txS.bc.CurrentBlockN())

		txS.proposedChain.clear(txS.bc.CurrentBlock())
		addrTxes = allAddrTxes
		availableTxs = availableBeforeFilter
	}

	log.Debug("tx proposal scheduler",
		"blockType", readableTxBlockType(blockType),
		"pendingTotal", pendingTotal,
		"availableTxs", availableTxs,
		"availableBeforeFilter", availableBeforeFilter,
		"accounts", len(addrTxes),
		"perAccountLimit", perAccountLimit,
		"maxTx", blockMaxTxCountForConfig(txS.config, blockType),
		"gasTargetPct", blockGasTarget(blockType, txS.bc.CurrentBlock().Header().GasLimit))
	return addrTxes
}

func precheckTxForProposal(config *params.ChainConfig, st *state.StateDB, header *types.Header, tx *types.Transaction, from common.Address) error {
	if st.GetNonce(from) == math.MaxUint64 {
		return core.ErrNonceMax
	}
	if st.GetNonce(from) > tx.Nonce() {
		return core.ErrNonceTooLow
	}
	if st.GetNonce(from) < tx.Nonce() {
		return core.ErrNonceTooHigh
	}
	if tx.Gas() > header.GasLimit {
		return core.ErrGasLimit
	}
	if st.GetBalance(from).Cmp(tx.Cost()) < 0 {
		return core.ErrInsufficientFunds
	}
	rules := params.Rules{}
	if config != nil {
		rules = config.CypheriumRules(header.Number, header.Time)
	}
	if err := core.ValidateTxTypeForRules(tx.Type(), rules); err != nil {
		return err
	}
	if tx.Type() == types.BlobTxType {
		sidecar := tx.BlobSidecar()
		if sidecar == nil {
			return types.ErrBlobSidecarMissing
		}
		expectedVersion := types.BlobSidecarVersionForOsaka(rules.IsOsaka)
		if err := tx.ValidateBlobSidecarVersion(sidecar, expectedVersion); err != nil {
			return err
		}
		maxBlobs := params.MaxBlobsPerTransaction(config, header.Time)
		blobBaseFee := params.CalcBlobBaseFeeAtTime(config, header.Time, header.ExcessBlobGas)
		if err := tx.ValidateBlobTx(maxBlobs, blobBaseFee); err != nil {
			return err
		}
	}
	if rules.IsLondon {
		code := st.GetCode(from)
		_, delegated := types.ParseDelegation(code)
		if len(code) != 0 && !(rules.IsPrague && delegated) {
			return core.ErrSenderNoEOA
		}
	}
	if rules.IsOsaka && tx.Gas() > params.MaxTxGas {
		return core.ErrTxGasLimitExceeded
	}
	if rules.IsOsaka && len(tx.BlobHashes()) > params.BlobTxMaxBlobs {
		return types.ErrBlobTxTooManyBlobs
	}
	if tx.Type() == types.SetCodeTxType {
		if tx.To() == nil {
			return core.ErrSetCodeTxCreate
		}
		if len(tx.SetCodeAuthorizations()) == 0 {
			return core.ErrEmptyAuthList
		}
	}
	intrGas, err := core.IntrinsicGasWithRulesAndAuthorizations(tx.Data(), tx.AccessList(), tx.SetCodeAuthorizations(), tx.To() == nil, rules)
	if err != nil {
		return err
	}
	if tx.Gas() < intrGas {
		return core.ErrIntrinsicGas
	}
	if rules.IsPrague {
		floorDataGas, err := core.FloorDataGas(tx.Data())
		if err != nil {
			return err
		}
		if tx.Gas() < floorDataGas {
			return core.ErrFloorDataGas
		}
	}
	return nil
}

type txResourceBudget struct {
	gasCaps map[core.TxResourceClass]uint64
	txCaps  map[core.TxResourceClass]uint64

	gasUsed map[core.TxResourceClass]uint64
	txUsed  map[core.TxResourceClass]uint64
}

func newTxResourceBudget(blockType uint8, gasTarget uint64, pendingTotal int) *txResourceBudget {
	b := &txResourceBudget{
		gasCaps: make(map[core.TxResourceClass]uint64),
		txCaps:  make(map[core.TxResourceClass]uint64),
		gasUsed: make(map[core.TxResourceClass]uint64),
		txUsed:  make(map[core.TxResourceClass]uint64),
	}

	drainLevel := 0
	if !isFastBlockType(blockType) {
		switch {
		case pendingTotal >= backlogEmergencyDrainPendingThreshold:
			drainLevel = 3
		case pendingTotal >= backlogStrongDrainPendingThreshold:
			drainLevel = 2
		case pendingTotal >= backlogDrainPendingThreshold:
			drainLevel = 1
		}
	}

	deployGasPct := deployBlockGasTargetPct
	heavyGasPct := heavyBlockGasTargetPct
	dataGasPct := dataBlockGasTargetPct
	dexGasPct := dexBlockGasTargetPct

	deployMaxTx := deployBlockMaxTxCount
	heavyMaxTx := heavyBlockMaxTxCount
	dataMaxTx := dataBlockMaxTxCount

	switch drainLevel {
	case 1:
		deployGasPct = deployDrainGasTargetPct
		heavyGasPct = heavyDrainGasTargetPct
		dataGasPct = dataDrainGasTargetPct
		dexGasPct = dexDrainGasTargetPct
		deployMaxTx = deployDrainMaxTxCount
		heavyMaxTx = heavyDrainMaxTxCount
		dataMaxTx = dataDrainMaxTxCount
	case 2:
		deployGasPct = deployStrongDrainGasTargetPct
		heavyGasPct = heavyStrongDrainGasTargetPct
		dataGasPct = dataStrongDrainGasTargetPct
		dexGasPct = dexStrongDrainGasTargetPct
		deployMaxTx = deployStrongDrainMaxTxCount
		heavyMaxTx = heavyStrongDrainMaxTxCount
		dataMaxTx = dataStrongDrainMaxTxCount
	case 3:
		deployGasPct = deployEmergencyDrainGasTargetPct
		heavyGasPct = heavyEmergencyDrainGasTargetPct
		dataGasPct = dataEmergencyDrainGasTargetPct
		dexGasPct = dexEmergencyDrainGasTargetPct
		deployMaxTx = deployEmergencyDrainMaxTxCount
		heavyMaxTx = heavyEmergencyDrainMaxTxCount
		dataMaxTx = dataEmergencyDrainMaxTxCount
	}

	if gasTarget > 0 {
		b.gasCaps[core.TxClassDeploy] = gasTarget * deployGasPct / 100
		b.gasCaps[core.TxClassHeavy] = gasTarget * heavyGasPct / 100
		b.gasCaps[core.TxClassData] = gasTarget * dataGasPct / 100
		b.gasCaps[core.TxClassDex] = gasTarget * dexGasPct / 100
	}

	b.txCaps[core.TxClassDeploy] = deployMaxTx
	b.txCaps[core.TxClassHeavy] = heavyMaxTx
	b.txCaps[core.TxClassData] = dataMaxTx
	b.txCaps[core.TxClassDex] = dexBlockMaxTxCount

	if drainLevel > 0 {
		log.Debug("tx resource budget drain mode",
			"pendingTotal", pendingTotal,
			"drainLevel", drainLevel,
			"deployGasPct", deployGasPct,
			"heavyGasPct", heavyGasPct,
			"dataGasPct", dataGasPct,
			"dexGasPct", dexGasPct,
			"deployMaxTx", deployMaxTx,
			"heavyMaxTx", heavyMaxTx,
			"dataMaxTx", dataMaxTx)
	}

	return b
}

// newTxResourceBudgetForConfig removes the legacy tiny per-class proposal caps
// on the high-capacity EVM-only genesis. Aggregate transaction, gas, byte,
// signature, access-list, authorization and blob limits are still enforced by
// the canonical FHS meter and block validator. Keeping deploy/data/heavy at
// 4/8/128 transactions would otherwise make the configured standard-EVM
// ceiling unreachable for independent contract workloads.
func newTxResourceBudgetForConfig(config *params.ChainConfig, blockType uint8, gasTarget uint64, pendingTotal int) *txResourceBudget {
	budget := newTxResourceBudget(blockType, gasTarget, pendingTotal)
	if !isEVMOnlyProposalMode(config) {
		return budget
	}
	limit := params.FairHotstuffEVMWorkLimitsForConfig(config).Transactions
	for _, class := range []core.TxResourceClass{core.TxClassDeploy, core.TxClassHeavy, core.TxClassData, core.TxClassDex} {
		budget.txCaps[class] = limit
		if gasTarget > 0 {
			budget.gasCaps[class] = gasTarget
		}
	}
	return budget
}

func (b *txResourceBudget) CanInclude(class core.TxResourceClass, requestedGas uint64) bool {
	if b == nil {
		return true
	}

	if maxTx, ok := b.txCaps[class]; ok && maxTx > 0 && b.txUsed[class] >= maxTx {
		return false
	}

	if maxGas, ok := b.gasCaps[class]; ok && maxGas > 0 {
		// Always allow the first tx of a capped class. This prevents a single
		// large deploy/heavy tx from being starved forever.
		if b.txUsed[class] > 0 && b.gasUsed[class]+requestedGas > maxGas {
			return false
		}
	}

	return true
}

func (b *txResourceBudget) Record(class core.TxResourceClass, gasUsed uint64) {
	if b == nil {
		return
	}
	b.txUsed[class]++
	b.gasUsed[class] += gasUsed
}

func (b *txResourceBudget) copy() *txResourceBudget {
	if b == nil {
		return nil
	}
	clone := &txResourceBudget{
		gasCaps: make(map[core.TxResourceClass]uint64, len(b.gasCaps)),
		txCaps:  make(map[core.TxResourceClass]uint64, len(b.txCaps)),
		gasUsed: make(map[core.TxResourceClass]uint64, len(b.gasUsed)),
		txUsed:  make(map[core.TxResourceClass]uint64, len(b.txUsed)),
	}
	for class, value := range b.gasCaps {
		clone.gasCaps[class] = value
	}
	for class, value := range b.txCaps {
		clone.txCaps[class] = value
	}
	for class, value := range b.gasUsed {
		clone.gasUsed[class] = value
	}
	for class, value := range b.txUsed {
		clone.txUsed[class] = value
	}
	return clone
}

// Current state information for building the next block
type work struct {
	config         *params.ChainConfig
	publicState    *state.StateDB
	Block          *types.Block
	header         *types.Header
	txPool         *core.TxPool
	maxTxCount     uint64
	gasTarget      uint64
	resourceBudget *txResourceBudget
	fhsWorkMeter   *core.FHSBlockWorkMeter
	blockType      uint8
	size           common.StorageSize
}

// nextFHSWorkMeter checks a proposal candidate against the same meter used by
// validators. The returned snapshot is installed only after EVM execution
// succeeds, so a failed candidate cannot consume the following candidates'
// consensus budget.
func (env *work) nextFHSWorkMeter(index int, tx *types.Transaction) (*core.FHSBlockWorkMeter, error) {
	if env == nil || env.fhsWorkMeter == nil {
		return nil, nil
	}
	next := *env.fhsWorkMeter
	if err := next.AddTransaction(index, tx); err != nil {
		return nil, err
	}
	return &next, nil
}

const (
	osakaBlockSizeBuffer = common.StorageSize(1_000_000)
	// A full 512-transaction admission certificate plus aligned references and
	// deterministic rewards amortizes to less than 300 encoded bytes per tx,
	// even with full-width boundary and fee fields. Keep additional headroom
	// while allowing 16,384 signed native transfers beside the separate 1 MiB
	// block/finality-proof reserve.
	osakaPerTxBodySizeBuffer = common.StorageSize(320)
)

func proposalTransactionBodyWeight(tx *types.Transaction) uint64 {
	if tx == nil {
		return 0
	}
	weight := uint64(tx.Size())
	if sidecar := tx.BlobSidecar(); sidecar != nil {
		// Account for the independent body field without allocating an RLP copy
		// during selection. Fixed/list prefixes are covered conservatively here;
		// the final canonical encoding remains the authoritative exact check.
		const blobSidecarRLPAllowance = uint64(256)
		if weight > ^uint64(0)-blobSidecarRLPAllowance {
			return ^uint64(0)
		}
		weight += blobSidecarRLPAllowance
		for _, blob := range sidecar.Blobs {
			if uint64(len(blob)) > ^uint64(0)-weight {
				return ^uint64(0)
			}
			weight += uint64(len(blob))
		}
		fixedBytes := uint64(len(sidecar.Commitments)+len(sidecar.Proofs)) * 48
		if fixedBytes > ^uint64(0)-weight {
			return ^uint64(0)
		}
		weight += fixedBytes
	}
	return weight
}

func (env *work) txFitsBlockSizeAt(current common.StorageSize, tx *types.Transaction) bool {
	if env == nil || tx == nil || env.config == nil || env.header == nil || env.header.Number == nil {
		return true
	}
	maxBlockBytes := proposalByteLimit(env.config, env.blockType)
	reservedBytes := uint64(0)
	if env.config.IsOsaka(env.header.Number, env.header.Time) {
		maxBlockBytes = env.config.EffectiveMaxBlockBytes()
		reservedBytes = uint64(osakaBlockSizeBuffer)
	}
	if maxBlockBytes <= reservedBytes {
		return false
	}
	weight := proposalTransactionBodyWeight(tx)
	buffer := uint64(osakaPerTxBodySizeBuffer)
	currentBytes := uint64(current)
	if weight > ^uint64(0)-buffer || currentBytes > ^uint64(0)-weight-buffer {
		return false
	}
	return currentBytes+weight+buffer < maxBlockBytes-reservedBytes
}

func (env *work) txFitsBlockSize(tx *types.Transaction) bool {
	if env == nil {
		return true
	}
	return env.txFitsBlockSizeAt(env.size, tx)
}

type evmProposalSelection struct {
	transactions types.Transactions
	failed       types.Transactions
	size         common.StorageSize
	blobGasUsed  uint64
	workMeter    *core.FHSBlockWorkMeter
	budget       *txResourceBudget
}

// A proposal attempt may execute the full candidate batch once, retry once
// after removing an invalid leading sender, and (only if needed) execute the
// canonically valid prefix of that retry. This keeps hostile moving-parent or
// runtime-limit failures at O(n) with a small fixed multiplier.
const evmProposalMaxExecutionAttempts = 3

// selectEVMProposalTransactions builds an execution batch without mutating the
// canonical price/nonce cursor or the proposal state. Sender nonce and maximum
// fee reservations are projected on a private StateDB copy. This is
// deliberately conservative: contract side effects may make a later omitted
// transaction affordable, but every selected transaction still passes through
// the same canonical EVM executor used by validators.
func (env *work) selectEVMProposalTransactions(txes *types.TransactionsByPriceAndNonce) evmProposalSelection {
	if env == nil || txes == nil || env.publicState == nil || env.header == nil {
		return evmProposalSelection{}
	}
	selection := evmProposalSelection{size: env.size, blobGasUsed: env.header.BlobGasUsed, budget: env.resourceBudget.copy()}
	if env.fhsWorkMeter != nil {
		meter := *env.fhsWorkMeter
		selection.workMeter = &meter
	}
	cursor := txes.Copy()
	projectedState := env.publicState.Copy()
	reservedGas := env.header.GasUsed
	reservationLimit := env.header.GasLimit
	if env.gasTarget > 0 && env.gasTarget < reservationLimit {
		reservationLimit = env.gasTarget
	}

	for {
		if env.maxTxCount > 0 && uint64(len(selection.transactions)) >= env.maxTxCount {
			break
		}
		tx := cursor.Peek()
		if tx == nil {
			break
		}
		if !env.txFitsBlockSizeAt(selection.size, tx) {
			cursor.Pop()
			continue
		}
		if tx.BlobGas() != 0 {
			probeHeader := types.CopyHeader(env.header)
			probeHeader.BlobGasUsed = selection.blobGasUsed
			if !canIncludeBlobGas(env.config, probeHeader, tx) {
				cursor.Pop()
				continue
			}
		}
		if reservedGas > reservationLimit || tx.Gas() > reservationLimit-reservedGas {
			// Reserving declared gas for the whole speculative batch is more
			// conservative than the serial builder's post-refund accounting,
			// but guarantees that canonical merges cannot cross the target.
			cursor.Pop()
			continue
		}
		var candidateMeter *core.FHSBlockWorkMeter
		if selection.workMeter != nil {
			next := *selection.workMeter
			if err := next.AddTransaction(len(selection.transactions), tx); err != nil {
				action := failedTxKeepAndPop
				if errors.Is(err, core.ErrFHSPerTransactionWorkLimit) {
					action = failedTxDropAndPop
				}
				logFailedTxAction(tx, err, action)
				applyFailedTxAction(cursor, &selection.failed, tx, action)
				continue
			}
			candidateMeter = &next
		}
		resourceClass := core.ClassifyTxResource(tx)
		if selection.budget != nil && !selection.budget.CanInclude(resourceClass, tx.Gas()) {
			cursor.Pop()
			continue
		}
		from, err := proposalTransactionSender(env.config, env.header.Number, tx)
		if err != nil {
			logFailedTxAction(tx, err, failedTxDropAndPop)
			applyFailedTxAction(cursor, &selection.failed, tx, failedTxDropAndPop)
			continue
		}
		if err := precheckTxForProposal(env.config, projectedState, env.header, tx, from); err != nil {
			action := classifyCommitTxError(err)
			logFailedTxAction(tx, err, action)
			applyFailedTxAction(cursor, &selection.failed, tx, action)
			continue
		}

		selection.transactions = append(selection.transactions, tx)
		selection.size += common.StorageSize(proposalTransactionBodyWeight(tx)) + osakaPerTxBodySizeBuffer
		selection.blobGasUsed += tx.BlobGas()
		reservedGas += tx.Gas()
		selection.workMeter = candidateMeter
		if selection.budget != nil {
			// GasUsed can never exceed the declared limit, so reserving the
			// latter keeps every later class check valid after real execution.
			selection.budget.Record(resourceClass, tx.Gas())
		}
		projectedState.SetNonce(from, tx.Nonce()+1)
		projectedState.SubBalance(from, tx.Cost())
		cursor.Shift()
	}
	return selection
}

func (env *work) commitTransactions(txes *types.TransactionsByPriceAndNonce, bc *core.BlockChain) (types.Transactions, types.Receipts, []*types.Log, types.Transactions, error) {
	if isEVMOnlyProposalMode(env.config) {
		selection := env.selectEVMProposalTransactions(txes)
		if len(selection.transactions) == 0 {
			return nil, nil, nil, selection.failed, nil
		}
		baseState := env.publicState.Copy()
		baseGasUsed := env.header.GasUsed
		baseBlobGasUsed := env.header.BlobGasUsed
		baseSize := env.size
		baseBudget := env.resourceBudget.copy()
		var baseWorkMeter *core.FHSBlockWorkMeter
		if env.fhsWorkMeter != nil {
			meter := *env.fhsWorkMeter
			baseWorkMeter = &meter
		}
		candidates := append(types.Transactions(nil), selection.transactions...)
		var (
			receipts types.Receipts
			logs     []*types.Log
			usedGas  uint64
			attempts int
		)
		for len(candidates) > 0 {
			// Every retry starts from the identical parent-derived state. A
			// failed speculative pass may already have merged a valid prefix.
			env.publicState = baseState.Copy()
			env.header.GasUsed = baseGasUsed
			env.header.BlobGasUsed = baseBlobGasUsed
			attempts++
			var err error
			receipts, logs, usedGas, err = core.ExecuteEVMProposalTransactions(env.config, bc, env.header, candidates, env.publicState, vm.Config{})
			if err == nil {
				break
			}
			var txErr *core.EVMTransactionExecutionError
			if !errors.As(err, &txErr) || txErr.TransactionIndex < 0 || txErr.TransactionIndex >= len(candidates) {
				return nil, nil, nil, selection.failed, fmt.Errorf("execute standard EVM proposal: %w", err)
			}
			failedIndex := txErr.TransactionIndex
			failedTx := candidates[failedIndex]
			failedSender, senderErr := proposalTransactionSender(env.config, env.header.Number, failedTx)
			if senderErr != nil {
				return nil, nil, nil, selection.failed, fmt.Errorf("recover failed standard EVM proposal sender: %w", senderErr)
			}
			action := classifyCommitTxError(txErr.Err)
			if action == failedTxDropAndShift || action == failedTxDropAndPop {
				selection.failed = append(selection.failed, failedTx)
			}

			var next types.Transactions
			if attempts == 1 && failedIndex == 0 {
				// A bad top-priced sender must not suppress all independent work.
				// Remove that sender's nonce suffix and permit one full retry.
				next = make(types.Transactions, 0, len(candidates)-1)
				for index, tx := range candidates {
					if index == failedIndex {
						continue
					}
					sender, err := proposalTransactionSender(env.config, env.header.Number, tx)
					if err != nil {
						return nil, nil, nil, selection.failed, fmt.Errorf("recover standard EVM retry sender at transaction %d: %w", index, err)
					}
					if sender != failedSender {
						next = append(next, tx)
					}
				}
			} else {
				// The prefix before a non-leading failure has already passed
				// canonical execution and every runtime/output meter. Re-execute
				// only that prefix; scanning the suffix again would permit an
				// O(k*n) proposer DoS from k hostile independent senders.
				next = append(types.Transactions(nil), candidates[:failedIndex]...)
			}
			log.Warn("Omitting failed EVM proposal candidate and rebuilding canonical MVCC schedule",
				"hash", failedTx.Hash(), "index", failedIndex, "remaining", len(next), "attempt", attempts, "err", txErr.Err)
			candidates = next
			if len(candidates) > 0 && attempts >= evmProposalMaxExecutionAttempts {
				return nil, nil, nil, selection.failed, fmt.Errorf("standard EVM proposal exceeded %d bounded execution attempts: %w", evmProposalMaxExecutionAttempts, err)
			}
		}
		if len(candidates) == 0 {
			env.publicState = baseState
			env.header.GasUsed = baseGasUsed
			env.header.BlobGasUsed = baseBlobGasUsed
			return nil, nil, nil, selection.failed, nil
		}

		// Install proposal accounting from the exact successful subset. All
		// consensus execution bounds were already applied inside the shared
		// executor; no serial path can bypass them.
		env.header.GasUsed = usedGas
		env.header.BlobGasUsed = baseBlobGasUsed
		env.size = baseSize
		env.resourceBudget = baseBudget
		env.fhsWorkMeter = baseWorkMeter
		for index, tx := range candidates {
			candidateMeter, err := env.nextFHSWorkMeter(index, tx)
			if err != nil {
				return nil, nil, nil, selection.failed, fmt.Errorf("rebuild standard EVM proposal work meter at transaction %d: %w", index, err)
			}
			env.fhsWorkMeter = candidateMeter
			env.size += common.StorageSize(proposalTransactionBodyWeight(tx)) + osakaPerTxBodySizeBuffer
			env.header.BlobGasUsed += tx.BlobGas()
			if env.resourceBudget != nil {
				env.resourceBudget.Record(core.ClassifyTxResource(tx), receipts[index].GasUsed)
			}
		}
		return candidates, receipts, logs, selection.failed, nil
	}
	return env.commitTransactionsSerial(txes, bc)
}

func (env *work) commitTransactionsSerial(txes *types.TransactionsByPriceAndNonce, bc *core.BlockChain) (types.Transactions, types.Receipts, []*types.Log, types.Transactions, error) {
	var allLogs []*types.Log
	var committedTxes types.Transactions
	var publicReceipts types.Receipts
	var failedTxes types.Transactions

	gp := new(core.GasPool).AddGas(env.header.GasLimit)
	txCount := 0

	for {
		if env.maxTxCount > 0 && uint64(txCount) >= env.maxTxCount {
			break
		}
		if env.gasTarget > 0 && env.header.GasUsed >= env.gasTarget {
			break
		}
		tx := txes.Peek()
		if tx == nil {
			break
		}
		if !env.txFitsBlockSize(tx) {
			log.Debug("Skipping tx above Osaka block size budget", "hash", tx.Hash(), "size", tx.Size(), "selectedSize", env.size, "blockType", env.blockType)
			txes.Pop()
			continue
		}
		if !canIncludeBlobGas(env.config, env.header, tx) {
			// Keep the transaction in the pool for a later block, but remove this
			// account head from the local proposal view so the current proposal
			// cannot exceed Cancun's block blob-gas limit.
			log.Debug("Skipping tx above block blob gas limit", "hash", tx.Hash(), "blobGasUsed", env.header.BlobGasUsed, "txBlobGas", tx.BlobGas(), "blockType", env.blockType)
			txes.Pop()
			continue
		}
		if env.gasTarget > 0 {
			remainingGas := env.gasTarget - env.header.GasUsed
			if tx.Gas() > remainingGas {
				// This transaction cannot fit into the remaining gas target budget.
				// Drop this account head from the local proposal view and continue,
				// so we can still consider other accounts' transactions.
				log.Trace("Skipping account head above gas target remainder", "gasUsed", env.header.GasUsed, "gasTarget", env.gasTarget, "nextTxGas", tx.Gas(), "blockType", env.blockType)
				txes.Pop()
				continue
			}
		}
		candidateWorkMeter, workErr := env.nextFHSWorkMeter(txCount, tx)
		if workErr != nil {
			action := failedTxKeepAndPop
			if errors.Is(workErr, core.ErrFHSPerTransactionWorkLimit) {
				action = failedTxDropAndPop
			}
			logFailedTxAction(tx, workErr, action)
			applyFailedTxAction(txes, &failedTxes, tx, action)
			continue
		}
		resourceClass := core.ClassifyTxResource(tx)
		if env.resourceBudget != nil && !env.resourceBudget.CanInclude(resourceClass, tx.Gas()) {
			log.Debug("Skipping tx above resource class budget", "hash", tx.Hash(), "class", resourceClass, "gas", tx.Gas(), "blockType", env.blockType)
			txes.Pop()
			continue
		}

		// Check sender
		from, err := proposalTransactionSender(env.config, env.header.Number, tx)
		if err != nil {
			log.Warn("Discarding transaction with invalid sender", "hash", tx.Hash(), "err", err)
			applyFailedTxAction(txes, &failedTxes, tx, failedTxDropAndPop)
			continue
		}
		if err := precheckTxForProposal(env.config, env.publicState, env.header, tx, from); err != nil {
			action := classifyCommitTxError(err)
			logFailedTxAction(tx, err, action)
			applyFailedTxAction(txes, &failedTxes, tx, action)
			continue
		}
		env.publicState.Prepare(tx.Hash(), common.Hash{}, txCount)

		publicReceipt, err := env.commitTransaction(tx, bc, gp)
		switch {
		case err != nil:
			action := classifyCommitTxError(err)
			logFailedTxAction(tx, err, action)
			applyFailedTxAction(txes, &failedTxes, tx, action)
		default:
			txCount++
			if candidateWorkMeter != nil {
				env.fhsWorkMeter = candidateWorkMeter
			}
			committedTxes = append(committedTxes, tx)
			// Reserve conservative room for the per-transaction CommonTxAdmission
			// and CommonTxReward RLP objects attached after execution.
			env.size += common.StorageSize(proposalTransactionBodyWeight(tx)) + osakaPerTxBodySizeBuffer
			env.header.BlobGasUsed += tx.BlobGas()
			if env.resourceBudget != nil {
				env.resourceBudget.Record(resourceClass, publicReceipt.GasUsed)
			}

			publicReceipts = append(publicReceipts, publicReceipt)
			allLogs = append(allLogs, publicReceipt.Logs...)

			txes.Shift()
		}
	}
	return committedTxes, publicReceipts, allLogs, failedTxes, nil
}

func (env *work) commitTransaction(tx *types.Transaction, bc *core.BlockChain, gp *core.GasPool) (*types.Receipt, error) {
	publicSnapshot := env.publicState.Snapshot()

	var author *common.Address
	var vmConf vm.Config
	publicReceipt, err := core.ApplyTransaction(env.config, bc, author, gp, env.publicState, env.header, tx, &env.header.GasUsed, vmConf)
	if err != nil {
		env.publicState.RevertToSnapshot(publicSnapshot)
		return nil, err
	}
	//txnStart := time.Now()
	//log.EmitCheckpoint(log.TxCompleted, "tx", tx.Hash().Hex(), "time", time.Since(txnStart))

	return publicReceipt, nil
}

type proposalValidationOutput struct {
	ref                  *types.HotstuffProposalRef
	verified             *core.VerifiedProposal
	extra                []byte
	parentQC             *hotstuff.SignedState
	serviceGeneration    uint64
	validationGeneration uint64
}

type proposalBuildOutput struct {
	stagedHotstuffProposal
	key                    hotstuff.FHSProposalBuildKey
	extra                  []byte
	txCandidate            *txProposalCandidate
	keyCandidate           *keyProposalCandidate
	keyBlock               *types.KeyBlock
	committee              *bftview.Committee
	blockType              uint8
	fixedMode              bool
	keyProposalAttempt     bool
	serviceGeneration      uint64
	constructionGeneration uint64
	publicationLocksHeld   bool
	workStamp              proposalWorkStamp
	workStampValid         bool
}

type stagedHotstuffProposal struct {
	proposalRef  []byte
	body         *proposalBodyMsg
	manifest     *proposalBodyMsg
	destinations []string
}

func (s *Service) stageHotstuffProposal(viewNumber uint64, viewID common.Hash, leaderID string, encodedBlock, extra []byte, parentQC *hotstuff.SignedState) (*stagedHotstuffProposal, error) {
	if len(encodedBlock) == 0 {
		return nil, fmt.Errorf("empty encoded block proposal")
	}
	bodyLimit := proposalBodyLimitForConfig(s.chainConfig)
	if len(encodedBlock) > bodyLimit {
		return nil, fmt.Errorf("encoded block proposal too large: bytes=%d limit=%d", len(encodedBlock), bodyLimit)
	}
	block := types.DecodeToBlock(encodedBlock)
	if block == nil {
		return nil, fmt.Errorf("failed to decode encoded block proposal")
	}
	if s.fairHotstuffEnabled() {
		current := s.GetCurrentView()
		if viewNumber != current.ViewNumber+1 {
			return nil, fmt.Errorf("FHS proposal view mismatch: have %d want %d", viewNumber, current.ViewNumber+1)
		}
		if block.ParentHash() != current.TxHash {
			return nil, fmt.Errorf("FHS proposal does not extend highest certified block: parent=%s highest=%s", block.ParentHash(), current.TxHash)
		}
	}
	parentQCID, err := fhsQCIdentityHash(parentQC)
	if err != nil {
		return nil, err
	}
	encodedParentQC, err := hotstuff.EncodeSignedState(parentQC)
	if err != nil {
		return nil, err
	}
	ref, err := types.NewHotstuffProposalRefWithProof(s.ChainID(), viewNumber, viewID, leaderID, block, encodedBlock, extra, parentQCID)
	if err != nil {
		return nil, err
	}
	proposalID := ref.ProposalID()
	body := &proposalBodyMsg{
		Type:               proposalBodyMsgManifest,
		ProposalID:         proposalID,
		BodyHash:           ref.BodyHash,
		BodySize:           ref.BodySize,
		Number:             ref.Number,
		ViewNumber:         ref.ViewNumber,
		ViewID:             ref.ViewID,
		LeaderID:           ref.LeaderID,
		From:               s.Self(),
		ProposalKeyHash:    ref.KeyHash,
		EncodedBlock:       encodedBlock,
		Extra:              append([]byte(nil), extra...),
		ParentQC:           encodedParentQC,
		KeyActivationProof: s.canonicalFHSKeyActivationProof(ref.KeyHash),
		CreatedAtUnixNano:  time.Now().UnixNano(),
	}
	manifest, err := encodeProposalDataManifestForConfig(s.chainConfig, block)
	if err != nil {
		return nil, err
	}
	refBytes := ref.EncodeToBytes()
	if len(refBytes) == 0 {
		return nil, fmt.Errorf("failed to encode hotstuff proposal ref")
	}
	log.Info("HOTSTUFF PROPOSAL REF",
		"number", ref.Number,
		"viewID", ref.ViewID,
		"proposalID", proposalID,
		"blockHash", ref.BlockHash,
		"bodyHash", ref.BodyHash,
		"bodySize", ref.BodySize,
		"refBytes", len(refBytes))
	wireBody := cloneProposalBodyEnvelope(body)
	wireBody.Type = proposalBodyMsgManifest
	wireBody.From = s.Self()
	wireBody.Manifest = append([]byte(nil), manifest...)
	if err := s.sealProposalBody(wireBody); err != nil {
		return nil, fmt.Errorf("sign proposal manifest: %w", err)
	}
	// Attach the relayable leader proof before caching and queuing durable
	// content, so a donor that retains this body can serve the same proof after
	// its original leader becomes unavailable, including after a donor restart.
	body.ManifestAuthSig = append([]byte(nil), wireBody.ManifestAuthSig...)
	if err := s.storeProposalBody(body); err != nil {
		return nil, err
	}
	_, committee, _, err := s.resolveExactFHSCommittee(ref.KeyHash, true)
	if err != nil || committee == nil || len(committee.List) == 0 {
		return nil, fmt.Errorf("proposal committee unavailable %s: %w", ref.KeyHash, err)
	}
	destinations := make([]string, 0, len(committee.List)-1)
	for _, node := range committee.List {
		if node == nil || node.Address == "" || IsSelf(node.Address) {
			continue
		}
		destinations = append(destinations, node.Address)
	}
	return &stagedHotstuffProposal{
		proposalRef:  refBytes,
		body:         body,
		manifest:     wireBody,
		destinations: destinations,
	}, nil
}

func (s *Service) prepareHotstuffProposal(viewNumber uint64, viewID common.Hash, leaderID string, encodedBlock, extra []byte) ([]byte, error) {
	staged, err := s.stageHotstuffProposal(viewNumber, viewID, leaderID, encodedBlock, extra, s.SelectedFHSProposalParent())
	if err != nil {
		return nil, err
	}
	s.dispatchProposalManifest(staged.manifest, staged.destinations, 0)
	return staged.proposalRef, nil
}

// OnPropose is retained for non-FHS callers. Production FHS nodes schedule the
// same validation on the bounded worker pool below and install its result on
// the serialized HotStuff control loop.
func (s *Service) OnPropose(state []byte, extra []byte, viewNumber uint64, parentQC *hotstuff.SignedState) error {
	output, err := s.validateHotstuffProposalApplication(context.Background(), state, extra, viewNumber, parentQC, nil, 0, 0)
	if err != nil {
		return err
	}
	return s.installHotstuffProposalValidation(output)
}

func (s *Service) validateHotstuffProposalApplication(ctx context.Context, state []byte, extra []byte, viewNumber uint64, parentQC *hotstuff.SignedState, parentVerified *core.VerifiedProposal, serviceGeneration, validationGeneration uint64) (*proposalValidationOutput, error) {
	if !s.isRunning() {
		return nil, types.ErrNotRunning
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, hotstuff.ErrOldState
	}
	if len(state) == 0 {
		err := fmt.Errorf("empty hotstuff proposal ref")
		log.Error("OnPropose", "error", err)
		return nil, err
	}

	ref, err := types.DecodeHotstuffProposalRef(state)
	if err != nil {
		log.Error("OnPropose decode proposal ref", "err", err)
		return nil, err
	}
	if ref.ChainID != s.ChainID() {
		return nil, fmt.Errorf("hotstuff proposal chain id mismatch: have %d want %d", ref.ChainID, s.ChainID())
	}
	if ref.ViewNumber != viewNumber {
		return nil, fmt.Errorf("hotstuff proposal view number mismatch: have %d want %d", ref.ViewNumber, viewNumber)
	}
	if s.fairHotstuffEnabled() {
		if ref.ExtraHash != types.HotstuffProposalExtraHash(extra) {
			return nil, fmt.Errorf("hotstuff proposal extra proof is not bound to the signed reference")
		}
		parentQCID, err := fhsQCIdentityHash(parentQC)
		if err != nil {
			return nil, err
		}
		if ref.ParentQCID != parentQCID {
			return nil, fmt.Errorf("hotstuff proposal parent QC is not bound to the signed reference")
		}
		if err := s.validateFHSProposalParent(ref, parentQC); err != nil {
			return nil, err
		}
	}
	proposalID := ref.ProposalID()
	log.Info("OnPropose",
		"number", ref.Number,
		"proposalID", proposalID,
		"blockHash", ref.BlockHash,
		"bodyHash", ref.BodyHash,
		"bodySize", ref.BodySize)

	body, err := s.waitProposalBodyForValidation(ctx, ref, serviceGeneration)
	if err != nil {
		log.Error("OnPropose wait proposal body", "number", ref.Number, "proposalID", proposalID, "err", err)
		return nil, err
	}
	block := types.DecodeToBlock(body.EncodedBlock)
	if block == nil {
		err := fmt.Errorf("DecodeToBlock(proposal body) error")
		log.Error("OnPropose", "proposalID", proposalID, "error", err)
		return nil, err
	}
	if err := ref.VerifyAgainstBlock(block, body.EncodedBlock); err != nil {
		log.Error("OnPropose proposal ref mismatch", "number", ref.Number, "proposalID", proposalID, "err", err)
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, hotstuff.ErrOldState
	}

	var verified *core.VerifiedProposal
	if parentVerified != nil {
		// Only ScheduleFHSProposalValidation supplies a non-nil parent here;
		// snapshotFHSCertifiedVerified has already isolated it from the cache.
		// An empty parent may legitimately have no execution state. Preserve
		// the existing StateAt fallback; there is no mutable state to transfer.
		if parentVerified.StateDB == nil {
			verified, err = s.txService.verifyHotstuffProposalWithParent(ref, block, extra, parentVerified)
		} else {
			verified, err = s.txService.verifyHotstuffProposalWithOwnedParent(ref, block, extra, parentVerified)
		}
	} else {
		verified, err = s.txService.verifyHotstuffProposal(ref, block, extra)
	}
	if err != nil {
		log.Error("verify hotstuff proposal", "number", block.NumberU64(), "proposalID", proposalID, "err", err)
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, hotstuff.ErrOldState
	}
	if block.BlockType() == types.Key_Block {
		kblock := types.DecodeToKeyBlock(block.KeyInfo())
		if kblock == nil {
			return nil, fmt.Errorf("Block's extra (keyblock) is error format!")
		}
		if s.hasConflictingUncommittedFHSKeyBlock(block) {
			return nil, fmt.Errorf("reject competing key block while a certified key transition is uncommitted: proposal=%s", block.Hash())
		}
		if block.NumberU64() == 0 {
			return nil, fmt.Errorf("key block carrier cannot be transaction genesis")
		}
	}
	return &proposalValidationOutput{
		ref:                  ref,
		verified:             verified,
		extra:                append([]byte(nil), extra...),
		parentQC:             hotstuff.CloneSignedState(parentQC),
		serviceGeneration:    serviceGeneration,
		validationGeneration: validationGeneration,
	}, nil
}

func (s *Service) installHotstuffProposalValidation(output *proposalValidationOutput) error {
	if output == nil || output.ref == nil || output.verified == nil || output.verified.ProposalID != output.ref.ProposalID() {
		return fmt.Errorf("invalid hotstuff proposal validation output")
	}
	if output.serviceGeneration != 0 && (atomic.LoadInt32(&s.runningState) != 1 || atomic.LoadUint64(&s.proposalValidationGeneration) != output.serviceGeneration) {
		return hotstuff.ErrOldState
	}
	if atomic.LoadInt32(&s.fhsEpochTransition) != 0 {
		return hotstuff.ErrOldState
	}
	if output.validationGeneration != 0 && !s.isProposalValidationOutputActive(output) {
		return hotstuff.ErrOldState
	}
	if err := output.verified.SanityCheck(); err != nil || output.verified.BlockHash() != output.ref.BlockHash ||
		output.verified.ViewNumber != output.ref.ViewNumber || output.verified.ViewID != output.ref.ViewID || output.verified.LeaderID != output.ref.LeaderID ||
		output.verified.ParentHash != output.ref.ParentHash {
		return fmt.Errorf("invalid verified proposal artifact: %v", err)
	}
	if output.ref.ExtraHash != types.HotstuffProposalExtraHash(output.extra) {
		return fmt.Errorf("validated proposal extra commitment changed")
	}
	parentQCID, err := fhsQCIdentityHash(output.parentQC)
	if err != nil {
		return err
	}
	if output.ref.ParentQCID != parentQCID {
		return fmt.Errorf("validated proposal parent QC commitment changed")
	}
	if s.fairHotstuffEnabled() {
		if err := s.validateFHSProposalParent(output.ref, output.parentQC); err != nil {
			return err
		}
	}
	if output.verified.Block != nil && output.verified.Block.BlockType() == types.Key_Block {
		block := output.verified.Block
		kblock := types.DecodeToKeyBlock(block.KeyInfo())
		if kblock == nil || block.NumberU64() == 0 || s.hasConflictingUncommittedFHSKeyBlock(block) {
			return fmt.Errorf("validated key block is no longer admissible")
		}
		if err := s.keyService.verifyKeyBlock(kblock, types.DecodeToCandidate(output.extra), block.NumberU64()-1); err != nil {
			return err
		}
	}
	if err := s.updateProposalBodyProof(output.ref.ProposalID(), output.extra, output.parentQC); err != nil {
		return err
	}
	s.storeVerifiedProposal(output.ref.ProposalID(), output.verified)
	s.pacetMakerTimer.start()
	return nil
}

func (s *Service) ApplyFHSProposalValidation(result *hotstuff.FHSProposalValidationResult) error {
	if result == nil || result.Err != nil {
		return fmt.Errorf("invalid FHS proposal validation result")
	}
	output, ok := result.ApplicationData.(*proposalValidationOutput)
	if !ok || output == nil || output.ref == nil || output.ref.ViewNumber != result.Key.ViewNumber ||
		output.ref.ViewID != result.Key.ViewID || output.ref.LeaderID != result.Key.LeaderID || output.ref.ProposalID() != result.Key.ProposalID {
		return fmt.Errorf("FHS proposal validation result context mismatch")
	}
	if err := s.acquireFHSValidationPublication(fhsValidationPublicationProposal); err != nil {
		return err
	}
	transferred := false
	defer func() {
		if !transferred {
			s.releaseFHSValidationPublication(fhsValidationPublicationProposal)
		}
	}()
	if err := s.installHotstuffProposalValidation(output); err != nil {
		return err
	}
	s.activeProposalValidationPublish = result
	transferred = true
	return nil
}

// FinishFHSProposalValidation releases the publication barrier only after the
// manager has durably persisted, signed and sent (or rejected) the vote.
func (s *Service) FinishFHSProposalValidation(result *hotstuff.FHSProposalValidationResult) {
	if s == nil || result == nil ||
		atomic.LoadInt32(&s.fhsValidationPublicationOwner) != int32(fhsValidationPublicationProposal) ||
		s.activeProposalValidationPublish != result {
		return
	}
	s.activeProposalValidationPublish = nil
	if !s.releaseFHSValidationPublication(fhsValidationPublicationProposal) {
		atomic.StoreInt32(&s.fhsEpochTransition, 1)
		s.setRunState(0)
		log.Error("Fair HotStuff proposal validation failed to release its publication barrier")
	}
}

func (s *Service) stageFHSProposalBuild(job *proposalBuildJob) (*proposalBuildOutput, error) {
	request := job.request
	output := &proposalBuildOutput{
		key:                    request.Key,
		serviceGeneration:      job.serviceGeneration,
		constructionGeneration: job.constructionGeneration,
	}
	if !s.isProposalBuildJobActive(job) {
		return output, hotstuff.ErrOldState
	}
	state, leaderID, number := s.CurrentState()
	if number != request.Key.ViewNumber || leaderID != request.Key.LeaderID || !bytes.Equal(state, request.CurrentState) {
		return output, hotstuff.ErrOldState
	}

	s.muCurrentView.Lock()
	leaderIndex := s.currentView.LeaderIndex
	noDone := s.currentView.NoDone
	replicaMatches := s.replicaView != nil && s.replicaView.EqualConsensus(&s.currentView)
	s.muCurrentView.Unlock()
	if !replicaMatches || !bftview.IamLeader(leaderIndex) {
		return output, hotstuff.ErrOldState
	}

	fixedMode := s.keyService.fixedModeEnabled()
	keyBlockIntervalElapsed := true
	if curKeyblock := s.kbc.CurrentBlock(); curKeyblock != nil {
		keyBlockIntervalElapsed = time.Since(time.Unix(int64(curKeyblock.Time()), 0)) >= params.KeyBlockMinInterval
	}
	keyProposalAttempt, keyProposalIsDone := keyProposalPlan(fixedMode, leaderIndex, noDone, keyBlockIntervalElapsed)
	if keyProposalAttempt && s.hasUncommittedFHSKeyBlock() {
		keyProposalAttempt = false
	}
	output.fixedMode = fixedMode
	output.keyProposalAttempt = keyProposalAttempt

	if output.keyProposalAttempt {
		txParentNumber := fhsProposalParentNumber(s.bc.CurrentBlockN(), s.highestFHSCertifiedProposal())
		keyblock, committee, bestCandidate, err := s.keyService.tryProposalChangeCommittee(leaderIndex, keyProposalIsDone, txParentNumber)
		if err != nil || keyblock == nil || committee == nil {
			if err == nil {
				err = fmt.Errorf("incomplete key block proposal")
			}
			return output, err
		}
		if bestCandidate != nil {
			output.extra = bestCandidate.EncodeToBytes()
		}
		candidate, err := s.txService.buildProposalNewKeyBlock(keyblock)
		if err != nil {
			return output, err
		}
		staged, err := s.stageHotstuffProposal(request.Key.ViewNumber, request.Key.ViewID, request.Key.LeaderID,
			candidate.encoded, output.extra, request.ParentQC)
		if err != nil {
			return output, err
		}
		output.stagedHotstuffProposal = *staged
		output.keyCandidate = candidate
		output.keyBlock = keyblock
		output.committee = committee
		output.blockType = types.Key_Block
		return output, nil
	}

	output.workStamp, output.workStampValid = s.captureProposalWorkStamp(
		time.Now(), request.Key.ViewNumber, request.Key.ViewID, request.Key.LeaderID,
	)
	candidate, err := s.txService.prepareTxProposal(s.chooseTxBlockType(), false)
	if err != nil {
		return output, err
	}
	staged, err := s.stageHotstuffProposal(request.Key.ViewNumber, request.Key.ViewID, request.Key.LeaderID,
		candidate.encoded, nil, request.ParentQC)
	if err != nil {
		return output, err
	}
	output.stagedHotstuffProposal = *staged
	output.txCandidate = candidate
	output.blockType = candidate.blockType
	return output, nil
}

// proposalBuildRouteMatchesLocked requires muCurrentView. It binds the manager
// request to the exact service route and to the block/key generation captured by
// the worker. Apply keeps this lock until candidate publication completes, so a
// timeout-only route change cannot slip between this check and install.
func (s *Service) proposalBuildRouteMatchesLocked(output *proposalBuildOutput) bool {
	if output == nil || output.key.ViewNumber != s.currentView.ViewNumber+1 ||
		hotstuff.StateDigest(s.currentView.EncodeConsensusToBytes()) != output.key.CurrentStateDigest ||
		s.replicaView == nil || !s.replicaView.EqualConsensus(&s.currentView) {
		return false
	}
	committee, err := s.loadViewCommittee(&s.currentView, true)
	if err != nil || s.currentView.LeaderIndex >= uint(len(committee.List)) || committee.List[s.currentView.LeaderIndex] == nil {
		return false
	}
	leader := committee.List[s.currentView.LeaderIndex]
	if bftview.GetNodeID(leader.Address, leader.Public) != output.key.LeaderID || output.key.LeaderID != s.Self() {
		return false
	}
	var generation proposalGeneration
	switch {
	case output.txCandidate != nil && output.keyCandidate == nil:
		generation = output.txCandidate.generation
	case output.keyCandidate != nil && output.txCandidate == nil:
		generation = output.keyCandidate.generation
	default:
		return false
	}
	return generation.parentHash == s.currentView.TxHash && generation.parentNumber == s.currentView.TxNumber &&
		generation.keyHash == s.currentView.KeyHash && generation.keyNumber == s.currentView.KeyNumber
}

func (s *Service) ApplyFHSProposalBuild(result *hotstuff.FHSProposalBuildResult) error {
	if result == nil || result.Err != nil {
		return fmt.Errorf("invalid FHS proposal construction result")
	}
	output, ok := result.ApplicationData.(*proposalBuildOutput)
	if !ok || output == nil || output.key != result.Key || !bytes.Equal(output.proposalRef, result.TProposal) ||
		!bytes.Equal(output.extra, result.Extra) || output.manifest == nil || output.body == nil {
		return fmt.Errorf("FHS proposal construction result context mismatch")
	}
	s.muProposalBuild.Lock()
	buildLockTransferred := false
	defer func() {
		if !buildLockTransferred {
			s.muProposalBuild.Unlock()
		}
	}()
	active := s.activeProposalBuild
	activeMatch := active != nil && active.key == result.Key && active.generation == output.constructionGeneration
	if !activeMatch || atomic.LoadInt32(&s.runningState) != 1 ||
		atomic.LoadUint64(&s.proposalValidationGeneration) != output.serviceGeneration {
		return hotstuff.ErrOldState
	}
	if err := s.reserveProposalManifestDispatch(); err != nil {
		return err
	}
	manifestReserved := true
	defer func() {
		if manifestReserved {
			s.releaseProposalManifestDispatch()
		}
	}()
	cleanupReserved := false
	if output.txCandidate != nil && len(output.txCandidate.failedTxes) > 0 {
		if err := s.reserveProposalFailedTxCleanup(); err != nil {
			return err
		}
		cleanupReserved = true
		defer func() {
			if cleanupReserved {
				s.releaseProposalFailedTxCleanup()
			}
		}()
	}

	// Lock order is muProposalBuild -> muCurrentView -> txService.mu. No
	// txService publication path acquires muCurrentView while holding txService.mu.
	s.muCurrentView.Lock()
	currentViewLockTransferred := false
	defer func() {
		if !currentViewLockTransferred {
			s.muCurrentView.Unlock()
		}
	}()
	if !s.proposalBuildRouteMatchesLocked(output) || atomic.LoadInt32(&s.runningState) != 1 ||
		atomic.LoadUint64(&s.proposalValidationGeneration) != output.serviceGeneration {
		return hotstuff.ErrOldState
	}

	switch {
	case output.txCandidate != nil && output.keyCandidate == nil:
		if err := s.txService.installProposalCandidate(output.txCandidate, nil); err != nil {
			return err
		}
	case output.keyCandidate != nil && output.txCandidate == nil && output.keyBlock != nil && output.committee != nil:
		if err := s.txService.installKeyProposalCandidate(output.keyCandidate, func() error {
			if output.committee.RlpHash() != output.keyBlock.CommitteeHash() {
				return fmt.Errorf("key proposal committee commitment changed")
			}
			// A proposed (not committed) committee must be available for proposal
			// verification/recovery, but Committee_OnStored only adjusts live peer
			// connections for an already-canonical key block. Defer that callback to
			// the normal commit/verification path.
			if !output.committee.StoreWithoutCallback(output.keyBlock) {
				return fmt.Errorf("failed to persist proposed committee for key block %d/%s", output.keyBlock.NumberU64(), output.keyBlock.Hash())
			}
			return nil
		}); err != nil {
			return err
		}
	default:
		return fmt.Errorf("FHS proposal construction result has ambiguous candidate")
	}

	s.proposalManifestJobs <- &proposalManifestDispatch{
		body:              cloneProposalBodyMsg(output.manifest),
		destinations:      append([]string(nil), output.destinations...),
		serviceGeneration: output.serviceGeneration,
	}
	manifestReserved = false
	if cleanupReserved {
		s.proposalFailedTxJobs <- &proposalFailedTxCleanup{
			txs:               append(types.Transactions(nil), output.txCandidate.failedTxes...),
			serviceGeneration: output.serviceGeneration,
		}
		cleanupReserved = false
	}
	now := time.Now()
	s.muProposalCadence.Lock()
	if output.blockType == types.SlowTx_Block {
		s.lastSlowBlockTime = now
	} else if output.blockType == types.FastTx_Block {
		s.lastFastBlockTime = now
	}
	s.muProposalCadence.Unlock()
	output.publicationLocksHeld = true
	currentViewLockTransferred = true
	buildLockTransferred = true
	return nil
}

// FinishFHSProposalBuild releases the publication barrier after the manager has
// cached, phase-transitioned and submitted the sealed Prepare. Apply transfers
// these locks only on success, and the manager defers this callback immediately,
// so Stop cannot linearize in the Apply-to-Broadcast gap.
func (s *Service) FinishFHSProposalBuild(result *hotstuff.FHSProposalBuildResult) {
	if result == nil {
		return
	}
	output, _ := result.ApplicationData.(*proposalBuildOutput)
	if output == nil || !output.publicationLocksHeld {
		return
	}
	output.publicationLocksHeld = false
	s.muCurrentView.Unlock()
	s.muProposalBuild.Unlock()
}

// Propose call by hotstuff
func (s *Service) Propose(viewNumber uint64, viewID common.Hash, leaderID string) (e error, kState []byte, tState []byte, extra []byte) { //buf recv by onpropose, onviewdown
	if s.fairHotstuffEnabled() {
		return fmt.Errorf("Fair HotStuff proposal construction is asynchronous"), nil, nil, nil
	}
	log.Debug("Propose..", "number", s.GetCurrentView().TxNumber)

	proposeOK := false
	defer func() {
		if !proposeOK && !errors.Is(e, errProposalNoWork) {
			go func() {
				time.Sleep(failedProposalRetry)
				curView := s.GetCurrentView()
				if bftview.IamLeader(curView.LeaderIndex) {
					s.triggerTryPropose(s.bc.CurrentBlockN())
				}
			}()
		}
	}()

	if !s.isRunning() {
		err := fmt.Errorf("not running for propose")
		return err, nil, nil, nil
	}

	s.muCurrentView.Lock()
	leaderIndex := s.currentView.LeaderIndex
	noDone := s.currentView.NoDone
	if !s.replicaView.EqualConsensus(&s.currentView) {
		log.Error("Propose", "replica view not equal to local current view txNumber", s.currentView.TxNumber, "keyNumber", s.currentView.KeyNumber, "LeaderIndex", leaderIndex, "NoDone",
			s.currentView.NoDone, "replica txNumber", s.replicaView.TxNumber, "keyNumber", s.replicaView.KeyNumber, "LeaderIndex", s.replicaView.LeaderIndex, "NoDone", s.replicaView.NoDone)
		s.muCurrentView.Unlock()
		return fmt.Errorf("replica view not equal to local current view"), nil, nil, nil
	}
	if !bftview.IamLeader(leaderIndex) {
		//proposeOK = true
		err := fmt.Errorf("not leader for propose")
		log.Error("Propose", "leaderIndex", leaderIndex, "error", err)
		s.muCurrentView.Unlock()
		return err, nil, nil, nil
	}
	s.muCurrentView.Unlock()

	fixedMode := s.keyService.fixedModeEnabled()
	keyBlockIntervalElapsed := true
	if curKeyblock := s.kbc.CurrentBlock(); curKeyblock != nil {
		lastKeyTime := time.Unix(int64(curKeyblock.Time()), 0)
		keyBlockIntervalElapsed = time.Since(lastKeyTime) >= params.KeyBlockMinInterval
		legacyKeyProposalSelected := leaderIndex > 0
		if fixedMode {
			legacyKeyProposalSelected = !noDone
		}
		if legacyKeyProposalSelected && !keyBlockIntervalElapsed {
			log.Debug("Propose keyblock suppressed by minimum interval",
				"elapsed", time.Since(lastKeyTime),
				"minimum", params.KeyBlockMinInterval,
				"lastKeyTime", lastKeyTime)
		}
	}

	keyProposalAttempt, keyProposalIsDone := keyProposalPlan(fixedMode, leaderIndex, noDone, keyBlockIntervalElapsed)

	if keyProposalAttempt {
		txParentNumber := s.bc.CurrentBlockN()
		keyblock, mb, bestCandi, err := s.keyService.tryProposalChangeCommittee(leaderIndex, keyProposalIsDone, txParentNumber)
		if err == nil && keyblock != nil && mb != nil {
			if bestCandi != nil {
				extra = bestCandi.EncodeToBytes()
			}
			data, err := s.txService.tryProposalNewKeyBlock(keyblock)
			if err != nil {
				log.Warn("tryProposalNewKeyBlock", "error", err)
				if fixedMode {
					s.abortFixedModeKeyProposal("assemble failed", err)
				}
				return err, nil, nil, nil
			}
			proposalRef, err := s.prepareHotstuffProposal(viewNumber, viewID, leaderID, data, extra)
			if err != nil {
				log.Warn("prepare keyblock hotstuff proposal", "error", err)
				if fixedMode {
					s.abortFixedModeKeyProposal("prepare proposal failed", err)
				}
				return err, nil, nil, nil
			}
			if !mb.Store(keyblock) {
				return fmt.Errorf("failed to persist proposed committee for key block %d/%s", keyblock.NumberU64(), keyblock.Hash()), nil, nil, nil
			}
			proposeOK = true
			return nil, nil, proposalRef, extra
		} else {
			log.Error("tryProposalChangeCommittee failed", "error", err)
			if fixedMode {
				s.abortFixedModeKeyProposal("change committee failed", err)
			}
			return fmt.Errorf("tryProposalChangeCommittee failed"), nil, nil, nil
		}
	}
	workStamp, workStampValid := s.captureProposalWorkStamp(time.Now(), viewNumber, viewID, leaderID)
	candidate, err := s.txService.prepareTxProposal(s.chooseTxBlockType(), true)
	if err != nil {
		if errors.Is(err, errProposalNoWork) {
			s.rememberProposalNoWork(workStamp, workStampValid)
		} else {
			s.clearProposalNoWork()
			log.Warn("tryProposalNewBlock", "error", err)
		}
		return err, nil, nil, nil
	}
	proposalRef, err := s.prepareHotstuffProposal(viewNumber, viewID, leaderID, append([]byte(nil), candidate.encoded...), nil)
	if err != nil {
		s.clearProposalNoWork()
		log.Warn("prepare txblock hotstuff proposal", "error", err)
		return err, nil, nil, nil
	}
	now := time.Now()
	s.muProposalCadence.Lock()
	if candidate.blockType == types.SlowTx_Block {
		s.lastSlowBlockTime = now
	} else if candidate.blockType == types.FastTx_Block {
		s.lastFastBlockTime = now
	}
	s.muProposalCadence.Unlock()
	s.clearProposalNoWork()
	proposeOK = true
	return nil, nil, proposalRef, nil
}

// OnViewDone call by hotstuff
func (s *Service) OnViewDone(tSign *hotstuff.SignedState) error {
	if !s.isRunning() {
		return types.ErrNotRunning
	}
	if tSign == nil {
		log.Warn("OnViewDone nil!")
		return nil
	}
	if s.fairHotstuffEnabled() {
		return fmt.Errorf("MsgDecide commit is disabled in FHS 2-chain mode")
	}
	ref, err := types.DecodeHotstuffProposalRef(tSign.State)
	if err != nil {
		log.Error("OnViewDone decode proposal ref", "err", err)
		return err
	}
	proposalID := ref.ProposalID()
	verified := s.getVerifiedProposal(proposalID)
	if verified == nil {
		log.Warn("OnViewDone verified proposal cache miss; revalidating before commit", "number", ref.Number, "proposalID", proposalID)
		body, err := s.waitProposalBody(ref)
		if err != nil {
			return err
		}
		block := types.DecodeToBlock(body.EncodedBlock)
		if block == nil {
			return fmt.Errorf("DecodeToBlock(proposal body) error")
		}
		if err := ref.VerifyAgainstBlock(block, body.EncodedBlock); err != nil {
			return err
		}
		verified, err = s.txService.verifyHotstuffProposal(ref, block, nil)
		if err != nil {
			return err
		}
	}
	if err := s.txService.decideVerifiedProposal(ref, verified, tSign.Sign, tSign.Mask, tSign.Number, tSign.ViewID, tSign.LeaderID); err != nil {
		return err
	}
	s.deleteProposalCaches(proposalID)
	return nil
}
