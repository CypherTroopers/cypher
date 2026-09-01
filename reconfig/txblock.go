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
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"sync"
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
	s               serviceI
	cph             *ReconfigBackend
	txPool          *core.TxPool
	bc              *core.BlockChain
	kbc             *core.KeyBlockChain
	config          *params.ChainConfig
	pendingLogsFeed *event.Feed
	mu              sync.Mutex
	mux             *event.TypeMux
	proposedChain   *proposedChain
	chainEventChan  chan core.ChainEvent
	chainEventSub   event.Subscription
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
	proposedRevision uint64
	parentHash       common.Hash
	parentRoot       common.Hash
	parentNumber     uint64
	keyHash          common.Hash
	keyNumber        uint64
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

func (generation proposalGeneration) matches(revision uint64, parent *types.Block, keyBlock *types.KeyBlock) bool {
	if parent == nil || keyBlock == nil || revision != generation.proposedRevision {
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
		s:      s,
		cph:    backend,
		bc:     backend.BlockChain(),
		kbc:    backend.KeyBlockChain(),
		txPool: backend.TxPool(),
		//		chainEventChan: make(chan core.ChainEvent, 1),
		config:        config,
		proposedChain: newProposedChain(),
		mux:           backend.EventMux(),
	}

	//	txS.chainEventSub = backend.BlockChain().SubscribeChainEvent(txS.chainEventChan)
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

	//go txS.eventLoop()

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

	work := txS.createWork(types.Key_Block)
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
	colossusX.AccumulateRewards(txS.bc.Config(), work.publicState, header, nil)
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
		if int(ref.Item) >= len(batch.TxHashes) || batch.TxHashes[ref.Item] != txHash || batch.Miner == (common.Address{}) {
			return nil, fmt.Errorf("Fair HotStuff transaction %s has invalid common RPC admission item %d", txHash, ref.Item)
		}
		actualFee := new(big.Int).Mul(new(big.Int).SetUint64(receipts[i].GasUsed), txEffectiveGasPrice(tx, baseFee))
		reward := new(big.Int).Div(actualFee, big.NewInt(5))
		burn := new(big.Int).Sub(actualFee, reward)
		rewards = append(rewards, &types.CommonTxReward{
			TxHash:         txHash,
			Approver:       batch.Miner,
			ApproverReward: reward,
			Burn:           burn,
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
	if st == nil {
		return
	}
	for _, reward := range rewards {
		if reward == nil || reward.Approver == (common.Address{}) || reward.ApproverReward == nil || reward.ApproverReward.Sign() <= 0 {
			continue
		}
		st.AddBalance(reward.Approver, reward.ApproverReward)
	}
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
	return proposalGeneration{
		proposedRevision: txS.proposedChain.revision,
		parentHash:       parent.Hash(),
		parentRoot:       parent.Root(),
		parentNumber:     parent.NumberU64(),
		keyHash:          keyBlock.Hash(),
		keyNumber:        keyBlock.NumberU64(),
	}, nil
}

// proposalGenerationCurrentLocked must be called with txService.mu held.
func (txS *txService) proposalGenerationCurrentLocked(generation proposalGeneration) bool {
	if txS == nil || txS.proposedChain == nil || txS.kbc == nil {
		return false
	}
	return generation.matches(txS.proposedChain.revision, txS.currentProposalParent(), txS.kbc.CurrentBlock())
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
		generation            proposalGeneration
		allowFHSFinalityBlock bool
	)
	if err := func() error {
		txS.mu.Lock()
		defer txS.mu.Unlock()

		work = txS.createWork(blockType)
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
		filteredAddrTxes = filterFHSAdmittedAddressTxes(
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
		committedTxes, publicReceipts, logs, failed := work.commitTransactions(transactions, txS.bc)
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

		//txS.firePendingBlockEvents(logs)

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
		commonAdmissionBatches, commonAdmissionRefs, err := core.BuildCommonTxAdmissions(committedTxes, txS.config, txS.bc.Genesis().Hash(), generation.keyNumber, header.Number.Uint64(), header.Time)
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
		colossusX.AccumulateRewards(txS.bc.Config(), work.publicState, header, nil)
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
			const rlpProofOverhead = 16
			maxProposalSize := params.MaxBlockSize - types.MaxFHSFinalityProofSize - rlpProofOverhead
			if len(encodedBlock) > maxProposalSize {
				return nil, fmt.Errorf("Osaka tx block proposal too large after finality-proof reserve: bytes=%d limit=%d", len(encodedBlock), maxProposalSize)
			}
		}
		if limit := proposalByteLimit(blockType); limit > 0 && len(encodedBlock) > limit {
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

// Try proposal new txBlock for synchronous non-FHS callers.
func (txS *txService) tryProposalNewBlock(blockType uint8) ([]byte, error) {
	candidate, err := txS.buildProposalNewBlock(blockType)
	if err != nil {
		return nil, err
	}
	if err := txS.installProposalCandidate(candidate, nil); err != nil {
		return nil, err
	}
	if len(candidate.failedTxes) > 0 {
		txS.txPool.RemoveBatch(candidate.failedTxes)
		log.Warn("Removed failed proposal txs from txpool", "count", len(candidate.failedTxes))
	}
	return append([]byte(nil), candidate.encoded...), nil
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

// verifyHistoricalCertifiedProposal executes a proposal whose QC has already
// been verified against the committee identified by ref.KeyHash. This is used
// only for FHS catch-up and WAL replay: a pipelined block may have been
// certified immediately before a key-block commit and therefore legitimately
// refer to the previous canonical committee after the live key head advances.
func (txS *txService) verifyHistoricalCertifiedProposal(ref *types.HotstuffProposalRef, txblock *types.Block, extra []byte) (*core.VerifiedProposal, error) {
	var parentVerified *core.VerifiedProposal
	if ref != nil && txS.config != nil && txS.config.FairHotstuff {
		if svc, ok := txS.s.(*Service); ok {
			parentVerified = svc.getFHSCertifiedVerified(ref.ParentHash)
		}
	}
	return txS.verifyHistoricalCertifiedProposalWithParent(ref, txblock, extra, parentVerified)
}

// verifyHotstuffProposalWithParent is also used by fail-closed WAL recovery,
// where an entire uncommitted chain must be validated before any record is
// published into the live certified-proposal maps.
func (txS *txService) verifyHotstuffProposalWithParent(ref *types.HotstuffProposalRef, txblock *types.Block, extra []byte, parentVerified *core.VerifiedProposal) (*core.VerifiedProposal, error) {
	return txS.verifyHotstuffProposalWithKeyContext(ref, txblock, extra, parentVerified, false)
}

// verifyHistoricalCertifiedProposalWithParent is deliberately separate from
// the live Prepare verifier. It accepts an older KeyHash only when that key
// block is present on the local canonical key chain. The caller must first
// verify the proposal QC with the committee selected by ref.KeyHash.
func (txS *txService) verifyHistoricalCertifiedProposalWithParent(ref *types.HotstuffProposalRef, txblock *types.Block, extra []byte, parentVerified *core.VerifiedProposal) (*core.VerifiedProposal, error) {
	return txS.verifyHotstuffProposalWithKeyContext(ref, txblock, extra, parentVerified, true)
}

func (txS *txService) verifyHotstuffProposalWithKeyContext(ref *types.HotstuffProposalRef, txblock *types.Block, extra []byte, parentVerified *core.VerifiedProposal, allowHistoricalKey bool) (*core.VerifiedProposal, error) {
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
	currentKey := kbc.CurrentBlock()
	if currentKey == nil {
		return nil, fmt.Errorf("cannot verify hotstuff proposal: missing current keyblock")
	}
	if header.KeyHash != currentKey.Hash() {
		if !allowHistoricalKey {
			return nil, fmt.Errorf("keyhash:%x does not match current keyhash: %x", header.KeyHash, currentKey.Hash())
		}
		historicalKey := kbc.GetBlockByHash(header.KeyHash)
		if historicalKey == nil {
			return nil, fmt.Errorf("historical keyhash is unknown: %x", header.KeyHash)
		}
		canonicalKey := kbc.GetBlockByNumber(historicalKey.NumberU64())
		if canonicalKey == nil || canonicalKey.Hash() != historicalKey.Hash() {
			return nil, fmt.Errorf("historical keyhash is not canonical: %x", header.KeyHash)
		}
	}

	verified, err := bc.ValidateBlockForHotstuffWithParent(proposalID, ref.ViewNumber, ref.ViewID, ref.LeaderID, txblock, parentVerified)
	if err != nil {
		return nil, err
	}
	return verified, nil
}

// decideVerifiedProposal commits the exact execution result obtained during
// VotePrepare validation. It is used by legacy Decide and by delayed FHS
// 2-chain commit, and deliberately avoids a second StateProcessor execution.
func (txS *txService) decideVerifiedProposal(ref *types.HotstuffProposalRef, verified *core.VerifiedProposal, sig []byte, mask []byte, viewNumber uint64, viewID common.Hash, leaderID string) error {
	return txS.decideVerifiedProposalWithChild(ref, verified, sig, mask, viewNumber, viewID, leaderID, nil)
}

func (txS *txService) decideFHSVerifiedProposal(ref *types.HotstuffProposalRef, verified *core.VerifiedProposal, targetQC, childQC *hotstuff.SignedState) error {
	if targetQC == nil || childQC == nil {
		return fmt.Errorf("incomplete FHS 2-chain commit proof")
	}
	return txS.decideVerifiedProposalWithChild(ref, verified, targetQC.Sign, targetQC.Mask, targetQC.Number, targetQC.ViewID, targetQC.LeaderID, childQC)
}

func (txS *txService) decideVerifiedProposalWithChild(ref *types.HotstuffProposalRef, verified *core.VerifiedProposal, sig []byte, mask []byte, viewNumber uint64, viewID common.Hash, leaderID string, childQC *hotstuff.SignedState) error {
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
		_, err = bc.CommitFHSVerifiedProposal(verified, childQC, false)
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
func (txS *txService) eventLoop() {
	defer txS.chainEventSub.Unsubscribe()

	for {
		select {
		case ev := <-txS.chainEventChan:
			newBlock := ev.Block
			log.Info("chainBlockEvent...", "number", newBlock.NumberU64())

			if txS.s.isRunning() {
				txS.updateChainPerNewHead(newBlock)
			} else {
				txS.mu.Lock()
				txS.proposedChain.setHead(newBlock)
				txS.mu.Unlock()
			}

			txS.s.procBlockDone(newBlock)
			//if newBlock.BlockType() == types.Key_Block {
			//	txS.txPool.ResetHead(newBlock.Header())
			//}
			//txS.txPool.RemoveBatch(newBlock.Transactions())

		// system stopped
		case <-txS.chainEventSub.Err():
			return
		}
	}
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
	// Transactions from one sender form a strict nonce chain and cannot use the
	// disjoint native-transfer executor. Keep that serial portion within one
	// validation/view budget while preserving the 16,384 transaction global
	// block limit for independent senders.
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

func proposalByteLimit(blockType uint8) int {
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

// filterFHSAdmittedAddressTxes keeps only each sender's contiguous nonce prefix
// whose admissions are valid for the proposal boundary. Later nonces cannot be
// executed when an earlier nonce lacks proof, so retaining a suffix would only
// create repeated speculative EVM work and invalid proposals.
func filterFHSAdmittedAddressTxes(addrTxes AddressTxes, config *params.ChainConfig, genesisHash common.Hash, keyBlockNumber uint64, txBlockNumber uint64, timestamp uint64) AddressTxes {
	return limitFHSAdmissionBatchPrefixes(addrTxes, int(params.MaxFHSCommonTxAdmissionBatchesPerBlock), func(tx *types.Transaction) (common.Hash, bool) {
		selection, err := core.CommonRPCAdmissionForBlockTransaction(tx, config, genesisHash, keyBlockNumber, txBlockNumber, timestamp)
		if err != nil || selection.Batch == nil {
			return common.Hash{}, false
		}
		return selection.Batch.AdmissionID, true
	})
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

func fastEligibleTx(tx *types.Transaction) bool {
	return core.IsFastLaneEligible(tx)
}

func selectTxsForBlockType(addrTxes AddressTxes, blockType uint8, perAccount int) AddressTxes {
	fastPath := isFastBlockType(blockType)
	if !fastPath && perAccount <= 0 {
		return addrTxes
	}

	selected := make(AddressTxes, len(addrTxes))
	for addr, txs := range addrTxes {
		picked := make(types.Transactions, 0, len(txs))
		for _, tx := range txs {
			if fastPath && !fastEligibleTx(tx) {
				break
			}
			picked = append(picked, tx)
			if perAccount > 0 && len(picked) >= perAccount {
				break
			}
		}
		if len(picked) > 0 {
			selected[addr] = picked
		}
	}
	return selected
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

// Assumes mu is held.
func (txS *txService) createWork(blockType uint8) *work {
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
		panic("failed to get proposal parent")
	}
	parentNumber := parent.Number()

	parentTime := int64(parent.Time())
	tstamp := time.Now().Unix()

	if parentTime >= tstamp { // Each successive block needs to be after its predecessor.
		tstamp = parentTime + 1
	}
	log.Info("createWork", "parent.Difficulty()", parent.Difficulty())

	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     parentNumber.Add(parentNumber, common.Big1),
		Difficulty: parent.Difficulty(), //colossusX.CalcDifficulty(txS.config, uint64(tstamp), parent.Header()),
		GasLimit:   txS.cph.calcGasLimitFunc(parent),
		GasUsed:    0,
		Coinbase:   bftview.GetServerCoinBase(),
		Time:       uint64(tstamp),
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
			panic(fmt.Sprint("failed to get parent state: ", err))
		}
	}
	if err := core.ProcessParentBlockHash(txS.config, header, publicState); err != nil {
		// The EIP-2935 call is deterministic system work. Continuing with a
		// partially updated state would create a proposal validators cannot
		// reproduce, so proposal construction must fail closed.
		panic(fmt.Sprint("failed to store Prague parent block hash: ", err))
	}

	gasTarget := blockGasTarget(blockType, header.GasLimit)
	pendingTotal, _ := txS.txPool.Stats()

	work := &work{
		config:         txS.config,
		publicState:    publicState,
		header:         header,
		txPool:         txS.txPool,
		maxTxCount:     blockMaxTxCount(blockType),
		gasTarget:      gasTarget,
		resourceBudget: newTxResourceBudget(blockType, gasTarget, pendingTotal),
		blockType:      blockType,
		size:           header.Size(),
	}
	if txS.config != nil && txS.config.FairHotstuff {
		work.fhsWorkMeter = core.NewFHSBlockWorkMeter()
	}
	return work
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
	maxTx, perAccountLimit := proposalPoolScanLimits(blockType, pendingTotal, txS.config != nil && txS.config.FairHotstuff)
	gasTarget := uint64(0)
	if head := txS.bc.CurrentBlock(); head != nil && head.Header() != nil {
		gasTarget = blockGasTarget(blockType, head.Header().GasLimit)
	}
	gasTarget = proposalPoolScanGasTarget(gasTarget, txS.config != nil && txS.config.FairHotstuff)

	return txS.txPool.PendingByLaneAndClassesLimited(
		lane,
		maxTx,
		perAccountLimit,
		gasTarget,
		pendingClassesForBlockType(blockType)...,
	)
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
	maxTx = int(blockMaxTxCount(blockType))
	perAccount = blockProposalLimit(blockType, pending)
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
	perAccountLimit := blockProposalLimit(blockType, pendingTotal)
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
		"maxTx", blockMaxTxCount(blockType),
		"gasTargetPct", blockGasTarget(blockType, txS.bc.CurrentBlock().Header().GasLimit))
	return addrTxes
}

// Sends-off events asynchronously.

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
		return core.ErrBlobDAUnavailable
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

func (txS *txService) firePendingBlockEvents(logs []*types.Log) {
	// Copy logs before we mutate them, adding a block hash.
	copiedLogs := make([]*types.Log, len(logs))
	for i, l := range logs {
		copiedLogs[i] = new(types.Log)
		*copiedLogs[i] = *l
	}

	go func() {
		txS.cph.pendingLogsFeed.Send(copiedLogs)
		txS.cph.eventMux.Post(core.PendingStateEvent{})
	}()
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

func (env *work) txFitsBlockSize(tx *types.Transaction) bool {
	if env == nil || tx == nil || env.config == nil || env.header == nil || env.header.Number == nil || !env.config.IsOsaka(env.header.Number, env.header.Time) {
		return true
	}
	if params.MaxBlockSize <= uint64(osakaBlockSizeBuffer) {
		return false
	}
	return uint64(env.size+tx.Size()+osakaPerTxBodySizeBuffer) < params.MaxBlockSize-uint64(osakaBlockSizeBuffer)
}

func (env *work) commitTransactions(txes *types.TransactionsByPriceAndNonce, bc *core.BlockChain) (types.Transactions, types.Receipts, []*types.Log, types.Transactions) {
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
			env.size += tx.Size() + osakaPerTxBodySizeBuffer
			env.header.BlobGasUsed += tx.BlobGas()
			if env.resourceBudget != nil {
				env.resourceBudget.Record(resourceClass, publicReceipt.GasUsed)
			}

			publicReceipts = append(publicReceipts, publicReceipt)
			allLogs = append(allLogs, publicReceipt.Logs...)

			txes.Shift()
		}
	}
	return committedTxes, publicReceipts, allLogs, failedTxes
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
