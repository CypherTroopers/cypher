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
	"errors"
	"fmt"
	"math/big"
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

	//go txS.eventLoop()

	return txS
}

func (txS *txService) tryProposalNewKeyBlock(keyblock *types.KeyBlock) ([]byte, error) {
	txS.mu.Lock()
	defer txS.mu.Unlock()

	work := txS.createWork(types.Key_Block)

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

	log.Info("Generated next keyblock", "block num", block.Number())

	return block.EncodeToBytes(), nil
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

func commonAdmissionApproverByTx(admissions []*types.CommonTxAdmission) map[common.Hash]common.Address {
	indexed := make(map[common.Hash]common.Address, len(admissions))
	for _, admission := range admissions {
		if admission == nil || admission.TxHash == (common.Hash{}) || admission.Miner == (common.Address{}) {
			continue
		}
		if _, exists := indexed[admission.TxHash]; !exists {
			indexed[admission.TxHash] = admission.Miner
		}
	}
	return indexed
}

func buildCommonTxRewards(txs types.Transactions, receipts types.Receipts, admissions []*types.CommonTxAdmission, baseFee *big.Int) []*types.CommonTxReward {
	approverByTx := commonAdmissionApproverByTx(admissions)
	if len(approverByTx) == 0 {
		return nil
	}
	rewards := make([]*types.CommonTxReward, 0, len(approverByTx))
	for i, tx := range txs {
		if tx == nil || i >= len(receipts) || receipts[i] == nil {
			continue
		}
		txHash := tx.Hash()
		approver, ok := approverByTx[txHash]
		if !ok {
			continue
		}
		actualFee := new(big.Int).Mul(new(big.Int).SetUint64(receipts[i].GasUsed), txEffectiveGasPrice(tx, baseFee))
		reward := new(big.Int).Div(actualFee, big.NewInt(5))
		burn := new(big.Int).Sub(actualFee, reward)
		rewards = append(rewards, &types.CommonTxReward{
			TxHash:         txHash,
			Approver:       approver,
			ApproverReward: reward,
			Burn:           burn,
		})
	}
	return rewards
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

// Try proposal new txBlock for current txs
func (txS *txService) tryProposalNewBlock(blockType uint8) ([]byte, error) {
	allAddrTxes, err := txS.loadPendingAddressTxes(blockType)
	if err != nil {
		return nil, err
	}

	var failedTxes types.Transactions
	data, err := func() ([]byte, error) {
		txS.mu.Lock()
		defer txS.mu.Unlock()

		work := txS.createWork(blockType)
		transactions := txS.getTransactions(blockType, allAddrTxes)

		committedTxes, publicReceipts, logs, failed := work.commitTransactions(transactions, txS.bc)
		failedTxes = failed
		txCount := len(committedTxes)

		allowFHSFinalityBlock := false
		if txS.config != nil && txS.config.FairHotstuff {
			if svc, ok := txS.s.(*Service); ok {
				allowFHSFinalityBlock = svc.needsFHSFinalityBlock()
			}
		}
		if txCount == 0 && !allowFHSFinalityBlock {
			log.Info("Not minting a new block since there are no pending transactions")
			return nil, fmt.Errorf("Not minting a new block since there are no pending transactions")
		}

		//txS.firePendingBlockEvents(logs)

		header := work.header
		header.KeyHash = txS.kbc.CurrentBlock().Hash()
		header.BlockType = blockType

		keyBlockNumber := uint64(0)
		if currentKey := txS.kbc.CurrentBlock(); currentKey != nil {
			keyBlockNumber = currentKey.NumberU64()
		}
		commonAdmissions := core.BuildCommonTxAdmissions(committedTxes, keyBlockNumber, header.Number.Uint64(), header.Time)
		commonRewards := buildCommonTxRewards(committedTxes, publicReceipts, commonAdmissions, header.BaseFee)
		applyCommonTxRewards(work.publicState, commonRewards)

		// commit state root after all state transitions and Common RPC reward settlement.
		colossusX.AccumulateRewards(txS.bc.Config(), work.publicState, header, nil)
		header.Root = work.publicState.IntermediateRoot(false)

		block := types.NewBlock(header, committedTxes, nil, publicReceipts, new(trie.Trie))
		block.AttachCommonTxData(commonAdmissions, commonRewards)
		encodedBlock := block.EncodeToBytes()
		if len(encodedBlock) == 0 {
			return nil, fmt.Errorf("failed to encode tx block proposal")
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

		log.Info("Generated next block", "block num", block.Number(), "num txes", txCount, "commonAdmissions", len(commonAdmissions), "commonRewards", len(commonRewards))

		txS.proposedChain.extend(block)

		elapsed := time.Since(time.Unix(int64(header.Time), 0))
		log.Info("🔨  Mined block", "number", block.Number(), "hash", fmt.Sprintf("%x", block.Hash().Bytes()[:4]), "elapsed", elapsed)
		return encodedBlock, nil
	}()

	if len(failedTxes) > 0 {
		txS.txPool.RemoveBatch(failedTxes)
		log.Warn("Removed failed proposal txs from txpool", "count", len(failedTxes))
	}

	return data, err
}

// Verify txBlock is kept for legacy callers. Production HotStuff v2 uses
// verifyHotstuffProposal so the execution result can be cached and committed
// after Decide without running StateProcessor a second time.
func (txS *txService) verifyTxBlock(txblock *types.Block) error {
	var retErr error
	bc := txS.bc
	kbc := txS.kbc
	blockNum := txblock.NumberU64()
	header := txblock.Header()
	log.Info("verifyTxBlock", "txblock num", blockNum)

	if blockNum <= bc.CurrentBlockN() {
		retErr = fmt.Errorf("invalid header, number:%d, current block number:%d", blockNum, bc.CurrentBlockN())
		return retErr
	}
	currentKey := kbc.CurrentBlock()
	if currentKey == nil {
		return fmt.Errorf("cannot verify txblock: missing current keyblock")
	}
	if header.KeyHash != currentKey.Hash() {
		retErr = fmt.Errorf("keyhash:%x does not match current keyhash: %x", header.KeyHash, currentKey.Hash())
		return retErr
	}
	err = bc.Engine().VerifyHeader(bc, header, false)
	if err != nil {
		retErr = fmt.Errorf("invalid header, error:%s", err.Error())
		return retErr
	}
	err = bc.Validator().ValidateBody(txblock)
	if err != nil {
		retErr = fmt.Errorf("invalid body, error:%s", err.Error())
		return retErr
	}
	parent := bc.GetBlock(txblock.ParentHash(), txblock.NumberU64()-1)
	if parent == nil {
		retErr = fmt.Errorf("cannot get parent block, number:%d parent:%x", txblock.NumberU64()-1, txblock.ParentHash())
		return retErr
	}
	statedb, err := bc.StateAt(parent.Root())
	if err != nil {
		retErr = fmt.Errorf("cannot get parent statedb, error:%s", err.Error())
		return retErr
	}
	receipts, _, usedGas, err := bc.Processor().Process(txblock, statedb, vm.Config{})
	if err != nil {
		retErr = fmt.Errorf("cannot process block state, error:%s", err.Error())
		return retErr
	}
	err = bc.Validator().ValidateState(txblock, statedb, receipts, usedGas)
	if err != nil {
		retErr = fmt.Errorf("invalid state, error:%s", err.Error())
		return retErr
	}
	return nil
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

// New txBlock done, when consensus agreement completed. This legacy path is
// kept for compatibility with non-v2 callers and still imports through the
// normal chain insertion path.
func (txS *txService) decideNewBlock(block *types.Block, sig []byte, mask []byte, viewID common.Hash, leaderID string) error {
	log.Info("decideNewBlock", "TxBlock Number", block.NumberU64(), "txs", len(block.Transactions()))
	bc := txS.bc
	if bc.HasBlockAndState(block.Hash(), block.NumberU64()) {
		return nil
	}
	block.SetSignature(sig, mask, viewID, leaderID, block.NumberU64())
	_, err := bc.InsertBlock(block)
	if err != nil {
		log.Error("decideNewBlock.InsertChain", "error", err)
		return err
	}
	txS.mux.Post(core.NewMinedBlockEvent{Block: block})
	log.Info("decideNewBlock InsertBlock ok")
	return nil
}

// decideVerifiedProposal commits the exact execution result obtained during
// VotePrepare validation. It is used by legacy Decide and by delayed FHS
// 2-chain commit, and deliberately avoids a second StateProcessor execution.
func (txS *txService) decideVerifiedProposal(ref *types.HotstuffProposalRef, verified *core.VerifiedProposal, sig []byte, mask []byte, viewNumber uint64, viewID common.Hash, leaderID string) error {
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
	if bc.HasBlockAndState(block.Hash(), block.NumberU64()) {
		log.Info("decideVerifiedProposal already known", "number", block.NumberU64(), "hash", block.Hash(), "proposalID", proposalID)
		return nil
	}
	if txS.config != nil && txS.config.FairHotstuff {
		block.SetFHSSignature(sig, mask, viewID, leaderID, viewNumber, ref.ExtraHash, ref.ParentQCID)
	} else {
		block.SetSignature(sig, mask, viewID, leaderID, viewNumber)
	}
	if _, err := bc.CommitVerifiedProposal(verified, false); err != nil {
		log.Error("decideVerifiedProposal.CommitVerifiedProposal", "number", block.NumberU64(), "proposalID", proposalID, "error", err)
		return err
	}
	txS.mux.Post(core.NewMinedBlockEvent{Block: block})
	log.Info("decideVerifiedProposal commit ok", "number", block.NumberU64(), "hash", block.Hash(), "proposalID", proposalID)
	return nil
}

// -----------------------------------------------------------------------------------------------------
func (txS *txService) procBlockDone(newBlock *types.Block) {
	log.Info("chainBlockEvent...", "number", newBlock.NumberU64())
	txS.txPool.RemoveBatch(newBlock.Transactions())
	core.DropCommonRPCAdmissions(newBlock.Transactions())

	if txS.config != nil && txS.config.FairHotstuff {
		txS.mu.Lock()
		txS.proposedChain.markCommitted(newBlock)
		txS.mu.Unlock()
	} else if txS.s.isRunning() {
		txS.updateChainPerNewHead(newBlock)
	} else {
		txS.proposedChain.setHead(newBlock)
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
				txS.proposedChain.setHead(newBlock)
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
	fastPerAccountTierLarge  = 16384
	slowPerAccountTierLarge  = 16384
	fastBlockMaxTxCount      = uint64(16384)
	slowBlockMaxTxCount      = uint64(16384)
	fastBlockGasTargetPct    = uint64(95)
	slowBlockGasTargetPct    = uint64(99)

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
	dexBlockMaxTxCount    = uint64(16384)

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
		errors.Is(err, core.ErrInvalidSender):
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
		BaseFee:    big.NewInt(params.FixedBaseFeePerGas),
	}
	log.Info("createWork", "GasLimit", header.GasLimit)
	if publicState == nil {
		var err error
		publicState, err = txS.bc.StateAt(parent.Root())
		if err != nil {
			panic(fmt.Sprint("failed to get parent state: ", err))
		}
	}

	gasTarget := blockGasTarget(blockType, header.GasLimit)
	pendingTotal, _ := txS.txPool.Stats()

	return &work{
		config:         txS.config,
		publicState:    publicState,
		header:         header,
		txPool:         txS.txPool,
		maxTxCount:     blockMaxTxCount(blockType),
		gasTarget:      gasTarget,
		resourceBudget: newTxResourceBudget(blockType, gasTarget, pendingTotal),
		blockType:      blockType,
	}
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
	perAccountLimit := blockProposalLimit(blockType, pendingTotal)
	maxTx := int(blockMaxTxCount(blockType))
	gasTarget := uint64(0)
	if head := txS.bc.CurrentBlock(); head != nil && head.Header() != nil {
		gasTarget = blockGasTarget(blockType, head.Header().GasLimit)
	}

	return txS.txPool.PendingByLaneAndClassesLimited(
		lane,
		maxTx,
		perAccountLimit,
		gasTarget,
		pendingClassesForBlockType(blockType)...,
	)
}

func (txS *txService) getTransactions(blockType uint8, allAddrTxes AddressTxes) *types.TransactionsByPriceAndNonce {
	addrTxes := txS.proposedChain.withoutProposedTxes(allAddrTxes, time.Now())
	pendingTotal, _ := txS.txPool.Stats()
	perAccountLimit := blockProposalLimit(blockType, pendingTotal)

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
	return types.NewTransactionsByPriceAndNonce(txS.config, txS.bc.CurrentBlock().Number(), addrTxes)
}

// Sends-off events asynchronously.

func precheckTxForProposal(st *state.StateDB, header *types.Header, tx *types.Transaction, from common.Address) error {
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
	intrGas, err := core.IntrinsicGas(tx.Data(), tx.To() == nil)
	if err != nil {
		return err
	}
	if tx.Gas() < intrGas {
		return core.ErrIntrinsicGas
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
	blockType      uint8
}

func (env *work) commitTransactions(txes *types.TransactionsByPriceAndNonce, bc *core.BlockChain) (types.Transactions, types.Receipts, []*types.Log, types.Transactions) {
	var allLogs []*types.Log
	var committedTxes types.Transactions
	var publicReceipts types.Receipts
	var failedTxes types.Transactions

	gp := new(core.GasPool).AddGas(env.header.GasLimit)
	signer := types.NewEIP155Signer(env.config.ChainID)
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
		resourceClass := core.ClassifyTxResource(tx)
		if env.resourceBudget != nil && !env.resourceBudget.CanInclude(resourceClass, tx.Gas()) {
			log.Debug("Skipping tx above resource class budget", "hash", tx.Hash(), "class", resourceClass, "gas", tx.Gas(), "blockType", env.blockType)
			txes.Pop()
			continue
		}

		// Check sender
		from, err := types.Sender(signer, tx)
		if err != nil {
			log.Warn("Discarding transaction with invalid sender", "hash", tx.Hash(), "err", err)
			applyFailedTxAction(txes, &failedTxes, tx, failedTxDropAndPop)
			continue
		}
		if err := precheckTxForProposal(env.publicState, env.header, tx, from); err != nil {
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
			committedTxes = append(committedTxes, tx)
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
