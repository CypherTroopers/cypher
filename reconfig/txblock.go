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

		if txCount == 0 {
			log.Info("Not minting a new block since there are no pending transactions")
			return nil, fmt.Errorf("Not minting a new block since there are no pending transactions")
		}

		//txS.firePendingBlockEvents(logs)

		header := work.header

		// commit state root after all state transitions.
		colossusX.AccumulateRewards(txS.bc.Config(), work.publicState, header, nil)
		header.Root = work.publicState.IntermediateRoot(false)
		header.KeyHash = txS.kbc.CurrentBlock().Hash()
		header.BlockType = blockType

		// update block hash since it is now available, but was not when the
		// receipt/log of individual transactions were created:
		headerHash := header.Hash()
		for _, l := range logs {
			l.BlockHash = headerHash
		}

		block := types.NewBlock(header, committedTxes, nil, publicReceipts, new(trie.Trie))

		log.Info("Generated next block", "block num", block.Number(), "num txes", txCount)

		txS.proposedChain.extend(block)

		elapsed := time.Since(time.Unix(0, int64(header.Time)))
		log.Info("🔨  Mined block", "number", block.Number(), "hash", fmt.Sprintf("%x", block.Hash().Bytes()[:4]), "elapsed", elapsed)
		return block.EncodeToBytes(), nil
	}()

	if len(failedTxes) > 0 {
		txS.txPool.RemoveBatch(failedTxes)
		log.Warn("Removed failed proposal txs from txpool", "count", len(failedTxes))
	}

	return data, err
}

// Verify txBlock
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
	if header.KeyHash != kbc.CurrentBlock().Hash() {
		retErr = fmt.Errorf("keyhash:%x does not match current keyhash: %x", header.KeyHash, kbc.CurrentBlock().Hash())
		return retErr
	}
	if bftview.IamLeader(txS.s.GetCurrentView().LeaderIndex) {
		return nil
	}
	err := bc.Engine().VerifyHeader(bc, header, false)
	if err != nil {
		retErr = fmt.Errorf("invalid header, error:%s", err.Error())
		return retErr
	}
	err = bc.Validator().ValidateBody(txblock)
	if err == types.ErrFutureBlock || err == types.ErrUnknownAncestor || err == types.ErrPrunedAncestor {
		retErr = fmt.Errorf("invalid body, error:%s", err.Error())
		return retErr
	}
	/*
		statedb, _, err := bc.State()
		if err != nil {
			retErr = fmt.Errorf("cannot get statedb, error:%s", err.Error())
			return retErr
		}
		receipts, _, usedGas, err := bc.Processor.Process(txblock, statedb, vm.Config{})
		if err != nil {
			retErr = fmt.Errorf("cannot get receipts, error:%s", err.Error())
			return retErr
		}
		err = bc.Validator.ValidateState(txblock, bc.GetBlockByHash(txblock.ParentHash()), statedb, receipts, usedGas)
		if err != nil {
			retErr = fmt.Errorf("Invalid state, error:%s", err.Error())
			return retErr
		}
	*/
	return nil
}

// New txBlock done, when consensus agreement completed
func (txS *txService) decideNewBlock(block *types.Block, sig []byte, mask []byte) error {
	log.Info("decideNewBlock", "TxBlock Number", block.NumberU64(), "txs", len(block.Transactions()))
	bc := txS.bc
	if bc.HasBlockAndState(block.Hash(), block.NumberU64()) {
		return nil
	}
	block.SetSignature(sig, mask)
	//	log.Info("decideNewBlock", "extra", block.Extra())
	_, err := bc.InsertBlock(block)
	if err != nil {
		log.Error("decideNewBlock.InsertChain", "error", err)
		return err
	}
	txS.mux.Post(core.NewMinedBlockEvent{Block: block})
	log.Info("decideNewBlock InsertBlock ok")
	return nil
}

// -----------------------------------------------------------------------------------------------------
func (txS *txService) procBlockDone(newBlock *types.Block) {
	log.Info("chainBlockEvent...", "number", newBlock.NumberU64())
	txS.txPool.RemoveBatch(newBlock.Transactions())

	if txS.s.isRunning() {
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
	proposalPerAccountLimit  = 8
	fastBlockPerAccountLimit = 4
	fastBlockMaxTxCount      = uint64(128)
	slowBlockMaxTxCount      = uint64(256)
	fastBlockMaxGasPerTx     = uint64(300000)
	fastBlockMaxDataBytes    = 1024

	fastBlockGasTargetPct = uint64(30)
	slowBlockGasTargetPct = uint64(70)
)

const (
	failedTxDropAndShift failedTxAction = iota
	failedTxDropAndPop
	failedTxKeepAndPop
)

func isFastBlockType(blockType uint8) bool {
	return blockType == types.FastTx_Block || blockType == types.Normal_Block
}

func blockProposalLimit(blockType uint8) int {
	if isFastBlockType(blockType) {
		return fastBlockPerAccountLimit
	}
	return proposalPerAccountLimit
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
	if tx == nil {
		return false
	}
	if tx.To() == nil {
		return false
	}
	if len(tx.Data()) > fastBlockMaxDataBytes {
		return false
	}
	if tx.Gas() > fastBlockMaxGasPerTx {
		return false
	}
	return true
}

func selectTxsForBlockType(addrTxes AddressTxes, blockType uint8) AddressTxes {
	selected := make(AddressTxes, len(addrTxes))
	perAccount := blockProposalLimit(blockType)
	fastPath := isFastBlockType(blockType)

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
	parentNumber := parent.Number()

	parentTime := int64(parent.Time())
	tstamp := time.Now().UnixNano() / 1e6

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
	log.Info("createWork", "GasLimit", header.GasLimit)
	publicState, err := txS.bc.StateAt(parent.Root())
	if err != nil {
		panic(fmt.Sprint("failed to get parent state: ", err))
	}

	return &work{
		config:      txS.config,
		publicState: publicState,
		header:      header,
		txPool:      txS.txPool,
		maxTxCount:  blockMaxTxCount(blockType),
		gasTarget:   blockGasTarget(blockType, header.GasLimit),
		blockType:   blockType,
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

func (txS *txService) loadPendingAddressTxes(blockType uint8) (AddressTxes, error) {
	lane := core.TxLaneSlow
	if isFastBlockType(blockType) {
		lane = core.TxLaneFast
	}
	return txS.txPool.PendingByLane(lane)
}

func (txS *txService) getTransactions(blockType uint8, allAddrTxes AddressTxes) *types.TransactionsByPriceAndNonce {
	addrTxes := txS.proposedChain.withoutProposedTxes(allAddrTxes, time.Now())
	addrTxes = selectTxsForBlockType(addrTxes, blockType)
	addrTxes = limitAddressTxes(addrTxes, blockProposalLimit(blockType))
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

// Current state information for building the next block
type work struct {
	config      *params.ChainConfig
	publicState *state.StateDB
	Block       *types.Block
	header      *types.Header
	txPool      *core.TxPool
	maxTxCount  uint64
	gasTarget   uint64
	blockType   uint8
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
		if to := tx.To(); to != nil {
			bannedTx := false
			for _, banned := range params.BlackAddressList {
				if *to == banned {
					log.Warn("Discarding transaction to banned address",
						"hash", tx.Hash(),
						"to", banned.Hex())
					applyFailedTxAction(txes, &failedTxes, tx, failedTxDropAndPop)
					bannedTx = true
					break
				}
			}
			if bannedTx {
				continue
			}
		}
		// Check sender
		from, err := types.Sender(signer, tx)
		if err != nil {
			log.Warn("Discarding transaction with invalid sender", "hash", tx.Hash(), "err", err)
			applyFailedTxAction(txes, &failedTxes, tx, failedTxDropAndPop)
			continue
		}
		bannedFrom := false
		for _, banned := range params.BlackAddressList {
			if from == banned {
				log.Warn("Discarding transaction from banned address",
					"hash", tx.Hash(),
					"from", banned.Hex())
				applyFailedTxAction(txes, &failedTxes, tx, failedTxDropAndPop)
				bannedFrom = true
				break
			}
		}
		if bannedFrom {
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
