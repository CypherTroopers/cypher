// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"
	"runtime"
	"sort"
	"sync"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/consensus/misc"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
)

// Keep wave memory bounded while allowing a large validator to use more than
// eight cores. The worker count remains capped by GOMAXPROCS; this limit only
// bounds the number of independently executable transfers captured per wave.
const maxParallelNativeBatch = 256

// Cryptographic validation is CPU-bound and independent per item. Keep the
// worker population tied to GOMAXPROCS and explicitly capped so a maximum-size
// block cannot turn into an unbounded goroutine burst. Callers store results by
// input index and consume them serially, preserving deterministic error order.
const maxParallelValidationWorkers = 64

// Stop after each bounded slice so an invalid block can force at most one
// micro-batch of speculative cryptographic work beyond its first bad item.
const parallelValidationMicroBatch = 256

func parallelValidationWorkerBudget() int {
	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		return 1
	}
	if workers > maxParallelValidationWorkers {
		return maxParallelValidationWorkers
	}
	return workers
}

// All validation entry points share one process-wide CPU budget. TxQUIC can
// accept many streams concurrently, so a per-call worker cap alone would still
// multiply into thousands of verifier goroutines during a burst. A caller
// blocks before spawning workers when the global budget is exhausted, turning
// CPU saturation into bounded ingress backpressure.
var parallelValidationSlots = make(chan struct{}, parallelValidationWorkerBudget())

func runBoundedParallelValidation(count int, validate func(int)) {
	runBoundedParallelValidationWithLimit(count, cap(parallelValidationSlots), validate)
}

// runBoundedParallelValidationWithLimit shares the process-wide CPU slots while
// allowing callers with a tighter memory budget to cap their own concurrency.
// The limit is node-local scheduling policy: callers still store and consume
// results in canonical input order.
func runBoundedParallelValidationWithLimit(count, workerLimit int, validate func(int)) {
	if count <= 0 || validate == nil {
		return
	}
	maxWorkers := cap(parallelValidationSlots)
	if workerLimit < 1 {
		workerLimit = 1
	}
	if maxWorkers > workerLimit {
		maxWorkers = workerLimit
	}
	if maxWorkers > count {
		maxWorkers = count
	}
	// Acquire one slot synchronously so no blocked worker goroutine is created.
	// Additional slots are opportunistic: concurrent callers make progress with
	// the remainder instead of deadlocking while each waits for a full quota.
	parallelValidationSlots <- struct{}{}
	workers := 1
	for workers < maxWorkers {
		select {
		case parallelValidationSlots <- struct{}{}:
			workers++
		default:
			maxWorkers = workers
		}
		if maxWorkers == workers {
			break
		}
	}
	defer func() {
		for worker := 0; worker < workers; worker++ {
			<-parallelValidationSlots
		}
	}()
	if workers == 1 {
		for index := 0; index < count; index++ {
			validate(index)
		}
		return
	}

	jobs := make(chan int, workers)
	var group sync.WaitGroup
	group.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer group.Done()
			for index := range jobs {
				validate(index)
			}
		}()
	}
	for index := 0; index < count; index++ {
		jobs <- index
	}
	close(jobs)
	group.Wait()
}

// RunBoundedCryptoJobs shares the process-wide cryptographic worker budget
// with ingress callers outside package core. In particular, raw RPC sender
// recovery and admission validation must not each create a full GOMAXPROCS
// worker set when concurrent bursts reach the same process.
func RunBoundedCryptoJobs(count int, run func(int)) {
	runBoundedParallelValidation(count, run)
}

type nativeTransferJob struct {
	index             int
	tx                *types.Transaction
	from              common.Address
	to                common.Address
	fromBalance       *big.Int
	toBalance         *big.Int
	fromNonce         uint64
	effectiveGasPrice *big.Int
}

type nativeTransferResult struct {
	receipt     *types.Receipt
	fromBalance *big.Int
	toBalance   *big.Int
	fromNonce   uint64
	err         error
}

type nativeTransferTask struct {
	slot int
	job  nativeTransferJob
}

type nativeTransferCompletion struct {
	slot   int
	result nativeTransferResult
}

type nativeTransferExecutor struct {
	blockHash   common.Hash
	blockNumber *big.Int
	tasks       chan nativeTransferTask
	results     chan nativeTransferCompletion
	workers     sync.WaitGroup
}

func newNativeTransferExecutor(block *types.Block, workerCount int) *nativeTransferExecutor {
	if workerCount < 1 {
		workerCount = 1
	}
	if workerCount > maxParallelNativeBatch {
		workerCount = maxParallelNativeBatch
	}
	executor := &nativeTransferExecutor{
		tasks:   make(chan nativeTransferTask, maxParallelNativeBatch),
		results: make(chan nativeTransferCompletion, maxParallelNativeBatch),
	}
	if block != nil {
		executor.blockHash = block.Hash()
		executor.blockNumber = new(big.Int).Set(block.Number())
	}
	executor.workers.Add(workerCount)
	for worker := 0; worker < workerCount; worker++ {
		go func() {
			defer executor.workers.Done()
			for task := range executor.tasks {
				executor.results <- nativeTransferCompletion{
					slot: task.slot, result: executeNativeTransferJob(task.job, executor.blockHash, executor.blockNumber),
				}
			}
		}()
	}
	return executor
}

func (executor *nativeTransferExecutor) execute(jobs []nativeTransferJob) []nativeTransferResult {
	results := make([]nativeTransferResult, len(jobs))
	for slot, job := range jobs {
		executor.tasks <- nativeTransferTask{slot: slot, job: job}
	}
	for range jobs {
		completion := <-executor.results
		results[completion.slot] = completion.result
	}
	return results
}

func (executor *nativeTransferExecutor) close() {
	if executor == nil {
		return
	}
	close(executor.tasks)
	executor.workers.Wait()
}

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

func effectiveTxGasPrice(tx *types.Transaction, baseFee *big.Int) *big.Int {
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

func commonRPCAdmissionKeyBlockNumberForHeader(bc *BlockChain, header *types.Header) (uint64, error) {
	if bc == nil || bc.keyBlockChain == nil {
		return 0, fmt.Errorf("key block chain is not available for common tx admission validation")
	}
	if header == nil {
		return 0, fmt.Errorf("missing header for common tx admission validation")
	}
	keyBlock := bc.keyBlockChain.GetBlockByHash(header.KeyHash)
	if keyBlock == nil {
		return 0, fmt.Errorf("unknown key block for common tx admission validation: keyHash=%s", header.KeyHash)
	}
	return keyBlock.NumberU64(), nil
}

func commonRPCAdmissionGenesisHash(bc *BlockChain) (common.Hash, error) {
	if bc == nil {
		return common.Hash{}, fmt.Errorf("block chain is not available for common tx admission validation")
	}
	genesis := bc.Genesis()
	if genesis == nil {
		return common.Hash{}, fmt.Errorf("genesis block is not available for common tx admission validation")
	}
	hash := genesis.Hash()
	if hash == (common.Hash{}) {
		return common.Hash{}, fmt.Errorf("genesis block has empty hash for common tx admission validation")
	}
	return hash, nil
}

// validateCommonTxAdmissionLayout rejects all cheap certificate/reference
// failures before any public-key recovery. expectedGenesis may be zero only for
// the early body check, where the chain handle is deliberately not part of the
// helper's API; StateProcessor always supplies and checks the canonical value.
// The returned miners are aligned with includedTransactions.
func validateCommonTxAdmissionLayout(config *params.ChainConfig, batches []*types.CommonTxAdmissionBatch, refs []types.CommonTxAdmissionRef, includedTransactions types.Transactions, expectedGenesis common.Hash) ([]common.Address, error) {
	if len(refs) != len(includedTransactions) {
		return nil, fmt.Errorf("common tx admission reference count %d does not match transaction count %d", len(refs), len(includedTransactions))
	}
	if len(includedTransactions) == 0 {
		if len(batches) != 0 {
			return nil, fmt.Errorf("common tx admission contains %d unreferenced batches for an empty transaction list", len(batches))
		}
		return nil, nil
	}
	if len(batches) == 0 {
		return nil, fmt.Errorf("common tx admission references require at least one batch")
	}
	if config == nil || config.ChainID == nil || config.ChainID.Sign() <= 0 {
		return nil, fmt.Errorf("chain configuration has no valid chain id for common tx admission validation")
	}

	var previousID common.Hash
	for index, batch := range batches {
		if batch == nil {
			return nil, fmt.Errorf("common tx admission batch %d is nil", index)
		}
		if batch.AdmissionID == (common.Hash{}) {
			return nil, fmt.Errorf("common tx admission batch %d has empty admission id", index)
		}
		if index > 0 {
			order := bytes.Compare(previousID[:], batch.AdmissionID[:])
			if order == 0 {
				return nil, fmt.Errorf("common tx admission batch %d duplicates admission id %s", index, batch.AdmissionID)
			}
			if order > 0 {
				return nil, fmt.Errorf("common tx admission batches are not in ascending admission id order at index %d", index)
			}
		}
		previousID = batch.AdmissionID
		if batch.ChainID == nil || batch.ChainID.Cmp(config.ChainID) != 0 {
			return nil, fmt.Errorf("invalid common tx admission batch %s chain id: have %v want %v", batch.AdmissionID, batch.ChainID, config.ChainID)
		}
		if batch.GenesisHash == (common.Hash{}) {
			return nil, fmt.Errorf("common tx admission batch %s has empty genesis hash", batch.AdmissionID)
		}
		if expectedGenesis != (common.Hash{}) && batch.GenesisHash != expectedGenesis {
			return nil, fmt.Errorf("invalid common tx admission batch %s genesis hash: have %s want %s", batch.AdmissionID, batch.GenesisHash, expectedGenesis)
		}
		if batch.Miner == (common.Address{}) {
			return nil, fmt.Errorf("common tx admission batch %s has empty miner", batch.AdmissionID)
		}
		if !config.IsCommonRPCSigner(batch.Miner) {
			return nil, fmt.Errorf("common tx admission batch %s signer %s is not genesis-authorized", batch.AdmissionID, batch.Miner)
		}
		if batch.Timestamp == 0 {
			return nil, fmt.Errorf("common tx admission batch %s has empty timestamp", batch.AdmissionID)
		}
		if len(batch.TxHashes) == 0 || len(batch.TxHashes) > types.MaxCommonTxAdmissionBatchItems {
			return nil, fmt.Errorf("common tx admission batch %s has invalid transaction count %d", batch.AdmissionID, len(batch.TxHashes))
		}
		seenHashes := make(map[common.Hash]struct{}, len(batch.TxHashes))
		for item, txHash := range batch.TxHashes {
			if txHash == (common.Hash{}) {
				return nil, fmt.Errorf("common tx admission batch %s has empty transaction hash at item %d", batch.AdmissionID, item)
			}
			if _, duplicate := seenHashes[txHash]; duplicate {
				return nil, fmt.Errorf("common tx admission batch %s repeats transaction %s", batch.AdmissionID, txHash)
			}
			seenHashes[txHash] = struct{}{}
		}
		wantTxRoot := types.DeriveCommonTxAdmissionTxRoot(batch.TxHashes)
		if batch.TxRoot != wantTxRoot {
			return nil, fmt.Errorf("common tx admission batch %s transaction root mismatch: have %s want %s", batch.AdmissionID, batch.TxRoot, wantTxRoot)
		}
		wantAdmissionID := types.CommonTxAdmissionID(batch)
		if batch.AdmissionID != wantAdmissionID {
			return nil, fmt.Errorf("common tx admission batch id mismatch at index %d: have %s want %s", index, batch.AdmissionID, wantAdmissionID)
		}
	}

	miners := make([]common.Address, len(refs))
	referencedBatches := make([]bool, len(batches))
	selectedItems := make(map[uint64]struct{}, len(refs))
	for index, ref := range refs {
		tx := includedTransactions[index]
		if tx == nil || !tx.IsInitialized() {
			return nil, fmt.Errorf("Fair HotStuff transaction %d is nil or uninitialized", index)
		}
		if int(ref.Batch) >= len(batches) {
			return nil, fmt.Errorf("common tx admission reference %d selects batch %d outside %d batches", index, ref.Batch, len(batches))
		}
		batch := batches[ref.Batch]
		if int(ref.Item) >= len(batch.TxHashes) {
			return nil, fmt.Errorf("common tx admission reference %d selects item %d outside batch %d size %d", index, ref.Item, ref.Batch, len(batch.TxHashes))
		}
		selectedKey := uint64(ref.Batch)<<16 | uint64(ref.Item)
		if _, duplicate := selectedItems[selectedKey]; duplicate {
			return nil, fmt.Errorf("common tx admission reference %d duplicates batch %d item %d", index, ref.Batch, ref.Item)
		}
		selectedItems[selectedKey] = struct{}{}
		wantHash := tx.Hash()
		if haveHash := batch.TxHashes[ref.Item]; haveHash != wantHash {
			return nil, fmt.Errorf("common tx admission reference %d transaction mismatch: batch %d item %d has %s want %s", index, ref.Batch, ref.Item, haveHash, wantHash)
		}
		referencedBatches[ref.Batch] = true
		miners[index] = batch.Miner
	}
	for index, referenced := range referencedBatches {
		if !referenced {
			return nil, fmt.Errorf("common tx admission batch %d (%s) is unreferenced", index, batches[index].AdmissionID)
		}
	}
	return miners, nil
}

func buildCommonAdmissionApprovers(config *params.ChainConfig, batches []*types.CommonTxAdmissionBatch, refs []types.CommonTxAdmissionRef, includedTransactions types.Transactions, expectedGenesis common.Hash, keyBlockNumber uint64, blockTimestamp uint64) ([]common.Address, error) {
	miners, err := validateCommonTxAdmissionLayout(config, batches, refs, includedTransactions, expectedGenesis)
	if err != nil {
		return nil, err
	}
	for _, batch := range batches {
		if err := validateCommonRPCAdmissionForBlock(batch, keyBlockNumber, blockTimestamp); err != nil {
			return nil, err
		}
	}
	if err := verifyCommonTxAdmissionSignatures(batches); err != nil {
		return nil, err
	}
	return miners, nil
}

func buildCommonRewardIndex(rewards []*types.CommonTxReward, includedTransactions types.Transactions) (map[common.Hash]uint32, error) {
	var included map[common.Hash]struct{}
	if includedTransactions != nil {
		included = make(map[common.Hash]struct{}, len(includedTransactions))
		for _, tx := range includedTransactions {
			if tx != nil {
				included[tx.Hash()] = struct{}{}
			}
		}
	}
	indexed := make(map[common.Hash]uint32, len(rewards))
	for position, reward := range rewards {
		if reward == nil {
			continue
		}
		if uint64(position) >= uint64(fhsRewardPositionMissing) {
			return nil, fmt.Errorf("common tx reward position %d exceeds supported range", position)
		}
		if reward.TxHash == (common.Hash{}) {
			return nil, fmt.Errorf("invalid common tx reward: empty tx hash")
		}
		if reward.ApproverReward == nil || reward.Burn == nil {
			return nil, fmt.Errorf("invalid common tx reward for %s: nil amount", reward.TxHash)
		}
		if reward.ApproverReward.Sign() < 0 || reward.Burn.Sign() < 0 {
			return nil, fmt.Errorf("invalid common tx reward for %s: negative amount", reward.TxHash)
		}
		if included != nil {
			if _, ok := included[reward.TxHash]; !ok {
				return nil, fmt.Errorf("common tx reward references tx not included in block: %s", reward.TxHash)
			}
		}
		if _, exists := indexed[reward.TxHash]; exists {
			return nil, fmt.Errorf("duplicate common tx reward for %s", reward.TxHash)
		}
		indexed[reward.TxHash] = uint32(position)
	}
	return indexed, nil
}

func validateCommonRPCReward(reward *types.CommonTxReward, expectedApprover common.Address, tx *types.Transaction, gasUsed uint64, baseFee *big.Int) error {
	if reward == nil {
		return fmt.Errorf("missing common tx reward for admitted tx %s", tx.Hash())
	}
	if expectedApprover == (common.Address{}) {
		return fmt.Errorf("invalid common tx admission for %s: empty miner", tx.Hash())
	}
	if reward.TxHash != tx.Hash() {
		return fmt.Errorf("invalid common tx reward hash: have %s want %s", reward.TxHash, tx.Hash())
	}
	if reward.Approver != expectedApprover {
		return fmt.Errorf("invalid common tx reward approver for %s: have %s want %s", tx.Hash(), reward.Approver, expectedApprover)
	}
	actualFee := new(big.Int).Mul(new(big.Int).SetUint64(gasUsed), effectiveTxGasPrice(tx, baseFee))
	expectedReward := new(big.Int).Div(actualFee, big.NewInt(5))
	expectedBurn := new(big.Int).Sub(actualFee, expectedReward)
	if reward.ApproverReward.Cmp(expectedReward) != 0 {
		return fmt.Errorf("invalid common tx approver reward for %s: have %s want %s", tx.Hash(), reward.ApproverReward, expectedReward)
	}
	if reward.Burn.Cmp(expectedBurn) != 0 {
		return fmt.Errorf("invalid common tx burn for %s: have %s want %s", tx.Hash(), reward.Burn, expectedBurn)
	}
	return nil
}

func applyCommonRPCRewards(statedb *state.StateDB, rewards []*types.CommonTxReward) {
	if statedb == nil || len(rewards) == 0 {
		return
	}
	// Rewards become visible only after every transaction has executed, so
	// additions for one approver are commutative. Collapse a maximum native
	// block's 262,144 sidecars to at most the committee's distinct approvers
	// before touching StateDB. Sorting keeps diagnostics and journal order
	// deterministic even though the resulting trie root is order-independent.
	totals := make(map[common.Address]*big.Int)
	for _, reward := range rewards {
		if reward == nil || reward.Approver == (common.Address{}) || reward.ApproverReward == nil || reward.ApproverReward.Sign() <= 0 {
			continue
		}
		if total := totals[reward.Approver]; total != nil {
			total.Add(total, reward.ApproverReward)
		} else {
			totals[reward.Approver] = new(big.Int).Set(reward.ApproverReward)
		}
	}
	approvers := make([]common.Address, 0, len(totals))
	for approver := range totals {
		approvers = append(approvers, approver)
	}
	sort.Slice(approvers, func(i, j int) bool {
		return bytes.Compare(approvers[i][:], approvers[j][:]) < 0
	})
	for _, approver := range approvers {
		statedb.AddBalance(approver, totals[approver])
	}
	// Burn is represented by intentionally not crediting the remaining fee to any account.
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, uint64, error) {
	var (
		receipts types.Receipts
		usedGas  = new(uint64)
		header   = block.Header()
		allLogs  []*types.Log
		gp       = new(GasPool).AddGas(block.GasLimit())
	)
	blockMode, err := ValidateNativeParallelBlockMode(p.config, block.BlockType(), block.Transactions())
	if err != nil {
		return nil, nil, 0, err
	}
	if err := ValidateBlockBlobGas(p.config, header, block.Transactions()); err != nil {
		return nil, nil, 0, err
	}
	body := block.Body()
	var sidecarContext fhsSidecarValidationContext
	var sidecarHandoff *fhsSidecarHandoff
	if isFHSSidecarHandoffCandidate(p.config, block, body) {
		genesisHash, err := commonRPCAdmissionGenesisHash(p.bc)
		if err != nil {
			return nil, nil, 0, err
		}
		keyBlockNumber, err := commonRPCAdmissionKeyBlockNumberForHeader(p.bc, header)
		if err != nil {
			return nil, nil, 0, err
		}
		sidecarContext = fhsSidecarValidationContext{genesisHash: genesisHash, keyBlockNumber: keyBlockNumber}
		if p.bc != nil {
			sidecarHandoff = p.bc.validatedFHSSidecars
		}
	}
	validatedSidecars, err := takeOrValidateFHSSidecars(p.config, block, sidecarContext, sidecarHandoff)
	if err != nil {
		return nil, nil, 0, err
	}
	admissionApprovers := validatedSidecars.approvers
	// Mutate the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	if err := ProcessParentBlockHash(p.config, header, statedb); err != nil {
		return nil, nil, 0, err
	}
	if err := PrepareNativeBlockHashes(p.config, header, statedb); err != nil {
		return nil, nil, 0, err
	}
	if blockMode == NativeParallelBlockModeNative {
		replayAnchors, err := NewNativeReplayAnchorSet(p.config, statedb, block.NumberU64())
		if err != nil {
			return nil, nil, 0, err
		}
		for index, tx := range block.Transactions() {
			if tx == nil || tx.Type() != types.NativeTxType {
				continue
			}
			if err := replayAnchors.Validate(tx); err != nil {
				return nil, nil, 0, fmt.Errorf("native transaction %d replay anchor: %w", index, err)
			}
		}
	}
	var totalGas uint64
	outputMeter := newBlockExecutionOutputMeter(p.config)

	recordReceipt := func(index int, tx *types.Transaction, receipt *types.Receipt) error {
		if tx == nil || receipt == nil {
			return fmt.Errorf("transaction %d has nil transaction or receipt", index)
		}
		txHash := tx.Hash()
		var admissionMiner common.Address
		hasAdmission := index >= 0 && index < len(admissionApprovers)
		if hasAdmission {
			admissionMiner = admissionApprovers[index]
		}
		reward, hasReward := validatedSidecars.rewardForTransaction(body, index)
		switch {
		case hasAdmission:
			if !hasReward {
				return fmt.Errorf("common tx admission without reward for included tx: %s", txHash)
			}
			if err := validateCommonRPCReward(reward, admissionMiner, tx, receipt.GasUsed, header.BaseFee); err != nil {
				return err
			}
		case hasReward:
			return fmt.Errorf("common tx reward without admission for included tx: %s", txHash)
		default:
			if p.config != nil && p.config.FairHotstuff {
				return fmt.Errorf("Fair HotStuff transaction has no common RPC admission or reward: %s", txHash)
			}
		}
		if err := outputMeter.Add(index, receipt); err != nil {
			return err
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
		totalGas += receipt.GasUsed
		return nil
	}

	// The first parallel lane is deliberately narrow: pairwise-disjoint,
	// existing EOA-to-EOA transfers with exact intrinsic gas. Every other
	// transaction remains on the long-standing serial path.
	txs := block.Transactions()
	rules := p.config.CypheriumRules(header.Number, header.Time)
	var nativeExecutor *nativeTransferExecutor
	evmWorkMeter := newEVMRuntimeWorkMeter(p.config)
	defer func() {
		nativeExecutor.close()
	}()
	if blockMode == NativeParallelBlockModeNative && len(txs) > 0 {
		if err := p.processNativeTransactions(block, statedb, gp, usedGas, cfg, recordReceipt); err != nil {
			return nil, nil, 0, err
		}
	} else if len(txs) > 1 && evmOptimisticParallelEnabled(p.config, cfg) {
		if err := p.processEVMOptimistic(block, statedb, gp, usedGas, cfg, recordReceipt); err != nil {
			return nil, nil, 0, err
		}
	} else {
		for i := 0; i < len(txs); {
			jobs := p.collectParallelNativeJobs(txs, i, block, statedb, gp, cfg, rules)
			if len(jobs) >= 2 {
				if nativeExecutor == nil {
					nativeExecutor = newNativeTransferExecutor(block, runtime.GOMAXPROCS(0))
				}
				results := nativeExecutor.execute(jobs)
				for offset, result := range results {
					job := jobs[offset]
					receipt, err := mergeParallelNativeResult(statedb, gp, usedGas, block, header, rules, job, result)
					if err != nil {
						return nil, nil, 0, err
					}
					if err := recordReceipt(job.index, job.tx, receipt); err != nil {
						return nil, nil, 0, err
					}
				}
				i += len(jobs)
				continue
			}

			tx := txs[i]
			var receipt *types.Receipt
			if evmWorkMeter != nil {
				var access evmMVCCAccessSet
				receipt, access, err = executeRecordedEVMSerial(p.config, p.bc, block, statedb, gp, usedGas, tx, i, cfg)
				if err == nil {
					err = evmWorkMeter.Add(p.config, header, i, tx, receipt, access)
				}
			} else {
				statedb.Prepare(tx.Hash(), block.Hash(), i)
				receipt, err = ApplyTransaction(p.config, p.bc, nil, gp, statedb, header, tx, usedGas, cfg)
			}
			if err != nil {
				return nil, nil, 0, err
			}
			if err := recordReceipt(i, tx, receipt); err != nil {
				return nil, nil, 0, err
			}
			i++
		}
	}
	// The proposer derives and applies Common RPC rewards only after executing
	// every transaction. Apply them at the same boundary during import so a
	// later transaction cannot observe rewards from an earlier transaction and
	// produce a different state root.
	applyCommonRPCRewards(statedb, body.CommonTxRewards)
	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles(), totalGas)

	return receipts, allLogs, *usedGas, nil
}

func (p *StateProcessor) collectParallelNativeJobs(txs types.Transactions, start int, block *types.Block, statedb *state.StateDB, gp *GasPool, cfg vm.Config, rules params.Rules) []nativeTransferJob {
	if p == nil || p.config == nil || block == nil || statedb == nil || gp == nil || !rules.IsByzantium ||
		!nativeParallelVMConfigSupported(cfg) {
		return nil
	}
	// EVM-only high-capacity genesis execution is metered from actual runtime
	// observations. The legacy transfer shortcut bypasses that StateDB recorder.
	if p.config.NativeParallelEnabled() && !p.config.NativeParallel.RequireNativeTransactions {
		return nil
	}
	maxJobs := int(gp.Gas() / params.TxGas)
	if maxJobs > maxParallelNativeBatch {
		maxJobs = maxParallelNativeBatch
	}
	if maxJobs < 2 {
		return nil
	}
	precompiles := make(map[common.Address]struct{})
	for _, address := range activePrecompileAddresses(rules) {
		precompiles[address] = struct{}{}
	}
	used := make(map[common.Address]struct{}, maxJobs*2)
	jobs := make([]nativeTransferJob, 0, maxJobs)
	baseFee := parallelExecutionBaseFee(p.config, block.Header())
	for index := start; index < len(txs) && len(jobs) < maxJobs; index++ {
		tx := txs[index]
		from, to, ok := parallelNativeTransferCandidate(tx, p.config, block.Number(), statedb, rules, precompiles)
		if !ok {
			break
		}
		if _, conflict := used[from]; conflict {
			break
		}
		if _, conflict := used[to]; conflict {
			break
		}
		tip, err := calcEffectiveGasTip(tx.GasFeeCap(), tx.GasTipCap(), baseFee)
		if err != nil {
			break
		}
		used[from] = struct{}{}
		used[to] = struct{}{}
		jobs = append(jobs, nativeTransferJob{
			index:             index,
			tx:                tx,
			from:              from,
			to:                to,
			fromBalance:       new(big.Int).Set(statedb.GetBalance(from)),
			toBalance:         new(big.Int).Set(statedb.GetBalance(to)),
			fromNonce:         statedb.GetNonce(from),
			effectiveGasPrice: calcEffectiveGasPrice(tip, baseFee),
		})
	}
	if len(jobs) < 2 {
		return nil
	}
	return jobs
}

func parallelExecutionBaseFee(config *params.ChainConfig, header *types.Header) *big.Int {
	if header == nil || header.BaseFee == nil || header.BaseFee.Sign() <= 0 {
		if config != nil && header != nil && config.IsLondon(header.Number) {
			return big.NewInt(params.FixedBaseFeePerGas)
		}
		return nil
	}
	return new(big.Int).Set(header.BaseFee)
}

func parallelNativeTransferCandidate(tx *types.Transaction, config *params.ChainConfig, blockNumber *big.Int, statedb *state.StateDB, rules params.Rules, precompiles map[common.Address]struct{}) (common.Address, common.Address, bool) {
	var zero common.Address
	if tx == nil {
		return zero, zero, false
	}
	from, err := types.Sender(types.MakeSignerAutoJudgement(config, blockNumber, tx.V()), tx)
	if err != nil {
		return zero, zero, false
	}
	to, ok := parallelNativeTransferStateCandidate(tx, from, config, statedb, rules, precompiles)
	return from, to, ok
}

func parallelNativeTransferStateCandidate(tx *types.Transaction, from common.Address, config *params.ChainConfig, statedb *state.StateDB, rules params.Rules, precompiles map[common.Address]struct{}) (common.Address, bool) {
	var zero common.Address
	if tx == nil || statedb == nil || tx.To() == nil || len(tx.Data()) != 0 || tx.Gas() != params.TxGas || tx.Value() == nil || tx.Value().Sign() <= 0 ||
		len(tx.AccessList()) != 0 || len(tx.BlobHashes()) != 0 || len(tx.SetCodeAuthorizations()) != 0 {
		return zero, false
	}
	switch tx.Type() {
	case types.LegacyTxType, types.AccessListTxType, types.DynamicFeeTxType:
	default:
		return zero, false
	}
	if err := ValidateTxTypeForRules(tx.Type(), rules); err != nil {
		return zero, false
	}
	to := *tx.To()
	if from == to || !statedb.Exist(from) || !statedb.Exist(to) || statedb.GetNonce(from) != tx.Nonce() || statedb.GetNonce(from) == math.MaxUint64 ||
		statedb.HasSuicided(from) || statedb.HasSuicided(to) ||
		len(statedb.GetCode(from)) != 0 || len(statedb.GetCode(to)) != 0 || statedb.GetBalance(from).Cmp(tx.Cost()) < 0 {
		return zero, false
	}
	if nativeTransferReservedAddress(from, config, rules, precompiles) {
		return zero, false
	}
	if nativeTransferReservedAddress(to, config, rules, precompiles) {
		return zero, false
	}
	return to, true
}

func nativeTransferReservedAddress(address common.Address, config *params.ChainConfig, rules params.Rules, precompiles map[common.Address]struct{}) bool {
	if config != nil && config.NativeParallelEnabled() && config.NativeParallel.RequireNativeTransactions && params.IsNativeReplayRegistryAddress(address) {
		return true
	}
	if precompiles != nil {
		_, reserved := precompiles[address]
		return reserved
	}
	for _, reserved := range activePrecompileAddresses(rules) {
		if reserved == address {
			return true
		}
	}
	return false
}

func executeNativeTransferJob(job nativeTransferJob, blockHash common.Hash, blockNumber *big.Int) nativeTransferResult {
	fee := new(big.Int).Mul(new(big.Int).SetUint64(params.TxGas), job.effectiveGasPrice)
	fromBalance := new(big.Int).Sub(new(big.Int).Set(job.fromBalance), fee)
	fromBalance.Sub(fromBalance, job.tx.Value())
	toBalance := new(big.Int).Add(new(big.Int).Set(job.toBalance), job.tx.Value())
	receipt := types.NewReceipt(nil, false, params.TxGas)
	receipt.Type = job.tx.Type()
	receipt.TxHash = job.tx.Hash()
	receipt.GasUsed = params.TxGas
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(job.index)
	return nativeTransferResult{
		receipt:     receipt,
		fromBalance: fromBalance,
		toBalance:   toBalance,
		fromNonce:   job.fromNonce + 1,
	}
}

func mergeParallelNativeResult(statedb *state.StateDB, gp *GasPool, usedGas *uint64, block *types.Block, header *types.Header, rules params.Rules, job nativeTransferJob, result nativeTransferResult) (*types.Receipt, error) {
	if block == nil {
		return nil, fmt.Errorf("parallel native transfer has no block context")
	}
	return mergeNativeTransferResult(statedb, gp, usedGas, block.Hash(), header, rules, job, result)
}

func mergeNativeTransferResult(statedb *state.StateDB, gp *GasPool, usedGas *uint64, blockHash common.Hash, header *types.Header, rules params.Rules, job nativeTransferJob, result nativeTransferResult) (*types.Receipt, error) {
	if result.err != nil {
		return nil, result.err
	}
	if statedb == nil || gp == nil || usedGas == nil || header == nil {
		return nil, fmt.Errorf("native transfer has incomplete execution context")
	}
	if result.receipt == nil || result.receipt.GasUsed != params.TxGas || len(result.receipt.Logs) != 0 {
		return nil, fmt.Errorf("parallel native transfer produced a non-canonical result")
	}
	if err := gp.SubGas(params.TxGas); err != nil {
		return nil, err
	}
	statedb.Prepare(job.tx.Hash(), blockHash, job.index)
	if rules.IsBerlin {
		statedb.PrepareAccessList(job.from, &job.to, activePrecompileAddresses(rules), nil)
		if rules.IsShanghai {
			statedb.AddAddressToAccessList(header.Coinbase)
		}
	}
	statedb.SetBalance(job.from, result.fromBalance)
	statedb.SetNonce(job.from, result.fromNonce)
	statedb.SetBalance(job.to, result.toBalance)
	statedb.Finalise(true)
	*usedGas += result.receipt.GasUsed
	result.receipt.CumulativeGasUsed = *usedGas
	return result.receipt, nil
}

// tryApplyNativeTransfer is the shared proposer/validator fast path for the
// narrow transfer class proven equivalent by the parallel-lane tests. Sender
// nonce dependencies remain serial; this only avoids constructing an EVM for
// a plain existing-EOA transfer whose intrinsic gas is exactly the gas limit.
func tryApplyNativeTransfer(config *params.ChainConfig, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, msg types.Message, usedGas *uint64, cfg vm.Config) (*types.Receipt, bool, error) {
	if config == nil || gp == nil || statedb == nil || header == nil || header.Number == nil || tx == nil || usedGas == nil ||
		cfg.Debug || cfg.Tracer != nil || cfg.EnablePreimageRecording || cfg.EVMInterpreter != "" || cfg.EWASMInterpreter != "" || len(cfg.ExtraEips) != 0 {
		return nil, false, nil
	}
	rules := config.CypheriumRules(header.Number, header.Time)
	if !rules.IsByzantium {
		return nil, false, nil
	}
	to, ok := parallelNativeTransferStateCandidate(tx, msg.From(), config, statedb, rules, nil)
	if !ok {
		return nil, false, nil
	}
	baseFee := parallelExecutionBaseFee(config, header)
	tip, err := calcEffectiveGasTip(tx.GasFeeCap(), tx.GasTipCap(), baseFee)
	if err != nil {
		return nil, true, err
	}
	job := nativeTransferJob{
		index:             statedb.TxIndex(),
		tx:                tx,
		from:              msg.From(),
		to:                to,
		fromBalance:       new(big.Int).Set(statedb.GetBalance(msg.From())),
		toBalance:         new(big.Int).Set(statedb.GetBalance(to)),
		fromNonce:         statedb.GetNonce(msg.From()),
		effectiveGasPrice: calcEffectiveGasPrice(tip, baseFee),
	}
	result := executeNativeTransferJob(job, statedb.BlockHash(), new(big.Int).Set(header.Number))
	receipt, err := mergeNativeTransferResult(statedb, gp, usedGas, statedb.BlockHash(), header, rules, job, result)
	return receipt, true, err
}

// ApplyNativeTransactionReference is the canonical serial execution oracle for
// NativeTxV1. Parallel executors must produce byte-identical receipt, logs,
// gas and state changes to this path before their deltas may be merged.
func ApplyNativeTransactionReference(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, error) {
	if tx == nil || tx.Type() != types.NativeTxType {
		return nil, fmt.Errorf("serial native reference executor requires NativeTxV1")
	}
	if err := validateNativeTransactionExecutionMode(config, tx); err != nil {
		return nil, err
	}
	// Standalone oracle callers prepare a singleton replay batch here. Normal
	// block execution has already consumed every sequence in one payer-grouped
	// prepass, and DAG branches inherit that immutable prepared set.
	standaloneReplayBatch := false
	if statedb == nil || !statedb.NativeReplayTransactionPrepared(tx.Hash()) {
		if err := PrepareNativeReplaySequences(config, statedb, types.Transactions{tx}); err != nil {
			return nil, err
		}
		standaloneReplayBatch = true
	}
	if standaloneReplayBatch {
		// Do not leave the singleton marker installed after execution. The
		// sequence state itself remains consumed, so accidentally applying the
		// same transaction again to this StateDB must run the replay prepass and
		// fail instead of treating the first call's marker as block preparation.
		defer statedb.SetNativeReplayTransactions(nil)
	}
	return ApplyTransaction(config, bc, author, gp, statedb, header, tx, usedGas, cfg)
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, error) {
	return applyTransactionWithEVMState(config, bc, author, gp, statedb, nil, header, tx, usedGas, cfg)
}

// applyTransactionWithEVMState is the shared serial oracle used by the
// standard-EVM optimistic executor. An override observes the complete vm.StateDB
// boundary while finalisation, receipts and trie ownership remain on statedb.
// Public callers pass nil and retain the historical fast paths unchanged.
func applyTransactionWithEVMState(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, executionState vm.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, error) {
	if err := validateNativeTransactionExecutionMode(config, tx); err != nil {
		return nil, err
	}
	msg, err := tx.AsMessage(types.MakeSignerAutoJudgement(config, header.Number, tx.V()))
	if err != nil {
		return nil, err
	}
	if executionState == nil {
		if config == nil || !config.NativeParallelEnabled() {
			if receipt, handled, err := tryApplyNativeTransfer(config, gp, statedb, header, tx, msg, usedGas, cfg); handled {
				return receipt, err
			}
		}
		executionState = statedb
	}
	log.Trace("ApplyTransaction", "msg.from", msg.From(), "msg.To()", msg.To())
	// Create a new context to be used in the EVM environment
	context := NewEVMContextWithConfig(config, msg, header, bc, author)
	if config != nil && config.NativeParallelEnabled() && statedb.NativeBlockHashesPrepared() {
		context.GetHash = statedb.NativeBlockHash
	}
	var nativeGuard *nativeStateGuard
	var evmGuard *evmResourceGuard
	var accessRecorder *evmMVCCRecorder
	var protocolGuard *protocolNamespaceGuard
	standardSnapshot := -1
	standardGas := uint64(0)
	if tx.Type() == types.NativeTxType {
		// Native consensus entry points prepare this immutable view before any
		// transaction branches are created. Prefer it over the node-local header
		// index so BLOCKHASH remains deterministic for an uncommitted certified
		// HotStuff parent. Direct reference-executor tests which intentionally do
		// not model EIP-2935 retain the legacy context as a test-only fallback.
		if !statedb.NativeReplayTransactionPrepared(tx.Hash()) {
			return nil, errors.New("native transaction sequence was not consumed by the block replay prepass")
		}
		if executionState != statedb {
			return nil, errors.New("native transaction cannot use the standard EVM MVCC state override")
		}
		nativeGuard = newNativeStateGuardForTransaction(statedb, tx)
		executionState = nativeGuard
		cfg.MaxMemoryBytes = tx.MemoryLimit()
		cfg.MaxReturnDataBytes = tx.OutputLimit()
	} else if config != nil && config.NativeParallelEnabled() {
		standardSnapshot = statedb.Snapshot()
		standardGas = gp.Gas()
		if recorder, ok := executionState.(*evmMVCCRecorder); ok {
			accessRecorder = recorder
		} else {
			accessRecorder = newEVMMVCCRecorder(executionState)
			executionState = accessRecorder
		}
		accessRecorder.setAccessLimit(config.NativeParallel.MaxAccessesPerTransaction)
		if config.NativeParallel.RequireNativeTransactions {
			protocolGuard = newProtocolNamespaceGuard(executionState)
			executionState = protocolGuard
		}
		evmGuard = newEVMResourceGuard(executionState, config.NativeParallel.MaxLogBytesPerTransaction)
		executionState = evmGuard
		cfg.MaxMemoryBytes = config.NativeParallel.MaxMemoryBytesPerTransaction
		cfg.MaxReturnDataBytes = config.NativeParallel.MaxOutputBytesPerTransaction
	}
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vmenv := vm.NewEVM(context, executionState, config, cfg)
	// Apply the transaction to the current state (included in the env)
	result, err := ApplyMessage(vmenv, msg, gp)
	if accessRecorder != nil && accessRecorder.Error() != nil {
		statedb.RevertToSnapshot(standardSnapshot)
		*gp = GasPool(standardGas)
		return nil, accessRecorder.Error()
	}
	if protocolGuard != nil && protocolGuard.Error() != nil {
		statedb.RevertToSnapshot(standardSnapshot)
		*gp = GasPool(standardGas)
		return nil, protocolGuard.Error()
	}
	if evmGuard != nil && evmGuard.Error() != nil {
		statedb.RevertToSnapshot(standardSnapshot)
		*gp = GasPool(standardGas)
		return nil, evmGuard.Error()
	}
	if err != nil {
		if standardSnapshot >= 0 {
			statedb.RevertToSnapshot(standardSnapshot)
			*gp = GasPool(standardGas)
		}
		return nil, err
	}
	if evmGuard != nil && (errors.Is(result.Err, vm.ErrMemoryLimitExceeded) || errors.Is(result.Err, vm.ErrReturnDataLimitExceeded)) {
		statedb.RevertToSnapshot(standardSnapshot)
		*gp = GasPool(standardGas)
		return nil, result.Err
	}
	if nativeGuard != nil {
		if err := nativeGuard.Error(); err != nil {
			return nil, err
		}
		if errors.Is(result.Err, vm.ErrMemoryLimitExceeded) {
			return nil, result.Err
		}
		if errors.Is(result.Err, vm.ErrReturnDataLimitExceeded) {
			return nil, result.Err
		}
		if uint64(len(result.ReturnData)) > tx.OutputLimit() {
			return nil, fmt.Errorf("native transaction output bytes %d exceed declared limit %d", len(result.ReturnData), tx.OutputLimit())
		}
		encodedLogs, err := consensusLogListRLPSize(statedb.GetLogs(tx.Hash()))
		if err != nil {
			return nil, fmt.Errorf("encode native transaction logs: %w", err)
		}
		if encodedLogs > tx.LogLimit() {
			return nil, fmt.Errorf("native transaction log bytes %d exceed declared limit %d", encodedLogs, tx.LogLimit())
		}
	}
	// Update the state with pending changes
	var root []byte
	if config.IsByzantium(header.Number) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(header.Number)).Bytes()
	}
	*usedGas += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used by the tx
	// based on the eip phase, we're passing whether the root touch-delete accounts.
	receipt := types.NewReceipt(root, result.Failed(), *usedGas)
	receipt.Type = tx.Type()
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas
	// if the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(vmenv.Context.Origin, tx.Nonce())
	}
	// Set the receipt logs and create a bloom for filtering
	receipt.Logs = statedb.GetLogs(tx.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = statedb.BlockHash()
	receipt.BlockNumber = header.Number
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt, err
}
