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
	"fmt"
	"math"
	"math/big"
	"runtime"
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
	if count <= 0 || validate == nil {
		return
	}
	maxWorkers := cap(parallelValidationSlots)
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
	selectedItems := make(map[uint32]struct{}, len(refs))
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
		selectedKey := uint32(ref.Batch)<<16 | uint32(ref.Item)
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
				return nil, validationErrors[index]
			}
		}
	}
	return miners, nil
}

func buildCommonRewardIndex(rewards []*types.CommonTxReward, includedTransactions types.Transactions) (map[common.Hash]*types.CommonTxReward, error) {
	var included map[common.Hash]struct{}
	if includedTransactions != nil {
		included = make(map[common.Hash]struct{}, len(includedTransactions))
		for _, tx := range includedTransactions {
			if tx != nil {
				included[tx.Hash()] = struct{}{}
			}
		}
	}
	indexed := make(map[common.Hash]*types.CommonTxReward, len(rewards))
	for _, reward := range rewards {
		if reward == nil {
			continue
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
		indexed[reward.TxHash] = reward
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
	for _, reward := range rewards {
		if reward == nil || reward.Approver == (common.Address{}) || reward.ApproverReward == nil || reward.ApproverReward.Sign() <= 0 {
			continue
		}
		statedb.AddBalance(reward.Approver, reward.ApproverReward)
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
	if err := validateFHSCommonRPCSidecarCoverage(p.config, block); err != nil {
		return nil, nil, 0, err
	}
	if err := ValidateBlockBlobGas(p.config, header, block.Transactions()); err != nil {
		return nil, nil, 0, err
	}
	if root := types.DeriveCommonTxAdmissionRoot(block.CommonTxAdmissionBatches(), block.CommonTxAdmissionRefs()); root != header.CommonTxAdmissionRoot {
		return nil, nil, 0, fmt.Errorf("common tx admission root mismatch: have %s want %s", root, header.CommonTxAdmissionRoot)
	}
	if root := types.DeriveCommonTxRewardRoot(block.CommonTxRewards()); root != header.CommonTxRewardRoot {
		return nil, nil, 0, fmt.Errorf("common tx reward root mismatch: have %s want %s", root, header.CommonTxRewardRoot)
	}
	commonTxAdmissionBatches := block.CommonTxAdmissionBatches()
	commonTxAdmissionRefs := block.CommonTxAdmissionRefs()
	var admissionApprovers []common.Address
	if len(commonTxAdmissionBatches) != 0 || len(commonTxAdmissionRefs) != 0 {
		genesisHash, err := commonRPCAdmissionGenesisHash(p.bc)
		if err != nil {
			return nil, nil, 0, err
		}
		keyBlockNumber, err := commonRPCAdmissionKeyBlockNumberForHeader(p.bc, header)
		if err != nil {
			return nil, nil, 0, err
		}
		admissionApprovers, err = buildCommonAdmissionApprovers(p.config, commonTxAdmissionBatches, commonTxAdmissionRefs, block.Transactions(), genesisHash, keyBlockNumber, header.Time)
		if err != nil {
			return nil, nil, 0, err
		}
	}
	rewardByTx, err := buildCommonRewardIndex(block.CommonTxRewards(), block.Transactions())
	if err != nil {
		return nil, nil, 0, err
	}
	// Mutate the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	if err := ProcessParentBlockHash(p.config, header, statedb); err != nil {
		return nil, nil, 0, err
	}
	var totalGas uint64

	recordReceipt := func(index int, tx *types.Transaction, receipt *types.Receipt) error {
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
		totalGas += receipt.GasUsed

		txHash := tx.Hash()
		var admissionMiner common.Address
		hasAdmission := index >= 0 && index < len(admissionApprovers)
		if hasAdmission {
			admissionMiner = admissionApprovers[index]
		}
		reward, hasReward := rewardByTx[txHash]
		switch {
		case hasAdmission:
			if !hasReward {
				return fmt.Errorf("common tx admission without reward for included tx: %s", txHash)
			}
			if err := validateCommonRPCReward(reward, admissionMiner, tx, receipt.GasUsed, header.BaseFee); err != nil {
				return err
			}
			delete(rewardByTx, txHash)
		case hasReward:
			return fmt.Errorf("common tx reward without admission for included tx: %s", txHash)
		default:
			if p.config != nil && p.config.FairHotstuff {
				return fmt.Errorf("Fair HotStuff transaction has no common RPC admission or reward: %s", txHash)
			}
		}
		return nil
	}

	// The first parallel lane is deliberately narrow: pairwise-disjoint,
	// existing EOA-to-EOA transfers with exact intrinsic gas. Every other
	// transaction remains on the long-standing serial path.
	txs := block.Transactions()
	rules := p.config.CypheriumRules(header.Number, header.Time)
	var nativeExecutor *nativeTransferExecutor
	defer func() {
		nativeExecutor.close()
	}()
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
		statedb.Prepare(tx.Hash(), block.Hash(), i)
		receipt, err := ApplyTransaction(p.config, p.bc, nil, gp, statedb, header, tx, usedGas, cfg)
		if err != nil {
			return nil, nil, 0, err
		}
		if err := recordReceipt(i, tx, receipt); err != nil {
			return nil, nil, 0, err
		}
		i++
	}
	if len(rewardByTx) > 0 {
		return nil, nil, 0, fmt.Errorf("%d common tx rewards were not consumed by block transactions", len(rewardByTx))
	}
	// The proposer derives and applies Common RPC rewards only after executing
	// every transaction. Apply them at the same boundary during import so a
	// later transaction cannot observe rewards from an earlier transaction and
	// produce a different state root.
	applyCommonRPCRewards(statedb, block.CommonTxRewards())
	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles(), totalGas)

	return receipts, allLogs, *usedGas, nil
}

func (p *StateProcessor) collectParallelNativeJobs(txs types.Transactions, start int, block *types.Block, statedb *state.StateDB, gp *GasPool, cfg vm.Config, rules params.Rules) []nativeTransferJob {
	if p == nil || p.config == nil || block == nil || statedb == nil || gp == nil || !rules.IsByzantium ||
		cfg.Debug || cfg.Tracer != nil || cfg.EnablePreimageRecording || cfg.EVMInterpreter != "" || cfg.EWASMInterpreter != "" || len(cfg.ExtraEips) != 0 {
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
	to, ok := parallelNativeTransferStateCandidate(tx, from, statedb, rules, precompiles)
	return from, to, ok
}

func parallelNativeTransferStateCandidate(tx *types.Transaction, from common.Address, statedb *state.StateDB, rules params.Rules, precompiles map[common.Address]struct{}) (common.Address, bool) {
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
	if nativeTransferReservedAddress(from, rules, precompiles) {
		return zero, false
	}
	if nativeTransferReservedAddress(to, rules, precompiles) {
		return zero, false
	}
	return to, true
}

func nativeTransferReservedAddress(address common.Address, rules params.Rules, precompiles map[common.Address]struct{}) bool {
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
	to, ok := parallelNativeTransferStateCandidate(tx, msg.From(), statedb, rules, nil)
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

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, error) {
	msg, err := tx.AsMessage(types.MakeSignerAutoJudgement(config, header.Number, tx.V()))
	if err != nil {
		return nil, err
	}
	if receipt, handled, err := tryApplyNativeTransfer(config, gp, statedb, header, tx, msg, usedGas, cfg); handled {
		return receipt, err
	}
	log.Trace("ApplyTransaction", "msg.from", msg.From(), "msg.To()", msg.To())
	// Create a new context to be used in the EVM environment
	context := NewEVMContextWithConfig(config, msg, header, bc, author)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vmenv := vm.NewEVM(context, statedb, config, cfg)
	// Apply the transaction to the current state (included in the env)
	result, err := ApplyMessage(vmenv, msg, gp)
	if err != nil {
		return nil, err
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
