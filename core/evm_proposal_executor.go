package core

import (
	"errors"
	"fmt"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/params"
)

// ExecuteEVMProposalTransactions is the proposer-side entry point for the
// standard Ethereum envelope executor used by block import. It intentionally
// stops before Fair HotStuff admission rewards and consensus-engine rewards;
// proposal construction attaches and settles those only after the final body
// has been selected, exactly as it did on the historical serial path.
//
// The supplied StateDB is mutated. If an error is returned, callers must
// discard it because a valid canonical prefix may already have been merged.
func ExecuteEVMProposalTransactions(config *params.ChainConfig, bc *BlockChain, header *types.Header, txs types.Transactions, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, uint64, error) {
	block, err := prepareEVMProposalExecution(config, bc, header, txs, statedb)
	if err != nil {
		return nil, nil, 0, err
	}
	executionHeader := block.Header()

	processor := &StateProcessor{config: config, bc: bc}
	gp := new(GasPool).AddGas(executionHeader.GasLimit)
	usedGas := new(uint64)
	receipts := make(types.Receipts, 0, len(txs))
	logs := make([]*types.Log, 0)
	outputMeter := newBlockExecutionOutputMeter(config)
	record := func(index int, tx *types.Transaction, receipt *types.Receipt) error {
		if index != len(receipts) || tx == nil || receipt == nil {
			return markEVMExecutionInfrastructure(fmt.Errorf("standard EVM proposal receipt order mismatch at transaction %d", index))
		}
		if err := outputMeter.Add(index, receipt); err != nil {
			return err
		}
		receipts = append(receipts, receipt)
		logs = append(logs, receipt.Logs...)
		return nil
	}

	if len(txs) > 1 && evmOptimisticParallelEnabled(config, cfg) {
		if err := processor.processEVMOptimistic(block, statedb, gp, usedGas, cfg, record); err != nil {
			return nil, nil, 0, err
		}
	} else {
		limiter, memoryLease := acquireEVMSerialMemoryLease(config, executionHeader, txs)
		defer limiter.release(memoryLease)
		workMeter := newEVMRuntimeWorkMeter(config)
		for index, tx := range block.Transactions() {
			receipt, access, err := executeRecordedEVMSerial(config, bc, block, statedb, gp, usedGas, tx, index, cfg)
			if err != nil {
				return nil, nil, 0, evmTransactionExecutionError(index, err)
			}
			if err := workMeter.Add(config, block.Header(), index, tx, receipt, access); err != nil {
				return nil, nil, 0, evmTransactionExecutionError(index, err)
			}
			if err := record(index, tx, receipt); err != nil {
				return nil, nil, 0, evmTransactionExecutionError(index, err)
			}
		}
	}
	return receipts, logs, *usedGas, nil
}

func prepareEVMProposalExecution(config *params.ChainConfig, bc *BlockChain, header *types.Header, txs types.Transactions, statedb *state.StateDB) (*types.Block, error) {
	if config == nil || !config.NativeParallelEnabled() || config.NativeParallel.RequireNativeTransactions || bc == nil || header == nil || header.Number == nil || statedb == nil {
		return nil, fmt.Errorf("standard EVM proposal executor has incomplete or incompatible context")
	}
	executionHeader := types.CopyHeader(header)
	executionHeader.BlobGasUsed = CalcBlobGasUsed(txs)
	block := types.NewBlockWithHeader(executionHeader).WithBody(txs, nil)
	if _, err := ValidateNativeParallelBlockMode(config, executionHeader.BlockType, block.Transactions()); err != nil {
		return nil, err
	}
	if err := ValidateBlockBlobExecution(config, executionHeader, block.Transactions(), types.KZGBlobVerifier{}); err != nil {
		return nil, err
	}
	if err := PrepareNativeBlockHashes(config, executionHeader, statedb); err != nil {
		return nil, err
	}
	return block, nil
}

// FilterEVMProposalTransactions visits each candidate at most once in canonical
// order, retaining independent work after transaction or resource failures. Each
// candidate executes on an isolated branch; only results passing the validator's
// runtime and output meters are merged. A rejected sender's remaining nonce
// suffix is omitted from this proposal, without deciding pool deletion policy.
//
// The returned errors index the original candidates. Infrastructure failures
// abort the pass. Callers must execute the selected body through
// ExecuteEVMProposalTransactions from the original parent state before publishing
// it, because selection can change block metadata such as BlobGasUsed.
func FilterEVMProposalTransactions(config *params.ChainConfig, bc *BlockChain, header *types.Header, txs types.Transactions, statedb *state.StateDB, cfg vm.Config) (types.Transactions, []*EVMTransactionExecutionError, error) {
	block, err := prepareEVMProposalExecution(config, bc, header, txs, statedb)
	if err != nil {
		return nil, nil, err
	}
	retainedWeight := evmRuntimeRetainedMemoryWeight(config, len(txs))
	var branchWeight uint64
	for _, tx := range txs {
		if weight := evmRuntimeTransactionMemoryWeight(config, block.Header(), tx); weight > branchWeight {
			branchWeight = weight
		}
	}
	if retainedWeight >= nativeExecutionMemoryBudget || branchWeight > nativeExecutionMemoryBudget-retainedWeight {
		return nil, nil, markEVMExecutionInfrastructure(fmt.Errorf("standard EVM proposal filtering exceeds executor memory budget %d", nativeExecutionMemoryBudget))
	}
	memoryLease := nativeDAGMemoryLimiter.acquire(retainedWeight + branchWeight)
	defer nativeDAGMemoryLimiter.release(memoryLease)

	selected := make(types.Transactions, 0, len(txs))
	var rejected []*EVMTransactionExecutionError
	blocked := make(map[common.Address]bool)
	gp := new(GasPool).AddGas(block.GasLimit())
	var usedGas uint64
	workMeter := newEVMRuntimeWorkMeter(config)
	outputMeter := newBlockExecutionOutputMeter(config)
	var snapshot *state.RuntimeMVCCSnapshot
	for originalIndex, tx := range txs {
		sender, err := types.Sender(types.MakeSignerAutoJudgement(config, header.Number, tx.V()), tx)
		if err != nil {
			rejected = append(rejected, &EVMTransactionExecutionError{TransactionIndex: originalIndex, Err: err})
			continue
		}
		if blocked[sender] {
			continue
		}
		reject := func(err error) {
			blocked[sender] = true
			rejected = append(rejected, &EVMTransactionExecutionError{TransactionIndex: originalIndex, Err: err})
		}
		if tx.Gas() > gp.Gas() {
			reject(ErrGasLimitReached)
			continue
		}
		// Rejections leave canonical state unchanged, so their isolated branches
		// can reuse one trie publication without copying or replaying the prefix.
		if snapshot == nil {
			snapshot, err = statedb.PrepareRuntimeMVCCSnapshot(true)
			if err != nil {
				return nil, rejected, markEVMExecutionInfrastructure(fmt.Errorf("prepare standard EVM filtering snapshot: %w", err))
			}
		}
		branch, err := snapshot.Branch()
		if err != nil {
			return nil, rejected, markEVMExecutionInfrastructure(fmt.Errorf("create standard EVM filtering branch: %w", err))
		}
		index := len(selected)
		var result evmMVCCResult
		runBoundedParallelValidationWithLimit(1, 1, func(int) {
			result = executeEVMMVCCTransaction(config, bc, block, branch, tx, index, cfg)
		})
		if result.err != nil {
			var infrastructure *EVMExecutionInfrastructureError
			if errors.As(result.err, &infrastructure) {
				return nil, rejected, result.err
			}
			reject(result.err)
			continue
		}
		result.receipt.CumulativeGasUsed = usedGas + result.receipt.GasUsed
		// Delta capture detaches logs from the worker receipt. Meter the full
		// prospective receipt before merge restores its canonical log metadata.
		result.receipt.Logs = result.delta.logs
		nextOutput := *outputMeter
		if err := nextOutput.Add(index, result.receipt); err != nil {
			reject(err)
			continue
		}
		// Dependency rejection leaves its frontiers unchanged, while access
		// accounting runs first. Restore that scalar before trying the suffix.
		previousAccesses := workMeter.access.total
		if err := workMeter.Add(config, block.Header(), index, tx, result.receipt, result.access); err != nil {
			workMeter.access.total = previousAccesses
			var infrastructure *EVMExecutionInfrastructureError
			if errors.As(err, &infrastructure) {
				return nil, rejected, err
			}
			reject(err)
			continue
		}
		if _, err := mergeEVMMVCCResult(statedb, gp, &usedGas, block, index, tx, result); err != nil {
			return nil, rejected, markEVMExecutionInfrastructure(fmt.Errorf("merge standard EVM filtering result: %w", err))
		}
		// The snapshot borrows canonical account objects. After an accepted
		// merge, the next executable candidate needs a fresh canonical version.
		snapshot = nil
		addresses := make([]common.Address, 0, len(result.delta.accounts)+len(result.delta.storage))
		for _, account := range result.delta.accounts {
			addresses = append(addresses, account.address)
		}
		for _, storage := range result.delta.storage {
			addresses = append(addresses, storage.address)
		}
		if err := statedb.RuntimeMVCCError(addresses...); err != nil {
			return nil, rejected, markEVMExecutionInfrastructure(fmt.Errorf("publish standard EVM filtering state: %w", err))
		}
		*outputMeter = nextOutput
		selected = append(selected, tx)
	}
	return selected, rejected, nil
}
