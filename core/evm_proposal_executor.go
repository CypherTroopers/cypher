package core

import (
	"fmt"

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
	if config == nil || !config.NativeParallelEnabled() || config.NativeParallel.RequireNativeTransactions || bc == nil || header == nil || header.Number == nil || statedb == nil {
		return nil, nil, 0, fmt.Errorf("standard EVM proposal executor has incomplete or incompatible context")
	}
	executionHeader := types.CopyHeader(header)
	executionHeader.BlobGasUsed = CalcBlobGasUsed(txs)
	block := types.NewBlockWithHeader(executionHeader).WithBody(txs, nil)
	if _, err := ValidateNativeParallelBlockMode(config, executionHeader.BlockType, block.Transactions()); err != nil {
		return nil, nil, 0, err
	}
	if err := ValidateBlockBlobExecution(config, executionHeader, block.Transactions(), types.KZGBlobVerifier{}); err != nil {
		return nil, nil, 0, err
	}
	if err := PrepareNativeBlockHashes(config, executionHeader, statedb); err != nil {
		return nil, nil, 0, err
	}

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
