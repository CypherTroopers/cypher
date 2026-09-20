package eth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/misc"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/eth/tracers"
	"github.com/cypherium/cypher/internal/ethapi"
	"github.com/cypherium/cypher/params"
)

// blockscoutObserver captures top-level output and cooperatively stops EVM
// execution at opcode boundaries on request cancellation or timeout.
type blockscoutObserver struct {
	vm.Tracer
	ctx          context.Context
	output       []byte
	executionErr error
}

func (t *blockscoutObserver) CaptureState(env *vm.EVM, pc uint64, op vm.OpCode, gas, cost uint64, memory *vm.Memory, stack *vm.Stack, rs *vm.ReturnStack, rd []byte, contract *vm.Contract, depth int, err error) error {
	if t.ctx.Err() != nil {
		env.Cancel()
		return nil
	}
	return t.Tracer.CaptureState(env, pc, op, gas, cost, memory, stack, rs, rd, contract, depth, err)
}

func (t *blockscoutObserver) CaptureEnd(output []byte, gasUsed uint64, elapsed time.Duration, err error) error {
	t.output = common.CopyBytes(output)
	t.executionErr = err
	return t.Tracer.CaptureEnd(output, gasUsed, elapsed, err)
}

// blockscoutApplyTrace uses the SAME transaction execution function as block
// import. In particular, signer selection, effective fees, access-list setup,
// typed transactions, native execution guards and receipt finalisation are not
// reimplemented in this RPC adapter.
func blockscoutApplyTrace(ctx context.Context, chainConfig *params.ChainConfig, chain core.ChainContext, block *types.Block, st *state.StateDB, gp *core.GasPool, usedGas *uint64, index int, config *TraceConfig) (interface{}, *types.Receipt, error) {
	timeout := defaultTraceTimeout
	if config != nil && config.Timeout != nil {
		var err error
		timeout, err = time.ParseDuration(*config.Timeout)
		if err != nil {
			return nil, nil, err
		}
		if timeout <= 0 {
			return nil, nil, errors.New("trace timeout must be positive")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	txs := block.Transactions()
	if index < 0 || index >= len(txs) {
		return nil, nil, errors.New("transaction index out of range")
	}
	tx := txs[index]
	var logger *vm.StructLogger
	var js *tracers.Tracer
	var tracer vm.Tracer
	if config != nil && config.Tracer != nil {
		var err error
		js, err = tracers.New(*config.Tracer)
		if err != nil {
			return nil, nil, err
		}
		defer js.Close()
		js.SetBlockscoutContext(st, block.NumberU64(), tx.Gas(), 0)
		tracer = js
	} else {
		var logConfig *vm.LogConfig
		if config != nil {
			logConfig = config.LogConfig
		}
		logger = vm.NewStructLogger(logConfig)
		tracer = logger
	}
	observer := &blockscoutObserver{Tracer: tracer, ctx: ctx}
	st.Prepare(tx.Hash(), block.Hash(), index)
	receipt, err := core.ApplyTransaction(chainConfig, chain, nil, gp, st, block.Header(), tx, usedGas, vm.Config{Debug: true, Tracer: observer})
	if err != nil {
		return nil, nil, fmt.Errorf("tracing %s: %w", tx.Hash(), err)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := st.Error(); err != nil {
		return nil, nil, err
	}
	if js != nil {
		js.SetBlockscoutContext(st, block.NumberU64(), tx.Gas(), receipt.GasUsed)
		result, err := js.GetResult()
		if err != nil {
			return nil, nil, err
		}
		// Blockscout's first-trace path requests onlyTopCall for callTracer.
		// The old embedded JS callTracer has no tracerConfig handler.
		if config != nil && config.Tracer != nil && *config.Tracer == "callTracer" && len(config.TracerConfig) != 0 {
			var options struct {
				OnlyTopCall bool `json:"onlyTopCall"`
			}
			if err := json.Unmarshal(config.TracerConfig, &options); err != nil {
				return nil, nil, err
			}
			if options.OnlyTopCall {
				var call map[string]interface{}
				if err := json.Unmarshal(result, &call); err != nil {
					return nil, nil, err
				}
				delete(call, "calls")
				result, err = json.Marshal(call)
				if err != nil {
					return nil, nil, err
				}
			}
		}
		return result, receipt, nil
	}
	return &ethapi.ExecutionResult{
		Gas:         receipt.GasUsed,
		Failed:      receipt.Status == types.ReceiptStatusFailed,
		ReturnValue: fmt.Sprintf("%x", observer.output),
		StructLogs:  ethapi.FormatLogs(logger.StructLogs()),
	}, receipt, nil
}

// Replay starts from the parent's state and applies the same block-start hooks
// as StateProcessor.Process. Common RPC rewards are credited AFTER all TXs by
// Process, so they must not be credited between transactions during tracing.
func (api *PrivateDebugAPI) blockscoutParentState(ctx context.Context, block *types.Block, config *TraceConfig) (*state.StateDB, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if block.NumberU64() == 0 {
		return nil, errors.New("genesis has no parent transaction state")
	}
	parent := api.eth.blockchain.GetBlock(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		return nil, fmt.Errorf("parent %s not found", block.ParentHash())
	}
	reexec := defaultTraceReexec
	if config != nil && config.Reexec != nil {
		reexec = *config.Reexec
	}
	st, err := api.computeStateDB(parent, reexec)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cfg := api.eth.blockchain.Config()
	if cfg.DAOForkSupport && cfg.DAOForkBlock != nil && cfg.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(st)
	}
	if err := core.ProcessParentBlockHash(cfg, block.Header(), st); err != nil {
		return nil, err
	}
	if err := core.PrepareNativeBlockHashes(cfg, block.Header(), st); err != nil {
		return nil, err
	}
	return st, nil
}

func (api *PrivateDebugAPI) blockscoutTraceBlock(ctx context.Context, block *types.Block, config *TraceConfig) ([]*txTraceResult, error) {
	if block == nil {
		return nil, errors.New("block not found")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	txs := block.Transactions()
	result := make([]*txTraceResult, len(txs))
	if len(txs) == 0 {
		return result, nil
	}
	st, err := api.blockscoutParentState(ctx, block, config)
	if err != nil {
		return nil, err
	}
	gp := new(core.GasPool).AddGas(block.GasLimit())
	usedGas := uint64(0)
	for i, tx := range txs {
		trace, _, err := blockscoutApplyTrace(ctx, api.eth.blockchain.Config(), api.eth.blockchain, block, st, gp, &usedGas, i, config)
		if err != nil {
			return nil, fmt.Errorf("block %s transaction %d: %w", block.Hash(), i, err)
		}
		result[i] = &txTraceResult{TxHash: tx.Hash(), Result: trace}
	}
	if usedGas != block.GasUsed() {
		return nil, fmt.Errorf("trace gas mismatch: replay=%d header=%d", usedGas, block.GasUsed())
	}
	return result, nil
}

func (api *PrivateDebugAPI) blockscoutTraceTransaction(ctx context.Context, hash common.Hash, config *TraceConfig) (interface{}, error) {
	tx, blockHash, _, index, err := api.eth.APIBackend.GetTransaction(ctx, hash)
	if err != nil {
		return nil, err
	}
	if tx == nil {
		return nil, fmt.Errorf("transaction %s not found", hash)
	}
	block := api.eth.blockchain.GetBlockByHash(blockHash)
	if block == nil {
		return nil, fmt.Errorf("block %s not found", blockHash)
	}
	txs := block.Transactions()
	if index >= uint64(len(txs)) || txs[index].Hash() != hash {
		return nil, errors.New("transaction lookup does not match block body")
	}
	st, err := api.blockscoutParentState(ctx, block, config)
	if err != nil {
		return nil, err
	}
	gp := new(core.GasPool).AddGas(block.GasLimit())
	usedGas := uint64(0)
	for i, previous := range txs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if uint64(i) == index {
			result, _, err := blockscoutApplyTrace(ctx, api.eth.blockchain.Config(), api.eth.blockchain, block, st, gp, &usedGas, i, config)
			return result, err
		}
		st.Prepare(previous.Hash(), block.Hash(), i)
		if _, err := core.ApplyTransaction(api.eth.blockchain.Config(), api.eth.blockchain, nil, gp, st, block.Header(), previous, &usedGas, vm.Config{}); err != nil {
			return nil, fmt.Errorf("replaying preceding transaction %s: %w", previous.Hash(), err)
		}
		if err := st.Error(); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("transaction index out of range")
}
