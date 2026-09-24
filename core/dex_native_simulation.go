package core

import (
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/params"
)

// NewEVMForNativeSimulation keeps call/estimate/legacy trace resource admission
// equal to canonical native transaction execution. It changes no other target's
// historical RPC semantics. The caller owns a temporary/replay StateDB; overrides
// and synthetic senders are simulation inputs, never canonical mutations.
// Call check after ApplyMessage, before consuming the result or finalising state.
func NewEVMForNativeSimulation(ctx vm.Context, st *state.StateDB, config *params.ChainConfig, cfg vm.Config, to *common.Address) (*vm.EVM, func() error) {
	if config == nil || config.DEXDevnet == nil || to == nil || *to != params.DEXSettlementAddress || !config.NativeParallelEnabled() {
		return vm.NewEVM(ctx, st, config, cfg), func() error { return nil }
	}
	snapshot := st.Snapshot()
	recorder := newEVMMVCCRecorder(st)
	recorder.setAccessLimit(config.NativeParallel.MaxAccessesPerTransaction)
	guard := newEVMResourceGuard(recorder, config.NativeParallel.MaxLogBytesPerTransaction)
	cfg.MaxMemoryBytes = config.NativeParallel.MaxMemoryBytesPerTransaction
	cfg.MaxReturnDataBytes = config.NativeParallel.MaxOutputBytesPerTransaction
	evm := vm.NewEVM(ctx, guard, config, cfg)
	var checked bool
	var result error
	check := func() error {
		if checked {
			return result
		}
		checked = true
		result = recorder.Error()
		if result == nil {
			result = guard.Error()
		}
		if result == nil {
			result = st.Error()
		}
		if result != nil {
			st.RevertToSnapshot(snapshot)
		}
		return result
	}
	return evm, check
}
