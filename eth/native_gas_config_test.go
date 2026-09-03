package eth

import (
	"testing"

	"github.com/cypherium/cypher/params"
)

func TestNativeMinerGasBoundsUseGenesisComputeCapacity(t *testing.T) {
	native := params.SolanaScaleNativeParallelConfig()
	config := &params.ChainConfig{NativeParallel: native}
	floor, ceil := nativeMinerGasBounds(config, params.MinGasLimit, params.GenesisGasLimit)
	if floor != native.MaxComputePerBlock || ceil != native.MaxComputePerBlock {
		t.Fatalf("native gas bounds = %d/%d, want %d", floor, ceil, native.MaxComputePerBlock)
	}
	legacyFloor, legacyCeil := nativeMinerGasBounds(new(params.ChainConfig), 1, 2)
	if legacyFloor != 1 || legacyCeil != 2 {
		t.Fatalf("legacy gas bounds changed to %d/%d", legacyFloor, legacyCeil)
	}
}
