package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	miner "colossusx"
	cx "colossusx/colossusx"
	"colossusx/pkg/consensus"
	"colossusx/pkg/types"
)

func TestParseDaemonFlagsAutoBackendUsesAutoResolution(t *testing.T) {
	cfg, err := parseDaemonFlags([]string{"-miner-backend=auto"})
	if err != nil {
		t.Fatalf("expected auto backend to parse, got err=%v", err)
	}
	want, err := miner.ParseBackendMode("auto")
	if err != nil {
		t.Fatalf("ParseBackendMode(auto): %v", err)
	}
	if cfg.MinerBackend != want {
		t.Fatalf("expected auto backend to resolve to %q, got %q", want, cfg.MinerBackend)
	}
	if !cfg.AutoBackend {
		t.Fatal("expected AutoBackend=true when -miner-backend=auto")
	}
}

func TestParseDaemonFlagsAllowsCPUBackendInColossusXProduction(t *testing.T) {
	cfg, err := parseDaemonFlags([]string{"-miner-backend=cpu", "-miner-dag-alloc=go-heap"})
	if err != nil {
		t.Fatalf("expected colossusx production config validation to allow cpu backend, got err=%v", err)
	}
	if cfg.MinerBackend != "cpu" {
		t.Fatalf("expected cpu miner backend, got %q", cfg.MinerBackend)
	}
}

func TestInitializeMiningUnifiedGoHeap(t *testing.T) {
	cfg := daemonConfig{MinerBackend: "unified", MinerDAGAlloc: "go-heap"}
	cfg.Chain.Spec.Mode = "colossusx"
	backend, strategy, status, err := initializeMining(cfg)
	if err != nil {
		t.Fatalf("initializeMining: %v", err)
	}
	if backend.Mode() != "unified" {
		t.Fatalf("expected unified backend, got %q", backend.Mode())
	}
	if strategy.Name() != "go-heap" {
		t.Fatalf("expected go-heap strategy, got %q", strategy.Name())
	}
	if status != "probed-no-accel" {
		t.Fatalf("expected probed-no-accel runtime status, got %q", status)
	}
}

type fakeRuntimeCapabilities struct {
	cuda   bool
	opencl bool
	metal  bool
}

func (f fakeRuntimeCapabilities) CUDADeviceOrdinal() (int, bool) {
	return 0, f.cuda
}
func (f fakeRuntimeCapabilities) OpenCLContext() (miner.OpenCLContext, bool) {
	if !f.opencl {
		return miner.OpenCLContext{}, false
	}
	return miner.OpenCLContext{Context: struct{}{}, Device: struct{}{}}, true
}
func (f fakeRuntimeCapabilities) MetalContext() (miner.MetalContext, bool) {
	if !f.metal {
		return miner.MetalContext{}, false
	}
	return miner.MetalContext{Device: struct{}{}}, true
}

func TestRuntimeInitStatus(t *testing.T) {
	if got := runtimeInitStatus(nil); got != "not-required" {
		t.Fatalf("expected not-required, got %q", got)
	}
	if got := runtimeInitStatus(fakeRuntimeCapabilities{}); got != "probed-no-accel" {
		t.Fatalf("expected probed-no-accel, got %q", got)
	}
	if got := runtimeInitStatus(fakeRuntimeCapabilities{cuda: true}); got != "ok" {
		t.Fatalf("expected ok with CUDA capability, got %q", got)
	}
	if got := runtimeInitStatus(fakeRuntimeCapabilities{opencl: true}); got != "ok" {
		t.Fatalf("expected ok with OpenCL capability, got %q", got)
	}
	if got := runtimeInitStatus(fakeRuntimeCapabilities{metal: true}); got != "ok" {
		t.Fatalf("expected ok with Metal capability, got %q", got)
	}
}

func TestInitializeMiningExplicitGPUAllocatorRequest(t *testing.T) {
	cfg := daemonConfig{MinerBackend: "gpu", MinerDAGAlloc: "opencl-svm"}
	cfg.Chain.Spec.Mode = "colossusx"
	_, _, _, err := initializeMining(cfg)
	if err == nil {
		t.Fatal("expected explicit gpu/opencl-svm request to fail gracefully in test environment")
	}
}

func TestResolveCommand(t *testing.T) {
	cases := []struct {
		args []string
		cmd  string
	}{
		{args: nil, cmd: "mine"},
		{args: []string{"--help"}, cmd: "help"},
		{args: []string{"-bench"}, cmd: "mine"},
		{args: []string{"mine", "-bench"}, cmd: "mine"},
		{args: []string{"daemon"}, cmd: "daemon"},
		{args: []string{"node"}, cmd: "daemon"},
		{args: []string{"verify"}, cmd: "verify"},
		{args: []string{"unknown"}, cmd: "unknown"},
	}
	for _, tc := range cases {
		cmd, _ := resolveCommand(tc.args)
		if cmd != tc.cmd {
			t.Fatalf("resolveCommand(%v) = %q want %q", tc.args, cmd, tc.cmd)
		}
	}
}

func TestRunVerifyColossusXBlockUsesMerkleRootWithoutLocalDAG(t *testing.T) {
	spec := cx.ColossusXSpec()
	spec.InitialDAGSizeBytes = 1 * 1024 * 1024
	spec.DAGSizeBytes = spec.InitialDAGSizeBytes
	spec.DAGGrowthBytesPerEpoch = 1 * 1024 * 1024
	target, err := cx.ParseTargetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if err != nil {
		t.Fatal(err)
	}
	chainCfg := types.ChainConfig{NetworkID: "verify-test", Spec: spec}
	genesisCfg := types.GenesisConfig{ChainID: "verify-test", Message: "verify", Timestamp: time.Now().Unix() - 1, Bits: target, Spec: spec}
	v, err := consensus.NewValidator(chainCfg, consensus.CPUBackend{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	genesis, _, err := v.SealBlock(types.NewGenesisBlock(genesisCfg), 32)
	if err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()
	blockPath := filepath.Join(tmp, "block.json")
	raw, err := json.Marshal(genesis)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blockPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runVerify([]string{
		"-block", blockPath,
		"-initial-dag-mib", "1",
		"-dag-growth-mib-per-epoch", "1",
	}); err != nil {
		t.Fatalf("runVerify should validate colossusx block with solution+merkle root: %v", err)
	}
}

func TestRunVerifyColossusXHeaderModeRequiresBlockSolution(t *testing.T) {
	spec := cx.ColossusXSpec()
	spec.InitialDAGSizeBytes = 1 * 1024 * 1024
	spec.DAGSizeBytes = spec.InitialDAGSizeBytes
	spec.DAGGrowthBytesPerEpoch = 1 * 1024 * 1024
	target, err := cx.ParseTargetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if err != nil {
		t.Fatal(err)
	}
	header := types.BlockHeader{
		Version:          1,
		AlgorithmVersion: spec.AlgorithmVersion,
		Height:           0,
		Timestamp:        time.Now().Unix() - 1,
		Target:           target,
		Nonce:            0,
		EpochSeed:        types.EpochSeedForHeight(spec, 0),
		DAGSizeBytes:     spec.DAGSizeForHeight(0),
		DAGMerkleRoot:    types.Hash{},
	}
	tmp := t.TempDir()
	headerPath := filepath.Join(tmp, "header.json")
	raw, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(headerPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runVerify([]string{
		"-header", headerPath,
		"-initial-dag-mib", "1",
		"-dag-growth-mib-per-epoch", "1",
	}); err == nil {
		t.Fatal("expected colossusx verify header mode to require block solution")
	}
}
