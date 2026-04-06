package node

import (
	"strings"
	"testing"
	"time"

	cx "colossusx/colossusx"
	"colossusx/pkg/chain"
	"colossusx/pkg/consensus"
	"colossusx/pkg/types"
)

func TestNodeUsesSelectedMiningConfiguration(t *testing.T) {
	spec := cx.ColossusXSpecWithGrowth(1024*1024, cx.DefaultDAGGrowthBytesPerEpoch)
	target, err := cx.ParseTargetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if err != nil {
		t.Fatal(err)
	}
	chainCfg := types.ChainConfig{NetworkID: "test", Spec: spec}
	genesis := types.GenesisConfig{ChainID: "test", Message: "test", Timestamp: time.Now().Unix() - 1, Bits: target, Spec: spec}
	validator, err := consensus.NewValidator(chainCfg, consensus.CPUBackend{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer validator.Close()
	var logs []string
	_, err = New(Config{
		Chain:              chainCfg,
		Genesis:            genesis,
		Mine:               false,
		MaxNonces:          16,
		MinerBackend:       "unified",
		MinerDAGAlloc:      "go-heap",
		ResolvedDAGAlloc:   "go-heap",
		RuntimeInitStatus:  "not-required",
		MinerExecutionPath: "unified-memory-compatible backend (dag-allocation=go-heap)",
		Logf: func(format string, args ...any) {
			logs = append(logs, format)
		},
	}, validator, chain.NewMemoryStore())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(logs) == 0 || !strings.Contains(logs[0], "node mining configured backend=%s") {
		t.Fatalf("expected mining configuration log, got %#v", logs)
	}
}
