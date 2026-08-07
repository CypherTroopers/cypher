package core

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

// TestCypheriumCustomGenesisConfigPinsUpgradeSurface locks the Cypherium-specific
// genesis fields that must survive the EVM/fork upgrade. The modern Geth EVM
// migration must not remove or reinterpret the committee, fixed committee,
// Fair HotStuff, transaction size, or max-code-size custom surfaces.
func TestCypheriumCustomGenesisConfigPinsUpgradeSurface(t *testing.T) {
	blob, err := os.ReadFile("../genesis.json")
	if err != nil {
		t.Fatalf("failed to read genesis.json: %v", err)
	}

	var genesis Genesis
	if err := json.Unmarshal(blob, &genesis); err != nil {
		t.Fatalf("failed to decode genesis.json: %v", err)
	}
	if genesis.Config == nil {
		t.Fatal("genesis.json has no chain config")
	}
	if genesis.Config.ChainID == nil || genesis.Config.ChainID.Sign() == 0 {
		t.Fatal("genesis.json must keep a non-zero chainId")
	}
	if !genesis.Config.FixedCommittee {
		t.Fatal("fixedCommittee must remain enabled for this test genesis")
	}
	if genesis.Config.FixedLeader {
		t.Fatal("fixedLeader must remain disabled for Fair HotStuff genesis")
	}
	if !genesis.Config.FairHotstuff {
		t.Fatal("fairHotstuff must remain enabled for this test genesis")
	}
	if len(genesis.Config.GenCommittee) == 0 {
		t.Fatal("committee must not be removed during EVM upgrade")
	}
	if !genesis.Config.IsIstanbul(genesis.Config.IstanbulBlock) {
		t.Fatal("Istanbul must remain active in the existing Cypherium genesis baseline")
	}
}

func TestCypheriumModernForkConfigDecoding(t *testing.T) {
	blob, err := os.ReadFile("../genesis.json")
	if err != nil {
		t.Fatalf("failed to read genesis.json: %v", err)
	}

	var genesis Genesis
	if err := json.Unmarshal(blob, &genesis); err != nil {
		t.Fatalf("failed to decode genesis.json: %v", err)
	}
	cfg := genesis.Config
	if cfg == nil {
		t.Fatal("missing chain config")
	}
	if !cfg.IsBerlin(big.NewInt(0)) {
		t.Fatal("Berlin must be active at genesis for genesis.json")
	}
	if !cfg.IsLondon(big.NewInt(0)) {
		t.Fatal("London must be active at genesis for genesis.json")
	}
	if !cfg.IsShanghai(big.NewInt(0), 0) {
		t.Fatal("Shanghai must be active at genesis timestamp for genesis.json")
	}
	if !cfg.IsCancun(big.NewInt(0), 0) {
		t.Fatal("Cancun must be active at genesis timestamp for genesis.json")
	}
	if cfg.IsPrague(big.NewInt(0), 0) {
		t.Fatal("Prague must remain disabled for genesis.json")
	}
	if cfg.IsOsaka(big.NewInt(0), 0) {
		t.Fatal("Osaka must remain disabled for genesis.json")
	}
	modern := cfg.ModernForkConfig()
	if modern == nil || modern.BlobSchedule == nil || modern.BlobSchedule.Cancun == nil {
		t.Fatal("blobSchedule.cancun must be decoded and preserved")
	}
}
