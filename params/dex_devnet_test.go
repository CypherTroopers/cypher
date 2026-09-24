package params

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto/bls"
)

func TestDEXDevnetConsensusConfigRoundTripAndBinding(t *testing.T) {
	cfg := *TestChainConfig
	cfg.FairHotstuff = true
	cfg.FixedCommittee = true
	cfg.GenCommittee = make(GenesisCommittee)
	cfg.FairHotstuffSeed = common.Hash{1}
	d := &DEXDevnetConfig{Version: 2, ActivationBlock: 3, DEXID: common.Hash{2}, GenesisSeed: common.Hash{3}, Custody: DEXSettlementAddress, MaxCheckpoints: 100}
	for i := 0; i < 7; i++ {
		var k bls.SecretKey
		if err := k.SetDecString(fmt.Sprint(910 + i)); err != nil {
			t.Fatal(err)
		}
		d.Committee = append(d.Committee, common.Cnode{Address: fmt.Sprintf("127.0.0.1:%d", 28000+i), Public: k.GetPublicKey().SerializeToHexStr()})
		cfg.GenCommittee[i] = d.Committee[i]
	}
	cfg.DEXDevnet = d
	if err := cfg.ValidateDEXDevnet(); err != nil {
		t.Fatal(err)
	}
	// Every supported version is explicit and genesis-committed. Version 5
	// selects ancestry finality without silently enabling unknown versions.
	seen := make(map[common.Hash]bool)
	for _, version := range []uint16{2, 3, 4, 5} {
		d.Version = version
		if err := cfg.ValidateDEXDevnet(); err != nil {
			t.Fatalf("version %d: %v", version, err)
		}
		commit, err := FairHotstuffGenesisCommitment(&cfg)
		if err != nil || seen[commit] || d.RollingAnchors() != (version >= 3) || d.ContinuousStorage() != (version >= 4) || d.AncestryProofs() != (version == 5) {
			t.Fatal("DEX version binding/predicates", version, err)
		}
		seen[commit] = true
	}
	for _, version := range []uint16{0, 1, 6, 65535} {
		d.Version = version
		if cfg.ValidateDEXDevnet() == nil || d.RollingAnchors() || d.ContinuousStorage() || d.AncestryProofs() {
			t.Fatal("unknown DEX version enabled", version)
		}
	}
	d.Version = 2
	raw, err := json.Marshal(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ChainConfig
	if err = json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	again, err := json.Marshal(&decoded)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("genesis config lost DEX fields", err)
	}
	h, err := FairHotstuffGenesisCommitment(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	other, err := FairHotstuffGenesisCommitment(&decoded)
	if err != nil || h != other {
		t.Fatal("roundtrip commitment", err)
	}
	decoded.DEXDevnet.ActivationBlock++
	other, err = FairHotstuffGenesisCommitment(&decoded)
	if err != nil || other == h {
		t.Fatal("activation not bound", err)
	}
	if cfg.DEXDevnetActive(big.NewInt(2)) || !cfg.DEXDevnetActive(big.NewInt(3)) {
		t.Fatal("activation boundary")
	}
	decoded.DEXDevnet.Committee[1].Public = decoded.DEXDevnet.Committee[0].Public
	if decoded.ValidateDEXDevnet() == nil {
		t.Fatal("duplicate voting key accepted")
	}
	cfg.DEXDevnet = nil
	raw, err = json.Marshal(&cfg)
	if err != nil || bytes.Contains(raw, []byte("dexDevnet")) {
		t.Fatal("nil config changed wire", err)
	}
}
