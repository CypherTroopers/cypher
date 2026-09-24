package clxevidence_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/devnet"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
)

// This is signed unit CLX evidence/MPT followed by actual execution/replay. It
// does not start CLI processes or establish a LIVE financial-network result.
func TestContinuousFinancialV6AuthenticatedInboxAnd320Actions(t *testing.T) {
	chain := clxevidence.ContinuousFinancialFixtureForTest(t, 1)
	f := financialExecutionForRollingChain(t, chain)
	x := f.execution
	x.Native.Continuous = true
	parent, root, err := x.Genesis()
	if err != nil {
		t.Fatal(err)
	}
	genesisRoot, err := protocol.NativeGenesisRootV4(x.Native.Seed, f.config.Domain, f.config.Custody)
	if err != nil || root != genesisRoot || x.Schema() != consensus.ContinuousExecutionSchema {
		t.Fatal("continuous genesis binding", err)
	}
	genesis, _, err := x.Decode(parent)
	if err != nil || genesis.Version != 6 || genesis.FeeHistory == nil || len(genesis.Fees) != 0 {
		t.Fatal("continuous genesis state", err)
	}
	proof := chain.Evidence(t, *genesis.RollingAnchor, 1, 0, true)
	inbox, err := devnet.EncodeRollingInboxAction(proof)
	if err != nil {
		t.Fatal(err)
	}
	for height := uint64(1); height <= 320; height++ {
		action := inbox
		if height > 1 {
			action, err = engine.Sign(engine.Action{Version: 1, Epoch: f.config.Domain.EpochKey(), Owner: f.config.Oracle, Nonce: height - 1, Kind: engine.Noop}, f.oracle)
			if err != nil {
				t.Fatal(err)
			}
		}
		before := bytes.Clone(parent)
		ctx := consensus.ExecutionContext{Domain: f.config.Domain, Height: height, ParentRoot: root}
		result, err := x.Execute(parent, action, ctx)
		if err != nil {
			t.Fatal("execute", height, err)
		}
		if !bytes.Equal(parent, before) {
			t.Fatal("execution mutated parent")
		}
		if err := x.ValidateSnapshot(result.State, height, result.PostRoot); err != nil {
			t.Fatal("snapshot", height, err)
		}
		if height%64 == 0 {
			// Discard the execution object, then replay the exact parent/action.
			cold := financialExecutionForRollingChain(t, chain).execution
			cold.Native.Continuous = true
			again, err := cold.Execute(before, action, ctx)
			if err != nil || again.PostRoot != result.PostRoot || !bytes.Equal(again.State, result.State) {
				t.Fatal("cold financial replay mismatch", height, err)
			}
			x = cold
		}
		parent, root = result.State, result.PostRoot
	}
	last, market, err := x.Decode(parent)
	if err != nil || market.Height != 320 || market.InboxCursor != 3 || market.Total != "6" || market.Support != "2" || market.Insurance != "3" || market.RewardReserved != "0" || market.RewardPeriod != 0 || len(last.Fees) != 0 || len(last.FeeHistory.Open) != 0 {
		t.Fatal("continuous final accounting/history", err)
	}
	for name, modify := range map[string]func(*devnet.FinancialState){
		"legacy version":         func(s *devnet.FinancialState) { s.Version = 5 },
		"missing history":        func(s *devnet.FinancialState) { s.FeeHistory = nil },
		"old history mixed":      func(s *devnet.FinancialState) { s.Fees = append(s.Fees, protocol.Amount{}) },
		"invented closed period": func(s *devnet.FinancialState) { s.FeeHistory.ClosedPeriod = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			var bad devnet.FinancialState
			if err := json.Unmarshal(parent, &bad); err != nil {
				t.Fatal(err)
			}
			modify(&bad)
			raw, err := bad.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := x.Decode(raw); err == nil {
				t.Fatal("invalid snapshot accepted")
			}
		})
	}
	if x.ValidateSnapshot(parent, 319, root) == nil || x.ValidateSnapshot(parent, 320, protocol.Hash{1}) == nil {
		t.Fatal("snapshot height/root not bound")
	}
}
