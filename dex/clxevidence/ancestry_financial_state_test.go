package clxevidence_test

import (
	"bytes"
	"testing"

	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/devnet"
	"github.com/cypherium/cypher/dex/engine"
)

// Hold the financial domain and authenticated inbox constant to compare the
// arithmetic alone. Configuration-v5 activation/native TX verification is tested
// separately; this does not claim a live v5 network or a financial migration.
func TestAncestryExecutionPreservesFinancialStateAndArithmetic(t *testing.T) {
	chain := clxevidence.ContinuousFinancialFixtureForTest(t, 1)
	f := financialExecutionForRollingChain(t, chain)
	old := f.execution
	old.Native.Continuous = true
	fresh := financialExecutionForRollingChain(t, chain).execution
	fresh.Native.Continuous, fresh.Native.Ancestry = true, true
	parent, root, err := old.Genesis()
	if err != nil {
		t.Fatal(err)
	}
	newer, newerRoot, err := fresh.Genesis()
	if err != nil || root != newerRoot || !bytes.Equal(parent, newer) {
		t.Fatal("financial genesis changed", err)
	}
	if old.Schema() != consensus.ContinuousExecutionSchema || fresh.Schema() != consensus.AncestryExecutionSchema || old.ID() == fresh.ID() {
		t.Fatal("execution schema/ID must separate proof semantics")
	}
	genesis, _, err := old.Decode(parent)
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := devnet.EncodeRollingInboxAction(chain.Evidence(t, *genesis.RollingAnchor, 1, 0, true))
	if err != nil {
		t.Fatal(err)
	}
	for h := uint64(1); h <= 320; h++ {
		action := inbox
		if h > 1 {
			action, err = engine.Sign(engine.Action{Version: 1, Epoch: f.config.Domain.EpochKey(), Owner: f.config.Oracle, Nonce: h - 1, Kind: engine.Noop}, f.oracle)
			if err != nil {
				t.Fatal(err)
			}
		}
		ctx := consensus.ExecutionContext{Domain: f.config.Domain, Height: h, ParentRoot: root}
		a, err := old.Execute(parent, action, ctx)
		if err != nil {
			t.Fatal(h, err)
		}
		b, err := fresh.Execute(parent, action, ctx)
		if err != nil || a.PostRoot != b.PostRoot || !bytes.Equal(a.State, b.State) {
			t.Fatal("ancestry changed financial transition", h, err)
		}
		if err = fresh.ValidateSnapshot(b.State, h, b.PostRoot); err != nil {
			t.Fatal(err)
		}
		parent, root = a.State, a.PostRoot
	}
}
