package clxevidence_test

import (
	"bytes"
	"testing"

	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/devnet"
)

// The source has real 5/7 signatures and MPT proofs; this remains an in-process
// integration fixture, not a replacement for ordinary CLI financial operation.
func TestRollingFinancialParentAcrossFixedMembershipRenewals(t *testing.T) {
	chain := clxevidence.RollingPermutationFixtureForTest(t, 10, []uint64{3, 7})
	f := financialExecutionForRollingChain(t, chain.RollingFinancialFixture)
	parent, root, err := f.execution.Genesis()
	if err != nil {
		t.Fatal(err)
	}
	initial, _, err := f.execution.Decode(parent)
	if err != nil {
		t.Fatal(err)
	}
	base := *initial.RollingAnchor
	keyContext := clxevidence.KeyContext{Order: []uint8{0, 1, 2, 3, 4, 5, 6}}
	changedCommittee := false
	for i, target := range []uint64{3, 4, 5, 7, 8, 10} {
		before, market, err := f.execution.Decode(parent)
		if err != nil {
			t.Fatal(err)
		}
		evidence := chain.Evidence(t, base, target, market.InboxCursor, keyContext)
		action, err := devnet.EncodeRollingInboxAction(evidence)
		if err != nil {
			t.Fatal(err)
		}
		ctx := consensus.ExecutionContext{Domain: f.config.Domain, Height: uint64(i + 1), ParentRoot: root}
		saved := bytes.Clone(parent)
		result, err := f.execution.Execute(parent, action, ctx)
		if err != nil {
			t.Fatalf("source %d, DEX %d: %v", target, i+1, err)
		}
		if !bytes.Equal(parent, saved) {
			t.Fatal("execution changed parent")
		}
		decoded, nextMarket, err := f.execution.Decode(result.State)
		if err != nil {
			t.Fatal("new v2 parent cannot be decoded", err)
		}
		if decoded.RollingAnchor.Version != 2 || nextMarket.InboxCursor != 3 || nextMarket.Total != "6" || nextMarket.Support != "2" || nextMarket.Insurance != "3" {
			t.Fatalf("financial renewal state: %+v %+v", decoded.RollingAnchor, nextMarket)
		}
		changedCommittee = changedCommittee || decoded.RollingAnchor.SourceCommittee != initial.RollingAnchor.SourceCommittee
		vr, next, err := chain.Verifier.VerifyRolling(base, market.InboxCursor, evidence)
		if err != nil || next != *decoded.RollingAnchor {
			t.Fatal("proof/state anchor mismatch", err)
		}
		// A caller cannot replace the authenticated parent anchor while reusing its
		// actual parent root, even though v2 shape permits an updated current key.
		for name, change := range map[string]func(*clxevidence.Anchor){
			"key":       func(a *clxevidence.Anchor) { a.SourceKeyHash[0] ^= 1 },
			"committee": func(a *clxevidence.Anchor) { a.SourceCommittee[0] ^= 1 },
			"epoch":     func(a *clxevidence.Anchor) { a.SourceEpoch++ },
			"custody":   func(a *clxevidence.Anchor) { a.Custody[0] ^= 1 },
		} {
			wrong := *before
			anchor := *before.RollingAnchor
			change(&anchor)
			wrong.RollingAnchor = &anchor
			raw, e := wrong.Encode()
			if e != nil {
				continue
			}
			if _, e = f.execution.Execute(raw, action, ctx); e == nil {
				t.Fatal("unbound parent accepted", name)
			}
		}
		// Fresh executor/verifier, same authenticated input and output, no cache.
		coldChain := *chain.RollingFinancialFixture
		coldChain.Verifier, err = clxevidence.New(chain.Config)
		if err != nil {
			t.Fatal(err)
		}
		cold := financialExecutionForRollingChain(t, &coldChain)
		replay, err := cold.execution.Execute(saved, action, ctx)
		if err != nil || !bytes.Equal(replay.State, result.State) || replay.PostRoot != result.PostRoot {
			t.Fatal("cold financial replay", err)
		}
		parent, root = result.State, result.PostRoot
		base = next
		keyContext = vr.KeyContext()
	}
	if !changedCommittee {
		t.Fatal("fixture did not exercise real ordered-committee change")
	}
}
