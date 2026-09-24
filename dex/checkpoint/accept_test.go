package checkpoint

import (
	"errors"
	"sync"
	"testing"

	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/bftview"
)

func acceptanceProof(t *testing.T, f *proofFixture) []byte {
	t.Helper()
	last := f.c.LastBlock
	encoded, err := EncodeProof(f.proof(t, []uint64{last, last + 1}, []uint64{last, last + 1}))
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func acceptanceFixture(t *testing.T, f *proofFixture, epochs []*Epoch, limit int) *Acceptor {
	t.Helper()
	a, err := NewAcceptor(f.c.PreRoot, epochs, []FinalizedAnchor{{10, protocol.Hash{5}}, {11, protocol.Hash{9}}}, limit)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func advanceCheckpoint(t *testing.T, c protocol.Checkpoint) protocol.Checkpoint {
	t.Helper()
	hash, err := c.Hash()
	if err != nil {
		t.Fatal(err)
	}
	c.Sequence++
	c.Previous, c.PreRoot = hash, c.PostRoot
	c.PostRoot[0]++
	c.FirstBlock, c.LastBlock = c.LastBlock+1, c.LastBlock+1
	return c
}

func TestNoFundsAcceptanceHistoryReplayConflictAndCapacity(t *testing.T) {
	f := newProofFixture(t)
	a := acceptanceFixture(t, f, []*Epoch{f.epoch}, 3)
	first := f.c
	for sequence := uint64(1); sequence <= 3; sequence++ {
		result, err := a.Accept(f.c, acceptanceProof(t, f))
		if err != nil {
			t.Fatal(err)
		}
		if result.Sequence != sequence || result.Replay || result.Verification.SignatureChecks != 2 || result.DataAvailability != DataAvailabilityNotVerified {
			t.Fatalf("bad acceptance result: %+v", result)
		}
		state := a.State()
		if state.Sequence != sequence || state.Root != f.c.PostRoot || state.Hash != result.Hash || state.InboxCursor != 0 || state.LastBlock != f.c.LastBlock || state.Epoch != f.c.Epoch || state.CLX != (FinalizedAnchor{f.c.CLXHeight, f.c.CLXHash}) {
			t.Fatalf("bad accepted state: %+v", state)
		}
		f.c = advanceCheckpoint(t, f.c)
	}
	before := a.State()
	result, err := a.Accept(first, nil)
	if err != nil || !result.Replay || result.Verification.SignatureChecks != 0 {
		t.Fatalf("historical idempotency: %+v, %v", result, err)
	}
	if a.State() != before {
		t.Fatal("historical replay mutated latest state")
	}
	conflict := first
	conflict.PostRoot[0] ^= 1
	if _, err := a.Accept(conflict, nil); !errors.Is(err, ErrCheckpointConflict) {
		t.Fatal(err)
	}
	if _, err := a.Accept(f.c, nil); !errors.Is(err, ErrHistoryCapacity) {
		t.Fatal(err)
	}
	if a.State() != before {
		t.Fatal("rejected checkpoint mutated state")
	}
}

func TestNoFundsAcceptanceRejectsUnconnectedAndFinancialPayloadsBeforeCrypto(t *testing.T) {
	f := newProofFixture(t)
	a := acceptanceFixture(t, f, []*Epoch{f.epoch}, 8)
	tests := []struct {
		name   string
		mutate func(*protocol.Checkpoint)
		want   error
	}{
		{"chain", func(c *protocol.Checkpoint) { c.ChainID++ }, ErrCheckpointConnection},
		{"genesis", func(c *protocol.Checkpoint) { c.Genesis[0]++ }, ErrCheckpointConnection},
		{"dex", func(c *protocol.Checkpoint) { c.DEXID[0]++ }, ErrCheckpointConnection},
		{"sequence", func(c *protocol.Checkpoint) { c.Sequence++ }, ErrCheckpointConnection},
		{"previous", func(c *protocol.Checkpoint) { c.Previous[0]++ }, ErrCheckpointConnection},
		{"pre_root", func(c *protocol.Checkpoint) { c.PreRoot[0]++ }, ErrCheckpointConnection},
		{"block_gap", func(c *protocol.Checkpoint) { c.FirstBlock++; c.LastBlock++ }, ErrCheckpointConnection},
		{"block_range", func(c *protocol.Checkpoint) { c.LastBlock = MaxCheckpointBlocks + 1 }, ErrCheckpointConnection},
		{"unknown_clx_height", func(c *protocol.Checkpoint) { c.CLXHeight = 12 }, ErrUnfinalizedAnchor},
		{"wrong_clx_hash", func(c *protocol.Checkpoint) { c.CLXHash[0]++ }, ErrUnfinalizedAnchor},
		{"self_declared_epoch", func(c *protocol.Checkpoint) { c.Epoch++ }, ErrUnauthorizedEpoch},
		{"self_declared_committee", func(c *protocol.Checkpoint) { c.Committee[0]++ }, ErrUnauthorizedEpoch},
		{"deposit_consumption", func(c *protocol.Checkpoint) { c.InboxEnd++ }, ErrNoFundsMode},
		{"deposit_cursor", func(c *protocol.Checkpoint) { c.InboxStart++; c.InboxEnd++ }, ErrNoFundsMode},
		{"deposit_commitment", func(c *protocol.Checkpoint) { c.InboxRoot[0]++ }, ErrNoFundsMode},
		{"withdrawal_commitment", func(c *protocol.Checkpoint) { c.WithdrawalRoot[0]++ }, ErrNoFundsMode},
		{"withdrawal_total", func(c *protocol.Checkpoint) { c.WithdrawalTotal[31]++ }, ErrNoFundsMode},
		{"reward_commitment", func(c *protocol.Checkpoint) { c.RewardRoot[0]++ }, ErrNoFundsMode},
		{"reward_total", func(c *protocol.Checkpoint) { c.RewardTotal[31]++ }, ErrNoFundsMode},
		{"reward_period", func(c *protocol.Checkpoint) { c.RewardPeriod++ }, ErrNoFundsMode},
		{"funding", func(c *protocol.Checkpoint) { c.FundingRef[0]++ }, ErrNoFundsMode},
	}
	before := a.State()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := f.c
			test.mutate(&c)
			result, err := a.Accept(c, nil)
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
			if result.Verification.SignatureChecks != 0 || a.State() != before {
				t.Fatal("rejection performed crypto or mutated state")
			}
		})
	}
	if _, err := a.Accept(f.c, acceptanceProof(t, f)); err != nil {
		t.Fatal(err)
	}
}

func TestNoFundsBadProofAtomicityAndFinalizedAnchorRegression(t *testing.T) {
	f := newProofFixture(t)
	a := acceptanceFixture(t, f, []*Epoch{f.epoch}, 8)
	p := f.proof(t, []uint64{1, 2}, []uint64{1, 2})
	p.Target.Sign[0] ^= 1
	before := a.State()
	result, err := a.Accept(f.c, rawProof(t, p))
	if err == nil || result.Verification.SignatureChecks == 0 {
		t.Fatal("invalid actual signature accepted or not checked")
	}
	if a.State() != before {
		t.Fatal("bad proof mutated state")
	}
	f.c.CLXHeight, f.c.CLXHash = 11, protocol.Hash{9}
	if _, err := a.Accept(f.c, acceptanceProof(t, f)); err != nil {
		t.Fatal(err)
	}
	before = a.State()
	f.c = advanceCheckpoint(t, f.c)
	f.c.CLXHeight, f.c.CLXHash = 10, protocol.Hash{5}
	if _, err := a.Accept(f.c, nil); !errors.Is(err, ErrUnfinalizedAnchor) {
		t.Fatal(err)
	}
	if a.State() != before {
		t.Fatal("anchor regression mutated state")
	}
}

func TestNoFundsHistoricalEpochBoundaryAndRegisteredRotation(t *testing.T) {
	f := newProofFixture(t)
	old, err := NewEpoch(f.c.Domain(), 1, 2, f.nodes)
	if err != nil {
		t.Fatal(err)
	}
	first, firstProof := f.c, acceptanceProof(t, f)
	// Rotate committee order so historical and new signer indexes and leader
	// schedules differ, while retaining seven real BLS fixture keys.
	for i, j := 0, len(f.nodes)-1; i < j; i, j = i+1, j-1 {
		f.nodes[i], f.nodes[j] = f.nodes[j], f.nodes[i]
		f.keys[i], f.keys[j] = f.keys[j], f.keys[i]
	}
	newDomain := f.c.Domain()
	newDomain.Epoch++
	newDomain.Committee = protocol.Hash((&bftview.Committee{List: f.nodes}).RlpHash())
	newEpoch, err := NewEpoch(newDomain, 2, 4, f.nodes)
	if err != nil {
		t.Fatal(err)
	}
	a := acceptanceFixture(t, f, []*Epoch{old, newEpoch}, 8)
	withoutApproval := acceptanceFixture(t, f, []*Epoch{old}, 8)
	for _, acceptor := range []*Acceptor{a, withoutApproval} {
		if _, err := acceptor.Accept(first, firstProof); err != nil {
			t.Fatal(err)
		}
	}
	f.c = advanceCheckpoint(t, first)
	if _, err := a.Accept(f.c, nil); !errors.Is(err, ErrUnauthorizedEpoch) {
		t.Fatal("old committee crossed activation boundary", err)
	}
	f.c.Epoch, f.c.Committee = newDomain.Epoch, newDomain.Committee
	f.epoch = newEpoch
	newProof := acceptanceProof(t, f)
	if _, err := withoutApproval.Accept(f.c, newProof); !errors.Is(err, ErrUnauthorizedEpoch) {
		t.Fatal("committee self-activation accepted", err)
	}
	if _, err := a.Accept(f.c, newProof); err != nil {
		t.Fatal(err)
	}
	if a.State().Epoch != newDomain.Epoch {
		t.Fatal("epoch did not advance")
	}
	if result, err := a.Accept(first, nil); err != nil || !result.Replay {
		t.Fatal("historical replay was judged by current members", err)
	}
	f.c = advanceCheckpoint(t, f.c)
	if _, err := a.Accept(f.c, acceptanceProof(t, f)); err != nil {
		t.Fatal(err)
	}
	f.c = advanceCheckpoint(t, f.c)
	if _, err := a.Accept(f.c, nil); !errors.Is(err, ErrUnauthorizedEpoch) {
		t.Fatal("epoch end was inclusive", err)
	}
}

func TestNoFundsTrustedInitializationAndConcurrentReplay(t *testing.T) {
	f := newProofFixture(t)
	for _, capacity := range []int{0, MaxAcceptedCheckpoints + 1} {
		if _, err := NewAcceptor(f.c.PreRoot, []*Epoch{f.epoch}, []FinalizedAnchor{{10, f.c.CLXHash}}, capacity); err == nil {
			t.Fatal("invalid history bound accepted")
		}
	}
	if _, err := NewAcceptor(f.c.PreRoot, []*Epoch{nil}, []FinalizedAnchor{{10, f.c.CLXHash}}, 8); err == nil {
		t.Fatal("nil epoch accepted")
	}
	if _, err := NewAcceptor(f.c.PreRoot, []*Epoch{f.epoch}, []FinalizedAnchor{{10, f.c.CLXHash}, {10, f.c.CLXHash}}, 8); err == nil {
		t.Fatal("duplicate anchor accepted")
	}
	wrongStart, err := NewEpoch(f.c.Domain(), 2, 10, f.nodes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAcceptor(f.c.PreRoot, []*Epoch{wrongStart}, []FinalizedAnchor{{10, f.c.CLXHash}}, 8); err == nil {
		t.Fatal("missing genesis epoch accepted")
	}
	firstEpoch, err := NewEpoch(f.c.Domain(), 1, 2, f.nodes)
	if err != nil {
		t.Fatal(err)
	}
	newDomain := f.c.Domain()
	newDomain.Epoch++
	gap, err := NewEpoch(newDomain, 3, 10, f.nodes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAcceptor(f.c.PreRoot, []*Epoch{firstEpoch, gap}, []FinalizedAnchor{{10, f.c.CLXHash}}, 8); err == nil {
		t.Fatal("ambiguous epoch gap accepted")
	}
	epochs, anchors := []*Epoch{f.epoch}, []FinalizedAnchor{{10, f.c.CLXHash}}
	a, err := NewAcceptor(f.c.PreRoot, epochs, anchors, 8)
	if err != nil {
		t.Fatal(err)
	}
	epochs[0] = nil
	anchors[0].Hash[0]++
	proof := acceptanceProof(t, f)
	results := make(chan Acceptance, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); result, err := a.Accept(f.c, proof); results <- result; errs <- err }()
	}
	wg.Wait()
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	one, two := <-results, <-results
	if one.Replay == two.Replay || one.Verification.SignatureChecks+two.Verification.SignatureChecks != 2 || a.State().Sequence != 1 {
		t.Fatal("concurrent duplicate mutated state twice")
	}
}
