package checkpoint

import (
	"testing"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

func TestCertifiedPlanningQCIsNeverFinality(t *testing.T) {
	f := newProofFixture(t)
	f.c.DataSchema = 6
	p := f.proof(t, []uint64{1}, []uint64{9})
	if _, err := f.epoch.VerifyCertified(f.c, p.Target); err != nil {
		t.Fatal("genuine five-signer planning certificate", err)
	}
	if _, err := f.epoch.Verify(f.c, rawHistoryProof(t, p)); err == nil {
		t.Fatal("planning certificate authorized finalized settlement")
	}
	for _, tc := range []struct {
		name string
		edit func(*protocol.Checkpoint, *hotstuff.SignedState)
	}{
		{"foreign-genesis", func(c *protocol.Checkpoint, q *hotstuff.SignedState) { c.Genesis[0] ^= 1 }},
		{"foreign-epoch", func(c *protocol.Checkpoint, q *hotstuff.SignedState) { c.Epoch++ }},
		{"changed-post-root", func(c *protocol.Checkpoint, q *hotstuff.SignedState) { c.PostRoot[0] ^= 1 }},
		{"changed-source-anchor", func(c *protocol.Checkpoint, q *hotstuff.SignedState) { c.CLXHash[0] ^= 1 }},
		{"changed-inbox-cursor", func(c *protocol.Checkpoint, q *hotstuff.SignedState) { c.InboxEnd++ }},
		{"four-signers", func(c *protocol.Checkpoint, q *hotstuff.SignedState) { q.Mask = []byte{15} }},
		{"outside-committee", func(c *protocol.Checkpoint, q *hotstuff.SignedState) { q.Mask = []byte{255} }},
		{"qc-view-metadata", func(c *protocol.Checkpoint, q *hotstuff.SignedState) { q.Number++ }},
		{"qc-leader-metadata", func(c *protocol.Checkpoint, q *hotstuff.SignedState) { q.LeaderID += "x" }},
		{"signature", func(c *protocol.Checkpoint, q *hotstuff.SignedState) { q.Sign[0] ^= 1 }},
		{"oversized-state", func(c *protocol.Checkpoint, q *hotstuff.SignedState) { q.State = make([]byte, MaxRefBytes+1) }},
		{"oversized-signature", func(c *protocol.Checkpoint, q *hotstuff.SignedState) { q.Sign = make([]byte, 129) }},
		{"signed-evm-metadata", func(c *protocol.Checkpoint, q *hotstuff.SignedState) {
			r, err := types.DecodeHotstuffProposalRef(q.State)
			if err != nil {
				t.Fatal(err)
			}
			r.GasUsed = 1
			*q = *f.sign(t, r)
		}},
		{"signed-clock-change", func(c *protocol.Checkpoint, q *hotstuff.SignedState) {
			r, err := types.DecodeHotstuffProposalRef(q.State)
			if err != nil {
				t.Fatal(err)
			}
			r.Time++
			*q = *f.sign(t, r)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, q := f.c, hotstuff.CloneSignedState(p.Target)
			tc.edit(&c, q)
			if _, err := f.epoch.VerifyCertified(c, q); err == nil {
				t.Fatal("invalid certified planning input accepted")
			}
		})
	}
}
