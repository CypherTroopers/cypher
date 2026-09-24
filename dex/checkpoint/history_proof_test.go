package checkpoint

import (
	"bytes"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

func historyProofFixture(t *testing.T) (*proofFixture, Proof) {
	t.Helper()
	f := newProofFixture(t)
	f.c.DataSchema = 6
	var frontier protocol.HistoryFrontier
	var qcs []*hotstuff.SignedState
	var ids []protocol.Hash
	var actionRoot protocol.Hash
	var root protocol.Hash
	for height := uint64(1); height <= 21; height++ {
		if height > 1 {
			id, _ := hotstuff.SignedStateID(qcs[len(qcs)-1])
			ids = append(ids, protocol.Hash(id.Hash()))
			if err := frontier.AppendQCID(ids[len(ids)-1]); err != nil {
				t.Fatal(err)
			}
		}
		root, _ = frontier.Root()
		actionRoot = protocol.Digest("history-proof-test-action", []byte{byte(height)})
		data, err := protocol.HistoryDataRoot(actionRoot, root, frontier.Count)
		if err != nil {
			t.Fatal(err)
		}
		view := height*2 - 1
		if height == 21 {
			view--
		}
		ref := &types.HotstuffProposalRef{Version: types.HotstuffProposalRefVersion, ChainID: f.c.ChainID, Number: height, ViewNumber: view, ViewID: common.Hash{byte(view), 17}, LeaderID: f.epoch.leaders[(view-1)%7], BlockHash: common.Hash{byte(height), 61}, ParentHash: common.Hash{77}, StateRoot: common.Hash(f.c.PostRoot), BodyHash: common.Hash(data), BodySize: 8, ExtraHash: types.HotstuffProposalExtraHash(nil), KeyHash: common.Hash(f.c.Domain().EpochKey()), Time: height}
		if height == 1 {
			f.c.DataRoot = data
			h, _ := f.c.Hash()
			ref.BlockHash = common.Hash(h)
		} else {
			parent, _ := types.DecodeHotstuffProposalRef(qcs[len(qcs)-1].State)
			ref.ParentHash = parent.BlockHash
			ref.ParentQCID = common.Hash(ids[len(ids)-1])
		}
		qcs = append(qcs, f.sign(t, ref))
	}
	path, err := protocol.BuildHistoryProof(ids[:19], 0)
	if err != nil {
		t.Fatal(err)
	}
	return f, Proof{Target: qcs[0], Descendants: []*hotstuff.SignedState{qcs[19], qcs[20]}, History: &HistoryWitness{Count: 19, ActionRoot: protocol.Digest("history-proof-test-action", []byte{20}), Siblings: path}}
}

func rawHistoryProof(t *testing.T, p Proof) []byte {
	t.Helper()
	e := envelopeV2{Version: 2}
	for _, q := range append([]*hotstuff.SignedState{p.Target}, p.Descendants...) {
		b, err := hotstuff.EncodeSignedState(q)
		if err != nil {
			t.Fatal(err)
		}
		e.QCs = append(e.QCs, b)
	}
	if p.History != nil {
		e.History = []HistoryWitness{*p.History}
	}
	b, err := rlp.EncodeToBytes(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHistoryFinalityBeyondEightDescendants(t *testing.T) {
	f, p := historyProofFixture(t)
	b, err := EncodeProofV2(p)
	if err != nil {
		t.Fatal(err)
	}
	stats, err := f.epoch.Verify(f.c, b)
	if err != nil || stats.SignatureChecks != 3 {
		t.Fatalf("history proof verification %+v %v", stats, err)
	}
	decoded, err := DecodeProof(b)
	if err != nil {
		t.Fatal(err)
	}
	again, err := EncodeProof(decoded)
	if err != nil || !bytes.Equal(b, again) {
		t.Fatal("history proof codec roundtrip", err)
	}
	if len(b) > MaxProofBytes || MaxDescendants != 8 {
		t.Fatal("proof limits expanded")
	}
	t.Logf("20 gapped ancestors recovered with 3 QCs, 12 siblings, %d proof bytes; no signature threshold or finality rule change", len(b))
}

func TestHistoryFinalityRejectsTamperingBeforeCrypto(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*proofFixture, *Proof)
	}{
		{"count", func(f *proofFixture, p *Proof) { p.History.Count++ }},
		{"oversized_count", func(f *proofFixture, p *Proof) { p.History.Count = 4096 }},
		{"short_path", func(f *proofFixture, p *Proof) { p.History.Siblings = p.History.Siblings[:11] }},
		{"path_root", func(f *proofFixture, p *Proof) { p.History.Siblings[7][0] ^= 1 }},
		{"action_root", func(f *proofFixture, p *Proof) { p.History.ActionRoot[0] ^= 1 }},
		{"target_view_identity", func(f *proofFixture, p *Proof) {
			r, _ := types.DecodeHotstuffProposalRef(p.Target.State)
			r.ViewID[1] ^= 1
			p.Target = f.sign(t, r)
		}},
		{"anchor_domain", func(f *proofFixture, p *Proof) {
			r, _ := types.DecodeHotstuffProposalRef(p.Descendants[0].State)
			r.KeyHash[0] ^= 1
			p.Descendants[0] = f.sign(t, r)
		}},
		{"anchor_height", func(f *proofFixture, p *Proof) {
			r, _ := types.DecodeHotstuffProposalRef(p.Descendants[0].State)
			r.Number++
			r.Time++
			p.Descendants[0] = f.sign(t, r)
		}},
		{"child_parent", func(f *proofFixture, p *Proof) {
			r, _ := types.DecodeHotstuffProposalRef(p.Descendants[1].State)
			r.ParentQCID[0] ^= 1
			p.Descendants[1] = f.sign(t, r)
		}},
		{"child_view_gap", func(f *proofFixture, p *Proof) {
			r, _ := types.DecodeHotstuffProposalRef(p.Descendants[1].State)
			r.ViewNumber++
			r.LeaderID = f.epoch.leaders[(r.ViewNumber-1)%7]
			p.Descendants[1] = f.sign(t, r)
		}},
		{"subquorum", func(f *proofFixture, p *Proof) { p.Descendants[0].Mask = []byte{15} }},
		{"single_qc", func(f *proofFixture, p *Proof) { p.Descendants = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f, p := historyProofFixture(t)
			test.mutate(f, &p)
			s, err := f.epoch.Verify(f.c, rawHistoryProof(t, p))
			if err == nil || s.SignatureChecks != 0 {
				t.Fatalf("malformed proof reached crypto %+v %v", s, err)
			}
		})
	}
	f, p := historyProofFixture(t)
	p.Descendants[1].Sign[0] ^= 1
	if _, err := f.epoch.Verify(f.c, rawHistoryProof(t, p)); err == nil {
		t.Fatal("forged child signature accepted")
	}
}

func TestHistoryProofSchemaAndDirectFinality(t *testing.T) {
	f := newProofFixture(t)
	f.c.DataSchema = 6
	p := f.proof(t, []uint64{1, 2}, []uint64{1, 2})
	old, err := EncodeProof(p)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := f.epoch.Verify(f.c, old); err == nil || s.SignatureChecks != 0 {
		t.Fatal("schema6 accepted version1")
	}
	b, err := EncodeProofV2(p)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := f.epoch.Verify(f.c, b); err != nil || s.SignatureChecks != 2 {
		t.Fatal("direct schema6 finality", err)
	}
	f.c.DataSchema = 5
	if s, err := f.epoch.Verify(f.c, b); err == nil || s.SignatureChecks != 0 {
		t.Fatal("legacy schema accepted history version")
	}
}
