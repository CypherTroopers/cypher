package checkpoint

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

type proofFixture struct {
	c     protocol.Checkpoint
	epoch *Epoch
	keys  []bls.SecretKey
	nodes []*common.Cnode
}

func newProofFixture(t *testing.T) *proofFixture {
	t.Helper()
	f := new(proofFixture)
	for i := 0; i < 7; i++ {
		var k bls.SecretKey
		if err := k.SetDecString(fmt.Sprint(i + 1)); err != nil {
			t.Fatal(err)
		}
		f.keys = append(f.keys, k)
		f.nodes = append(f.nodes, &common.Cnode{Address: fmt.Sprintf("127.0.0.1:%d", 24000+i), CoinBase: fmt.Sprintf("devnet-only-%d", i), Public: k.GetPublicKey().SerializeToHexStr()})
	}
	f.c = protocol.Checkpoint{Version: 1, ProofMode: 1, ChainID: 10101919, Genesis: protocol.Hash{1}, DEXID: protocol.Hash{2}, Epoch: 1,
		Committee: protocol.Hash((&bftview.Committee{List: f.nodes}).RlpHash()), Sequence: 1, PreRoot: protocol.Hash{3}, PostRoot: protocol.Hash{4},
		FirstBlock: 1, LastBlock: 1, CLXHeight: 10, CLXHash: protocol.Hash{5}, DataRoot: protocol.Hash{6}, DataSchema: 1}
	var err error
	f.epoch, err = NewEpoch(f.c.Domain(), 1, ^uint64(0), f.nodes)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *proofFixture) sign(t *testing.T, ref *types.HotstuffProposalRef) *hotstuff.SignedState {
	t.Helper()
	data := ref.EncodeToBytes()
	var aggregate *bls.Sign
	for i := 0; i < 5; i++ {
		sig, err := hotstuff.SignFHSSignatureWithContext(&f.keys[i], f.keys[i].GetPublicKey(), data, ref.ChainID, hotstuff.MsgVotePrepare, ref.ViewID, ref.LeaderID)
		if err != nil {
			t.Fatal(err)
		}
		if aggregate == nil {
			aggregate = sig
		} else {
			aggregate.Add(sig)
		}
	}
	return &hotstuff.SignedState{State: data, Sign: aggregate.Serialize(), Mask: []byte{31}, ViewID: ref.ViewID, LeaderID: ref.LeaderID, Number: ref.ViewNumber}
}

func (f *proofFixture) proof(t *testing.T, heights, views []uint64) Proof {
	t.Helper()
	var qcs []*hotstuff.SignedState
	hash, err := f.c.Hash()
	if err != nil {
		t.Fatal(err)
	}
	for i := range heights {
		view := views[i]
		ref := &types.HotstuffProposalRef{Version: types.HotstuffProposalRefVersion, ChainID: f.c.ChainID, Number: heights[i], ViewNumber: view,
			ViewID: common.Hash{byte(view), 42}, LeaderID: f.epoch.leaders[(view-1)%7], BlockHash: common.Hash(hash), ParentHash: common.Hash{99},
			StateRoot: common.Hash(f.c.PostRoot), BodyHash: common.Hash(f.c.DataRoot), BodySize: 8, ExtraHash: types.HotstuffProposalExtraHash(nil), KeyHash: common.Hash(f.c.Domain().EpochKey()), Time: heights[i]}
		if i > 0 {
			parent, _ := types.DecodeHotstuffProposalRef(qcs[i-1].State)
			ref.ParentHash = parent.BlockHash
			ref.BlockHash = common.Hash{byte(i), 51}
			id, err := hotstuff.SignedStateID(qcs[i-1])
			if err != nil {
				t.Fatal(err)
			}
			ref.ParentQCID = id.Hash()
		}
		qcs = append(qcs, f.sign(t, ref))
	}
	return Proof{Target: qcs[0], Descendants: qcs[1:]}
}

func rawProof(t *testing.T, p Proof) []byte {
	t.Helper()
	e := envelope{Version: 1}
	for _, q := range append([]*hotstuff.SignedState{p.Target}, p.Descendants...) {
		b, err := hotstuff.EncodeSignedState(q)
		if err != nil {
			t.Fatal(err)
		}
		e.QCs = append(e.QCs, b)
	}
	b, err := rlp.EncodeToBytes(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFHSFinalityGolden(t *testing.T) {
	data, err := os.ReadFile("../testdata/finality.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Vectors []struct {
			Name           string
			Heights, Views []uint64
			Valid          bool
		}
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Vectors) != 8 {
		t.Fatal("missing golden fixtures")
	}
	f := newProofFixture(t)
	for _, v := range vectors.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			p := f.proof(t, v.Heights, v.Views)
			stats, err := f.epoch.Verify(f.c, rawProof(t, p))
			if (err == nil) != v.Valid {
				t.Fatalf("valid=%v: %v", v.Valid, err)
			}
			if !v.Valid && stats.SignatureChecks != 0 {
				t.Fatal("topology rejected after crypto")
			}
			if v.Valid && stats.SignatureChecks != len(v.Heights) {
				t.Fatal("skipped signature checks")
			}
		})
	}
}

func TestProofDomainBoundsTampering(t *testing.T) {
	f := newProofFixture(t)
	tests := []struct {
		name      string
		mutate    func(*Proof)
		precrypto bool
	}{
		{"bad_signature", func(p *Proof) { p.Descendants[0].Sign[0] ^= 1 }, false},
		{"bad_mask", func(p *Proof) { p.Target.Mask = []byte{255} }, true},
		{"four_votes", func(p *Proof) { p.Target.Mask = []byte{15} }, true},
		{"large_signature", func(p *Proof) { p.Target.Sign = make([]byte, 129) }, true},
		{"large_ref", func(p *Proof) { p.Target.State = make([]byte, MaxRefBytes+1) }, true},
		{"large_leader", func(p *Proof) { p.Target.LeaderID = string(make([]byte, 129)) }, true},
		{"long_catchup", func(p *Proof) {
			for len(p.Descendants) <= MaxDescendants {
				p.Descendants = append(p.Descendants, p.Descendants[0])
			}
		}, true},
		{"wrong_parent_qc", func(p *Proof) {
			r, _ := types.DecodeHotstuffProposalRef(p.Descendants[0].State)
			r.ParentQCID[0] ^= 1
			p.Descendants[0] = f.sign(t, r)
		}, true},
		{"clx_gas_metadata", func(p *Proof) {
			r, _ := types.DecodeHotstuffProposalRef(p.Target.State)
			r.GasUsed = 1
			p.Target = f.sign(t, r)
		}, true},
		{"oversized_body_metadata", func(p *Proof) {
			r, _ := types.DecodeHotstuffProposalRef(p.Target.State)
			r.BodySize = 1024*1024 + 1
			p.Target = f.sign(t, r)
		}, true},
		{"nonlogical_time", func(p *Proof) {
			r, _ := types.DecodeHotstuffProposalRef(p.Target.State)
			r.Time++
			p.Target = f.sign(t, r)
		}, true},
		{"different_dex", func(p *Proof) {
			r, _ := types.DecodeHotstuffProposalRef(p.Target.State)
			d := f.c.Domain()
			d.DEXID[0] ^= 1
			r.KeyHash = common.Hash(d.EpochKey())
			p.Target = f.sign(t, r)
		}, true},
		{"clx_chain_replay", func(p *Proof) {
			r, _ := types.DecodeHotstuffProposalRef(p.Target.State)
			r.ChainID++
			p.Target = f.sign(t, r)
		}, true},
		{"old_epoch", func(p *Proof) {
			r, _ := types.DecodeHotstuffProposalRef(p.Target.State)
			d := f.c.Domain()
			d.Epoch++
			r.KeyHash = common.Hash(d.EpochKey())
			p.Target = f.sign(t, r)
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := f.proof(t, []uint64{1, 2}, []uint64{1, 2})
			tt.mutate(&p)
			stats, err := f.epoch.Verify(f.c, rawProof(t, p))
			if err == nil {
				t.Fatal("bad proof accepted")
			}
			if tt.precrypto && stats.SignatureChecks != 0 {
				t.Fatal("invalid shape reached crypto")
			}
		})
	}
	stats, err := f.epoch.Verify(f.c, make([]byte, MaxProofBytes+1))
	if err == nil || stats.SignatureChecks != 0 {
		t.Fatal("oversized envelope reached crypto")
	}
	p := f.proof(t, []uint64{1, 2}, []uint64{1, 2})
	encoded, err := EncodeProof(p)
	if err != nil {
		t.Fatal(err)
	}
	changed := f.c
	changed.PostRoot[0] ^= 1
	if _, err := f.epoch.Verify(changed, encoded); err == nil {
		t.Fatal("wrong checkpoint accepted")
	}
	changed = f.c
	changed.Sequence = 0
	if _, err := f.epoch.Verify(changed, encoded); err == nil {
		t.Fatal("unregistered boundary accepted")
	}
}

func TestEpochRegistrationSnapshot(t *testing.T) {
	f := newProofFixture(t)
	p := f.proof(t, []uint64{1, 2}, []uint64{1, 2})
	encoded, err := EncodeProof(p)
	if err != nil {
		t.Fatal(err)
	}
	f.nodes[0].Public = f.nodes[1].Public
	if _, err := f.epoch.Verify(f.c, encoded); err != nil {
		t.Fatal("caller mutated registered keys:", err)
	}
	if _, err := NewEpoch(f.c.Domain(), 1, 5, f.nodes); err == nil {
		t.Fatal("duplicate key accepted")
	}
}

func FuzzProofDecode(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xc0})
	q := &hotstuff.SignedState{State: []byte{0xc0}, Sign: []byte{1}, Mask: []byte{31}, LeaderID: "devnet", Number: 1}
	b, err := EncodeProof(Proof{Target: q, Descendants: []*hotstuff.SignedState{q}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	v2, err := EncodeProofV2(Proof{Target: q, Descendants: []*hotstuff.SignedState{q}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(v2)
	history, err := EncodeProofV2(Proof{Target: q, Descendants: []*hotstuff.SignedState{q, q}, History: &HistoryWitness{Count: 1, ActionRoot: protocol.Hash{1}, Siblings: make([]protocol.Hash, protocol.HistoryDepth)}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(history)
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := DecodeProof(data)
		if err != nil {
			return
		}
		encoded, err := EncodeProof(p)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != string(encoded) {
			t.Fatal("noncanonical proof accepted")
		}
	})
}
