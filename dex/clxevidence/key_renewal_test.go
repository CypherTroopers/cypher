package clxevidence

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"sync"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

func TestKeyRenewalIndependentGolden(t *testing.T) {
	raw, err := os.ReadFile("../testdata/key_renewal.json")
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		AnchorSize       int                          `json:"anchor_size"`
		Legacy           struct{ Encoded, ID string } `json:"legacy_anchor"`
		Anchors          []struct{ Name, Encoded, ID string }
		IDs              []string                 `json:"boundary_ids"`
		Root             string                   `json:"boundary_root"`
		Codec            struct{ Encoded string } `json:"codec_only_evidence"`
		PermutationCodec struct{ Encoded string } `json:"codec_only_permutation_evidence"`
	}
	if err = json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	if g.AnchorSize != AnchorV2Size {
		t.Fatal("size")
	}
	legacyRaw, _ := hex.DecodeString(g.Legacy.Encoded)
	legacy, err := DecodeAnchor(legacyRaw)
	if err != nil {
		t.Fatal(err)
	}
	oldID, _ := legacy.ID()
	if hex.EncodeToString(oldID[:]) != g.Legacy.ID {
		t.Fatal("legacy ID changed")
	}
	ids := []protocol.Hash{}
	for _, encoded := range g.IDs {
		b, _ := hex.DecodeString(encoded)
		var id protocol.Hash
		copy(id[:], b)
		ids = append(ids, id)
	}
	root, err := BoundaryCommitment(ids)
	if err != nil || hex.EncodeToString(root[:]) != g.Root {
		t.Fatal("independent boundary golden", err)
	}
	for _, vector := range g.Anchors {
		t.Run(vector.Name, func(t *testing.T) {
			a := legacy
			a.Version = 2
			if vector.Name == "pending" {
				a.ActivationEnd = 259
				a.ActivationRoot = root
			}
			encoded, err := a.Encode()
			if err != nil || hex.EncodeToString(encoded) != vector.Encoded {
				t.Fatal("independent anchor golden", err)
			}
			id, _ := a.ID()
			if hex.EncodeToString(id[:]) != vector.ID {
				t.Fatal("ID")
			}
			decoded, err := DecodeAnchor(encoded)
			if err != nil || decoded != a {
				t.Fatal("roundtrip", err)
			}
			j, _ := json.Marshal(a)
			var parsed Anchor
			if err = json.Unmarshal(j, &parsed); err != nil || parsed != a {
				t.Fatal("JSON", err)
			}
		})
	}
	codec, _ := hex.DecodeString(g.Codec.Encoded)
	e, err := DecodeRollingEvidence(codec)
	if err != nil {
		t.Fatal(err)
	}
	again, err := EncodeRollingEvidence(e)
	if err != nil || !bytes.Equal(codec, again) {
		t.Fatal("RLPv3 golden", err)
	}
	wire4, _ := hex.DecodeString(g.PermutationCodec.Encoded)
	e4, err := DecodeRollingEvidence(wire4)
	if err != nil {
		t.Fatal(err)
	}
	again4, err := EncodeRollingEvidence(e4)
	if err != nil || !bytes.Equal(wire4, again4) {
		t.Fatal("RLPv4 independent golden", err)
	}
	// The old JSON fields and order are unchanged, so legacy DEX state roots do
	// not gain zero-valued fields when this Go type is extended.
	type oldAnchor struct {
		Version                                              uint16
		ChainID                                              uint64
		Genesis, DEXID                                       protocol.Hash
		Custody                                              [20]byte
		Height                                               uint64
		BlockHash, StateRoot, SourceKeyHash, SourceCommittee protocol.Hash
		SourceEpoch, InboxCount                              uint64
	}
	want, _ := json.Marshal(oldAnchor{legacy.Version, legacy.ChainID, legacy.Genesis, legacy.DEXID, legacy.Custody, legacy.Height, legacy.BlockHash, legacy.StateRoot, legacy.SourceKeyHash, legacy.SourceCommittee, legacy.SourceEpoch, legacy.InboxCount})
	got, _ := json.Marshal(legacy)
	if !bytes.Equal(want, got) {
		t.Fatal("legacy JSON/root bytes changed")
	}
	for _, field := range []string{`"unknown":1`, `"ActivationRoot":null`, `"ActivationEnd":0`} {
		bad := append(bytes.Clone(got[:len(got)-1]), []byte(","+field+"}")...)
		var parsed Anchor
		if json.Unmarshal(bad, &parsed) == nil {
			t.Fatal("nested unknown legacy field accepted", field)
		}
	}
}

// RollingRenewalFixture is unit-generated actual BLS/CLX codecs plus MPT state;
// it is not an actual FHS process and does not replace the long-run gate.
type RollingRenewalFixture struct {
	*RollingFinancialFixture
	KeyHeaders map[protocol.Hash]*types.KeyBlockHeader
}

func RollingRenewalFixtureForTest(t *testing.T, last uint64, carriers []uint64) *RollingRenewalFixture {
	return renewalFixture(t, last, carriers, nil)
}
func RollingPermutationFixtureForTest(t *testing.T, last uint64, carriers []uint64) *RollingRenewalFixture {
	return renewalFixtureOptions(t, last, carriers, nil, true)
}
func renewalFixture(t *testing.T, last uint64, carriers []uint64, mutate func(*types.KeyBlock) *types.KeyBlock) *RollingRenewalFixture {
	return renewalFixtureOptions(t, last, carriers, mutate, false)
}
func renewalFixtureOptions(t *testing.T, last uint64, carriers []uint64, mutate func(*types.KeyBlock) *types.KeyBlock, permutation bool) *RollingRenewalFixture {
	t.Helper()
	template := RollingFinancialFixtureForTest(t, 1)
	f := testFixture(t)
	c := template.Config
	committee := &bftview.Committee{List: c.Epochs[0].Members}
	key := &types.KeyBlockHeader{Number: new(big.Int), Difficulty: big.NewInt(1), CommitteeHash: committee.RlpHash()}
	c.Epochs = append([]CommitteeEpoch(nil), c.Epochs...)
	c.Epochs[0].KeyHash = key.Hash()
	v, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	f.config, f.v = c, v
	r := &RollingRenewalFixture{RollingFinancialFixture: &RollingFinancialFixture{Config: c, Verifier: v, Sources: template.Sources, Entries: template.Entries}, KeyHeaders: map[protocol.Hash]*types.KeyBlockHeader{protocol.Hash(key.Hash()): types.CopyKeyBlockHeader(key)}}
	scheduled := map[uint64]bool{}
	for _, height := range carriers {
		scheduled[height] = true
	}
	parent := c.Genesis.Hash()
	var parentQC *hotstuff.SignedState
	var nextKey *types.KeyBlockHeader
	var nextCommittee *bftview.Committee
	keys := append([]bls.SecretKey(nil), f.keys...)
	activation := uint64(0)
	view := uint64(0)
	qcs := []*hotstuff.SignedState{}
	state := template.Sources[1]
	root := template.Blocks[0].Root()
	for height := uint64(1); height <= last+1; height++ {
		if height == activation {
			key = nextKey
			committee = nextCommittee
		}
		view++
		if scheduled[height] {
			for {
				index, _ := LeaderIndex(c.Seed, c.ChainID, view, committee.RlpHash())
				if (!permutation && index == 0) || (permutation && index != 0) {
					break
				}
				view++
			}
		}
		leader, _ := LeaderIndex(c.Seed, c.ChainID, view, committee.RlpHash())
		h := &types.Header{ParentHash: parent, Number: new(big.Int).SetUint64(height), Difficulty: big.NewInt(1), Root: root, TxHash: types.EmptyRootHash, ReceiptHash: types.EmptyRootHash, KeyHash: key.Hash(), Time: height}
		if scheduled[height] {
			nextCommittee = committee.Copy()
			nextCommittee.Add(nil, int(leader), "")
			kh := &types.KeyBlockHeader{ParentHash: key.Hash(), Number: new(big.Int).Add(key.Number, big.NewInt(1)), Difficulty: new(big.Int).Set(key.Difficulty), Time: key.Time + 600, BlockType: types.TimeReconfig, CommitteeHash: nextCommittee.RlpHash(), T_Number: height - 1}
			kb := types.NewKeyBlock(kh).WithBody(nextCommittee.In().Public, nextCommittee.In().CoinBase, "", "", nextCommittee.Leader().Public, nextCommittee.Leader().CoinBase)
			if mutate != nil {
				kb = mutate(kb)
			}
			h.BlockType = types.Key_Block
			h.KeyInfo = kb.EncodeToBytes()
			nextKey = kb.Header()
			activation = height + 2
			r.KeyHeaders[protocol.Hash(nextKey.Hash())] = types.CopyKeyBlockHeader(nextKey)
		}
		b := types.NewBlockWithHeader(h)
		pid := common.Hash{}
		if parentQC != nil {
			id, _ := hotstuff.SignedStateID(parentQC)
			pid = id.Hash()
		}
		ref, err := types.NewHotstuffProposalRefFromUnsignedBlockWithCommitments(c.ChainID, view, common.BigToHash(new(big.Int).SetUint64(view)), bftview.GetNodeID(committee.List[leader].Address, committee.List[leader].Public), b, types.HotstuffProposalExtraHash(nil), pid)
		if err != nil {
			t.Fatal(err)
		}
		for i, m := range committee.List {
			for j, registered := range c.Epochs[0].Members {
				if m.Public == registered.Public {
					f.keys[i] = keys[j]
					break
				}
			}
		}
		qc := f.sign(t, ref)
		b.SetFHSSignature(qc.Sign, qc.Mask, qc.ViewID, qc.LeaderID, qc.Number, ref.ExtraHash, ref.ParentQCID)
		r.Blocks = append(r.Blocks, b)
		qcs = append(qcs, qc)
		r.Sources[height] = state
		r.Entries[height] = template.Entries[1]
		parent, parentQC = b.Hash(), qc
	}
	for i := 0; i < int(last); i++ {
		q, _ := hotstuff.EncodeSignedState(qcs[i+1])
		desc := [][]byte{q}
		if qcs[i+1].Number != qcs[i].Number+1 {
			q2, _ := hotstuff.EncodeSignedState(qcs[i+2])
			desc = append(desc, q2)
		}
		proof, _ := rlp.EncodeToBytes(finalityEnvelope{2, desc})
		if err := r.Blocks[i].SetFHSFinalityProof(proof); err != nil {
			t.Fatal(err)
		}
		w, err := BuildHeaderWitness(c.ChainID, r.Blocks[i])
		if err != nil {
			t.Fatal(err)
		}
		r.Headers = append(r.Headers, w)
	}
	r.Blocks = r.Blocks[:last]
	return r
}
func (f *RollingRenewalFixture) Evidence(t *testing.T, base Anchor, target, cursor uint64, context KeyContext) RollingEvidence {
	t.Helper()
	id, _ := base.ID()
	e, err := BuildRollingEvidence(id, f.Headers[base.Height:target], f.Sources[target], f.Entries[target][cursor:], f.Config.Custody)
	if err != nil {
		t.Fatal(err)
	}
	if len(context.KeyHeader) == 0 {
		context.KeyHeader, err = rlp.EncodeToBytes(f.KeyHeaders[base.SourceKeyHash])
		if err != nil {
			t.Fatal(err)
		}
	}
	e.SetKeyContext(context)
	return e
}
func TestKeyRenewalBoundaryColdRestartAndRepeatedIntervals(t *testing.T) {
	f := RollingRenewalFixtureForTest(t, 260, []uint64{3, 130, 255})
	base, _ := f.Verifier.BootstrapAnchor()
	context := KeyContext{}
	for _, target := range []uint64{3, 4, 5, 37, 69, 101, 130, 131, 163, 195, 227, 255, 256, 260} {
		e := f.Evidence(t, base, target, 0, context)
		raw, err := EncodeRollingEvidence(e)
		if err != nil {
			t.Fatal(err)
		}
		e, err = DecodeRollingEvidence(raw)
		if err != nil {
			t.Fatal(err)
		}
		cold, err := New(f.Config)
		if err != nil {
			t.Fatal(err)
		}
		vr, next, err := cold.VerifyRolling(base, 0, e)
		if err != nil {
			t.Fatalf("%d -> %d: %v", base.Height, target, err)
		}
		if next.Version != 2 || next.Height != target || vr.Count() != 3 {
			t.Fatal("derived context/count")
		}
		pending := target == 3 || target == 130 || target == 255
		if pending != (next.ActivationEnd != 0) {
			t.Fatal("activation boundary lifetime")
		}
		// Every interval is independent of older renewal evidence; only one header
		// preimage and at most the current carrier's descendants remain.
		if len(vr.KeyContext().Boundary) > 1 || len(e.Headers) > 32 {
			t.Fatal("accumulated history")
		}
		context = vr.KeyContext()
		base = next
	}
	same := f.Evidence(t, base, base.Height, 1, context)
	vr, next, err := f.Verifier.VerifyRolling(base, 1, same)
	if err != nil || next != base || len(vr.Entries()) != 2 {
		t.Fatal("same-anchor later credit", err)
	}
}
func TestKeyRenewalRejectsContextAndGenerationAttacks(t *testing.T) {
	f := RollingRenewalFixtureForTest(t, 7, []uint64{3})
	base, _ := f.Verifier.BootstrapAnchor()
	e := f.Evidence(t, base, 3, 0, KeyContext{})
	vr, pending, err := f.Verifier.VerifyRolling(base, 0, e)
	if err != nil {
		t.Fatal(err)
	}
	e = f.Evidence(t, pending, 4, 0, vr.KeyContext())
	for name, change := range map[string]func(*RollingEvidence){"unknown-key": func(e *RollingEvidence) { e.KeyHeader[2] ^= 1 }, "missing-boundary": func(e *RollingEvidence) { e.Boundary = nil }, "changed-boundary": func(e *RollingEvidence) { e.Boundary[0][0] ^= 1 }, "duplicate-boundary": func(e *RollingEvidence) { e.Boundary = append(e.Boundary, e.Boundary[0]) }, "changed-signed-header": func(e *RollingEvidence) { alterHeader(t, e, func(h *types.Header) { h.KeyHash[0] ^= 1 }) }} {
		t.Run(name, func(t *testing.T) {
			bad := cloneRolling(t, e)
			change(&bad)
			if v, a, err := f.Verifier.VerifyRolling(pending, 0, bad); err == nil || v != nil || a != (Anchor{}) {
				t.Fatal("accepted", err)
			}
		})
	}
	_, cleared, err := f.Verifier.VerifyRolling(pending, 0, e)
	if err != nil {
		t.Fatal(err)
	}
	old := cloneRolling(t, e)
	id, _ := cleared.ID()
	old.Base = id
	if _, _, err := f.Verifier.VerifyRolling(cleared, 0, old); err == nil {
		t.Fatal("old boundary replay accepted")
	}
	for name, change := range map[string]func(*types.KeyBlock) *types.KeyBlock{
		"cadence": func(b *types.KeyBlock) *types.KeyBlock {
			h := b.Header()
			h.Time = 599
			return types.NewKeyBlock(h).WithBody(b.InPubKey(), b.InAddress(), "", "", b.LeaderPubKey(), b.LeaderAddress())
		},
		"key-parent": func(b *types.KeyBlock) *types.KeyBlock {
			h := b.Header()
			h.ParentHash[0] ^= 1
			return types.NewKeyBlock(h).WithBody(b.InPubKey(), b.InAddress(), "", "", b.LeaderPubKey(), b.LeaderAddress())
		},
		"new-member": func(b *types.KeyBlock) *types.KeyBlock {
			return b.WithBody("other", b.InAddress(), "", "", b.LeaderPubKey(), b.LeaderAddress())
		},
		"reordered-committee": func(b *types.KeyBlock) *types.KeyBlock {
			h := b.Header()
			h.CommitteeHash[0] ^= 1
			return types.NewKeyBlock(h).WithBody(b.InPubKey(), b.InAddress(), "", "", b.LeaderPubKey(), b.LeaderAddress())
		},
		"pow-candidate": func(b *types.KeyBlock) *types.KeyBlock {
			return b.WithBody(b.InPubKey(), b.InAddress(), "candidate", "recipient", b.LeaderPubKey(), b.LeaderAddress())
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := renewalFixture(t, 4, []uint64{3}, change)
			base, _ := bad.Verifier.BootstrapAnchor()
			e := bad.Evidence(t, base, 3, 0, KeyContext{})
			if _, _, err := bad.Verifier.VerifyRolling(base, 0, e); err == nil {
				t.Fatal("authenticated but unsupported renewal accepted")
			}
		})
	}
}

func TestKeyRenewalPermutationAndConcurrentLegacy(t *testing.T) {
	f := RollingPermutationFixtureForTest(t, 260, []uint64{3, 130, 255})
	base, _ := f.Verifier.BootstrapAnchor()
	context := KeyContext{Order: identityOrder()}
	initial := base
	initialEvidence := f.Evidence(t, base, 3, 0, context)
	for _, target := range []uint64{3, 4, 36, 68, 100, 130, 131, 163, 195, 227, 255, 256, 260} {
		e := f.Evidence(t, base, target, 0, context)
		raw, err := EncodeRollingEvidence(e)
		if err != nil {
			t.Fatal(err)
		}
		e, err = DecodeRollingEvidence(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err = f.Verifier.VerifyRollingPayload(e); err != nil {
			t.Fatalf("partial ingress %d: %v", target, err)
		}
		vr, next, err := f.Verifier.VerifyRolling(base, 0, e)
		if err != nil {
			t.Fatalf("%d -> %d: %v", base.Height, target, err)
		}
		if target == 3 && next.SourceCommittee == initial.SourceCommittee {
			t.Fatal("fixture did not permute")
		}
		if next.ActivationEnd > 0 {
			if len(vr.KeyContext().PreviousKeyHeader) == 0 || len(vr.KeyContext().PreviousOrder) != 7 {
				t.Fatal("missing old context")
			}
			oldAPI, err := f.Verifier.VerifyHeaderWitnesses(next, f.Headers[target:target+1])
			if err == nil || oldAPI != nil {
				t.Fatal("legacy helper accepted dynamic anchor without context")
			}
			boundary := f.Evidence(t, next, target+1, 0, vr.KeyContext())
			for name, mutate := range map[string]func(*RollingEvidence){"new-order": func(e *RollingEvidence) { e.Order[0], e.Order[1] = e.Order[1], e.Order[0] }, "old-order": func(e *RollingEvidence) {
				e.PreviousOrder[0], e.PreviousOrder[1] = e.PreviousOrder[1], e.PreviousOrder[0]
			}, "old-header": func(e *RollingEvidence) { e.PreviousKeyHeader[2] ^= 1 }, "duplicate-identity": func(e *RollingEvidence) { e.Order[0] = e.Order[1] }} {
				bad := cloneRolling(t, boundary)
				mutate(&bad)
				if _, _, err := f.Verifier.VerifyRolling(next, 0, bad); err == nil {
					t.Fatal("accepted", name)
				}
			}
		} else if len(vr.KeyContext().PreviousKeyHeader) > 0 || len(vr.KeyContext().PreviousOrder) > 0 {
			t.Fatal("old key context retained past deadline")
		}
		base, context = next, vr.KeyContext()
	}
	legacy := f.Evidence(t, initial, 1, 0, KeyContext{})
	legacy.KeyHeader = nil
	var group sync.WaitGroup
	errors := make(chan error, 8)
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			e := initialEvidence
			if i%2 == 0 {
				e = legacy
			}
			_, _, err := f.Verifier.VerifyRolling(initial, 0, e)
			errors <- err
		}(i)
	}
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal("shared immutable verifier", err)
		}
	}
}

// This generates cryptographically valid alternative children, so rejection
// proves the activation lifetime/semantic-ID rule, not a broken signature.
func renewalAttackChild(t *testing.T, f *RollingRenewalFixture, base Anchor, header *types.KeyBlockHeader, order []uint8) HeaderWitness {
	t.Helper()
	signer := testFixture(t)
	signer.config = f.Config
	original := append([]bls.SecretKey(nil), signer.keys...)
	for i, index := range order {
		signer.keys[i] = original[index]
	}
	ep, err := f.Verifier.orderedEpoch(header, order)
	if err != nil {
		t.Fatal(err)
	}
	blocks := []*types.Block{}
	qcs := []*hotstuff.SignedState{}
	parent := common.Hash(base.BlockHash)
	for i := uint64(0); i < 2; i++ {
		height, view := base.Height+1+i, uint64(900)+i
		leader, _ := LeaderIndex(f.Config.Seed, f.Config.ChainID, view, header.CommitteeHash)
		block := types.NewBlockWithHeader(&types.Header{Number: new(big.Int).SetUint64(height), Difficulty: big.NewInt(1), ParentHash: parent, Root: common.Hash(base.StateRoot), TxHash: types.EmptyRootHash, ReceiptHash: types.EmptyRootHash, Time: 999, KeyHash: header.Hash()})
		parentQC := common.Hash{}
		if i > 0 {
			id, _ := hotstuff.SignedStateID(qcs[i-1])
			parentQC = id.Hash()
		}
		ref, err := types.NewHotstuffProposalRefFromUnsignedBlockWithCommitments(f.Config.ChainID, view, common.BigToHash(new(big.Int).SetUint64(view)), ep.leaders[leader], block, types.HotstuffProposalExtraHash(nil), parentQC)
		if err != nil {
			t.Fatal(err)
		}
		qc := signer.sign(t, ref)
		control := *f.Verifier
		control.qcEpoch = func(*types.HotstuffProposalRef, *hotstuff.SignedState) *epoch { return ep }
		if err = control.verifyQC(qc); err != nil {
			t.Fatal("negative fixture QC itself invalid", err)
		}
		block.SetFHSSignature(qc.Sign, qc.Mask, qc.ViewID, qc.LeaderID, qc.Number, ref.ExtraHash, ref.ParentQCID)
		blocks = append(blocks, block)
		qcs = append(qcs, qc)
		parent = block.Hash()
	}
	child, _ := hotstuff.EncodeSignedState(qcs[1])
	proof, _ := rlp.EncodeToBytes(finalityEnvelope{2, [][]byte{child}})
	if err = blocks[0].SetFHSFinalityProof(proof); err != nil {
		t.Fatal(err)
	}
	w, err := BuildHeaderWitness(f.Config.ChainID, blocks[0])
	if err != nil {
		t.Fatal(err)
	}
	return w
}
func TestKeyRenewalValidSignaturesCannotExtendOldLifetime(t *testing.T) {
	f := RollingPermutationFixtureForTest(t, 6, []uint64{3})
	initial, _ := f.Verifier.BootstrapAnchor()
	e := f.Evidence(t, initial, 3, 0, KeyContext{Order: identityOrder()})
	vr, pending, err := f.Verifier.VerifyRolling(initial, 0, e)
	if err != nil {
		t.Fatal(err)
	}
	k := vr.KeyContext()
	oldHeader, _ := DecodeKeyHeader(k.PreviousKeyHeader)
	newHeader, _ := DecodeKeyHeader(k.KeyHeader)
	for name, w := range map[string]HeaderWitness{"old-key-new-semantic-QC": renewalAttackChild(t, f, pending, oldHeader, k.PreviousOrder), "new-key-before-activation-end": renewalAttackChild(t, f, pending, newHeader, k.Order)} {
		if _, _, _, err = f.Verifier.VerifyHeaderContext(pending, k, []HeaderWitness{w}); err == nil {
			t.Fatal("validly signed attack accepted", name)
		}
	}
	e = f.Evidence(t, pending, 4, 0, k)
	vr, cleared, err := f.Verifier.VerifyRolling(pending, 0, e)
	if err != nil {
		t.Fatal(err)
	}
	late := renewalAttackChild(t, f, cleared, oldHeader, k.PreviousOrder)
	if _, _, _, err = f.Verifier.VerifyHeaderContext(cleared, vr.KeyContext(), []HeaderWitness{late}); err == nil {
		t.Fatal("old key signed valid new height after boundary")
	}
}
