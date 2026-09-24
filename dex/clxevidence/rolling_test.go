package clxevidence

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

func TestRollingAnchorIndependentGolden(t *testing.T) {
	raw, err := os.ReadFile("../testdata/rolling_anchor.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		AnchorSize int `json:"anchor_size"`
		Anchors    []struct{ Name, Encoded, ID string }
		Codec      []struct{ Encoded string } `json:"codec_only_rolling_evidence"`
	}
	if err = json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	if golden.AnchorSize != AnchorSize || len(golden.Anchors) != 2 || len(golden.Codec) != 1 {
		t.Fatal("golden inventory changed")
	}
	fill := func(n byte) (h protocol.Hash) {
		for i := range h {
			h[i] = n
		}
		return
	}
	for _, vector := range golden.Anchors {
		t.Run(vector.Name, func(t *testing.T) {
			a := Anchor{Version: 1, ChainID: 10101919, Genesis: fill(0x11), DEXID: fill(0x22), BlockHash: fill(0x11), StateRoot: fill(0x44), SourceKeyHash: fill(0x55), SourceCommittee: fill(0x66), SourceEpoch: 1}
			for i := range a.Custody {
				a.Custody[i] = 0x33
			}
			if vector.Name == "after_257" {
				a.Height = 257
				a.BlockHash = fill(0x77)
				a.StateRoot = fill(0x88)
				a.InboxCount = 37
			}
			encoded, err := a.Encode()
			if err != nil {
				t.Fatal(err)
			}
			id, err := a.ID()
			if err != nil {
				t.Fatal(err)
			}
			if len(encoded) != 246 || hex.EncodeToString(encoded) != vector.Encoded || hex.EncodeToString(id[:]) != vector.ID {
				t.Fatal("independent Python golden mismatch")
			}
			decoded, err := DecodeAnchor(encoded)
			if err != nil || decoded != a {
				t.Fatalf("decode: %+v %v", decoded, err)
			}
			for _, invalid := range [][]byte{nil, encoded[:245], append(bytes.Clone(encoded), 0)} {
				if _, err := DecodeAnchor(invalid); err == nil {
					t.Fatal("bad length accepted")
				}
			}
			for name, change := range map[string]func(*Anchor){"version": func(x *Anchor) { x.Version = 3 }, "chain": func(x *Anchor) { x.ChainID = 0 }, "epoch": func(x *Anchor) { x.SourceEpoch = 2 }, "count": func(x *Anchor) { x.InboxCount = protocol.MaxInboxEntries + 1 }, "root": func(x *Anchor) { x.StateRoot = protocol.Hash{} }, "key": func(x *Anchor) { x.SourceKeyHash = protocol.Hash{} }, "committee": func(x *Anchor) { x.SourceCommittee = protocol.Hash{} }, "genesis": func(x *Anchor) { x.Height = 0; x.BlockHash = fill(0x99) }} {
				t.Run(name, func(t *testing.T) {
					bad := a
					change(&bad)
					if _, err := bad.Encode(); err == nil {
						t.Fatal("invalid anchor encoded")
					}
				})
			}
		})
	}
	encoded, err := hex.DecodeString(golden.Codec[0].Encoded)
	if err != nil {
		t.Fatal(err)
	}
	e, err := DecodeRollingEvidence(encoded)
	if err != nil {
		t.Fatal(err)
	}
	again, err := EncodeRollingEvidence(e)
	if err != nil || !bytes.Equal(encoded, again) {
		t.Fatalf("RLPv2 golden: %v", err)
	}
	if _, err = DecodeRangeEvidence(encoded); err == nil {
		t.Fatal("v1 accepted v2")
	}
}

func rollingFixture(t *testing.T) (*fixture, Anchor, RollingEvidence) {
	t.Helper()
	f := testFixture(t)
	base, err := f.v.BootstrapAnchor()
	if err != nil {
		t.Fatal(err)
	}
	id, err := base.ID()
	if err != nil {
		t.Fatal(err)
	}
	w, err := BuildHeaderWitness(f.config.ChainID, f.block)
	if err != nil {
		t.Fatal(err)
	}
	e, err := BuildRollingEvidence(id, []HeaderWitness{w}, f.state, f.entries)
	if err != nil {
		t.Fatal(err)
	}
	return f, base, e
}
func cloneRolling(t *testing.T, e RollingEvidence) RollingEvidence {
	t.Helper()
	raw, err := EncodeRollingEvidence(e)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeRollingEvidence(raw)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func alterHeader(t *testing.T, e *RollingEvidence, mutate func(*types.Header)) {
	t.Helper()
	var h types.Header
	if err := rlp.DecodeBytes(e.Headers[0].Header, &h); err != nil {
		t.Fatal(err)
	}
	mutate(&h)
	raw, err := rlp.EncodeToBytes(&h)
	if err != nil {
		t.Fatal(err)
	}
	e.Headers[0].Header = raw
}
func alterRef(t *testing.T, e *RollingEvidence, mutate func(*types.HotstuffProposalRef)) {
	t.Helper()
	r, err := types.DecodeHotstuffProposalRef(e.Headers[0].ProposalRef)
	if err != nil {
		t.Fatal(err)
	}
	mutate(r)
	e.Headers[0].ProposalRef = r.EncodeToBytes()
}

func TestRollingVerificationAndSameAnchorRange(t *testing.T) {
	f, base, e := rollingFixture(t)
	verified, target, err := f.v.VerifyRolling(base, 0, e)
	if err != nil {
		t.Fatal(err)
	}
	v1, err := f.v.VerifyRange(0, f.evidence)
	if err != nil {
		t.Fatal(err)
	}
	if target.Height != 1 || target.BlockHash != protocol.Hash(f.block.Hash()) || target.StateRoot != protocol.Hash(f.block.Root()) || target.InboxCount != 3 || verified.Count() != v1.Count() || verified.Header().Hash() != v1.Header().Hash() {
		t.Fatal("rolling/v1 result mismatch")
	}
	domain := protocol.Domain{ChainID: f.config.ChainID, Genesis: base.Genesis, DEXID: base.DEXID, Epoch: 1}
	if !verified.Matches(domain, base.Custody) {
		t.Fatal("source binding absent")
	}
	targetID, _ := target.ID()
	same, err := BuildRollingEvidence(targetID, nil, f.state, f.entries[1:])
	if err != nil {
		t.Fatal(err)
	}
	again, sameTarget, err := f.v.VerifyRolling(target, 1, same)
	if err != nil {
		t.Fatal(err)
	}
	if sameTarget != target || again.Header() != nil || again.Count() != 3 || len(again.Entries()) != 2 || !again.Matches(domain, base.Custody) {
		t.Fatal("same-anchor capability/identity mismatch")
	}
	empty, err := BuildRollingEvidence(targetID, nil, f.state, nil, f.config.Custody)
	if err != nil {
		t.Fatal(err)
	}
	closed, unchanged, err := f.v.VerifyRolling(target, 3, empty)
	if err != nil || unchanged != target || len(closed.Entries()) != 0 {
		t.Fatalf("empty same-anchor range: %v", err)
	}
	entries := again.Entries()
	entries[0].Amount[31]++
	if again.Entries()[0] != f.entries[1] {
		t.Fatal("verified entry alias")
	}
	h := verified.Header()
	h.Root[0] ^= 1
	if verified.Header().Root != f.block.Root() {
		t.Fatal("verified header alias")
	}
	e.Headers[0].Header[0] ^= 1
	e.AccountProof[0][0] ^= 1
	if verified.Header().Hash() != f.block.Hash() {
		t.Fatal("input alias")
	}
	old, err := EncodeRangeEvidence(f.evidence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeRollingEvidence(old); err == nil {
		t.Fatal("v2 accepted v1")
	}
}

func TestRollingRejectHeaderRefAndSignInfoTampering(t *testing.T) {
	f, base, original := rollingFixture(t)
	headerCases := map[string]func(*types.Header){
		"number": func(h *types.Header) { h.Number.SetUint64(2) }, "parent": func(h *types.Header) { h.ParentHash[0] ^= 1 }, "state_root": func(h *types.Header) { h.Root[0] ^= 1 }, "tx_root": func(h *types.Header) { h.TxHash[0] ^= 1 }, "receipt_root": func(h *types.Header) { h.ReceiptHash[0] ^= 1 }, "admission_root": func(h *types.Header) { h.CommonTxAdmissionRoot[0] ^= 1 }, "reward_root": func(h *types.Header) { h.CommonTxRewardRoot[0] ^= 1 }, "key": func(h *types.Header) { h.KeyHash[0] ^= 1 }, "time": func(h *types.Header) { h.Time++ }, "gas_limit": func(h *types.Header) { h.GasLimit++ }, "gas_used": func(h *types.Header) { h.GasUsed++ }, "extra": func(h *types.Header) { h.Extra = []byte{1} },
		"signature_same_hash": func(h *types.Header) { h.SignInfo.Signature[0] ^= 1 }, "mask": func(h *types.Header) { h.SignInfo.Exceptions[0] = 15 }, "mask_extra_bit": func(h *types.Header) { h.SignInfo.Exceptions[0] = 255 }, "view_number": func(h *types.Header) { h.SignInfo.ViewNumber++ }, "view_id": func(h *types.Header) { h.SignInfo.ViewID[0] ^= 1 }, "leader": func(h *types.Header) { h.SignInfo.LeaderID += "wrong" }, "extra_hash": func(h *types.Header) { h.SignInfo.ExtraHash[0] ^= 1 }, "parent_qc": func(h *types.Header) { h.SignInfo.ParentQCID[0] ^= 1 }, "single_qc": func(h *types.Header) { h.SignInfo.FHSFinalityProof = nil },
	}
	for name, mutate := range headerCases {
		t.Run(name, func(t *testing.T) {
			e := cloneRolling(t, original)
			alterHeader(t, &e, mutate)
			out, target, err := f.v.VerifyRolling(base, 0, e)
			if err == nil || out != nil || target != (Anchor{}) {
				t.Fatal("tamper granted credit/anchor")
			}
		})
	}
	refCases := map[string]func(*types.HotstuffProposalRef){"chain": func(r *types.HotstuffProposalRef) { r.ChainID++ }, "body_hash": func(r *types.HotstuffProposalRef) { r.BodyHash[0] ^= 1 }, "body_size": func(r *types.HotstuffProposalRef) { r.BodySize++ }, "header_hash": func(r *types.HotstuffProposalRef) { r.BlockHash[0] ^= 1 }, "version": func(r *types.HotstuffProposalRef) { r.Version++ }}
	for name, mutate := range refCases {
		t.Run("ref_"+name, func(t *testing.T) {
			e := cloneRolling(t, original)
			alterRef(t, &e, mutate)
			if _, _, err := f.v.VerifyRolling(base, 0, e); err == nil {
				t.Fatal("ref tamper accepted")
			}
		})
	}
	for _, name := range []string{"view_gap", "parent_qc", "parent_hash", "height", "signature", "single_empty", "too_many"} {
		t.Run("descendant_"+name, func(t *testing.T) {
			e := cloneRolling(t, original)
			alterHeader(t, &e, func(h *types.Header) {
				var proof finalityEnvelope
				if err := rlp.DecodeBytes(h.SignInfo.FHSFinalityProof, &proof); err != nil {
					t.Fatal(err)
				}
				q, err := hotstuff.DecodeSignedState(proof.QCs[0])
				if err != nil {
					t.Fatal(err)
				}
				r, err := types.DecodeHotstuffProposalRef(q.State)
				if err != nil {
					t.Fatal(err)
				}
				switch name {
				case "view_gap":
					r.ViewNumber = 3
					r.ViewID = common.Hash{3}
					i, _ := LeaderIndex(f.v.seed, f.v.chainID, 3, f.v.epochs[0].committeeHash)
					r.LeaderID = f.v.epochs[0].leaders[i]
				case "parent_qc":
					r.ParentQCID[0] ^= 1
				case "parent_hash":
					r.ParentHash[0] ^= 1
				case "height":
					r.Number++
				case "signature":
					q.Sign[0] ^= 1
				}
				if name != "signature" {
					q = f.sign(t, r)
				}
				proof.QCs[0], _ = hotstuff.EncodeSignedState(q)
				if name == "single_empty" {
					proof.QCs = nil
				}
				if name == "too_many" {
					for len(proof.QCs) <= MaxDescendants {
						proof.QCs = append(proof.QCs, proof.QCs[0])
					}
				}
				h.SignInfo.FHSFinalityProof, _ = rlp.EncodeToBytes(proof)
			})
			if _, _, err := f.v.VerifyRolling(base, 0, e); err == nil {
				t.Fatal("bad finality accepted")
			}
		})
	}
	// Valid signatures do not authorize a fork detached from the trusted base.
	orphan := f.makeBlock(t, common.Hash{44}, f.block.Root())
	w, err := BuildHeaderWitness(f.config.ChainID, orphan)
	if err != nil {
		t.Fatal(err)
	}
	e := cloneRolling(t, original)
	e.Headers[0] = w
	if _, _, err = f.v.VerifyRolling(base, 0, e); !errors.Is(err, ErrRollingBase) {
		t.Fatalf("orphan: %v", err)
	}
}

func TestRollingRejectBaseAndPartialStorageProofs(t *testing.T) {
	f, base, original := rollingFixture(t)
	for name, change := range map[string]func(*Anchor){"chain": func(a *Anchor) { a.ChainID++ }, "genesis": func(a *Anchor) { a.Genesis[0] ^= 1 }, "dex": func(a *Anchor) { a.DEXID[0] ^= 1 }, "custody": func(a *Anchor) { a.Custody[0] ^= 1 }, "key": func(a *Anchor) { a.SourceKeyHash[0] ^= 1 }, "committee": func(a *Anchor) { a.SourceCommittee[0] ^= 1 }, "epoch": func(a *Anchor) { a.SourceEpoch++ }, "genesis_root": func(a *Anchor) { a.StateRoot[0] ^= 1 }, "overflow_height": func(a *Anchor) { a.Height = math.MaxUint64 }} {
		t.Run(name, func(t *testing.T) {
			bad := base
			change(&bad)
			e := cloneRolling(t, original)
			e.Base, _ = bad.ID()
			if _, _, err := f.v.VerifyRolling(bad, 0, e); err == nil {
				t.Fatal("base mismatch accepted")
			}
		})
	}
	for _, name := range []string{"base_id", "cursor", "cursor_overflow", "account_missing", "account_corrupt", "count_missing", "count_duplicate", "entry_missing", "entry_corrupt", "entry_duplicate", "amount", "owner", "entry_domain", "index_gap"} {
		t.Run(name, func(t *testing.T) {
			e := cloneRolling(t, original)
			start := uint64(0)
			switch name {
			case "base_id":
				e.Base[0] ^= 1
			case "cursor":
				start = 1
			case "cursor_overflow":
				start = math.MaxUint64
			case "account_missing":
				e.AccountProof = nil
			case "account_corrupt":
				e.AccountProof[0][0] ^= 1
			case "count_missing":
				e.CountProof = nil
			case "count_duplicate":
				e.CountProof = append(e.CountProof, e.CountProof[0])
			case "entry_missing":
				e.Entries[0].Proof = nil
			case "entry_corrupt":
				e.Entries[0].Proof[0][0] ^= 1
			case "entry_duplicate":
				e.Entries[0].Proof = append(e.Entries[0].Proof, e.Entries[0].Proof[0])
			case "amount":
				e.Entries[0].Entry.Amount[31]++
			case "owner":
				e.Entries[0].Entry.Owner[0]++
			case "entry_domain":
				e.Entries[0].Entry.DEXID[0]++
			case "index_gap":
				e.Entries[1].Entry.Index++
			}
			if out, target, err := f.v.VerifyRolling(base, start, e); err == nil || out != nil || target != (Anchor{}) {
				t.Fatal("bad storage/domain granted capability")
			}
		})
	}
	_, target, err := f.v.VerifyRolling(base, 0, original)
	if err != nil {
		t.Fatal(err)
	}
	for _, delta := range []int{-1, 1} {
		bad := target
		bad.InboxCount = uint64(int(bad.InboxCount) + delta)
		id, _ := bad.ID()
		e, err := BuildRollingEvidence(id, nil, f.state, nil, f.config.Custody)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = f.v.VerifyRolling(bad, 3, e); err == nil {
			t.Fatal("same-root count conflict accepted")
		}
	}
}

func TestRollingIngressIsNotContinuityAuthorization(t *testing.T) {
	f, base, e := rollingFixture(t)
	e.Base[0] ^= 1
	if err := f.v.VerifyRollingPayload(e); err != nil {
		t.Fatal("partial auth must not claim base continuity", err)
	}
	if _, _, err := f.v.VerifyRolling(base, 0, e); !errors.Is(err, ErrRollingBase) {
		t.Fatal("execution failed to enforce base", err)
	}
	id, _ := base.ID()
	shape := RollingEvidence{Base: id, AccountProof: [][]byte{{0xc0}}}
	if err := f.v.VerifyRollingPayload(shape); err != nil {
		t.Fatal("same-anchor ingress is shape-only", err)
	}
	if out, _, err := f.v.VerifyRolling(base, 0, shape); err == nil || out != nil {
		t.Fatal("shape-only ingress granted credit")
	}
}

func TestRollingCodecBoundsBeforeVerification(t *testing.T) {
	f, _, original := rollingFixture(t)
	for _, name := range []string{"headers", "witness_bytes", "reference_bytes", "account_nodes", "node_bytes", "entries", "aggregate"} {
		t.Run(name, func(t *testing.T) {
			e := cloneRolling(t, original)
			switch name {
			case "headers":
				for len(e.Headers) <= MaxAncestryBlocks {
					e.Headers = append(e.Headers, e.Headers[0])
				}
			case "witness_bytes":
				e.Headers[0].Header = make([]byte, MaxHeaderWitnessBytes)
			case "reference_bytes":
				e.Headers[0].ProposalRef = make([]byte, MaxRefBytes+1)
			case "account_nodes":
				for len(e.AccountProof) <= MaxProofNodes {
					e.AccountProof = append(e.AccountProof, e.AccountProof[0])
				}
			case "node_bytes":
				e.AccountProof[0] = make([]byte, MaxProofNodeBytes+1)
			case "entries":
				for len(e.Entries) <= protocol.MaxDepositsPerCheckpoint {
					e.Entries = append(e.Entries, e.Entries[0])
				}
			case "aggregate":
				e.Entries = nil
				p := make([][]byte, MaxProofNodes)
				for i := range p {
					p[i] = make([]byte, MaxProofNodeBytes)
				}
				for i := 0; i < protocol.MaxDepositsPerCheckpoint; i++ {
					e.Entries = append(e.Entries, EntryProof{original.Entries[0].Entry, p})
				}
			}
			if _, err := EncodeRollingEvidence(e); err == nil {
				t.Fatal("oversize encoding accepted")
			}
			w := rollingEnvelope{Version: 2, Base: e.Base, Headers: e.Headers, AccountProof: e.AccountProof, CountProof: e.CountProof}
			for _, p := range e.Entries {
				raw, _ := p.Entry.Encode()
				w.Entries = append(w.Entries, evidenceEntry{raw, p.Proof})
			}
			raw, err := rlp.EncodeToBytes(w)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = DecodeRollingEvidence(raw); err == nil {
				t.Fatal("oversize decode accepted")
			}
		})
	}
	raw, _ := EncodeRollingEvidence(original)
	for _, bad := range [][]byte{nil, raw[:len(raw)-1], append(bytes.Clone(raw), 0), make([]byte, MaxEvidenceBytes+1)} {
		if _, err := DecodeRollingEvidence(bad); err == nil {
			t.Fatal("malformed wire accepted")
		}
	}
	if _, err := BuildHeaderWitness(1, nil); !errors.Is(err, ErrRollingUnavailable) {
		t.Fatal("missing block not unavailable")
	}
	for _, missing := range []string{"finality", "signature"} {
		h := f.block.Header()
		if missing == "finality" {
			h.SignInfo.FHSFinalityProof = nil
		} else {
			h.SignInfo.Signature = nil
		}
		if _, err := BuildHeaderWitness(f.config.ChainID, types.NewBlockWithHeader(h)); !errors.Is(err, ErrRollingUnavailable) {
			t.Fatalf("missing %s not unavailable: %v", missing, err)
		}
	}
	if _, err := BuildRollingEvidence(original.Base, nil, unavailableRollingSource{}, nil, common.Address{9}); !errors.Is(err, ErrRollingUnavailable) {
		t.Fatal("missing historical trie not unavailable", err)
	}
}

type unavailableRollingSource struct{}

func (unavailableRollingSource) GetProof(common.Address) ([][]byte, error) {
	return nil, errors.New("pruned account data")
}
func (unavailableRollingSource) GetStorageProof(common.Address, common.Hash) ([][]byte, error) {
	return nil, errors.New("pruned storage data")
}
