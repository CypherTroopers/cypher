package clxevidence_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/devnet"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/relay"
	"github.com/cypherium/cypher/dex/relay/source"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

type noInboxSigner struct{ calls int }

func (s *noInboxSigner) Sign(context.Context, common.Address, *types.Transaction, *big.Int) (*types.Transaction, error) {
	s.calls++
	return nil, errors.New("inbox must never sign a native transaction")
}

func observationBundle(t *testing.T, cp protocol.Checkpoint, finance protocol.FinanceSummary, members []*common.Cnode) []byte {
	t.Helper()
	var err error
	cp.FundingRef, err = finance.Hash()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := cp.Hash()
	if err != nil {
		t.Fatal(err)
	}
	ref := &types.HotstuffProposalRef{Version: types.HotstuffProposalRefVersion, ChainID: cp.ChainID, Number: 1, ViewNumber: 1, ViewID: common.Hash{1}, LeaderID: bftview.GetNodeID(members[0].Address, members[0].Public), BlockHash: common.Hash(hash), ParentHash: common.Hash{3}, StateRoot: common.Hash(cp.PostRoot), BodyHash: common.Hash(cp.DataRoot), BodySize: 8, ExtraHash: types.HotstuffProposalExtraHash(nil), KeyHash: common.Hash(cp.Domain().EpochKey()), Time: 1}
	sign := func(r *types.HotstuffProposalRef) *hotstuff.SignedState {
		var sig *bls.Sign
		for i := 0; i < 5; i++ {
			var k bls.SecretKey
			if err := k.SetDecString(fmt.Sprint(1200 + i)); err != nil {
				t.Fatal(err)
			}
			s, err := hotstuff.SignFHSSignatureWithContext(&k, k.GetPublicKey(), r.EncodeToBytes(), r.ChainID, hotstuff.MsgVotePrepare, r.ViewID, r.LeaderID)
			if err != nil {
				t.Fatal(err)
			}
			if sig == nil {
				sig = s
			} else {
				sig.Add(s)
			}
		}
		return &hotstuff.SignedState{State: r.EncodeToBytes(), Sign: sig.Serialize(), Mask: []byte{31}, ViewID: r.ViewID, LeaderID: r.LeaderID, Number: r.ViewNumber}
	}
	q := sign(ref)
	child := *ref
	child.Number = 2
	child.Time = 2
	child.ViewNumber = 2
	child.ViewID = common.Hash{2}
	child.LeaderID = bftview.GetNodeID(members[1].Address, members[1].Public)
	child.ParentHash = ref.BlockHash
	child.BlockHash = common.Hash{9}
	id, err := hotstuff.SignedStateID(q)
	if err != nil {
		t.Fatal(err)
	}
	child.ParentQCID = id.Hash()
	proof, err := checkpoint.EncodeProof(checkpoint.Proof{Target: q, Descendants: []*hotstuff.SignedState{sign(&child)}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := checkpoint.BuildSettlementBundle(cp, proof, finance, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := checkpoint.EncodeSettlementBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Source observations use actual HTTP, actual signed source headers and MPT
// paths. DEX bundle signatures are registered committee fixtures. A bundle is
// not a validity proof, and these tests do not infer correct trading from a QC.
func TestRelayInboxCompletionNeedsWholeProofBoundEffect(t *testing.T) {
	src := newSourceHTTP(t, 1)
	members := make([]*common.Cnode, 7)
	for i, node := range src.f.Config.ChainConfig.DEXDevnet.Committee {
		n := node
		members[i] = &n
	}
	d := protocol.Domain{Version: 1, ChainID: src.f.Config.ChainID, Genesis: protocol.Hash(src.f.Config.Genesis.Hash()), DEXID: src.f.Config.DEXID, Epoch: 1, Committee: protocol.Hash((&bftview.Committee{List: members}).RlpHash())}
	custody := src.f.Config.Custody
	genesis, err := protocol.NativeGenesisRootV3(protocol.Hash(src.f.Config.ChainConfig.DEXDevnet.GenesisSeed), d, [20]byte(custody))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"matching-range", "cursor-only", "wrong-entry-root", "empty-exact-action", "empty-equivalent-anchor", "empty-conflicting-anchor", "altered-entry-amount", "forged-same-hash-metadata", "untrusted-target"} {
		t.Run(name, func(t *testing.T) {
			var bundle []byte
			var bundleMu sync.Mutex
			dex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/status" {
					json.NewEncoder(w).Encode(struct{ Finalized uint64 }{1})
					return
				}
				if r.URL.Path == "/v1/settlement" {
					bundleMu.Lock()
					defer bundleMu.Unlock()
					json.NewEncoder(w).Encode(struct{ Bytes []byte }{bundle})
					return
				}
				t.Error("unexpected DEX submission")
				http.Error(w, "unexpected", 400)
			}))
			defer dex.Close()
			c := relay.Config{Devnet: true, Domain: d, Custody: custody, Payers: map[relay.Lane]common.Address{relay.Anchor: {19: 90}, relay.Checkpoint: {19: 91}, relay.Claim: {19: 92}}, GasLimits: map[relay.Lane]uint64{relay.Anchor: 1, relay.Checkpoint: 1, relay.Claim: 1}, GasPrice: big.NewInt(1), MaxGasCost: big.NewInt(1)}
			n, err := relay.OpenNetwork(relay.NetworkConfig{Relay: c, Source: source.Config{Endpoint: src.server.URL, Dir: filepath.Join(t.TempDir(), "source"), CLX: src.f.Config}, SubmitURL: src.server.URL, DEXURL: dex.URL, MaxHeight: 4})
			if err != nil {
				t.Fatal(err)
			}
			defer n.Close()
			seg, err := n.Source.Advance(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			empty := name == "empty-exact-action" || name == "empty-equivalent-anchor" || name == "empty-conflicting-anchor"
			e := src.f.Evidence(t, seg.Base, 1, 0, !empty)
			if name == "altered-entry-amount" {
				e.Entries[0].Entry.Amount[31]++
			}
			if name == "forged-same-hash-metadata" {
				var h types.Header
				if err = rlp.DecodeBytes(e.Headers[0].Header, &h); err != nil {
					t.Fatal(err)
				}
				before := h.Hash()
				h.SignInfo.Signature[0] ^= 1
				if h.Hash() != before {
					t.Fatal("signature changed block hash")
				}
				e.Headers[0].Header, err = rlp.EncodeToBytes(&h)
				if err != nil {
					t.Fatal(err)
				}
			}
			payload, err := devnet.EncodeRollingInboxAction(e)
			if err != nil {
				t.Fatal(err)
			}
			entries := make([]protocol.InboxEntry, len(e.Entries))
			for i, p := range e.Entries {
				entries[i] = p.Entry
			}
			root, err := protocol.InboxEntriesRoot(entries)
			if err != nil {
				t.Fatal(err)
			}
			var rawKey [48]byte
			binary.BigEndian.PutUint64(rawKey[8:16], uint64(len(entries)))
			copy(rawKey[16:], root[:])
			key := protocol.Digest("common-dex/relay-inbox-key/v1", rawKey[:])
			if empty {
				key, _ = seg.Target.ID()
			}
			target := seg.Target
			if name == "untrusted-target" {
				target.StateRoot[0]++
			}
			auth, err := target.Encode()
			if err != nil {
				t.Fatal(err)
			}
			j := relay.Job{Version: 1, Lane: relay.Inbox, ID: relay.BusinessID(d, custody, relay.Inbox, key), Payload: payload, Authorization: auth}
			cp := protocol.Checkpoint{Version: 1, ProofMode: 1, ChainID: d.ChainID, Genesis: d.Genesis, DEXID: d.DEXID, Epoch: 1, Committee: d.Committee, Sequence: 1, PreRoot: genesis, PostRoot: protocol.Hash{9}, FirstBlock: 1, LastBlock: 1, CLXHeight: 1, CLXHash: seg.Target.BlockHash, InboxEnd: uint64(len(entries)), InboxRoot: root, DataRoot: protocol.Hash{8}, DataSchema: 4}
			f := protocol.FinanceSummary{Version: 1, Domain: d, Custody: [20]byte(custody), Sequence: 1}
			if len(entries) > 0 {
				f.DepositTotal = entries[0].Amount
			}
			if name == "cursor-only" {
				cp.InboxStart = 3
				cp.InboxEnd = 3
				cp.InboxRoot = protocol.Hash{}
				f.DepositTotal = protocol.Amount{}
			}
			if name == "wrong-entry-root" {
				cp.InboxRoot[0]++
			}
			if name == "empty-exact-action" {
				cp.DataRoot, err = consensus.ComputeExecutionDataRoot(payload)
				if err != nil {
					t.Fatal(err)
				}
			}
			if name == "empty-conflicting-anchor" {
				cp.CLXHash[0] ^= 1
			}
			bundleMu.Lock()
			bundle = observationBundle(t, cp, f, members)
			bundleMu.Unlock()
			signer := new(noInboxSigner)
			r, err := relay.Open(filepath.Join(t.TempDir(), "relay"), c, n, signer)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if err = r.Enqueue(j); err != nil {
				t.Fatal(err)
			}
			err = r.Step(context.Background())
			bad := name == "altered-entry-amount" || name == "forged-same-hash-metadata" || name == "untrusted-target"
			if bad && !errors.Is(err, relay.ErrInvalidJob) {
				t.Fatal("unauthenticated job not rejected", err)
			}
			if !bad && err != nil {
				t.Fatal(err)
			}
			phase := r.Status()[0].Phase
			// An empty update has no credit effect. Its semantic result is the
			// source-authenticated anchor in a finalized DEX checkpoint, even
			// when another relay used different action bytes. The adjacent
			// negative still rejects a quorum-certified conflicting anchor.
			complete := name == "matching-range" || name == "empty-exact-action" || name == "empty-equivalent-anchor"
			if complete && phase != "complete" || !complete && phase == "complete" || signer.calls != 0 {
				t.Fatal("false inbox completion/native signing", phase, signer.calls)
			}
			if bad && phase != "quarantined" {
				t.Fatal("bad authorization remains eligible", phase)
			}
			if name == "empty-conflicting-anchor" && phase != "nonce_conflict" {
				t.Fatal("conflicting source anchor was not isolated", phase)
			}
		})
	}
}
