package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

type auditRoundTripper func(*http.Request) (*http.Response, error)

func (f auditRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func auditBundle(t *testing.T, domain protocol.Domain, nodes []*common.Cnode, keys []bls.SecretKey, cp protocol.Checkpoint, finance protocol.FinanceSummary, withdrawals ...protocol.Claim) []byte {
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
	ref := &types.HotstuffProposalRef{Version: types.HotstuffProposalRefVersion, ChainID: domain.ChainID, Number: cp.LastBlock, ViewNumber: cp.Sequence, ViewID: common.Hash{byte(cp.Sequence), 42}, LeaderID: bftview.GetNodeID(nodes[(cp.Sequence-1)%7].Address, nodes[(cp.Sequence-1)%7].Public), BlockHash: common.Hash(hash), ParentHash: common.Hash{99}, StateRoot: common.Hash(cp.PostRoot), BodyHash: common.Hash(cp.DataRoot), BodySize: 8, ExtraHash: types.HotstuffProposalExtraHash(nil), KeyHash: common.Hash(domain.EpochKey()), Time: cp.LastBlock}
	sign := func(r *types.HotstuffProposalRef) *hotstuff.SignedState {
		var aggregate *bls.Sign
		for i := 0; i < 5; i++ {
			s, e := hotstuff.SignFHSSignatureWithContext(&keys[i], keys[i].GetPublicKey(), r.EncodeToBytes(), r.ChainID, hotstuff.MsgVotePrepare, r.ViewID, r.LeaderID)
			if e != nil {
				t.Fatal(e)
			}
			if aggregate == nil {
				aggregate = s
			} else {
				aggregate.Add(s)
			}
		}
		return &hotstuff.SignedState{State: r.EncodeToBytes(), Sign: aggregate.Serialize(), Mask: []byte{31}, ViewID: r.ViewID, LeaderID: r.LeaderID, Number: r.ViewNumber}
	}
	q := sign(ref)
	child := *ref
	child.Number++
	child.Time++
	child.ViewNumber++
	child.ViewID[0]++
	child.LeaderID = bftview.GetNodeID(nodes[(child.ViewNumber-1)%7].Address, nodes[(child.ViewNumber-1)%7].Public)
	child.ParentHash = ref.BlockHash
	child.BlockHash = common.Hash{byte(cp.Sequence), 88}
	id, err := hotstuff.SignedStateID(q)
	if err != nil {
		t.Fatal(err)
	}
	child.ParentQCID = id.Hash()
	encoder := checkpoint.EncodeProof
	if cp.DataSchema == 6 {
		encoder = checkpoint.EncodeProofV2
	}
	proof, err := encoder(checkpoint.Proof{Target: q, Descendants: []*hotstuff.SignedState{sign(&child)}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := checkpoint.BuildSettlementBundle(cp, proof, finance, withdrawals, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := checkpoint.EncodeSettlementBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestNetworkDiscoveryRequiresAuthenticatedSequentialBundles(t *testing.T) {
	keys := make([]bls.SecretKey, 7)
	nodes := make([]*common.Cnode, 7)
	for i := range keys {
		if err := keys[i].SetDecString(fmt.Sprint(9100 + i)); err != nil {
			t.Fatal(err)
		}
		nodes[i] = &common.Cnode{Address: fmt.Sprintf("127.0.0.1:%d", 30000+i), Public: keys[i].GetPublicKey().SerializeToHexStr(), CoinBase: common.Address{19: byte(i + 1)}.Hex()}
	}
	d := protocol.Domain{Version: 1, ChainID: 9001, Genesis: protocol.Hash{1}, DEXID: protocol.Hash{2}, Epoch: 1, Committee: protocol.Hash((&bftview.Committee{List: nodes}).RlpHash())}
	epoch, err := checkpoint.NewEpoch(d, 1, math.MaxUint64, nodes)
	if err != nil {
		t.Fatal(err)
	}
	custody := common.Address{19: 240}
	genesis := protocol.Hash{3}
	cp := protocol.Checkpoint{Version: 1, ProofMode: 1, ChainID: d.ChainID, Genesis: d.Genesis, DEXID: d.DEXID, Epoch: d.Epoch, Committee: d.Committee, Sequence: 1, PreRoot: genesis, PostRoot: protocol.Hash{4}, FirstBlock: 1, LastBlock: 1, CLXHeight: 1, CLXHash: protocol.Hash{5}, DataRoot: protocol.Hash{6}, DataSchema: 4}
	finance := protocol.FinanceSummary{Version: 1, Domain: d, Custody: [20]byte(custody), Sequence: 1}
	for _, name := range []string{"valid", "untrusted-height-only", "wrong-signature", "foreign-custody", "pre-root", "previous", "sequence", "schema", "height-bound", "missing-data"} {
		t.Run(name, func(t *testing.T) {
			c, f := cp, finance
			status := uint64(1)
			switch name {
			case "foreign-custody":
				f.Custody[0]++
			case "pre-root":
				c.PreRoot[0]++
			case "previous":
				c.Previous[0]++
			case "sequence":
				c.Sequence = 2
				c.FirstBlock = 2
				c.LastBlock = 2
				f.Sequence = 2
			case "schema":
				c.DataSchema = 3
			case "height-bound":
				status = 129
			case "untrusted-height-only":
				status = 128
			}
			body := auditBundle(t, d, nodes, keys, c, f)
			if name == "wrong-signature" {
				b, e := checkpoint.DecodeSettlementBundle(body)
				if e != nil {
					t.Fatal(e)
				}
				p, e := checkpoint.DecodeProof(b.Proof)
				if e != nil {
					t.Fatal(e)
				}
				p.Target.Sign[0] ^= 1
				b.Proof, e = checkpoint.EncodeProof(p)
				if e != nil {
					t.Fatal(e)
				}
				body, e = checkpoint.EncodeSettlementBundle(b)
				if e != nil {
					t.Fatal(e)
				}
			}
			n := &Network{cfg: NetworkConfig{Relay: Config{Domain: d, Custody: custody}, DEXURL: "http://127.0.0.1:1", MaxHeight: 128}, epoch: epoch, genesisRoot: genesis}
			n.http = &http.Client{Transport: auditRoundTripper(func(r *http.Request) (*http.Response, error) {
				var value interface{}
				if r.URL.Path == "/v1/status" {
					value = struct{ Finalized uint64 }{status}
				} else {
					height, _ := strconv.ParseUint(r.URL.Query().Get("height"), 10, 64)
					if name == "missing-data" || name == "untrusted-height-only" || height != 1 {
						return nil, errors.New("fixture unavailable")
					}
					value = struct{ Bytes []byte }{body}
				}
				raw, e := json.Marshal(value)
				if e != nil {
					return nil, e
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(raw)), Header: http.Header{}}, nil
			})}
			err := n.refreshDEX(context.Background())
			if name == "valid" {
				if err != nil || len(n.bundles) != 1 {
					t.Fatal("valid proof discovery", err)
				}
			} else if err == nil || len(n.bundles) != 0 {
				t.Fatal("untrusted discovery changed authenticated cache", name, err, len(n.bundles))
			}
		})
	}
}
