package reconfig_test

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/rewards"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// Reproduces the height25 retained-set shape which stopped long trial2. All
// thirteen certificates carry real five-collector signatures; no fake receipt
// or relaxed production reward rule is involved in the test selection.
func TestContinuousParticipationSelectsAuthenticatedProposal(t *testing.T) {
	keys := make([]bls.SecretKey, 7)
	members := make([]*common.Cnode, 7)
	recipients := make([][20]byte, 7)
	for i := range keys {
		if err := keys[i].SetDecString(fmt.Sprint(71 + i)); err != nil {
			t.Fatal(err)
		}
		recipients[i][19] = byte(i + 1)
		members[i] = &common.Cnode{Address: fmt.Sprintf("continuous-participation-%d", i), Public: keys[i].GetPublicKey().SerializeToHexStr(), CoinBase: common.Address(recipients[i]).Hex()}
	}
	domain := protocol.Domain{Version: 1, ChainID: 9127001, Genesis: protocol.Hash{1}, DEXID: protocol.Hash{2}, Epoch: 1, Committee: protocol.Hash((&bftview.Committee{List: members}).RlpHash())}
	registry, err := rewards.NewRegistry(domain, members, recipients)
	if err != nil {
		t.Fatal(err)
	}
	collectors := make([]*rewards.Collector, 5)
	for i := range collectors {
		collectors[i], err = rewards.OpenCollector(filepath.Join(t.TempDir(), "collector"), registry, uint8(i), &keys[i])
		if err != nil {
			t.Fatal(err)
		}
		c := collectors[i]
		t.Cleanup(func() { c.Shutdown() })
	}
	makeRef := func(view uint64) *types.HotstuffProposalRef {
		return &types.HotstuffProposalRef{Version: types.HotstuffProposalRefVersion, ChainID: domain.ChainID, Number: 25, ViewNumber: view, ViewID: common.Hash{byte(view)}, LeaderID: members[(view-1)%7].Address, BlockHash: common.Hash{1, byte(view)}, ParentHash: common.Hash{2}, StateRoot: common.Hash{3}, BodyHash: common.Hash{4}, BodySize: 8, ExtraHash: types.HotstuffProposalExtraHash(nil), KeyHash: common.Hash(domain.EpochKey()), Time: 25}
	}
	prior, target := makeRef(66), makeRef(67)
	var all []rewards.Certificate
	for group, ref := range []*types.HotstuffProposalRef{prior, target} {
		raw := ref.EncodeToBytes()
		watermark := &hotstuff.PersistedVote{ViewNumber: ref.ViewNumber, ViewID: ref.ViewID, LeaderID: ref.LeaderID, ProposalRef: raw, ProposalID: ref.ProposalID(), ProposalRefHash: hotstuff.StateDigest(raw)}
		for _, collector := range collectors {
			if err := collector.BeforeVote(watermark); err != nil {
				t.Fatal(err)
			}
		}
		for participant := 0; participant < 6+group; participant++ {
			sig, err := hotstuff.SignFHSSignatureWithContext(&keys[participant], keys[participant].GetPublicKey(), raw, domain.ChainID, hotstuff.MsgVotePrepare, ref.ViewID, ref.LeaderID)
			if err != nil {
				t.Fatal(err)
			}
			vote := &hotstuff.HotstuffMessage{Code: hotstuff.MsgVotePrepare, Number: ref.ViewNumber, ViewId: ref.ViewID, Id: members[participant].Address, PubKey: keys[participant].GetPublicKey().Serialize(), DataC: sig.Serialize()}
			var receipts []rewards.Receipt
			for _, collector := range collectors {
				receipt, err := collector.Issue(raw, vote)
				if err != nil {
					t.Fatal(err)
				}
				receipts = append(receipts, receipt)
			}
			cert, err := registry.Certificate(receipts)
			if err != nil {
				t.Fatal(err)
			}
			if err = collectors[0].RememberCertificate(cert); err != nil {
				t.Fatal(err)
			}
			all = append(all, cert)
		}
	}
	retained, err := collectors[0].Certificates(25)
	if err != nil || len(retained) != 13 {
		t.Fatal("multi-view retained fixture", len(retained), err)
	}
	selected, err := continuousSelectCertificates(registry, target, retained)
	if err != nil || len(selected) != 7 {
		t.Fatal("current proposal selection", len(selected), err)
	}
	for i, cert := range selected {
		if int(cert.Duty.Participant) != i || cert.Duty.View != 67 || cert.Duty.ProposalID != protocol.Hash(target.ProposalID()) {
			t.Fatal("wrong participant/proposal")
		}
	}
	old, err := continuousSelectCertificates(registry, prior, retained)
	if err != nil || len(old) != 6 {
		t.Fatal("prior proposal selection", len(old), err)
	}
	after, err := collectors[0].Certificates(25)
	if err != nil || len(after) != 13 {
		t.Fatal("selection erased retained evidence", err)
	}
	duplicate := append(append([]rewards.Certificate(nil), retained...), selected[0])
	if _, err := continuousSelectCertificates(registry, target, duplicate); err == nil {
		t.Fatal("duplicate eligible duty accepted")
	}
	bad := append([]rewards.Certificate(nil), retained...)
	bad[0].Signatures = append([]rewards.CollectorSignature(nil), bad[0].Signatures...)
	bad[0].Signatures[0].Signature[0] ^= 1
	if _, err := continuousSelectCertificates(registry, target, bad); err == nil {
		t.Fatal("invalid alternative-view evidence accepted")
	}
}
