package settlement

import (
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// Genuine registered fixture signatures over a long gapped DEX chain. This
// helper tests CLX's committee-proof boundary, not DEX execution correctness.
func (f *fixture) historyProof(t *testing.T, c protocol.Checkpoint) []byte {
	t.Helper()
	if c.Sequence != 1 || c.DataSchema != 6 {
		t.Fatal("history native fixture scope")
	}
	sign := func(ref *types.HotstuffProposalRef) *hotstuff.SignedState {
		var aggregate *bls.Sign
		for i := 0; i < 5; i++ {
			s, err := hotstuff.SignFHSSignatureWithContext(&f.keys[i], f.keys[i].GetPublicKey(), ref.EncodeToBytes(), ref.ChainID, hotstuff.MsgVotePrepare, ref.ViewID, ref.LeaderID)
			if err != nil {
				t.Fatal(err)
			}
			if aggregate == nil {
				aggregate = s
			} else {
				aggregate.Add(s)
			}
		}
		return &hotstuff.SignedState{State: ref.EncodeToBytes(), Sign: aggregate.Serialize(), Mask: []byte{31}, ViewID: ref.ViewID, LeaderID: ref.LeaderID, Number: ref.ViewNumber}
	}
	var frontier protocol.HistoryFrontier
	var ids []protocol.Hash
	var qcs []*hotstuff.SignedState
	for height := uint64(1); height <= 21; height++ {
		if height > 1 {
			id, _ := hotstuff.SignedStateID(qcs[len(qcs)-1])
			ids = append(ids, protocol.Hash(id.Hash()))
			if err := frontier.AppendQCID(ids[len(ids)-1]); err != nil {
				t.Fatal(err)
			}
		}
		root, err := frontier.Root()
		if err != nil {
			t.Fatal(err)
		}
		action := protocol.Hash{81, byte(height)}
		data, err := protocol.HistoryDataRoot(action, root, frontier.Count)
		if err != nil {
			t.Fatal(err)
		}
		view := height*2 - 1
		if height == 21 {
			view--
		}
		ref := &types.HotstuffProposalRef{Version: types.HotstuffProposalRefVersion, ChainID: c.ChainID, Number: height, ViewNumber: view, ViewID: common.Hash{byte(view), 54}, LeaderID: bftview.GetNodeID(f.nodes[(view-1)%7].Address, f.nodes[(view-1)%7].Public), BlockHash: common.Hash{82, byte(height)}, ParentHash: common.Hash{83}, StateRoot: common.Hash(c.PostRoot), BodyHash: common.Hash(data), BodySize: 8, ExtraHash: types.HotstuffProposalExtraHash(nil), KeyHash: common.Hash(c.Domain().EpochKey()), Time: height}
		if height == 1 {
			hash, e := c.Hash()
			if e != nil {
				t.Fatal(e)
			}
			ref.BlockHash = common.Hash(hash)
			ref.BodyHash = common.Hash(c.DataRoot)
		} else {
			parent, _ := types.DecodeHotstuffProposalRef(qcs[len(qcs)-1].State)
			ref.ParentHash = parent.BlockHash
			ref.ParentQCID = common.Hash(ids[len(ids)-1])
		}
		qcs = append(qcs, sign(ref))
	}
	path, err := protocol.BuildHistoryProof(ids[:19], 0)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := checkpoint.EncodeProofV2(checkpoint.Proof{Target: qcs[0], Descendants: []*hotstuff.SignedState{qcs[19], qcs[20]}, History: &checkpoint.HistoryWitness{Count: 19, ActionRoot: protocol.Hash{81, 20}, Siblings: path}})
	if err != nil {
		t.Fatal(err)
	}
	return proof
}
