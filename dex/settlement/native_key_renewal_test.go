package settlement

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

func TestNativeAnchorVersionedStorageGolden(t *testing.T) {
	raw, err := os.ReadFile("../testdata/key_renewal.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Legacy  struct{ Encoded, ID string } `json:"legacy_anchor"`
		Anchors []struct{ Encoded, ID string }
	}
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	cases := append([]struct{ Encoded, ID string }{{vector.Legacy.Encoded, vector.Legacy.ID}}, vector.Anchors...)
	for _, c := range cases {
		encoded, err := hex.DecodeString(c.Encoded)
		if err != nil {
			t.Fatal(err)
		}
		anchor, err := clxevidence.DecodeAnchor(encoded)
		if err != nil {
			t.Fatal(err)
		}
		r := newRollingNativeFixture(t, true)
		a := &Adapter{db: stateWithError{r.state}, custody: common.Address(anchor.Custody)}
		id, _ := anchor.ID()
		if hex.EncodeToString(id[:]) != c.ID {
			t.Fatal("independent anchor ID")
		}
		a.writeBlob("rolling-anchor", anchor.Height, encoded)
		a.set("rolling-id", anchor.Height, common.Hash(id))
		a.set("rolling-evidence", anchor.Height, common.Hash{1})
		got, err := ReadNativeAnchor(r.state, a.custody, anchor.Height)
		if err != nil || got != anchor {
			t.Fatal("versioned anchor roundtrip", err)
		}
		keys, err := RollingAnchorStorageKeysVersion(anchor.Height, anchor.Version)
		if err != nil || len(keys) != (len(encoded)+31)/32+2 {
			t.Fatal("versioned storage bound", len(keys), err)
		}
		legacy, _ := RollingAnchorStorageKeys(anchor.Height)
		if len(legacy) != 10 || legacy[8] != key("rolling-id", anchor.Height, 0) || legacy[9] != key("rolling-evidence", anchor.Height, 0) {
			t.Fatal("legacy storage key API changed")
		}
		last := key("rolling-anchor", anchor.Height, uint32((len(encoded)-1)/32))
		value := r.state.GetState(a.custody, last)
		value[31] ^= 1
		r.state.SetState(a.custody, last, value)
		if _, err = ReadNativeAnchor(r.state, a.custody, anchor.Height); err == nil {
			t.Fatal("nonzero storage padding")
		}
	}
	if _, err := RollingAnchorStorageKeysVersion(1, 3); err == nil {
		t.Fatal("unknown version")
	}
}

// Real BLS/QC/header/MPT codecs with a registered fixed committee. This unit
// fixture is separate from the actual CLX process key-cadence evidence.
func nativeRenewalFixture(t *testing.T, permute bool) (*rollingNativeFixture, clxevidence.KeyContext, clxevidence.KeyContext) {
	t.Helper()
	r := newRollingNativeFixture(t, true)
	oldCommittee := (&bftview.Committee{List: r.f.nodes}).Copy()
	committee := oldCommittee.Copy()
	startView := uint64(1)
	carrierLeader := -1
	for ; startView < 1000; startView++ {
		leader, err := clxevidence.LeaderIndex(r.config.FairHotstuffSeed, r.config.ChainID.Uint64(), startView+1, oldCommittee.RlpHash())
		if err != nil {
			t.Fatal(err)
		}
		if (leader != 0) == permute {
			carrierLeader = int(leader)
			break
		}
	}
	if carrierLeader < 0 {
		t.Fatal("no bounded requested carrier PRF leader")
	}
	old := &types.KeyBlockHeader{Number: new(big.Int), Difficulty: big.NewInt(1), Time: 600, BlockType: types.TimeReconfig, CommitteeHash: committee.RlpHash()}
	r.ctx.GenesisKeyHash = old.Hash()
	oldRaw, _ := rlp.EncodeToBytes(old)
	committee.Add(nil, carrierLeader, "")
	next := &types.KeyBlockHeader{ParentHash: old.Hash(), Number: big.NewInt(1), Difficulty: big.NewInt(1), Time: 1200, BlockType: types.TimeReconfig, CommitteeHash: committee.RlpHash(), T_Number: 1}
	keyBlock := types.NewKeyBlock(next).WithBody(committee.In().Public, committee.In().CoinBase, "", "", committee.Leader().Public, committee.Leader().CoinBase)
	nextRaw, _ := rlp.EncodeToBytes(next)
	var err error
	r.verifier, err = r.f.a.nativeCLXVerifier(r.config, r.ctx)
	if err != nil {
		t.Fatal(err)
	}
	r.blocks = nil
	r.headers = nil
	parent := r.ctx.Genesis.Hash()
	var qcs []*hotstuff.SignedState
	for h := uint64(1); h <= 7; h++ {
		view := startView + h - 1
		keyHash := old.Hash()
		active := oldCommittee
		if h >= 4 {
			keyHash = next.Hash()
			active = committee
		}
		header := &types.Header{ParentHash: parent, Number: new(big.Int).SetUint64(h), Difficulty: big.NewInt(1), Root: r.source.IntermediateRoot(false), TxHash: types.EmptyRootHash, ReceiptHash: types.EmptyRootHash, KeyHash: keyHash, Time: 1200 + h}
		if h == 2 {
			header.BlockType = types.Key_Block
			header.KeyInfo = keyBlock.EncodeToBytes()
		}
		block := types.NewBlockWithHeader(header)
		leader, err := clxevidence.LeaderIndex(r.config.FairHotstuffSeed, r.config.ChainID.Uint64(), view, active.RlpHash())
		if err != nil {
			t.Fatal(err)
		}
		parentID := common.Hash{}
		if len(qcs) > 0 {
			id, _ := hotstuff.SignedStateID(qcs[len(qcs)-1])
			parentID = id.Hash()
		}
		ref, err := types.NewHotstuffProposalRefFromUnsignedBlockWithCommitments(r.config.ChainID.Uint64(), view, common.BigToHash(new(big.Int).SetUint64(view)), bftview.GetNodeID(active.List[leader].Address, active.List[leader].Public), block, types.HotstuffProposalExtraHash(nil), parentID)
		if err != nil {
			t.Fatal(err)
		}
		var signature *bls.Sign
		for i := 0; i < 5; i++ {
			keyIndex := -1
			for j, node := range r.f.nodes {
				if node.Public == active.List[i].Public {
					keyIndex = j
					break
				}
			}
			if keyIndex < 0 {
				t.Fatal("fixture committee introduced member")
			}
			sig, err := hotstuff.SignFHSSignatureWithContext(&r.f.keys[keyIndex], r.f.keys[keyIndex].GetPublicKey(), ref.EncodeToBytes(), r.config.ChainID.Uint64(), hotstuff.MsgVotePrepare, ref.ViewID, ref.LeaderID)
			if err != nil {
				t.Fatal(err)
			}
			if signature == nil {
				signature = sig
			} else {
				signature.Add(sig)
			}
		}
		qc := &hotstuff.SignedState{State: ref.EncodeToBytes(), Sign: signature.Serialize(), Mask: []byte{31}, ViewID: ref.ViewID, LeaderID: ref.LeaderID, Number: view}
		qcs = append(qcs, qc)
		block.SetFHSSignature(qc.Sign, qc.Mask, qc.ViewID, qc.LeaderID, qc.Number, ref.ExtraHash, ref.ParentQCID)
		r.blocks = append(r.blocks, block)
		parent = block.Hash()
	}
	for i := 0; i < 6; i++ {
		raw, _ := hotstuff.EncodeSignedState(qcs[i+1])
		proof, _ := rlp.EncodeToBytes(struct {
			Version uint32
			QCs     [][]byte
		}{2, [][]byte{raw}})
		if err := r.blocks[i].SetFHSFinalityProof(proof); err != nil {
			t.Fatal(err)
		}
		w, err := clxevidence.BuildHeaderWitness(r.config.ChainID.Uint64(), r.blocks[i])
		if err != nil {
			t.Fatal(err)
		}
		r.headers = append(r.headers, w)
	}
	id, _ := hotstuff.SignedStateID(qcs[2])
	r.ctx.BlockNumber = 10
	oldContext := clxevidence.KeyContext{KeyHeader: oldRaw}
	newContext := clxevidence.KeyContext{KeyHeader: nextRaw, Boundary: []protocol.Hash{protocol.Hash(id.Hash())}}
	if permute {
		oldContext.Order = []uint8{0, 1, 2, 3, 4, 5, 6}
		newContext.PreviousKeyHeader = oldRaw
		newContext.PreviousOrder = append([]uint8(nil), oldContext.Order...)
		for _, node := range committee.List {
			for j, original := range r.f.nodes {
				if original.Public == node.Public {
					newContext.Order = append(newContext.Order, uint8(j))
					break
				}
			}
		}
	}
	t.Logf("authenticated carrier view=%d PRFLeader=%d committeeChanged=%t", startView+1, carrierLeader, old.CommitteeHash != next.CommitteeHash)
	return r, oldContext, newContext
}

func TestNativeRenewalAnchorWritesHistoricalContinuationAndRestart(t *testing.T) {
	for _, permute := range []bool{false, true} {
		name := "fixed-order-v3"
		if permute {
			name = "authenticated-permutation-v4"
		}
		t.Run(name, func(t *testing.T) { testNativeRenewalAnchor(t, permute) })
	}
}

func testNativeRenewalAnchor(t *testing.T, permute bool) {
	r, oldContext, newContext := nativeRenewalFixture(t, permute)
	attachContext := func(e *clxevidence.RollingEvidence, k clxevidence.KeyContext) {
		e.KeyHeader, e.Boundary, e.Order = bytes.Clone(k.KeyHeader), append([]protocol.Hash(nil), k.Boundary...), append([]uint8(nil), k.Order...)
		e.PreviousKeyHeader, e.PreviousOrder = bytes.Clone(k.PreviousKeyHeader), append([]uint8(nil), k.PreviousOrder...)
	}
	base, _ := r.verifier.BootstrapAnchor()
	e := r.evidence(t, base, 2)
	attachContext(&e, oldContext)
	raw, err := EncodeNativeAnchorUpdate(e, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Unallocated one-atom custody surplus forces all three initialization writes.
	r.state.AddBalance(r.config.DEXDevnet.Custody, big.NewInt(1))
	counted := &countingNativeState{StateDB: r.state}
	if _, err = RunNative(counted, r.config, r.ctx, raw); err != nil {
		t.Fatal(err)
	}
	if counted.writes != 16 || counted.logs != 1 {
		t.Fatal("first v2 write budget", counted.writes, counted.logs)
	}
	t.Logf("first v2 native update writes=%d logs=%d calldataBytes=%d", counted.writes, counted.logs, len(raw))
	a2, err := ReadNativeAnchor(r.state, r.config.DEXDevnet.Custody, 2)
	if err != nil || a2.Version != 2 || a2.ActivationEnd != 3 || a2.SourceKeyHash == base.SourceKeyHash {
		t.Fatal("activated anchor", a2, err)
	}
	counted.writes = 0
	counted.logs = 0
	if out, err := RunNative(counted, r.config, r.ctx, raw); err != nil || len(out) != 33 || out[32] != 1 || counted.writes != 0 || counted.logs != 0 {
		t.Fatal("v2 exact replay", err)
	}
	e = r.evidence(t, a2, 4)
	attachContext(&e, newContext)
	raw4, err := EncodeNativeAnchorUpdate(e, nil)
	if err != nil {
		t.Fatal(err)
	}
	if permute {
		for _, name := range []string{"current-order", "previous-order", "previous-key"} {
			bad := e
			bad.SetKeyContext(e.KeyContext())
			switch name {
			case "current-order":
				bad.Order[0], bad.Order[1] = bad.Order[1], bad.Order[0]
			case "previous-order":
				bad.PreviousOrder[0], bad.PreviousOrder[1] = bad.PreviousOrder[1], bad.PreviousOrder[0]
			case "previous-key":
				bad.PreviousKeyHeader = bytes.Clone(newContext.KeyHeader)
			}
			encoded, err := EncodeNativeAnchorUpdate(bad, nil)
			if err != nil {
				t.Fatal(err)
			}
			before := r.state.IntermediateRoot(false)
			if _, err = RunNative(counted, r.config, r.ctx, encoded); err == nil || counted.writes != 0 || counted.logs != 0 || r.state.IntermediateRoot(false) != before {
				t.Fatal("forged permutation context changed native state", name, err)
			}
		}
	}
	if _, err = RunNative(counted, r.config, r.ctx, raw4); err != nil {
		t.Fatal(err)
	}
	if counted.writes != 13 {
		t.Fatal("established v2 write budget", counted.writes)
	}
	t.Logf("established v2 native update writes=%d calldataBytes=%d", counted.writes, len(raw4))
	a4, err := ReadNativeAnchor(r.state, r.config.DEXDevnet.Custody, 4)
	if err != nil || a4.Version != 2 || a4.ActivationEnd != 0 || a4.ActivationRoot != (protocol.Hash{}) {
		t.Fatal("cleared boundary", err)
	}
	e = r.evidence(t, a2, 3)
	attachContext(&e, newContext)
	before := r.state.IntermediateRoot(false)
	bad := e
	bad.KeyHeader = bytes.Clone(oldContext.KeyHeader)
	malformed, err := EncodeNativeAnchorUpdate(bad, r.headers[3:4])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = RunNative(r.state, r.config, r.ctx, malformed); err == nil || r.state.IntermediateRoot(false) != before {
		t.Fatal("wrong key context altered retained state", err)
	}
	historical, err := EncodeNativeAnchorUpdate(e, r.headers[3:4])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = RunNative(r.state, r.config, r.ctx, historical); err != nil {
		t.Fatal("historical dynamic-key continuation", err)
	}
	a3, err := ReadNativeAnchor(r.state, r.config.DEXDevnet.Custody, 3)
	if err != nil || a3.SourceKeyHash != a4.SourceKeyHash || a3.ActivationRoot != (protocol.Hash{}) {
		t.Fatal("historical anchor", err)
	}

	root, err := r.state.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	db := r.state.Database()
	if err = db.TrieDB().Commit(root, false, nil); err != nil {
		t.Fatal(err)
	}
	r.state, err = state.New(root, state.NewDatabase(rawdb.NewDatabase(db.TrieDB().DiskDB())), nil)
	if err != nil {
		t.Fatal(err)
	}
	for height, want := range map[uint64]clxevidence.Anchor{2: a2, 3: a3, 4: a4} {
		got, err := ReadNativeAnchor(r.state, r.config.DEXDevnet.Custody, height)
		if err != nil || got != want {
			t.Fatal("cold native v2 anchor", height, err)
		}
	}

}
