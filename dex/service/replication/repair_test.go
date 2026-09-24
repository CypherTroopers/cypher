package replication

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/rewards"
	"github.com/cypherium/cypher/dex/transport"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// These are real five-signature QC fixtures. Every received record still takes
// Application.ImportProposalData's signature, exact-parent, execution and FHS
// finality checks; no authenticated flag or safety snapshot is injected.
func TestRepairColdSameHeightQCSiblingWithoutNewActions(t *testing.T) {
	var keys [7]bls.SecretKey
	members, peers, recipients := make([]*common.Cnode, 7), make([]transport.Peer, 7), make([][20]byte, 7)
	for i := range keys {
		if err := keys[i].SetDecString(fmt.Sprint(790 + i)); err != nil {
			t.Fatal(err)
		}
		recipients[i][19] = byte(i + 1)
		members[i] = &common.Cnode{Address: fmt.Sprintf("repair-%d", i), Public: keys[i].GetPublicKey().SerializeToHexStr(), CoinBase: common.Address(recipients[i]).Hex()}
		peers[i] = transport.Peer{ID: members[i].Address, BLSPublic: members[i].Public, RewardRecipient: recipients[i]}
	}
	domain := protocol.Domain{Version: 1, ChainID: 991, Genesis: protocol.Hash{1}, DEXID: protocol.Hash{2}, Epoch: 1, Committee: protocol.Hash((&bftview.Committee{List: members}).RlpHash())}
	cfg := consensus.Config{Domain: domain, Members: members, Index: 0, Secret: &keys[0], DataDir: filepath.Join(t.TempDir(), "source"), CLXHeight: 1, CLXHash: protocol.Hash{3}, MaxHeight: 8}
	source, err := consensus.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	targetConfig := cfg
	targetConfig.Index = 2
	targetConfig.Secret = &keys[2]
	targetConfig.DataDir = filepath.Join(t.TempDir(), "target")
	var restoredVote *hotstuff.PersistedVote
	targetConfig.RestoreVote = func(v *hotstuff.PersistedVote) error { restoredVote = hotstuff.ClonePersistedVote(v); return nil }
	target, err := consensus.Open(targetConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { target.Close() }()
	counterRoot := func(n uint64) protocol.Hash {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], n)
		return protocol.Digest("common-dex/counter/v1", b[:])
	}
	makeRecord := func(parent *consensus.Record, view uint64) *consensus.Record {
		height := uint64(1)
		epoch := domain.EpochKey()
		parentHash := common.Hash(protocol.Digest("common-dex/counter-genesis/v1", epoch[:]))
		var previous protocol.Hash
		var parentID common.Hash
		if parent != nil {
			height = parent.Checkpoint.Sequence + 1
			h, _ := parent.Checkpoint.Hash()
			previous = h
			parentHash = common.Hash(h)
			id, e := hotstuff.SignedStateID(parent.QC)
			if e != nil {
				t.Fatal(e)
			}
			parentID = id.Hash()
		}
		var action [8]byte
		binary.BigEndian.PutUint64(action[:], 1)
		cp := protocol.Checkpoint{Version: domain.Version, ProofMode: protocol.CommitteeSignatures, ChainID: domain.ChainID, Genesis: domain.Genesis, DEXID: domain.DEXID, Epoch: domain.Epoch, Committee: domain.Committee, Sequence: height, Previous: previous, PreRoot: counterRoot(height - 1), PostRoot: counterRoot(height), FirstBlock: height, LastBlock: height, CLXHeight: cfg.CLXHeight, CLXHash: cfg.CLXHash, DataRoot: protocol.Digest("common-dex/counter-action/v1", action[:]), DataSchema: 1}
		body, e := cp.Encode()
		if e != nil {
			t.Fatal(e)
		}
		extra := append(body, action[:]...)
		h, _ := cp.Hash()
		leader := members[(view-1)%7].Address
		context := hotstuff.FHSViewContext{Version: 3, ChainID: domain.ChainID, TargetView: view, KeyNumber: 1, KeyHash: common.Hash(epoch), CommitteeHash: common.Hash(domain.Committee), LeaderID: leader, EntryKind: hotstuff.FHSViewFromQC}
		ref := &types.HotstuffProposalRef{Version: types.HotstuffProposalRefVersion, ChainID: domain.ChainID, Number: height, ViewNumber: view, ViewID: context.ID(), LeaderID: leader, BlockHash: common.Hash(h), ParentHash: parentHash, StateRoot: common.Hash(cp.PostRoot), BodyHash: common.Hash(cp.DataRoot), BodySize: 8, ExtraHash: types.HotstuffProposalExtraHash(extra), ParentQCID: parentID, KeyHash: common.Hash(epoch), Time: height}
		r := &consensus.Record{Checkpoint: cp, Action: 1, Ref: ref.EncodeToBytes()}
		var agg *bls.Sign
		for i := 0; i < 5; i++ {
			s, e := hotstuff.SignFHSSignatureWithContext(&keys[i], keys[i].GetPublicKey(), r.Ref, domain.ChainID, hotstuff.MsgVotePrepare, ref.ViewID, leader)
			if e != nil {
				t.Fatal(e)
			}
			if agg == nil {
				agg = s
			} else {
				agg.Add(s)
			}
		}
		r.QC = &hotstuff.SignedState{State: r.Ref, Sign: agg.Serialize(), Mask: []byte{31}, ViewID: ref.ViewID, LeaderID: leader, Number: view}
		return r
	}
	encodeRecord := func(r *consensus.Record) []byte {
		b, e := json.Marshal(r)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	importRecord := func(a *consensus.Application, r *consensus.Record) {
		if e := a.ImportProposalData(encodeRecord(r)); e != nil {
			t.Fatal(e)
		}
	}
	first := makeRecord(nil, 1)
	old := makeRecord(first, 4)
	selected := makeRecord(first, 5)
	importRecord(source, first)
	importRecord(source, old)
	importRecord(source, selected)
	importRecord(target, first)
	extra, _ := old.Checkpoint.Encode()
	var action [8]byte
	binary.BigEndian.PutUint64(action[:], 1)
	extra = append(extra, action[:]...)
	if err = target.OnPropose(old.Ref, extra, 4, first.QC); err != nil {
		t.Fatal(err)
	}
	ref, _ := types.DecodeHotstuffProposalRef(old.Ref)
	vote := &hotstuff.PersistedVote{ViewNumber: ref.ViewNumber, ViewID: ref.ViewID, LeaderID: ref.LeaderID, ProposalID: ref.ProposalID(), ProposalRef: old.Ref, ProposalRefHash: hotstuff.StateDigest(old.Ref)}
	if err = target.PersistFHSVote(vote); err != nil {
		t.Fatal(err)
	}
	importRecord(target, old)
	parent := selected
	var child *consensus.Record
	for view := uint64(6); view <= 9; view++ {
		parent = makeRecord(parent, view)
		if child == nil {
			child = parent
		}
		importRecord(source, parent)
	}
	// A higher-view sibling at height2 must not be spliced into the selected
	// ancestry of height3. It has the same checkpoint, but a different QC ID.
	unselected := makeRecord(first, 8)
	importRecord(source, unselected)
	if source.CertifiedHeight() != 6 || source.FinalizedHeight() != 5 || target.CertifiedHeight() != 2 || target.FinalizedHeight() != 0 {
		t.Fatal("fixture boundaries")
	}
	if err = target.Close(); err != nil {
		t.Fatal(err)
	}
	target, err = consensus.Open(targetConfig)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restoredVote, vote) {
		t.Fatal("cold restart lost own vote")
	}
	if err = target.ImportProposalData(encodeRecord(child)); !errors.Is(err, consensus.ErrUnavailable) {
		t.Fatal("height-only repair unexpectedly filled absent exact parent", err)
	}
	registry, err := rewards.NewRegistry(domain, members, recipients)
	if err != nil {
		t.Fatal(err)
	}
	type delivery struct {
		from, to uint8
		raw      []byte
	}
	var queue []delivery
	controllers := map[uint8]*Controller{}
	for _, i := range []uint8{0, 2} {
		collector, e := rewards.OpenCollector(filepath.Join(t.TempDir(), fmt.Sprint(i)), registry, i, &keys[i])
		if e != nil {
			t.Fatal(e)
		}
		defer collector.Shutdown()
		c, e := New(Config{Index: i, Peers: peers, Registry: registry, Collector: collector})
		if e != nil {
			t.Fatal(e)
		}
		a := source
		if i == 2 {
			a = target
		}
		index := i
		if e = c.Bind(a, func(to string, kind uint8, raw []byte) error {
			if kind != transport.KindExtension {
				t.Fatal("wrong wire kind")
			}
			for j, p := range peers {
				if p.ID == to {
					queue = append(queue, delivery{index, uint8(j), bytes.Clone(raw)})
					return nil
				}
			}
			return errors.New("unknown peer")
		}); e != nil {
			t.Fatal(e)
		}
		controllers[i] = c
	}
	c := controllers[2]
	c.repairStarted[0] = true
	c.repairAfter[0] = 2
	wire, _ := encode(recordKind, encodeRecord(child))
	if err = c.Receive(0, wire); !errors.Is(err, transport.ErrBusy) {
		t.Fatal("missing parent not retriable", err)
	}
	if c.repairAfter[0] != target.FinalizedHeight() {
		t.Fatal("did not rewind only advisory cursor")
	}
	// Malformed records cannot advance the scheduling cursor, let alone safety.
	bad := *selected
	bad.QC = hotstuff.CloneSignedState(selected.QC)
	bad.QC.Sign[0] ^= 1
	wire, _ = encode(recordKind, encodeRecord(&bad))
	if err = c.Receive(0, wire); err == nil || c.repairAfter[0] != 0 {
		t.Fatal("invalid QC changed cursor", err)
	}
	delivered := 0
	for len(queue) > 0 && delivered < 32 {
		d := queue[0]
		queue = queue[1:]
		delivered++
		if e := controllers[d.to].Receive(d.from, d.raw); e != nil {
			t.Fatal(e)
		}
	}
	if len(queue) != 0 || delivered > 16 || target.CertifiedHeight() != 6 || target.FinalizedHeight() != 5 {
		t.Fatalf("bounded repair failed messages=%d certified=%d final=%d", delivered, target.CertifiedHeight(), target.FinalizedHeight())
	}
	got, e := target.SelectedCertifiedData(2)
	if e != nil {
		t.Fatal(e)
	}
	var received consensus.Record
	if json.Unmarshal(got, &received) != nil || !hotstuff.SignedStateSemanticEqual(received.QC, selected.QC) {
		t.Fatal("selected ancestry was spliced")
	}
	if err = target.Close(); err != nil {
		t.Fatal(err)
	}
	target, err = consensus.Open(targetConfig)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restoredVote, vote) || target.FinalizedHeight() != 5 {
		t.Fatal("repair/cold reopen changed local vote or finality")
	}
	t.Logf("cold exact-parent repair without Start/new actions: old QC height2/view4 -> selected height2/view5 -> height6/final5; %d bounded extension messages; own vote unchanged", delivered)
}
