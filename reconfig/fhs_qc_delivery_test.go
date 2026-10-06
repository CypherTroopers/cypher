package reconfig

import (
	"math/big"
	"path/filepath"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/ethdb/leveldb"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// Keep the certified generation canonical, but replace one member in the new
// current generation. A routing test must distinguish member identities, not
// only key-block hashes that happen to name identical committees.
func newFHSQCDeliveryFixture(t *testing.T) (*fhsEpochTestFixture, *hotstuff.HotstuffMessage, *bftview.Committee) {
	t.Helper()
	fixture := newFHSEpochTestFixture(t)
	nextCommittee := fixture.committee.Copy()
	newMember := *nextCommittee.List[len(nextCommittee.List)-1]
	newMember.Address = "validator-new"
	var nextSecret bls.SecretKey
	nextSecret.SetByCSPRNG()
	newMember.Public = nextSecret.GetPublicKey().SerializeToHexStr()
	nextCommittee.List[len(nextCommittee.List)-1] = &newMember
	nextKey := types.NewKeyBlock(&types.KeyBlockHeader{
		ParentHash: fixture.current.Hash(), Difficulty: big.NewInt(1), Number: big.NewInt(2),
		Time: 3, CommitteeHash: nextCommittee.RlpHash(),
	})
	rawdb.WriteKeyBlock(fixture.db, nextKey)
	rawdb.WriteKeyBlockHash(fixture.db, nextKey.Hash(), nextKey.NumberU64())
	rawdb.WriteTd(fixture.db, nextKey.Hash(), nextKey.NumberU64(), nextKey.Difficulty())
	rawdb.WriteHeadKeyBlockHash(fixture.db, nextKey.Hash())
	rawdb.WriteHeadKeyHeaderHash(fixture.db, nextKey.Hash())
	if !bftview.WriteCommittee(nextKey.NumberU64(), nextKey.Hash(), nextCommittee) {
		t.Fatal("store new delivery committee")
	}
	kbc, err := core.NewKeyBlockChain(&fhsEpochTestBackend{}, fixture.db, nil, fixture.service.chainConfig, nil, new(event.TypeMux))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kbc.Stop)
	fixture.service.kbc = kbc
	fixture.service.currentView.KeyNumber = nextKey.NumberU64()
	fixture.service.currentView.KeyHash = nextKey.Hash()
	fixture.service.currentView.CommitteeHash = nextKey.CommitteeHash()
	bftview.SetCommitteeConfig(fixture.db, kbc, nil)
	t.Cleanup(func() { bftview.SetCommitteeConfig(nil, nil, nil) })

	leader := fixture.committee.List[0].Address
	block := types.NewBlockWithHeader(&types.Header{
		ParentHash: common.HexToHash("0xd001"), Number: big.NewInt(2),
		Difficulty: big.NewInt(1), KeyHash: fixture.current.Hash(),
	})
	ref, err := types.NewHotstuffProposalRefWithProof(
		fixture.service.ChainID(), 21, common.HexToHash("0xd021"), leader,
		block, block.EncodeToBytes(), nil, common.Hash{},
	)
	if err != nil {
		t.Fatal(err)
	}
	qc := signFHSEpochProposalQC(t, fixture, ref)
	fixture.service.netService = &netService{serverID: leader}
	manager := hotstuff.NewHotstuffProtocolManager(fixture.service, &fixture.keys[0], fixture.public[0])
	msg, err := manager.RebuildFHSQCBroadcast(qc)
	if err != nil {
		t.Fatal(err)
	}
	return fixture, msg, nextCommittee
}

func TestFHSQCBroadcastUsesCertifiedCommitteeAfterHandoff(t *testing.T) {
	fixture, replay, current := newFHSQCDeliveryFixture(t)
	if got := bftview.GetCurrentMember(); got == nil || got.RlpHash() != current.RlpHash() {
		t.Fatal("fixture did not activate the replacement committee")
	}
	if current.RlpHash() == fixture.committee.RlpHash() {
		t.Fatal("fixture has identical old and current committees")
	}
	for _, name := range []string{"rebuilt durable QC", "QC with optional key signature"} {
		t.Run(name, func(t *testing.T) {
			msg := cloneHotstuffMessage(replay)
			if name == "QC with optional key signature" {
				// Standalone QC decoding permits this original-view field; routing
				// must still use the independently certified transaction reference.
				msg.DataA = []byte("optional-key-state-aggregate")
			}
			got, err := fixture.service.hotstuffBroadcastCommittee(msg)
			if err != nil {
				t.Fatal(err)
			}
			if got == nil || got.RlpHash() != fixture.committee.RlpHash() {
				t.Fatal("QC was redirected from its certified committee to the current committee")
			}
			removed := fixture.committee.List[len(fixture.committee.List)-1].Address
			if node, _ := got.Get(removed, bftview.Address); node == nil {
				t.Fatalf("QC delivery omitted original member %s", removed)
			}
			if node, _ := got.Get("validator-new", bftview.Address); node != nil {
				t.Fatal("QC delivery substituted a new-committee member")
			}
		})
	}
}

func TestFHSQCBroadcastCommitteeRejectsMalformedContext(t *testing.T) {
	fixture, original, _ := newFHSQCDeliveryFixture(t)
	tests := []struct {
		name   string
		mutate func(*hotstuff.HotstuffMessage)
	}{
		{"missing signature", func(msg *hotstuff.HotstuffMessage) { msg.DataB = nil }},
		{"missing signer mask", func(msg *hotstuff.HotstuffMessage) { msg.DataC = nil }},
		{"missing proposal", func(msg *hotstuff.HotstuffMessage) { msg.DataD = nil }},
		{"malformed proposal", func(msg *hotstuff.HotstuffMessage) { msg.DataD = []byte{0xff} }},
		{"view number mismatch", func(msg *hotstuff.HotstuffMessage) { msg.Number++ }},
		{"view id mismatch", func(msg *hotstuff.HotstuffMessage) { msg.ViewId = common.HexToHash("0xbad") }},
		{"leader mismatch", func(msg *hotstuff.HotstuffMessage) { msg.Id = "validator-new" }},
		{"foreign chain", func(msg *hotstuff.HotstuffMessage) {
			ref, _ := types.DecodeHotstuffProposalRef(msg.DataD)
			ref.ChainID++
			msg.DataD = ref.EncodeToBytes()
		}},
		{"missing committee", func(msg *hotstuff.HotstuffMessage) {
			ref, _ := types.DecodeHotstuffProposalRef(msg.DataD)
			ref.KeyHash = common.Hash{}
			msg.DataD = ref.EncodeToBytes()
		}},
		{"unknown committee", func(msg *hotstuff.HotstuffMessage) {
			ref, _ := types.DecodeHotstuffProposalRef(msg.DataD)
			ref.KeyHash = common.HexToHash("0xdead")
			msg.DataD = ref.EncodeToBytes()
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			msg := cloneHotstuffMessage(original)
			test.mutate(msg)
			if committee, err := fixture.service.hotstuffBroadcastCommittee(msg); err == nil || committee != nil {
				t.Fatalf("malformed QC selected committee: committee=%v err=%v", committee, err)
			}
		})
	}
}

func TestFHSQCDeliveryKeepsRemovedValidatorReachable(t *testing.T) {
	fixture, _, current := newFHSQCDeliveryFixture(t)
	peers, err := fixture.service.fhsPeerAuthorizationWithCertifiedCarriers(current)
	if err != nil {
		t.Fatal(err)
	}
	for _, committee := range []*bftview.Committee{fixture.committee, current} {
		for _, member := range committee.List {
			if len(peers[member.Address]) == 0 {
				t.Fatalf("committee handoff disconnected QC recipient %s", member.Address)
			}
		}
	}
	if len(peers) != len(current.List)+1 {
		t.Fatalf("unexpected retained peer set: %d", len(peers))
	}
}

func TestFHSQCDeliveryReplaysDurableOldCommitteeAfterRestart(t *testing.T) {
	fixture, original, current := newFHSQCDeliveryFixture(t)
	s := fixture.service
	ref, err := types.DecodeHotstuffProposalRef(original.DataD)
	if err != nil {
		t.Fatal(err)
	}
	qc := &hotstuff.SignedState{State: original.DataD, Number: original.Number, ViewID: original.ViewId,
		LeaderID: original.Id, Sign: original.DataB, Mask: original.DataC}
	path := filepath.Join(t.TempDir(), "outbox")
	db, err := leveldb.New(path, 1, 8, "")
	if err != nil {
		t.Fatal(err)
	}
	genesis := common.HexToHash("0xd00")
	s.fhsStore = newFHSSafetyStore(db, s.ChainID(), genesis)
	if err := s.persistValidatedFHSCertificateWithBroadcast(ref, qc, true); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = leveldb.New(path, 1, 8, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s.fhsStore = newFHSSafetyStore(db, s.ChainID(), genesis)
	s.protocolMng = hotstuff.NewHotstuffProtocolManager(s, &fixture.keys[0], fixture.public[0])
	s.runningState = 1
	pending, replay, err := s.preparePendingFHSQCBroadcastReplay()
	if err != nil || replay == nil || !hotstuff.SignedStateSemanticEqual(pending, qc) {
		t.Fatalf("restore durable old-epoch broadcast: %v", err)
	}
	recipients, err := s.hotstuffBroadcastCommittee(replay)
	if err != nil || recipients.RlpHash() != fixture.committee.RlpHash() || recipients.RlpHash() == current.RlpHash() {
		t.Fatalf("restart changed the QC's recipient committee: %v", err)
	}
}
