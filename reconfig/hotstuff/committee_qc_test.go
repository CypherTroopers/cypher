package hotstuff

import (
	"errors"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/reconfig/bftview"
)

type fhsParentQCFixture struct {
	app        *recoveryTestApp
	manager    *HotstuffProtocolManager
	prepare    *HotstuffMessage
	parentQC   *SignedState
	oldKeyHash common.Hash
	newKeyHash common.Hash
	oldKeys    []*bls.PublicKey
	newKeys    []*bls.PublicKey
}

func makeTestCommittee(t *testing.T, size int) ([]bls.SecretKey, []*bls.PublicKey) {
	t.Helper()
	secrets := make([]bls.SecretKey, size)
	publicKeys := make([]*bls.PublicKey, size)
	for i := range secrets {
		secrets[i].SetByCSPRNG()
		publicKeys[i] = secrets[i].GetPublicKey()
		if publicKeys[i] == nil {
			t.Fatalf("public key %d is nil", i)
		}
	}
	return secrets, publicKeys
}

func aggregateContextSignatures(t *testing.T, secrets []bls.SecretKey, signerIndexes []int, chainID uint64, msgCode uint32, viewID common.Hash, leaderID string, state []byte) []byte {
	t.Helper()
	var aggregate *bls.Sign
	digest := hotstuffContextDigest(chainID, msgCode, viewID, leaderID, state)
	for _, index := range signerIndexes {
		if index < 0 || index >= len(secrets) {
			t.Fatalf("signer index %d is out of range", index)
		}
		signerDigest := digest
		if msgCode == MsgVotePrepare {
			var err error
			signerDigest, err = fhsSignerDigest(digest, secrets[index].GetPublicKey())
			if err != nil {
				t.Fatal(err)
			}
		}
		signature := secrets[index].SignHash(signerDigest)
		if aggregate == nil {
			aggregate = signature
		} else {
			aggregate.Add(signature)
		}
	}
	if aggregate == nil {
		t.Fatal("no signatures to aggregate")
	}
	return aggregate.Serialize()
}

func newFHSParentQCFixture(t *testing.T, includeHistoricalCommittee bool) *fhsParentQCFixture {
	t.Helper()
	const (
		chainID     = uint64(1)
		parentView  = uint64(7)
		childView   = uint64(8)
		parentLead  = "old-leader"
		currentLead = "new-leader"
	)

	secrets, oldKeys := makeTestCommittee(t, 4)
	// Reconfiguration rotates the positional mask meaning. The same mask 0x07
	// selects secrets 0,1,2 in oldKeys but secrets 3,0,1 in newKeys.
	newKeys := []*bls.PublicKey{oldKeys[3], oldKeys[0], oldKeys[1], oldKeys[2]}
	oldKeyHash := common.HexToHash("0x1001")
	newKeyHash := common.HexToHash("0x2002")

	currentState := (&bftview.View{
		TxNumber:      40,
		TxHash:        common.HexToHash("0x4000"),
		KeyNumber:     4,
		KeyHash:       newKeyHash,
		CommitteeHash: common.HexToHash("0x2200"),
		LeaderIndex:   0,
		ViewNumber:    parentView,
	}).EncodeConsensusToBytes()
	childViewID := hotstuffDigestHash([]byte(currentLead), currentState)

	parentViewID := common.HexToHash("0x7007")
	parentState := (&types.HotstuffProposalRef{
		Version:    types.HotstuffProposalRefVersion,
		ChainID:    chainID,
		Number:     40,
		ViewNumber: parentView,
		ViewID:     parentViewID,
		LeaderID:   parentLead,
		BlockHash:  common.HexToHash("0x4010"),
		ParentHash: common.HexToHash("0x4009"),
		BodyHash:   common.HexToHash("0x4011"),
		BodySize:   1,
		ExtraHash:  types.HotstuffProposalExtraHash(nil),
		KeyHash:    oldKeyHash,
	}).EncodeToBytes()
	parentMask := []byte{0x07}
	parentSignature := aggregateContextSignatures(t, secrets, []int{0, 1, 2}, chainID, MsgVotePrepare, parentViewID, parentLead, parentState)
	parentQC := &SignedState{
		State:    parentState,
		Sign:     parentSignature,
		Mask:     parentMask,
		ViewID:   parentViewID,
		LeaderID: parentLead,
		Number:   parentView,
	}
	encodedParentQC, err := EncodeSignedState(parentQC)
	if err != nil {
		t.Fatal(err)
	}

	committeeByHash := map[common.Hash][]*bls.PublicKey{newKeyHash: newKeys}
	if includeHistoricalCommittee {
		committeeByHash[oldKeyHash] = oldKeys
	}
	app := &recoveryTestApp{
		self:             "replica",
		fhs:              true,
		publicKeysByHash: committeeByHash,
		validateState:    currentState,
		validateLeader:   currentLead,
		validateNumber:   childView,
	}
	manager := NewHotstuffProtocolManager(app, &secrets[2], oldKeys[2])
	highQCSignature := aggregateContextSignatures(t, secrets, []int{3, 0, 1}, chainID, MsgNewView, childViewID, currentLead, currentState)
	prepare := &HotstuffMessage{
		Code:   MsgPrepare,
		Number: childView,
		ViewId: childViewID,
		Id:     currentLead,
		DataB:  []byte("child-proposal-ref"),
		DataC:  highQCSignature,
		DataD:  []byte{0x07},
		DataE:  currentState,
		DataG:  encodedParentQC,
	}

	return &fhsParentQCFixture{
		app:        app,
		manager:    manager,
		prepare:    prepare,
		parentQC:   parentQC,
		oldKeyHash: oldKeyHash,
		newKeyHash: newKeyHash,
		oldKeys:    oldKeys,
		newKeys:    newKeys,
	}
}

func TestFHSPrepareUsesHistoricalCommitteeForParentQC(t *testing.T) {
	fixture := newFHSParentQCFixture(t, true)

	if !VerifyFHSSignatureWithContext(
		fixture.parentQC.Sign,
		fixture.parentQC.Mask,
		fixture.parentQC.State,
		fixture.oldKeys,
		CalcThreshold(len(fixture.oldKeys)),
		fixture.app.ChainID(),
		MsgVotePrepare,
		fixture.parentQC.ViewID,
		fixture.parentQC.LeaderID,
	) {
		t.Fatal("test parent QC does not verify with its historical committee")
	}
	if VerifyFHSSignatureWithContext(
		fixture.parentQC.Sign,
		fixture.parentQC.Mask,
		fixture.parentQC.State,
		fixture.newKeys,
		CalcThreshold(len(fixture.newKeys)),
		fixture.app.ChainID(),
		MsgVotePrepare,
		fixture.parentQC.ViewID,
		fixture.parentQC.LeaderID,
	) {
		t.Fatal("test parent QC unexpectedly verifies with reordered current committee")
	}

	if err := fixture.manager.handlePrepareMsg(fixture.prepare); err != nil {
		t.Fatalf("Prepare was rejected across keyblock boundary: %v", err)
	}
	if len(fixture.app.writes) != 1 || fixture.app.writes[0].Code != MsgVotePrepare {
		t.Fatalf("writes = %#v, want one VotePrepare", fixture.app.writes)
	}
	if len(fixture.app.keyLookups) != 2 || fixture.app.keyLookups[0] != fixture.newKeyHash || fixture.app.keyLookups[1] != fixture.oldKeyHash {
		t.Fatalf("committee lookups = %v, want current %s then parent %s", fixture.app.keyLookups, fixture.newKeyHash, fixture.oldKeyHash)
	}
}

func TestFHSParentQCMissingHistoricalCommitteeFailsClosed(t *testing.T) {
	fixture := newFHSParentQCFixture(t, false)

	err := fixture.manager.handlePrepareMsg(fixture.prepare)
	if !errors.Is(err, ErrInvalidHighQC) {
		t.Fatalf("error = %v, want %v", err, ErrInvalidHighQC)
	}
	if len(fixture.app.writes) != 0 {
		t.Fatalf("sent %d votes after parent committee lookup failure", len(fixture.app.writes))
	}
}

func TestViewCommitteeSnapshotIsNotRefreshed(t *testing.T) {
	_, oldKeys := makeTestCommittee(t, 4)
	_, replacementKeys := makeTestCommittee(t, 4)
	keyHash := common.HexToHash("0x3003")
	state := (&bftview.View{
		TxNumber:      10,
		TxHash:        common.HexToHash("0x3010"),
		KeyNumber:     3,
		KeyHash:       keyHash,
		CommitteeHash: common.HexToHash("0x3300"),
		ViewNumber:    9,
	}).EncodeConsensusToBytes()
	app := &recoveryTestApp{publicKeysByHash: map[common.Hash][]*bls.PublicKey{keyHash: oldKeys}}
	manager := NewHotstuffProtocolManager(app, nil, nil)

	view, err := manager.createView(false, PhasePrepare, "leader", state, 10)
	if err != nil {
		t.Fatal(err)
	}
	app.publicKeysByHash[keyHash] = replacementKeys
	if err := manager.initViewCommittee(view); err != nil {
		t.Fatal(err)
	}

	if len(app.keyLookups) != 1 {
		t.Fatalf("committee was reloaded %d times, want once", len(app.keyLookups))
	}
	for i := range oldKeys {
		if !view.groupPublicKey[i].IsEqual(oldKeys[i]) {
			t.Fatalf("snapshot key %d changed after committee replacement", i)
		}
	}
}
