package hotstuff

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
)

type fhsFutureJumpApp struct {
	*recoveryTestApp
	current       uint64
	keyNumber     uint64
	keyHash       common.Hash
	committeeHash common.Hash
	leaderID      string
	highestTC     *TimeoutCertificate
	acceptCalls   int
	adoptCalls    int
	adoptErr      error
	events        []string
}

func (a *fhsFutureJumpApp) CurrentN() uint64 { return a.current }

func (a *fhsFutureJumpApp) CurrentState() ([]byte, string, uint64) {
	state := (&bftview.View{
		TxNumber:      36,
		TxHash:        common.HexToHash("0x3600"),
		KeyNumber:     a.keyNumber,
		KeyHash:       a.keyHash,
		CommitteeHash: a.committeeHash,
		ViewNumber:    a.current,
	}).EncodeConsensusToBytes()
	return state, a.leaderID, a.current + 1
}

func (a *fhsFutureJumpApp) ValidateFHSContext(ctx *FHSViewContext) error {
	if ctx == nil || ctx.ChainID != a.ChainID() || ctx.TargetView != a.current+1 ||
		ctx.KeyNumber != a.keyNumber || ctx.KeyHash != a.keyHash || ctx.CommitteeHash != a.committeeHash ||
		ctx.LeaderID != a.leaderID {
		return ErrInvalidLeaderView
	}
	return nil
}

func (a *fhsFutureJumpApp) AdoptFHSHighQC(qc *SignedState) error {
	a.adoptCalls++
	a.events = append(a.events, "qc")
	if a.adoptErr != nil {
		return a.adoptErr
	}
	a.highest = CloneSignedState(qc)
	if qc != nil && qc.Number > a.current {
		a.current = qc.Number
	}
	return nil
}

func (a *fhsFutureJumpApp) HighestFHSTimeoutCertificate() *TimeoutCertificate {
	return CloneTimeoutCertificate(a.highestTC)
}

func (a *fhsFutureJumpApp) PersistFHSVote(*PersistedVote) error { return nil }

func (a *fhsFutureJumpApp) PersistFHSTimeoutVote(*TimeoutStatement) error { return nil }

func (a *fhsFutureJumpApp) AcceptFHSTimeoutCertificate(tc *TimeoutCertificate) error {
	a.acceptCalls++
	a.events = append(a.events, "tc")
	a.highestTC = CloneTimeoutCertificate(tc)
	if tc != nil && tc.Statement.TimedOutView > a.current {
		a.current = tc.Statement.TimedOutView
	}
	return nil
}

func (*fhsFutureJumpApp) RequireMessageAuth() bool { return true }

type fhsFutureJumpFixture struct {
	app       *fhsFutureJumpApp
	manager   *HotstuffProtocolManager
	secrets   []bls.SecretKey
	keys      []*bls.PublicKey
	committee *bftview.Committee
	memberIDs []string
}

func newFHSFutureJumpFixture(t *testing.T, current uint64) *fhsFutureJumpFixture {
	t.Helper()
	secrets, keys := makeTestCommittee(t, 4)
	committee := &bftview.Committee{List: make([]*common.Cnode, len(keys))}
	memberIDs := make([]string, len(keys))
	for index, key := range keys {
		committee.List[index] = &common.Cnode{
			Address:  fmt.Sprintf("127.0.0.1:%d", 7100+index),
			CoinBase: fmt.Sprintf("coinbase-%d", index),
			Public:   key.SerializeToHexStr(),
		}
		memberIDs[index] = bftview.GetNodeID(committee.List[index].Address, committee.List[index].Public)
	}
	db := rawdb.NewMemoryDatabase()
	bftview.SetCommitteeConfig(db, nil, nil)
	keyHash := common.HexToHash("0xf001")
	if !bftview.WriteCommittee(3, keyHash, committee) {
		t.Fatal("write future-jump committee")
	}
	app := &fhsFutureJumpApp{
		recoveryTestApp: &recoveryTestApp{
			self:             memberIDs[3],
			fhs:              true,
			publicKeysByHash: map[common.Hash][]*bls.PublicKey{keyHash: keys},
		},
		current:       current,
		keyNumber:     3,
		keyHash:       keyHash,
		committeeHash: committee.RlpHash(),
		leaderID:      memberIDs[3],
	}
	return &fhsFutureJumpFixture{
		app: app, manager: NewHotstuffProtocolManager(app, &secrets[3], keys[3]),
		secrets: secrets, keys: keys, committee: committee, memberIDs: memberIDs,
	}
}

func (f *fhsFutureJumpFixture) timeoutCertificate(t *testing.T, timedOutView uint64) *TimeoutCertificate {
	t.Helper()
	statement := &TimeoutStatement{
		Version:       fhsWireVersion,
		ChainID:       f.app.ChainID(),
		TimedOutView:  timedOutView,
		KeyNumber:     f.app.keyNumber,
		KeyHash:       f.app.keyHash,
		CommitteeHash: f.app.committeeHash,
	}
	digest, err := TimeoutStatementDigest(statement)
	if err != nil {
		t.Fatal(err)
	}
	votes := make(map[int]*bls.Sign)
	for index := 0; index < CalcThreshold(len(f.keys)); index++ {
		signerDigest, err := fhsSignerDigest(digest, f.keys[index])
		if err != nil {
			t.Fatal(err)
		}
		votes[index] = f.secrets[index].SignHash(signerDigest)
	}
	tc, err := buildTimeoutCertificate(statement, votes, len(f.keys))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyTimeoutCertificate(tc, f.keys, CalcThreshold(len(f.keys))); err != nil {
		t.Fatalf("invalid future-jump TC fixture: %v", err)
	}
	return tc
}

func (f *fhsFutureJumpFixture) authenticate(t *testing.T, sender int, msg *HotstuffMessage) {
	t.Helper()
	msg.Id = f.memberIDs[sender]
	msg.PubKey = append([]byte(nil), f.keys[sender].Serialize()...)
	digest, err := MessageAuthDigest(f.app.ChainID(), msg)
	if err != nil {
		t.Fatal(err)
	}
	signature := f.secrets[sender].SignHash(digest)
	if signature == nil {
		t.Fatal("sign future-jump message envelope")
	}
	msg.AuthSig = signature.Serialize()
}

func (f *fhsFutureJumpFixture) timeoutQCMessage(t *testing.T, tc *TimeoutCertificate) *HotstuffMessage {
	t.Helper()
	encoded, err := rlp.EncodeToBytes(&tc.Statement)
	if err != nil {
		t.Fatal(err)
	}
	msg := &HotstuffMessage{
		Code: MsgTimeoutQC, Number: tc.Statement.TimedOutView, ViewId: tc.Statement.ID(),
		DataA: encoded, DataB: append([]byte(nil), tc.Sign...), DataC: append([]byte(nil), tc.Mask...),
	}
	f.authenticate(t, 0, msg)
	return msg
}

func (f *fhsFutureJumpFixture) newViewMessage(t *testing.T, target uint64, tc *TimeoutCertificate, highQC *SignedState) *HotstuffMessage {
	t.Helper()
	ctx := FHSViewContext{
		Version:       fhsWireVersion,
		ChainID:       f.app.ChainID(),
		TargetView:    target,
		KeyNumber:     f.app.keyNumber,
		KeyHash:       f.app.keyHash,
		CommitteeHash: f.app.committeeHash,
		LeaderID:      f.app.Self(),
		EntryKind:     FHSViewFromQC,
	}
	if tc != nil {
		ctx.EntryKind = FHSViewFromTimeout
		ctx.EntryID = tc.Statement.ID()
	}
	report := &NewViewReport{Context: ctx, SignerIndex: 0, HighQC: CloneSignedState(highQC)}
	encodedReport, err := EncodeNewViewReport(report)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := NewViewReportDigest(report)
	if err != nil {
		t.Fatal(err)
	}
	reportSignature := f.secrets[0].SignHash(digest)
	msg := &HotstuffMessage{
		Code: MsgNewView, Number: target, ViewId: ctx.ID(),
		DataA: encodedReport, DataB: reportSignature.Serialize(),
	}
	if tc != nil {
		msg.DataD, err = EncodeTimeoutCertificate(tc)
		if err != nil {
			t.Fatal(err)
		}
	}
	f.authenticate(t, 0, msg)
	return msg
}

func (f *fhsFutureJumpFixture) parentQC(t *testing.T, view uint64, valid bool) *SignedState {
	t.Helper()
	viewID := common.BigToHash(new(big.Int).SetUint64(view))
	ref := &types.HotstuffProposalRef{
		Version: types.HotstuffProposalRefVersion, ChainID: f.app.ChainID(),
		Number: 37, ViewNumber: view, ViewID: viewID, LeaderID: f.memberIDs[0],
		BlockHash: common.HexToHash("0x3700"), ParentHash: common.HexToHash("0x3600"),
		BodyHash: common.HexToHash("0x3701"), BodySize: 1,
		ExtraHash: types.HotstuffProposalExtraHash(nil), KeyHash: f.app.keyHash,
	}
	state := ref.EncodeToBytes()
	signature := aggregateContextSignatures(t, f.secrets, []int{0, 1, 2}, f.app.ChainID(), MsgVotePrepare, viewID, ref.LeaderID, state)
	if !valid {
		signature[0] ^= 0xff
	}
	return &SignedState{State: state, Sign: signature, Mask: []byte{0x07}, ViewID: viewID, LeaderID: ref.LeaderID, Number: view}
}

func assertNoFutureProofMutation(t *testing.T, fixture *fhsFutureJumpFixture, current uint64) {
	t.Helper()
	manager := fixture.manager
	if fixture.app.current != current || fixture.app.acceptCalls != 0 || fixture.app.adoptCalls != 0 {
		t.Fatalf("invalid future proof mutated application: current=%d accept=%d adopt=%d",
			fixture.app.current, fixture.app.acceptCalls, fixture.app.adoptCalls)
	}
	if len(manager.pendingNewView) != 0 || len(manager.views) != 0 || len(manager.timeoutVotes) != 0 ||
		len(manager.timeoutQC) != 0 || len(manager.timeoutSeen) != 0 || len(manager.timeoutView) != 0 {
		t.Fatalf("invalid future proof mutated volatile maps: pending=%d views=%d votes=%d qc=%d seen=%d timeoutViews=%d",
			len(manager.pendingNewView), len(manager.views), len(manager.timeoutVotes), len(manager.timeoutQC),
			len(manager.timeoutSeen), len(manager.timeoutView))
	}
}

func TestFarFutureTimeoutQCJumpsAfterFullVerification(t *testing.T) {
	fixture := newFHSFutureJumpFixture(t, 100)
	tc := fixture.timeoutCertificate(t, 130)
	if err := fixture.manager.handleTimeoutQCMsg(fixture.timeoutQCMessage(t, tc)); err != nil {
		t.Fatalf("valid far-future timeout QC rejected: %v", err)
	}
	if fixture.app.current != 130 || fixture.app.acceptCalls != 1 {
		t.Fatalf("far TC did not advance application: current=%d accepts=%d", fixture.app.current, fixture.app.acceptCalls)
	}
	if fixture.manager.timeoutQC[tc.Statement.ID()] == nil {
		t.Fatal("verified far TC was not retained for recovery")
	}
}

func TestFarSingleTimeoutVoteRemainsBoundToExactCurrentView(t *testing.T) {
	fixture := newFHSFutureJumpFixture(t, 100)
	tc := fixture.timeoutCertificate(t, 130)
	msg := fixture.timeoutQCMessage(t, tc)
	msg.Code = MsgTimeout
	fixture.authenticate(t, 0, msg)
	if err := fixture.manager.handleTimeoutMsg(msg); err == nil {
		t.Fatal("far single timeout vote was accepted")
	}
	assertNoFutureProofMutation(t, fixture, 100)
}

func TestStaleTimeoutQCIsQuietNoOp(t *testing.T) {
	fixture := newFHSFutureJumpFixture(t, 130)
	tc := fixture.timeoutCertificate(t, 129)
	msg := fixture.timeoutQCMessage(t, tc)
	msg.DataB[0] ^= 0xff // stale path must not spend BLS work or publish state
	if err := fixture.manager.handleTimeoutQCMsg(msg); !errors.Is(err, ErrOldState) {
		t.Fatalf("stale timeout QC error = %v, want %v", err, ErrOldState)
	}
	assertNoFutureProofMutation(t, fixture, 130)
}

func TestInvalidFarFutureProofsHaveNoSideEffects(t *testing.T) {
	t.Run("timeout certificate", func(t *testing.T) {
		fixture := newFHSFutureJumpFixture(t, 100)
		tc := fixture.timeoutCertificate(t, 130)
		msg := fixture.timeoutQCMessage(t, tc)
		msg.DataB[0] ^= 0xff
		fixture.authenticate(t, 0, msg)
		if err := fixture.manager.handleTimeoutQCMsg(msg); err == nil {
			t.Fatal("invalid far timeout QC was accepted")
		}
		assertNoFutureProofMutation(t, fixture, 100)
	})

	t.Run("new-view timeout proof", func(t *testing.T) {
		fixture := newFHSFutureJumpFixture(t, 100)
		tc := fixture.timeoutCertificate(t, 129)
		tc.Sign[0] ^= 0xff
		msg := fixture.newViewMessage(t, 130, tc, nil)
		if err := fixture.manager.handleNewViewMsg(msg); err == nil {
			t.Fatal("new-view with invalid far TC was accepted")
		}
		assertNoFutureProofMutation(t, fixture, 100)
	})

	t.Run("new-view high QC", func(t *testing.T) {
		fixture := newFHSFutureJumpFixture(t, 100)
		msg := fixture.newViewMessage(t, 130, nil, fixture.parentQC(t, 101, false))
		if err := fixture.manager.handleNewViewMsg(msg); err == nil {
			t.Fatal("new-view with invalid far high QC was accepted")
		}
		assertNoFutureProofMutation(t, fixture, 100)
	})
}

func TestFarNewViewAppliesVerifiedTCBeforeHighQCCatchup(t *testing.T) {
	fixture := newFHSFutureJumpFixture(t, 100)
	fixture.app.adoptErr = errors.New("proposal body not available")
	tc := fixture.timeoutCertificate(t, 129)
	msg := fixture.newViewMessage(t, 130, tc, fixture.parentQC(t, 101, true))
	if err := fixture.manager.handleNewViewMsg(msg); err == nil {
		t.Fatal("injected high-QC catch-up failure was hidden")
	}
	if fixture.app.current != 129 || fixture.app.acceptCalls != 1 || fixture.app.adoptCalls != 1 {
		t.Fatalf("verified TC was not retained before QC catch-up failure: current=%d accepts=%d adopts=%d",
			fixture.app.current, fixture.app.acceptCalls, fixture.app.adoptCalls)
	}
	if len(fixture.app.events) != 2 || fixture.app.events[0] != "tc" || fixture.app.events[1] != "qc" {
		t.Fatalf("future proof application order = %v, want [tc qc]", fixture.app.events)
	}
	if len(fixture.manager.pendingNewView) != 0 || len(fixture.manager.views) != 0 {
		t.Fatal("failed high-QC catch-up stored an unvalidated future NewView")
	}
}

func TestFarNewViewWithoutTCStaysOutsideBoundedQueue(t *testing.T) {
	fixture := newFHSFutureJumpFixture(t, 100)
	msg := fixture.newViewMessage(t, 130, nil, nil)
	if err := fixture.manager.handleNewViewMsg(msg); err != ErrFutureState {
		t.Fatalf("far proofless NewView error = %v, want %v", err, ErrFutureState)
	}
	assertNoFutureProofMutation(t, fixture, 100)
}
