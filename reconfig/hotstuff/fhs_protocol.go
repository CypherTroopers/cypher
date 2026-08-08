package hotstuff

import (
	"bytes"
	"fmt"
	"sort"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
)

const (
	maxFHSNewViewExtraBytes    = 2 * 1024
	maxFHSNewViewReportBytes   = 8 * 1024
	maxFHSAggregateReportBytes = 256 * 1024
	maxFHSAggregateQCBytes     = 320 * 1024
)

func validateFHSNewViewReportSize(encoded []byte, report *NewViewReport) error {
	if report == nil || len(encoded) == 0 || len(encoded) > maxFHSNewViewReportBytes || len(report.Extra) > maxFHSNewViewExtraBytes {
		return fmt.Errorf("FHS NewView report exceeds bounded proof size")
	}
	return nil
}

func (hsm *HotstuffProtocolManager) fhsApplication() (FHSApplication, bool) {
	if hsm == nil || hsm.app == nil || !hsm.app.UseFHS2Chain() {
		return nil, false
	}
	app, ok := hsm.app.(FHSApplication)
	return app, ok
}

func (hsm *HotstuffProtocolManager) usesFHSProtocolV2() bool {
	_, ok := hsm.fhsApplication()
	return ok
}

func (hsm *HotstuffProtocolManager) makeFHSContext(state []byte, leaderID string, targetView uint64) (*FHSViewContext, *TimeoutCertificate, error) {
	app, ok := hsm.fhsApplication()
	if !ok {
		return nil, nil, fmt.Errorf("Fair HotStuff application callbacks are unavailable")
	}
	view := bftview.DecodeToView(state)
	if view == nil || leaderID == "" || targetView == 0 {
		return nil, nil, ErrInvalidLeaderView
	}
	ctx := &FHSViewContext{
		Version:       fhsWireVersion,
		ChainID:       hsm.app.ChainID(),
		TargetView:    targetView,
		KeyNumber:     view.KeyNumber,
		KeyHash:       view.KeyHash,
		CommitteeHash: view.CommitteeHash,
		LeaderID:      leaderID,
		EntryKind:     FHSViewFromQC,
	}
	tc := app.HighestFHSTimeoutCertificate()
	if tc != nil && tc.Statement.TimedOutView+1 == targetView {
		ctx.EntryKind = FHSViewFromTimeout
		ctx.EntryID = tc.Statement.ID()
	} else {
		tc = nil
	}
	if err := ctx.Validate(); err != nil {
		return nil, nil, err
	}
	return ctx, tc, nil
}

func (hsm *HotstuffProtocolManager) createFHSView(asLeader bool, phase uint32, ctx *FHSViewContext, state []byte) (*View, error) {
	if ctx == nil {
		return nil, ErrInvalidLeaderView
	}
	viewState := bftview.DecodeToView(state)
	if viewState == nil || viewState.KeyNumber != ctx.KeyNumber || viewState.KeyHash != ctx.KeyHash || viewState.CommitteeHash != ctx.CommitteeHash {
		return nil, ErrInvalidLeaderView
	}
	v, err := hsm.createView(asLeader, phase, ctx.LeaderID, state, ctx.TargetView)
	if err != nil {
		return nil, err
	}
	v.hash = ctx.ID()
	contextCopy := *ctx
	v.fhsContext = &contextCopy
	v.fhsReports = make(map[uint32]*NewViewReport)
	v.fhsReportSigns = make(map[uint32]*bls.Sign)
	return v, nil
}

func (hsm *HotstuffProtocolManager) fhsCommittee(ctx *FHSViewContext, needIP bool) (*bftview.Committee, []*bls.PublicKey, error) {
	if ctx == nil {
		return nil, nil, ErrInvalidLeaderView
	}
	committee := bftview.LoadMember(ctx.KeyNumber, ctx.KeyHash, needIP)
	if committee == nil || committee.RlpHash() != ctx.CommitteeHash {
		return nil, nil, ErrInvalidLeaderView
	}
	keys, err := hsm.app.GetPublicKey(ctx.KeyHash)
	if err != nil {
		return nil, nil, err
	}
	keys, err = snapshotPublicKeys(keys)
	if err != nil {
		return nil, nil, err
	}
	if len(keys) != len(committee.List) {
		return nil, nil, ErrInvalidPublicKey
	}
	if err := ValidateBFTCommitteeSize(len(keys)); err != nil {
		return nil, nil, err
	}
	return committee, keys, nil
}

func fhsMemberID(committee *bftview.Committee, index int) string {
	if committee == nil || index < 0 || index >= len(committee.List) || committee.List[index] == nil {
		return ""
	}
	node := committee.List[index]
	return bftview.GetNodeID(node.Address, node.Public)
}

func fhsFindMember(committee *bftview.Committee, id string) int {
	if committee == nil || id == "" {
		return -1
	}
	for index := range committee.List {
		if fhsMemberID(committee, index) == id {
			return index
		}
	}
	return -1
}

func (hsm *HotstuffProtocolManager) verifyFHSContextCertificate(ctx *FHSViewContext, tc *TimeoutCertificate, keys []*bls.PublicKey) error {
	if ctx.EntryKind == FHSViewFromQC {
		if tc != nil || ctx.EntryID != (common.Hash{}) {
			return ErrInvalidHighQC
		}
		return nil
	}
	if tc == nil || tc.Statement.ID() != ctx.EntryID || tc.Statement.ChainID != ctx.ChainID ||
		tc.Statement.TimedOutView+1 != ctx.TargetView || tc.Statement.KeyNumber != ctx.KeyNumber ||
		tc.Statement.KeyHash != ctx.KeyHash || tc.Statement.CommitteeHash != ctx.CommitteeHash {
		return ErrInvalidHighQC
	}
	return VerifyTimeoutCertificate(tc, keys, CalcThreshold(len(keys)))
}

// attachFHSContextCertificate keeps the transition certificate on the View
// that will eventually produce a Prepare. A replica may create this View when
// it sends its own NewView before the leader receives the first remote report,
// so acceptFHSNewView can legitimately reuse an existing View. Losing the TC
// in that merge produces a timeout-derived Prepare without DataD, which every
// correct replica must reject.
func attachFHSContextCertificate(v *View, ctx *FHSViewContext, tc *TimeoutCertificate) error {
	if v == nil || ctx == nil {
		return ErrInvalidHighQC
	}
	if ctx.EntryKind == FHSViewFromQC {
		if tc != nil || ctx.EntryID != (common.Hash{}) {
			return ErrInvalidHighQC
		}
		v.fhsTimeout = nil
		return nil
	}
	if tc == nil || tc.Statement.ID() != ctx.EntryID ||
		tc.Statement.TimedOutView+1 != ctx.TargetView {
		return ErrInvalidHighQC
	}
	if v.fhsTimeout != nil && v.fhsTimeout.Statement.ID() != tc.Statement.ID() {
		return ErrInvalidHighQC
	}
	v.fhsTimeout = CloneTimeoutCertificate(tc)
	return nil
}

func (hsm *HotstuffProtocolManager) newFHSNewView() error {
	app, ok := hsm.fhsApplication()
	if !ok {
		return fmt.Errorf("Fair HotStuff application callbacks are unavailable")
	}
	state, leaderID, targetView := hsm.app.CurrentState()
	ctx, tc, err := hsm.makeFHSContext(state, leaderID, targetView)
	if err != nil {
		return err
	}
	v, err := hsm.createFHSView(false, PhasePrepare, ctx, state)
	if err != nil {
		return err
	}
	index := v.lookupReplica(hsm.publicKey)
	if index < 0 {
		return ErrInvalidReplica
	}
	report := &NewViewReport{
		Context:     *ctx,
		SignerIndex: uint32(index),
		HighQC:      hsm.app.HighestCertified(),
		Extra:       append([]byte(nil), hsm.app.GetExtra()...),
	}
	reportBytes, err := EncodeNewViewReport(report)
	if err != nil {
		return err
	}
	if err := validateFHSNewViewReportSize(reportBytes, report); err != nil {
		return err
	}
	digest, err := NewViewReportDigest(report)
	if err != nil {
		return err
	}
	signature := hsm.secretKey.SignHash(digest)
	if signature == nil {
		return ErrQCVerification
	}
	msg := hsm.newMsg(MsgNewView, targetView, ctx.ID(), reportBytes, signature.Serialize(), nil)
	if tc != nil {
		msg.DataD, err = EncodeTimeoutCertificate(tc)
		if err != nil {
			return err
		}
	}
	if err := hsm.sealMessage(msg); err != nil {
		return err
	}
	if err := ValidateHotstuffWireMessage(msg); err != nil {
		return err
	}

	hsm.discardStaleReplicaNewViews(v.number, v.hash)
	if existing := hsm.views[v.hash]; existing != nil {
		v = existing
	} else {
		hsm.views[v.hash] = v
	}
	if err := attachFHSContextCertificate(v, ctx, tc); err != nil {
		return err
	}
	v.replicaMsg[MsgNewView] = msg
	v.lastReplicaRecoveryAt = time.Now()
	_ = app
	return hsm.app.Write(leaderID, msg)
}

func (hsm *HotstuffProtocolManager) validateFHSNewViewMsg(msg *HotstuffMessage) (*View, *VoteInfo, error) {
	app, ok := hsm.fhsApplication()
	if !ok || msg == nil {
		return nil, nil, ErrNewViewFail
	}
	report, err := DecodeNewViewReport(msg.DataA)
	if err != nil {
		return nil, nil, ErrNewViewFail
	}
	if err := validateFHSNewViewReportSize(msg.DataA, report); err != nil {
		return nil, nil, ErrNewViewFail
	}
	ctx := &report.Context
	if ctx.ChainID != hsm.app.ChainID() || msg.Number != ctx.TargetView || msg.ViewId != ctx.ID() || ctx.LeaderID != hsm.app.Self() {
		return nil, nil, ErrInvalidLeaderView
	}
	if ctx.TargetView > hsm.app.CurrentN()+maxPendingNewViewIDs {
		return nil, nil, ErrFutureState
	}
	committee, keys, err := hsm.fhsCommittee(ctx, true)
	if err != nil {
		return nil, nil, err
	}
	index := int(report.SignerIndex)
	if index < 0 || index >= len(keys) || fhsMemberID(committee, index) != msg.Id || !bytes.Equal(msg.PubKey, keys[index].Serialize()) {
		return nil, nil, ErrInvalidReplica
	}
	if err := hsm.verifyMessageAuth(msg, msg.Id, keys[index]); err != nil {
		return nil, nil, err
	}
	digest, err := NewViewReportDigest(report)
	if err != nil {
		return nil, nil, err
	}
	var sign bls.Sign
	if err := sign.Deserialize(msg.DataB); err != nil || !sign.VerifyHash(keys[index], digest) {
		return nil, nil, ErrQCVerification
	}
	if report.HighQC != nil {
		if err := hsm.verifyFHSParentQC(report.HighQC, ctx.TargetView); err != nil {
			return nil, nil, err
		}
	}
	tc, err := DecodeTimeoutCertificate(msg.DataD)
	if err != nil || hsm.verifyFHSContextCertificate(ctx, tc, keys) != nil {
		return nil, nil, ErrInvalidHighQC
	}

	// A valid QC/TC is itself sufficient proof to advance a lagging replica.
	// Persist it before accepting the report into any volatile queue.
	if report.HighQC != nil {
		if err := app.AdoptFHSHighQC(report.HighQC); err != nil {
			return nil, nil, err
		}
	}
	if tc != nil {
		if err := app.AcceptFHSTimeoutCertificate(tc); err != nil {
			return nil, nil, err
		}
	}
	if err := app.ValidateFHSContext(ctx); err != nil {
		return nil, nil, err
	}
	state, _, currentTarget := hsm.app.CurrentState()
	if currentTarget < ctx.TargetView {
		return nil, &VoteInfo{Index: index, PubKey: keys[index], KSign: sign, ValidKSign: true}, ErrFutureState
	}
	if currentTarget > ctx.TargetView {
		return nil, nil, ErrOldState
	}
	v, err := hsm.createFHSView(true, PhasePrepare, ctx, state)
	if err != nil {
		return nil, nil, err
	}
	v.fhsTimeout = CloneTimeoutCertificate(tc)
	vote := &VoteInfo{Index: index, PubKey: keys[index], KSign: sign, ValidKSign: true}
	return v, vote, nil
}

func (hsm *HotstuffProtocolManager) acceptFHSNewView(msg *HotstuffMessage, validated *View, vote *VoteInfo) error {
	if msg == nil || validated == nil || vote == nil {
		return ErrNewViewFail
	}
	report, err := DecodeNewViewReport(msg.DataA)
	if err != nil || int(report.SignerIndex) != vote.Index {
		return ErrNewViewFail
	}
	v := hsm.views[msg.ViewId]
	if v == nil {
		v = validated
		hsm.views[v.hash] = v
	}
	if v.fhsContext == nil || *v.fhsContext != report.Context {
		return ErrViewIdNotMatch
	}
	if err := attachFHSContextCertificate(v, &report.Context, validated.fhsTimeout); err != nil {
		return err
	}
	if _, duplicate := v.fhsReports[report.SignerIndex]; duplicate {
		return nil
	}
	if v.fhsReportBytes > maxFHSAggregateReportBytes-len(msg.DataA) {
		return fmt.Errorf("FHS aggregate NewView report budget exceeded")
	}
	if v.phaseAsLeader != PhasePrepare {
		if prepare := v.leaderMsg[MsgPrepare]; prepare != nil {
			return hsm.app.Write(msg.Id, prepare)
		}
		return nil
	}
	v.fhsReports[report.SignerIndex] = report
	v.fhsReportBytes += len(msg.DataA)
	signCopy := vote.KSign
	v.fhsReportSigns[report.SignerIndex] = &signCopy
	v.highVoteInfo = append(v.highVoteInfo, vote)
	if len(report.Extra) > 0 {
		v.extra = append(v.extra, append([]byte(nil), report.Extra...))
	}
	hsm.leaderView = v
	if len(v.fhsReports) < v.threshold {
		return ErrInsufficientQC
	}
	return hsm.activateFHSLeaderView(v)
}

func (hsm *HotstuffProtocolManager) buildFHSAggregate(v *View) (*AggregateQC, *SignedState, error) {
	if v == nil || v.fhsContext == nil || len(v.fhsReports) < v.threshold {
		return nil, nil, ErrInsufficientQC
	}
	indices := make([]int, 0, len(v.fhsReports))
	for index := range v.fhsReports {
		indices = append(indices, int(index))
	}
	sort.Ints(indices)
	aggregate := &AggregateQC{
		Context: *v.fhsContext,
		Reports: make([]NewViewReport, 0, len(indices)),
		Mask:    make([]byte, canonicalMaskLength(len(v.groupPublicKey))),
	}
	var combined bls.Sign
	for position, index := range indices {
		report := v.fhsReports[uint32(index)]
		signature := v.fhsReportSigns[uint32(index)]
		if report == nil || signature == nil {
			return nil, nil, ErrQCVerification
		}
		aggregate.Reports = append(aggregate.Reports, *report)
		aggregate.Mask[index/8] |= 1 << uint(index&7)
		if position == 0 {
			if err := combined.Deserialize(signature.Serialize()); err != nil {
				return nil, nil, err
			}
		} else {
			combined.Add(signature)
		}
	}
	aggregate.Sign = combined.Serialize()
	encoded, err := EncodeAggregateQC(aggregate)
	if err != nil {
		return nil, nil, err
	}
	if len(encoded) > maxFHSAggregateQCBytes {
		return nil, nil, fmt.Errorf("FHS aggregate QC exceeds bounded wire size")
	}
	highest, err := VerifyAggregateQC(aggregate, v.groupPublicKey, v.threshold, func(qc *SignedState) error {
		return hsm.verifyFHSParentQC(qc, v.number)
	})
	return aggregate, highest, err
}

func (hsm *HotstuffProtocolManager) activateFHSLeaderView(v *View) error {
	app, ok := hsm.fhsApplication()
	if !ok {
		return ErrInvalidLeaderView
	}
	aggregate, highest, err := hsm.buildFHSAggregate(v)
	if err != nil {
		return err
	}
	localHighest := hsm.app.HighestCertified()
	if localHighest != nil && (highest == nil || localHighest.Number > highest.Number ||
		(localHighest.Number == highest.Number && !SignedStateSemanticEqual(localHighest, highest))) {
		return ErrInvalidHighQC
	}
	if highest != nil {
		if err := app.AdoptFHSHighQC(highest); err != nil {
			return err
		}
	}
	state, leaderID, number := hsm.app.CurrentState()
	if leaderID != v.leaderId || number != v.number {
		return ErrInvalidLeaderView
	}
	v.currentState = append(v.currentState[:0], state...)
	v.fhsAggregate = aggregate
	v.fhsHighest = CloneSignedState(highest)
	if err := hsm.app.OnNewView(v.currentState, v.extra); err != nil {
		return err
	}
	v.phaseAsLeader = PhaseTryPropose
	v.lastLeaderRecoveryAt = time.Now()
	hsm.lockView(v)
	return hsm.TryPropose()
}

func (hsm *HotstuffProtocolManager) tryFHSPropose() error {
	v := hsm.leaderView
	if v == nil || v.fhsContext == nil || v.fhsAggregate == nil || v.phaseAsLeader != PhaseTryPropose {
		return ErrInvalidLeaderView
	}
	_, keys, err := hsm.fhsCommittee(v.fhsContext, true)
	if err != nil {
		return err
	}
	if err := hsm.verifyFHSContextCertificate(v.fhsContext, v.fhsTimeout, keys); err != nil {
		return err
	}
	err, kProposal, tProposal, extra := hsm.app.Propose(v.number, v.hash, v.leaderId)
	if err != nil {
		return err
	}
	if len(kProposal) == 0 && len(tProposal) == 0 {
		return ErrInvalidProposal
	}
	aggregateBytes, err := EncodeAggregateQC(v.fhsAggregate)
	if err != nil {
		return err
	}
	msg := hsm.newMsg(MsgPrepare, v.number, v.hash, kProposal, tProposal, aggregateBytes)
	if v.fhsTimeout != nil {
		msg.DataD, err = EncodeTimeoutCertificate(v.fhsTimeout)
		if err != nil {
			return err
		}
	}
	msg.DataE = append([]byte(nil), v.currentState...)
	msg.DataF = append([]byte(nil), extra...)
	if v.fhsHighest != nil {
		msg.DataG, err = EncodeSignedState(v.fhsHighest)
		if err != nil {
			return err
		}
	}
	if err := hsm.sealMessage(msg); err != nil {
		return err
	}
	if err := ValidateHotstuffWireMessage(msg); err != nil {
		return err
	}
	if len(kProposal) > 0 {
		v.proposedKState = append([]byte(nil), kProposal...)
		v.proposedKDigest = hotstuffDigest(v.proposedKState)
	}
	if len(tProposal) > 0 {
		v.proposedTState = append([]byte(nil), tProposal...)
		v.proposedTDigest = hotstuffDigest(v.proposedTState)
	}
	v.leaderMsg[MsgPrepare] = msg
	v.phaseAsLeader = PhasePreCommit
	v.waitingMoreVoteInfo = true
	v.waitingMoreVoteInfoAt = time.Now()
	v.lastLeaderRecoveryAt = v.waitingMoreVoteInfoAt
	hsm.leaderView = nil
	hsm.app.Broadcast(msg)
	return nil
}

func (hsm *HotstuffProtocolManager) handleFHSPrepareMsg(msg *HotstuffMessage) error {
	app, ok := hsm.fhsApplication()
	if !ok || msg == nil {
		return ErrInvalidProposal
	}
	aggregate, err := DecodeAggregateQC(msg.DataC)
	if err != nil {
		return ErrInvalidHighQC
	}
	ctx := &aggregate.Context
	if ctx.ChainID != hsm.app.ChainID() || ctx.TargetView != msg.Number || ctx.ID() != msg.ViewId || ctx.LeaderID != msg.Id {
		return ErrInvalidLeaderView
	}
	committee, keys, err := hsm.fhsCommittee(ctx, true)
	if err != nil {
		return err
	}
	leaderIndex := fhsFindMember(committee, ctx.LeaderID)
	if leaderIndex < 0 || leaderIndex >= len(keys) {
		return ErrInvalidLeaderView
	}
	if err := hsm.verifyMessageAuth(msg, ctx.LeaderID, keys[leaderIndex]); err != nil {
		return err
	}
	tc, err := DecodeTimeoutCertificate(msg.DataD)
	if err != nil {
		return ErrInvalidHighQC
	}
	if err := hsm.verifyFHSContextCertificate(ctx, tc, keys); err != nil {
		return err
	}
	highest, err := VerifyAggregateQC(aggregate, keys, CalcThreshold(len(keys)), func(qc *SignedState) error {
		return hsm.verifyFHSParentQC(qc, ctx.TargetView)
	})
	if err != nil {
		return ErrInvalidHighQC
	}
	carriedHighest, err := DecodeSignedState(msg.DataG)
	if err != nil || !SignedStateSemanticEqual(highest, carriedHighest) {
		return ErrInvalidHighQC
	}
	localHighest := hsm.app.HighestCertified()
	if localHighest != nil && (highest == nil || localHighest.Number > highest.Number ||
		(localHighest.Number == highest.Number && !SignedStateSemanticEqual(localHighest, highest))) {
		return ErrInvalidHighQC
	}
	if highest != nil {
		if err := app.AdoptFHSHighQC(highest); err != nil {
			return err
		}
	}
	if tc != nil {
		if err := app.AcceptFHSTimeoutCertificate(tc); err != nil {
			return err
		}
	}
	if err := app.ValidateFHSContext(ctx); err != nil {
		return err
	}
	state, leaderID, number := hsm.app.CurrentState()
	if leaderID != ctx.LeaderID || number != ctx.TargetView {
		return ErrInvalidLeaderView
	}

	v := hsm.views[msg.ViewId]
	if v == nil {
		v, err = hsm.createFHSView(false, PhasePrepare, ctx, state)
		if err != nil {
			return err
		}
		hsm.views[v.hash] = v
	} else if v.fhsContext == nil || *v.fhsContext != *ctx {
		return ErrViewIdNotMatch
	}
	if v.phaseAsReplica != PhasePrepare {
		if cached := v.replicaMsg[MsgVotePrepare]; cached != nil {
			return hsm.app.Write(msg.Id, cached)
		}
		return ErrViewPhaseNotMatch
	}
	v.fhsAggregate = aggregate
	v.fhsHighest = CloneSignedState(highest)
	v.fhsTimeout = CloneTimeoutCertificate(tc)
	v.currentState = append(v.currentState[:0], state...)

	if err := hsm.app.OnPropose(msg.DataB, msg.DataF, v.number, highest); err != nil {
		return ErrInvalidProposal
	}
	if len(msg.DataA) > 0 {
		v.proposedKState = append([]byte(nil), msg.DataA...)
		v.proposedKDigest = hotstuffDigest(v.proposedKState)
	}
	if len(msg.DataB) > 0 {
		v.proposedTState = append([]byte(nil), msg.DataB...)
		v.proposedTDigest = hotstuffDigest(v.proposedTState)
	}
	persisted := &PersistedVote{
		ViewNumber: v.number,
		ViewID:     v.hash,
		LeaderID:   v.leaderId,
		KState:     append([]byte(nil), v.proposedKState...),
		TState:     append([]byte(nil), v.proposedTState...),
		Extra:      append([]byte(nil), msg.DataF...),
	}
	if len(persisted.KState) > 0 {
		persisted.KStateHash = StateDigest(persisted.KState)
	}
	if len(persisted.TState) > 0 {
		persisted.TStateHash = StateDigest(persisted.TState)
	}
	// The WAL must be durable before either the signature or the message can
	// escape to the network.
	if err := app.PersistFHSVote(persisted); err != nil {
		return err
	}
	var kSign, tSign []byte
	if len(v.proposedKState) > 0 {
		kSign = hsm.SignHashByMessage(MsgVotePrepare, v.hash, v.leaderId, v.proposedKState)
	}
	if len(v.proposedTState) > 0 {
		tSign = hsm.SignHashByMessage(MsgVotePrepare, v.hash, v.leaderId, v.proposedTState)
	}
	vote := hsm.newMsg(MsgVotePrepare, v.number, v.hash, nil, kSign, tSign)
	if err := hsm.sealMessage(vote); err != nil {
		return err
	}
	v.replicaMsg[MsgVotePrepare] = vote
	v.leaderMsg[MsgPrepare] = msg
	v.lastReplicaRecoveryAt = time.Now()
	v.phaseAsReplica = PhaseDecide
	hsm.lockView(v)
	return hsm.app.Write(msg.Id, vote)
}

func (hsm *HotstuffProtocolManager) timeoutStatementForCurrentView() (*TimeoutStatement, error) {
	state, _, activeView := hsm.app.CurrentState()
	view := bftview.DecodeToView(state)
	if view == nil || activeView == 0 {
		return nil, ErrInvalidLeaderView
	}
	statement := &TimeoutStatement{
		Version:       fhsWireVersion,
		ChainID:       hsm.app.ChainID(),
		TimedOutView:  activeView,
		KeyNumber:     view.KeyNumber,
		KeyHash:       view.KeyHash,
		CommitteeHash: view.CommitteeHash,
	}
	if _, err := TimeoutStatementDigest(statement); err != nil {
		return nil, err
	}
	return statement, nil
}

// LocalTimeout broadcasts a durable timeout vote. It deliberately does not
// mutate the view; only a verified 2f+1 timeout certificate may do that.
func (hsm *HotstuffProtocolManager) LocalTimeout() error {
	if !hsm.usesFHSProtocolV2() {
		return ErrInvalidLeaderView
	}
	statement, err := hsm.timeoutStatementForCurrentView()
	if err != nil {
		return err
	}
	return hsm.broadcastTimeoutVote(statement)
}

func (hsm *HotstuffProtocolManager) broadcastTimeoutVote(statement *TimeoutStatement) error {
	app, ok := hsm.fhsApplication()
	if !ok || statement == nil {
		return ErrInvalidLeaderView
	}
	id := statement.ID()
	hsm.pruneTimeoutState(hsm.app.CurrentN())
	if hsm.timeoutEchoed[id] {
		return nil
	}
	if err := app.PersistFHSTimeoutVote(statement); err != nil {
		return err
	}
	digest, err := TimeoutStatementDigest(statement)
	if err != nil {
		return err
	}
	digest, err = fhsSignerDigest(digest, hsm.publicKey)
	if err != nil {
		return err
	}
	signature := hsm.secretKey.SignHash(digest)
	if signature == nil {
		return ErrQCVerification
	}
	encoded, err := rlp.EncodeToBytes(statement)
	if err != nil {
		return err
	}
	msg := hsm.newMsg(MsgTimeout, statement.TimedOutView, id, encoded, signature.Serialize(), nil)
	if err := hsm.sealMessage(msg); err != nil {
		return err
	}
	hsm.timeoutEchoed[id] = true
	hsm.timeoutSeen[id] = time.Now()
	hsm.timeoutView[id] = statement.TimedOutView
	hsm.app.Broadcast(msg)
	return nil
}

func decodeTimeoutStatement(data []byte) (*TimeoutStatement, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty timeout statement")
	}
	var statement TimeoutStatement
	if err := rlp.DecodeBytes(data, &statement); err != nil {
		return nil, err
	}
	if _, err := TimeoutStatementDigest(&statement); err != nil {
		return nil, err
	}
	return &statement, nil
}

func (hsm *HotstuffProtocolManager) validateTimeoutSender(msg *HotstuffMessage, statement *TimeoutStatement) (int, []*bls.PublicKey, error) {
	if msg == nil || statement == nil || msg.Number != statement.TimedOutView || msg.ViewId != statement.ID() || statement.ChainID != hsm.app.ChainID() {
		return -1, nil, ErrViewIdNotMatch
	}
	active := hsm.app.CurrentN()
	if msg.Code == MsgTimeout {
		if statement.TimedOutView != active {
			return -1, nil, ErrViewIdNotMatch
		}
	} else if statement.TimedOutView+1 < active || statement.TimedOutView > active+maxPendingNewViewIDs {
		return -1, nil, ErrViewIdNotMatch
	}
	ctx := &FHSViewContext{
		Version:       fhsWireVersion,
		ChainID:       statement.ChainID,
		TargetView:    statement.TimedOutView + 1,
		KeyNumber:     statement.KeyNumber,
		KeyHash:       statement.KeyHash,
		CommitteeHash: statement.CommitteeHash,
		LeaderID:      msg.Id,
		EntryKind:     FHSViewFromTimeout,
		EntryID:       statement.ID(),
	}
	committee, keys, err := hsm.fhsCommittee(ctx, true)
	if err != nil {
		return -1, nil, err
	}
	index := fhsFindMember(committee, msg.Id)
	if index < 0 || !bytes.Equal(msg.PubKey, keys[index].Serialize()) {
		return -1, nil, ErrInvalidReplica
	}
	if err := hsm.verifyMessageAuth(msg, msg.Id, keys[index]); err != nil {
		return -1, nil, err
	}
	return index, keys, nil
}

func (hsm *HotstuffProtocolManager) pruneTimeoutState(current uint64) {
	now := time.Now()
	for id, seen := range hsm.timeoutSeen {
		view := hsm.timeoutView[id]
		if now.Sub(seen) > pendingMessageTTL || view+1 < current {
			delete(hsm.timeoutVotes, id)
			delete(hsm.timeoutEchoed, id)
			delete(hsm.timeoutQC, id)
			delete(hsm.timeoutSeen, id)
			delete(hsm.timeoutView, id)
		}
	}
	for len(hsm.timeoutSeen) >= maxTimeoutStates {
		var oldestID common.Hash
		var oldest time.Time
		for id, seen := range hsm.timeoutSeen {
			if oldest.IsZero() || seen.Before(oldest) {
				oldestID, oldest = id, seen
			}
		}
		delete(hsm.timeoutVotes, oldestID)
		delete(hsm.timeoutEchoed, oldestID)
		delete(hsm.timeoutQC, oldestID)
		delete(hsm.timeoutSeen, oldestID)
		delete(hsm.timeoutView, oldestID)
	}
}

func (hsm *HotstuffProtocolManager) handleTimeoutMsg(msg *HotstuffMessage) error {
	statement, err := decodeTimeoutStatement(msg.DataA)
	if err != nil {
		return err
	}
	index, keys, err := hsm.validateTimeoutSender(msg, statement)
	if err != nil {
		return err
	}
	digest, _ := TimeoutStatementDigest(statement)
	digest, err = fhsSignerDigest(digest, keys[index])
	if err != nil {
		return err
	}
	var signature bls.Sign
	if err := signature.Deserialize(msg.DataB); err != nil || !signature.VerifyHash(keys[index], digest) {
		return ErrQCVerification
	}
	id := statement.ID()
	hsm.pruneTimeoutState(hsm.app.CurrentN())
	hsm.timeoutSeen[id] = time.Now()
	hsm.timeoutView[id] = statement.TimedOutView
	votes := hsm.timeoutVotes[id]
	if votes == nil {
		votes = make(map[int]*bls.Sign)
		hsm.timeoutVotes[id] = votes
	}
	if _, duplicate := votes[index]; !duplicate {
		copySign := signature
		votes[index] = &copySign
	}
	f := (len(keys) - 1) / 3
	if len(votes) >= f+1 && !hsm.timeoutEchoed[id] {
		if err := hsm.broadcastTimeoutVote(statement); err != nil {
			return err
		}
	}
	if len(votes) < CalcThreshold(len(keys)) || hsm.timeoutQC[id] != nil {
		return ErrInsufficientQC
	}
	tc, err := buildTimeoutCertificate(statement, votes, len(keys))
	if err != nil {
		return err
	}
	if err := VerifyTimeoutCertificate(tc, keys, CalcThreshold(len(keys))); err != nil {
		return err
	}
	app, _ := hsm.fhsApplication()
	if err := app.AcceptFHSTimeoutCertificate(tc); err != nil {
		return err
	}
	hsm.timeoutQC[id] = CloneTimeoutCertificate(tc)
	return hsm.broadcastTimeoutCertificate(tc)
}

func buildTimeoutCertificate(statement *TimeoutStatement, votes map[int]*bls.Sign, committeeSize int) (*TimeoutCertificate, error) {
	if statement == nil || len(votes) == 0 {
		return nil, ErrInsufficientQC
	}
	indices := make([]int, 0, len(votes))
	for index := range votes {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	mask := make([]byte, canonicalMaskLength(committeeSize))
	var aggregate bls.Sign
	for position, index := range indices {
		if index < 0 || index >= committeeSize || votes[index] == nil {
			return nil, ErrInvalidReplica
		}
		mask[index/8] |= 1 << uint(index&7)
		if position == 0 {
			if err := aggregate.Deserialize(votes[index].Serialize()); err != nil {
				return nil, err
			}
		} else {
			aggregate.Add(votes[index])
		}
	}
	return &TimeoutCertificate{Statement: *statement, Sign: aggregate.Serialize(), Mask: mask}, nil
}

func (hsm *HotstuffProtocolManager) broadcastTimeoutCertificate(tc *TimeoutCertificate) error {
	encoded, err := rlp.EncodeToBytes(&tc.Statement)
	if err != nil {
		return err
	}
	msg := hsm.newMsg(MsgTimeoutQC, tc.Statement.TimedOutView, tc.Statement.ID(), encoded, tc.Sign, tc.Mask)
	if err := hsm.sealMessage(msg); err != nil {
		return err
	}
	hsm.app.Broadcast(msg)
	return hsm.NewView()
}

func (hsm *HotstuffProtocolManager) handleTimeoutQCMsg(msg *HotstuffMessage) error {
	statement, err := decodeTimeoutStatement(msg.DataA)
	if err != nil {
		return err
	}
	_, keys, err := hsm.validateTimeoutSender(msg, statement)
	if err != nil {
		return err
	}
	tc := &TimeoutCertificate{Statement: *statement, Sign: append([]byte(nil), msg.DataB...), Mask: append([]byte(nil), msg.DataC...)}
	if err := VerifyTimeoutCertificate(tc, keys, CalcThreshold(len(keys))); err != nil {
		return err
	}
	app, _ := hsm.fhsApplication()
	if err := app.AcceptFHSTimeoutCertificate(tc); err != nil {
		return err
	}
	id := statement.ID()
	hsm.pruneTimeoutState(hsm.app.CurrentN())
	hsm.timeoutSeen[id] = time.Now()
	hsm.timeoutView[id] = statement.TimedOutView
	if hsm.timeoutQC[id] != nil {
		return nil
	}
	hsm.timeoutQC[id] = CloneTimeoutCertificate(tc)
	return hsm.NewView()
}
