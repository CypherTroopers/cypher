package hotstuff

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
)

const (
	maxFHSNewViewExtraBytes    = 2 * 1024
	maxFHSNewViewReportBytes   = 8 * 1024
	maxFHSAggregateReportBytes = 256 * 1024
	maxFHSAggregateQCBytes     = 320 * 1024
	// HighQC validation may retain more than one already-authenticated control
	// message while the body/EVM worker catches up. Keep the aggregate memory
	// bounded independently from the per-message wire limit and count limit;
	// three envelopes leave RLP headroom for two maximum-size continuations.
	maxFHSHighQCContinuationBytes = 3 * MaxHotstuffControlBytes
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

// validateFHSHighQCScheduleTarget prevents an authenticated sender from using
// arbitrary target views to start HighQC workers. The current canonical target
// is checked immediately. A future target is eligible only when the verified
// HighQC directly certifies its preceding view; a verified TC is accepted by
// the caller first and advances CurrentState to the exact target. Future views
// without either proof remain in the existing bounded NewView queue.
func (hsm *HotstuffProtocolManager) validateFHSHighQCScheduleTarget(ctx *FHSViewContext, highQC *SignedState) error {
	app, ok := hsm.fhsApplication()
	if !ok || ctx == nil {
		return ErrInvalidLeaderView
	}
	var currentTarget uint64
	if readiness, ok := hsm.app.(FHSProposalReadinessApplication); ok {
		_, currentTarget, _ = readiness.FHSProposalReadinessSnapshot()
	} else {
		_, _, currentTarget = hsm.app.CurrentState()
	}
	if currentTarget == 0 || ctx.TargetView == 0 {
		return ErrInvalidLeaderView
	}
	if ctx.TargetView < currentTarget {
		return ErrOldState
	}
	directQCProof := highQC != nil && highQC.Number < ctx.TargetView && ctx.TargetView-highQC.Number == 1
	current := hsm.app.CurrentN()
	farFuture := ctx.TargetView > current && ctx.TargetView-current > maxPendingNewViewIDs
	if (farFuture || ctx.TargetView > currentTarget) && !directQCProof {
		return ErrFutureState
	}
	if ctx.TargetView == currentTarget {
		return app.ValidateFHSContext(ctx)
	}
	return nil
}

// sameFHSHighQCContinuationSlot assigns one pending slot to each authenticated
// signer and message kind across every view. A single signer therefore cannot
// consume the continuation count by changing only the target view.
func sameFHSHighQCContinuationSlot(a, b *HotstuffMessage) bool {
	return a != nil && b != nil && a.Code == b.Code && a.Id == b.Id
}

// preferFHSHighQCContinuation deterministically advances a signer's slot. A
// strictly higher view replaces a lower view, so a stale first arrival cannot
// hide the signer's later valid NewView. Same-height conflicts and equivalent
// wire encodings retain the first authenticated copy, preventing hash-grinding
// from repeatedly rewriting the slot.
func preferFHSHighQCContinuation(candidate, existing *HotstuffMessage) bool {
	if candidate == nil || existing == nil {
		return candidate != nil
	}
	return candidate.Number > existing.Number
}

func fhsHighQCContinuationMessageBytes(msg *HotstuffMessage) (int, error) {
	if msg == nil {
		return 0, nil
	}
	canonical := cloneFHSPrepare(msg)
	canonical.ReceivedAt = time.Time{}
	encoded, err := rlp.EncodeToBytes(canonical)
	if err != nil {
		return 0, err
	}
	return len(encoded), nil
}

func fhsHighQCContinuationBytes(pending *pendingFHSHighQCValidation) (int, error) {
	if pending == nil {
		return 0, ErrInvalidHighQC
	}
	total := len(pending.leaderViews) * common.HashLength
	for _, msg := range pending.messages {
		size, err := fhsHighQCContinuationMessageBytes(msg)
		if err != nil {
			return 0, err
		}
		if size > maxFHSHighQCContinuationBytes-total {
			return 0, fmt.Errorf("FHS HighQC continuation byte limit reached")
		}
		total += size
	}
	return total, nil
}

func appendFHSHighQCContinuation(pending *pendingFHSHighQCValidation, resumeMessage *HotstuffMessage, resumeLeaderView common.Hash) error {
	if pending == nil {
		return ErrInvalidHighQC
	}
	if resumeMessage != nil {
		replace := -1
		for index, existing := range pending.messages {
			if sameFHSHighQCContinuationSlot(existing, resumeMessage) {
				if !preferFHSHighQCContinuation(resumeMessage, existing) {
					return nil
				}
				replace = index
				break
			}
		}
		if replace < 0 {
			if len(pending.messages) >= maxPendingNewViewsPerID {
				return fmt.Errorf("FHS HighQC continuation limit reached")
			}
		}
		used, err := fhsHighQCContinuationBytes(pending)
		if err != nil {
			return err
		}
		if replace >= 0 {
			replacedBytes, err := fhsHighQCContinuationMessageBytes(pending.messages[replace])
			if err != nil {
				return err
			}
			used -= replacedBytes
		}
		size, err := fhsHighQCContinuationMessageBytes(resumeMessage)
		if err != nil {
			return err
		}
		if size > maxFHSHighQCContinuationBytes-used {
			return fmt.Errorf("FHS HighQC continuation byte limit reached")
		}
		if replace >= 0 {
			pending.messages[replace] = cloneFHSPrepare(resumeMessage)
		} else {
			pending.messages = append(pending.messages, cloneFHSPrepare(resumeMessage))
		}
	}
	if resumeLeaderView != (common.Hash{}) {
		if pending.leaderViews == nil {
			pending.leaderViews = make(map[common.Hash]struct{})
		}
		if _, duplicate := pending.leaderViews[resumeLeaderView]; !duplicate {
			if len(pending.leaderViews) >= maxPendingNewViewsPerID {
				return fmt.Errorf("FHS HighQC leader continuation limit reached")
			}
			used, err := fhsHighQCContinuationBytes(pending)
			if err != nil {
				return err
			}
			if common.HashLength > maxFHSHighQCContinuationBytes-used {
				return fmt.Errorf("FHS HighQC continuation byte limit reached")
			}
			pending.leaderViews[resumeLeaderView] = struct{}{}
		}
	}
	return nil
}

func (hsm *HotstuffProtocolManager) scheduleFHSHighQCCatchup(qc *SignedState, targetView uint64, resumeMessage *HotstuffMessage, resumeLeaderView common.Hash) error {
	app, ok := hsm.fhsApplication()
	if !ok || qc == nil {
		return ErrInvalidHighQC
	}
	local := hsm.app.HighestCertified()
	if local != nil {
		switch {
		case local.Number > qc.Number:
			return nil
		case local.Number == qc.Number:
			if SignedStateSemanticEqual(local, qc) {
				return nil
			}
			return ErrInvalidHighQC
		}
	}
	async, ok := hsm.app.(FHSHighQCValidationApplication)
	if !ok {
		return app.AdoptFHSHighQC(qc)
	}
	id, err := SignedStateID(qc)
	if err != nil {
		return ErrInvalidHighQC
	}
	qcID := id.Hash()
	if targetView == 0 {
		targetView = qc.Number + 1
	}
	previous := hsm.pendingHighQC
	if pending := hsm.pendingHighQC; pending != nil {
		switch {
		case pending.key.QCID == qcID:
			if !SignedStateSemanticEqual(pending.qc, qc) {
				return ErrInvalidHighQC
			}
			if targetView < pending.key.TargetView {
				return ErrOldState
			}
			// TargetView only identifies the control-plane continuation; the
			// expensive worker validates the same semantic QC. Coalesce a newer
			// valid target behind the existing worker instead of cancelling and
			// restarting identical body/EVM work.
			if err := appendFHSHighQCContinuation(pending, resumeMessage, resumeLeaderView); err != nil {
				return err
			}
			return ErrProposalValidationPending
		case pending.qc != nil && pending.qc.Number >= qc.Number:
			return ErrOldState
		}
	}

	hsm.validationSequence++
	if hsm.validationSequence == 0 {
		hsm.validationSequence++
	}
	key := FHSHighQCValidationKey{RequestID: hsm.validationSequence, QCID: qcID, TargetView: targetView}
	pending := &pendingFHSHighQCValidation{
		key:         key,
		qc:          CloneSignedState(qc),
		leaderViews: make(map[common.Hash]struct{}),
	}
	// A newer certificate supersedes the worker, not the already-authenticated
	// control messages waiting behind it. Move those bounded continuations to
	// the replacement request and revalidate them only after the newer QC has
	// been installed. If the bound is already full, leave the old request alive
	// and reject the additional continuation instead of silently dropping one.
	if previous != nil {
		for _, message := range previous.messages {
			if err := appendFHSHighQCContinuation(pending, message, common.Hash{}); err != nil {
				return err
			}
		}
		leaderViews := make([]common.Hash, 0, len(previous.leaderViews))
		for viewID := range previous.leaderViews {
			leaderViews = append(leaderViews, viewID)
		}
		sort.Slice(leaderViews, func(i, j int) bool { return bytes.Compare(leaderViews[i][:], leaderViews[j][:]) < 0 })
		for _, viewID := range leaderViews {
			if err := appendFHSHighQCContinuation(pending, nil, viewID); err != nil {
				return err
			}
		}
	}
	if err := appendFHSHighQCContinuation(pending, resumeMessage, resumeLeaderView); err != nil {
		return err
	}
	hsm.pendingHighQC = pending
	if err := async.ScheduleFHSHighQCValidation(&FHSHighQCValidationRequest{Key: key, QC: CloneSignedState(qc)}); err != nil {
		if hsm.pendingHighQC == pending {
			// The application scheduler rejects a lower target before cancelling
			// its still-live worker. Restore that exact manager request and retain
			// the authenticated continuation behind it. When the older worker
			// completes, normal replay will re-evaluate the newer certificate and
			// schedule it against the then-current canonical state.
			if previous != nil && errors.Is(err, ErrOldState) {
				hsm.pendingHighQC = previous
				if retainErr := appendFHSHighQCContinuation(previous, resumeMessage, resumeLeaderView); retainErr != nil {
					return retainErr
				}
				return ErrProposalValidationPending
			}
			hsm.pendingHighQC = nil
		}
		return err
	}
	return ErrProposalValidationPending
}

// RecoverFHSHighQC starts the same bounded validation/catch-up path used for a
// network HighQC, without manufacturing a wire message during startup. The
// caller keeps normal consensus gated until the asynchronous result installs
// this exact durable certificate.
func (hsm *HotstuffProtocolManager) RecoverFHSHighQC(qc *SignedState, targetView uint64) error {
	if hsm == nil {
		return ErrInvalidHighQC
	}
	hsm.applyScheduledFHSEpochReset()
	return hsm.scheduleFHSHighQCCatchup(qc, targetView, nil, common.Hash{})
}

// certifyFHSQC schedules any missing body/EVM catch-up before invoking the
// ordinary certification callback. The QCBroadcast itself is retained as an
// exact continuation, so after the worker publishes the QC it is replayed and
// performs only the small idempotent completion callback. Applications without
// the async interface keep the synchronous behavior used by focused tests.
func (hsm *HotstuffProtocolManager) certifyFHSQC(qc *SignedState, resumeMessage *HotstuffMessage) error {
	if hsm == nil || qc == nil {
		return ErrInvalidHighQC
	}
	if _, ok := hsm.fhsApplication(); !ok {
		return hsm.app.OnCertified(qc)
	}
	if _, ok := hsm.app.(FHSHighQCValidationApplication); !ok {
		return hsm.app.OnCertified(qc)
	}
	if local := hsm.app.HighestCertified(); local != nil {
		switch {
		case local.Number > qc.Number:
			return nil
		case local.Number == qc.Number:
			if !SignedStateSemanticEqual(local, qc) {
				return ErrInvalidHighQC
			}
			return hsm.app.OnCertified(qc)
		}
	}
	return hsm.scheduleFHSHighQCCatchup(qc, qc.Number+1, resumeMessage, common.Hash{})
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

	// Both proofs have passed cryptographic verification above. A TC is an
	// independent 2f+1 pacemaker proof, so persist it before adopting HighQC:
	// proposal-body catch-up for a valid HighQC may fail transiently, but that
	// must not prevent a lagging replica from retaining the proven view jump.
	if tc != nil {
		if err := app.AcceptFHSTimeoutCertificate(tc); err != nil {
			return nil, nil, err
		}
	}
	vote := &VoteInfo{Index: index, PubKey: keys[index], KSign: sign, ValidKSign: true}
	if err := hsm.validateFHSHighQCScheduleTarget(ctx, report.HighQC); err != nil {
		if errors.Is(err, ErrFutureState) {
			return nil, vote, ErrFutureState
		}
		return nil, nil, err
	}
	if report.HighQC != nil {
		if err := hsm.scheduleFHSHighQCCatchup(report.HighQC, ctx.TargetView, msg, common.Hash{}); err != nil {
			return nil, nil, err
		}
	}
	// A synchronous catch-up may have advanced the canonical target. Repeat the
	// exact-context check before creating any volatile view state.
	if err := app.ValidateFHSContext(ctx); err != nil {
		return nil, nil, err
	}
	state, _, currentTarget := hsm.app.CurrentState()
	if currentTarget < ctx.TargetView {
		return nil, vote, ErrFutureState
	}
	if currentTarget > ctx.TargetView {
		return nil, nil, ErrOldState
	}
	v, err := hsm.createFHSView(true, PhasePrepare, ctx, state)
	if err != nil {
		return nil, nil, err
	}
	v.fhsTimeout = CloneTimeoutCertificate(tc)
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
	_, ok := hsm.fhsApplication()
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
	if err := hsm.validateFHSHighQCScheduleTarget(v.fhsContext, highest); err != nil {
		return err
	}
	if highest != nil {
		if err := hsm.scheduleFHSHighQCCatchup(highest, v.number, nil, v.hash); err != nil {
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
	async, ok := hsm.app.(FHSProposalBuildApplication)
	if !ok {
		return ErrInvalidProposal
	}
	if v.fhsBuild != nil {
		return ErrProposalValidationPending
	}
	var parentQCID common.Hash
	if v.fhsHighest != nil {
		id, err := SignedStateID(v.fhsHighest)
		if err != nil {
			return ErrInvalidHighQC
		}
		parentQCID = id.Hash()
	}
	hsm.validationSequence++
	if hsm.validationSequence == 0 {
		hsm.validationSequence++
	}
	key := FHSProposalBuildKey{
		RequestID:          hsm.validationSequence,
		ViewNumber:         v.number,
		ViewID:             v.hash,
		LeaderID:           v.leaderId,
		CurrentStateDigest: StateDigest(v.currentState),
		ParentQCID:         parentQCID,
	}
	v.fhsBuild = &key
	request := &FHSProposalBuildRequest{
		Key:          key,
		CurrentState: append([]byte(nil), v.currentState...),
		ParentQC:     CloneSignedState(v.fhsHighest),
	}
	if err := async.ScheduleFHSProposalBuild(request); err != nil {
		v.fhsBuild = nil
		return err
	}
	return ErrProposalValidationPending
}

// CompleteFHSProposalBuild verifies a worker result against the exact active
// leader view, seals the wire message, and only then permits the application to
// publish its staged proposal. After Apply succeeds, all remaining operations
// are infallible local state changes followed by the existing recoverable
// network broadcast.
func (hsm *HotstuffProtocolManager) CompleteFHSProposalBuild(result *FHSProposalBuildResult) error {
	if hsm == nil || result == nil {
		return ErrInvalidProposal
	}
	v := hsm.leaderView
	if v == nil || v.fhsBuild == nil || *v.fhsBuild != result.Key ||
		v.number != result.Key.ViewNumber || v.hash != result.Key.ViewID || v.leaderId != result.Key.LeaderID ||
		v.phaseAsLeader != PhaseTryPropose {
		return ErrOldState
	}
	state, leaderID, number := hsm.app.CurrentState()
	if leaderID != v.leaderId || number != v.number || !bytes.Equal(state, v.currentState) ||
		StateDigest(state) != result.Key.CurrentStateDigest || !SignedStateSemanticEqual(hsm.app.HighestCertified(), v.fhsHighest) {
		v.fhsBuild = nil
		return ErrOldState
	}
	var parentQCID common.Hash
	if v.fhsHighest != nil {
		id, err := SignedStateID(v.fhsHighest)
		if err != nil {
			v.fhsBuild = nil
			return ErrInvalidHighQC
		}
		parentQCID = id.Hash()
	}
	if parentQCID != result.Key.ParentQCID {
		v.fhsBuild = nil
		return ErrOldState
	}
	if result.Err != nil {
		v.fhsBuild = nil
		return fmt.Errorf("FHS proposal construction failed: %w", result.Err)
	}
	if len(result.TProposal) == 0 {
		v.fhsBuild = nil
		return ErrInvalidProposal
	}
	ref, err := types.DecodeHotstuffProposalRef(result.TProposal)
	if err != nil || ref.ViewNumber != v.number || ref.ViewID != v.hash || ref.LeaderID != v.leaderId ||
		ref.ParentQCID != parentQCID || ref.ExtraHash != types.HotstuffProposalExtraHash(result.Extra) {
		v.fhsBuild = nil
		return ErrInvalidProposal
	}
	aggregateBytes, err := EncodeAggregateQC(v.fhsAggregate)
	if err != nil {
		v.fhsBuild = nil
		return err
	}
	msg := hsm.newMsg(MsgPrepare, v.number, v.hash, nil, result.TProposal, aggregateBytes)
	if v.fhsTimeout != nil {
		msg.DataD, err = EncodeTimeoutCertificate(v.fhsTimeout)
		if err != nil {
			v.fhsBuild = nil
			return err
		}
	}
	msg.DataE = append([]byte(nil), v.currentState...)
	msg.DataF = append([]byte(nil), result.Extra...)
	if v.fhsHighest != nil {
		msg.DataG, err = EncodeSignedState(v.fhsHighest)
		if err != nil {
			v.fhsBuild = nil
			return err
		}
	}
	if err := hsm.sealMessage(msg); err != nil {
		v.fhsBuild = nil
		return err
	}
	if err := ValidateHotstuffWireMessage(msg); err != nil {
		v.fhsBuild = nil
		return err
	}
	async, ok := hsm.app.(FHSProposalBuildApplication)
	if !ok {
		v.fhsBuild = nil
		return ErrInvalidProposal
	}
	if err := async.ApplyFHSProposalBuild(result); err != nil {
		v.fhsBuild = nil
		if err == ErrOldState {
			return ErrOldState
		}
		return fmt.Errorf("apply FHS proposal construction: %w", err)
	}
	defer async.FinishFHSProposalBuild(result)
	v.fhsBuild = nil
	v.proposedTState = append([]byte(nil), result.TProposal...)
	v.proposedTDigest = hotstuffDigest(v.proposedTState)
	v.leaderMsg[MsgPrepare] = msg
	v.phaseAsLeader = PhasePreCommit
	v.waitingMoreVoteInfo = true
	v.waitingMoreVoteInfoAt = time.Now()
	v.lastLeaderRecoveryAt = v.waitingMoreVoteInfoAt
	hsm.leaderView = nil
	hsm.app.Broadcast(msg)
	return nil
}

// HandleFHSProposalBuildResult applies the same epoch-reset barriers as all
// other asynchronous FHS completions.
func (hsm *HotstuffProtocolManager) HandleFHSProposalBuildResult(result *FHSProposalBuildResult) error {
	if hsm == nil || result == nil {
		return ErrInvalidProposal
	}
	if hsm.applyScheduledFHSEpochReset() {
		return ErrOldState
	}
	err := hsm.CompleteFHSProposalBuild(result)
	if hsm.applyScheduledFHSEpochReset() {
		return ErrOldState
	}
	return err
}

func (hsm *HotstuffProtocolManager) handleFHSPrepareMsg(msg *HotstuffMessage) error {
	app, ok := hsm.fhsApplication()
	if !ok || msg == nil {
		return ErrInvalidProposal
	}
	if len(msg.DataA) != 0 || len(msg.DataB) == 0 {
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
	// A TC is an independent quorum proof and must advance the durable pacemaker
	// before target gating. Without it, only the exact canonical target or an
	// immediately preceding HighQC may start expensive catch-up work.
	if tc != nil {
		if err := app.AcceptFHSTimeoutCertificate(tc); err != nil {
			return err
		}
	}
	if err := hsm.validateFHSHighQCScheduleTarget(ctx, highest); err != nil {
		return err
	}
	if highest != nil {
		if err := hsm.scheduleFHSHighQCCatchup(highest, ctx.TargetView, msg, common.Hash{}); err != nil {
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
	ref, err := types.DecodeHotstuffProposalRef(msg.DataB)
	if err != nil || ref.ChainID != hsm.app.ChainID() || ref.ViewNumber != ctx.TargetView ||
		ref.ViewID != ctx.ID() || ref.LeaderID != ctx.LeaderID || ref.KeyHash != ctx.KeyHash ||
		ref.ExtraHash != types.HotstuffProposalExtraHash(msg.DataF) {
		return ErrInvalidProposal
	}
	var parentQCID common.Hash
	if highest != nil {
		id, err := SignedStateID(highest)
		if err != nil {
			return ErrInvalidHighQC
		}
		parentQCID = id.Hash()
	}
	if ref.ParentQCID != parentQCID {
		return ErrInvalidProposal
	}
	// Service-level proposal scheduling deliberately cannot cancel a manager-
	// owned HighQC worker. Retain this fully authenticated, canonical Prepare on
	// that semantic QC continuation before any proposal worker is requested.
	// This also covers the genesis/highest=nil edge where no schedule call above
	// had an opportunity to attach the message.
	if pending := hsm.pendingHighQC; pending != nil {
		if err := appendFHSHighQCContinuation(pending, msg, common.Hash{}); err != nil {
			return err
		}
		return ErrProposalValidationPending
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
	key := FHSProposalValidationKey{
		ViewNumber: v.number,
		ViewID:     v.hash,
		LeaderID:   v.leaderId,
		ProposalID: ref.ProposalID(),
	}
	if existing := v.leaderMsg[MsgPrepare]; existing != nil && !sameFHSPrepare(existing, msg) {
		return ErrInvalidProposal
	}
	if v.fhsValidation != nil {
		if v.fhsValidation.ViewNumber != key.ViewNumber || v.fhsValidation.ViewID != key.ViewID ||
			v.fhsValidation.LeaderID != key.LeaderID || v.fhsValidation.ProposalID != key.ProposalID {
			return ErrInvalidProposal
		}
		return ErrProposalValidationPending
	}
	if v.leaderMsg[MsgPrepare] == nil {
		v.fhsAggregate = aggregate
		v.fhsHighest = CloneSignedState(highest)
		v.fhsTimeout = CloneTimeoutCertificate(tc)
		v.currentState = append(v.currentState[:0], state...)
		v.proposedKState = nil
		v.proposedKDigest = nil
		v.proposedTState = append([]byte(nil), msg.DataB...)
		v.proposedTDigest = hotstuffDigest(v.proposedTState)
		v.leaderMsg[MsgPrepare] = cloneFHSPrepare(msg)
	}
	prepare := v.leaderMsg[MsgPrepare]

	if async, ok := hsm.app.(FHSProposalValidationApplication); ok {
		hsm.validationSequence++
		if hsm.validationSequence == 0 {
			hsm.validationSequence++
		}
		key.RequestID = hsm.validationSequence
		request := &FHSProposalValidationRequest{
			Key:         key,
			ProposalRef: append([]byte(nil), prepare.DataB...),
			Extra:       append([]byte(nil), prepare.DataF...),
			ParentQC:    CloneSignedState(v.fhsHighest),
		}
		v.fhsValidation = &key
		if err := async.ScheduleFHSProposalValidation(request); err != nil {
			v.fhsValidation = nil
			return err
		}
		return ErrProposalValidationPending
	}

	if err := hsm.app.OnPropose(prepare.DataB, prepare.DataF, v.number, v.fhsHighest); err != nil {
		return ErrInvalidProposal
	}
	return hsm.finishFHSPrepare(v, prepare, key, app)
}

func sameFHSPrepare(a, b *HotstuffMessage) bool {
	if a == nil || b == nil || a.Code != b.Code || a.Number != b.Number || a.ViewId != b.ViewId || a.Id != b.Id {
		return false
	}
	return bytes.Equal(a.DataA, b.DataA) && bytes.Equal(a.DataB, b.DataB) && bytes.Equal(a.DataC, b.DataC) &&
		bytes.Equal(a.DataD, b.DataD) && bytes.Equal(a.DataE, b.DataE) && bytes.Equal(a.DataF, b.DataF) &&
		bytes.Equal(a.DataG, b.DataG) && bytes.Equal(a.PubKey, b.PubKey) && bytes.Equal(a.AuthSig, b.AuthSig)
}

func cloneFHSPrepare(msg *HotstuffMessage) *HotstuffMessage {
	if msg == nil {
		return nil
	}
	clone := *msg
	clone.PubKey = append([]byte(nil), msg.PubKey...)
	clone.DataA = append([]byte(nil), msg.DataA...)
	clone.DataB = append([]byte(nil), msg.DataB...)
	clone.DataC = append([]byte(nil), msg.DataC...)
	clone.DataD = append([]byte(nil), msg.DataD...)
	clone.DataE = append([]byte(nil), msg.DataE...)
	clone.DataF = append([]byte(nil), msg.DataF...)
	clone.DataG = append([]byte(nil), msg.DataG...)
	clone.AuthSig = append([]byte(nil), msg.AuthSig...)
	return &clone
}

// CompleteFHSProposalValidation installs a worker result and performs the
// safety WAL/sign/send sequence on the serialized HotStuff control loop.
func (hsm *HotstuffProtocolManager) CompleteFHSProposalValidation(result *FHSProposalValidationResult) error {
	if hsm == nil || result == nil {
		return ErrInvalidProposal
	}
	app, ok := hsm.fhsApplication()
	if !ok {
		return ErrInvalidProposal
	}
	v := hsm.views[result.Key.ViewID]
	if v == nil || v.fhsValidation == nil || *v.fhsValidation != result.Key ||
		v.number != result.Key.ViewNumber || v.leaderId != result.Key.LeaderID {
		return ErrOldState
	}
	state, leaderID, number := hsm.app.CurrentState()
	if leaderID != v.leaderId || number != v.number || v.phaseAsReplica != PhasePrepare ||
		!bytes.Equal(state, v.currentState) || !SignedStateSemanticEqual(hsm.app.HighestCertified(), v.fhsHighest) {
		v.fhsValidation = nil
		return ErrOldState
	}
	prepare := v.leaderMsg[MsgPrepare]
	if prepare == nil || !bytes.Equal(prepare.DataB, v.proposedTState) {
		v.fhsValidation = nil
		return ErrInvalidProposal
	}
	if result.Err != nil {
		v.fhsValidation = nil
		return fmt.Errorf("FHS proposal validation failed: %w", result.Err)
	}
	async, ok := hsm.app.(FHSProposalValidationApplication)
	if !ok {
		v.fhsValidation = nil
		return ErrInvalidProposal
	}
	if err := async.ApplyFHSProposalValidation(result); err != nil {
		v.fhsValidation = nil
		if err == ErrOldState {
			return ErrOldState
		}
		return ErrInvalidProposal
	}
	defer async.FinishFHSProposalValidation(result)
	v.fhsValidation = nil
	return hsm.finishFHSPrepare(v, prepare, result.Key, app)
}

// HandleFHSProposalValidationResult applies the same epoch-reset barriers as a
// normal control message, so a result from a discarded committee generation
// cannot reach the safety WAL or signer.
func (hsm *HotstuffProtocolManager) HandleFHSProposalValidationResult(result *FHSProposalValidationResult) error {
	if hsm == nil || result == nil {
		return ErrInvalidProposal
	}
	if hsm.applyScheduledFHSEpochReset() {
		return ErrOldState
	}
	err := hsm.CompleteFHSProposalValidation(result)
	if hsm.applyScheduledFHSEpochReset() {
		return ErrOldState
	}
	return err
}

func snapshotFHSHighQCContinuations(pending *pendingFHSHighQCValidation) ([]*HotstuffMessage, []common.Hash) {
	if pending == nil {
		return nil, nil
	}
	messages := make([]*HotstuffMessage, 0, len(pending.messages))
	for _, msg := range pending.messages {
		messages = append(messages, cloneFHSPrepare(msg))
	}
	leaderViews := make([]common.Hash, 0, len(pending.leaderViews))
	for viewID := range pending.leaderViews {
		leaderViews = append(leaderViews, viewID)
	}
	sort.Slice(leaderViews, func(i, j int) bool { return bytes.Compare(leaderViews[i][:], leaderViews[j][:]) < 0 })
	return messages, leaderViews
}

func expectedFHSHighQCContinuationError(err error) bool {
	return err == nil || errors.Is(err, ErrInsufficientQC) || errors.Is(err, ErrProposalValidationPending) || errors.Is(err, ErrOldState)
}

func (hsm *HotstuffProtocolManager) replayFHSHighQCContinuations(messages []*HotstuffMessage, leaderViews []common.Hash) error {
	var replayErr error
	for _, msg := range messages {
		if msg == nil {
			continue
		}
		if err := hsm.HandleMessage(msg); !expectedFHSHighQCContinuationError(err) {
			replayErr = err
		}
	}
	for _, viewID := range leaderViews {
		v := hsm.views[viewID]
		if v == nil {
			continue
		}
		if err := hsm.activateFHSLeaderView(v); !expectedFHSHighQCContinuationError(err) {
			replayErr = err
		}
	}
	return replayErr
}

func (hsm *HotstuffProtocolManager) retryFHSHighQCContinuations(messages []*HotstuffMessage, leaderViews []common.Hash) error {
	// The staged result was built over an obsolete canonical base. Release only
	// that request, then feed its authenticated continuations through the normal
	// validation path. The first still-relevant continuation schedules a fresh
	// worker against the new base; later ones join the same bounded request.
	hsm.pendingHighQC = nil
	if hsm.applyScheduledFHSEpochReset() {
		return ErrOldState
	}
	if err := hsm.replayFHSHighQCContinuations(messages, leaderViews); err != nil {
		return err
	}
	return ErrOldState
}

// HandleFHSHighQCValidationResult installs a fully staged certificate chain on
// the serialized control loop, then replays only the continuations that were
// cryptographically accepted for that exact semantic QC. A superseded worker
// result cannot publish application state or resume an obsolete view.
func (hsm *HotstuffProtocolManager) HandleFHSHighQCValidationResult(result *FHSHighQCValidationResult) error {
	if hsm == nil || result == nil {
		return ErrInvalidHighQC
	}
	if hsm.applyScheduledFHSEpochReset() {
		return ErrOldState
	}
	pending := hsm.pendingHighQC
	if pending == nil || pending.key != result.Key {
		return ErrOldState
	}
	async, ok := hsm.app.(FHSHighQCValidationApplication)
	if !ok {
		hsm.pendingHighQC = nil
		return ErrInvalidHighQC
	}
	messages, leaderViews := snapshotFHSHighQCContinuations(pending)
	if result.Err != nil {
		if errors.Is(result.Err, ErrOldState) {
			return hsm.retryFHSHighQCContinuations(messages, leaderViews)
		}
		hsm.pendingHighQC = nil
		return fmt.Errorf("FHS HighQC validation failed: %w", result.Err)
	}
	if err := async.ApplyFHSHighQCValidation(result); err != nil {
		if errors.Is(err, ErrOldState) {
			return hsm.retryFHSHighQCContinuations(messages, leaderViews)
		}
		hsm.pendingHighQC = nil
		return ErrInvalidHighQC
	}
	defer async.FinishFHSHighQCValidation(result)
	certified := CloneSignedState(pending.qc)
	hsm.pendingHighQC = nil
	if hsm.applyScheduledFHSEpochReset() {
		// Apply may commit the key carrier finalized by this exact QC. That
		// transition deliberately discards every old-epoch wire continuation and
		// leader view, but the applied certificate still owns the one small
		// certification completion that rearms the pacemaker and emits the first
		// NewView for the new epoch. Replaying the old QCBroadcast here would
		// evaluate an obsolete committee envelope; invoke only its already-
		// authenticated certificate continuation instead.
		return hsm.app.OnCertified(certified)
	}

	return hsm.replayFHSHighQCContinuations(messages, leaderViews)
}

func (hsm *HotstuffProtocolManager) finishFHSPrepare(v *View, msg *HotstuffMessage, expected FHSProposalValidationKey, app FHSApplication) error {
	if v == nil || msg == nil || app == nil {
		return ErrInvalidProposal
	}
	ref, err := types.DecodeHotstuffProposalRef(msg.DataB)
	if err != nil || expected.ViewNumber != v.number || expected.ViewID != v.hash || expected.LeaderID != v.leaderId ||
		expected.ProposalID != ref.ProposalID() || !bytes.Equal(msg.DataB, v.proposedTState) || len(v.proposedKState) != 0 {
		return ErrInvalidProposal
	}
	persisted := &PersistedVote{
		ViewNumber:      v.number,
		ViewID:          v.hash,
		LeaderID:        v.leaderId,
		ProposalRef:     append([]byte(nil), v.proposedTState...),
		ProposalRefHash: StateDigest(v.proposedTState),
	}
	persisted.ProposalID = ref.ProposalID()
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
	} else if msg.Code == MsgTimeoutQC {
		// A single timeout vote never advances the pacemaker, but a complete
		// 2f+1 timeout certificate is safe at any forward distance. Do not cap it
		// by the volatile pending-view window; handleTimeoutQCMsg authenticates
		// the sender and cryptographically verifies the TC before adoption.
		if statement.TimedOutView < active {
			return -1, nil, ErrOldState
		}
	} else {
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
