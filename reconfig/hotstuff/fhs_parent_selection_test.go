package hotstuff

import (
	"errors"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

// The selected parent is justified by a quorum of reports. A QC disclosed to
// this replica alone remains its observed maximum, but is not an extra veto on
// a correctly justified proposal in a later view.
type fhsParentSelectionTestApp struct {
	*fhsAsyncValidationApp
	selected               *SignedState
	selectCalls            int
	requireStaging         bool
	observedContentMissing bool
	ready                  map[common.Hash]bool
}

func (a *fhsParentSelectionTestApp) SelectedFHSProposalParent() *SignedState {
	return CloneSignedState(a.selected)
}

func (a *fhsParentSelectionTestApp) HasValidatedFHSCertificate(qc *SignedState) bool {
	if SignedStateSemanticEqual(qc, a.highest) && !a.observedContentMissing {
		return true
	}
	id, err := SignedStateID(qc)
	return err == nil && a.ready[id.Hash()]
}

func TestFHSCertificationStagesObservedMaximumWithoutContent(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	app := &fhsParentSelectionTestApp{fhsAsyncValidationApp: fixture.async, observedContentMissing: true}
	fixture.manager.app = app
	qc := fixture.parentQC(t, 11, true)
	app.highest = CloneSignedState(qc)
	completed := false
	app.onCertified = func(*SignedState) error { completed = true; return nil }
	if err := fixture.manager.certifyFHSQC(qc, nil); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("WAL-only maximum bypassed asynchronous content validation: %v", err)
	}
	if completed || len(app.highScheduled) != 1 || app.highScheduled[0].Key.SelectProposalParent {
		t.Fatal("missing observed content completed certification or changed proposal selection")
	}
}

func (a *fhsParentSelectionTestApp) SelectFHSProposalParent(qc *SignedState) error {
	a.selectCalls++
	if qc != nil && a.requireStaging {
		id, err := SignedStateID(qc)
		if err != nil {
			return err
		}
		if !a.ready[id.Hash()] {
			return ErrProposalValidationPending
		}
	}
	a.selected = CloneSignedState(qc)
	return nil
}

func (a *fhsParentSelectionTestApp) ApplyFHSHighQCValidation(result *FHSHighQCValidationResult) error {
	observed := CloneSignedState(a.highest)
	if err := a.fhsAsyncValidationApp.ApplyFHSHighQCValidation(result); err != nil {
		return err
	}
	if observed != nil && observed.Number > a.highest.Number {
		a.highest = observed
	}
	for _, request := range a.highScheduled {
		if request.Key == result.Key {
			if a.ready == nil {
				a.ready = make(map[common.Hash]bool)
			}
			a.ready[request.Key.QCID] = true
			if result.Key.SelectProposalParent {
				return a.SelectFHSProposalParent(request.QC)
			}
		}
	}
	return nil
}

func TestFHSDelayedLowerCertificateCompletesWithoutDowngradeOrRestaging(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	app := &fhsParentSelectionTestApp{fhsAsyncValidationApp: fixture.async}
	fixture.manager.app = app
	observed := fixture.parentQC(t, 11, true)
	delayed := fixture.parentQC(t, 10, true)
	app.highest = CloneSignedState(observed)
	certified := 0
	app.onCertified = func(qc *SignedState) error {
		if !SignedStateSemanticEqual(qc, delayed) {
			t.Fatal("completed wrong delayed QC")
		}
		certified++
		return nil
	}
	if err := fixture.manager.certifyFHSQC(delayed, nil); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("delayed lower QC was dropped instead of staged: %v", err)
	}
	if len(app.highScheduled) != 1 || app.highScheduled[0].Key.SelectProposalParent || app.highScheduled[0].Key.TargetView != 12 {
		t.Fatal("lower observation selected a proposal parent or used an obsolete continuation view")
	}
	request := app.highScheduled[0]
	stale := request.Key
	stale.SelectProposalParent = true
	if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: stale}); !errors.Is(err, ErrOldState) {
		t.Fatalf("worker result changed its authorization purpose: %v", err)
	}
	if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: request.Key}); err != nil {
		t.Fatalf("delayed lower QC validation failed: %v", err)
	}
	if err := fixture.manager.certifyFHSQC(delayed, nil); err != nil {
		t.Fatalf("cached lower QC completion failed: %v", err)
	}
	if certified != 1 || len(app.highScheduled) != 1 || app.selectCalls != 0 || !SignedStateSemanticEqual(app.highest, observed) {
		t.Fatal("lower QC did not finish once while retaining observed maximum and selected parent")
	}
}

func TestFHSPrepareAcceptsQuorumParentBelowObservedQC(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	app := &fhsParentSelectionTestApp{fhsAsyncValidationApp: fixture.async}
	fixture.manager.app = app
	observed := fixture.parentQC(t, 11, true)
	app.highest = CloneSignedState(observed)
	_, prepare := fixture.prepare(t)
	if err := fixture.manager.handleFHSPrepareMsg(prepare); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("valid quorum-selected parent rejected by private higher QC: %v", err)
	}
	if len(app.scheduled) != 1 || app.selectCalls == 0 || app.scheduled[0].ParentQC != nil {
		t.Fatal("verified quorum's genesis parent did not reach proposal validation")
	}
	if err := fixture.manager.CompleteFHSProposalValidation(&FHSProposalValidationResult{Key: app.scheduled[0].Key}); err != nil {
		t.Fatalf("quorum-selected parent could not complete its vote: %v", err)
	}
	if len(app.persisted) != 1 || !SignedStateSemanticEqual(app.highest, observed) {
		t.Fatal("vote was not persisted or observed QC was downgraded")
	}
}

func TestFHSPrepareInvalidAggregateCannotSelectParent(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	app := &fhsParentSelectionTestApp{fhsAsyncValidationApp: fixture.async}
	fixture.manager.app = app
	_, prepare := fixture.prepare(t)
	aggregate, err := DecodeAggregateQC(prepare.DataC)
	if err != nil {
		t.Fatal(err)
	}
	aggregate.Sign[0] ^= 1
	prepare.DataC, err = EncodeAggregateQC(aggregate)
	if err != nil {
		t.Fatal(err)
	}
	fixture.authenticate(t, 3, prepare)
	if err := fixture.manager.handleFHSPrepareMsg(prepare); err == nil {
		t.Fatal("invalid aggregate accepted")
	}
	if app.selectCalls != 0 || len(app.scheduled) != 0 {
		t.Fatal("invalid aggregate changed selected parent or scheduled proposal validation")
	}
}

func TestFHSQuorumParentBelowObservedQCStagesOnceAndVotes(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	app := &fhsParentSelectionTestApp{fhsAsyncValidationApp: fixture.async, requireStaging: true}
	fixture.manager.app = app
	observed := fixture.parentQC(t, 11, true)
	selected := fixture.parentQC(t, 10, true)
	observedRef, err := types.DecodeHotstuffProposalRef(observed.State)
	if err != nil {
		t.Fatal(err)
	}
	observedRef.BlockHash = common.HexToHash("0x3711")
	observed.State = observedRef.EncodeToBytes()
	observed.Sign = aggregateContextSignatures(t, fixture.secrets, []int{0, 1, 2}, app.ChainID(), MsgVotePrepare, observed.ViewID, observed.LeaderID, observed.State)
	app.highest = CloneSignedState(observed)
	ref, prepare := fixture.prepare(t)
	aggregate, err := DecodeAggregateQC(prepare.DataC)
	if err != nil {
		t.Fatal(err)
	}
	aggregate = aggregateReportsWithHighQC(t, fixture.secrets, aggregate.Context, []*SignedState{selected, selected, selected})
	prepare.DataC, err = EncodeAggregateQC(aggregate)
	if err != nil {
		t.Fatal(err)
	}
	prepare.DataG, err = EncodeSignedState(selected)
	if err != nil {
		t.Fatal(err)
	}
	id, err := SignedStateID(selected)
	if err != nil {
		t.Fatal(err)
	}
	ref.ParentQCID = id.Hash()
	ref.ParentHash = common.HexToHash("0x3700")
	ref.BlockHash = common.HexToHash("0x3800")
	ref.Number = 38
	prepare.DataB = ref.EncodeToBytes()
	fixture.authenticate(t, 3, prepare)
	for attempt := 0; attempt < 2; attempt++ {
		if err := fixture.manager.handleFHSPrepareMsg(prepare); !errors.Is(err, ErrProposalValidationPending) {
			t.Fatalf("schedule lower selected parent: %v", err)
		}
	}
	if len(app.highScheduled) != 1 || !app.highScheduled[0].Key.SelectProposalParent || len(app.scheduled) != 0 {
		t.Fatal("selected parent was not staged once before proposal voting")
	}
	request := app.highScheduled[0]
	if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: request.Key}); err != nil {
		t.Fatalf("complete selected-parent staging: %v", err)
	}
	if len(app.highScheduled) != 1 || len(app.scheduled) != 1 || !SignedStateSemanticEqual(app.selected, selected) {
		t.Fatal("selected-parent replay repeated staging or lost the quorum parent")
	}
	if err := fixture.manager.CompleteFHSProposalValidation(&FHSProposalValidationResult{Key: app.scheduled[0].Key}); err != nil {
		t.Fatalf("complete proposal using lower selected parent: %v", err)
	}
	if len(app.persisted) != 1 || !SignedStateSemanticEqual(app.highest, observed) {
		t.Fatal("lower selected parent changed observed maximum or failed to vote")
	}
}

func TestFHSLeaderUsesQuorumParentBelowObservedQC(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	app := &fhsParentSelectionTestApp{fhsAsyncValidationApp: fixture.async}
	fixture.manager.app = app
	observed := fixture.parentQC(t, 11, true)
	app.highest = CloneSignedState(observed)
	state, leader, target := app.CurrentState()
	ctx, _, err := fixture.manager.makeFHSContext(state, leader, target)
	if err != nil {
		t.Fatal(err)
	}
	v, err := fixture.manager.createFHSView(true, PhasePrepare, ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < v.threshold; index++ {
		report := &NewViewReport{Context: *ctx, SignerIndex: uint32(index)}
		digest, err := NewViewReportDigest(report)
		if err != nil {
			t.Fatal(err)
		}
		v.fhsReports[uint32(index)] = report
		v.fhsReportSigns[uint32(index)] = fixture.secrets[index].SignHash(digest)
	}
	fixture.manager.views[v.hash] = v
	fixture.manager.leaderView = v
	if err := fixture.manager.activateFHSLeaderView(v); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("leader rejected valid aggregate selecting lower parent: %v", err)
	}
	if len(app.buildScheduled) != 1 || app.selectCalls == 0 || app.buildScheduled[0].ParentQC != nil {
		t.Fatal("leader did not construct on quorum-selected parent")
	}
	if err := fixture.manager.CompleteFHSProposalBuild(fixture.proposalBuildResult(t, app.buildScheduled[0])); err != nil {
		t.Fatalf("leader failed to publish quorum-selected proposal: %v", err)
	}
	if !SignedStateSemanticEqual(app.highest, observed) {
		t.Fatal("leader selection downgraded observed maximum")
	}
}
