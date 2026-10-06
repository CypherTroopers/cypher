package reconfig

import (
	"testing"

	"github.com/cypherium/cypher/reconfig/hotstuff"
)

func fhsTimeoutCertificateForActiveEpoch(t *testing.T, fixture *fhsEpochTestFixture, timedOutView uint64) *hotstuff.TimeoutCertificate {
	t.Helper()
	return fhsEpochTestTC(t, hotstuff.TimeoutStatement{
		Version:       3,
		ChainID:       fixture.service.ChainID(),
		TimedOutView:  timedOutView,
		KeyNumber:     fixture.current.NumberU64(),
		KeyHash:       fixture.current.Hash(),
		CommitteeHash: fixture.current.CommitteeHash(),
	}, fixture.keys, fixture.public)
}

func TestAcceptFHSTimeoutCertificateReplayPreservesLocalProposalState(t *testing.T) {
	fixture := newFHSEpochTestFixture(t)
	service := fixture.service

	service.muCurrentView.Lock()
	service.currentView.ViewNumber = 19
	service.currentView.TxNumber = 41
	service.currentView.NoDone = true
	service.currentView.LeaderIndex = 3
	service.muCurrentView.Unlock()

	tc := fhsTimeoutCertificateForActiveEpoch(t, fixture, 20)
	if err := service.AcceptFHSTimeoutCertificate(tc); err != nil {
		t.Fatalf("accept newer timeout certificate: %v", err)
	}
	advanced := service.GetCurrentView()
	if advanced.ViewNumber != tc.Statement.TimedOutView || !advanced.NoDone {
		t.Fatalf("newer timeout certificate did not advance the pacemaker: %+v", advanced)
	}

	// Model the fixed-mode key-block wake after the TC has already advanced the
	// pacemaker. NoDone and the waiting watermarks are local proposal state and an
	// equivalent replay must not switch the service back to transaction mode.
	service.muCurrentView.Lock()
	service.currentView.NoDone = false
	service.currentView.Round = 7
	service.waittingView.TxNumber = service.currentView.TxNumber + 1
	service.waittingView.KeyNumber = service.currentView.KeyNumber + 1
	beforeCurrent := service.currentView
	beforeWaiting := service.waittingView
	service.muCurrentView.Unlock()

	if err := service.AcceptFHSTimeoutCertificate(tc); err != nil {
		t.Fatalf("accept equivalent timeout certificate replay: %v", err)
	}
	service.muCurrentView.Lock()
	afterCurrent := service.currentView
	afterWaiting := service.waittingView
	service.muCurrentView.Unlock()
	if !afterCurrent.EqualAll(&beforeCurrent) {
		t.Fatalf("equivalent timeout certificate changed current view: got %+v want %+v", afterCurrent, beforeCurrent)
	}
	if !afterWaiting.EqualAll(&beforeWaiting) {
		t.Fatalf("equivalent timeout certificate changed waiting view: got %+v want %+v", afterWaiting, beforeWaiting)
	}

	reopened := newFHSSafetyStore(fixture.db, service.ChainID(), fixture.genesisHash)
	state, _, err := reopened.snapshot()
	if err != nil {
		t.Fatalf("snapshot timeout safety state: %v", err)
	}
	if state.HighestTC == nil || state.HighestTC.Statement != tc.Statement || state.LastTimeoutView != tc.Statement.TimedOutView {
		t.Fatalf("equivalent timeout certificate was not retained durably: %+v", state)
	}
}

func TestAcceptFHSTimeoutCertificateStrictlyNewerUpdatesVolatileState(t *testing.T) {
	fixture := newFHSEpochTestFixture(t)
	service := fixture.service

	service.muCurrentView.Lock()
	service.currentView.TxNumber = 41
	service.currentView.NoDone = false
	service.currentView.LeaderIndex = 3
	service.waittingView.TxNumber = 42
	service.waittingView.KeyNumber = service.currentView.KeyNumber + 1
	service.muCurrentView.Unlock()

	tc := fhsTimeoutCertificateForActiveEpoch(t, fixture, 21)
	if err := service.AcceptFHSTimeoutCertificate(tc); err != nil {
		t.Fatalf("accept strictly newer timeout certificate: %v", err)
	}
	service.muCurrentView.Lock()
	current := service.currentView
	waiting := service.waittingView
	service.muCurrentView.Unlock()
	if current.ViewNumber != tc.Statement.TimedOutView {
		t.Fatalf("current view = %d, want %d", current.ViewNumber, tc.Statement.TimedOutView)
	}
	if !current.NoDone {
		t.Fatal("strictly newer timeout certificate did not restore transaction proposal mode")
	}
	if current.LeaderIndex != 0 {
		t.Fatalf("leader index = %d, want deterministic fixture leader 0", current.LeaderIndex)
	}
	if waiting.TxNumber != current.TxNumber || waiting.KeyNumber != current.KeyNumber {
		t.Fatalf("waiting view was not reset after view advance: got tx=%d key=%d want tx=%d key=%d",
			waiting.TxNumber, waiting.KeyNumber, current.TxNumber, current.KeyNumber)
	}
}
