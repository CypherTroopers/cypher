package reconfig

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

type fhsSyncResumeDelivery struct {
	to  string
	msg *hotstuff.HotstuffMessage
}

// Only the physical transport and absence of mining candidates are replaced.
// NewView construction, epoch context, signatures and quorum admission use the
// real Service and protocol manager. Deliveries are replayed after Write returns
// because bftview's process-wide identity must not change inside a sender call.
type fhsSyncResumeApplication struct {
	*Service
	sent         []fhsSyncResumeDelivery
	writeErr     error
	serviceWrite bool
}

func (a *fhsSyncResumeApplication) GetExtra() []byte { return nil }

func (a *fhsSyncResumeApplication) Write(to string, msg *hotstuff.HotstuffMessage) error {
	if a.serviceWrite {
		return a.Service.Write(to, msg)
	}
	if a.writeErr != nil {
		return a.writeErr
	}
	a.sent = append(a.sent, fhsSyncResumeDelivery{to, cloneHotstuffMessage(msg)})
	return nil
}

type fhsSyncResumeFixture struct {
	f           *convergenceFixture
	carrier     *fhsCertifiedProposal
	child       *fhsCertifiedProposal
	key         *types.KeyBlock
	committeeDB ethdb.Database
	committee   *bftview.Committee
	apps        []*fhsSyncResumeApplication
	block       *types.Block
}

func newFHSSyncResumeFixture(t *testing.T) *fhsSyncResumeFixture {
	t.Helper()
	f, carrier, key := historicalKeyFixture(t)
	child := f.proposal(t, carrier, carrier.qc.Number+1, 'c')
	committee := bftview.LoadMember(0, key.ParentHash(), true)
	committeeDB := rawdb.NewMemoryDatabase()
	t.Cleanup(func() {
		bftview.SetServerInfo("", "")
		bftview.SetCommitteeConfig(nil, nil, nil)
		_ = committeeDB.Close()
	})
	bftview.SetCommitteeConfig(committeeDB, f.replicas[0].kbc, nil)
	if !bftview.WriteCommittee(0, key.ParentHash(), committee) {
		t.Fatal("store original committee")
	}
	nextCommittee := committee.Copy()
	nextCommittee.Add(nil, 6, "")
	if !bftview.WriteCommittee(key.NumberU64(), key.Hash(), nextCommittee) {
		t.Fatal("store next committee")
	}
	fixture := &fhsSyncResumeFixture{f: f, carrier: carrier, child: child, key: key,
		committeeDB: committeeDB, committee: nextCommittee}
	for i, s := range f.replicas {
		s.netService.serverID = committee.List[i].Address
		s.pacetMakerTimer = &paceMakerTimer{beStop: true}
		// No dispatcher goroutine or socket is required. Live certification's
		// local admission is stepped explicitly by the test.
		s.hotstuffMsgQ = &hotstuffMessageQueue{priorityInput: make(chan *hotstuffMsg, 2)}
		s.proposalBuildJobs = make(chan *proposalBuildJob, 1)
		candidateEvents := new(event.TypeMux)
		t.Cleanup(candidateEvents.Stop)
		s.keyService.candidatepool = core.NewCandidatePool(nil, candidateEvents, nil)
		s.muLifecycle.Lock()
		s.lifecycleGenerationLocked()
		s.muLifecycle.Unlock()
		atomic.StoreUint64(&s.proposalValidationGeneration, 1)
		atomic.StoreInt32(&s.runningState, 1)
		app := &fhsSyncResumeApplication{Service: s}
		s.protocolMng = hotstuff.NewHotstuffProtocolManager(app, &f.keys[i], f.public[i])
		s.bc.SetFHSFinalizedSyncLifecycle(s.beforeFHSFinalizedSyncKeyCommit,
			s.waitFHSValidationPublication, s.afterFHSFinalizedSyncCommit, s.finishFHSFinalizedSyncKeyCommit)
		fixture.apps = append(fixture.apps, app)
	}
	block := carrier.verified.Block.WithSeal(carrier.verified.Block.Header())
	block.SetFHSSignature(carrier.qc.Sign, carrier.qc.Mask, carrier.qc.ViewID, carrier.qc.LeaderID,
		carrier.qc.Number, carrier.ref.ExtraHash, carrier.ref.ParentQCID)
	proof, err := core.EncodeFHSCommitProof(&core.FHSCommitProof{QCs: []*hotstuff.SignedState{child.qc}})
	if err != nil {
		t.Fatal(err)
	}
	if err := block.SetFHSFinalityProof(proof); err != nil {
		t.Fatal(err)
	}
	fixture.block = block
	return fixture
}

func (f *fhsSyncResumeFixture) activate(index int) *Service {
	s := f.f.replicas[index]
	bftview.SetCommitteeConfig(f.committeeDB, s.kbc, nil)
	bftview.SetServerInfo(s.Self(), f.f.public[index].SerializeToHexStr())
	return s
}

func (f *fhsSyncResumeFixture) importKey(t *testing.T, index int) {
	t.Helper()
	s := f.activate(index)
	block := f.block.WithSeal(f.block.Header())
	if n, err := s.bc.InsertChain(types.Blocks{block}); err != nil || n != 1 {
		t.Fatalf("import finalized key carrier: count=%d error=%v", n, err)
	}
	if s.bc.CurrentBlock().Hash() != block.Hash() || s.kbc.CurrentBlock().Hash() != f.key.Hash() {
		t.Fatal("fixture did not complete the actual canonical key transition")
	}
	if len(f.apps[index].sent) != 0 {
		t.Fatal("sync callback sent a consensus message while the importer held chainmu")
	}
}

func (f *fhsSyncResumeFixture) requireNewView(t *testing.T, index int) fhsSyncResumeDelivery {
	t.Helper()
	app := f.apps[index]
	if len(app.sent) != 1 {
		t.Fatalf("validator %d emitted %d messages after key sync, want one signed NewView", index, len(app.sent))
	}
	delivery := app.sent[0]
	msg := delivery.msg
	if msg.Code != hotstuff.MsgNewView || msg.Number != f.child.qc.Number+1 {
		t.Fatalf("unexpected post-sync message: code=%d view=%d", msg.Code, msg.Number)
	}
	report, err := hotstuff.DecodeNewViewReport(msg.DataA)
	if err != nil {
		t.Fatal(err)
	}
	if report.Context.KeyHash != f.key.Hash() || report.Context.KeyNumber != f.key.NumberU64() ||
		report.Context.CommitteeHash != f.committee.RlpHash() || report.Context.ID() != msg.ViewId ||
		report.Context.LeaderID != delivery.to {
		t.Fatalf("NewView does not name the committed epoch: %+v", report.Context)
	}
	if err := hotstuff.VerifyMessageAuth(app.ChainID(), msg, app.Self(), f.f.public[index]); err != nil {
		t.Fatalf("invalid NewView envelope signature: %v", err)
	}
	digest, err := hotstuff.NewViewReportDigest(report)
	if err != nil {
		t.Fatal(err)
	}
	var signature bls.Sign
	if err := signature.Deserialize(msg.DataB); err != nil || !signature.VerifyHash(f.f.public[index], digest) {
		t.Fatalf("invalid NewView report signature: %v", err)
	}
	if f.committee.List[report.SignerIndex].Public != f.f.public[index].SerializeToHexStr() {
		t.Fatal("NewView signer used the old committee ordering")
	}
	return delivery
}

func TestFHSSyncKeyEpochResumesSignedNewView(t *testing.T) {
	f := newFHSSyncResumeFixture(t)
	f.importKey(t, 0)
	s := f.activate(0)
	s.processFHSSyncResume()
	f.requireNewView(t, 0)
	s.processFHSSyncResume()
	if len(f.apps[0].sent) != 1 {
		t.Fatal("completed sync request was replayed as new work")
	}
	_, stopped, _, _ := s.pacetMakerTimer.get()
	if stopped {
		t.Fatal("sync recovery left the validator pacemaker stopped")
	}
}

func TestFHSSyncKeyEpochResumesQuorumWithPassiveReplicas(t *testing.T) {
	for _, passive := range []int{3, 6} {
		t.Run(fmt.Sprintf("sync_%d_of_7", passive), func(t *testing.T) {
			f := newFHSSyncResumeFixture(t)
			leaderPosition, err := fairHotstuffLeaderIndex(f.f.replicas[0].chainConfig.FairHotstuffSeed,
				f.f.replicas[0].ChainID(), f.child.qc.Number+1, f.committee.RlpHash(), len(f.apps))
			if err != nil {
				t.Fatal(err)
			}
			leader := -1
			for i, app := range f.apps {
				if app.Self() == f.committee.List[leaderPosition].Address {
					leader = i
				}
			}
			if leader < 0 {
				t.Fatal("new-epoch leader not found among fixture identities")
			}
			remaining := passive
			for i := range f.apps {
				s := f.activate(i)
				if i != leader && remaining > 0 {
					remaining--
					f.importKey(t, i)
					s.processFHSSyncResume()
				} else {
					if err := s.OnCertified(f.child.qc); err != nil {
						t.Fatalf("live certification on validator %d: %v", i, err)
					}
					select {
					case msg := <-s.hotstuffMsgQ.priorityInput:
						if err := s.protocolMng.HandleMessage(msg.hMsg); err != nil {
							t.Fatalf("live NewView on validator %d: %v", i, err)
						}
					default:
						t.Fatalf("live certification did not admit NewView on validator %d", i)
					}
				}
				f.requireNewView(t, i)
			}
			// Include the live leader's highest QC in the first quorum. NewView
			// signatures use current committee indices, not fixture key indices.
			order := []int{leader}
			for i := range f.apps {
				if i != leader {
					order = append(order, i)
				}
			}
			collector := f.activate(leader)
			for position, sender := range order[:5] {
				delivery := f.apps[sender].sent[0]
				if delivery.to != collector.Self() {
					t.Fatal("replicas disagree on the new-epoch leader")
				}
				err := collector.protocolMng.HandleMessage(delivery.msg)
				if position < 4 && !errors.Is(err, hotstuff.ErrInsufficientQC) {
					t.Fatalf("report %d before quorum: %v", position+1, err)
				}
				if position == 4 && !errors.Is(err, hotstuff.ErrProposalValidationPending) {
					t.Fatalf("fifth signed report did not activate proposal construction: %v", err)
				}
			}
			select {
			case job := <-collector.proposalBuildJobs:
				if job == nil || job.request == nil || job.request.Key.ViewNumber != f.child.qc.Number+1 ||
					!hotstuff.SignedStateSemanticEqual(job.request.ParentQC, f.child.qc) {
					t.Fatal("new-epoch quorum did not schedule a proposal over the certified child")
				}
				job.cancel()
			default:
				t.Fatal("five valid post-sync NewViews left proposal construction dormant")
			}
		})
	}
}

func TestFHSSyncResumeSurvivesFullPriorityQueueAndDedup(t *testing.T) {
	f := newFHSSyncResumeFixture(t)
	f.importKey(t, 0)
	s := f.activate(0)
	for len(s.hotstuffMsgQ.priorityInput) < cap(s.hotstuffMsgQ.priorityInput) {
		s.hotstuffMsgQ.priorityInput <- &hotstuffMsg{hMsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgTimer}}
	}
	s.lastStartNewViewN = s.currentHotstuffBaseNumber()
	s.lastStartNewViewHash = s.GetCurrentView().ConsensusHash()
	s.lastStartNewViewAt = time.Now()
	s.processFHSSyncResume()
	f.requireNewView(t, 0)
}

func TestFHSSyncResumeDoesNotReactivateStoppedGeneration(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(fmt.Sprintf("restart_%t", restart), func(t *testing.T) {
			f := newFHSSyncResumeFixture(t)
			f.importKey(t, 0)
			s := f.activate(0)
			s.stop()
			if restart {
				s.muLifecycle.Lock()
				s.advanceLifecycleGenerationLocked()
				s.setRunState(1)
				s.muLifecycle.Unlock()
			}
			s.processFHSSyncResume()
			if len(f.apps[0].sent) != 0 {
				t.Fatal("old sync completion sent NewView across a lifecycle boundary")
			}
			_, stopped, _, _ := s.pacetMakerTimer.get()
			if !stopped {
				t.Fatal("old sync completion restarted the pacemaker")
			}
		})
	}
}

func TestFHSSyncResumeAfterBothEpochResetBoundaries(t *testing.T) {
	f := newFHSSyncResumeFixture(t)
	s := f.activate(0)
	beforeApplied, afterApplied := false, false
	s.bc.SetFHSFinalizedSyncLifecycle(
		func(block *types.Block, child *hotstuff.SignedState) (bool, error) {
			acquired, err := s.beforeFHSFinalizedSyncKeyCommit(block, child)
			if err == nil {
				// A normal loop tick can observe the first reset while sync still
				// owns chainmu and the publication barrier.
				if timerErr := s.protocolMng.HandleMessage(&hotstuff.HotstuffMessage{Code: hotstuff.MsgTimer}); timerErr != nil {
					t.Errorf("apply first reset at message boundary: %v", timerErr)
				}
				s.processFHSSyncResume()
				beforeApplied = true
			}
			return acquired, err
		}, s.waitFHSValidationPublication,
		func(block *types.Block, own, child *hotstuff.SignedState) error {
			err := s.afterFHSFinalizedSyncCommit(block, own, child)
			if err == nil {
				// The second reset is pending now, but Finish has not reopened
				// publication. This early visit must not consume the resume.
				s.processFHSSyncResume()
				afterApplied = true
			}
			return err
		}, s.finishFHSFinalizedSyncKeyCommit,
	)
	f.importKey(t, 0)
	if !beforeApplied || !afterApplied {
		t.Fatal("fixture did not traverse both reset boundaries")
	}
	s.processFHSSyncResume()
	f.requireNewView(t, 0)
}

func TestFHSSyncResumePreservesReadyRequestAfterEarlyRejection(t *testing.T) {
	f := newFHSSyncResumeFixture(t)
	f.importKey(t, 0)
	s := f.activate(0)
	// The real before-hook acquires publication but rejects this input before
	// invalidation/begin. Its paired Finish must not erase the previous success.
	invalid := f.child.verified.Block
	acquired, err := s.beforeFHSFinalizedSyncKeyCommit(invalid, f.child.qc)
	if !acquired || err == nil {
		t.Fatalf("early rejected key transition: acquired=%t error=%v", acquired, err)
	}
	s.finishFHSFinalizedSyncKeyCommit(invalid, core.FHSFinalizedSyncPreCommitFailed)
	s.processFHSSyncResume()
	f.requireNewView(t, 0)
}

func TestFHSSyncResumePreservesCanonicalWakeAfterInvalidatedPrecommitFailure(t *testing.T) {
	f := newFHSSyncResumeFixture(t)
	f.importKey(t, 0)
	s := f.activate(0)
	previousGeneration := atomic.LoadUint64(&s.proposalValidationGeneration)
	// Re-enter the accepted carrier branch without committing it again. This
	// exercises the actual invalidation, WAL rotation and failed Finish while
	// the earlier successful import's NewView is still pending.
	acquired, err := s.beforeFHSFinalizedSyncKeyCommit(f.block, f.child.qc)
	if !acquired || err != nil {
		t.Fatalf("accepted transition before injected precommit failure: acquired=%t error=%v", acquired, err)
	}
	if atomic.LoadUint64(&s.proposalValidationGeneration) <= previousGeneration {
		t.Fatal("fixture did not invalidate the previous worker generation")
	}
	s.finishFHSFinalizedSyncKeyCommit(f.block, core.FHSFinalizedSyncPreCommitFailed)
	s.processFHSSyncResume()
	f.requireNewView(t, 0)
	if s.bc.CurrentBlock().Hash() != f.block.Hash() || s.kbc.CurrentBlock().Hash() != f.key.Hash() {
		t.Fatal("failed transition changed canonical heads")
	}
}

func TestFHSSyncResumeRetriesActualLocalPriorityBackpressure(t *testing.T) {
	f := newFHSSyncResumeFixture(t)
	position, err := fairHotstuffLeaderIndex(f.f.replicas[0].chainConfig.FairHotstuffSeed,
		f.f.replicas[0].ChainID(), f.child.qc.Number+1, f.committee.RlpHash(), len(f.apps))
	if err != nil {
		t.Fatal(err)
	}
	leader := -1
	for i, app := range f.apps {
		if app.Self() == f.committee.List[position].Address {
			leader = i
		}
	}
	if leader < 0 {
		t.Fatal("new-epoch leader not found")
	}
	f.importKey(t, leader)
	s := f.activate(leader)
	app := f.apps[leader]
	app.serviceWrite = true // Traverse Service.Write(self), with no socket.
	for len(s.hotstuffMsgQ.priorityInput) < cap(s.hotstuffMsgQ.priorityInput) {
		s.hotstuffMsgQ.priorityInput <- &hotstuffMsg{hMsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgTimer}}
	}
	s.processFHSSyncResume()
	s.muFHSSyncResume.Lock()
	if s.fhsSyncResume == nil {
		s.muFHSSyncResume.Unlock()
		t.Fatal("local queue rejection incorrectly completed the pending resume")
	}
	s.fhsSyncResume.lastAttempt = time.Now().Add(-startNewViewDedupWindow)
	s.muFHSSyncResume.Unlock()
	for len(s.hotstuffMsgQ.priorityInput) > 0 {
		queued := <-s.hotstuffMsgQ.priorityInput
		if queued.hMsg.Code != hotstuff.MsgTimer {
			t.Fatal("full queue unexpectedly admitted a NewView")
		}
	}
	s.processFHSSyncResume()
	select {
	case queued := <-s.hotstuffMsgQ.priorityInput:
		// Reuse the independent envelope/report signature assertions on the
		// message actually admitted by Service.Write(self).
		app.sent = append(app.sent, fhsSyncResumeDelivery{s.Self(), queued.hMsg})
		f.requireNewView(t, leader)
	default:
		t.Fatal("draining the local queue did not allow the pending NewView retry")
	}
}

func TestFHSSyncCallbackDoesNotWaitForLifecycleLock(t *testing.T) {
	f := newFHSSyncResumeFixture(t)
	s := f.activate(0)
	type importResult struct {
		count int
		err   error
	}
	done := make(chan importResult, 1)
	s.muLifecycle.Lock()
	go func() {
		n, err := s.bc.InsertChain(types.Blocks{f.block.WithSeal(f.block.Header())})
		done <- importResult{n, err}
	}()
	select {
	case result := <-done:
		s.muLifecycle.Unlock()
		if result.err != nil || result.count != 1 {
			t.Fatalf("key sync while lifecycle was occupied: %+v", result)
		}
	case <-time.After(3 * time.Second):
		s.muLifecycle.Unlock()
		// Let a regressing importer unwind before fixture databases close.
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("key sync remained blocked after releasing lifecycle")
		}
		t.Fatal("sync callback waited for lifecycle while holding chainmu")
	}
	if len(f.apps[0].sent) != 0 {
		t.Fatal("sync callback performed a physical consensus send")
	}
	s.processFHSSyncResume()
	f.requireNewView(t, 0)
}

func TestFHSSyncResumeRetriesTransportFailureWithoutResettingPacemaker(t *testing.T) {
	f := newFHSSyncResumeFixture(t)
	f.importKey(t, 0)
	s := f.activate(0)
	app := f.apps[0]
	app.writeErr = errors.New("bounded transport unavailable")
	s.processFHSSyncResume()
	if len(app.sent) != 0 {
		t.Fatal("failed transport was recorded as delivered")
	}
	startedAt, stopped, _, _ := s.pacetMakerTimer.get()
	if stopped {
		t.Fatal("resume did not arm pacemaker before the transient send failure")
	}
	// Advance only the retry clock. There are no control-loop goroutines in
	// this fixture, and a wall-clock sleep would add no protocol evidence.
	s.muFHSSyncResume.Lock()
	if s.fhsSyncResume == nil {
		s.muFHSSyncResume.Unlock()
		t.Fatal("failed NewView send lost the pending resume")
	}
	s.fhsSyncResume.lastAttempt = time.Now().Add(-startNewViewDedupWindow)
	s.muFHSSyncResume.Unlock()
	app.writeErr = nil
	s.processFHSSyncResume()
	f.requireNewView(t, 0)
	retriedAt, _, _, _ := s.pacetMakerTimer.get()
	if !retriedAt.Equal(startedAt) {
		t.Fatal("transport retry reset the pacemaker timeout")
	}
}
