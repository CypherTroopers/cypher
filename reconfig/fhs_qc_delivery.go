package reconfig

import (
	"bytes"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// Keep the previous canonical generation reachable during asynchronous sends,
// plus the signing generations still referenced by our durable QC state. This
// changes transport reachability only; each message still proves its committee.
func (s *Service) addFHSQCDeliveryPeers(peers map[string][]byte) error {
	if s == nil || s.kbc == nil {
		return nil
	}
	generations := make(map[common.Hash]struct{})
	if key := s.kbc.CurrentBlock(); key != nil && key.NumberU64() > 0 {
		generations[key.ParentHash()] = struct{}{}
	}
	qcs := []*hotstuff.SignedState{s.HighestCertified()}
	if s.fhsStore != nil {
		pending, err := s.fhsStore.pendingBroadcastSnapshot()
		if err != nil {
			return err
		}
		qcs = append(qcs, pending)
	}
	for _, qc := range qcs {
		if qc == nil {
			continue
		}
		ref, err := types.DecodeHotstuffProposalRef(qc.State)
		if err != nil {
			return fmt.Errorf("decode retained FHS delivery certificate: %w", err)
		}
		generations[ref.KeyHash] = struct{}{}
	}
	for keyHash := range generations {
		if err := s.addFHSCommitteePeers(peers, keyHash); err != nil {
			return err
		}
	}
	return nil
}

// fhsQCBroadcastCommittee preserves the certified proposal's recipients across
// committee changes, including broadcasts rebuilt from the durable outbox.
// DataB/DataC carry the transaction QC signature/mask; DataD carries the exact
// signed proposal reference. An optional DataA key-state signature does not
// change that routing identity. QC cryptographic validation remains at the
// certification and receiving boundaries.
func (s *Service) fhsQCBroadcastCommittee(data *hotstuff.HotstuffMessage) (*bftview.Committee, error) {
	if s == nil || data == nil || data.Code != hotstuff.MsgQCBroadcast ||
		len(data.DataB) == 0 || len(data.DataC) == 0 || len(data.DataD) == 0 {
		return nil, fmt.Errorf("incomplete FHS QC broadcast")
	}
	ref, err := types.DecodeHotstuffProposalRef(data.DataD)
	if err != nil {
		return nil, fmt.Errorf("decode FHS QC broadcast proposal: %w", err)
	}
	if ref.ChainID != s.ChainID() || ref.ViewNumber != data.Number ||
		ref.ViewID != data.ViewId || ref.LeaderID != data.Id {
		return nil, fmt.Errorf("FHS QC broadcast proposal context mismatch")
	}
	_, committee, _, err := s.resolveExactFHSCommittee(ref.KeyHash, true)
	if err != nil {
		return nil, fmt.Errorf("resolve FHS QC broadcast committee %s: %w", ref.KeyHash, err)
	}
	return committee, nil
}

// A leader keeps its durable QC dissemination outbox until a higher QC makes
// it obsolete. Suppress only the immediate same-process replay caused by the
// leader consuming its own just-sent QC. The marker is intentionally bounded
// and memory-only: ordinary delivery recovery resumes after the window, while
// a restart can replay the durable outbox immediately.
const fhsQCBroadcastReplaySuppressionWindow = 5 * time.Second

func (s *Service) beginFHSQCBroadcastForGeneration(cert *hotstuff.SignedState, generation uint64) error {
	if s == nil || cert == nil {
		return fmt.Errorf("cannot begin an empty FHS certification broadcast")
	}
	s.muFHSQCBroadcast.Lock()
	defer s.muFHSQCBroadcast.Unlock()
	if s.fhsActiveQCBroadcast != nil {
		if !hotstuff.SignedStateSemanticEqual(s.fhsActiveQCBroadcast, cert) {
			return fmt.Errorf("another FHS certification broadcast is already active")
		}
		if s.fhsActiveQCBroadcastGeneration != generation {
			return fmt.Errorf("FHS certification broadcast belongs to another service generation")
		}
		return nil
	}
	// A direct protocol retry must not be blocked by the post-send replay
	// suppression marker. Only replayPendingFHSQCBroadcast consults that marker.
	s.fhsActiveQCBroadcast = hotstuff.CloneSignedState(cert)
	s.fhsActiveQCBroadcastGeneration = generation
	return nil
}

// abortFHSQCBroadcast clears an active attempt which did not achieve complete
// committee queue admission. It must not create a post-send suppression marker.
func (s *Service) abortFHSQCBroadcast(cert *hotstuff.SignedState) error {
	if s == nil || cert == nil {
		return fmt.Errorf("cannot abort an empty FHS certification broadcast")
	}
	s.muFHSQCBroadcast.Lock()
	defer s.muFHSQCBroadcast.Unlock()
	if s.fhsActiveQCBroadcast == nil {
		return nil
	}
	if !hotstuff.SignedStateSemanticEqual(s.fhsActiveQCBroadcast, cert) {
		return fmt.Errorf("FHS certification broadcast abort mismatch")
	}
	s.fhsActiveQCBroadcast = nil
	s.fhsActiveQCBroadcastGeneration = 0
	return nil
}

// completeFHSQCBroadcast records that the physical broadcast happened.
// The completed marker is a single bounded entry and is never persisted.
func (s *Service) completeFHSQCBroadcast(cert *hotstuff.SignedState, now time.Time) error {
	if s == nil || cert == nil {
		return fmt.Errorf("cannot complete an empty FHS certification broadcast")
	}
	s.muFHSQCBroadcast.Lock()
	defer s.muFHSQCBroadcast.Unlock()
	if s.fhsActiveQCBroadcast == nil {
		return fmt.Errorf("cannot complete an FHS certification broadcast that is not active")
	}
	if !hotstuff.SignedStateSemanticEqual(s.fhsActiveQCBroadcast, cert) {
		return fmt.Errorf("FHS certification broadcast completion mismatch")
	}
	s.fhsActiveQCBroadcast = nil
	s.fhsActiveQCBroadcastGeneration = 0
	s.fhsCompletedQCBroadcast = hotstuff.CloneSignedState(cert)
	s.fhsCompletedQCBroadcastExpiry = now.Add(fhsQCBroadcastReplaySuppressionWindow)
	return nil
}

func (s *Service) fhsQCBroadcastReplaySuppressed(cert *hotstuff.SignedState, now time.Time) bool {
	if s == nil || cert == nil {
		return false
	}
	s.muFHSQCBroadcast.Lock()
	defer s.muFHSQCBroadcast.Unlock()
	if hotstuff.SignedStateSemanticEqual(s.fhsActiveQCBroadcast, cert) {
		return true
	}
	if s.fhsCompletedQCBroadcast == nil {
		return false
	}
	if !now.Before(s.fhsCompletedQCBroadcastExpiry) {
		s.fhsCompletedQCBroadcast = nil
		s.fhsCompletedQCBroadcastExpiry = time.Time{}
		return false
	}
	return hotstuff.SignedStateSemanticEqual(s.fhsCompletedQCBroadcast, cert)
}

func (s *Service) fhsQCBroadcastActiveGeneration(cert *hotstuff.SignedState) (uint64, bool) {
	if s == nil || cert == nil {
		return 0, false
	}
	s.muFHSQCBroadcast.Lock()
	defer s.muFHSQCBroadcast.Unlock()
	if !hotstuff.SignedStateSemanticEqual(s.fhsActiveQCBroadcast, cert) {
		return 0, false
	}
	return s.fhsActiveQCBroadcastGeneration, true
}

func (s *Service) clearFHSQCBroadcastMarkers() {
	if s == nil {
		return
	}
	s.muFHSQCBroadcast.Lock()
	s.fhsActiveQCBroadcast = nil
	s.fhsActiveQCBroadcastGeneration = 0
	s.fhsCompletedQCBroadcast = nil
	s.fhsCompletedQCBroadcastExpiry = time.Time{}
	s.muFHSQCBroadcast.Unlock()
}

func (s *Service) OnFHSLeaderCertifiedBeforeBroadcast(cert *hotstuff.SignedState) (err error) {
	if s == nil {
		return fmt.Errorf("cannot begin an FHS certification broadcast on a nil service")
	}
	s.muLifecycle.Lock()
	defer s.muLifecycle.Unlock()
	if atomic.LoadInt32(&s.runningState) != 1 {
		return types.ErrNotRunning
	}
	generation := s.lifecycleGenerationLocked()
	if err := s.beginFHSQCBroadcastForGeneration(cert, generation); err != nil {
		return err
	}
	ready := false
	defer func() {
		if !ready {
			if cleanupErr := s.abortFHSQCBroadcast(cert); cleanupErr != nil {
				log.Error("failed to clear aborted FHS certification broadcast", "number", cert.Number, "err", cleanupErr)
			}
		}
	}()
	if err := s.adoptFHSHighQC(cert, false, true); err != nil {
		return err
	}
	if err := s.refreshFHSCertifiedCommitteePeerAuthorization(); err != nil {
		return err
	}
	activeGeneration, active := s.fhsQCBroadcastActiveGeneration(cert)
	generationCurrent := s.lifecycleGenerationActiveLocked(generation) && active && activeGeneration == generation
	if !generationCurrent {
		return types.ErrNotRunning
	}
	ready = true
	return nil
}

func (s *Service) OnFHSLeaderCertifiedAfterBroadcast(cert *hotstuff.SignedState, broadcastSucceeded bool) (err error) {
	// Before has bracketed this physical send attempt, including retries. Mark
	// a successful queue admission completed even when canonical adoption below
	// fails. If any committee delivery was rejected, clear the active marker
	// before finishing so sendNewViewMsg can immediately replay the durable outbox.
	// Calling After without a successful Before is rejected rather than pretending
	// that a send occurred.
	generation, active := s.fhsQCBroadcastActiveGeneration(cert)
	if !active || generation == 0 {
		return fmt.Errorf("cannot complete an FHS certification broadcast that is not active")
	}
	if !s.lifecycleGenerationActive(generation) {
		return types.ErrNotRunning
	}
	if !broadcastSucceeded {
		if err := s.abortFHSQCBroadcast(cert); err != nil {
			return err
		}
		return s.finishFHSCertificationForGeneration(cert, generation)
	}
	defer func() {
		if cleanupErr := s.completeFHSQCBroadcast(cert, time.Now()); cleanupErr != nil {
			if err == nil {
				err = cleanupErr
			} else {
				log.Error("failed to clear completed FHS certification broadcast", "number", cert.Number, "err", cleanupErr)
			}
		}
	}()
	return s.finishFHSCertificationForGeneration(cert, generation)
}

func (s *Service) finishFHSCertificationState(cert *hotstuff.SignedState) error {
	if err := s.refreshFHSCertifiedCommitteePeerAuthorization(); err != nil {
		return fmt.Errorf("authorize certified FHS committee handoff peers: %w", err)
	}
	if err := s.commitFHS2ChainForCertified(cert); err != nil {
		return err
	}
	return nil
}

func (s *Service) finishFHSCertificationForGeneration(cert *hotstuff.SignedState, generation uint64) error {
	var (
		pendingReplay *hotstuff.SignedState
		replayMessage *hotstuff.HotstuffMessage
		replayErr     error
	)

	// Keep every local persistence and activation step inside the MinerStop
	// boundary. Preparing a durable replay can read the safety DB, so it belongs
	// here too; only the already-built network message is sent after unlocking.
	s.muLifecycle.Lock()
	if !s.lifecycleGenerationActiveLocked(generation) {
		s.muLifecycle.Unlock()
		return types.ErrNotRunning
	}
	if err := s.finishFHSCertificationState(cert); err != nil {
		s.muLifecycle.Unlock()
		return err
	}
	// Canonical insertion invokes ProcInsertDone synchronously. Reconciliation
	// may stop this service without taking muLifecycle, so fail closed before
	// rearming the pacemaker even though the outer lifecycle lock is still held.
	if !s.lifecycleGenerationActiveLocked(generation) {
		s.muLifecycle.Unlock()
		return types.ErrNotRunning
	}
	_ = s.pacetMakerTimer.start()
	if s.fairHotstuffEnabled() && !s.hasDeferredFHSRecovery() {
		pendingReplay, replayMessage, replayErr = s.preparePendingFHSQCBroadcastReplay()
	}
	s.muLifecycle.Unlock()

	// A physical send may wait on bounded transport backpressure. Do not make
	// MinerStop wait for it. No database or consensus state is touched here.
	if replayErr != nil {
		log.Error("cannot replay durable FHS QC broadcast", "err", replayErr)
	} else {
		s.broadcastPreparedFHSQCBroadcast(pendingReplay, replayMessage)
	}

	// Stop, or a Stop/Start pair, may have happened while the prepared message
	// was sent. Revalidate the exact generation before admitting NewView.
	s.muLifecycle.Lock()
	defer s.muLifecycle.Unlock()
	if !s.lifecycleGenerationActiveLocked(generation) {
		return types.ErrNotRunning
	}
	s.sendNewViewMsgAfterReplay(cert.Number)
	return nil
}

func activeFHSAuthorizedPeers(committee *bftview.Committee) (map[string][]byte, error) {
	if committee == nil {
		return nil, fmt.Errorf("active Fair HotStuff committee is unavailable")
	}
	if err := hotstuff.ValidateBFTCommitteeSize(len(committee.List)); err != nil {
		return nil, err
	}
	peers := make(map[string][]byte, len(committee.List))
	for index, node := range committee.List {
		if node == nil || node.Address == "" || node.Public == "" {
			return nil, fmt.Errorf("active Fair HotStuff committee member %d is incomplete", index)
		}
		public := bftview.StrToBlsPubKey(node.Public)
		if public == nil {
			return nil, fmt.Errorf("active Fair HotStuff committee member %d has an invalid BLS key", index)
		}
		if _, duplicate := peers[node.Address]; duplicate {
			return nil, fmt.Errorf("active Fair HotStuff committee has duplicate address %q", node.Address)
		}
		peers[node.Address] = public.Serialize()
	}
	return peers, nil
}

// fhsPeerAuthorizationWithCertifiedCarriers widens only the transport-level
// allow-list during a key handoff. The pending committee obtains no consensus
// authority here: proposal sidecars still require a verified activation QC,
// and HotStuff messages remain bound to their exact committee/view proofs.
// This union merely lets a newly added member deliver that self-contained
// proof. The previous canonical generation and durable QC generations remain
// reachable until their delivery/recovery references expire.
func (s *Service) fhsPeerAuthorizationWithCertifiedCarriers(active *bftview.Committee) (map[string][]byte, error) {
	peers, err := activeFHSAuthorizedPeers(active)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, fmt.Errorf("missing FHS service")
	}

	if err := s.addFHSQCDeliveryPeers(peers); err != nil {
		return nil, err
	}

	s.muProposalBody.RLock()
	carriers := make([]*certifiedFHSKeyCarrier, 0, 1)
	for _, record := range s.fhsCertifiedByHash {
		if record == nil || record.verified == nil || record.verified.Block == nil || record.verified.Block.BlockType() != types.Key_Block {
			continue
		}
		candidate := types.DecodeToKeyBlock(record.verified.Block.KeyInfo())
		artifact := &fhsHighQCValidationItem{ref: record.ref, qc: record.qc, verified: record.verified}
		if candidate == nil || validateStagedFHSCertificateArtifact(artifact) != nil ||
			record.verified.Block.KeyHash() != candidate.ParentHash() || record.verified.Block.NumberU64() == 0 ||
			candidate.T_Number() != record.verified.Block.NumberU64()-1 {
			s.muProposalBody.RUnlock()
			return nil, fmt.Errorf("invalid certified FHS key carrier in peer authorization pipeline")
		}
		refCopy := *record.ref
		carriers = append(carriers, &certifiedFHSKeyCarrier{
			keyBlock: candidate,
			ref:      &refCopy,
			qc:       hotstuff.CloneSignedState(record.qc),
		})
	}
	s.muProposalBody.RUnlock()

	for _, carrier := range carriers {
		verifiedRef, err := s.verifyFHSQCCryptographic(carrier.qc)
		if err != nil {
			return nil, fmt.Errorf("verify certified FHS key carrier for peer authorization: %w", err)
		}
		if verifiedRef == nil || verifiedRef.ProposalID() != carrier.ref.ProposalID() {
			return nil, fmt.Errorf("certified FHS key carrier peer authorization context mismatch")
		}
		committee := bftview.LoadMember(carrier.keyBlock.NumberU64(), carrier.keyBlock.Hash(), true)
		if committee == nil || len(committee.List) == 0 || committee.RlpHash() != carrier.keyBlock.CommitteeHash() {
			return nil, fmt.Errorf("certified FHS key carrier committee commitment mismatch")
		}
		generationPeers, err := activeFHSAuthorizedPeers(committee)
		if err != nil {
			return nil, err
		}
		for address, publicKey := range generationPeers {
			if existing := peers[address]; len(existing) > 0 && !bytes.Equal(existing, publicKey) {
				return nil, fmt.Errorf("conflicting FHS peer key for %q across committee handoff", address)
			}
			peers[address] = append([]byte(nil), publicKey...)
		}
	}
	return peers, nil
}

func (s *Service) refreshFHSCertifiedCommitteePeerAuthorization() error {
	if s == nil || !s.fairHotstuffEnabled() || !s.isRunning() || s.netService == nil || s.netService.server == nil {
		return nil
	}
	peers, err := s.fhsPeerAuthorizationWithCertifiedCarriers(bftview.GetCurrentMember())
	if err != nil {
		return err
	}
	if err := s.netService.server.UpdatePeerAuthorization(peers); err != nil {
		return err
	}
	s.netService.setAuthenticatedPeerKeys(peers)
	return nil
}

func (s *Service) addFHSCommitteePeers(peers map[string][]byte, keyHash common.Hash) error {
	if s == nil || s.kbc == nil || peers == nil || keyHash == (common.Hash{}) {
		return fmt.Errorf("missing FHS committee generation")
	}
	_, committee, _, err := s.resolveExactFHSCommittee(keyHash, true)
	if err != nil {
		return fmt.Errorf("load FHS committee %s: %w", keyHash, err)
	}
	generationPeers, err := activeFHSAuthorizedPeers(committee)
	if err != nil {
		return fmt.Errorf("load FHS committee %s: %w", keyHash, err)
	}
	for address, publicKey := range generationPeers {
		if existing := peers[address]; len(existing) > 0 && !bytes.Equal(existing, publicKey) {
			return fmt.Errorf("conflicting FHS peer key for %q across committee generations", address)
		}
		peers[address] = append([]byte(nil), publicKey...)
	}
	return nil
}

func (s *Service) addDeferredFHSRecoveryPeers(peers map[string][]byte, recovery *fhsDeferredRecovery) error {
	if recovery == nil {
		return nil
	}
	if s == nil || s.kbc == nil || recovery.HighestQC == nil {
		return fmt.Errorf("missing deferred FHS recovery committee")
	}
	ref, err := types.DecodeHotstuffProposalRef(recovery.HighestQC.State)
	if err != nil || ref == nil || ref.KeyHash == (common.Hash{}) {
		return fmt.Errorf("decode deferred FHS recovery committee: %w", err)
	}
	return s.addFHSCommitteePeers(peers, ref.KeyHash)
}

// extendDeferredFHSRecoveryPeers admits an older proposal generation only
// after its QC has been cryptographically verified and authorized by the
// active HighQC worker. This is needed when a repaired parent crosses more
// than one key-block boundary; completion narrows the transport back to the
// current committee before the consensus gate opens.
func (s *Service) extendDeferredFHSRecoveryPeers(keyHash common.Hash) error {
	if s == nil || !s.hasDeferredFHSRecovery() || s.netService == nil || s.netService.server == nil {
		return nil
	}
	peers, err := s.fhsPeerAuthorizationWithCertifiedCarriers(bftview.GetCurrentMember())
	if err != nil {
		return err
	}
	if err := s.addDeferredFHSRecoveryPeers(peers, s.fhsStore.deferredRecoverySnapshot()); err != nil {
		return err
	}
	if err := s.addFHSCommitteePeers(peers, keyHash); err != nil {
		return err
	}
	if err := s.netService.server.UpdatePeerAuthorization(peers); err != nil {
		return err
	}
	s.netService.setAuthenticatedPeerKeys(peers)
	return nil
}
