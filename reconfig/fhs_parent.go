package reconfig

import (
	"fmt"
	"sync/atomic"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// SelectedFHSProposalParent is a view's quorum-selected execution parent.
// HighestCertified remains the maximum observation advertised in NewView.
func (s *Service) SelectedFHSProposalParent() *hotstuff.SignedState {
	s.muProposalBody.RLock()
	selected, explicit := s.fhsSelectedParent, s.fhsParentSelected
	if !explicit {
		selected = s.fhsHighest
	}
	s.muProposalBody.RUnlock()
	if selected != nil {
		return hotstuff.CloneSignedState(selected.qc)
	}
	if !explicit {
		return s.HighestCertified()
	}
	return nil
}

// SelectFHSProposalParent is called only after the protocol authenticates the
// complete n-f NewView proof. A lower selected parent does not lower the WAL's
// observed-QC watermark, and cannot replace any canonical block.
func (s *Service) SelectFHSProposalParent(qc *hotstuff.SignedState) error {
	canonical := s.bc.CurrentBlock()
	if canonical == nil {
		return fmt.Errorf("missing canonical FHS parent")
	}
	var selected *fhsCertifiedProposal
	if qc == nil {
		if canonical.NumberU64() != 0 {
			return fmt.Errorf("nil FHS quorum parent above genesis")
		}
	} else {
		ref, err := s.verifyFHSQCCryptographic(qc)
		if err != nil {
			return err
		}
		if ref.Number < canonical.NumberU64() || (ref.Number == canonical.NumberU64() && ref.BlockHash != canonical.Hash()) {
			return fmt.Errorf("selected FHS parent conflicts with canonical head")
		}
		s.muProposalBody.RLock()
		selected = s.fhsCertifiedByID[ref.ProposalID()]
		s.muProposalBody.RUnlock()
		if selected == nil {
			if ref.BlockHash != canonical.Hash() {
				return hotstuff.ErrProposalValidationPending
			}
			if observed := s.HighestCertified(); observed == nil || observed.Number < qc.Number {
				return hotstuff.ErrProposalValidationPending
			}
			selected = &fhsCertifiedProposal{ref: ref, qc: hotstuff.CloneSignedState(qc), verified: &core.VerifiedProposal{Block: canonical}}
		} else if !hotstuff.SignedStateSemanticEqual(selected.qc, qc) {
			return fmt.Errorf("selected FHS parent certificate mismatch")
		}
	}
	if err := s.publishFHSExecutionParent(selected, canonical); err != nil {
		return err
	}
	s.muProposalBody.Lock()
	s.fhsSelectedParent, s.fhsParentSelected = selected, true
	s.muProposalBody.Unlock()
	return nil
}

func (s *Service) publishFHSExecutionParent(parent *fhsCertifiedProposal, canonical *types.Block) error {
	blocks := make([]*types.Block, 0, 4)
	s.muProposalBody.RLock()
	for cursor := parent; cursor != nil && cursor.ref.BlockHash != canonical.Hash(); cursor = fhsCertifiedParent(s.fhsCertifiedByID, cursor) {
		if cursor.verified == nil || cursor.verified.Block == nil || cursor.ref.Number <= canonical.NumberU64() {
			s.muProposalBody.RUnlock()
			return fmt.Errorf("selected FHS execution chain crosses canonical head")
		}
		blocks = append(blocks, cursor.verified.Block)
		if cursor.ref.ParentHash == canonical.Hash() {
			break
		}
		if fhsCertifiedParent(s.fhsCertifiedByID, cursor) == nil || len(blocks) > fhsMaxCertifiedChainDepth {
			s.muProposalBody.RUnlock()
			return fmt.Errorf("selected FHS execution chain is incomplete")
		}
	}
	s.muProposalBody.RUnlock()
	if s.txService != nil {
		s.txService.mu.Lock()
		// Reset exclusions as well as the head: transactions on an abandoned
		// certified fork must become eligible for proposals again.
		s.txService.proposedChain.clear(canonical)
		for i := len(blocks) - 1; i >= 0; i-- {
			s.txService.proposedChain.adoptCertified(blocks[i])
		}
		s.txService.mu.Unlock()
	}
	hash, number := canonical.Hash(), canonical.NumberU64()
	if parent != nil {
		hash, number = parent.ref.BlockHash, parent.ref.Number
	}
	s.muCurrentView.Lock()
	s.currentView.TxHash, s.currentView.TxNumber = hash, number
	s.waittingView.TxNumber = number
	s.muCurrentView.Unlock()
	return nil
}

// canonicalFHSParentQC verifies the certificate at the boundary of a staged
// branch without treating any uncommitted local QC as an immutable ancestor.
func (s *Service) canonicalFHSParentQC(qc *hotstuff.SignedState, canonical *types.Block) error {
	if qc == nil {
		if canonical.NumberU64() != 0 {
			return fmt.Errorf("missing canonical FHS parent QC")
		}
		return nil
	}
	ref, err := s.verifyFHSQCCryptographic(qc)
	if err != nil || ref.BlockHash != canonical.Hash() || ref.Number != canonical.NumberU64() {
		return fmt.Errorf("staged FHS chain has a non-canonical parent QC")
	}
	return nil
}

func (s *Service) HasValidatedFHSCertificate(qc *hotstuff.SignedState) bool {
	if qc == nil {
		return false
	}
	ref, err := types.DecodeHotstuffProposalRef(qc.State)
	if err != nil {
		return false
	}
	s.muProposalBody.RLock()
	record := s.fhsCertifiedByID[ref.ProposalID()]
	valid := record != nil && record.verified != nil && hotstuff.SignedStateSemanticEqual(record.qc, qc)
	s.muProposalBody.RUnlock()
	if valid {
		return true
	}
	if s.bc == nil || ref.Number > s.bc.CurrentBlockN() || s.bc.GetCanonicalHash(ref.Number) != ref.BlockHash {
		return false
	}
	observed := s.HighestCertified()
	return observed != nil && observed.Number >= qc.Number
}

// Caller holds muProposalBody. Proposal construction follows its selected
// ancestry; retained certificates on abandoned forks do not reserve work.
func (s *Service) fhsExecutionBranchLocked() map[common.Hash]*fhsCertifiedProposal {
	branch := make(map[common.Hash]*fhsCertifiedProposal)
	parent := s.fhsHighest
	if s.fhsParentSelected {
		parent = s.fhsSelectedParent
	}
	for cursor := parent; cursor != nil && cursor.ref != nil; cursor = fhsCertifiedParent(s.fhsCertifiedByID, cursor) {
		if _, seen := branch[cursor.ref.BlockHash]; seen {
			break
		}
		branch[cursor.ref.BlockHash] = cursor
	}
	return branch
}

// A block payload can be certified in more than one view. Hashes identify the
// execution state, while a child's ParentQCID identifies one exact certificate.
// The proposal-ID index retains every such certificate, including older ones
// still referenced by an independently valid child.
func fhsCertifiedParent(certificates map[common.Hash]*fhsCertifiedProposal, child *fhsCertifiedProposal) *fhsCertifiedProposal {
	if child == nil || child.ref == nil || child.ref.ParentQCID == (common.Hash{}) {
		return nil
	}
	for _, candidate := range certificates {
		if candidate == nil || candidate.ref == nil || candidate.qc == nil || candidate.ref.BlockHash != child.ref.ParentHash {
			continue
		}
		id, err := hotstuff.SignedStateID(candidate.qc)
		if err == nil && id.Hash() == child.ref.ParentQCID {
			return candidate
		}
	}
	return nil
}

// Caller holds muProposalBody. The hash index is only an execution artifact
// shortcut; consensus identity and ancestry always use fhsCertifiedByID.
func (s *Service) cacheFHSCertificateLocked(record *fhsCertifiedProposal) {
	s.fhsCertifiedByID[record.ref.ProposalID()] = record
	previous := s.fhsCertifiedByHash[record.ref.BlockHash]
	if previous == nil || previous.qc.Number <= record.qc.Number {
		s.fhsCertifiedByHash[record.ref.BlockHash] = record
	}
}

type fhsCertifiedProposal struct {
	ref      *types.HotstuffProposalRef
	verified *core.VerifiedProposal
	qc       *hotstuff.SignedState
	// Keep only authenticated metadata here. The encoded body and donor index
	// are evictable; verified.Block remains the source for reconstructing them
	// even if the asynchronous content writer has not reached disk yet.
	envelope       *proposalBodyMsg
	originalHeader *types.Header
}

func (s *Service) HighestCertified() *hotstuff.SignedState {
	s.muProposalBody.RLock()
	var qc *hotstuff.SignedState
	if s.fhsHighest != nil {
		qc = hotstuff.CloneSignedState(s.fhsHighest.qc)
	}
	s.muProposalBody.RUnlock()
	if s.fhsStore != nil {
		state, _, err := s.fhsStore.snapshot()
		if err == nil && state != nil && state.HighestQC != nil && (qc == nil || state.HighestQC.Number > qc.Number) {
			qc = hotstuff.CloneSignedState(state.HighestQC)
		}
	}
	return qc
}

// fhsCertifiedFrontierAboveCanonical returns the only in-memory certificate
// that is allowed to act as an execution base. A proof-aware block import can
// advance the canonical chain while an asynchronous HighQC worker still sees
// the old certified cache. Such a record is historical state, not a parent
// overlay: feeding it back to ValidateBlockForHotstuff would replay an already
// canonical block against the current StateDB.
func fhsCertifiedFrontierAboveCanonical(highest *fhsCertifiedProposal, canonicalNumber uint64) *fhsCertifiedProposal {
	if highest == nil || highest.ref == nil || highest.ref.Number <= canonicalNumber {
		return nil
	}
	return highest
}

// Reconciliation retains certified branches rooted at the committed head and
// selects the greatest observed view. Multiple uncommitted siblings are legal;
// a fork below the canonical head is not an execution base.
func (s *Service) reconcileFHSCertifiedFrontierLocked(canonical *types.Block) error {
	if s == nil || canonical == nil {
		return fmt.Errorf("cannot reconcile FHS certified frontier without canonical head")
	}
	if s.fhsCertifiedByHash == nil {
		s.fhsCertifiedByHash = make(map[common.Hash]*fhsCertifiedProposal)
	}
	if s.fhsCertifiedByID == nil {
		s.fhsCertifiedByID = make(map[common.Hash]*fhsCertifiedProposal)
	}
	kept := make(map[common.Hash]struct{})
	views := make(map[uint64]*hotstuff.SignedState)
	var frontier *fhsCertifiedProposal
	for id, record := range s.fhsCertifiedByID {
		if record == nil || record.ref == nil || record.ref.Number <= canonical.NumberU64() {
			continue
		}
		if record.ref.ProposalID() != id {
			return fmt.Errorf("FHS certified cache key mismatch for %s", id)
		}
		if err := validateStagedFHSCertificateArtifact(&fhsHighQCValidationItem{ref: record.ref, qc: record.qc, verified: record.verified}); err != nil {
			return err
		}
		cursor := record
		anchored := false
		for depth := 0; depth <= fhsMaxCertifiedChainDepth; depth++ {
			if cursor.ref.ParentHash == canonical.Hash() {
				anchored = cursor.ref.Number == canonical.NumberU64()+1
				break
			}
			parent := fhsCertifiedParent(s.fhsCertifiedByID, cursor)
			if parent == nil || parent.ref == nil || parent.qc == nil || parent.ref.Number <= canonical.NumberU64() {
				break
			}
			if parent.ref.Number+1 != cursor.ref.Number || parent.qc.Number >= cursor.qc.Number {
				return fmt.Errorf("invalid FHS certified ancestry")
			}
			cursor = parent
		}
		if !anchored {
			continue
		}
		if previous := views[record.qc.Number]; previous != nil && !hotstuff.SignedStateSemanticEqual(previous, record.qc) {
			return fmt.Errorf("conflicting FHS certificates at view %d", record.qc.Number)
		}
		views[record.qc.Number] = record.qc
		kept[id] = struct{}{}
		if frontier == nil || record.qc.Number > frontier.qc.Number {
			frontier = record
		}
	}
	s.fhsCertifiedByHash = make(map[common.Hash]*fhsCertifiedProposal)
	for id, record := range s.fhsCertifiedByID {
		if _, ok := kept[id]; ok {
			s.cacheFHSCertificateLocked(record)
			continue
		}
		delete(s.fhsCertifiedByID, id)
		if record != nil && record.ref != nil {
			s.deleteProposalBodyLocked(record.ref.ProposalID())
		}
	}
	s.fhsHighest = frontier
	if selected := s.fhsSelectedParent; selected != nil {
		if _, ok := kept[selected.ref.ProposalID()]; !ok {
			s.fhsSelectedParent, s.fhsParentSelected = nil, false
		}
	}
	return nil
}

func (s *Service) reconcileFHSCertifiedFrontier(canonical *types.Block) error {
	s.muProposalBody.Lock()
	defer s.muProposalBody.Unlock()
	return s.reconcileFHSCertifiedFrontierLocked(canonical)
}

func (s *Service) highestFHSCertifiedProposal() *core.VerifiedProposal {
	s.muProposalBody.RLock()
	defer s.muProposalBody.RUnlock()
	parent := s.fhsHighest
	if s.fhsParentSelected {
		parent = s.fhsSelectedParent
	}
	if parent == nil || (s.bc != nil && parent.ref.Number <= s.bc.CurrentBlockN()) {
		return nil
	}
	return parent.verified
}

func fhsProposalParentNumber(canonical uint64, highest *core.VerifiedProposal) uint64 {
	if highest != nil && highest.Block != nil && highest.Block.NumberU64() > canonical {
		return highest.Block.NumberU64()
	}
	return canonical
}

func (s *Service) getFHSCertifiedVerified(hash common.Hash) *core.VerifiedProposal {
	s.muProposalBody.RLock()
	defer s.muProposalBody.RUnlock()
	if certified := s.fhsCertifiedByHash[hash]; certified != nil {
		return certified.verified
	}
	return nil
}

// snapshotFHSCertifiedVerified is called by the serialized HotStuff loop when
// dispatching a worker. The private StateDB copy prevents a later 2-chain
// commit from consuming the mutable parent state while child validation is in
// flight. The receiving worker exclusively owns this snapshot and transfers its
// state to execution rather than making another copy.
func (s *Service) snapshotFHSCertifiedVerified(hash common.Hash) *core.VerifiedProposal {
	s.muProposalBody.RLock()
	defer s.muProposalBody.RUnlock()
	certified := s.fhsCertifiedByHash[hash]
	if certified == nil || certified.verified == nil {
		return nil
	}
	snapshot := *certified.verified
	if certified.verified.StateDB != nil {
		snapshot.StateDB = certified.verified.StateDB.Copy()
	}
	return &snapshot
}

func (s *Service) validateFHSProposalParent(ref *types.HotstuffProposalRef, parentQC *hotstuff.SignedState) error {
	if ref == nil {
		return fmt.Errorf("nil FHS proposal ref")
	}
	current := s.GetCurrentView()
	if ref.ParentHash != current.TxHash {
		return fmt.Errorf("FHS proposal does not extend selected execution parent")
	}
	selected := s.SelectedFHSProposalParent()
	if !hotstuff.SignedStateSemanticEqual(parentQC, selected) {
		return fmt.Errorf("FHS proposal parent differs from verified quorum selection")
	}
	if parentQC == nil {
		canonical := s.bc.CurrentBlock()
		if ref.ParentHash != canonical.Hash() || ref.Number != canonical.NumberU64()+1 {
			return fmt.Errorf("first FHS proposal must extend canonical head")
		}
		return nil
	}
	parentRef, err := types.DecodeHotstuffProposalRef(parentQC.State)
	if err != nil {
		return err
	}
	if parentRef.BlockHash != ref.ParentHash || ref.Number != parentRef.Number+1 || ref.ViewNumber <= parentRef.ViewNumber {
		return fmt.Errorf("FHS proposal does not directly extend its certified quorum parent")
	}
	return nil
}

func (s *Service) OnCertified(cert *hotstuff.SignedState) error {
	if s == nil {
		return types.ErrNotRunning
	}
	s.muLifecycle.Lock()
	if atomic.LoadInt32(&s.runningState) != 1 {
		s.muLifecycle.Unlock()
		return types.ErrNotRunning
	}
	generation := s.lifecycleGenerationLocked()

	// Async HighQC completion replays the authenticated QCBroadcast after Apply
	// has already installed and committed this exact QC. Keep that continuation
	// on the control loop small; it only advances the pacemaker/outbound NewView
	// and must not enter body retrieval or historical EVM execution again.
	if s.HasValidatedFHSCertificate(cert) {
		s.muLifecycle.Unlock()
		return s.finishFHSCertificationForGeneration(cert, generation)
	}
	// Replica path: the originating leader owns the durable dissemination
	// outbox. A receiver persists/adopts the QC, but must not claim it as a
	// locally replayable leader broadcast. Keep adoption inside the lifecycle
	// boundary so Backend.Stop cannot close its DB underneath the callback.
	if err := s.adoptFHSHighQC(cert, false, false); err != nil {
		s.muLifecycle.Unlock()
		return err
	}
	s.muLifecycle.Unlock()
	return s.finishFHSCertificationForGeneration(cert, generation)
}

func (s *Service) needsFHSFinalityBlock() bool {
	if !s.fairHotstuffEnabled() {
		return false
	}
	currentKeyHash := common.Hash{}
	if currentKey := s.kbc.CurrentBlock(); currentKey != nil {
		currentKeyHash = currentKey.Hash()
	}
	s.muProposalBody.RLock()
	defer s.muProposalBody.RUnlock()
	return fhsNeedsFinalityBlock(s.fhsExecutionBranchLocked(), currentKeyHash, s.isCanonicalFHSBlock)
}

// fhsNeedsFinalityBlock reports whether the certified frontier still needs a
// child proposal before it can reach 2-chain finality. An empty transaction
// block normally does not justify producing another empty block. The exception
// is an empty block certified under the previous key epoch: after its parent
// key block commits, one child under the new key is required to finish the
// handoff. Once that child is certified, its KeyHash matches currentKeyHash and
// the empty chain stops growing.
func fhsNeedsFinalityBlock(certifiedByHash map[common.Hash]*fhsCertifiedProposal, currentKeyHash common.Hash, isCommitted func(*types.Block) bool) bool {
	for _, certified := range certifiedByHash {
		if certified == nil || certified.verified == nil || certified.verified.Block == nil {
			continue
		}
		block := certified.verified.Block
		if isCommitted != nil && isCommitted(block) {
			continue
		}
		if block.BlockType() == types.Key_Block || len(block.Transactions()) > 0 || block.KeyHash() != currentKeyHash {
			return true
		}
	}
	return false
}

func (s *Service) isCanonicalFHSBlock(block *types.Block) bool {
	if block == nil {
		return false
	}
	hash := block.Hash()
	number := block.NumberU64()
	return s.bc.GetCanonicalHash(number) == hash && s.bc.HasBlockAndState(hash, number)
}

func fhsHasUncommittedKeyBlock(certifiedByHash map[common.Hash]*fhsCertifiedProposal, isCommitted func(*types.Block) bool) bool {
	return fhsHasConflictingUncommittedKeyBlock(certifiedByHash, nil, isCommitted)
}

func fhsHasConflictingUncommittedKeyBlock(certifiedByHash map[common.Hash]*fhsCertifiedProposal, candidate *types.Block, isCommitted func(*types.Block) bool) bool {
	for _, certified := range certifiedByHash {
		if certified == nil || certified.verified == nil || certified.verified.Block == nil {
			continue
		}
		block := certified.verified.Block
		if block.BlockType() == types.Key_Block && !isCommitted(block) && (candidate == nil || candidate.Hash() != block.Hash()) {
			return true
		}
	}
	return false
}

func (s *Service) hasConflictingUncommittedFHSKeyBlock(candidate *types.Block) bool {
	if !s.fairHotstuffEnabled() || candidate == nil || candidate.BlockType() != types.Key_Block {
		return false
	}
	s.muProposalBody.RLock()
	defer s.muProposalBody.RUnlock()
	return fhsHasConflictingUncommittedKeyBlock(s.fhsExecutionBranchLocked(), candidate, s.isCanonicalFHSBlock)
}

// hasUncommittedFHSKeyBlock reports whether the certified pipeline already
// contains a key-block transition which has not reached 2-chain finality yet.
// Building another key block on the still-canonical key head would create a
// competing key block at the same height and make historical QC verification
// depend on which sibling happened to be installed last.
func (s *Service) hasUncommittedFHSKeyBlock() bool {
	if !s.fairHotstuffEnabled() {
		return false
	}
	s.muProposalBody.RLock()
	defer s.muProposalBody.RUnlock()
	return fhsHasUncommittedKeyBlock(s.fhsExecutionBranchLocked(), s.isCanonicalFHSBlock)
}

func fhs2ChainCommitTarget(certificates map[common.Hash]*fhsCertifiedProposal, tip *fhsCertifiedProposal) *fhsCertifiedProposal {
	if tip == nil || tip.ref == nil || tip.qc == nil {
		return nil
	}
	parent := fhsCertifiedParent(certificates, tip)
	if parent == nil || parent.ref == nil || parent.qc == nil || parent.ref.BlockHash != tip.ref.ParentHash {
		return nil
	}
	if tip.ref.Number != parent.ref.Number+1 || tip.qc.Number <= parent.qc.Number || tip.qc.Number-parent.qc.Number != 1 {
		return nil
	}
	return parent
}

// preflightFHSCommitStep validates one independently finalizable parent/child
// pair before any epoch-local WAL or pacemaker state is changed. Callers run it
// immediately before each sequential commit so a preceding key carrier can
// advance the effective key head for the next step in a recovered prefix.
func (s *Service) preflightFHSCommitStep(target *fhsCertifiedProposal, proof *core.FHSCommitProof) (*types.KeyBlock, error) {
	if target == nil || target.ref == nil || target.verified == nil || target.verified.Block == nil || proof == nil || len(proof.QCs) == 0 {
		return nil, fmt.Errorf("incomplete FHS 2-chain commit proof")
	}
	block := target.verified.Block
	if err := s.bc.VerifyFHSCommitProof(block, proof); err != nil {
		return nil, fmt.Errorf("invalid Fair HotStuff 2-chain commit proof: %w", err)
	}
	if block.BlockType() != types.Key_Block {
		return nil, nil
	}
	keyBlock := types.DecodeToKeyBlock(block.KeyInfo())
	if keyBlock == nil || block.NumberU64() == 0 {
		return nil, fmt.Errorf("invalid FHS key-block transition %s", target.ref.BlockHash)
	}
	if block.KeyHash() != keyBlock.ParentHash() {
		return nil, fmt.Errorf("FHS key-block carrier key hash mismatch: block=%s keyHash=%s keyParent=%s", block.Hash(), block.KeyHash(), keyBlock.ParentHash())
	}
	if err := verifyKeyBlockCarrierParent(keyBlock, block.NumberU64()-1); err != nil {
		return nil, fmt.Errorf("invalid FHS key-block carrier: %w", err)
	}
	currentKey := s.kbc.CurrentBlock()
	if currentKey != nil && currentKey.Hash() == keyBlock.Hash() {
		// A proof-aware sync/import may have atomically committed this exact
		// carrier after the service built its certified-prefix snapshot. Treat
		// the transition as idempotent only when the transaction target is also
		// the exact canonical block; a key-only match is not sufficient.
		if s.bc.GetCanonicalHash(block.NumberU64()) != block.Hash() || !s.bc.HasBlockAndState(block.Hash(), block.NumberU64()) {
			return nil, fmt.Errorf("FHS key transition is current without its canonical carrier: key=%s carrier=%s", keyBlock.Hash(), block.Hash())
		}
	} else if err := s.kbc.ValidateKeyBlockForCanonicalInsert(keyBlock); err != nil {
		return nil, fmt.Errorf("invalid FHS canonical key transition: %w", err)
	}
	return keyBlock, nil
}

func (s *Service) commitFHS2ChainForCertified(qc *hotstuff.SignedState) error {
	if qc == nil {
		return fmt.Errorf("nil certified FHS state")
	}
	ref, err := types.DecodeHotstuffProposalRef(qc.State)
	if err != nil {
		return err
	}
	s.muProposalBody.RLock()
	tip := s.fhsCertifiedByID[ref.ProposalID()]
	target := fhs2ChainCommitTarget(s.fhsCertifiedByID, tip)
	if target == nil {
		s.muProposalBody.RUnlock()
		return nil
	}

	type commitStep struct {
		target *fhsCertifiedProposal
		proof  *core.FHSCommitProof
	}
	currentHash := s.bc.CurrentBlock().Hash()
	chain := make([]commitStep, 0, 2)
	path := []*hotstuff.SignedState{tip.qc}
	for cursor := target; cursor != nil && cursor.ref.BlockHash != currentHash; cursor = fhsCertifiedParent(s.fhsCertifiedByID, cursor) {
		chain = append(chain, commitStep{target: cursor, proof: &core.FHSCommitProof{QCs: append([]*hotstuff.SignedState(nil), path...)}})
		if cursor.ref.ParentHash == currentHash {
			break
		}
		if fhsCertifiedParent(s.fhsCertifiedByID, cursor) == nil {
			s.muProposalBody.RUnlock()
			return fmt.Errorf("FHS commit prefix missing certified ancestor %s", cursor.ref.ParentHash)
		}
		path = append([]*hotstuff.SignedState{cursor.qc}, path...)
	}
	s.muProposalBody.RUnlock()

	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	for _, step := range chain {
		certified := step.target
		keyBlock, err := s.preflightFHSCommitStep(certified, step.proof)
		if err != nil {
			return err
		}
		if keyBlock != nil {
			if err := s.rotateFHSEpochSafety(keyBlock.Hash()); err != nil {
				return fmt.Errorf("rotate FHS epoch safety before key-block commit: %w", err)
			}
			// The timeout proof was committee-specific and has just been rotated
			// out of WAL. Normalize immediately, even if the canonical DB write
			// below transiently fails, so replicas do not retain different local
			// old-epoch TC heights while retrying the same common proof.
			if err := s.normalizeFHSEpochView(qc, s.kbc.CurrentBlock()); err != nil {
				return fmt.Errorf("prepare FHS epoch view normalization: %w", err)
			}
		}
		if err := s.txService.decideFHSVerifiedProposal(certified.ref, certified.verified, certified.qc, step.proof); err != nil {
			return err
		}
		if keyBlock != nil {
			// The key head and committee are now canonical. Apply the same QC base
			// to that exact new key context before any later commit step can fail.
			if err := s.normalizeFHSEpochView(qc, s.kbc.CurrentBlock()); err != nil {
				return fmt.Errorf("complete FHS epoch view normalization: %w", err)
			}
		}
		proposalID := certified.ref.ProposalID()
		s.muProposalBody.Lock()
		delete(s.fhsCertifiedByHash, certified.ref.BlockHash)
		delete(s.fhsCertifiedByID, proposalID)
		s.deleteProposalBodyLocked(proposalID)
		s.muProposalBody.Unlock()
		log.Info("FHS 2-CHAIN COMMIT",
			"number", certified.ref.Number,
			"view", certified.qc.Number,
			"hash", certified.ref.BlockHash,
			"trigger", tip.ref.BlockHash,
			"triggerView", tip.qc.Number)
	}
	canonical := s.bc.CurrentBlock()
	if err := s.reconcileFHSCertifiedFrontier(canonical); err != nil {
		return err
	}
	s.muProposalBody.RLock()
	parent := s.fhsHighest
	if s.fhsParentSelected {
		parent = s.fhsSelectedParent
	}
	s.muProposalBody.RUnlock()
	return s.publishFHSExecutionParent(parent, canonical)
}

// normalizeFHSEpochView gives every replica the same numeric pacemaker base
// after a key epoch transition. A replica may have observed a valid higher TC
// from the old epoch while another replica missed it; retaining those local
// maxima would split their NewView target numbers. The child QC that finalized
// the transition is common proof, so its view is the deterministic new base.
// LastVote remains durable and still rejects a conflicting same-view proposal;
// replicas with a higher old-epoch vote advance together through new-epoch TCs.
func (s *Service) normalizeFHSEpochView(qc *hotstuff.SignedState, keyBlock *types.KeyBlock) error {
	if qc == nil || keyBlock == nil {
		return fmt.Errorf("missing FHS epoch normalization proof")
	}
	ref, err := types.DecodeHotstuffProposalRef(qc.State)
	if err != nil {
		return err
	}
	if ref.ChainID != s.ChainID() || ref.ViewNumber != qc.Number || ref.ViewID != qc.ViewID || ref.LeaderID != qc.LeaderID {
		return fmt.Errorf("FHS epoch normalization QC context mismatch")
	}
	s.muCurrentView.Lock()
	s.currentView.TxNumber = ref.Number
	s.currentView.TxHash = ref.BlockHash
	s.currentView.KeyNumber = keyBlock.NumberU64()
	s.currentView.KeyHash = keyBlock.Hash()
	s.currentView.CommitteeHash = keyBlock.CommitteeHash()
	s.currentView.ViewNumber = qc.Number
	s.currentView.Round = 0
	s.currentView.NoDone = true
	s.currentView.LeaderIndex = s.fairHotstuffLeaderIndexForCurrentLocked()
	s.waittingView.TxNumber = ref.Number
	s.waittingView.KeyNumber = keyBlock.NumberU64()
	s.muCurrentView.Unlock()
	if s.protocolMng != nil {
		s.protocolMng.ScheduleFHSEpochReset()
	}
	return nil
}

func (s *Service) ApplyFHSHighQCValidation(result *hotstuff.FHSHighQCValidationResult) error {
	if result == nil || result.Err != nil {
		return fmt.Errorf("invalid FHS HighQC validation result")
	}
	output, ok := result.ApplicationData.(*fhsHighQCValidationOutput)
	if !ok || output == nil || output.key != result.Key {
		return fmt.Errorf("FHS HighQC validation result context mismatch")
	}
	if err := s.acquireFHSValidationPublication(fhsValidationPublicationHighQC); err != nil {
		return err
	}
	transferred := false
	defer func() {
		if !transferred {
			s.releaseFHSValidationPublication(fhsValidationPublicationHighQC)
		}
	}()
	if output.serviceGeneration != 0 && (atomic.LoadInt32(&s.runningState) != 1 ||
		atomic.LoadUint64(&s.proposalValidationGeneration) != output.serviceGeneration) {
		return hotstuff.ErrOldState
	}
	if atomic.LoadInt32(&s.fhsEpochTransition) != 0 {
		return hotstuff.ErrOldState
	}
	if output.validationGeneration != 0 && !s.isHighQCValidationOutputActive(output) {
		return hotstuff.ErrOldState
	}
	if err := s.installStagedFHSHighQC(output, false, false); err != nil {
		return err
	}
	if err := s.commitFHS2ChainForCertified(output.targetQC); err != nil {
		return err
	}
	if _, err := s.completeDeferredFHSRecovery(output.targetQC); err != nil {
		return err
	}
	if output.validationGeneration != 0 && !s.markHighQCValidationApplied(result.Key, output.validationGeneration) {
		return hotstuff.ErrOldState
	}
	s.activeHighQCValidationPublish = result
	transferred = true
	return nil
}

// FinishFHSHighQCValidation retains the same barrier through manager state
// cleanup and exact continuation replay, not merely through application install.
func (s *Service) FinishFHSHighQCValidation(result *hotstuff.FHSHighQCValidationResult) {
	if s == nil || result == nil ||
		atomic.LoadInt32(&s.fhsValidationPublicationOwner) != int32(fhsValidationPublicationHighQC) ||
		s.activeHighQCValidationPublish != result {
		return
	}
	s.activeHighQCValidationPublish = nil
	if !s.releaseFHSValidationPublication(fhsValidationPublicationHighQC) {
		atomic.StoreInt32(&s.fhsEpochTransition, 1)
		s.setRunState(0)
		log.Error("Fair HotStuff HighQC validation failed to release its publication barrier")
	}
}
