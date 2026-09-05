package reconfig

import (
	"fmt"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
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

func fhsCertificateBlockHash(qc *hotstuff.SignedState) common.Hash {
	if qc == nil {
		return common.Hash{}
	}
	ref, err := types.DecodeHotstuffProposalRef(qc.State)
	if err != nil {
		return common.Hash{}
	}
	return ref.BlockHash
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
