package reconfig

import (
	"fmt"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// verifyFHSKeyActivationFinality authenticates every certified descendant of a
// known key carrier. Unlike the direct-child shortcut, its earlier edges may
// skip views; the terminal pair must be consecutive. All descendants precede
// activation and must therefore be signed by the carrier's old committee.
func (s *Service) verifyFHSKeyActivationFinality(carrier *certifiedFHSKeyCarrier, encoded []byte) (*types.HotstuffProposalRef, error) {
	if carrier == nil || carrier.keyBlock == nil || carrier.ref == nil || carrier.qc == nil {
		return nil, fmt.Errorf("incomplete certified key activation carrier")
	}
	proof, err := core.DecodeFHSCommitProofBytes(encoded)
	if err != nil {
		return nil, err
	}
	parentRef, err := s.verifyFHSQCCryptographic(carrier.qc)
	if err != nil || parentRef.ProposalID() != carrier.ref.ProposalID() {
		return nil, fmt.Errorf("invalid certified key activation carrier QC")
	}
	parentQC := carrier.qc
	for index, qc := range proof.QCs {
		unverifiedRef, err := types.DecodeHotstuffProposalRef(qc.State)
		if err != nil || unverifiedRef.KeyHash != carrier.keyBlock.ParentHash() {
			return nil, fmt.Errorf("key activation descendant %d uses another signing epoch", index)
		}
		ref, err := s.verifyFHSQCCryptographic(qc)
		if err != nil {
			return nil, fmt.Errorf("invalid key activation descendant QC %d: %w", index, err)
		}
		parentID, err := hotstuff.SignedStateID(parentQC)
		if err != nil || ref.ParentQCID != parentID.Hash() || ref.ParentHash != parentRef.BlockHash ||
			ref.Number <= parentRef.Number || ref.Number-parentRef.Number != 1 || ref.ViewNumber <= parentRef.ViewNumber ||
			ref.KeyHash != carrier.keyBlock.ParentHash() {
			return nil, fmt.Errorf("key activation descendant %d does not extend the old-epoch proof", index)
		}
		if index == len(proof.QCs)-1 && ref.ViewNumber-parentRef.ViewNumber != 1 {
			return nil, fmt.Errorf("key activation finality requires consecutive terminal views")
		}
		parentRef, parentQC = ref, qc
	}
	return parentRef, nil
}

// canonicalFHSKeyActivationProof carries the proof that activated a proposal's
// signer generation. Lagging members can authenticate the first new-epoch
// manifest without already having received the terminal old-epoch QC.
func (s *Service) canonicalFHSKeyActivationProof(keyHash common.Hash) []byte {
	if s == nil || !s.fairHotstuffEnabled() || s.bc == nil || s.kbc == nil {
		return nil
	}
	key := s.kbc.GetBlockByHash(keyHash)
	if key == nil || key.NumberU64() == 0 || key.T_Number() == ^uint64(0) {
		return nil
	}
	carrier := s.bc.GetBlockByNumber(key.T_Number() + 1)
	if carrier == nil || carrier.BlockType() != types.Key_Block {
		return nil
	}
	embedded := types.DecodeToKeyBlock(carrier.KeyInfo())
	if embedded == nil || embedded.Hash() != keyHash {
		return nil
	}
	return carrier.FHSFinalityProof()
}

func (s *Service) loadViewCommittee(view *bftview.View, needIP bool) (*bftview.Committee, error) {
	if view == nil || view.KeyHash == (common.Hash{}) {
		return nil, fmt.Errorf("view has no committee key block")
	}
	keyblock := s.kbc.GetBlock(view.KeyHash, view.KeyNumber)
	if keyblock == nil {
		return nil, fmt.Errorf("unknown committee key block number=%d hash=%s", view.KeyNumber, view.KeyHash)
	}
	if keyblock.CommitteeHash() != view.CommitteeHash {
		return nil, fmt.Errorf("view committee hash mismatch: view=%s keyblock=%s", view.CommitteeHash, keyblock.CommitteeHash())
	}
	committee := bftview.LoadMember(view.KeyNumber, view.KeyHash, needIP)
	if committee == nil {
		return nil, fmt.Errorf("committee unavailable for key block number=%d hash=%s", view.KeyNumber, view.KeyHash)
	}
	if committee.RlpHash() != keyblock.CommitteeHash() {
		return nil, fmt.Errorf("stored committee hash mismatch for key block %s", view.KeyHash)
	}
	return committee, nil
}

// resolveExactFHSCommittee resolves a committee only from an exact key-block
// commitment. The normal path uses the key chain. During an epoch handoff a
// lagging replica may have installed the certified key carrier while the QC
// for its direct child was dropped by transport backpressure. In that gap the
// first new-epoch manifest carries the missing child QC. Once that old-epoch
// QC is verified against the locally certified carrier, it is a complete
// two-chain activation proof for authenticating the new committee.
//
// The generic path below accepts either an installed child certificate or an
// activation proof retained in an already authenticated proposal manifest.
// The initial manifest is handled by resolveExactFHSCommitteeWithActivation.
// Merely receiving/validating a carrier, or finding an arbitrary committee DB
// entry, remains insufficient.
func (s *Service) resolveExactFHSCommittee(keyHash common.Hash, needIP bool) (*types.KeyBlock, *bftview.Committee, bool, error) {
	return s.resolveExactFHSCommitteeWithActivation(keyHash, needIP, nil)
}

func (s *Service) resolveExactFHSCommitteeWithActivation(keyHash common.Hash, needIP bool, activationQC []byte, finalityProof ...[]byte) (*types.KeyBlock, *bftview.Committee, bool, error) {
	if s == nil || s.kbc == nil || keyHash == (common.Hash{}) {
		return nil, nil, false, fmt.Errorf("missing FHS committee generation")
	}
	if keyBlock := s.kbc.GetBlockByHash(keyHash); keyBlock != nil {
		canonical := s.kbc.GetBlockByNumber(keyBlock.NumberU64())
		if canonical != nil && canonical.Hash() == keyHash {
			committee := bftview.LoadMember(keyBlock.NumberU64(), keyHash, needIP)
			if committee == nil || len(committee.List) == 0 {
				return nil, nil, false, fmt.Errorf("committee unavailable for key block %s", keyHash)
			}
			if committee.RlpHash() != keyBlock.CommitteeHash() {
				return nil, nil, false, fmt.Errorf("committee commitment mismatch for key block %s", keyHash)
			}
			return keyBlock, committee, false, nil
		}
	}

	keyBlock, err := s.certifiedUncommittedFHSKeyBlock(keyHash, activationQC, finalityProof...)
	if err != nil {
		return nil, nil, false, err
	}
	committee := bftview.LoadMember(keyBlock.NumberU64(), keyHash, needIP)
	if committee == nil || len(committee.List) == 0 {
		return nil, nil, false, fmt.Errorf("certified uncommitted committee unavailable for key block %s", keyHash)
	}
	if committee.RlpHash() != keyBlock.CommitteeHash() {
		return nil, nil, false, fmt.Errorf("certified uncommitted committee commitment mismatch for key block %s", keyHash)
	}
	return keyBlock, committee, true, nil
}

type certifiedFHSKeyCarrier struct {
	keyBlock *types.KeyBlock
	ref      *types.HotstuffProposalRef
	qc       *hotstuff.SignedState
}

func (s *Service) certifiedUncommittedFHSKeyBlock(keyHash common.Hash, encodedActivationQC []byte, encodedFinalityProof ...[]byte) (*types.KeyBlock, error) {
	if s == nil || keyHash == (common.Hash{}) {
		return nil, fmt.Errorf("invalid certified FHS key generation")
	}
	s.muProposalBody.RLock()
	var (
		carriers         []*certifiedFHSKeyCarrier
		activationProofs [][]byte
		finalityProofs   [][]byte
	)
	// A block may have certificates in multiple views. Keep each exact QC
	// candidate: the activation proof binds ParentQCID, not just BlockHash.
	for _, record := range s.fhsCertifiedByID {
		if record == nil || record.verified == nil || record.verified.Block == nil || record.verified.Block.BlockType() != types.Key_Block {
			continue
		}
		candidate := types.DecodeToKeyBlock(record.verified.Block.KeyInfo())
		if candidate == nil || candidate.Hash() != keyHash {
			continue
		}
		artifact := &fhsHighQCValidationItem{ref: record.ref, qc: record.qc, verified: record.verified}
		if err := validateStagedFHSCertificateArtifact(artifact); err != nil {
			s.muProposalBody.RUnlock()
			return nil, fmt.Errorf("invalid certified key carrier for %s: %w", keyHash, err)
		}
		if record.verified.Block.KeyHash() != candidate.ParentHash() ||
			record.verified.Block.NumberU64() == 0 || candidate.T_Number() != record.verified.Block.NumberU64()-1 {
			s.muProposalBody.RUnlock()
			return nil, fmt.Errorf("certified key carrier commitment mismatch for %s", keyHash)
		}
		refCopy := *record.ref
		carriers = append(carriers, &certifiedFHSKeyCarrier{
			keyBlock: candidate, ref: &refCopy, qc: hotstuff.CloneSignedState(record.qc),
		})
	}
	if len(carriers) == 0 {
		s.muProposalBody.RUnlock()
		return nil, fmt.Errorf("committee %s is unavailable from the key chain and certified pipeline", keyHash)
	}
	for _, proof := range encodedFinalityProof {
		if len(proof) > 0 {
			finalityProofs = append(finalityProofs, append([]byte(nil), proof...))
		}
	}
	if len(encodedActivationQC) > 0 {
		activationProofs = append(activationProofs, append([]byte(nil), encodedActivationQC...))
	}
	for _, child := range s.fhsCertifiedByID {
		if child == nil || child.ref == nil || child.qc == nil {
			continue
		}
		encoded, err := hotstuff.EncodeSignedState(child.qc)
		if err == nil {
			activationProofs = append(activationProofs, encoded)
		}
	}
	// Only authenticated manifests reach proposalBodies. Retaining the proof
	// bridges manifest -> Prepare ordering without publishing certificates or
	// unverified application state on behalf of the incoming manifest.
	if len(encodedActivationQC) == 0 {
		for _, record := range s.fhsCertifiedByID {
			if record == nil {
				continue
			}
			if body := record.envelope; body != nil && body.ProposalKeyHash == keyHash && len(body.ParentQC) > 0 {
				activationProofs = append(activationProofs, append([]byte(nil), body.ParentQC...))
				if len(body.KeyActivationProof) > 0 {
					finalityProofs = append(finalityProofs, append([]byte(nil), body.KeyActivationProof...))
				}
			}
		}
		for _, body := range s.proposalBodies {
			if body != nil && body.ProposalKeyHash == keyHash && len(body.ParentQC) > 0 {
				activationProofs = append(activationProofs, append([]byte(nil), body.ParentQC...))
				if len(body.KeyActivationProof) > 0 {
					finalityProofs = append(finalityProofs, append([]byte(nil), body.KeyActivationProof...))
				}
			}
		}
	}
	s.muProposalBody.RUnlock()

	for _, carrier := range carriers {
		verifiedCarrierRef, err := s.verifyFHSQCCryptographic(carrier.qc)
		if err != nil || verifiedCarrierRef == nil || verifiedCarrierRef.ProposalID() != carrier.ref.ProposalID() {
			continue
		}
		for _, encoded := range finalityProofs {
			if _, err := s.verifyFHSKeyActivationFinality(carrier, encoded); err == nil {
				return carrier.keyBlock, nil
			}
		}
		for _, encoded := range activationProofs {
			activationQC, err := hotstuff.DecodeSignedState(encoded)
			if err != nil || activationQC == nil {
				continue
			}
			// Check epoch before signature resolution to avoid recursively
			// trying to activate this same unknown signer generation.
			ref, err := types.DecodeHotstuffProposalRef(activationQC.State)
			if err != nil || ref.KeyHash != carrier.keyBlock.ParentHash() {
				continue
			}
			if _, err := s.verifyCertifiedFHSKeyActivation(carrier, activationQC); err == nil {
				return carrier.keyBlock, nil
			}
		}
	}
	return nil, fmt.Errorf("certified key block %s has no verified consecutive-view activation proof", keyHash)
}

func (s *Service) verifyCertifiedFHSKeyActivation(carrier *certifiedFHSKeyCarrier, activationQC *hotstuff.SignedState) (*types.HotstuffProposalRef, error) {
	if carrier == nil || carrier.keyBlock == nil || carrier.ref == nil || carrier.qc == nil || activationQC == nil {
		return nil, fmt.Errorf("incomplete certified key activation proof")
	}
	activationRef, err := s.verifyFHSQCCryptographic(activationQC)
	if err != nil {
		return nil, fmt.Errorf("verify certified key activation QC: %w", err)
	}
	carrierQCID, err := hotstuff.SignedStateID(carrier.qc)
	if err != nil {
		return nil, fmt.Errorf("derive certified key carrier QC id: %w", err)
	}
	if activationRef.ParentHash != carrier.ref.BlockHash || activationRef.Number != carrier.ref.Number+1 ||
		activationRef.ViewNumber <= carrier.ref.ViewNumber || activationRef.ViewNumber-carrier.ref.ViewNumber != 1 || activationRef.KeyHash != carrier.keyBlock.ParentHash() ||
		activationRef.ParentQCID != carrierQCID.Hash() {
		return nil, fmt.Errorf("certified key activation QC is not the carrier's direct old-epoch child")
	}
	return activationRef, nil
}
