package reconfig

import (
	"fmt"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
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
