// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"fmt"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/trie"
)

// BlockValidator is responsible for validating block headers, uncles and
// processed state.
//
// BlockValidator implements Validator.
type BlockValidator struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for validating
}

// NewBlockValidator returns a new block validator which is safe for re-use
func NewBlockValidator(config *params.ChainConfig, blockchain *BlockChain, engine consensus.Engine) *BlockValidator {
	validator := &BlockValidator{
		config: config,
		engine: engine,
		bc:     blockchain,
	}
	return validator
}

// ValidateBody validates the given block's uncles and verifies the block
// header's transaction and uncle roots. The headers are assumed to be already
// validated at this point.
func (v *BlockValidator) ValidateBody(block *types.Block) error {
	return v.validateBody(block, false, false)
}

// ValidateBodyWithHotstuffParent validates a proposal whose parent is a
// certified, locally executed HotStuff block that has not been committed yet.
func (v *BlockValidator) ValidateBodyWithHotstuffParent(block *types.Block) error {
	return v.validateBody(block, true, false)
}

// ValidateBodyForHotstuffSync revalidates a downloaded FHS block even when a
// crash left the same hash and state root in the database before the canonical
// head marker was advanced. A raw block is not a 2-chain finality proof.
func (v *BlockValidator) ValidateBodyForHotstuffSync(block *types.Block, hotstuffParentAvailable bool) error {
	return v.validateBody(block, hotstuffParentAvailable, true)
}

func (v *BlockValidator) validateBody(block *types.Block, hotstuffParentAvailable, revalidateKnown bool) error {
	// Check whether the block's known, and if not, that it's linkable
	if !revalidateKnown && v.bc.HasBlockAndState(block.Hash(), block.NumberU64()) {
		return ErrKnownBlock
	}
	// Header validity is known at this point, check the uncles and transactions
	header := block.Header()

	// Fixed-fee policy:
	// All London-active tx blocks must carry the canonical fixed baseFeePerGas.
	// This prevents validators from accepting blocks whose actual effectiveGasPrice
	// would differ from the public RPC policy:
	//   baseFeePerGas          = 0.8 gwei
	//   maxPriorityFeePerGas   = 0.2 gwei
	//   effectiveGasPrice      = 1.0 gwei for normal type-2 transfers
	if v.config != nil && v.config.IsLondon(header.Number) {
		wantBaseFee := big.NewInt(params.FixedBaseFeePerGas)
		if header.BaseFee == nil || header.BaseFee.Cmp(wantBaseFee) != 0 {
			return fmt.Errorf("invalid fixed baseFeePerGas: have %v want %v", header.BaseFee, wantBaseFee)
		}
	}

	/*??
	if err := v.engine.VerifyUncles(v.bc, block); err != nil {
		return err
	}
	if hash := types.CalcUncleHash(block.Uncles()); hash != header.UncleHash {
		return fmt.Errorf("uncle root hash mismatch: have %x, want %x", hash, header.UncleHash)
	}
	*/
	if hash := types.DeriveSha(block.Transactions(), new(trie.Trie)); hash != header.TxHash {
		return fmt.Errorf("transaction root hash mismatch: have %x, want %x", hash, header.TxHash)
	}
	if hash := types.DeriveCommonTxAdmissionRoot(block.CommonTxAdmissions()); hash != header.CommonTxAdmissionRoot {
		return fmt.Errorf("common tx admission root mismatch: have %x, want %x", hash, header.CommonTxAdmissionRoot)
	}
	if hash := types.DeriveCommonTxRewardRoot(block.CommonTxRewards()); hash != header.CommonTxRewardRoot {
		return fmt.Errorf("common tx reward root mismatch: have %x, want %x", hash, header.CommonTxRewardRoot)
	}
	if err := ValidateBlockBlobBody(v.config, header, block.Transactions()); err != nil {
		return err
	}
	if !hotstuffParentAvailable && !v.bc.HasBlockAndState(block.ParentHash(), block.NumberU64()-1) {
		if !v.bc.HasBlock(block.ParentHash(), block.NumberU64()-1) {
			return consensus.ErrUnknownAncestor
		}
		return consensus.ErrPrunedAncestor
	}

	return nil
}

// ValidateState validates the various changes that happen after a state
// transition, such as amount of used gas, the receipt roots and the state root
// itself. ValidateState returns a database batch if the validation was a success
// otherwise nil and an error is returned.
//
// it also verifies if the canonical hash in the blocks state points to a valid parent hash.
func (v *BlockValidator) ValidateState(block *types.Block, statedb *state.StateDB, receipts types.Receipts, usedGas uint64) error {
	header := block.Header()
	if block.GasUsed() != usedGas {
		return fmt.Errorf("invalid gas used (remote: %d local: %d)", block.GasUsed(), usedGas)
	}
	// Validate the received block's bloom with the one derived from the generated receipts.
	// For valid blocks this should always validate to true.
	rbloom := types.CreateBloom(receipts)
	if rbloom != header.Bloom {
		return fmt.Errorf("invalid bloom (remote: %x  local: %x)", header.Bloom, rbloom)
	}
	// Tre receipt Trie's root (R = (Tr [[H1, R1], ... [Hn, R1]]))
	receiptSha := types.DeriveSha(receipts, new(trie.Trie))
	if receiptSha != header.ReceiptHash {
		return fmt.Errorf("invalid receipt root hash (remote: %x local: %x)", header.ReceiptHash, receiptSha)
	}
	// Validate the state root against the received state root and throw
	// an error if they don't match.
	if root := statedb.IntermediateRoot(v.config.IsEIP158(header.Number)); header.Root != root {
		return fmt.Errorf("invalid merkle root (remote: %x local: %x)", header.Root, root)
	}
	return nil
}

// CalcGasLimit computes the gas limit of the next block after parent. It aims
// to keep the baseline gas above the provided floor, and increase it towards the
// ceil if the blocks are full. If the ceil is exceeded, it will always decrease
// the gas allowance.
func CalcGasLimit(parent *types.Block, gasFloor, gasCeil uint64) uint64 {
	// contrib = (parentGasUsed * 3 / 2) / 1024
	contrib := (parent.GasUsed() + parent.GasUsed()/2) / params.GasLimitBoundDivisor

	// decay = parentGasLimit / 1024 -1
	decay := parent.GasLimit()/params.GasLimitBoundDivisor - 1

	/*
		strategy: gasLimit of block-to-mine is set based on parent's
		gasUsed value.  if parentGasUsed > parentGasLimit * (2/3) then we
		increase it, otherwise lower it (or leave it unchanged if it's right
		at that usage) the amount increased/decreased depends on how far away
		from parentGasLimit * (2/3) parentGasUsed is.
	*/
	limit := parent.GasLimit() - decay + contrib
	if limit < params.MinGasLimit {
		limit = params.MinGasLimit
	}
	// If we're outside our allowed gas range, we try to hone towards them
	if limit < gasFloor {
		limit = parent.GasLimit() + decay
		if limit > gasFloor {
			limit = gasFloor
		}
	} else if limit > gasCeil {
		limit = parent.GasLimit() - decay
		if limit < gasCeil {
			limit = gasCeil
		}
	}
	return limit
}

func (v *BlockValidator) VerifySignature(block *types.Block) error {
	// HotStuff proposal-reference signature verification.
	//
	// Validators now sign the compact HotstuffProposalRef carried in
	// MsgPrepare.DataB, not the full block RLP.
	//
	// Full block RLP is a sidecar body referenced by BodyHash. Therefore normal
	// downloader/import validation must reconstruct the exact ProposalRef from
	// the downloaded unsigned block and verify the aggregated VotePrepare
	// signature against those ProposalRef bytes.
	//
	// Important:
	//   - BodyHash is computed from the unsigned block encoding.
	//   - block.Hash() / header.Hash() already ignores SignInfo.
	//   - CopyOrg() clears SignInfo and gives the same unsigned body that was
	//     used when the leader created the original ProposalRef.
	mycommittee := &bftview.Committee{List: v.bc.keyBlockChain.GetCommitteeByHash(block.KeyHash())}
	if mycommittee == nil || len(mycommittee.List) < 2 {
		return types.ErrInvalidCommittee
	}
	pubs := mycommittee.ToBlsPublicKeys(block.KeyHash())

	si := block.SignInfo()
	if si == nil {
		return types.ErrEmptySignature
	}
	if si.ViewID == (common.Hash{}) || si.LeaderID == "" {
		return types.ErrInvalidSignature
	}

	unsignedBlock := block.CopyOrg()
	encodedUnsignedBlock := unsignedBlock.EncodeToBytes()
	if encodedUnsignedBlock == nil {
		return types.ErrEncodeRLP
	}

	threshold := hotstuff.CalcThreshold(len(pubs))
	chainID := uint64(0)
	if v.config != nil && v.config.ChainID != nil {
		chainID = v.config.ChainID.Uint64()
	}

	var proposalRef *types.HotstuffProposalRef
	var err error
	if v.config != nil && v.config.FairHotstuff {
		proposalRef, err = types.NewHotstuffProposalRefWithCommitments(chainID, si.ViewNumber, si.ViewID, si.LeaderID, unsignedBlock, encodedUnsignedBlock, si.ExtraHash, si.ParentQCID)
	} else {
		proposalRef, err = types.NewHotstuffProposalRef(chainID, si.ViewNumber, si.ViewID, si.LeaderID, unsignedBlock, encodedUnsignedBlock)
	}
	if err != nil {
		return types.ErrInvalidSignature
	}
	proposalBytes := proposalRef.EncodeToBytes()
	if len(proposalBytes) == 0 {
		return types.ErrEncodeRLP
	}

	var validSignature bool
	if v.config != nil && v.config.FairHotstuff {
		validSignature = hotstuff.VerifyFHSSignatureWithContext(si.Signature, si.Exceptions, proposalBytes, pubs, threshold, chainID, hotstuff.MsgVotePrepare, si.ViewID, si.LeaderID)
	} else {
		validSignature = hotstuff.VerifySignatureWithContext(si.Signature, si.Exceptions, proposalBytes, pubs, threshold, chainID, hotstuff.MsgVotePrepare, si.ViewID, si.LeaderID)
	}
	if !validSignature {
		return types.ErrInvalidSignature
	}
	return nil
}

// ReconstructFHSQC verifies a block's own FHS signature and reconstructs the
// exact semantic QC committed in SignInfo. Header.Hash deliberately excludes
// SignInfo, so callers must use this verified representation rather than a
// same-hash block received from an untrusted peer.
func (v *BlockValidator) ReconstructFHSQC(block *types.Block) (*types.HotstuffProposalRef, *hotstuff.SignedState, error) {
	if block == nil || v.config == nil || !v.config.FairHotstuff {
		return nil, nil, types.ErrInvalidSignature
	}
	if err := v.VerifySignature(block); err != nil {
		return nil, nil, err
	}
	si := block.SignInfo()
	unsigned := block.CopyOrg()
	encoded := unsigned.EncodeToBytes()
	chainID := uint64(0)
	if v.config.ChainID != nil {
		chainID = v.config.ChainID.Uint64()
	}
	ref, err := types.NewHotstuffProposalRefWithCommitments(chainID, si.ViewNumber, si.ViewID, si.LeaderID, unsigned, encoded, si.ExtraHash, si.ParentQCID)
	if err != nil {
		return nil, nil, err
	}
	qc := &hotstuff.SignedState{
		State:    ref.EncodeToBytes(),
		Sign:     append([]byte(nil), si.Signature...),
		Mask:     append([]byte(nil), si.Exceptions...),
		ViewID:   si.ViewID,
		LeaderID: si.LeaderID,
		Number:   si.ViewNumber,
	}
	return ref, qc, nil
}

// VerifyFHS2ChainCommitProof verifies that childQC certifies the direct child
// of target and therefore finalizes target under the Fast-HotStuff 2-chain
// rule. Generic block sync must never advance the FHS canonical head from the
// target's own one-chain QC alone.
func (v *BlockValidator) VerifyFHS2ChainCommitProof(target *types.Block, childQC *hotstuff.SignedState) error {
	if target == nil || childQC == nil || v.config == nil || !v.config.FairHotstuff {
		return fmt.Errorf("incomplete Fair HotStuff 2-chain commit proof")
	}
	targetRef, targetQC, err := v.ReconstructFHSQC(target)
	if err != nil {
		return fmt.Errorf("invalid target FHS QC: %w", err)
	}
	childRef, err := types.DecodeHotstuffProposalRef(childQC.State)
	if err != nil {
		return fmt.Errorf("invalid child FHS proposal reference: %w", err)
	}
	chainID := uint64(0)
	if v.config.ChainID != nil {
		chainID = v.config.ChainID.Uint64()
	}
	if childRef.ChainID != chainID || childQC.Number != childRef.ViewNumber || childQC.ViewID != childRef.ViewID || childQC.LeaderID != childRef.LeaderID {
		return fmt.Errorf("child FHS QC context mismatch")
	}
	if childRef.ParentHash != target.Hash() || childRef.Number != target.NumberU64()+1 || childRef.ViewNumber <= targetRef.ViewNumber {
		return fmt.Errorf("child FHS QC does not directly extend target")
	}
	targetID, err := hotstuff.SignedStateID(targetQC)
	if err != nil {
		return fmt.Errorf("invalid target FHS QC identity: %w", err)
	}
	if childRef.ParentQCID != targetID.Hash() {
		return fmt.Errorf("child FHS QC does not bind the target QC")
	}

	committee := &bftview.Committee{List: v.bc.keyBlockChain.GetCommitteeByHash(childRef.KeyHash)}
	if committee == nil || len(committee.List) < 2 {
		return types.ErrInvalidCommittee
	}
	pubs := committee.ToBlsPublicKeys(childRef.KeyHash)
	threshold := hotstuff.CalcThreshold(len(pubs))
	if err := hotstuff.ValidateCanonicalSignerMask(childQC.Mask, len(pubs), threshold); err != nil {
		return fmt.Errorf("invalid child FHS signer mask: %w", err)
	}
	if !hotstuff.VerifyFHSSignatureWithContext(childQC.Sign, childQC.Mask, childQC.State, pubs, threshold, chainID, hotstuff.MsgVotePrepare, childQC.ViewID, childQC.LeaderID) {
		return fmt.Errorf("invalid child FHS QC signature")
	}

	latestKey := v.bc.keyBlockChain.CurrentBlock()
	if target.BlockType() == types.Key_Block {
		latestKey = types.DecodeToKeyBlock(target.KeyInfo())
	}
	if latestKey == nil {
		return fmt.Errorf("missing Fair HotStuff key activation state")
	}
	latestHash := latestKey.Hash()
	if childRef.KeyHash != target.KeyHash() && childRef.KeyHash != latestHash {
		return fmt.Errorf("child FHS QC uses an invalid signing key transition")
	}
	if childRef.KeyHash != latestHash && target.KeyHash() != latestHash &&
		(latestKey.T_Number() > ^uint64(0)-2 || childRef.Number > latestKey.T_Number()+2) {
		return fmt.Errorf("child FHS QC continues an expired signing key")
	}
	return nil
}
