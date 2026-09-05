package core

import (
	"errors"
	"fmt"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

const (
	fhsFinalityProofEnvelopeVersion = uint32(2)
	// Match the bounded certified ancestry retained by the consensus service.
	MaxFHSCommitProofQCs = 128
)

// FHSCommitProof contains the certified descendants of a target in ascending
// block order. The final edge must join consecutive views; earlier edges may
// skip views. One QC proves a direct 2-chain commit, while a longer path also
// proves finality of ancestors preceding the terminal pair.
type FHSCommitProof struct {
	QCs []*hotstuff.SignedState
}

func CloneFHSCommitProof(proof *FHSCommitProof) *FHSCommitProof {
	if proof == nil {
		return nil
	}
	copy := &FHSCommitProof{QCs: make([]*hotstuff.SignedState, len(proof.QCs))}
	for index, qc := range proof.QCs {
		copy.QCs[index] = hotstuff.CloneSignedState(qc)
	}
	return copy
}

func fhsCommitProofSemanticEqual(a, b *FHSCommitProof) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if len(a.QCs) != len(b.QCs) {
		return false
	}
	for index := range a.QCs {
		if !hotstuff.SignedStateSemanticEqual(a.QCs[index], b.QCs[index]) {
			return false
		}
	}
	return true
}

func (proof *FHSCommitProof) validateShape() error {
	if proof == nil || len(proof.QCs) == 0 || len(proof.QCs) > MaxFHSCommitProofQCs {
		return fmt.Errorf("Fair HotStuff finality proof requires 1..%d descendant QCs", MaxFHSCommitProofQCs)
	}
	for index, qc := range proof.QCs {
		if qc == nil {
			return fmt.Errorf("nil Fair HotStuff finality QC at index %d", index)
		}
	}
	return nil
}

func singleFHSCommitProof(childQC *hotstuff.SignedState) *FHSCommitProof {
	if childQC == nil {
		return nil
	}
	return &FHSCommitProof{QCs: []*hotstuff.SignedState{hotstuff.CloneSignedState(childQC)}}
}

type fhsFinalityProofEnvelope struct {
	Version uint32
	QCs     [][]byte
}

func EncodeFHSCommitProof(proof *FHSCommitProof) ([]byte, error) {
	if err := proof.validateShape(); err != nil {
		return nil, err
	}
	envelope := fhsFinalityProofEnvelope{Version: fhsFinalityProofEnvelopeVersion, QCs: make([][]byte, len(proof.QCs))}
	for index, qc := range proof.QCs {
		encoded, err := hotstuff.EncodeSignedState(qc)
		if err != nil {
			return nil, fmt.Errorf("encode Fair HotStuff finality QC %d: %w", index, err)
		}
		envelope.QCs[index] = encoded
	}
	encoded, err := rlp.EncodeToBytes(&envelope)
	if err != nil {
		return nil, fmt.Errorf("encode Fair HotStuff finality proof: %w", err)
	}
	if len(encoded) > types.MaxFHSFinalityProofSize {
		return nil, fmt.Errorf("invalid Fair HotStuff finality proof size %d", len(encoded))
	}
	return encoded, nil
}

func DecodeFHSCommitProof(block *types.Block) (*FHSCommitProof, bool, error) {
	if block == nil {
		return nil, false, errors.New("nil Fair HotStuff proof block")
	}
	encoded := block.FHSFinalityProof()
	if len(encoded) == 0 {
		return nil, false, nil
	}
	proof, err := DecodeFHSCommitProofBytes(encoded)
	return proof, true, err
}

func DecodeFHSCommitProofBytes(encoded []byte) (*FHSCommitProof, error) {
	if len(encoded) > types.MaxFHSFinalityProofSize {
		return nil, fmt.Errorf("Fair HotStuff finality proof exceeds %d bytes", types.MaxFHSFinalityProofSize)
	}
	var envelope fhsFinalityProofEnvelope
	if err := rlp.DecodeBytes(encoded, &envelope); err != nil {
		return nil, fmt.Errorf("decode Fair HotStuff finality proof: %w", err)
	}
	if envelope.Version != fhsFinalityProofEnvelopeVersion {
		return nil, fmt.Errorf("unsupported Fair HotStuff finality proof version %d", envelope.Version)
	}
	if len(envelope.QCs) == 0 || len(envelope.QCs) > MaxFHSCommitProofQCs {
		return nil, fmt.Errorf("invalid Fair HotStuff finality QC count %d", len(envelope.QCs))
	}
	proof := &FHSCommitProof{QCs: make([]*hotstuff.SignedState, len(envelope.QCs))}
	for index, encodedQC := range envelope.QCs {
		qc, err := hotstuff.DecodeSignedState(encodedQC)
		if err != nil || qc == nil {
			return nil, fmt.Errorf("invalid Fair HotStuff finality QC %d: %v", index, err)
		}
		proof.QCs[index] = qc
	}
	return proof, nil
}

// The single-child helpers remain for focused callers. They never truncate a
// descendant proof into a different, potentially non-finalizing certificate.
func encodeFHSFinalityProof(childQC *hotstuff.SignedState) ([]byte, error) {
	return EncodeFHSCommitProof(singleFHSCommitProof(childQC))
}

func decodeFHSFinalityProof(block *types.Block) (*hotstuff.SignedState, bool, error) {
	proof, present, err := DecodeFHSCommitProof(block)
	if err != nil || !present {
		return nil, present, err
	}
	if len(proof.QCs) != 1 {
		return nil, true, errors.New("Fair HotStuff ancestor proof requires the full-proof API")
	}
	return proof.QCs[0], true, nil
}

func verifyFHSCommitProofWithValidator(validator interface{}, target *types.Block, proof *FHSCommitProof) error {
	if target == nil {
		return errors.New("nil Fair HotStuff finality target")
	}
	if err := proof.validateShape(); err != nil {
		return err
	}
	if full, ok := validator.(interface {
		VerifyFHSCommitProof(*types.Block, *FHSCommitProof) error
	}); ok {
		return full.VerifyFHSCommitProof(target, CloneFHSCommitProof(proof))
	}
	// Preserve one-child validator seams without allowing an old validator to
	// bypass the terminal pair in a longer proof.
	if direct, ok := validator.(interface {
		VerifyFHS2ChainCommitProof(*types.Block, *hotstuff.SignedState) error
	}); ok && len(proof.QCs) == 1 {
		return direct.VerifyFHS2ChainCommitProof(target, hotstuff.CloneSignedState(proof.QCs[0]))
	}
	return errors.New("Fair HotStuff full finality proof validator is unavailable")
}

// fhsQCInKeyActivationProof recognizes only descendants that were already
// certified when the key carrier committed. It does not extend the lifetime of
// an old committee to newly created blocks after activation.
func (bc *BlockChain) fhsQCInKeyActivationProof(qc *hotstuff.SignedState, key *types.KeyBlock) bool {
	if bc == nil || bc.db == nil || qc == nil || key == nil || key.T_Number() == ^uint64(0) {
		return false
	}
	carrierNumber := key.T_Number() + 1
	carrierHash := rawdb.ReadCanonicalHash(bc.db, carrierNumber)
	carrier := rawdb.ReadBlock(bc.db, carrierHash, carrierNumber)
	if carrier == nil || carrier.BlockType() != types.Key_Block {
		return false
	}
	embedded := types.DecodeToKeyBlock(carrier.KeyInfo())
	if embedded == nil || embedded.Hash() != key.Hash() {
		return false
	}
	proof, present, err := DecodeFHSCommitProof(carrier)
	if err != nil || !present || bc.VerifyFHSCommitProof(carrier, proof) != nil {
		return false
	}
	for _, certified := range proof.QCs {
		if hotstuff.SignedStateSemanticEqual(certified, qc) {
			return true
		}
	}
	return false
}

func (bc *BlockChain) validateFHSKeyActivationWithProof(block *types.Block, parentSigningKey common.Hash, latestKey *types.KeyBlock) error {
	err := validateFHSKeyActivation(block, parentSigningKey, latestKey)
	if err == nil || block == nil || latestKey == nil || block.KeyHash() != parentSigningKey {
		return err
	}
	_, qc, proofErr := bc.ReconstructFHSQC(block)
	if proofErr == nil && bc.fhsQCInKeyActivationProof(qc, latestKey) {
		return nil
	}
	return err
}
