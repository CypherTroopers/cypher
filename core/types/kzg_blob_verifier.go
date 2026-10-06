package types

import (
	"fmt"

	kzg "github.com/cypherium/cypher/crypto/kzg4844"
)

// KZGBlobVerifier verifies blob commitments/proofs using the real KZG backend.
type KZGBlobVerifier struct{}

func (KZGBlobVerifier) VerifyBlob(blob Blob, commitment KZGCommitment, proof KZGProof) error {
	if len(blob) != len(kzg.Blob{}) {
		return fmt.Errorf("invalid blob length %d", len(blob))
	}
	if len(commitment) != len(kzg.Commitment{}) {
		return fmt.Errorf("invalid commitment length %d", len(commitment))
	}
	if len(proof) != len(kzg.Proof{}) {
		return fmt.Errorf("invalid proof length %d", len(proof))
	}

	var kb kzg.Blob
	copy(kb[:], blob)

	var kc kzg.Commitment
	copy(kc[:], commitment[:])

	var kp kzg.Proof
	copy(kp[:], proof[:])

	return kzg.VerifyBlobProof(&kb, kc, kp)
}

func (KZGBlobVerifier) VerifyCellProofs(blobs []Blob, commitments []KZGCommitment, proofs []KZGProof) error {
	if len(blobs) != len(commitments) || len(proofs) != len(blobs)*kzg.CellProofsPerBlob {
		return ErrBlobSidecarLengthMismatch
	}
	kzgBlobs := make([]kzg.Blob, len(blobs))
	for i, blob := range blobs {
		if len(blob) != len(kzg.Blob{}) {
			return fmt.Errorf("invalid blob length %d", len(blob))
		}
		copy(kzgBlobs[i][:], blob)
	}
	kzgCommitments := make([]kzg.Commitment, len(commitments))
	for i, commitment := range commitments {
		kzgCommitments[i] = kzg.Commitment(commitment)
	}
	kzgProofs := make([]kzg.Proof, len(proofs))
	for i, proof := range proofs {
		kzgProofs[i] = kzg.Proof(proof)
	}
	return kzg.VerifyCellProofs(kzgBlobs, kzgCommitments, kzgProofs)
}
