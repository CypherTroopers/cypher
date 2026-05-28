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
