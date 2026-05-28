package types

import (
	"errors"
	"testing"

	"github.com/cypherium/cypher/common"

	kzg "github.com/cypherium/cypher/crypto/kzg4844"
)

func buildValidBlobTuple(t *testing.T) (Blob, KZGCommitment, KZGProof) {
	t.Helper()
	var kb kzg.Blob
	for offset, scalar := 0, byte(1); offset < len(kb); offset, scalar = offset+32, scalar+1 {
		// EIP-4844 blobs are encoded as 4096 BLS12-381 scalar field elements.
		// Keep each 32-byte big-endian value small so it is always canonical.
		kb[offset+31] = scalar
		if scalar == 250 {
			scalar = 0
		}
	}
	kc, err := kzg.BlobToCommitment(&kb)
	if err != nil {
		t.Fatalf("BlobToCommitment failed: %v", err)
	}
	kp, err := kzg.ComputeBlobProof(&kb, kc)
	if err != nil {
		t.Fatalf("ComputeBlobProof failed: %v", err)
	}
	blob := make(Blob, len(kb))
	copy(blob, kb[:])
	var commitment KZGCommitment
	copy(commitment[:], kc[:])
	var proof KZGProof
	copy(proof[:], kp[:])
	return blob, commitment, proof
}

func TestKZGBlobVerifierVerifyBlob(t *testing.T) {
	blob, commitment, proof := buildValidBlobTuple(t)
	if err := (KZGBlobVerifier{}).VerifyBlob(blob, commitment, proof); err != nil {
		t.Fatalf("expected valid proof, got %v", err)
	}
}

func TestKZGBlobVerifierRejectsBadBlobLength(t *testing.T) {
	blob, commitment, proof := buildValidBlobTuple(t)
	if err := (KZGBlobVerifier{}).VerifyBlob(blob[:len(blob)-1], commitment, proof); err == nil {
		t.Fatalf("expected blob length error")
	}
}

func TestKZGBlobVerifierRejectsInvalidProof(t *testing.T) {
	blob, commitment, proof := buildValidBlobTuple(t)
	proof[0] ^= 0xff
	if err := (KZGBlobVerifier{}).VerifyBlob(blob, commitment, proof); err == nil {
		t.Fatalf("expected invalid proof")
	}
}

func TestVerifyBlobSidecarUsesRealVerifier(t *testing.T) {
	blob, commitment, proof := buildValidBlobTuple(t)
	tx := testVerifyBlobTx(KZGToVersionedHash(commitment))
	sidecar := &BlobTxSidecar{Blobs: []Blob{blob}, Commitments: []KZGCommitment{commitment}, Proofs: []KZGProof{proof}}
	if err := tx.VerifyBlobSidecar(sidecar, KZGBlobVerifier{}); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	badTx := testVerifyBlobTx(common.Hash{})
	if err := badTx.VerifyBlobSidecar(sidecar, KZGBlobVerifier{}); !errors.Is(err, ErrBlobVersionedHashMismatch) {
		t.Fatalf("expected versioned hash mismatch, got %v", err)
	}
}

func TestVerifyBlobSidecarsUsesRealVerifier(t *testing.T) {
	blob, commitment, proof := buildValidBlobTuple(t)
	tx := testVerifyBlobTx(KZGToVersionedHash(commitment)).WithBlobSidecar(&BlobTxSidecar{
		Blobs:       []Blob{blob},
		Commitments: []KZGCommitment{commitment},
		Proofs:      []KZGProof{proof},
	})
	if err := VerifyBlobSidecars(Transactions{tx}, KZGBlobVerifier{}); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestVerifyBlobSidecarRejectsInvalidProofWithRealVerifier(t *testing.T) {
	blob, commitment, proof := buildValidBlobTuple(t)
	proof[0] ^= 0xff
	tx := testVerifyBlobTx(KZGToVersionedHash(commitment))
	sidecar := &BlobTxSidecar{Blobs: []Blob{blob}, Commitments: []KZGCommitment{commitment}, Proofs: []KZGProof{proof}}
	if err := tx.VerifyBlobSidecar(sidecar, KZGBlobVerifier{}); err == nil {
		t.Fatalf("expected invalid proof error")
	}
}

func TestVerifyBlobSidecarsRejectsMissingSidecarWithRealVerifier(t *testing.T) {
	_, commitment, _ := buildValidBlobTuple(t)
	tx := testVerifyBlobTx(KZGToVersionedHash(commitment))
	if err := VerifyBlobSidecars(Transactions{tx}, KZGBlobVerifier{}); !errors.Is(err, ErrBlobSidecarMissing) {
		t.Fatalf("expected missing sidecar error, got %v", err)
	}
}
