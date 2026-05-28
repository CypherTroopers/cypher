package types

import (
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
)

type mockBlobVerifier struct {
	calls int
	err   error
}

func (v *mockBlobVerifier) VerifyBlob(blob Blob, commitment KZGCommitment, proof KZGProof) error {
	v.calls++
	return v.err
}

func testVerifyBlobTx(hash common.Hash) *Transaction {
	return &Transaction{data: &BlobTx{
		ChainID:    big.NewInt(12367),
		GasTipCap:  big.NewInt(1),
		GasFeeCap:  big.NewInt(10),
		Gas:        21000,
		BlobFeeCap: big.NewInt(1),
		BlobHashes: []common.Hash{hash},
		V:          big.NewInt(0),
		R:          big.NewInt(1),
		S:          big.NewInt(1),
	}}
}

func TestVerifyBlobSidecarCallsVerifier(t *testing.T) {
	commitment := testKZGCommitment(7)
	sidecar := &BlobTxSidecar{
		Blobs:       []Blob{Blob{1, 2, 3}},
		Commitments: []KZGCommitment{commitment},
		Proofs:      []KZGProof{{}},
	}
	tx := testVerifyBlobTx(KZGToVersionedHash(commitment))
	verifier := &mockBlobVerifier{}
	if err := tx.VerifyBlobSidecar(sidecar, verifier); err != nil {
		t.Fatalf("expected valid sidecar verification, got %v", err)
	}
	if verifier.calls != 1 {
		t.Fatalf("verifier calls = %d, want 1", verifier.calls)
	}
}

func TestVerifyBlobSidecarRejectsBadHashBeforeVerifier(t *testing.T) {
	commitment := testKZGCommitment(8)
	sidecar := &BlobTxSidecar{
		Blobs:       []Blob{Blob{1}},
		Commitments: []KZGCommitment{commitment},
		Proofs:      []KZGProof{{}},
	}
	verifier := &mockBlobVerifier{}
	tx := testVerifyBlobTx(common.Hash{})
	if err := tx.VerifyBlobSidecar(sidecar, verifier); !errors.Is(err, ErrBlobVersionedHashMismatch) {
		t.Fatalf("expected versioned hash mismatch, got %v", err)
	}
	if verifier.calls != 0 {
		t.Fatalf("verifier should not be called after hash mismatch, got %d", verifier.calls)
	}
}

func TestVerifyBlobSidecarPropagatesVerifierError(t *testing.T) {
	commitment := testKZGCommitment(9)
	sidecar := &BlobTxSidecar{
		Blobs:       []Blob{Blob{1}},
		Commitments: []KZGCommitment{commitment},
		Proofs:      []KZGProof{{}},
	}
	wantErr := errors.New("mock verifier error")
	verifier := &mockBlobVerifier{err: wantErr}
	tx := testVerifyBlobTx(KZGToVersionedHash(commitment))
	if err := tx.VerifyBlobSidecar(sidecar, verifier); !errors.Is(err, wantErr) {
		t.Fatalf("expected verifier error, got %v", err)
	}
}
