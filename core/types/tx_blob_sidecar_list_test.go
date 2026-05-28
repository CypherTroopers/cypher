package types

import (
	"errors"
	"testing"

	"github.com/cypherium/cypher/common"
)

type listMockBlobVerifier struct {
	calls int
	err   error
}

func (v *listMockBlobVerifier) VerifyBlob(blob Blob, commitment KZGCommitment, proof KZGProof) error {
	v.calls++
	return v.err
}

func TestVerifyBlobSidecarsRequiresVerifier(t *testing.T) {
	if err := VerifyBlobSidecars(nil, nil); !errors.Is(err, ErrBlobVerifierMissing) {
		t.Fatalf("expected missing verifier, got %v", err)
	}
}

func TestVerifyBlobSidecarsIgnoresNonBlobTransactions(t *testing.T) {
	verifier := &listMockBlobVerifier{}
	txs := Transactions{NewTransaction(0, common.Address{}, nil, 21000, nil, nil)}
	if err := VerifyBlobSidecars(txs, verifier); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verifier.calls != 0 {
		t.Fatalf("verifier calls = %d, want 0", verifier.calls)
	}
}

func TestVerifyBlobSidecarsVerifiesAttachedSidecars(t *testing.T) {
	commitment := testKZGCommitment(1)
	hash := KZGToVersionedHash(commitment)
	tx := testBlobTxWithHash(hash).WithBlobSidecar(&BlobTxSidecar{
		Blobs:       []Blob{Blob{1, 2, 3}},
		Commitments: []KZGCommitment{commitment},
		Proofs:      []KZGProof{{}},
	})
	verifier := &listMockBlobVerifier{}
	if err := VerifyBlobSidecars(Transactions{tx}, verifier); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verifier.calls != 1 {
		t.Fatalf("verifier calls = %d, want 1", verifier.calls)
	}
}

func TestVerifyBlobSidecarsRejectsMissingSidecar(t *testing.T) {
	commitment := testKZGCommitment(1)
	hash := KZGToVersionedHash(commitment)
	tx := testBlobTxWithHash(hash)
	verifier := &listMockBlobVerifier{}
	if err := VerifyBlobSidecars(Transactions{tx}, verifier); !errors.Is(err, ErrBlobSidecarMissing) {
		t.Fatalf("expected missing sidecar, got %v", err)
	}
}

func TestVerifyBlobSidecarsPropagatesVerifierError(t *testing.T) {
	commitment := testKZGCommitment(1)
	hash := KZGToVersionedHash(commitment)
	tx := testBlobTxWithHash(hash).WithBlobSidecar(&BlobTxSidecar{
		Blobs:       []Blob{Blob{1, 2, 3}},
		Commitments: []KZGCommitment{commitment},
		Proofs:      []KZGProof{{}},
	})
	wantErr := errors.New("mock verifier error")
	verifier := &listMockBlobVerifier{err: wantErr}
	if err := VerifyBlobSidecars(Transactions{tx}, verifier); !errors.Is(err, wantErr) {
		t.Fatalf("expected verifier error, got %v", err)
	}
}
