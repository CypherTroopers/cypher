package types

import (
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
)

func testBlobSidecarWrapper(commitment KZGCommitment) *BlobTxSidecar {
	return &BlobTxSidecar{
		Blobs:       []Blob{{1, 2, 3}},
		Commitments: []KZGCommitment{commitment},
		Proofs:      []KZGProof{{}},
	}
}

func TestNewBlobTxWithSidecar(t *testing.T) {
	commitment := testKZGCommitment(11)
	tx := testVerifyBlobTx(KZGToVersionedHash(commitment))
	sidecar := testBlobSidecarWrapper(commitment)
	wrapped, err := NewBlobTxWithSidecar(tx, sidecar)
	if err != nil {
		t.Fatalf("expected wrapper, got %v", err)
	}
	if wrapped.Tx == nil || wrapped.Sidecar == nil {
		t.Fatalf("wrapper did not include tx and sidecar")
	}
	if wrapped.Tx.Hash() != tx.Hash() {
		t.Fatalf("wrapper changed transaction hash")
	}
	if wrapped.Tx == tx {
		t.Fatalf("wrapper should attach sidecar to a transaction copy")
	}
	if wrapped.Sidecar != wrapped.Tx.BlobSidecar() {
		t.Fatalf("wrapper sidecar should match attached transaction sidecar")
	}
}

func TestNewBlobTxWithSidecarRejectsNonBlobTx(t *testing.T) {
	to := common.Address{1}
	tx := NewTransaction(0, to, big.NewInt(0), 21000, big.NewInt(1), nil)
	if _, err := NewBlobTxWithSidecar(tx, &BlobTxSidecar{}); !errors.Is(err, ErrBlobTxSidecarOnNonBlobTx) {
		t.Fatalf("expected non-blob tx error, got %v", err)
	}
}

func TestNewVerifiedBlobTxWithSidecar(t *testing.T) {
	commitment := testKZGCommitment(12)
	tx := testVerifyBlobTx(KZGToVersionedHash(commitment))
	sidecar := testBlobSidecarWrapper(commitment)
	verifier := &mockBlobVerifier{}
	if _, err := NewVerifiedBlobTxWithSidecar(tx, sidecar, verifier); err != nil {
		t.Fatalf("expected verified wrapper, got %v", err)
	}
	if verifier.calls != 1 {
		t.Fatalf("verifier calls = %d, want 1", verifier.calls)
	}
}
