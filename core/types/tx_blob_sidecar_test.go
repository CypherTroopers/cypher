package types

import (
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
)

func testKZGCommitment(n byte) KZGCommitment {
	var commitment KZGCommitment
	commitment[47] = n
	return commitment
}

func testBlobTxWithHash(hash common.Hash) *Transaction {
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

func TestKZGToVersionedHash(t *testing.T) {
	commitment := testKZGCommitment(1)
	hash := KZGToVersionedHash(commitment)
	if hash[0] != BlobCommitmentVersionKZG {
		t.Fatalf("version byte = %x, want %x", hash[0], BlobCommitmentVersionKZG)
	}
}

func TestValidateBlobSidecar(t *testing.T) {
	commitment := testKZGCommitment(1)
	hash := KZGToVersionedHash(commitment)
	tx := testBlobTxWithHash(hash)
	sidecar := &BlobTxSidecar{
		Blobs:       []Blob{{1, 2, 3}},
		Commitments: []KZGCommitment{commitment},
		Proofs:      []KZGProof{{}},
	}
	if err := tx.ValidateBlobSidecar(sidecar); err != nil {
		t.Fatalf("expected valid sidecar, got %v", err)
	}

	badTx := testBlobTxWithHash(common.Hash{})
	if err := badTx.ValidateBlobSidecar(sidecar); !errors.Is(err, ErrBlobVersionedHashMismatch) {
		t.Fatalf("expected versioned hash mismatch, got %v", err)
	}

	badSidecar := &BlobTxSidecar{Blobs: []Blob{{1}}, Commitments: nil, Proofs: []KZGProof{{}}}
	if err := tx.ValidateBlobSidecar(badSidecar); !errors.Is(err, ErrBlobSidecarLengthMismatch) {
		t.Fatalf("expected sidecar length mismatch, got %v", err)
	}
}
