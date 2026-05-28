package types

import (
	"errors"
	"testing"

	"github.com/cypherium/cypher/common"
)

func TestValidateBlobCommitmentHashes(t *testing.T) {
	commitment := testKZGCommitment(41)
	sidecar := &BlobTxSidecar{
		Blobs:       []Blob{Blob{1, 2, 3}},
		Commitments: []KZGCommitment{commitment},
		Proofs:      []KZGProof{{}},
	}
	if err := sidecar.ValidateBlobCommitmentHashes([]common.Hash{KZGToVersionedHash(commitment)}); err != nil {
		t.Fatalf("expected valid commitment hashes, got %v", err)
	}
	if err := sidecar.ValidateBlobCommitmentHashes([]common.Hash{common.Hash{}}); !errors.Is(err, ErrBlobVersionedHashMismatch) {
		t.Fatalf("expected versioned hash mismatch, got %v", err)
	}
}

func TestValidateBlobHashesAlias(t *testing.T) {
	commitment := testKZGCommitment(42)
	sidecar := &BlobTxSidecar{
		Blobs:       []Blob{Blob{1}},
		Commitments: []KZGCommitment{commitment},
		Proofs:      []KZGProof{{}},
	}
	if err := sidecar.ValidateBlobHashes([]common.Hash{KZGToVersionedHash(commitment)}); err != nil {
		t.Fatalf("expected alias validation to pass, got %v", err)
	}
}
