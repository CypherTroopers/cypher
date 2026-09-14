package types

import (
	"testing"
)

func TestBlobTxWithBlobSidecarDoesNotChangeHash(t *testing.T) {
	commitment := testKZGCommitment(21)
	tx := testVerifyBlobTx(KZGToVersionedHash(commitment))
	before := tx.Hash()
	sidecar := &BlobTxSidecar{
		Blobs:       []Blob{{1, 2, 3}},
		Commitments: []KZGCommitment{commitment},
		Proofs:      []KZGProof{{}},
	}
	withSidecar := tx.WithBlobSidecar(sidecar)
	if withSidecar.Hash() != before {
		t.Fatalf("sidecar changed transaction hash: before %s after %s", before, withSidecar.Hash())
	}
	if withSidecar.BlobSidecar() == nil {
		t.Fatalf("expected attached sidecar")
	}
}

func TestBlobTxSidecarCopyIsDeep(t *testing.T) {
	commitment := testKZGCommitment(22)
	sidecar := &BlobTxSidecar{
		Blobs:       []Blob{{1, 2, 3}},
		Commitments: []KZGCommitment{commitment},
		Proofs:      []KZGProof{{}},
	}
	copy := sidecar.Copy()
	if copy == sidecar {
		t.Fatalf("expected distinct sidecar copy")
	}
	copy.Blobs[0][0] = 9
	if sidecar.Blobs[0][0] == 9 {
		t.Fatalf("blob copy is not deep")
	}
	copy.Commitments[0][47] = 99
	if sidecar.Commitments[0][47] == 99 {
		t.Fatalf("commitment copy is not independent")
	}
}
