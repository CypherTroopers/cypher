package types

import "testing"

func TestNewBlobTxWithSidecarAttachesSidecar(t *testing.T) {
	commitment := testKZGCommitment(31)
	tx := testVerifyBlobTx(KZGToVersionedHash(commitment))
	sidecar := &BlobTxSidecar{
		Blobs:       []Blob{Blob{1, 2, 3}},
		Commitments: []KZGCommitment{commitment},
		Proofs:      []KZGProof{{}},
	}
	bundle, err := NewBlobTxWithSidecar(tx, sidecar)
	if err != nil {
		t.Fatalf("expected bundle, got %v", err)
	}
	if bundle.Tx == tx {
		t.Fatalf("expected bundle tx copy with attached sidecar")
	}
	if bundle.Tx.BlobSidecar() == nil {
		t.Fatalf("expected attached sidecar on bundle tx")
	}
	if bundle.Sidecar != bundle.Tx.BlobSidecar() {
		t.Fatalf("expected bundle sidecar to match tx sidecar")
	}
}
