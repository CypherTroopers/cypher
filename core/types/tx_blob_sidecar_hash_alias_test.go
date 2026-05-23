package types

import "testing"

func TestBlobTxSidecarBlobHashesAlias(t *testing.T) {
	commitment := testKZGCommitment(51)
	sidecar := &BlobTxSidecar{
		Blobs:       []Blob{Blob{1, 2, 3}},
		Commitments: []KZGCommitment{commitment},
		Proofs:      []KZGProof{{}},
	}
	blobHashes := sidecar.BlobHashes()
	versionedHashes := sidecar.VersionedHashes()
	if len(blobHashes) != 1 || len(versionedHashes) != 1 {
		t.Fatalf("unexpected hash lengths: blob=%d versioned=%d", len(blobHashes), len(versionedHashes))
	}
	if blobHashes[0] != versionedHashes[0] {
		t.Fatalf("BlobHashes and VersionedHashes mismatch")
	}
	if blobHashes[0] != KZGToVersionedHash(commitment) {
		t.Fatalf("unexpected blob hash")
	}
}
