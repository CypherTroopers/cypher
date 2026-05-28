package core

import (
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	kzg "github.com/cypherium/cypher/crypto/kzg4844"
)

func buildCoreValidBlobTuple(t *testing.T) (types.Blob, types.KZGCommitment, types.KZGProof) {
	t.Helper()
	var blob kzg.Blob
	for offset, scalar := 0, byte(1); offset < len(blob); offset, scalar = offset+32, scalar+1 {
		// Keep every 32-byte field element canonical.
		blob[offset+31] = scalar
		if scalar == 250 {
			scalar = 0
		}
	}
	commitment, err := kzg.BlobToCommitment(&blob)
	if err != nil {
		t.Fatalf("BlobToCommitment failed: %v", err)
	}
	proof, err := kzg.ComputeBlobProof(&blob, commitment)
	if err != nil {
		t.Fatalf("ComputeBlobProof failed: %v", err)
	}
	outBlob := make(types.Blob, len(blob))
	copy(outBlob, blob[:])
	var outCommitment types.KZGCommitment
	copy(outCommitment[:], commitment[:])
	var outProof types.KZGProof
	copy(outProof[:], proof[:])
	return outBlob, outCommitment, outProof
}

func buildCoreBlobTxWithRealSidecar(t *testing.T) *types.Transaction {
	t.Helper()
	blob, commitment, proof := buildCoreValidBlobTuple(t)
	hash := types.KZGToVersionedHash(commitment)
	tx := newTxpoolBlobTxWithNonce(t, 1, []common.Hash{hash}, common.Big1)
	return tx.WithBlobSidecar(&types.BlobTxSidecar{
		Blobs:       []types.Blob{blob},
		Commitments: []types.KZGCommitment{commitment},
		Proofs:      []types.KZGProof{proof},
	})
}

func TestValidateBlockBlobSidecarsUsesRealKZGVerifier(t *testing.T) {
	cfg := blobGasTestConfig(0)
	tx := buildCoreBlobTxWithRealSidecar(t)
	header := blobBlockValidationHeader(types.Transactions{tx}, 0)
	if err := ValidateBlockBlobSidecars(cfg, header, types.Transactions{tx}, types.KZGBlobVerifier{}); err != nil {
		t.Fatalf("expected real KZG block sidecar validation to pass, got %v", err)
	}
}

func TestValidateBlockBlobSidecarsRejectsInvalidRealKZGProof(t *testing.T) {
	cfg := blobGasTestConfig(0)
	tx := buildCoreBlobTxWithRealSidecar(t)
	sidecar := tx.BlobSidecar().Copy()
	sidecar.Proofs[0][0] ^= 0xff
	tx = tx.WithBlobSidecar(sidecar)
	header := blobBlockValidationHeader(types.Transactions{tx}, 0)
	if err := ValidateBlockBlobSidecars(cfg, header, types.Transactions{tx}, types.KZGBlobVerifier{}); err == nil {
		t.Fatalf("expected invalid real KZG proof to be rejected")
	}
}
