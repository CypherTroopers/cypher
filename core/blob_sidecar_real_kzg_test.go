package core

import (
	"errors"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	kzg "github.com/cypherium/cypher/crypto/kzg4844"
	"github.com/cypherium/cypher/params"
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

func toOsakaBlobSidecar(t *testing.T, tx *types.Transaction) *types.Transaction {
	t.Helper()
	sidecar := tx.BlobSidecar().Copy()
	proofs := make([]types.KZGProof, 0, len(sidecar.Blobs)*kzg.CellProofsPerBlob)
	for i, blob := range sidecar.Blobs {
		var kzgBlob kzg.Blob
		copy(kzgBlob[:], blob)
		cellProofs, err := kzg.ComputeCellProofs(&kzgBlob)
		if err != nil {
			t.Fatalf("ComputeCellProofs(%d) failed: %v", i, err)
		}
		for _, proof := range cellProofs {
			proofs = append(proofs, types.KZGProof(proof))
		}
	}
	sidecar.Version = types.BlobSidecarVersion1
	sidecar.Proofs = proofs
	return tx.WithBlobSidecar(sidecar)
}

func TestValidateBlockBlobSidecarsUsesRealKZGVerifier(t *testing.T) {
	cfg := blobGasTestConfig(0)
	tx := buildCoreBlobTxWithRealSidecar(t)
	header := blobBlockValidationHeader(types.Transactions{tx}, 0)
	if err := ValidateBlockBlobSidecars(cfg, header, types.Transactions{tx}, types.KZGBlobVerifier{}); err != nil {
		t.Fatalf("expected real KZG block sidecar validation to pass, got %v", err)
	}
}

func TestValidateBlockBlobExecutionUsesRealKZGVerifier(t *testing.T) {
	cfg := blobGasTestConfig(0)
	tx := buildCoreBlobTxWithRealSidecar(t)
	txs := types.Transactions{tx}
	header := blobBlockValidationHeader(txs, 0)
	if err := ValidateBlockBlobExecution(cfg, header, txs, types.KZGBlobVerifier{}); err != nil {
		t.Fatalf("expected complete EIP-4844 block validation to pass, got %v", err)
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

func TestValidateBlockBlobExecutionRejectsInvalidRealKZGProof(t *testing.T) {
	cfg := blobGasTestConfig(0)
	tx := buildCoreBlobTxWithRealSidecar(t)
	sidecar := tx.BlobSidecar().Copy()
	sidecar.Proofs[0][0] ^= 0xff
	tx = tx.WithBlobSidecar(sidecar)
	txs := types.Transactions{tx}
	header := blobBlockValidationHeader(txs, 0)
	if err := ValidateBlockBlobExecution(cfg, header, txs, types.KZGBlobVerifier{}); err == nil {
		t.Fatal("invalid KZG proof passed complete EIP-4844 block validation")
	}
}

func TestValidateBlockBlobExecutionSelectsOsakaCellProofs(t *testing.T) {
	zero := uint64(0)
	cfg := blobGasTestConfig(0)
	modern := cfg.ModernForkConfig()
	modern.OsakaTime = &zero
	modern.BlobSchedule = &params.BlobScheduleConfig{
		Cancun: &params.BlobConfig{Target: 3, Max: 6, BaseFeeUpdateFraction: 3338477},
		Osaka:  &params.BlobConfig{Target: 6, Max: 9, BaseFeeUpdateFraction: 5007716},
	}
	txV0 := buildCoreBlobTxWithRealSidecar(t)
	header := blobBlockValidationHeader(types.Transactions{txV0}, 0)
	if err := ValidateBlockBlobExecution(cfg, header, types.Transactions{txV0}, types.KZGBlobVerifier{}); !errors.Is(err, types.ErrBlobSidecarVersionMismatch) {
		t.Fatalf("Prague sidecar under Osaka rules error = %v", err)
	}
	txV1 := toOsakaBlobSidecar(t, txV0)
	header = blobBlockValidationHeader(types.Transactions{txV1}, 0)
	if err := ValidateBlockBlobExecution(cfg, header, types.Transactions{txV1}, types.KZGBlobVerifier{}); err != nil {
		t.Fatalf("valid Osaka sidecar rejected: %v", err)
	}
}

func TestTxPoolRequiresOsakaCellProofSidecar(t *testing.T) {
	zero := uint64(0)
	cfg := blobGasTestConfig(0)
	cfg.ModernForkConfig().OsakaTime = &zero
	txV0 := buildCoreBlobTxWithRealSidecar(t)
	pool := &TxPool{chainconfig: cfg}
	if err := pool.validateBlobTx(txV0); !errors.Is(err, types.ErrBlobSidecarVersionMismatch) {
		t.Fatalf("Prague sidecar admitted to Osaka pool: %v", err)
	}
	if err := pool.validateBlobTx(toOsakaBlobSidecar(t, txV0)); err != nil {
		t.Fatalf("Osaka sidecar rejected by pool: %v", err)
	}
}
