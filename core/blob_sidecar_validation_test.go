package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

type blockBlobMockVerifier struct {
	calls int
	err   error
}

func (v *blockBlobMockVerifier) VerifyBlob(blob types.Blob, commitment types.KZGCommitment, proof types.KZGProof) error {
	v.calls++
	return v.err
}

func blockBlobSidecarTx(t *testing.T, n byte) *types.Transaction {
	t.Helper()
	var commitment types.KZGCommitment
	commitment[47] = n
	hash := types.KZGToVersionedHash(commitment)
	tx := newTxpoolBlobTxWithNonce(t, uint64(n), []common.Hash{hash}, common.Big1)
	tx = tx.WithBlobSidecar(&types.BlobTxSidecar{
		Blobs:       []types.Blob{types.Blob{1, 2, 3}},
		Commitments: []types.KZGCommitment{commitment},
		Proofs:      []types.KZGProof{{}},
	})
	if err := tx.ValidateBlobSidecar(tx.BlobSidecar()); err != nil {
		t.Fatalf("sidecar setup failed: %v", err)
	}
	if hashes := tx.BlobHashes(); len(hashes) != 1 || hashes[0] != hash {
		t.Fatalf("blob hash setup mismatch")
	}
	return tx
}

func TestValidateBlockBlobSidecarsIgnoresNonBlobBlocks(t *testing.T) {
	cfg := blobGasTestConfig(0)
	header := &types.Header{Number: big.NewInt(1), Time: 0}
	verifier := &blockBlobMockVerifier{}
	txs := types.Transactions{types.NewTransaction(0, common.Address{}, nil, 21000, nil, nil)}
	if err := ValidateBlockBlobSidecars(cfg, header, txs, verifier); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verifier.calls != 0 {
		t.Fatalf("verifier calls = %d, want 0", verifier.calls)
	}
}

func TestValidateBlockBlobSidecarsRejectsPreCancunBlobTx(t *testing.T) {
	cfg := blobGasTestConfig(10)
	header := &types.Header{Number: big.NewInt(1), Time: 0}
	txs := types.Transactions{blockBlobSidecarTx(t, 1)}
	if err := ValidateBlockBlobSidecars(cfg, header, txs, &blockBlobMockVerifier{}); !errors.Is(err, ErrBlobTxBeforeCancun) {
		t.Fatalf("expected pre-Cancun blob tx error, got %v", err)
	}
}

func TestValidateBlockBlobSidecarsRequiresVerifier(t *testing.T) {
	cfg := blobGasTestConfig(0)
	header := &types.Header{Number: big.NewInt(1), Time: 0}
	txs := types.Transactions{blockBlobSidecarTx(t, 1)}
	if err := ValidateBlockBlobSidecars(cfg, header, txs, nil); !errors.Is(err, types.ErrBlobVerifierMissing) {
		t.Fatalf("expected missing verifier error, got %v", err)
	}
}

func TestValidateBlockBlobSidecarsRejectsMissingSidecar(t *testing.T) {
	cfg := blobGasTestConfig(0)
	header := &types.Header{Number: big.NewInt(1), Time: 0}
	txs := types.Transactions{blobGasTestTx(t, 1)}
	if err := ValidateBlockBlobSidecars(cfg, header, txs, &blockBlobMockVerifier{}); !errors.Is(err, types.ErrBlobSidecarMissing) {
		t.Fatalf("expected missing sidecar error, got %v", err)
	}
}

func TestValidateBlockBlobSidecarsVerifiesSidecars(t *testing.T) {
	cfg := blobGasTestConfig(0)
	header := &types.Header{Number: big.NewInt(1), Time: 0}
	txs := types.Transactions{blockBlobSidecarTx(t, 1)}
	verifier := &blockBlobMockVerifier{}
	if err := ValidateBlockBlobSidecars(cfg, header, txs, verifier); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verifier.calls != 1 {
		t.Fatalf("verifier calls = %d, want 1", verifier.calls)
	}
}

func TestValidateBlockBlobSidecarsPropagatesVerifierError(t *testing.T) {
	cfg := blobGasTestConfig(0)
	header := &types.Header{Number: big.NewInt(1), Time: 0}
	txs := types.Transactions{blockBlobSidecarTx(t, 1)}
	wantErr := errors.New("mock verifier error")
	if err := ValidateBlockBlobSidecars(cfg, header, txs, &blockBlobMockVerifier{err: wantErr}); !errors.Is(err, wantErr) {
		t.Fatalf("expected verifier error, got %v", err)
	}
}
