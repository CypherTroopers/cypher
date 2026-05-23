package core

import (
	"errors"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

type txpoolMockBlobVerifier struct {
	calls int
	err   error
}

func (v *txpoolMockBlobVerifier) VerifyBlob(blob types.Blob, commitment types.KZGCommitment, proof types.KZGProof) error {
	v.calls++
	return v.err
}

func txpoolSidecarBundle(t *testing.T) (*types.BlobTxWithSidecar, *txpoolMockBlobVerifier) {
	t.Helper()
	var commitment types.KZGCommitment
	commitment[47] = 1
	hash := types.KZGToVersionedHash(commitment)
	tx := newTxpoolBlobTx(t, []common.Hash{hash}, common.Big1)
	sidecar := &types.BlobTxSidecar{
		Blobs:       []types.Blob{types.Blob{1, 2, 3}},
		Commitments: []types.KZGCommitment{commitment},
		Proofs:      []types.KZGProof{{}},
	}
	bundle, err := types.NewBlobTxWithSidecar(tx, sidecar)
	if err != nil {
		t.Fatalf("failed to build blob tx sidecar bundle: %v", err)
	}
	return bundle, &txpoolMockBlobVerifier{}
}

func TestValidateBlobTxWithVerifierRequiresVerifier(t *testing.T) {
	bundle, _ := txpoolSidecarBundle(t)
	if err := validateBlobTxWithVerifier(bundle, nil); !errors.Is(err, types.ErrBlobVerifierMissing) {
		t.Fatalf("expected missing verifier error, got %v", err)
	}
}

func TestValidateBlobTxWithVerifier(t *testing.T) {
	bundle, verifier := txpoolSidecarBundle(t)
	if err := validateBlobTxWithVerifier(bundle, verifier); err != nil {
		t.Fatalf("expected valid bundle with verifier, got %v", err)
	}
	if verifier.calls != 1 {
		t.Fatalf("verifier calls = %d, want 1", verifier.calls)
	}
}

func TestValidateBlobTxWithVerifierPropagatesError(t *testing.T) {
	bundle, verifier := txpoolSidecarBundle(t)
	wantErr := errors.New("mock blob verification error")
	verifier.err = wantErr
	if err := validateBlobTxWithVerifier(bundle, verifier); !errors.Is(err, wantErr) {
		t.Fatalf("expected verifier error, got %v", err)
	}
}
