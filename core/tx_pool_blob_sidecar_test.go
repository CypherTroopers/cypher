package core

import (
	"errors"
	"math/big"
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
		Blobs:       []types.Blob{{1, 2, 3}},
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

func TestAttachBlobSidecarsToTransactions(t *testing.T) {
	pool := &TxPool{}
	legacy := types.NewTransaction(0, common.Address{}, nil, 21000, nil, nil)
	blobTx, sidecar := testBlobTxWithSidecar(t)
	pool.storeBlobSidecar(blobTx, sidecar)

	attached, err := pool.AttachBlobSidecarsToTransactions(types.Transactions{legacy, blobTx})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(attached) != 2 {
		t.Fatalf("expected two transactions, got %d", len(attached))
	}
	if attached[0] != legacy {
		t.Fatalf("legacy transaction should be kept unchanged")
	}
	if attached[1].Hash() != blobTx.Hash() {
		t.Fatalf("attached blob tx hash changed")
	}
	if attached[1] == blobTx {
		t.Fatalf("blob tx should be copied when sidecar is attached")
	}
	if attached[1].BlobSidecar() == nil {
		t.Fatalf("blob sidecar was not attached")
	}
}

func TestAttachBlobSidecarsToTransactionsRequiresSidecar(t *testing.T) {
	pool := &TxPool{}
	blobTx, _ := testBlobTxWithSidecar(t)
	_, err := pool.AttachBlobSidecarsToTransactions(types.Transactions{blobTx})
	if err != ErrMissingBlobTxSidecar {
		t.Fatalf("expected missing sidecar error, got %v", err)
	}
}

func TestBlobSidecarsForTransactionsIgnoresLegacy(t *testing.T) {
	pool := &TxPool{}
	legacy := types.NewTransaction(0, common.Address{}, nil, 21000, nil, nil)
	sidecars, err := pool.BlobSidecarsForTransactions(types.Transactions{legacy})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sidecars != nil {
		t.Fatalf("expected nil sidecars for legacy txs")
	}
}

func TestBlobSidecarsForTransactionsRequiresSidecar(t *testing.T) {
	pool := &TxPool{}
	tx, _ := testBlobTxWithSidecar(t)
	_, err := pool.BlobSidecarsForTransactions(types.Transactions{tx})
	if err != ErrMissingBlobTxSidecar {
		t.Fatalf("expected missing sidecar error, got %v", err)
	}
}

func TestBlobBundlesForTransactionsReturnsBundles(t *testing.T) {
	pool := &TxPool{}
	tx, sidecar := testBlobTxWithSidecar(t)
	pool.storeBlobSidecar(tx, sidecar)
	bundles, err := pool.BlobBundlesForTransactions(types.Transactions{tx})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(bundles) != 1 {
		t.Fatalf("expected one bundle, got %d", len(bundles))
	}
	if bundles[0].Tx.Hash() != tx.Hash() {
		t.Fatalf("bundle tx hash mismatch")
	}
	if bundles[0].Sidecar == nil {
		t.Fatalf("missing bundle sidecar")
	}
}

func TestContentWithBlobSidecarsFiltersMissingBlobSidecars(t *testing.T) {
	legacy := types.NewTransaction(0, common.Address{}, nil, 21000, nil, nil)
	blobTx := newTxpoolBlobTxWithNonce(t, 1, []common.Hash{txpoolBlobTestHash(1)}, common.Big1)
	_, sidecar := testTxPoolSidecar(t, 1)
	missingBlobTx := newTxpoolBlobTxWithNonce(t, 2, []common.Hash{txpoolBlobTestHash(2)}, common.Big1)

	addr := common.HexToAddress("0x1234")
	pool := &TxPool{
		pending: map[common.Address]*txList{
			addr: newTxList(true),
		},
		queue: map[common.Address]*txList{},
	}
	pool.pending[addr].Add(legacy, 10)
	pool.pending[addr].Add(blobTx, 10)
	pool.pending[addr].Add(missingBlobTx, 10)
	pool.storeBlobSidecar(blobTx, sidecar)

	pending, queued := pool.ContentWithBlobSidecars()
	if len(queued) != 0 {
		t.Fatalf("expected empty queued map")
	}
	got := pending[addr]
	if len(got) != 2 {
		t.Fatalf("expected legacy + blob tx with sidecar, got %d", len(got))
	}
	for _, tx := range got {
		if tx.Type() == types.BlobTxType && tx.Hash() != blobTx.Hash() {
			t.Fatalf("unexpected blob tx without sidecar was kept")
		}
	}
}

func testSidecarSelectionBlobTx(t *testing.T, n byte) (*types.Transaction, *types.BlobTxSidecar) {
	t.Helper()
	var commitment types.KZGCommitment
	commitment[47] = n
	hash := types.KZGToVersionedHash(commitment)
	tx := newTxpoolBlobTx(t, []common.Hash{hash}, common.Big1)
	sidecar := &types.BlobTxSidecar{
		Blobs:       []types.Blob{{1, 2, 3}},
		Commitments: []types.KZGCommitment{commitment},
		Proofs:      []types.KZGProof{{}},
	}
	return tx, sidecar
}

func TestValidateBlobSidecarsForTransactions(t *testing.T) {
	pool := &TxPool{all: newTxLookup()}
	blobTx, sidecar := testSidecarSelectionBlobTx(t, 1)
	legacyTx := types.NewTransaction(0, common.Address{1}, big.NewInt(0), 21000, big.NewInt(1), nil)

	if err := pool.ValidateBlobSidecarsForTransactions(types.Transactions{legacyTx}); err != nil {
		t.Fatalf("legacy tx should not require sidecar: %v", err)
	}
	if err := pool.ValidateBlobSidecarsForTransactions(types.Transactions{blobTx}); !errors.Is(err, ErrMissingBlobTxSidecar) {
		t.Fatalf("expected missing sidecar error, got %v", err)
	}
	pool.all.Add(blobTx, false)
	pool.storeBlobSidecar(blobTx, sidecar)
	if err := pool.ValidateBlobSidecarsForTransactions(types.Transactions{legacyTx, blobTx}); err != nil {
		t.Fatalf("expected valid sidecars, got %v", err)
	}
}

func TestFilterTransactionsWithBlobSidecars(t *testing.T) {
	pool := &TxPool{all: newTxLookup()}
	withSidecar, sidecar := testSidecarSelectionBlobTx(t, 2)
	withoutSidecar, _ := testSidecarSelectionBlobTx(t, 3)
	legacyTx := types.NewTransaction(1, common.Address{2}, big.NewInt(0), 21000, big.NewInt(1), nil)

	pool.all.Add(withSidecar, false)
	pool.storeBlobSidecar(withSidecar, sidecar)
	filtered := pool.FilterTransactionsWithBlobSidecars(types.Transactions{legacyTx, withSidecar, withoutSidecar, nil})
	if len(filtered) != 2 {
		t.Fatalf("filtered len = %d, want 2", len(filtered))
	}
	if filtered[0] != legacyTx || filtered[1] != withSidecar {
		t.Fatalf("unexpected filtered transactions")
	}
}
