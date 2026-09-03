package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
)

func signedPoolBlobTx(t *testing.T, nonce uint64, invalidProof bool) (*types.Transaction, *types.BlobTxSidecar) {
	t.Helper()
	key, err := crypto.HexToECDSA("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	blob, commitment, proof := buildCoreValidBlobTuple(t)
	if invalidProof {
		proof[0] ^= 0xff
	}
	sidecar := &types.BlobTxSidecar{
		Blobs:       []types.Blob{blob},
		Commitments: []types.KZGCommitment{commitment},
		Proofs:      []types.KZGProof{proof},
	}
	to := crypto.PubkeyToAddress(key.PublicKey)
	unsigned := types.NewTx(&types.BlobTx{
		ChainID:    big.NewInt(1),
		Nonce:      nonce,
		GasTipCap:  big.NewInt(1),
		GasFeeCap:  big.NewInt(2),
		Gas:        params.TxGas,
		To:         to,
		Value:      new(big.Int),
		BlobFeeCap: big.NewInt(2),
		BlobHashes: sidecar.BlobHashes(),
	}).WithBlobSidecar(sidecar)
	signed, err := types.SignTx(unsigned, types.NewLondonSigner(big.NewInt(1)), key)
	if err != nil {
		t.Fatal(err)
	}
	return signed, sidecar
}

func newBlobAdmissionPool(t *testing.T) *TxPool {
	t.Helper()
	key, err := crypto.HexToECDSA("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	payer := crypto.PubkeyToAddress(key.PublicKey)
	chain, _ := newNativePoolTestChain(t, payer)
	config := DefaultTxPoolConfig
	config.NoLocals = true
	config.Journal = ""
	config.PriceLimit = 1
	pool := NewTxPool(config, evmOnlyNativePoolTestConfig(t), chain)
	t.Cleanup(pool.Stop)
	return pool
}

func TestTxPoolGenericAddAcceptsOnlyRealKZGBlobSidecar(t *testing.T) {
	pool := newBlobAdmissionPool(t)
	valid, expectedSidecar := signedPoolBlobTx(t, 0, false)
	if err := pool.AddRemote(valid); err != nil {
		t.Fatalf("generic AddRemote rejected valid type-3 bundle: %v", err)
	}
	if pool.Get(valid.Hash()) == nil {
		t.Fatal("valid type-3 transaction missing from pool")
	}
	got := pool.GetBlobSidecar(valid.Hash())
	if got == nil || len(got.Blobs) != len(expectedSidecar.Blobs) {
		t.Fatal("verified type-3 sidecar was not atomically published")
	}
	pool.RemoveBatch(types.Transactions{valid})
	if pool.getBlobSidecar(valid.Hash(), false) != nil {
		t.Fatal("removing a type-3 transaction retained stale sidecar data")
	}
}

func TestTxPoolGenericAddRejectsBareBlobEnvelopeWithoutStaleSidecar(t *testing.T) {
	pool := newBlobAdmissionPool(t)
	withSidecar, _ := signedPoolBlobTx(t, 0, false)
	bare := withSidecar.WithBlobSidecar(nil)
	if err := pool.AddRemote(bare); !errors.Is(err, types.ErrBlobSidecarMissing) {
		t.Fatalf("generic AddRemote error = %v, want %v", err, types.ErrBlobSidecarMissing)
	}
	if pool.Get(bare.Hash()) != nil || pool.getBlobSidecar(bare.Hash(), false) != nil {
		t.Fatal("failed bare type-3 admission left transaction or sidecar state")
	}
}

func TestTxPoolGenericAddRejectsInvalidKZGProofWithoutStaleSidecar(t *testing.T) {
	pool := newBlobAdmissionPool(t)
	invalid, _ := signedPoolBlobTx(t, 0, true)
	if err := pool.AddRemote(invalid); err == nil {
		t.Fatal("generic AddRemote accepted invalid KZG proof")
	}
	if pool.Get(invalid.Hash()) != nil || pool.getBlobSidecar(invalid.Hash(), false) != nil {
		t.Fatal("failed KZG admission left transaction or sidecar state")
	}
}

func TestTxPoolBlobAdmissionHonorsGenericSidecarByteQuota(t *testing.T) {
	pool := newBlobAdmissionPool(t)
	pool.config.GlobalSlots = 1
	pool.config.GlobalQueue = 1
	tx, _ := signedPoolBlobTx(t, 0, false)
	if err := pool.AddRemote(tx); !errors.Is(err, ErrTxPoolOverflow) {
		t.Fatalf("oversized blob admission error = %v, want %v", err, ErrTxPoolOverflow)
	}
	if pool.Get(tx.Hash()) != nil || pool.getBlobSidecar(tx.Hash(), false) != nil {
		t.Fatal("quota-rejected type-3 transaction retained pool or sidecar state")
	}
}

func TestBlobTransactionSlotsChargeBothSidecarCopies(t *testing.T) {
	tx, _ := signedPoolBlobTx(t, 0, false)
	bareSlots := numSlots(tx.WithBlobSidecar(nil))
	withSidecarSlots := numSlots(tx)
	if withSidecarSlots <= bareSlots {
		t.Fatalf("blob sidecar was not charged: bare=%d attached=%d", bareSlots, withSidecarSlots)
	}
	wantMinimum := (2*len(tx.BlobSidecar().Blobs[0]) + txSlotSize - 1) / txSlotSize
	if withSidecarSlots < wantMinimum {
		t.Fatalf("blob slot charge = %d, want at least %d", withSidecarSlots, wantMinimum)
	}
}

func TestTxLookupBlobChargeIsImmutableAfterAdmission(t *testing.T) {
	tx, _ := signedPoolBlobTx(t, 0, false)
	lookup := newTxLookup()
	lookup.Add(tx, false)
	charged := lookup.Slots()
	if charged <= 1 {
		t.Fatalf("unexpected blob charge %d", charged)
	}
	// Some in-process APIs historically expose transaction pointers. Even if a
	// caller mutates that attached view, removal must subtract the admission
	// snapshot instead of recomputing a smaller charge.
	tx.BlobSidecar().Blobs[0] = nil
	lookup.Remove(tx.Hash())
	if got := lookup.Slots(); got != 0 {
		t.Fatalf("slot accounting after sidecar mutation/removal = %d, want 0", got)
	}
}
