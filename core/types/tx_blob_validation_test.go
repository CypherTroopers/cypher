package types

import (
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/params"
)

func validationBlobHash(n byte) common.Hash {
	var h common.Hash
	h[0] = BlobCommitmentVersionKZG
	h[31] = n
	return h
}

func newValidationBlobTx(hashes []common.Hash, feeCap *big.Int) *Transaction {
	return &Transaction{data: &BlobTx{
		ChainID:    big.NewInt(12367),
		GasTipCap:  big.NewInt(1),
		GasFeeCap:  big.NewInt(10),
		Gas:        21000,
		Value:      big.NewInt(5),
		BlobFeeCap: feeCap,
		BlobHashes: hashes,
		V:          big.NewInt(0),
		R:          big.NewInt(1),
		S:          big.NewInt(1),
	}}
}

func TestBlobGas(t *testing.T) {
	tx := newValidationBlobTx([]common.Hash{validationBlobHash(1), validationBlobHash(2)}, big.NewInt(1))
	if got, want := tx.BlobGas(), uint64(2)*params.BlobTxBlobGasPerBlob; got != want {
		t.Fatalf("blob gas mismatch: got %d want %d", got, want)
	}
}

func TestBlobGasCost(t *testing.T) {
	tx := newValidationBlobTx([]common.Hash{validationBlobHash(1), validationBlobHash(2)}, big.NewInt(3))
	wantBlobCost := new(big.Int).Mul(big.NewInt(3), new(big.Int).SetUint64(uint64(2)*params.BlobTxBlobGasPerBlob))
	if got := tx.BlobGasCost(); got.Cmp(wantBlobCost) != 0 {
		t.Fatalf("blob gas cost mismatch: got %s want %s", got, wantBlobCost)
	}
	wantTotal := tx.Cost()
	if got := tx.CostWithBlobGas(); got.Cmp(wantTotal) != 0 {
		t.Fatalf("cost with blob gas mismatch: got %s want %s", got, wantTotal)
	}
}

func TestValidateBlobTx(t *testing.T) {
	if err := newValidationBlobTx(nil, big.NewInt(1)).ValidateBlobTx(6, nil); !errors.Is(err, ErrBlobTxMissingBlobHashes) {
		t.Fatalf("expected missing blob hashes, got %v", err)
	}
	if err := newValidationBlobTx([]common.Hash{validationBlobHash(1)}, nil).ValidateBlobTx(6, nil); !errors.Is(err, ErrBlobTxInvalidFeeCap) {
		t.Fatalf("expected invalid fee cap, got %v", err)
	}
	if err := newValidationBlobTx([]common.Hash{validationBlobHash(1), validationBlobHash(2)}, big.NewInt(1)).ValidateBlobTx(1, nil); !errors.Is(err, ErrBlobTxTooManyBlobs) {
		t.Fatalf("expected too many blobs, got %v", err)
	}
	if err := newValidationBlobTx([]common.Hash{{}}, big.NewInt(1)).ValidateBlobTx(6, nil); !errors.Is(err, ErrBlobTxInvalidBlobHashVersion) {
		t.Fatalf("expected invalid blob hash version, got %v", err)
	}
	if err := newValidationBlobTx([]common.Hash{validationBlobHash(1)}, big.NewInt(1)).ValidateBlobTx(6, big.NewInt(2)); !errors.Is(err, ErrBlobTxInvalidFeeCap) {
		t.Fatalf("expected fee cap below blob base fee, got %v", err)
	}
	if err := newValidationBlobTx([]common.Hash{validationBlobHash(1)}, big.NewInt(2)).ValidateBlobTx(6, big.NewInt(2)); err != nil {
		t.Fatalf("expected valid blob tx, got %v", err)
	}
}
