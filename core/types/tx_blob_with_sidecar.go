package types

import "errors"

var ErrBlobTxSidecarOnNonBlobTx = errors.New("blob sidecar attached to non-blob transaction")

type BlobTxWithSidecar struct {
	Tx      *Transaction
	Sidecar *BlobTxSidecar
}

func NewBlobTxWithSidecar(tx *Transaction, sidecar *BlobTxSidecar) (*BlobTxWithSidecar, error) {
	if tx == nil || tx.Type() != BlobTxType {
		return nil, ErrBlobTxSidecarOnNonBlobTx
	}
	if err := tx.ValidateBlobSidecar(sidecar); err != nil {
		return nil, err
	}
	attached := tx.WithBlobSidecar(sidecar)
	return &BlobTxWithSidecar{Tx: attached, Sidecar: attached.BlobSidecar()}, nil
}

func NewVerifiedBlobTxWithSidecar(tx *Transaction, sidecar *BlobTxSidecar, verifier BlobVerifier) (*BlobTxWithSidecar, error) {
	if tx == nil || tx.Type() != BlobTxType {
		return nil, ErrBlobTxSidecarOnNonBlobTx
	}
	if err := tx.VerifyBlobSidecar(sidecar, verifier); err != nil {
		return nil, err
	}
	attached := tx.WithBlobSidecar(sidecar)
	return &BlobTxWithSidecar{Tx: attached, Sidecar: attached.BlobSidecar()}, nil
}

func (w *BlobTxWithSidecar) activeSidecar() *BlobTxSidecar {
	if w == nil {
		return nil
	}
	if w.Sidecar != nil {
		return w.Sidecar
	}
	if w.Tx != nil {
		return w.Tx.BlobSidecar()
	}
	return nil
}

func (w *BlobTxWithSidecar) Validate() error {
	if w == nil || w.Tx == nil || w.Tx.Type() != BlobTxType {
		return ErrBlobTxSidecarOnNonBlobTx
	}
	return w.Tx.ValidateBlobSidecar(w.activeSidecar())
}

func (w *BlobTxWithSidecar) Verify(verifier BlobVerifier) error {
	if w == nil || w.Tx == nil || w.Tx.Type() != BlobTxType {
		return ErrBlobTxSidecarOnNonBlobTx
	}
	return w.Tx.VerifyBlobSidecar(w.activeSidecar(), verifier)
}
