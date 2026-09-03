package core

import "github.com/cypherium/cypher/core/types"

func validateBlobTxWithVerifier(w *types.BlobTxWithSidecar, verifier types.BlobVerifier) error {
	if verifier == nil {
		return types.ErrBlobVerifierMissing
	}
	return w.Verify(verifier)
}

func blobTxWithAttachedSidecar(w *types.BlobTxWithSidecar) (*types.Transaction, error) {
	if w == nil || w.Tx == nil || w.Tx.Type() != types.BlobTxType {
		return nil, types.ErrBlobTxSidecarOnNonBlobTx
	}
	sidecar := w.Sidecar
	if sidecar == nil {
		sidecar = w.Tx.BlobSidecar()
	}
	if err := w.Tx.ValidateBlobSidecar(sidecar); err != nil {
		return nil, err
	}
	return w.Tx.WithBlobSidecar(sidecar), nil
}

// AddLocalBlobTx verifies a BlobTx sidecar bundle and then submits the
// transaction through the existing local txpool path.
func (pool *TxPool) AddLocalBlobTx(w *types.BlobTxWithSidecar, verifier types.BlobVerifier) error {
	if err := validateBlobTxWithVerifier(w, verifier); err != nil {
		return err
	}
	tx, err := blobTxWithAttachedSidecar(w)
	if err != nil {
		return err
	}
	// AddLocal applies the mandatory real-KZG admission gate and publishes the
	// sidecar only after the transaction itself is inserted successfully.
	return pool.AddLocal(tx)
}

// AddRemoteBlobTx verifies a BlobTx sidecar bundle and then submits the
// transaction through the existing remote txpool path.
func (pool *TxPool) AddRemoteBlobTx(w *types.BlobTxWithSidecar, verifier types.BlobVerifier) error {
	if err := validateBlobTxWithVerifier(w, verifier); err != nil {
		return err
	}
	tx, err := blobTxWithAttachedSidecar(w)
	if err != nil {
		return err
	}
	return pool.AddRemote(tx)
}

// AddRemoteBlobTxSync verifies a BlobTx sidecar bundle and then submits the
// transaction through the existing synchronous remote txpool path.
func (pool *TxPool) AddRemoteBlobTxSync(w *types.BlobTxWithSidecar, verifier types.BlobVerifier) error {
	if err := validateBlobTxWithVerifier(w, verifier); err != nil {
		return err
	}
	tx, err := blobTxWithAttachedSidecar(w)
	if err != nil {
		return err
	}
	return pool.addRemoteSync(tx)
}
