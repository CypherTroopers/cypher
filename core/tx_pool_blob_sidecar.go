package core

import "github.com/cypherium/cypher/core/types"

func validateBlobTxWithVerifier(w *types.BlobTxWithSidecar, verifier types.BlobVerifier) error {
	if verifier == nil {
		return types.ErrBlobVerifierMissing
	}
	return w.Verify(verifier)
}

// AddLocalBlobTx verifies a BlobTx sidecar bundle and then submits the
// transaction through the existing local txpool path.
func (pool *TxPool) AddLocalBlobTx(w *types.BlobTxWithSidecar, verifier types.BlobVerifier) error {
	if err := validateBlobTxWithVerifier(w, verifier); err != nil {
		return err
	}
	if err := pool.AddLocal(w.Tx); err != nil {
		return err
	}
	pool.storeBlobSidecar(w.Tx, w.Sidecar)
	return nil
}

// AddRemoteBlobTx verifies a BlobTx sidecar bundle and then submits the
// transaction through the existing remote txpool path.
func (pool *TxPool) AddRemoteBlobTx(w *types.BlobTxWithSidecar, verifier types.BlobVerifier) error {
	if err := validateBlobTxWithVerifier(w, verifier); err != nil {
		return err
	}
	if err := pool.AddRemote(w.Tx); err != nil {
		return err
	}
	pool.storeBlobSidecar(w.Tx, w.Sidecar)
	return nil
}

// AddRemoteBlobTxSync verifies a BlobTx sidecar bundle and then submits the
// transaction through the existing synchronous remote txpool path.
func (pool *TxPool) AddRemoteBlobTxSync(w *types.BlobTxWithSidecar, verifier types.BlobVerifier) error {
	if err := validateBlobTxWithVerifier(w, verifier); err != nil {
		return err
	}
	if err := pool.addRemoteSync(w.Tx); err != nil {
		return err
	}
	pool.storeBlobSidecar(w.Tx, w.Sidecar)
	return nil
}
