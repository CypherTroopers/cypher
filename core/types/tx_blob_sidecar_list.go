package types

// VerifyBlobSidecars verifies every BlobTx sidecar attached to the transaction
// list. Non-blob transactions are ignored. BlobTxs must have an attached sidecar
// and a non-nil verifier.
func VerifyBlobSidecars(txs Transactions, verifier BlobVerifier) error {
	if verifier == nil {
		return ErrBlobVerifierMissing
	}
	for _, tx := range txs {
		if tx == nil || tx.Type() != BlobTxType {
			continue
		}
		if err := tx.VerifyBlobSidecar(tx.BlobSidecar(), verifier); err != nil {
			return err
		}
	}
	return nil
}
