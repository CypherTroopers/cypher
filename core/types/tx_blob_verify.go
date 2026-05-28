package types

import "errors"

type BlobVerifier interface {
	VerifyBlob(blob Blob, commitment KZGCommitment, proof KZGProof) error
}

var ErrBlobVerifierMissing = errors.New("blob verifier missing")

func (s *BlobTxSidecar) VerifyBlobs(verifier BlobVerifier) error {
	if s == nil {
		return ErrBlobSidecarMissing
	}
	if verifier == nil {
		return ErrBlobVerifierMissing
	}
	if len(s.Blobs) != len(s.Commitments) || len(s.Blobs) != len(s.Proofs) {
		return ErrBlobSidecarLengthMismatch
	}
	for i := range s.Blobs {
		if err := verifier.VerifyBlob(s.Blobs[i], s.Commitments[i], s.Proofs[i]); err != nil {
			return err
		}
	}
	return nil
}

func (tx *Transaction) VerifyBlobSidecar(sidecar *BlobTxSidecar, verifier BlobVerifier) error {
	if tx == nil || tx.Type() != BlobTxType {
		return nil
	}
	if err := tx.ValidateBlobSidecar(sidecar); err != nil {
		return err
	}
	return sidecar.VerifyBlobs(verifier)
}
