package types

import "errors"

type BlobVerifier interface {
	VerifyBlob(blob Blob, commitment KZGCommitment, proof KZGProof) error
}

type BlobCellProofVerifier interface {
	VerifyCellProofs(blobs []Blob, commitments []KZGCommitment, proofs []KZGProof) error
}

var (
	ErrBlobVerifierMissing          = errors.New("blob verifier missing")
	ErrBlobCellProofVerifierMissing = errors.New("blob cell-proof verifier missing")
)

func (s *BlobTxSidecar) VerifyBlobs(verifier BlobVerifier) error {
	if s == nil {
		return ErrBlobSidecarMissing
	}
	if verifier == nil {
		return ErrBlobVerifierMissing
	}
	if err := s.ValidateShape(); err != nil {
		return err
	}
	switch s.Version {
	case BlobSidecarVersion0:
		for i := range s.Blobs {
			if err := verifier.VerifyBlob(s.Blobs[i], s.Commitments[i], s.Proofs[i]); err != nil {
				return err
			}
		}
		return nil
	case BlobSidecarVersion1:
		cellVerifier, ok := verifier.(BlobCellProofVerifier)
		if !ok {
			return ErrBlobCellProofVerifierMissing
		}
		return cellVerifier.VerifyCellProofs(s.Blobs, s.Commitments, s.Proofs)
	default:
		return ErrBlobSidecarUnsupportedVersion
	}
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

func (tx *Transaction) VerifyBlobSidecarVersion(sidecar *BlobTxSidecar, version byte, verifier BlobVerifier) error {
	if tx == nil || tx.Type() != BlobTxType {
		return nil
	}
	if err := tx.ValidateBlobSidecarVersion(sidecar, version); err != nil {
		return err
	}
	return sidecar.VerifyBlobs(verifier)
}
