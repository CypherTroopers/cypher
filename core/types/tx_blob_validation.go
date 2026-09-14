package types

import (
	"errors"
	"math/big"

	"github.com/cypherium/cypher/params"
)

var (
	ErrBlobTxMissingBlobHashes      = errors.New("blob transaction missing blob versioned hashes")
	ErrBlobTxInvalidBlobHashVersion = errors.New("blob transaction invalid blob versioned hash version")
	ErrBlobTxTooManyBlobs           = errors.New("blob transaction exceeds max blob count")
	ErrBlobTxMissingFeeCap          = errors.New("blob transaction missing blob fee cap")
	ErrBlobTxInvalidFeeCap          = errors.New("blob transaction invalid blob fee cap")
)

// BlobGas returns the blob gas consumed by this transaction. Non-blob
// transactions consume zero blob gas.
func (tx *Transaction) BlobGas() uint64 {
	if tx == nil || tx.data == nil || tx.Type() != BlobTxType {
		return 0
	}
	return uint64(len(tx.BlobHashes())) * params.BlobTxBlobGasPerBlob
}

// BlobGasCost returns maxFeePerBlobGas * blobGas. Non-blob transactions return 0.
func (tx *Transaction) BlobGasCost() *big.Int {
	if tx == nil || tx.Type() != BlobTxType {
		return new(big.Int)
	}
	return new(big.Int).Mul(tx.BlobGasFeeCap(), new(big.Int).SetUint64(tx.BlobGas()))
}

// CostWithBlobGas returns the full upfront balance requirement including blob gas.
// Legacy/non-blob transactions are equivalent to Cost().
func (tx *Transaction) CostWithBlobGas() *big.Int {
	// Transaction.Cost already includes the blob fee cap for BlobTx.
	return tx.Cost()
}

// ValidateBlobTx performs EIP-4844 BlobTx surface validation without checking
// sidecars/proofs. Sidecar KZG proof verification is handled separately by a
// BlobVerifier.
func (tx *Transaction) ValidateBlobTx(maxBlobs int, blobBaseFee *big.Int) error {
	if tx == nil || tx.Type() != BlobTxType {
		return nil
	}
	hashes := tx.BlobHashes()
	if len(hashes) == 0 {
		return ErrBlobTxMissingBlobHashes
	}
	if maxBlobs > 0 && len(hashes) > maxBlobs {
		return ErrBlobTxTooManyBlobs
	}
	for _, hash := range hashes {
		if hash[0] != BlobCommitmentVersionKZG {
			return ErrBlobTxInvalidBlobHashVersion
		}
	}
	feeCap := tx.BlobGasFeeCap()
	if feeCap == nil {
		return ErrBlobTxMissingFeeCap
	}
	if feeCap.Sign() <= 0 {
		return ErrBlobTxInvalidFeeCap
	}
	if blobBaseFee != nil && feeCap.Cmp(blobBaseFee) < 0 {
		return ErrBlobTxInvalidFeeCap
	}
	return nil
}
