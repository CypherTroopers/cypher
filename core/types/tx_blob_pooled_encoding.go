package types

import (
	"errors"
	"fmt"

	kzg4844 "github.com/cypherium/cypher/crypto/kzg4844"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
)

var ErrBlobSidecarInvalidBlobLength = errors.New("blob sidecar contains an invalid blob length")

// blobTxPooledRLP is the EIP-4844 pooled transaction network wrapper used
// through Prague:
// rlp([tx_payload_body, blobs, commitments, proofs]). The leading 0x03 type
// byte is added outside this structure.
type blobTxPooledRLP struct {
	Tx          BlobTx
	Blobs       []Blob
	Commitments []KZGCommitment
	Proofs      []KZGProof
}

// blobTxPooledRLPV1 is the EIP-7594 pooled transaction network wrapper used
// from Osaka: rlp([tx_payload_body, wrapper_version, blobs, commitments,
// cell_proofs]). WrapperVersion is currently required to be 1.
type blobTxPooledRLPV1 struct {
	Tx             BlobTx
	WrapperVersion byte
	Blobs          []Blob
	Commitments    []KZGCommitment
	CellProofs     []KZGProof
}

func validateBlobSidecarWireShape(sidecar *BlobTxSidecar) error {
	if err := sidecar.ValidateShape(); err != nil {
		return err
	}
	if sidecar.Version == BlobSidecarVersion1 && len(sidecar.Blobs) > params.BlobTxMaxBlobs {
		return ErrBlobTxTooManyBlobs
	}
	blobSize := len(kzg4844.Blob{})
	for index, blob := range sidecar.Blobs {
		if len(blob) != blobSize {
			return fmt.Errorf("%w at index %d: have %d want %d", ErrBlobSidecarInvalidBlobLength, index, len(blob), blobSize)
		}
	}
	return nil
}

// MarshalPooledBinary encodes the EIP-4844 sidecar-bearing transaction wrapper
// used for transaction propagation. Non-blob transactions use their canonical
// wire encoding. BlobTx execution encoding, transaction hash, and trie leaves
// remain sidecar-free through MarshalBinary.
func (tx *Transaction) MarshalPooledBinary() ([]byte, error) {
	if tx == nil || tx.data == nil {
		return nil, fmt.Errorf("unsupported transaction inner type %T", nil)
	}
	if tx.Type() != BlobTxType {
		return tx.MarshalBinary()
	}
	inner, ok := tx.data.(*BlobTx)
	if !ok {
		return nil, fmt.Errorf("transaction type %d has inner type %T", BlobTxType, tx.data)
	}
	if err := validateTypedIntegerBounds(inner); err != nil {
		return nil, err
	}
	sidecar := inner.Sidecar
	if err := tx.ValidateBlobSidecar(sidecar); err != nil {
		return nil, err
	}
	if err := validateBlobSidecarWireShape(sidecar); err != nil {
		return nil, err
	}
	execution := *inner.copy().(*BlobTx)
	execution.Sidecar = nil
	switch sidecar.Version {
	case BlobSidecarVersion0:
		return encodeTypedEnvelope(BlobTxType, &blobTxPooledRLP{
			Tx: execution, Blobs: sidecar.Blobs, Commitments: sidecar.Commitments, Proofs: sidecar.Proofs,
		})
	case BlobSidecarVersion1:
		return encodeTypedEnvelope(BlobTxType, &blobTxPooledRLPV1{
			Tx: execution, WrapperVersion: sidecar.Version, Blobs: sidecar.Blobs,
			Commitments: sidecar.Commitments, CellProofs: sidecar.Proofs,
		})
	default:
		return nil, fmt.Errorf("%w: %d", ErrBlobSidecarUnsupportedVersion, sidecar.Version)
	}
}

func decodeBlobTypedPayload(payload []byte) (*BlobTx, error) {
	var execution BlobTx
	executionErr := decodeTypedPayload(payload, &execution)
	if executionErr == nil {
		if err := validateTypedIntegerBounds(&execution); err != nil {
			return nil, err
		}
		execution.Sidecar = nil
		return &execution, nil
	}

	content, rest, err := rlp.SplitList(payload)
	if err != nil {
		return nil, fmt.Errorf("invalid blob transaction payload: execution envelope: %v; pooled wrapper: %w", executionErr, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("invalid blob transaction payload: execution envelope: %v; pooled wrapper has %d trailing bytes", executionErr, len(rest))
	}
	fields, err := rlp.CountValues(content)
	if err != nil {
		return nil, fmt.Errorf("invalid blob transaction pooled wrapper: %w", err)
	}
	var pooledTx *BlobTx
	var sidecar *BlobTxSidecar
	switch fields {
	case 4:
		var pooled blobTxPooledRLP
		if err := rlp.DecodeBytes(payload, &pooled); err != nil {
			return nil, fmt.Errorf("invalid Prague blob transaction pooled wrapper: %w", err)
		}
		pooledTx = &pooled.Tx
		sidecar = NewBlobTxSidecar(BlobSidecarVersion0, pooled.Blobs, pooled.Commitments, pooled.Proofs)
	case 5:
		var pooled blobTxPooledRLPV1
		if err := rlp.DecodeBytes(payload, &pooled); err != nil {
			return nil, fmt.Errorf("invalid Osaka blob transaction pooled wrapper: %w", err)
		}
		if pooled.WrapperVersion != BlobSidecarVersion1 {
			return nil, fmt.Errorf("%w: %d", ErrBlobSidecarUnsupportedVersion, pooled.WrapperVersion)
		}
		pooledTx = &pooled.Tx
		sidecar = NewBlobTxSidecar(pooled.WrapperVersion, pooled.Blobs, pooled.Commitments, pooled.CellProofs)
	default:
		return nil, fmt.Errorf("invalid blob transaction pooled wrapper field count %d", fields)
	}
	if err := validateTypedIntegerBounds(pooledTx); err != nil {
		return nil, err
	}
	decoded := &Transaction{data: pooledTx}
	if err := decoded.ValidateBlobSidecar(sidecar); err != nil {
		return nil, err
	}
	if err := validateBlobSidecarWireShape(sidecar); err != nil {
		return nil, err
	}
	pooledTx.Sidecar = sidecar.Copy()
	return pooledTx, nil
}
