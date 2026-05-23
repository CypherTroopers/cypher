package types

import (
	"crypto/sha256"
	"errors"

	"github.com/cypherium/cypher/common"
)

const (
	BlobCommitmentVersionKZG byte = 0x01
)

type Blob []byte
type KZGCommitment [48]byte
type KZGProof [48]byte

type BlobTxSidecar struct {
	Blobs       []Blob
	Commitments []KZGCommitment
	Proofs      []KZGProof
}

var (
	ErrBlobSidecarMissing        = errors.New("blob transaction sidecar missing")
	ErrBlobSidecarLengthMismatch = errors.New("blob sidecar length mismatch")
	ErrBlobVersionedHashMismatch = errors.New("blob versioned hash mismatch")
)

func KZGToVersionedHash(commitment KZGCommitment) common.Hash {
	digest := sha256.Sum256(commitment[:])
	var h common.Hash
	copy(h[:], digest[:])
	h[0] = BlobCommitmentVersionKZG
	return h
}

func (s *BlobTxSidecar) Copy() *BlobTxSidecar {
	if s == nil {
		return nil
	}
	cpy := &BlobTxSidecar{
		Commitments: append([]KZGCommitment(nil), s.Commitments...),
		Proofs:      append([]KZGProof(nil), s.Proofs...),
	}
	if len(s.Blobs) > 0 {
		cpy.Blobs = make([]Blob, len(s.Blobs))
		for i, blob := range s.Blobs {
			cpy.Blobs[i] = append(Blob(nil), blob...)
		}
	}
	return cpy
}

func (s *BlobTxSidecar) BlobHashes() []common.Hash {
	if s == nil || len(s.Commitments) == 0 {
		return nil
	}
	hashes := make([]common.Hash, len(s.Commitments))
	for i, commitment := range s.Commitments {
		hashes[i] = KZGToVersionedHash(commitment)
	}
	return hashes
}

func (s *BlobTxSidecar) VersionedHashes() []common.Hash {
	return s.BlobHashes()
}

func (s *BlobTxSidecar) ValidateBlobCommitmentHashes(expected []common.Hash) error {
	if s == nil {
		return ErrBlobSidecarMissing
	}
	if len(s.Blobs) != len(expected) || len(s.Commitments) != len(expected) || len(s.Proofs) != len(expected) {
		return ErrBlobSidecarLengthMismatch
	}
	actual := s.BlobHashes()
	for i := range expected {
		if actual[i] != expected[i] {
			return ErrBlobVersionedHashMismatch
		}
	}
	return nil
}

func (s *BlobTxSidecar) ValidateBlobHashes(expected []common.Hash) error {
	return s.ValidateBlobCommitmentHashes(expected)
}

func (tx *Transaction) ValidateBlobSidecar(sidecar *BlobTxSidecar) error {
	if tx == nil || tx.Type() != BlobTxType {
		return nil
	}
	return sidecar.ValidateBlobCommitmentHashes(tx.BlobHashes())
}
