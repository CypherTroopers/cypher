package types

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/cypherium/cypher/common"
	kzg "github.com/cypherium/cypher/crypto/kzg4844"
)

const (
	BlobCommitmentVersionKZG byte = 0x01

	// BlobSidecarVersion0 is the EIP-4844 pooled sidecar used through Prague.
	// It carries one whole-blob KZG proof for every blob.
	BlobSidecarVersion0 byte = 0
	// BlobSidecarVersion1 is the EIP-7594 pooled sidecar used from Osaka. It
	// carries a proof for every cell of every extended blob.
	BlobSidecarVersion1 byte = 1

	BlobCellProofsPerBlob = kzg.CellProofsPerBlob
)

type Blob []byte
type KZGCommitment [48]byte
type KZGProof [48]byte

type BlobTxSidecar struct {
	Version     byte
	Blobs       []Blob
	Commitments []KZGCommitment
	Proofs      []KZGProof
}

var (
	ErrBlobSidecarMissing            = errors.New("blob transaction sidecar missing")
	ErrBlobSidecarLengthMismatch     = errors.New("blob sidecar length mismatch")
	ErrBlobSidecarUnsupportedVersion = errors.New("unsupported blob sidecar version")
	ErrBlobSidecarVersionMismatch    = errors.New("blob sidecar version does not match active fork")
	ErrBlobVersionedHashMismatch     = errors.New("blob versioned hash mismatch")
)

func NewBlobTxSidecar(version byte, blobs []Blob, commitments []KZGCommitment, proofs []KZGProof) *BlobTxSidecar {
	return &BlobTxSidecar{Version: version, Blobs: blobs, Commitments: commitments, Proofs: proofs}
}

func BlobSidecarVersionForOsaka(osaka bool) byte {
	if osaka {
		return BlobSidecarVersion1
	}
	return BlobSidecarVersion0
}

func (s *BlobTxSidecar) ValidateShape() error {
	if s == nil {
		return ErrBlobSidecarMissing
	}
	if len(s.Blobs) != len(s.Commitments) {
		return ErrBlobSidecarLengthMismatch
	}
	wantProofs := len(s.Blobs)
	switch s.Version {
	case BlobSidecarVersion0:
	case BlobSidecarVersion1:
		if len(s.Blobs) > int(^uint(0)>>1)/BlobCellProofsPerBlob {
			return ErrBlobSidecarLengthMismatch
		}
		wantProofs *= BlobCellProofsPerBlob
	default:
		return fmt.Errorf("%w: %d", ErrBlobSidecarUnsupportedVersion, s.Version)
	}
	if len(s.Proofs) != wantProofs {
		return fmt.Errorf("%w: blobs=%d commitments=%d proofs=%d wantProofs=%d", ErrBlobSidecarLengthMismatch, len(s.Blobs), len(s.Commitments), len(s.Proofs), wantProofs)
	}
	return nil
}

func (s *BlobTxSidecar) ValidateVersion(version byte) error {
	if err := s.ValidateShape(); err != nil {
		return err
	}
	if s.Version != version {
		return fmt.Errorf("%w: have %d want %d", ErrBlobSidecarVersionMismatch, s.Version, version)
	}
	return nil
}

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
		Version:     s.Version,
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
	if err := s.ValidateShape(); err != nil {
		return err
	}
	if len(s.Blobs) != len(expected) || len(s.Commitments) != len(expected) {
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

func (tx *Transaction) ValidateBlobSidecarVersion(sidecar *BlobTxSidecar, version byte) error {
	if tx == nil || tx.Type() != BlobTxType {
		return nil
	}
	if err := sidecar.ValidateVersion(version); err != nil {
		return err
	}
	return sidecar.ValidateBlobCommitmentHashes(tx.BlobHashes())
}
