package types

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
)

func TestBlobTransactionPooledWrapperRoundTripKeepsExecutionIdentity(t *testing.T) {
	plain, sidecar := testBlockBlobSidecar(11)
	tx := plain.WithBlobSidecar(sidecar)
	canonical, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	plainCanonical, err := plain.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, plainCanonical) {
		t.Fatal("MarshalBinary included the attached blob sidecar")
	}
	if trieLeaf := (Transactions{tx}).GetRlp(0); !bytes.Equal(trieLeaf, canonical) {
		t.Fatal("transaction trie leaf included the pooled blob wrapper")
	}

	pooled, err := tx.MarshalPooledBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(pooled) == 0 || pooled[0] != BlobTxType || bytes.Equal(pooled, canonical) {
		t.Fatalf("invalid pooled type-3 wrapper: %x", pooled)
	}
	var decoded Transaction
	if err := decoded.UnmarshalBinary(pooled); err != nil {
		t.Fatal(err)
	}
	if decoded.BlobSidecar() == nil {
		t.Fatal("pooled wrapper did not attach its sidecar")
	}
	if decoded.Hash() != plain.Hash() {
		t.Fatal("pooled wrapper changed transaction identity")
	}
	if got, err := decoded.MarshalBinary(); err != nil || !bytes.Equal(got, canonical) {
		t.Fatalf("decoded canonical envelope = %x err %v, want %x", got, err, canonical)
	}
	if got, err := decoded.MarshalPooledBinary(); err != nil || !bytes.Equal(got, pooled) {
		t.Fatalf("pooled wrapper round trip = %x err %v, want %x", got, err, pooled)
	}

	embedded, err := rlp.EncodeToBytes(tx)
	if err != nil {
		t.Fatal(err)
	}
	var embeddedPayload []byte
	if err := rlp.DecodeBytes(embedded, &embeddedPayload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(embeddedPayload, canonical) {
		t.Fatal("block/trie transaction encoding used the pooled wrapper")
	}
}

func TestBlobTransactionCanonicalDecodeHasNoSidecar(t *testing.T) {
	tx, _ := testBlockBlobSidecar(12)
	canonical, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var decoded Transaction
	if err := decoded.UnmarshalBinary(canonical); err != nil {
		t.Fatal(err)
	}
	if decoded.BlobSidecar() != nil {
		t.Fatal("canonical execution envelope unexpectedly created a sidecar")
	}
}

func TestBlobTransactionOsakaPooledWrapperRoundTrip(t *testing.T) {
	plain, sidecar := testBlockBlobSidecar(21)
	sidecar.Version = BlobSidecarVersion1
	sidecar.Proofs = make([]KZGProof, BlobCellProofsPerBlob)
	tx := plain.WithBlobSidecar(sidecar)

	pooled, err := tx.MarshalPooledBinary()
	if err != nil {
		t.Fatal(err)
	}
	var fields []rlp.RawValue
	if err := rlp.DecodeBytes(pooled[1:], &fields); err != nil {
		t.Fatalf("decode Osaka pooled wrapper: %v", err)
	}
	if len(fields) != 5 {
		t.Fatalf("Osaka pooled wrapper has %d fields, want 5", len(fields))
	}
	var version byte
	if err := rlp.DecodeBytes(fields[1], &version); err != nil {
		t.Fatalf("decode Osaka wrapper version: %v", err)
	}
	if version != BlobSidecarVersion1 {
		t.Fatalf("Osaka wrapper version = %d, want %d", version, BlobSidecarVersion1)
	}

	var decoded Transaction
	if err := decoded.UnmarshalBinary(pooled); err != nil {
		t.Fatal(err)
	}
	got := decoded.BlobSidecar()
	if got == nil || got.Version != BlobSidecarVersion1 || len(got.Proofs) != BlobCellProofsPerBlob {
		t.Fatalf("decoded Osaka sidecar = %#v", got)
	}
	if decoded.Hash() != plain.Hash() {
		t.Fatal("Osaka pooled wrapper changed transaction identity")
	}
	if roundTrip, err := decoded.MarshalPooledBinary(); err != nil || !bytes.Equal(roundTrip, pooled) {
		t.Fatalf("Osaka pooled round trip mismatch: err=%v", err)
	}
}

func TestBlobTransactionPooledWrapperRejectsUnsupportedVersionAndProofCount(t *testing.T) {
	plain, sidecar := testBlockBlobSidecar(22)
	sidecar.Version = BlobSidecarVersion1
	sidecar.Proofs = make([]KZGProof, BlobCellProofsPerBlob-1)
	if _, err := plain.WithBlobSidecar(sidecar).MarshalPooledBinary(); !errors.Is(err, ErrBlobSidecarLengthMismatch) {
		t.Fatalf("cell proof count error = %v", err)
	}

	sidecar.Proofs = make([]KZGProof, BlobCellProofsPerBlob)
	sidecar.Version = 2
	if _, err := plain.WithBlobSidecar(sidecar).MarshalPooledBinary(); !errors.Is(err, ErrBlobSidecarUnsupportedVersion) {
		t.Fatalf("unsupported sidecar version error = %v", err)
	}

	execution := *plain.data.(*BlobTx).copy().(*BlobTx)
	execution.Sidecar = nil
	wrongWireVersion, err := rlp.EncodeToBytes(&blobTxPooledRLPV1{
		Tx: execution, WrapperVersion: BlobSidecarVersion0,
		Blobs: sidecar.Blobs, Commitments: sidecar.Commitments,
		CellProofs: make([]KZGProof, BlobCellProofsPerBlob),
	})
	if err != nil {
		t.Fatal(err)
	}
	var decoded Transaction
	if err := decoded.UnmarshalBinary(append([]byte{BlobTxType}, wrongWireVersion...)); !errors.Is(err, ErrBlobSidecarUnsupportedVersion) {
		t.Fatalf("wrong Osaka wire version error = %v", err)
	}

	tooMany := &BlobTxSidecar{Version: BlobSidecarVersion1}
	for i := 0; i < params.BlobTxMaxBlobs+1; i++ {
		tooMany.Blobs = append(tooMany.Blobs, sidecar.Blobs[0])
		tooMany.Commitments = append(tooMany.Commitments, sidecar.Commitments[0])
		tooMany.Proofs = append(tooMany.Proofs, make([]KZGProof, BlobCellProofsPerBlob)...)
	}
	if err := validateBlobSidecarWireShape(tooMany); !errors.Is(err, ErrBlobTxTooManyBlobs) {
		t.Fatalf("Osaka per-transaction blob limit error = %v", err)
	}
}

func TestBlobTransactionPooledWrapperRejectsMalformedData(t *testing.T) {
	plain, sidecar := testBlockBlobSidecar(13)
	tx := plain.WithBlobSidecar(sidecar)
	pooled, err := tx.MarshalPooledBinary()
	if err != nil {
		t.Fatal(err)
	}
	var decoded Transaction
	if err := decoded.UnmarshalBinary(append(append([]byte(nil), pooled...), 0x80)); err == nil {
		t.Fatal("pooled wrapper with trailing RLP was accepted")
	}

	inner := *plain.data.(*BlobTx).copy().(*BlobTx)
	missingProof, err := rlp.EncodeToBytes(&blobTxPooledRLP{
		Tx: inner, Blobs: sidecar.Blobs, Commitments: sidecar.Commitments,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.UnmarshalBinary(append([]byte{BlobTxType}, missingProof...)); !errors.Is(err, ErrBlobSidecarLengthMismatch) {
		t.Fatalf("missing proof error = %v", err)
	}

	short := sidecar.Copy()
	short.Blobs[0] = short.Blobs[0][:len(short.Blobs[0])-1]
	if _, err := plain.WithBlobSidecar(short).MarshalPooledBinary(); !errors.Is(err, ErrBlobSidecarInvalidBlobLength) {
		t.Fatalf("short blob error = %v", err)
	}

	wrongCommitment := sidecar.Copy()
	wrongCommitment.Commitments[0][0] ^= 1
	if _, err := plain.WithBlobSidecar(wrongCommitment).MarshalPooledBinary(); !errors.Is(err, ErrBlobVersionedHashMismatch) {
		t.Fatalf("commitment mismatch error = %v", err)
	}
}
