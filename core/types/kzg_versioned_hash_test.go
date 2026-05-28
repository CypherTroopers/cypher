package types

import (
	"crypto/sha256"
	"testing"

	kzg "github.com/cypherium/cypher/crypto/kzg4844"
)

func TestKZGToVersionedHashMatchesKZGBackend(t *testing.T) {
	_, commitment, _ := buildValidBlobTuple(t)

	var kc kzg.Commitment
	copy(kc[:], commitment[:])

	got := KZGToVersionedHash(commitment)
	want := kzg.CalcBlobHashV1(sha256.New(), &kc)
	if got != want {
		t.Fatalf("versioned hash mismatch: got %x want %x", got, want)
	}
}
