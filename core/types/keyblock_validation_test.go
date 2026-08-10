package types

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/rlp"
)

func validTestKeyBlockHeader() *KeyBlockHeader {
	return &KeyBlockHeader{
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(1),
		BlockType:  TimeReconfig,
	}
}

func TestKeyBlockValidateBasicRejectsMissingRequiredFields(t *testing.T) {
	tests := []struct {
		name  string
		block *KeyBlock
	}{
		{name: "nil block"},
		{name: "nil header", block: &KeyBlock{}},
		{name: "nil number", block: &KeyBlock{header: &KeyBlockHeader{Difficulty: big.NewInt(1)}}},
		{name: "nil difficulty", block: &KeyBlock{header: &KeyBlockHeader{Number: big.NewInt(1)}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.block.ValidateBasic(); err == nil {
				t.Fatal("expected malformed key block to be rejected")
			}
		})
	}
}

func TestKeyBlockDecodeRLPRejectsMalformedHeader(t *testing.T) {
	tests := []struct {
		name   string
		header *KeyBlockHeader
	}{
		{name: "nil header"},
		{name: "oversize number", header: func() *KeyBlockHeader {
			h := validTestKeyBlockHeader()
			h.Number = new(big.Int).Lsh(big.NewInt(1), 64)
			return h
		}()},
		{name: "oversize difficulty", header: func() *KeyBlockHeader {
			h := validTestKeyBlockHeader()
			h.Difficulty = new(big.Int).Lsh(big.NewInt(1), 256)
			return h
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := rlp.EncodeToBytes(extKeyblock{Header: test.header})
			if err != nil {
				// Some malformed pointer encodings are rejected before decode,
				// which is also an acceptable fail-closed result.
				return
			}
			if decoded := DecodeToKeyBlock(encoded); decoded != nil {
				t.Fatal("expected malformed encoded key block to be rejected")
			}
		})
	}
}

func TestKeyBlockDecodeRLPRoundTripValidHeader(t *testing.T) {
	want := NewKeyBlock(validTestKeyBlockHeader()).WithBody("in-pub", "in-address", "", "", "leader-pub", "leader-address")
	encoded, err := rlp.EncodeToBytes(want)
	if err != nil {
		t.Fatalf("encode valid key block: %v", err)
	}
	got := DecodeToKeyBlock(encoded)
	if got == nil {
		t.Fatal("valid key block was rejected")
	}
	if got.Hash() != want.Hash() || got.NumberU64() != want.NumberU64() || got.Difficulty().Cmp(want.Difficulty()) != 0 {
		t.Fatal("valid key block round trip changed header")
	}
	if decoded := DecodeToKeyBlock(append(encoded, 0x80)); decoded != nil {
		t.Fatal("key block decoder accepted trailing RLP data")
	}
}

func TestCandidateDecodeRejectsTrailingRLPData(t *testing.T) {
	candidate := &Candidate{
		KeyCandidate: validTestKeyBlockHeader(),
		IP:           []byte{127, 0, 0, 1},
		Port:         30303,
	}
	encoded, err := rlp.EncodeToBytes(candidate)
	if err != nil {
		t.Fatalf("encode candidate: %v", err)
	}
	if decoded := DecodeToCandidate(append(encoded, 0x80)); decoded != nil {
		t.Fatal("candidate decoder accepted trailing RLP data")
	}
}
