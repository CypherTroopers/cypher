package eth

import (
	"math/big"
	"net"
	"testing"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/rlp"
)

const (
	handlerTestBLSPublicKey = "3912d236e16d97b70244a6c3f0693c8ff855bca8771b521bb3af948f0c682a15a8ca1a90265f7db37dacd2621e389c1cc8526eca9efd31a66e6ce6debdb1560b"
	handlerTestCoinbase     = "0x3555D2c2Af8ff75009F7dbFCF7de7Ed80F68588d"
)

func TestValidateCandidateMessageRejectsMalformedFields(t *testing.T) {
	valid := func() *types.Candidate {
		return &types.Candidate{
			KeyCandidate: &types.KeyBlockHeader{
				Number:     big.NewInt(1),
				Difficulty: big.NewInt(2),
			},
			IP:       net.ParseIP("127.0.0.1"),
			Port:     30303,
			PubKey:   handlerTestBLSPublicKey,
			Coinbase: handlerTestCoinbase,
		}
	}
	if err := validateCandidateMessage(valid()); err != nil {
		t.Fatalf("valid candidate rejected: %v", err)
	}
	tests := []struct {
		name      string
		candidate func() *types.Candidate
	}{
		{name: "nil candidate", candidate: func() *types.Candidate { return nil }},
		{name: "nil header", candidate: func() *types.Candidate { return &types.Candidate{} }},
		{name: "nil number", candidate: func() *types.Candidate {
			candidate := valid()
			candidate.KeyCandidate.Number = nil
			return candidate
		}},
		{name: "huge number", candidate: func() *types.Candidate {
			candidate := valid()
			candidate.KeyCandidate.Number = new(big.Int).Lsh(big.NewInt(1), 128)
			return candidate
		}},
		{name: "nil difficulty", candidate: func() *types.Candidate {
			candidate := valid()
			candidate.KeyCandidate.Difficulty = nil
			return candidate
		}},
		{name: "zero difficulty", candidate: func() *types.Candidate {
			candidate := valid()
			candidate.KeyCandidate.Difficulty = new(big.Int)
			return candidate
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateCandidateMessage(test.candidate()); err == nil {
				t.Fatal("malformed candidate was accepted")
			}
		})
	}
}

func TestValidateCandidateMessageRejectsRLPWithNilHeader(t *testing.T) {
	payload, err := rlp.EncodeToBytes(&types.Candidate{IP: net.ParseIP("127.0.0.1"), Port: 30303, PubKey: handlerTestBLSPublicKey, Coinbase: handlerTestCoinbase})
	if err != nil {
		t.Fatalf("encode malformed candidate: %v", err)
	}
	var decoded types.Candidate
	if err := rlp.DecodeBytes(payload, &decoded); err != nil {
		t.Fatalf("decode malformed candidate envelope: %v", err)
	}
	if err := validateCandidateMessage(&decoded); err == nil {
		t.Fatal("RLP candidate with nil header was accepted")
	}
}
