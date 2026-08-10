package core

import (
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

const (
	legacyTestBLSPublicKey = "3912d236e16d97b70244a6c3f0693c8ff855bca8771b521bb3af948f0c682a15a8ca1a90265f7db37dacd2621e389c1cc8526eca9efd31a66e6ce6debdb1560b"
	legacyTestCoinbase     = "0x3555D2c2Af8ff75009F7dbFCF7de7Ed80F68588d"
)

func candidateValidationFixture() (*types.KeyBlock, *types.Candidate, uint64) {
	keyBlock := types.NewKeyBlock(&types.KeyBlockHeader{
		Number:     big.NewInt(9),
		Difficulty: big.NewInt(100000),
		Time:       100,
		T_Number:   20,
	})
	candidate := types.NewCandidate(keyBlock.Hash(), big.NewInt(2), 10, 21, nil, net.ParseIP("127.0.0.1"), legacyTestBLSPublicKey, legacyTestCoinbase, 30303)
	candidate.KeyCandidate.Time = keyBlock.Time() + uint64(params.KeyBlockMinInterval/time.Second)
	return keyBlock, candidate, 21
}

func TestValidateLegacyCandidateIdentityAndEndpoint(t *testing.T) {
	_, candidate, _ := candidateValidationFixture()
	publicKey, err := ValidateLegacyCandidate(candidate)
	if err != nil {
		t.Fatalf("valid worker-compatible candidate rejected: %v", err)
	}
	if got := hex.EncodeToString(publicKey); got != legacyTestBLSPublicKey {
		t.Fatalf("decoded public key = %s, want %s", got, legacyTestBLSPublicKey)
	}
	for _, port := range []int{1, 65535} {
		_, boundary, _ := candidateValidationFixture()
		boundary.Port = port
		if _, err := ValidateLegacyCandidate(boundary); err != nil {
			t.Fatalf("valid port boundary %d rejected: %v", port, err)
		}
	}
	_, ipv6, _ := candidateValidationFixture()
	ipv6.IP = net.ParseIP("2001:db8::1")
	if _, err := ValidateLegacyCandidate(ipv6); err != nil {
		t.Fatalf("canonical IPv6 endpoint rejected: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*types.Candidate)
		wantErr error
	}{
		{name: "prefixed public key", mutate: func(candidate *types.Candidate) { candidate.PubKey = "0x" + candidate.PubKey }, wantErr: ErrCandidateIdentityInvalid},
		{name: "uppercase public key", mutate: func(candidate *types.Candidate) { candidate.PubKey = strings.ToUpper(candidate.PubKey) }, wantErr: ErrCandidateIdentityInvalid},
		{name: "invalid BLS point", mutate: func(candidate *types.Candidate) { candidate.PubKey = strings.Repeat("0", 128) }, wantErr: ErrCandidateIdentityInvalid},
		{name: "noncanonical BLS serialization", mutate: func(candidate *types.Candidate) { candidate.PubKey = strings.Repeat("ff", 64) }, wantErr: ErrCandidateIdentityInvalid},
		{name: "coinbase without prefix", mutate: func(candidate *types.Candidate) { candidate.Coinbase = candidate.Coinbase[2:] }, wantErr: ErrCandidateIdentityInvalid},
		{name: "coinbase without EIP-55 case", mutate: func(candidate *types.Candidate) { candidate.Coinbase = strings.ToLower(candidate.Coinbase) }, wantErr: ErrCandidateIdentityInvalid},
		{name: "four-byte IPv4", mutate: func(candidate *types.Candidate) { candidate.IP = net.IP{127, 0, 0, 1} }, wantErr: ErrCandidateEndpointInvalid},
		{name: "unspecified IP", mutate: func(candidate *types.Candidate) { candidate.IP = append(net.IP(nil), net.IPv6zero...) }, wantErr: ErrCandidateEndpointInvalid},
		{name: "zero port", mutate: func(candidate *types.Candidate) { candidate.Port = 0 }, wantErr: ErrCandidateEndpointInvalid},
		{name: "oversize port", mutate: func(candidate *types.Candidate) { candidate.Port = 65536 }, wantErr: ErrCandidateEndpointInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, candidate, _ := candidateValidationFixture()
			test.mutate(candidate)
			if _, err := ValidateLegacyCandidate(candidate); !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestLegacyCandidatePublicKeyInCommitteeUsesDecodedBytes(t *testing.T) {
	publicKey, err := hex.DecodeString(legacyTestBLSPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	committee := []*common.Cnode{{Public: strings.ToUpper(legacyTestBLSPublicKey)}}
	if !LegacyCandidatePublicKeyInCommittee(publicKey, committee) {
		t.Fatal("byte-identical committee public key was not detected")
	}
}

func TestCandidateLookupDedupeIsBoundToCanonicalParent(t *testing.T) {
	_, candidate, _ := candidateValidationFixture()
	lookup := &candidateLookup{all: map[common.Hash]*types.Candidate{candidate.Hash(): candidate}}
	if _, found := lookup.FindCandidate(candidate.KeyCandidate.Number, candidate.KeyCandidate.ParentHash, candidate.PubKey); !found {
		t.Fatal("exact candidate identity was not found")
	}
	reorgParent := common.HexToHash("0xdeadbeef")
	if _, found := lookup.FindCandidate(candidate.KeyCandidate.Number, reorgParent, candidate.PubKey); found {
		t.Fatal("candidate from a stale same-height parent suppressed re-mining on the canonical parent")
	}
}

func TestValidateCandidateAgainstHeadAtRejectsFarFuture(t *testing.T) {
	keyBlock, candidate, txHead := candidateValidationFixture()
	now := time.Unix(int64(keyBlock.Time()), 0)
	candidate.KeyCandidate.Time = uint64(now.Unix()) + uint64(params.LegacyKeyTimeMaxFuture/time.Second) + 1
	if err := validateCandidateAgainstHeadAt(candidate, keyBlock, txHead, now); !errors.Is(err, ErrCandidateTimeInvalid) {
		t.Fatalf("error = %v, want %v", err, ErrCandidateTimeInvalid)
	}
}

func TestVerifyCandidateForHeadAcceptsCanonicalCandidate(t *testing.T) {
	keyBlock, candidate, txHead := candidateValidationFixture()
	prepareCalls, verifyCalls := 0, 0
	err := verifyCandidateForHead(candidate, keyBlock, txHead, 7,
		func(expected *types.Candidate, committeeSize int) error {
			prepareCalls++
			if committeeSize != 7 {
				t.Fatalf("committee size = %d, want 7", committeeSize)
			}
			expected.KeyCandidate.Difficulty = big.NewInt(2)
			return nil
		},
		func(got *types.Candidate) error {
			verifyCalls++
			if got != candidate {
				t.Fatal("proof verifier received a different candidate")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("canonical candidate rejected: %v", err)
	}
	if prepareCalls != 1 || verifyCalls != 1 {
		t.Fatalf("prepare/verify calls = %d/%d, want 1/1", prepareCalls, verifyCalls)
	}
}

func TestVerifyCandidateForHeadRejectsCheapInvalidBeforePoW(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*types.Candidate)
		wantErr     error
		wantPrepare int
	}{
		{
			name: "nil header",
			mutate: func(candidate *types.Candidate) {
				candidate.KeyCandidate = nil
			},
			wantErr: ErrCandidateMalformed,
		},
		{
			name: "nil number",
			mutate: func(candidate *types.Candidate) {
				candidate.KeyCandidate.Number = nil
			},
			wantErr: ErrCandidateMalformed,
		},
		{
			name: "huge number",
			mutate: func(candidate *types.Candidate) {
				candidate.KeyCandidate.Number = new(big.Int).Lsh(big.NewInt(1), 128)
			},
			wantErr: ErrCandidateMalformed,
		},
		{
			name: "non canonical parent",
			mutate: func(candidate *types.Candidate) {
				candidate.KeyCandidate.ParentHash = common.HexToHash("0xdeadbeef")
			},
			wantErr: ErrCandidateParentMismatch,
		},
		{
			name: "not exact next key height",
			mutate: func(candidate *types.Candidate) {
				candidate.KeyCandidate.Number = big.NewInt(11)
			},
			wantErr: ErrCandidateNumberLow,
		},
		{
			name: "transaction number below key head",
			mutate: func(candidate *types.Candidate) {
				candidate.KeyCandidate.T_Number = 19
			},
			wantErr: ErrCandidateTxNumberInvalid,
		},
		{
			name: "transaction number ahead of tx head",
			mutate: func(candidate *types.Candidate) {
				candidate.KeyCandidate.T_Number = 22
			},
			wantErr: ErrCandidateTxNumberInvalid,
		},
		{
			name: "timestamp before minimum interval",
			mutate: func(candidate *types.Candidate) {
				candidate.KeyCandidate.Time--
			},
			wantErr: ErrCandidateTimeInvalid,
		},
		{
			name: "difficulty one mismatches canonical work",
			mutate: func(candidate *types.Candidate) {
				candidate.KeyCandidate.Difficulty = big.NewInt(1)
			},
			wantErr:     ErrCandidateDifficultyMismatch,
			wantPrepare: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keyBlock, candidate, txHead := candidateValidationFixture()
			test.mutate(candidate)
			prepareCalls, verifyCalls := 0, 0
			err := verifyCandidateForHead(candidate, keyBlock, txHead, 7,
				func(expected *types.Candidate, _ int) error {
					prepareCalls++
					expected.KeyCandidate.Difficulty = big.NewInt(2)
					return nil
				},
				func(*types.Candidate) error {
					verifyCalls++
					return nil
				},
			)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			if prepareCalls != test.wantPrepare {
				t.Fatalf("prepare calls = %d, want %d", prepareCalls, test.wantPrepare)
			}
			if verifyCalls != 0 {
				t.Fatalf("expensive proof verifier called %d times", verifyCalls)
			}
		})
	}
}

func TestVerifyCandidateForHeadMapsPoWFailure(t *testing.T) {
	keyBlock, candidate, txHead := candidateValidationFixture()
	err := verifyCandidateForHead(candidate, keyBlock, txHead, 7,
		func(expected *types.Candidate, _ int) error {
			expected.KeyCandidate.Difficulty = big.NewInt(2)
			return nil
		},
		func(*types.Candidate) error { return errors.New("bad seal") },
	)
	if !errors.Is(err, ErrCandidatePowVerificationFail) {
		t.Fatalf("error = %v, want %v", err, ErrCandidatePowVerificationFail)
	}
}
