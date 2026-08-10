package core

import (
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

func TestPoWResultUDPAddrFromCommitteeNodeSupportsIPv6(t *testing.T) {
	addr, err := powResultUDPAddrFromCommitteeNode(&common.Cnode{Address: "[2001:db8::20]:7102"}, 7103)
	if err != nil {
		t.Fatal(err)
	}
	if got := addr.String(); got != "[2001:db8::20]:7103" {
		t.Fatalf("addr = %q, want %q", got, "[2001:db8::20]:7103")
	}
}

func TestPoWResultUDPAddrFromCommitteeNodePreservesIPv4(t *testing.T) {
	addr, err := powResultUDPAddrFromCommitteeNode(&common.Cnode{Address: "192.0.2.20:7102"}, 7103)
	if err != nil {
		t.Fatal(err)
	}
	if got := addr.String(); got != "192.0.2.20:7103" {
		t.Fatalf("addr = %q, want %q", got, "192.0.2.20:7103")
	}
}

func TestValidateRemotePoWResultCandidateAcceptsCanonicalFixedResult(t *testing.T) {
	keyBlock, candidate, txHead := candidateValidationFixture()
	candidate.KeyCandidate.Difficulty = new(big.Int) // Filled locally after this boundary.
	now := time.Unix(int64(keyBlock.Time()), 0)
	if _, err := validateRemotePoWResultCandidate(candidate, keyBlock, txHead, nil, now); err != nil {
		t.Fatalf("canonical fixed PoW result rejected: %v", err)
	}
}

func TestValidatePoWResultWireRejectsPortBeforeIntConversion(t *testing.T) {
	if err := validatePoWResultWire(nil); !errors.Is(err, ErrCandidateMalformed) {
		t.Fatalf("nil result error = %v, want %v", err, ErrCandidateMalformed)
	}
	for _, port := range []uint64{1, 65535} {
		if err := validatePoWResultWire(&types.PoWResult{Port: port}); err != nil {
			t.Fatalf("valid wire port %d rejected: %v", port, err)
		}
	}
	for _, port := range []uint64{0, 65536, ^uint64(0)} {
		if err := validatePoWResultWire(&types.PoWResult{Port: port}); !errors.Is(err, ErrCandidateEndpointInvalid) {
			t.Fatalf("wire port %d error = %v, want %v", port, err, ErrCandidateEndpointInvalid)
		}
	}
}

func TestValidateRemotePoWResultCandidateRejectsBeforeDifficultyPreparation(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*types.Candidate)
		committee func(*types.Candidate) []*common.Cnode
		wantErr   error
	}{
		{name: "far future", mutate: func(candidate *types.Candidate) {
			candidate.KeyCandidate.Time = 100 + uint64(params.LegacyKeyTimeMaxFuture/time.Second) + 1
		}, wantErr: ErrCandidateTimeInvalid},
		{name: "uppercase public key", mutate: func(candidate *types.Candidate) {
			candidate.PubKey = strings.ToUpper(candidate.PubKey)
		}, wantErr: ErrCandidateIdentityInvalid},
		{name: "noncanonical IPv4", mutate: func(candidate *types.Candidate) {
			candidate.IP = net.IP{127, 0, 0, 1}
		}, wantErr: ErrCandidateEndpointInvalid},
		{name: "invalid port", mutate: func(candidate *types.Candidate) {
			candidate.Port = 0
		}, wantErr: ErrCandidateEndpointInvalid},
		{name: "committee member by decoded bytes", committee: func(candidate *types.Candidate) []*common.Cnode {
			return []*common.Cnode{{Public: strings.ToUpper(candidate.PubKey)}}
		}, wantErr: ErrCandidateIsMember},
		{name: "wrong parent", mutate: func(candidate *types.Candidate) {
			candidate.KeyCandidate.ParentHash = common.HexToHash("0x01")
		}, wantErr: ErrCandidateParentMismatch},
		{name: "wrong key height", mutate: func(candidate *types.Candidate) {
			candidate.KeyCandidate.Number = big.NewInt(11)
		}, wantErr: ErrCandidateNumberLow},
		{name: "tx number ahead", mutate: func(candidate *types.Candidate) {
			candidate.KeyCandidate.T_Number = 22
		}, wantErr: ErrCandidateTxNumberInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keyBlock, candidate, txHead := candidateValidationFixture()
			candidate.KeyCandidate.Difficulty = new(big.Int)
			if test.mutate != nil {
				test.mutate(candidate)
			}
			var committee []*common.Cnode
			if test.committee != nil {
				committee = test.committee(candidate)
			}
			now := time.Unix(int64(keyBlock.Time()), 0)
			if _, err := validateRemotePoWResultCandidate(candidate, keyBlock, txHead, committee, now); !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
		})
	}
}
