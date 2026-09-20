package miner

import (
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

func candidateTimestampTestKeyBlock(number, timestamp uint64, blockType uint8) *types.KeyBlock {
	return types.NewKeyBlock(&types.KeyBlockHeader{
		Number:     new(big.Int).SetUint64(number),
		Difficulty: big.NewInt(1),
		Time:       timestamp,
		BlockType:  blockType,
	})
}

func TestKeyBlockCandidateTimestampFixedModeIsExactWhenMiningStartsLate(t *testing.T) {
	parentTime := uint64(1_700_000_000)
	parent := candidateTimestampTestKeyBlock(1, parentTime, types.TimeReconfig)
	want := parentTime + uint64(params.KeyBlockMinInterval/time.Second)
	lateStart := time.Unix(int64(want+3600), 0)

	if got := keyBlockCandidateTimestamp(parent, lateStart, true); got != want {
		t.Fatalf("candidate timestamp = %d, want fixed slot %d", got, want)
	}
}

func TestKeyBlockCandidateTimestampZeroGenesisUsesMiningStartAnchor(t *testing.T) {
	genesis := candidateTimestampTestKeyBlock(0, 0, types.Initialization)
	startedAt := time.Unix(1_700_000_000, 0)
	if got := keyBlockCandidateTimestamp(genesis, startedAt, true); got != uint64(startedAt.Unix()) {
		t.Fatalf("bootstrap candidate timestamp = %d, want start anchor %d", got, startedAt.Unix())
	}
}

func TestKeyBlockCandidateTimestampNonFixedKeepsMinimumSemantics(t *testing.T) {
	parentTime := uint64(1_700_000_000)
	parent := candidateTimestampTestKeyBlock(1, parentTime, types.TimeReconfig)
	slot := parentTime + uint64(params.KeyBlockMinInterval/time.Second)
	earlyStart := time.Unix(int64(slot-60), 0)
	lateStart := time.Unix(int64(slot+60), 0)

	if got := keyBlockCandidateTimestamp(parent, earlyStart, false); got != slot {
		t.Fatalf("early non-fixed candidate timestamp = %d, want minimum %d", got, slot)
	}
	if got := keyBlockCandidateTimestamp(parent, lateStart, false); got != uint64(lateStart.Unix()) {
		t.Fatalf("late non-fixed candidate timestamp = %d, want start time %d", got, lateStart.Unix())
	}
}

type powRecipientTestBackend struct {
	Backend
	recipient func(common.Address) (common.Address, error)
}

func (b powRecipientTestBackend) PoWRewardRecipient(signer common.Address) (common.Address, error) {
	return b.recipient(signer)
}

func TestPoWCandidateRewardRecipient(t *testing.T) {
	a := common.HexToAddress("0xa1")
	b := common.HexToAddress("0xb1")
	parent := candidateTimestampTestKeyBlock(1, 1_700_000_000, types.TimeReconfig)
	registryErr := errors.New("unreadable reward registry")
	for _, test := range []struct {
		name       string
		config     params.ChainConfig
		configured bool
		lookupErr  error
		want       common.Address
		wantCalls  int
	}{
		{name: "fixed committee B", config: params.ChainConfig{FixedCommittee: true}, configured: true, want: b, wantCalls: 1},
		{name: "fixed leader B", config: params.ChainConfig{FixedLeader: true}, configured: true, want: b, wantCalls: 1},
		{name: "fixed committee unregistered A", config: params.ChainConfig{FixedCommittee: true}, want: a, wantCalls: 1},
		{name: "nonfixed keeps A", configured: true, want: a},
		{name: "nonfixed ignores unavailable registry", lookupErr: registryErr, want: a},
		{name: "fixed committee fails on registry error", config: params.ChainConfig{FixedCommittee: true}, lookupErr: registryErr, wantCalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			backend := powRecipientTestBackend{recipient: func(signer common.Address) (common.Address, error) {
				calls++
				if signer != a {
					t.Fatalf("registry signer = %s, want A", signer)
				}
				if test.lookupErr != nil {
					return common.Address{}, test.lookupErr
				}
				if test.configured {
					return b, nil
				}
				return signer, nil
			}}
			test.config.RnetPort = "7100"
			w := &worker{config: &test.config, coinBase: a, pubKey: []byte{1, 2, 3}, IP: []byte{127, 0, 0, 1}, eth: backend}
			w.mu.Lock()
			candidate, err := w.newCandidate(parent, 9, time.Unix(int64(parent.Time()), 0))
			w.mu.Unlock()
			if calls != test.wantCalls {
				t.Fatalf("registry calls = %d, want %d", calls, test.wantCalls)
			}
			if test.wantCalls != 0 && test.lookupErr != nil {
				if !errors.Is(err, registryErr) || candidate != nil {
					t.Fatalf("candidate/error = %v/%v, want no candidate and registry error", candidate, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if candidate.Coinbase != test.want.Hex() || w.coinBase != a || candidate.PubKey != common.HexString(w.pubKey) {
				t.Fatalf("recipient or mining identity changed incorrectly: candidate=%+v account=%s", candidate, w.coinBase)
			}
			if candidate.KeyCandidate.ParentHash != parent.Hash() || candidate.KeyCandidate.Number.Uint64() != 2 || candidate.KeyCandidate.T_Number != 9 || candidate.Port != 7100 {
				t.Fatalf("recipient selection changed candidate work identifiers: %+v", candidate)
			}
		})
	}
}

func TestPoWCandidateRecipientSnapshotSurvivesSettingChanges(t *testing.T) {
	a, b := common.HexToAddress("0xa1"), common.HexToAddress("0xb1")
	d, c := common.HexToAddress("0xd1"), common.HexToAddress("0xc1")
	recipients := map[common.Address]common.Address{a: b, d: common.HexToAddress("0xd2")}
	w := &worker{
		config: &params.ChainConfig{FixedCommittee: true, RnetPort: "7100"}, coinBase: a,
		eth: powRecipientTestBackend{recipient: func(signer common.Address) (common.Address, error) { return recipients[signer], nil }},
	}
	parent := candidateTimestampTestKeyBlock(1, 1_700_000_000, types.TimeReconfig)
	build := func() *types.Candidate {
		t.Helper()
		w.mu.Lock()
		defer w.mu.Unlock()
		candidate, err := w.newCandidate(parent, 9, time.Unix(int64(parent.Time()), 0))
		if err != nil {
			t.Fatal(err)
		}
		return candidate
	}
	first := build()
	firstHash := first.Hash()
	recipients[a] = c
	second := build()
	w.SetCoinbase(d)
	third := build()
	if first.Coinbase != b.Hex() || second.Coinbase != c.Hex() || third.Coinbase != recipients[d].Hex() {
		t.Fatalf("work templates did not retain independent recipients: %s, %s, %s", first.Coinbase, second.Coinbase, third.Coinbase)
	}
	if first.Hash() != firstHash || second.Hash() == firstHash {
		t.Fatal("recipient update mutated old work or was not encoded in the new candidate")
	}
}

func TestPoWCandidateConcurrentAccountChanges(t *testing.T) {
	a, d := common.HexToAddress("0xa1"), common.HexToAddress("0xd1")
	b, c := common.HexToAddress("0xb1"), common.HexToAddress("0xc1")
	w := &worker{
		config: &params.ChainConfig{FixedCommittee: true, RnetPort: "7100"}, coinBase: a,
		eth: powRecipientTestBackend{recipient: func(signer common.Address) (common.Address, error) {
			if signer == a {
				return b, nil
			}
			if signer == d {
				return c, nil
			}
			return common.Address{}, errors.New("unexpected signing account")
		}},
	}
	parent := candidateTimestampTestKeyBlock(1, 1_700_000_000, types.TimeReconfig)
	var setters sync.WaitGroup
	setters.Add(1)
	go func() {
		defer setters.Done()
		for i := 0; i < 100; i++ {
			w.SetCoinbase(d)
			w.SetCoinbase(a)
		}
	}()
	defer setters.Wait()
	for i := 0; i < 100; i++ {
		w.mu.Lock()
		candidate, err := w.newCandidate(parent, 9, time.Unix(int64(parent.Time()), 0))
		w.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if candidate.Coinbase != b.Hex() && candidate.Coinbase != c.Hex() {
			t.Fatalf("candidate has inconsistent account/recipient: %s", candidate.Coinbase)
		}
	}
}
