package reconfig

import (
	"math/big"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

func fixedCadenceTestKeyBlock(timestamp uint64) *types.KeyBlock {
	return types.NewKeyBlock(&types.KeyBlockHeader{
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(1),
		Time:       timestamp,
	})
}

func TestVerifyKeyBlockIntervalFixedCadence(t *testing.T) {
	parentTime := uint64(1_700_000_000)
	slot := parentTime + uint64(params.KeyBlockMinInterval/time.Second)
	parent := fixedCadenceTestKeyBlock(parentTime)

	for _, test := range []struct {
		name      string
		timestamp uint64
		wantError bool
	}{
		{name: "exact slot", timestamp: slot},
		{name: "too early", timestamp: slot - 1, wantError: true},
		{name: "too late", timestamp: slot + 1, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := verifyKeyBlockInterval(fixedCadenceTestKeyBlock(test.timestamp), parent, true)
			if test.wantError && err == nil {
				t.Fatalf("fixed timestamp %d accepted, want exact slot %d", test.timestamp, slot)
			}
			if !test.wantError && err != nil {
				t.Fatalf("exact fixed timestamp rejected: %v", err)
			}
		})
	}
}

func TestVerifyFixedKeyBlockRejectsSlotTooFarAheadOfLocalClock(t *testing.T) {
	parentTime := uint64(1_700_000_000)
	slot := scheduledKeyBlockTimestamp(parentTime)
	parent := fixedCadenceTestKeyBlock(parentTime)
	child := fixedCadenceTestKeyBlock(slot)

	tooEarly := time.Unix(int64(slot), 0).Add(-fixedKeyBlockFutureClockSkew - time.Second)
	if err := verifyKeyBlockIntervalAt(child, parent, true, tooEarly); err == nil {
		t.Fatal("fixed slot more than the clock-skew window ahead was accepted")
	}
	boundary := time.Unix(int64(slot), 0).Add(-fixedKeyBlockFutureClockSkew)
	if err := verifyKeyBlockIntervalAt(child, parent, true, boundary); err != nil {
		t.Fatalf("fixed slot at the clock-skew boundary was rejected: %v", err)
	}
}

func TestVerifyKeyBlockIntervalNonFixedKeepsMinimumSemantics(t *testing.T) {
	parentTime := uint64(1_700_000_000)
	minimum := parentTime + uint64(params.KeyBlockMinInterval/time.Second)
	parent := fixedCadenceTestKeyBlock(parentTime)

	for _, test := range []struct {
		name      string
		timestamp uint64
		wantError bool
	}{
		{name: "minimum", timestamp: minimum},
		{name: "later", timestamp: minimum + 123},
		{name: "too early", timestamp: minimum - 1, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := verifyKeyBlockInterval(fixedCadenceTestKeyBlock(test.timestamp), parent, false)
			if test.wantError && err == nil {
				t.Fatalf("non-fixed timestamp %d accepted below minimum %d", test.timestamp, minimum)
			}
			if !test.wantError && err != nil {
				t.Fatalf("valid non-fixed timestamp rejected: %v", err)
			}
		})
	}
}

func TestFixedKeyBlockProposalTimestampIgnoresLateConstructionTime(t *testing.T) {
	parentTime := uint64(1_700_000_000)
	slot := parentTime + uint64(params.KeyBlockMinInterval/time.Second)
	lateNow := slot + 146

	if got := keyBlockProposalTimestamp(parentTime, lateNow, true); got != slot {
		t.Fatalf("fixed proposal timestamp = %d, want slot %d", got, slot)
	}
	if got := keyBlockProposalTimestamp(parentTime, lateNow, false); got != lateNow {
		t.Fatalf("non-fixed proposal timestamp = %d, want construction time %d", got, lateNow)
	}
}

func TestZeroTimestampGenesisBootstrapsFixedCadenceAnchor(t *testing.T) {
	genesis := types.NewKeyBlock(&types.KeyBlockHeader{
		Number:     new(big.Int),
		Difficulty: big.NewInt(1),
		Time:       0,
		BlockType:  types.Initialization,
	})
	proposalTime := uint64(1_700_000_000)
	if fixedKeyBlockCadenceApplies(genesis, true) {
		t.Fatal("zero-timestamp genesis unexpectedly enabled the 1970 cadence")
	}
	if got := keyBlockProposalTimestamp(genesis.Time(), proposalTime, fixedKeyBlockCadenceApplies(genesis, true)); got != proposalTime {
		t.Fatalf("bootstrap timestamp = %d, want proposal anchor %d", got, proposalTime)
	}
	bootstrap := fixedCadenceTestKeyBlock(proposalTime)
	if err := verifyKeyBlockInterval(bootstrap, genesis, true); err != nil {
		t.Fatalf("bootstrap keyblock rejected: %v", err)
	}
	farFuture := fixedCadenceTestKeyBlock(proposalTime + uint64(fixedKeyBlockFutureClockSkew/time.Second) + 1)
	if err := verifyKeyBlockIntervalAt(farFuture, genesis, true, time.Unix(int64(proposalTime), 0)); err == nil {
		t.Fatal("bootstrap anchor beyond the clock-skew window was accepted")
	}
	if err := verifyKeyBlockInterval(fixedCadenceTestKeyBlock(599), genesis, true); err == nil {
		t.Fatal("bootstrap keyblock below the legacy minimum was accepted")
	}
	if !fixedKeyBlockCadenceApplies(bootstrap, true) {
		t.Fatal("first committed keyblock did not activate fixed cadence")
	}
	nextSlot := scheduledKeyBlockTimestamp(bootstrap.Time())
	if err := verifyKeyBlockInterval(fixedCadenceTestKeyBlock(nextSlot+1), bootstrap, true); err == nil {
		t.Fatal("post-bootstrap keyblock outside the exact slot was accepted")
	}
}

func TestFixedCadenceBootstrapPredicateIsNarrow(t *testing.T) {
	tests := []struct {
		name      string
		number    uint64
		timestamp uint64
		blockType uint8
	}{
		{name: "nonzero genesis timestamp", timestamp: 1, blockType: types.Initialization},
		{name: "non-genesis number", number: 1, blockType: types.Initialization},
		{name: "non-initialization type", blockType: types.TimeReconfig},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parent := types.NewKeyBlock(&types.KeyBlockHeader{
				Number:     new(big.Int).SetUint64(test.number),
				Difficulty: big.NewInt(1),
				Time:       test.timestamp,
				BlockType:  test.blockType,
			})
			if !fixedKeyBlockCadenceApplies(parent, true) {
				t.Fatal("bootstrap exception applied outside zero-time Initialization genesis")
			}
		})
	}
}

func TestFixedModeRewardCandidateRequiresExactSlotWithoutMutation(t *testing.T) {
	slot := uint64(1_700_000_600)
	exact := &types.Candidate{KeyCandidate: &types.KeyBlockHeader{Time: slot}}
	if got := fixedModeRewardCandidateForSlot(exact, slot); got != exact {
		t.Fatal("exact-slot reward candidate was omitted")
	}

	wrong := &types.Candidate{KeyCandidate: &types.KeyBlockHeader{Time: slot + 1}}
	if got := fixedModeRewardCandidateForSlot(wrong, slot); got != nil {
		t.Fatal("wrong-slot reward candidate was retained")
	}
	if wrong.KeyCandidate.Time != slot+1 {
		t.Fatalf("wrong-slot candidate timestamp mutated to %d", wrong.KeyCandidate.Time)
	}

	if got := fixedModeRewardCandidateForSlot(nil, slot); got != nil {
		t.Fatal("nil reward candidate became non-nil")
	}
	if got := fixedModeRewardCandidateForSlot(&types.Candidate{}, slot); got != nil {
		t.Fatal("candidate without a key header was retained")
	}
}

func TestBestFixedModeRewardCandidateFiltersBeforeNonceRanking(t *testing.T) {
	parentHash := common.HexToHash("0x1234")
	number := uint64(7)
	slot := uint64(1_700_000_600)
	candidate := func(hash common.Hash, timestamp, nonce uint64) *types.Candidate {
		return &types.Candidate{KeyCandidate: &types.KeyBlockHeader{
			ParentHash: hash,
			Number:     new(big.Int).SetUint64(number),
			Time:       timestamp,
			Nonce:      types.EncodeNonce(nonce),
		}}
	}

	wrongSlotLowerNonce := candidate(parentHash, slot+1, 1)
	wrongParentLowerNonce := candidate(common.HexToHash("0xbeef"), slot, 2)
	exactSlot := candidate(parentHash, slot, 3)
	got := bestFixedModeRewardCandidateForSlot(
		[]*types.Candidate{wrongSlotLowerNonce, wrongParentLowerNonce, exactSlot},
		parentHash, number, slot,
	)
	if got != exactSlot {
		t.Fatalf("best exact-slot candidate = %p, want %p", got, exactSlot)
	}
}
