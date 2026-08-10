package reconfig

import (
	"math/big"
	"testing"
	"time"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

func legacyTimeTestKeyBlock(number int64, timestamp uint64) *types.KeyBlock {
	return types.NewKeyBlock(&types.KeyBlockHeader{
		Number:     big.NewInt(number),
		Difficulty: big.NewInt(1),
		Time:       timestamp,
	})
}

func TestVerifyKeyBlockLegacyTimeBoundaries(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	parent := legacyTimeTestKeyBlock(9, uint64(now.Unix()))
	minimum := parent.Time() + uint64(params.KeyBlockMinInterval/time.Second)
	maximum := uint64(now.Unix()) + uint64(params.LegacyKeyTimeMaxFuture/time.Second)

	tests := []struct {
		name      string
		timestamp uint64
		wantErr   bool
	}{
		{name: "below minimum", timestamp: minimum - 1, wantErr: true},
		{name: "worker minimum", timestamp: minimum},
		{name: "future upper boundary", timestamp: maximum},
		{name: "far future", timestamp: maximum + 1, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			child := legacyTimeTestKeyBlock(10, test.timestamp)
			err := verifyKeyBlockLegacyFutureAt(child, now)
			if err == nil {
				err = verifyKeyBlockMinInterval(child, parent)
			}
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestVerifyKeyBlockMinIntervalRejectsOverflowingParent(t *testing.T) {
	parent := legacyTimeTestKeyBlock(9, ^uint64(0))
	child := legacyTimeTestKeyBlock(10, ^uint64(0))
	if err := verifyKeyBlockMinInterval(child, parent); err == nil {
		t.Fatal("overflowing parent timestamp was accepted")
	}
}

func TestVerifyKeyBlockLegacyFutureAtDoesNotApplyHeadRelativeRuleToKnownBlock(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	known := legacyTimeTestKeyBlock(9, uint64(now.Unix()))
	if err := verifyKeyBlockLegacyFutureAt(known, now); err != nil {
		t.Fatalf("wall-clock-valid known block rejected before known-block shortcut: %v", err)
	}
}

func TestVerifyCandidateLegacyFutureAtBoundary(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	maximum := uint64(now.Unix()) + uint64(params.LegacyKeyTimeMaxFuture/time.Second)
	candidate := &types.Candidate{KeyCandidate: &types.KeyBlockHeader{Time: maximum}}
	if err := verifyCandidateLegacyFutureAt(candidate, now); err != nil {
		t.Fatalf("upper-bound candidate rejected: %v", err)
	}
	candidate.KeyCandidate.Time++
	if err := verifyCandidateLegacyFutureAt(candidate, now); err == nil {
		t.Fatal("far-future candidate accepted at final KeyBlock boundary")
	}
}

func candidateBindingFixture(blockType uint8, rewardIdentity bool) (*types.KeyBlock, *types.KeyBlock, *types.Candidate) {
	parent := types.NewKeyBlock(&types.KeyBlockHeader{
		Number:     big.NewInt(9),
		Difficulty: big.NewInt(100),
		Time:       100,
	})
	candidate := &types.Candidate{
		KeyCandidate: &types.KeyBlockHeader{
			ParentHash: parent.Hash(),
			Difficulty: big.NewInt(200),
			Number:     big.NewInt(10),
			Time:       200,
			BlockType:  types.PowReconfig,
		},
		PubKey:   "candidate-public",
		Coinbase: "candidate-address",
	}
	header := types.CopyKeyBlockHeader(candidate.KeyCandidate)
	header.BlockType = blockType
	block := types.NewKeyBlock(header)
	if rewardIdentity {
		block = block.WithBody("in-public", "in-address", candidate.PubKey, candidate.Coinbase, "leader-public", "leader-address")
	} else {
		block = block.WithBody(candidate.PubKey, candidate.Coinbase, "outer-public", "outer-address", "leader-public", "leader-address")
	}
	return parent, block, candidate
}

func TestVerifyKeyBlockCandidateBindingModes(t *testing.T) {
	parent, dynamic, candidate := candidateBindingFixture(types.PowReconfig, false)
	if err := verifyKeyBlockCandidateBinding(dynamic, parent, candidate, false); err != nil {
		t.Fatalf("valid dynamic PoW binding rejected: %v", err)
	}
	if err := verifyKeyBlockCandidateBinding(dynamic, parent, candidate, true); err == nil {
		t.Fatal("dynamic PoW reconfiguration accepted in fixed mode")
	}

	parent, fixedReward, candidate := candidateBindingFixture(types.TimeReconfig, true)
	originalType := candidate.KeyCandidate.BlockType
	if err := verifyKeyBlockCandidateBinding(fixedReward, parent, candidate, true); err != nil {
		t.Fatalf("valid fixed-mode reward binding rejected: %v", err)
	}
	if candidate.KeyCandidate.BlockType != originalType {
		t.Fatal("candidate binding mutated the pooled candidate header")
	}
	if err := verifyKeyBlockCandidateBinding(fixedReward, parent, nil, true); err == nil {
		t.Fatal("unproven fixed-mode reward identity was accepted")
	}
	if err := verifyKeyBlockCandidateBinding(fixedReward, parent, candidate, false); err == nil {
		t.Fatal("candidate-bearing Time block was accepted outside fixed mode")
	}
}

func TestVerifyKeyBlockCandidateBindingNoCandidateRules(t *testing.T) {
	parent := legacyTimeTestKeyBlock(9, 100)
	header := &types.KeyBlockHeader{
		ParentHash: parent.Hash(),
		Difficulty: parent.Difficulty(),
		Number:     big.NewInt(10),
		Time:       200,
		BlockType:  types.TimeReconfig,
	}
	valid := types.NewKeyBlock(header).WithBody("in-public", "in-address", "", "", "leader-public", "leader-address")
	if err := verifyKeyBlockCandidateBinding(valid, parent, nil, true); err != nil {
		t.Fatalf("valid no-candidate Time block rejected: %v", err)
	}

	changedDifficulty := valid.CopyMe()
	changedDifficulty.SetDifficulty(big.NewInt(2))
	if err := verifyKeyBlockCandidateBinding(changedDifficulty, parent, nil, true); err == nil {
		t.Fatal("no-candidate Time block changed parent difficulty")
	}

	partialReward := types.NewKeyBlock(header).WithBody("in-public", "in-address", "", "unproven-address", "leader-public", "leader-address")
	if err := verifyKeyBlockCandidateBinding(partialReward, parent, nil, true); err == nil {
		t.Fatal("partial unproven reward identity was accepted")
	}
}

func TestKeyBlockBodiesEqualRejectsAlternateBodyUnderSameHeader(t *testing.T) {
	header := &types.KeyBlockHeader{
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(10),
		BlockType:  types.TimeReconfig,
	}
	stored := types.NewKeyBlock(header).WithBody("in-public", "in-address", "", "", "leader-public", "leader-address")
	if !keyBlockBodiesEqual(stored, stored.CopyMe()) {
		t.Fatal("identical key block body was not recognized")
	}
	alternate := types.NewKeyBlock(header).WithBody("in-public", "in-address", "", "attacker-address", "leader-public", "leader-address")
	if stored.Hash() != alternate.Hash() {
		t.Fatal("test requires the legacy header-only key block hash")
	}
	if keyBlockBodiesEqual(stored, alternate) {
		t.Fatal("alternate body under the same key block header was accepted")
	}
}
