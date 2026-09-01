package reconfig

import (
	"math/big"
	"testing"
	"time"

	"github.com/cypherium/cypher/core/types"
)

func TestFixedModeKeyblockViewStartZeroGenesisUsesNow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	genesis := types.NewKeyBlock(&types.KeyBlockHeader{
		Number:     new(big.Int),
		Difficulty: big.NewInt(1),
		Time:       0,
		BlockType:  types.Initialization,
	})
	if got := fixedModeKeyblockViewStartFromHeads(now, time.Unix(0, 0), genesis); !got.Equal(now) {
		t.Fatalf("bootstrap view start = %s, want %s", got, now)
	}
}

func TestKeyProposalPlanFixedModeIsIntervalDerived(t *testing.T) {
	tests := []struct {
		name            string
		leaderIndex     uint
		noDone          bool
		intervalElapsed bool
		wantAttempt     bool
	}{
		{
			name:            "due while local view says transaction proposal",
			leaderIndex:     0,
			noDone:          true,
			intervalElapsed: true,
			wantAttempt:     true,
		},
		{
			name:            "due while local view says key proposal",
			leaderIndex:     3,
			noDone:          false,
			intervalElapsed: true,
			wantAttempt:     true,
		},
		{
			name:            "not due",
			leaderIndex:     3,
			noDone:          false,
			intervalElapsed: false,
			wantAttempt:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attempt, isDone := keyProposalPlan(true, tt.leaderIndex, tt.noDone, tt.intervalElapsed)
			if attempt != tt.wantAttempt {
				t.Fatalf("attempt = %t, want %t", attempt, tt.wantAttempt)
			}
			if !isDone {
				t.Fatal("fixed-mode key proposal must use TimeReconfig isDone semantics")
			}
		})
	}
}

func TestKeyProposalPlanNonFixedPreservesLegacySelection(t *testing.T) {
	tests := []struct {
		name            string
		leaderIndex     uint
		noDone          bool
		intervalElapsed bool
		wantAttempt     bool
		wantIsDone      bool
	}{
		{
			name:            "ordinary leader does not propose key block",
			leaderIndex:     0,
			noDone:          true,
			intervalElapsed: true,
			wantAttempt:     false,
			wantIsDone:      false,
		},
		{
			name:            "key leader waits for minimum interval",
			leaderIndex:     1,
			noDone:          false,
			intervalElapsed: false,
			wantAttempt:     false,
			wantIsDone:      true,
		},
		{
			name:            "key leader proposes after minimum interval",
			leaderIndex:     1,
			noDone:          false,
			intervalElapsed: true,
			wantAttempt:     true,
			wantIsDone:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attempt, isDone := keyProposalPlan(false, tt.leaderIndex, tt.noDone, tt.intervalElapsed)
			if attempt != tt.wantAttempt {
				t.Fatalf("attempt = %t, want %t", attempt, tt.wantAttempt)
			}
			if isDone != tt.wantIsDone {
				t.Fatalf("isDone = %t, want %t", isDone, tt.wantIsDone)
			}
		})
	}
}
