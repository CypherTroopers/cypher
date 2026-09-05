package reconfig

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

func TestFHSProposalTimestamp(t *testing.T) {
	config := &params.ChainConfig{FairHotstuff: true}
	now := time.Unix(1_700_000_000, 0)
	for _, test := range []struct {
		name       string
		parentTime uint64
		want       uint64
		wantError  bool
	}{
		{"old parent", 1_699_999_999, 1_700_000_000, false},
		{"same second", 1_700_000_000, 1_700_000_001, false},
		{"clock skew or burst", 1_700_000_030, 1_700_000_031, false},
		{"last allowed second", 1_700_000_299, 1_700_000_300, false},
		{"window exhausted", 1_700_000_300, 0, true},
		{"signed integer overflow", uint64(math.MaxInt64) + 1, 0, true},
		{"unsigned overflow", math.MaxUint64, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := nextProposalTimestamp(config, test.parentTime, now)
			if test.wantError {
				if err == nil || got != 0 {
					t.Fatalf("invalid parent timestamp produced proposal timestamp %d, error %v", got, err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("proposal timestamp = %d, error %v; want %d", got, err, test.want)
			}
		})
	}
}

func TestFHSProposalTimestampBurstRetriesAfterClockAdvances(t *testing.T) {
	config := &params.ChainConfig{FairHotstuff: true}
	now := time.Unix(1_700_000_000, 0)
	parentTime := uint64(now.Unix())
	// A short burst can advance block time once per block within the existing
	// five-minute allowance, without sleeping in proposal construction.
	for block := 0; block < 300; block++ {
		timestamp, err := nextProposalTimestamp(config, parentTime, now)
		if err != nil || timestamp != parentTime+1 {
			t.Fatalf("burst block %d: timestamp=%d error=%v", block, timestamp, err)
		}
		parentTime = timestamp
	}
	_, exhaustedErr := nextProposalTimestamp(config, parentTime, now)
	if !errors.Is(exhaustedErr, consensus.ErrFutureBlock) {
		t.Fatalf("exhausted allowance should return a future-block error: %v", exhaustedErr)
	}
	if !shouldRetryFHSProposalBuild(exhaustedErr) {
		t.Fatal("timestamp exhaustion suppressed the service's proposal retry")
	}
	timestamp, err := nextProposalTimestamp(config, parentTime, now.Add(time.Second))
	if err != nil || timestamp != parentTime+1 {
		t.Fatalf("clock advance did not allow the next proposal: timestamp=%d error=%v", timestamp, err)
	}
}

func TestFHSCreateWorkReturnsTimestampErrorBeforeStateWork(t *testing.T) {
	for _, parentTime := range []uint64{uint64(math.MaxInt64) + 1, math.MaxUint64} {
		service, _ := newPrevRandaoProposalFixture(t)
		service.config = &params.ChainConfig{FairHotstuff: true}
		service.bc.CurrentBlock().Header0().Time = parentTime
		// The fixture deliberately has no proposer backend or txpool. Invalid
		// time must return before dereferencing either or opening execution work.
		for _, blockType := range []uint8{types.Key_Block, types.FastTx_Block, types.SlowTx_Block} {
			work, err := service.createWork(blockType)
			if err == nil || work != nil {
				t.Fatalf("parent time %d type %d produced work instead of an error: work=%v error=%v", parentTime, blockType, work, err)
			}
		}
		if _, err := service.buildProposalNewKeyBlock(nil); err == nil {
			t.Fatal("key proposal builder did not propagate timestamp failure")
		}
	}
}
