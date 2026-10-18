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

func TestFHSProposalSlotTime(t *testing.T) {
	config := &params.ChainConfig{FairHotstuff: true, FairHotstuffSlotMillis: 250}
	now := time.Unix(1_700_000_000, 499_999_999)
	current := uint64(1_700_000_000*4 + 1)
	for _, test := range []struct {
		name       string
		parentSlot uint64
		want       uint64
		wantFuture bool
	}{
		{"old parent skips idle slots", current - 100, current, false},
		{"same-second successor", current, current + 1, false},
		{"skewed parent", current + 30, current + 31, false},
		{"last allowed slot", current + 1199, current + 1200, false},
		{"exhausted future allowance", current + 1200, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := new(types.Header)
			parent.SetFHSSlot(test.parentSlot)
			timestamp, extra, err := nextProposalTime(config, parent, now)
			if test.wantFuture {
				if !errors.Is(err, consensus.ErrFutureBlock) || !shouldRetryFHSProposalBuild(err) || timestamp != 0 || extra != nil {
					t.Fatalf("slot allowance must fail with retryable future error: time=%d extra=%x error=%v", timestamp, extra, err)
				}
				return
			}
			header := &types.Header{Time: timestamp, Extra: extra}
			slot, slotErr := header.FHSSlot()
			if err != nil || slotErr != nil || slot != test.want || timestamp != test.want/4 {
				t.Fatalf("proposal slot=%d timestamp=%d error=%v/%v; want slot=%d", slot, timestamp, err, slotErr, test.want)
			}
		})
	}
}

func TestFHSProposalSlotBurstRetriesAfterQuarterSecond(t *testing.T) {
	config := &params.ChainConfig{FairHotstuff: true, FairHotstuffSlotMillis: 250}
	now := time.Unix(1_700_000_000, 0)
	parent := new(types.Header)
	parent.SetFHSSlot(uint64(now.Unix()) * 4)
	for block := 0; block < 1200; block++ {
		timestamp, extra, err := nextProposalTime(config, parent, now)
		if err != nil {
			t.Fatalf("burst block %d: %v", block, err)
		}
		parent = &types.Header{Time: timestamp, Extra: extra}
	}
	if _, _, err := nextProposalTime(config, parent, now); !errors.Is(err, consensus.ErrFutureBlock) {
		t.Fatalf("exhausted slot allowance should return future-block error: %v", err)
	}
	timestamp, extra, err := nextProposalTime(config, parent, now.Add(250*time.Millisecond))
	if err != nil {
		t.Fatalf("quarter-second advance did not allow retry: %v", err)
	}
	slot, err := (&types.Header{Time: timestamp, Extra: extra}).FHSSlot()
	if err != nil || slot != uint64(now.Unix())*4+1201 {
		t.Fatalf("unexpected successor slot after retry: %d error=%v", slot, err)
	}
}

func TestFHSCreateWorkRejectsInvalidSlotBeforeStateWork(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*types.Header)
	}{
		{"missing slot", func(h *types.Header) { h.Extra = nil }},
		{"inconsistent seconds", func(h *types.Header) { h.SetFHSSlot(4); h.Time++ }},
		{"slot overflow", func(h *types.Header) { h.SetFHSSlot(math.MaxUint64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, _ := newPrevRandaoProposalFixture(t)
			service.config = &params.ChainConfig{FairHotstuff: true, FairHotstuffSlotMillis: 250}
			test.mutate(service.bc.CurrentBlock().Header0())
			for _, blockType := range []uint8{types.Key_Block, types.FastTx_Block, types.SlowTx_Block} {
				if work, err := service.createWork(blockType); err == nil || work != nil {
					t.Fatalf("invalid parent type %d reached state work: work=%v error=%v", blockType, work, err)
				}
			}
			if _, err := service.buildProposalNewKeyBlock(nil); err == nil {
				t.Fatal("key carrier builder did not propagate slot failure")
			}
		})
	}
}

func TestFHSProposalSlotDisabledPreservesLegacyTime(t *testing.T) {
	now := time.Unix(1_700_000_000, 750_000_000)
	parent := &types.Header{Time: uint64(now.Unix()), Extra: []byte{'F', 'H', 'S', 1}}
	for _, config := range []*params.ChainConfig{nil, {}, {FairHotstuff: true}} {
		timestamp, extra, err := nextProposalTime(config, parent, now)
		if err != nil || timestamp != parent.Time+1 || extra != nil {
			t.Fatalf("disabled slot mode changed legacy time/extra: time=%d extra=%x error=%v", timestamp, extra, err)
		}
	}
}
