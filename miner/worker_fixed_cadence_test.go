package miner

import (
	"math/big"
	"testing"
	"time"

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
