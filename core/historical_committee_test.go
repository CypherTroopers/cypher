package core

import (
	"testing"

	"github.com/cypherium/cypher/common"
)

func TestHistoricalCommitteeCheckpointFixtures(t *testing.T) {
	if len(historicalCommitteeCheckpoints) != 4 {
		t.Fatalf("checkpoint count have %d, want 4", len(historicalCommitteeCheckpoints))
	}
	var previousActivation uint64
	for i := range historicalCommitteeCheckpoints {
		checkpoint := &historicalCommitteeCheckpoints[i]
		if checkpoint.activationTx <= previousActivation {
			t.Fatalf("checkpoint %d activation %d is not increasing", checkpoint.keyBlock, checkpoint.activationTx)
		}
		previousActivation = checkpoint.activationTx

		encoded, committee, err := decodeHistoricalCommittee(checkpoint)
		if err != nil {
			t.Fatalf("checkpoint %d: %v", checkpoint.keyBlock, err)
		}
		if len(encoded) != checkpoint.encodedSize {
			t.Fatalf("checkpoint %d encoded size have %d, want %d", checkpoint.keyBlock, len(encoded), checkpoint.encodedSize)
		}
		if len(committee.List) != checkpoint.memberCount {
			t.Fatalf("checkpoint %d members have %d, want %d", checkpoint.keyBlock, len(committee.List), checkpoint.memberCount)
		}
		if committee.RlpHash() != checkpoint.committeeHash {
			t.Fatalf("checkpoint %d hash have %s, want %s", checkpoint.keyBlock, committee.RlpHash(), checkpoint.committeeHash)
		}

		if got := historicalCommitteeCheckpointFor(checkpoint.activationTx-1, checkpoint.keyHash); got != nil {
			t.Fatalf("checkpoint %d selected before activation", checkpoint.keyBlock)
		}
		if got := historicalCommitteeCheckpointFor(checkpoint.activationTx, common.Hash{}); got != nil {
			t.Fatalf("checkpoint %d selected for wrong key hash", checkpoint.keyBlock)
		}
		if got := historicalCommitteeCheckpointFor(checkpoint.activationTx, checkpoint.keyHash); got != checkpoint {
			t.Fatalf("checkpoint %d not selected at activation", checkpoint.keyBlock)
		}
		if got := historicalCommitteeCheckpointFor(checkpoint.activationTx+1, checkpoint.keyHash); got != checkpoint {
			t.Fatalf("checkpoint %d not selected after activation", checkpoint.keyBlock)
		}
	}
}

func TestHistoricalCommitteeCheckpointRejectsCorruption(t *testing.T) {
	checkpoint := historicalCommitteeCheckpoints[0]
	checkpoint.encodedSHA256 = "00"
	if _, _, err := decodeHistoricalCommittee(&checkpoint); err == nil {
		t.Fatal("corrupt checkpoint metadata was accepted")
	}
}
