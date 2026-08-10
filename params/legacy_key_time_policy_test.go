package params

import (
	"testing"
	"time"
)

func TestLegacyCandidateTimestampPolicyBoundaries(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	parent := uint64(now.Unix())
	minimum := parent + uint64(KeyBlockMinInterval/time.Second)
	maximum := uint64(now.Unix()) + uint64(LegacyKeyTimeMaxFuture/time.Second)

	tests := []struct {
		name      string
		timestamp uint64
		want      bool
	}{
		{name: "below worker minimum", timestamp: minimum - 1, want: false},
		{name: "worker parent plus minimum", timestamp: minimum, want: true},
		{name: "future upper boundary", timestamp: maximum, want: true},
		{name: "one second too far future", timestamp: maximum + 1, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := LegacyCandidateTimestampAllowed(parent, test.timestamp, now); got != test.want {
				t.Fatalf("allowed = %t, want %t", got, test.want)
			}
		})
	}
}

func TestLegacyKeyTimestampFuturePolicyBoundaries(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	maximum := uint64(now.Unix()) + uint64(LegacyKeyTimeMaxFuture/time.Second)
	if !LegacyKeyTimestampWithinFutureLimit(maximum, now) {
		t.Fatal("upper-bound timestamp was rejected")
	}
	if LegacyKeyTimestampWithinFutureLimit(maximum+1, now) {
		t.Fatal("far-future timestamp was accepted")
	}
	if LegacyKeyTimestampWithinFutureLimit(0, time.Unix(-1, 0)) {
		t.Fatal("negative wall clock was accepted")
	}
}

func TestLegacyCandidateTimestampRejectsParentOverflow(t *testing.T) {
	if LegacyCandidateTimestampAllowed(^uint64(0), ^uint64(0), time.Unix(1_700_000_000, 0)) {
		t.Fatal("overflowing parent timestamp was accepted")
	}
}
