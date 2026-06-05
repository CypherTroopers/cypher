package reconfig

import (
	"testing"
	"time"
)

func TestCommonApprovalVoteSetWaitsForActiveMembers(t *testing.T) {
	tests := []struct {
		name          string
		voteCount     int
		committeeSize int
		threshold     int
		allowPartial  bool
		want          bool
	}{
		{
			name:          "bootstrap self vote waits for dynamic member",
			voteCount:     1,
			committeeSize: 2,
			threshold:     1,
			want:          false,
		},
		{
			name:          "all active members respond",
			voteCount:     2,
			committeeSize: 2,
			threshold:     1,
			want:          true,
		},
		{
			name:          "timeout keeps bootstrap fallback",
			voteCount:     1,
			committeeSize: 2,
			threshold:     1,
			allowPartial:  true,
			want:          true,
		},
		{
			name:          "timeout does not bypass normal threshold",
			voteCount:     1,
			committeeSize: 3,
			threshold:     2,
			allowPartial:  true,
			want:          false,
		},
		{
			name:          "single-member committee completes immediately",
			voteCount:     1,
			committeeSize: 1,
			threshold:     1,
			want:          true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := commonApprovalVoteSetReady(test.voteCount, test.committeeSize, test.threshold, test.allowPartial)
			if got != test.want {
				t.Fatalf("unexpected readiness: have=%t want=%t", got, test.want)
			}
		})
	}
}

func TestCommonApprovalVoteTimeout(t *testing.T) {
	if commonApprovalVoteTimeout != 100*time.Millisecond {
		t.Fatalf("unexpected common approval vote timeout: have=%s want=%s", commonApprovalVoteTimeout, 100*time.Millisecond)
	}
}
