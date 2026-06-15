package reconfig

import "testing"

func TestFixedModeKeyblockLeaderRemainsDeterministic(t *testing.T) {
	for primary := uint(0); primary < 16; primary++ {
		leader, round := fixedModeKeyblockLeader(primary)
		if leader != primary || round != 0 {
			t.Fatalf("primary %d selected leader=%d round=%d", primary, leader, round)
		}
	}
}
