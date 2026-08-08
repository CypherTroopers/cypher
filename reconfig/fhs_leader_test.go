package reconfig

import (
	"testing"

	"github.com/cypherium/cypher/common"
)

func TestFairHotstuffLeaderScheduleIsDeterministicAndQCIndependent(t *testing.T) {
	seed := common.HexToHash("0xacb7b49e23815caf94dc47bcf81dab93cc986cf9ab04e243efcbc204c6a2a627")
	committee := common.HexToHash("0x1234")
	for view := uint64(1); view <= 100; view++ {
		first, err := fairHotstuffLeaderIndex(seed, 10101919, view, committee, 7)
		if err != nil {
			t.Fatal(err)
		}
		for signerSubset := 0; signerSubset < 21; signerSubset++ {
			// No QC signature, signer mask, block hash, proposal data, or leader ID
			// is an argument to the election function. All C(7,5) possible QCs
			// therefore resolve to the same next leader.
			again, err := fairHotstuffLeaderIndex(seed, 10101919, view, committee, 7)
			if err != nil || again != first {
				t.Fatalf("view %d subset %d leader = %d/%v, want %d", view, signerSubset, again, err, first)
			}
		}
	}
}

func TestFairHotstuffLeaderScheduleCoversSevenNodeCommittee(t *testing.T) {
	seed := common.HexToHash("0xacb7b49e23815caf94dc47bcf81dab93cc986cf9ab04e243efcbc204c6a2a627")
	committee := common.HexToHash("0x5678")
	seen := make(map[uint]bool)
	for view := uint64(1); view <= 700; view++ {
		index, err := fairHotstuffLeaderIndex(seed, 10101919, view, committee, 7)
		if err != nil {
			t.Fatal(err)
		}
		if index >= 7 {
			t.Fatalf("leader index %d outside committee", index)
		}
		seen[index] = true
	}
	if len(seen) != 7 {
		t.Fatalf("leader schedule covered %d/7 committee members", len(seen))
	}
}

func TestFairHotstuffLeaderScheduleRejectsMissingTrustAnchor(t *testing.T) {
	if _, err := fairHotstuffLeaderIndex(common.Hash{}, 1, 1, common.HexToHash("0x1"), 7); err == nil {
		t.Fatal("zero seed accepted")
	}
}
