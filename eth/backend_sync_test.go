package eth

import (
	"math/big"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
)

func TestConsensusSyncStateReady(t *testing.T) {
	hashA := common.HexToHash("0x01")
	hashB := common.HexToHash("0x02")
	tests := []struct {
		name  string
		state consensusSyncState
		want  bool
	}{
		{
			name:  "standalone node",
			state: consensusSyncState{standalone: true, localNumber: 10, observedNumber: 10},
			want:  true,
		},
		{
			name:  "configured network without a peer",
			state: consensusSyncState{localNumber: 10, observedNumber: 10},
		},
		{
			name:  "downloader active",
			state: consensusSyncState{downloading: true, localNumber: 10, observedNumber: 10},
		},
		{
			name:  "fetcher announcement ahead",
			state: consensusSyncState{localNumber: 10, observedNumber: 11},
		},
		{
			name: "peer total difficulty ahead",
			state: consensusSyncState{
				hasPeer: true, localNumber: 10, observedNumber: 10,
				localHash: hashA, peerHash: hashB,
				localTD: big.NewInt(10), peerTD: big.NewInt(11),
			},
		},
		{
			name: "equal total difficulty and head",
			state: consensusSyncState{
				hasPeer: true, localNumber: 10, observedNumber: 10,
				localHash: hashA, peerHash: hashA,
				localTD: big.NewInt(10), peerTD: big.NewInt(10),
			},
			want: true,
		},
		{
			name: "equal total difficulty but divergent head",
			state: consensusSyncState{
				hasPeer: true, localNumber: 10, observedNumber: 10,
				localHash: hashA, peerHash: hashB,
				localTD: big.NewInt(10), peerTD: big.NewInt(10),
			},
		},
		{
			name: "local total difficulty ahead",
			state: consensusSyncState{
				hasPeer: true, localNumber: 11, observedNumber: 11,
				localHash: hashA, peerHash: hashB,
				localTD: big.NewInt(11), peerTD: big.NewInt(10),
			},
			want: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.state.ready(); got != test.want {
				t.Fatalf("ready() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestRequiredObservedHeightDoesNotExpireKnownAhead(t *testing.T) {
	// The timestamp is deliberately not part of this calculation: a known
	// ahead height remains required even if start is called long after it was
	// announced.
	if got := requiredObservedHeight(10, 11); got != 11 {
		t.Fatalf("requiredObservedHeight(10, 11) = %d, want 11", got)
	}
	if got := requiredObservedHeight(12, 11); got != 12 {
		t.Fatalf("requiredObservedHeight(12, 11) = %d, want local height 12", got)
	}
}

func TestRaiseObservedHeadIsMonotonic(t *testing.T) {
	var observed uint64 = 11
	raiseObservedHead(&observed, 10)
	if observed != 11 {
		t.Fatalf("lower announcement reduced observed height to %d", observed)
	}
	raiseObservedHead(&observed, 12)
	if observed != 12 {
		t.Fatalf("higher announcement left observed height at %d, want 12", observed)
	}
}

func TestWaitForConsensusSyncRetriesUntilReady(t *testing.T) {
	calls := 0
	state, err := waitForConsensusSync(100*time.Millisecond, time.Millisecond, 0, func() consensusSyncState {
		calls++
		return consensusSyncState{standalone: true, downloading: calls < 3, localNumber: 7, observedNumber: 7}
	})
	if err != nil {
		t.Fatalf("waitForConsensusSync returned error: %v", err)
	}
	if !state.ready() || calls < 3 {
		t.Fatalf("returned before sync was ready: state=%+v calls=%d", state, calls)
	}
}

func TestWaitForConsensusSyncLatchesObservedHead(t *testing.T) {
	hash := common.HexToHash("0x01")
	calls := 0
	_, err := waitForConsensusSync(8*time.Millisecond, time.Millisecond, 0, func() consensusSyncState {
		calls++
		observed := uint64(10)
		if calls == 1 {
			observed = 11
		}
		return consensusSyncState{
			hasPeer: true, localNumber: 10, observedNumber: observed,
			localHash: hash, peerHash: hash,
			localTD: big.NewInt(10), peerTD: big.NewInt(10),
		}
	})
	if err == nil {
		t.Fatal("expected the first observed ahead height to remain required until timeout")
	}
	if calls < 2 {
		t.Fatalf("snapshot called %d times, want at least 2", calls)
	}
}

func TestWaitForConsensusSyncReleasesLatchAfterImport(t *testing.T) {
	calls := 0
	state, err := waitForConsensusSync(100*time.Millisecond, time.Millisecond, 0, func() consensusSyncState {
		calls++
		if calls == 1 {
			return consensusSyncState{standalone: true, localNumber: 10, observedNumber: 11}
		}
		return consensusSyncState{standalone: true, localNumber: 11, observedNumber: 11}
	})
	if err != nil {
		t.Fatalf("waitForConsensusSync returned error after import: %v", err)
	}
	if state.localNumber != 11 || state.observedNumber != 11 {
		t.Fatalf("state after import = %+v, want local and required observed height 11", state)
	}
}

func TestWaitForConsensusSyncRequiresPeer(t *testing.T) {
	_, err := waitForConsensusSync(5*time.Millisecond, time.Millisecond, 0, func() consensusSyncState {
		return consensusSyncState{localNumber: 7, observedNumber: 7}
	})
	if err == nil {
		t.Fatal("expected configured network without peers to time out")
	}
}

func TestWaitForConsensusSyncTimesOut(t *testing.T) {
	_, err := waitForConsensusSync(5*time.Millisecond, time.Millisecond, 0, func() consensusSyncState {
		return consensusSyncState{downloading: true}
	})
	if err == nil {
		t.Fatal("expected timeout error")
	}
}
