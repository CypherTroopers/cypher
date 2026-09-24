package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cypherium/cypher/dex/consensus"
)

func TestPendingSubmissionReplacesIdleOfflineLeaderOverTLS(t *testing.T) {
	for _, missing := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("unavailable-%d", missing), func(t *testing.T) {
			testPendingSubmissionLeaderTimeout(t, missing)
		})
	}
}

func testPendingSubmissionLeaderTimeout(t *testing.T, missing int) {
	cs := serviceConfigs(t)
	for i := range cs {
		cs[i].Timeout = 300 * time.Millisecond
		// Short explicit local grace for this failover-only fixture. The
		// ordinary CLI default remains 15s (or the longer market timeout).
		cs[i].SubmissionTimeout = 600 * time.Millisecond
		cs[i].Consensus.Execution = idleExecution{}
		cs[i].Consensus.ActionsWithParent = func([]byte, consensus.ExecutionContext) ([]byte, error) {
			return nil, consensus.ErrUnavailable
		}
		cs[i].TimeoutReady = func(*consensus.Application) (bool, error) { return false, nil }
	}
	ss := openServices(t, cs)
	oldLeases := make([]<-chan struct{}, len(ss))
	for i, s := range ss {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		state, done, err := s.LeadershipLease(ctx)
		cancel()
		if err != nil || state.View != 1 || state.Active != (i == 0) || done == nil {
			t.Fatalf("initial node%d leadership %+v: %v", i, state, err)
		}
		oldLeases[i] = done
	}
	if err := ss[0].Close(); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < missing; i++ {
		if err := ss[len(ss)-i].Close(); err != nil {
			t.Fatal(err)
		}
	}
	active := ss[1 : len(ss)-missing+1]
	select {
	case <-oldLeases[0]:
	default:
		t.Fatal("stopping actor retained live submission lease")
	}
	for _, s := range active {
		s.SetSubmissionPending(true)
	}
	deadline := time.Now().Add(8 * time.Second)
	if missing == 3 {
		deadline = time.Now().Add(4 * cs[0].SubmissionTimeout)
	}
	for time.Now().Before(deadline) {
		advanced := 0
		for i, s := range active {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			state, err := s.Status(ctx)
			cancel()
			if err != nil {
				t.Fatalf("follower%d: %v", i+1, err)
			}
			if state.Certified != 0 || state.Finalized != 0 {
				t.Fatal("settlement scheduling manufactured a market action")
			}
			if state.Leadership.View > 1 {
				advanced++
			}
		}
		if missing == 3 && advanced != 0 {
			t.Fatal("four participants manufactured a five-vote timeout certificate")
		}
		if advanced == len(active) {
			for i, s := range active {
				select {
				case <-oldLeases[i+1]:
				default:
					t.Fatal("authenticated view advance retained old submission lease")
				}
				s.SetSubmissionPending(false)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	if missing == 3 {
		return // four genuine signers cannot replace the authenticated view
	}
	t.Fatal("authenticated timeout quorum did not replace idle offline leader")
}
