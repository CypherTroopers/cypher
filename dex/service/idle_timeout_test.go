package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/protocol"
)

// This execution is deliberately not a financial noop. Test ingress authorizes
// each next counter value; the service itself never manufactures an action.
type idleExecution struct{}

func (idleExecution) ID() string     { return "socket-idle-counter-v1" }
func (idleExecution) Schema() uint16 { return consensus.ExecutionSchema }
func (idleExecution) Genesis() ([]byte, protocol.Hash, error) {
	return []byte{0}, protocol.Digest("socket-idle-state", []byte{0}), nil
}
func (idleExecution) Execute(parent, action []byte, ctx consensus.ExecutionContext) (consensus.ExecutionResult, error) {
	if len(parent) != 1 || len(action) != 1 || uint64(parent[0])+1 != ctx.Height || uint64(action[0]) != ctx.Height || ctx.ParentRoot != protocol.Digest("socket-idle-state", parent) {
		return consensus.ExecutionResult{}, errors.New("idle counter parent/action")
	}
	return consensus.ExecutionResult{State: append([]byte(nil), action...), PostRoot: protocol.Digest("socket-idle-state", action)}, nil
}

func TestIdleTimeoutPacingOverTLSAndMissingLeaders(t *testing.T) {
	testIdleTimeoutPacingOverTLS(t, false)
}

func TestPendingSubmissionsPreserveSparseIngressFinalityOverTLS(t *testing.T) {
	testIdleTimeoutPacingOverTLS(t, true)
}

func testIdleTimeoutPacingOverTLS(t *testing.T, pendingSubmission bool) {
	cs := serviceConfigs(t)
	var allowed [7]uint64
	for i := range cs {
		i := i
		cs[i].Consensus.MaxHeight = 6
		cs[i].Consensus.Execution = idleExecution{}
		cs[i].Consensus.ActionsWithParent = func(_ []byte, ctx consensus.ExecutionContext) ([]byte, error) {
			if ctx.Height > allowed[i] {
				return nil, consensus.ErrUnavailable
			}
			return []byte{byte(ctx.Height)}, nil
		}
		cs[i].TimeoutReady = func(a *consensus.Application) (bool, error) {
			pending, err := a.PendingFHSTimeoutVote()
			ready := a.CertifiedHeight() < allowed[i] || a.HasUncertifiedVote() || pending != nil && pending.TimedOutView >= a.CurrentN()
			return ready, err
		}
	}
	ss := openServices(t, cs)
	for _, s := range ss {
		s.SetSubmissionPending(pendingSubmission)
	}
	active := []int{0, 1, 2, 3, 4, 5, 6}
	call := func(i int, fn func(*consensus.Application) error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := ss[i].Do(ctx, fn); err != nil {
			t.Fatalf("node%d: %v", i, err)
		}
	}
	checkIdle := func(height, view uint64) {
		t.Helper()
		// A finite observation interval intentionally exceeds three timeout
		// periods. Progress assertions below wait for observed certificates.
		deadline := time.Now().Add(3*cs[0].Timeout + 100*time.Millisecond)
		for time.Now().Before(deadline) {
			for _, i := range active {
				call(i, func(a *consensus.Application) error {
					p, e := a.PendingFHSTimeoutVote()
					if e != nil {
						return e
					}
					if a.CertifiedHeight() != height || a.CurrentN() != view || p != nil {
						return fmt.Errorf("idle interval changed: certified=%d expected=%d view=%d expected=%d pending=%+v vote=%t", a.CertifiedHeight(), height, a.CurrentN(), view, p, a.HasUncertifiedVote())
					}
					return nil
				})
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	admit := func(height uint64) {
		t.Helper()
		for _, i := range active {
			i := i
			call(i, func(a *consensus.Application) error {
				allowed[i] = height
				err := a.NotifyIngress()
				if benign(err) {
					return nil
				}
				return err
			})
		}
	}
	wait := func(certified, finalized, view uint64) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			done := true
			for _, i := range active {
				call(i, func(a *consensus.Application) error {
					q := a.HighestCertified()
					if a.CertifiedHeight() != certified || a.FinalizedHeight() != finalized || q == nil || q.Number != view {
						done = false
					}
					return nil
				})
			}
			if done {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		for _, i := range active {
			call(i, func(a *consensus.Application) error {
				t.Logf("node%d cert=%d final=%d view=%d qc=%+v", i, a.CertifiedHeight(), a.FinalizedHeight(), a.CurrentN(), a.HighestCertified())
				return nil
			})
		}
		t.Fatal("bounded TLS progress deadline exceeded")
	}
	checkIdle(0, 1)
	admit(1)
	wait(1, 0, 1)
	checkIdle(1, 2)
	admit(2)
	wait(2, 1, 2)
	for _, s := range ss {
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
	ss = openServices(t, cs)
	for _, s := range ss {
		s.SetSubmissionPending(pendingSubmission)
	}
	checkIdle(2, 3)
	// View3's leader is offline: executable ingress must still create a real
	// timeout certificate, then a threshold QC in view4 with six live nodes.
	if err := ss[2].Close(); err != nil {
		t.Fatal(err)
	}
	active = []int{0, 1, 3, 4, 5, 6}
	admit(3)
	wait(3, 1, 4)
	checkIdle(3, 5)
	// A second leader is now offline (view5). The remaining five must preserve
	// the threshold and use view6. A genuine child in view7 finalizes the gaps.
	if err := ss[4].Close(); err != nil {
		t.Fatal(err)
	}
	active = []int{0, 1, 3, 5, 6}
	admit(4)
	wait(4, 1, 6)
	checkIdle(4, 7)
	admit(5)
	wait(5, 4, 7)
	for _, i := range active {
		call(i, func(a *consensus.Application) error {
			_, proof, err := a.FinalizedCheckpoint(4)
			if err == nil && len(proof) == 0 {
				return errors.New("missing real finality proof")
			}
			return err
		})
	}
	t.Log("idle periods produced no timeout votes; sparse genuine ingress, same-WAL restart and one/two missing leaders formed ordinary threshold QCs over pinned TLS; final tail remains certified only")
}
