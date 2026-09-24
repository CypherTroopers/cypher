package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/protocol"
)

type quotaExecution struct{ idleExecution }

func (quotaExecution) ID() string     { return "quota-ancestry-counter-v1" }
func (quotaExecution) Schema() uint16 { return consensus.AncestryExecutionSchema }
func (e quotaExecution) Execute(parent, action []byte, ctx consensus.ExecutionContext) (consensus.ExecutionResult, error) {
	r, err := e.idleExecution.Execute(parent, action, ctx)
	r.CLXHeight, r.CLXHash = ctx.CLXHeight, ctx.CLXHash
	return r, err
}
func (quotaExecution) ValidateSnapshot(raw []byte, height uint64, root protocol.Hash) error {
	if len(raw) != 1 || uint64(raw[0]) != height || root != protocol.Digest("socket-idle-state", raw) {
		return errors.New("quota execution snapshot mismatch")
	}
	return nil
}

func TestOfflinePeerQuotaPreservesFHSQuorumProgress(t *testing.T) {
	cs := serviceConfigs(t)
	const target = uint64(40)
	var ss []*Service
	for i := range cs {
		cs[i].Consensus.MaxHeight = target
		cs[i].Consensus.StorageGenerations = true
		cs[i].Consensus.Execution = quotaExecution{}
		cs[i].Consensus.ActionsWithParent = func(_ []byte, ctx consensus.ExecutionContext) ([]byte, error) { return []byte{byte(ctx.Height)}, nil }
		cs[i].TimeoutReady = func(a *consensus.Application) (bool, error) { return a.CertifiedHeight() < target, nil }
		cs[i].Timeout = 2 * time.Second
		s, err := Open(cs[i])
		if err != nil {
			t.Fatal(err)
		}
		ss = append(ss, s)
		t.Cleanup(func() { s.Close() })
	}
	// Node zero never starts its listener. The other six must continue ordinary
	// FHS beyond the 36-message per-peer allowance without discarding its queue.
	for _, s := range ss[1:] {
		if err := s.Start(); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		done, saturated := true, false
		var root protocol.Hash
		for i, s := range ss[1:] {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			status, err := s.Status(ctx)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			done = done && status.Finalized >= target-1
			if status.PendingTransportByPeer[0] > 36 {
				cancel()
				t.Fatal("offline queue exceeded its share", status)
			}
			saturated = saturated || status.PendingTransportByPeer[0] == 36
			if status.Finalized >= target-1 {
				err = s.Do(ctx, func(a *consensus.Application) error {
					cp, _, e := a.FinalizedCheckpoint(target - 1)
					if e != nil {
						return e
					}
					if root == (protocol.Hash{}) {
						root = cp.PostRoot
					} else if root != cp.PostRoot {
						t.Errorf("node%d conflicting finalized root", i+1)
					}
					return nil
				})
			}
			cancel()
			if err != nil {
				t.Fatal(err)
			}
		}
		if done && saturated {
			// Reopen a healthy node with the exact same vote/outbox DB while
			// the absent peer still owns its full share. Startup backpressure
			// must neither erase the queue nor prevent recovery from running.
			if err := ss[1].Close(); err != nil {
				t.Fatal(err)
			}
			restarted, err := Open(cs[1])
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { restarted.Close() })
			if err = restarted.Start(); err != nil {
				t.Fatal("restart with full offline share", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			state, err := restarted.Status(ctx)
			cancel()
			if err != nil || state.Finalized < target-1 || state.PendingTransportByPeer[0] != 36 {
				t.Fatal("restart lost finality or accepted offline frames", state, err)
			}
			t.Log("six live FHS actors finalized39/certified40 while one destination retained its36 accepted frames; normal quorum and root agreement retained")
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	for i, s := range ss[1:] {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		status, err := s.Status(ctx)
		cancel()
		t.Logf("node%d status=%+v error=%v", i+1, status, err)
	}
	t.Fatal("offline transport destination starved healthy FHS quorum")
}
