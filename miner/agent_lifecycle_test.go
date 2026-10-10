package miner

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/core/types"
)

type cpuAgentLifecycleEngine struct {
	consensus.Engine
	seal func(*types.Candidate, <-chan struct{}) (*types.Candidate, error)
}

func (e *cpuAgentLifecycleEngine) SealCandidate(candidate *types.Candidate, stop <-chan struct{}) (*types.Candidate, error) {
	return e.seal(candidate, stop)
}

func cpuAgentLifecycleWork() *Work {
	return &Work{candidate: &types.Candidate{KeyCandidate: new(types.KeyBlockHeader)}}
}

func waitCpuAgentSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for CPU agent lifecycle")
	}
}

func assertCpuAgentPending(t *testing.T, signal <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-signal:
		t.Fatalf("%s returned before sealing drained", operation)
	case <-time.After(25 * time.Millisecond):
	}
}

func TestCpuAgentStopWaitsForSealingAndSerializesRestart(t *testing.T) {
	first, second, queued := cpuAgentLifecycleWork(), cpuAgentLifecycleWork(), cpuAgentLifecycleWork()
	firstStarted, secondStarted := make(chan struct{}), make(chan struct{})
	firstCanceled, releaseFirst := make(chan struct{}), make(chan struct{})
	unexpectedWork := make(chan struct{}, 1)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseFirst) }) }
	var active atomic.Int32
	engine := &cpuAgentLifecycleEngine{seal: func(candidate *types.Candidate, stop <-chan struct{}) (*types.Candidate, error) {
		active.Add(1)
		defer active.Add(-1)
		if candidate == first.candidate {
			close(firstStarted)
			<-stop
			close(firstCanceled)
			<-releaseFirst // Simulate initialization that cannot finish immediately on cancellation.
		} else if candidate == second.candidate {
			close(secondStarted)
			<-stop
		} else {
			unexpectedWork <- struct{}{}
			<-stop
		}
		return nil, nil
	}}
	agent := NewCpuAgent(nil, engine)
	defer func() { release(); agent.Stop() }()
	agent.Start()
	agent.Work() <- first
	waitCpuAgentSignal(t, firstStarted)
	stopped := make(chan struct{})
	go func() { agent.Stop(); close(stopped) }()
	waitCpuAgentSignal(t, firstCanceled)
	assertCpuAgentPending(t, stopped, "Stop")
	agent.Work() <- queued // Stop must drain work queued behind the canceled update loop.
	restarted := make(chan struct{})
	go func() { agent.Start(); close(restarted) }()
	assertCpuAgentPending(t, restarted, "Start")
	release()
	waitCpuAgentSignal(t, stopped)
	waitCpuAgentSignal(t, restarted)
	if got := active.Load(); got != 0 {
		t.Fatalf("old sealing calls after Stop = %d, want 0", got)
	}
	agent.Work() <- second
	waitCpuAgentSignal(t, secondStarted)
	select {
	case <-unexpectedWork:
		t.Fatal("restarted generation sealed stale queued work")
	default:
	}
	agent.Stop()
	if got := active.Load(); got != 0 {
		t.Fatalf("sealing calls after restarted Stop = %d, want 0", got)
	}
}

func TestCpuAgentStopCancelsBlockedResultDelivery(t *testing.T) {
	for _, successful := range []bool{false, true} {
		name := "failed seal"
		if successful {
			name = "successful seal"
		}
		t.Run(name, func(t *testing.T) {
			sealed := make(chan struct{})
			engine := &cpuAgentLifecycleEngine{seal: func(candidate *types.Candidate, _ <-chan struct{}) (*types.Candidate, error) {
				close(sealed)
				if successful {
					return candidate, nil
				}
				return nil, nil
			}}
			agent := NewCpuAgent(nil, engine)
			results := make(chan *Result, 1)
			sentinel := new(Result)
			results <- sentinel
			agent.SetReturnCh(results)
			agent.Start()
			agent.Work() <- cpuAgentLifecycleWork()
			waitCpuAgentSignal(t, sealed)
			stopped := make(chan struct{})
			go func() { agent.Stop(); close(stopped) }()
			waitCpuAgentSignal(t, stopped)
			if got := <-results; got != sentinel {
				t.Fatal("Stop replaced a queued result")
			}
			if len(results) != 0 {
				t.Fatal("canceled sealing published a result after Stop")
			}
		})
	}
}

func TestCpuAgentStopWaitsForOverlappingCanceledSeals(t *testing.T) {
	first, second := cpuAgentLifecycleWork(), cpuAgentLifecycleWork()
	firstStarted, secondStarted := make(chan struct{}), make(chan struct{})
	firstCanceled, secondCanceled := make(chan struct{}), make(chan struct{})
	releaseFirst, releaseSecond := make(chan struct{}), make(chan struct{})
	var firstOnce, secondOnce sync.Once
	finishFirst := func() { firstOnce.Do(func() { close(releaseFirst) }) }
	finishSecond := func() { secondOnce.Do(func() { close(releaseSecond) }) }
	engine := &cpuAgentLifecycleEngine{seal: func(candidate *types.Candidate, stop <-chan struct{}) (*types.Candidate, error) {
		if candidate == first.candidate {
			close(firstStarted)
			<-stop
			close(firstCanceled)
			<-releaseFirst
		} else {
			close(secondStarted)
			<-stop
			close(secondCanceled)
			<-releaseSecond
		}
		return nil, nil
	}}
	agent := NewCpuAgent(nil, engine)
	defer func() { finishFirst(); finishSecond(); agent.Stop() }()
	agent.Start()
	agent.Work() <- first
	waitCpuAgentSignal(t, firstStarted)
	agent.Work() <- second
	waitCpuAgentSignal(t, firstCanceled)
	waitCpuAgentSignal(t, secondStarted)
	stopped := make(chan struct{})
	go func() { agent.Stop(); close(stopped) }()
	waitCpuAgentSignal(t, secondCanceled)
	finishSecond()
	assertCpuAgentPending(t, stopped, "Stop with a replaced operation still running")
	finishFirst()
	waitCpuAgentSignal(t, stopped)
}

func TestCpuAgentReplacedSealDeliversCompletion(t *testing.T) {
	first, second := cpuAgentLifecycleWork(), cpuAgentLifecycleWork()
	firstStarted, secondStarted := make(chan struct{}), make(chan struct{})
	engine := &cpuAgentLifecycleEngine{seal: func(candidate *types.Candidate, stop <-chan struct{}) (*types.Candidate, error) {
		if candidate == first.candidate {
			close(firstStarted)
		} else {
			close(secondStarted)
		}
		<-stop
		return nil, nil
	}}
	agent := NewCpuAgent(nil, engine)
	results := make(chan *Result, 1)
	agent.SetReturnCh(results)
	defer agent.Stop()
	agent.Start()
	agent.Work() <- first
	waitCpuAgentSignal(t, firstStarted)
	agent.Work() <- second
	waitCpuAgentSignal(t, secondStarted)
	// Routine work replacement must still notify the worker so it can account
	// for the completed operation. Only stopping the generation drops delivery.
	select {
	case result := <-results:
		if result != nil {
			t.Fatal("canceled seal delivered a successful result")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("replaced sealing operation did not report completion")
	}
}

func TestCpuAgentRepeatedStartStopDrainsEachGeneration(t *testing.T) {
	started := make(chan struct{}, 1)
	var active atomic.Int32
	engine := &cpuAgentLifecycleEngine{seal: func(_ *types.Candidate, stop <-chan struct{}) (*types.Candidate, error) {
		active.Add(1)
		defer active.Add(-1)
		started <- struct{}{}
		<-stop
		return nil, nil
	}}
	agent := NewCpuAgent(nil, engine)
	defer agent.Stop()
	for generation := 0; generation < 32; generation++ {
		agent.Start()
		agent.Start() // Starting a running generation is idempotent.
		agent.Work() <- cpuAgentLifecycleWork()
		waitCpuAgentSignal(t, started)
		agent.Stop()
		agent.Stop()
		if got := active.Load(); got != 0 {
			t.Fatalf("generation %d has %d sealing calls after Stop", generation, got)
		}
	}
}
