package miner

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/event"
)

type dagLifecycleTestEngine struct {
	consensus.Engine
	start func() error
	stop  func() error
}

func (e *dagLifecycleTestEngine) StartMining() error {
	if e.start != nil {
		return e.start()
	}
	return nil
}

func (e *dagLifecycleTestEngine) StopMining() error {
	if e.stop != nil {
		return e.stop()
	}
	return nil
}

type dagStopTestAgent struct{ stop func() }

func (*dagStopTestAgent) Work() chan<- *Work         { return nil }
func (*dagStopTestAgent) SetReturnCh(chan<- *Result) {}
func (*dagStopTestAgent) Start()                     {}
func (a *dagStopTestAgent) Stop()                    { a.stop() }

func TestMinerStopWaitsForReadersBeforeDAGRelease(t *testing.T) {
	readerStopping := make(chan struct{})
	readerDone := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(readerDone) }) })
	wantErr := errors.New("DAG release failed")
	released := make(chan struct{})
	engine := &dagLifecycleTestEngine{stop: func() error {
		select {
		case <-readerDone:
		default:
			t.Error("DAG was released before its reader finished")
		}
		close(released)
		return wantErr
	}}
	agent := &dagStopTestAgent{stop: func() {
		close(readerStopping)
		<-readerDone
	}}
	subscription := event.NewSubscription(func(quit <-chan struct{}) error { <-quit; return nil })
	t.Cleanup(subscription.Unsubscribe)
	w := &worker{engine: engine, running: 1, shouldStart: 1, keyHeadSub: subscription, agents: map[Agent]struct{}{agent: {}}}
	m := &Miner{worker: w, engine: engine}
	stopped := make(chan error, 1)
	go func() { stopped <- m.Stop() }()
	select {
	case <-readerStopping:
	case <-time.After(time.Second):
		t.Fatal("miner did not stop its reader")
	}
	select {
	case <-released:
		t.Fatal("DAG release did not wait for the reader")
	default:
	}
	if atomic.LoadInt32(&w.shouldStart) != 0 {
		t.Fatal("miner stop left automatic restart permitted")
	}
	releaseOnce.Do(func() { close(readerDone) })
	select {
	case err := <-stopped:
		if !errors.Is(err, wantErr) {
			t.Fatalf("stop error = %v, want %v", err, wantErr)
		}
	case <-time.After(time.Second):
		t.Fatal("miner stop did not finish after the reader")
	}
}

func TestMinerStopReleasesDAGWhenWorkerAlreadyIdle(t *testing.T) {
	calls := 0
	engine := &dagLifecycleTestEngine{stop: func() error { calls++; return nil }}
	m := &Miner{worker: &worker{engine: engine}, engine: engine}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("idle worker DAG release calls = %d, want 1", calls)
	}
}

func TestMinerStopRejectsStaleHeadEventRestart(t *testing.T) {
	releasing := make(chan struct{})
	releaseDone := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseDone) }) })
	var starts atomic.Int32
	engine := &dagLifecycleTestEngine{
		start: func() error { starts.Add(1); return nil },
		stop:  func() error { close(releasing); <-releaseDone; return nil },
	}
	w := &worker{engine: engine, shouldStart: 1}
	m := &Miner{worker: w, engine: engine}
	stopped := make(chan error, 1)
	go func() { stopped <- m.Stop() }()
	select {
	case <-releasing:
	case <-time.After(time.Second):
		t.Fatal("miner did not begin DAG release")
	}
	// A head-event loop may have captured shouldStart=true before explicit stop.
	restarted := make(chan error, 1)
	go func() { restarted <- w.start() }()
	releaseOnce.Do(func() { close(releaseDone) })
	for _, completion := range []<-chan error{stopped, restarted} {
		select {
		case err := <-completion:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("stop or stale restart deadlocked")
		}
	}
	if starts.Load() != 0 || w.isRunning() {
		t.Fatal("stale head event restarted the stopped miner")
	}
}
