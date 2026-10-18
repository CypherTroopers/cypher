package miner

import (
	"context"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/reconfig/bftview"
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

type committeeAutoCommitTestChain struct {
	head      *types.KeyBlock
	committee []*common.Cnode
}

func (c *committeeAutoCommitTestChain) CurrentBlock() *types.KeyBlock { return c.head }
func (c *committeeAutoCommitTestChain) CurrentBlockN() uint64         { return c.head.NumberU64() }
func (c *committeeAutoCommitTestChain) CurrentCommittee() []*common.Cnode {
	return c.committee
}
func (c *committeeAutoCommitTestChain) GetBlockByHash(hash common.Hash) *types.KeyBlock {
	if c.head.Hash() == hash {
		return c.head
	}
	return nil
}

func TestCommitteeAutoCommitDoesNotRequestPoW(t *testing.T) {
	const isolated = "CYPHER_TEST_COMMITTEE_AUTOCOMMIT"
	if os.Getenv(isolated) != "1" {
		// bftview has no public snapshot/restore API for its committee globals.
		// Isolate the fixture so every other test retains its exact prior role.
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, "-test.run=^TestCommitteeAutoCommitDoesNotRequestPoW$", "-test.count=1", "-test.timeout=10s")
		cmd.Env = append(os.Environ(), isolated+"=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated committee worker: %v\n%s", err, output)
		}
		return
	}
	previousAddress, previousPublic := bftview.GetServerAddress(), bftview.GetServerInfo(bftview.PublicKey)
	previousCoinbase := bftview.GetServerCoinBase()
	t.Cleanup(func() {
		bftview.SetServerInfo(previousAddress, previousPublic)
		bftview.SetServerCoinBase(previousCoinbase)
	})
	const public = "synthetic-committee-public-key"
	chain := &committeeAutoCommitTestChain{
		head:      types.NewKeyBlock(&types.KeyBlockHeader{Number: big.NewInt(1), Difficulty: big.NewInt(1)}),
		committee: []*common.Cnode{{Public: public}},
	}
	bftview.SetCommitteeConfig(nil, chain, nil)
	bftview.SetServerInfo("127.0.0.1:0", public)
	if got := bftview.IamMember(); got != 0 {
		t.Fatalf("synthetic committee index = %d, want 0", got)
	}
	var starts, stops atomic.Int32
	engine := &dagLifecycleTestEngine{start: func() error { starts.Add(1); return nil }}
	agent := &dagStopTestAgent{stop: func() { stops.Add(1) }}
	subscription := event.NewSubscription(func(quit <-chan struct{}) error { <-quit; return nil })
	current := new(Work)
	w := &worker{
		engine: engine, running: 1, shouldStart: 1, atWork: 7, current: current,
		keyHeadCh: make(chan core.KeyChainHeadEvent), keyHeadSub: subscription,
		agents: map[Agent]struct{}{agent: {}},
		// A wrong initial-work branch hits the nil chain before sealing; a wrong
		// restart hits the nil config before connectivity checks. Neither can
		// allocate a DAG or open a socket, even when this regression fails.
	}
	done := make(chan struct{})
	var loopPanic interface{}
	go func() {
		defer func() { loopPanic = recover(); close(done) }()
		w.autoCommit(subscription)
	}()
	t.Cleanup(func() {
		subscription.Unsubscribe()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("committee worker did not exit")
		}
	})
	// Receiving this unbuffered event proves the initial role gate completed.
	// Joining after unsubscribe also waits for the head-event role gate.
	select {
	case w.keyHeadCh <- core.KeyChainHeadEvent{}:
	case <-done:
		t.Fatalf("committee worker exited before head event: %v", loopPanic)
	case <-time.After(time.Second):
		t.Fatal("committee worker did not receive head event")
	}
	subscription.Unsubscribe()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("committee worker did not finish after head event")
	}
	if loopPanic != nil {
		t.Fatalf("committee worker entered work or restart branch: %v", loopPanic)
	}
	if starts.Load() != 0 || stops.Load() != 0 || !w.isRunning() || atomic.LoadInt32(&w.shouldStart) != 1 || atomic.LoadInt32(&w.atWork) != 7 || w.current != current {
		t.Fatalf("committee head event changed mining work: starts=%d stops=%d running=%t permitted=%d atWork=%d", starts.Load(), stops.Load(), w.isRunning(), w.shouldStart, w.atWork)
	}
}
