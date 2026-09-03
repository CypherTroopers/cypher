package eth

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestTxLiveIngressSchedulerBoundsAndAlternatesSources(t *testing.T) {
	scheduler := newTxLiveIngressScheduler(txLiveIngressSchedulerConfig{
		MaxActiveJobs: 1, MaxActiveTxs: 4, MaxActiveBytes: 400,
		MaxPendingJobs: 4, MaxPendingTxs: 16, MaxPendingBytes: 1_600,
	})
	if err := scheduler.Start(); err != nil {
		t.Fatal(err)
	}
	defer scheduler.Stop()

	firstRelease, err := scheduler.Acquire(context.Background(), txPoolIngressRPC, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	type acquired struct {
		source  txPoolIngressSource
		release func()
		err     error
	}
	results := make(chan acquired, 3)
	for _, source := range []txPoolIngressSource{txPoolIngressRPC, txPoolIngressRPC, txPoolIngressQUIC} {
		source := source
		go func() {
			release, err := scheduler.Acquire(context.Background(), source, 1, 100)
			results <- acquired{source: source, release: release, err: err}
		}()
	}
	deadline := time.Now().Add(time.Second)
	for {
		scheduler.mu.Lock()
		rpcQueued := len(scheduler.queues[txPoolIngressRPC])
		quicQueued := len(scheduler.queues[txPoolIngressQUIC])
		scheduler.mu.Unlock()
		if rpcQueued == 2 && quicQueued == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("live source queues did not fill: rpc=%d quic=%d", rpcQueued, quicQueued)
		}
		time.Sleep(time.Millisecond)
	}
	firstRelease()
	first := <-results
	if first.err != nil {
		t.Fatal(first.err)
	}
	if first.source != txPoolIngressQUIC {
		t.Fatalf("first waiting source=%d, want QUIC fairness", first.source)
	}
	first.release()
	for index := 0; index < 2; index++ {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		result.release()
	}
}

func TestTxLiveIngressSchedulerCancellationAndPendingCapacity(t *testing.T) {
	scheduler := newTxLiveIngressScheduler(txLiveIngressSchedulerConfig{
		MaxActiveJobs: 1, MaxActiveTxs: 1, MaxActiveBytes: 100,
		MaxPendingJobs: 2, MaxPendingTxs: 2, MaxPendingBytes: 200,
	})
	if err := scheduler.Start(); err != nil {
		t.Fatal(err)
	}
	defer scheduler.Stop()
	release, err := scheduler.Acquire(context.Background(), txPoolIngressRPC, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	queuedCtx, cancelQueued := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelQueued()
	queuedDone := make(chan error, 1)
	go func() {
		_, err := scheduler.Acquire(queuedCtx, txPoolIngressQUIC, 1, 100)
		queuedDone <- err
	}()

	deadline := time.Now().Add(time.Second)
	for {
		scheduler.mu.Lock()
		pending := scheduler.pendingJobs
		scheduler.mu.Unlock()
		if pending == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("queued live request did not reserve pending capacity")
		}
		time.Sleep(time.Millisecond)
	}
	fullCtx, cancelFull := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, fullErr := scheduler.Acquire(fullCtx, txPoolIngressRPC, 1, 100)
	cancelFull()
	if fullErr != context.DeadlineExceeded {
		t.Fatalf("full pending scheduler error=%v, want deadline exceeded", fullErr)
	}
	if err := <-queuedDone; err != context.DeadlineExceeded {
		t.Fatalf("queued cancellation error=%v, want deadline exceeded", err)
	}
	release()
	scheduler.mu.Lock()
	pending, active := scheduler.pendingJobs, scheduler.activeJobs
	scheduler.mu.Unlock()
	if pending != 0 || active != 0 {
		t.Fatalf("scheduler leaked capacity: pending=%d active=%d", pending, active)
	}
}

func TestTxLiveIngressSchedulerReleaseIsIdempotent(t *testing.T) {
	scheduler := newTxLiveIngressScheduler(txLiveIngressSchedulerConfig{
		MaxActiveJobs: 1, MaxActiveTxs: 1, MaxActiveBytes: 100,
		MaxPendingJobs: 1, MaxPendingTxs: 1, MaxPendingBytes: 100,
	})
	if err := scheduler.Start(); err != nil {
		t.Fatal(err)
	}
	defer scheduler.Stop()
	release, err := scheduler.Acquire(context.Background(), txPoolIngressRPC, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for index := 0; index < 8; index++ {
		group.Add(1)
		go func() { defer group.Done(); release() }()
	}
	group.Wait()
	scheduler.mu.Lock()
	pending, active := scheduler.pendingJobs, scheduler.activeJobs
	scheduler.mu.Unlock()
	if pending != 0 || active != 0 {
		t.Fatalf("idempotent release counters: pending=%d active=%d", pending, active)
	}
}
