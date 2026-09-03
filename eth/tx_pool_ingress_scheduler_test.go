package eth

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cypherium/cypher/core/types"
)

func TestTxPoolIngressSchedulerAccountsForRealBlobSidecarCapacity(t *testing.T) {
	tx := testTxQUICBlobTransaction(t, false)
	sidecar := tx.BlobSidecar()
	if sidecar == nil || len(sidecar.Blobs) != 1 {
		t.Fatal("real KZG test transaction has no blob sidecar")
	}
	want := int64(tx.Size()) + int64(len(sidecar.Blobs[0])) +
		int64(len(sidecar.Commitments)*len(types.KZGCommitment{})) +
		int64(len(sidecar.Proofs)*len(types.KZGProof{}))
	got, err := txPoolIngressJobBytes([]*types.Transaction{tx})
	if err != nil {
		t.Fatal(err)
	}
	if got != want || got <= int64(tx.Size()) {
		t.Fatalf("pooled blob ingress bytes = %d, want %d (execution envelope %d)", got, want, int64(tx.Size()))
	}

	scheduler := newTxPoolIngressScheduler(&testTxPoolIngressTarget{}, txPoolIngressSchedulerConfig{
		Workers: 1, MaxJobs: 1, MaxTxs: 1, MaxBytes: got - 1,
	})
	if _, err := scheduler.Submit(context.Background(), txPoolIngressRPC, []*types.Transaction{tx}); err == nil || !strings.Contains(err.Error(), "exceeds scheduler capacity") {
		t.Fatalf("sidecar-over-capacity submission error = %v", err)
	}

	total := int64(^uint64(0)>>1) - 1
	if addTxPoolIngressJobBytes(&total, 2) {
		t.Fatal("ingress byte accumulator accepted int64 overflow")
	}
}

type testTxPoolIngressTarget struct {
	mu        sync.Mutex
	active    int
	maxActive int
	order     []txPoolIngressSource
	started   chan txPoolIngressSource
	release   <-chan struct{}
}

func (p *testTxPoolIngressTarget) AddLocalsAsync(txs []*types.Transaction) []error {
	return p.publish(txPoolIngressRPC, txs)
}

func (p *testTxPoolIngressTarget) AddRemotes(txs []*types.Transaction) []error {
	return p.publish(txPoolIngressQUIC, txs)
}

func (p *testTxPoolIngressTarget) publish(source txPoolIngressSource, txs []*types.Transaction) []error {
	p.mu.Lock()
	p.active++
	if p.active > p.maxActive {
		p.maxActive = p.active
	}
	p.order = append(p.order, source)
	p.mu.Unlock()
	if p.started != nil {
		p.started <- source
	}
	if p.release != nil {
		<-p.release
	}
	results := make([]error, len(txs))
	for index := range results {
		results[index] = fmt.Errorf("source=%d index=%d", source, index)
	}
	p.mu.Lock()
	p.active--
	p.mu.Unlock()
	return results
}

func TestTxPoolIngressSchedulerConcurrencyBackpressureAndFairness(t *testing.T) {
	t.Run("concurrency and ordered outcomes", func(t *testing.T) {
		release := make(chan struct{})
		target := &testTxPoolIngressTarget{started: make(chan txPoolIngressSource, 2), release: release}
		scheduler := newTxPoolIngressScheduler(target, txPoolIngressSchedulerConfig{Workers: 2, MaxJobs: 2, MaxTxs: 8, MaxBytes: 1 << 20})
		if err := scheduler.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		defer scheduler.Stop()

		type response struct {
			results []error
			err     error
		}
		responses := make(chan response, 2)
		for _, source := range []txPoolIngressSource{txPoolIngressRPC, txPoolIngressQUIC} {
			source := source
			go func() {
				results, err := scheduler.Submit(context.Background(), source, []*types.Transaction{
					testTxQUICTransaction(uint64(source)+1, 8),
					testTxQUICTransaction(uint64(source)+11, 8),
				})
				responses <- response{results: results, err: err}
			}()
		}
		for index := 0; index < 2; index++ {
			select {
			case <-target.started:
			case <-time.After(time.Second):
				close(release)
				t.Fatal("scheduler did not reach configured concurrency")
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err := scheduler.Submit(ctx, txPoolIngressRPC, []*types.Transaction{testTxQUICTransaction(30, 8)})
		cancel()
		if err != context.DeadlineExceeded {
			close(release)
			t.Fatalf("full scheduler error=%v, want deadline exceeded", err)
		}
		close(release)
		for index := 0; index < 2; index++ {
			response := <-responses
			if response.err != nil {
				t.Fatal(response.err)
			}
			if len(response.results) != 2 || response.results[0] == nil || response.results[1] == nil || response.results[0].Error() == response.results[1].Error() {
				t.Fatalf("pool outcomes lost input alignment: %v", response.results)
			}
		}
		target.mu.Lock()
		maxActive := target.maxActive
		target.mu.Unlock()
		if maxActive != 2 {
			t.Fatalf("scheduler max concurrency=%d, want 2", maxActive)
		}
	})

	t.Run("round robin source fairness", func(t *testing.T) {
		release := make(chan struct{})
		target := &testTxPoolIngressTarget{started: make(chan txPoolIngressSource, 4), release: release}
		scheduler := newTxPoolIngressScheduler(target, txPoolIngressSchedulerConfig{Workers: 1, MaxJobs: 4, MaxTxs: 4, MaxBytes: 1 << 20})
		if err := scheduler.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		defer scheduler.Stop()

		done := make(chan error, 4)
		submit := func(source txPoolIngressSource, nonce byte) {
			_, err := scheduler.Submit(context.Background(), source, []*types.Transaction{testTxQUICTransaction(uint64(nonce), 8)})
			done <- err
		}
		go submit(txPoolIngressRPC, 1)
		select {
		case source := <-target.started:
			if source != txPoolIngressRPC {
				t.Fatalf("first source=%d, want RPC", source)
			}
		case <-time.After(time.Second):
			close(release)
			t.Fatal("first RPC job did not start")
		}
		go submit(txPoolIngressRPC, 2)
		go submit(txPoolIngressRPC, 3)
		go submit(txPoolIngressQUIC, 4)
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
				close(release)
				t.Fatalf("source queues did not fill: rpc=%d quic=%d", rpcQueued, quicQueued)
			}
			time.Sleep(time.Millisecond)
		}
		close(release)
		for index := 0; index < 4; index++ {
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		}
		target.mu.Lock()
		order := append([]txPoolIngressSource(nil), target.order...)
		target.mu.Unlock()
		if len(order) != 4 || order[0] != txPoolIngressRPC || order[1] != txPoolIngressQUIC {
			t.Fatalf("source fairness order=%v, want RPC then waiting QUIC", order)
		}
	})
}
